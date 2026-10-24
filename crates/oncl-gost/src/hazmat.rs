//! Raw GOST R 34.10 (2001/2012) arithmetic on big integers.
//!
//! "Hazmat": no hashing, no encodings, no randomness. Callers supply the digest already turned
//! into an integer `e` and, for signing, the nonce `k`. Secret scalars (`d`, `k`) are processed
//! by a fixed-length Montgomery ladder with constant-time selection and zeroized after use.
//!
//! Integers may come at any [`BoxedUint`] precision; results are returned at the precision of
//! `p` (256 or 512 bits for the GOST curves).

use crate::point::{Curve, Point, fit};
use crypto_bigint::{BoxedUint, CtLt, CtSelect};
use zeroize::Zeroizing;

/// Short Weierstrass curve `y² = x³ + a·x + b (mod p)` with a base point `G = (gx, gy)` of prime
/// order `q`.
///
/// All fields are expected at the same precision (the one [`CurveParams::from_hex`] produces).
/// The curve must have no points of order two (true for prime-order curves); the complete
/// addition formulas rely on that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurveParams {
    pub p: BoxedUint,
    pub a: BoxedUint,
    pub b: BoxedUint,
    pub q: BoxedUint,
    pub gx: BoxedUint,
    pub gy: BoxedUint,
}

impl CurveParams {
    /// Parses big-endian hex constants (any length, no `0x` prefix). Every value is carried at
    /// the precision of `p` rounded up to whole limbs.
    ///
    /// # Panics
    ///
    /// If a string is not hex, or a value does not fit in the bit length of `p`. These are
    /// compile-time constants, so a panic is a programming error.
    pub fn from_hex(p: &str, a: &str, b: &str, q: &str, gx: &str, gy: &str) -> CurveParams {
        let bits = BoxedUint::from_str_radix_vartime(p, 16)
            .expect("p: invalid hex")
            .bits_vartime();
        let parse = |name: &str, hex: &str| {
            BoxedUint::from_str_radix_with_precision_vartime(hex, 16, bits)
                .unwrap_or_else(|err| panic!("{name}: invalid curve constant: {err:?}"))
        };
        CurveParams {
            p: parse("p", p),
            a: parse("a", a),
            b: parse("b", b),
            q: parse("q", q),
            gx: parse("gx", gx),
            gy: parse("gy", gy),
        }
    }

    fn precision(&self) -> u32 {
        self.p.bits_precision()
    }

    fn field(&self, name: &str, x: &BoxedUint) -> BoxedUint {
        fit(x, self.precision()).unwrap_or_else(|| panic!("curve parameter {name} is wider than p"))
    }

    /// # Panics
    ///
    /// If `p` or `q` is even, or a parameter is wider than `p`.
    fn curve(&self) -> Curve {
        Curve::new(
            &self.p,
            &self.field("q", &self.q),
            &self.field("a", &self.a),
            &self.field("b", &self.b),
        )
    }

    fn base_point(&self, curve: &Curve) -> Point {
        curve
            .affine(&self.gx, &self.gy)
            .expect("base point must lie on the curve")
    }
}

/// Public key `Q = d·G` as affine `(x, y)`. `d` is reduced modulo `q`.
///
/// # Panics
///
/// If `d ≡ 0 (mod q)` (the result would be the point at infinity) or the curve parameters are
/// malformed.
pub fn public_point(c: &CurveParams, d: &BoxedUint) -> (BoxedUint, BoxedUint) {
    let curve = c.curve();
    let g = c.base_point(&curve);
    let d = curve.fq.reduce(d);
    let q = curve.mul(&g, &d);
    let (x, y) = curve
        .to_affine(&q)
        .expect("private key must be non-zero modulo q");
    ((*x).clone(), (*y).clone())
}

/// `true` if `0 ≤ x, y < p` and `y² ≡ x³ + a·x + b (mod p)`.
pub fn is_on_curve(c: &CurveParams, x: &BoxedUint, y: &BoxedUint) -> bool {
    c.curve().affine(x, y).is_some()
}

/// `true` if `1 ≤ x ≤ q − 1`, i.e. `x` is usable as a private key or nonce as is.
///
/// Constant time in the value of `x`; only its precision may leak.
pub fn is_valid_scalar(c: &CurveParams, x: &BoxedUint) -> bool {
    let Some(x) = fit(x, c.precision()).map(Zeroizing::new) else {
        return false;
    };
    let q = c.field("q", &c.q);
    (!x.is_zero() & x.ct_lt(&q)).to_bool()
}

/// GOST R 34.10 signature with a caller-chosen nonce `k`:
/// `e ← e mod q` (`1` if that is `0`), `r = x(k·G) mod q`, `s = (r·d + k·e) mod q`.
///
/// `k` must lie in `[1, q − 1]`; it is never reduced. Returns `None` if it does not (see
/// [`is_valid_scalar`]), or if `r = 0` or `s = 0`; the caller retries with a new `k`.
pub fn sign_with_k(
    c: &CurveParams,
    d: &BoxedUint,
    e: &BoxedUint,
    k: &BoxedUint,
) -> Option<(BoxedUint, BoxedUint)> {
    let curve = c.curve();
    let g = c.base_point(&curve);
    let fq = &curve.fq;

    if !is_valid_scalar(c, k) {
        return None;
    }
    let k = fq.reduce(k);
    let point = curve.mul(&g, &k);
    let r = fq.reduce(&*curve.affine_x(&point)?);
    if r.is_zero().to_bool() {
        return None;
    }

    let e = digest_scalar(&curve, e);
    let d = fq.element(d);
    let k = fq.element(&k);
    let s = fq.element(&r).mul(&d).add(&k.mul(&e));
    if s.is_zero().to_bool() {
        return None;
    }
    Some(((*r).clone(), (*s.retrieve()).clone()))
}

/// GOST R 34.10 verification of `(r, s)` over digest integer `e` against public key `(qx, qy)`.
///
/// Checks `0 < r, s < q` and that `Q` lies on the curve, then `v = e⁻¹`, `z1 = s·v`,
/// `z2 = −r·v` and accepts iff `x(z1·G + z2·Q) mod q = r`.
pub fn verify(
    c: &CurveParams,
    qx: &BoxedUint,
    qy: &BoxedUint,
    e: &BoxedUint,
    r: &BoxedUint,
    s: &BoxedUint,
) -> bool {
    let curve = c.curve();
    let prec = c.precision();
    let (Some(r), Some(s)) = (fit(r, prec), fit(s, prec)) else {
        return false;
    };
    let q = curve.fq.modulus();
    let in_range = |x: &BoxedUint| !x.is_zero().to_bool() && x < q;
    if !in_range(&r) || !in_range(&s) {
        return false;
    }
    let Some(public) = curve.affine(qx, qy) else {
        return false;
    };
    let g = c.base_point(&curve);

    let fq = &curve.fq;
    let Some(v) = digest_scalar(&curve, e).invert() else {
        return false;
    };
    let z1 = fq.element(&s).mul(&v).retrieve();
    let z2 = fq.element(&r).mul(&v).neg().retrieve();
    let sum = curve.add(&curve.mul(&g, &z1), &curve.mul(&public, &z2));
    match curve.affine_x(&sum) {
        Some(x) => *fq.reduce(&x) == r,
        None => false,
    }
}

/// `e mod q`, replaced by `1` when it is `0`.
fn digest_scalar(curve: &Curve, e: &BoxedUint) -> crate::point::Fe {
    let fq = &curve.fq;
    let e: Zeroizing<BoxedUint> = fq.reduce(e);
    let one = BoxedUint::one_with_precision(e.bits_precision());
    fq.element(&e.ct_select(&one, e.is_zero()))
}
