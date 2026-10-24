//! Modular arithmetic, projective points and the constant-time Montgomery ladder.
//!
//! Every value here may be secret-dependent, so all intermediates live in [`Fe`] (which zeroizes
//! on drop) or [`Zeroizing`] and selection between them goes through [`CtSelect`].

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Choice, CtSelect, NonZero, Odd, Resize};
use zeroize::{Zeroize, Zeroizing};

/// Odd modulus (`p` or `q`) together with its Montgomery parameters.
pub(crate) struct Modulus {
    params: BoxedMontyParams,
    nz: NonZero<BoxedUint>,
}

impl Modulus {
    /// `m` must be odd and carried at the curve precision.
    pub(crate) fn new(m: &BoxedUint) -> Self {
        let odd = Odd::new(m.clone())
            .into_option()
            .expect("curve modulus must be odd");
        let nz = NonZero::new(m.clone())
            .into_option()
            .expect("odd modulus is non-zero");
        Self {
            params: BoxedMontyParams::new(odd),
            nz,
        }
    }

    pub(crate) fn modulus(&self) -> &BoxedUint {
        self.nz.as_ref()
    }

    pub(crate) fn bits_precision(&self) -> u32 {
        self.nz.as_ref().bits_precision()
    }

    /// `x mod m` at the modulus precision, in constant time for any input precision.
    pub(crate) fn reduce(&self, x: &BoxedUint) -> Zeroizing<BoxedUint> {
        let wide;
        let x = if x.bits_precision() < self.bits_precision() {
            wide = Zeroizing::new(x.resize_unchecked(self.bits_precision()));
            &*wide
        } else {
            x
        };
        let (mut quotient, remainder) = x.div_rem(&self.nz);
        quotient.zeroize();
        Zeroizing::new(remainder)
    }

    /// `x mod m` as a field element.
    pub(crate) fn element(&self, x: &BoxedUint) -> Fe {
        let reduced = self.reduce(x);
        Fe(BoxedMontyForm::new((*reduced).clone(), &self.params))
    }

    pub(crate) fn zero(&self) -> Fe {
        Fe(BoxedMontyForm::zero(&self.params))
    }

    pub(crate) fn one(&self) -> Fe {
        Fe(BoxedMontyForm::one(&self.params))
    }
}

/// Residue modulo `p` or `q` in Montgomery form, zeroized on drop.
#[derive(Clone)]
pub(crate) struct Fe(BoxedMontyForm);

impl Drop for Fe {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl CtSelect for Fe {
    fn ct_select(&self, other: &Self, choice: Choice) -> Self {
        Fe(self.0.ct_select(&other.0, choice))
    }
}

impl Fe {
    pub(crate) fn add(&self, rhs: &Fe) -> Fe {
        Fe(self.0.add(&rhs.0))
    }

    pub(crate) fn sub(&self, rhs: &Fe) -> Fe {
        Fe(self.0.sub(&rhs.0))
    }

    pub(crate) fn mul(&self, rhs: &Fe) -> Fe {
        Fe(self.0.mul(&rhs.0))
    }

    pub(crate) fn square(&self) -> Fe {
        Fe(self.0.square())
    }

    pub(crate) fn neg(&self) -> Fe {
        Fe(self.0.neg())
    }

    /// Multiplicative inverse; `None` only for zero (the moduli are prime).
    pub(crate) fn invert(&self) -> Option<Fe> {
        self.0.invert().into_option().map(Fe)
    }

    pub(crate) fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    /// Canonical integer in `[0, m)`.
    pub(crate) fn retrieve(&self) -> Zeroizing<BoxedUint> {
        Zeroizing::new(self.0.retrieve())
    }
}

/// Curve `y² = x³ + a·x + b` over `F_p` with the constants used by the addition formulas.
pub(crate) struct Curve {
    pub(crate) fp: Modulus,
    pub(crate) fq: Modulus,
    a: Fe,
    b3: Fe,
    b: Fe,
}

impl Curve {
    /// All inputs must be carried at the precision of `p`.
    pub(crate) fn new(p: &BoxedUint, q: &BoxedUint, a: &BoxedUint, b: &BoxedUint) -> Self {
        let fp = Modulus::new(p);
        let fq = Modulus::new(q);
        let a = fp.element(a);
        let b = fp.element(b);
        let b3 = b.add(&b).add(&b);
        Self { fp, fq, a, b3, b }
    }

    /// Affine `(x, y)` as a projective point, or `None` unless `0 ≤ x, y < p` and the curve
    /// equation holds. Inputs are public.
    pub(crate) fn affine(&self, x: &BoxedUint, y: &BoxedUint) -> Option<Point> {
        let prec = self.fp.bits_precision();
        let (x, y) = (fit(x, prec)?, fit(y, prec)?);
        let p = self.fp.modulus();
        if x >= *p || y >= *p {
            return None;
        }
        let (x, y) = (self.fp.element(&x), self.fp.element(&y));
        let lhs = y.square();
        let rhs = x.square().add(&self.a).mul(&x).add(&self.b);
        if lhs.retrieve() != rhs.retrieve() {
            return None;
        }
        Some(Point {
            x,
            y,
            z: self.fp.one(),
        })
    }

    pub(crate) fn identity(&self) -> Point {
        Point {
            x: self.fp.zero(),
            y: self.fp.one(),
            z: self.fp.zero(),
        }
    }

    /// `P + Q` by the complete projective addition of Renes–Costello–Batina 2015, Algorithm 1
    /// (arbitrary `a`). Exception-free on curves without points of order two, doubling and the
    /// identity included, so the ladder never branches.
    pub(crate) fn add(&self, p: &Point, q: &Point) -> Point {
        let (x1, y1, z1) = (&p.x, &p.y, &p.z);
        let (x2, y2, z2) = (&q.x, &q.y, &q.z);
        let (a, b3) = (&self.a, &self.b3);

        let mut t0 = x1.mul(x2); // 1
        let mut t1 = y1.mul(y2); // 2
        let mut t2 = z1.mul(z2); // 3
        let mut t3 = x1.add(y1); // 4
        let mut t4 = x2.add(y2); // 5
        t3 = t3.mul(&t4); // 6
        t4 = t0.add(&t1); // 7
        t3 = t3.sub(&t4); // 8
        t4 = x1.add(z1); // 9
        let mut t5 = x2.add(z2); // 10
        t4 = t4.mul(&t5); // 11
        t5 = t0.add(&t2); // 12
        t4 = t4.sub(&t5); // 13
        t5 = y1.add(z1); // 14
        let mut x3 = y2.add(z2); // 15
        t5 = t5.mul(&x3); // 16
        x3 = t1.add(&t2); // 17
        t5 = t5.sub(&x3); // 18
        let mut z3 = a.mul(&t4); // 19
        x3 = b3.mul(&t2); // 20
        z3 = x3.add(&z3); // 21
        x3 = t1.sub(&z3); // 22
        z3 = t1.add(&z3); // 23
        let mut y3 = x3.mul(&z3); // 24
        t1 = t0.add(&t0); // 25
        t1 = t1.add(&t0); // 26
        t2 = a.mul(&t2); // 27
        t4 = b3.mul(&t4); // 28
        t1 = t1.add(&t2); // 29
        t2 = t0.sub(&t2); // 30
        t2 = a.mul(&t2); // 31
        t4 = t4.add(&t2); // 32
        t0 = t1.mul(&t4); // 33
        y3 = y3.add(&t0); // 34
        t0 = t5.mul(&t4); // 35
        x3 = x3.mul(&t3); // 36
        x3 = x3.sub(&t0); // 37
        t0 = t3.mul(&t1); // 38
        z3 = z3.mul(&t5); // 39
        z3 = z3.add(&t0); // 40

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `k·P` by a Montgomery ladder over exactly `bits` iterations (the bit length of `q`):
    /// the sequence of field operations does not depend on `k`.
    pub(crate) fn mul(&self, point: &Point, k: &BoxedUint) -> Point {
        let bits = self.fq.modulus().bits_vartime();
        let mut r0 = self.identity();
        let mut r1 = point.clone();
        for i in (0..bits).rev() {
            let bit = k.bit(i);
            r0.ct_swap(&mut r1, bit);
            r1 = self.add(&r0, &r1);
            r0 = self.add(&r0, &r0);
            r0.ct_swap(&mut r1, bit);
        }
        r0
    }

    /// Affine `x` of the point; `None` for the identity.
    pub(crate) fn affine_x(&self, point: &Point) -> Option<Zeroizing<BoxedUint>> {
        let z_inv = point.z.invert()?;
        Some(point.x.mul(&z_inv).retrieve())
    }

    /// Affine `(x, y)` of the point; `None` for the identity.
    pub(crate) fn to_affine(
        &self,
        point: &Point,
    ) -> Option<(Zeroizing<BoxedUint>, Zeroizing<BoxedUint>)> {
        let z_inv = point.z.invert()?;
        Some((
            point.x.mul(&z_inv).retrieve(),
            point.y.mul(&z_inv).retrieve(),
        ))
    }
}

/// Projective point `(X : Y : Z)` with `x = X/Z`, `y = Y/Z`; the identity is `(0 : 1 : 0)`.
#[derive(Clone)]
pub(crate) struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl CtSelect for Point {
    fn ct_select(&self, other: &Self, choice: Choice) -> Self {
        Point {
            x: self.x.ct_select(&other.x, choice),
            y: self.y.ct_select(&other.y, choice),
            z: self.z.ct_select(&other.z, choice),
        }
    }
}

/// Value re-carried at precision `prec`; `None` if it does not fit.
pub(crate) fn fit(x: &BoxedUint, prec: u32) -> Option<BoxedUint> {
    x.try_resize(prec)
}
