//! GOST R 34.10-2012 test examples: RFC 7091 §7 (the standard's Appendix A.1, 256 bits)
//! and the standard's Appendix A.2 (512 bits).

use crypto_bigint::BoxedUint;
use oncl_gost::hazmat::{CurveParams, is_on_curve, public_point, sign_with_k, verify};

fn h(hex: &str, bits: u32) -> BoxedUint {
    BoxedUint::from_str_radix_with_precision_vartime(hex, 16, bits).expect("valid test hex")
}

struct Vector {
    bits: u32,
    curve: CurveParams,
    d: &'static str,
    qx: &'static str,
    qy: &'static str,
    e: &'static str,
    k: &'static str,
    r: &'static str,
    s: &'static str,
}

impl Vector {
    fn get(&self, hex: &str) -> BoxedUint {
        h(hex, self.bits)
    }
}

fn a1() -> Vector {
    Vector {
        bits: 256,
        curve: CurveParams::from_hex(
            "8000000000000000000000000000000000000000000000000000000000000431",
            "7",
            "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
            "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
            "2",
            "8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8",
        ),
        d: "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28",
        qx: "7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B",
        qy: "26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA",
        e: "2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5",
        k: "77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3",
        r: "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493",
        s: "1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40",
    }
}

fn a2() -> Vector {
    Vector {
        bits: 512,
        curve: CurveParams::from_hex(
            "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15D\
             F1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373",
            "7",
            "1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC43\
             61834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC",
            "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15D\
             A82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF",
            "24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762\
             FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A",
            "2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C\
             83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E",
        ),
        d: "0BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B1020\
            72E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4",
        qx: "115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD\
             5A515856D13314AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1",
        qy: "37C7C90CD40B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7FB72AFD61\
             EA199441D943FFE7F0C70A2759A3CDB84C114E1F9339FDF27F35ECA93677BEEC",
        e: "3754F3CFACC9E0615C4F4A7C4D8DAB531B09B6F9C170C533A71D147035B0C591\
            7184EE536593F4414339976C647C5D5A407ADEDB1D560C4FC6777D2972075B8C",
        k: "0359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F3658\
            86748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1",
        r: "2F86FA60A081091A23DD795E1E3C689EE512A3C82EE0DCC2643C78EEA8FCACD3\
            5492558486B20F1C9EC197C90699850260C93BCBCD9C5C3317E19344E173AE36",
        s: "1081B394696FFE8E6585E7A9362D26B6325F56778AADBC081C0BFBE933D52FF5\
            823CE288E8C4F362526080DF7F70CE406A6EEB1F56919CB92A9853BDE73E5B4A",
    }
}

fn check_public_key(v: &Vector) {
    assert_eq!(
        public_point(&v.curve, &v.get(v.d)),
        (v.get(v.qx), v.get(v.qy))
    );
}

fn check_signature(v: &Vector) {
    let sig = sign_with_k(&v.curve, &v.get(v.d), &v.get(v.e), &v.get(v.k)).unwrap();
    assert_eq!(sig, (v.get(v.r), v.get(v.s)));
}

fn check_verify_and_tamper(v: &Vector) {
    let (c, qx, qy, e, r, s) = (
        &v.curve,
        v.get(v.qx),
        v.get(v.qy),
        v.get(v.e),
        v.get(v.r),
        v.get(v.s),
    );
    assert!(verify(c, &qx, &qy, &e, &r, &s));
    assert!(!verify(
        c,
        &qx,
        &qy,
        &(e.wrapping_add(BoxedUint::one())),
        &r,
        &s
    ));
    assert!(!verify(
        c,
        &qx,
        &qy,
        &e,
        &BoxedUint::zero_with_precision(v.bits),
        &s
    ));
    assert!(!verify(
        c,
        &qx,
        &qy,
        &e,
        &r,
        &BoxedUint::zero_with_precision(v.bits)
    ));
    assert!(!verify(c, &qx, &qy, &e, &c.q, &s), "r = q is out of range");
    assert!(!verify(c, &qx, &qy, &e, &s, &r), "swapped r and s");
    assert!(!verify(c, &c.gx, &c.gy, &e, &r, &s), "wrong public key");
    let off_curve_y = qy.wrapping_add(BoxedUint::one());
    assert!(
        !verify(c, &qx, &off_curve_y, &e, &r, &s),
        "public key off the curve"
    );
}

#[test]
fn rfc7091_a1_public_key() {
    check_public_key(&a1());
}

#[test]
fn rfc7091_a1_signature() {
    check_signature(&a1());
}

#[test]
fn rfc7091_a1_verify_and_tamper() {
    check_verify_and_tamper(&a1());
}

#[test]
fn rfc7091_a2_public_key() {
    check_public_key(&a2());
}

#[test]
fn rfc7091_a2_signature() {
    check_signature(&a2());
}

#[test]
fn rfc7091_a2_verify_and_tamper() {
    check_verify_and_tamper(&a2());
}

#[test]
fn points_on_curve() {
    for v in [a1(), a2()] {
        let c = &v.curve;
        assert!(is_on_curve(c, &c.gx, &c.gy));
        assert!(is_on_curve(c, &v.get(v.qx), &v.get(v.qy)));
        assert!(!is_on_curve(c, &c.gx, &c.gy.wrapping_add(BoxedUint::one())));
        // Coordinates must be reduced: (gx + p, gy) satisfies the equation mod p but is rejected.
        assert!(!is_on_curve(c, &c.gx.wrapping_add(&c.p), &c.gy));
    }
}

#[test]
fn zero_e_is_treated_as_one() {
    let v = a1();
    let (d, k) = (v.get(v.d), v.get(v.k));
    let zero = BoxedUint::zero_with_precision(v.bits);
    let one = BoxedUint::one_with_precision(v.bits);
    let sig_zero = sign_with_k(&v.curve, &d, &zero, &k).unwrap();
    assert_eq!(sig_zero, sign_with_k(&v.curve, &d, &one, &k).unwrap());
    assert_eq!(
        sig_zero,
        sign_with_k(&v.curve, &d, &v.curve.q, &k).unwrap(),
        "e = q reduces to 0"
    );
    let (qx, qy) = (v.get(v.qx), v.get(v.qy));
    assert!(verify(&v.curve, &qx, &qy, &zero, &sig_zero.0, &sig_zero.1));
}

#[test]
fn zero_k_yields_none() {
    let v = a1();
    let zero = BoxedUint::zero_with_precision(v.bits);
    assert_eq!(sign_with_k(&v.curve, &v.get(v.d), &v.get(v.e), &zero), None);
}

#[test]
fn mixed_input_precision() {
    // A 256-bit curve must accept scalars carried at a wider precision (e.g. a 512-bit e).
    let v = a1();
    let wide = |hex: &str| h(hex, 512);
    let sig = sign_with_k(&v.curve, &wide(v.d), &wide(v.e), &wide(v.k)).unwrap();
    assert_eq!(sig, (v.get(v.r), v.get(v.s)));
    assert!(verify(
        &v.curve,
        &wide(v.qx),
        &wide(v.qy),
        &wide(v.e),
        &wide(v.r),
        &wide(v.s)
    ));
}
