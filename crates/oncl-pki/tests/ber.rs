//! BER → DER shape normalization.

use hex_literal::hex;
use oncl_pki::ber::{BerError, to_der};
use oncl_testkit::{fixture, read};

#[test]
fn indefinite_to_definite() {
    assert_eq!(
        to_der(&hex!("308004030102030000")).unwrap(),
        hex!("30050403010203")
    );
}

#[test]
fn constructed_octets_flattened() {
    assert_eq!(
        to_der(&hex!("24800401aa0401bb0000")).unwrap(),
        hex!("0402aabb")
    );
}

#[test]
fn der_passthrough_identical() {
    let d = read(fixture("nca/prod/rcagost22.der"));
    assert_eq!(to_der(&d).unwrap(), d);
}

#[test]
fn truncated_is_error() {
    assert!(to_der(&hex!("3080040301")).is_err());
}

#[test]
fn all_nca_certificates_pass_through_unchanged() {
    for dir in ["nca/prod", "nca/test"] {
        for entry in std::fs::read_dir(fixture(dir)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "der") {
                let d = read(&path);
                assert_eq!(to_der(&d).unwrap(), d, "{}", path.display());
            }
        }
    }
}

#[test]
fn nested_constructed_octets_inside_indefinite_explicit_tag() {
    // [0] EXPLICIT { OCTET STRING (constructed, nested twice) } as CMS eContent is written.
    let ber = hex!("a080 2480 0401aa 2480 0402bbcc 0000 0000 0000");
    assert_eq!(to_der(&ber).unwrap(), hex!("a005 0403aabbcc"));
}

#[test]
fn constructed_bit_string_flattened_keeps_last_unused_bits() {
    let ber = hex!("2380 030200aa 030204b0 0000");
    assert_eq!(to_der(&ber).unwrap(), hex!("0303 04aab0"));
}

#[test]
fn unused_bits_only_in_last_bit_string_segment() {
    assert!(matches!(
        to_der(&hex!("2380 030204a0 030200bb 0000")),
        Err(BerError::Invalid { .. })
    ));
}

#[test]
fn set_order_is_kept() {
    // Not DER-sorted on purpose: normalization must not reorder (signed attributes).
    let ber = hex!("3180 0201 02 0201 01 0000");
    assert_eq!(to_der(&ber).unwrap(), hex!("3106 020102 020101"));
}

#[test]
fn long_form_lengths_become_minimal() {
    assert_eq!(to_der(&hex!("0481 02 aabb")).unwrap(), hex!("0402aabb"));
    let mut big = vec![0x04, 0x82, 0x01, 0x00];
    big.extend([0x5a; 256]);
    assert_eq!(to_der(&big).unwrap(), big);
}

#[test]
fn high_tag_numbers_are_copied() {
    let ber = hex!("bf8a3b80 0201 05 0000");
    assert_eq!(to_der(&ber).unwrap(), hex!("bf8a3b03 020105"));
}

#[test]
fn malformed_inputs_are_errors() {
    for bad in [
        &hex!("")[..],
        &hex!("0480 00")[..],           // indefinite primitive
        &hex!("3003 020101 00")[..],    // trailing byte
        &hex!("3003 02020101")[..],     // child overruns parent
        &hex!("2480 0201 01 0000")[..], // INTEGER inside constructed OCTET STRING
        &hex!("3080 0000 0000")[..],    // stray end-of-contents (trailing)
        &hex!("30ff")[..],
    ] {
        assert!(to_der(bad).is_err(), "{bad:02x?}");
    }
}

#[test]
fn deep_nesting_is_rejected_without_overflow() {
    let mut ber = Vec::new();
    for _ in 0..10_000 {
        ber.extend([0x30, 0x80]);
    }
    for _ in 0..10_000 {
        ber.extend([0x00, 0x00]);
    }
    assert_eq!(to_der(&ber), Err(BerError::TooDeep));
}
