//! KZ conventions on top of the GOST arithmetic: hashes, curves, key and signature encodings,
//! cross-checked against the real NCA CA certificates in `fixtures/nca`.

use crypto_bigint::BoxedUint;
use oncl_gost::hazmat;
use oncl_gost::{CurveId, GostAlg, GostError, SigningKey, VerifyingKey, gost34311, streebog512};
use x509_cert::Certificate;
use x509_cert::der::asn1::{ObjectIdentifier, OctetString};
use x509_cert::der::{Decode, Encode};

const CURVES: [CurveId; 2] = [CurveId::Pkigovkz2004A, CurveId::Tc26_512A];

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn alg_for(curve: CurveId) -> GostAlg {
    match curve {
        CurveId::Pkigovkz2004A => GostAlg::Gost34310_2004,
        CurveId::Tc26_512A => GostAlg::Gost3410_2015_512,
    }
}

/// A key with a fixed, valid scalar `0x0102…` of curve width.
fn test_key(curve: CurveId) -> SigningKey {
    let d: Vec<u8> = (1..=curve.coord_len() as u8).collect();
    SigningKey::from_scalar_be(curve, &d).unwrap()
}

/// Big-endian bytes of `q`.
fn order_be(curve: CurveId) -> Vec<u8> {
    curve.params().q.to_be_bytes().to_vec()
}

#[test]
fn gost34311_test_paramset_vectors() {
    assert_eq!(
        hex(gost34311(b"This is message, length=32 bytes")),
        "b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa"
    );
    assert_eq!(
        hex(gost34311(b"")),
        "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d"
    );
}

#[test]
fn streebog512_empty() {
    assert!(hex(streebog512(b"")).starts_with("8e945da2"));
}

#[test]
fn alg_hash_matches_free_functions() {
    assert_eq!(
        GostAlg::Gost34310_2004.hash(b"abc"),
        gost34311(b"abc").to_vec()
    );
    assert_eq!(
        GostAlg::Gost3410_2015_512.hash(b"abc"),
        streebog512(b"abc").to_vec()
    );
}

#[test]
fn curve_and_alg_tables() {
    assert_eq!(CurveId::Pkigovkz2004A.coord_len(), 32);
    assert_eq!(CurveId::Tc26_512A.coord_len(), 64);
    assert_eq!(CurveId::Pkigovkz2004A.curve_oid(), "1.2.398.3.10.1.1.1.1.1");
    assert_eq!(CurveId::Tc26_512A.curve_oid(), "1.2.398.3.10.1.1.2.2.1");
    assert_eq!(
        CurveId::Pkigovkz2004A.digest_param_oid(),
        "1.2.398.3.10.1.3.1.1.0"
    );
    assert_eq!(CurveId::Tc26_512A.digest_param_oid(), "1.2.398.3.10.1.3.3");
    assert_eq!(CurveId::Pkigovkz2004A.key_oid(), "1.2.398.3.10.1.1.1.1");
    assert_eq!(CurveId::Tc26_512A.key_oid(), "1.2.398.3.10.1.1.2.2");
    for curve in CURVES {
        assert_eq!(CurveId::from_curve_oid(curve.curve_oid()), Some(curve));
        assert_eq!(alg_for(curve).curve(), curve);
    }
    assert_eq!(CurveId::from_curve_oid("1.2.643.2.2.35.1"), None);

    assert_eq!(
        GostAlg::Gost34310_2004.signature_oid(),
        "1.2.398.3.10.1.1.1.2"
    );
    assert_eq!(
        GostAlg::Gost3410_2015_512.signature_oid(),
        "1.2.398.3.10.1.1.2.3.2"
    );
    assert_eq!(GostAlg::Gost34310_2004.digest_oid(), "1.2.398.3.10.1.3.1");
    assert_eq!(
        GostAlg::Gost3410_2015_512.digest_oid(),
        "1.2.398.3.10.1.3.3"
    );
}

/// Raw `tbsCertificate` TLV of a DER certificate (no re-encoding).
fn tbs_der(cert_der: &[u8]) -> &[u8] {
    // Returns (header length, content length) of the TLV at the start of `b`.
    fn header(b: &[u8]) -> (usize, usize) {
        assert_eq!(b[0], 0x30, "expected a SEQUENCE");
        match b[1] {
            n @ 0..=0x7f => (2, n as usize),
            0x81 => (3, b[2] as usize),
            0x82 => (4, (b[2] as usize) << 8 | b[3] as usize),
            0x83 => (
                5,
                (b[2] as usize) << 16 | (b[3] as usize) << 8 | b[4] as usize,
            ),
            other => panic!("unsupported DER length form {other:#x}"),
        }
    }
    let (outer, _) = header(cert_der);
    let inner = &cert_der[outer..];
    let (h, len) = header(inner);
    &inner[..h + len]
}

#[test]
fn nca_gost_certificates_verify_by_issuer() {
    let mut certs = Vec::new();
    for dir in ["nca/prod", "nca/test"] {
        let path = oncl_testkit::fixture(dir);
        for entry in std::fs::read_dir(&path).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "der") {
                let der = oncl_testkit::read(&path);
                let cert = Certificate::from_der(&der).unwrap();
                certs.push((path, der, cert));
            }
        }
    }
    assert_eq!(certs.len(), 16, "all NCA CA certificates are parsed");

    let mut verified_gost_count = 0;
    for (path, der, cert) in &certs {
        let sig_oid = cert.signature_algorithm().oid.to_string();
        let Some(alg) = [GostAlg::Gost34310_2004, GostAlg::Gost3410_2015_512]
            .into_iter()
            .find(|a| a.signature_oid() == sig_oid)
        else {
            continue;
        };
        let issuer = certs
            .iter()
            .map(|(_, _, c)| c)
            .find(|c| c.tbs_certificate().subject() == cert.tbs_certificate().issuer())
            .unwrap_or_else(|| panic!("issuer of {} not found", path.display()));

        let spki = issuer.tbs_certificate().subject_public_key_info();
        assert_eq!(spki.algorithm.oid.to_string(), alg.curve().key_oid());
        let params: Vec<ObjectIdentifier> = spki
            .algorithm
            .parameters
            .as_ref()
            .expect("GOST key parameters")
            .decode_as()
            .unwrap();
        let curve = CurveId::from_curve_oid(&params[0].to_string()).unwrap();
        assert_eq!(curve, alg.curve(), "{}", path.display());
        assert_eq!(params[1].to_string(), curve.digest_param_oid());

        let xy = OctetString::from_der(spki.subject_public_key.raw_bytes()).unwrap();
        let key = VerifyingKey::from_kz_bytes(curve, xy.as_bytes()).unwrap();
        assert_eq!(key.to_kz_bytes(), xy.as_bytes(), "KZ key round-trip");

        let tbs = tbs_der(der);
        assert_eq!(tbs, cert.tbs_certificate().to_der().unwrap().as_slice());
        let digest = alg.hash(tbs);
        let sig = cert.signature().raw_bytes();
        key.verify_digest(&digest, sig)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));

        let mut tampered = digest.clone();
        tampered[0] ^= 1;
        assert_eq!(
            key.verify_digest(&tampered, sig),
            Err(GostError::BadSignature)
        );

        // The fully reversed buffer is the standard `s_BE ‖ r_BE`: only 34.310 accepts it.
        let standard: Vec<u8> = sig.iter().rev().copied().collect();
        let expected = match alg {
            GostAlg::Gost34310_2004 => Ok(()),
            GostAlg::Gost3410_2015_512 => Err(GostError::BadSignature),
        };
        assert_eq!(key.verify_digest(&digest, &standard), expected);
        verified_gost_count += 1;
    }
    assert_eq!(verified_gost_count, 9);
}

#[test]
fn sign_then_verify_both_curves() {
    for curve in CURVES {
        let mut d = vec![0u8; curve.coord_len()];
        getrandom::fill(&mut d).unwrap();
        d[0] &= 0x7f; // below q for both curves
        let key = SigningKey::from_scalar_be(curve, &d).unwrap();
        assert_eq!(key.curve(), curve);
        let vk = key.verifying_key();

        let digest = alg_for(curve).hash(b"OpenNCALayer");
        let sig = key.sign_digest(&digest);
        assert_eq!(sig.len(), 2 * curve.coord_len());
        assert_eq!(vk.verify_digest(&digest, &sig), Ok(()));
        assert_ne!(sig, key.sign_digest(&digest), "random nonce per signature");

        let mut other = digest.clone();
        other[5] ^= 0x40;
        assert_eq!(vk.verify_digest(&other, &sig), Err(GostError::BadSignature));
        assert_eq!(
            vk.verify_digest(&digest, &sig[1..]),
            Err(GostError::InvalidLength)
        );
    }
}

#[test]
fn sign_with_k_is_deterministic_and_kz_encoded() {
    for curve in CURVES {
        let key = test_key(curve);
        let n = curve.coord_len();
        let digest = alg_for(curve).hash(b"fixed k");
        let k: Vec<u8> = (0..n)
            .map(|i| ((i as u8).wrapping_mul(7) | 1) & 0x7f)
            .collect();
        let sig = key.sign_digest_with_k(&digest, &k).unwrap();
        assert_eq!(sig, key.sign_digest_with_k(&digest, &k).unwrap());

        // Same signature through hazmat: e = digest read little-endian, output r_LE ‖ s_LE.
        let prec = curve.params().p.bits_precision();
        let d: Vec<u8> = (1..=n as u8).collect();
        let (r, s) = hazmat::sign_with_k(
            curve.params(),
            &BoxedUint::from_be_slice(&d, prec).unwrap(),
            &BoxedUint::from_le_slice(&digest, (digest.len() * 8) as u32).unwrap(),
            &BoxedUint::from_be_slice(&k, prec).unwrap(),
        )
        .unwrap();
        let mut expected = r.to_le_bytes()[..n].to_vec();
        expected.extend_from_slice(&s.to_le_bytes()[..n]);
        assert_eq!(sig, expected);
        assert_eq!(key.verifying_key().verify_digest(&digest, &sig), Ok(()));
    }
}

#[test]
fn nonce_outside_one_to_q_minus_one_is_rejected() {
    for curve in CURVES {
        let key = test_key(curve);
        let digest = alg_for(curve).hash(b"k range");
        let q = order_be(curve);
        let zero = vec![0u8; curve.coord_len()];
        let mut q_plus_one = q.clone();
        *q_plus_one.last_mut().unwrap() += 1; // q is odd: no carry
        for bad in [&zero[..], &q[..], &q_plus_one[..], &[0xff; 65][..], &[][..]] {
            assert_eq!(
                key.sign_digest_with_k(&digest, bad),
                Err(GostError::InvalidScalar),
                "k = {}",
                hex(bad)
            );
        }
        let mut q_minus_one = q.clone();
        *q_minus_one.last_mut().unwrap() -= 1;
        for good in [&[1u8][..], &q_minus_one[..]] {
            let sig = key.sign_digest_with_k(&digest, good).unwrap();
            assert_eq!(key.verifying_key().verify_digest(&digest, &sig), Ok(()));
        }
    }
}

#[test]
fn hazmat_sign_with_k_rejects_out_of_range_nonce() {
    for curve in CURVES {
        let c = curve.params();
        let prec = c.p.bits_precision();
        let d = BoxedUint::from_be_slice(&[7], prec).unwrap();
        let e = BoxedUint::from_be_slice(&[9], prec).unwrap();
        let one = BoxedUint::one_with_precision(prec);
        let q_plus_one = c.q.wrapping_add(&one);
        assert_eq!(hazmat::sign_with_k(c, &d, &e, &c.q), None, "k = q");
        assert_eq!(
            hazmat::sign_with_k(c, &d, &e, &q_plus_one),
            None,
            "k = q + 1"
        );
        assert!(hazmat::sign_with_k(c, &d, &e, &one).is_some(), "k = 1");
    }
}

#[test]
fn private_scalar_outside_one_to_q_minus_one_is_rejected() {
    for curve in CURVES {
        let q = order_be(curve);
        let mut q_plus_one = q.clone();
        *q_plus_one.last_mut().unwrap() += 1;
        let zero = vec![0u8; curve.coord_len() + 3];
        let too_wide = [0xffu8; 65];
        for bad in [&[][..], &zero[..], &q[..], &q_plus_one[..], &too_wide[..]] {
            assert_eq!(
                SigningKey::from_scalar_be(curve, bad).err(),
                Some(GostError::InvalidScalar),
                "d = {}",
                hex(bad)
            );
        }
        // Leading zero bytes (e.g. a DER INTEGER sign byte) are fine.
        let mut padded = vec![0u8];
        padded.extend((1..=curve.coord_len() as u8).collect::<Vec<_>>());
        let key = SigningKey::from_scalar_be(curve, &padded).unwrap();
        assert_eq!(key.verifying_key(), test_key(curve).verifying_key());
        let mut q_minus_one = q;
        *q_minus_one.last_mut().unwrap() -= 1;
        assert!(SigningKey::from_scalar_be(curve, &q_minus_one).is_ok());
    }
}

#[test]
fn verifying_key_rejects_bad_encodings() {
    for curve in CURVES {
        let n = curve.coord_len();
        let good = test_key(curve).verifying_key().to_kz_bytes();
        assert_eq!(
            VerifyingKey::from_kz_bytes(curve, &good[1..]).err(),
            Some(GostError::InvalidLength)
        );
        let mut off_curve = good.clone();
        off_curve[n] ^= 1; // flip the lowest bit of y
        assert_eq!(
            VerifyingKey::from_kz_bytes(curve, &off_curve).err(),
            Some(GostError::InvalidPoint)
        );
        let other = match curve {
            CurveId::Pkigovkz2004A => CurveId::Tc26_512A,
            CurveId::Tc26_512A => CurveId::Pkigovkz2004A,
        };
        assert!(VerifyingKey::from_kz_bytes(other, &good).is_err());
        assert_eq!(
            VerifyingKey::from_kz_bytes(curve, &vec![0u8; 2 * n]).err(),
            Some(GostError::InvalidPoint)
        );
    }
}

#[test]
fn accepts_big_endian_s_r_only_for_2004() {
    for curve in CURVES {
        let key = test_key(curve);
        let n = curve.coord_len();
        let prec = curve.params().p.bits_precision();
        let digest = alg_for(curve).hash(b"big-endian block");
        let d: Vec<u8> = (1..=n as u8).collect();
        let (r, s) = hazmat::sign_with_k(
            curve.params(),
            &BoxedUint::from_be_slice(&d, prec).unwrap(),
            &BoxedUint::from_le_slice(&digest, (digest.len() * 8) as u32).unwrap(),
            &BoxedUint::from_be_slice(&[0x2a; 16], prec).unwrap(),
        )
        .unwrap();
        let be = |x: &BoxedUint| x.to_be_bytes()[x.to_be_bytes().len() - n..].to_vec();
        let mut standard = be(&s);
        standard.extend(be(&r));

        let result = key.verifying_key().verify_digest(&digest, &standard);
        match curve {
            CurveId::Pkigovkz2004A => assert_eq!(result, Ok(())),
            CurveId::Tc26_512A => assert_eq!(result, Err(GostError::BadSignature)),
        }
    }
}

#[test]
fn kz_encoding_is_fixed_width_for_short_coordinates() {
    for curve in CURVES {
        let n = curve.coord_len();
        let digest = alg_for(curve).hash(b"short coordinate");
        let mut found = false;
        for d in 1u32..5000 {
            let key = SigningKey::from_scalar_be(curve, &d.to_be_bytes()).unwrap();
            let vk = key.verifying_key();
            let xy = vk.to_kz_bytes();
            assert_eq!(xy.len(), 2 * n);
            // x_LE: the most significant byte of x is the last byte of the first half.
            if xy[n - 1] != 0 {
                continue;
            }
            assert_eq!(&VerifyingKey::from_kz_bytes(curve, &xy).unwrap(), vk);
            let sig = key.sign_digest(&digest);
            assert_eq!(vk.verify_digest(&digest, &sig), Ok(()));
            found = true;
            break;
        }
        assert!(found, "no key with a short x coordinate found");
    }
}
