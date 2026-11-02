//! Independent primitive vectors, not a claim of KZ CMS interoperability.
//! RFC 7836 Appendix B examples 7, 8, 11; §§3, 4.3, 4.6 and verified
//! errata 6197–6201. All RFC byte strings below are in the printed order.
//! New APIs are proposed in task-08-proposed-api.md; no production stubs.

use oncl_gost::agreement::{AgreementError, AgreementProfile, derive_kek};
use oncl_gost::wrap::{WrapError, WrapProfile, unwrap_cek, wrap_cek};
use oncl_gost::{CurveId, GostError, SigningKey, VerifyingKey};

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2, "literal fixture width");
    std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
}

// RFC 7836 §3 byte representation: scalars/UKM are little-endian.
const PRIVATE_A_LE: &str = concat!(
    "c990ecd972fce84ec4db022778f50fca",
    "c726f46708384b8d458304962d7147f8",
    "c2db41cef22c90b102f2968404f9b9be",
    "6d47c79692d81826b32b8daca43cb667"
);
const PRIVATE_B_LE: &str = concat!(
    "48c859f7b6f11585887cc05ec6ef1390",
    "cfea739b1a18c0d4662293ef63b79e3b",
    "8014070b44918590b4b996acfea4edfb",
    "bbcccc8c06edd8bf5bda92a51392d0db"
);
const PUBLIC_A_XY_LE: &str = concat!(
    "aab0eda4abff21208d18799fb9a85566",
    "54ba783070eba10cb9abb253ec56dcf5",
    "d3ccba6192e464e6e5bcb6dea137792f",
    "2431f6c897eb1b3c0cc14327b1adc0a7",
    "914613a3074e363aedb204d38d356397",
    "1bd8758e878c9db11403721b48002d38",
    "461f92472d40ea92f9958c0ffa4c9375",
    "6401b97f89fdbe0b5e46e4a4631cdb5a"
);
const PUBLIC_B_XY_LE: &str = concat!(
    "192fe183b9713a077253c72c8735de2e",
    "a42a3dbc66ea317838b65fa32523cd5e",
    "fca974eda7c863f4954d1147f1f2b25c",
    "395fce1c129175e876d132e94ed5a651",
    "04883b414c9b592ec4dc84826f07d0b6",
    "d9006dda176ce48c391e3f97d102e03b",
    "b598bf132a228a45f7201aba08fc524a",
    "2d77e43a362ab022ad4028f75bde3b79"
);

fn private_key(little_endian: &str) -> SigningKey {
    // Only public standard test scalars, never a production export seam.
    let mut scalar_be = bytes::<64>(little_endian);
    scalar_be.reverse();
    SigningKey::from_scalar_be(CurveId::Tc26_512A, &scalar_be).unwrap()
}

mod agreement {
    use super::*;

    #[test]
    fn vko_known_vector() {
        // Catches wrong UKM endian, coordinate endian/order, hash selection,
        // hash truncation, or a wrong scalar multiplication; not a round trip.
        let a = private_key(PRIVATE_A_LE);
        let b = private_key(PRIVATE_B_LE);
        let public_a = bytes::<128>(PUBLIC_A_XY_LE);
        let public_b = bytes::<128>(PUBLIC_B_XY_LE);
        assert_eq!(a.verifying_key().to_kz_bytes(), public_a);
        assert_eq!(b.verifying_key().to_kz_bytes(), public_b);
        let peer_a = VerifyingKey::from_kz_bytes(CurveId::Tc26_512A, &public_a).unwrap();
        let peer_b = VerifyingKey::from_kz_bytes(CurveId::Tc26_512A, &public_b).unwrap();
        let ukm = bytes::<8>("1d80603c8544c727");
        for (profile, expected) in [
            (
                AgreementProfile::Rfc7836Tc26_512AStreebog256,
                "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221",
            ),
            (
                AgreementProfile::Rfc7836Tc26_512AStreebog512,
                concat!(
                    "79f002a96940ce7bde3259a52e015297",
                    "adaad84597a0d205b50e3e1719f97bfa",
                    "7ee1d2661fa9979a5aa235b558a7e6d9",
                    "f88f982dd63fc35a8ec0dd5e242d3bdf"
                ),
            ),
        ] {
            let expected: Vec<u8> = expected
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(
                derive_kek(profile, &a, &peer_b, &ukm).unwrap().as_bytes(),
                expected
            );
            assert_eq!(
                derive_kek(profile, &b, &peer_a, &ukm).unwrap().as_bytes(),
                expected
            );
        }
    }

    #[test]
    fn invalid_ukm_and_identity_shared_point_rejected() {
        // RFC 7836 §§4.3.1/4.3.2: explicit nonzero UKM, at most 512 bits.
        // Erratum 6197: UKM=q is nonzero but gives the identity; never hash it.
        let a = private_key(PRIVATE_A_LE);
        let peer =
            VerifyingKey::from_kz_bytes(CurveId::Tc26_512A, &bytes::<128>(PUBLIC_B_XY_LE)).unwrap();
        for profile in [
            AgreementProfile::Rfc7836Tc26_512AStreebog256,
            AgreementProfile::Rfc7836Tc26_512AStreebog512,
        ] {
            for invalid in [&[][..], &[0_u8; 8][..], &[1_u8; 65][..]] {
                assert!(matches!(
                    derive_kek(profile, &a, &peer, invalid),
                    Err(AgreementError::InvalidUkm)
                ));
            }
            let mut order_le = bytes::<64>(concat!(
                "ffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff",
                "27e69532f48d89116ff22b8d4e056060",
                "9b4b38abfad2b85dcacdb1411f10b275"
            ));
            order_le.reverse();
            assert!(matches!(
                derive_kek(profile, &a, &peer, &order_le),
                Err(AgreementError::InvalidSharedPoint)
            ));
        }
    }

    #[test]
    fn curve_mismatch_rejected_before_agreement() {
        let a = private_key(PRIVATE_A_LE);
        let other = SigningKey::from_scalar_be(CurveId::Pkigovkz2004A, &[2]).unwrap();
        for profile in [
            AgreementProfile::Rfc7836Tc26_512AStreebog256,
            AgreementProfile::Rfc7836Tc26_512AStreebog512,
        ] {
            assert!(matches!(
                derive_kek(profile, &a, other.verifying_key(), &[1]),
                Err(AgreementError::CurveMismatch)
            ));
            assert!(matches!(
                derive_kek(profile, &other, a.verifying_key(), &[1]),
                Err(AgreementError::CurveMismatch)
            ));
        }
    }

    #[test]
    fn invalid_off_curve_zero_peer_refused_at_key_boundary() {
        // The derive API accepts only validated VerifyingKey, not raw points.
        for curve in [CurveId::Pkigovkz2004A, CurveId::Tc26_512A] {
            let width = 2 * curve.coord_len();
            assert_eq!(
                VerifyingKey::from_kz_bytes(curve, &vec![0; width - 1]),
                Err(GostError::InvalidLength)
            );
            assert_eq!(
                VerifyingKey::from_kz_bytes(curve, &vec![0; width]),
                Err(GostError::InvalidPoint)
            );
            let mut off_curve = vec![0; width];
            off_curve[0] = 1; // (1,0), not on either supported curve.
            assert_eq!(
                VerifyingKey::from_kz_bytes(curve, &off_curve),
                Err(GostError::InvalidPoint)
            );
            let mut noncanonical = vec![0; width];
            let p_le = curve.params().p.to_le_bytes();
            noncanonical[..curve.coord_len()].copy_from_slice(&p_le);
            assert_eq!(
                VerifyingKey::from_kz_bytes(curve, &noncanonical),
                Err(GostError::InvalidPoint)
            );
        }
    }
}

mod wrap {
    use super::*;

    const PROFILE: WrapProfile = WrapProfile::Rfc7836Tc26Z;
    const KEK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const CEK: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const WRAPPED: &str = concat!(
        "af21434145656378",
        "d15547f8ee85121bc87d4b1027d26027",
        "ecc071bba6e72f3fec6f620f56834c5a",
        "be33f052"
    );

    #[test]
    fn rfc7836_wrap_known_vector() {
        // Independent exact expected ciphertext AND MAC, Appendix B example 11.
        // Catches substituting RFC4357 plain/CryptoPro wrap for §4.6 KDF wrap.
        let wrapped = wrap_cek(
            PROFILE,
            &bytes::<32>(KEK),
            &bytes::<32>(CEK),
            &bytes::<8>("af21434145656378"),
        )
        .unwrap();
        assert_eq!(wrapped.as_bytes(), bytes::<44>(WRAPPED));
    }

    #[test]
    fn rfc7836_external_vector_unwrap() {
        // Input is the published external bytes, NOT output of our wrap.
        let cek = unwrap_cek(PROFILE, &bytes::<32>(KEK), &bytes::<44>(WRAPPED)).unwrap();
        assert_eq!(&*cek, &bytes::<32>(CEK));
    }

    #[test]
    fn wrong_ukm_and_mac_rejected() {
        // Seed (UKM-like input), every ciphertext byte and every MAC byte.
        // Never return a tentative CEK after a failed authentication check.
        for index in 0..44 {
            let mut corrupt = bytes::<44>(WRAPPED);
            corrupt[index] ^= 1;
            assert!(
                matches!(
                    unwrap_cek(PROFILE, &bytes::<32>(KEK), &corrupt),
                    Err(WrapError::AuthenticationFailed)
                ),
                "changed wrapped byte {index}"
            );
        }
        let mut wrong_key = bytes::<32>(KEK);
        wrong_key[0] ^= 1;
        assert!(matches!(
            unwrap_cek(PROFILE, &wrong_key, &bytes::<44>(WRAPPED)),
            Err(WrapError::AuthenticationFailed)
        ));
    }

    #[test]
    fn seed_and_wrapped_length_boundaries() {
        let kek = bytes::<32>(KEK);
        let cek = bytes::<32>(CEK);
        for len in [0, 7, 17] {
            assert!(matches!(
                wrap_cek(PROFILE, &kek, &cek, &vec![1; len]),
                Err(WrapError::InvalidSeedLength)
            ));
        }
        for len in [0, 35, 43, 53] {
            assert!(matches!(
                unwrap_cek(PROFILE, &kek, &vec![1; len]),
                Err(WrapError::InvalidWrappedLength)
            ));
        }
        // Supplemental length handling only, not independent proof of crypto.
        for len in 8..=16 {
            let wrapped = wrap_cek(PROFILE, &kek, &cek, &vec![1; len]).unwrap();
            assert_eq!(wrapped.as_bytes().len(), len + 32 + 4);
            assert_eq!(
                &*unwrap_cek(PROFILE, &kek, wrapped.as_bytes()).unwrap(),
                &cek
            );
        }
    }
}
