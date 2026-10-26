//! Private and public keys (GOST 34.310-2004, GOST 34.10-2015-512, RSA) and the signature
//! algorithms of the Kazakhstan PKI.

use crate::ber;
use crate::oid;
use der::asn1::{Any, AnyRef, BitString, ObjectIdentifier, OctetStringRef, UintRef};
use der::{Decode, Encode};
use oncl_gost::{CurveId, GostAlg, SigningKey, VerifyingKey};
use pkcs8::PrivateKeyInfoRef;
use ring::signature::{self, UnparsedPublicKey};
use sha1::Digest;
use spki::SubjectPublicKeyInfoOwned;
use std::sync::Arc;
use x509_cert::Certificate;
use zeroize::Zeroizing;

/// Key type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyAlg {
    /// GOST 34.310-2004 on PKIGOVKZ-A.
    Gost2004,
    /// GOST 34.10-2015, 512-bit ParamSetA.
    Gost2015_512,
    /// RSA.
    Rsa,
}

/// Signature algorithm: hash plus key type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigAlg {
    /// GOST 34.311-95 with GOST 34.310-2004.
    Gost2004,
    /// GOST 34.11-2015 (512) with GOST 34.10-2015 (512).
    Gost2015_512,
    /// sha256WithRSAEncryption (PKCS#1 v1.5).
    RsaSha256,
    /// sha1WithRSAEncryption (PKCS#1 v1.5); verification only.
    RsaSha1,
}

impl SigAlg {
    const ALL: [SigAlg; 4] = [
        SigAlg::Gost2004,
        SigAlg::Gost2015_512,
        SigAlg::RsaSha256,
        SigAlg::RsaSha1,
    ];

    /// Algorithm of a certificate / CMS signature algorithm OID.
    pub fn from_signature_oid(oid: &ObjectIdentifier) -> Option<SigAlg> {
        SigAlg::ALL.into_iter().find(|a| a.signature_oid() == *oid)
    }

    /// Signature algorithm OID.
    pub fn signature_oid(self) -> ObjectIdentifier {
        match self {
            SigAlg::Gost2004 => oid::GOST_2004_SIGNATURE,
            SigAlg::Gost2015_512 => oid::GOST_2015_512_SIGNATURE,
            SigAlg::RsaSha256 => oid::SHA256_WITH_RSA,
            SigAlg::RsaSha1 => oid::SHA1_WITH_RSA,
        }
    }

    /// Digest algorithm OID.
    pub fn digest_oid(self) -> ObjectIdentifier {
        match self {
            SigAlg::Gost2004 => oid::GOST_34311,
            SigAlg::Gost2015_512 => oid::STREEBOG_512,
            SigAlg::RsaSha256 => oid::SHA256,
            SigAlg::RsaSha1 => oid::SHA1,
        }
    }

    /// Digest of `data` with this algorithm's hash.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            SigAlg::Gost2004 | SigAlg::Gost2015_512 => {
                self.gost().expect("GOST algorithm").hash(data)
            }
            SigAlg::RsaSha256 => sha2::Sha256::digest(data).to_vec(),
            SigAlg::RsaSha1 => sha1::Sha1::digest(data).to_vec(),
        }
    }

    /// Type of the keys this algorithm works with.
    pub fn key_alg(self) -> KeyAlg {
        match self {
            SigAlg::Gost2004 => KeyAlg::Gost2004,
            SigAlg::Gost2015_512 => KeyAlg::Gost2015_512,
            SigAlg::RsaSha256 | SigAlg::RsaSha1 => KeyAlg::Rsa,
        }
    }

    fn gost(self) -> Option<GostAlg> {
        match self {
            SigAlg::Gost2004 => Some(GostAlg::Gost34310_2004),
            SigAlg::Gost2015_512 => Some(GostAlg::Gost3410_2015_512),
            SigAlg::RsaSha256 | SigAlg::RsaSha1 => None,
        }
    }
}

/// Error of a key operation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The key encoding is invalid.
    #[error("malformed key: {0}")]
    Malformed(String),
    /// The key algorithm (OID or curve) is not supported.
    #[error("unsupported key algorithm {0}")]
    UnknownKeyAlgorithm(String),
    /// The signature algorithm cannot be used with this key.
    #[error("signature algorithm not supported for this key")]
    UnsupportedAlgorithm,
    /// The private key does not belong to the certificate's public key.
    #[error("private key does not match the certificate")]
    KeyMismatch,
    /// The signature does not verify.
    #[error("signature does not verify")]
    BadSignature,
}

fn malformed(e: impl std::fmt::Display) -> KeyError {
    KeyError::Malformed(e.to_string())
}

/// Private key.
#[derive(Clone, Debug)]
pub enum PrivateKey {
    /// GOST key.
    Gost(SigningKey),
    /// RSA key.
    Rsa(Arc<RsaKeyPair>),
}

/// RSA private key: the `ring` key pair and the PKCS#8 it was read from (zeroized on drop).
pub struct RsaKeyPair {
    pair: ring::rsa::KeyPair,
    pkcs8: Zeroizing<Vec<u8>>,
}

impl RsaKeyPair {
    /// The DER `RSAPublicKey`.
    pub fn public_key_der(&self) -> &[u8] {
        self.pair.public().as_ref()
    }
}

impl std::fmt::Debug for RsaKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaKeyPair")
            .field("pair", &self.pair)
            .finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// Private key from a PKCS#8 `PrivateKeyInfo` (BER is accepted).
    ///
    /// For GOST keys the scalar `d` is looked up in every form Kalkan produces: the
    /// `privateKey` octets as a DER INTEGER (big-endian), as raw little-endian or big-endian
    /// bytes, or as a nested OCTET STRING (`04 xx …`, either byte order). With `cert`, the
    /// form whose `d·G` equals the certificate key is taken. Without it: the INTEGER for
    /// GOST 2004; for GOST 2015 the little-endian octets (raw when exactly a coordinate long,
    /// else the nested OCTET STRING). An RSA key given with `cert` must match it too.
    ///
    /// # Errors
    ///
    /// [`KeyError::Malformed`] for invalid encodings or out-of-range scalars,
    /// [`KeyError::UnknownKeyAlgorithm`] for other key types, [`KeyError::KeyMismatch`] if no
    /// candidate matches `cert`.
    pub fn from_pkcs8_der(der: &[u8], cert: Option<&Certificate>) -> Result<PrivateKey, KeyError> {
        let expected = cert
            .map(|c| PublicKey::from_spki(c.tbs_certificate().subject_public_key_info()))
            .transpose()?;
        match expected {
            None => decode_pkcs8(der, Expected::DefaultForm),
            Some(public) => decode_pkcs8(der, Expected::Key(&public)),
        }
    }

    /// Private key from a PKCS#8 `PrivateKeyInfo` whose public key has the key identifier
    /// `key_id` (SHA-1 of the `subjectPublicKey` BIT STRING contents): for a key stored
    /// without a certificate under that `localKeyId`, as Kalkan stores generated keys. Of
    /// the GOST forms (see [`PrivateKey::from_pkcs8_der`]) the one with this identifier is
    /// taken.
    ///
    /// # Errors
    ///
    /// As [`PrivateKey::from_pkcs8_der`]; [`KeyError::KeyMismatch`] if no form has the
    /// identifier.
    pub(crate) fn from_pkcs8_der_with_key_id(
        der: &[u8],
        key_id: &[u8],
    ) -> Result<PrivateKey, KeyError> {
        decode_pkcs8(der, Expected::KeyId(key_id))
    }

    /// Key type.
    pub fn alg(&self) -> KeyAlg {
        match self {
            PrivateKey::Gost(key) => curve_alg(key.curve()),
            PrivateKey::Rsa(_) => KeyAlg::Rsa,
        }
    }

    /// Public half of this key.
    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Gost(key) => PublicKey::Gost(key.verifying_key().clone()),
            PrivateKey::Rsa(key) => PublicKey::Rsa(key.public_key_der().to_vec()),
        }
    }

    /// DER `PrivateKeyInfo` of this key. GOST keys take the forms Kalkan writes (and
    /// [`PrivateKey::from_pkcs8_der`] picks without a certificate): the algorithm is the key
    /// OID with `SEQUENCE { curve OID, digest parameter OID }`, the `privateKey` octets a DER
    /// INTEGER (`d` big-endian) for GOST 2004 and a DER OCTET STRING (`d` little-endian,
    /// coordinate width) for GOST 2015. An RSA key gives back the PKCS#8 it was read from.
    pub fn to_pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        let key = match self {
            PrivateKey::Gost(key) => key,
            PrivateKey::Rsa(key) => return key.pkcs8.clone(),
        };
        let curve = key.curve();
        let d = key.scalar_be();
        let private_key = Zeroizing::new(match curve {
            CurveId::Pkigovkz2004A => UintRef::new(&d)
                .and_then(|int| int.to_der())
                .expect("scalar INTEGER encodes"),
            CurveId::Tc26_512A => {
                let d_le = Zeroizing::new(d.iter().rev().copied().collect::<Vec<u8>>());
                OctetStringRef::new(&d_le)
                    .and_then(|octets| octets.to_der())
                    .expect("scalar OCTET STRING encodes")
            }
        });
        let params = gost_params_der(curve);
        let info = PrivateKeyInfoRef {
            algorithm: spki::AlgorithmIdentifier {
                oid: ObjectIdentifier::new_unwrap(curve.key_oid()),
                parameters: Some(AnyRef::from_der(&params).expect("DER parameters")),
            },
            private_key: OctetStringRef::new(&private_key).expect("privateKey fits DER"),
            public_key: None,
        };
        Zeroizing::new(info.to_der().expect("PrivateKeyInfo encodes"))
    }

    /// Signs `message` (hashed here) with `alg`. GOST signatures use a fresh random nonce and
    /// the KZ encoding `r_LE ‖ s_LE`; RSA signatures are PKCS#1 v1.5.
    ///
    /// # Errors
    ///
    /// [`KeyError::UnsupportedAlgorithm`] if `alg` does not fit the key, and for
    /// [`SigAlg::RsaSha1`].
    ///
    /// # Panics
    ///
    /// If the operating system RNG fails.
    pub fn sign(&self, alg: SigAlg, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        match (self, alg) {
            (PrivateKey::Gost(key), SigAlg::Gost2004 | SigAlg::Gost2015_512)
                if alg.key_alg() == self.alg() =>
            {
                Ok(key.sign_digest(&alg.digest(message)))
            }
            (PrivateKey::Rsa(key), SigAlg::RsaSha256) => {
                let mut sig = vec![0; key.pair.public().modulus_len()];
                key.pair
                    .sign(
                        &signature::RSA_PKCS1_SHA256,
                        &ring::rand::SystemRandom::new(),
                        message,
                        &mut sig,
                    )
                    .expect("RSA signing with a valid key and buffer");
                Ok(sig)
            }
            _ => Err(KeyError::UnsupportedAlgorithm),
        }
    }
}

/// Which key a PKCS#8 decoding looks for.
#[derive(Clone, Copy)]
enum Expected<'a> {
    /// Any; GOST scalars in the default form ([`default_form`]).
    DefaultForm,
    /// This public key.
    Key(&'a PublicKey),
    /// The public key with this key identifier.
    KeyId(&'a [u8]),
}

impl Expected<'_> {
    fn accepts(self, public: &PublicKey) -> bool {
        match self {
            Expected::DefaultForm => true,
            Expected::Key(key) => key == public,
            Expected::KeyId(id) => key_id_bytes(&public.to_spki()) == id,
        }
    }
}

fn decode_pkcs8(der: &[u8], expected: Expected<'_>) -> Result<PrivateKey, KeyError> {
    let der = Zeroizing::new(ber::to_der(der).map_err(malformed)?);
    let info = PrivateKeyInfoRef::from_der(&der).map_err(malformed)?;

    if info.algorithm.oid == oid::RSA_ENCRYPTION {
        let pair = ring::rsa::KeyPair::from_pkcs8(&der).map_err(malformed)?;
        if !expected.accepts(&PublicKey::Rsa(pair.public().as_ref().to_vec())) {
            return Err(KeyError::KeyMismatch);
        }
        return Ok(PrivateKey::Rsa(Arc::new(RsaKeyPair { pair, pkcs8: der })));
    }

    let params = info
        .algorithm
        .parameters
        .map(|p| p.decode_as::<Vec<ObjectIdentifier>>());
    let curve = gost_curve(&info.algorithm.oid, params)?;
    if let Expected::Key(PublicKey::Rsa(_)) = expected {
        return Err(KeyError::KeyMismatch);
    }
    let octets = info.private_key.as_bytes();
    let candidates = scalar_candidates(curve, octets);
    if let Expected::DefaultForm = expected {
        let d = candidates
            .into_iter()
            .find(|c| c.form == default_form(curve, octets))
            .ok_or_else(|| malformed("no GOST private key in the expected form"))?;
        let key = SigningKey::from_scalar_be(curve, &d.be).map_err(malformed)?;
        return Ok(PrivateKey::Gost(key));
    }
    candidates
        .iter()
        .filter_map(|c| SigningKey::from_scalar_be(curve, &c.be).ok())
        .find(|k| expected.accepts(&PublicKey::Gost(k.verifying_key().clone())))
        .map(PrivateKey::Gost)
        .ok_or(KeyError::KeyMismatch)
}

/// Public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// GOST key.
    Gost(VerifyingKey),
    /// RSA key: the DER `RSAPublicKey` from the SPKI BIT STRING.
    Rsa(Vec<u8>),
}

impl PublicKey {
    /// `SubjectPublicKeyInfo` of this key, as NCA certificates carry it: for GOST the key OID
    /// with `SEQUENCE { curve OID, digest parameter OID }` and the OCTET STRING `X_LE ‖ Y_LE`
    /// in the BIT STRING; for RSA `rsaEncryption` with NULL parameters and the
    /// `RSAPublicKey`.
    pub fn to_spki(&self) -> SubjectPublicKeyInfoOwned {
        let (algorithm, bits) = match self {
            PublicKey::Gost(key) => {
                let curve = key.curve();
                let params = Any::from_der(&gost_params_der(curve)).expect("DER parameters");
                let xy = OctetStringRef::new(&key.to_kz_bytes())
                    .and_then(|xy| xy.to_der())
                    .expect("public key OCTET STRING encodes");
                let oid = ObjectIdentifier::new_unwrap(curve.key_oid());
                ((oid, Some(params)), xy)
            }
            PublicKey::Rsa(der) => ((oid::RSA_ENCRYPTION, Some(Any::null())), der.clone()),
        };
        SubjectPublicKeyInfoOwned {
            algorithm: spki::AlgorithmIdentifierOwned {
                oid: algorithm.0,
                parameters: algorithm.1,
            },
            subject_public_key: BitString::from_bytes(&bits).expect("public key BIT STRING"),
        }
    }

    /// Public key from a `SubjectPublicKeyInfo`. A GOST key is the OCTET STRING `X_LE ‖ Y_LE`
    /// inside the BIT STRING.
    ///
    /// # Errors
    ///
    /// [`KeyError::UnknownKeyAlgorithm`] for other key types, [`KeyError::Malformed`] for
    /// invalid encodings or points.
    pub fn from_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<PublicKey, KeyError> {
        let bits = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| malformed("public key BIT STRING has unused bits"))?;
        if spki.algorithm.oid == oid::RSA_ENCRYPTION {
            return Ok(PublicKey::Rsa(bits.to_vec()));
        }
        let params = spki
            .algorithm
            .parameters
            .as_ref()
            .map(|p| p.decode_as::<Vec<ObjectIdentifier>>());
        let curve = gost_curve(&spki.algorithm.oid, params)?;
        let xy = <&OctetStringRef>::from_der(bits).map_err(malformed)?;
        VerifyingKey::from_kz_bytes(curve, xy.as_bytes())
            .map(PublicKey::Gost)
            .map_err(malformed)
    }

    /// Verifies `sig` over `message` (hashed here). RSA uses PKCS#1 v1.5 through `ring`,
    /// SHA-1 only for legacy verification.
    ///
    /// # Errors
    ///
    /// [`KeyError::UnsupportedAlgorithm`] if `alg` does not fit the key,
    /// [`KeyError::BadSignature`] if the signature does not verify.
    pub fn verify(&self, alg: SigAlg, message: &[u8], sig: &[u8]) -> Result<(), KeyError> {
        match self {
            PublicKey::Gost(key) => {
                if alg.gost().map(GostAlg::curve) != Some(key.curve()) {
                    return Err(KeyError::UnsupportedAlgorithm);
                }
                key.verify_digest(&alg.digest(message), sig)
                    .map_err(|_| KeyError::BadSignature)
            }
            PublicKey::Rsa(key) => {
                let params: &'static signature::RsaParameters = match alg {
                    SigAlg::RsaSha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    SigAlg::RsaSha1 => &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
                    SigAlg::Gost2004 | SigAlg::Gost2015_512 => {
                        return Err(KeyError::UnsupportedAlgorithm);
                    }
                };
                UnparsedPublicKey::new(params, key)
                    .verify(message, sig)
                    .map_err(|_| KeyError::BadSignature)
            }
        }
    }
}

/// Key identifier of a public key: SHA-1 of the `subjectPublicKey` BIT STRING contents
/// (RFC 5280 §4.2.1.2 method 1, Kalkan's `createKeyId`).
pub(crate) fn key_id_bytes(spki: &SubjectPublicKeyInfoOwned) -> [u8; 20] {
    sha1::Sha1::digest(spki.subject_public_key.raw_bytes()).into()
}

fn curve_alg(curve: CurveId) -> KeyAlg {
    match curve {
        CurveId::Pkigovkz2004A => KeyAlg::Gost2004,
        CurveId::Tc26_512A => KeyAlg::Gost2015_512,
    }
}

/// DER of the GOST key parameters `SEQUENCE { curve OID, digest parameter OID }`.
fn gost_params_der(curve: CurveId) -> Vec<u8> {
    vec![
        ObjectIdentifier::new_unwrap(curve.curve_oid()),
        ObjectIdentifier::new_unwrap(curve.digest_param_oid()),
    ]
    .to_der()
    .expect("OIDs encode")
}

/// Curve of a GOST key: from the key OID, cross-checked with the `publicKeyParamSet` OID when
/// the parameters are `SEQUENCE { curve OID, digest OID }`.
fn gost_curve(
    key_oid: &ObjectIdentifier,
    params: Option<der::Result<Vec<ObjectIdentifier>>>,
) -> Result<CurveId, KeyError> {
    let curve = [CurveId::Pkigovkz2004A, CurveId::Tc26_512A]
        .into_iter()
        .find(|c| c.key_oid() == key_oid.to_string())
        .ok_or_else(|| KeyError::UnknownKeyAlgorithm(key_oid.to_string()))?;
    if let Some(Ok(oids)) = params
        && let Some(param_set) = oids.first()
    {
        let param_set = param_set.to_string();
        if CurveId::from_curve_oid(&param_set) != Some(curve) {
            return Err(KeyError::UnknownKeyAlgorithm(format!(
                "{key_oid} with parameter set {param_set}"
            )));
        }
    }
    Ok(curve)
}

/// Where a candidate scalar was found in the PKCS#8 `privateKey` octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    Integer,
    RawLe,
    RawBe,
    NestedLe,
    NestedBe,
}

struct Candidate {
    form: Form,
    /// Big-endian scalar bytes.
    be: Zeroizing<Vec<u8>>,
}

/// Form chosen without a certificate (see [`PrivateKey::from_pkcs8_der`]).
fn default_form(curve: CurveId, octets: &[u8]) -> Form {
    match curve {
        CurveId::Pkigovkz2004A => Form::Integer,
        CurveId::Tc26_512A if octets.len() == curve.coord_len() => Form::RawLe,
        CurveId::Tc26_512A => Form::NestedLe,
    }
}

/// Candidate scalars, most likely forms for the curve first.
fn scalar_candidates(curve: CurveId, octets: &[u8]) -> Vec<Candidate> {
    let reversed = |b: &[u8]| Zeroizing::new(b.iter().rev().copied().collect::<Vec<u8>>());
    let mut all = Vec::new();
    if let Ok(int) = UintRef::from_der(octets) {
        all.push(Candidate {
            form: Form::Integer,
            be: Zeroizing::new(int.as_bytes().to_vec()),
        });
    }
    all.push(Candidate {
        form: Form::RawLe,
        be: reversed(octets),
    });
    all.push(Candidate {
        form: Form::RawBe,
        be: Zeroizing::new(octets.to_vec()),
    });
    if let Ok(inner) = <&OctetStringRef>::from_der(octets) {
        all.push(Candidate {
            form: Form::NestedLe,
            be: reversed(inner.as_bytes()),
        });
        all.push(Candidate {
            form: Form::NestedBe,
            be: Zeroizing::new(inner.as_bytes().to_vec()),
        });
    }
    let preferred = default_form(curve, octets);
    all.sort_by_key(|c| c.form != preferred);
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::OctetString;
    use pkcs8::PrivateKeyInfo;
    use spki::AlgorithmIdentifier;

    const CURVES: [CurveId; 2] = [CurveId::Pkigovkz2004A, CurveId::Tc26_512A];

    fn scalar(curve: CurveId) -> Vec<u8> {
        // Top byte zero: the INTEGER and BE forms then differ in length from the LE form.
        let mut d: Vec<u8> = (0..curve.coord_len() as u8)
            .map(|i| i.wrapping_mul(29) | 1)
            .collect();
        d[0] = 0;
        d
    }

    fn pkcs8(curve: CurveId, private_key: &[u8]) -> Vec<u8> {
        pkcs8_with_oid(curve.key_oid(), curve, private_key)
    }

    fn pkcs8_with_oid(key_oid: &str, curve: CurveId, private_key: &[u8]) -> Vec<u8> {
        let params = gost_params_der(curve);
        let info = PrivateKeyInfo::<AnyRef<'_>, &OctetStringRef, der::asn1::BitStringRef<'_>> {
            algorithm: AlgorithmIdentifier {
                oid: ObjectIdentifier::new_unwrap(key_oid),
                parameters: Some(AnyRef::from_der(&params).unwrap()),
            },
            private_key: OctetStringRef::new(private_key).unwrap(),
            public_key: None,
        };
        info.to_der().unwrap()
    }

    fn integer(d_be: &[u8]) -> Vec<u8> {
        UintRef::new(d_be).unwrap().to_der().unwrap()
    }

    fn le(d_be: &[u8]) -> Vec<u8> {
        d_be.iter().rev().copied().collect()
    }

    fn octets(bytes: &[u8]) -> Vec<u8> {
        OctetString::new(bytes).unwrap().to_der().unwrap()
    }

    fn gost(key: PrivateKey) -> SigningKey {
        match key {
            PrivateKey::Gost(k) => k,
            PrivateKey::Rsa(_) => panic!("expected a GOST key"),
        }
    }

    #[test]
    fn sig_alg_tables() {
        for alg in SigAlg::ALL {
            assert_eq!(SigAlg::from_signature_oid(&alg.signature_oid()), Some(alg));
        }
        assert_eq!(SigAlg::from_signature_oid(&oid::RSA_ENCRYPTION), None);
        assert_eq!(SigAlg::RsaSha256.digest(b"abc").len(), 32);
        assert_eq!(SigAlg::RsaSha1.digest(b"abc").len(), 20);
        assert_eq!(SigAlg::Gost2004.digest(b"abc").len(), 32);
        assert_eq!(SigAlg::Gost2015_512.digest(b"abc").len(), 64);
        assert_eq!(
            SigAlg::Gost2004.digest_oid().to_string(),
            GostAlg::Gost34310_2004.digest_oid()
        );
    }

    #[test]
    fn default_forms_without_certificate() {
        for curve in CURVES {
            let d = scalar(curve);
            let expected = SigningKey::from_scalar_be(curve, &d).unwrap();
            let der = match curve {
                CurveId::Pkigovkz2004A => pkcs8(curve, &integer(&d)),
                CurveId::Tc26_512A => pkcs8(curve, &le(&d)),
            };
            let key = gost(PrivateKey::from_pkcs8_der(&der, None).unwrap());
            assert_eq!(key.verifying_key(), expected.verifying_key(), "{curve:?}");
        }
        // GOST 2015 written as BC/Kalkan `getEncoded` does: nested OCTET STRING, LE.
        let curve = CurveId::Tc26_512A;
        let d = scalar(curve);
        let der = pkcs8(curve, &octets(&le(&d)));
        let key = gost(PrivateKey::from_pkcs8_der(&der, None).unwrap());
        let expected = SigningKey::from_scalar_be(curve, &d).unwrap();
        assert_eq!(key.verifying_key(), expected.verifying_key());
        // GOST 2004 without an INTEGER is refused rather than guessed.
        let der = pkcs8(CurveId::Pkigovkz2004A, &le(&scalar(CurveId::Pkigovkz2004A)));
        assert!(matches!(
            PrivateKey::from_pkcs8_der(&der, None),
            Err(KeyError::Malformed(_))
        ));
    }

    #[test]
    fn out_of_range_scalar_is_an_error_not_a_panic() {
        for curve in CURVES {
            let zero = vec![0u8; curve.coord_len()];
            let q = curve.params().q.to_be_bytes().to_vec();
            for bad in [integer(&zero), integer(&q), le(&zero)] {
                let der = pkcs8(curve, &bad);
                assert!(PrivateKey::from_pkcs8_der(&der, None).is_err(), "{curve:?}");
            }
        }
    }

    #[test]
    fn candidates_cover_every_form() {
        let curve = CurveId::Tc26_512A;
        let d = scalar(curve);
        let forms = |octets: &[u8]| -> Vec<(Form, Vec<u8>)> {
            scalar_candidates(curve, octets)
                .into_iter()
                .map(|c| (c.form, c.be.to_vec()))
                .collect()
        };
        let trimmed = d[1..].to_vec();
        assert!(forms(&integer(&d)).contains(&(Form::Integer, trimmed)));
        assert!(forms(&le(&d)).contains(&(Form::RawLe, d.clone())));
        assert!(forms(&d).contains(&(Form::RawBe, d.clone())));
        assert!(forms(&octets(&le(&d))).contains(&(Form::NestedLe, d.clone())));
        assert!(forms(&octets(&d)).contains(&(Form::NestedBe, d.clone())));
        assert_eq!(forms(&le(&d))[0].0, Form::RawLe, "preferred form first");
    }

    #[test]
    fn gost_sign_rejects_foreign_algorithms() {
        let curve = CurveId::Pkigovkz2004A;
        let der = pkcs8(curve, &integer(&scalar(curve)));
        let key = PrivateKey::from_pkcs8_der(&der, None).unwrap();
        assert_eq!(key.alg(), KeyAlg::Gost2004);
        for alg in [SigAlg::Gost2015_512, SigAlg::RsaSha256, SigAlg::RsaSha1] {
            assert_eq!(key.sign(alg, b"m"), Err(KeyError::UnsupportedAlgorithm));
        }
        let sig = key.sign(SigAlg::Gost2004, b"m").unwrap();
        let PrivateKey::Gost(k) = &key else {
            unreachable!()
        };
        let public = PublicKey::Gost(k.verifying_key().clone());
        assert_eq!(public.verify(SigAlg::Gost2004, b"m", &sig), Ok(()));
        assert_eq!(
            public.verify(SigAlg::Gost2004, b"n", &sig),
            Err(KeyError::BadSignature)
        );
        assert_eq!(
            public.verify(SigAlg::RsaSha256, b"m", &sig),
            Err(KeyError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn unknown_key_algorithm() {
        let curve = CurveId::Tc26_512A;
        // GOST 2015-256 key OID, and a 512-bit key OID with the 2004 parameter set.
        for der in [
            pkcs8_with_oid("1.2.398.3.10.1.1.2.1", curve, &[1; 64]),
            pkcs8_with_oid(curve.key_oid(), CurveId::Pkigovkz2004A, &[1; 64]),
        ] {
            assert!(matches!(
                PrivateKey::from_pkcs8_der(&der, None),
                Err(KeyError::UnknownKeyAlgorithm(_))
            ));
        }
    }

    #[test]
    fn gost_pkcs8_export_is_the_kalkan_form() {
        for curve in CURVES {
            let d = scalar(curve);
            let key = PrivateKey::Gost(SigningKey::from_scalar_be(curve, &d).unwrap());
            let expected = match curve {
                // INTEGER: the leading zero byte is not encoded.
                CurveId::Pkigovkz2004A => pkcs8(curve, &integer(&d)),
                CurveId::Tc26_512A => pkcs8(curve, &octets(&le(&d))),
            };
            assert_eq!(*key.to_pkcs8_der(), expected, "{curve:?}");
            let back = gost(PrivateKey::from_pkcs8_der(&key.to_pkcs8_der(), None).unwrap());
            assert_eq!(*back.scalar_be(), d, "{curve:?}");
        }
    }

    #[test]
    fn spki_export_reads_back() {
        for curve in CURVES {
            let key = PrivateKey::Gost(SigningKey::from_scalar_be(curve, &scalar(curve)).unwrap());
            let spki = key.public_key().to_spki();
            assert_eq!(spki.algorithm.oid.to_string(), curve.key_oid());
            assert_eq!(
                spki.algorithm
                    .parameters
                    .as_ref()
                    .unwrap()
                    .to_der()
                    .unwrap(),
                gost_params_der(curve)
            );
            assert_eq!(PublicKey::from_spki(&spki).unwrap(), key.public_key());
        }
        let rsa = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/openssl/rsa.pk8.der"),
        )
        .unwrap();
        let key = PrivateKey::from_pkcs8_der(&rsa, None).unwrap();
        assert_eq!(*key.to_pkcs8_der(), rsa, "RSA keeps its PKCS#8");
        let spki = key.public_key().to_spki();
        assert_eq!(spki.algorithm.oid, oid::RSA_ENCRYPTION);
        assert_eq!(spki.algorithm.parameters, Some(Any::null()));
        assert_eq!(PublicKey::from_spki(&spki).unwrap(), key.public_key());
    }

    #[test]
    fn key_id_picks_the_stored_form() {
        for curve in CURVES {
            let d = scalar(curve);
            let public = PublicKey::Gost(
                SigningKey::from_scalar_be(curve, &d)
                    .unwrap()
                    .verifying_key()
                    .clone(),
            );
            let id = key_id_bytes(&public.to_spki());
            // Raw big-endian octets: not the default form of either curve.
            let der = pkcs8(curve, &d);
            let key = PrivateKey::from_pkcs8_der_with_key_id(&der, &id).unwrap();
            assert_eq!(key.public_key(), public, "{curve:?}");
            assert_ne!(
                PrivateKey::from_pkcs8_der(&der, None)
                    .map(|k| k.public_key())
                    .ok(),
                Some(public),
                "{curve:?}: the default form would read another scalar"
            );
            assert_eq!(
                PrivateKey::from_pkcs8_der_with_key_id(&der, &[0; 20]).unwrap_err(),
                KeyError::KeyMismatch
            );
        }
    }
}
