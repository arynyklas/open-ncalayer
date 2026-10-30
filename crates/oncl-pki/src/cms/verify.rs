//! Verification of every signer of a CMS `SignedData`.

use super::CmsError;
use super::asn1::{
    Attribute, ContentInfo, IssuerAndSerialNumber, RawSet, SignedData, SignerInfo,
    SigningCertificateV2,
};
use crate::ber;
use crate::key::{KeyError, PublicKey, SigAlg};
use crate::oid;
use der::asn1::{AnyRef, GeneralizedTime, ObjectIdentifier, OctetStringRef, UtcTime};
use der::{Decode, Encode, Tag, TagNumber, Tagged};
use sha2::Digest;
use std::cell::OnceCell;
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::ext::pkix::SubjectKeyIdentifier;

/// A signer whose signature verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSigner {
    /// Signer certificate, from the CMS `certificates`.
    pub cert: Certificate,
    /// Signature algorithm.
    pub sig_alg: SigAlg,
    /// signingTime attribute, if present.
    pub signing_time: Option<OffsetDateTime>,
    /// The `signature` value of the `SignerInfo`: what a time-stamp token of this signer
    /// covers (see [`crate::tsp::verify_token_for`]).
    pub signature: Vec<u8>,
    /// DER of the timeStampToken unsigned attribute (a `ContentInfo`), if present.
    pub timestamp_token: Option<Vec<u8>>,
}

/// Verifies every signer of a DER or BER `ContentInfo{SignedData}` over its encapsulated
/// content, or over `detached` when it has none. Certificates are not checked beyond the
/// signingCertificateV2 hash: no chain, validity or revocation.
///
/// Every signer must have signed attributes (with messageDigest), as NCALayer writes them:
/// a signer without them is refused, which also hashes the content at most once per
/// algorithm however many signers there are.
///
/// # Errors
///
/// [`CmsError::NoEncapsulatedData`] without content; [`CmsError::Malformed`] for invalid
/// encodings, a signer without signed attributes, missing messageDigest, or a repeated
/// contentType, messageDigest, signingTime or signingCertificateV2 attribute; for the first
/// failing signer:
/// [`CmsError::UnknownAlgorithm`], [`CmsError::CertNotFound`],
/// [`CmsError::DigestMismatch`], [`CmsError::SigningCertificateMismatch`],
/// [`CmsError::BadSignature`] or [`CmsError::Key`].
pub fn verify(cms: &[u8], detached: Option<&[u8]>) -> Result<Vec<VerifiedSigner>, CmsError> {
    let der = ber::to_der(cms)?;
    let content_info = ContentInfo::from_der(&der)?;
    if content_info.content_type != oid::SIGNED_DATA {
        return Err(CmsError::Malformed(format!(
            "content type {} is not signedData",
            content_info.content_type
        )));
    }
    let signed_data: SignedData<'_> = content_info.content.decode_as()?;
    let encap = signed_data.encap_content_info;
    let content = match (encap.e_content, detached) {
        (Some(content), _) => content.as_bytes(),
        (None, Some(detached)) => detached,
        (None, None) => return Err(CmsError::NoEncapsulatedData),
    };
    let certs = certificates(&signed_data)?;
    let signers = signed_data.signer_infos.tlvs()?;
    if signers.is_empty() {
        return Err(CmsError::Malformed("no signers".to_owned()));
    }
    let digests = ContentDigests::new(Some(content));
    signers
        .into_iter()
        .enumerate()
        .map(|(index, tlv)| {
            let signer = Signer {
                index,
                info: SignerInfo::from_der(tlv)?,
                content_type: encap.e_content_type,
                digests: &digests,
            };
            signer.verify(&certs)
        })
        .collect()
}

/// The certificates of a `SignedData` with their DER; other `CertificateChoices`
/// (attribute certificates, …) are skipped.
pub(super) fn certificates<'a>(
    signed_data: &SignedData<'a>,
) -> Result<Vec<(Certificate, &'a [u8])>, CmsError> {
    match signed_data.certificates {
        Some(set) => set
            .tlvs()?
            .into_iter()
            .filter(|tlv| tlv.first() == Some(&0x30))
            .map(|tlv| Ok((Certificate::from_der(tlv)?, tlv)))
            .collect(),
        None => Ok(Vec::new()),
    }
}

/// Digests of the signed content, each computed at most once per algorithm however many
/// signers share it, so a document is hashed at most once per [`SigAlg`].
pub(super) struct ContentDigests<'a> {
    content: Option<&'a [u8]>,
    by_alg: [OnceCell<Vec<u8>>; 4],
}

impl<'a> ContentDigests<'a> {
    /// Digests of `content`; none without it.
    pub(super) fn new(content: Option<&'a [u8]>) -> Self {
        ContentDigests {
            content,
            by_alg: Default::default(),
        }
    }

    fn get(&self, alg: SigAlg) -> Option<&[u8]> {
        let content = self.content?;
        let slot = match alg {
            SigAlg::Gost2004 => 0,
            SigAlg::Gost2015_512 => 1,
            SigAlg::RsaSha256 => 2,
            SigAlg::RsaSha1 => 3,
        };
        Some(self.by_alg[slot].get_or_init(|| alg.digest(content)))
    }
}

pub(super) struct Signer<'a> {
    pub(super) index: usize,
    pub(super) info: SignerInfo<'a>,
    pub(super) content_type: ObjectIdentifier,
    pub(super) digests: &'a ContentDigests<'a>,
}

/// What the signed attributes say, checked against the content and the certificate.
pub(super) struct SeenAttrs {
    /// signingTime.
    pub(super) signing_time: Option<OffsetDateTime>,
    /// Whether messageDigest is the content's digest; `None` without content.
    pub(super) digest_matches: Option<bool>,
    /// Whether signingCertificateV2 names the certificate; `None` without the attribute
    /// (or without a certificate).
    pub(super) ess_matches: Option<bool>,
}

/// `SignerIdentifier`.
enum Sid<'a> {
    IssuerSerial(IssuerAndSerialNumber),
    KeyId(&'a [u8]),
}

impl Sid<'_> {
    fn matches(&self, cert: &Certificate) -> bool {
        let tbs = cert.tbs_certificate();
        match self {
            Sid::IssuerSerial(sid) => {
                *tbs.issuer() == sid.issuer
                    && tbs.serial_number().as_bytes() == sid.serial_number.as_bytes()
            }
            Sid::KeyId(id) => matches!(
                tbs.get_extension::<SubjectKeyIdentifier>(),
                Ok(Some((_, ski))) if ski.0.as_bytes() == *id
            ),
        }
    }
}

impl Signer<'_> {
    fn verify(&self, certs: &[(Certificate, &[u8])]) -> Result<VerifiedSigner, CmsError> {
        // Without signed attributes the signature covers the whole content, which would be
        // hashed again for every such signer; NCALayer always writes signed attributes.
        let attrs = self.signed_attrs()?;
        let alg = self.algorithm()?;
        let (cert, cert_der) = self
            .find_cert(certs, |_| true)?
            .ok_or(CmsError::CertNotFound(self.index))?;
        let key = PublicKey::from_spki(cert.tbs_certificate().subject_public_key_info())
            .map_err(CmsError::Key)?;

        let signing_time = self
            .check_signed_attrs(attrs, alg, Some(cert_der), true)?
            .signing_time;
        key.verify(alg, &signed_message(attrs)?, self.info.signature.as_bytes())
            .map_err(|e| match e {
                KeyError::BadSignature => CmsError::BadSignature(self.index),
                e => CmsError::Key(e),
            })?;

        Ok(VerifiedSigner {
            cert: cert.clone(),
            sig_alg: alg,
            signing_time,
            signature: self.info.signature.as_bytes().to_vec(),
            timestamp_token: self.timestamp_token()?,
        })
    }

    /// Whether the signature verifies with `key` over the signed attributes.
    pub(super) fn signature_verifies(
        &self,
        attrs: RawSet<'_>,
        alg: SigAlg,
        key: &PublicKey,
    ) -> Result<bool, CmsError> {
        match key.verify(alg, &signed_message(attrs)?, self.info.signature.as_bytes()) {
            Ok(()) => Ok(true),
            Err(KeyError::BadSignature) => Ok(false),
            Err(e) => Err(CmsError::Key(e)),
        }
    }

    /// The signed attributes, which NCALayer always writes.
    pub(super) fn signed_attrs(&self) -> Result<RawSet<'_>, CmsError> {
        self.info
            .signed_attrs
            .ok_or_else(|| self.malformed("no signed attributes"))
    }

    /// Signature algorithm from `signatureAlgorithm`, which must agree with
    /// `digestAlgorithm`. Plain `rsaEncryption` (as OpenSSL writes) takes the digest from
    /// `digestAlgorithm`.
    pub(super) fn algorithm(&self) -> Result<SigAlg, CmsError> {
        let signature = self.info.signature_algorithm.oid;
        let digest = self.info.digest_algorithm.oid;
        let alg = if signature == oid::RSA_ENCRYPTION {
            [SigAlg::RsaSha256, SigAlg::RsaSha1]
                .into_iter()
                .find(|a| a.digest_oid() == digest)
        } else {
            SigAlg::from_signature_oid(&signature).filter(|a| a.digest_oid() == digest)
        };
        alg.ok_or_else(|| CmsError::UnknownAlgorithm(format!("{signature} with digest {digest}")))
    }

    /// The first certificate named by `sid` (`IssuerAndSerialNumber` or `[0]
    /// SubjectKeyIdentifier`) that `accept` takes, if any.
    pub(super) fn find_cert<'c>(
        &self,
        certs: &'c [(Certificate, &'c [u8])],
        accept: impl Fn(&Certificate) -> bool,
    ) -> Result<Option<(&'c Certificate, &'c [u8])>, CmsError> {
        const SKI: Tag = Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(0),
        };
        let sid = self.info.sid;
        let sid = match sid.tag() {
            Tag::Sequence => Sid::IssuerSerial(sid.decode_as()?),
            SKI => Sid::KeyId(sid.value()),
            tag => return Err(self.malformed(&format!("unknown SignerIdentifier {tag}"))),
        };
        Ok(certs
            .iter()
            .find(|(cert, _)| sid.matches(cert) && accept(cert))
            .map(|(cert, der)| (cert, *der)))
    }

    /// Checks contentType, messageDigest (against the content, if any) and
    /// signingCertificateV2 (against `cert_der`, if any); reads signingTime. Each of these
    /// may appear once (RFC 5652 §11, RFC 5035 §5.4). `strict` fails on the first mismatch,
    /// in attribute order; otherwise mismatches are only reported.
    pub(super) fn check_signed_attrs(
        &self,
        attrs: RawSet<'_>,
        alg: SigAlg,
        cert_der: Option<&[u8]>,
        strict: bool,
    ) -> Result<SeenAttrs, CmsError> {
        let (mut content_type_seen, mut digest_seen) = (false, false);
        let (mut time_seen, mut signing_cert_seen) = (false, false);
        let mut seen = SeenAttrs {
            signing_time: None,
            digest_matches: None,
            ess_matches: None,
        };
        for tlv in attrs.tlvs()? {
            let attr = Attribute::from_der(tlv)?;
            let attr_type = attr.attr_type;
            let value = || single_value(attr, self.index);
            if attr_type == oid::CONTENT_TYPE {
                self.first(&mut content_type_seen, "contentType")?;
                if value()?.decode_as::<ObjectIdentifier>()? != self.content_type {
                    return Err(self.malformed("contentType differs from eContentType"));
                }
            } else if attr_type == oid::MESSAGE_DIGEST {
                self.first(&mut digest_seen, "messageDigest")?;
                let digest = value()?.decode_as::<&OctetStringRef>()?;
                seen.digest_matches = self
                    .digests
                    .get(alg)
                    .map(|expected| digest.as_bytes() == expected);
                if strict && seen.digest_matches == Some(false) {
                    return Err(CmsError::DigestMismatch(self.index));
                }
            } else if attr_type == oid::SIGNING_TIME {
                self.first(&mut time_seen, "signingTime")?;
                seen.signing_time = Some(decode_time(value()?)?);
            } else if attr_type == oid::SIGNING_CERTIFICATE_V2 {
                self.first(&mut signing_cert_seen, "signingCertificateV2")?;
                let signing_cert: SigningCertificateV2<'_> = value()?.decode_as()?;
                let first = signing_cert
                    .certs
                    .first()
                    .ok_or_else(|| self.malformed("empty signingCertificateV2"))?;
                let hash_oid = first.hash_algorithm.map_or(oid::SHA256, |a| a.oid);
                if let Some(cert_der) = cert_der {
                    let matches = first.cert_hash.as_bytes() == hash(&hash_oid, cert_der)?;
                    if strict && !matches {
                        return Err(CmsError::SigningCertificateMismatch(self.index));
                    }
                    seen.ess_matches = Some(matches);
                }
            }
        }
        if !digest_seen {
            return Err(self.malformed("no messageDigest attribute"));
        }
        Ok(seen)
    }

    /// The value of the single `attr_type` attribute among `attrs`, if there is one.
    pub(super) fn attribute<'r>(
        &self,
        attrs: Option<RawSet<'r>>,
        attr_type: ObjectIdentifier,
    ) -> Result<Option<AnyRef<'r>>, CmsError> {
        let Some(attrs) = attrs else {
            return Ok(None);
        };
        for tlv in attrs.tlvs()? {
            let attr = Attribute::from_der(tlv)?;
            if attr.attr_type == attr_type {
                return Ok(Some(single_value(attr, self.index)?));
            }
        }
        Ok(None)
    }

    /// Marks a single-instance attribute as seen; [`CmsError::Malformed`] if it already was.
    fn first(&self, seen: &mut bool, name: &str) -> Result<(), CmsError> {
        if std::mem::replace(seen, true) {
            return Err(self.malformed(&format!("more than one {name} attribute")));
        }
        Ok(())
    }

    pub(super) fn timestamp_token(&self) -> Result<Option<Vec<u8>>, CmsError> {
        self.attribute(self.info.unsigned_attrs, oid::TIME_STAMP_TOKEN)?
            .map(|token| token.to_der())
            .transpose()
            .map_err(CmsError::from)
    }

    fn malformed(&self, what: &str) -> CmsError {
        CmsError::Malformed(format!("signer {}: {what}", self.index))
    }
}

/// What a signature with signed attributes covers: the DER `SET OF`, not the `[0]
/// IMPLICIT` encoding.
fn signed_message(attrs: RawSet<'_>) -> Result<Vec<u8>, CmsError> {
    Ok(attrs.to_der()?)
}

/// The only value of an attribute.
fn single_value<'a>(attr: Attribute<'a>, index: usize) -> Result<AnyRef<'a>, CmsError> {
    match attr.attr_values.tlvs()?.as_slice() {
        [value] => Ok(AnyRef::from_der(value)?),
        values => Err(CmsError::Malformed(format!(
            "signer {index}: attribute {} has {} values",
            attr.attr_type,
            values.len()
        ))),
    }
}

/// signingTime: UTCTime or GeneralizedTime.
fn decode_time(value: AnyRef<'_>) -> Result<OffsetDateTime, CmsError> {
    let since_epoch = match value.tag() {
        Tag::UtcTime => value.decode_as::<UtcTime>()?.to_unix_duration(),
        Tag::GeneralizedTime => value.decode_as::<GeneralizedTime>()?.to_unix_duration(),
        tag => {
            return Err(CmsError::Malformed(format!("signingTime is a {tag}")));
        }
    };
    Ok(OffsetDateTime::UNIX_EPOCH + since_epoch)
}

/// Hash for an `ESSCertIDv2`.
fn hash(alg: &ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>, CmsError> {
    Ok(match *alg {
        oid::SHA256 => sha2::Sha256::digest(data).to_vec(),
        oid::SHA384 => sha2::Sha384::digest(data).to_vec(),
        oid::SHA512 => sha2::Sha512::digest(data).to_vec(),
        oid::GOST_34311 => SigAlg::Gost2004.digest(data),
        oid::STREEBOG_512 => SigAlg::Gost2015_512.digest(data),
        _ => return Err(CmsError::UnknownAlgorithm(alg.to_string())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::asn1::{EncapsulatedContentInfo, SignedContentInfo, der_set_contents};
    use crate::cms::sign::{AttrSpec, SignOptions, sign_content, signed_attributes};
    use crate::pkcs12::{KeyEntry, load};
    use oncl_testkit::{read, synthetic};
    use time::macros::datetime;

    fn entry(name: &str) -> KeyEntry {
        let key = synthetic(name);
        load(&read(&key.path), &key.password)
            .unwrap()
            .swap_remove(0)
    }

    fn opts() -> SignOptions {
        SignOptions {
            encapsulate: true,
            digested: false,
            signing_time: datetime!(2026-03-01 10:00 UTC),
        }
    }

    #[test]
    fn sign_content_writes_its_content_type() {
        let e = entry("tsa-gost2015");
        let cms = sign_content(&e, &oid::TST_INFO, b"tst-info", true, &opts()).unwrap();
        assert_eq!(verify(&cms, None).unwrap().len(), 1);
        let ci = ContentInfo::from_der(&cms).unwrap();
        let sd: SignedData<'_> = ci.content.decode_as().unwrap();
        assert_eq!(sd.encap_content_info.e_content_type, oid::TST_INFO);
        let si = SignerInfo::from_der(sd.signer_infos.tlvs().unwrap()[0]).unwrap();
        let content_type = si
            .signed_attrs
            .unwrap()
            .tlvs()
            .unwrap()
            .into_iter()
            .map(|t| Attribute::from_der(t).unwrap())
            .find(|a| a.attr_type == oid::CONTENT_TYPE)
            .unwrap();
        let value = single_value(content_type, 0).unwrap();
        assert_eq!(
            value.decode_as::<ObjectIdentifier>().unwrap(),
            oid::TST_INFO
        );
    }

    /// Contents of the profile's signed attributes for `content`, naming `attrs_cert`.
    fn attrs_for(e: &KeyEntry, attrs_cert: &Certificate, content: &[u8]) -> Vec<u8> {
        let alg = crate::info::cert_info(&e.cert).signing_alg().unwrap();
        signed_attributes(
            &AttrSpec::cades(opts().signing_time),
            &oid::DATA,
            &alg.digest(content),
            &attrs_cert.to_der().unwrap(),
        )
        .unwrap()
        .unwrap()
    }

    /// One-signer CMS whose signed attributes name `attrs_cert` and are signed by `e`.
    fn cms_with_attrs_for(e: &KeyEntry, attrs_cert: &Certificate, content: &[u8]) -> Vec<u8> {
        cms_signed_over(e, Some(&attrs_for(e, attrs_cert, content)), content)
    }

    /// One-signer CMS of `content` with a valid signature by `e` over `attrs` (contents of
    /// the signed attributes `SET OF`), or over the content itself without `attrs`.
    fn cms_signed_over(e: &KeyEntry, attrs: Option<&[u8]>, content: &[u8]) -> Vec<u8> {
        let alg = crate::info::cert_info(&e.cert).signing_alg().unwrap();
        let signed = match attrs {
            Some(attrs) => RawSet(attrs).to_der().unwrap(),
            None => content.to_vec(),
        };
        let signature = e.key.sign(alg, &signed).unwrap();
        let tbs = e.cert.tbs_certificate();
        let sid = IssuerAndSerialNumber {
            issuer: tbs.issuer().clone(),
            serial_number: der::asn1::Int::new(tbs.serial_number().as_bytes()).unwrap(),
        }
        .to_der()
        .unwrap();
        let alg_id = |oid| spki::AlgorithmIdentifierRef {
            oid,
            parameters: Some(AnyRef::NULL),
        };
        let si = SignerInfo {
            version: 1,
            sid: AnyRef::from_der(&sid).unwrap(),
            digest_algorithm: alg_id(alg.digest_oid()),
            signed_attrs: attrs.map(RawSet),
            signature_algorithm: alg_id(alg.signature_oid()),
            signature: OctetStringRef::new(&signature).unwrap(),
            unsigned_attrs: None,
        }
        .to_der()
        .unwrap();
        let digest_algs = der_set_contents(vec![alg_id(alg.digest_oid()).to_der().unwrap()]);
        let cert = e.cert.to_der().unwrap();
        let sd = SignedData {
            version: 1,
            digest_algorithms: RawSet(&digest_algs),
            encap_content_info: EncapsulatedContentInfo {
                e_content_type: oid::DATA,
                e_content: Some(OctetStringRef::new(content).unwrap()),
            },
            certificates: Some(RawSet(&cert)),
            crls: None,
            signer_infos: RawSet(&si),
        };
        SignedContentInfo { signed_data: &sd }.to_der().unwrap()
    }

    #[test]
    fn signer_without_signed_attributes_is_refused() {
        for name in ["user-gost2015-sign", "user-rsa-sign"] {
            let e = entry(name);
            // The signature over the bare content is valid; only the missing attributes fail.
            let cms = cms_signed_over(&e, None, b"c");
            match verify(&cms, None) {
                Err(CmsError::Malformed(m)) => {
                    assert!(m.contains("no signed attributes"), "{name}: {m}");
                }
                other => panic!("{name}: {other:?}"),
            }
        }
    }

    #[test]
    fn signing_certificate_v2_must_match_signer_certificate() {
        let e = entry("user-gost2015-sign");
        let good = cms_with_attrs_for(&e, &e.cert, b"c");
        assert_eq!(verify(&good, None).unwrap().len(), 1);
        let other = entry("user-gost2015-auth").cert;
        let bad = cms_with_attrs_for(&e, &other, b"c");
        assert_eq!(
            verify(&bad, None),
            Err(CmsError::SigningCertificateMismatch(0))
        );
    }

    #[test]
    fn single_instance_attributes_may_not_repeat() {
        let e = entry("user-gost2015-sign");
        let attrs = attrs_for(&e, &e.cert, b"c");
        let tlvs = RawSet(&attrs).tlvs().unwrap();
        for repeated in [
            oid::CONTENT_TYPE,
            oid::MESSAGE_DIGEST,
            oid::SIGNING_TIME,
            oid::SIGNING_CERTIFICATE_V2,
        ] {
            let mut doubled: Vec<Vec<u8>> = tlvs.iter().map(|t| t.to_vec()).collect();
            let original = tlvs
                .iter()
                .find(|t| Attribute::from_der(t).unwrap().attr_type == repeated)
                .unwrap();
            doubled.push(original.to_vec());
            // Validly signed, so only the repetition can make it fail.
            let cms = cms_signed_over(&e, Some(&der_set_contents(doubled)), b"c");
            match verify(&cms, None) {
                Err(CmsError::Malformed(m)) => assert!(m.contains("more than one"), "{m}"),
                other => panic!("{repeated}: {other:?}"),
            }
        }
    }

    #[test]
    fn content_is_hashed_once_per_algorithm() {
        let digests = ContentDigests::new(Some(b"document"));
        let algs = [
            SigAlg::Gost2004,
            SigAlg::Gost2015_512,
            SigAlg::RsaSha256,
            SigAlg::RsaSha1,
        ];
        for alg in algs {
            let first = digests.get(alg).unwrap();
            assert_eq!(first, alg.digest(b"document"));
            // The same buffer comes back: the digest was not recomputed.
            assert!(std::ptr::eq(first, digests.get(alg).unwrap()), "{alg:?}");
        }
        assert_eq!(
            digests.by_alg.iter().filter(|c| c.get().is_some()).count(),
            4
        );
    }

    #[test]
    fn cosigners_share_one_digest_per_algorithm() {
        // Two GOST 2015 signers and one RSA signer: two digests of the content in total.
        let gost = entry("user-gost2015-sign");
        let rsa = entry("user-rsa-sign");
        let a = crate::cms::sign(&gost, b"shared", &opts()).unwrap();
        let b = crate::cms::sign(&gost, &a, &opts()).unwrap();
        let c = crate::cms::sign(&rsa, &b, &opts()).unwrap();
        let ci = ContentInfo::from_der(&c).unwrap();
        let sd: SignedData<'_> = ci.content.decode_as().unwrap();
        let digests = ContentDigests::new(Some(b"shared"));
        let certs: Vec<(Certificate, &[u8])> = sd
            .certificates
            .unwrap()
            .tlvs()
            .unwrap()
            .into_iter()
            .map(|t| (Certificate::from_der(t).unwrap(), t))
            .collect();
        for (index, tlv) in sd.signer_infos.tlvs().unwrap().into_iter().enumerate() {
            Signer {
                index,
                info: SignerInfo::from_der(tlv).unwrap(),
                content_type: oid::DATA,
                digests: &digests,
            }
            .verify(&certs)
            .unwrap();
        }
        let computed: Vec<usize> = (0..4)
            .filter(|&i| digests.by_alg[i].get().is_some())
            .collect();
        assert_eq!(computed, [1, 2], "Streebog-512 and SHA-256 only, once each");
    }

    #[test]
    fn plain_rsa_encryption_signature_algorithm() {
        let rsa = SignerInfo {
            version: 1,
            sid: AnyRef::NULL,
            digest_algorithm: spki::AlgorithmIdentifierRef {
                oid: oid::SHA256,
                parameters: None,
            },
            signed_attrs: None,
            signature_algorithm: spki::AlgorithmIdentifierRef {
                oid: oid::RSA_ENCRYPTION,
                parameters: None,
            },
            signature: OctetStringRef::new(&[]).unwrap(),
            unsigned_attrs: None,
        };
        let digests = ContentDigests::new(Some(b""));
        let signer = |info| Signer {
            index: 0,
            info,
            content_type: oid::DATA,
            digests: &digests,
        };
        assert_eq!(signer(rsa).algorithm(), Ok(SigAlg::RsaSha256));
        let mismatched = SignerInfo {
            signature_algorithm: spki::AlgorithmIdentifierRef {
                oid: oid::GOST_2015_512_SIGNATURE,
                parameters: None,
            },
            ..rsa
        };
        assert!(matches!(
            signer(mismatched).algorithm(),
            Err(CmsError::UnknownAlgorithm(_))
        ));
    }

    #[test]
    fn decodes_both_time_types() {
        let utc = UtcTime::from_unix_duration(std::time::Duration::from_secs(1_000_000_000))
            .unwrap()
            .to_der()
            .unwrap();
        let t = decode_time(AnyRef::from_der(&utc).unwrap()).unwrap();
        assert_eq!(t.unix_timestamp(), 1_000_000_000);
        let generalized = b"\x18\x0f20600101000000Z";
        let t = decode_time(AnyRef::from_der(generalized).unwrap()).unwrap();
        assert_eq!(t, datetime!(2060-01-01 0:00 UTC));
        let other = der::asn1::Null.to_der().unwrap();
        assert!(decode_time(AnyRef::from_der(&other).unwrap()).is_err());
    }
}
