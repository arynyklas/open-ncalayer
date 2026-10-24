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
    /// DER of the timeStampToken unsigned attribute (a `ContentInfo`), if present.
    pub timestamp_token: Option<Vec<u8>>,
}

/// Verifies every signer of a DER or BER `ContentInfo{SignedData}` over its encapsulated
/// content, or over `detached` when it has none. Certificates are not checked beyond the
/// signingCertificateV2 hash: no chain, validity or revocation.
///
/// # Errors
///
/// [`CmsError::NoEncapsulatedData`] without content; [`CmsError::Malformed`] for invalid
/// encodings or missing mandatory attributes; for the first failing signer:
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
    let certs = match signed_data.certificates {
        // Other CertificateChoices (attribute certificates, …) are skipped.
        Some(set) => set
            .tlvs()?
            .into_iter()
            .filter(|tlv| tlv.first() == Some(&0x30))
            .map(|tlv| Ok((Certificate::from_der(tlv)?, tlv)))
            .collect::<Result<Vec<_>, CmsError>>()?,
        None => Vec::new(),
    };
    let signers = signed_data.signer_infos.tlvs()?;
    if signers.is_empty() {
        return Err(CmsError::Malformed("no signers".to_owned()));
    }
    signers
        .into_iter()
        .enumerate()
        .map(|(index, tlv)| {
            let signer = Signer {
                index,
                info: SignerInfo::from_der(tlv)?,
                content_type: encap.e_content_type,
                content,
            };
            signer.verify(&certs)
        })
        .collect()
}

struct Signer<'a> {
    index: usize,
    info: SignerInfo<'a>,
    content_type: ObjectIdentifier,
    content: &'a [u8],
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
        let alg = self.algorithm()?;
        let (cert, cert_der) = self.find_cert(certs)?;
        let key = PublicKey::from_spki(cert.tbs_certificate().subject_public_key_info())
            .map_err(CmsError::Key)?;

        let mut signing_time = None;
        let signed_attrs;
        let message = match self.info.signed_attrs {
            Some(attrs) => {
                signing_time = self.check_signed_attrs(attrs, alg, cert_der)?;
                // Signed over the DER `SET OF`, not the `[0] IMPLICIT` encoding.
                signed_attrs = attrs.to_der()?;
                &signed_attrs[..]
            }
            None => self.content,
        };
        key.verify(alg, message, self.info.signature.as_bytes())
            .map_err(|e| match e {
                KeyError::BadSignature => CmsError::BadSignature(self.index),
                e => CmsError::Key(e),
            })?;

        Ok(VerifiedSigner {
            cert: cert.clone(),
            sig_alg: alg,
            signing_time,
            timestamp_token: self.timestamp_token()?,
        })
    }

    /// Signature algorithm from `signatureAlgorithm`, which must agree with
    /// `digestAlgorithm`. Plain `rsaEncryption` (as OpenSSL writes) takes the digest from
    /// `digestAlgorithm`.
    fn algorithm(&self) -> Result<SigAlg, CmsError> {
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

    /// Certificate named by `sid`: `IssuerAndSerialNumber` or `[0] SubjectKeyIdentifier`.
    fn find_cert<'c>(
        &self,
        certs: &'c [(Certificate, &'c [u8])],
    ) -> Result<(&'c Certificate, &'c [u8]), CmsError> {
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
        certs
            .iter()
            .find(|(cert, _)| sid.matches(cert))
            .map(|(cert, der)| (cert, *der))
            .ok_or(CmsError::CertNotFound(self.index))
    }

    /// Checks contentType, messageDigest and signingCertificateV2; returns signingTime.
    fn check_signed_attrs(
        &self,
        attrs: RawSet<'_>,
        alg: SigAlg,
        cert_der: &[u8],
    ) -> Result<Option<OffsetDateTime>, CmsError> {
        let mut digest_seen = false;
        let mut signing_time = None;
        for tlv in attrs.tlvs()? {
            let attr = Attribute::from_der(tlv)?;
            let attr_type = attr.attr_type;
            let value = || single_value(attr, self.index);
            if attr_type == oid::CONTENT_TYPE {
                if value()?.decode_as::<ObjectIdentifier>()? != self.content_type {
                    return Err(self.malformed("contentType differs from eContentType"));
                }
            } else if attr_type == oid::MESSAGE_DIGEST {
                let digest = value()?.decode_as::<&OctetStringRef>()?;
                if digest.as_bytes() != alg.digest(self.content) {
                    return Err(CmsError::DigestMismatch(self.index));
                }
                digest_seen = true;
            } else if attr_type == oid::SIGNING_TIME {
                signing_time = Some(decode_time(value()?)?);
            } else if attr_type == oid::SIGNING_CERTIFICATE_V2 {
                let signing_cert: SigningCertificateV2<'_> = value()?.decode_as()?;
                let first = signing_cert
                    .certs
                    .first()
                    .ok_or_else(|| self.malformed("empty signingCertificateV2"))?;
                let hash_oid = first.hash_algorithm.map_or(oid::SHA256, |a| a.oid);
                if first.cert_hash.as_bytes() != hash(&hash_oid, cert_der)? {
                    return Err(CmsError::SigningCertificateMismatch(self.index));
                }
            }
        }
        if !digest_seen {
            return Err(self.malformed("no messageDigest attribute"));
        }
        Ok(signing_time)
    }

    fn timestamp_token(&self) -> Result<Option<Vec<u8>>, CmsError> {
        let Some(attrs) = self.info.unsigned_attrs else {
            return Ok(None);
        };
        for tlv in attrs.tlvs()? {
            let attr = Attribute::from_der(tlv)?;
            if attr.attr_type == oid::TIME_STAMP_TOKEN {
                return Ok(Some(single_value(attr, self.index)?.to_der()?));
            }
        }
        Ok(None)
    }

    fn malformed(&self, what: &str) -> CmsError {
        CmsError::Malformed(format!("signer {}: {what}", self.index))
    }
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
    use crate::cms::sign::{SignOptions, sign_content, signed_attributes};
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

    /// One-signer CMS whose signed attributes name `attrs_cert` and are signed by `e`.
    fn cms_with_attrs_for(e: &KeyEntry, attrs_cert: &Certificate, content: &[u8]) -> Vec<u8> {
        let alg = crate::info::cert_info(&e.cert).signing_alg().unwrap();
        let attrs = signed_attributes(
            &oid::DATA,
            opts().signing_time,
            &alg.digest(content),
            &attrs_cert.to_der().unwrap(),
        )
        .unwrap();
        let signature = e.key.sign(alg, &RawSet(&attrs).to_der().unwrap()).unwrap();
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
            signed_attrs: Some(RawSet(&attrs)),
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
        let signer = |info| Signer {
            index: 0,
            info,
            content_type: oid::DATA,
            content: b"",
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
