//! Signing and co-signing.

use super::CmsError;
use super::asn1::{
    Attribute, EncapsulatedContentInfo, EssCertIdV2, IssuerAndSerialNumber, RawSet,
    SignedContentInfo, SignedData, SignerInfo, SigningCertificateV2, der_set_contents,
};
use crate::ber;
use crate::info::cert_info;
use crate::key::HashAlg;
use crate::oid;
use crate::pkcs12::KeyEntry;
use der::asn1::{AnyRef, GeneralizedTime, Int, ObjectIdentifier, OctetStringRef, UtcTime};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierRef;
use std::time::Duration;
use time::OffsetDateTime;
use x509_cert::Certificate;

/// How to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignOptions {
    /// Put the content into the CMS (`eContent`); otherwise the signature is detached.
    pub encapsulate: bool,
    /// The data is already the digest: it goes into messageDigest as is, and is never
    /// treated as a CMS to co-sign.
    pub digested: bool,
    /// Value of the signingTime attribute.
    pub signing_time: OffsetDateTime,
}

/// Signs `data` with `entry`, returning a DER `ContentInfo{SignedData}`.
///
/// Unless `opts.digested`, data that is a CMS `SignedData` (DER or BER) is co-signed: its
/// encapsulated content is signed, its signers and certificates are kept and the new signer
/// is appended.
///
/// # Errors
///
/// - [`CmsError::NoEncapsulatedData`] when co-signing a CMS without encapsulated content;
/// - [`CmsError::Malformed`] when `data` is a `ContentInfo{id-signedData}` whose
///   `SignedData` cannot be read;
/// - [`CmsError::UnknownAlgorithm`] if the certificate's signature algorithm is unknown;
/// - [`CmsError::Key`] if the key cannot sign with it (e.g. a sha1WithRSA certificate).
pub fn sign(entry: &KeyEntry, data: &[u8], opts: &SignOptions) -> Result<Vec<u8>, CmsError> {
    let spec = SignSpec {
        content: if opts.digested {
            Content::Digest(data)
        } else {
            Content::Data(data)
        },
        encapsulate: opts.encapsulate,
        cosign: if opts.digested {
            CoSign::Never
        } else {
            CoSign::Auto
        },
        econtent_type: None,
        digest: None,
        attrs: AttrSpec::cades(opts.signing_time),
        certificates: CertSpec::Signer,
    };
    sign_spec(entry, &[], &spec)
}

/// Signs `content` of type `content_type` (written into both `eContentType` and the
/// contentType attribute). `opts.encapsulate` is ignored in favour of `encapsulate`;
/// `opts.digested` makes `content` the messageDigest value.
///
/// # Errors
///
/// As [`sign`].
#[cfg(any(test, feature = "testing"))]
pub(crate) fn sign_content(
    entry: &KeyEntry,
    content_type: &ObjectIdentifier,
    content: &[u8],
    encapsulate: bool,
    opts: &SignOptions,
) -> Result<Vec<u8>, CmsError> {
    let spec = SignSpec {
        content: if opts.digested {
            Content::Digest(content)
        } else {
            Content::Data(content)
        },
        encapsulate,
        cosign: CoSign::Never,
        econtent_type: Some(*content_type),
        digest: None,
        attrs: AttrSpec::cades(opts.signing_time),
        certificates: CertSpec::Signer,
    };
    sign_spec(entry, &[], &spec)
}

/// What a [`SignSpec`] signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Content<'a> {
    /// The content; messageDigest is its hash.
    Data(&'a [u8]),
    /// The content's hash, already computed: messageDigest as is. It is never encapsulated.
    Digest(&'a [u8]),
}

/// Whether a [`SignSpec`] adds its signer to an existing CMS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CoSign<'a> {
    /// As `createCAdES`: content that is itself a CMS `SignedData` (DER or BER) with
    /// encapsulated content gets co-signed — its content signed, its signers and
    /// certificates kept, the new signer appended.
    #[default]
    Auto,
    /// Never: the content is signed as it is.
    Never,
    /// Into this CMS (DER or BER): its signers and certificates kept, the new signer over
    /// the spec's content appended.
    Into(&'a [u8]),
}

/// How the signingTime attribute encodes its time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TimeForm {
    /// RFC 5652: UTCTime for 1950–2049, GeneralizedTime otherwise.
    #[default]
    Auto,
    /// UTCTime.
    Utc,
    /// GeneralizedTime.
    Generalized,
}

/// The signed attributes of a [`SignSpec`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttrSpec {
    /// contentType: the eContentType.
    pub content_type: bool,
    /// messageDigest.
    pub message_digest: bool,
    /// signingCertificateV2 with the SHA-256 of the signer certificate.
    pub signing_certificate_v2: bool,
    /// signingTime, if any, and its encoding.
    pub signing_time: Option<(OffsetDateTime, TimeForm)>,
    /// Other attributes: their type and values, each a DER value. None may be of a type
    /// the flags above add.
    pub extra: Vec<(ObjectIdentifier, Vec<Vec<u8>>)>,
}

impl AttrSpec {
    /// The attributes of `createCAdES`: contentType, signingTime at `signing_time`,
    /// messageDigest and signingCertificateV2.
    pub fn cades(signing_time: OffsetDateTime) -> Self {
        AttrSpec {
            content_type: true,
            message_digest: true,
            signing_certificate_v2: true,
            signing_time: Some((signing_time, TimeForm::Auto)),
            extra: Vec::new(),
        }
    }
}

/// The certificates a [`SignSpec`] puts into the CMS (besides those it co-signs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum CertSpec {
    /// The signer certificate.
    #[default]
    Signer,
    /// The signer's chain, as given to [`sign_spec`].
    Chain,
    /// The signer certificate and these.
    Extra(Vec<Certificate>),
}

/// A CMS signature as a client of the NCA services makes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignSpec<'a> {
    /// What is signed.
    pub content: Content<'a>,
    /// Put the content into the CMS (`eContent`); otherwise the signature is detached.
    pub encapsulate: bool,
    /// Co-signing.
    pub cosign: CoSign<'a>,
    /// The eContentType (and contentType attribute); `None`: id-data, or the co-signed
    /// CMS's.
    pub econtent_type: Option<ObjectIdentifier>,
    /// The digest algorithm; `None`: the certificate signature algorithm's. Another one
    /// than that is refused: the verifiers of the NCA services take only that pair.
    pub digest: Option<HashAlg>,
    /// The signed attributes; none at all signs the content itself.
    pub attrs: AttrSpec,
    /// The certificates.
    pub certificates: CertSpec,
}

/// Signs as `spec` says with `entry` (whose chain from it up is `chain`, for
/// [`CertSpec::Chain`]), returning a DER `ContentInfo{SignedData}`.
///
/// # Errors
///
/// - [`CmsError::NoEncapsulatedData`] when co-signing a CMS without encapsulated content
///   automatically;
/// - [`CmsError::Malformed`] when the CMS to co-sign cannot be read, or an extra
///   attribute value is not DER;
/// - [`CmsError::Constraint`] for a spec that cannot be met: another digest than the
///   certificate's, an extra attribute the flags add too, a digest to sign without signed
///   attributes or to encapsulate;
/// - [`CmsError::UnknownAlgorithm`] if the certificate's signature algorithm is unknown;
/// - [`CmsError::Key`] if the key cannot sign with it (e.g. a sha1WithRSA certificate).
pub fn sign_spec(
    entry: &KeyEntry,
    chain: &[Certificate],
    spec: &SignSpec<'_>,
) -> Result<Vec<u8>, CmsError> {
    let base_der = match spec.cosign {
        CoSign::Into(cms) => Some(ber::to_der(cms)?),
        CoSign::Auto => match spec.content {
            Content::Data(data) => ber::to_der(data).ok().filter(|der| {
                super::asn1::ContentInfo::from_der(der)
                    .is_ok_and(|ci| ci.content_type == oid::SIGNED_DATA)
            }),
            Content::Digest(_) => None,
        },
        CoSign::Never => None,
    };
    let base = match &base_der {
        Some(der) => {
            let content_info = super::asn1::ContentInfo::from_der(der)?;
            if content_info.content_type != oid::SIGNED_DATA {
                return Err(CmsError::Malformed(format!(
                    "content type {} is not signedData",
                    content_info.content_type
                )));
            }
            Some(content_info.content.decode_as::<SignedData<'_>>()?)
        }
        None => None,
    };
    let (content, content_type) = match (&spec.cosign, &base) {
        (CoSign::Auto, Some(base)) => {
            let encap = base.encap_content_info;
            let content = encap.e_content.ok_or(CmsError::NoEncapsulatedData)?;
            (
                Content::Data(content.as_bytes()),
                spec.econtent_type.unwrap_or(encap.e_content_type),
            )
        }
        (_, Some(base)) => (
            spec.content,
            spec.econtent_type
                .unwrap_or(base.encap_content_info.e_content_type),
        ),
        (_, None) => (spec.content, spec.econtent_type.unwrap_or(oid::DATA)),
    };
    build(entry, chain, spec, &content_type, content, base.as_ref())
}

/// Builds the `ContentInfo` of `spec` over `content`, appending the new signer to `base`
/// when co-signing.
fn build(
    entry: &KeyEntry,
    chain: &[Certificate],
    spec: &SignSpec<'_>,
    content_type: &ObjectIdentifier,
    content: Content<'_>,
    base: Option<&SignedData<'_>>,
) -> Result<Vec<u8>, CmsError> {
    let alg = cert_info(&entry.cert)
        .signing_alg()
        .map_err(|e| CmsError::UnknownAlgorithm(e.0))?;
    if spec.digest.is_some_and(|digest| digest != alg.hash_alg()) {
        return Err(CmsError::Constraint(format!(
            "the digest of a {alg:?} signature is {:?}",
            alg.hash_alg()
        )));
    }
    let digest = match content {
        Content::Data(data) => alg.digest(data),
        Content::Digest(digest) => digest.to_vec(),
    };
    let cert_der = entry.cert.to_der()?;
    let attrs = signed_attributes(&spec.attrs, content_type, &digest, &cert_der)?;
    let signature = match (&attrs, content) {
        (Some(attrs), _) => entry.key.sign(alg, &RawSet(attrs).to_der()?),
        (None, Content::Data(data)) => entry.key.sign(alg, data),
        (None, Content::Digest(_)) => {
            return Err(CmsError::Constraint(
                "a digest is signed only through signed attributes".to_owned(),
            ));
        }
    }
    .map_err(CmsError::Key)?;

    let tbs = entry.cert.tbs_certificate();
    let sid = IssuerAndSerialNumber {
        issuer: tbs.issuer().clone(),
        serial_number: Int::new(tbs.serial_number().as_bytes())?,
    }
    .to_der()?;
    let digest_algorithm = AlgorithmIdentifierRef {
        oid: alg.digest_oid(),
        parameters: Some(AnyRef::NULL),
    };
    let signer_info = SignerInfo {
        version: 1,
        sid: AnyRef::from_der(&sid)?,
        digest_algorithm,
        signed_attrs: attrs.as_deref().map(RawSet),
        signature_algorithm: AlgorithmIdentifierRef {
            oid: alg.signature_oid(),
            parameters: Some(AnyRef::NULL),
        },
        signature: OctetStringRef::new(&signature)?,
        unsigned_attrs: None,
    }
    .to_der()?;
    let digest_algorithm = digest_algorithm.to_der()?;

    let mut digest_algorithms = Vec::new();
    let mut certificates = Vec::new();
    let mut signer_infos = Vec::new();
    if let Some(base) = base {
        digest_algorithms.extend_from_slice(base.digest_algorithms.0);
        if let Some(certs) = base.certificates {
            certificates.extend_from_slice(certs.0);
        }
        signer_infos.extend_from_slice(base.signer_infos.0);
    }
    let digest_known = base.is_some_and(|b| {
        b.digest_algorithms.tlvs().is_ok_and(|algs| {
            algs.iter().any(|a| {
                AlgorithmIdentifierRef::from_der(a).is_ok_and(|a| a.oid == alg.digest_oid())
            })
        })
    });
    if !digest_known {
        digest_algorithms.extend_from_slice(&digest_algorithm);
    }
    let mut added = vec![cert_der];
    match &spec.certificates {
        CertSpec::Signer => {}
        CertSpec::Chain => {
            for cert in chain {
                added.push(cert.to_der()?);
            }
        }
        CertSpec::Extra(extra) => {
            for cert in extra {
                added.push(cert.to_der()?);
            }
        }
    }
    for cert in added {
        if !RawSet(&certificates).tlvs()?.contains(&cert.as_slice()) {
            certificates.extend_from_slice(&cert);
        }
    }
    signer_infos.extend_from_slice(&signer_info);

    let encapsulated = match (spec.encapsulate, content) {
        (false, _) => None,
        (true, Content::Data(data)) => Some(OctetStringRef::new(data)?),
        (true, Content::Digest(_)) => {
            return Err(CmsError::Constraint(
                "a digest cannot be the encapsulated content".to_owned(),
            ));
        }
    };
    // RFC 5652 §5.1: v3 when eContentType is not id-data (e.g. a TSTInfo), else v1; a
    // co-signature never lowers the existing version.
    let version = if *content_type == oid::DATA { 1 } else { 3 };
    let signed_data = SignedData {
        version: base.map_or(version, |b| b.version.max(version)),
        digest_algorithms: RawSet(&digest_algorithms),
        encap_content_info: EncapsulatedContentInfo {
            e_content_type: *content_type,
            e_content: encapsulated,
        },
        certificates: Some(RawSet(&certificates)),
        crls: base.and_then(|b| b.crls),
        signer_infos: RawSet(&signer_infos),
    };
    Ok(SignedContentInfo {
        signed_data: &signed_data,
    }
    .to_der()?)
}

/// Contents of the DER `SET OF Attribute` of the signed attributes of `spec`; `None`
/// without any.
pub(super) fn signed_attributes(
    spec: &AttrSpec,
    content_type: &ObjectIdentifier,
    digest: &[u8],
    cert_der: &[u8],
) -> Result<Option<Vec<u8>>, CmsError> {
    let mut values: Vec<(ObjectIdentifier, Vec<u8>)> = Vec::new();
    if spec.content_type {
        values.push((oid::CONTENT_TYPE, content_type.to_der()?));
    }
    if let Some((time, form)) = spec.signing_time {
        values.push((oid::SIGNING_TIME, encode_time(time, form)?));
    }
    if spec.message_digest {
        values.push((oid::MESSAGE_DIGEST, OctetStringRef::new(digest)?.to_der()?));
    }
    if spec.signing_certificate_v2 {
        let cert_hash = Sha256::digest(cert_der);
        let signing_certificate = SigningCertificateV2 {
            certs: vec![EssCertIdV2 {
                hash_algorithm: None,
                cert_hash: OctetStringRef::new(&cert_hash)?,
                issuer_serial: None,
            }],
            policies: None,
        };
        values.push((oid::SIGNING_CERTIFICATE_V2, signing_certificate.to_der()?));
    }
    let mut attributes = Vec::new();
    for (attr_type, value) in &values {
        attributes.push(
            Attribute {
                attr_type: *attr_type,
                attr_values: RawSet(value),
            }
            .to_der()?,
        );
    }
    for (attr_type, extra) in &spec.extra {
        if values.iter().any(|(t, _)| t == attr_type) {
            return Err(CmsError::Constraint(format!(
                "attribute {attr_type} is already added"
            )));
        }
        let mut encoded = Vec::new();
        for value in extra {
            der::asn1::AnyRef::from_der(value).map_err(|e| {
                CmsError::Malformed(format!("a value of attribute {attr_type}: {e}"))
            })?;
            encoded.push(value.clone());
        }
        let set = der_set_contents(encoded);
        attributes.push(
            Attribute {
                attr_type: *attr_type,
                attr_values: RawSet(&set),
            }
            .to_der()?,
        );
    }
    Ok((!attributes.is_empty()).then(|| der_set_contents(attributes)))
}

/// `Time` of signingTime in `form`. Fractions of a second are dropped.
fn encode_time(t: OffsetDateTime, form: TimeForm) -> Result<Vec<u8>, CmsError> {
    let secs = u64::try_from(t.unix_timestamp())
        .map_err(|_| CmsError::Malformed(format!("signing time {t} is before 1970")))?;
    let since_epoch = Duration::from_secs(secs);
    let utc = match form {
        TimeForm::Auto => t.year() < 2050,
        TimeForm::Utc => true,
        TimeForm::Generalized => false,
    };
    Ok(if utc {
        UtcTime::from_unix_duration(since_epoch)?.to_der()?
    } else {
        GeneralizedTime::from_unix_duration(since_epoch)?.to_der()?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_encoding_switches_at_2050() {
        use time::macros::datetime;
        let utc = encode_time(datetime!(2049-12-31 23:59:59.75 UTC), TimeForm::Auto).unwrap();
        assert_eq!(utc, b"\x17\x0d491231235959Z");
        let generalized = encode_time(datetime!(2050-01-01 0:00 UTC), TimeForm::Auto).unwrap();
        assert_eq!(generalized, b"\x18\x0f20500101000000Z");
        assert!(matches!(
            encode_time(datetime!(1969-12-31 23:59:59 UTC), TimeForm::Auto),
            Err(CmsError::Malformed(_))
        ));
    }

    #[test]
    fn signed_data_version_follows_content_type() {
        use crate::pkcs12::load;
        use oncl_testkit::{read, synthetic};
        use time::macros::datetime;

        let key = synthetic("tsa-gost2015");
        let e = load(&read(&key.path), &key.password)
            .unwrap()
            .swap_remove(0);
        let opts = SignOptions {
            encapsulate: true,
            digested: false,
            signing_time: datetime!(2026-03-01 10:00 UTC),
        };
        let version = |cms: &[u8]| {
            let ci = super::super::asn1::ContentInfo::from_der(cms).unwrap();
            ci.content.decode_as::<SignedData<'_>>().unwrap().version
        };
        // RFC 5652 §5.1: v1 for id-data, v3 for any other eContentType.
        let data = sign_content(&e, &oid::DATA, b"x", true, &opts).unwrap();
        assert_eq!(version(&data), 1);
        let tst = sign_content(&e, &oid::TST_INFO, b"x", true, &opts).unwrap();
        assert_eq!(version(&tst), 3);
        // A co-signature keeps v3.
        assert_eq!(version(&sign(&e, &tst, &opts).unwrap()), 3);
    }
}
