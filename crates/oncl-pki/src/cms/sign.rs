//! Signing and co-signing.

use super::CmsError;
use super::asn1::{
    Attribute, EncapsulatedContentInfo, EssCertIdV2, IssuerAndSerialNumber, RawSet,
    SignedContentInfo, SignedData, SignerInfo, SigningCertificateV2, der_set_contents,
};
use crate::ber;
use crate::info::cert_info;
use crate::oid;
use crate::pkcs12::KeyEntry;
use der::asn1::{AnyRef, GeneralizedTime, Int, ObjectIdentifier, OctetStringRef, UtcTime};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierRef;
use std::time::Duration;
use time::OffsetDateTime;

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
    if !opts.digested
        && let Ok(der) = ber::to_der(data)
        && let Ok(content_info) = super::asn1::ContentInfo::from_der(&der)
        && content_info.content_type == oid::SIGNED_DATA
    {
        let existing: SignedData<'_> = content_info.content.decode_as()?;
        let encap = existing.encap_content_info;
        let content = encap.e_content.ok_or(CmsError::NoEncapsulatedData)?;
        return build(
            entry,
            &encap.e_content_type,
            content.as_bytes(),
            opts.encapsulate,
            opts,
            Some(&existing),
        );
    }
    sign_content(entry, &oid::DATA, data, opts.encapsulate, opts)
}

/// Signs `content` of type `content_type` (written into both `eContentType` and the
/// contentType attribute). `opts.encapsulate` is ignored in favour of `encapsulate`;
/// `opts.digested` makes `content` the messageDigest value.
///
/// # Errors
///
/// As [`sign`].
pub(crate) fn sign_content(
    entry: &KeyEntry,
    content_type: &ObjectIdentifier,
    content: &[u8],
    encapsulate: bool,
    opts: &SignOptions,
) -> Result<Vec<u8>, CmsError> {
    build(entry, content_type, content, encapsulate, opts, None)
}

/// Builds the `ContentInfo`, appending the new signer to `base` when co-signing.
fn build(
    entry: &KeyEntry,
    content_type: &ObjectIdentifier,
    content: &[u8],
    encapsulate: bool,
    opts: &SignOptions,
    base: Option<&SignedData<'_>>,
) -> Result<Vec<u8>, CmsError> {
    let alg = cert_info(&entry.cert)
        .signing_alg()
        .map_err(|e| CmsError::UnknownAlgorithm(e.0))?;
    let digest = if opts.digested {
        content.to_vec()
    } else {
        alg.digest(content)
    };
    let cert_der = entry.cert.to_der()?;
    let attrs = signed_attributes(content_type, opts.signing_time, &digest, &cert_der)?;
    let signature = entry
        .key
        .sign(alg, &RawSet(&attrs).to_der()?)
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
        signed_attrs: Some(RawSet(&attrs)),
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
    if !RawSet(&certificates).tlvs()?.contains(&cert_der.as_slice()) {
        certificates.extend_from_slice(&cert_der);
    }
    signer_infos.extend_from_slice(&signer_info);

    // RFC 5652 §5.1: v3 when eContentType is not id-data (e.g. a TSTInfo), else v1; a
    // co-signature never lowers the existing version.
    let version = if *content_type == oid::DATA { 1 } else { 3 };
    let signed_data = SignedData {
        version: base.map_or(version, |b| b.version.max(version)),
        digest_algorithms: RawSet(&digest_algorithms),
        encap_content_info: EncapsulatedContentInfo {
            e_content_type: *content_type,
            e_content: if encapsulate {
                Some(OctetStringRef::new(content)?)
            } else {
                None
            },
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

/// Contents of the DER `SET OF Attribute` of signed attributes.
pub(super) fn signed_attributes(
    content_type: &ObjectIdentifier,
    signing_time: OffsetDateTime,
    digest: &[u8],
    cert_der: &[u8],
) -> Result<Vec<u8>, CmsError> {
    let cert_hash = Sha256::digest(cert_der);
    let signing_certificate = SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            hash_algorithm: None,
            cert_hash: OctetStringRef::new(&cert_hash)?,
            issuer_serial: None,
        }],
        policies: None,
    };
    let values = [
        (oid::CONTENT_TYPE, content_type.to_der()?),
        (oid::SIGNING_TIME, encode_time(signing_time)?),
        (oid::MESSAGE_DIGEST, OctetStringRef::new(digest)?.to_der()?),
        (oid::SIGNING_CERTIFICATE_V2, signing_certificate.to_der()?),
    ];
    let attributes = values
        .iter()
        .map(|(attr_type, value)| {
            Attribute {
                attr_type: *attr_type,
                attr_values: RawSet(value),
            }
            .to_der()
        })
        .collect::<der::Result<Vec<_>>>()?;
    Ok(der_set_contents(attributes))
}

/// `Time` as RFC 5652 wants it for signingTime: UTCTime for 1950–2049, else
/// GeneralizedTime. Fractions of a second are dropped.
fn encode_time(t: OffsetDateTime) -> Result<Vec<u8>, CmsError> {
    let secs = u64::try_from(t.unix_timestamp())
        .map_err(|_| CmsError::Malformed(format!("signing time {t} is before 1970")))?;
    let since_epoch = Duration::from_secs(secs);
    Ok(if t.year() < 2050 {
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
        let utc = encode_time(datetime!(2049-12-31 23:59:59.75 UTC)).unwrap();
        assert_eq!(utc, b"\x17\x0d491231235959Z");
        let generalized = encode_time(datetime!(2050-01-01 0:00 UTC)).unwrap();
        assert_eq!(generalized, b"\x18\x0f20500101000000Z");
        assert!(matches!(
            encode_time(datetime!(1969-12-31 23:59:59 UTC)),
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
