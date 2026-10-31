//! The ESEDO CMS profile and its relatives, as data: a detached CMS whose signed attributes
//! name the signed files (1.2.840.113549.1.9.77), carry the signer's DN
//! (1.3.6.1.4.1.6801.2.8), a description (signingDescription) and an OCSP answer
//! (1.3.6.1.5.5.7.48.1.1), plus the OCSP request made before it.
//!
//! Each port keeps its [`Profile`] (and [`OcspRequest`]) as a constant in its own crate;
//! this module only turns a profile and an [`EsedoInput`] into the arguments of the host
//! functions: [`signed_attrs`] and [`sign_args`] for `keys_sign_cms_ex`, [`ocsp_args`] for
//! `ocsp_fetch`. Time-stamps stay with the ports (`tsp_stamp`, or
//! [`SignCmsExArgs::timestamp`] on the returned arguments).

use crate::{attr, x509text};
use der::{Decode, Encode};
use oncl_pdk::abi::{
    Bytes, CmsCerts, CmsContent, CoSign, HashAlg, IssuerSel, Nonce, OcspArgs, OcspOutcome,
    PkiMethod, PkiUrl, RawAttribute, SignCmsExArgs, SignedAttrs, SigningTime, TimeForm, TimeSource,
};
use x509_cert::Certificate;

/// 1.2.840.113549.1.9.77: the names of the signed files, a UTF8String.
pub const FILE_NAMES: &str = "1.2.840.113549.1.9.77";
/// 1.3.6.1.4.1.6801.2.8: the signer's DN, a Name.
pub const SIGNER_DN: &str = "1.3.6.1.4.1.6801.2.8";
/// 1.2.840.113549.1.9.13: signingDescription.
pub const SIGNING_DESCRIPTION: &str = "1.2.840.113549.1.9.13";
/// 1.3.6.1.5.5.7.48.1.1 (the OID of id-pkix-ocsp-basic): the OCSP answer.
pub const OCSP_ANSWER: &str = "1.3.6.1.5.5.7.48.1.1";

/// What the CMS signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentMode {
    /// The data: the host hashes it into messageDigest.
    Data,
    /// The data is the hash: messageDigest as it is.
    Digest,
    /// As [`EsedoInput::hashed`] says.
    AsAsked,
}

/// Whether the CMS carries the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encapsulate {
    /// Detached.
    Never,
    /// Attached.
    Always,
    /// As [`EsedoInput::attached`] says.
    AsAsked,
}

/// Where the signingTime comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeFrom {
    /// The core's clock at signing.
    Now,
    /// producedAt of the OCSP answer ([`OcspAnswer::produced_at_ms`]).
    OcspProducedAt,
    /// genTime of a time-stamp taken before signing ([`EsedoInput::tsp_gen_time_ms`]).
    TspGenTime,
}

/// The signingTime attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningTimeRule {
    /// When.
    pub from: TimeFrom,
    /// UTCTime, GeneralizedTime, or by year (`Auto`: Kalkan's `Time`).
    pub form: TimeForm,
}

/// The file-names attribute: [`EsedoInput::file_names`] joined, as a UTF8String.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileNames {
    /// What goes between two names (`<>` by the ESEDO convention).
    pub separator: &'static str,
    /// Leave the attribute out when the joined text is blank (only whitespace).
    pub omit_blank: bool,
}

/// How the signer's DN attribute is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerDn {
    /// `new X509Name(cert.getSubjectDN().getName())`: Kalkan's DN text
    /// ([`EsedoInput::kalkan_dn`], `cert_details().subject_dn`) parsed again.
    Kalkan,
    /// `new X509Name(cert.getSubjectX500Principal().getName())`: the RFC 2253 text parsed in
    /// its order, which reverses the RDNs.
    Rfc2253Reversed,
    /// The certificate's subject as it is (`X509Principal`, `getEncoded()` of the subject).
    Encoded,
}

/// The string type of a text value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringKind {
    /// PrintableString of the bytes as they are (a NUL kept).
    Printable,
    /// UTF8String.
    Utf8,
}

/// The signingDescription attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Description {
    /// The text: `ESEDO`, `ESEDO\0`, `ESEDO ` (with its space).
    pub text: &'static str,
    /// Its string type.
    pub kind: StringKind,
}

/// The value of the OCSP attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspForm {
    /// OCTET STRING { the whole `OCSPResponse` }.
    OctetResponse,
    /// OCTET STRING { its `BasicOCSPResponse` }.
    OctetBasic,
    /// The `BasicOCSPResponse` itself as the value in the SET.
    BareBasic,
}

/// Where the issuer of the OCSP `CertID` comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerRule {
    /// Among the core's CAs.
    HostCas,
    /// The certificate the port gives (bundled, from `ca_list`, from the page).
    Given,
    /// The first of the certificates the port gives whose key verifies the signer's.
    VerifiesCert,
}

/// The hash of the OCSP `CertID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertIdHash {
    /// This one.
    Fixed(HashAlg),
    /// By the issuer's issuer DN: containing `GOST` → GOST 34.311-95; containing `RSA` →
    /// GOST 34.311 GT, which the core has not; otherwise a GOST `CertID` of other
    /// parameters, which it has not either.
    ByIssuerIssuerDn,
}

/// The OCSP responder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspUrl {
    /// `http://ocsp.pki.gov.kz`.
    Default,
    /// The certificate's authorityInfoAccess.
    FromCert,
    /// This URL.
    Fixed(&'static str),
}

/// The OCSP request made before signing, as `ocsp_fetch` takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspRequest {
    /// The issuer of the `CertID`.
    pub issuer: IssuerRule,
    /// The hash of the `CertID`.
    pub cert_id_hash: CertIdHash,
    /// The nonce extension.
    pub nonce: Nonce,
    /// The binding.
    pub method: PkiMethod,
    /// The responder.
    pub url: OcspUrl,
    /// Timeout, at most `MAX_PKI_TIMEOUT_MS` (that one where the original waited forever).
    pub timeout_ms: u32,
    /// The core checks the answer (responder, signature, freshness, nonce).
    pub check: bool,
}

/// A plugin's CMS: the content, the signed attributes and the OCSP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The eContentType (and the contentType attribute's value), a dotted OID; `None`:
    /// id-data.
    pub econtent_type: Option<&'static str>,
    /// What is signed.
    pub content: ContentMode,
    /// The digest; `None`: the certificate's (the host accepts no other).
    pub digest: Option<HashAlg>,
    /// Attached or detached.
    pub encapsulate: Encapsulate,
    /// Co-signing a CMS given as the content.
    pub cosign: CoSign,
    /// The certificates.
    pub certificates: CmsCerts,
    /// The contentType attribute.
    pub content_type: bool,
    /// The signingCertificateV2 attribute.
    pub signing_certificate_v2: bool,
    /// The signingTime attribute.
    pub signing_time: Option<SigningTimeRule>,
    /// The file-names attribute.
    pub file_names: Option<FileNames>,
    /// The signer's DN attribute.
    pub signer_dn: Option<SignerDn>,
    /// The signingDescription attribute.
    pub description: Option<Description>,
    /// The OCSP attribute, when [`EsedoInput::ocsp`] has an answer.
    pub ocsp: Option<OcspForm>,
    /// The OCSP request before signing; `None`: the answer comes from elsewhere (the page)
    /// or there is none.
    pub ocsp_request: Option<OcspRequest>,
}

/// An OCSP answer for the attribute.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OcspAnswer<'a> {
    /// The `OCSPResponse`.
    pub response: &'a [u8],
    /// Its `BasicOCSPResponse`.
    pub basic: Option<&'a [u8]>,
    /// producedAt, Unix milliseconds.
    pub produced_at_ms: Option<i64>,
}

impl<'a> OcspAnswer<'a> {
    /// The answer `ocsp_fetch` came to; `None` if it got none.
    pub fn from_outcome(outcome: &'a OcspOutcome) -> Option<OcspAnswer<'a>> {
        match outcome {
            OcspOutcome::Ok {
                response,
                basic,
                produced_at_ms,
                ..
            } => Some(OcspAnswer {
                response,
                basic: basic.as_ref().map(|basic| basic.as_slice()),
                produced_at_ms: *produced_at_ms,
            }),
            OcspOutcome::Failed(_) => None,
        }
    }
}

/// What one signature takes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EsedoInput<'a> {
    /// The signer's certificate, DER.
    pub cert: &'a [u8],
    /// Its subject as Kalkan writes it (`cert_details().subject_dn`), for
    /// [`SignerDn::Kalkan`].
    pub kalkan_dn: Option<&'a str>,
    /// The file names, joined by [`FileNames::separator`]; one name for a text the page
    /// joined itself.
    pub file_names: &'a [&'a str],
    /// The OCSP answer; `None` leaves the attribute out.
    pub ocsp: Option<OcspAnswer<'a>>,
    /// genTime of a time-stamp taken before signing, Unix milliseconds.
    pub tsp_gen_time_ms: Option<i64>,
    /// The content, or its hash.
    pub data: &'a [u8],
    /// `data` is the hash, for [`ContentMode::AsAsked`].
    pub hashed: bool,
    /// Attach the content, for [`Encapsulate::AsAsked`].
    pub attached: bool,
}

/// The signed attributes of `profile` for `input`: messageDigest always, the flags of the
/// profile, and the ESEDO attributes as DER values (the host sorts the SET).
///
/// # Errors
///
/// What the profile needs and `input` lacks: Kalkan's DN, a `BasicOCSPResponse`, a
/// producedAt or a genTime; a certificate or DN that does not parse.
pub fn signed_attrs(profile: &Profile, input: &EsedoInput) -> Result<SignedAttrs, String> {
    let mut extra = Vec::new();
    if let Some(rule) = profile.file_names {
        let joined = input.file_names.join(rule.separator);
        if !(rule.omit_blank && joined.trim().is_empty()) {
            extra.push(raw(FILE_NAMES, attr::utf8(&joined)));
        }
    }
    if let (Some(form), Some(answer)) = (profile.ocsp, &input.ocsp) {
        let basic = || {
            answer
                .basic
                .ok_or_else(|| "the OCSP answer has no BasicOCSPResponse".to_owned())
        };
        let value = match form {
            OcspForm::OctetResponse => attr::octets(answer.response),
            OcspForm::OctetBasic => attr::octets(basic()?),
            OcspForm::BareBasic => basic()?.to_vec(),
        };
        extra.push(raw(OCSP_ANSWER, value));
    }
    if let Some(form) = profile.signer_dn {
        let name = match form {
            SignerDn::Kalkan => attr::x509_name_from_kalkan_dn(
                input
                    .kalkan_dn
                    .ok_or_else(|| "no Kalkan DN of the signer".to_owned())?,
            )?,
            SignerDn::Rfc2253Reversed => {
                attr::x509_name_from_rfc2253(&x509text::rfc2253(&subject(input.cert)?)?)?
            }
            SignerDn::Encoded => subject(input.cert)?,
        };
        extra.push(raw(SIGNER_DN, name));
    }
    if let Some(description) = profile.description {
        let value = match description.kind {
            StringKind::Printable => attr::printable(description.text.as_bytes()),
            StringKind::Utf8 => attr::utf8(description.text),
        };
        extra.push(raw(SIGNING_DESCRIPTION, value));
    }
    let signing_time = match profile.signing_time {
        None => None,
        Some(rule) => {
            let at = match rule.from {
                TimeFrom::Now => TimeSource::Now,
                TimeFrom::OcspProducedAt => TimeSource::UnixMs(
                    input
                        .ocsp
                        .and_then(|answer| answer.produced_at_ms)
                        .ok_or_else(|| "no producedAt of an OCSP answer".to_owned())?,
                ),
                TimeFrom::TspGenTime => TimeSource::UnixMs(
                    input
                        .tsp_gen_time_ms
                        .ok_or_else(|| "no genTime of a time-stamp".to_owned())?,
                ),
            };
            Some(SigningTime {
                at,
                form: rule.form,
            })
        }
    };
    Ok(SignedAttrs {
        content_type: profile.content_type,
        message_digest: true,
        signing_certificate_v2: profile.signing_certificate_v2,
        signing_time,
        extra,
    })
}

/// The arguments of `keys_sign_cms_ex` for `profile`, `input` and the key `handle`, without
/// a time-stamp.
///
/// # Errors
///
/// As [`signed_attrs`].
pub fn sign_args(
    profile: &Profile,
    input: &EsedoInput,
    handle: u32,
) -> Result<SignCmsExArgs, String> {
    let hashed = match profile.content {
        ContentMode::Data => false,
        ContentMode::Digest => true,
        ContentMode::AsAsked => input.hashed,
    };
    let data = Bytes::from(input.data.to_vec());
    Ok(SignCmsExArgs {
        handle,
        content: if hashed {
            CmsContent::Digest(data)
        } else {
            CmsContent::Data(data)
        },
        encapsulate: match profile.encapsulate {
            Encapsulate::Never => false,
            Encapsulate::Always => true,
            Encapsulate::AsAsked => input.attached,
        },
        cosign: profile.cosign.clone(),
        econtent_type: profile.econtent_type.map(str::to_owned),
        digest: profile.digest,
        attrs: signed_attrs(profile, input)?,
        certificates: profile.certificates.clone(),
        timestamp: None,
        output: oncl_pdk::abi::CmsOutput::Der,
    })
}

/// The arguments of `ocsp_fetch` for `request` about `cert`. `issuers` are the issuer
/// ([`IssuerRule::Given`]) or the candidates ([`IssuerRule::VerifiesCert`]); with
/// [`CertIdHash::ByIssuerIssuerDn`] the first of them is the issuer whose issuer decides
/// the hash, whatever the rule.
///
/// # Errors
///
/// No issuer where one is needed; an issuer that does not parse; a `CertID` hash the core
/// has not.
pub fn ocsp_args(
    request: &OcspRequest,
    cert: &[u8],
    issuers: &[&[u8]],
) -> Result<OcspArgs, String> {
    let first = || {
        issuers
            .first()
            .copied()
            .ok_or_else(|| "no issuer certificate".to_owned())
    };
    let cert_id_hash = match request.cert_id_hash {
        CertIdHash::Fixed(alg) => alg,
        CertIdHash::ByIssuerIssuerDn => {
            let issuer = Certificate::from_der(first()?).map_err(|e| e.to_string())?;
            let dn = x509text::rfc2253(
                &issuer
                    .tbs_certificate()
                    .issuer()
                    .to_der()
                    .map_err(|e| e.to_string())?,
            )?;
            hash_by_issuer_dn(&dn)?
        }
    };
    let issuer = match request.issuer {
        IssuerRule::HostCas => IssuerSel::HostCas,
        IssuerRule::Given => IssuerSel::Given(Bytes::from(first()?.to_vec())),
        IssuerRule::VerifiesCert => {
            first()?;
            IssuerSel::VerifiesCert(issuers.iter().map(|c| Bytes::from(c.to_vec())).collect())
        }
    };
    Ok(OcspArgs {
        cert: Bytes::from(cert.to_vec()),
        issuer,
        cert_id_hash,
        nonce: request.nonce.clone(),
        url: match request.url {
            OcspUrl::Default => PkiUrl::Default,
            OcspUrl::FromCert => PkiUrl::FromCert(Bytes::from(cert.to_vec())),
            OcspUrl::Fixed(url) => PkiUrl::Fixed(url.to_owned()),
        },
        method: request.method.clone(),
        timeout_ms: request.timeout_ms,
        check: request.check,
    })
}

/// The `CertID` hash for an issuer whose issuer is `dn` ([`CertIdHash::ByIssuerIssuerDn`]).
fn hash_by_issuer_dn(dn: &str) -> Result<HashAlg, String> {
    if dn.contains("GOST") {
        Ok(HashAlg::Gost34311)
    } else if dn.contains("RSA") {
        Err("the CertID hash GOST 34.311 GT is not supported".to_owned())
    } else {
        Err("the GOST CertID of other parameters is not supported".to_owned())
    }
}

/// A signed attribute of one value.
fn raw(oid: &str, value: Vec<u8>) -> RawAttribute {
    RawAttribute {
        oid: oid.to_owned(),
        values: vec![Bytes::from(value)],
    }
}

/// The DER of the subject of the certificate `cert`.
fn subject(cert: &[u8]) -> Result<Vec<u8>, String> {
    Certificate::from_der(cert)
        .map_err(|e| e.to_string())?
        .tbs_certificate()
        .subject()
        .to_der()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv;
    use oncl_pdk::abi::{MAX_PKI_TIMEOUT_MS, TsaChoice};

    const SIGNER: &[u8] = include_bytes!("../../../../fixtures/synthetic/inter-gost2015.cer");
    const ROOT_GOST: &[u8] = include_bytes!("../../../../fixtures/synthetic/root-gost2015.cer");
    const ROOT_RSA: &[u8] = include_bytes!("../../../../fixtures/synthetic/root-rsa.cer");
    const SIGNER_KALKAN_DN: &str = "CN=SYNTHETIC NCA (GOST) 2015,C=KZ";
    /// An `OCSPResponse` and a `BasicOCSPResponse` stand-in: the attribute takes them as
    /// they are.
    const RESPONSE: &[u8] = &[0x30, 0x03, 0x0a, 0x01, 0x00];
    const BASIC: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x07];

    /// bas: eContentType 6801.11.1.9, UTCTime, Kalkan DN, `ESEDO\0`, OCTET{OCSPResponse}.
    const BAS: Profile = Profile {
        econtent_type: Some("1.3.6.1.4.1.6801.11.1.9"),
        content: ContentMode::Data,
        digest: None,
        encapsulate: Encapsulate::Never,
        cosign: CoSign::Never,
        certificates: CmsCerts::Signer,
        content_type: true,
        signing_certificate_v2: false,
        signing_time: Some(SigningTimeRule {
            from: TimeFrom::Now,
            form: TimeForm::Utc,
        }),
        file_names: Some(FileNames {
            separator: "<>",
            omit_blank: false,
        }),
        signer_dn: Some(SignerDn::Kalkan),
        description: Some(Description {
            text: "ESEDO\0",
            kind: StringKind::Printable,
        }),
        ocsp: Some(OcspForm::OctetResponse),
        ocsp_request: Some(OcspRequest {
            issuer: IssuerRule::HostCas,
            cert_id_hash: CertIdHash::Fixed(HashAlg::Sha256),
            nonce: Nonce::None,
            method: PkiMethod::Post { content_type: None },
            url: OcspUrl::Default,
            timeout_ms: MAX_PKI_TIMEOUT_MS,
            check: false,
        }),
    };

    /// metadoc: signingTime = producedAt, the subject as encoded, `ESEDO ` UTF8.
    const METADOC: Profile = Profile {
        econtent_type: None,
        content: ContentMode::AsAsked,
        digest: None,
        encapsulate: Encapsulate::Never,
        cosign: CoSign::Never,
        certificates: CmsCerts::Signer,
        content_type: true,
        signing_certificate_v2: false,
        signing_time: Some(SigningTimeRule {
            from: TimeFrom::OcspProducedAt,
            form: TimeForm::Utc,
        }),
        file_names: Some(FileNames {
            separator: "<>",
            omit_blank: false,
        }),
        signer_dn: Some(SignerDn::Encoded),
        description: Some(Description {
            text: "ESEDO ",
            kind: StringKind::Utf8,
        }),
        ocsp: Some(OcspForm::OctetResponse),
        ocsp_request: Some(OcspRequest {
            issuer: IssuerRule::HostCas,
            cert_id_hash: CertIdHash::ByIssuerIssuerDn,
            nonce: Nonce::Random(16),
            method: PkiMethod::GetUnder(256),
            url: OcspUrl::FromCert,
            timeout_ms: 10_000,
            check: false,
        }),
    };

    /// dogovor24: GeneralizedTime, the RFC 2253 DN parsed again (reversed).
    const DOGOVOR24: Profile = Profile {
        signing_time: Some(SigningTimeRule {
            from: TimeFrom::Now,
            form: TimeForm::Generalized,
        }),
        signer_dn: Some(SignerDn::Rfc2253Reversed),
        econtent_type: None,
        ..BAS
    };

    /// eot: messageDigest = the input, signingCertificateV2, OCTET{Basic}, `ESEDO`.
    const EOT: Profile = Profile {
        econtent_type: None,
        content: ContentMode::Digest,
        signing_certificate_v2: true,
        description: Some(Description {
            text: "ESEDO",
            kind: StringKind::Printable,
        }),
        ocsp: Some(OcspForm::OctetBasic),
        ocsp_request: Some(OcspRequest {
            issuer: IssuerRule::Given,
            cert_id_hash: CertIdHash::Fixed(HashAlg::Sha1),
            nonce: Nonce::Random(8),
            method: PkiMethod::PostWithPath,
            url: OcspUrl::Default,
            timeout_ms: MAX_PKI_TIMEOUT_MS,
            check: false,
        }),
        ..BAS
    };

    /// Simourg's CAdES: the generator's attributes, the bare Basic, no DN, no description.
    const SIMOURG_CADES: Profile = Profile {
        econtent_type: None,
        content: ContentMode::Data,
        digest: None,
        encapsulate: Encapsulate::AsAsked,
        cosign: CoSign::Auto,
        certificates: CmsCerts::Signer,
        content_type: true,
        signing_certificate_v2: true,
        signing_time: Some(SigningTimeRule {
            from: TimeFrom::Now,
            form: TimeForm::Auto,
        }),
        file_names: Some(FileNames {
            separator: "<>",
            omit_blank: false,
        }),
        signer_dn: None,
        description: None,
        ocsp: Some(OcspForm::BareBasic),
        ocsp_request: Some(OcspRequest {
            issuer: IssuerRule::VerifiesCert,
            cert_id_hash: CertIdHash::Fixed(HashAlg::Sha1),
            nonce: Nonce::None,
            method: PkiMethod::GetUrlEncoded,
            url: OcspUrl::FromCert,
            timeout_ms: MAX_PKI_TIMEOUT_MS,
            check: true,
        }),
    };

    fn subject_der() -> Vec<u8> {
        Certificate::from_der(SIGNER)
            .unwrap()
            .tbs_certificate()
            .subject()
            .to_der()
            .unwrap()
    }

    /// RDN { type = value } with `value` a DER value.
    fn rdn(oid_der: &[u8], value: &[u8]) -> Vec<u8> {
        tlv(
            0x31,
            &tlv(0x30, &[tlv(0x06, oid_der), value.to_vec()].concat()),
        )
    }

    const CN: &[u8] = &[0x55, 0x04, 0x03];
    const C: &[u8] = &[0x55, 0x04, 0x06];

    fn raw(oid: &str, value: Vec<u8>) -> RawAttribute {
        RawAttribute {
            oid: oid.to_owned(),
            values: vec![Bytes::from(value)],
        }
    }

    fn input<'a>(names: &'a [&'a str]) -> EsedoInput<'a> {
        EsedoInput {
            cert: SIGNER,
            kalkan_dn: Some(SIGNER_KALKAN_DN),
            file_names: names,
            ocsp: Some(OcspAnswer {
                response: RESPONSE,
                basic: Some(BASIC),
                produced_at_ms: Some(1_772_359_200_000),
            }),
            tsp_gen_time_ms: Some(1_772_359_201_000),
            data: b"data",
            hashed: false,
            attached: false,
        }
    }

    #[test]
    fn bas_attribute_set() {
        let attrs = signed_attrs(&BAS, &input(&["a.pdf<>б.docx"])).unwrap();
        // The subject in the certificate's order: CN, then C.
        let name = tlv(
            0x30,
            &[
                rdn(CN, &tlv(0x0c, b"SYNTHETIC NCA (GOST) 2015")),
                rdn(C, &tlv(0x13, b"KZ")),
            ]
            .concat(),
        );
        assert_eq!(name, subject_der());
        assert_eq!(
            attrs,
            SignedAttrs {
                content_type: true,
                message_digest: true,
                signing_certificate_v2: false,
                signing_time: Some(SigningTime {
                    at: TimeSource::Now,
                    form: TimeForm::Utc,
                }),
                extra: vec![
                    raw(FILE_NAMES, tlv(0x0c, "a.pdf<>б.docx".as_bytes())),
                    raw(OCSP_ANSWER, [&[0x04, 0x05][..], RESPONSE].concat()),
                    raw(SIGNER_DN, name),
                    raw(
                        SIGNING_DESCRIPTION,
                        vec![0x13, 0x06, b'E', b'S', b'E', b'D', b'O', 0x00],
                    ),
                ],
            }
        );
    }

    #[test]
    fn metadoc_attribute_set() {
        let attrs = signed_attrs(&METADOC, &input(&["x.txt"])).unwrap();
        assert_eq!(
            attrs,
            SignedAttrs {
                content_type: true,
                message_digest: true,
                signing_certificate_v2: false,
                signing_time: Some(SigningTime {
                    at: TimeSource::UnixMs(1_772_359_200_000),
                    form: TimeForm::Utc,
                }),
                extra: vec![
                    raw(FILE_NAMES, tlv(0x0c, b"x.txt")),
                    raw(OCSP_ANSWER, [&[0x04, 0x05][..], RESPONSE].concat()),
                    raw(SIGNER_DN, subject_der()),
                    raw(
                        SIGNING_DESCRIPTION,
                        vec![0x0c, 0x06, b'E', b'S', b'E', b'D', b'O', b' '],
                    ),
                ],
            }
        );
    }

    #[test]
    fn dogovor24_reversed_dn_and_no_ocsp() {
        let mut no_ocsp = input(&["d.pdf"]);
        no_ocsp.ocsp = None;
        let attrs = signed_attrs(&DOGOVOR24, &no_ocsp).unwrap();
        // RFC 2253 writes C first; parsed in that order, C comes first.
        let reversed = tlv(
            0x30,
            &[
                rdn(C, &tlv(0x13, b"KZ")),
                rdn(CN, &tlv(0x0c, b"SYNTHETIC NCA (GOST) 2015")),
            ]
            .concat(),
        );
        assert_eq!(
            attrs,
            SignedAttrs {
                content_type: true,
                message_digest: true,
                signing_certificate_v2: false,
                signing_time: Some(SigningTime {
                    at: TimeSource::Now,
                    form: TimeForm::Generalized,
                }),
                extra: vec![
                    raw(FILE_NAMES, tlv(0x0c, b"d.pdf")),
                    raw(SIGNER_DN, reversed),
                    raw(
                        SIGNING_DESCRIPTION,
                        vec![0x13, 0x06, b'E', b'S', b'E', b'D', b'O', 0x00],
                    ),
                ],
            }
        );
    }

    #[test]
    fn eot_and_simourg_attribute_sets() {
        let eot = signed_attrs(&EOT, &input(&["a", "b"])).unwrap();
        assert!(eot.signing_certificate_v2);
        assert_eq!(
            eot.extra,
            vec![
                raw(FILE_NAMES, tlv(0x0c, b"a<>b")),
                raw(OCSP_ANSWER, [&[0x04, 0x05][..], BASIC].concat()),
                raw(SIGNER_DN, subject_der()),
                raw(SIGNING_DESCRIPTION, tlv(0x13, b"ESEDO")),
            ]
        );
        let cades = signed_attrs(&SIMOURG_CADES, &input(&["f.xml"])).unwrap();
        assert_eq!(
            cades,
            SignedAttrs {
                content_type: true,
                message_digest: true,
                signing_certificate_v2: true,
                signing_time: Some(SigningTime {
                    at: TimeSource::Now,
                    form: TimeForm::Auto,
                }),
                extra: vec![
                    raw(FILE_NAMES, tlv(0x0c, b"f.xml")),
                    raw(OCSP_ANSWER, BASIC.to_vec()),
                ],
            }
        );
    }

    #[test]
    fn ocsp_attribute_forms() {
        let names: &[&str] = &[];
        let value = |form| {
            let profile = Profile {
                ocsp: Some(form),
                ..SIMOURG_CADES
            };
            signed_attrs(&profile, &input(names))
                .map(|a| a.extra.into_iter().find(|x| x.oid == OCSP_ANSWER))
        };
        assert_eq!(
            value(OcspForm::OctetResponse).unwrap().unwrap().values,
            vec![Bytes::from(tlv(0x04, RESPONSE))]
        );
        assert_eq!(
            value(OcspForm::OctetBasic).unwrap().unwrap().values,
            vec![Bytes::from(tlv(0x04, BASIC))]
        );
        assert_eq!(
            value(OcspForm::BareBasic).unwrap().unwrap().values,
            vec![Bytes::from(BASIC.to_vec())]
        );
        // An answer without a Basic one cannot give the Basic forms.
        let mut no_basic = input(names);
        no_basic.ocsp = Some(OcspAnswer {
            response: RESPONSE,
            basic: None,
            produced_at_ms: None,
        });
        assert!(signed_attrs(&SIMOURG_CADES, &no_basic).is_err());
        let octet = Profile {
            ocsp: Some(OcspForm::OctetResponse),
            ..SIMOURG_CADES
        };
        assert!(signed_attrs(&octet, &no_basic).is_ok());
        // No answer, no attribute.
        let mut none = input(names);
        none.ocsp = None;
        let attrs = signed_attrs(&octet, &none).unwrap();
        assert!(attrs.extra.iter().all(|a| a.oid != OCSP_ANSWER));
    }

    #[test]
    fn signing_time_sources_and_forms() {
        let time = |from, form| {
            let profile = Profile {
                signing_time: Some(SigningTimeRule { from, form }),
                ..SIMOURG_CADES
            };
            signed_attrs(&profile, &input(&[])).map(|a| a.signing_time)
        };
        assert_eq!(
            time(TimeFrom::Now, TimeForm::Utc),
            Ok(Some(SigningTime {
                at: TimeSource::Now,
                form: TimeForm::Utc
            }))
        );
        assert_eq!(
            time(TimeFrom::OcspProducedAt, TimeForm::Utc),
            Ok(Some(SigningTime {
                at: TimeSource::UnixMs(1_772_359_200_000),
                form: TimeForm::Utc
            }))
        );
        assert_eq!(
            time(TimeFrom::TspGenTime, TimeForm::Generalized),
            Ok(Some(SigningTime {
                at: TimeSource::UnixMs(1_772_359_201_000),
                form: TimeForm::Generalized
            }))
        );
        let none = Profile {
            signing_time: None,
            ..SIMOURG_CADES
        };
        assert_eq!(signed_attrs(&none, &input(&[])).unwrap().signing_time, None);
        // A time the input does not have.
        let mut bare = input(&[]);
        bare.ocsp = Some(OcspAnswer {
            response: RESPONSE,
            basic: Some(BASIC),
            produced_at_ms: None,
        });
        bare.tsp_gen_time_ms = None;
        for from in [TimeFrom::OcspProducedAt, TimeFrom::TspGenTime] {
            let profile = Profile {
                signing_time: Some(SigningTimeRule {
                    from,
                    form: TimeForm::Utc,
                }),
                ..SIMOURG_CADES
            };
            assert!(signed_attrs(&profile, &bare).is_err(), "{from:?}");
        }
    }

    #[test]
    fn file_names_join_and_blank() {
        let names = |profile: &Profile, list: &[&str]| {
            signed_attrs(profile, &input(list))
                .unwrap()
                .extra
                .into_iter()
                .find(|a| a.oid == FILE_NAMES)
                .map(|a| a.values)
        };
        // Always present, even empty (eot).
        assert_eq!(names(&EOT, &[]), Some(vec![Bytes::from(vec![0x0c, 0x00])]));
        assert_eq!(
            names(&EOT, &["один"]),
            Some(vec![Bytes::from(tlv(0x0c, "один".as_bytes()))])
        );
        // Left out when blank (ThunderCrypt).
        let blank = Profile {
            file_names: Some(FileNames {
                separator: "<>",
                omit_blank: true,
            }),
            ..EOT
        };
        assert_eq!(names(&blank, &[" "]), None);
        assert_eq!(names(&blank, &[]), None);
        assert!(names(&blank, &["a"]).is_some());
        let without = Profile {
            file_names: None,
            ..EOT
        };
        assert_eq!(names(&without, &["a"]), None);
    }

    #[test]
    fn description_encodings() {
        let description = |text, kind| {
            let profile = Profile {
                description: Some(Description { text, kind }),
                ..EOT
            };
            signed_attrs(&profile, &input(&[]))
                .unwrap()
                .extra
                .into_iter()
                .find(|a| a.oid == SIGNING_DESCRIPTION)
                .unwrap()
                .values[0]
                .to_vec()
        };
        assert_eq!(
            description("ESEDO\0", StringKind::Printable),
            b"\x13\x06ESEDO\x00"
        );
        assert_eq!(
            description("ESEDO", StringKind::Printable),
            b"\x13\x05ESEDO"
        );
        assert_eq!(description("ESEDO", StringKind::Utf8), b"\x0c\x05ESEDO");
        assert_eq!(description("ESEDO ", StringKind::Utf8), b"\x0c\x06ESEDO ");
    }

    #[test]
    fn kalkan_dn_is_needed_for_its_form() {
        let mut no_dn = input(&[]);
        no_dn.kalkan_dn = None;
        assert!(signed_attrs(&BAS, &no_dn).is_err());
        assert!(signed_attrs(&METADOC, &no_dn).is_ok());
        no_dn.cert = b"not a certificate";
        assert!(signed_attrs(&METADOC, &no_dn).is_err());
    }

    #[test]
    fn sign_args_content_and_encapsulation() {
        let bas = sign_args(&BAS, &input(&["n"]), 7).unwrap();
        assert_eq!(bas.handle, 7);
        assert_eq!(bas.content, CmsContent::Data(Bytes::from(b"data".to_vec())));
        assert!(!bas.encapsulate);
        assert_eq!(bas.cosign, CoSign::Never);
        assert_eq!(
            bas.econtent_type.as_deref(),
            Some("1.3.6.1.4.1.6801.11.1.9")
        );
        assert_eq!(bas.digest, None);
        assert_eq!(bas.certificates, CmsCerts::Signer);
        assert_eq!(bas.timestamp, None::<TsaChoice>);
        assert_eq!(bas.attrs, signed_attrs(&BAS, &input(&["n"])).unwrap());

        let eot = sign_args(&EOT, &input(&[]), 1).unwrap();
        assert_eq!(
            eot.content,
            CmsContent::Digest(Bytes::from(b"data".to_vec()))
        );
        assert_eq!(eot.econtent_type, None);

        let mut asked = input(&[]);
        asked.hashed = true;
        let metadoc = sign_args(&METADOC, &asked, 1).unwrap();
        assert_eq!(
            metadoc.content,
            CmsContent::Digest(Bytes::from(b"data".to_vec()))
        );
        asked.hashed = false;
        asked.attached = true;
        let cades = sign_args(&SIMOURG_CADES, &asked, 1).unwrap();
        assert_eq!(
            cades.content,
            CmsContent::Data(Bytes::from(b"data".to_vec()))
        );
        assert!(cades.encapsulate);
        assert_eq!(cades.cosign, CoSign::Auto);
        assert!(!sign_args(&METADOC, &asked, 1).unwrap().encapsulate);

        let streebog = Profile {
            digest: Some(HashAlg::Streebog512),
            encapsulate: Encapsulate::Always,
            certificates: CmsCerts::Chain,
            ..EOT
        };
        let args = sign_args(&streebog, &input(&[]), 1).unwrap();
        assert_eq!(args.digest, Some(HashAlg::Streebog512));
        assert!(args.encapsulate);
        assert_eq!(args.certificates, CmsCerts::Chain);
    }

    #[test]
    fn ocsp_args_request_parameters() {
        let bas = ocsp_args(BAS.ocsp_request.as_ref().unwrap(), SIGNER, &[]).unwrap();
        assert_eq!(
            bas,
            OcspArgs {
                cert: Bytes::from(SIGNER.to_vec()),
                issuer: IssuerSel::HostCas,
                cert_id_hash: HashAlg::Sha256,
                nonce: Nonce::None,
                url: PkiUrl::Default,
                method: PkiMethod::Post { content_type: None },
                timeout_ms: MAX_PKI_TIMEOUT_MS,
                check: false,
            }
        );
        let eot = ocsp_args(EOT.ocsp_request.as_ref().unwrap(), SIGNER, &[ROOT_GOST]).unwrap();
        assert_eq!(
            eot.issuer,
            IssuerSel::Given(Bytes::from(ROOT_GOST.to_vec()))
        );
        assert_eq!(eot.cert_id_hash, HashAlg::Sha1);
        assert_eq!(eot.nonce, Nonce::Random(8));
        assert_eq!(eot.method, PkiMethod::PostWithPath);
        assert!(ocsp_args(EOT.ocsp_request.as_ref().unwrap(), SIGNER, &[]).is_err());

        let simourg = ocsp_args(
            SIMOURG_CADES.ocsp_request.as_ref().unwrap(),
            SIGNER,
            &[ROOT_RSA, ROOT_GOST],
        )
        .unwrap();
        assert_eq!(
            simourg.issuer,
            IssuerSel::VerifiesCert(vec![
                Bytes::from(ROOT_RSA.to_vec()),
                Bytes::from(ROOT_GOST.to_vec())
            ])
        );
        assert_eq!(simourg.url, PkiUrl::FromCert(Bytes::from(SIGNER.to_vec())));
        assert_eq!(simourg.method, PkiMethod::GetUrlEncoded);
        assert!(simourg.check);

        let fixed = OcspRequest {
            url: OcspUrl::Fixed("http://ocsp.pki.gov.kz/"),
            ..BAS.ocsp_request.clone().unwrap()
        };
        assert_eq!(
            ocsp_args(&fixed, SIGNER, &[]).unwrap().url,
            PkiUrl::Fixed("http://ocsp.pki.gov.kz/".to_owned())
        );
    }

    #[test]
    fn cert_id_hash_by_the_issuers_issuer() {
        let request = METADOC.ocsp_request.as_ref().unwrap();
        // The signer's issuer is the GOST root, whose issuer (itself) names GOST.
        let gost = ocsp_args(request, SIGNER, &[ROOT_GOST]).unwrap();
        assert_eq!(gost.cert_id_hash, HashAlg::Gost34311);
        assert_eq!(gost.issuer, IssuerSel::HostCas);
        assert_eq!(gost.nonce, Nonce::Random(16));
        assert_eq!(gost.method, PkiMethod::GetUnder(256));
        // An issuer under an RSA root: GOST 34.311 GT, which the core has not.
        assert!(ocsp_args(request, SIGNER, &[ROOT_RSA]).is_err());
        // The rule on the text: GOST first, then RSA; neither is another GOST CertID,
        // which the core has not either.
        assert_eq!(
            hash_by_issuer_dn("CN=ROOT (GOST RSA),C=KZ"),
            Ok(HashAlg::Gost34311)
        );
        assert!(hash_by_issuer_dn("CN=ROOT (RSA),C=KZ").is_err());
        assert!(hash_by_issuer_dn("CN=ROOT,C=KZ").is_err());
        // No issuer to read.
        assert!(ocsp_args(request, SIGNER, &[]).is_err());
    }

    #[test]
    fn ocsp_answer_from_outcome() {
        let ok = OcspOutcome::Ok {
            http_status: 200,
            response: Bytes::from(RESPONSE.to_vec()),
            basic: Some(Bytes::from(BASIC.to_vec())),
            response_status: 0,
            cert_status: None,
            produced_at_ms: Some(5),
            problem: None,
        };
        assert_eq!(
            OcspAnswer::from_outcome(&ok),
            Some(OcspAnswer {
                response: RESPONSE,
                basic: Some(BASIC),
                produced_at_ms: Some(5),
            })
        );
        let failed = OcspOutcome::Failed(oncl_pdk::abi::NetFailure {
            stage: oncl_pdk::abi::NetStage::Ocsp,
            kind: oncl_pdk::abi::NetKind::Timeout,
            address: "ocsp.pki.gov.kz".to_owned(),
            detail: "read timed out".to_owned(),
        });
        assert_eq!(OcspAnswer::from_outcome(&failed), None);
    }
}
