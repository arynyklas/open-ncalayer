//! The manifest of the original NCALayer, `ncalayer.der`: a CMS `SignedData` (GOST) whose
//! encapsulated content is the JSON `{"ncalayer": {…}}` naming the version, the
//! distributions and the bundles. The signer must be `CN=NCALayer`, issued by a trusted CA.

use std::collections::BTreeMap;
use std::fmt;

use oncl_pki::cert::{Certificate, verify_signature};
use oncl_pki::cms::{self, CmsError};
use oncl_pki::info::{cert_info, common_name};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{MANIFEST_MAX, sha256_hex};

/// The JSON of the manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// `version` of the core.
    pub version: String,
    /// `info`: the release notes.
    pub info: String,
    /// `updurl`: where the manifest is.
    pub updurl: String,
    /// `syspkgs`, split at commas, trimmed, empty items dropped, in order.
    pub syspkgs: Vec<String>,
    /// `disturls`.
    pub disturls: Vec<DistUrl>,
    /// `bundles`.
    pub bundles: Vec<Bundle>,
    /// Keys of `ncalayer` not named above.
    pub extra: BTreeMap<String, Value>,
}

/// One of `disturls`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistUrl {
    /// `type`: `appzip`, `setupexe`, `setupsh`, `jresetupexe`, `jar`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Its URL; empty when unused.
    pub url: String,
    /// SHA-256 of the file (lowercase hex); empty when unused.
    pub hash: String,
}

/// One of `bundles`: an OSGi bundle of the core or a plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    /// `name`.
    pub name: String,
    /// `symname`: the bundle's symbolic name.
    pub symname: String,
    /// `version`.
    pub version: String,
    /// `required`: part of the core (missing = `false`).
    pub required: bool,
    /// `hidden`.
    pub hidden: bool,
    /// `banned`.
    pub banned: bool,
    /// `info`.
    pub info: String,
    /// `url` of the JAR.
    pub url: String,
    /// `hash`: SHA-256 of the JAR.
    pub hash: String,
    /// `csernum`: serial of the JAR's signing certificate.
    pub csernum: String,
    /// `chash`: SHA-256 of the JAR's signing certificate.
    pub chash: String,
    /// Keys not named above.
    pub extra: BTreeMap<String, Value>,
}

/// The signer of the manifest, as public facts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerFacts {
    /// SHA-256 of the certificate.
    pub sha256: String,
    /// Serial, lowercase hex.
    pub serial: String,
    /// Subject (RFC 4514).
    pub subject: String,
    /// Issuer (RFC 4514).
    pub issuer: String,
    /// Start of validity, RFC 3339.
    pub not_before: String,
    /// End of validity, RFC 3339.
    pub not_after: String,
}

/// A manifest whose signature verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The parsed JSON.
    pub manifest: Manifest,
    /// The JSON bytes (`eContent`).
    pub content: Vec<u8>,
    /// SHA-256 of the file.
    pub sha256: String,
    /// Size of the file.
    pub size: u64,
    /// The signer.
    pub signer: SignerFacts,
    /// The signingTime attribute.
    pub signing_time: Option<OffsetDateTime>,
}

/// Why a manifest is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestError {
    /// The CMS does not verify.
    Cms(CmsError),
    /// Not exactly one signer.
    SignerCount(usize),
    /// The signer's CN is not `NCALayer`.
    NotNcaLayerSigner(String),
    /// No trusted certificate is named as the signer's issuer.
    UnknownIssuer(String),
    /// A trusted certificate has the issuer's name but did not sign the signer's.
    BadIssuerSignature,
    /// The content is not the manifest JSON.
    Json(String),
    /// The file is larger than [`MANIFEST_MAX`].
    TooLarge(u64),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::Cms(e) => write!(f, "manifest CMS: {e}"),
            ManifestError::SignerCount(n) => write!(f, "manifest has {n} signers, not one"),
            ManifestError::NotNcaLayerSigner(cn) => {
                write!(f, "manifest signer is CN={cn:?}, not CN=NCALayer")
            }
            ManifestError::UnknownIssuer(dn) => write!(f, "manifest signer issuer {dn} is unknown"),
            ManifestError::BadIssuerSignature => {
                f.write_str("manifest signer certificate is not signed by its issuer")
            }
            ManifestError::Json(e) => write!(f, "manifest JSON: {e}"),
            ManifestError::TooLarge(n) => write!(f, "manifest of {n} bytes is too large"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<CmsError> for ManifestError {
    fn from(e: CmsError) -> Self {
        ManifestError::Cms(e)
    }
}

/// The CN the manifest signer must have.
const SIGNER_CN: &str = "NCALayer";

/// Parses the manifest JSON `{"ncalayer": {…}}`. Unknown keys are kept in `extra`.
///
/// # Errors
///
/// [`ManifestError::Json`] if it is not JSON, has no `ncalayer` object or a known key has
/// the wrong type; [`ManifestError::TooLarge`] over [`MANIFEST_MAX`].
pub fn parse_json(content: &[u8]) -> Result<Manifest, ManifestError> {
    if content.len() as u64 > MANIFEST_MAX {
        return Err(ManifestError::TooLarge(content.len() as u64));
    }
    let root: Value =
        serde_json::from_slice(content).map_err(|e| ManifestError::Json(e.to_string()))?;
    let Some(Value::Object(mut top)) = root.get("ncalayer").cloned() else {
        return Err(ManifestError::Json("no \"ncalayer\" object".to_owned()));
    };
    let version = take_str(&mut top, "version")?;
    let info = take_str(&mut top, "info")?;
    let updurl = take_str(&mut top, "updurl")?;
    let syspkgs = take_str(&mut top, "syspkgs")?
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let disturls = match top.remove("disturls") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => serde_json::from_value::<Vec<RawDistUrl>>(v)
            .map_err(|e| ManifestError::Json(format!("disturls: {e}")))?
            .into_iter()
            .map(|d| DistUrl {
                kind: d.kind,
                url: d.url,
                hash: d.hash,
            })
            .collect(),
    };
    let bundles = match top.remove("bundles") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .into_iter()
            .enumerate()
            .map(|(i, item)| {
                bundle(item).map_err(|e| ManifestError::Json(format!("bundles[{i}]: {e}")))
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(ManifestError::Json("bundles is not an array".to_owned())),
    };
    Ok(Manifest {
        version,
        info,
        updurl,
        syspkgs,
        disturls,
        bundles,
        extra: top.into_iter().collect(),
    })
}

/// `disturls` items; extra keys are tolerated.
#[derive(Deserialize)]
struct RawDistUrl {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    hash: String,
}

fn bundle(item: Value) -> Result<Bundle, String> {
    let Value::Object(mut map) = item else {
        return Err("not an object".to_owned());
    };
    let s = |map: &mut serde_json::Map<String, Value>, key: &str| {
        take_str(map, key).map_err(|e| e.to_string())
    };
    let b = |map: &mut serde_json::Map<String, Value>, key: &str| match map.remove(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(v)) => Ok(v),
        Some(Value::String(v)) if v == "true" || v == "false" => Ok(v == "true"),
        Some(_) => Err(format!("{key} is not a boolean")),
    };
    Ok(Bundle {
        name: s(&mut map, "name")?,
        symname: s(&mut map, "symname")?,
        version: s(&mut map, "version")?,
        required: b(&mut map, "required")?,
        hidden: b(&mut map, "hidden")?,
        banned: b(&mut map, "banned")?,
        info: s(&mut map, "info")?,
        url: s(&mut map, "url")?,
        hash: s(&mut map, "hash")?,
        csernum: s(&mut map, "csernum")?,
        chash: s(&mut map, "chash")?,
        extra: map.into_iter().collect(),
    })
}

/// A string value; missing or null = `""`.
fn take_str(map: &mut serde_json::Map<String, Value>, key: &str) -> Result<String, ManifestError> {
    match map.remove(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s),
        Some(Value::Number(n)) => Ok(n.to_string()),
        Some(_) => Err(ManifestError::Json(format!("{key} is not a string"))),
    }
}

/// Verifies the manifest file `der` and parses its content: one signer, `CN=NCALayer`, whose
/// certificate is signed by one of `trusted_issuers` with its issuer's name (any of several
/// candidates with that name will do).
///
/// # Errors
///
/// [`ManifestError`]: the first check that fails.
pub fn verify_and_parse(
    der: &[u8],
    trusted_issuers: &[Certificate],
) -> Result<Verified, ManifestError> {
    if der.len() as u64 > MANIFEST_MAX {
        return Err(ManifestError::TooLarge(der.len() as u64));
    }
    let mut signers = cms::verify(der, None)?;
    if signers.len() != 1 {
        return Err(ManifestError::SignerCount(signers.len()));
    }
    let signer = signers.remove(0);
    let cert = &signer.cert;
    let tbs = cert.tbs_certificate();
    let cn = common_name(tbs.subject()).unwrap_or_default();
    if cn != SIGNER_CN {
        return Err(ManifestError::NotNcaLayerSigner(cn));
    }
    let candidates: Vec<&Certificate> = trusted_issuers
        .iter()
        .filter(|c| c.tbs_certificate().subject() == tbs.issuer())
        .collect();
    if candidates.is_empty() {
        return Err(ManifestError::UnknownIssuer(tbs.issuer().to_string()));
    }
    if !candidates.iter().any(|c| verify_signature(cert, c).is_ok()) {
        return Err(ManifestError::BadIssuerSignature);
    }
    let content = cms::content(der)?.ok_or(ManifestError::Cms(CmsError::NoEncapsulatedData))?;
    let manifest = parse_json(&content)?;
    Ok(Verified {
        manifest,
        content,
        sha256: sha256_hex(der),
        size: der.len() as u64,
        signer: signer_facts(cert),
        signing_time: signer.signing_time,
    })
}

/// The public facts of a certificate that signs something of the original.
pub fn signer_facts(cert: &Certificate) -> SignerFacts {
    use der::Encode;
    let info = cert_info(cert);
    let tbs = cert.tbs_certificate();
    SignerFacts {
        sha256: sha256_hex(&cert.to_der().expect("a parsed certificate re-encodes")),
        serial: info.serial_hex.clone(),
        subject: tbs.subject().to_string(),
        issuer: tbs.issuer().to_string(),
        not_before: rfc3339(info.not_before),
        not_after: rfc3339(info.not_after),
    }
}

/// RFC 3339 of a UTC time.
pub(crate) fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).expect("a certificate time formats")
}
