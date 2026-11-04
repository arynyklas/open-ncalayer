//! Host options for the guarded legacy `XmlSignSpec` / `XadesSpec` Core facades.
//!
//! Every option maps to one accepted SDK field. Combinations the SDK facade
//! cannot express are rejected by `preflight` before any file, key or network
//! I/O; no option accepts a raw key path, algorithm OID or free-form transform.
use crate::{args::SignProfile, bounded, local::Input};
use clap::{Args, ValueEnum};
use oncl_core::{OperationContext, OperationError};
use oncl_pki::{
    cert::Certificate,
    resource::{ProcessingError, ResourceReservation},
};
use oncl_xml::{C14n, Placement, SigningTimeObject, Transform, XmlOutput, XmlSignSpec};

const MAX_TEXT: usize = 1024;
const MAX_NAMESPACES: usize = 32;
const MAX_CHAIN: usize = 16;
const MAX_CHAIN_CERTIFICATE_BYTES: usize = 16_384;

#[derive(Clone, Copy, ValueEnum)]
pub enum Algorithm {
    RsaSha256,
    Gost2004,
    Gost2015_512,
}
impl Algorithm {
    fn signature_uri(self) -> &'static str {
        match self {
            Self::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::Gost2004 => "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
            Self::Gost2015_512 => {
                "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512"
            }
        }
    }
    fn digest_uri(self) -> &'static str {
        match self {
            Self::RsaSha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Gost2004 => "http://www.w3.org/2001/04/xmldsig-more#gost34311",
            Self::Gost2015_512 => {
                "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512"
            }
        }
    }
}
#[derive(Clone, Copy, ValueEnum)]
pub enum Canonicalization {
    Inclusive,
    InclusiveWithComments,
    Exclusive,
    ExclusiveWithComments,
}
impl Canonicalization {
    fn sdk(self) -> C14n {
        match self {
            Self::Inclusive => C14n::Inclusive,
            Self::InclusiveWithComments => C14n::InclusiveWithComments,
            Self::Exclusive => C14n::Exclusive,
            Self::ExclusiveWithComments => C14n::ExclusiveWithComments,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TransformKind {
    Enveloped,
    Inclusive,
    InclusiveWithComments,
    Exclusive,
    ExclusiveWithComments,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum PlacementKind {
    DocumentElement,
    FirstChild,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum OutputForm {
    /// The input bytes with the signature spliced in.
    AsIs,
    /// JDK `Transformer` form (the Kalkan default is `serialize` without a declaration).
    Serialize,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum Switch {
    On,
    Off,
}

/// All legacy options. `--legacy` selects the facade; any other `--legacy-*`
/// option without it is a typed rejection, not a silent no-op.
#[derive(Args, Default)]
pub struct LegacyOptions {
    /// Sign through the guarded Kalkan/NCALayer-compatible XmlSignSpec (`--profile xml`)
    /// or XadesSpec (`--profile xades-b|xades-t|xades-lt`) facade.
    #[arg(long)]
    pub legacy: bool,
    /// XPath (supported subset) of the element to sign; it must carry an `Id`.
    #[arg(long)]
    pub legacy_element: Option<String>,
    /// XPath of the element the signature is appended to.
    #[arg(long)]
    pub legacy_parent: Option<String>,
    /// `PREFIX=NAMESPACE-URI` binding for the XPaths; repeatable.
    #[arg(long)]
    pub legacy_namespace: Vec<String>,
    /// Namespace URI of every prefix `--legacy-namespace` does not bind.
    #[arg(long)]
    pub legacy_other_prefix_uri: Option<String>,
    /// Where the signature goes when no `--legacy-parent` is given.
    #[arg(long, value_enum)]
    pub legacy_placement: Option<PlacementKind>,
    /// SignatureMethod (XML and XAdES). The key must fit it.
    #[arg(long, value_enum)]
    pub legacy_signature_method: Option<Algorithm>,
    /// DigestMethod (XML and XAdES).
    #[arg(long, value_enum)]
    pub legacy_digest_method: Option<Algorithm>,
    /// CanonicalizationMethod of SignedInfo.
    #[arg(long, value_enum)]
    pub legacy_signed_info_c14n: Option<Canonicalization>,
    /// Reference transform, in order: `enveloped` (first only) and at most one canonicalization.
    #[arg(long, value_enum)]
    pub legacy_transform: Vec<TransformKind>,
    /// `Id` of the SignatureProperty holding the signing time (needs `--signature-id` and `--legacy-signing-time`).
    #[arg(long)]
    pub legacy_signing_time_id: Option<String>,
    /// Text of the signing-time `<timestamp>` element.
    #[arg(long)]
    pub legacy_signing_time: Option<String>,
    /// Also sign the signing-time property with a second reference.
    #[arg(long)]
    pub legacy_signing_time_reference: bool,
    /// Santuario line breaks between the signature elements (default: none).
    #[arg(long)]
    pub legacy_line_breaks: bool,
    /// Base64 in 76-character lines (`on`) or one line (`off`).
    #[arg(long, value_enum)]
    pub legacy_base64_line_breaks: Option<Switch>,
    /// Output form of the signed document.
    #[arg(long, value_enum)]
    pub legacy_output: Option<OutputForm>,
    /// With `--legacy-output serialize`: write `<?xml version="1.0" encoding="UTF-8"?>`.
    #[arg(long)]
    pub legacy_xml_declaration: bool,
    /// With the declaration: `standalone="no"`.
    #[arg(long)]
    pub legacy_standalone_no: bool,
    /// With `--legacy-output serialize`: keep whitespace at both ends of the document.
    #[arg(long)]
    pub legacy_keep_outer_whitespace: bool,
    /// Public DER certificate of the XAdES signer's path (issuers; the root may be among them); repeatable.
    #[arg(long)]
    pub legacy_chain: Vec<std::path::PathBuf>,
}
fn text_ok(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_TEXT && !text.chars().any(char::is_control)
}
impl LegacyOptions {
    fn xml_only(&self) -> bool {
        self.legacy_element.is_some()
            || self.legacy_parent.is_some()
            || !self.legacy_namespace.is_empty()
            || self.legacy_other_prefix_uri.is_some()
            || self.legacy_placement.is_some()
            || self.legacy_signed_info_c14n.is_some()
            || !self.legacy_transform.is_empty()
            || self.legacy_signing_time_id.is_some()
            || self.legacy_signing_time.is_some()
            || self.legacy_signing_time_reference
            || self.legacy_line_breaks
            || self.legacy_base64_line_breaks.is_some()
            || self.legacy_output.is_some()
            || self.legacy_xml_declaration
            || self.legacy_standalone_no
            || self.legacy_keep_outer_whitespace
    }
    fn any(&self) -> bool {
        self.legacy
            || self.xml_only()
            || self.legacy_signature_method.is_some()
            || self.legacy_digest_method.is_some()
            || !self.legacy_chain.is_empty()
    }
    pub fn level_is_evidence(profile: SignProfile) -> bool {
        matches!(profile, SignProfile::XadesT | SignProfile::XadesLt)
    }
    /// Typed rejection of every combination the legacy facade cannot express.
    pub fn preflight(&self, args: &crate::args::SignArgs, tsa: bool) -> Result<(), &'static str> {
        const BAD: &str = "InvalidCombination";
        if !self.any() {
            return Ok(());
        }
        if !self.legacy {
            return Err(BAD);
        }
        let xml = matches!(args.profile, SignProfile::Xml);
        let xades = matches!(
            args.profile,
            SignProfile::XadesB | SignProfile::XadesT | SignProfile::XadesLt
        );
        // XAdES-LTA has no legacy XadesSpec level; other families have no facade.
        if !(xml || xades)
            || args.add
            || args.detached
            || args.detached_input.is_some()
            || args.target_id.is_some()
            || args.parent_id.is_some()
            || args.wsse.any()
        {
            return Err(BAD);
        }
        if Self::level_is_evidence(args.profile) && !tsa {
            return Err("TsaRequired");
        }
        if xades {
            if self.xml_only() || args.signature_id.is_some() {
                return Err(BAD);
            }
        } else if !self.legacy_chain.is_empty() {
            return Err(BAD);
        }
        if self.legacy_chain.len() > MAX_CHAIN {
            return Err("ConfigurationLimit");
        }
        if self.legacy_parent.is_some() && self.legacy_placement.is_some() {
            return Err(BAD);
        }
        if self.legacy_namespace.len() > MAX_NAMESPACES {
            return Err("ConfigurationLimit");
        }
        for text in self
            .legacy_element
            .iter()
            .chain(self.legacy_parent.iter())
            .chain(self.legacy_other_prefix_uri.iter())
            .chain(self.legacy_signing_time_id.iter())
            .chain(self.legacy_signing_time.iter())
        {
            if !text_ok(text) {
                return Err(BAD);
            }
        }
        for binding in &self.legacy_namespace {
            match binding.split_once('=') {
                Some((prefix, uri)) if text_ok(prefix) && text_ok(uri) && !prefix.contains(':') => {
                }
                _ => return Err(BAD),
            }
        }
        // Transforms: enveloped-signature first and once, at most one canonicalization.
        let enveloped = self
            .legacy_transform
            .iter()
            .filter(|t| **t == TransformKind::Enveloped)
            .count();
        if enveloped > 1
            || (enveloped == 1 && self.legacy_transform[0] != TransformKind::Enveloped)
            || self.legacy_transform.len() - enveloped > 1
        {
            return Err(BAD);
        }
        // The signing-time object needs both texts and the signature Id.
        if self.legacy_signing_time_id.is_some() != self.legacy_signing_time.is_some()
            || (self.legacy_signing_time_id.is_some() && args.signature_id.is_none())
            || (self.legacy_signing_time_reference && self.legacy_signing_time_id.is_none())
        {
            return Err(BAD);
        }
        // Serialization detail flags only qualify the serialize form.
        let serialize = !matches!(self.legacy_output, Some(OutputForm::AsIs));
        if !serialize
            && (self.legacy_xml_declaration
                || self.legacy_standalone_no
                || self.legacy_keep_outer_whitespace)
        {
            return Err(BAD);
        }
        if self.legacy_standalone_no && !self.legacy_xml_declaration {
            return Err(BAD);
        }
        Ok(())
    }
    pub fn xml_spec<'a>(&'a self, args: &'a crate::args::SignArgs) -> XmlSignSpec<'a> {
        let mut spec = XmlSignSpec::kalkan(
            self.legacy_element.as_deref(),
            self.legacy_parent.as_deref(),
        );
        spec.namespaces = self
            .legacy_namespace
            .iter()
            .filter_map(|binding| binding.split_once('='))
            .collect();
        spec.other_prefix_uri = self.legacy_other_prefix_uri.as_deref();
        if self.legacy_parent.is_none() {
            spec.placement = match self.legacy_placement {
                Some(PlacementKind::FirstChild) => Placement::FirstChildOfDocument,
                _ => Placement::DocumentElement,
            };
        }
        if let Some(method) = self.legacy_signature_method {
            spec.signature_method = Some(method.signature_uri());
        }
        if let Some(method) = self.legacy_digest_method {
            spec.digest_method = Some(method.digest_uri());
        }
        spec.signed_info_c14n = self.legacy_signed_info_c14n.map(Canonicalization::sdk);
        if !self.legacy_transform.is_empty() {
            spec.transforms = Some(
                self.legacy_transform
                    .iter()
                    .map(|kind| match kind {
                        TransformKind::Enveloped => Transform::Enveloped,
                        TransformKind::Inclusive => Transform::C14n(C14n::Inclusive),
                        TransformKind::InclusiveWithComments => {
                            Transform::C14n(C14n::InclusiveWithComments)
                        }
                        TransformKind::Exclusive => Transform::C14n(C14n::Exclusive),
                        TransformKind::ExclusiveWithComments => {
                            Transform::C14n(C14n::ExclusiveWithComments)
                        }
                    })
                    .collect(),
            );
        }
        spec.signature_id = args.signature_id.as_deref();
        if let (Some(property_id), Some(text)) = (
            self.legacy_signing_time_id.as_deref(),
            self.legacy_signing_time.as_deref(),
        ) {
            spec.signing_time_object = Some(SigningTimeObject {
                property_id,
                target_ref: self.legacy_signing_time_reference,
                text,
            });
        }
        if self.legacy_line_breaks {
            spec.strip_whitespace = false;
        }
        spec.base64_line_breaks = self
            .legacy_base64_line_breaks
            .map(|switch| matches!(switch, Switch::On));
        match self.legacy_output {
            Some(OutputForm::AsIs) => spec.output = XmlOutput::AsIs,
            _ => {
                spec.output = XmlOutput::Serialize {
                    declaration: self.legacy_xml_declaration,
                    standalone_no: self.legacy_standalone_no,
                    trim: !self.legacy_keep_outer_whitespace,
                }
            }
        }
        spec
    }
    pub fn xades_signature_method(&self) -> Option<&'static str> {
        self.legacy_signature_method.map(Algorithm::signature_uri)
    }
    pub fn xades_digest_method(&self) -> Option<&'static str> {
        self.legacy_digest_method.map(Algorithm::digest_uri)
    }
}
/// Public signer-path certificates, bounded and charged to the operation before parsing.
pub struct Chain {
    pub certificates: Vec<Certificate>,
    _encoded: Vec<bounded::Bytes>,
    _metadata: Vec<ResourceReservation>,
}
pub fn chain(
    paths: &[std::path::PathBuf],
    ctx: &mut OperationContext,
) -> Result<Chain, OperationError> {
    let mut chain = Chain {
        certificates: Vec::new(),
        _encoded: Vec::new(),
        _metadata: Vec::new(),
    };
    for path in paths {
        let name = path
            .to_str()
            .ok_or(ProcessingError::InvalidInput("non-Unicode chain path"))?;
        let mut input = Input::open(name)?;
        let encoded = bounded::read(input.source(), MAX_CHAIN_CERTIFICATE_BYTES, ctx)?;
        let metadata = ctx.resources().reserve_metadata(
            (encoded.as_bytes().len() as u64)
                .checked_mul(bounded::CERTIFICATE_METADATA_FACTOR)
                .ok_or(ProcessingError::MetadataLimit)?,
        )?;
        chain.certificates.push(
            oncl_pki::cert::parse(encoded.as_bytes())
                .map_err(|_| ProcessingError::InvalidInput("invalid legacy chain certificate"))?,
        );
        chain._encoded.push(encoded);
        chain._metadata.push(metadata);
    }
    Ok(chain)
}
