//! XML signatures (XMLDSig) in the shape Kalkan's `XMLUtil.createXmlSignature` produces, in
//! the shapes other signers ask for ([`sign_spec`]), and their verification.
//!
//! - [`sign_enveloped`] signs the whole document: a `ds:Signature` with one `Reference URI=""`
//!   (enveloped-signature, then Canonical XML with comments) becomes the last child of the
//!   document element; SignedInfo is canonicalized with Canonical XML 1.0.
//! - [`sign_element`] signs the element with an `Id` attribute selected by an XPath:
//!   `Reference URI="#<Id>"` with Canonical XML with comments only, SignedInfo canonicalized
//!   with Exclusive XML Canonicalization; the signature goes into the element selected by
//!   the parent XPath, else into the document element.
//! - [`sign_spec`] takes an [`XmlSignSpec`]: placement, algorithm URIs, canonicalization,
//!   transforms, namespaces of the XPaths, a signature `Id` with a signing-time object,
//!   layout and output form; [`XmlSignSpec::kalkan`] is the two above.
//!
//! The input bytes are kept: the signature is spliced in before the end tag of its parent
//! (an empty-element tag `<p/>` becomes `<p>…</p>`). The signature layout follows Kalkan's
//! (Apache Santuario's) serialization: a line break after every element and base64 in lines
//! of 76 characters ended by `&#13;` (unless a spec says otherwise).
//!
//! Without a `SignatureMethod` URI of their own, signing algorithms follow the signature
//! algorithm of the signer's certificate, and sha1RSA certificates are refused; RSA-SHA1
//! signature methods are refused too (verification only). Same-document references (`URI=""`, `URI="#id"`)
//! leave comments out whatever the canonicalization method says, as XMLDSig requires and
//! Santuario does.
//!
//! Input is untrusted: no DOCTYPE (so no entity expansion and nothing fetched), at most
//! [`MAX_INPUT`] bytes, [`MAX_DEPTH`] levels, [`MAX_NODES`] nodes and [`MAX_ATTRIBUTES`]
//! attributes, bounded parse work for attributes and namespaces in scope, canonical forms
//! of at most [`MAX_CANONICAL`] bytes, at most [`REFERENCE_WORK`] bytes canonicalized by
//! [`verify`], and XPaths of at most 32 steps. Signing holds one parse tree at a time.

mod c14n;
mod parse;
mod xpath;

pub use c14n::{C14n, MAX_CANONICAL, NodeRef, canonicalize};
pub use parse::{MAX_ATTRIBUTES, MAX_DEPTH, MAX_INPUT, MAX_NODES};

use crate::cert::{self, Certificate};
use crate::key::{HashAlg, KeyError, PrivateKey, PublicKey, SigAlg};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use c14n::{Canonicalizer, escape_attribute, escape_text};
use der::Encode;
use roxmltree::{Document, Node, NodeId};

const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// The namespace of XAdES 1.3.2 (ETSI EN 319 132-1).
pub(crate) const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";
/// The `Type` of the reference to `xades:SignedProperties`.
const SIGNED_PROPERTIES_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";

/// A `ds:Object` with `xades:QualifyingProperties` (`Target` the signature's `Id`) around
/// the given `xades:SignedProperties`, which a second reference signs (its `Type`
/// [`SIGNED_PROPERTIES_TYPE`], Exclusive XML Canonicalization alone, the signature's
/// digest method). The unsigned properties are added to the signed document afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QualifyingObject<'a> {
    /// The `xades:SignedProperties` element as written, with the `xades` prefix (bound by
    /// `QualifyingProperties`) and the `ds` prefix (bound by the signature).
    pub(crate) signed_properties: &'a str,
    /// Its `Id`.
    pub(crate) signed_properties_id: &'a str,
}

/// Bound on the references of a document times its size, the bytes [`verify`] may
/// canonicalize: a 64 MiB document may carry 16 references, a 1 MiB one 1024.
pub const REFERENCE_WORK: usize = 1 << 30;

/// `(SignatureMethod, DigestMethod)` URIs Kalkan writes for an algorithm.
fn signing_uris(alg: SigAlg) -> Option<(&'static str, &'static str)> {
    match alg {
        SigAlg::Gost2015_512 => Some((
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512",
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512",
        )),
        SigAlg::Gost2004 => Some((
            "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
            "http://www.w3.org/2001/04/xmldsig-more#gost34311",
        )),
        SigAlg::RsaSha256 => Some((
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        )),
        SigAlg::RsaSha1 => None,
    }
}

/// Algorithm of a `SignatureMethod` URI; legacy RSA-SHA1 is accepted for verification.
fn signature_method(uri: &str) -> Option<SigAlg> {
    match uri {
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1" => Some(SigAlg::RsaSha1),
        _ => [SigAlg::Gost2015_512, SigAlg::Gost2004, SigAlg::RsaSha256]
            .into_iter()
            .find(|&alg| signing_uris(alg).is_some_and(|(sig, _)| sig == uri)),
    }
}

/// Algorithm whose hash a `DigestMethod` URI names.
fn digest_method(uri: &str) -> Option<SigAlg> {
    match uri {
        "http://www.w3.org/2000/09/xmldsig#sha1"
        | "http://www.w3.org/2001/04/xmldsig-more#sha1" => Some(SigAlg::RsaSha1),
        _ => [SigAlg::Gost2015_512, SigAlg::Gost2004, SigAlg::RsaSha256]
            .into_iter()
            .find(|&alg| signing_uris(alg).is_some_and(|(_, digest)| digest == uri)),
    }
}

/// Error of an XML signature operation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum XmlError {
    /// The input is not well-formed UTF-8 XML (or not namespace-well-formed: an attribute
    /// with a prefix and the local name `xmlns`), or a signature is malformed.
    #[error("malformed XML: {0}")]
    Parse(String),
    /// The input has a DOCTYPE declaration.
    #[error("DOCTYPE is not allowed in XML")]
    Doctype,
    /// The input would take too much memory or work: larger than [`MAX_INPUT`], more than
    /// [`MAX_NODES`] nodes or `<` bytes, more than [`MAX_ATTRIBUTES`] `=` bytes, attributes
    /// or namespaces in scope beyond the parse work bounds (duplicate checks, namespace
    /// lookups and copies), a canonical form over [`MAX_CANONICAL`] bytes, or signature
    /// references whose count times the input size, or whose canonical forms together,
    /// exceed [`REFERENCE_WORK`].
    #[error("XML input exceeds the processing limits")]
    TooLarge,
    /// Elements are nested deeper than [`MAX_DEPTH`].
    #[error("XML elements are nested deeper than 256 levels")]
    TooDeep,
    /// The XPath is outside the supported subset.
    #[error("{0}")]
    XPath(String),
    /// The element to sign or the signature parent breaks a signing rule (not found, no
    /// `Id`, signature inside the signed element): Kalkan's `CREATE_XML_SIGNATURE_CONSTRAINT`.
    #[error("{0}")]
    Constraint(String),
    /// An algorithm, transform or reference form is not supported.
    #[error("unsupported XML signature algorithm {0}")]
    UnsupportedAlgorithm(String),
    /// The document has no signature.
    #[error("the XML document has no signature")]
    NoSignature,
    /// A reference digest does not match.
    #[error("XML signature reference digest does not match")]
    BadDigest,
    /// The signature value does not verify.
    #[error("XML signature value does not verify")]
    BadSignature,
    /// The key cannot be used with the algorithm.
    #[error("key: {0}")]
    Key(KeyError),
}

/// One verified signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlSignatureInfo {
    /// Signer certificate from `KeyInfo`.
    pub cert: Certificate,
    /// Signature algorithm.
    pub sig_alg: SigAlg,
}

/// Where a signature goes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Placement {
    /// Last child of the document element.
    #[default]
    DocumentElement,
    /// Last child of the document's first node, which must be an element (Santuario users
    /// that append to `document.getFirstChild()`).
    FirstChildOfDocument,
    /// Last child of the element [`XmlSignSpec::parent`] selects.
    Parent,
}

/// A transform of the signed reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transform {
    /// enveloped-signature: the signature itself is left out.
    Enveloped,
    /// A canonicalization (comments are left out of same-document references whatever it
    /// says).
    C14n(C14n),
}

/// A `ds:Object` holding the signing time, as `SignatureProperties`:
/// `<ds:SignatureProperty Id="<property_id>" Target="#<signature Id>">` around an
/// unqualified `<timestamp>` with `text`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningTimeObject<'a> {
    /// The `Id` of the `SignatureProperty`.
    pub property_id: &'a str,
    /// Whether a second reference (`URI="#<property_id>"`, the same transforms and digest)
    /// signs it.
    pub target_ref: bool,
    /// The text of `<timestamp>`.
    pub text: &'a str,
}

/// The bytes [`sign_spec`] returns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum XmlOutput {
    /// The input bytes with the signature spliced in.
    #[default]
    AsIs,
    /// As a JDK `Transformer` writes a document: the input's XML declaration replaced
    /// (`declaration`: by `<?xml version="1.0" encoding="UTF-8"?>`, with
    /// `standalone="no"` if `standalone_no`), nothing between it and the document's first
    /// node; with `trim`, no whitespace at either end. The rest keeps the input bytes.
    Serialize {
        /// Write an XML declaration.
        declaration: bool,
        /// With `standalone="no"`.
        standalone_no: bool,
        /// Drop whitespace at both ends (Java `String.trim()`).
        trim: bool,
    },
}

/// How to sign an XML document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlSignSpec<'a> {
    /// An XPath to the element to sign, which has an `Id` (`Reference URI="#Id"`);
    /// `None`: the whole document (`URI=""`).
    pub element: Option<&'a str>,
    /// An XPath to the element the signature goes into, with [`Placement::Parent`].
    pub parent: Option<&'a str>,
    /// Prefix → namespace URI for the XPaths; with them (or `other_prefix_uri`) names are
    /// matched by namespace, otherwise as written.
    pub namespaces: Vec<(&'a str, &'a str)>,
    /// The namespace of every prefix `namespaces` does not bind.
    pub other_prefix_uri: Option<&'a str>,
    /// Where the signature goes.
    pub placement: Placement,
    /// The `SignatureMethod` URI; `None`: Kalkan's for the certificate's algorithm. A URI
    /// must be known and fit the key.
    pub signature_method: Option<&'a str>,
    /// The `DigestMethod` URI; `None`: the one paired with the signature method.
    pub digest_method: Option<&'a str>,
    /// The `CanonicalizationMethod` of `SignedInfo`; `None`: Kalkan's (inclusive for the
    /// whole document, exclusive for an element).
    pub signed_info_c14n: Option<C14n>,
    /// The reference's transforms (enveloped-signature first, at most one
    /// canonicalization); `None`: Kalkan's (enveloped and inclusive with comments for the
    /// whole document, inclusive with comments for an element).
    pub transforms: Option<Vec<Transform>>,
    /// The `Id` of `ds:Signature`.
    pub signature_id: Option<&'a str>,
    /// A signing-time object (needs `signature_id`).
    pub signing_time_object: Option<SigningTimeObject<'a>>,
    /// No line breaks between the elements of the signature.
    pub strip_whitespace: bool,
    /// Base64 in lines of 76 characters (`None`: as Kalkan, in lines).
    pub base64_line_breaks: Option<bool>,
    /// The output form.
    pub output: XmlOutput,
}

impl<'a> XmlSignSpec<'a> {
    /// The signature Kalkan's `XMLUtil.createXmlSignature` makes: [`sign_enveloped`] without
    /// `element`, [`sign_element`] with it.
    pub fn kalkan(element: Option<&'a str>, parent: Option<&'a str>) -> Self {
        XmlSignSpec {
            element,
            parent,
            namespaces: Vec::new(),
            other_prefix_uri: None,
            placement: if parent.is_some() {
                Placement::Parent
            } else {
                Placement::DocumentElement
            },
            signature_method: None,
            digest_method: None,
            signed_info_c14n: None,
            transforms: None,
            signature_id: None,
            signing_time_object: None,
            strip_whitespace: false,
            base64_line_breaks: None,
            output: XmlOutput::AsIs,
        }
    }
}

/// Signs the whole document (enveloped signature, appended to the document element).
///
/// # Errors
///
/// The parsing errors, [`XmlError::UnsupportedAlgorithm`] for a certificate signature
/// algorithm other than GOST 2015-512, GOST 2004 or sha256RSA, [`XmlError::Key`] if the key
/// does not fit that algorithm.
pub fn sign_enveloped(
    xml: &[u8],
    key: &PrivateKey,
    cert: &Certificate,
) -> Result<Vec<u8>, XmlError> {
    sign_spec(xml, &XmlSignSpec::kalkan(None, None), key, cert)
}

/// Signs the element selected by `tbs_xpath`, which must have an `Id` attribute; the
/// signature goes into the element selected by `parent_xpath`, else into the document
/// element. Both XPaths are in the supported subset: absolute paths of element names as
/// written in the document, each step optionally `[n]`, `//` for descendants
/// (`/root/body[2]`, `//data`).
///
/// # Errors
///
/// As [`sign_enveloped`], plus [`XmlError::XPath`] for an unsupported XPath and
/// [`XmlError::Constraint`] if an element is not found, the element to sign has no `Id`
/// (Kalkan refuses such elements too) or an `Id` used twice, or the signature would land
/// inside the signed element. The element to sign not found and its missing `Id` have
/// Kalkan's (Russian) messages, which NCALayer sends to pages.
pub fn sign_element(
    xml: &[u8],
    tbs_xpath: &str,
    parent_xpath: Option<&str>,
    key: &PrivateKey,
    cert: &Certificate,
) -> Result<Vec<u8>, XmlError> {
    sign_spec(
        xml,
        &XmlSignSpec::kalkan(Some(tbs_xpath), parent_xpath),
        key,
        cert,
    )
}

/// Signs as `spec` says with `key`, whose certificate `cert` goes into `KeyInfo`.
///
/// # Errors
///
/// The parsing errors; [`XmlError::UnsupportedAlgorithm`] for an unknown URI or (without
/// one) a certificate algorithm Kalkan does not sign XML with; [`XmlError::XPath`] for an
/// unsupported XPath or an unbound prefix; [`XmlError::Constraint`] for what cannot be
/// signed so (an element not found or without a unique `Id`, a signature inside the
/// element it signs without the enveloped transform, the whole document without it, a
/// placement that does not fit `parent` or a document whose first node is not an element,
/// a URI that does not fit the key, transforms out of order, a signing-time object without
/// a signature `Id`); [`XmlError::Key`] if the key does not fit the certificate's algorithm.
pub fn sign_spec(
    xml: &[u8],
    spec: &XmlSignSpec<'_>,
    key: &PrivateKey,
    cert: &Certificate,
) -> Result<Vec<u8>, XmlError> {
    sign_with(xml, spec, key, cert, None)
}

/// [`sign_spec`] with XAdES qualifying properties in a `ds:Object` instead of a
/// signing-time object (the spec has none, and a signature `Id`); the result is spliced
/// as [`XmlOutput::AsIs`] whatever the spec says.
pub(crate) fn sign_qualified(
    xml: &[u8],
    spec: &XmlSignSpec<'_>,
    key: &PrivateKey,
    cert: &Certificate,
    qualifying: QualifyingObject<'_>,
) -> Result<Vec<u8>, XmlError> {
    if spec.signature_id.is_none() || spec.signing_time_object.is_some() {
        return Err(XmlError::Constraint(
            "qualifying properties need a signature Id and no signing-time object".to_owned(),
        ));
    }
    sign_with(
        xml,
        &XmlSignSpec {
            output: XmlOutput::AsIs,
            ..spec.clone()
        },
        key,
        cert,
        Some(qualifying),
    )
}

fn sign_with(
    xml: &[u8],
    spec: &XmlSignSpec<'_>,
    key: &PrivateKey,
    cert: &Certificate,
    qualifying: Option<QualifyingObject<'_>>,
) -> Result<Vec<u8>, XmlError> {
    let transforms = spec
        .transforms
        .clone()
        .unwrap_or_else(|| match spec.element {
            None => vec![
                Transform::Enveloped,
                Transform::C14n(C14n::InclusiveWithComments),
            ],
            Some(_) => vec![Transform::C14n(C14n::InclusiveWithComments)],
        });
    let reference_c14n = check_transforms(&transforms)?;
    let enveloped = transforms.contains(&Transform::Enveloped);
    if spec.signing_time_object.is_some() && spec.signature_id.is_none() {
        return Err(XmlError::Constraint(
            "a signing-time object needs a signature Id".to_owned(),
        ));
    }
    // Only one parse tree at a time: this one is gone before the signature is spliced in.
    let (algorithms, digest, point, uri, default_namespace) = {
        let doc = parse::parse(xml)?;
        // Kalkan parses, then checks the certificate algorithm, then evaluates the XPaths.
        let algorithms = Algorithms::of(spec, key, cert)?;
        let ns = (!spec.namespaces.is_empty() || spec.other_prefix_uri.is_some()).then_some(
            xpath::Namespaces {
                bindings: &spec.namespaces,
                other: spec.other_prefix_uri,
            },
        );
        let tbs = match spec.element {
            None if !enveloped => {
                return Err(XmlError::Constraint(
                    "signing the whole document needs the enveloped-signature transform".to_owned(),
                ));
            }
            None => None,
            Some(expr) => Some(xpath::select_first_in(&doc, expr, ns)?.ok_or_else(|| {
                XmlError::Constraint(format!("Указанный для подписи элемент {expr} не найден"))
            })?),
        };
        let parent = match (spec.placement, spec.parent) {
            (Placement::Parent, Some(expr)) => {
                xpath::select_first_in(&doc, expr, ns)?.ok_or_else(|| {
                    XmlError::Constraint(format!(
                        "the signature parent element {expr} is not found"
                    ))
                })?
            }
            (Placement::Parent, None) => {
                return Err(XmlError::Constraint(
                    "the parent placement needs a parent XPath".to_owned(),
                ));
            }
            (_, Some(_)) => {
                return Err(XmlError::Constraint(
                    "a parent XPath needs the parent placement".to_owned(),
                ));
            }
            (Placement::DocumentElement, None) => doc.root_element(),
            (Placement::FirstChildOfDocument, None) => doc
                .root()
                .first_child()
                .filter(Node::is_element)
                .ok_or_else(|| {
                    XmlError::Constraint(
                        "the first node of the document is not an element".to_owned(),
                    )
                })?,
        };
        let uri = match tbs {
            None => String::new(),
            Some(tbs) => {
                if !enveloped && parent.ancestors().any(|a| a == tbs) {
                    return Err(XmlError::Constraint(
                        "the signature cannot be placed inside the signed element".to_owned(),
                    ));
                }
                let id = tbs
                    .attribute("Id")
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| {
                        XmlError::Constraint(
                            "Указанный для подписи элемент не содержит атрибут 'Id'".to_owned(),
                        )
                    })?;
                if element_by_id(&doc, id).ok().flatten() != Some(tbs) {
                    return Err(XmlError::Constraint(format!(
                        "the Id {id:?} also belongs to another element"
                    )));
                }
                format!("#{id}")
            }
        };
        // The new signature is the only node the enveloped transform drops, so the digest
        // is that of the target as it is now; comments are out (a same-document reference).
        let target = tbs.unwrap_or_else(|| doc.root());
        let canonical = canonicalizer(reference_c14n).run(target)?;
        let point = SplicePoint::of(xml, parent)?;
        let default_namespace = parent
            .lookup_namespace_uri(None)
            .is_some_and(|uri| !uri.is_empty());
        drop(doc);
        (
            algorithms,
            algorithms.digest.digest(&canonical),
            point,
            uri,
            default_namespace,
        )
    };
    let method = spec.signed_info_c14n.unwrap_or(if spec.element.is_some() {
        C14n::Exclusive
    } else {
        C14n::Inclusive
    });
    let transform_uris: Vec<&str> = transforms
        .iter()
        .map(|t| match t {
            Transform::Enveloped => ENVELOPED_SIGNATURE,
            Transform::C14n(m) => m.uri(),
        })
        .collect();
    let template = Template {
        algorithms,
        method,
        uri: &uri,
        transforms: &transform_uris,
        digest,
        cert: cert_der(cert)?,
        id: spec.signature_id,
        object: match (spec.signing_time_object, qualifying) {
            (Some(object), _) => Some(ObjectTemplate::SigningTime {
                object,
                reset_default_namespace: default_namespace,
            }),
            (None, Some(qualifying)) => Some(ObjectTemplate::Qualifying(qualifying)),
            (None, None) => None,
        },
        reference_c14n,
        separator: if spec.strip_whitespace { "" } else { "\n" },
        line_breaks: spec.base64_line_breaks.unwrap_or(true),
    };
    let signed = template.insert(xml, &point, key)?;
    Ok(output(signed, spec.output))
}

/// The reference's canonicalization: enveloped-signature may come first, then at most one
/// canonicalization (inclusive without one).
fn check_transforms(transforms: &[Transform]) -> Result<C14n, XmlError> {
    let rest = match transforms {
        [Transform::Enveloped, rest @ ..] => rest,
        rest => rest,
    };
    match rest {
        [] => Ok(C14n::Inclusive),
        [Transform::C14n(method)] => Ok(*method),
        _ => Err(XmlError::Constraint(
            "transforms: enveloped-signature first, then at most one canonicalization".to_owned(),
        )),
    }
}

/// The signing and digest algorithms of a signature, with their URIs.
#[derive(Clone, Copy, Debug)]
struct Algorithms<'a> {
    signature: SigAlg,
    signature_uri: &'a str,
    digest: HashAlg,
    digest_uri: &'a str,
}

impl<'a> Algorithms<'a> {
    fn of(spec: &XmlSignSpec<'a>, key: &PrivateKey, cert: &Certificate) -> Result<Self, XmlError> {
        let (signature, signature_uri, paired) = match spec.signature_method {
            None => {
                let alg = signing_alg(cert)?;
                let (sig, digest) = signing_uris(alg).expect("signing algorithm");
                (alg, sig, digest)
            }
            Some(uri) => {
                let alg = signature_method(uri)
                    .ok_or_else(|| XmlError::UnsupportedAlgorithm(uri.to_owned()))?;
                if alg == SigAlg::RsaSha1 {
                    return Err(XmlError::Constraint(format!(
                        "the signature method {uri} is unsupported: SHA-1 RSA signatures are not made"
                    )));
                }
                if alg.key_alg() != key.alg() {
                    return Err(XmlError::Constraint(format!(
                        "the signature method {uri} does not fit the key"
                    )));
                }
                (alg, uri, signing_uris(alg).expect("a signing algorithm").1)
            }
        };
        let digest_uri = spec.digest_method.unwrap_or(paired);
        let digest = digest_method(digest_uri)
            .ok_or_else(|| XmlError::UnsupportedAlgorithm(digest_uri.to_owned()))?
            .hash_alg();
        Ok(Algorithms {
            signature,
            signature_uri,
            digest,
            digest_uri,
        })
    }
}

/// `signed` in the `output` form.
fn output(signed: Vec<u8>, output: XmlOutput) -> Vec<u8> {
    let XmlOutput::Serialize {
        declaration,
        standalone_no,
        trim,
    } = output
    else {
        return signed;
    };
    let mut body = signed.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&signed);
    if body.starts_with(b"<?xml")
        && let Some(end) = body.windows(2).position(|w| w == b"?>")
    {
        body = &body[end + 2..];
    }
    // The document's prolog whitespace is not part of a DOM.
    let start = body
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(body.len());
    let mut body = &body[start..];
    if trim {
        // `String.trim()`: every character up to U+0020.
        while let [rest @ .., last] = body
            && *last <= b' '
        {
            body = rest;
        }
    }
    let mut out = Vec::with_capacity(body.len() + 60);
    if declaration {
        out.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"UTF-8\"");
        if standalone_no {
            out.extend_from_slice(b" standalone=\"no\"");
        }
        out.extend_from_slice(b"?>");
    }
    out.extend_from_slice(body);
    out
}

/// One signature found by [`verify_each`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlSignatureCheck {
    /// The certificate of its `KeyInfo`, if it reads.
    pub cert: Option<Certificate>,
    /// Its algorithm if it verifies, else why not.
    pub result: Result<SigAlg, XmlError>,
}

/// Checks every signature of the document as [`verify`] does, but each on its own: the
/// signatures in document order, whether each verifies. A document without signatures has
/// none.
///
/// # Errors
///
/// The parsing errors of the document, and [`XmlError::TooLarge`] as [`verify`].
pub fn verify_each(xml: &[u8]) -> Result<Vec<XmlSignatureCheck>, XmlError> {
    let doc = parse::parse(xml)?;
    let (signatures, mut budget) = signatures(&doc, xml.len())?;
    let root = doc.root_element();
    let mut checks = Vec::with_capacity(signatures.len());
    let mut appended_later: Vec<NodeId> = Vec::new();
    for signature in signatures.iter().rev() {
        checks.push(XmlSignatureCheck {
            cert: signature_cert(*signature).ok(),
            result: verify_signature(&doc, *signature, &appended_later, &mut budget)
                .map(|info| info.sig_alg),
        });
        if signature.parent() == Some(root) {
            appended_later.insert(0, signature.id());
        }
    }
    checks.reverse();
    Ok(checks)
}

/// Verifies every signature of the document, from the last to the first, each against the
/// certificate in its own `KeyInfo`. Signatures are the `ds:Signature` elements not nested in
/// another one. A signature is checked as if the later signatures that are children of the
/// document element were removed, as NCANode does (`root.removeChild`), so signatures
/// appended one after another all verify; a later signature placed anywhere else (inside a
/// signed element, say) stays part of what earlier signatures cover.
///
/// Returns the signatures in that order (last first).
///
/// # Errors
///
/// The parsing errors, [`XmlError::NoSignature`], [`XmlError::BadSignature`],
/// [`XmlError::BadDigest`], [`XmlError::UnsupportedAlgorithm`], [`XmlError::Key`] if the
/// certificate key does not fit the signature algorithm, [`XmlError::Parse`] for a malformed
/// signature, [`XmlError::TooLarge`] if the references times the input size exceed
/// [`REFERENCE_WORK`], or the canonical forms together would.
pub fn verify(xml: &[u8]) -> Result<Vec<XmlSignatureInfo>, XmlError> {
    let doc = parse::parse(xml)?;
    let (signatures, mut budget) = signatures(&doc, xml.len())?;
    if signatures.is_empty() {
        return Err(XmlError::NoSignature);
    }
    let root = doc.root_element();
    let mut infos = Vec::with_capacity(signatures.len());
    // Appended signatures (children of the document element) after the current one.
    let mut appended_later: Vec<NodeId> = Vec::new();
    for signature in signatures.iter().rev() {
        infos.push(verify_signature(
            &doc,
            *signature,
            &appended_later,
            &mut budget,
        )?);
        if signature.parent() == Some(root) {
            appended_later.insert(0, signature.id());
        }
    }
    Ok(infos)
}

/// The signatures of a document of `len` bytes (the `ds:Signature` elements not nested in
/// another one), in document order, and the bytes their verification may canonicalize.
///
/// # Errors
///
/// [`XmlError::TooLarge`] if the references times `len` exceed [`REFERENCE_WORK`]: each
/// reference may canonicalize the whole document.
fn signatures<'a, 'i>(
    doc: &'a Document<'i>,
    len: usize,
) -> Result<(Vec<Node<'a, 'i>>, usize), XmlError> {
    let signatures: Vec<Node<'_, '_>> = doc
        .root_element()
        .descendants()
        .filter(|n| is_ds(*n, "Signature") && !n.ancestors().skip(1).any(|a| is_ds(a, "Signature")))
        .collect();
    let references: usize = signatures
        .iter()
        .filter_map(|s| ds_child(*s, "SignedInfo").ok())
        .map(|info| info.children().filter(|n| is_ds(*n, "Reference")).count())
        .sum();
    if references.saturating_mul(len) > REFERENCE_WORK {
        return Err(XmlError::TooLarge);
    }
    Ok((signatures, REFERENCE_WORK))
}

/// Algorithm for signing with `cert`.
fn signing_alg(cert: &Certificate) -> Result<SigAlg, XmlError> {
    let oid = cert.signature_algorithm().oid;
    SigAlg::from_signature_oid(&oid)
        .filter(|&alg| signing_uris(alg).is_some())
        .ok_or_else(|| XmlError::UnsupportedAlgorithm(oid.to_string()))
}

fn cert_der(cert: &Certificate) -> Result<Vec<u8>, XmlError> {
    cert.to_der()
        .map_err(|e| XmlError::Parse(format!("signer certificate: {e}")))
}

/// Canonicalizer for signing: no comments, no subtree left out.
fn canonicalizer(method: C14n) -> Canonicalizer<'static> {
    Canonicalizer {
        exclusive: method.is_exclusive(),
        comments: false,
        inclusive_prefixes: &[],
        excluded: &[],
        limit: MAX_CANONICAL,
    }
}

/// The `ds:Object` of a signature to write.
enum ObjectTemplate<'t> {
    /// A signing-time object.
    SigningTime {
        object: SigningTimeObject<'t>,
        /// The signature's parent has a default namespace: `<timestamp>` resets it.
        reset_default_namespace: bool,
    },
    /// XAdES qualifying properties.
    Qualifying(QualifyingObject<'t>),
}

impl ObjectTemplate<'_> {
    /// The `Id`, `Type`, transforms and canonicalization of the second reference, if the
    /// object has one.
    fn reference<'s>(
        &'s self,
        template: &'s Template<'_>,
    ) -> Option<(&'s str, Option<&'static str>, Vec<&'s str>, C14n)> {
        match self {
            ObjectTemplate::SigningTime { object, .. } => object.target_ref.then(|| {
                (
                    object.property_id,
                    None,
                    template.transforms.to_vec(),
                    template.reference_c14n,
                )
            }),
            ObjectTemplate::Qualifying(q) => Some((
                q.signed_properties_id,
                Some(SIGNED_PROPERTIES_TYPE),
                vec![C14n::Exclusive.uri()],
                C14n::Exclusive,
            )),
        }
    }
}

/// The signature to write.
struct Template<'t> {
    algorithms: Algorithms<'t>,
    method: C14n,
    uri: &'t str,
    transforms: &'t [&'t str],
    digest: Vec<u8>,
    cert: Vec<u8>,
    id: Option<&'t str>,
    object: Option<ObjectTemplate<'t>>,
    /// The canonicalization of the references.
    reference_c14n: C14n,
    /// Between the elements: a line break, or nothing.
    separator: &'static str,
    /// Base64 in lines.
    line_breaks: bool,
}

impl Template<'_> {
    fn base64(&self, bytes: &[u8]) -> String {
        if self.line_breaks {
            base64_lines(bytes)
        } else {
            STANDARD.encode(bytes)
        }
    }

    fn reference(
        &self,
        s: &mut String,
        uri: &str,
        kind: Option<&str>,
        transforms: &[&str],
        digest: &[u8],
    ) {
        let n = self.separator;
        let kind = kind
            .map(|kind| format!(" Type=\"{}\"", escape_attribute(kind)))
            .unwrap_or_default();
        s.push_str(&format!(
            "<ds:Reference URI=\"{}\"{kind}>{n}<ds:Transforms>{n}",
            escape_attribute(uri)
        ));
        for transform in transforms {
            s.push_str(&format!("<ds:Transform Algorithm=\"{transform}\"/>{n}"));
        }
        s.push_str(&format!(
            "</ds:Transforms>{n}<ds:DigestMethod Algorithm=\"{}\"/>{n}\
             <ds:DigestValue>{}</ds:DigestValue>{n}</ds:Reference>{n}",
            escape_attribute(self.algorithms.digest_uri),
            self.base64(digest),
        ));
    }

    /// `ds:Signature` element; without `value` the `SignatureValue` is empty, without
    /// `object_digest` the signing-time object's reference has an empty digest.
    fn render(&self, value: Option<&[u8]>, object_digest: Option<&[u8]>) -> String {
        let n = self.separator;
        let id = self
            .id
            .map(|id| format!(" Id=\"{}\"", escape_attribute(id)))
            .unwrap_or_default();
        let mut s = format!(
            "<ds:Signature xmlns:ds=\"{DSIG_NS}\"{id}>{n}<ds:SignedInfo>{n}\
             <ds:CanonicalizationMethod Algorithm=\"{}\"/>{n}\
             <ds:SignatureMethod Algorithm=\"{}\"/>{n}",
            self.method.uri(),
            escape_attribute(self.algorithms.signature_uri),
        );
        self.reference(&mut s, self.uri, None, self.transforms, &self.digest);
        if let Some((id, kind, transforms, _)) =
            self.object.as_ref().and_then(|o| o.reference(self))
        {
            let uri = format!("#{id}");
            self.reference(
                &mut s,
                &uri,
                kind,
                &transforms,
                object_digest.unwrap_or_default(),
            );
        }
        s.push_str(&format!("</ds:SignedInfo>{n}<ds:SignatureValue>"));
        if let Some(value) = value {
            // Santuario puts a long value on lines of its own.
            let text = self.base64(value);
            if self.line_breaks && text.len() > 76 {
                s.push_str(&format!("\n{text}\n"));
            } else {
                s.push_str(&text);
            }
        }
        let cert = self.base64(&self.cert);
        let cert = if self.line_breaks {
            format!("\n{cert}\n")
        } else {
            cert
        };
        s.push_str(&format!(
            "</ds:SignatureValue>{n}<ds:KeyInfo>{n}<ds:X509Data>{n}<ds:X509Certificate>{cert}\
             </ds:X509Certificate>{n}</ds:X509Data>{n}</ds:KeyInfo>{n}"
        ));
        match &self.object {
            Some(ObjectTemplate::SigningTime {
                object,
                reset_default_namespace,
            }) => {
                let reset = if *reset_default_namespace {
                    " xmlns=\"\""
                } else {
                    ""
                };
                s.push_str(&format!(
                    "<ds:Object>{n}<ds:SignatureProperties>{n}\
                     <ds:SignatureProperty Id=\"{}\" Target=\"#{}\">{n}\
                     <timestamp{reset}>{}</timestamp>{n}</ds:SignatureProperty>{n}\
                     </ds:SignatureProperties>{n}</ds:Object>{n}",
                    escape_attribute(object.property_id),
                    escape_attribute(self.id.unwrap_or_default()),
                    escape_text(object.text),
                ));
            }
            Some(ObjectTemplate::Qualifying(q)) => s.push_str(&format!(
                "<ds:Object>{n}<xades:QualifyingProperties xmlns:xades=\"{XADES_NS}\" \
                 Target=\"#{}\">{n}{}{n}</xades:QualifyingProperties>{n}</ds:Object>{n}",
                escape_attribute(self.id.unwrap_or_default()),
                q.signed_properties,
            )),
            None => {}
        }
        s.push_str("</ds:Signature>");
        s
    }

    /// The signature spliced into `xml` at `point`, parsed: `f` on its element.
    fn in_place<T>(
        &self,
        xml: &[u8],
        point: &SplicePoint,
        object_digest: Option<&[u8]>,
        f: impl FnOnce(Node<'_, '_>) -> Result<T, XmlError>,
    ) -> Result<T, XmlError> {
        let unsigned = point.splice(xml, &self.render(None, object_digest));
        let doc = parse::parse_signed(&unsigned)?;
        let signature = doc
            .descendants()
            .find(|n| n.is_element() && n.range().start == point.signature_offset())
            .expect("the inserted signature");
        f(signature)
    }

    /// Splices the signature into the parent at `point` as its last child, then fills in the
    /// signing-time object's digest over the object as canonicalized in place, and the value
    /// over the SignedInfo as canonicalized in place.
    fn insert(
        &self,
        xml: &[u8],
        point: &SplicePoint,
        key: &PrivateKey,
    ) -> Result<Vec<u8>, XmlError> {
        let object_digest = match self.object.as_ref().and_then(|o| o.reference(self)) {
            Some((id, _, _, c14n)) => Some(self.in_place(xml, point, None, |signature| {
                let target = signature
                    .descendants()
                    .find(|n| n.is_element() && n.attribute("Id") == Some(id))
                    .expect("the object's signed element");
                // The enveloped-signature transform does not drop it: a document-order
                // filter of a subtree inside the signature never meets the signature.
                let canonical = canonicalizer(c14n).run(target)?;
                Ok(self.algorithms.digest.digest(&canonical))
            })?),
            None => None,
        };
        let tbs = self.in_place(xml, point, object_digest.as_deref(), |signature| {
            let signed_info = signature.first_element_child().expect("SignedInfo");
            canonicalizer(self.method).run(signed_info)
        })?;
        let value = key
            .sign(self.algorithms.signature, &tbs)
            .map_err(XmlError::Key)?;
        Ok(point.splice(xml, &self.render(Some(&value), object_digest.as_deref())))
    }
}

/// Where a signature goes into its parent: before the parent's end tag, or into its
/// empty-element tag, which is opened (`<p/>` becomes `<p>…</p>`).
struct SplicePoint {
    /// Input offset of the parent's end tag, or of the `/>` of its empty-element tag.
    at: usize,
    /// Qualified name of an empty-element parent, closed after the signature.
    close: Option<String>,
}

impl SplicePoint {
    fn of(xml: &[u8], parent: Node<'_, '_>) -> Result<SplicePoint, XmlError> {
        let range = parent.range();
        if xml[..range.end].ends_with(b"/>") {
            return Ok(SplicePoint {
                at: range.end - 2,
                close: Some(parse::element_qname(parent).to_owned()),
            });
        }
        let at = xml[range.clone()]
            .windows(2)
            .rposition(|w| w == b"</")
            .map(|p| range.start + p)
            .ok_or_else(|| XmlError::Parse("element without an end tag".to_owned()))?;
        Ok(SplicePoint { at, close: None })
    }

    /// Offset of the signature in the spliced document.
    fn signature_offset(&self) -> usize {
        self.at + usize::from(self.close.is_some())
    }

    /// `xml` with `signature` spliced in; the other input bytes are kept.
    fn splice(&self, xml: &[u8], signature: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            xml.len() + signature.len() + 3 + self.close.as_ref().map_or(0, String::len),
        );
        out.extend_from_slice(&xml[..self.at]);
        match &self.close {
            Some(qname) => {
                out.push(b'>');
                out.extend_from_slice(signature.as_bytes());
                out.extend_from_slice(b"</");
                out.extend_from_slice(qname.as_bytes());
                out.push(b'>');
                out.extend_from_slice(&xml[self.at + 2..]);
            }
            None => {
                out.extend_from_slice(signature.as_bytes());
                out.extend_from_slice(&xml[self.at..]);
            }
        }
        out
    }
}

/// The signature of `doc` whose `Id` is `id`.
fn signature_by_id<'a, 'i>(doc: &'a Document<'i>, id: &str) -> Result<Node<'a, 'i>, XmlError> {
    doc.descendants()
        .find(|n| is_ds(*n, "Signature") && n.attribute("Id") == Some(id))
        .ok_or_else(|| malformed(&format!("no signature with Id {id:?}")))
}

/// The `ds:SignatureValue` of the signature `id` in `signed` (a document [`sign_qualified`]
/// made), canonicalized in place with Exclusive XML Canonicalization: what a XAdES
/// `SignatureTimeStamp` stamps.
pub(crate) fn signature_value_c14n(signed: &[u8], id: &str) -> Result<Vec<u8>, XmlError> {
    let doc = parse::parse_signed(signed)?;
    let value = ds_child(signature_by_id(&doc, id)?, "SignatureValue")?;
    canonicalizer(C14n::Exclusive).run(value)
}

/// `signed` (a document [`sign_qualified`] made) with `properties` spliced in as the last
/// child of the `xades:QualifyingProperties` of the signature `id`; the other bytes are
/// kept.
pub(crate) fn append_qualifying(
    signed: &[u8],
    id: &str,
    properties: &str,
) -> Result<Vec<u8>, XmlError> {
    let doc = parse::parse_signed(signed)?;
    let qualifying = signature_by_id(&doc, id)?
        .children()
        .filter(|n| is_ds(*n, "Object"))
        .flat_map(|object| object.children())
        .find(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(XADES_NS)
                && n.tag_name().name() == "QualifyingProperties"
        })
        .ok_or_else(|| malformed("the signature has no xades:QualifyingProperties"))?;
    let point = SplicePoint::of(signed, qualifying)?;
    Ok(point.splice(signed, properties))
}

/// The certificate of a signature's `KeyInfo/X509Data/X509Certificate`.
fn signature_cert(signature: Node<'_, '_>) -> Result<Certificate, XmlError> {
    let certificate = ds_child(signature, "KeyInfo")?
        .children()
        .filter(|n| is_ds(*n, "X509Data"))
        .flat_map(|data| data.children().filter(|n| is_ds(*n, "X509Certificate")))
        .next()
        .ok_or_else(|| malformed("no KeyInfo/X509Data/X509Certificate"))?;
    cert::parse(&base64_content(certificate)?)
        .map_err(|e| XmlError::Parse(format!("signer certificate: {e}")))
}

fn verify_signature(
    doc: &Document<'_>,
    signature: Node<'_, '_>,
    later: &[NodeId],
    budget: &mut usize,
) -> Result<XmlSignatureInfo, XmlError> {
    let signed_info = ds_child(signature, "SignedInfo")?;
    let method_element = ds_child(signed_info, "CanonicalizationMethod")?;
    let method_uri = algorithm(method_element)?;
    let method = C14n::from_uri(method_uri)
        .ok_or_else(|| XmlError::UnsupportedAlgorithm(method_uri.to_owned()))?;
    let sig_uri = algorithm(ds_child(signed_info, "SignatureMethod")?)?;
    let alg = signature_method(sig_uri)
        .ok_or_else(|| XmlError::UnsupportedAlgorithm(sig_uri.to_owned()))?;
    let value = base64_content(ds_child(signature, "SignatureValue")?)?;

    let cert = signature_cert(signature)?;
    let public = PublicKey::from_spki(cert.tbs_certificate().subject_public_key_info())
        .map_err(XmlError::Key)?;

    let prefixes = inclusive_prefixes(method_element);
    let tbs = run_within(
        Canonicalizer {
            exclusive: method.is_exclusive(),
            comments: method.with_comments(),
            inclusive_prefixes: &prefixes,
            excluded: &[],
            limit: 0,
        },
        signed_info,
        budget,
    )?;
    public.verify(alg, &tbs, &value).map_err(|e| match e {
        KeyError::BadSignature => XmlError::BadSignature,
        e => XmlError::Key(e),
    })?;

    let mut references = signed_info
        .children()
        .filter(|n| is_ds(*n, "Reference"))
        .peekable();
    if references.peek().is_none() {
        return Err(malformed("SignedInfo has no Reference"));
    }
    for reference in references {
        verify_reference(doc, signature, reference, later, budget)?;
    }
    Ok(XmlSignatureInfo { cert, sig_alg: alg })
}

/// Runs `canonicalizer` on `node` within what is left of the verification budget.
fn run_within(
    mut canonicalizer: Canonicalizer<'_>,
    node: Node<'_, '_>,
    budget: &mut usize,
) -> Result<Vec<u8>, XmlError> {
    canonicalizer.limit = MAX_CANONICAL.min(*budget);
    let out = canonicalizer.run(node)?;
    *budget -= out.len();
    Ok(out)
}

fn verify_reference(
    doc: &Document<'_>,
    signature: Node<'_, '_>,
    reference: Node<'_, '_>,
    later: &[NodeId],
    budget: &mut usize,
) -> Result<(), XmlError> {
    let uri = reference
        .attribute("URI")
        .ok_or_else(|| XmlError::UnsupportedAlgorithm("Reference without URI".to_owned()))?;
    let target = match uri.strip_prefix('#') {
        None if uri.is_empty() => doc.root(),
        Some(id) if !id.starts_with("xpointer(") => element_by_id(doc, id)?
            .ok_or_else(|| malformed(&format!("no element with Id {id:?}")))?,
        _ => {
            return Err(XmlError::UnsupportedAlgorithm(format!(
                "Reference URI {uri:?}"
            )));
        }
    };

    let mut enveloped = false;
    let mut method = None;
    if let Ok(transforms) = ds_child(reference, "Transforms") {
        for transform in transforms.children().filter(|n| is_ds(*n, "Transform")) {
            let uri = algorithm(transform)?;
            match (method, C14n::from_uri(uri)) {
                (None, _) if uri == ENVELOPED_SIGNATURE => enveloped = true,
                (None, Some(m)) => method = Some((m, transform)),
                _ => return Err(XmlError::UnsupportedAlgorithm(uri.to_owned())),
            }
        }
    }
    let (method, prefixes) = match method {
        Some((m, transform)) => (m, inclusive_prefixes(transform)),
        None => (C14n::Inclusive, Vec::new()),
    };
    // In document order: the signature itself comes before the later ones.
    let excluded: Vec<NodeId> = enveloped
        .then_some(signature.id())
        .into_iter()
        .chain(later.iter().copied())
        .collect();
    let data = run_within(
        Canonicalizer {
            exclusive: method.is_exclusive(),
            // Same-document references drop comments.
            comments: false,
            inclusive_prefixes: &prefixes,
            excluded: &excluded,
            limit: 0,
        },
        target,
        budget,
    )?;

    let digest_uri = algorithm(ds_child(reference, "DigestMethod")?)?;
    let digest_alg = digest_method(digest_uri)
        .ok_or_else(|| XmlError::UnsupportedAlgorithm(digest_uri.to_owned()))?;
    if digest_alg.digest(&data) != base64_content(ds_child(reference, "DigestValue")?)? {
        return Err(XmlError::BadDigest);
    }
    Ok(())
}

fn malformed(what: &str) -> XmlError {
    XmlError::Parse(format!("malformed XML signature: {what}"))
}

fn is_ds(node: Node<'_, '_>, local: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(DSIG_NS)
        && node.tag_name().name() == local
}

fn ds_child<'a, 'i>(node: Node<'a, 'i>, local: &str) -> Result<Node<'a, 'i>, XmlError> {
    node.children()
        .find(|n| is_ds(*n, local))
        .ok_or_else(|| malformed(&format!("no ds:{local}")))
}

fn algorithm<'a>(node: Node<'a, '_>) -> Result<&'a str, XmlError> {
    node.attribute("Algorithm")
        .ok_or_else(|| malformed(&format!("{} without Algorithm", node.tag_name().name())))
}

/// `InclusiveNamespaces PrefixList` of an exclusive canonicalization element, sorted;
/// `#default` becomes `""`.
fn inclusive_prefixes<'a>(method: Node<'a, '_>) -> Vec<&'a str> {
    let mut prefixes: Vec<&str> = method
        .children()
        .find(|n| {
            n.tag_name().namespace() == Some(EXC_C14N_NS)
                && n.tag_name().name() == "InclusiveNamespaces"
        })
        .and_then(|n| n.attribute("PrefixList"))
        .map(|list| {
            list.split_ascii_whitespace()
                .map(|p| if p == "#default" { "" } else { p })
                .collect()
        })
        .unwrap_or_default();
    prefixes.sort_unstable();
    prefixes.dedup();
    prefixes
}

/// The element whose `Id`, `ID` or `id` attribute is `id`; an `Id` on two elements is an
/// error (a signature wrapping attack, or an ambiguous reference).
fn element_by_id<'a, 'i>(
    doc: &'a Document<'i>,
    id: &str,
) -> Result<Option<Node<'a, 'i>>, XmlError> {
    let mut found = doc.descendants().filter(|n| {
        n.is_element()
            && ["Id", "ID", "id"]
                .iter()
                .any(|name| n.attribute(*name) == Some(id))
    });
    let first = found.next();
    if found.next().is_some() {
        return Err(malformed(&format!("Id {id:?} is not unique")));
    }
    Ok(first)
}

/// Base64 content of an element, XML whitespace ignored.
fn base64_content(node: Node<'_, '_>) -> Result<Vec<u8>, XmlError> {
    let text: Vec<u8> = node
        .descendants()
        .filter(Node::is_text)
        .flat_map(|t| t.text().unwrap_or("").bytes())
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    STANDARD
        .decode(text)
        .map_err(|e| malformed(&format!("bad base64 in {}: {e}", node.tag_name().name())))
}

/// Base64 in lines of 76 characters, each line break written as Santuario's serializer
/// writes the MIME `\r\n`: `&#13;` and a line feed.
fn base64_lines(bytes: &[u8]) -> String {
    let encoded = STANDARD.encode(bytes);
    encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("&#13;\n")
}
