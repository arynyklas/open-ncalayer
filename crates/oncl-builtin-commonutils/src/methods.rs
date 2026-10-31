//! The public methods of the original's `CommonUtils`. Each answers like its
//! `ResponseMessage`: `200` with a `responseObject` (none for `changeLocale`), or `500` with
//! the exception's message (none where the original's exception has none).
//!
//! The signing methods first ask for the key ([`choose_key`]):
//!
//! - an empty (or blank) `storageName` is `storageName.param.empty`, a name Kalkan does not
//!   know `storage.unknown`, a hardware token `storage.empty` when none of its family is
//!   connected (always with token support off), as is the cloud storage;
//! - a token storage with such a token connected opens the storage dialog for that storage
//!   alone, in the first reader holding one (the original does not ask which), for the PIN;
//!   the key dialog follows as for the files below;
//! - `PKCS12` and `JKS` (read-only) open the storage dialog for that storage alone, then the
//!   key dialog with the keys whose certificate is of the requested `keyType`, any other
//!   `keyType` meaning SIGNATURE or AUTHENTICATION, newest certificate first. A store
//!   without such keys is asked for again, with the original's message for the type.
//!   Cancelling either dialog is `action.canceled`.
//!
//! `createCAdESFromBase64`, `createCAdESFromBase64Hash` and `applyCAdEST` then check the
//! signer's certificate chain against the core's CAs, as the original's
//! `getSigningEntityDefaultChained` does with its bundled CA list (expired keys at their
//! notAfter). Base64 inputs are decoded after the dialogs, with Java's decoder and its
//! messages. Paths a page names (`createCAdESFromFile`, `createCMSSignatureFromFile`) are
//! read before any dialog (by the core: regular files of at most 64 MiB, local or on a
//! network path the user chose in the file chooser) and shown in both dialogs as absolute
//! paths.

use crate::dispatch::Args;
use crate::{Chosen, Core};
use oncl_pdk::abi::{
    Action, Bytes, CmsCerts, CmsContent, CmsOutcome, CmsOutput, CoSign, FlowArgs, FlowChecks,
    FlowFile, FlowNone, FlowOrder, FlowReader, FlowReaders, FlowStart, HostError, PageRead,
    PathOutcome, SignCmsExArgs, SignedAttrs, SignerSel, SigningTime, StampArgs, StampMode,
    StampOutcome, TimeForm, TimeSource, TokenForm, TsaChoice, cause,
};
use oncl_pdk::{AddInfo, Locale};
use serde::Serialize;
use serde_json::{Value, json};

/// A method's reply: `Ok` is `200` with the `responseObject` if any, `Err` is `500` with the
/// `message` if any.
pub(crate) type Outcome = Result<Option<Value>, Option<String>>;

const ACTION_CANCELED: &str = "action.canceled";
const STORAGE_NAME_EMPTY: &str = "storageName.param.empty";
const STORAGE_UNKNOWN: &str = "storage.unknown";
const STORAGE_EMPTY: &str = "storage.empty";
const FILE_NOT_FOUND: &str = "file.not_found";
const FILE_TOO_LARGE: &str = "file.too_large: files over 64 MiB are not signed";
const UNKNOWN_ALGORITHM: &str = "UNKNOWN_ALGORITHM";
const CMS_NO_ENCAPSULATED_DATA: &str = "CMS_NO_ENCAPSULATED_DATA";
const ISSUER_CERT_NOT_FOUND: &str = "ISSUER_CERT_NOT_FOUND";
/// sha1WithRSAEncryption: the original signs XML with it, the core refuses.
const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";

/// The storages Kalkan knows, in its order; `PKCS12` and `JKS` are files, the others
/// tokens (the cloud storage never has one).
const STORAGES: [&str; 9] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKEToken72KStore",
    "AKEToken5110Store",
    "AKJaCartaStore",
    "AKAKEYStore",
    "PKCS12",
    "JKS",
    "ABCloudServiceStore",
];

/// The file types of the file chooser (`FileChooser.FileType`).
const FILE_TYPES: [&str; 7] = ["DIRECTORY", "CRL", "CER", "P12", "KEYSTORE", "JKS", "ALL"];

/// Kalkan's certificate types (`KNCACertificateType`).
const KNCA_TYPES: [&str; 5] = [
    "SIGNATURE",
    "AUTHENTICATION",
    "SSL",
    "OCSP_RESPONSE_SIGNING",
    "TSP_SIGNING",
];

/// `getActiveTokens()`: the storages with a connected token, in Kalkan's order; none with
/// token support off or without the smart card service.
pub(crate) fn get_active_tokens<C: Core>(cu: &C, _: &Args<'_>, _: &AddInfo) -> Outcome {
    Ok(Some(json!(cu.active_tokens())))
}

/// `getKeyInfo(storageName)`: the chosen key's certificate details, nothing signed.
pub(crate) fn get_key_info<C: Core>(cu: &C, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    let key = choose_key(cu, args.str(0), None, Action::KeyInfo, None, add_info)?;
    Ok(Some(key_info(cu, &key)))
}

/// `signXml(storageName, keyType, xml, tbsElementXPath, signatureParentElementXPath)`.
pub(crate) fn sign_xml<C: Core>(cu: &C, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    let key = signing_key(cu, args.str(0), args.str(1), add_info)?;
    let signed = sign_one_xml(cu, &key, args.str(2), args.str(3), args.str(4))?;
    Ok(Some(Value::String(signed)))
}

/// `signXmls(storageName, keyType, String[] xmls, tbsElementXPath,
/// signatureParentElementXPath)`: every document with the key of one dialog.
pub(crate) fn sign_xmls<C: Core>(cu: &C, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    let key = signing_key(cu, args.str(0), args.str(1), add_info)?;
    let signed = args
        .strs(2)
        .iter()
        .map(|xml| sign_one_xml(cu, &key, xml, args.str(3), args.str(4)).map(Value::String))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(Value::Array(signed)))
}

/// `createCMSSignatureFromBase64(storageName, keyType, base64Data, attached)` (deprecated in
/// the original): CAdES with a time-stamp from Kalkan's TSA on the chosen key's signer.
pub(crate) fn create_cms_signature_from_base64<C: Core>(
    cu: &C,
    args: &Args<'_>,
    add_info: &AddInfo,
) -> Outcome {
    let request = Signing {
        storage_name: args.str(0),
        key_type: key_type(args.str(1)),
        detail: None,
    };
    cms_with_timestamp(
        cu,
        &request,
        Data::Base64(args.str(2)),
        args.bool(3),
        add_info,
    )
}

/// `createCMSSignatureFromFile(storageName, keyType, filePath, attached)`:
/// [`create_cms_signature_from_base64`] of the file's contents.
pub(crate) fn create_cms_signature_from_file<C: Core>(
    cu: &C,
    args: &Args<'_>,
    add_info: &AddInfo,
) -> Outcome {
    let (shown, data) = read_page_file(cu, args.str(2))?;
    let request = Signing {
        storage_name: args.str(0),
        key_type: key_type(args.str(1)),
        detail: Some(file_detail(cu.locale(), &shown)),
    };
    cms_with_timestamp(cu, &request, Data::Bytes(data), args.bool(3), add_info)
}

/// `createCAdESFromBase64(storageName, keyType, base64Data, attached)`: CAdES without a
/// time-stamp; a CMS with encapsulated content as the data gets the new signer added.
pub(crate) fn create_cades_from_base64<C: Core>(
    cu: &C,
    args: &Args<'_>,
    add_info: &AddInfo,
) -> Outcome {
    let request = Signing {
        storage_name: args.str(0),
        key_type: key_type(args.str(1)),
        detail: None,
    };
    let content = Content::Data {
        attached: args.bool(3),
    };
    cades(cu, &request, Data::Base64(args.str(2)), content, add_info)
}

/// `createCAdESFromFile(storageName, keyType, filePath, attached)`:
/// [`create_cades_from_base64`] of the file's contents.
pub(crate) fn create_cades_from_file<C: Core>(
    cu: &C,
    args: &Args<'_>,
    add_info: &AddInfo,
) -> Outcome {
    let (shown, data) = read_page_file(cu, args.str(2))?;
    let request = Signing {
        storage_name: args.str(0),
        key_type: key_type(args.str(1)),
        detail: Some(file_detail(cu.locale(), &shown)),
    };
    let content = Content::Data {
        attached: args.bool(3),
    };
    cades(cu, &request, Data::Bytes(data), content, add_info)
}

/// `createCAdESFromBase64Hash(storageName, keyType, base64Hash)`: a detached CAdES over a
/// hash the page computed (`digested`).
pub(crate) fn create_cades_from_base64_hash<C: Core>(
    cu: &C,
    args: &Args<'_>,
    add_info: &AddInfo,
) -> Outcome {
    let request = Signing {
        storage_name: args.str(0),
        key_type: key_type(args.str(1)),
        detail: None,
    };
    cades(
        cu,
        &request,
        Data::Base64(args.str(2)),
        Content::Hash,
        add_info,
    )
}

/// `applyCAdEST(storageName, keyType, base64Cms)`: a time-stamp on the signer of the chosen
/// key's certificate. A CMS without such a signer fails as the original does, on a
/// `NullPointerException` (no message).
pub(crate) fn apply_cades_t<C: Core>(cu: &C, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    let key = signing_key(cu, args.str(0), args.str(1), add_info)?;
    check_chain(cu, cu.certificate(&key))?;
    let cms = Data::Base64(args.str(2)).bytes(cu)?;
    let stamped = timestamp(cu, cms, cu.certificate(&key))?;
    Ok(Some(Value::String(cu.encode(&stamped))))
}

/// `showFileChooser(fileExtension, currentDirectory)`: the path of a chosen file (or folder
/// for `DIRECTORY` or an empty `fileExtension`), starting in `currentDirectory` if given.
/// A path that does not exist counts as cancelled, as in the original. The path given to
/// the page may be named by it later, even on a network share.
pub(crate) fn show_file_chooser<C: Core>(cu: &C, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let extension = args.str(0);
    let unknown = || {
        Some(format!(
            "No enum constant kz.gov.pki.knca.gui.fileChooser.FileChooser.FileType.{extension}"
        ))
    };
    if !extension.is_empty() && !FILE_TYPES.contains(&extension) {
        return Err(unknown());
    }
    match cu.choose_kind(extension, args.str(1)) {
        Ok(Some(path)) => Ok(Some(Value::String(path))),
        Ok(None) => Err(canceled()),
        Err(e) if e.cause() == Some(cause::FILE_UNKNOWN_KIND) => Err(unknown()),
        Err(e) => panic!("file_choose_kind: {e}"),
    }
}

/// `changeLocale(language)`: `ru`, `kk` or `en` (exact) switches the dialog language, an
/// empty one restores Russian, anything else changes nothing.
pub(crate) fn change_locale<C: Core>(cu: &C, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let locale = match args.str(0) {
        "" | "ru" => Some(Locale::Ru),
        "kk" => Some(Locale::Kk),
        "en" => Some(Locale::En),
        _ => None,
    };
    if let Some(l) = locale {
        cu.set_locale(l);
    }
    Ok(None)
}

/// The key a signing method asks for.
struct Signing<'a> {
    storage_name: &'a str,
    key_type: Option<&'static str>,
    /// The line both dialogs show, e.g. the file to be signed.
    detail: Option<String>,
}

/// What a CAdES signs.
enum Content {
    /// The data, encapsulated if `attached`.
    Data { attached: bool },
    /// A hash of the data, detached.
    Hash,
}

/// Input of a signing method.
enum Data<'a> {
    /// Base64 from the page, decoded after the dialogs.
    Base64(&'a str),
    /// A file's contents.
    Bytes(Vec<u8>),
}

impl Data<'_> {
    fn bytes(self, cu: &impl Core) -> Result<Vec<u8>, Option<String>> {
        match self {
            Data::Base64(text) => cu.decode(text).map_err(Some),
            Data::Bytes(bytes) => Ok(bytes),
        }
    }
}

/// The signature `cms::sign` makes of `data` now: contentType, messageDigest,
/// signingCertificateV2 and signingTime, the signer's certificate, a CMS content
/// co-signed unless `digested`.
fn sign_args(data: Vec<u8>, encapsulate: bool, digested: bool, output: CmsOutput) -> SignCmsExArgs {
    let data = Bytes::from(data);
    SignCmsExArgs {
        handle: 0,
        content: if digested {
            CmsContent::Digest(data)
        } else {
            CmsContent::Data(data)
        },
        encapsulate,
        cosign: if digested {
            CoSign::Never
        } else {
            CoSign::Auto
        },
        econtent_type: None,
        digest: None,
        attrs: SignedAttrs {
            content_type: true,
            message_digest: true,
            signing_certificate_v2: true,
            signing_time: Some(SigningTime {
                at: TimeSource::Now,
                form: TimeForm::Auto,
            }),
            extra: Vec::new(),
        },
        certificates: CmsCerts::Signer,
        timestamp: None,
        output,
    }
}

/// The CMS of `outcome`.
fn signed(outcome: Result<CmsOutcome, HostError>) -> Result<Vec<u8>, Option<String>> {
    match outcome {
        Ok(CmsOutcome::Signed(cms)) => Ok(cms.into_vec()),
        Ok(CmsOutcome::TspFailed(_)) => unreachable!("no time-stamp is asked"),
        Err(e) => Err(cms_message(&e)),
    }
}

/// `createCAdES` with the default-chained signing entity: no time-stamp.
fn cades<C: Core>(
    cu: &C,
    request: &Signing<'_>,
    data: Data<'_>,
    content: Content,
    add_info: &AddInfo,
) -> Outcome {
    let key = request.choose(cu, add_info)?;
    check_chain(cu, cu.certificate(&key))?;
    let data = data.bytes(cu)?;
    let (encapsulate, digested) = match content {
        Content::Data { attached } => (attached, false),
        Content::Hash => (false, true),
    };
    let args = sign_args(data, encapsulate, digested, CmsOutput::Base64);
    let base64 = signed(cu.sign_cms(&key, args))?;
    let base64 = String::from_utf8(base64).expect("the core writes base64 in ASCII");
    Ok(Some(Value::String(base64)))
}

/// The deprecated `createCAdES` with a time-stamp: no chain check.
fn cms_with_timestamp<C: Core>(
    cu: &C,
    request: &Signing<'_>,
    data: Data<'_>,
    attached: bool,
    add_info: &AddInfo,
) -> Outcome {
    let key = request.choose(cu, add_info)?;
    let data = data.bytes(cu)?;
    let args = sign_args(data, attached, false, CmsOutput::Der);
    let cms = signed(cu.sign_cms(&key, args))?;
    let stamped = timestamp(cu, cms, cu.certificate(&key))?;
    Ok(Some(Value::String(cu.encode(&stamped))))
}

/// The CMS with a time-stamp from Kalkan's TSA on the first signer of `cert`.
fn timestamp<C: Core>(cu: &C, cms: Vec<u8>, cert: &[u8]) -> Result<Vec<u8>, Option<String>> {
    let args = StampArgs {
        cms: Bytes::from(cms),
        signers: SignerSel::OfCert(Bytes::from(cert.to_vec())),
        tsa: TsaChoice::Kalkan,
        mode: StampMode::Replace,
        token: TokenForm::Token,
    };
    match cu.stamp(&args) {
        Ok(StampOutcome::Stamped(cms)) => Ok(cms.into_vec()),
        Ok(StampOutcome::Failed(failure)) => Err(Some(failure.detail)),
        Ok(StampOutcome::NoSigner) => Err(None),
        Err(e) => Err(Some(e.message)),
    }
}

/// The storage dialog then the key dialog. The keys listed are those of `key_type`
/// (`None`: SIGNATURE or AUTHENTICATION), newest notBefore first; a store without any is
/// asked again with the original's message for the type, an empty store too.
fn choose_key<C: Core>(
    cu: &C,
    storage_name: &str,
    key_type: Option<&'static str>,
    action: Action,
    detail: Option<String>,
    add_info: &AddInfo,
) -> Result<C::Key, Option<String>> {
    let _ = add_info;
    let (storage, reader) = storage_of(cu, storage_name)?;
    let flow = FlowArgs {
        action,
        storages: vec![storage.to_owned()],
        readers: match reader {
            Some(reader) => FlowReaders::Fixed(vec![FlowReader {
                storage: storage.to_owned(),
                reader,
            }]),
            None => FlowReaders::None,
        },
        start: FlowStart::Empty,
        remember: false,
        detail,
        non_empty_password: false,
        inner_password_policy: false,
        same_storage: false,
        file: FlowFile::Open,
        knca_types: Some(match key_type {
            Some(t) => vec![t.to_owned()],
            None => vec!["SIGNATURE".to_owned(), "AUTHENTICATION".to_owned()],
        }),
        none: match key_type {
            Some("SIGNATURE") => FlowNone::NoSigningKeys,
            Some("AUTHENTICATION") => FlowNone::NoAuthKeys,
            _ => FlowNone::NoKeys,
        },
        empty_is_none: true,
        order: FlowOrder::NewestFirst,
        checks: FlowChecks::Settled,
        skip_blocked_reader: false,
    };
    match cu.choose_key(&flow) {
        Chosen::Key(key) => Ok(key),
        Chosen::Canceled => Err(canceled()),
        // The token went between the readers and the window.
        Chosen::ReaderGone => Err(Some(STORAGE_EMPTY.to_owned())),
    }
}

/// The storage `name` names (`StorageInfo`'s checks), with the reader of a token: the first
/// one holding a token of its family.
fn storage_of<C: Core>(
    cu: &C,
    name: &str,
) -> Result<(&'static str, Option<String>), Option<String>> {
    // Java's `trim`: every character up to U+0020.
    if name.trim_matches(|c| c <= ' ').is_empty() {
        return Err(Some(STORAGE_NAME_EMPTY.to_owned()));
    }
    let storage = STORAGES
        .into_iter()
        .find(|s| *s == name)
        .ok_or_else(|| Some(STORAGE_UNKNOWN.to_owned()))?;
    if matches!(storage, "PKCS12" | "JKS") {
        return Ok((storage, None));
    }
    let reader = cu
        .readers(storage)
        .into_iter()
        .next()
        .ok_or_else(|| Some(STORAGE_EMPTY.to_owned()))?;
    Ok((storage, Some(reader)))
}

/// The dialogs' action for a signing method's `key_type`.
fn signing_action(key_type: Option<&str>) -> Action {
    if key_type == Some("AUTHENTICATION") {
        Action::Authenticate
    } else {
        Action::Sign
    }
}

/// The key a signing method without a file asks for: [`choose_key`] for `key_type_name`.
fn signing_key<C: Core>(
    cu: &C,
    storage_name: &str,
    key_type_name: &str,
    add_info: &AddInfo,
) -> Result<C::Key, Option<String>> {
    let key_type = key_type(key_type_name);
    choose_key(
        cu,
        storage_name,
        key_type,
        signing_action(key_type),
        None,
        add_info,
    )
}

impl Signing<'_> {
    /// [`choose_key`] for this request.
    fn choose<C: Core>(&self, cu: &C, add_info: &AddInfo) -> Result<C::Key, Option<String>> {
        choose_key(
            cu,
            self.storage_name,
            self.key_type,
            signing_action(self.key_type),
            self.detail.clone(),
            add_info,
        )
    }
}

/// `KNCACertificateType.valueOf(keyType)`, an unknown name being `null`.
fn key_type(name: &str) -> Option<&'static str> {
    KNCA_TYPES.into_iter().find(|t| *t == name)
}

/// The original's default-chained signing entity: a certification path from `cert` through
/// the core's CAs, at the current time or, for an expired certificate, at its notAfter.
fn check_chain<C: Core>(cu: &C, cert: &[u8]) -> Result<(), Option<String>> {
    match cu.path(cert) {
        PathOutcome::Valid => Ok(()),
        PathOutcome::IssuerNotFound => Err(Some(ISSUER_CERT_NOT_FOUND.to_owned())),
        PathOutcome::Invalid(why) => Err(Some(format!(
            "java.security.cert.CertPathBuilderException: {why}"
        ))),
    }
}

/// `XMLUtil.createXmlSignature`: the whole document for an empty `tbs_xpath`, else the
/// element it selects, the signature going into the element `parent_xpath` selects (the
/// document element for an empty one).
fn sign_one_xml<C: Core>(
    cu: &C,
    key: &C::Key,
    xml: &str,
    tbs_xpath: &str,
    parent_xpath: &str,
) -> Result<String, Option<String>> {
    let signed = if tbs_xpath.is_empty() {
        cu.sign_xml(key, xml.as_bytes(), None, None)
    } else {
        if java_equals_ignore_case(parent_xpath, tbs_xpath) {
            return Err(Some(
                "При подписи элемента XML, элемент подписи не может быть родительским элементом подписи."
                    .to_owned(),
            ));
        }
        let parent = (!parent_xpath.is_empty()).then_some(parent_xpath);
        cu.sign_xml(key, xml.as_bytes(), Some(tbs_xpath), parent)
    }
    .map_err(|e| Some(xml_message(cu, &e, cu.certificate(key))))?;
    // The input was UTF-8 text and only ASCII markup and base64 were spliced in.
    String::from_utf8(signed).map_err(|e| Some(e.to_string()))
}

/// Java's `String.equalsIgnoreCase`: the same number of UTF-16 units, each pair equal, or
/// equal after `Character.toUpperCase`, or after `toLowerCase` of those (single-unit simple
/// case mappings; surrogates compare as they are).
fn java_equals_ignore_case(a: &str, b: &str) -> bool {
    fn map(unit: u16, f: fn(char) -> Option<char>) -> u16 {
        char::from_u32(u32::from(unit))
            .and_then(f)
            .and_then(|c| u16::try_from(u32::from(c)).ok())
            .unwrap_or(unit)
    }
    fn single(mut it: impl Iterator<Item = char>) -> Option<char> {
        let c = it.next()?;
        it.next().is_none().then_some(c)
    }
    let upper = |u| map(u, |c| single(c.to_uppercase()));
    // The only lowercase mapping longer than one character is U+0130 → `i` + U+0307; its
    // simple mapping, Java's, is the `i`.
    let lower = |u| map(u, |c| c.to_lowercase().next());
    a.encode_utf16().count() == b.encode_utf16().count()
        && a.encode_utf16().zip(b.encode_utf16()).all(|(x, y)| {
            let (ux, uy) = (upper(x), upper(y));
            x == y || ux == uy || lower(ux) == lower(uy)
        })
}

/// The message of an XML signing failure: the original's `IllegalArgumentException` for a
/// certificate algorithm it cannot sign with; `UNKNOWN_ALGORITHM` for sha1RSA certificates,
/// which OpenNCALayer refuses (the original signs them with rsa-sha1); else the core's.
fn xml_message<C: Core>(cu: &C, e: &HostError, cert: &[u8]) -> String {
    match e.cause() {
        Some(cause::XML_UNSUPPORTED_ALGORITHM) => {
            let oid = cu.cert_info(cert).signature_alg_oid;
            if oid == SHA1_WITH_RSA {
                UNKNOWN_ALGORITHM.to_owned()
            } else {
                format!("Incorrect algorithm: {oid}")
            }
        }
        Some(cause::KEY_UNSUPPORTED) => UNKNOWN_ALGORITHM.to_owned(),
        _ => e.message.clone(),
    }
}

/// The message of a CMS signing failure: the original's `ProviderUtilException` codes where
/// it raises one, else the core's.
fn cms_message(e: &HostError) -> Option<String> {
    Some(match e.cause() {
        Some(cause::CMS_NO_ENCAPSULATED_DATA) => CMS_NO_ENCAPSULATED_DATA.to_owned(),
        Some(cause::CMS_UNKNOWN_ALGORITHM | cause::KEY_UNSUPPORTED) => UNKNOWN_ALGORITHM.to_owned(),
        _ => e.message.clone(),
    })
}

/// The original's `KeyInfo` of a key: certificate details, dates as epoch milliseconds,
/// `null` fields left out.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyInfo {
    alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    algorithm: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject_cn: Option<String>,
    subject_dn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_cn: Option<String>,
    issuer_dn: String,
    serial_number: String,
    cert_not_after: String,
    cert_not_before: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority_key_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pem: Option<String>,
}

fn key_info<C: Core>(cu: &C, key: &C::Key) -> Value {
    let description = cu.describe(key);
    let cert = description.certificate.as_slice();
    let info = cu.cert_info(cert);
    let details = cu.cert_details(cert);
    // The original reads both identifiers in one `try`: without a SubjectKeyIdentifier the
    // AuthorityKeyIdentifier is left out too.
    let key_id = details.ski_hex;
    let authority_key_identifier = key_id.as_ref().and(details.aki_hex);
    let key_info = KeyInfo {
        alias: description.alias,
        key_id,
        algorithm: match description.alg.as_str() {
            "gost2004" => "ECGOST34310",
            "gost2015_512" => "ECGOST3410-2015",
            "rsa" => "RSA",
            other => panic!("a key of the algorithm {other}"),
        },
        subject_cn: info.subject_cn,
        subject_dn: details.subject_dn,
        issuer_cn: details.issuer_cn,
        issuer_dn: details.issuer_dn,
        serial_number: info.serial_hex,
        cert_not_after: info.not_after.to_string(),
        cert_not_before: info.not_before.to_string(),
        authority_key_identifier,
        pem: Some(info.pem),
    };
    serde_json::to_value(key_info).expect("KeyInfo serializes")
}

/// The file a page names, with the module's messages: `file.not_found`, or
/// `file.too_large: …` for a file over 64 MiB. Its absolute path and contents.
fn read_page_file<C: Core>(cu: &C, path: &str) -> Result<(String, Vec<u8>), Option<String>> {
    match cu.page_read(path) {
        PageRead::Ok(file) => Ok((file.path, file.data.into_vec())),
        PageRead::NotFound | PageRead::Declined => Err(Some(FILE_NOT_FOUND.to_owned())),
        PageRead::TooLarge => Err(Some(FILE_TOO_LARGE.to_owned())),
    }
}

fn canceled() -> Option<String> {
    Some(ACTION_CANCELED.to_owned())
}

/// The dialogs' line for a file the page has signed.
fn file_detail(l: Locale, path: &str) -> String {
    match l {
        Locale::Kk | Locale::Ru => format!("Файл: {path}"),
        Locale::En => format!("File: {path}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equals_ignore_case() {
        assert!(java_equals_ignore_case("/Root/A", "/root/a"));
        assert!(java_equals_ignore_case("/Әлем", "/әлем"));
        assert!(!java_equals_ignore_case("/root/a", "/root/b"));
        assert!(!java_equals_ignore_case("", "/a"));
        // Java compares UTF-16 units: surrogates do not change case.
        assert!(!java_equals_ignore_case("/\u{10428}", "/\u{10400}"));
        assert!(java_equals_ignore_case("/\u{10428}", "/\u{10428}"));
        // Single-character mappings only: `ß` is not `SS`.
        assert!(!java_equals_ignore_case("ß", "SS"));
        assert!(java_equals_ignore_case("ı", "I"));
        // `İ` lowercases to `i` by its simple mapping.
        assert!(java_equals_ignore_case("İ", "i"));
    }

    /// No token connected, nothing else asked.
    struct NoTokens;

    impl Core for NoTokens {
        type Key = ();
        fn locale(&self) -> Locale {
            Locale::Ru
        }
        fn set_locale(&self, _: Locale) {}
        fn call_locale(&self, _: Locale) {}
        fn debug(&self, _: &str) {}
        fn active_tokens(&self) -> Vec<String> {
            Vec::new()
        }
        fn readers(&self, _: &str) -> Vec<String> {
            Vec::new()
        }
        fn choose_key(&self, _: &FlowArgs) -> Chosen<()> {
            unreachable!()
        }
        fn certificate<'k>(&self, _: &'k ()) -> &'k [u8] {
            unreachable!()
        }
        fn describe(&self, _: &()) -> oncl_pdk::abi::KeyDescription {
            unreachable!()
        }
        fn cert_info(&self, _: &[u8]) -> oncl_pdk::abi::CertInfo {
            unreachable!()
        }
        fn cert_details(&self, _: &[u8]) -> oncl_pdk::abi::CertDetails {
            unreachable!()
        }
        fn path(&self, _: &[u8]) -> PathOutcome {
            unreachable!()
        }
        fn sign_cms(&self, _: &(), _: SignCmsExArgs) -> Result<CmsOutcome, HostError> {
            unreachable!()
        }
        fn stamp(&self, _: &StampArgs) -> Result<StampOutcome, HostError> {
            unreachable!()
        }
        fn sign_xml(
            &self,
            _: &(),
            _: &[u8],
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<Vec<u8>, HostError> {
            unreachable!()
        }
        fn decode(&self, _: &str) -> Result<Vec<u8>, String> {
            unreachable!()
        }
        fn encode(&self, _: &[u8]) -> String {
            unreachable!()
        }
        fn page_read(&self, _: &str) -> PageRead {
            unreachable!()
        }
        fn choose_kind(&self, _: &str, _: &str) -> Result<Option<String>, HostError> {
            unreachable!()
        }
    }

    #[test]
    fn storage_checks() {
        let err = |s: &str| storage_of(&NoTokens, s).unwrap_err().unwrap();
        assert_eq!(err(""), STORAGE_NAME_EMPTY);
        assert_eq!(err(" \t\n"), STORAGE_NAME_EMPTY);
        assert_eq!(err("pkcs12"), STORAGE_UNKNOWN);
        assert_eq!(err(" PKCS12"), STORAGE_UNKNOWN);
        assert_eq!(err("AKKaztokenStore"), STORAGE_EMPTY);
        assert_eq!(err("ABCloudServiceStore"), STORAGE_EMPTY);
        assert_eq!(storage_of(&NoTokens, "PKCS12"), Ok(("PKCS12", None)));
        assert_eq!(storage_of(&NoTokens, "JKS"), Ok(("JKS", None)));
    }
}
