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
//!   key dialog with the keys whose certificate is of the requested `keyType`
//!   ([`oncl_pki::info::kcert_types`]), any other `keyType` meaning SIGNATURE or
//!   AUTHENTICATION, newest certificate first. A store without such keys is asked for
//!   again, with the original's message for the type. Cancelling either dialog is
//!   `action.canceled`.
//!
//! `createCAdESFromBase64`, `createCAdESFromBase64Hash` and `applyCAdEST` then check the
//! signer's certificate chain against the module's CAs, as the original's
//! `getSigningEntityDefaultChained` does with its bundled CA list (expired keys at their
//! notAfter). Base64 inputs are decoded after the dialogs, with Java's decoder and its
//! messages. Paths a page names (`createCAdESFromFile`, `createCMSSignatureFromFile`) are
//! read before any dialog (regular files of at most [`MAX_PAGE_FILE`] bytes only, local or
//! on a network path the user chose in the file chooser, [`PageFile`]), shown in both
//! dialogs as absolute paths, and never logged.

use crate::CommonUtils;
use crate::dispatch::Args;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Encode;
use oncl_basics::{
    Action, Availability, BusyPrompt, FileKind, FilePrompt, KeyPrompt, LiveAvailability, Locale,
    MAX_PAGE_FILE, OpenError, PageFile, PageFileError, Prompt, ReaderEntry, ReaderList,
    StorageKind, StoragePrompt, lock_dialog_flow, page_path, remember_chosen_path,
};
use oncl_pki::cms::{self, CmsError, SignOptions};
use oncl_pki::info::{CertInfo, KncaCertType, cert_info, common_name, kalkan_dn, kcert_types};
use oncl_pki::key::{KeyAlg, KeyError, SigAlg};
use oncl_pki::pkcs12::KeyEntry;
use oncl_pki::pkix::{self, PathError};
use oncl_pki::xmldsig::{self, XmlError};
use oncl_pki::{pem, tsp};
use oncl_protocol::AddInfo;
use oncl_protocol::javab64::decode_java;
use oncl_token::TokenKind;
use serde::Serialize;
use serde_json::{Value, json};
use std::fmt::Write;
use std::path::Path;
use x509_cert::Certificate;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};

/// A method's reply: `Ok` is `200` with the `responseObject` if any, `Err` is `500` with the
/// `message` if any.
pub(crate) type Outcome = Result<Option<Value>, Option<String>>;

const ACTION_CANCELED: &str = "action.canceled";
const STORAGE_NAME_EMPTY: &str = "storageName.param.empty";
const STORAGE_UNKNOWN: &str = "storage.unknown";
const STORAGE_EMPTY: &str = "storage.empty";
const FILE_NOT_FOUND: &str = "file.not_found";
const UNKNOWN_ALGORITHM: &str = "UNKNOWN_ALGORITHM";
const CMS_NO_ENCAPSULATED_DATA: &str = "CMS_NO_ENCAPSULATED_DATA";
const ISSUER_CERT_NOT_FOUND: &str = "ISSUER_CERT_NOT_FOUND";
/// Origin shown when the connection sent none.
const UNIDENTIFIED: &str = "UNIDENTIFIED";

/// `getActiveTokens()`: the storages with a connected token, in Kalkan's order; none with
/// token support off or without the smart card service.
pub(crate) fn get_active_tokens(cu: &CommonUtils, _: &Args<'_>, _: &AddInfo) -> Outcome {
    let present = cu.tokens.scan().present;
    let names: Vec<&str> = TokenKind::ALL
        .into_iter()
        .filter(|kind| present.iter().any(|p| p.kind == *kind))
        .map(TokenKind::storage_name)
        .collect();
    Ok(Some(json!(names)))
}

/// `getKeyInfo(storageName)`: the chosen key's certificate details, nothing signed.
pub(crate) fn get_key_info(cu: &CommonUtils, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    let entry = choose_key(cu, args.str(0), None, Action::KeyInfo, None, add_info)?;
    Ok(Some(key_info(&entry)))
}

/// `signXml(storageName, keyType, xml, tbsElementXPath, signatureParentElementXPath)`.
pub(crate) fn sign_xml(cu: &CommonUtils, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    let entry = signing_key(cu, args.str(0), args.str(1), add_info)?;
    let signed = sign_one_xml(&entry, args.str(2), args.str(3), args.str(4))?;
    Ok(Some(Value::String(signed)))
}

/// `signXmls(storageName, keyType, String[] xmls, tbsElementXPath,
/// signatureParentElementXPath)`: every document with the key of one dialog.
pub(crate) fn sign_xmls(cu: &CommonUtils, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    let entry = signing_key(cu, args.str(0), args.str(1), add_info)?;
    let signed = args
        .strs(2)
        .iter()
        .map(|xml| sign_one_xml(&entry, xml, args.str(3), args.str(4)).map(Value::String))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(Value::Array(signed)))
}

/// `createCMSSignatureFromBase64(storageName, keyType, base64Data, attached)` (deprecated in
/// the original): CAdES with a time-stamp from the module's TSA on the chosen key's signer.
pub(crate) fn create_cms_signature_from_base64(
    cu: &CommonUtils,
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
pub(crate) fn create_cms_signature_from_file(
    cu: &CommonUtils,
    args: &Args<'_>,
    add_info: &AddInfo,
) -> Outcome {
    let file = read_page_file(args.str(2))?;
    let request = Signing {
        storage_name: args.str(0),
        key_type: key_type(args.str(1)),
        detail: Some(file_detail(cu.locale(), &file.shown)),
    };
    cms_with_timestamp(cu, &request, Data::Bytes(file.data), args.bool(3), add_info)
}

/// `createCAdESFromBase64(storageName, keyType, base64Data, attached)`: CAdES without a
/// time-stamp; a CMS with encapsulated content as the data gets the new signer added.
pub(crate) fn create_cades_from_base64(
    cu: &CommonUtils,
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
pub(crate) fn create_cades_from_file(
    cu: &CommonUtils,
    args: &Args<'_>,
    add_info: &AddInfo,
) -> Outcome {
    let file = read_page_file(args.str(2))?;
    let request = Signing {
        storage_name: args.str(0),
        key_type: key_type(args.str(1)),
        detail: Some(file_detail(cu.locale(), &file.shown)),
    };
    let content = Content::Data {
        attached: args.bool(3),
    };
    cades(cu, &request, Data::Bytes(file.data), content, add_info)
}

/// `createCAdESFromBase64Hash(storageName, keyType, base64Hash)`: a detached CAdES over a
/// hash the page computed (`digested`).
pub(crate) fn create_cades_from_base64_hash(
    cu: &CommonUtils,
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
pub(crate) fn apply_cades_t(cu: &CommonUtils, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    let entry = signing_key(cu, args.str(0), args.str(1), add_info)?;
    check_chain(cu, &entry.cert)?;
    let cms = Data::Base64(args.str(2)).bytes()?;
    let stamped = timestamp(cu, &cms, &entry.cert)?;
    Ok(Some(Value::String(STANDARD.encode(stamped))))
}

/// `showFileChooser(fileExtension, currentDirectory)`: the path of a chosen file (or folder
/// for `DIRECTORY` or an empty `fileExtension`), starting in `currentDirectory` if given.
/// A path that does not exist counts as cancelled, as in the original. The path given to
/// the page may be named by it later, even on a network share ([`remember_chosen_path`]).
pub(crate) fn show_file_chooser(cu: &CommonUtils, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    let extension = args.str(0);
    let kind = if extension.is_empty() {
        FileKind::Directory
    } else {
        FileKind::from_name(extension).ok_or_else(|| {
            Some(format!(
                "No enum constant kz.gov.pki.knca.gui.fileChooser.FileChooser.FileType.{extension}"
            ))
        })?
    };
    let directory = args.str(1);
    let prompt = FilePrompt {
        origin: origin(add_info),
        locale: cu.locale(),
        kind,
        // A network folder the user did not choose is not opened: the system dialog would
        // connect to its host.
        directory: page_path(directory)
            .filter(|d| !d.as_os_str().is_empty())
            .map(Path::to_path_buf),
        source: None,
    };
    let answer = {
        let _flow = lock_dialog_flow();
        cu.prompter.file(&prompt)
    };
    match answer {
        Prompt::Answer(path) if path.exists() => {
            remember_chosen_path(&path);
            Ok(Some(Value::String(path.to_string_lossy().into_owned())))
        }
        Prompt::Answer(_) | Prompt::Cancelled => Err(canceled()),
    }
}

/// `changeLocale(language)`: `ru`, `kk` or `en` (exact) switches the dialog language, an
/// empty one restores Russian, anything else changes nothing.
pub(crate) fn change_locale(cu: &CommonUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
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
    key_type: Option<KncaCertType>,
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
    fn bytes(self) -> Result<Vec<u8>, Option<String>> {
        match self {
            Data::Base64(text) => decode_java(text).map_err(Some),
            Data::Bytes(bytes) => Ok(bytes),
        }
    }
}

/// `createCAdES` with the default-chained signing entity: no time-stamp.
fn cades(
    cu: &CommonUtils,
    request: &Signing<'_>,
    data: Data<'_>,
    content: Content,
    add_info: &AddInfo,
) -> Outcome {
    let entry = request.choose(cu, add_info)?;
    check_chain(cu, &entry.cert)?;
    let data = data.bytes()?;
    let (encapsulate, digested) = match content {
        Content::Data { attached } => (attached, false),
        Content::Hash => (false, true),
    };
    let opts = SignOptions {
        encapsulate,
        digested,
        signing_time: (cu.clock)(),
    };
    let signed = cms::sign(&entry, &data, &opts).map_err(cms_message)?;
    Ok(Some(Value::String(STANDARD.encode(signed))))
}

/// The deprecated `createCAdES` with a time-stamp: no chain check.
fn cms_with_timestamp(
    cu: &CommonUtils,
    request: &Signing<'_>,
    data: Data<'_>,
    attached: bool,
    add_info: &AddInfo,
) -> Outcome {
    let entry = request.choose(cu, add_info)?;
    let data = data.bytes()?;
    let opts = SignOptions {
        encapsulate: attached,
        digested: false,
        signing_time: (cu.clock)(),
    };
    let signed = cms::sign(&entry, &data, &opts).map_err(cms_message)?;
    let stamped = timestamp(cu, &signed, &entry.cert)?;
    Ok(Some(Value::String(STANDARD.encode(stamped))))
}

/// The CMS with a time-stamp on the first signer of `cert`.
fn timestamp(cu: &CommonUtils, cms: &[u8], cert: &Certificate) -> Result<Vec<u8>, Option<String>> {
    let index = cms::signer_index_of(cms, cert)
        .map_err(|e| Some(e.to_string()))?
        .ok_or(None)?;
    tsp::timestamp_signer(cms, index, &cu.tsa, cu.http.as_ref()).map_err(|e| Some(e.to_string()))
}

/// The storage dialog then the key dialog, under the process-wide dialog-flow turn; the
/// busy indicator shows while the key store opens.
fn choose_key(
    cu: &CommonUtils,
    storage_name: &str,
    key_type: Option<KncaCertType>,
    action: Action,
    detail: Option<String>,
    add_info: &AddInfo,
) -> Result<KeyEntry, Option<String>> {
    let (storage, reader) = storage_of(cu, storage_name)?;
    let origin = origin(add_info);
    let locale = cu.locale();
    let _flow = lock_dialog_flow();
    let mut prompt = StoragePrompt {
        origin: origin.clone(),
        locale,
        action,
        storages: vec![storage],
        recent_path: None,
        error: None,
        detail: detail.clone(),
        tokens: reader.map(|reader| ReaderList::fixed(vec![ReaderEntry { storage, reader }], None)),
        chosen: None,
        reader: None,
    };
    let mut keys = loop {
        let Prompt::Answer(answer) = cu.prompter.storage(&prompt) else {
            return Err(canceled());
        };
        let _busy = cu.prompter.busy(&BusyPrompt {
            origin: origin.clone(),
            locale,
        });
        // An empty store gets the text of the requested type too, as in the original.
        let opened = match answer.open_with(&prompt.storages, &cu.tokens) {
            Err(OpenError::NoKeys) => Ok(Vec::new()),
            opened => opened,
        };
        match opened.and_then(|entries| keys_of_type(entries, key_type)) {
            Ok(keys) => break keys,
            Err(e) => {
                prompt.error = Some(e);
                if prompt.tokens.is_some() {
                    prompt.chosen = Some(answer.storage);
                    prompt.reader = answer.reader;
                } else {
                    prompt.recent_path = Some(answer.path);
                }
            }
        }
    };
    let mut prompt = KeyPrompt::new(
        origin,
        locale,
        action,
        keys.iter()
            .map(|(entry, info)| (entry.alias.clone(), info.clone())),
        LiveAvailability::settled(vec![Availability::Enabled; keys.len()]),
    );
    prompt.detail = detail;
    match prompt.ask(cu.prompter.as_ref()) {
        Some(i) => Ok(keys.swap_remove(i).0),
        None => Err(canceled()),
    }
}

/// The storage `name` names (`StorageInfo`'s checks), with the reader of a token: the first
/// one holding a token of its family.
fn storage_of(
    cu: &CommonUtils,
    name: &str,
) -> Result<(StorageKind, Option<String>), Option<String>> {
    // Java's `trim`: every character up to U+0020.
    if name.trim_matches(|c| c <= ' ').is_empty() {
        return Err(Some(STORAGE_NAME_EMPTY.to_owned()));
    }
    let storage = StorageKind::from_name(name).ok_or_else(|| Some(STORAGE_UNKNOWN.to_owned()))?;
    let StorageKind::Token(_) = storage else {
        return Ok((storage, None));
    };
    let reader = storage
        .token_kind()
        .and_then(|kind| cu.tokens.readers(kind).ok())
        .and_then(|readers| readers.into_iter().next())
        .ok_or_else(|| Some(STORAGE_EMPTY.to_owned()))?;
    Ok((storage, Some(reader)))
}

/// The keys whose certificate is of `key_type` (`None`: SIGNATURE or AUTHENTICATION), with
/// their details, newest notBefore first. Without any, the original's message for the type:
/// [`OpenError::NoSigningKeys`], [`OpenError::NoAuthKeys`], else [`OpenError::NoKeys`].
fn keys_of_type(
    entries: Vec<KeyEntry>,
    key_type: Option<KncaCertType>,
) -> Result<Vec<(KeyEntry, CertInfo)>, OpenError> {
    let mut keys: Vec<(KeyEntry, CertInfo)> = entries
        .into_iter()
        .filter_map(|entry| {
            let info = cert_info(&entry.cert);
            let types = kcert_types(&info);
            let wanted = match key_type {
                Some(t) => types.contains(&t),
                None => {
                    types.contains(&KncaCertType::Signature)
                        || types.contains(&KncaCertType::Authentication)
                }
            };
            wanted.then_some((entry, info))
        })
        .collect();
    if keys.is_empty() {
        return Err(match key_type {
            Some(KncaCertType::Signature) => OpenError::NoSigningKeys,
            Some(KncaCertType::Authentication) => OpenError::NoAuthKeys,
            _ => OpenError::NoKeys,
        });
    }
    keys.sort_by_key(|(_, info)| std::cmp::Reverse(info.not_before));
    Ok(keys)
}

/// The dialogs' action for a signing method's `key_type`.
fn signing_action(key_type: Option<KncaCertType>) -> Action {
    if key_type == Some(KncaCertType::Authentication) {
        Action::Authenticate
    } else {
        Action::Sign
    }
}

/// The key a signing method without a file asks for: [`choose_key`] for `key_type_name`.
fn signing_key(
    cu: &CommonUtils,
    storage_name: &str,
    key_type_name: &str,
    add_info: &AddInfo,
) -> Result<KeyEntry, Option<String>> {
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
    fn choose(&self, cu: &CommonUtils, add_info: &AddInfo) -> Result<KeyEntry, Option<String>> {
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
fn key_type(name: &str) -> Option<KncaCertType> {
    KncaCertType::from_name(name)
}

/// The original's default-chained signing entity: a certification path from `cert` through
/// the module's CAs, at the current time or, for an expired certificate, at its notAfter.
fn check_chain(cu: &CommonUtils, cert: &Certificate) -> Result<(), Option<String>> {
    let at = pkix::validation_time(cert, (cu.clock)());
    match pkix::build_path(cert, &cu.cas, at) {
        Ok(_) => Ok(()),
        Err(PathError::IssuerNotFound) => Err(Some(ISSUER_CERT_NOT_FOUND.to_owned())),
        Err(e) => Err(Some(format!(
            "java.security.cert.CertPathBuilderException: {e}"
        ))),
    }
}

/// `XMLUtil.createXmlSignature`: the whole document for an empty `tbs_xpath`, else the
/// element it selects, the signature going into the element `parent_xpath` selects (the
/// document element for an empty one).
fn sign_one_xml(
    entry: &KeyEntry,
    xml: &str,
    tbs_xpath: &str,
    parent_xpath: &str,
) -> Result<String, Option<String>> {
    let signed = if tbs_xpath.is_empty() {
        xmldsig::sign_enveloped(xml.as_bytes(), &entry.key, &entry.cert)
    } else {
        if java_equals_ignore_case(parent_xpath, tbs_xpath) {
            return Err(Some(
                "При подписи элемента XML, элемент подписи не может быть родительским элементом подписи."
                    .to_owned(),
            ));
        }
        let parent = (!parent_xpath.is_empty()).then_some(parent_xpath);
        xmldsig::sign_element(xml.as_bytes(), tbs_xpath, parent, &entry.key, &entry.cert)
    }
    .map_err(|e| Some(xml_message(e, &entry.cert)))?;
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
/// which OpenNCALayer refuses (the original signs them with rsa-sha1); else the error.
fn xml_message(e: XmlError, cert: &Certificate) -> String {
    match e {
        XmlError::UnsupportedAlgorithm(_)
            if SigAlg::from_signature_oid(&cert.signature_algorithm().oid)
                == Some(SigAlg::RsaSha1) =>
        {
            UNKNOWN_ALGORITHM.to_owned()
        }
        XmlError::UnsupportedAlgorithm(oid) => format!("Incorrect algorithm: {oid}"),
        XmlError::Key(KeyError::UnsupportedAlgorithm) => UNKNOWN_ALGORITHM.to_owned(),
        e => e.to_string(),
    }
}

/// The message of a CMS signing failure: the original's `ProviderUtilException` codes where
/// it raises one, else the error.
fn cms_message(e: CmsError) -> Option<String> {
    Some(match e {
        CmsError::NoEncapsulatedData => CMS_NO_ENCAPSULATED_DATA.to_owned(),
        CmsError::UnknownAlgorithm(_) | CmsError::Key(KeyError::UnsupportedAlgorithm) => {
            UNKNOWN_ALGORITHM.to_owned()
        }
        e => e.to_string(),
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

fn key_info(entry: &KeyEntry) -> Value {
    let cert = &entry.cert;
    let tbs = cert.tbs_certificate();
    let info = cert_info(cert);
    // The original reads both identifiers in one `try`: without a SubjectKeyIdentifier the
    // AuthorityKeyIdentifier is left out too.
    let key_id = match tbs.get_extension::<SubjectKeyIdentifier>() {
        Ok(Some((_, ski))) => Some(hex(ski.0.as_bytes())),
        Ok(None) | Err(_) => None,
    };
    let authority_key_identifier =
        key_id
            .as_ref()
            .and_then(|_| match tbs.get_extension::<AuthorityKeyIdentifier>() {
                Ok(Some((_, aki))) => aki.key_identifier.map(|id| hex(id.as_bytes())),
                Ok(None) | Err(_) => None,
            });
    let key_info = KeyInfo {
        alias: entry.alias.clone(),
        key_id,
        algorithm: match entry.key.alg() {
            KeyAlg::Gost2004 => "ECGOST34310",
            KeyAlg::Gost2015_512 => "ECGOST3410-2015",
            KeyAlg::Rsa => "RSA",
        },
        subject_cn: info.subject_cn,
        subject_dn: kalkan_dn(tbs.subject()),
        issuer_cn: common_name(tbs.issuer()),
        issuer_dn: kalkan_dn(tbs.issuer()),
        serial_number: info.serial_hex,
        cert_not_after: epoch_millis(info.not_after),
        cert_not_before: epoch_millis(info.not_before),
        authority_key_identifier,
        pem: cert
            .to_der()
            .ok()
            .map(|der| pem::encode("CERTIFICATE", &der)),
    };
    serde_json::to_value(key_info).expect("KeyInfo serializes")
}

fn epoch_millis(t: time::OffsetDateTime) -> String {
    (t.unix_timestamp_nanos() / 1_000_000).to_string()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").expect("writing to a String");
    }
    out
}

/// [`PageFile::read`] with the module's messages: `file.not_found`, or
/// `file.too_large: …` for a file over [`MAX_PAGE_FILE`].
fn read_page_file(path: &str) -> Result<PageFile, Option<String>> {
    PageFile::read(path).map_err(|e| {
        Some(match e {
            PageFileError::NotFound => FILE_NOT_FOUND.to_owned(),
            PageFileError::TooLarge => format!(
                "file.too_large: files over {} MiB are not signed",
                MAX_PAGE_FILE >> 20
            ),
        })
    })
}

fn origin(add_info: &AddInfo) -> String {
    add_info
        .origin
        .clone()
        .unwrap_or_else(|| UNIDENTIFIED.to_owned())
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

    /// No network.
    struct Offline;

    impl oncl_pki::http::HttpTransport for Offline {
        fn send(
            &self,
            _: &oncl_pki::http::HttpRequest<'_>,
        ) -> Result<oncl_pki::http::HttpReply, oncl_pki::http::HttpError> {
            Err(oncl_pki::http::HttpError::other("offline"))
        }
    }

    #[test]
    fn storage_checks() {
        let cu = CommonUtils::new(
            std::sync::Arc::new(oncl_basics::testing::ScriptedPrompter::new(vec![])),
            std::sync::Arc::new(Offline),
        );
        let err = |s: &str| storage_of(&cu, s).unwrap_err().unwrap();
        assert_eq!(err(""), STORAGE_NAME_EMPTY);
        assert_eq!(err(" \t\n"), STORAGE_NAME_EMPTY);
        assert_eq!(err("pkcs12"), STORAGE_UNKNOWN);
        assert_eq!(err(" PKCS12"), STORAGE_UNKNOWN);
        assert_eq!(err("AKKaztokenStore"), STORAGE_EMPTY);
        assert_eq!(err("ABCloudServiceStore"), STORAGE_EMPTY);
        assert_eq!(storage_of(&cu, "PKCS12"), Ok((StorageKind::Pkcs12, None)));
        assert_eq!(storage_of(&cu, "JKS"), Ok((StorageKind::Jks, None)));
    }
}
