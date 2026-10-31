//! EFactoringSign (`kz.efactoring.EfactoringSignBundle` 1.2) as an OpenNCALayer plugin:
//! MarketSign's `version` and `text`, `xml` with an element to sign and the element the
//! signature goes into, and `binary`. Version 1.2 never downloaded `upload_url` (its download
//! window failed before any request), so `binary` and a remote `xml` end in the original's
//! «Ошибка при разборе запроса» window after the key dialog, without network.
#![cfg(target_arch = "wasm32")]

mod texts;

use oncl_pdk::abi::{
    Action, C14n, ChoiceArgs, ChooseArgs, CmsCerts, CmsContent, CmsOutcome, CoSign, Filter,
    MessageKind, NsBinding, Placement, SignCmsExArgs, SignXmlExArgs, SignedAttrs, SigningTime,
    TimeForm, TimeSource, Transform, TsaChoice, XmlOutput,
};
use oncl_pdk::keys::{self, Key};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{self, Map, Value};
use oncl_pdk::{Request, dialogs, host, javab64};
use oncl_port_kit::reply::{ecc, error_text};
use texts::Texts;

/// The storages the key dialog offers, in the original's order.
const STORAGES: [&str; 7] = [
    "AKAKEYStore",
    "AKEToken72KStore",
    "AKEToken5110Store",
    "AKJaCartaStore",
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "PKCS12",
];

/// The namespace of every XPath prefix but `SOAP-ENV`.
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// The namespace of the XPath prefix `SOAP-ENV`.
const SOAP_ENV_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

fn handle(request: &Request) -> String {
    let Ok(Value::Object(req)) = serde_json::from_str::<Value>(&request.text) else {
        return drop_connection();
    };
    let texts = Texts::of(request.locale);
    match orgjson::opt_string(&req, "type")
        .as_deref()
        .unwrap_or("unknown")
    {
        "version" => {
            let mut version = JObject::hash_map();
            version.put("version", "1.0.0");
            ecc(Some(JValue::Obj(version)), Some("NONE"))
        }
        "text" => sign_text(&req, texts),
        "xml" => sign_xml(&req, texts),
        "binary" => sign_binary(&req, texts),
        // The spaces are the original's.
        _ => error_text(" Неизвестный тип ", "UNKNOWN TYPE"),
    }
}

oncl_pdk::plugin!(handle);

/// `text`, as MarketSign's: the key first, then `data`, whose absence ended the connection.
fn sign_text(req: &Map<String, Value>, texts: &Texts) -> String {
    loop {
        let Some(key) = choose() else {
            return cancel();
        };
        let attach = orgjson::opt_boolean(req, "attach", false);
        let has_timestamp = orgjson::opt_boolean(req, "has_timestamp", true);
        let Ok(data) = orgjson::get_string(req, "data") else {
            return drop_connection();
        };
        let signed = cades(&key, data.as_bytes(), attach, has_timestamp);
        drop(key);
        match signed {
            Some(cms) => return ecc(Some(base64(&cms).into()), Some("NONE")),
            None if retry(texts, texts.sign_xml_failed) => {}
            None => return cancel(),
        }
    }
}

/// `xml`: the whole document, or the element `sign_element` selects with the signature in
/// the one `signature_parent_element` selects.
fn sign_xml(req: &Map<String, Value>, texts: &Texts) -> String {
    loop {
        let Some(key) = choose() else {
            return cancel();
        };
        let source = orgjson::opt_string(req, "source").unwrap_or_else(|| "local".to_owned());
        let error = if source != "local" {
            // Unverified against the original: what the live portal sends as `source`; version
            // 1.2 failed every remote download before any request.
            texts.bad_request
        } else {
            match orgjson::get_string(req, "data") {
                Err(_) => texts.bad_request,
                Ok(xml) => {
                    let element = orgjson::opt_string(req, "sign_element").unwrap_or_default();
                    let parent =
                        orgjson::opt_string(req, "signature_parent_element").unwrap_or_default();
                    match xmldsig(&key, xml, &element, &parent) {
                        Some(signed) => return ecc(Some(signed.into()), Some("NONE")),
                        None => texts.sign_xml_failed,
                    }
                }
            }
        };
        drop(key);
        if !retry(texts, error) {
            return cancel();
        }
    }
}

/// `binary`: without `upload_url`, `CANCEL` once the key is picked; with one, the failed
/// download window.
fn sign_binary(req: &Map<String, Value>, texts: &Texts) -> String {
    loop {
        let Some(key) = choose() else {
            return cancel();
        };
        drop(key);
        if orgjson::opt_string(req, "upload_url").is_none_or(|url| url.is_empty()) {
            return cancel();
        }
        // Unverified against the original: whether the live portal still sends `binary`; in
        // version 1.2 its download window failed before any request.
        if !retry(texts, texts.bad_request) {
            return cancel();
        }
    }
}

/// Kalkan's `createXmlSignature`: without `element`, the whole document; with it, the
/// element (which has an `Id`) under `parent`. A `parent` that is empty or names the element
/// itself fails, as in the original. Written without an XML declaration, as the original's
/// serializer wrote it.
fn xmldsig(key: &Key, xml: &str, element: &str, parent: &str) -> Option<String> {
    let mut args = SignXmlExArgs {
        handle: key.handle(),
        xml: xml.as_bytes().to_vec().into(),
        element: None,
        parent: None,
        namespaces: Vec::new(),
        other_prefix_uri: None,
        placement: Placement::DocumentElement,
        signature_method: None,
        digest_method: None,
        signed_info_c14n: None,
        transforms: None,
        signature_id: None,
        signing_time_object: None,
        strip_whitespace: true,
        base64_line_breaks: None,
        output: XmlOutput::Serialize {
            declaration: false,
            standalone_no: false,
            trim: true,
        },
    };
    if !element.is_empty() {
        if parent.is_empty() || equals_ignore_case(parent, element) {
            return None;
        }
        args.element = Some(element.to_owned());
        args.parent = Some(parent.to_owned());
        args.namespaces = vec![NsBinding {
            prefix: "SOAP-ENV".to_owned(),
            uri: SOAP_ENV_NS.to_owned(),
        }];
        args.other_prefix_uri = Some(XMLDSIG_NS.to_owned());
        args.placement = Placement::Parent;
        args.signed_info_c14n = Some(C14n::Exclusive);
        // A deliberate fix (registry.toml): the original used only the C14N transform; the
        // enveloped one also lets a signature placed inside the signed element verify.
        args.transforms = Some(vec![
            Transform::Enveloped,
            Transform::C14n(C14n::InclusiveWithComments),
        ]);
    }
    let signed = key.sign_xml_ex(args).ok()?;
    Some(String::from_utf8_lossy(&signed).into_owned())
}

/// Java's `String.equalsIgnoreCase`.
fn equals_ignore_case(a: &str, b: &str) -> bool {
    a.chars().count() == b.chars().count()
        && a.chars().zip(b.chars()).all(|(x, y)| {
            x == y || x.to_uppercase().eq(y.to_uppercase()) || x.to_lowercase().eq(y.to_lowercase())
        })
}

/// The key dialog with the original's storages and no condition on the key: it checked
/// none.
fn choose() -> Option<Key> {
    let args = ChooseArgs {
        action: Action::Sign,
        storages: STORAGES.map(str::to_owned).to_vec(),
        filter: Filter {
            chain: Some(Vec::new()),
            allow_expired: true,
            allow_revoked: true,
            ..Filter::default()
        },
        detail: None,
    };
    keys::choose(&args).ok().flatten()
}

/// Kalkan's `createCAdES`: contentType, signingTime, messageDigest and signingCertificateV2,
/// the signer certificate, an encapsulated CMS co-signed; with `timestamp`, a time-stamp of
/// Kalkan's default TSA. `None` if signing or the time-stamp fails.
fn cades(key: &Key, data: &[u8], attach: bool, timestamp: bool) -> Option<Vec<u8>> {
    let args = SignCmsExArgs {
        handle: key.handle(),
        content: CmsContent::Data(data.to_vec().into()),
        encapsulate: attach,
        cosign: CoSign::Auto,
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
        timestamp: timestamp.then_some(TsaChoice::Kalkan),
        output: oncl_pdk::abi::CmsOutput::Der,
    };
    match key.sign_cms_ex(args) {
        Ok(CmsOutcome::Signed(cms)) => Some(cms.into_vec()),
        Ok(CmsOutcome::TspFailed(_)) | Err(_) => None,
    }
}

/// The error window: `true` for «Закрыть» (try again), `false` for «Отменить» or closing it.
fn retry(texts: &Texts, text: &str) -> bool {
    let args = ChoiceArgs {
        kind: MessageKind::Error,
        title: Some(texts.error_title.to_owned()),
        text: text.to_owned(),
        buttons: vec![texts.close.to_owned(), texts.cancel.to_owned()],
        default: 0,
        options: Vec::new(),
    };
    matches!(dialogs::choice(&args), Ok(Some(0)))
}

fn cancel() -> String {
    ecc(None, Some("CANCEL"))
}

/// No reply: the connection closes, as the original's did on an exception it did not catch.
fn drop_connection() -> String {
    let _ = host::reply_drop();
    String::new()
}

/// Base64 without line breaks.
fn base64(bytes: &[u8]) -> String {
    javab64::encode_mime(bytes).replace("\r\n", "")
}
