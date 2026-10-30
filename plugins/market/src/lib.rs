//! MarketSign (`kz.ecc.MarketSignBundle` 1.0.7) as an OpenNCALayer plugin: `version`,
//! `text` (CAdES, time-stamped by Kalkan's default TSA unless asked not to) and `xml`
//! (enveloped XMLDSig of the whole document). A failure to sign shows the original's window:
//! «Закрыть» goes back to the key dialog, «Отменить» replies `CANCEL`.
#![cfg(target_arch = "wasm32")]

mod texts;

use oncl_pdk::abi::{
    Action, ChoiceArgs, ChooseArgs, CmsCerts, CmsContent, CmsOutcome, CoSign, Filter, MessageKind,
    SignCmsExArgs, SignXmlExArgs, SignedAttrs, SigningTime, TimeForm, TimeSource, TsaChoice,
    XmlOutput,
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
        // The spaces are the original's.
        _ => error_text(" Неизвестный тип ", "UNKNOWN TYPE"),
    }
}

oncl_pdk::plugin!(handle);

/// `text`: the key first, then `data`, which the original read only after its dialog; a
/// missing `data` ended the connection without a reply.
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
            // Every failure, the time-stamp's too, has the XML text, as in the original.
            None if retry(texts, texts.sign_xml_failed) => {}
            None => return cancel(),
        }
    }
}

/// `xml`: the whole document signed, without an XML declaration (the original's serializer
/// omitted it).
fn sign_xml(req: &Map<String, Value>, texts: &Texts) -> String {
    loop {
        let Some(key) = choose() else {
            return cancel();
        };
        let error = match orgjson::get_string(req, "data") {
            Err(_) => texts.bad_request,
            Ok(xml) => match key.sign_xml_ex(xmldsig_args(&key, xml)) {
                Ok(signed) => {
                    let signed = String::from_utf8_lossy(&signed).into_owned();
                    return ecc(Some(signed.into()), Some("NONE"));
                }
                Err(_) => texts.sign_xml_failed,
            },
        };
        drop(key);
        if !retry(texts, error) {
            return cancel();
        }
    }
}

/// Kalkan's signature of the whole document, written without the XML declaration.
fn xmldsig_args(key: &Key, xml: &str) -> SignXmlExArgs {
    SignXmlExArgs {
        handle: key.handle(),
        xml: xml.as_bytes().to_vec().into(),
        element: None,
        parent: None,
        namespaces: Vec::new(),
        other_prefix_uri: None,
        placement: Default::default(),
        signature_method: None,
        digest_method: None,
        signed_info_c14n: None,
        transforms: None,
        signature_id: None,
        signing_time_object: None,
        strip_whitespace: false,
        base64_line_breaks: None,
        output: XmlOutput::Serialize {
            declaration: false,
            standalone_no: false,
            trim: false,
        },
    }
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
