//! The module's exports and the core it asks, on `wasm32`.

use crate::Chosen;
use oncl_pdk::abi::{
    CertDetails, CertInfo, CmsOutcome, ErrorCode, FlowArgs, FlowReaders, HostResult,
    KeyDescription, PageRead, PathOutcome, PathTime, SignCmsExArgs, SignXmlArgs, StampArgs,
    StampOutcome,
};
use oncl_pdk::data::{self, DataDecoded, DataDecoding, DataEncoding};
use oncl_pdk::keys::{self, Key};
use oncl_pdk::serde_json::{self, Value};
use oncl_pdk::{Locale, Request, files, host, pki, shared, tokens};
use std::borrow::Cow;
use std::collections::BTreeSet;

/// The process's dialog language in the core's shared state.
const LOCALE_KEY: &str = "locale";

/// The methods whose third argument is data the module hands to the core.
const DATA_METHODS: [&str; 6] = [
    "createCAdESFromBase64",
    "createCAdESFromBase64Hash",
    "createCMSSignatureFromBase64",
    "applyCAdEST",
    "signXml",
    "signXmls",
];

/// The core, through the host functions, with the prefix of the call's data markers. A
/// failure the module has no answer for is the module's failure: the connection is
/// dropped.
struct Host {
    prefix: String,
}

impl Host {
    fn is_marker(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(self.prefix.as_bytes())
    }
}

impl crate::Core for Host {
    type Key = Key;

    fn decode(&self, text: &str) -> Result<Vec<u8>, String> {
        if !self.is_marker(text.as_bytes()) {
            return oncl_pdk::javab64::decode_java(text);
        }
        match data::decode(text, DataDecoding::JavaBase64).expect("data_decode") {
            DataDecoded::Data(marker) => Ok(marker.into_bytes()),
            DataDecoded::Invalid(message) => Err(message),
        }
    }

    fn encode(&self, bytes: &[u8]) -> String {
        use base64::Engine;
        if self.is_marker(bytes) {
            let marker = std::str::from_utf8(bytes).expect("a marker is text");
            data::encode(marker, DataEncoding::Base64).expect("data_encode")
        } else {
            base64::engine::general_purpose::STANDARD.encode(bytes)
        }
    }

    fn locale(&self) -> Locale {
        match shared::get(LOCALE_KEY).expect("shared_get").as_deref() {
            Some(b"kk") => Locale::Kk,
            Some(b"en") => Locale::En,
            _ => Locale::Ru,
        }
    }

    fn set_locale(&self, locale: Locale) {
        let value: &[u8] = match locale {
            Locale::Ru => b"ru",
            Locale::Kk => b"kk",
            Locale::En => b"en",
        };
        shared::put(LOCALE_KEY, Some(value), None).expect("shared_put");
    }

    fn debug(&self, line: &str) {
        // A line the core does not keep is no failure of the request.
        let _ = host::log(host::Level::Debug, line);
    }

    fn call_locale(&self, locale: Locale) {
        host::call_locale(locale).expect("call_locale");
    }

    fn active_tokens(&self) -> Vec<String> {
        tokens::scan().expect("tokens_scan").present
    }

    fn readers(&self, storage: &str) -> Vec<String> {
        // As the original read them: a failing smart card service has no readers.
        keys::terminals(storage).unwrap_or_else(|e| {
            self.debug(&format!("the readers of {storage}: {e}"));
            Vec::new()
        })
    }

    fn choose_key(&self, flow: &FlowArgs) -> Chosen<Key> {
        let (flow, _) = match keys::flow_open(flow) {
            Ok(opened) => opened,
            // A fixed reader is checked before any window: its token went since
            // `readers`, or the smart card service failed.
            Err(e)
                if matches!(flow.readers, FlowReaders::Fixed(_))
                    && matches!(e.code, ErrorCode::Invalid | ErrorCode::Failed) =>
            {
                self.debug(&format!("the key choice's reader: {e}"));
                return Chosen::ReaderGone;
            }
            Err(e) => panic!("keys_flow_open: {e}"),
        };
        match flow.map(|flow| flow.pick(None).expect("keys_flow_pick")) {
            Some(Some(key)) => Chosen::Key(key),
            _ => Chosen::Canceled,
        }
    }

    fn certificate<'k>(&self, key: &'k Key) -> &'k [u8] {
        key.certificate()
    }

    fn describe(&self, key: &Key) -> KeyDescription {
        key.describe().expect("keys_describe")
    }

    fn cert_info(&self, der: &[u8]) -> CertInfo {
        host::cert_info(der).expect("cert_info")
    }

    fn cert_details(&self, der: &[u8]) -> CertDetails {
        host::cert_details(der).expect("cert_details")
    }

    fn path(&self, der: &[u8]) -> PathOutcome {
        pki::path(der, PathTime::NotAfterIfExpired).expect("pkix_path")
    }

    fn sign_cms(&self, key: &Key, args: SignCmsExArgs) -> HostResult<CmsOutcome> {
        data::sign_cms(&SignCmsExArgs {
            handle: key.handle(),
            ..args
        })
    }

    fn stamp(&self, args: &StampArgs) -> HostResult<StampOutcome> {
        data::stamp(args)
    }

    fn sign_xml(
        &self,
        key: &Key,
        xml: &[u8],
        element: Option<&str>,
        parent: Option<&str>,
    ) -> HostResult<Vec<u8>> {
        data::sign_xml(&SignXmlArgs {
            handle: key.handle(),
            xml: xml.to_vec().into(),
            element: element.map(str::to_owned),
            parent: parent.map(str::to_owned),
        })
        .map(String::into_bytes)
    }

    fn page_read(&self, path: &str) -> PageRead {
        data::page_read(path).expect("data_page_read")
    }

    fn choose_kind(&self, kind: &str, directory: &str) -> HostResult<Option<String>> {
        files::choose_kind(kind, Some(directory))
    }
}

fn handle(request: &Request) -> String {
    let Some(prefix) = request.data_prefix.clone() else {
        panic!("a built-in module's call keeps data");
    };
    // The core keeps the long strings of the request; the module reads all but the data
    // of the signing methods.
    let text = if data::holds_markers(&request.text, &prefix) {
        match serde_json::from_str::<Value>(&request.text) {
            Ok(parsed) => {
                let data_method = parsed["method"]
                    .as_str()
                    .is_some_and(|m| DATA_METHODS.contains(&m));
                let kept: BTreeSet<&str> = match (&parsed["args"][2], data_method) {
                    (Value::String(s), true) => BTreeSet::from([s.as_str()]),
                    (Value::Array(items), true) => items.iter().filter_map(Value::as_str).collect(),
                    _ => BTreeSet::new(),
                };
                data::restore(&request.text, &prefix, |m| kept.contains(m)).expect("data_read")
            }
            Err(_) => Cow::Borrowed(request.text.as_str()),
        }
    } else {
        Cow::Borrowed(request.text.as_str())
    };
    crate::handle(&Host { prefix }, &text, &request.add_info())
}

oncl_pdk::plugin!(handle);
