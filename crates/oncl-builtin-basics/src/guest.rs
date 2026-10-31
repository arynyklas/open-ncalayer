//! The module's exports and the core it asks, on `wasm32`.

use oncl_pdk::abi::{
    CertInfo, CmsOutcome, CsrChoice, CsrDialogArgs, ErrorCode, FlowArgs, HostResult, ImportChoice,
    ImportDialogArgs, InstallCertArgs, InstalledCert, NewKey, NewKeyArgs, SignCmsExArgs,
    SignXmlArgs,
};
use oncl_pdk::data::{self, DataDecoded, DataDecoding};
use oncl_pdk::keys::{self, Key};
use oncl_pdk::serde_json::{self, Value};
use oncl_pdk::{Locale, Request, builtin, host};

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
            return oncl_pdk::javab64::decode_basics(text).map_err(|e| e.to_string());
        }
        match data::decode(text, DataDecoding::BasicsBase64).expect("data_decode") {
            DataDecoded::Data(marker) => Ok(marker.into_bytes()),
            DataDecoded::Invalid(message) => Err(message),
        }
    }

    fn set_locale(&self, locale: Locale) {
        host::call_locale(locale).expect("call_locale");
    }

    fn log(&self, message: &str) {
        // A line the core does not keep is no failure of the request.
        let _ = host::log(host::Level::Info, message);
    }

    fn cert_info(&self, der: &[u8]) -> Option<CertInfo> {
        match host::cert_info(der) {
            Ok(info) => Some(info),
            Err(e) if e.code == ErrorCode::Invalid => None,
            Err(e) => panic!("cert_info: {e}"),
        }
    }

    fn now(&self) -> i64 {
        host::now().expect("now")
    }

    fn line_separator(&self) -> String {
        host::platform().expect("platform").line_separator
    }

    fn choose_key(&self, flow: &FlowArgs) -> Option<Key> {
        let (flow, _) = keys::flow_open(flow).expect("keys_flow_open");
        flow?.pick(None).expect("keys_flow_pick")
    }

    fn certificate<'k>(&self, key: &'k Key) -> &'k [u8] {
        key.certificate()
    }

    fn sign_cms(&self, key: &Key, args: SignCmsExArgs) -> HostResult<CmsOutcome> {
        data::sign_cms(&SignCmsExArgs {
            handle: key.handle(),
            ..args
        })
    }

    fn sign_raw(&self, key: &Key, bytes: &[u8]) -> HostResult<Vec<u8>> {
        if self.is_marker(bytes) {
            let marker = std::str::from_utf8(bytes).expect("a marker is text");
            key.sign_raw(&data::read(marker).expect("data_read"))
        } else {
            key.sign_raw(bytes)
        }
    }

    fn sign_xml(&self, key: &Key, xml: &[u8]) -> HostResult<Vec<u8>> {
        data::sign_xml(&SignXmlArgs {
            handle: key.handle(),
            xml: xml.to_vec().into(),
            element: None,
            parent: None,
        })
        .map(String::into_bytes)
    }

    fn dialog_csr(&self, args: &CsrDialogArgs) -> HostResult<Option<CsrChoice>> {
        builtin::dialog_csr(args)
    }

    fn dialog_import(&self, args: &ImportDialogArgs) -> Option<ImportChoice> {
        builtin::dialog_import(args).expect("dialog_import")
    }

    fn new_key(&self, args: &NewKeyArgs) -> HostResult<NewKey> {
        builtin::new_key(args)
    }

    fn install_cert(&self, args: &InstallCertArgs) -> HostResult<InstalledCert> {
        builtin::install_cert(args)
    }
}

fn handle(request: &Request) -> String {
    let Some(prefix) = request.data_prefix.clone() else {
        panic!("a built-in module's call keeps data");
    };
    // The core keeps the long strings of the request; the module reads all but `data`.
    let text = match serde_json::from_str::<Value>(&request.text) {
        Ok(parsed) => {
            let kept: Vec<&str> = match &parsed["args"]["data"] {
                Value::String(s) => vec![s.as_str()],
                Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            data::restore(&request.text, &prefix, |m| kept.contains(&m)).expect("data_read")
        }
        Err(_) => request.text.clone(),
    };
    crate::handle(&Host { prefix }, &text, &request.add_info())
}

oncl_pdk::plugin!(handle);
