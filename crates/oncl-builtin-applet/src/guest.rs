//! The module's exports and the core it asks, on `wasm32`.

use oncl_pdk::abi::{
    ChangePasswordArgs, FlowArgs, FlowWrongPin, HostResult, IdCardHolder, InstallCertArgs,
    InstalledCert, NewKey, NewKeyArgs, PasswordArgs, SignXmlArgs, TokenScan,
};
use oncl_pdk::keys::{self, Flow, Key};
use oncl_pdk::serde_json::{self, Value};
use oncl_pdk::{Locale, Request, builtin, data, dialogs, files, host, shared, tokens};

/// The process's PIN try count in the core's shared state.
const TRY_COUNT_KEY: &str = "try_count";

/// The method whose last argument is data the module hands to the core: `signXml`'s
/// document.
const DATA_METHOD: &str = "signXml";

/// The core, through the host functions. A failure the module has no answer for is the
/// module's failure: the connection is dropped.
struct Host;

impl Host {
    fn log(&self, level: host::Level, line: &str) {
        // A line the core does not keep is no failure of the request.
        let _ = host::log(level, line);
    }
}

impl crate::Core for Host {
    type Flow = Flow;
    type Key = Key;

    fn debug(&self, line: &str) {
        self.log(host::Level::Debug, line);
    }

    fn info(&self, line: &str) {
        self.log(host::Level::Info, line);
    }

    fn warn(&self, line: &str) {
        self.log(host::Level::Warn, line);
    }

    fn call_locale(&self, locale: Locale) {
        host::call_locale(locale).expect("call_locale");
    }

    fn try_count(&self) -> i32 {
        shared::get(TRY_COUNT_KEY)
            .expect("shared_get")
            .and_then(|value| std::str::from_utf8(&value).ok()?.parse().ok())
            .unwrap_or(crate::methods::FILE_TRY_COUNT)
    }

    fn set_try_count(&self, tries: i32) {
        shared::put(TRY_COUNT_KEY, Some(tries.to_string().as_bytes()), None).expect("shared_put");
    }

    fn tokens(&self) -> TokenScan {
        tokens::scan().expect("tokens_scan")
    }

    fn readers(&self, storage: &str) -> Result<Vec<String>, String> {
        keys::terminals(storage).map_err(|e| e.message)
    }

    fn choose_reader(&self, storage: &str) -> Option<String> {
        dialogs::reader(storage).expect("dialog_reader")
    }

    fn choose_kind(&self, kind: &str, directory: Option<&str>) -> HostResult<Option<String>> {
        files::choose_kind(kind, directory)
    }

    fn password(&self, message: Option<&str>) -> bool {
        let args = PasswordArgs {
            title: String::new(),
            label: message.unwrap_or_default().to_owned(),
            ok: String::new(),
            cancel: String::new(),
            allow_empty: true,
        };
        dialogs::password(&args).expect("dialog_password").is_some()
    }

    fn id_card(&self, reader: &str) -> HostResult<IdCardHolder> {
        builtin::id_card(reader)
    }

    fn is_certificate(&self, der: &[u8]) -> bool {
        host::cert_info(der).is_ok()
    }

    fn install_cert(&self, args: InstallCertArgs) -> HostResult<InstalledCert> {
        builtin::install_cert(&args)
    }

    fn new_key(&self, args: NewKeyArgs) -> HostResult<NewKey> {
        builtin::new_key(&args)
    }

    fn change_password(&self, args: ChangePasswordArgs) -> HostResult<()> {
        builtin::change_password(&args)
    }

    fn flow_open(&self, flow: &FlowArgs) -> (Option<Flow>, Option<FlowWrongPin>) {
        keys::flow_open(flow).expect("keys_flow_open")
    }

    fn pick(&self, flow: &Flow, error: Option<&str>) -> Option<Key> {
        flow.pick(error).expect("keys_flow_pick")
    }

    fn alias<'k>(&self, key: &'k Key) -> &'k str {
        key.alias()
    }

    fn sign_xml(&self, key: &Key, xml: &str) -> HostResult<String> {
        data::sign_xml(&SignXmlArgs {
            handle: key.handle(),
            xml: xml.as_bytes().to_vec().into(),
            element: None,
            parent: None,
        })
    }
}

fn handle(request: &Request) -> String {
    let Some(prefix) = request.data_prefix.as_deref() else {
        panic!("a built-in module's call keeps data");
    };
    // The core keeps the long strings of the request; the module reads all but the
    // document `signXml` signs.
    let text = match serde_json::from_str::<Value>(&request.text) {
        Ok(parsed) => {
            let document = match (&parsed["method"], &parsed["args"]) {
                (Value::String(m), Value::Array(args)) if m == DATA_METHOD && args.len() == 4 => {
                    args[3].as_str()
                }
                _ => None,
            };
            data::restore(&request.text, prefix, |m| document == Some(m)).expect("data_read")
        }
        Err(_) => request.text.clone(),
    };
    crate::handle(&Host, &text)
}

oncl_pdk::plugin!(handle);
