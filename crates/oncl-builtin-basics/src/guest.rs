//! The module's exports and the core it asks, on `wasm32`.

use oncl_pdk::abi::{
    CertInfo, CmsOutcome, CsrChoice, CsrDialogArgs, ErrorCode, FlowArgs, HostResult, ImportChoice,
    ImportDialogArgs, InstallCertArgs, InstalledCert, NewKey, NewKeyArgs, SignCmsExArgs,
};
use oncl_pdk::keys::{self, Key};
use oncl_pdk::{Locale, Request, builtin, host};

/// The core, through the host functions. A failure the module has no answer for is the
/// module's failure: the connection is dropped.
struct Host;

impl crate::Core for Host {
    type Key = Key;

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
        key.sign_cms_ex(args)
    }

    fn sign_raw(&self, key: &Key, data: &[u8]) -> HostResult<Vec<u8>> {
        key.sign_raw(data)
    }

    fn sign_xml(&self, key: &Key, xml: &[u8]) -> HostResult<Vec<u8>> {
        key.sign_xml(xml, None, None)
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
    crate::handle(&Host, &request.text, &request.add_info())
}

oncl_pdk::plugin!(handle);
