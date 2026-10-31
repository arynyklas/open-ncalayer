//! The module's exports and the core it asks, on `wasm32`.

use oncl_pdk::abi::{
    CertDetails, CertInfo, CmsOutcome, FlowArgs, HostResult, KeyDescription, PageRead, PathOutcome,
    PathTime, SignCmsExArgs, StampArgs, StampOutcome,
};
use oncl_pdk::keys::{self, Key};
use oncl_pdk::{Locale, Request, files, host, pki, shared, tokens};

/// The process's dialog language in the core's shared state.
const LOCALE_KEY: &str = "locale";

/// The core, through the host functions. A failure the module has no answer for is the
/// module's failure: the connection is dropped.
struct Host;

impl crate::Core for Host {
    type Key = Key;

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
        keys::terminals(storage).expect("keys_terminals")
    }

    fn choose_key(&self, flow: &FlowArgs) -> Option<Key> {
        let (flow, _) = keys::flow_open(flow).expect("keys_flow_open");
        flow?.pick(None).expect("keys_flow_pick")
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
        key.sign_cms_ex(args)
    }

    fn stamp(&self, args: &StampArgs) -> HostResult<StampOutcome> {
        pki::stamp(args)
    }

    fn sign_xml(
        &self,
        key: &Key,
        xml: &[u8],
        element: Option<&str>,
        parent: Option<&str>,
    ) -> HostResult<Vec<u8>> {
        key.sign_xml(xml, element, parent)
    }

    fn page_read(&self, path: &str) -> PageRead {
        files::page_read(path).expect("page_file_read")
    }

    fn choose_kind(&self, kind: &str, directory: &str) -> HostResult<Option<String>> {
        files::choose_kind(kind, Some(directory))
    }
}

fn handle(request: &Request) -> String {
    crate::handle(&Host, &request.text, &request.add_info())
}

oncl_pdk::plugin!(handle);
