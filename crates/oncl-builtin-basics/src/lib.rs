//! The `kz.gov.pki.knca.basics` module, built into the core as a WebAssembly module:
//! `CommonInvoker` over the classes `PKIExtras` (`sign`: cms with NCA time-stamps, raw, and
//! enveloped XMLDSig) and `PKIEssentials` (`generateCsr`: new keys in PKCS#12 key files and
//! their requests; `importCertificate`: certificates installed next to those keys).
//!
//! The module reads the requests, in the original's order and with its error texts, and
//! writes the replies; the core shows the windows, checks the keys offered (against
//! `signerParams.chain` and their OCSP responders), signs, time-stamps and writes the key
//! files ([`Core`]). The private keys never reach the module.

mod args;
mod essentials;
mod failures;
mod sign;

#[cfg(target_arch = "wasm32")]
mod guest;

use oncl_pdk::abi::{
    CertInfo, CmsOutcome, CsrChoice, CsrDialogArgs, FlowArgs, HostResult, ImportChoice,
    ImportDialogArgs, InstallCertArgs, InstalledCert, NewKey, NewKeyArgs, SignCmsExArgs,
};
use oncl_pdk::invoker::Failure;
use oncl_pdk::invoker::java::{self, BadRequest, InvokeOptions, NlClass, NlMethod};
use oncl_pdk::orgjson::{JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{AddInfo, Locale};

/// Name the module is registered under.
pub const MODULE_NAME: &str = "kz.gov.pki.knca.basics";

/// What the module asks of the core. A failure the module has no answer for (the core
/// refusing what the module never sends) is the module's failure: the connection is
/// dropped.
pub trait Core {
    /// A key the user chose, usable until dropped.
    type Key;

    /// The windows of this call speak `locale`.
    fn set_locale(&self, locale: Locale);
    /// Writes `message` to the core's log (never a password, a path or the page's data).
    fn log(&self, message: &str);
    /// The details of the certificate `der`; `None` if it is no certificate.
    fn cert_info(&self, der: &[u8]) -> Option<CertInfo>;
    /// The core's time, Unix milliseconds.
    fn now(&self) -> i64;
    /// The line separator of the core's system.
    fn line_separator(&self) -> String;
    /// The storage and key windows of `flow`: the key picked, `None` if the user cancels.
    fn choose_key(&self, flow: &FlowArgs) -> Option<Self::Key>;
    /// The certificate of `key`, DER.
    fn certificate<'k>(&self, key: &'k Self::Key) -> &'k [u8];
    /// `text` (a string of the request, or the marker of one the core keeps) decoded by
    /// Java's `Base64.getDecoder()` ([`oncl_pdk::javab64::decode_java`]): the data, or the
    /// marker of the data the core keeps; else the decoder's message.
    fn decode(&self, text: &str) -> Result<Vec<u8>, String>;
    /// A CMS signature with `key` as `args` say, of data or of the data a marker stands
    /// for: the CMS, or the marker of the CMS the core keeps.
    fn sign_cms(&self, key: &Self::Key, args: SignCmsExArgs) -> HostResult<CmsOutcome>;
    /// A signature of `data` (or of the data a marker stands for) with `key`'s algorithm.
    fn sign_raw(&self, key: &Self::Key, data: &[u8]) -> HostResult<Vec<u8>>;
    /// `xml` (or the document a marker stands for) with an enveloped signature of the whole
    /// document: the document, or the marker of the document the core keeps.
    fn sign_xml(&self, key: &Self::Key, xml: &[u8]) -> HostResult<Vec<u8>>;
    /// The `generateCsr` window.
    fn dialog_csr(&self, args: &CsrDialogArgs) -> HostResult<Option<CsrChoice>>;
    /// The `importCertificate` window.
    fn dialog_import(&self, args: &ImportDialogArgs) -> Option<ImportChoice>;
    /// A new key in a key file, and its request.
    fn new_key(&self, args: &NewKeyArgs) -> HostResult<NewKey>;
    /// A certificate installed next to its key.
    fn install_cert(&self, args: &InstallCertArgs) -> HostResult<InstalledCert>;
}

/// The reply to `request` from the page of `add_info`. A request without a string `method`
/// is a `GENERAL_ERROR` whose `details` is org.json's exception, as the original answers it.
pub fn handle(core: &(impl Core + Sync), request: &str, add_info: &AddInfo) -> String {
    java::invoke_with(
        request,
        add_info,
        &[&PkiExtras(core), &PkiEssentials(core)],
        &InvokeOptions {
            bad_request: BadRequest::CatchAll,
        },
    )
    .into_text()
    .expect("the dispatcher answers every request")
}

/// What a method of the module returns: the reply's `body`, or a failure.
type CallResult = Result<Value, Failure>;

/// `body` as the module writes it: the keys of its objects in the order the method put them.
fn body(value: Value) -> JValue {
    match value {
        Value::Object(map) => {
            let mut object = JObject::stringer();
            for (key, value) in map {
                object.put(key, body(value));
            }
            JValue::Obj(object)
        }
        Value::Array(items) => JValue::Arr(items.into_iter().map(body).collect()),
        other => JValue::from(other),
    }
}

/// `PKIExtras`, the default class.
struct PkiExtras<'a, C>(&'a C);

/// `PKIExtras.sign(args, addInfo)`.
const EXTRAS_METHODS: &[NlMethod] = &[NlMethod {
    name: "sign",
    annotation: None,
    params: 2,
}];

impl<C: Core + Sync> NlClass for PkiExtras<'_, C> {
    fn class_name(&self) -> &'static str {
        "PKIExtras"
    }

    fn methods(&self) -> &'static [NlMethod] {
        EXTRAS_METHODS
    }

    fn call(
        &self,
        _: &NlMethod,
        args: Option<&Map<String, Value>>,
        _: &AddInfo,
    ) -> java::CallResult {
        let args = args.expect("sign has parameters");
        sign::sign(self.0, args).map(body)
    }
}

/// `PKIEssentials`, reachable only by name.
struct PkiEssentials<'a, C>(&'a C);

/// `PKIEssentials.generateCsr(args)` and `importCertificate(args)`.
const ESSENTIALS_METHODS: &[NlMethod] = &[
    NlMethod {
        name: "generateCsr",
        annotation: None,
        params: 1,
    },
    NlMethod {
        name: "importCertificate",
        annotation: None,
        params: 1,
    },
];

impl<C: Core + Sync> NlClass for PkiEssentials<'_, C> {
    fn class_name(&self) -> &'static str {
        "PKIEssentials"
    }

    fn methods(&self) -> &'static [NlMethod] {
        ESSENTIALS_METHODS
    }

    fn call(
        &self,
        method: &NlMethod,
        args: Option<&Map<String, Value>>,
        _: &AddInfo,
    ) -> java::CallResult {
        let args = args.expect("the methods have parameters");
        match method.name {
            "generateCsr" => essentials::generate_csr(self.0, args),
            _ => essentials::import_certificate(self.0, args),
        }
        .map(body)
    }
}
