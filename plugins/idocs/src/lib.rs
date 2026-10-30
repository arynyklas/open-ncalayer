//! The module `kz.idocs` of idocs.kz: one method, `sign{name, data}`, in the original's
//! `CommonInvoker` dialect (class `EsedoController`), whose body is a JSON **text** (the
//! page gets it encoded twice): `{"content":"<base64 CMS>","status":"success"}`,
//! `{"status":"cancelled"}` or `{"message":…,"status":"failure"}`.
//!
//! The CMS is the idocs ESEDO profile ([`IDOCS`]): detached, GOST 34.11-2015 (512) whatever
//! the key, the file name, an OCSP answer about the signer (embedded unchecked, left out
//! when the responder fails) and the description `ESEDO`.

use der::{Decode, Encode};
use oncl_pdk::abi::{CmsCerts, CmsOutcome, CoSign, HashAlg, Nonce, PkiMethod, TimeForm};
use oncl_pdk::invoker::Failure;
use oncl_pdk::invoker::java::{
    BadRequest, CallResult, InvokeOptions, NlClass, NlMethod, invoke_with,
};
use oncl_pdk::keys::{Action, Filter, FilterMore, KeyOrder, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{AddInfo, Reply, Request, host, javab64, keys, pki};
use oncl_port_pki::esedo::{
    self, CertIdHash, ContentMode, Description, Encapsulate, EsedoInput, FileNames, IssuerRule,
    OcspAnswer, OcspForm, OcspRequest, OcspUrl, Profile, SigningTimeRule, StringKind, TimeFrom,
};
use x509_cert::Certificate;

/// The idocs ESEDO CMS.
pub const IDOCS: Profile = Profile {
    econtent_type: None,
    content: ContentMode::Data,
    digest: Some(HashAlg::Streebog512),
    encapsulate: Encapsulate::Never,
    cosign: CoSign::Never,
    certificates: CmsCerts::Signer,
    // contentType and signingTime: the defaults of Kalkan's generator.
    content_type: true,
    signing_certificate_v2: false,
    signing_time: Some(SigningTimeRule {
        from: TimeFrom::Now,
        form: TimeForm::Auto,
    }),
    file_names: Some(FileNames {
        separator: "<>",
        omit_blank: false,
    }),
    signer_dn: None,
    description: Some(Description {
        text: "ESEDO",
        kind: StringKind::Utf8,
    }),
    ocsp: Some(OcspForm::OctetResponse),
    ocsp_request: Some(IDOCS_OCSP),
};

/// The OCSP request before signing: `CertID` with SHA-1 against the NCA GOST 2022
/// certificate, an 8-byte nonce, POST to `http://ocsp.pki.gov.kz`, 10 seconds, no check.
pub const IDOCS_OCSP: OcspRequest = OcspRequest {
    issuer: IssuerRule::Given,
    cert_id_hash: CertIdHash::Fixed(HashAlg::Sha1),
    nonce: Nonce::Random(8),
    method: PkiMethod::Post { content_type: None },
    url: OcspUrl::Default,
    timeout_ms: 10_000,
    check: false,
};

/// The class of the exceptions of the request's checks.
const INVALID_REQUEST: &str = "kz.idocs.units.esedo.exceptions.InvalidEsedoSignReq";

fn handle(request: &Request) -> String {
    let options = InvokeOptions {
        bad_request: BadRequest::CatchAll,
    };
    match invoke_with(
        &request.text,
        &request.add_info(),
        &[&EsedoController],
        &options,
    ) {
        Reply::Text(text) => text,
        Reply::Drop => {
            let _ = host::reply_drop();
            String::new()
        }
    }
}

oncl_pdk::plugin!(handle);

/// The class `EsedoController`.
struct EsedoController;

const METHODS: &[NlMethod] = &[NlMethod {
    name: "sign",
    annotation: Some("sign"),
    params: 1,
}];

impl NlClass for EsedoController {
    fn class_name(&self) -> &'static str {
        "EsedoController"
    }

    fn methods(&self) -> &'static [NlMethod] {
        METHODS
    }

    fn call(&self, _: &NlMethod, args: Option<&Map<String, Value>>, _: &AddInfo) -> CallResult {
        sign(args.expect("sign has a parameter"))
    }
}

/// An exception of the method, as the dispatcher reports it.
fn thrown(class: &str, message: &str) -> Failure {
    Failure::Invocation(Some(format!("{class}: {message}")))
}

/// `sign{name, data}`: checks the request (both keys present, then each a non-empty
/// string, then `data` base64), asks for the key and signs.
fn sign(args: &Map<String, Value>) -> CallResult {
    for key in ["name", "data"] {
        if !args.contains_key(key) {
            return Err(thrown(
                INVALID_REQUEST,
                &format!("Поле \"{key}\" не найдено в теле запроса"),
            ));
        }
    }
    let json = |e: String| thrown("org.json.JSONException", &e);
    let name = orgjson::get_string(args, "name").map_err(json)?;
    let data = orgjson::get_string(args, "data").map_err(json)?;
    for (key, value) in [("name", name), ("data", data)] {
        if value.is_empty() {
            return Err(thrown(
                INVALID_REQUEST,
                &format!("Поле \"{key}\" не может быть пустым"),
            ));
        }
    }
    let content =
        javab64::decode_java(data).map_err(|e| thrown("java.lang.IllegalArgumentException", &e))?;

    let request = SelectArgs {
        action: Action::Sign,
        storages: vec!["PKCS12".to_owned()],
        // No checks before signing, as the original.
        filter: Filter {
            chain: Some(Vec::new()),
            allow_expired: true,
            allow_revoked: true,
            ..Filter::default()
        },
        more: FilterMore::default(),
        detail: Some(name.to_owned()),
        initial_path: None,
        order: KeyOrder::default(),
    };
    let mut reply = JObject::hash_map();
    match keys::select(&request) {
        Ok(None) => {
            reply.put("status", "cancelled");
        }
        Ok(Some(key)) => match signed(&key, name, &content) {
            Ok(cms) => {
                reply.put("content", base64(&cms));
                reply.put("status", "success");
            }
            Err(message) => {
                reply.put("message", message);
                reply.put("status", "failure");
            }
        },
        Err(e) => {
            reply.put("message", e.message);
            reply.put("status", "failure");
        }
    }
    Ok(JValue::Str(reply.to_json()))
}

/// The CMS of `content` named `name`, signed with `key`; an error is the reply's message.
// Unverified against the original: the message of a failed signature (Kalkan's text there,
// the core's here), e.g. for a key that is not GOST 2015-512.
fn signed(key: &keys::Key, name: &str, content: &[u8]) -> Result<Vec<u8>, String> {
    let cert = key.certificate();
    let outcome = nca_gost_2022().and_then(|issuer| {
        let args = esedo::ocsp_args(&IDOCS_OCSP, cert, &[&issuer]).ok()?;
        pki::ocsp_fetch(&args).ok()
    });
    let input = EsedoInput {
        cert,
        file_names: &[name],
        ocsp: outcome.as_ref().and_then(OcspAnswer::from_outcome),
        data: content,
        ..EsedoInput::default()
    };
    let args = esedo::sign_args(&IDOCS, &input, key.handle())?;
    match key.sign_cms_ex(args).map_err(|e| e.message)? {
        CmsOutcome::Signed(cms) => Ok(cms.into_vec()),
        CmsOutcome::TspFailed(failure) => Err(failure.detail),
    }
}

/// The issuer the `CertID` names whatever the signer's real one: the NCA GOST 2022
/// certificate, the first CA of the core's that a root issued (not self-signed) with a
/// GOST 2015 key.
fn nca_gost_2022() -> Option<Vec<u8>> {
    const GOST_2015_KEY: &str = "1.2.398.3.10.1.1.2.";
    host::ca_list().ok()?.into_iter().find(|der| {
        Certificate::from_der(der).is_ok_and(|cert| {
            let tbs = cert.tbs_certificate();
            let key = tbs.subject_public_key_info().algorithm.oid.to_string();
            key.starts_with(GOST_2015_KEY)
                && tbs.subject().to_der().ok() != tbs.issuer().to_der().ok()
        })
    })
}

/// Standard base64, padded, on one line.
fn base64(bytes: &[u8]) -> String {
    javab64::encode_mime(bytes).replace("\r\n", "")
}
