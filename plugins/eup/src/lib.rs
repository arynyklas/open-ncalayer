//! The Zan Komegi signer (`kz.nitec.eup.eupsigner`): one operation,
//! `{uuid, args:[<base64 data>, <file names>]}`, answered with one detached ESEDO CMS over
//! the data with the OCSP answer about the signer inside its signed attributes; no
//! time-stamp.
//!
//! Replies are the original's `ResponseJson` bean plus `uuid` (a `HashMap` of 16 buckets).
//! An exception answers code `500`, its `toString()` and the error model
//! (`"<code> <text>"`, `"null null"` when none was set); a failure inside the CMS answers
//! code `200` with its message.
#![cfg(target_arch = "wasm32")]

use oncl_pdk::abi::{
    Action, CmsCerts, CmsOutcome, CoSign, Filter, HashAlg, KeyOrder, MAX_PKI_TIMEOUT_MS, Nonce,
    PkiMethod, TimeForm,
};
use oncl_pdk::keys::{self, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::pki::OcspOutcome;
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{Request, host, javab64, pki};
use oncl_port_pki::esedo::{
    self, CertIdHash, ContentMode, Description, Encapsulate, EsedoInput, FileNames, IssuerRule,
    OcspAnswer, OcspForm, OcspRequest, OcspUrl, Profile, SignerDn, SigningTimeRule, StringKind,
    TimeFrom,
};

oncl_pdk::plugin!(handle);

/// The OCSP request before signing: the core's CAs, a SHA-256 `CertID`, no nonce, POST to
/// `http://ocsp.pki.gov.kz`; the answer is embedded as it is, unchecked.
pub const OCSP: OcspRequest = OcspRequest {
    issuer: IssuerRule::HostCas,
    cert_id_hash: CertIdHash::Fixed(HashAlg::Sha256),
    nonce: Nonce::None,
    method: PkiMethod::Post { content_type: None },
    url: OcspUrl::Default,
    // The original waited without a limit.
    timeout_ms: MAX_PKI_TIMEOUT_MS,
    check: false,
};

/// eup's CMS: detached id-data, the seven ESEDO attributes (signingTime as
/// GeneralizedTime, `ESEDO\0`, the whole `OCSPResponse` in an OCTET STRING). messageDigest
/// uses the certificate's digest (the original always used GOST 34.311, which made RSA
/// signatures invalid, and refused GOST 2015 certificates).
pub const EUP: Profile = Profile {
    econtent_type: None,
    content: ContentMode::Data,
    digest: None,
    encapsulate: Encapsulate::Never,
    cosign: CoSign::Never,
    certificates: CmsCerts::Signer,
    content_type: true,
    signing_certificate_v2: false,
    signing_time: Some(SigningTimeRule {
        from: TimeFrom::Now,
        form: TimeForm::Generalized,
    }),
    file_names: Some(FileNames {
        separator: "<>",
        omit_blank: false,
    }),
    signer_dn: Some(SignerDn::Kalkan),
    description: Some(Description {
        text: "ESEDO\0",
        kind: StringKind::Printable,
    }),
    ocsp: Some(OcspForm::OctetResponse),
    ocsp_request: Some(OCSP),
};

/// The error model once the OCSP request failed.
const OCSP_MODEL: &str =
    "102 Ошибка при формировании подписи. Возможная причина: отсутствие соединения с интернет.";

/// How a call ended.
enum Outcome {
    /// The CMS, base64.
    Signed(String),
    /// An exception: its `toString()` and the error model, if set.
    Failed(String, Option<&'static str>),
    /// A failure inside the CMS: code 200 with its message.
    CmsFailed(String),
}

fn handle(request: &Request) -> String {
    let Ok(JValue::Obj(root)) = orgjson::parse(&request.text) else {
        let _ = host::reply_drop();
        return String::new();
    };
    let root = root.to_map();
    let uuid = orgjson::opt_string(&root, "uuid").unwrap_or_default();
    let mut reply = JObject::hash_map();
    match sign(&root) {
        Outcome::Signed(cms) => {
            reply.put("responseObject", cms);
            reply.put("code", "200");
        }
        Outcome::Failed(message, model) => {
            reply.put("responseObject", model.unwrap_or("null null"));
            reply.put("code", "500");
            reply.put("message", message);
        }
        Outcome::CmsFailed(message) => {
            reply.put("code", "200");
            reply.put("message", message);
        }
    }
    reply.put("uuid", uuid);
    reply.to_json()
}

/// `args.get(i).toString()`.
fn arg(args: &[Value], i: usize) -> Result<String, Outcome> {
    args.get(i).map(orgjson::value_to_string).ok_or_else(|| {
        Outcome::Failed(
            format!("org.json.JSONException: JSONArray[{i}] not found."),
            None,
        )
    })
}

/// The operation, in the original's order: arguments, dialog, OCSP, base64, CMS.
fn sign(root: &Map<String, Value>) -> Outcome {
    match try_sign(root) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn try_sign(root: &Map<String, Value>) -> Result<Outcome, Outcome> {
    let npe = || Outcome::Failed("java.lang.NullPointerException".to_owned(), None);
    let args = orgjson::opt_array(root, "args").ok_or_else(npe)?;
    let data = arg(args, 0)?;
    let names = arg(args, 1)?;
    let key = keys::select(&SelectArgs {
        action: Action::Sign,
        storages: vec!["PKCS12".to_owned()],
        filter: Filter {
            // The original signs with any key of the file, unchecked.
            allow_expired: true,
            chain: Some(Vec::new()),
            allow_revoked: true,
            ..Filter::default()
        },
        more: Default::default(),
        detail: None,
        initial_path: None,
        order: KeyOrder::OldestFirst,
    })
    .ok()
    .flatten()
    // A closed dialog leaves the path null.
    .ok_or_else(npe)?;
    let cert = key.certificate();
    let details = host::cert_details(cert).map_err(|_| npe())?;
    let ocsp = esedo::ocsp_args(&OCSP, cert, &[])
        .ok()
        .and_then(|args| pki::ocsp_fetch(&args).ok());
    let Some(
        ocsp @ OcspOutcome::Ok {
            http_status: 200, ..
        },
    ) = &ocsp
    else {
        return Err(Outcome::Failed(
            "java.lang.Exception: OCSP response generation error. Check internet connection"
                .to_owned(),
            Some(OCSP_MODEL),
        ));
    };
    let bytes = javab64::decode_kalkan(&data)
        .map_err(|e| Outcome::Failed(format!("java.lang.{e}"), None))?;
    let input = EsedoInput {
        cert,
        kalkan_dn: Some(&details.subject_dn),
        file_names: &[&names],
        ocsp: OcspAnswer::from_outcome(ocsp),
        data: &bytes,
        ..EsedoInput::default()
    };
    Ok(
        match esedo::sign_args(&EUP, &input, key.handle()).map(|args| key.sign_cms_ex(args)) {
            Ok(Ok(CmsOutcome::Signed(cms))) => {
                Outcome::Signed(javab64::encode_mime(&cms).replace("\r\n", ""))
            }
            Ok(Ok(CmsOutcome::TspFailed(failure))) => Outcome::CmsFailed(failure.detail),
            Ok(Err(e)) => Outcome::CmsFailed(e.message),
            Err(message) => Outcome::CmsFailed(message),
        },
    )
}
