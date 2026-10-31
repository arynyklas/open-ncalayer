//! The Dogovor24 module (`kz.dogovor24.module`): the key dialog comes first, for every
//! request, then the method: `signCMS` (an attached CAdES, time-stamped by Kalkan's default
//! TSA), `batchSignCMS` (one per element) and `signEsedo` (a detached ESEDO CMS with the
//! OCSP answer inside). Any other method answers the plain text
//! `error: method not found [<method>]`.
#![cfg(target_arch = "wasm32")]

use oncl_pdk::abi::{
    Action, Bytes, CmsCerts, CmsContent, CmsOutcome, CoSign, Filter, HashAlg, KeyOrder,
    MAX_PKI_TIMEOUT_MS, Nonce, PkiMethod, SignCmsExArgs, SignedAttrs, SigningTime, TimeForm,
    TimeSource, TsaChoice,
};
use oncl_pdk::keys::{self, Key, SelectArgs};
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

/// clientAuth: a key for authentication, which must not sign here.
const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

/// What `signEsedo` and the EKU check answer.
const NOT_A_SIGNING_KEY: &str = "Необходимо использовать ключ для подписи!";

/// The OCSP request of `signEsedo`: the core's CAs, a SHA-256 `CertID`, no nonce, POST to
/// `http://ocsp.pki.gov.kz`; the answer is embedded unchecked, or left out on a failure.
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

/// `signEsedo`'s CMS: detached id-data, the ESEDO attributes (signingTime as
/// GeneralizedTime, `ESEDO\0`, the signer DN from its RFC 2253 text, which reverses the
/// RDNs, the whole `OCSPResponse` in an OCTET STRING). messageDigest uses the certificate's
/// digest (the original used GOST 34.311 for RSA, which made those signatures invalid).
pub const DOGOVOR24: Profile = Profile {
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
    signer_dn: Some(SignerDn::Rfc2253Reversed),
    description: Some(Description {
        text: "ESEDO\0",
        kind: StringKind::Printable,
    }),
    ocsp: Some(OcspForm::OctetResponse),
    ocsp_request: Some(OCSP),
};

fn handle(request: &Request) -> String {
    let Ok(JValue::Obj(root)) = orgjson::parse(&request.text) else {
        let _ = host::reply_drop();
        return String::new();
    };
    let root = root.to_map();
    let method = orgjson::opt_string(&root, "method").unwrap_or_default();
    // The dialog comes before the method is looked at; a closed one leaves no key.
    let key = keys::select(&SelectArgs {
        action: Action::Sign,
        storages: vec!["PKCS12".to_owned()],
        filter: Filter {
            // The original opens the file and checks nothing in the dialog.
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
    .flatten();
    match method.as_str() {
        "signCMS" => reply(sign_cms(&root, key.as_ref()), None),
        "batchSignCMS" => batch_sign_cms(&root, key.as_ref()),
        "signEsedo" => {
            let uuid = orgjson::opt_string(&root, "uuid").unwrap_or_default();
            reply(sign_esedo(&root, key.as_ref()), Some(uuid))
        }
        other => format!("error: method not found [{other}]"),
    }
}

/// The reply: `responseObject` and code `200`, or code `500` and the message (left out
/// when `null`); `uuid` last if given.
fn reply(outcome: Result<JValue, Option<String>>, uuid: Option<String>) -> String {
    let mut reply = JObject::hash_map();
    match outcome {
        Ok(result) => {
            reply.put("responseObject", result);
            reply.put("code", "200");
        }
        Err(message) => {
            reply.put("code", "500");
            reply.put_opt("message", message);
        }
    }
    reply.put_opt("uuid", uuid);
    reply.to_json()
}

/// `signCMS{args:[<base64>]}`.
fn sign_cms(root: &Map<String, Value>, key: Option<&Key>) -> Result<JValue, Option<String>> {
    let args = orgjson::get_array(root, "args")?;
    let data = orgjson::array_get_string(args, 0)?;
    cades(data, key).map(JValue::Str)
}

/// `batchSignCMS{args:[<base64>…]}`: every element as `signCMS`; one failure fails all.
fn batch_sign_cms(root: &Map<String, Value>, key: Option<&Key>) -> String {
    let args = match orgjson::get_array(root, "args") {
        Ok(args) => args,
        Err(message) => {
            let mut reply = JObject::hash_map();
            reply.put("code", "100");
            reply.put("message", message);
            return reply.to_json();
        }
    };
    let signed: Result<Vec<JValue>, _> = args
        .iter()
        .map(|data| cades(&orgjson::value_to_string(data), key).map(JValue::Str))
        .collect();
    reply(
        signed
            .map(JValue::Arr)
            .map_err(|_| Some("action canceled".to_owned())),
        None,
    )
}

/// The `signCMS` of one element: base64 decoded first, then the key and its EKU, then
/// `createCAdES` (attached) and Kalkan's default time-stamp.
fn cades(data: &str, key: Option<&Key>) -> Result<String, Option<String>> {
    let bytes = javab64::decode_java(data)?;
    // A closed dialog: the original opens a null path.
    let key = key.ok_or(None)?;
    let info = host::cert_info(key.certificate()).map_err(|e| Some(e.message))?;
    // A certificate without the extension: the original dereferences null.
    if info.ext_key_usages.is_empty() {
        return Err(None);
    }
    if info.ext_key_usages.iter().any(|oid| oid == CLIENT_AUTH) {
        return Err(Some(NOT_A_SIGNING_KEY.to_owned()));
    }
    let args = SignCmsExArgs {
        handle: key.handle(),
        content: CmsContent::Data(Bytes::from(bytes)),
        encapsulate: true,
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
        timestamp: Some(TsaChoice::Kalkan),
        output: oncl_pdk::abi::CmsOutput::Der,
    };
    // Unverified against the original: the message of a failed time-stamp (here the
    // core's description of the failure).
    match key.sign_cms_ex(args) {
        Ok(CmsOutcome::Signed(cms)) => Ok(base64(&cms)),
        Ok(CmsOutcome::TspFailed(failure)) => Err(Some(failure.detail)),
        Err(e) => Err(Some(e.message)),
    }
}

/// `signEsedo{uuid, args:[<base64>, <file names>]}`: exceptions answer their `toString()`;
/// any failure of the CMS itself answers the original's misleading key message.
fn sign_esedo(root: &Map<String, Value>, key: Option<&Key>) -> Result<JValue, Option<String>> {
    let json = |message: String| Some(format!("org.json.JSONException: {message}"));
    let args = orgjson::get_array(root, "args").map_err(json)?;
    let arg = |i: usize| {
        args.get(i)
            .map(orgjson::value_to_string)
            .ok_or_else(|| json(format!("JSONArray[{i}] not found.")))
    };
    let (data, names) = (arg(0)?, arg(1)?);
    // A closed dialog: the original swallows the load error and reads an unloaded store.
    let key = key.ok_or_else(|| {
        Some("java.security.KeyStoreException: Uninitialized keystore".to_owned())
    })?;
    let cert = key.certificate();
    let ocsp = esedo::ocsp_args(&OCSP, cert, &[])
        .ok()
        .and_then(|args| pki::ocsp_fetch(&args).ok());
    let answer = match &ocsp {
        Some(
            outcome @ OcspOutcome::Ok {
                http_status: 200, ..
            },
        ) => OcspAnswer::from_outcome(outcome),
        _ => None,
    };
    let bytes = javab64::decode_kalkan(&data).map_err(|e| Some(format!("java.lang.{e}")))?;
    let not_signing = || Some(NOT_A_SIGNING_KEY.to_owned());
    let info = host::cert_info(cert).map_err(|_| not_signing())?;
    // A clientAuth key, or one without the extension (null dereferenced), fails alike.
    if info.ext_key_usages.is_empty() || info.ext_key_usages.iter().any(|oid| oid == CLIENT_AUTH) {
        return Err(not_signing());
    }
    let input = EsedoInput {
        cert,
        file_names: &[&names],
        ocsp: answer,
        data: &bytes,
        ..EsedoInput::default()
    };
    let args = esedo::sign_args(&DOGOVOR24, &input, key.handle()).map_err(|_| not_signing())?;
    match key.sign_cms_ex(args) {
        Ok(CmsOutcome::Signed(cms)) => Ok(JValue::Str(base64(&cms))),
        _ => Err(not_signing()),
    }
}

/// `Base64.getEncoder()`: without line breaks.
fn base64(bytes: &[u8]) -> String {
    javab64::encode_mime(bytes).replace("\r\n", "")
}
