//! The module `kz.doodocs.moduleservice.SampleBundle` of Doodocs.kz: the class
//! `SampleNLClass` in the original's `CommonInvoker` dialect, without dialogs. The page
//! sends a PKCS#12 key store (base64) and its password to `auth`; for five minutes
//! `createCAdESFromBase64` signs with its last key (CAdES with a time-stamp of Kalkan's
//! default TSA profile); `isAuthorized` counts the session down, `logOut` ends it.
//!
//! The session lives in the plugin instance: one connection of the page.

use der::Decode;
use oncl_pdk::abi::{
    CmsCerts, CmsContent, CmsOutcome, CoSign, NetFailure, NetKind, SignCmsExArgs, SignedAttrs,
    SigningTime, TimeForm, TimeSource, TsaChoice,
};
use oncl_pdk::invoker::Failure;
use oncl_pdk::invoker::java::{
    BadRequest, CallResult, InvokeOptions, NlClass, NlMethod, invoke_with,
};
use oncl_pdk::keys::{self, Key, KeySource, OpenArgs, Password};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{AddInfo, Reply, Request, host, javab64};
use std::sync::Mutex;
use x509_cert::Certificate;

/// How long a session lasts after `auth`, in milliseconds.
const SESSION_MS: i64 = 5 * 60 * 1000;

/// The OID of the keyUsage extension.
const KEY_USAGE: &str = "2.5.29.15";

/// The login of this instance.
struct Session {
    /// The key of the last `auth` that succeeded; `None` after `logOut`.
    signer: Option<Key>,
    /// Whether the user is logged in.
    logged_in: bool,
    /// When the last successful `auth` was (kept by `logOut`), Unix milliseconds.
    logged_at: Option<i64>,
}

static SESSION: Mutex<Session> = Mutex::new(Session {
    signer: None,
    logged_in: false,
    logged_at: None,
});

fn handle(request: &Request) -> String {
    let options = InvokeOptions {
        bad_request: BadRequest::Drop,
    };
    match invoke_with(
        &request.text,
        &request.add_info(),
        &[&SampleNlClass],
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

/// The class `SampleNLClass`.
struct SampleNlClass;

const METHODS: &[NlMethod] = &[
    NlMethod {
        name: "auth",
        annotation: None,
        params: 1,
    },
    NlMethod {
        name: "logOut",
        annotation: None,
        params: 0,
    },
    NlMethod {
        name: "isAuthorized",
        annotation: None,
        params: 0,
    },
    NlMethod {
        name: "createCAdESFromBase64",
        annotation: None,
        params: 1,
    },
];

impl NlClass for SampleNlClass {
    fn class_name(&self) -> &'static str {
        "SampleNLClass"
    }

    fn methods(&self) -> &'static [NlMethod] {
        METHODS
    }

    fn call(&self, m: &NlMethod, args: Option<&Map<String, Value>>, _: &AddInfo) -> CallResult {
        let mut session = SESSION.lock().unwrap_or_else(|e| e.into_inner());
        let now = host::now().unwrap_or_default();
        match m.name {
            "auth" => auth(&mut session, args.expect("auth has a parameter"), now),
            "logOut" => {
                log_out(&mut session);
                Ok("success".into())
            }
            "isAuthorized" => Ok(is_authorized(&mut session, now)),
            "createCAdESFromBase64" => sign(&mut session, args.expect("one parameter"), now),
            _ => unreachable!("only METHODS are called"),
        }
    }
}

/// A failure of the plugin's own: `code` with its message, without details.
fn failure(code: &str, message: &str) -> Failure {
    Failure::Custom {
        code: code.to_owned(),
        message: Some(message.to_owned()),
        details: None,
    }
}

/// `auth{storagePath, password}`: the last key of the store, if its certificate is valid
/// now. Any failure is `WRONG_PASSWORD` and keeps the earlier session.
fn auth(session: &mut Session, args: &Map<String, Value>, now: i64) -> CallResult {
    let opt = |key: &str| orgjson::opt_string(args, key).unwrap_or_default();
    let key = javab64::decode_java(&opt("storagePath"))
        .ok()
        .and_then(|store| {
            let request = OpenArgs {
                storage: "PKCS12".to_owned(),
                source: KeySource::Bytes(store.into()),
                password: Password::Text(opt("password")),
            };
            keys::open(&request).ok()?.ok()?.pop()
        })
        .filter(|key| {
            host::cert_info(key.certificate())
                .is_ok_and(|info| info.not_before <= now && now <= info.not_after)
        });
    let Some(key) = key else {
        return Err(failure("WRONG_PASSWORD", "wrong password"));
    };
    session.signer = Some(key);
    session.logged_in = true;
    session.logged_at = Some(now);
    Ok("success".into())
}

fn log_out(session: &mut Session) {
    session.signer = None;
    session.logged_in = false;
}

/// Whether the session is over: never logged in, or five whole minutes since `auth`.
fn expired(session: &Session, now: i64) -> bool {
    session
        .logged_at
        .is_none_or(|at| (now - at) / 60_000 >= SESSION_MS / 60_000)
}

/// `isAuthorized`: `{"logged_in":false}`, or `{"logged_in":true,"expire_after":"MM:SS"}`.
fn is_authorized(session: &mut Session, now: i64) -> JValue {
    if expired(session, now) {
        log_out(session);
    }
    let mut body = JObject::hash_map();
    body.put("logged_in", session.logged_in);
    if session.logged_in {
        let left = (session.logged_at.unwrap_or(now) + SESSION_MS - now).max(0) / 1000;
        body.put("expire_after", format!("{:02}:{:02}", left / 60, left % 60));
    }
    body.into()
}

/// `createCAdESFromBase64{keyType, base64ToSign, attached?}`.
fn sign(session: &mut Session, args: &Map<String, Value>, now: i64) -> CallResult {
    if !session.logged_in {
        return Err(failure("USER_NOT_LOGGED_IN", "user is not logged in"));
    }
    if expired(session, now) {
        log_out(session);
        return Err(failure("SESSION_EXPIRED", "session expired"));
    }
    let Some(key) = &session.signer else {
        return Err(failure("USER_NOT_LOGGED_IN", "user is not logged in"));
    };
    check_key_type(
        key,
        &orgjson::opt_string(args, "keyType").unwrap_or_default(),
    )?;
    let data = javab64::decode_java(&orgjson::opt_string(args, "base64ToSign").unwrap_or_default())
        .ok()
        .filter(|data| !data.is_empty())
        .ok_or_else(|| failure("BAD_PAYLOAD_BASE64", "invalid payload for base64"))?;
    let attached = orgjson::opt_boolean(args, "attached", false);
    cades(key, data, attached)
}

/// `AUTH` needs digitalSignature and keyEncipherment, `SIGN` digitalSignature and
/// nonRepudiation; a certificate without keyUsage fails as the original's
/// `NullPointerException`.
fn check_key_type(key: &Key, key_type: &str) -> Result<(), Failure> {
    let needs_encipherment = match key_type {
        "AUTH" => true,
        "SIGN" => false,
        _ => return Err(failure("UNKNOWN_KEY_TYPE", "unknown key type")),
    };
    let has_key_usage = Certificate::from_der(key.certificate()).is_ok_and(|cert| {
        cert.tbs_certificate()
            .extensions()
            .is_some_and(|exts| exts.iter().any(|e| e.extn_id.to_string() == KEY_USAGE))
    });
    if !has_key_usage {
        return Err(Failure::Invocation(Some(
            "java.lang.NullPointerException".to_owned(),
        )));
    }
    let usage = host::cert_info(key.certificate())
        .map_err(|e| provider_failure(&e.message))?
        .key_usage;
    let second = if needs_encipherment {
        usage.key_encipherment
    } else {
        usage.non_repudiation
    };
    if usage.digital_signature && second {
        Ok(())
    } else {
        Err(failure("ILLEGAL_KEY_TYPE", "illegal key type"))
    }
}

/// An exception of Kalkan's signing utilities, as the dispatcher reports it.
fn provider_failure(message: &str) -> Failure {
    Failure::Invocation(Some(format!(
        "kz.gov.pki.provider.exception.ProviderUtilException: {message}"
    )))
}

/// Kalkan's `createCAdES` of `data` (a CMS with content gets co-signed) with a time-stamp
/// of Kalkan's default TSA profile: base64 of the CMS.
fn cades(key: &Key, data: Vec<u8>, attached: bool) -> CallResult {
    let args = SignCmsExArgs {
        handle: key.handle(),
        content: CmsContent::Data(data.into()),
        encapsulate: attached,
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
    };
    match key.sign_cms_ex(args) {
        Ok(CmsOutcome::Signed(cms)) => Ok(javab64::encode_mime(&cms).replace("\r\n", "").into()),
        Ok(CmsOutcome::TspFailed(failure)) => Err(provider_failure(&tsp_cause(&failure))),
        // Unverified against the original: the provider's message (the core's here).
        Err(e) => Err(provider_failure(&e.message)),
    }
}

/// The `toString()` of the cause of a failed time-stamp.
// Unverified against the original: the exception texts (JDK and Kalkan), built here from
// the core's failure.
fn tsp_cause(failure: &NetFailure) -> String {
    match failure.kind {
        NetKind::Http(status) => {
            format!("kz.gov.pki.kalkan.tsp.TSPException: HTTP error code: {status}")
        }
        NetKind::UnknownHost => format!("java.net.UnknownHostException: {}", failure.address),
        NetKind::Timeout => "java.net.SocketTimeoutException: Read timed out".to_owned(),
        NetKind::Connect => "java.net.ConnectException: Connection refused: connect".to_owned(),
        _ => format!("kz.gov.pki.kalkan.tsp.TSPException: {}", failure.detail),
    }
}
