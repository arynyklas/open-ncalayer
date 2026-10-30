//! The Workspace signer (`kz.workspace.Signer`): `sign` makes a detached ESEDO CMS of the
//! document card (`files[0]`, the SLED file) with the signer's OCSP answer inside, then an
//! attached, time-stamped CMS for each further file; `getKaztokenKeys` lists the keys of a
//! Kaztoken.
//!
//! Replies are written as `JSONStringer` writes them, `code` a number. As in the original,
//! every attachment entry signs `files[1]`, and the job stops 10 seconds after it started.
#![cfg(target_arch = "wasm32")]

use oncl_pdk::abi::{
    Action, CmsCerts, CmsOutcome, CoSign, Filter, HashAlg, KeyOrder, MAX_PKI_TIMEOUT_MS, Nonce,
    PkiMethod, PkiUrl, SignerSel, StampArgs, StampMode, StampOutcome, TimeForm, TokenForm,
    TsaChoice, TsaSpec,
};
use oncl_pdk::keys::{self, Key, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::pki::{CertStatusAbi, OcspOutcome};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{Request, host, javab64, pki};
use oncl_port_pki::esedo::{
    self, CertIdHash, ContentMode, Description, Encapsulate, EsedoInput, FileNames, IssuerRule,
    OcspAnswer, OcspForm, OcspRequest, OcspUrl, Profile, SignerDn, SigningTimeRule, StringKind,
    TimeFrom,
};
use std::sync::atomic::{AtomicBool, Ordering};

oncl_pdk::plugin!(handle);

/// The Kalkan storage of a Kaztoken.
const KAZTOKEN: &str = "AKKaztokenStore";

/// How long a job may run, milliseconds.
const WATCHDOG_MS: i64 = 10_000;

const CANCELLED: &str = "отмена ввода пароля";
const BUSY: &str = "процесс уже запущен (имеется незавершенный процесс)";
const TIMED_OUT: &str = "процесс остановлен по таймауту";

/// The SLED card's OCSP request: the page's issuer, a GOST 34.311 `CertID`, no nonce, GET
/// with the URL-encoded request to the certificate's responder, checked.
pub const SLED_OCSP: OcspRequest = OcspRequest {
    issuer: IssuerRule::Given,
    cert_id_hash: CertIdHash::Fixed(HashAlg::Gost34311),
    nonce: Nonce::None,
    method: PkiMethod::GetUrlEncoded,
    url: OcspUrl::FromCert,
    // The original waited without a limit (but within its 10-second job).
    timeout_ms: MAX_PKI_TIMEOUT_MS,
    check: true,
};

/// The SLED card's CMS: detached id-data, the ESEDO attributes (the names only when the
/// page gives them, signingTime as GeneralizedTime, `ESEDO\0`, the `BasicOCSPResponse` in
/// an OCTET STRING).
pub const WORKSPACE_SLED: Profile = Profile {
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
        omit_blank: true,
    }),
    signer_dn: Some(SignerDn::Kalkan),
    description: Some(Description {
        text: "ESEDO\0",
        kind: StringKind::Printable,
    }),
    ocsp: Some(OcspForm::OctetBasic),
    ocsp_request: Some(SLED_OCSP),
};

/// An attachment's CMS: attached, the ESEDO attributes without names and OCSP answer.
pub const WORKSPACE_ATTACHMENT: Profile = Profile {
    encapsulate: Encapsulate::Always,
    file_names: None,
    ocsp: None,
    ocsp_request: None,
    ..WORKSPACE_SLED
};

/// Whether a `sign` job runs in this instance.
static RUNNING: AtomicBool = AtomicBool::new(false);

fn handle(request: &Request) -> String {
    let Ok(JValue::Obj(root)) = orgjson::parse(&request.text) else {
        let _ = host::reply_drop();
        return String::new();
    };
    let root = root.to_map();
    let method = orgjson::opt_string(&root, "method").unwrap_or_default();
    let outcome = match method.as_str() {
        "sign" => sign(&root),
        // The Kaztoken's keys, once the core opens tokens; until then it has none.
        "getKaztokenKeys" => Ok(Vec::new()),
        _ => Err(Some("Wrong method. Try 'createCMSSignature'".to_owned())),
    };
    let mut reply = JObject::stringer();
    match outcome {
        Ok(body) => {
            reply.put("code", 200);
            reply.put("body", JValue::Arr(body));
        }
        Err(message) => {
            reply.put("code", 500);
            // A `SignException` without a message writes `null`.
            reply.put("message", message.map_or(JValue::Null, JValue::Str));
        }
    }
    reply.to_json()
}

/// `sign{files, fileNames, isKaztoken, storagePath, alias, issuerCert}`.
fn sign(root: &Map<String, Value>) -> Result<Vec<JValue>, Option<String>> {
    let args = orgjson::get_object(root, "args")?;
    let kaztoken = orgjson::opt_boolean(args, "isKaztoken", false);
    // The core's dialogs replace the original's password dialog and the key file the page
    // names (`storagePath`, a token's `alias`): those are not read.
    let key = keys::select(&SelectArgs {
        action: Action::Sign,
        storages: vec![if kaztoken { KAZTOKEN } else { "PKCS12" }.to_owned()],
        filter: Filter {
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
    .map_err(|e| Some(e.message))?
    .ok_or_else(|| Some(CANCELLED.to_owned()))?;
    let issuer = orgjson::opt_string(args, "issuerCert");
    let names = orgjson::opt_string(args, "fileNames");
    let files = match orgjson::opt_array(args, "files") {
        Some(items) => (0..items.len())
            .map(|i| orgjson::array_get_string(items, i).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err(Some(BUSY.to_owned()));
    }
    let outcome = job(&key, &files, names.as_deref(), issuer.as_deref());
    RUNNING.store(false, Ordering::SeqCst);
    outcome
}

/// The job's watchdog: the time it started.
struct Watchdog(i64);

impl Watchdog {
    fn check(&self) -> Result<(), Option<String>> {
        let now = host::now().map_err(|e| Some(e.message))?;
        if now - self.0 > WATCHDOG_MS {
            Err(Some(TIMED_OUT.to_owned()))
        } else {
            Ok(())
        }
    }
}

/// `getMessage()` of a failed Kalkan base64 decoding (`<Class>: <message>`).
fn decode(text: &str) -> Result<Vec<u8>, Option<String>> {
    javab64::decode_kalkan(text)
        .map_err(|e| Some(e.split_once(": ").map_or(e.as_str(), |(_, m)| m).to_owned()))
}

/// The signing job: the SLED card, then each attachment.
fn job(
    key: &Key,
    files: &[String],
    names: Option<&str>,
    issuer: Option<&str>,
) -> Result<Vec<JValue>, Option<String>> {
    let watchdog = Watchdog(host::now().map_err(|e| Some(e.message))?);
    let cert = key.certificate();
    let details = host::cert_details(cert).map_err(|e| Some(e.message))?;
    watchdog.check()?;
    let sled = files
        .first()
        .ok_or_else(|| Some(format!("Index: 0, Size: {}", files.len())))?;
    let sled = decode(sled)?;
    let ocsp = sled_ocsp(cert, issuer)?;
    watchdog.check()?;
    let names: Vec<&str> = names.into_iter().collect();
    let input = EsedoInput {
        cert,
        kalkan_dn: Some(&details.subject_dn),
        file_names: &names,
        ocsp: OcspAnswer::from_outcome(&ocsp),
        data: &sled,
        ..EsedoInput::default()
    };
    let mut body = vec![JValue::Str(base64(&cms(key, &WORKSPACE_SLED, &input)?))];
    watchdog.check()?;
    for _ in 1..files.len() {
        // As the original: every attachment entry is `files[1]`.
        // Unverified against the original: whether pages send more than one attachment.
        let attachment = decode(&files[1])?;
        let input = EsedoInput {
            cert,
            kalkan_dn: Some(&details.subject_dn),
            data: &attachment,
            ..EsedoInput::default()
        };
        let signed = cms(key, &WORKSPACE_ATTACHMENT, &input)?;
        body.push(JValue::Str(stamp(signed)?));
        watchdog.check()?;
    }
    Ok(body)
}

/// The OCSP answer about `cert` from its responder, issued by the page's `issuer` and
/// checked: good, or the job fails.
fn sled_ocsp(cert: &[u8], issuer: Option<&str>) -> Result<OcspOutcome, Option<String>> {
    // Unverified against the original: the texts of Kalkan's OCSP checker.
    let issuer = issuer.ok_or_else(|| Some("TARGET_CERT_ISSUER_NOT_FOUND".to_owned()))?;
    let issuer = decode(issuer)?;
    let args = esedo::ocsp_args(&SLED_OCSP, cert, &[&issuer]).map_err(Some)?;
    let outcome = pki::ocsp_fetch(&args).map_err(|e| Some(e.message))?;
    match &outcome {
        OcspOutcome::Ok {
            cert_status: Some(CertStatusAbi::Good),
            problem: None,
            basic: Some(_),
            ..
        } => Ok(outcome),
        OcspOutcome::Ok {
            problem: Some(problem),
            ..
        } => Err(Some(format!("OCSP response is not valid: {problem:?}"))),
        OcspOutcome::Ok { cert_status, .. } => {
            Err(Some(format!("Certificate status: {cert_status:?}")))
        }
        OcspOutcome::Failed(failure) => Err(Some(failure.detail.clone())),
    }
}

/// The CMS of `profile` for `input`, DER.
fn cms(key: &Key, profile: &Profile, input: &EsedoInput) -> Result<Vec<u8>, Option<String>> {
    let args = esedo::sign_args(profile, input, key.handle()).map_err(Some)?;
    match key.sign_cms_ex(args).map_err(|e| Some(e.message))? {
        CmsOutcome::Signed(cms) => Ok(cms.into_vec()),
        CmsOutcome::TspFailed(failure) => Err(Some(failure.detail)),
    }
}

/// An attachment's time-stamp: SHA-1 imprint, policy 1.2.398.3.3.2.6.1, GET
/// `http://tsp.pki.gov.kz/<base64>`, the time in milliseconds as nonce, replacing.
fn stamp(cms: Vec<u8>) -> Result<String, Option<String>> {
    let now = host::now().map_err(|e| Some(e.message))?;
    let args = StampArgs {
        cms: cms.into(),
        signers: SignerSel::Last,
        tsa: TsaChoice::Custom(TsaSpec {
            url: PkiUrl::Default,
            method: PkiMethod::Get,
            hash: HashAlg::Sha1,
            policy: Some("1.2.398.3.3.2.6.1".to_owned()),
            nonce: Nonce::Value(big_integer(now).into()),
            cert_req: true,
            retries: 0,
            // The original waited without a limit.
            timeout_ms: MAX_PKI_TIMEOUT_MS,
            check_skew_ms: None,
            require_tsa_eku: false,
        }),
        mode: StampMode::Replace,
        token: TokenForm::Token,
    };
    // Unverified against the original: the message of a failed time-stamp.
    match pki::stamp(&args).map_err(|e| Some(e.message))? {
        StampOutcome::Stamped(cms) => Ok(base64(&cms)),
        StampOutcome::Failed(failure) => Err(Some(failure.detail)),
    }
}

/// `BigInteger.valueOf(value).toByteArray()`: two's complement, big-endian, minimal.
fn big_integer(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < bytes.len() - 1 {
        let (first, next) = (bytes[start], bytes[start + 1]);
        if (first == 0 && next & 0x80 == 0) || (first == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    bytes[start..].to_vec()
}

/// `Base64.getEncoder()`: without line breaks.
fn base64(bytes: &[u8]) -> String {
    javab64::encode_mime(bytes).replace("\r\n", "")
}
