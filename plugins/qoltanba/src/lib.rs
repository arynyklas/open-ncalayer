//! The OpenNCALayer port of `kz.btsdigital.qoltanba` 1.1, the module
//! `kz.btsdigital.qoltanba.CMSSignUtil` of qoltanba.kz: CAdES-T signatures of files
//! (`signFileBytes`), the check of a CMS's signers (`checkCMSBytes`), a signed PDF with a
//! report of its signers appended (`visualCMS`) and the signed file itself
//! (`extractSignedFileBytes`).
//!
//! - A request org.json reads and that names a `method` must come from an origin matching
//!   `.*qoltanba.kz$` (the dot any character, as the original's pattern), else
//!   `INVALID_ORIGIN`; then the reflective dispatcher of the original's `commonUtils` samples
//!   ([`legacy`]) finds the method.
//! - Replies are the `ResponseForJS` bean (`responseObjects`, `responseObject`, `code`,
//!   `message`) in the texts of the request's `lang` (`kk` Kazakh, anything else Russian);
//!   a method not found speaks the language of the request before (the original sets it
//!   only once the method is found). The language lives in the session (the original's in
//!   the process).
//! - The key: OpenNCALayer's storage and key dialogs, signing keys of the core's CAs only,
//!   none with the electronic government's blocked usages; then its OCSP status (revoked or
//!   unknown refuses it, a responder that cannot be asked does not).

mod pdf;
mod report;
mod texts;
mod ttf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Decode;
use oncl_pdk::abi::{Bytes, HashAlg};
use oncl_pdk::keys::{
    self, Action, CmsCerts, CmsContent, CmsOutcome, CoSign, Filter, FilterMore, KeyOrder,
    SelectArgs, SignCmsExArgs, SignedAttrs, SigningTime, TimeForm, TimeSource,
};
use oncl_pdk::legacy::{
    self, Arg, Args, ErrorBean, LegacyBody, LegacyClass, LegacyMethod, Outcome, Param,
};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::pki::{
    self, CertStatusAbi, Check, IssuerSel, Nonce, OcspArgs, OcspOutcome, PkiMethod, PkiUrl,
    Problem, Revocation, SignerReport, TsaChoice, VerifyArgs, VerifyAt,
};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{AddInfo, Reply, Request, host, javab64};
use oncl_port_kit::date::format_java;
use oncl_port_pki::{cms_read, x509text};
use std::cell::Cell;
use texts::{Lang, text};
use x509_cert::Certificate;

/// The module's state: the language of the replies.
struct Qoltanba {
    lang: Cell<Lang>,
}

thread_local! {
    static STATE: Qoltanba = const { Qoltanba { lang: Cell::new(Lang::Ru) } };
}

/// Extended key usages of the electronic government's certificates the original refuses.
const BLOCKED_EKUS: [&str; 2] = ["1.2.398.5.19.1.2.2.1", "1.2.398.5.19.1.2.2.1.2"];

/// The extended key usage of an individual's certificate.
const EKU_INDIVIDUAL: &str = "1.2.398.3.3.4.1.1";

/// Kalkan's token storages.
const TOKEN_STORAGES: [&str; 6] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKEToken72KStore",
    "AKEToken5110Store",
    "AKJaCartaStore",
    "AKAKEYStore",
];

/// The original's text of a token storage without a token (not in its bundles).
const NO_TOKEN: &str = "Носитель не обнаружен";

/// The original's text of a failed `createCAdES`/`applyCAdEST`: `"Ошибка. Код: "` and the
/// code of Kalkan's `ProviderUtilException`.
// Unverified against the original: the code Kalkan gives a time-stamp that fails.
const TSA_FAILED: &str = "Ошибка. Код: TIMESTAMP_CREATION_FAILURE";

/// `dd/MM/yyyy HH:mm:ss`, the dates of a SignerInfo.
const DATE: &str = "dd/MM/yyyy HH:mm:ss";

/// Why a method fails: a key of the bundles, or a fixed text.
enum Failure {
    Key(&'static str),
    Text(&'static str),
}

/// The dispatcher's view of `CMSSignUtil`: its declared methods.
// Unverified against the original: the order of `getDeclaredMethods()` and the number of
// parameters of the private methods (a request naming one with another count is a method
// not found).
static CLASS: LegacyClass<Qoltanba> = LegacyClass {
    dispatcher: "kz.btsdigital.qoltanba.QoltanbaActivator",
    target: "kz.btsdigital.qoltanba.CMSSignUtil",
    methods: &[
        LegacyMethod {
            name: "signFileBytes",
            arity: 2,
            body: LegacyBody::Public(&[Param::Str, Param::Str], sign_file_bytes),
        },
        LegacyMethod {
            name: "checkCMSBytes",
            arity: 1,
            body: LegacyBody::Public(&[Param::Str], check_cms_bytes),
        },
        LegacyMethod {
            name: "visualCMS",
            arity: 1,
            body: LegacyBody::Public(&[Param::Str], visual_cms),
        },
        LegacyMethod {
            name: "extractSignedFileBytes",
            arity: 1,
            body: LegacyBody::Public(&[Param::Str], extract_signed_file_bytes),
        },
        LegacyMethod {
            name: "changeLang",
            arity: 1,
            body: LegacyBody::Public(&[Param::Str], change_lang),
        },
        LegacyMethod {
            name: "getMessage",
            arity: 1,
            body: LegacyBody::Public(&[Param::Str], get_message),
        },
        LegacyMethod {
            name: "getJson",
            arity: 1,
            body: LegacyBody::Public(&[Param::Object], get_json),
        },
        // Takes a `Collection`, which no JSON value becomes.
        LegacyMethod {
            name: "showKeyChooser",
            arity: 1,
            body: LegacyBody::Unconvertible,
        },
        private("sign", 2),
        private("verifyCMSResult", 1),
        private("verifyCert", 2),
        private("getStorageInfo", 1),
        private("checkCert", 2),
        private("saveFile", 2),
        private("createCAdES", 2),
        private("getOriginalFileName", 1),
        private("fillFromCert", 2),
        private("getCaCertList", 0),
        private("getCaCertsMap", 0),
        private("getMainException", 1),
    ],
    error_bean: ErrorBean::ResponseForJs,
    no_such_method,
    before_invoke: Some(change_lang_before_invoke),
};

const fn private(name: &'static str, arity: usize) -> LegacyMethod<Qoltanba> {
    LegacyMethod {
        name,
        arity,
        body: LegacyBody::Private,
    }
}

fn handle(request: &Request) -> String {
    let reply = STATE.with(|state| {
        if names_method(&request.text) && !origin_matches(request.origin.as_deref().unwrap_or("")) {
            let mut reply = JObject::stringer();
            reply.put("success", false);
            reply.put("errorCode", "INVALID_ORIGIN");
            reply.put("message", "Origin is invalid!");
            return Reply::Text(reply.to_json());
        }
        legacy::dispatch(state, &CLASS, &request.text, &request.add_info())
    });
    match reply {
        Reply::Text(text) => text,
        Reply::Drop => {
            let _ = host::reply_drop();
            String::new()
        }
    }
}

oncl_pdk::plugin!(handle);

/// Whether org.json reads `text` and finds a string `method` in it: the reads before the
/// origin check (their failures are the dispatcher's replies).
fn names_method(text: &str) -> bool {
    matches!(orgjson::parse(text), Ok(JValue::Obj(request))
        if matches!(request.get("method"), Some(JValue::Str(_))))
}

/// `Pattern.matches(".*qoltanba.kz$", origin)`: `.` is any character but a line terminator.
fn origin_matches(origin: &str) -> bool {
    let terminator = |c: char| matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}');
    let Some(rest) = origin.strip_suffix("kz") else {
        return false;
    };
    let mut chars = rest.chars();
    match chars.next_back() {
        Some(dot) if !terminator(dot) => {
            let head = chars.as_str();
            head.ends_with("qoltanba") && !head.chars().any(terminator)
        }
        _ => false,
    }
}

fn no_such_method(state: &Qoltanba, name: &str) -> String {
    format!(
        "{} {name}",
        text(state.lang.get(), "module.NoSuchMethodException")
    )
}

/// `changeLang(lang)` with the request's `lang`, once the method is found.
fn change_lang_before_invoke(state: &Qoltanba, request: &Map<String, Value>) {
    let lang = orgjson::opt_string(request, "lang").unwrap_or_default();
    state.lang.set(Lang::of(&lang));
}

/// The `ResponseForJS` bean.
fn response(
    objects: Option<Vec<JValue>>,
    object: Option<String>,
    code: &str,
    message: Option<&str>,
) -> Outcome {
    let mut bean = JObject::hash_map();
    bean.put_opt("responseObjects", objects);
    bean.put_opt("responseObject", object);
    bean.put("code", code);
    bean.put_opt("message", message);
    Outcome::Json(bean)
}

fn ok(state: &Qoltanba, object: &[u8], message: &str) -> Outcome {
    response(
        None,
        Some(STANDARD.encode(object)),
        "200",
        Some(text(state.lang.get(), message)),
    )
}

fn fail(state: &Qoltanba, failure: Failure) -> Outcome {
    let message = match failure {
        Failure::Key(key) => text(state.lang.get(), key),
        Failure::Text(text) => text,
    };
    response(None, None, "500", Some(message))
}

fn sign_file_bytes(state: &Qoltanba, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let (data, storage) = (args.str(0), args.str(1));
    // Unverified against the original: blank as `trim().isEmpty()`, checked before the
    // data is decoded.
    if storage.trim().is_empty() {
        return fail(state, Failure::Key("404"));
    }
    match sign(data, storage) {
        Ok(cms) => ok(state, &cms, "cms.signed"),
        Err(failure) => fail(state, failure),
    }
}

/// The CAdES-T of the base64 `data` with a key of `storage`.
fn sign(data: &str, storage: &str) -> Result<Vec<u8>, Failure> {
    fn internal<E>(_: E) -> Failure {
        Failure::Key("internalError")
    }
    let token = TOKEN_STORAGES.contains(&storage);
    if !token && storage != "PKCS12" && storage != "JKS" {
        // Kalkan's `Storage.get` knows no such storage: a NullPointerException.
        return Err(Failure::Key("internalError"));
    }
    let data = javab64::decode_java(data).map_err(internal)?;
    if token && keys::terminals(storage).unwrap_or_default().is_empty() {
        return Err(Failure::Text(NO_TOKEN));
    }
    // The core's CAs: the NCA's (the original's embedded list).
    let chain = host::ca_list()
        .ok()
        .filter(|cas| !cas.is_empty())
        .map(|cas| cas.into_iter().map(Bytes::from).collect());
    // Unverified against the original: closing its storage dialog («Не удалось открыть
    // хранилище») and its key list (`action.canceled`) are one cancel here.
    let key = keys::select(&SelectArgs {
        action: Action::Sign,
        storages: vec![storage.to_owned()],
        filter: Filter {
            chain,
            // The status is asked below, where a responder that cannot be asked passes.
            allow_revoked: true,
            ..Filter::default()
        },
        more: FilterMore {
            knca_types: vec!["SIGNATURE".to_owned()],
            exclude_ext_key_usages: BLOCKED_EKUS.map(str::to_owned).to_vec(),
            ..FilterMore::default()
        },
        detail: None,
        initial_path: None,
        order: KeyOrder::default(),
    })
    .map_err(internal)?
    .ok_or(Failure::Key("action.canceled"))?;
    ocsp_check(key.certificate()).map_err(Failure::Key)?;
    let outcome = key
        .sign_cms_ex(SignCmsExArgs {
            handle: key.handle(),
            content: CmsContent::Data(data.into()),
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
        })
        .map_err(internal)?;
    match outcome {
        CmsOutcome::Signed(cms) => Ok(cms.into_vec()),
        CmsOutcome::TspFailed(_) => Err(Failure::Text(TSA_FAILED)),
    }
}

/// The OCSP status of `cert` as the original's checker asks it (SHA-1 CertID, GET, no
/// nonce, 5 s): revoked, unknown, a response that does not verify or is not current
/// refuse the key; a responder that cannot be asked does not.
fn ocsp_check(cert: &[u8]) -> Result<(), &'static str> {
    let args = OcspArgs {
        cert: cert.to_vec().into(),
        issuer: IssuerSel::HostCas,
        cert_id_hash: HashAlg::Sha1,
        nonce: Nonce::None,
        url: PkiUrl::FromCert(cert.to_vec().into()),
        method: PkiMethod::GetUrlEncoded,
        timeout_ms: 5000,
        check: true,
    };
    let Ok(OcspOutcome::Ok {
        response_status: 0,
        cert_status,
        problem,
        ..
    }) = pki::ocsp_fetch(&args)
    else {
        return Ok(());
    };
    if let Some(problem) = problem {
        return match problem {
            Problem::ResponderUnverified => Err("error.certificate.ocsp.not_verified"),
            Problem::OcspStale => Err("ocsp.exception"),
            Problem::NonceMismatch => Err("error.certificate.ocsp.nonces"),
            _ => Ok(()),
        };
    }
    match cert_status {
        Some(CertStatusAbi::Revoked { .. }) => Err("ocsp.revoked"),
        Some(CertStatusAbi::Unknown) => Err("error.certificate.ocsp.unknown"),
        _ => Ok(()),
    }
}

/// The outcome of one of a signer's checks, a `VerificationResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Judged {
    Valid,
    /// Not valid, without a message.
    Invalid,
    /// Not valid, this message key.
    Failed(&'static str),
}

impl Judged {
    /// `{"valid":…,"message"?:…}` in `lang`.
    fn bean(self, lang: Lang) -> JObject {
        let mut bean = JObject::hash_map();
        bean.put("valid", self == Judged::Valid);
        if let Judged::Failed(key) = self {
            bean.put("message", text(lang, key));
        }
        bean
    }
}

/// A verified signer: the properties of its SignerInfo.
struct Verified {
    person: bool,
    serial: String,
    organization: Option<String>,
    period: String,
    tsp_date: Option<String>,
    bin: Option<String>,
    iin: Option<String>,
    name: String,
    tsp: Judged,
    certificate: Judged,
    signature: Judged,
}

impl Verified {
    /// The `SignerInfo` bean, its texts in `lang`; `sigantureAlgorithm` (sic) is never set.
    fn bean(&self, lang: Lang) -> JValue {
        let valid = [self.tsp, self.certificate, self.signature]
            .iter()
            .all(|judged| *judged == Judged::Valid);
        let mut bean = JObject::hash_map();
        bean.put("personCertificate", self.person);
        bean.put("serialNumber", self.serial.as_str());
        bean.put("validSignature", valid);
        bean.put_opt("organizationName", self.organization.as_deref());
        bean.put("certificateValidityPeriod", self.period.as_str());
        bean.put_opt("tspDate", self.tsp_date.as_deref());
        bean.put_opt("bin", self.bin.as_deref());
        bean.put_opt("iin", self.iin.as_deref());
        bean.put("tspVerificationResult", self.tsp.bean(lang));
        bean.put("number", 0);
        bean.put("certificateVerificationResult", self.certificate.bean(lang));
        bean.put("name", self.name.as_str());
        bean.put("signatureVerificationResult", self.signature.bean(lang));
        JValue::Obj(bean)
    }

    /// The signer's rows of the report.
    fn report(self) -> report::Signer {
        report::Signer {
            name: self.name,
            // Unverified against the original: a missing value in the report.
            iin: self.iin.unwrap_or_default(),
            serial: self.serial,
            period: self.period,
            signed_at: self.tsp_date.unwrap_or_default(),
        }
    }
}

/// The signers of the base64 CMS `b64`, judged at their time-stamps with the OCSP status
/// at that time, and its content; else the message key of the failure.
fn verify(b64: &str) -> Result<(Vec<Verified>, Option<Vec<u8>>), &'static str> {
    let cms = javab64::decode_java(b64).map_err(|_| "internalError")?;
    let report = pki::cms_verify(&VerifyArgs {
        cms: cms.into(),
        data: None,
        at: VerifyAt::TspTime,
        chain: None,
        revocation: Revocation::LiveOcsp,
        first_signer_only: false,
        require_key_usage: Vec::new(),
    })
    .map_err(|_| "cms.exception")?;
    let signers = report
        .signers
        .iter()
        .map(signer_info)
        .collect::<Result<_, _>>()?;
    Ok((signers, report.content.map(Bytes::into_vec)))
}

/// `dd/MM/yyyy HH:mm:ss` of `unix_ms` in the system's zone.
fn date(unix_ms: i64) -> String {
    format_java(DATE, unix_ms, host::local_offset(unix_ms).unwrap_or(0))
}

/// BigInteger's `toString(16)` of a serial number's bytes.
fn serial_hex(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    match hex.trim_start_matches('0') {
        "" => "0".to_owned(),
        trimmed => trimmed.to_owned(),
    }
}

/// What the original reads of a signer and its certificate.
fn signer_info(signer: &SignerReport) -> Result<Verified, &'static str> {
    // A signer without its certificate: the original's NullPointerException.
    let der = signer.certificate.as_ref().ok_or("internalError")?;
    let cert = Certificate::from_der(der).map_err(|_| "cert.process.exception")?;
    let tbs = cert.tbs_certificate();
    let subject = der::Encode::to_der(tbs.subject()).map_err(|_| "cert.process.exception")?;
    let values = |oid: &str| x509text::attribute_values(&subject, oid).unwrap_or_default();
    let ekus: Vec<String> = tbs
        .get_extension::<x509_cert::ext::pkix::ExtendedKeyUsage>()
        .ok()
        .flatten()
        .map(|(_, usages)| usages.0.iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    let details = host::cert_details(der).map_err(|_| "cert.process.exception")?;
    let ms = |t: &x509_cert::time::Time| t.to_unix_duration().as_millis() as i64;
    let not_before = ms(&tbs.validity().not_before);
    let not_after = ms(&tbs.validity().not_after);

    let person = ekus.iter().any(|eku| eku == EKU_INDIVIDUAL);
    // Unverified against the original: a subject without CN (here its NullPointerException).
    let cn = values("2.5.4.3")
        .into_iter()
        .next()
        .ok_or("internalError")?;
    let name = match values("2.5.4.42").into_iter().next() {
        Some(given) => format!("{} {given}", cn.trim()),
        None => cn.trim().to_owned(),
    };
    let iin = values("2.5.4.5")
        .into_iter()
        .next()
        .map(|serial_number| serial_number.chars().skip(3).collect());
    let (bin, organization) = if person {
        (None, None)
    } else {
        let bin = values("2.5.4.11")
            .into_iter()
            .find(|ou| (ou.contains("BIN") || ou.contains("bin")) && ou.chars().count() == 15)
            .map(|ou| ou.chars().skip(3).collect());
        (bin, values("2.5.4.10").into_iter().next())
    };

    let tsp = match &signer.tsp {
        None => Judged::Failed("tsp.notFound"),
        Some(tsp) if tsp.check == Check::Ok => Judged::Valid,
        Some(_) => Judged::Failed("tsp.verification.error"),
    };
    // `SignerInformation.verify(cert)` checks the certificate at the signingTime too.
    let signature = match signer.signing_time_ms {
        Some(at) if at < not_before || at > not_after => {
            Judged::Failed("sign.validity.cert.invalid")
        }
        _ if signer.signature != Check::Ok => Judged::Invalid,
        _ => Judged::Valid,
    };
    Ok(Verified {
        person,
        serial: serial_hex(tbs.serial_number().as_bytes()),
        organization,
        period: format!("{} - {}", date(not_before), date(not_after)),
        tsp_date: signer
            .tsp
            .as_ref()
            .and_then(|tsp| tsp.gen_time_ms)
            .map(date),
        bin,
        iin,
        name,
        tsp,
        certificate: certificate_check(signer, &details.knca_types, &ekus),
        signature,
    })
}

/// The original's certificate check at the signer's time: the key type, the validity, the
/// path to the CAs, the blocked usages, the OCSP status (a revocation after that time, or a
/// responder that cannot be asked, passes).
fn certificate_check(signer: &SignerReport, knca_types: &[String], ekus: &[String]) -> Judged {
    if !knca_types.iter().any(|t| t == "SIGNATURE") {
        return Judged::Failed("error.certificate.type");
    }
    match signer.validity {
        Check::Fail(Problem::Expired) => return Judged::Failed("cert.expired"),
        Check::Fail(Problem::NotYetValid) => return Judged::Failed("cert.not_yet_valid"),
        _ => {}
    }
    if let Check::Fail(_) = signer.path {
        return Judged::Failed("error.certificate.ca");
    }
    if ekus.iter().any(|eku| BLOCKED_EKUS.contains(&eku.as_str())) {
        return Judged::Failed("cert.verification.error");
    }
    match signer.revocation {
        Check::Fail(Problem::Revoked { .. }) => Judged::Failed("ocsp.revoked"),
        Check::Fail(Problem::StatusUnknown) => Judged::Failed("error.certificate.ocsp.unknown"),
        Check::Fail(Problem::ResponderUnverified) => {
            Judged::Failed("error.certificate.ocsp.not_verified")
        }
        Check::Fail(Problem::OcspStale) => Judged::Failed("ocsp.exception"),
        Check::Fail(Problem::NonceMismatch) => Judged::Failed("error.certificate.ocsp.nonces"),
        _ => Judged::Valid,
    }
}

fn check_cms_bytes(state: &Qoltanba, args: &Args<'_>, _: &AddInfo) -> Outcome {
    match verify(args.str(0)) {
        Ok((signers, _)) => {
            let lang = state.lang.get();
            let beans = signers.iter().map(|s| s.bean(lang)).collect();
            response(Some(beans), None, "200", None)
        }
        Err(key) => fail(state, Failure::Key(key)),
    }
}

fn visual_cms(state: &Qoltanba, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let pdf = verify(args.str(0)).ok().and_then(|(signers, content)| {
        let signers: Vec<report::Signer> = signers.into_iter().map(Verified::report).collect();
        report::append(&content?, &signers).ok()
    });
    match pdf {
        Some(pdf) => ok(state, &pdf, "file.saved"),
        None => fail(state, Failure::Key("internalError")),
    }
}

fn extract_signed_file_bytes(state: &Qoltanba, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let content = javab64::decode_java(args.str(0))
        .ok()
        .and_then(|cms| cms_read::content(&cms));
    match content {
        Some(content) => ok(state, &content, "file.saved"),
        None => fail(state, Failure::Key("internalError")),
    }
}

fn change_lang(state: &Qoltanba, args: &Args<'_>, _: &AddInfo) -> Outcome {
    state.lang.set(Lang::of(args.str(0)));
    Outcome::Null
}

fn get_message(state: &Qoltanba, args: &Args<'_>, _: &AddInfo) -> Outcome {
    match texts::get(state.lang.get(), args.str(0)) {
        Some(message) => Outcome::Text(message.to_owned()),
        // `MissingResourceException`.
        None => Outcome::Thrown,
    }
}

/// `JSONObject.wrap(x).toString()`.
fn get_json(_: &Qoltanba, args: &Args<'_>, _: &AddInfo) -> Outcome {
    Outcome::Text(match args.get(0) {
        Arg::Value(value) => orgjson::value_to_string(value),
        Arg::Ints(ints) => JValue::Arr(ints.iter().map(|i| JValue::from(*i)).collect()).to_json(),
        other => unreachable!("an Object parameter gets {other:?}"),
    })
}
