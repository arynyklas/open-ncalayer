//! The module `asia.dbt.thundercrypt.osgi.ThunderCryptModule` (ThunderCrypt 1.16.5,
//! "Everflow"): one operation, a detached ESEDO CAdES-T of `dataForSign` with the key file
//! the page names (`keyType: file`) or a KazToken (`keyType: token`), checked after signing.
//!
//! A request with a `method` goes to the original's `CommonInvoker` (class `SignNLClass`,
//! method `sign`, everything in `args`); one without is the legacy request, its fields at
//! the top level, answered by the `Response` bean `{"result":…,"errorCode":…,"params":…}`.
//!
//! The steps keep the original's order: the password window before the data is checked,
//! the OCSP answer before signing (embedded), the time-stamp on the signature, then the
//! check (embedded OCSP, else the responder, else the CRL; the certificate at the
//! time-stamp's time; the policy or the legacy permission rule; the path), and for V2 the
//! B-LTA upgrade.

mod lta;
mod policy;

use der::{Decode, Encode};
use oncl_pdk::abi::{
    CmsCerts, CmsOutcome, CoSign, HashAlg, KeyUsage, NetFailure, NetKind, NetStage, Nonce,
    PkiMethod, PkiUrl, Problem, TimeForm,
};
use oncl_pdk::dialogs::{self, PasswordArgs};
use oncl_pdk::invoker::Failure;
use oncl_pdk::invoker::java::{
    BadRequest, CallResult, InvokeOptions, NlClass, NlMethod, invoke_with,
};
use oncl_pdk::keys::{self, Key, KeySource, OpenArgs, OpenOutcome, Password};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::pki::{
    self, Check, CrlArgs, CrlOutcome, IssuerSel, OcspOutcome, Revocation, SignerSel, StampArgs,
    StampMode, StampOutcome, TokenForm, TsaChoice, TsaSpec, TspOutcome,
};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{AddInfo, Reply, Request, host, javab64};
use oncl_port_pki::esedo::{
    self, CertIdHash, ContentMode, Description, Encapsulate, EsedoInput, FileNames, IssuerRule,
    OcspAnswer, OcspForm, OcspRequest, OcspUrl, Profile, SignerDn, SigningTimeRule, StringKind,
    TimeFrom,
};
use oncl_port_pki::x509text;
use policy::{CertFacts, Cond};
use x509_cert::Certificate;
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
use x509_cert::ext::pkix::name::GeneralName;

/// ThunderCrypt's ESEDO CMS: detached, the certificate's digest, the OCSP answer, the
/// signer's subject as encoded, signingTime, contentType, signingCertificateV2, the file
/// names and the description `ESEDO`.
pub const THUNDERCRYPT: Profile = Profile {
    econtent_type: None,
    content: ContentMode::Data,
    digest: None,
    encapsulate: Encapsulate::Never,
    cosign: CoSign::Never,
    certificates: CmsCerts::Signer,
    content_type: true,
    signing_certificate_v2: true,
    signing_time: Some(SigningTimeRule {
        from: TimeFrom::Now,
        form: TimeForm::Auto,
    }),
    file_names: Some(FileNames {
        separator: "<>",
        omit_blank: true,
    }),
    signer_dn: Some(SignerDn::Encoded),
    description: Some(Description {
        text: "ESEDO",
        kind: StringKind::Utf8,
    }),
    ocsp: Some(OcspForm::OctetResponse),
    ocsp_request: Some(THUNDERCRYPT_OCSP),
};

/// The OCSP request before signing: the responder of the certificate, the `CertID` hash
/// by the issuer's issuer, a 16-byte nonce, GET when short, the answer checked.
pub const THUNDERCRYPT_OCSP: OcspRequest = OcspRequest {
    issuer: IssuerRule::HostCas,
    cert_id_hash: CertIdHash::ByIssuerIssuerDn,
    nonce: Nonce::Random(16),
    method: PkiMethod::GetUnder(256),
    url: OcspUrl::FromCert,
    timeout_ms: 10_000,
    check: true,
};

/// The TSA when the certificate names none.
const DEFAULT_TSA: &str = "http://tsp.pki.gov.kz/";

/// id-ad-timeStamping.
const AD_TIME_STAMPING: &str = "1.3.6.1.5.5.7.48.3";
/// authorityInfoAccess, subjectInfoAccess.
const AIA: &str = "1.3.6.1.5.5.7.1.1";
const SIA: &str = "1.3.6.1.5.5.7.1.11";
/// keyUsage.
const KEY_USAGE: &str = "2.5.29.15";

fn handle(request: &Request) -> String {
    let has_method = matches!(
        orgjson::parse(&request.text),
        Ok(JValue::Obj(object)) if object.get("method").is_some()
    );
    if !has_method {
        return legacy(&request.text);
    }
    let options = InvokeOptions {
        bad_request: BadRequest::Drop,
    };
    match invoke_with(
        &request.text,
        &request.add_info(),
        &[&SignNlClass],
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

/// The class `SignNLClass`.
struct SignNlClass;

const METHODS: &[NlMethod] = &[NlMethod {
    name: "sign",
    annotation: None,
    params: 1,
}];

impl NlClass for SignNlClass {
    fn class_name(&self) -> &'static str {
        "SignNLClass"
    }

    fn methods(&self) -> &'static [NlMethod] {
        METHODS
    }

    fn call(&self, _: &NlMethod, args: Option<&Map<String, Value>>, _: &AddInfo) -> CallResult {
        match sign(args.expect("sign has a parameter"), Mode::V2) {
            Ok(result) => {
                let mut bean = JObject::hash_map();
                bean.put("result", result);
                bean.put("errorCode", "NONE");
                Ok(bean.into())
            }
            Err(e) => {
                let code = e.code.filter(|c| !c.trim().is_empty());
                let code = code.unwrap_or_else(|| "SIGNING_FAILED".to_owned());
                let address = e.params.iter().find(|(k, _)| *k == "address");
                let message = match address {
                    Some((_, address)) => format!("Signing failed: {code} at {address}"),
                    None => format!("Signing failed: {code}"),
                };
                Err(Failure::Custom {
                    code,
                    message: Some(message),
                    details: (!e.params.is_empty()).then(|| params(&e.params).to_json()),
                })
            }
        }
    }
}

/// The legacy request: the `Response` bean.
fn legacy(text: &str) -> String {
    let args: Map<String, Value> = oncl_pdk::serde_json::from_str(text).unwrap_or_default();
    let mut bean = JObject::hash_map();
    match sign(&args, Mode::Legacy) {
        Ok(result) => {
            bean.put("result", result);
            bean.put("errorCode", "NONE");
        }
        Err(e) => {
            if let Some(code) = e.code {
                bean.put("errorCode", code);
                if !e.params.is_empty() {
                    bean.put("params", params(&e.params));
                }
            }
        }
    }
    bean.to_json()
}

/// `params` as org.json wraps the original's `HashMap`: a map of its size filled in the
/// order of the first one.
// Unverified against the original: the order of three params (`failure` before `address`
// by this rule), and the order the original put the keys into its map.
fn params(entries: &[(&'static str, String)]) -> JObject {
    let mut source = JObject::hash_map();
    for (key, value) in entries {
        source.put(*key, value.clone());
    }
    let mut out = JObject::from_map(source.len());
    for (key, value) in source.iter() {
        out.put(key, value.clone());
    }
    out
}

/// The request's shape.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    V2,
    Legacy,
}

/// A failed `sign`: the error code (`None`: the original's `null`) and its params.
#[derive(Debug)]
struct Error {
    code: Option<String>,
    params: Vec<(&'static str, String)>,
}

impl Error {
    fn code(code: impl Into<String>) -> Error {
        Error {
            code: Some(code.into()),
            params: Vec::new(),
        }
    }

    fn with(code: impl Into<String>, params: Vec<(&'static str, String)>) -> Error {
        Error {
            code: Some(code.into()),
            params,
        }
    }
}

/// A network failure as the original classifies it: `<SERVICE>_…` with `address`,
/// `failure`, `status` and `detail`.
fn remote(failure: &NetFailure, address: &str, attempted: Option<String>) -> Error {
    let service = match failure.stage {
        NetStage::Tsp => "TSP",
        NetStage::Ocsp => "OCSP",
        NetStage::Crl => "CRL",
    };
    let mut status = None;
    let (code, kind) = match failure.kind {
        NetKind::ClockSkew => ("LOCAL_CLOCK_SKEW".to_owned(), "CLOCK_SKEW"),
        NetKind::UnknownHost => (format!("UNKNOWN_{service}_ADDRESS"), "DNS"),
        NetKind::Timeout => (format!("{service}_TIMEOUT"), "TIMEOUT"),
        NetKind::Tls => (format!("{service}_TLS_ERROR"), "TLS"),
        NetKind::Http(code) => {
            status = Some(code.to_string());
            (format!("{service}_HTTP_ERROR"), "HTTP_STATUS")
        }
        NetKind::Connect => (format!("{service}_CONNECTION_FAILED"), "CONNECTION"),
        NetKind::InvalidResponse => (format!("{service}_INVALID_RESPONSE"), "INVALID_RESPONSE"),
        NetKind::Rejected(code) if failure.stage != NetStage::Crl => {
            status = Some(code.to_string());
            (format!("{service}_REQUEST_REJECTED"), "REQUEST_REJECTED")
        }
        NetKind::Rejected(_) => ("CRL_DOWNLOAD_FAILED".to_owned(), "DOWNLOAD"),
        NetKind::Other => (format!("{service}_NETWORK_ERROR"), "NETWORK"),
    };
    let mut params = Vec::new();
    if let Some(attempted) = attempted.filter(|a| !a.is_empty()) {
        params.push(("attemptedAddresses", attempted));
    }
    if !address.is_empty() {
        params.push(("address", address.to_owned()));
    }
    params.push(("failure", kind.to_owned()));
    if let Some(status) = status {
        params.push(("status", status));
    }
    let detail = detail(failure, service, address);
    if !detail.is_empty() {
        params.push(("detail", detail));
    }
    Error::with(code, params)
}

/// `<SimpleName>: <message>` of the deepest cause, white space collapsed, at most 512
/// characters.
// Unverified against the original: the JDK's exception texts, built here from the core's
// failure.
fn detail(failure: &NetFailure, service: &str, address: &str) -> String {
    let text = match failure.kind {
        NetKind::UnknownHost => format!("UnknownHostException: {}", failure.address),
        NetKind::Timeout => "SocketTimeoutException: Read timed out".to_owned(),
        NetKind::Connect => "ConnectException: Connection refused: connect".to_owned(),
        NetKind::Http(code) if failure.stage == NetStage::Crl => {
            format!("IOException: HTTP {code} while downloading CRL from: {address}")
        }
        NetKind::Http(code) => format!("IOException: {service} server returned HTTP {code}"),
        NetKind::Tls => format!("SSLException: {}", failure.detail),
        NetKind::ClockSkew => format!("TspResponseTimeIncorrectException: {}", failure.detail),
        _ => format!("IOException: {}", failure.detail),
    };
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(512)
        .collect()
}

/// The `sign` operation; the base64 of the CMS.
fn sign(args: &Map<String, Value>, mode: Mode) -> Result<String, Error> {
    let upgrade = if mode == Mode::V2 {
        let rejected: Vec<&str> = ["skipCheckPermissions", "policies"]
            .into_iter()
            .filter(|k| args.contains_key(*k))
            .collect();
        if !rejected.is_empty() {
            return Err(Error::with(
                "INVALID_ARGUMENT",
                vec![("argument", rejected.join(","))],
            ));
        }
        match args.get("upgradeToLta") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(upgrade)) => *upgrade,
            Some(_) => {
                return Err(Error::with(
                    "INVALID_ARGUMENT",
                    vec![("argument", "upgradeToLta".to_owned())],
                ));
            }
        }
    } else {
        false
    };
    let key_type = orgjson::get_string(args, "keyType").map_err(Error::code)?;
    let secret = dialogs::password(&PasswordArgs {
        title: "Подписание".to_owned(),
        label: "Введите пароль на хранилище ключей:".to_owned(),
        ok: "Подписать".to_owned(),
        cancel: "Отмена".to_owned(),
        allow_empty: true,
    })
    .map_err(|e| Error::code(e.message))?
    .ok_or_else(|| Error::code("ABORT"))?;
    let key = load_key(args, key_type, secret.id)?;

    let files_names = orgjson::get_string(args, "filesNames")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::code("\"filesNames\" argument could not be empty or NULL!"))?;
    let data = orgjson::get_string(args, "dataForSign")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::code("\"dataForSign\" argument could not be empty or NULL!"))?;
    let data = javab64::decode_java(data)
        .map_err(|_| Error::code("\"dataForSign\" argument should use BASE64 format!"))?;

    let permission = match mode {
        Mode::V2 => match args.get("certPolicy") {
            None | Some(Value::Null) => Permission::None,
            Some(value) => Permission::Policy(
                policy::parse(value)
                    .map_err(|m| Error::with("INVALID_POLICY", vec![("policy", m)]))?,
            ),
        },
        Mode::Legacy => {
            let skip = if args.contains_key("skipCheckPermissions") {
                orgjson::get_boolean(args, "skipCheckPermissions").map_err(Error::code)?
            } else {
                false
            };
            let policies = match orgjson::opt_array(args, "policies") {
                None => None,
                Some(list) => Some(
                    (0..list.len())
                        .map(|i| orgjson::array_get_string(list, i).map(str::to_owned))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(Error::code)?,
                ),
            };
            Permission::Legacy { policies, skip }
        }
    };

    let signed = sign_cms(&key, files_names, &data)?;
    check(&key, &signed.cms, &data, &permission)?;
    let cms = if upgrade {
        upgrade_to_lta(&key, &signed.cms, &data, &signed.ocsp)?
    } else {
        signed.cms
    };
    Ok(javab64::encode_mime(&cms).replace("\r\n", ""))
}

/// The key of `keyType`: the file the page names (`Users private key`, else the last
/// alias) or the KazToken in the reader `tokenName` (its first key).
fn load_key(args: &Map<String, Value>, key_type: &str, secret: u32) -> Result<Key, Error> {
    let (storage, source) = match key_type {
        "file" => (
            "PKCS12",
            KeySource::PagePath(
                orgjson::get_string(args, "filePath")
                    .map_err(Error::code)?
                    .to_owned(),
            ),
        ),
        "token" => (
            "AKKaztokenStore",
            KeySource::Terminal(
                orgjson::get_string(args, "tokenName")
                    .map_err(Error::code)?
                    .to_owned(),
            ),
        ),
        other => {
            return Err(Error::code(format!(
                "KeyType: \"{other}\" is not allowed! Required \"file\" or \"token\"."
            )));
        }
    };
    let path = match &source {
        KeySource::PagePath(path) => Some(path.clone()),
        _ => None,
    };
    let opened = keys::open(&OpenArgs {
        storage: storage.to_owned(),
        source,
        password: Password::Secret(secret),
    })
    .map_err(|e| Error::code(e.message))?;
    let could_not = || Error::code("Could not load key!");
    match opened {
        Ok(mut keys) => {
            if key_type == "token" {
                return keys.into_iter().next().ok_or_else(could_not);
            }
            let named = keys.iter().position(|k| k.alias() == "Users private key");
            match named {
                Some(i) => Ok(keys.swap_remove(i)),
                None => keys.pop().ok_or_else(could_not),
            }
        }
        Err(OpenOutcome::WrongPassword { .. }) => Err(Error::code("WRONG_PASSWORD")),
        // The JDK's message of a missing file: its path.
        Err(OpenOutcome::NotFound) => Err(Error::code(path.unwrap_or_default())),
        Err(OpenOutcome::Declined) => Err(Error::code("ABORT")),
        Err(_) => Err(could_not()),
    }
}

/// A signed CMS and the OCSP answer it embeds.
struct Signed {
    cms: Vec<u8>,
    ocsp: Option<Vec<u8>>,
}

/// The time-stamping URL a certificate names: authorityInfoAccess, then subjectInfoAccess.
fn tsa_url(der: &[u8]) -> Option<String> {
    let cert = Certificate::from_der(der).ok()?;
    let extensions = cert.tbs_certificate().extensions()?;
    [AIA, SIA].iter().find_map(|wanted| {
        let ext = extensions
            .iter()
            .find(|e| e.extn_id.to_string() == *wanted)?;
        let access = AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes()).ok()?;
        access.0.iter().find_map(|d| match &d.access_location {
            GeneralName::UniformResourceIdentifier(uri)
                if d.access_method.to_string() == AD_TIME_STAMPING =>
            {
                Some(uri.to_string())
            }
            _ => None,
        })
    })
}

/// OCSP first, the ESEDO CMS, then the signature time-stamp.
fn sign_cms(key: &Key, files_names: &str, data: &[u8]) -> Result<Signed, Error> {
    let cert = key.certificate();
    let details = host::cert_details(cert).map_err(|e| Error::code(e.message))?;
    let issuer = if details.subject_dn == details.issuer_dn {
        Some(cert.to_vec())
    } else {
        host::ca_issuer(cert).map_err(|e| Error::code(e.message))?
    };
    let issuer = issuer.ok_or_else(|| Error::code("UNKNOWN_CA"))?;
    // Unverified against the original: the code of a certificate without an OCSP URL.
    let ocsp_url = details
        .ocsp_urls
        .first()
        .cloned()
        .ok_or_else(|| Error::code("UNKNOWN_OCSP_ADDRESS"))?;
    // GOST 34.311 GT and the other GOST CertID are not the core's: SIGNING_FAILED.
    let ocsp_args = esedo::ocsp_args(&THUNDERCRYPT_OCSP, cert, &[&issuer])
        .map_err(|_| Error::code("SIGNING_FAILED"))?;
    let outcome = pki::ocsp_fetch(&ocsp_args).map_err(|e| {
        remote(
            &NetFailure {
                stage: NetStage::Ocsp,
                kind: NetKind::Other,
                address: String::new(),
                detail: e.message,
            },
            &ocsp_url,
            None,
        )
    })?;
    match &outcome {
        OcspOutcome::Failed(failure) => return Err(remote(failure, &ocsp_url, None)),
        OcspOutcome::Ok {
            response_status, ..
        } if *response_status != 0 => {
            return Err(Error::with(
                "OCSP_REQUEST_REJECTED",
                vec![
                    ("address", ocsp_url),
                    ("failure", "REQUEST_REJECTED".to_owned()),
                    ("status", response_status.to_string()),
                ],
            ));
        }
        // A nonce that does not match is only logged, as the original does.
        OcspOutcome::Ok {
            problem: Some(problem),
            ..
        } if *problem != Problem::NonceMismatch => {
            return Err(Error::with(
                "OCSP_INVALID_RESPONSE",
                vec![
                    ("address", ocsp_url),
                    ("failure", "INVALID_RESPONSE".to_owned()),
                ],
            ));
        }
        OcspOutcome::Ok { .. } => {}
    }
    let answer = OcspAnswer::from_outcome(&outcome);
    let input = EsedoInput {
        cert,
        file_names: &[files_names],
        ocsp: answer,
        data,
        ..EsedoInput::default()
    };
    let args = esedo::sign_args(&THUNDERCRYPT, &input, key.handle())
        .map_err(|_| Error::code("SIGNING_FAILED"))?;
    // sha1RSA and GOST3411_GT certificates: the core does not sign with them.
    let cms = match key.sign_cms_ex(args) {
        Ok(CmsOutcome::Signed(cms)) => cms.into_vec(),
        _ => return Err(Error::code("SIGNING_FAILED")),
    };

    let url = tsa_url(cert).unwrap_or_else(|| DEFAULT_TSA.to_owned());
    let tsa = TsaSpec {
        url: PkiUrl::Fixed(url.clone()),
        method: PkiMethod::Post {
            content_type: Some("application/timestamp-query".to_owned()),
        },
        hash: HashAlg::Sha256,
        policy: None,
        nonce: Nonce::Random(16),
        cert_req: true,
        retries: 0,
        timeout_ms: 15_000,
        check_skew_ms: Some(5 * 60 * 1000),
        require_tsa_eku: true,
    };
    let stamped = pki::stamp(&StampArgs {
        cms: cms.into(),
        signers: SignerSel::Last,
        tsa: TsaChoice::Custom(tsa),
        mode: StampMode::Replace,
        token: TokenForm::Token,
    })
    .map_err(|_| Error::code("TSP_NOT_VALID"))?;
    let cms = match stamped {
        StampOutcome::Stamped(cms) => cms.into_vec(),
        StampOutcome::Failed(failure) => return Err(remote(&failure, &url, None)),
        // Answers only `of_cert`, which is not asked here.
        StampOutcome::NoSigner => return Err(Error::code("TSP_NOT_VALID")),
    };
    Ok(Signed {
        cms,
        ocsp: answer.map(|a| a.response.to_vec()),
    })
}

/// The permission check of the request.
enum Permission {
    /// V2 without `certPolicy`: none.
    None,
    /// V2 `certPolicy`.
    Policy(Cond),
    /// The legacy rule.
    Legacy {
        policies: Option<Vec<String>>,
        skip: bool,
    },
}

/// What the policies look at in the certificate `der`.
fn facts(der: &[u8]) -> Result<CertFacts, Error> {
    let info = host::cert_info(der).map_err(|e| Error::code(e.message))?;
    let cert = Certificate::from_der(der).map_err(|e| Error::code(e.to_string()))?;
    let tbs = cert.tbs_certificate();
    let mut key_usage = [false; 9];
    let bits = tbs.extensions().and_then(|exts| {
        let ext = exts.iter().find(|e| e.extn_id.to_string() == KEY_USAGE)?;
        let bit_string = der::asn1::BitString::from_der(ext.extn_value.as_bytes()).ok()?;
        Some(bit_string.raw_bytes().to_vec())
    });
    match bits {
        Some(bytes) => {
            for (i, bit) in key_usage.iter_mut().enumerate() {
                *bit = bytes.get(i / 8).is_some_and(|b| b & (0x80 >> (i % 8)) != 0);
            }
        }
        None => {
            let KeyUsage {
                digital_signature,
                non_repudiation,
                key_encipherment,
                key_agreement,
            } = info.key_usage;
            key_usage[0] = digital_signature;
            key_usage[1] = non_repudiation;
            key_usage[2] = key_encipherment;
            key_usage[4] = key_agreement;
        }
    }
    let issuer = tbs.issuer().to_der().unwrap_or_default();
    Ok(CertFacts {
        key_usage,
        ekus: info.ext_key_usages,
        sig_alg: info.signature_alg_oid,
        issuer: [
            x509text::x500_principal(&issuer).unwrap_or_default(),
            x509text::rfc2253(&issuer).unwrap_or_default(),
        ],
    })
}

/// The check after signing: the time-stamp, the certificate at its time, the revocation
/// status (embedded OCSP, the responder, the CRL), the permission, the path.
fn check(key: &Key, cms: &[u8], data: &[u8], permission: &Permission) -> Result<(), Error> {
    let report = pki::cms_verify(&pki::VerifyArgs {
        cms: cms.to_vec().into(),
        data: Some(data.to_vec().into()),
        at: pki::VerifyAt::TspTime,
        chain: None,
        revocation: Revocation::LiveOcspThenCrl,
        first_signer_only: false,
        require_key_usage: Vec::new(),
    })
    .map_err(|_| Error::code("SIGNING_FAILED"))?;
    let details = host::cert_details(key.certificate()).map_err(|e| Error::code(e.message))?;
    let ocsp_url = details.ocsp_urls.first().cloned().unwrap_or_default();
    for signer in &report.signers {
        if let Check::Fail(_) = signer.signature {
            return Err(Error::code("SIGNING_FAILED"));
        }
        if let Some(tsp) = &signer.tsp
            && let Check::Fail(_) = tsp.check
        {
            return Err(Error::code("TSP_NOT_VALID"));
        }
        match &signer.validity {
            Check::Fail(Problem::Expired) => return Err(Error::code("CERTIFICATE_EXPIRED")),
            Check::Fail(Problem::NotYetValid) => {
                return Err(Error::code("CERTIFICATE_NOT_YET_VALID"));
            }
            _ => {}
        }
        if let Check::Fail(problem) = &signer.revocation {
            return Err(match problem {
                Problem::Revoked { .. } => Error::code("CERTIFICATE_REVOKED"),
                Problem::Net(failure) => {
                    let (address, attempted) = match failure.stage {
                        NetStage::Crl => (
                            details.crl_urls.first().cloned().unwrap_or_default(),
                            Some(details.crl_urls.join(", ")),
                        ),
                        _ => (ocsp_url.clone(), None),
                    };
                    remote(failure, &address, attempted)
                }
                Problem::CrlInvalid => Error::code("CRL_VERIFICATION_FAILED"),
                Problem::ResponderUnverified | Problem::OcspStale | Problem::NonceMismatch => {
                    Error::with(
                        "OCSP_INVALID_RESPONSE",
                        vec![
                            ("address", ocsp_url.clone()),
                            ("failure", "INVALID_RESPONSE".to_owned()),
                        ],
                    )
                }
                _ => Error::code("CERTIFICATE_UNKNOWN"),
            });
        }
        let cert = signer
            .certificate
            .as_ref()
            .map(|c| c.to_vec())
            .unwrap_or_else(|| key.certificate().to_vec());
        match permission {
            Permission::None => {}
            Permission::Policy(cond) => {
                cond.eval(&facts(&cert)?).map_err(|(kind, detail)| {
                    Error::with(
                        kind.code(),
                        vec![(
                            "policy",
                            format!("Certificate policy check failed: {detail}"),
                        )],
                    )
                })?;
            }
            Permission::Legacy { policies, skip } => {
                policy::legacy(&facts(&cert)?, policies.as_deref(), *skip).map_err(Error::code)?;
            }
        }
        if let Check::Fail(_) = signer.path {
            return Err(Error::code("UNKNOWN_CA"));
        }
    }
    Ok(())
}

/// B-LT then B-LTA: the chain and the revocation values (the embedded OCSP answer, the
/// CRL), then the archive time-stamp of the default TSA over a GOST 34.11-2015 (512)
/// imprint with its hash index.
fn upgrade_to_lta(
    key: &Key,
    cms: &[u8],
    data: &[u8],
    ocsp: &Option<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let failed = |_: String| Error::code("LTA_UPGRADE_FAILED");
    let chain = key.chain().map_err(|e| failed(e.message))?;
    let details = host::cert_details(key.certificate()).map_err(|e| failed(e.message))?;
    let crls: Vec<Vec<u8>> = match pki::crl_fetch(&CrlArgs {
        cert: key.certificate().to_vec().into(),
        issuer: IssuerSel::HostCas,
        timeout_ms: 10_000,
    })
    .map_err(|e| failed(e.message))?
    {
        CrlOutcome::Ok { crls, .. } => crls.into_iter().map(|c| c.into_vec()).collect(),
        CrlOutcome::Failed(failure) => {
            return Err(remote(
                &failure,
                &details.crl_urls.first().cloned().unwrap_or_default(),
                Some(details.crl_urls.join(", ")),
            ));
        }
        CrlOutcome::Invalid(_) => return Err(Error::code("CRL_VERIFICATION_FAILED")),
    };
    let ocsp: Vec<Vec<u8>> = ocsp.iter().cloned().collect();
    let values = lta::Values {
        certificates: &chain,
        ocsp: &ocsp,
        crls: &crls,
    };
    let cms = lta::with_values(cms, &values).map_err(failed)?;
    let hash = |bytes: &[u8]| host::hash(HashAlg::Streebog512, bytes).map_err(|e| e.message);
    let index = lta::hash_index(&cms, &hash).map_err(failed)?;
    let content_hash = hash(data).map_err(failed)?;
    let input = lta::imprint_input(&cms, &content_hash, &index).map_err(failed)?;
    let tsa = TsaSpec {
        url: PkiUrl::Fixed(DEFAULT_TSA.to_owned()),
        method: PkiMethod::Post {
            content_type: Some("application/timestamp-query".to_owned()),
        },
        hash: HashAlg::Streebog512,
        policy: None,
        nonce: Nonce::Random(16),
        cert_req: true,
        retries: 0,
        timeout_ms: 15_000,
        check_skew_ms: None,
        require_tsa_eku: true,
    };
    // The imprint is the hash; the TSA gets it as it is.
    let imprint = hash(&input).map_err(failed)?;
    let token = match pki::tsp_request(&tsa, &imprint).map_err(|e| failed(e.message))? {
        TspOutcome::Ok { token, .. } => token.into_vec(),
        TspOutcome::Failed(failure) => return Err(remote(&failure, DEFAULT_TSA, None)),
    };
    let token = lta::token_with_index(&token, &index).map_err(failed)?;
    lta::with_archive_time_stamp(&cms, &token).map_err(failed)
}
