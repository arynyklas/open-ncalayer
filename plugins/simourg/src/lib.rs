//! Simourg SimBASE (`kz.Simourg.SimBASEModule`): `salemAit` (a greeting),
//! `createCMSSignatureWithTspFromBase64` (a CAdES with the signer's `BasicOCSPResponse` among
//! its signed attributes, time-stamped by Kalkan's default TSA) and `createCMSForEsedo` (a
//! detached ESEDO CMS with the OCSP answer, time-stamped by a GOST TSA request, then again
//! by Kalkan's default, which replaces the first).
//!
//! The CMS replies are the original's `Response` bean (`responseObject`, `code`, `message`);
//! errors answer `Error: <message>`, a cancelled dialog `Cancel`.
#![cfg(target_arch = "wasm32")]

use oncl_pdk::abi::{
    Action, CmsCerts, CmsOutcome, CoSign, Filter, FilterMore, HashAlg, KeyOrder,
    MAX_PKI_TIMEOUT_MS, MessageKind, Nonce, PkiMethod, PkiUrl, SignerSel, StampArgs, StampMode,
    StampOutcome, TimeForm, TokenForm, TsaChoice, TsaSpec,
};
use oncl_pdk::dialogs::{self, ChoiceArgs};
use oncl_pdk::keys::{self, Key, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::pki::{CertStatusAbi, OcspOutcome};
use oncl_pdk::{Request, host, javab64, pki};
use oncl_port_pki::esedo::{
    self, CertIdHash, ContentMode, Description, Encapsulate, EsedoInput, FileNames, IssuerRule,
    OcspAnswer, OcspForm, OcspRequest, OcspUrl, Profile, SigningTimeRule, StringKind, TimeFrom,
};

oncl_pdk::plugin!(handle);

/// The Kalkan storages `StorageInfo` knows.
const STORAGES: [&str; 9] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKEToken72KStore",
    "AKEToken5110Store",
    "AKJaCartaStore",
    "AKAKEYStore",
    "PKCS12",
    "JKS",
    "ABCloudServiceStore",
];

/// Kalkan's `KNCACertificateType` constants.
const KEY_TYPES: [&str; 5] = [
    "SIGNATURE",
    "AUTHENTICATION",
    "SSL",
    "OCSP_RESPONSE_SIGNING",
    "TSP_SIGNING",
];

/// The CAdES's OCSP request: the issuer among the CAs whose key verifies the certificate, a
/// SHA-1 `CertID`, no nonce, GET with the URL-encoded request to the certificate's
/// responder, checked.
pub const CADES_OCSP: OcspRequest = OcspRequest {
    issuer: IssuerRule::VerifiesCert,
    cert_id_hash: CertIdHash::Fixed(HashAlg::Sha1),
    nonce: Nonce::None,
    method: PkiMethod::GetUrlEncoded,
    url: OcspUrl::FromCert,
    // The original waited without a limit.
    timeout_ms: MAX_PKI_TIMEOUT_MS,
    check: true,
};

/// The CAdES: Kalkan's attributes, signingCertificateV2, the names and the bare
/// `BasicOCSPResponse`; attached as asked, co-signing a CMS given as the data.
pub const SIMOURG_CADES: Profile = Profile {
    econtent_type: None,
    content: ContentMode::Data,
    digest: None,
    encapsulate: Encapsulate::AsAsked,
    cosign: CoSign::Auto,
    certificates: CmsCerts::Signer,
    content_type: true,
    signing_certificate_v2: true,
    signing_time: Some(SigningTimeRule {
        from: TimeFrom::Now,
        form: TimeForm::Auto,
    }),
    file_names: Some(FileNames {
        separator: "<>",
        omit_blank: false,
    }),
    signer_dn: None,
    description: None,
    ocsp: Some(OcspForm::BareBasic),
    ocsp_request: Some(CADES_OCSP),
};

/// The ESEDO OCSP request: the issuer among the CAs whose key verifies the certificate, a
/// GOST 34.311 `CertID`, an 8-byte nonce, POST to `http://ocsp.pki.gov.kz/`; the answer is
/// embedded only when successful and good.
pub const ESEDO_OCSP: OcspRequest = OcspRequest {
    issuer: IssuerRule::VerifiesCert,
    cert_id_hash: CertIdHash::Fixed(HashAlg::Gost34311),
    nonce: Nonce::Random(8),
    method: PkiMethod::Post { content_type: None },
    url: OcspUrl::Fixed("http://ocsp.pki.gov.kz/"),
    // The original waited without a limit.
    timeout_ms: MAX_PKI_TIMEOUT_MS,
    check: false,
};

/// The ESEDO CMS: detached id-data, signingTime as GeneralizedTime, the names, `ESEDO`
/// (no NUL), the whole `OCSPResponse` in an OCTET STRING; no signer DN.
pub const SIMOURG_ESEDO: Profile = Profile {
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
    signer_dn: None,
    description: Some(Description {
        text: "ESEDO",
        kind: StringKind::Printable,
    }),
    ocsp: Some(OcspForm::OctetResponse),
    ocsp_request: Some(ESEDO_OCSP),
};

/// The OCSP failure of the CAdES.
const OCSP_ERROR: &str = "Ошибка при запросе списка отозванных сертификатов. Попробуйте позже или обратитесь к администратору. Ошибка: ";

/// How a CMS method ended.
enum Outcome {
    /// The CMS, base64.
    Signed(String),
    /// The dialog was cancelled.
    Cancel,
    /// An exception: its message.
    Error(String),
}

impl From<String> for Outcome {
    fn from(message: String) -> Outcome {
        Outcome::Error(message)
    }
}

fn handle(request: &Request) -> String {
    let Ok(JValue::Obj(root)) = orgjson::parse(&request.text) else {
        return dropped();
    };
    let root = root.to_map();
    let method = orgjson::opt_string(&root, "method").unwrap_or_default();
    let esedo = match method.as_str() {
        "salemAit" => {
            let Ok(args) = orgjson::get_object(&root, "args") else {
                return dropped();
            };
            let name =
                orgjson::opt_string(args, "username").unwrap_or_else(|| "Silent Bob".to_owned());
            let mut body = JObject::stringer();
            body.put("result", format!("Salem, {name}"));
            let mut reply = JObject::stringer();
            reply.put("success", true);
            reply.put("body", body);
            return reply.to_json();
        }
        "createCMSSignatureWithTspFromBase64" => false,
        "createCMSForEsedo" => true,
        other => {
            let mut reply = JObject::stringer();
            reply.put("success", false);
            reply.put("errorCode", "method_not_defined");
            reply.put("message", format!("Error method {other} is not defined"));
            return reply.to_json();
        }
    };
    // `args.get(i).toString()`, outside the original's `try`: a missing one drops the
    // connection. The ESEDO method does not use `args[3]` but needs `args[4]`.
    let Ok(args) = orgjson::get_array(&root, "args") else {
        return dropped();
    };
    if args.len() < 5 {
        return dropped();
    }
    let arg = |i: usize| orgjson::value_to_string(&args[i]);
    let outcome = if esedo {
        sign_esedo(&arg(0), &arg(1), &arg(2), &arg(4))
    } else {
        let attached = arg(3).eq_ignore_ascii_case("true");
        sign_cades(&arg(0), &arg(1), &arg(2), attached, &arg(4))
    };
    let mut reply = JObject::hash_map();
    match outcome {
        Outcome::Signed(cms) => {
            reply.put("responseObject", cms);
            reply.put("code", "200");
            reply.put("message", "Ok");
        }
        Outcome::Cancel => {
            reply.put("code", "500");
            reply.put("message", "Cancel");
        }
        Outcome::Error(message) => {
            reply.put("code", "500");
            reply.put("message", format!("Error: {message}"));
        }
    }
    reply.to_json()
}

/// The connection is dropped without a reply, as for an exception the original let out.
fn dropped() -> String {
    let _ = host::reply_drop();
    String::new()
}

/// The storage checks of `StorageInfo`, then the key dialog over keys of `key_type`
/// chained to the core's CAs, then «Подписать» / «Выбрать другие ключи» / «Отменить».
fn choose(storage: &str, key_type: &str, cas: &[Vec<u8>]) -> Result<Key, Outcome> {
    if storage.trim().is_empty() {
        return Err(Outcome::Error("storageName.param.empty".to_owned()));
    }
    if !STORAGES.contains(&storage) {
        return Err(Outcome::Error("Unknown storage".to_owned()));
    }
    if !matches!(storage, "PKCS12" | "JKS") {
        let readers = keys::terminals(storage).map_err(|e| Outcome::Error(e.message))?;
        if readers.is_empty() {
            return Err(Outcome::Error("Empty storage".to_owned()));
        }
    }
    // An unknown type is Kalkan's `null`: signing and authentication keys.
    let knca_types = if KEY_TYPES.contains(&key_type) {
        vec![key_type.to_owned()]
    } else {
        vec!["SIGNATURE".to_owned(), "AUTHENTICATION".to_owned()]
    };
    loop {
        let key = keys::select(&SelectArgs {
            action: Action::Sign,
            storages: vec![storage.to_owned()],
            filter: Filter {
                allow_expired: true,
                chain: Some(cas.iter().map(|ca| ca.clone().into()).collect()),
                allow_revoked: true,
                ..Filter::default()
            },
            more: FilterMore {
                knca_types: knca_types.clone(),
                ..FilterMore::default()
            },
            detail: None,
            initial_path: None,
            order: KeyOrder::OldestFirst,
        })
        .map_err(|e| Outcome::Error(e.message))?
        .ok_or(Outcome::Cancel)?;
        let owner = host::cert_info(key.certificate())
            .ok()
            .and_then(|info| info.subject_cn)
            .unwrap_or_default();
        let choice = dialogs::choice(&ChoiceArgs {
            kind: MessageKind::Info,
            title: Some("Подписать данные - Simbase®".to_owned()),
            text: format!("Подписать документ Simbase®\n{owner}"),
            buttons: ["Подписать", "Выбрать другие ключи", "Отменить"]
                .map(str::to_owned)
                .to_vec(),
            default: 0,
            options: Vec::new(),
        })
        .map_err(|e| Outcome::Error(e.message))?;
        match choice {
            Some(0) => return Ok(key),
            Some(1) => continue,
            _ => return Err(Outcome::Cancel),
        }
    }
}

/// The OCSP answer `request` gets about `cert`, its issuer among `cas`.
fn ocsp(request: &OcspRequest, cert: &[u8], cas: &[Vec<u8>]) -> Option<OcspOutcome> {
    let cas: Vec<&[u8]> = cas.iter().map(Vec::as_slice).collect();
    let args = esedo::ocsp_args(request, cert, &cas).ok()?;
    pki::ocsp_fetch(&args).ok()
}

/// Whether the answer is successful, about a good certificate, and passed the core's check.
fn good(outcome: &OcspOutcome) -> bool {
    matches!(
        outcome,
        OcspOutcome::Ok {
            response_status: 0,
            cert_status: Some(CertStatusAbi::Good),
            problem: None,
            ..
        }
    )
}

/// `createCMSSignatureWithTspFromBase64[storage, keyType, data, attached, fileNames]`.
fn sign_cades(storage: &str, key_type: &str, data: &str, attached: bool, names: &str) -> Outcome {
    let run = || -> Result<String, Outcome> {
        let cas = host::ca_list().map_err(|e| e.message)?;
        let key = choose(storage, key_type, &cas)?;
        let bytes = javab64::decode_java(data)?;
        let cert = key.certificate();
        // Two attempts, as the original; the answer must pass the core's check.
        // Unverified against the original: the text after «Ошибка: » (Kalkan's checker).
        let answer = match ocsp(&CADES_OCSP, cert, &cas).filter(good) {
            Some(answer) => answer,
            None => match ocsp(&CADES_OCSP, cert, &cas) {
                Some(answer) if good(&answer) => answer,
                Some(OcspOutcome::Failed(failure)) => {
                    return Err(format!("{OCSP_ERROR}{}", failure.detail).into());
                }
                Some(OcspOutcome::Ok {
                    problem: Some(problem),
                    ..
                }) => return Err(format!("{OCSP_ERROR}{problem:?}").into()),
                Some(OcspOutcome::Ok { cert_status, .. }) => {
                    return Err(format!("{OCSP_ERROR}{cert_status:?}").into());
                }
                None => return Err(format!("{OCSP_ERROR}TARGET_CERT_ISSUER_NOT_FOUND").into()),
            },
        };
        let input = EsedoInput {
            cert,
            file_names: &[names],
            ocsp: OcspAnswer::from_outcome(&answer),
            data: &bytes,
            attached,
            ..EsedoInput::default()
        };
        let mut args = esedo::sign_args(&SIMOURG_CADES, &input, key.handle())?;
        args.timestamp = Some(TsaChoice::Kalkan);
        // Unverified against the original: the texts of signing and time-stamp failures.
        match key.sign_cms_ex(args).map_err(|e| e.message)? {
            CmsOutcome::Signed(cms) => Ok(base64(&cms)),
            CmsOutcome::TspFailed(failure) => Err(failure.detail.into()),
        }
    };
    run().map_or_else(|outcome| outcome, Outcome::Signed)
}

/// `createCMSForEsedo[storage, keyType, data, -, fileNames]`.
fn sign_esedo(storage: &str, key_type: &str, data: &str, names: &str) -> Outcome {
    let run = || -> Result<String, Outcome> {
        let cas = host::ca_list().map_err(|e| e.message)?;
        let key = choose(storage, key_type, &cas)?;
        let bytes = javab64::decode_java(data)?;
        let cert = key.certificate();
        // A failed, unsuccessful or not good answer is left out.
        let answer = ocsp(&ESEDO_OCSP, cert, &cas).filter(good);
        let input = EsedoInput {
            cert,
            file_names: &[names],
            ocsp: answer.as_ref().and_then(OcspAnswer::from_outcome),
            data: &bytes,
            ..EsedoInput::default()
        };
        let args = esedo::sign_args(&SIMOURG_ESEDO, &input, key.handle())?;
        let cms = match key.sign_cms_ex(args).map_err(|e| e.message)? {
            CmsOutcome::Signed(cms) => cms,
            CmsOutcome::TspFailed(failure) => return Err(failure.detail.into()),
        };
        let now = host::now().map_err(|e| e.message)?;
        let gost = TsaChoice::Custom(TsaSpec {
            url: PkiUrl::Default,
            method: PkiMethod::Get,
            hash: HashAlg::Gost34311,
            policy: Some("1.2.398.3.3.2.6.4".to_owned()),
            nonce: Nonce::Value(big_integer(now).into()),
            cert_req: true,
            retries: 0,
            // The original waited without a limit.
            timeout_ms: MAX_PKI_TIMEOUT_MS,
            check_skew_ms: None,
            require_tsa_eku: false,
        });
        let cms = stamp(cms.into_vec(), gost).map_err(|_| {
            "kz.gov.pki.kalkan.tsp.TSPException: Ошибка при получении TSP".to_owned()
        })?;
        // Unverified against the original: the text of the second time-stamp's failure.
        let cms = stamp(cms, TsaChoice::Kalkan)?;
        Ok(base64(&cms))
    };
    run().map_or_else(|outcome| outcome, Outcome::Signed)
}

/// The CMS with the signer's time-stamp replaced by one of `tsa`.
fn stamp(cms: Vec<u8>, tsa: TsaChoice) -> Result<Vec<u8>, String> {
    let args = StampArgs {
        cms: cms.into(),
        signers: SignerSel::Last,
        tsa,
        mode: StampMode::Replace,
        token: TokenForm::Token,
    };
    match pki::stamp(&args).map_err(|e| e.message)? {
        StampOutcome::Stamped(cms) => Ok(cms.into_vec()),
        StampOutcome::Failed(failure) => Err(failure.detail),
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
