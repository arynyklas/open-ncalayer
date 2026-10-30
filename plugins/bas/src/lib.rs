//! The BAS signer module (`kz.bas.nca.multiSignService`): one operation,
//! `{uuid, args:[<base64 data>, <file names>]}`, answered with one detached ESEDO CMS over
//! the data: the OCSP answer about the signer inside its signed attributes, then a
//! time-stamp appended.
//!
//! Replies are the original's `ResponseJson` bean plus `uuid` (a `HashMap` of 16 buckets).
//! Failures inside the CMS or its time-stamp answer with code `200`, as the original's did.
#![cfg(target_arch = "wasm32")]

use oncl_pdk::abi::{
    Action, CmsCerts, CmsOutcome, CoSign, Filter, HashAlg, KeyOrder, MAX_PKI_TIMEOUT_MS,
    MAX_TSP_RETRIES, Nonce, PkiMethod, PkiUrl, SignerSel, StampArgs, StampMode, StampOutcome,
    TimeForm, TokenForm, TsaChoice, TsaSpec,
};
use oncl_pdk::keys::{self, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::pki::{NetKind, OcspOutcome};
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

/// bas's CMS: detached, eContentType `1.3.6.1.4.1.6801.11.1.9`, exactly the seven ESEDO
/// attributes (signingTime as UTCTime, `ESEDO\0`, the whole `OCSPResponse` in an OCTET
/// STRING). messageDigest uses the certificate's digest (the original used GOST 34.311 for
/// RSA too, which made those signatures invalid).
pub const BAS: Profile = Profile {
    econtent_type: Some("1.3.6.1.4.1.6801.11.1.9"),
    content: ContentMode::Data,
    digest: None,
    encapsulate: Encapsulate::Never,
    cosign: CoSign::Never,
    certificates: CmsCerts::Signer,
    content_type: true,
    signing_certificate_v2: false,
    signing_time: Some(SigningTimeRule {
        from: TimeFrom::Now,
        form: TimeForm::Utc,
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

/// How a call ended.
enum Outcome {
    /// The CMS, base64.
    Signed(String),
    /// An exception before the CMS: code 500 with `getMessage()`.
    Failed(Option<String>),
    /// A failure inside the CMS or its time-stamp: code 200 with the message.
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
        Outcome::Failed(message) => {
            reply.put("code", "500");
            reply.put_opt("message", message);
        }
        Outcome::CmsFailed(message) => {
            reply.put("code", "200");
            reply.put("message", message);
        }
    }
    reply.put("uuid", uuid);
    reply.to_json()
}

/// The operation, in the original's order: arguments, dialog, expiry, OCSP, base64, CMS,
/// time-stamp.
fn sign(root: &oncl_pdk::serde_json::Map<String, oncl_pdk::serde_json::Value>) -> Outcome {
    let failed = |message: &str| Outcome::Failed(Some(message.to_owned()));
    let args = match orgjson::opt_array(root, "args") {
        Some(args) if args.len() >= 2 => args,
        _ => return failed("Invalid arguments"),
    };
    let (data, names) = match (
        orgjson::array_get_string(args, 0),
        orgjson::array_get_string(args, 1),
    ) {
        (Ok(data), Ok(names)) => (data, names),
        (Err(e), _) | (_, Err(e)) => return Outcome::Failed(Some(e)),
    };
    let key = match keys::select(&SelectArgs {
        action: Action::Sign,
        storages: vec!["PKCS12".to_owned()],
        filter: Filter {
            // The original signs with any key of the file: no path, validity or OCSP
            // condition in the dialog; expiry is checked below.
            allow_expired: true,
            chain: Some(Vec::new()),
            allow_revoked: true,
            ..Filter::default()
        },
        more: Default::default(),
        detail: None,
        initial_path: None,
        order: KeyOrder::OldestFirst,
    }) {
        Ok(Some(key)) => key,
        // A closed dialog leaves the path null: a NullPointerException.
        Ok(None) => return Outcome::Failed(None),
        Err(e) => return Outcome::Failed(Some(e.message)),
    };
    let cert = key.certificate();
    let (Ok(info), Ok(details), Ok(now)) =
        (host::cert_info(cert), host::cert_details(cert), host::now())
    else {
        return Outcome::Failed(None);
    };
    if info.not_after < now {
        return failed("The certificate has expired.");
    }
    let ocsp = esedo::ocsp_args(&OCSP, cert, &[])
        .ok()
        .and_then(|args| pki::ocsp_fetch(&args).ok());
    let ocsp = match &ocsp {
        Some(
            outcome @ OcspOutcome::Ok {
                http_status: 200, ..
            },
        ) => outcome,
        _ => return failed("OCSP response generation error"),
    };
    let bytes = match javab64::decode_java(data) {
        Ok(bytes) => bytes,
        Err(e) => return Outcome::Failed(Some(e)),
    };
    let input = EsedoInput {
        cert,
        kalkan_dn: Some(&details.subject_dn),
        file_names: &[names],
        ocsp: OcspAnswer::from_outcome(ocsp),
        data: &bytes,
        ..EsedoInput::default()
    };
    let cms = match esedo::sign_args(&BAS, &input, key.handle()).map(|args| key.sign_cms_ex(args)) {
        Ok(Ok(CmsOutcome::Signed(cms))) => cms,
        Ok(Ok(CmsOutcome::TspFailed(failure))) => return Outcome::CmsFailed(failure.detail),
        Ok(Err(e)) => return Outcome::CmsFailed(e.message),
        Err(message) => return Outcome::CmsFailed(message),
    };
    let stamp = StampArgs {
        cms,
        signers: SignerSel::Last,
        tsa: TsaChoice::Custom(tsa(&info.signature_alg_oid, now)),
        mode: StampMode::Append,
        token: TokenForm::Token,
    };
    match pki::stamp(&stamp) {
        Ok(StampOutcome::Stamped(cms)) => {
            Outcome::Signed(javab64::encode_mime(&cms).replace("\r\n", ""))
        }
        Ok(StampOutcome::Failed(failure)) => Outcome::CmsFailed(match failure.kind {
            NetKind::Http(status) => format!("Invalid TSP response status: {status}"),
            _ => "TSP creation failure".to_owned(),
        }),
        Err(_) => Outcome::CmsFailed("TSP creation failure".to_owned()),
    }
}

/// The original's TSA request for a certificate signed with `sig_oid`: POST to
/// `http://tsp.pki.gov.kz`, the imprint hash and policy by the algorithm, the time in
/// milliseconds as the nonce, 10 attempts of 5 seconds.
fn tsa(sig_oid: &str, now_ms: i64) -> TsaSpec {
    let hash = match sig_oid {
        "1.2.840.113549.1.1.5" => HashAlg::Sha1,
        "1.2.840.113549.1.1.11" => HashAlg::Sha256,
        "1.2.840.113549.1.1.13" => HashAlg::Sha512,
        // Every GOST certificate, 2015 too.
        _ => HashAlg::Gost34311,
    };
    let policy = if sig_oid.contains("1.2.840.113549.1.1.11") {
        "1.2.398.3.3.2.6.2"
    } else if sig_oid.contains("1.2.398.3.10.1.1.1.2") {
        "1.2.398.3.3.2.6.1"
    } else if sig_oid.contains("1.2.398.3.10.1.1.2.3") {
        "1.2.398.3.3.2.6.4"
    } else {
        "1.2.398.3.3.2.6.3"
    };
    TsaSpec {
        url: PkiUrl::Default,
        method: PkiMethod::Post { content_type: None },
        hash,
        policy: Some(policy.to_owned()),
        nonce: Nonce::Value(big_integer(now_ms).into()),
        cert_req: true,
        // Ten attempts: the first and nine repeats.
        retries: MAX_TSP_RETRIES - 1,
        timeout_ms: 5_000,
        check_skew_ms: None,
        require_tsa_eku: false,
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
