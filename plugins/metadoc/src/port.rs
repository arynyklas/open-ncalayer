//! The module's switch and its operations.

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfos};
use der::asn1::{ObjectIdentifier, SetOfVec};
use der::{Any, Decode, Encode, SliceReader};
use oncl_pdk::abi::{
    CmsCerts, CmsOutcome, CoSign, FileMode, HashAlg, MAX_PKI_TIMEOUT_MS, NetKind, Nonce,
    OcspOutcome, PkiMethod, PkiUrl, Problem, TimeForm, TsaChoice, TsaSpec,
};
use oncl_pdk::dialogs::{self, PasswordArgs};
use oncl_pdk::files::{self, ChooseFileArgs, FileFilter};
use oncl_pdk::keys::{
    self, Action, Filter, Key, KeyOrder, KeySource, OpenArgs, OpenOutcome, Password,
};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::pki::{
    self, Check, Revocation, SignerSel, StampArgs, StampMode, StampOutcome, TokenForm, VerifyArgs,
    VerifyAt,
};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{Reply, Request, host, javab64};
use oncl_port_legacy::{
    ACTION_CANCELED, Select, base64, into_text, knca_types, official_key_info, select, sign_xml,
};
use oncl_port_pki::esedo::{
    CertIdHash, ContentMode, Description, Encapsulate, EsedoInput, FileNames, IssuerRule,
    OcspAnswer, OcspForm, OcspRequest, OcspUrl, Profile, SignerDn, SigningTimeRule, StringKind,
    TimeFrom, ocsp_args, sign_args,
};
use oncl_port_pki::x509text::kalkan_sig_alg_name;

/// The module's ESEDO CMS: detached, of the data or (`hashed`) of its hash, the signer
/// certificate; contentType, signingTime (UTCTime) the producedAt of the OCSP answer, the
/// file names as given, the signer's DN as its certificate encodes it, signingDescription
/// UTF8String `ESEDO ` (with the space) and OCTET STRING { OCSPResponse }.
pub const METADOC: Profile = Profile {
    econtent_type: None,
    content: ContentMode::AsAsked,
    digest: None,
    encapsulate: Encapsulate::Never,
    cosign: CoSign::Never,
    certificates: CmsCerts::Signer,
    content_type: true,
    signing_certificate_v2: false,
    signing_time: Some(SigningTimeRule {
        from: TimeFrom::OcspProducedAt,
        form: TimeForm::Utc,
    }),
    file_names: Some(FileNames {
        separator: "<>",
        omit_blank: false,
    }),
    signer_dn: Some(SignerDn::Encoded),
    description: Some(Description {
        text: "ESEDO ",
        kind: StringKind::Utf8,
    }),
    ocsp: Some(OcspForm::OctetResponse),
    ocsp_request: Some(METADOC_OCSP),
};

/// The OCSP request before signing: the issuer among the core's CAs, the `CertID` hash by
/// the issuer's issuer (GOST 34.311 under a GOST root), a 16-byte nonce, the certificate's
/// responder, GET while the request is short, else POST. The status is checked later, on
/// the CMS.
pub const METADOC_OCSP: OcspRequest = OcspRequest {
    issuer: IssuerRule::HostCas,
    cert_id_hash: CertIdHash::ByIssuerIssuerDn,
    nonce: Nonce::Random(16),
    method: PkiMethod::GetUnder(256),
    url: OcspUrl::FromCert,
    timeout_ms: 10_000,
    // Checked for the echoed nonce only (the original refused a response without it).
    check: true,
};

/// The time-stamp policy: the TSA's GOST 2015 one.
const TSA_GOST2015_POLICY: &str = "1.2.398.3.3.2.6.4";

const NONE: &str = "NONE";
const CANCELLED: &str = "action.cancelled";
const FILE_NOT_FOUND: &str = "FILE_NOT_FOUND";
const WRONG_PASSWORD: &str = "WRONG_PASSWORD";
const COULD_NOT_LOAD_KEY: &str = "Could not load key!";
const COULD_NOT_CREATE_SIGN: &str = "Could not create sign!";
const UNKNOWN_CAUSE: &str = "UNKNOWN_CAUSE";
const UNKNOWN_CA: &str = "UNKNOWN_CA";
const OCSP_HAS_BROKEN: &str = "OCSP_HAS_BROKEN";

/// The `Response` bean: `responseObject`, `code`, `message` and `params` (`{"address":…}`),
/// the absent ones left out, in Java's `HashMap` order.
fn response(
    object: Option<JValue>,
    code: &str,
    message: Option<&str>,
    address: Option<&str>,
) -> String {
    let mut bean = JObject::hash_map();
    bean.put_opt("responseObject", object);
    bean.put("code", code);
    // Unverified against the original: `message` and `params` share a bucket, and their
    // order is the bean's.
    bean.put_opt("message", message);
    if let Some(address) = address {
        let mut params = JObject::hash_map();
        params.put("address", address);
        bean.put("params", params);
    }
    bean.to_json()
}

/// A success: `{"responseObject":…,"code":"200","message":"NONE"}`.
fn done(object: impl Into<JValue>) -> String {
    response(Some(object.into()), "200", Some(NONE), None)
}

/// A failure of `processError`: its message (none for an exception without one), and the
/// address of an unknown host.
#[derive(Debug)]
struct Failure {
    message: Option<String>,
    address: Option<String>,
}

impl Failure {
    fn reply(&self) -> String {
        response(
            None,
            "500",
            self.message.as_deref(),
            self.address.as_deref(),
        )
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Failure {
        Failure {
            message: Some(message),
            address: None,
        }
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Failure {
        message.to_owned().into()
    }
}

/// The plugin's handler.
pub fn handle(request: &Request) -> String {
    into_text(process(&request.text))
}

/// The switch on `method`: a request that does not parse, without a string `method`, or
/// without the fields its method reads outside its own error handling, drops the
/// connection.
fn process(text: &str) -> Reply {
    let Ok(JValue::Obj(object)) = orgjson::parse(text) else {
        return Reply::Drop;
    };
    let request = object.to_map();
    let Ok(method) = orgjson::get_string(&request, "method") else {
        return Reply::Drop;
    };
    let reply = match method {
        "getKeyInfo" => {
            let storage = orgjson::opt_array(&request, "args")
                .and_then(|args| orgjson::array_get_string(args, 0).ok());
            match storage {
                Some(storage) => get_key_info(storage),
                None => return Reply::Drop,
            }
        }
        "getModuleVersion" => done("1.7.0"),
        "signXml" => sign_xml_method(&request),
        "getKeyInfoByFilePathAndPassword" => {
            let (Ok(path), Ok(password)) = (
                orgjson::get_string(&request, "filePath"),
                orgjson::get_string(&request, "password"),
            ) else {
                return Reply::Drop;
            };
            key_info_by_file(path, password)
        }
        "getFilePath" => get_file_path(),
        _ => sign(&request),
    };
    Reply::Text(reply)
}

/// The module's `KeyInfo`: the official one, and `usage` — `auth` for a key of Kalkan's
/// type AUTHENTICATION, else `sign` — and the key store's `path` if the page named it.
fn key_info(key: &Key, path: Option<&str>) -> Result<JObject, String> {
    let mut info = official_key_info(key.alias(), key.certificate())?;
    let details = host::cert_details(key.certificate()).map_err(|e| e.message)?;
    info.put_opt("path", path);
    let usage = match details.knca_types.iter().any(|t| t == "AUTHENTICATION") {
        true => "auth",
        false => "sign",
    };
    info.put("usage", usage);
    Ok(info)
}

/// `getKeyInfo` with `args[0]` the storage: the official storage and key dialogs, its
/// `ResponseMessage` reply. The key store's path is not given: the core does not tell a
/// plugin where the key the user chose lies.
fn get_key_info(storage: &str) -> String {
    let message = |m: &str| oncl_port_legacy::response(None, "500", Some(m)).to_json();
    let key = select(Select {
        storage,
        action: Action::KeyInfo,
        knca_types: knca_types(""),
        order: KeyOrder::NewestFirst,
        filter: Filter {
            allow_expired: true,
            chain: Some(Vec::new()),
            allow_revoked: true,
            ..Filter::default()
        },
    });
    let key = match key {
        Ok(Some(key)) => key,
        Ok(None) => return message(ACTION_CANCELED),
        Err(m) => return message(&m),
    };
    match key_info(&key, None) {
        Ok(info) => oncl_port_legacy::response(Some(info.into()), "200", None).to_json(),
        Err(m) => message(&m),
    }
}

/// `getFilePath`: the official file chooser for `P12` files, its `ResponseMessage` reply.
fn get_file_path() -> String {
    let chosen = files::choose(&ChooseFileArgs {
        mode: FileMode::Open,
        title: None,
        filters: vec![FileFilter {
            name: "P12".to_owned(),
            extensions: vec!["p12".to_owned()],
        }],
        initial_dir: None,
    });
    match chosen {
        Ok(Some(path)) => oncl_port_legacy::response(Some(path.path.into()), "200", None),
        _ => oncl_port_legacy::response(None, "500", Some(ACTION_CANCELED)),
    }
    .to_json()
}

/// `getKeyInfoByFilePathAndPassword`: the `KeyInfo` of the module's key of the PKCS#12
/// file, with its `path`.
fn key_info_by_file(path: &str, password: &str) -> String {
    let info = open_key(
        "PKCS12",
        KeySource::PagePath(path.to_owned()),
        Password::Text(password.to_owned()),
    )
    .and_then(|key| key_info(&key, Some(path)).map_err(Failure::from));
    match info {
        Ok(info) => done(info),
        Err(failure) => failure.reply(),
    }
}

/// Java's `trim().isEmpty()`.
fn blank(s: &str) -> bool {
    s.trim_matches(|c| c <= ' ').is_empty()
}

/// The key of the request's `keyType` (`file`: the PKCS#12 file `filePath`; `token`: the
/// Kaztoken in the reader `tokenName`), with the request's `password` or, when it is absent
/// or blank, one the user types first — before any field but `keyType` is read.
fn load_key(request: &Map<String, Value>) -> Result<Key, Failure> {
    let key_type = orgjson::get_string(request, "keyType")?;
    let given = match request.contains_key("password") {
        true => Some(orgjson::get_string(request, "password")?),
        false => None,
    };
    let password = match given {
        Some(password) if !blank(password) => Password::Text(password.to_owned()),
        _ => {
            let secret = dialogs::password(&PasswordArgs {
                title: "Подписание".to_owned(),
                label: "Введите пароль на хранилище ключей:".to_owned(),
                ok: "Подписать".to_owned(),
                cancel: "Отмена".to_owned(),
                allow_empty: true,
            })
            .map_err(|e| e.message)?
            .ok_or(CANCELLED)?;
            Password::Secret(secret.id)
        }
    };
    match key_type {
        "file" => {
            let path = orgjson::get_string(request, "filePath")?;
            open_key("PKCS12", KeySource::PagePath(path.to_owned()), password)
        }
        "token" => {
            let reader = orgjson::get_string(request, "tokenName")?;
            open_key(
                "AKKaztokenStore",
                KeySource::Terminal(reader.to_owned()),
                password,
            )
        }
        other => Err(format!(
            "KeyType: \"{other}\" is not allowed! Required \"file\" or \"token\"."
        )
        .into()),
    }
}

/// The module's key of a store: of a file, the alias `Users private key`, else the last
/// one; of a token, the first.
fn open_key(storage: &str, source: KeySource, password: Password) -> Result<Key, Failure> {
    let token = matches!(source, KeySource::Terminal(_));
    let opened = keys::open(&OpenArgs {
        storage: storage.to_owned(),
        source,
        password,
    })
    .map_err(|e| e.message)?;
    let mut keys = match opened {
        Ok(keys) => keys,
        Err(OpenOutcome::WrongPassword { .. }) => return Err(WRONG_PASSWORD.into()),
        Err(OpenOutcome::NotFound) => return Err(FILE_NOT_FOUND.into()),
        // The user did not let the page open the file.
        Err(OpenOutcome::Declined) => return Err(CANCELLED.into()),
        // Unverified against the original: the text of a token that is blocked or not
        // there (no tokens until the core has them).
        Err(_) => return Err(COULD_NOT_LOAD_KEY.into()),
    };
    if token {
        return match keys.is_empty() {
            true => Err(COULD_NOT_LOAD_KEY.into()),
            false => Ok(keys.remove(0)),
        };
    }
    match keys.iter().position(|k| k.alias() == "Users private key") {
        Some(i) => Ok(keys.remove(i)),
        None => keys.pop().ok_or_else(|| COULD_NOT_LOAD_KEY.into()),
    }
}

/// `signXml`: Kalkan's whole-document XML signature of `xml` with the request's key.
fn sign_xml_method(request: &Map<String, Value>) -> String {
    let signed = (|| {
        let key = load_key(request)?;
        let xml = orgjson::get_string(request, "xml")?;
        if xml.is_empty() {
            // Unverified against the original: the text, by its other required fields.
            return Err("\"xml\" argument could not be empty or NULL!".into());
        }
        sign_xml(&key, xml, "", "").map_err(Failure::from)
    })();
    match signed {
        Ok(xml) => done(xml),
        Err(failure) => failure.reply(),
    }
}

/// `get(key)` as a Boolean if present, else `false`.
fn flag(request: &Map<String, Value>, key: &str) -> Result<bool, String> {
    match request.contains_key(key) {
        true => orgjson::get_boolean(request, key),
        false => Ok(false),
    }
}

/// What the page asks a CMS of.
struct Order<'a> {
    file_names: &'a str,
    data: Vec<u8>,
    hashed: bool,
    skip_check_permissions: bool,
    policies: Option<Vec<&'a str>>,
}

/// The default branch: the ESEDO CMS of `dataForSign`, checked before it is given out.
fn sign(request: &Map<String, Value>) -> String {
    match sign_checked(request) {
        Ok(cms) => done(base64(&cms)),
        Err(failure) => failure.reply(),
    }
}

fn sign_checked(request: &Map<String, Value>) -> Result<Vec<u8>, Failure> {
    let key = load_key(request)?;
    let file_names = orgjson::get_string(request, "filesNames")?;
    if file_names.is_empty() {
        return Err("\"filesNames\" argument could not be empty or NULL!".into());
    }
    let data = orgjson::get_string(request, "dataForSign")?;
    if data.is_empty() {
        return Err("\"dataForSign\" argument could not be empty or NULL!".into());
    }
    // Unverified against the original: its Base64 decoder, taken as Java's.
    let data = javab64::decode_java(data)
        .map_err(|_| "\"dataForSign\" argument should use BASE64 format!")?;
    let skip_check_permissions = flag(request, "skipCheckPermissions")?;
    let hashed = flag(request, "hashed")?;
    let policies = match request.contains_key("policies") {
        true => {
            let policies = orgjson::get_array(request, "policies")?;
            Some(
                (0..policies.len())
                    .map(|i| orgjson::array_get_string(policies, i))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        false => None,
    };
    let order = Order {
        file_names,
        data,
        hashed,
        skip_check_permissions,
        policies,
    };
    let (cms, produced_at_ms) = make_signature(&key, &order)?;
    self_check(&key, &order, &cms, produced_at_ms)?;
    Ok(cms)
}

/// The CMS: the OCSP answer first, then the signature and the time-stamp. A failure after
/// the OCSP answer is `Could not create sign!`, as the original wrapped every one.
fn make_signature(key: &Key, order: &Order<'_>) -> Result<(Vec<u8>, Option<i64>), Failure> {
    let cert = key.certificate();
    let issuer = host::ca_issuer(cert)
        .map_err(|e| e.message)?
        .ok_or(UNKNOWN_CA)?;
    // A `CertID` the core cannot build (GOST 34.311 GT for an issuer under an RSA root, the
    // module's own GOST one otherwise) fails as a request that fails.
    let request = ocsp_args(&METADOC_OCSP, cert, &[&issuer]).map_err(|_| UNKNOWN_CAUSE)?;
    // Unverified against the original: a certificate without an OCSP responder, whose
    // exception carries its cause's text.
    let outcome = pki::ocsp_fetch(&request).map_err(|_| UNKNOWN_CAUSE)?;
    let produced_at_ms = match &outcome {
        OcspOutcome::Failed(failure) if failure.kind == NetKind::UnknownHost => {
            return Err(Failure {
                message: Some("UNKNOWN_OCSP_ADDRESS".to_owned()),
                address: Some(failure.address.clone()),
            });
        }
        OcspOutcome::Failed(_) => return Err(UNKNOWN_CAUSE.into()),
        OcspOutcome::Ok {
            response_status,
            problem,
            produced_at_ms,
            ..
        } => {
            if *response_status != 0 || *problem == Some(Problem::NonceMismatch) {
                return Err(UNKNOWN_CAUSE.into());
            }
            *produced_at_ms
        }
    };
    let names = [order.file_names];
    let input = EsedoInput {
        cert,
        file_names: &names,
        ocsp: OcspAnswer::from_outcome(&outcome),
        data: &order.data,
        hashed: order.hashed,
        ..EsedoInput::default()
    };
    let args = sign_args(&METADOC, &input, key.handle()).map_err(|_| COULD_NOT_CREATE_SIGN)?;
    let cms = match key.sign_cms_ex(args) {
        Ok(CmsOutcome::Signed(cms)) => cms,
        _ => return Err(COULD_NOT_CREATE_SIGN.into()),
    };
    let stamped = pki::stamp(&StampArgs {
        cms,
        signers: SignerSel::Last,
        tsa: TsaChoice::Custom(tsa(cert)?),
        mode: StampMode::Replace,
        token: TokenForm::WholeResponse,
    });
    match stamped {
        Ok(StampOutcome::Stamped(cms)) => Ok((cms.into_vec(), produced_at_ms)),
        _ => Err(COULD_NOT_CREATE_SIGN.into()),
    }
}

/// The TSA: `http://tsp.pki.gov.kz/`, GET while the request is short (POST otherwise,
/// which a request of this module never needs), a GOST 34.311 imprint of the signature for
/// a certificate signed by GOST 34.310-2004 and SHA-1 for any other, the GOST 2015 policy,
/// the signer's serial number as the nonce, `certReq`.
fn tsa(cert: &[u8]) -> Result<TsaSpec, Failure> {
    let info = host::cert_info(cert).map_err(|e| e.message)?;
    let gost = kalkan_sig_alg_name(&info.signature_alg_oid) == Some("ECGOST34310")
        || matches!(
            info.signature_alg_oid.as_str(),
            "1.2.398.3.10.1.1.1.2" | "1.3.6.1.4.1.6801.1.2.2"
        );
    let serial = from_hex(&info.serial_hex).ok_or(COULD_NOT_CREATE_SIGN)?;
    Ok(TsaSpec {
        url: PkiUrl::Default,
        // Unverified against the original: the base64 of a GET in the path as is, here
        // percent-encoded.
        method: PkiMethod::GetUnder(255),
        hash: if gost {
            HashAlg::Gost34311
        } else {
            HashAlg::Sha1
        },
        policy: Some(TSA_GOST2015_POLICY.to_owned()),
        nonce: Nonce::Value(serial.into()),
        cert_req: true,
        retries: 0,
        // The original waited without a limit.
        timeout_ms: MAX_PKI_TIMEOUT_MS,
        check_skew_ms: None,
        require_tsa_eku: false,
    })
}

fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

/// id-aa-signatureTimeStampToken.
const TIMESTAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// `cms` with the `TimeStampResp` of its first signer's time-stamp attribute replaced by the
/// response's token.
fn token_form(cms: &[u8]) -> Option<Vec<u8>> {
    let mut info = ContentInfo::from_der(cms).ok()?;
    let mut signed: SignedData = info.content.decode_as().ok()?;
    let mut signers = signed.signer_infos.0.into_vec();
    let first = signers.first_mut()?;
    let mut attrs = Vec::new();
    for mut attr in first.unsigned_attrs.take()?.into_vec() {
        if attr.oid == TIMESTAMP_TOKEN {
            let response = attr.values.iter().next()?;
            let mut reader = SliceReader::new(response.value()).ok()?;
            let _status = Any::decode(&mut reader).ok()?;
            let token = Any::decode(&mut reader).ok()?;
            attr.values = SetOfVec::try_from(vec![token]).ok()?;
        }
        attrs.push(attr);
    }
    first.unsigned_attrs = Some(SetOfVec::try_from(attrs).ok()?);
    signed.signer_infos = SignerInfos(SetOfVec::try_from(signers).ok()?);
    info.content = Any::encode_from(&signed).ok()?;
    info.to_der().ok()
}

/// The longest distance between the OCSP answer's producedAt and the time-stamp's genTime.
const OCSP_WINDOW_MS: i64 = 5 * 60 * 1000;

/// Extended key usages: a legal entity's certificate, its first head, a person who signs
/// for it.
const EKU_LEGAL: &str = "1.2.398.3.3.4.1.2";
const EKU_FIRST_HEAD: &str = "1.2.398.3.3.4.1.2.1";
const EKU_SIGNER: &str = "1.2.398.3.3.4.1.2.2";

/// The check of the CMS before it is given out: the signature, the time-stamp, the
/// certificate at the time-stamp, its OCSP answer, what it may sign, its chain. The core's
/// verifier reads a time-stamp token, so it checks a copy with the token in place of the
/// whole response.
fn self_check(
    key: &Key,
    order: &Order<'_>,
    cms: &[u8],
    produced_at_ms: Option<i64>,
) -> Result<(), Failure> {
    let with_token = token_form(cms).ok_or(COULD_NOT_CREATE_SIGN)?;
    let report = pki::cms_verify(&VerifyArgs {
        cms: with_token.into(),
        data: (!order.hashed).then(|| order.data.clone().into()),
        at: VerifyAt::TspTime,
        chain: None,
        revocation: Revocation::EmbeddedOcsp,
        first_signer_only: true,
        require_key_usage: Vec::new(),
    })
    .map_err(|_| COULD_NOT_CREATE_SIGN)?;
    let signer = report.signers.first().ok_or(COULD_NOT_CREATE_SIGN)?;
    match &signer.signature {
        Check::Ok => {}
        // A hash in place of the data: the digest is not checked.
        Check::Fail(Problem::NoContent) if order.hashed => {}
        _ => return Err("java.lang.Exception: Message digest verification fail!".into()),
    }
    // Unverified against the original: an exception without a message for a CMS without a
    // (valid) time-stamp, which the module never makes.
    let Some(gen_time_ms) = signer
        .tsp
        .as_ref()
        .filter(|tsp| tsp.check == Check::Ok)
        .and_then(|tsp| tsp.gen_time_ms)
    else {
        return Err(Failure {
            message: None,
            address: None,
        });
    };
    match &signer.validity {
        Check::Fail(Problem::Expired) => return Err("CERTIFICATE_EXPIRED".into()),
        Check::Fail(Problem::NotYetValid) => return Err("CERTIFICATE_NOT_YET_VALID".into()),
        _ => {}
    }
    match &signer.revocation {
        Check::Ok => {}
        Check::Fail(Problem::Revoked { .. }) => return Err("CERTIFICATE_REVOKED".into()),
        Check::Fail(Problem::StatusUnknown) => return Err("CERTIFICATE_UNKNOWN".into()),
        Check::Fail(Problem::ResponderUnverified) => return Err(UNKNOWN_CA.into()),
        _ => return Err(OCSP_HAS_BROKEN.into()),
    }
    match produced_at_ms {
        Some(produced) if (produced - gen_time_ms).abs() <= OCSP_WINDOW_MS => {}
        _ => return Err(OCSP_HAS_BROKEN.into()),
    }
    permissions(key.certificate(), order)?;
    match &signer.path {
        Check::Ok | Check::Skipped => Ok(()),
        Check::Fail(Problem::Expired) => Err("CERTIFICATE_EXPIRED".into()),
        Check::Fail(Problem::NotYetValid) => Err("CERTIFICATE_NOT_YET_VALID".into()),
        Check::Fail(_) => Err(UNKNOWN_CA.into()),
    }
}

/// What the certificate may sign: without `policies`, digitalSignature and
/// nonRepudiation; with them, any one (`AUTH`: digitalSignature and keyEncipherment;
/// `SIGN`: digitalSignature and nonRepudiation); then, unless skipped or issued by the
/// test CA `C=KZ,O=TTC,CN=PKI`, a legal entity's signer.
fn permissions(cert: &[u8], order: &Order<'_>) -> Result<(), Failure> {
    let info = host::cert_info(cert).map_err(|e| e.message)?;
    let usage = &info.key_usage;
    let sign = usage.digital_signature && usage.non_repudiation;
    let auth = usage.digital_signature && usage.key_encipherment;
    match &order.policies {
        None if !sign => return Err("CERTIFICATE_FOR_AUTHENTICATION".into()),
        None => {}
        Some(policies) => {
            let mut allowed = false;
            for policy in policies {
                allowed |= match *policy {
                    "AUTH" => auth,
                    "SIGN" => sign,
                    other => {
                        return Err(format!(
                            "No enum constant kz.metadoc.ncamodule.core.utils.CertificatePolicy.{other}"
                        )
                        .into());
                    }
                };
            }
            if !allowed {
                return Err("CERTIFICATE_NO_HAVE_PERM".into());
            }
        }
    }
    if order.skip_check_permissions {
        return Ok(());
    }
    let details = host::cert_details(cert).map_err(|e| e.message)?;
    // Unverified against the original: the DN text it compares with. The certificates of
    // the state CA (УЦГО), which it also let pass, are not supported by the core.
    if details.issuer_dn == "C=KZ,O=TTC,CN=PKI" {
        return Ok(());
    }
    let has = |oid: &str| info.ext_key_usages.iter().any(|eku| eku == oid);
    if has(EKU_LEGAL) && (has(EKU_SIGNER) || has(EKU_FIRST_HEAD)) {
        Ok(())
    } else {
        Err("CERTIFICATE_NO_HAVE_PERM_FOR_SIGN".into())
    }
}
