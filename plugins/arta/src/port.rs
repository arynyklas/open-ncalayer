//! The methods of `SignService`, reached through the reflective dispatcher.

use oncl_pdk::abi::{
    CmsCerts, CmsOutcome, CoSign, FileMode, HashAlg, MAX_PKI_TIMEOUT_MS, Nonce, OcspOutcome,
    PageRead, PageWrite, PkiMethod, PkiUrl, TimeForm, TsaChoice, TsaSpec,
};
use oncl_pdk::files::{self, ChooseFileArgs, FileFilter};
use oncl_pdk::keys::{
    self, Action, C14n, Filter, Key, KeyOrder, Placement, SignXmlExArgs, Transform, XmlOutput,
};
use oncl_pdk::legacy::{
    self, Args, ErrorBean, LegacyBody, LegacyClass, LegacyMethod, Outcome, Param,
};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::{AddInfo, Request, host, javab64, pki};
use oncl_port_legacy::{
    ACTION_CANCELED, KeyInfoProp, Select, TOKEN_STORAGES, base64, cades, cades_args, fail,
    into_text, knca_types, official_key_info, ok, response, select, split_path,
};
use oncl_port_pki::esedo::{
    CertIdHash, ContentMode, Description, Encapsulate, EsedoInput, FileNames, IssuerRule,
    OcspAnswer, OcspForm, OcspRequest, OcspUrl, Profile, SignerDn, SigningTimeRule, StringKind,
    TimeFrom, ocsp_args, sign_args,
};
use oncl_port_pki::x509text::{kalkan_key_alg_name, ldap_avas};
use std::cell::RefCell;

/// The module's ESEDO CMS: detached, messageDigest the page's digest, the signer
/// certificate; contentType, signingTime (UTCTime, now), the file names joined by `<>`, the
/// signer's DN from Kalkan's DN text, signingDescription PrintableString `ESEDO` and
/// OCTET STRING { BasicOCSPResponse } — the set of the E-Otinish module without
/// signingCertificateV2.
pub const ARTA: Profile = Profile {
    econtent_type: None,
    content: ContentMode::Digest,
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
    // Not observable: the DER of the signer's DN (its X509Name of the subject, rendered here
    // from Kalkan's DN text as the E-Otinish module's); the original builds no ESEDO CMS here.
    signer_dn: Some(SignerDn::Kalkan),
    description: Some(Description {
        text: "ESEDO",
        kind: StringKind::Printable,
    }),
    // Not observable: the BasicOCSPResponse inside an OCTET STRING, as the E-Otinish
    // module's attribute; the original builds no ESEDO CMS here (its OCSP and TSA calls fail).
    ocsp: Some(OcspForm::OctetBasic),
    ocsp_request: Some(ARTA_OCSP),
};

/// The OCSP request before an ESEDO signature: the issuer among the core's CAs (for the
/// original's bundled ones), a SHA-256 `CertID`, an 8-byte nonce, `GET
/// http://ocsp.pki.gov.kz/<request>`; the status is not checked.
pub const ARTA_OCSP: OcspRequest = OcspRequest {
    issuer: IssuerRule::HostCas,
    cert_id_hash: CertIdHash::Fixed(HashAlg::Sha256),
    nonce: Nonce::Random(8),
    method: PkiMethod::Get,
    url: OcspUrl::Default,
    // The original waited without a limit.
    timeout_ms: MAX_PKI_TIMEOUT_MS,
    check: false,
};

/// The time-stamp policy of an ESEDO signature: the TSA's GOST 2015 one.
const TSA_GOST2015_POLICY: &str = "1.2.398.3.3.2.6.4";

/// The key the page chose, with what `getKeyInfo` reads of it.
struct Selected {
    key: Key,
    /// Kalkan's name of the key's algorithm.
    algorithm: String,
    /// The subject's CN.
    cn: Option<String>,
    /// The subject's O.
    o: Option<String>,
}

/// The module's state, for the session (the original kept it, password and all, for the
/// process).
struct State {
    /// The `storageName` of the last `getKeyInfo`/`getFullKeyInfo`, failed or not.
    storage_name: String,
    selected: Option<Selected>,
}

thread_local! {
    static STATE: RefCell<State> = const {
        RefCell::new(State {
            storage_name: String::new(),
            selected: None,
        })
    };
}

/// The module's state lives in [`STATE`].
pub struct SignService;

use LegacyBody::{Private, PrivateTakingObject, Public, Unconvertible};
use Param::Str;

const METHODS: &[LegacyMethod<SignService>] = &[
    method("getActiveTokens", 0, Public(&[], get_active_tokens)),
    method(
        "checkModuleAvailability",
        0,
        Public(&[], check_module_availability),
    ),
    method("getKeyInfo", 1, Public(&[Str], get_key_info)),
    method("getFullKeyInfo", 1, Public(&[Str], get_full_key_info)),
    method("signFilePath", 2, Public(&[Str, Str], sign_file_path)),
    method("signBase64File", 2, Public(&[Str, Str], sign_base64_file)),
    method("signDocument", 3, Public(&[Str, Str, Str], sign_document)),
    method("showFileChooser", 2, Public(&[Str, Str], show_file_chooser)),
    method("signXML", 1, Public(&[Str], sign_xml)),
    method("setKeyInfoServices", 1, Unconvertible),
    method("setKeyInfoSetterService", 1, Unconvertible),
    method("sign", 1, Private),
    method("signBase64FileStr", 1, Private),
    method("saveFile", 3, Private),
    method("createCAdES", 4, Private),
    method("getFileFromBase64String", 2, Private),
    method("getFileFromPath", 1, Private),
    method("getBytes", 1, Private),
    method("chooseFile", 2, Private),
    method("getJson", 1, PrivateTakingObject),
    method("setSelectedKey", 1, Private),
];

const fn method(
    name: &'static str,
    arity: usize,
    body: LegacyBody<SignService>,
) -> LegacyMethod<SignService> {
    LegacyMethod { name, arity, body }
}

const CLASS: LegacyClass<SignService> = LegacyClass {
    dispatcher: "kz.arta.synergy.agent.SynergySignActivator",
    target: "kz.arta.synergy.signmodule.SignService",
    methods: METHODS,
    error_bean: ErrorBean::ResponseMessage,
    no_such_method: legacy::no_such_method_exception,
    before_invoke: None,
};

/// The plugin's handler.
pub fn handle(request: &Request) -> String {
    into_text(legacy::dispatch(
        &SignService,
        &CLASS,
        &request.text,
        &request.add_info(),
    ))
}

fn failed(message: &str) -> Outcome {
    fail(Some(message))
}

/// Java's `trim().isEmpty()`.
fn blank(s: &str) -> bool {
    s.trim_matches(|c| c <= ' ').is_empty()
}

/// `getActiveTokens()`: the token storages with a connected token.
fn get_active_tokens(_: &SignService, _: &Args<'_>, _: &AddInfo) -> Outcome {
    let active: Vec<JValue> = TOKEN_STORAGES
        .into_iter()
        .filter(|name| keys::terminals(name).is_ok_and(|readers| !readers.is_empty()))
        .map(JValue::from)
        .collect();
    ok(JValue::Arr(active))
}

/// `checkModuleAvailability()`: `OK`, not JSON.
fn check_module_availability(_: &SignService, _: &Args<'_>, _: &AddInfo) -> Outcome {
    Outcome::Text("OK".to_owned())
}

/// The order the module's `KeyInfo` bean puts the properties that share a `HashMap`
/// bucket in.
const KEY_INFO_PUTS: [KeyInfoProp; 5] = [
    KeyInfoProp::KeyId,
    KeyInfoProp::Alias,
    KeyInfoProp::Pem,
    KeyInfoProp::Algorithm,
    KeyInfoProp::SubjectDn,
];

/// The chosen `key` with the algorithm and the subject's CN and O of its certificate, the
/// subject read from Kalkan's DN text as an `LdapName`.
fn selected(key: Key) -> Result<Selected, String> {
    let info = host::cert_info(key.certificate()).map_err(|e| e.message)?;
    let details = host::cert_details(key.certificate()).map_err(|e| e.message)?;
    let algorithm = kalkan_key_alg_name(&info.spki_alg_oid)
        .unwrap_or(&info.spki_alg_oid)
        .to_owned();
    let (mut cn, mut o) = (None, None);
    // `getRdns()` runs from the last RDN of the text to the first, so of repeated types the
    // first in the text stays. Not observable: the walk over `getRdns()`; no key to compare
    // with repeats a type.
    for (kind, value) in ldap_avas(&details.subject_dn) {
        match kind.as_str() {
            "CN" => cn = Some(value),
            "O" => o = Some(value),
            _ => {}
        }
    }
    Ok(Selected {
        key,
        algorithm,
        cn,
        o,
    })
}

/// The storage and key dialogs (no key type filter, the newest first): the key, kept for
/// the session. `storageName` is kept even when this fails.
fn choose_key(storage: &str) -> Result<(), Outcome> {
    STATE.with(|s| s.borrow_mut().storage_name = storage.to_owned());
    let key = select(Select {
        storage,
        action: Action::KeyInfo,
        knca_types: knca_types(""),
        order: KeyOrder::NewestFirst,
        // The module checks nothing of the certificate.
        filter: Filter {
            allow_expired: true,
            chain: Some(Vec::new()),
            allow_revoked: true,
            ..Filter::default()
        },
    })
    .map_err(|message| failed(&message))?
    .ok_or_else(|| failed(ACTION_CANCELED))?;
    let selected = selected(key).map_err(|message| failed(&message))?;
    STATE.with(|s| s.borrow_mut().selected = Some(selected));
    Ok(())
}

/// The kept key, if the page chose one.
fn with_selected<T>(f: impl FnOnce(&Selected) -> T) -> Option<T> {
    STATE.with(|s| s.borrow().selected.as_ref().map(f))
}

/// `getKeyInfo(storageName)`: `{"code":"200","signInfoObject":{pem, cn, algorithm, o}}`.
fn get_key_info(_: &SignService, args: &Args<'_>, _: &AddInfo) -> Outcome {
    if let Err(outcome) = choose_key(args.str(0)) {
        return outcome;
    }
    let object = with_selected(|selected| {
        let mut object = JObject::hash_map();
        object.put("pem", base64(selected.key.certificate()));
        object.put_opt("cn", selected.cn.as_deref());
        object.put("algorithm", selected.algorithm.as_str());
        object.put_opt("o", selected.o.as_deref());
        object
    });
    let mut bean = response(None, "200", None);
    bean.put_opt("signInfoObject", object);
    Outcome::Json(bean)
}

/// `getFullKeyInfo(storageName)`: the official `KeyInfo`.
fn get_full_key_info(_: &SignService, args: &Args<'_>, _: &AddInfo) -> Outcome {
    if let Err(outcome) = choose_key(args.str(0)) {
        return outcome;
    }
    let info = with_selected(|selected| {
        official_key_info(
            selected.key.alias(),
            selected.key.certificate(),
            KEY_INFO_PUTS,
        )
    });
    match info {
        Some(Ok(info)) => ok(info),
        Some(Err(message)) => failed(&message),
        None => failed(ACTION_CANCELED),
    }
}

/// The kept key for a signing method: none, or a blank `storageName`, is `EXCEPTION`.
fn signing_key<T>(f: impl FnOnce(&Key) -> Result<T, String>) -> Result<T, String> {
    let storage_blank = STATE.with(|s| blank(&s.borrow().storage_name));
    if storage_blank {
        return Err("EXCEPTION".to_owned());
    }
    with_selected(|selected| f(&selected.key)).unwrap_or_else(|| Err("EXCEPTION".to_owned()))
}

/// A time-stamped CAdES of `data`, attached, as Kalkan's `createCAdES` and `applyCAdEST`.
fn cades_t(key: &Key, data: &[u8]) -> Result<Vec<u8>, String> {
    cades(
        key,
        cades_args(key.handle(), data, true, CoSign::Auto, true),
    )
}

/// `signFilePath(filePath, base64)`: the file's CAdES-T with the kept key, written as
/// `<name>.cms` into the folder that is the path with every occurrence of the file name
/// removed (so a folder named like the file goes too, as in the original); `base64` is
/// ignored.
fn sign_file_path(_: &SignService, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let path = args.str(0);
    if blank(path) {
        return failed("404");
    }
    let signed = signing_key(|key| {
        let data = match files::page_read(path) {
            Ok(PageRead::Ok(file)) => file.data.into_vec(),
            _ => return Err("file.ioException".to_owned()),
        };
        let cms = cades_t(key, &data)?;
        let (name, _) = split_path(path);
        let dir = path.replace(name, "");
        let file_name = if name.ends_with(".cms") {
            name.to_owned()
        } else {
            format!("{name}.cms")
        };
        let io = || "file.ioException".to_owned();
        match files::page_write(&dir, &file_name, &cms).map_err(|_| io())? {
            PageWrite::Written(path) => Ok(path),
            // A name the folder cannot take: the original's fallback name.
            PageWrite::Invalid => match files::page_write(&dir, "signedCMS.cms", &cms) {
                Ok(PageWrite::Written(path)) => Ok(path),
                _ => Err(io()),
            },
            PageWrite::Declined => Err(io()),
        }
    });
    match signed {
        Ok(path) => Outcome::Json(response(Some(path.into()), "200", Some("cms.signed"))),
        Err(message) => failed(&message),
    }
}

/// `signBase64File(base64, fileName)`: the CAdES-T of the data with the kept key; a failed
/// signature (no key included) is an empty `responseObject`, as the original swallowed it.
fn sign_base64_file(_: &SignService, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let text = args.str(0);
    if blank(text) {
        return failed("404");
    }
    let Ok(data) = javab64::decode_java(text) else {
        return failed("internalError");
    };
    let cms = signing_key(|key| cades_t(key, &data))
        .map(|cms| base64(&cms))
        .unwrap_or_default();
    Outcome::Json(response(Some(cms.into()), "200", Some("cms.signed")))
}

/// `signDocument(digest, type, dataForSign)`: `INFO` (any case) is the text `{"empty":false}`
/// once a key is chosen (the module's key-info map is not given out), `SIGN` a raw
/// signature of `dataForSign` and, for a `digest` object with file names, an ESEDO CMS of
/// its digest. Without a key, and on any failure of `SIGN`, the original threw.
fn sign_document(_: &SignService, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let kind = args.str(1);
    if kind.eq_ignore_ascii_case("INFO") {
        let info = with_selected(|_| {
            let mut object = JObject::hash_map();
            object.put("empty", false);
            object.to_json()
        });
        return match info {
            Some(text) => ok(text),
            None => Outcome::Thrown,
        };
    }
    if !kind.eq_ignore_ascii_case("SIGN") {
        return failed("TYPE NOT RECOGNIZED");
    }
    let signed = with_selected(|selected| sign(&selected.key, args.str(0), args.str(2)));
    match signed {
        Some(Ok(object)) => ok(object),
        _ => Outcome::Thrown,
    }
}

/// Kalkan's base64 of a `SIGN` reply: lines of 60 characters, `\r\n` between them.
fn kalkan_base64(bytes: &[u8]) -> String {
    let text = base64(bytes);
    text.as_bytes()
        .chunks(60)
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// The `KeyStore` bean of a `SIGN`: `dataForSign`, `signedData` (the raw signature),
/// `certificate`, `id` (the serial number, a JSON number) and `esedoSign`.
fn sign(key: &Key, digest: &str, data_for_sign: &str) -> Result<JObject, String> {
    let esedo_sign = match digest.is_empty() {
        true => None,
        false => esedo(key, digest)?,
    };
    let data = javab64::decode_kalkan(data_for_sign)?;
    // Kalkan signs with the key's algorithm name (`RSA` for an RSA key); the core's raw
    // signature of the key's algorithm is the same: RSA bytes are equal (PKCS#1 v1.5 is
    // deterministic), a GOST signature matches in form.
    let signed = key.sign_raw(&data).map_err(|e| e.message)?;
    let details = host::cert_details(key.certificate()).map_err(|e| e.message)?;
    let mut object = JObject::hash_map();
    object.put("dataForSign", data_for_sign);
    object.put("signedData", kalkan_base64(&signed));
    object.put("certificate", kalkan_base64(key.certificate()));
    object.put("id", JValue::Raw(details.serial_dec));
    object.put_opt("esedoSign", esedo_sign);
    Ok(object)
}

/// The ESEDO CMS of the `digest` text (`{"digest":<base64>,"fileNames":[…]}`), if it has
/// file names: `None` without them.
fn esedo(key: &Key, digest: &str) -> Result<Option<String>, String> {
    let JValue::Obj(object) = orgjson::parse(digest)? else {
        return Err("not an object".to_owned());
    };
    let object = object.to_map();
    let names = match orgjson::opt_array(&object, "fileNames") {
        Some(names) if digest.contains("fileNames") && !names.is_empty() => names,
        _ => return Ok(None),
    };
    let names = (0..names.len())
        .map(|i| orgjson::array_get_string(names, i))
        .collect::<Result<Vec<&str>, String>>()?;
    let hash = javab64::decode_kalkan(orgjson::get_string(&object, "digest")?)?;
    let cert = key.certificate();
    let details = host::cert_details(cert).map_err(|e| e.message)?;
    let outcome = pki::ocsp_fetch(&ocsp_args(&ARTA_OCSP, cert, &[])?).map_err(|e| e.message)?;
    match &outcome {
        OcspOutcome::Failed(failure) => return Err(failure.detail.clone()),
        OcspOutcome::Ok {
            response_status, ..
        } if *response_status != 0 => {
            return Err(format!("Unsuccessful request. Status: {response_status}"));
        }
        OcspOutcome::Ok { .. } => {}
    }
    let input = EsedoInput {
        cert,
        kalkan_dn: Some(&details.subject_dn),
        file_names: &names,
        ocsp: OcspAnswer::from_outcome(&outcome),
        data: &hash,
        ..EsedoInput::default()
    };
    let mut args = sign_args(&ARTA, &input, key.handle())?;
    args.timestamp = Some(TsaChoice::Custom(tsa()?));
    match key.sign_cms_ex(args) {
        Ok(CmsOutcome::Signed(cms)) => Ok(Some(base64(&cms))),
        Ok(CmsOutcome::TspFailed(failure)) => Err(failure.detail),
        Err(e) => Err(e.message),
    }
}

/// The TSA of an ESEDO signature: `POST http://tsp.pki.gov.kz` as
/// `application/timestamp-query`, a GOST 34.311 imprint of the signature for every key, the
/// GOST 2015 policy, the current time in milliseconds as the nonce, `certReq`.
fn tsa() -> Result<TsaSpec, String> {
    let now = host::now().map_err(|e| e.message)?;
    Ok(TsaSpec {
        url: PkiUrl::Default,
        method: PkiMethod::Post {
            content_type: Some("application/timestamp-query".to_owned()),
        },
        hash: HashAlg::Gost34311,
        policy: Some(TSA_GOST2015_POLICY.to_owned()),
        nonce: Nonce::Value(java_big_integer(now).into()),
        cert_req: true,
        retries: 0,
        // The original waited without a limit.
        timeout_ms: MAX_PKI_TIMEOUT_MS,
        check_skew_ms: None,
        require_tsa_eku: false,
    })
}

/// `BigInteger.valueOf(n).toByteArray()`: big-endian two's complement, minimal.
fn java_big_integer(n: i64) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (b, next) = (bytes[start], bytes[start + 1]);
        if (b == 0x00 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    bytes[start..].to_vec()
}

/// `showFileChooser(fileExtension, currentDirectory)`: the official chooser — a folder for
/// an empty extension or `DIRECTORY`, else files of the type of that name; the path, or
/// `action.canceled`.
fn show_file_chooser(_: &SignService, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let extension = args.str(0);
    let (mode, extensions): (FileMode, &[&str]) = match extension {
        "" | "DIRECTORY" => (FileMode::Directory, &[]),
        "CRL" => (FileMode::Open, &["crl"]),
        "CER" => (FileMode::Open, &["der", "cer"]),
        "P12" => (FileMode::Open, &["p12"]),
        "KEYSTORE" => (FileMode::Open, &["pfx", "p12", "bin", "jks"]),
        "JKS" => (FileMode::Open, &["jks"]),
        "ALL" => (FileMode::Open, &[]),
        other => {
            return failed(&format!(
                "No enum constant kz.arta.synergy.gui.fileChooser.FileChooser.FileType.{other}"
            ));
        }
    };
    let filters = match extensions.is_empty() {
        true => Vec::new(),
        false => vec![FileFilter {
            name: extension.to_owned(),
            extensions: extensions.iter().map(|e| (*e).to_owned()).collect(),
        }],
    };
    let directory = args.str(1);
    let chosen = files::choose(&ChooseFileArgs {
        mode,
        title: None,
        filters,
        initial_dir: (!directory.is_empty()).then(|| directory.to_owned()),
    });
    match chosen {
        Ok(Some(path)) => ok(path.path),
        _ => failed(ACTION_CANCELED),
    }
}

/// `signXML(xml)`: the document with an enveloped signature of the kept key in its first
/// node, as the module's XML library writes it (SignedInfo in Canonical XML 1.0, the
/// reference's transforms enveloped-signature and Canonical XML with comments), the whole
/// document serialized again — not JSON; `null` on any failure, no key included.
fn sign_xml(_: &SignService, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let xml = args.str(0);
    let signed = with_selected(|selected| xml_signature(&selected.key, xml));
    match signed {
        Some(Ok(xml)) => Outcome::Text(xml),
        _ => Outcome::Null,
    }
}

fn xml_signature(key: &Key, xml: &str) -> Result<String, String> {
    let details = host::cert_details(key.certificate()).map_err(|e| e.message)?;
    // The module's URIs: RSA SHA-256 and GOST 34.310-2004 as Kalkan's; it named the GOST
    // 2004 ones for every other key too, so a GOST 2015 key got no signature from it (`null`).
    // Such a key gets Kalkan's URIs for its algorithm here (registry.toml). SHA-1 RSA keys
    // are refused by the core.
    let (signature_method, digest_method) = match details.signing_alg.as_deref() {
        Some("rsa_sha256") => (
            Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
            Some("http://www.w3.org/2001/04/xmlenc#sha256"),
        ),
        Some("gost2004") => (
            Some("http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311"),
            Some("http://www.w3.org/2001/04/xmldsig-more#gost34311"),
        ),
        _ => (None, None),
    };
    // The original's XML library writes no line breaks inside the signature (observed with
    // an RSA key); the bytes of the serialized document are the core's.
    let signed = key
        .sign_xml_ex(SignXmlExArgs {
            handle: key.handle(),
            xml: xml.as_bytes().to_vec().into(),
            element: None,
            parent: None,
            namespaces: Vec::new(),
            other_prefix_uri: None,
            placement: Placement::FirstChildOfDocument,
            signature_method: signature_method.map(str::to_owned),
            digest_method: digest_method.map(str::to_owned),
            signed_info_c14n: Some(C14n::Inclusive),
            transforms: Some(vec![
                Transform::Enveloped,
                Transform::C14n(C14n::InclusiveWithComments),
            ]),
            signature_id: None,
            signing_time_object: None,
            strip_whitespace: true,
            base64_line_breaks: None,
            output: XmlOutput::Serialize {
                declaration: true,
                standalone_no: true,
                trim: true,
            },
        })
        .map_err(|e| e.message)?;
    String::from_utf8(signed).map_err(|e| e.to_string())
}
