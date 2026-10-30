//! The methods of `SignUtils`, reached through the reflective dispatcher.

use crate::keyinfo::{Facts, KeyInfo};
use oncl_pdk::keys::{Action, Filter, Key, KeyOrder};
use oncl_pdk::legacy::{
    self, Args, ErrorBean, LegacyBody, LegacyClass, LegacyMethod, Outcome, Param,
};
use oncl_pdk::orgjson::{JObject, JValue};
use oncl_pdk::{AddInfo, Request, host, javab64, keys};
use oncl_port_legacy::{
    ACTION_CANCELED, Select, TOKEN_STORAGES, base64, cades, cades_args, common_name, fail,
    into_text, knca_types, name_values, ok, response, select, sign_xml, subject_and_issuer,
};
use oncl_port_pki::x509text::{kalkan_key_alg_name, x500_principal};

/// The module's state: none.
pub struct SignUtils;

use LegacyBody::{Private, PrivateTakingObject, Public, Unconvertible};
use Param::{Bool, Str, Strs};

const SIGN_XML: [Param; 6] = [Str, Str, Str, Str, Str, Str];
const SIGN_XMLS: [Param; 6] = [Str, Str, Strs, Str, Str, Str];
const CMS: [Param; 6] = [Str, Str, Str, Bool, Bool, Str];
const CMSES: [Param; 6] = [Str, Str, Strs, Bool, Bool, Str];
const RAW: [Param; 4] = [Str, Str, Str, Str];
const RAWS: [Param; 4] = [Str, Str, Strs, Str];

/// `SignUtils.getDeclaredMethods()`.
const METHODS: &[LegacyMethod<SignUtils>] = &[
    method("getActiveTokens", 0, Public(&[], get_active_tokens)),
    method("getKeyInfo", 1, Public(&[Str], get_key_info)),
    method("TestConnect", 0, Public(&[], test_connect)),
    method("TestKeyOwner", 3, Public(&[Str, Str, Str], test_key_owner)),
    method("signXml", 6, Public(&SIGN_XML, sign_xml_method)),
    method("signXmls", 6, Public(&SIGN_XMLS, sign_xmls)),
    method("createCmsFromBase64", 6, Public(&CMS, create_cms)),
    method("createCmsesFromBase64", 6, Public(&CMSES, create_cmses)),
    method("createRawSignFromBase64", 4, Public(&RAW, create_raw)),
    method("createRawsSignFromBase64", 4, Public(&RAWS, create_raws)),
    method("setKeyInfoServices", 1, Unconvertible),
    method("setKeyInfoSetterService", 1, Unconvertible),
    method("saveKey", 2, Private),
    method("checkSelectedkeyStoreEntry", 4, Private),
    method("getJson", 1, PrivateTakingObject),
];

const fn method(
    name: &'static str,
    arity: usize,
    body: LegacyBody<SignUtils>,
) -> LegacyMethod<SignUtils> {
    LegacyMethod { name, arity, body }
}

const CLASS: LegacyClass<SignUtils> = LegacyClass {
    dispatcher: "kz.rating1c.edo.NCALayerCommonActivator",
    target: "kz.rating1c.edo.SignUtils",
    methods: METHODS,
    error_bean: ErrorBean::ResponseMessage,
    no_such_method: legacy::no_such_method_exception,
    before_invoke: None,
};

/// The plugin's handler.
pub fn handle(request: &Request) -> String {
    into_text(legacy::dispatch(
        &SignUtils,
        &CLASS,
        &request.text,
        &request.add_info(),
    ))
}

/// A method's own failure: `{"code":"500","message":…}`.
type Failed = Outcome;

fn failed(message: impl AsRef<str>) -> Failed {
    fail(Some(message.as_ref()))
}

/// `getActiveTokens()`: the token storages with a connected token.
fn get_active_tokens(_: &SignUtils, _: &Args<'_>, _: &AddInfo) -> Outcome {
    let active: Vec<JValue> = TOKEN_STORAGES
        .into_iter()
        .filter(|name| keys::terminals(name).is_ok_and(|readers| !readers.is_empty()))
        .map(JValue::from)
        .collect();
    ok(JValue::Arr(active))
}

/// `TestConnect()`.
fn test_connect(_: &SignUtils, _: &Args<'_>, _: &AddInfo) -> Outcome {
    ok("Plugin connected successfully: 1.6.")
}

/// The storage and key dialogs: the key, `None` if cancelled.
fn choose(storage: &str, key_type: &str, action: Action) -> Result<Option<Key>, Failed> {
    select(Select {
        storage,
        action,
        knca_types: knca_types(key_type),
        order: KeyOrder::NewestFirst,
        // The original takes the key without a chain or revocation check and checks the
        // validity itself.
        filter: Filter {
            allow_expired: true,
            chain: Some(Vec::new()),
            allow_revoked: true,
            ..Filter::default()
        },
    })
    .map_err(failed)
}

/// The dialogs' action for `key_type`.
fn signing_action(key_type: &str) -> Action {
    if key_type == "AUTHENTICATION" {
        Action::Authenticate
    } else {
        Action::Sign
    }
}

/// The module's `KeyInfo` of `key`.
fn key_info(key: &Key) -> Result<KeyInfo, Failed> {
    facts(key).and_then(KeyInfo::new).map_err(failed)
}

fn facts(key: &Key) -> Result<Facts, String> {
    let der = key.certificate();
    let info = host::cert_info(der).map_err(|e| e.message)?;
    let details = host::cert_details(der).map_err(|e| e.message)?;
    let (subject, issuer) = subject_and_issuer(der)?;
    Ok(Facts {
        alias: key.alias().to_owned(),
        key_id: details.ski_hex,
        algorithm: kalkan_key_alg_name(&info.spki_alg_oid).map(str::to_owned),
        subject_cn: info.subject_cn,
        subject_dn: x500_principal(&subject)?,
        serial: info.serial_hex,
        issuer_cn: common_name(&issuer),
        issuer_dn: details.issuer_dn,
        not_after_ms: info.not_after,
        not_before_ms: info.not_before,
        aki: details.aki_hex,
        pem: info.pem,
        ous: name_values(&subject, "2.5.4.11")?,
        serial_numbers: name_values(&subject, "2.5.4.5")?,
    })
}

/// `checkSelectedkeyStoreEntry`: the owner check for a non-empty `bin`, then the validity
/// now; each failure adds `" " + text` to the result.
fn check(key: &Key, bin: &str) -> Result<String, Failed> {
    let mut errors = String::new();
    if !bin.is_empty() && !key_info(key)?.owned_by(bin) {
        errors.push_str(" Ключ не принадлежит указанному БИН");
    }
    let info = host::cert_info(key.certificate()).map_err(|e| failed(e.message))?;
    let now = host::now().map_err(|e| failed(e.message))?;
    if now < info.not_before {
        errors.push_str(" Срок действия сертификата еще не наступил");
    } else if now > info.not_after {
        errors.push_str(" Срок действия сертификата истек");
    }
    Ok(errors)
}

/// The signing methods' prologue: the dialogs, then the owner and validity check.
fn signing_key(storage: &str, key_type: &str, bin: &str) -> Result<Key, Failed> {
    let key = choose(storage, key_type, signing_action(key_type))?
        .ok_or_else(|| failed(ACTION_CANCELED))?;
    let errors = check(&key, bin)?;
    if !errors.is_empty() {
        return Err(failed(format!("{ACTION_CANCELED}.{errors}")));
    }
    Ok(key)
}

fn outcome(result: Result<Outcome, Failed>) -> Outcome {
    result.unwrap_or_else(|failed| failed)
}

/// `getKeyInfo(storageName)`.
fn get_key_info(_: &SignUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    outcome((|| {
        let key =
            choose(args.str(0), "", Action::KeyInfo)?.ok_or_else(|| failed(ACTION_CANCELED))?;
        Ok(ok(key_info(&key)?.bean()))
    })())
}

/// `TestKeyOwner(storageName, keyType, BINControl)`: cancelling is a `500` without a
/// message.
fn test_key_owner(_: &SignUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    outcome((|| {
        let Some(key) = choose(args.str(0), args.str(1), Action::KeyInfo)? else {
            return Ok(fail(None));
        };
        let info = key_info(&key)?;
        let errors = check(&key, args.str(2))?;
        let message = format!("IsKeysValid result: {}. {errors}", errors.is_empty());
        Ok(Outcome::Json(response(
            Some(JValue::Obj(info.bean())),
            "200",
            Some(&message),
        )))
    })())
}

/// `signXml(storageName, keyType, xml, tbsXPath, parentXPath, BINControl)`.
fn sign_xml_method(_: &SignUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    outcome((|| {
        let key = signing_key(args.str(0), args.str(1), args.str(5))?;
        let signed = sign_xml(&key, args.str(2), args.str(3), args.str(4)).map_err(failed)?;
        Ok(ok(signed))
    })())
}

/// `signXmls(storageName, keyType, xmls, tbsXPath, parentXPath, BINControl)`.
fn sign_xmls(_: &SignUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    outcome((|| {
        let key = signing_key(args.str(0), args.str(1), args.str(5))?;
        let signed = args
            .strs(2)
            .iter()
            .map(|xml| sign_xml(&key, xml, args.str(3), args.str(4)).map(JValue::from))
            .collect::<Result<Vec<_>, _>>()
            .map_err(failed)?;
        Ok(ok(JValue::Arr(signed)))
    })())
}

/// A CAdES of the base64 `data`, time-stamped with `with_tsa`.
fn one_cms(key: &Key, data: &str, attached: bool, with_tsa: bool) -> Result<JValue, Failed> {
    let data = javab64::decode_java(data).map_err(failed)?;
    let args = cades_args(key.handle(), &data, attached, Default::default(), with_tsa);
    let cms = cades(key, args).map_err(failed)?;
    Ok(JValue::from(base64(&cms)))
}

/// `createCmsFromBase64(storageName, keyType, base64, attached, withTSA, BINControl)`.
fn create_cms(_: &SignUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    outcome((|| {
        let key = signing_key(args.str(0), args.str(1), args.str(5))?;
        Ok(ok(one_cms(&key, args.str(2), args.bool(3), args.bool(4))?))
    })())
}

/// `createCmsesFromBase64(storageName, keyType, base64s, attached, withTSA, BINControl)`.
fn create_cmses(_: &SignUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    outcome((|| {
        let key = signing_key(args.str(0), args.str(1), args.str(5))?;
        let signed = args
            .strs(2)
            .iter()
            .map(|data| one_cms(&key, data, args.bool(3), args.bool(4)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ok(JValue::Arr(signed)))
    })())
}

/// A raw signature of the base64 `data`: `SHA256withRSA` for RSA, the key's own algorithm
/// for GOST.
fn one_raw(key: &Key, data: &str) -> Result<String, Failed> {
    let data = javab64::decode_java(data).map_err(failed)?;
    // Unverified against the original: Kalkan's encoding of GOST raw signatures.
    let signature = key.sign_raw(&data).map_err(|e| failed(e.message))?;
    Ok(base64(&signature))
}

/// `{"signResult":…,"signerCert":<KeyInfo.toString()>}`.
fn raw_reply(key: &Key, result: JValue) -> Result<Outcome, Failed> {
    let mut object = JObject::hash_map();
    object.put("signResult", result);
    object.put("signerCert", key_info(key)?.lombok());
    Ok(ok(object))
}

/// `createRawSignFromBase64(storageName, keyType, base64, BINControl)`.
fn create_raw(_: &SignUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    outcome((|| {
        let key = signing_key(args.str(0), args.str(1), args.str(3))?;
        let signature = one_raw(&key, args.str(2))?;
        raw_reply(&key, JValue::from(signature))
    })())
}

/// `createRawsSignFromBase64(storageName, keyType, base64s, BINControl)`: `signResult` is
/// the JSON text of the array of signatures.
fn create_raws(_: &SignUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    outcome((|| {
        let key = signing_key(args.str(0), args.str(1), args.str(3))?;
        let signatures = args
            .strs(2)
            .iter()
            .map(|data| one_raw(&key, data).map(JValue::from))
            .collect::<Result<Vec<_>, _>>()?;
        raw_reply(&key, JValue::from(JValue::Arr(signatures).to_json()))
    })())
}
