//! `PKIExtras.sign`: the arguments as the original reads them with org.json, then the
//! storage → key → sign flow of the core's windows.

use crate::Core;
use crate::args::{
    STORAGES, class_cast, decode_base64, encode_base64, get_array, get_object, get_string,
    json_exception, locale, null_pointer, opt_bool, pem, pem_or_base64, storage_list,
};
use crate::failures::{
    certificate_parsing_failure, cms_failure, invalid_signing_params, key_failure, signing_failure,
    tsp_failure, xml_failure,
};
use oncl_pdk::abi::{
    Action, Bytes, CmsCerts, CmsContent, CmsOutcome, CmsOutput, CoSign, Filter, FlowArgs,
    FlowChecks, FlowFile, FlowNone, FlowOrder, FlowReaders, FlowStart, SignCmsExArgs, SignedAttrs,
    SigningTime, TimeForm, TimeSource, TsaChoice,
};
use oncl_pdk::invoker::{CallResult, Failure};
use oncl_pdk::orgjson::opt_string;
use oncl_pdk::serde_json::{Map, Value, json};
use std::borrow::Cow;
use std::collections::BTreeSet;

/// clientAuth: asking for it makes the windows an authentication.
const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

/// What to produce.
enum Format {
    Cms {
        encapsulate: bool,
        digested: bool,
        timestamp: bool,
    },
    Raw {
        output_cert: bool,
    },
    /// Enveloped XMLDSig of each (UTF-8, never decoded) document.
    Xml,
}

/// A parsed `sign` request; `data` borrows from the request unless base64-decoded.
struct SignRequest<'a> {
    locale: oncl_pdk::Locale,
    flow: FlowArgs,
    format: Format,
    data: Vec<Cow<'a, [u8]>>,
}

/// `PKIExtras.sign`.
pub(crate) fn sign<C: Core>(core: &C, args: &Map<String, Value>) -> CallResult {
    let request = SignRequest::parse(core, args)?;
    core.set_locale(request.locale);
    let Some(key) = core.choose_key(&request.flow) else {
        return Ok(json!({}));
    };
    let result = match request.format {
        Format::Cms {
            encapsulate,
            digested,
            timestamp,
        } => {
            // One signingTime for every document, as the original signs them.
            let at = core.now();
            let pems = request
                .data
                .into_iter()
                .map(|data| {
                    let args = cms_args(data.into_owned(), encapsulate, digested, timestamp, at);
                    sign_cms(core, &key, args).map(Value::String)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Value::Array(pems)
        }
        Format::Raw { output_cert } => sign_raw(core, &key, &request.data, output_cert)?,
        Format::Xml => Value::from(
            request
                .data
                .iter()
                .map(|xml| sign_xml(core, &key, xml))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };
    Ok(json!({ "result": result }))
}

impl<'a> SignRequest<'a> {
    /// Reads the arguments in the original's order, so the first missing one is reported.
    fn parse(core: &impl Core, args: &'a Map<String, Value>) -> Result<Self, Failure> {
        let storages = match args.get("allowedStorages") {
            Some(Value::Array(names)) => storage_list(names)?,
            _ => STORAGES.map(str::to_owned).to_vec(),
        };
        let locale = locale(args);

        let format = get_string(args, "format")?;
        let signing_params = get_object(args, "signingParams")?;
        // xml reads only allowRevoked and allowExpired; its data is never decoded.
        let decode = format != "xml" && opt_bool(signing_params, "decode", false);
        // Read for cms and xml; raw keys are always checked.
        let allow_revoked =
            matches!(format, "cms" | "xml") && opt_bool(signing_params, "allowRevoked", false);
        let allow_expired = format == "xml" && opt_bool(signing_params, "allowExpired", false);
        let format = match format {
            "cms" => Format::Cms {
                encapsulate: opt_bool(signing_params, "encapsulate", true),
                digested: opt_bool(signing_params, "digested", false),
                // Only its presence counts; the profile is always the basics one.
                timestamp: matches!(signing_params.get("tsaProfile"), Some(Value::Object(_))),
            },
            "raw" => Format::Raw {
                output_cert: opt_bool(signing_params, "outputCert", false),
            },
            "xml" => Format::Xml,
            _ => return Err(invalid_signing_params()),
        };

        let data: Vec<&str> = match args.get("data") {
            Some(Value::Array(items)) => items
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    item.as_str()
                        .ok_or_else(|| json_exception(format!("JSONArray[{i}] is not a String.")))
                })
                .collect::<Result<_, _>>()?,
            _ => vec![get_string(args, "data")?],
        };

        let signer_params = get_object(args, "signerParams")?;
        let chain = parse_chain(core, signer_params)?;
        // `toList().stream().map(Object::toString)`: a null entry is a NullPointerException.
        let ext_key_usages = get_array(signer_params, "extKeyUsageOids")?
            .iter()
            .map(|oid| match oid {
                Value::String(s) => Ok(s.clone()),
                Value::Null => Err(null_pointer()),
                other => Ok(other.to_string()),
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let action = if ext_key_usages.contains(CLIENT_AUTH) {
            Action::Authenticate
        } else {
            Action::Sign
        };
        let filter = Filter {
            ext_key_usages: ext_key_usages.into_iter().collect(),
            iin: opt_string(signer_params, "iin").unwrap_or_default(),
            bin: opt_string(signer_params, "bin").unwrap_or_default(),
            serial_number: opt_string(signer_params, "serialNumber").unwrap_or_default(),
            allow_expired,
            chain,
            allow_revoked,
        };

        // Invalid base64 fails before the windows (the original fails after them, with the
        // same code).
        let data = data
            .into_iter()
            .map(|item| {
                if decode {
                    decode_base64(item).map(Cow::Owned).map_err(signing_failure)
                } else {
                    Ok(Cow::Borrowed(item.as_bytes()))
                }
            })
            .collect::<Result<_, _>>()?;

        Ok(SignRequest {
            locale,
            flow: FlowArgs {
                action,
                storages,
                readers: FlowReaders::Live,
                start: FlowStart::Recent,
                remember: true,
                detail: None,
                non_empty_password: false,
                inner_password_policy: false,
                same_storage: false,
                file: FlowFile::Open,
                knca_types: None,
                none: FlowNone::NoKeys,
                empty_is_none: false,
                order: FlowOrder::Store,
                checks: FlowChecks::Live {
                    filter: Box::new(filter),
                    more: Box::default(),
                },
                skip_blocked_reader: false,
            },
            format,
            data,
        })
    }
}

/// `signerParams.chain`, read like the original's `optJSONArray`: anything but an array
/// (absent, `null`, another type) is no chain (`None`: the NCA's CAs). Entries are
/// certificates as text ([`pem_or_base64`]); the first bad entry fails the request: an
/// unparsable string with CERTIFICATE_PARSING_FAILURE, any other value as the original's
/// `(String) e` and `X509Util.getX509Certificate` fail on it (INVOCATION_ERROR).
fn parse_chain(
    core: &impl Core,
    signer_params: &Map<String, Value>,
) -> Result<Option<Vec<Bytes>>, Failure> {
    let Some(Value::Array(entries)) = signer_params.get("chain") else {
        return Ok(None);
    };
    entries
        .iter()
        .map(|entry| match entry {
            Value::String(text) => pem_or_base64(text)
                .filter(|der| core.cert_info(der).is_some())
                .map(Bytes::from)
                .ok_or_else(certificate_parsing_failure),
            // `(String) null` passes; `pem.getBytes()` then dereferences it.
            Value::Null => Err(null_pointer()),
            other => Err(class_cast(other)),
        })
        .collect::<Result<_, _>>()
        .map(Some)
}

/// The CAdES of `createCAdES` over `data` signed at `at` (Unix ms), time-stamped on its new
/// signer by the basics TSA if asked; the core writes it as PEM.
fn cms_args(
    data: Vec<u8>,
    encapsulate: bool,
    digested: bool,
    timestamp: bool,
    at: i64,
) -> SignCmsExArgs {
    let data = Bytes::from(data);
    SignCmsExArgs {
        handle: 0,
        content: if digested {
            CmsContent::Digest(data)
        } else {
            CmsContent::Data(data)
        },
        encapsulate,
        cosign: if digested {
            CoSign::Never
        } else {
            CoSign::Auto
        },
        econtent_type: None,
        digest: None,
        attrs: SignedAttrs {
            content_type: true,
            message_digest: true,
            signing_certificate_v2: true,
            signing_time: Some(SigningTime {
                at: TimeSource::UnixMs(at),
                form: TimeForm::Auto,
            }),
            extra: Vec::new(),
        },
        certificates: CmsCerts::Signer,
        timestamp: timestamp.then_some(TsaChoice::Basics),
        output: CmsOutput::Pem,
    }
}

/// A CAdES PEM.
fn sign_cms<C: Core>(core: &C, key: &C::Key, args: SignCmsExArgs) -> Result<String, Failure> {
    match core.sign_cms(key, args) {
        Ok(CmsOutcome::Signed(pem)) => {
            Ok(String::from_utf8(pem.into_vec()).expect("the core writes PEM in ASCII"))
        }
        Ok(CmsOutcome::TspFailed(failure)) => Err(tsp_failure(&failure.detail)),
        Err(e) => Err(cms_failure(&e)),
    }
}

/// Raw signatures with the key's algorithm (RSA: SHA-256): one string for one input, an
/// array for several, `{signatures, certificate}` with `output_cert`.
fn sign_raw<C: Core>(
    core: &C,
    key: &C::Key,
    data: &[Cow<'_, [u8]>],
    output_cert: bool,
) -> CallResult {
    let mut signatures = data
        .iter()
        .map(|d| {
            core.sign_raw(key, d)
                .map(|sig| encode_base64(&sig))
                .map_err(|e| key_failure(&e))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(if output_cert {
        let certificate = pem("CERTIFICATE", core.certificate(key), &core.line_separator());
        json!({ "signatures": signatures, "certificate": certificate })
    } else if signatures.len() == 1 {
        Value::String(signatures.swap_remove(0))
    } else {
        Value::from(signatures)
    })
}

/// The document with an enveloped signature appended to its root element.
fn sign_xml<C: Core>(core: &C, key: &C::Key, xml: &[u8]) -> Result<String, Failure> {
    let signed = core.sign_xml(key, xml).map_err(|e| {
        let cert_alg = core
            .cert_info(core.certificate(key))
            .map(|info| info.signature_alg_oid)
            .unwrap_or_default();
        xml_failure(&e, &cert_alg)
    })?;
    // The input was UTF-8 text and only ASCII markup and base64 were spliced in.
    String::from_utf8(signed).map_err(signing_failure)
}
