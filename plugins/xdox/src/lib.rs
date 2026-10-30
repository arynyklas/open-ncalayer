//! The OpenNCALayer port of `kz.xdox.osgi.SignerBundle` 1.1, the module
//! `kz.xdox.signerbundle`: its own `{method, params}` switch for xdox.kz — `CREATECMS` (an
//! attached, time-stamped CAdES of the document manifest) and `ADDSIGNERTOCMS` (a signer
//! added to the page's CMS over the manifest, the result detached). Replies are written in
//! the order of the original's `JSONStringer`; the module echoes no `uuid`.

#[cfg(target_arch = "wasm32")]
mod port {
    use oncl_pdk::abi::ErrorCode;
    use oncl_pdk::keys::{Action, CmsOutcome, CoSign, Filter, Key, KeyOrder};
    use oncl_pdk::orgjson::{self, JObject, JValue};
    use oncl_pdk::serde_json::{Map, Value};
    use oncl_pdk::{Request, host, javab64};
    use oncl_port_legacy::{
        Select, TSA_FAILED, UNKNOWN_ALGORITHM, base64, cades, cades_args, select,
    };

    /// The origin check: the page's origin must contain this text (not anchored).
    const SITE: &str = "xdox.kz";

    /// The plugin's handler.
    pub fn handle(request: &Request) -> String {
        if !request.origin.as_deref().unwrap_or_default().contains(SITE) {
            return failure(Some("That module can be used only on https://xdox.kz"));
        }
        // These reads sit outside the original's try: a failure ends the connection.
        let Ok(JValue::Obj(parsed)) = orgjson::parse(&request.text) else {
            return dropped();
        };
        let map = parsed.to_map();
        let method = orgjson::opt_string(&map, "method").unwrap_or_default();
        let Ok(params) = orgjson::get_object(&map, "params") else {
            return dropped();
        };
        let Ok(storage_name) = orgjson::get_string(params, "storageName") else {
            return dropped();
        };
        // The ID card is a token; any other name is a PKCS#12 file.
        let storage = if storage_name == "AKKZIDCardStore" {
            "AKKZIDCardStore"
        } else {
            "PKCS12"
        };
        match method.to_uppercase().as_str() {
            "CREATECMS" => create_cms(storage, params),
            "ADDSIGNERTOCMS" => add_signer(storage, params),
            _ => {
                let mut reply = JObject::stringer();
                reply.put("success", false);
                reply.put("errorCode", "method_not_defined");
                reply.to_json()
            }
        }
    }

    /// The connection dropped without a reply.
    fn dropped() -> String {
        let _ = host::reply_drop();
        String::new()
    }

    /// `{"success":false,"errorCode":"unknown_exception","message":…}` (`null` for an
    /// exception without a message).
    fn failure(message: Option<&str>) -> String {
        let mut reply = JObject::stringer();
        reply.put("success", false);
        reply.put("errorCode", "unknown_exception");
        reply.put("message", message.map_or(JValue::Null, JValue::from));
        reply.to_json()
    }

    /// `{"success":true,"code":"200","responseObject":<base64 CMS>}`.
    fn success(cms: &[u8]) -> String {
        let mut reply = JObject::stringer();
        reply.put("success", true);
        reply.put("code", "200");
        reply.put("responseObject", base64(cms));
        reply.to_json()
    }

    /// The storage and key dialogs: signing keys only, oldest first, with a certification
    /// path through the core's CAs (the original's default-chained signing entity, which
    /// checks no revocation).
    fn choose(storage: &str) -> Result<Key, String> {
        let chain = host::ca_list().map_err(|e| e.message)?;
        let key = select(Select {
            storage,
            action: Action::Sign,
            knca_types: vec!["SIGNATURE".to_owned()],
            order: KeyOrder::OldestFirst,
            filter: Filter {
                chain: Some(chain.into_iter().map(Into::into).collect()),
                allow_revoked: true,
                ..Filter::default()
            },
        })?;
        // The original's cancelled dialog writes a key after the end of its reply object:
        // org.json's `Misplaced key.`.
        key.ok_or_else(|| "Misplaced key.".to_owned())
    }

    /// `CREATECMS`: `ncaManifest` signed as UTF-8, attached (a manifest that is itself a CMS
    /// is co-signed), time-stamped by Kalkan's default TSA profile.
    fn create_cms(storage: &str, params: &Map<String, Value>) -> String {
        let signed = choose(storage).and_then(|key| {
            let manifest = orgjson::get_string(params, "ncaManifest")?;
            let args = cades_args(key.handle(), manifest.as_bytes(), true, CoSign::Auto, true);
            cades(&key, args)
        });
        match signed {
            Ok(cms) => success(&cms),
            Err(message) => failure(Some(&message)),
        }
    }

    /// `ADDSIGNERTOCMS`: a signer over `ncaManifest` added to the CMS `cms`, its signers and
    /// certificates kept, the output detached, only the new signer time-stamped.
    fn add_signer(storage: &str, params: &Map<String, Value>) -> String {
        let key = match choose(storage) {
            Ok(key) => key,
            Err(message) => return failure(Some(&message)),
        };
        // Outside the original's try.
        let (Ok(manifest), Ok(cms)) = (
            orgjson::get_string(params, "ncaManifest"),
            orgjson::get_string(params, "cms"),
        ) else {
            return dropped();
        };
        let Ok(cms) = javab64::decode_kalkan(cms) else {
            return dropped();
        };
        match add_signer_to(&key, manifest, cms) {
            Ok(cms) => success(&cms),
            Err(message) => failure(Some(&message)),
        }
    }

    fn add_signer_to(key: &Key, manifest: &str, cms: Vec<u8>) -> Result<Vec<u8>, String> {
        // The digest by the certificate: SHA-256 for sha256RSA, GOST 34.311 for GOST 2004;
        // any other (GOST 2015 included) is Kalkan's UNKNOWN_ALGORITHM.
        let details = host::cert_details(key.certificate()).map_err(|e| e.message)?;
        if !matches!(
            details.signing_alg.as_deref(),
            Some("rsa_sha256" | "gost2004")
        ) {
            return Err(UNKNOWN_ALGORITHM.to_owned());
        }
        let args = cades_args(
            key.handle(),
            manifest.as_bytes(),
            false,
            CoSign::Into(cms.into()),
            true,
        );
        match key.sign_cms_ex(args) {
            Ok(CmsOutcome::Signed(cms)) => Ok(cms.into_vec()),
            Ok(CmsOutcome::TspFailed(_)) => Err(TSA_FAILED.to_owned()),
            // A CMS the core cannot read: Kalkan's CMS_PROCESSING_FAILURE.
            // Unverified against the original: the reply's text for it (the code here, the
            // cause's `toString()` there).
            Err(e) if e.code == ErrorCode::Invalid => Err("CMS_PROCESSING_FAILURE".to_owned()),
            Err(e) => Err(e.message),
        }
    }
}

#[cfg(target_arch = "wasm32")]
oncl_pdk::plugin!(port::handle);
