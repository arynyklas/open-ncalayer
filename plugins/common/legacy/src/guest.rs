//! The clones' code that calls the host.

use crate::{STORAGE_EMPTY, Storage, TSA_FAILED, common_name, storage, subject_and_issuer};
use oncl_pdk::Reply;
use oncl_pdk::host;
use oncl_pdk::keys::{
    self, Action, CmsOutcome, Filter, FilterMore, Key, KeyOrder, SelectArgs, SignCmsExArgs,
};
use oncl_pdk::orgjson::JObject;
use oncl_port_pki::x509text::kalkan_key_alg_name;

/// A CMS of `key` as `args` say ([`crate::cades_args`]).
///
/// # Errors
///
/// [`TSA_FAILED`] when the time-stamp failed, else the host's message.
pub fn cades(key: &Key, args: SignCmsExArgs) -> Result<Vec<u8>, String> {
    match key.sign_cms_ex(args) {
        Ok(CmsOutcome::Signed(cms)) => Ok(cms.into_vec()),
        Ok(CmsOutcome::TspFailed(_)) => Err(TSA_FAILED.to_owned()),
        // Unverified against the original: the message of a CMS failure other than the
        // time-stamp (the host's text stands for Kalkan's).
        Err(e) => Err(e.message),
    }
}

/// Kalkan's `XMLUtil.createXmlSignature`: the whole document for an empty `tbs`, else the
/// element it selects, the signature into the element `parent` selects (the document
/// element for an empty one); `tbs` and `parent` equal regardless of case are refused with
/// Kalkan's text.
///
/// # Errors
///
/// That text, or the host's message.
pub fn sign_xml(key: &Key, xml: &str, tbs: &str, parent: &str) -> Result<String, String> {
    let signed = if tbs.is_empty() {
        key.sign_xml(xml.as_bytes(), None, None)
    } else {
        if tbs.to_lowercase() == parent.to_lowercase() {
            return Err(
                "При подписи элемента XML, элемент подписи не может быть родительским элементом подписи."
                    .to_owned(),
            );
        }
        key.sign_xml(
            xml.as_bytes(),
            Some(tbs),
            (!parent.is_empty()).then_some(parent),
        )
    }
    // Unverified against the original: the messages of failed XML signatures (the host's
    // text stands for Kalkan's).
    .map_err(|e| e.message)?;
    String::from_utf8(signed).map_err(|e| e.to_string())
}

/// The text of `reply`; a dropped connection asks the host to drop it (the text returned
/// then is not sent).
pub fn into_text(reply: Reply) -> String {
    match reply {
        Reply::Text(text) => text,
        Reply::Drop => {
            let _ = host::reply_drop();
            String::new()
        }
    }
}

/// A key choice of a clone's `StorageInfo` and key dialog.
pub struct Select<'a> {
    /// The page's `storageName`.
    pub storage: &'a str,
    /// What the dialogs say the key is for.
    pub action: Action,
    /// The key types listed ([`crate::knca_types`]).
    pub knca_types: Vec<String>,
    /// The order of the keys.
    pub order: KeyOrder,
    /// The other conditions.
    pub filter: Filter,
}

/// `StorageInfo`'s checks, then the storage and key dialogs: the key, `None` if the user
/// cancels.
///
/// # Errors
///
/// The message of a failed check ([`crate::storage`], [`STORAGE_EMPTY`] for a token
/// storage without a reader), or the host's message.
pub fn select(choice: Select<'_>) -> Result<Option<Key>, String> {
    let storage = storage(choice.storage).map_err(str::to_owned)?;
    if let Storage::Token(name) = storage {
        let readers = keys::terminals(name).map_err(|e| e.message)?;
        if readers.is_empty() {
            return Err(STORAGE_EMPTY.to_owned());
        }
    }
    keys::select(&SelectArgs {
        action: choice.action,
        storages: vec![storage.name().to_owned()],
        filter: choice.filter,
        more: FilterMore {
            knca_types: choice.knca_types,
            ..FilterMore::default()
        },
        detail: None,
        initial_path: None,
        order: choice.order,
    })
    .map_err(|e| e.message)
}

/// The official `KeyInfo` of `alias` and its certificate `der`, in the field order of the
/// bean (which decides the order of keys sharing a `HashMap` bucket): `alias`, `keyId`
/// (subjectKeyIdentifier hex), `algorithm` (Kalkan's key algorithm), `subjectCn`,
/// `subjectDn` and `issuerDn` (Kalkan's DN texts), `issuerCn`, `serialNumber` (hex),
/// `certNotAfter`/`certNotBefore` (Unix milliseconds as text), `authorityKeyIdentifier`
/// (only with a `keyId`, both read in one `try`) and `pem`; absent values left out.
///
/// # Errors
///
/// `der` is not a certificate.
pub fn official_key_info(alias: &str, der: &[u8]) -> Result<JObject, String> {
    let info = host::cert_info(der).map_err(|e| e.message)?;
    let details = host::cert_details(der).map_err(|e| e.message)?;
    let (_, issuer) = subject_and_issuer(der)?;
    let key_id = details.ski_hex.clone();
    let mut bean = JObject::hash_map();
    bean.put("alias", alias);
    bean.put_opt("keyId", key_id.clone());
    bean.put_opt("algorithm", kalkan_key_alg_name(&info.spki_alg_oid));
    bean.put_opt("subjectCn", info.subject_cn.clone());
    bean.put("subjectDn", details.subject_dn.as_str());
    bean.put_opt("issuerCn", common_name(&issuer));
    bean.put("issuerDn", details.issuer_dn.as_str());
    bean.put("serialNumber", info.serial_hex.as_str());
    bean.put("certNotAfter", info.not_after.to_string());
    bean.put("certNotBefore", info.not_before.to_string());
    bean.put_opt(
        "authorityKeyIdentifier",
        key_id.and(details.aki_hex.clone()),
    );
    bean.put("pem", info.pem.as_str());
    Ok(bean)
}
