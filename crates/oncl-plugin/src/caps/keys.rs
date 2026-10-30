//! `keys`: the user's key, chosen in the storage and key dialogs ([`KeyChooser`]), behind a
//! handle of the instance; signatures made here, the private key never reaching the guest.

use super::{DialogTurn, MAX_KEY_HANDLES, MAX_LINE, check_line, failed, invalid, origin, source};
use crate::host::HostState;
use oncl_basics::{ChainPolicy, KeyChooser, KeyFilter, KeyRequest, StorageKind};
use oncl_pdk::abi::{
    Action, Bytes, ChooseArgs, Chosen, ErrorCode, Filter, Handle, HostError, HostResult,
    SignCmsArgs, SignRawArgs, SignXmlArgs,
};
use oncl_pki::cms::{self, SignOptions};
use oncl_pki::key::{KeyAlg, SigAlg};
use oncl_pki::pkcs12::KeyEntry;
use oncl_pki::pkix::CaSet;
use oncl_pki::{cert, tsp, xmldsig};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The keys an instance holds, by handle. Handles count up and are never reused, so a
/// released handle never names another key.
#[derive(Default)]
pub(crate) struct KeyTable {
    keys: BTreeMap<u32, KeyEntry>,
    last: u32,
}

impl KeyTable {
    /// Whether another key fits.
    fn has_room(&self) -> HostResult<()> {
        if self.keys.len() >= MAX_KEY_HANDLES {
            return Err(HostError::new(
                ErrorCode::Limit,
                format!("at most {MAX_KEY_HANDLES} keys at once: release one first"),
            ));
        }
        if self.last == u32::MAX {
            return Err(HostError::new(ErrorCode::Limit, "no key handles left"));
        }
        Ok(())
    }

    /// Keeps `key` under a new handle.
    fn insert(&mut self, key: KeyEntry) -> HostResult<u32> {
        self.has_room()?;
        self.last += 1;
        self.keys.insert(self.last, key);
        Ok(self.last)
    }

    /// The key of `handle`.
    fn get(&self, handle: u32) -> HostResult<&KeyEntry> {
        self.keys.get(&handle).ok_or_else(|| unknown_handle(handle))
    }

    /// Lets go of the key of `handle`.
    fn remove(&mut self, handle: u32) -> HostResult<()> {
        self.keys
            .remove(&handle)
            .map(drop)
            .ok_or_else(|| unknown_handle(handle))
    }
}

fn unknown_handle(handle: u32) -> HostError {
    HostError::new(
        ErrorCode::Invalid,
        format!("no key has the handle {handle}"),
    )
}

/// `keys_choose`: the storage and key dialogs; the key stays in the instance.
pub(crate) fn keys_choose(state: &mut HostState, args: ChooseArgs) -> HostResult<Option<Chosen>> {
    state.keys.has_room()?;
    let storages = if args.storages.is_empty() {
        vec![StorageKind::Pkcs12, StorageKind::Jks]
    } else {
        args.storages
            .iter()
            .map(|name| {
                StorageKind::from_name(name).ok_or_else(|| invalid(format!("no storage {name:?}")))
            })
            .collect::<HostResult<_>>()?
    };
    let name = source(state);
    let detail = match &args.detail {
        Some(detail) => {
            check_line("detail", detail, MAX_LINE)?;
            format!("{name}: {detail}")
        }
        None => name,
    };
    let request = KeyRequest {
        origin: origin(state),
        locale: state.call.locale,
        action: match args.action {
            Action::Sign => oncl_basics::Action::Sign,
            Action::Authenticate => oncl_basics::Action::Authenticate,
            Action::KeyInfo => oncl_basics::Action::KeyInfo,
        },
        storages,
        filter: key_filter(args.filter)?,
        detail: Some(detail),
    };
    let services = &state.services;
    let chooser = KeyChooser {
        prompter: Arc::clone(&services.prompter),
        recent: Arc::clone(&services.recent),
        http: Arc::clone(&services.http),
        ocsp_cache: Arc::clone(&services.ocsp_cache),
        clock: services.clock,
    };
    DialogTurn::hold();
    let Some(entry) = chooser.choose(&request) else {
        return Ok(None);
    };
    let certificate = der::Encode::to_der(&entry.cert).map_err(failed)?;
    let alias = entry.alias.clone();
    let handle = state.keys.insert(entry)?;
    Ok(Some(Chosen {
        handle,
        alias,
        certificate: Bytes::from(certificate),
    }))
}

/// The basics module's conditions of `filter`.
fn key_filter(filter: Filter) -> HostResult<KeyFilter> {
    let chain = match filter.chain {
        None => ChainPolicy::Default,
        Some(certs) if certs.is_empty() => ChainPolicy::Empty,
        Some(certs) => ChainPolicy::Custom(Arc::new(CaSet::new(
            certs
                .iter()
                .map(|der| cert::parse(der).map_err(|e| invalid(format!("chain: {e}"))))
                .collect::<HostResult<_>>()?,
        ))),
    };
    Ok(KeyFilter {
        ext_key_usages: filter.ext_key_usages.into_iter().collect(),
        iin: filter.iin,
        bin: filter.bin,
        serial_number: filter.serial_number,
        allow_expired: filter.allow_expired,
        chain,
        allow_revoked: filter.allow_revoked,
    })
}

/// `keys_sign_cms`: a CAdES signature, time-stamped on its new signer if asked.
pub(crate) fn keys_sign_cms(state: &mut HostState, args: SignCmsArgs) -> HostResult<Bytes> {
    let entry = state.keys.get(args.handle)?;
    let opts = SignOptions {
        encapsulate: args.attached,
        digested: false,
        signing_time: (state.services.clock)(),
    };
    let mut der = cms::sign(entry, &args.data, &opts).map_err(failed)?;
    if args.timestamp {
        let last = cms::signer_count(&der)
            .map_err(failed)?
            .checked_sub(1)
            .ok_or_else(|| failed("the signed CMS has no signers"))?;
        der = tsp::timestamp_signer(
            &der,
            last,
            &state.services.tsa,
            state.services.http.as_ref(),
        )
        .map_err(failed)?;
    }
    Ok(Bytes::from(der))
}

/// `keys_sign_raw`: the key's algorithm, RSA with SHA-256.
pub(crate) fn keys_sign_raw(state: &mut HostState, args: SignRawArgs) -> HostResult<Bytes> {
    let entry = state.keys.get(args.handle)?;
    let alg = match entry.key.alg() {
        KeyAlg::Gost2004 => SigAlg::Gost2004,
        KeyAlg::Gost2015_512 => SigAlg::Gost2015_512,
        KeyAlg::Rsa => SigAlg::RsaSha256,
    };
    let signature = entry.key.sign(alg, &args.data).map_err(failed)?;
    Ok(Bytes::from(signature))
}

/// `keys_sign_xml`: the whole document, or an element, with an enveloped signature.
pub(crate) fn keys_sign_xml(state: &mut HostState, args: SignXmlArgs) -> HostResult<Bytes> {
    let entry = state.keys.get(args.handle)?;
    let signed = match &args.element {
        None if args.parent.is_some() => {
            return Err(invalid("parent is only for a signed element"));
        }
        None => xmldsig::sign_enveloped(&args.xml, &entry.key, &entry.cert),
        Some(element) => xmldsig::sign_element(
            &args.xml,
            element,
            args.parent.as_deref(),
            &entry.key,
            &entry.cert,
        ),
    }
    .map_err(failed)?;
    Ok(Bytes::from(signed))
}

/// `keys_release`.
pub(crate) fn keys_release(state: &mut HostState, args: Handle) -> HostResult<()> {
    state.keys.remove(args.handle)
}
