//! `keys`: the user's key, chosen in the storage and key dialogs ([`KeyChooser`]) or opened
//! from a store the plugin names ([`keys_open`]), behind a handle of the instance;
//! signatures made here, the private key never reaching the guest. With token support on,
//! the storage dialog offers the tokens plugged in, and `keys_open` opens a token in a
//! reader with the PIN the plugin passes.

use super::{
    DialogTurn, MAX_KEY_HANDLES, MAX_LINE, check_line, denied, failed, invalid, origin, source,
};
use crate::host::HostState;
use oncl_basics::{
    ChainPolicy, ConfirmPrompt, FilterMore as BasicsMore, KeyChooser, KeyFilter, KeyOrder,
    KeyRequest, Locale, MAX_PAGE_FILE, OpenError, PageFile, PageFileError, Prompt, StorageAnswer,
    StorageKind, page_path,
};
use oncl_pdk::abi::{
    self, Action, Bytes, ChooseArgs, Chosen, ErrorCode, Filter, FilterMore, Handle, HostError,
    HostResult, KeySource, KeyUsageBit, OpenArgs, OpenOutcome, OpenedKey, Password, SelectArgs,
    SignCmsArgs, SignRawArgs, SignXmlArgs, TerminalsArgs,
};
use oncl_pki::cert::Certificate;
use oncl_pki::cms::{self, SignOptions};
use oncl_pki::info::{KeyUsageBits, KncaCertType};
use oncl_pki::key::{KeyAlg, SigAlg};
use oncl_pki::pkcs12::{self, KeyEntry};
use oncl_pki::pkix::CaSet;
use oncl_pki::{cert, tsp, xmldsig};
use oncl_token::TokenError;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

/// A key an instance holds: the key with its certificate, and the other certificates of
/// its store (for its chain).
struct Held {
    entry: KeyEntry,
    store_certs: Arc<[Certificate]>,
}

/// The keys an instance holds, by handle. Handles count up and are never reused, so a
/// released handle never names another key.
#[derive(Default)]
pub(crate) struct KeyTable {
    keys: BTreeMap<u32, Held>,
    last: u32,
}

impl KeyTable {
    /// Whether another key fits.
    fn has_room(&self) -> HostResult<()> {
        self.has_room_for(1)
    }

    /// Whether `count` more keys fit.
    fn has_room_for(&self, count: usize) -> HostResult<()> {
        if self.keys.len() + count > MAX_KEY_HANDLES {
            return Err(HostError::new(
                ErrorCode::Limit,
                format!("at most {MAX_KEY_HANDLES} keys at once: release one first"),
            ));
        }
        if u32::MAX - self.last < count as u32 {
            return Err(HostError::new(ErrorCode::Limit, "no key handles left"));
        }
        Ok(())
    }

    /// Keeps `key` under a new handle, with the other certificates of its store.
    fn insert(&mut self, key: KeyEntry, store_certs: Arc<[Certificate]>) -> HostResult<u32> {
        self.has_room()?;
        self.last += 1;
        self.keys.insert(
            self.last,
            Held {
                entry: key,
                store_certs,
            },
        );
        Ok(self.last)
    }

    /// The key of `handle`.
    fn get(&self, handle: u32) -> HostResult<&KeyEntry> {
        self.held(handle).map(|held| &held.entry)
    }

    fn held(&self, handle: u32) -> HostResult<&Held> {
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

fn der_of(cert: &Certificate) -> HostResult<Vec<u8>> {
    der::Encode::to_der(cert).map_err(failed)
}

/// What [`choose`] asks for.
struct Choice {
    action: Action,
    storages: Vec<String>,
    filter: KeyFilter,
    detail: Option<String>,
    initial_path: Option<PathBuf>,
    order: KeyOrder,
}

/// `keys_choose`: the storage and key dialogs; the key stays in the instance.
pub(crate) fn keys_choose(state: &mut HostState, args: ChooseArgs) -> HostResult<Option<Chosen>> {
    state.keys.has_room()?;
    let choice = Choice {
        action: args.action,
        storages: args.storages,
        filter: key_filter(args.filter, BasicsMore::default())?,
        detail: args.detail,
        initial_path: None,
        order: KeyOrder::Store,
    };
    choose(state, choice)
}

/// `keys_select`: `keys_choose` with more conditions, a key store the storage dialog starts
/// with, and the keys in the order of the original's dialogs.
pub(crate) fn keys_select(state: &mut HostState, args: SelectArgs) -> HostResult<Option<Chosen>> {
    state.keys.has_room()?;
    if let Some(path) = &args.initial_path {
        check_line("initial_path", path, MAX_LINE)?;
    }
    let choice = Choice {
        action: args.action,
        storages: args.storages,
        filter: key_filter(args.filter, filter_more(args.more)?)?,
        detail: args.detail,
        // A path a page may not name is not offered.
        initial_path: args
            .initial_path
            .as_deref()
            .and_then(page_path)
            .map(Path::to_path_buf),
        order: match args.order {
            abi::KeyOrder::NewestFirst => KeyOrder::NewestFirst,
            abi::KeyOrder::OldestFirst => KeyOrder::OldestFirst,
        },
    };
    choose(state, choice)
}

/// The storage and key dialogs of `choice`; the key stays in the instance.
fn choose(state: &mut HostState, choice: Choice) -> HostResult<Option<Chosen>> {
    let storages = if choice.storages.is_empty() {
        vec![StorageKind::Pkcs12, StorageKind::Jks]
    } else {
        choice
            .storages
            .iter()
            .map(|name| storage_kind(name))
            .collect::<HostResult<_>>()?
    };
    let name = source(state);
    let detail = match &choice.detail {
        Some(detail) => {
            check_line("detail", detail, MAX_LINE)?;
            format!("{name}: {detail}")
        }
        None => name,
    };
    let request = KeyRequest {
        origin: origin(state),
        locale: state.call.locale,
        action: match choice.action {
            Action::Sign => oncl_basics::Action::Sign,
            Action::Authenticate => oncl_basics::Action::Authenticate,
            Action::KeyInfo => oncl_basics::Action::KeyInfo,
        },
        storages,
        filter: choice.filter,
        detail: Some(detail),
        initial_path: choice.initial_path,
        order: choice.order,
    };
    let services = &state.services;
    let chooser = KeyChooser {
        prompter: Arc::clone(&services.prompter),
        recent: Arc::clone(&services.recent),
        http: Arc::clone(&services.http),
        ocsp_cache: Arc::clone(&services.ocsp_cache),
        clock: services.clock,
        tokens: Arc::clone(&services.tokens),
    };
    DialogTurn::hold();
    let Some(entry) = chooser.choose(&request) else {
        return Ok(None);
    };
    let certificate = der_of(&entry.cert)?;
    let alias = entry.alias.clone();
    let handle = state.keys.insert(entry, Arc::from([]))?;
    Ok(Some(Chosen {
        handle,
        alias,
        certificate: Bytes::from(certificate),
    }))
}

/// The storage named `name`.
fn storage_kind(name: &str) -> HostResult<StorageKind> {
    StorageKind::from_name(name).ok_or_else(|| invalid(format!("no storage {name:?}")))
}

/// The basics module's conditions of `filter` and `more`.
fn key_filter(filter: Filter, more: BasicsMore) -> HostResult<KeyFilter> {
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
        more,
    })
}

/// The basics module's conditions of `more`.
fn filter_more(more: FilterMore) -> HostResult<BasicsMore> {
    let knca_types = more
        .knca_types
        .iter()
        .map(|name| {
            KncaCertType::from_name(name)
                .ok_or_else(|| invalid(format!("no Kalkan certificate type {name:?}")))
        })
        .collect::<HostResult<_>>()?;
    let mut key_usage = KeyUsageBits::default();
    for bit in more.key_usage {
        match bit {
            KeyUsageBit::DigitalSignature => key_usage.digital_signature = true,
            KeyUsageBit::NonRepudiation => key_usage.non_repudiation = true,
            KeyUsageBit::KeyEncipherment => key_usage.key_encipherment = true,
            KeyUsageBit::KeyAgreement => key_usage.key_agreement = true,
        }
    }
    Ok(BasicsMore {
        any_ext_key_usages: more.any_ext_key_usages.into_iter().collect(),
        exclude_ext_key_usages: more.exclude_ext_key_usages.into_iter().collect(),
        knca_types,
        tin: more.tin,
        key_usage,
        obsolete_auth: more.obsolete_auth,
    })
}

/// `keys_open`: every key of a store the plugin names, by page path (`key_files`), by its
/// bytes, or a token in a reader. A page path is opened only once the user allows the page
/// to open that file, once per session.
pub(crate) fn keys_open(state: &mut HostState, args: OpenArgs) -> HostResult<OpenOutcome> {
    let storage = storage_kind(&args.storage)?;
    let password = match &args.password {
        Password::Text(text) => Zeroizing::new(text.clone()),
        Password::Secret(id) => Zeroizing::new(state.secrets.get(*id)?.to_owned()),
    };
    let data = match args.source {
        KeySource::Terminal(reader) => {
            if !matches!(storage, StorageKind::Token(_)) {
                return Err(invalid(format!("{} has no terminals", storage.name())));
            }
            check_line("the reader", &reader, MAX_LINE)?;
            return open_token(state, storage, &reader, &password);
        }
        _ if !storage.readable() => {
            return Err(invalid(format!(
                "{} is opened in a terminal, not from a file",
                storage.name()
            )));
        }
        KeySource::Bytes(bytes) => {
            if bytes.len() as u64 > MAX_PAGE_FILE {
                return Ok(OpenOutcome::Corrupt);
            }
            bytes.into_vec()
        }
        KeySource::PagePath(path) => {
            if !state.capabilities.key_files {
                return Err(denied(
                    "opening a key store by a page's path needs key_files in the manifest",
                ));
            }
            check_line("the path", &path, MAX_LINE)?;
            match page_key_file(state, &path) {
                Ok(data) => data,
                Err(outcome) => return Ok(outcome),
            }
        }
    };
    let answer = StorageAnswer {
        storage,
        path: PathBuf::new(),
        password,
        reader: None,
    };
    let entries = match answer.open_data(&data) {
        Ok(entries) => entries,
        Err(e) => {
            return Ok(match e {
                OpenError::WrongPassword
                | OpenError::EmptyPassword
                | OpenError::InnerPasswordPolicy => OpenOutcome::WrongPassword { tries_left: None },
                OpenError::FileNotFound => OpenOutcome::NotFound,
                OpenError::NoKeys | OpenError::NoSigningKeys | OpenError::NoAuthKeys => {
                    OpenOutcome::NoKeys
                }
                // A file's data opens with none of a token's errors.
                OpenError::NotPkcs12
                | OpenError::NotJks
                | OpenError::UnsupportedStorage
                | OpenError::TokenAbsent
                | OpenError::TokenService
                | OpenError::WrongPin { .. }
                | OpenError::PinBlocked
                | OpenError::InvalidPin
                | OpenError::TokenFailure => OpenOutcome::Corrupt,
            });
        }
    };
    // The CA certificates the store keeps beside its keys, for `keys_chain`.
    let store_certs: Arc<[Certificate]> = match storage {
        StorageKind::Pkcs12 => pkcs12::load_contents(&data, &answer.password)
            .map(|contents| contents.other_certs.into())
            .unwrap_or_else(|_| Arc::from([])),
        StorageKind::Jks | StorageKind::Token(_) => Arc::from([]),
    };
    keep_opened(state, entries, store_certs)
}

/// Keeps every key of `entries` under a handle of its own, with the other certificates of
/// its store; none when they do not all fit.
fn keep_opened(
    state: &mut HostState,
    entries: Vec<KeyEntry>,
    store_certs: Arc<[Certificate]>,
) -> HostResult<OpenOutcome> {
    state.keys.has_room_for(entries.len())?;
    let mut opened = Vec::with_capacity(entries.len());
    for entry in entries {
        let certificate = Bytes::from(der_of(&entry.cert)?);
        let alias = entry.alias.clone();
        let handle = state.keys.insert(entry, Arc::clone(&store_certs))?;
        opened.push(OpenedKey {
            handle,
            alias,
            certificate,
        });
    }
    Ok(OpenOutcome::Opened(opened))
}

/// The contents of the key store file a page names, if a page may name it, it is a regular
/// file within [`MAX_PAGE_FILE`], and the user allows this page to open it (asked once per
/// session and page for each file). Nothing is read before the user allows it.
fn page_key_file(state: &mut HostState, path: &str) -> Result<Vec<u8>, OpenOutcome> {
    let named = page_path(path).ok_or(OpenOutcome::NotFound)?;
    let meta = std::fs::metadata(named).map_err(|_| OpenOutcome::NotFound)?;
    if !meta.is_file() {
        return Err(OpenOutcome::NotFound);
    }
    if meta.len() > MAX_PAGE_FILE {
        return Err(OpenOutcome::Corrupt);
    }
    let canonical = std::fs::canonicalize(named).map_err(|_| OpenOutcome::NotFound)?;
    let key = (origin(state), canonical);
    if !state.consents.contains(&key) {
        let text = consent_text(state.call.locale, &key.0, &source(state), &shown(&key.1));
        let prompt = ConfirmPrompt {
            origin: key.0.clone(),
            locale: state.call.locale,
            source: source(state),
            text,
        };
        DialogTurn::hold();
        if state.services.prompter.confirm(&prompt) != Prompt::Answer(true) {
            return Err(OpenOutcome::Declined);
        }
        state.consents.insert(key);
    }
    match PageFile::read(path) {
        Ok(file) => Ok(file.data),
        Err(PageFileError::NotFound) => Err(OpenOutcome::NotFound),
        Err(PageFileError::TooLarge) => Err(OpenOutcome::Corrupt),
    }
}

/// `path` as the user reads it: without Windows' `\\?\` prefix.
fn shown(path: &Path) -> String {
    let text = path.display().to_string();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{unc}");
    }
    text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
}

/// The question that lets a page open a key store file.
fn consent_text(locale: Locale, origin: &str, plugin: &str, path: &str) -> String {
    match locale {
        Locale::Ru => format!(
            "Сайт {origin} через плагин «{plugin}» просит открыть хранилище ключей:\n{path}\n\nРазрешить?"
        ),
        Locale::Kk => format!(
            "{origin} сайты «{plugin}» плагині арқылы кілттер қоймасын ашуды сұрайды:\n{path}\n\nРұқсат етесіз бе?"
        ),
        Locale::En => format!(
            "The site {origin} asks, through the plugin “{plugin}”, to open the key store:\n{path}\n\nAllow?"
        ),
    }
}

/// `keys_terminals`: the readers of a token storage.
pub(crate) fn keys_terminals(
    state: &mut HostState,
    args: TerminalsArgs,
) -> HostResult<Vec<String>> {
    let storage = storage_kind(&args.storage)?;
    if !matches!(storage, StorageKind::Token(_)) {
        return Err(invalid(format!("{} has no terminals", storage.name())));
    }
    token_readers(state, storage)
}

/// The readers holding a token of the storage `storage`: none with token support off, and
/// none for the cloud storage, which no reader holds.
pub(crate) fn token_readers(
    state: &mut HostState,
    storage: StorageKind,
) -> HostResult<Vec<String>> {
    let Some(kind) = storage.token_kind() else {
        return Ok(Vec::new());
    };
    state.services.tokens.readers(kind).map_err(failed)
}

/// Opens the token of `storage` in `reader` with `pin`: every key of the token with a
/// certificate, in the token's order, each behind a handle that keeps the PIN in memory for
/// its signatures until it is released or the instance ends.
pub(crate) fn open_token(
    state: &mut HostState,
    storage: StorageKind,
    reader: &str,
    pin: &str,
) -> HostResult<OpenOutcome> {
    let Some(kind) = storage.token_kind() else {
        return Ok(OpenOutcome::NoDevice);
    };
    let entries = match state.services.tokens.open(reader, kind, pin) {
        Ok(entries) => entries,
        Err(e) => {
            return match e {
                TokenError::WrongPin { tries_left } => {
                    Ok(OpenOutcome::WrongPassword { tries_left })
                }
                // Refused before any command: no try spent.
                TokenError::InvalidPin => Ok(OpenOutcome::WrongPassword { tries_left: None }),
                TokenError::PinBlocked => Ok(OpenOutcome::Blocked),
                TokenError::Disabled
                | TokenError::NoService
                | TokenError::NoDevice
                | TokenError::WrongCard
                | TokenError::CardRemoved => Ok(OpenOutcome::NoDevice),
                TokenError::Card { .. } | TokenError::Malformed(_) | TokenError::Transport(_) => {
                    Err(failed(e))
                }
            };
        }
    };
    if entries.is_empty() {
        return Ok(OpenOutcome::NoKeys);
    }
    keep_opened(state, entries, Arc::from([]))
}

/// Longest chain `keys_chain` builds.
const MAX_CHAIN: usize = 16;

/// `keys_chain`: the key's certificate, then its issuers up to a self-signed one: from its
/// store's certificates first, then from the CAs the core trusts.
pub(crate) fn keys_chain(state: &mut HostState, args: Handle) -> HostResult<Vec<Bytes>> {
    let held = state.keys.held(args.handle)?;
    let store = CaSet::new(held.store_certs.to_vec());
    let mut chain = vec![held.entry.cert.clone()];
    while chain.len() < MAX_CHAIN {
        let last = chain.last().expect("the chain has its leaf");
        let tbs = last.tbs_certificate();
        if tbs.subject() == tbs.issuer() {
            break;
        }
        let next = store
            .issuers_of(last)
            .next()
            .or_else(|| state.services.cas.issuers_of(last).next());
        match next {
            Some(issuer) if !chain.contains(issuer) => chain.push(issuer.clone()),
            _ => break,
        }
    }
    chain
        .iter()
        .map(|cert| der_of(cert).map(Bytes::from))
        .collect()
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
