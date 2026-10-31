//! `keys`: the user's key, chosen in the storage and key dialogs ([`KeyChooser`]) or opened
//! from a store the plugin names ([`keys_open`]), behind a handle of the instance;
//! signatures made here, the private key never reaching the guest. With token support on,
//! the storage dialog offers the tokens plugged in, and `keys_open` opens a token in a
//! reader with the PIN the plugin passes, once the user allows it
//! ([`PagePins`](oncl_flows::PagePins)).

use super::{
    ConsentKind, DialogTurn, MAX_DIALOG_TEXT, MAX_KEY_HANDLES, MAX_LINE, check_line, crypto,
    denied, failed, invalid, limit, origin, source, source_line,
};
use crate::cause;
use crate::host::HostState;
use der::asn1::ObjectIdentifier;
use oncl_flows::{
    ChainPolicy, ConfirmPrompt, FilterMore as BasicsMore, KeyChooser, KeyFilter, KeyFlow, KeyOrder,
    KeyRequest, Locale, MAX_PAGE_FILE, OpenError, PageFile, PageFileError, Prompt, StorageAnswer,
    StorageKind, page_path,
};
use oncl_flows::{FileRead, KeyChecks, OpenedFlow, PasswordRules, ReaderEntry, Readers, StartPath};
use oncl_flows::{PinFrom, PinRefusal, PinUse, page_pin_text};
use oncl_pdk::abi::{
    self, Action, Bytes, ChooseArgs, Chosen, ErrorCode, Filter, FilterMore, Handle, HostError,
    HostResult, KeySource, KeyUsageBit, OpenArgs, OpenOutcome, OpenedKey, Password, SelectArgs,
    SignCmsArgs, SignRawArgs, SignXmlArgs, TerminalsArgs,
};
use oncl_pdk::abi::{
    C14n, CmsCerts, CmsContent, CmsOutcome, Placement, SignCmsExArgs, SignXmlExArgs, TimeSource,
    Transform, XmlOutput,
};
use oncl_pdk::abi::{
    FlowArgs, FlowChecks, FlowFile, FlowKey, FlowNone, FlowOpened, FlowOrder, FlowOutcome,
    FlowReaders, FlowStart, FlowWrongPin, KeyDescription, MAX_FLOWS, PickArgs, TokenScan,
};
use oncl_pdk::abi::{NetFailure, NetStage, Problem, XadesArgs, XadesLevel, XadesOutcome};
use oncl_pki::cert::Certificate;
use oncl_pki::cms::{
    self, AttrSpec, CertSpec, CmsError, CoSign, Content, SignOptions, SignSpec, TimeForm,
};
use oncl_pki::crl::CrlError;
use oncl_pki::info::{KeyUsageBits, KncaCertType};
use oncl_pki::key::{KeyAlg, KeyError, SigAlg};
use oncl_pki::ocsp::CertStatus;
use oncl_pki::pkcs12::{self, KeyEntry, Pkcs12Error};
use oncl_pki::pkix::CaSet;
use oncl_pki::xades;
use oncl_pki::{cert, tsp, xmldsig};
use oncl_token::{TokenError, TokenKind};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;
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
    let storages = storage_kinds(&choice.storages)?;
    let detail = dialog_detail(state, choice.detail)?;
    let request = KeyRequest {
        origin: origin(state),
        locale: state.call.locale,
        action: basics_action(choice.action),
        storages,
        filter: choice.filter,
        detail,
        initial_path: choice.initial_path,
        order: choice.order,
    };
    let flow = KeyFlow::from_request(&request);
    let chooser = key_chooser(state);
    DialogTurn::hold();
    let Some(mut opened) = chooser.open(&flow).opened else {
        return Ok(None);
    };
    let Some(index) = opened.pick(&chooser, &flow, None) else {
        return Ok(None);
    };
    let entry = opened.take(index);
    let certificate = der_of(&entry.cert)?;
    let alias = entry.alias.clone();
    let handle = state.keys.insert(entry, Arc::from([]))?;
    Ok(Some(Chosen {
        handle,
        alias,
        certificate: Bytes::from(certificate),
    }))
}

/// The line the key choice's dialogs show: a plugin's name leads it; a built-in module's
/// line is its own.
fn dialog_detail(state: &HostState, detail: Option<String>) -> HostResult<Option<String>> {
    if let Some(detail) = &detail {
        check_line("detail", detail, MAX_LINE)?;
    }
    Ok(match (source_line(state), detail) {
        (Some(name), Some(detail)) => Some(format!("{name}: {detail}")),
        (Some(name), None) => Some(name),
        (None, detail) => detail,
    })
}

/// The dialogs' wording of `action`.
fn basics_action(action: Action) -> oncl_flows::Action {
    match action {
        Action::Sign => oncl_flows::Action::Sign,
        Action::Authenticate => oncl_flows::Action::Authenticate,
        Action::KeyInfo => oncl_flows::Action::KeyInfo,
    }
}

/// The key choice of the instance's services.
fn key_chooser(state: &HostState) -> KeyChooser {
    let services = &state.services;
    KeyChooser {
        prompter: Arc::clone(&services.prompter),
        recent: Arc::clone(&services.recent),
        http: Arc::clone(&services.http),
        ocsp_cache: Arc::clone(&services.ocsp_cache),
        clock: services.clock,
        tokens: Arc::clone(&services.tokens),
    }
}

/// The storages named `names`; none: PKCS#12 and JKS.
fn storage_kinds(names: &[String]) -> HostResult<Vec<StorageKind>> {
    if names.is_empty() {
        return Ok(vec![StorageKind::Pkcs12, StorageKind::Jks]);
    }
    names.iter().map(|name| storage_kind(name)).collect()
}

/// The storage named `name`.
fn storage_kind(name: &str) -> HostResult<StorageKind> {
    StorageKind::from_name(name).ok_or_else(|| invalid(format!("no storage {name:?}")))
}

/// The key choice flows of a call, by id; `None` for one whose storage dialog was
/// cancelled. An opened flow keeps its busy indicator up to its first key dialog.
#[derive(Default)]
pub(crate) struct Flows(Vec<Option<(KeyFlow, OpenedFlow)>>);

/// `keys_flow_open`: a key choice's storage dialog by the flow's rules; the opened flow
/// stays until the call returns, at most [`MAX_FLOWS`] in a call.
pub(crate) fn keys_flow_open(state: &mut HostState, args: FlowArgs) -> HostResult<FlowOutcome> {
    if state.call.flows.0.len() >= MAX_FLOWS {
        return Err(limit(format!("at most {MAX_FLOWS} key choices in a call")));
    }
    let flow = key_flow(state, args)?;
    let chooser = key_chooser(state);
    DialogTurn::hold();
    let open = chooser.open(&flow);
    let wrong_pin = open.wrong_pin.map(|wrong| FlowWrongPin {
        storage: wrong.storage.name().to_owned(),
        tries_left: wrong.tries_left,
    });
    let Some(opened) = open.opened else {
        state.call.flows.0.push(None);
        return Ok(FlowOutcome {
            opened: None,
            wrong_pin,
        });
    };
    let keys = opened
        .entries()
        .iter()
        .map(|entry| {
            Ok(FlowKey {
                alias: entry.alias.clone(),
                certificate: Bytes::from(der_of(&entry.cert)?),
            })
        })
        .collect::<HostResult<_>>()?;
    // At most MAX_FLOWS, which fits a u32.
    let id = state.call.flows.0.len() as u32;
    state.call.flows.0.push(Some((flow, opened)));
    Ok(FlowOutcome {
        opened: Some(FlowOpened { flow: id, keys }),
        wrong_pin,
    })
}

/// The core's flow of `args`, checked: known storages (offered as given, none for none) and
/// types, fixed readers that hold a token of their storage now, a start path a page may
/// name (else none), a detail line within [`MAX_LINE`] led by a plugin's name.
fn key_flow(state: &mut HostState, args: FlowArgs) -> HostResult<KeyFlow> {
    let storages = args
        .storages
        .iter()
        .map(|name| storage_kind(name))
        .collect::<HostResult<Vec<_>>>()?;
    let readers = match args.readers {
        FlowReaders::Live => Readers::Live,
        FlowReaders::None => Readers::None,
        FlowReaders::Fixed(list) => {
            let mut entries = Vec::with_capacity(list.len());
            for fixed in list {
                check_line("the reader", &fixed.reader, MAX_LINE)?;
                let storage = storage_kind(&fixed.storage)?;
                if !token_readers(state, storage)?.contains(&fixed.reader) {
                    return Err(invalid(format!(
                        "no token of {} is in the reader",
                        storage.name()
                    )));
                }
                entries.push(ReaderEntry {
                    storage,
                    reader: fixed.reader,
                });
            }
            Readers::Fixed(entries)
        }
    };
    let start = match args.start {
        FlowStart::Recent => StartPath::Recent,
        FlowStart::Empty => StartPath::Empty,
        FlowStart::Page(path) => {
            // A path a page may not name is not offered, however long.
            page_path(&path)
                .filter(|p| !p.as_os_str().is_empty())
                .map_or(StartPath::Empty, |p| StartPath::Given(p.to_path_buf()))
        }
    };
    let kinds = args
        .knca_types
        .map(|names| {
            names
                .iter()
                .map(|name| {
                    KncaCertType::from_name(name)
                        .ok_or_else(|| invalid(format!("no Kalkan type {name:?}")))
                })
                .collect::<HostResult<Vec<_>>>()
        })
        .transpose()?;
    let checks = match args.checks {
        FlowChecks::Settled => KeyChecks::Settled,
        FlowChecks::Live { filter, more } => {
            KeyChecks::Live(Box::new(key_filter(*filter, filter_more(*more)?)?))
        }
    };
    Ok(KeyFlow {
        origin: origin(state),
        locale: state.call.locale,
        action: basics_action(args.action),
        storages,
        readers,
        start,
        remember: args.remember,
        detail: dialog_detail(state, args.detail)?,
        password: PasswordRules {
            non_empty: args.non_empty_password,
            inner_policy: args.inner_password_policy,
        },
        same_storage: args.same_storage,
        file: match args.file {
            FlowFile::Open => FileRead::Open,
            FlowFile::Chosen => FileRead::Chosen,
        },
        kinds,
        none: match args.none {
            FlowNone::NoKeys => OpenError::NoKeys,
            FlowNone::NoSigningKeys => OpenError::NoSigningKeys,
            FlowNone::NoAuthKeys => OpenError::NoAuthKeys,
        },
        empty_is_none: args.empty_is_none,
        order: match args.order {
            FlowOrder::Store => KeyOrder::Store,
            FlowOrder::NewestFirst => KeyOrder::NewestFirst,
            FlowOrder::OldestFirst => KeyOrder::OldestFirst,
        },
        checks,
        skip_blocked_reader: args.skip_blocked_reader,
    })
}

/// `keys_flow_pick`: the key dialog of an opened flow, with the error line given; each key
/// picked is kept under a new handle.
pub(crate) fn keys_flow_pick(state: &mut HostState, args: PickArgs) -> HostResult<Option<Chosen>> {
    if let Some(error) = &args.error {
        check_line("the error", error, MAX_DIALOG_TEXT)?;
    }
    state.keys.has_room()?;
    let chooser = key_chooser(state);
    let Some(Some((flow, opened))) = state.call.flows.0.get_mut(args.flow as usize) else {
        return Err(invalid(format!("no key choice {} in this call", args.flow)));
    };
    DialogTurn::hold();
    let Some(index) = opened.pick(&chooser, flow, args.error) else {
        return Ok(None);
    };
    let entry = opened.entries()[index].clone();
    let certificate = der_of(&entry.cert)?;
    let alias = entry.alias.clone();
    let handle = state.keys.insert(entry, Arc::from([]))?;
    Ok(Some(Chosen {
        handle,
        alias,
        certificate: Bytes::from(certificate),
    }))
}

/// `keys_describe`: the alias, algorithm and certificate of a key the instance holds.
pub(crate) fn keys_describe(state: &mut HostState, args: Handle) -> HostResult<KeyDescription> {
    let entry = state.keys.get(args.handle)?;
    Ok(KeyDescription {
        alias: entry.alias.clone(),
        alg: match entry.key.alg() {
            KeyAlg::Gost2004 => "gost2004",
            KeyAlg::Gost2015_512 => "gost2015_512",
            KeyAlg::Rsa => "rsa",
        }
        .to_owned(),
        certificate: Bytes::from(der_of(&entry.cert)?),
    })
}

/// `tokens_scan`: whether token support is on, the storages of the tokens connected in
/// Kalkan's order, and whether a card of any kind is in a reader.
pub(crate) fn tokens_scan(state: &HostState) -> TokenScan {
    let tokens = &state.services.tokens;
    let present = tokens.scan().present;
    TokenScan {
        enabled: tokens.is_enabled(),
        present: TokenKind::ALL
            .into_iter()
            .filter(|kind| present.iter().any(|p| p.kind == *kind))
            .map(|kind| kind.storage_name().to_owned())
            .collect(),
        any_card: tokens.any_card(),
    }
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
            let from = match args.password {
                Password::Text(_) => PinFrom::Page,
                Password::Secret(id) => PinFrom::Typed(id),
            };
            return open_token(state, storage, &reader, &password, from);
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
    let (entries, store_certs) = match open_file_store(storage, &data, password) {
        Ok(opened) => opened,
        Err(outcome) => return Ok(outcome),
    };
    keep_opened(state, entries, store_certs)
}

/// The most encrypted safes a key store from a plugin may have: real stores have one or
/// two; each costs a key derivation before any key is read.
const MAX_ENCRYPTED_SAFES: usize = 4;

/// The keys of a key store file's contents, with the CA certificates a PKCS#12 store keeps
/// beside its keys (for `keys_chain`). A PKCS#12 store is read once, and refused as corrupt
/// before the work it would cost when it holds more keys than an instance keeps
/// ([`MAX_KEY_HANDLES`]) or more than [`MAX_ENCRYPTED_SAFES`] encrypted safes.
fn open_file_store(
    storage: StorageKind,
    data: &[u8],
    password: Zeroizing<String>,
) -> Result<(Vec<KeyEntry>, Arc<[Certificate]>), OpenOutcome> {
    if storage == StorageKind::Pkcs12 {
        let limits = pkcs12::Limits {
            key_bags: MAX_KEY_HANDLES,
            encrypted_safes: MAX_ENCRYPTED_SAFES,
        };
        let loaded = pkcs12::load_within(data, &password, &limits).map_err(|e| match e {
            Pkcs12Error::WrongPassword => OpenOutcome::WrongPassword { tries_left: None },
            Pkcs12Error::Malformed(_) | Pkcs12Error::Unsupported(_) => OpenOutcome::Corrupt,
        })?;
        if loaded.entries.is_empty() {
            return Err(OpenOutcome::NoKeys);
        }
        return Ok((loaded.entries, loaded.other_certs.into()));
    }
    let answer = StorageAnswer {
        storage,
        path: PathBuf::new(),
        password,
        reader: None,
    };
    match answer.open_data(data) {
        Ok(entries) => Ok((entries, Arc::from([]))),
        Err(e) => Err(match e {
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
        }),
    }
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
    let key = (ConsentKind::KeyStore, origin(state), canonical);
    if !state.consents.contains(&key) {
        let text = consent_text(state.call.locale, &key.1, &source(state), &shown(&key.2));
        let prompt = ConfirmPrompt {
            origin: key.1.clone(),
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
pub(super) fn shown(path: &Path) -> String {
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
/// its signatures until it is released or the instance ends. A PIN from the page (or a
/// typed one the card refused before) is sent only once the user allows it
/// ([`PagePins`]); declined, the outcome is [`OpenOutcome::Declined`] and nothing reaches
/// the card.
pub(crate) fn open_token(
    state: &mut HostState,
    storage: StorageKind,
    reader: &str,
    pin: &str,
    from: PinFrom,
) -> HostResult<OpenOutcome> {
    let Some(kind) = storage.token_kind() else {
        return Ok(OpenOutcome::NoDevice);
    };
    let origin = origin(state);
    let (locale, plugin) = (state.call.locale, source(state));
    let prompter = Arc::clone(&state.services.prompter);
    let ask = |tries| {
        let prompt = ConfirmPrompt {
            origin: origin.clone(),
            locale,
            text: page_pin_text(locale, &origin, &plugin, kind, reader, tries),
            source: plugin.clone(),
        };
        DialogTurn::hold();
        prompter.confirm(&prompt) == Prompt::Answer(true)
    };
    let pin_use = PinUse {
        origin: &origin,
        reader,
        kind,
        pin,
        from,
    };
    let opened = state.page_pins.open(&state.services.tokens, pin_use, ask);
    let entries = match opened {
        Ok(entries) => entries,
        Err(PinRefusal::Declined) => return Ok(OpenOutcome::Declined),
        Err(PinRefusal::Token(e)) => {
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
    chain_of(state, args.handle)?
        .iter()
        .map(|cert| der_of(cert).map(Bytes::from))
        .collect()
}

/// The certificate of the key `handle`, then its issuers up to a self-signed one.
fn chain_of(state: &HostState, handle: u32) -> HostResult<Vec<Certificate>> {
    let held = state.keys.held(handle)?;
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
    Ok(chain)
}

/// `keys_sign_cms`: a CAdES signature, time-stamped on its new signer if asked.
pub(crate) fn keys_sign_cms(state: &mut HostState, args: SignCmsArgs) -> HostResult<Bytes> {
    let entry = state.keys.get(args.handle)?;
    let opts = SignOptions {
        encapsulate: args.attached,
        digested: false,
        signing_time: (state.services.clock)(),
    };
    let mut der = cms::sign(entry, &args.data, &opts).map_err(cms_failed)?;
    if args.timestamp {
        let last = cms::signer_count(&der)
            .map_err(cms_failed)?
            .checked_sub(1)
            .ok_or_else(|| failed("the signed CMS has no signers"))?;
        der = tsp::timestamp_signer(
            &der,
            last,
            &state.services.tsa,
            state.services.http.as_ref(),
        )
        .map_err(|e| failed(&e).with_cause(cause::tsp(&e)))?;
    }
    Ok(Bytes::from(der))
}

/// `keys_sign_cms_ex`: a CMS signature as the plugin's profile says, time-stamped on its
/// new signer if asked; a failed time-stamp is an outcome, not an error.
pub(crate) fn keys_sign_cms_ex(
    state: &mut HostState,
    args: SignCmsExArgs,
) -> HostResult<CmsOutcome> {
    let content = match &args.content {
        CmsContent::Data(data) => Content::Data(data),
        CmsContent::Digest(digest) => Content::Digest(digest),
    };
    let into = match &args.cosign {
        abi::CoSign::Into(cms) => Some(cms.as_slice()),
        abi::CoSign::Auto | abi::CoSign::Never => None,
    };
    let output = args.output;
    Ok(match sign_cms_ex(state, &args, content, into)? {
        Ok(der) => CmsOutcome::Signed(cms_output(der, output)),
        Err(failure) => CmsOutcome::TspFailed(failure),
    })
}

/// [`keys_sign_cms_ex`] of `content`, co-signed into `into` for [`abi::CoSign::Into`]: the
/// DER CMS, or the failure of its time-stamp.
pub(crate) fn sign_cms_ex(
    state: &HostState,
    args: &SignCmsExArgs,
    content: Content<'_>,
    into: Option<&[u8]>,
) -> HostResult<Result<Vec<u8>, NetFailure>> {
    let tsa = args
        .timestamp
        .as_ref()
        .map(|choice| crypto::tsa_spec(state, choice))
        .transpose()?;
    let chain = match args.certificates {
        CmsCerts::Chain => chain_of(state, args.handle)?,
        CmsCerts::Signer | CmsCerts::Extra(_) => Vec::new(),
    };
    let certificates = match &args.certificates {
        CmsCerts::Signer => CertSpec::Signer,
        CmsCerts::Chain => CertSpec::Chain,
        CmsCerts::Extra(certs) => CertSpec::Extra(
            certs
                .iter()
                .map(|der| crypto::parse(der))
                .collect::<HostResult<_>>()?,
        ),
    };
    let oid =
        |text: &str| ObjectIdentifier::new(text).map_err(|e| invalid(format!("OID {text:?}: {e}")));
    let signing_time = match &args.attrs.signing_time {
        None => None,
        Some(time) => {
            let at = match time.at {
                TimeSource::Now => (state.services.clock)(),
                TimeSource::UnixMs(ms) => {
                    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
                        .map_err(|e| invalid(format!("signing time: {e}")))?
                }
            };
            let form = match time.form {
                abi::TimeForm::Auto => TimeForm::Auto,
                abi::TimeForm::Utc => TimeForm::Utc,
                abi::TimeForm::Generalized => TimeForm::Generalized,
            };
            Some((at, form))
        }
    };
    let extra = args
        .attrs
        .extra
        .iter()
        .map(|attr| {
            Ok((
                oid(&attr.oid)?,
                attr.values.iter().map(|v| v.to_vec()).collect(),
            ))
        })
        .collect::<HostResult<_>>()?;
    let spec = SignSpec {
        content,
        encapsulate: args.encapsulate,
        cosign: match &args.cosign {
            abi::CoSign::Auto => CoSign::Auto,
            abi::CoSign::Never => CoSign::Never,
            abi::CoSign::Into(cms) => CoSign::Into(into.unwrap_or(cms)),
        },
        econtent_type: args.econtent_type.as_deref().map(oid).transpose()?,
        digest: args.digest.map(crypto::hash_alg),
        attrs: AttrSpec {
            content_type: args.attrs.content_type,
            message_digest: args.attrs.message_digest,
            signing_certificate_v2: args.attrs.signing_certificate_v2,
            signing_time,
            extra,
        },
        certificates,
    };
    let entry = state.keys.get(args.handle)?;
    let der = cms::sign_spec(entry, &chain, &spec).map_err(|e| match e {
        CmsError::Key(_) | CmsError::UnknownAlgorithm(_) => cms_failed(e),
        e => invalid(e.to_string()).with_cause(cause::cms(&e)),
    })?;
    drop(spec);
    let Some(tsa) = tsa else {
        return Ok(Ok(der));
    };
    let spec = match tsa {
        Ok(spec) => spec,
        Err(failure) => return Ok(Err(failure)),
    };
    Ok(
        match tsp::stamp(
            &der,
            tsp::SignerSel::Last,
            &spec,
            tsp::StampMode::Replace,
            tsp::TokenForm::Token,
            &crypto::PkiHttp::of(state),
        ) {
            Ok(stamped) => Ok(stamped),
            Err(e) => Err(crypto::tsp_failure(&spec, &e)),
        },
    )
}

/// `der` in the form `output` asks for.
pub(crate) fn cms_output(der: Vec<u8>, output: abi::CmsOutput) -> Bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    match output {
        abi::CmsOutput::Der => Bytes::from(der),
        abi::CmsOutput::Base64 => Bytes::from(STANDARD.encode(&der).into_bytes()),
        abi::CmsOutput::Pem => {
            const DASHES: &str = "-----";
            let nl = crate::host::line_separator();
            let body = STANDARD.encode(&der);
            drop(der);
            let mut pem = String::with_capacity(body.len() + body.len() / 64 * nl.len() + 64);
            for part in [DASHES, "BEGIN CMS", DASHES, nl] {
                pem.push_str(part);
            }
            for line in body.as_bytes().chunks(64) {
                pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
                pem.push_str(nl);
            }
            for part in [DASHES, "END CMS", DASHES, nl] {
                pem.push_str(part);
            }
            Bytes::from(pem.into_bytes())
        }
    }
}

/// `keys_sign_raw`: the key's algorithm, RSA with SHA-256.
pub(crate) fn keys_sign_raw(state: &mut HostState, args: SignRawArgs) -> HostResult<Bytes> {
    let entry = state.keys.get(args.handle)?;
    let alg = match entry.key.alg() {
        KeyAlg::Gost2004 => SigAlg::Gost2004,
        KeyAlg::Gost2015_512 => SigAlg::Gost2015_512,
        KeyAlg::Rsa => SigAlg::RsaSha256,
    };
    let signature = entry
        .key
        .sign(alg, &args.data)
        .map_err(|e: KeyError| failed(&e).with_cause(cause::key(&e)))?;
    Ok(Bytes::from(signature))
}

/// `keys_sign_xml`: the whole document, or an element, with an enveloped signature.
pub(crate) fn keys_sign_xml(state: &mut HostState, args: SignXmlArgs) -> HostResult<Bytes> {
    sign_xml(state, &args, &args.xml).map(Bytes::from)
}

/// [`keys_sign_xml`] of the document `xml`.
pub(crate) fn sign_xml(state: &HostState, args: &SignXmlArgs, xml: &[u8]) -> HostResult<Vec<u8>> {
    let entry = state.keys.get(args.handle)?;
    match &args.element {
        None if args.parent.is_some() => Err(invalid("parent is only for a signed element")),
        None => xmldsig::sign_enveloped(xml, &entry.key, &entry.cert).map_err(xml_failed),
        Some(element) => xmldsig::sign_element(
            xml,
            element,
            args.parent.as_deref(),
            &entry.key,
            &entry.cert,
        )
        .map_err(xml_failed),
    }
}

/// The core's canonicalization of `method`.
fn c14n(method: C14n) -> xmldsig::C14n {
    match method {
        C14n::Inclusive => xmldsig::C14n::Inclusive,
        C14n::InclusiveWithComments => xmldsig::C14n::InclusiveWithComments,
        C14n::Exclusive => xmldsig::C14n::Exclusive,
        C14n::ExclusiveWithComments => xmldsig::C14n::ExclusiveWithComments,
    }
}

/// `keys_sign_xml_ex`: an XML signature as the arguments say.
pub(crate) fn keys_sign_xml_ex(state: &mut HostState, args: SignXmlExArgs) -> HostResult<Bytes> {
    let entry = state.keys.get(args.handle)?;
    let spec = xmldsig::XmlSignSpec {
        element: args.element.as_deref(),
        parent: args.parent.as_deref(),
        namespaces: args
            .namespaces
            .iter()
            .map(|b| (b.prefix.as_str(), b.uri.as_str()))
            .collect(),
        other_prefix_uri: args.other_prefix_uri.as_deref(),
        placement: match args.placement {
            Placement::DocumentElement => xmldsig::Placement::DocumentElement,
            Placement::FirstChildOfDocument => xmldsig::Placement::FirstChildOfDocument,
            Placement::Parent => xmldsig::Placement::Parent,
        },
        signature_method: args.signature_method.as_deref(),
        digest_method: args.digest_method.as_deref(),
        signed_info_c14n: args.signed_info_c14n.map(c14n),
        transforms: args.transforms.as_ref().map(|transforms| {
            transforms
                .iter()
                .map(|t| match t {
                    Transform::Enveloped => xmldsig::Transform::Enveloped,
                    Transform::C14n(method) => xmldsig::Transform::C14n(c14n(*method)),
                })
                .collect()
        }),
        signature_id: args.signature_id.as_deref(),
        signing_time_object: args.signing_time_object.as_ref().map(|object| {
            xmldsig::SigningTimeObject {
                property_id: &object.property_id,
                target_ref: object.target_ref,
                text: &object.text,
            }
        }),
        strip_whitespace: args.strip_whitespace,
        base64_line_breaks: args.base64_line_breaks,
        output: match args.output {
            XmlOutput::AsIs => xmldsig::XmlOutput::AsIs,
            XmlOutput::Serialize {
                declaration,
                standalone_no,
                trim,
            } => xmldsig::XmlOutput::Serialize {
                declaration,
                standalone_no,
                trim,
            },
        },
    };
    let signed =
        xmldsig::sign_spec(&args.xml, &spec, &entry.key, &entry.cert).map_err(xml_failed)?;
    Ok(Bytes::from(signed))
}

/// `keys_sign_xades`: a XAdES-BASELINE signature of the whole document; time-stamps and
/// OCSP requests only to the PKI hosts.
pub(crate) fn keys_sign_xades(state: &mut HostState, args: XadesArgs) -> HostResult<XadesOutcome> {
    let level = match args.level {
        XadesLevel::B => xades::XadesLevel::B,
        XadesLevel::T => xades::XadesLevel::T,
        XadesLevel::Lt => xades::XadesLevel::Lt,
    };
    let tsa = match level {
        xades::XadesLevel::B => None,
        _ => match crypto::tsa_spec(state, &args.tsa)? {
            Ok(spec) => Some(spec),
            Err(failure) => return Ok(XadesOutcome::Failed(failure)),
        },
    };
    let chain = args
        .chain
        .iter()
        .map(|der| crypto::parse(der))
        .collect::<HostResult<Vec<_>>>()?;
    let spec = xades::XadesSpec {
        level,
        tsa,
        chain,
        signature_method: args.signature_method.as_deref(),
        digest_method: args.digest_method.as_deref(),
    };
    let now = (state.services.clock)();
    let http = crypto::PkiHttp::of(state);
    let entry = state.keys.get(args.handle)?;
    Ok(
        match xades::sign(&args.xml, &spec, &entry.key, &entry.cert, &http, now) {
            Ok(signed) => XadesOutcome::Signed(Bytes::from(signed)),
            Err(xades::XadesError::Tsp(e)) => {
                let tsa = spec.tsa.as_ref().expect("a TSA stamped");
                XadesOutcome::Failed(crypto::tsp_failure(tsa, &e))
            }
            Err(xades::XadesError::Ocsp { url, error, .. }) => XadesOutcome::Failed(
                crypto::net_failure(NetStage::Ocsp, &url, error.kind(), error.to_string()),
            ),
            Err(xades::XadesError::OcspRejected { url, status, .. }) => {
                XadesOutcome::Failed(crypto::net_failure(
                    NetStage::Ocsp,
                    &url,
                    oncl_pki::http::NetKind::Rejected(status),
                    format!("OCSP response status {status}"),
                ))
            }
            Err(xades::XadesError::NotGood { status, .. }) => XadesOutcome::Invalid(match status {
                CertStatus::Revoked { time, reason } => Problem::Revoked {
                    at_ms: crate::host::unix_ms(time),
                    reason,
                },
                CertStatus::Good | CertStatus::Unknown => Problem::StatusUnknown,
            }),
            Err(xades::XadesError::Crl {
                url,
                error: error @ (CrlError::NoUrl | CrlError::Http(_) | CrlError::HttpStatus(_)),
                ..
            }) => XadesOutcome::Failed(crypto::net_failure(
                NetStage::Crl,
                &url,
                error.kind(),
                error.to_string(),
            )),
            Err(xades::XadesError::Crl { .. }) => XadesOutcome::Invalid(Problem::CrlInvalid),
            Err(e @ xades::XadesError::NoIssuer(_)) => return Err(invalid(e.to_string())),
            Err(xades::XadesError::Xml(e)) => return Err(xml_failed(e)),
        },
    )
}

/// A CMS that did not sign: `failed` with its cause.
fn cms_failed(e: CmsError) -> HostError {
    failed(&e).with_cause(cause::cms(&e))
}

/// An XML document that did not sign: `failed` with its cause.
fn xml_failed(e: xmldsig::XmlError) -> HostError {
    failed(&e).with_cause(cause::xml(&e))
}

/// `keys_release`.
pub(crate) fn keys_release(state: &mut HostState, args: Handle) -> HostResult<()> {
    state.keys.remove(args.handle)
}
