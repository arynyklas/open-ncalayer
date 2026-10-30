//! The host functions of the capabilities a manifest declares:
//!
//! - `keys`: the user's key, chosen in the storage and key dialogs ([`KeyChooser`]), behind a
//!   handle of the instance; signatures made here, the private key never reaching the guest;
//! - `dialogs`: a message and a yes/no question;
//! - `files`: a file the user opens or saves in the system dialogs;
//! - `http`: HTTPS requests to URLs under the manifest's prefixes, redirects not followed.
//!
//! The first host function that shows a window takes the process-wide dialog-flow turn
//! ([`lock_dialog_flow`]) and holds it until `oncl_process` returns, trap or not
//! ([`DialogTurn`]), so a plugin's dialogs and those of other modules do not interleave.

use crate::host::HostState;
use crate::manifest::HttpPrefix;
use oncl_basics::{
    ChainPolicy, ConfirmPrompt, FileKind, FilePrompt, KeyChooser, KeyFilter, KeyRequest,
    MAX_PAGE_FILE, MessagePrompt, PageFile, PageFileError, Prompt, SavePrompt, StorageKind,
    is_device_path, lock_dialog_flow, remember_chosen_path,
};
use oncl_pdk::abi::{
    Action, Bytes, ChooseArgs, Chosen, ConfirmArgs, ErrorCode, Filter, Handle, HostError,
    HostResult, HttpArgs, HttpResponse, MessageArgs, MessageKind, Method, OpenedFile, SaveArgs,
    SignCmsArgs, SignRawArgs, SignXmlArgs,
};
use oncl_pki::cms::{self, SignOptions};
use oncl_pki::fsutil::{Access, write_atomically};
use oncl_pki::http::{CONNECT_TIMEOUT, GetOptions, HttpTransport};
use oncl_pki::key::{KeyAlg, SigAlg};
use oncl_pki::pkcs12::KeyEntry;
use oncl_pki::pkix::CaSet;
use oncl_pki::{cert, tsp, xmldsig};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, MutexGuard};
use std::time::Duration;

/// The most keys an instance holds at once.
pub const MAX_KEY_HANDLES: usize = 16;

/// The largest body of an HTTP request or reply.
pub const MAX_HTTP_BODY: u64 = 32 << 20;

/// The most HTTP requests of one `oncl_process` call: more are a `limit` error.
pub const MAX_HTTP_REQUESTS: u32 = 64;

/// The timeout of an HTTP request, connecting to reading the reply.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// Longest text of a message or a question, in bytes.
const MAX_DIALOG_TEXT: usize = 16 << 10;

/// Longest `detail` of `keys_choose` and suggested file name, in bytes.
const MAX_LINE: usize = 1024;

/// Origin shown when the connection sent none.
const UNIDENTIFIED: &str = "UNIDENTIFIED";

thread_local! {
    /// The dialog-flow turn this thread's request holds, once a dialog was shown.
    static TURN: RefCell<Option<MutexGuard<'static, ()>>> = const { RefCell::new(None) };
    /// How many [`DialogTurn`] scopes are open on this thread.
    static SCOPES: Cell<usize> = const { Cell::new(0) };
}

/// The span of one `oncl_process` call on this thread: the dialog-flow turn a host function
/// takes in it is let go when the outermost scope ends, whatever ended it.
pub(crate) struct DialogTurn(());

impl DialogTurn {
    /// Opens a scope.
    pub(crate) fn scope() -> DialogTurn {
        SCOPES.set(SCOPES.get() + 1);
        DialogTurn(())
    }

    /// Takes the turn for the rest of the scope, unless this thread has it already.
    fn hold() {
        TURN.with_borrow_mut(|turn| {
            if turn.is_none() {
                *turn = Some(lock_dialog_flow());
            }
        });
    }
}

impl Drop for DialogTurn {
    fn drop(&mut self) {
        let open = SCOPES.get().saturating_sub(1);
        SCOPES.set(open);
        if open == 0 {
            TURN.with_borrow_mut(|turn| drop(turn.take()));
        }
    }
}

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

fn invalid(message: impl Into<String>) -> HostError {
    HostError::new(ErrorCode::Invalid, message)
}

fn failed(message: impl std::fmt::Display) -> HostError {
    HostError::new(ErrorCode::Failed, message.to_string())
}

fn limit(message: impl Into<String>) -> HostError {
    HostError::new(ErrorCode::Limit, message)
}

/// The page's origin, as the dialogs show it.
fn origin(state: &HostState) -> String {
    state
        .call
        .origin
        .clone()
        .unwrap_or_else(|| UNIDENTIFIED.to_owned())
}

/// The plugin's name in the request's language, as the dialogs show it.
fn source(state: &HostState) -> String {
    state.session.plugin_name.get(state.call.locale).to_owned()
}

fn check_line(what: &str, text: &str, max: usize) -> HostResult<()> {
    if text.len() > max {
        return Err(limit(format!("{what} is over {max} bytes")));
    }
    Ok(())
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

/// `dialog_message`.
pub(crate) fn dialog_message(state: &mut HostState, args: MessageArgs) -> HostResult<()> {
    check_line("the text", &args.text, MAX_DIALOG_TEXT)?;
    let prompt = MessagePrompt {
        origin: origin(state),
        locale: state.call.locale,
        source: source(state),
        kind: match args.kind {
            MessageKind::Info => oncl_basics::MessageKind::Info,
            MessageKind::Warning => oncl_basics::MessageKind::Warning,
            MessageKind::Error => oncl_basics::MessageKind::Error,
        },
        text: args.text,
    };
    DialogTurn::hold();
    // Read or closed: the plugin goes on either way.
    let _ = state.services.prompter.message(&prompt);
    Ok(())
}

/// `dialog_confirm`: `true` only for yes.
pub(crate) fn dialog_confirm(state: &mut HostState, args: ConfirmArgs) -> HostResult<bool> {
    check_line("the text", &args.text, MAX_DIALOG_TEXT)?;
    let prompt = ConfirmPrompt {
        origin: origin(state),
        locale: state.call.locale,
        source: source(state),
        text: args.text,
    };
    DialogTurn::hold();
    Ok(state.services.prompter.confirm(&prompt) == Prompt::Answer(true))
}

/// `file_open`: a file the user chooses, at most [`MAX_PAGE_FILE`] bytes.
pub(crate) fn file_open(state: &mut HostState) -> HostResult<Option<OpenedFile>> {
    let prompt = FilePrompt {
        origin: origin(state),
        locale: state.call.locale,
        kind: FileKind::All,
        directory: None,
    };
    DialogTurn::hold();
    let path = match state.services.prompter.file(&prompt) {
        Prompt::Answer(path) => path,
        Prompt::Cancelled => return Ok(None),
    };
    let file = PageFile::read_chosen(&path).map_err(|e| match e {
        PageFileError::TooLarge => limit(format!("the file is over {MAX_PAGE_FILE} bytes")),
        PageFileError::NotFound => failed(format!("{} cannot be read", path.display())),
    })?;
    remember_chosen_path(&path);
    Ok(Some(OpenedFile {
        path: file.shown,
        data: Bytes::from(file.data),
    }))
}

/// `file_save`: the data written, through a temporary file, where the user chooses.
pub(crate) fn file_save(state: &mut HostState, args: SaveArgs) -> HostResult<Option<String>> {
    if args.data.len() as u64 > MAX_PAGE_FILE {
        return Err(limit(format!("the data is over {MAX_PAGE_FILE} bytes")));
    }
    check_line("the file name", &args.suggested_name, MAX_LINE)?;
    let suggested_name = Path::new(&args.suggested_name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();
    let prompt = SavePrompt {
        origin: origin(state),
        locale: state.call.locale,
        source: source(state),
        suggested_name,
        directory: None,
    };
    DialogTurn::hold();
    let path = match state.services.prompter.save_file(&prompt) {
        Prompt::Answer(path) => path,
        Prompt::Cancelled => return Ok(None),
    };
    let text = path
        .to_str()
        .ok_or_else(|| failed("the chosen path is not Unicode"))?;
    if is_device_path(text) {
        return Err(failed(format!("{text} is not a file path")));
    }
    write_atomically(&path, &args.data, Access::Default)
        .map_err(|e| failed(format!("{}: {e}", path.display())))?;
    Ok(Some(text.to_owned()))
}

/// `http_request`: one HTTPS request to a URL under a prefix of the manifest, sent as
/// checked, without following redirects; at most [`MAX_HTTP_REQUESTS`] in one call.
pub(crate) fn http_request(state: &mut HostState, args: HttpArgs) -> HostResult<HttpResponse> {
    let url = allowed_url(&state.capabilities.http, &args.url)?;
    if args.body.len() as u64 > MAX_HTTP_BODY {
        return Err(limit(format!("the body is over {MAX_HTTP_BODY} bytes")));
    }
    if state.call.http_requests >= MAX_HTTP_REQUESTS {
        return Err(limit(format!(
            "at most {MAX_HTTP_REQUESTS} HTTP requests in one call"
        )));
    }
    state.call.http_requests += 1;
    let opts = GetOptions {
        timeout: HTTP_TIMEOUT,
        connect_timeout: CONNECT_TIMEOUT,
        max_len: MAX_HTTP_BODY,
        https_only: true,
        redirects: false,
    };
    let http: &dyn HttpTransport = state.services.http.as_ref();
    let reply = match args.method {
        Method::Get if !args.body.is_empty() || args.content_type.is_some() => {
            return Err(invalid("a GET has no body"));
        }
        Method::Get => http.get_with(url.as_str(), opts),
        Method::Post => http.post_with(
            url.as_str(),
            args.content_type
                .as_deref()
                .unwrap_or("application/octet-stream"),
            &args.body,
            opts,
        ),
    }
    .map_err(failed)?;
    Ok(HttpResponse {
        status: reply.status,
        content_type: reply.content_type,
        location: reply.location,
        body: Bytes::from(reply.body),
    })
}

/// `url` as checked under the first of `prefixes` that allows it, without its fragment
/// (which stays with the client, as in browsers).
fn allowed_url(prefixes: &[HttpPrefix], url: &str) -> HostResult<url::Url> {
    let mut checked = prefixes
        .iter()
        .find_map(|prefix| prefix.check(url))
        .ok_or_else(|| {
            HostError::new(
                ErrorCode::Denied,
                format!("{url} is not under the plugin's HTTP prefixes"),
            )
        })?;
    checked.set_fragment(None);
    Ok(checked)
}
