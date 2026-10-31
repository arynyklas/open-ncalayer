//! The host side of the ABI: what an instance's store holds, the host functions as the
//! linker defines them, and the guest memory they read and write. Every host function reads
//! its CBOR argument from the guest, runs, and writes its CBOR [`HostResult`] into a buffer
//! of the guest's `oncl_alloc`.

use crate::caps::{self, CallData, Consents, Flows, KeyFiles, KeyTable, RequestBudget, Secrets};
use crate::core::{self, CoreHooks};
use crate::manifest::Capabilities;
use crate::runtime::SessionContext;
use oncl_flows::{Locale, OcspCache, PagePins, Prompter, RecentPathStore};
use oncl_pdk::abi::{
    self, CertArgs, CertInfo, ErrorCode, HostError, HostResult, IMPORT_MODULE, Import, KeyUsage,
    Level, LocalTime, LocalTimeArgs, LocaleArgs, LogArgs, MAX_RANDOM, Os, Platform, RandomArgs,
};
use oncl_pki::http::HttpTransport;
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::TsaProfile;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;
use time::OffsetDateTime;
use wasmi::{Caller, Linker, Memory, StoreLimits, TypedFunc};

/// Longest `log` line kept, in bytes; the rest is cut.
const MAX_LOG_LINE: usize = 4096;

/// What the host functions use: the dialogs, the key checks, the network, the clock.
#[derive(Clone)]
pub struct HostServices {
    /// Shows the dialogs.
    pub prompter: Arc<dyn Prompter>,
    /// The last opened key store path.
    pub recent: Arc<dyn RecentPathStore>,
    /// The network: OCSP checks of the keys offered, time-stamps, the `http` capability.
    pub http: Arc<dyn HttpTransport>,
    /// The OCSP memory shared with the basics module.
    pub ocsp_cache: Arc<OcspCache>,
    /// Where `keys_sign_cms` time-stamps.
    pub tsa: TsaProfile,
    /// The time of `now`, signatures and key checks.
    pub clock: fn() -> OffsetDateTime,
    /// The language of OpenNCALayer's windows now.
    pub locale: Arc<dyn Fn() -> Locale + Send + Sync>,
    /// The CAs of `ca_list`, `ca_issuer` and the chains of `keys_chain`: the NCA's
    /// ([`CaSet::nca_production`]).
    pub cas: Arc<CaSet>,
    /// The only hosts (and their subdomains) the core asks for time-stamps, OCSP and CRLs
    /// on a plugin's behalf: the NCA's ([`crate::nca_pki_hosts`]).
    pub pki_hosts: Arc<[String]>,
    /// The folder of the plugins' settings files (`<data>/plugins/settings`,
    /// [`crate::Store::settings_dir`]); `None`: `settings_*` fail.
    pub settings_dir: Option<PathBuf>,
    /// The hardware tokens of `keys_choose`, `keys_terminals` and `keys_open`, while their
    /// support is on.
    pub tokens: Arc<oncl_token::Tokens>,
    /// What the `core_*` functions of the built-in modules answer and do; `None`: they
    /// fail.
    pub core: Option<Arc<CoreHooks>>,
}

impl HostServices {
    /// Services showing the dialogs with `prompter`, remembering the key store path in
    /// `recent`, reaching the network through `http` and the hardware tokens of `tokens`;
    /// the rest as the daemon has it by default: the basics TSA profile, the system clock,
    /// Russian windows, the NCA's CAs and PKI hosts, no settings folder and an empty OCSP
    /// memory.
    pub fn new(
        prompter: Arc<dyn Prompter>,
        recent: Arc<dyn RecentPathStore>,
        http: Arc<dyn HttpTransport>,
        tokens: Arc<oncl_token::Tokens>,
    ) -> Self {
        HostServices {
            prompter,
            recent,
            http,
            ocsp_cache: Arc::new(OcspCache::new()),
            tsa: TsaProfile::basics_default(),
            clock: OffsetDateTime::now_utc,
            locale: Arc::new(|| Locale::Ru),
            cas: Arc::new(CaSet::nca_production()),
            pki_hosts: crate::nca_pki_hosts(),
            settings_dir: None,
            tokens,
            core: None,
        }
    }
}

/// Who runs in an instance now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Nothing.
    Idle,
    /// The guest's `oncl_process`: host functions may be called.
    Guest,
    /// The host (a host function, or the host calling `oncl_alloc` or `oncl_free`): a host
    /// function called now is a re-entry, and traps.
    Host,
}

/// The request being answered.
pub(crate) struct CallContext {
    /// The page's origin, if any.
    pub(crate) origin: Option<String>,
    /// The language of the windows during this request.
    pub(crate) locale: Locale,
    /// The plugin asked for the connection to be dropped instead of a reply (`reply_drop`).
    pub(crate) drop: bool,
    /// The HTTP requests sent during this request, the core's PKI requests included.
    pub(crate) http_requests: RequestBudget,
    /// The key choice flows opened during this request, with their busy indicators.
    pub(crate) flows: Flows,
    /// The folders the key file windows answered during this request, and the keys and
    /// certificates it asked for.
    pub(crate) key_files: KeyFiles,
    /// The data kept for a built-in module during this request.
    pub(crate) data: Option<CallData>,
}

/// An instance's store data.
pub(crate) struct HostState {
    pub(crate) limits: StoreLimits,
    pub(crate) services: HostServices,
    pub(crate) session: SessionContext,
    pub(crate) capabilities: Arc<Capabilities>,
    pub(crate) phase: Phase,
    pub(crate) call: CallContext,
    pub(crate) keys: KeyTable,
    /// The passwords of `dialog_password`.
    pub(crate) secrets: Secrets,
    /// The page files the user allowed the pages to open in this session.
    pub(crate) consents: Consents,
    /// The token PINs from the pages the user allowed in this session.
    pub(crate) page_pins: PagePins,
    guest: Option<(Memory, TypedFunc<i32, i32>)>,
    /// The largest argument or result of a host function.
    max_transfer: usize,
    /// The most bytes of data kept for a call (`0`: none kept, the call has no
    /// [`CallData`]).
    max_kept: usize,
}

impl HostState {
    pub(crate) fn new(
        limits: StoreLimits,
        services: HostServices,
        session: SessionContext,
        capabilities: Arc<Capabilities>,
        max_transfer: usize,
        max_kept: usize,
    ) -> Self {
        HostState {
            limits,
            services,
            session,
            capabilities,
            phase: Phase::Idle,
            call: CallContext {
                origin: None,
                locale: Locale::Ru,
                drop: false,
                http_requests: RequestBudget::default(),
                flows: Flows::default(),
                key_files: KeyFiles::default(),
                data: None,
            },
            keys: KeyTable::default(),
            secrets: Secrets::default(),
            consents: Consents::default(),
            page_pins: PagePins::default(),
            guest: None,
            max_transfer,
            max_kept,
        }
    }

    /// The guest's memory and allocator, once instantiated.
    pub(crate) fn attach(&mut self, memory: Memory, alloc: TypedFunc<i32, i32>) {
        self.guest = Some((memory, alloc));
    }

    /// A request from `origin` starts.
    pub(crate) fn begin_call(&mut self, origin: Option<String>, locale: Locale) {
        self.call = CallContext {
            origin,
            locale,
            drop: false,
            http_requests: RequestBudget::default(),
            flows: Flows::default(),
            key_files: KeyFiles::default(),
            data: (self.max_kept > 0).then(|| CallData::new(self.max_kept)),
        };
    }

    /// The request is answered: its flows and the folders of its windows end.
    pub(crate) fn end_call(&mut self) {
        self.phase = Phase::Idle;
        self.call.origin = None;
        self.call.flows = Flows::default();
        self.call.key_files = KeyFiles::default();
        self.call.data = None;
    }

    /// Lets go of every key, password and consent: the instance is spent, or goes back to
    /// a pool for anyone's next call.
    pub(crate) fn release_all(&mut self) {
        self.keys = KeyTable::default();
        self.secrets = Secrets::default();
        self.consents = Consents::default();
        self.page_pins = PagePins::default();
    }
}

/// A trap of a host function: the request fails with `message`.
pub(crate) fn trap(message: impl Into<String>) -> wasmi::Error {
    wasmi::Error::new(message.into())
}

/// The `len` bytes at `ptr` of guest memory `data`.
pub(crate) fn read_guest(data: &[u8], ptr: u32, len: u32) -> Result<&[u8], wasmi::Error> {
    let start = ptr as usize;
    start
        .checked_add(len as usize)
        .and_then(|end| data.get(start..end))
        .ok_or_else(|| {
            trap(format!(
                "{len} bytes at {ptr} are outside the guest's memory"
            ))
        })
}

/// Writes `bytes` at `ptr` of guest memory `data`; `ptr` came from the guest's `oncl_alloc`.
pub(crate) fn write_guest(data: &mut [u8], ptr: i32, bytes: &[u8]) -> Result<(), wasmi::Error> {
    if ptr == 0 {
        return Err(trap("oncl_alloc returned no buffer"));
    }
    // The guest's i32 is an address of its 32-bit memory.
    let start = ptr as u32 as usize;
    let target = start
        .checked_add(bytes.len())
        .and_then(|end| data.get_mut(start..end))
        .ok_or_else(|| {
            trap(format!(
                "oncl_alloc returned {} bytes at {start}, outside the guest's memory",
                bytes.len()
            ))
        })?;
    target.copy_from_slice(bytes);
    Ok(())
}

/// Defines the host function `import` in `linker`. A panic of the host function (a
/// prompter's, a capability's) traps: it cannot unwind through the interpreter, which
/// would abort the process, so the call fails as on any other trap.
pub(crate) fn define(linker: &mut Linker<HostState>, import: Import) -> Result<(), wasmi::Error> {
    linker.func_wrap(
        IMPORT_MODULE,
        import.name(),
        move |caller: Caller<'_, HostState>, ptr: i32, len: i32| {
            panic::catch_unwind(AssertUnwindSafe(|| call(caller, import, ptr, len))).unwrap_or_else(
                |payload| {
                    let message = payload
                        .downcast_ref::<&str>()
                        .copied()
                        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                        .unwrap_or("a non-string payload");
                    Err(trap(format!(
                        "the host function {} panicked: {message}",
                        import.name()
                    )))
                },
            )
        },
    )?;
    Ok(())
}

/// Runs the host function `import` on the argument at `ptr`/`len`: its result goes into a
/// buffer of the guest's `oncl_alloc`, returned packed. Only while the guest's
/// `oncl_process` runs; anything else traps.
fn call(
    mut caller: Caller<'_, HostState>,
    import: Import,
    ptr: i32,
    len: i32,
) -> Result<i64, wasmi::Error> {
    if caller.data().phase != Phase::Guest {
        return Err(trap(format!(
            "the host function {} was called while the host was running",
            import.name()
        )));
    }
    let Some((memory, alloc)) = caller.data().guest else {
        return Err(trap("the instance is not set up"));
    };
    caller.data_mut().phase = Phase::Host;
    let (ptr, len) = (ptr as u32, len as u32);
    let max = caller.data().max_transfer;
    if len as usize > max {
        return Err(trap(format!(
            "the argument of {} is over {max} bytes",
            import.name()
        )));
    }
    let args = read_guest(memory.data(&caller), ptr, len)?.to_vec();
    let reply = dispatch(caller.data_mut(), import, &args);
    if reply.len() > max {
        return Err(trap(format!(
            "the result of {} is over {max} bytes",
            import.name()
        )));
    }
    // Within the limit, which fits an i32.
    let reply_len = reply.len() as i32;
    let reply_ptr = alloc.call(&mut caller, reply_len)?;
    write_guest(memory.data_mut(&mut caller), reply_ptr, &reply)?;
    caller.data_mut().phase = Phase::Guest;
    Ok(abi::pack(reply_ptr as u32, reply_len as u32))
}

/// The CBOR [`HostResult`] of `import` on the CBOR `args`.
fn dispatch(state: &mut HostState, import: Import, args: &[u8]) -> Vec<u8> {
    match import {
        Import::Log => run(args, |a| log(state, a)),
        Import::Now => run(args, |()| Ok(unix_ms((state.services.clock)()))),
        Import::Random => run(args, random),
        Import::CertInfo => run(args, cert_info),
        Import::KeysChoose => run(args, |a| caps::keys_choose(state, a)),
        Import::KeysSignCms => run(args, |a| caps::keys_sign_cms(state, a)),
        Import::KeysSignRaw => run(args, |a| caps::keys_sign_raw(state, a)),
        Import::KeysSignXml => run(args, |a| caps::keys_sign_xml(state, a)),
        Import::KeysRelease => run(args, |a| caps::keys_release(state, a)),
        Import::DialogMessage => run(args, |a| caps::dialog_message(state, a)),
        Import::DialogConfirm => run(args, |a| caps::dialog_confirm(state, a)),
        Import::FileOpen => run(args, |()| caps::file_open(state)),
        Import::FileSave => run(args, |a| caps::file_save(state, a)),
        Import::HttpRequest => run(args, |a| caps::http_request(state, a)),
        Import::ReplyDrop => run(args, |()| {
            state.call.drop = true;
            Ok(())
        }),
        Import::Hash => run(args, caps::hash),
        Import::CertDetails => run(args, caps::cert_details),
        Import::LocalTime => run(args, |a: LocalTimeArgs| {
            Ok(LocalTime {
                offset_seconds: local_offset_seconds(a.unix_ms),
            })
        }),
        Import::Platform => run(args, |()| Ok(platform())),
        Import::CaList => run(args, |()| Ok(caps::ca_list(state))),
        Import::CaIssuer => run(args, |a| caps::ca_issuer(state, a)),
        Import::KeysSelect => run(args, |a| caps::keys_select(state, a)),
        Import::KeysChain => run(args, |a| caps::keys_chain(state, a)),
        Import::KeysTerminals => run(args, |a| caps::keys_terminals(state, a)),
        Import::KeysOpen => run(args, |a| caps::keys_open(state, a)),
        Import::DialogPassword => run(args, |a| caps::dialog_password(state, a)),
        Import::KeysSignCmsEx => run(args, |a| caps::keys_sign_cms_ex(state, a)),
        Import::TspStamp => run(args, |a| caps::tsp_stamp(state, a)),
        Import::TspRequest => run(args, |a| caps::tsp_request(state, a)),
        Import::OcspFetch => run(args, |a| caps::ocsp_fetch(state, a)),
        Import::CrlFetch => run(args, |a| caps::crl_fetch(state, a)),
        Import::CmsVerify => run(args, |a| caps::cms_verify(state, a)),
        Import::KeysSignXmlEx => run(args, |a| caps::keys_sign_xml_ex(state, a)),
        Import::XmlVerify => run(args, caps::xml_verify),
        Import::HttpRequestEx => run(args, |a| caps::http_request_ex(state, a)),
        Import::FileChoose => run(args, |a| caps::file_choose(state, a)),
        Import::FileOpenEx => run(args, |a| caps::file_open_ex(state, a)),
        Import::PageFileRead => run(args, |a| caps::page_file_read(state, a)),
        Import::PageFileWrite => run(args, |a| caps::page_file_write(state, a)),
        Import::DialogChoice => run(args, |a| caps::dialog_choice(state, a)),
        Import::SettingsGet => run(args, |()| caps::settings_get(state)),
        Import::SettingsPut => run(args, |a| caps::settings_put(state, a)),
        Import::SharedGet => run(args, |a| caps::shared_get(state, a)),
        Import::SharedPut => run(args, |a| caps::shared_put(state, a)),
        Import::KeysSignXades => run(args, |a| caps::keys_sign_xades(state, a)),
        Import::CallLocale => run(args, |a| call_locale(state, a)),
        Import::KeysFlowOpen => run(args, |a| caps::keys_flow_open(state, a)),
        Import::KeysFlowPick => run(args, |a| caps::keys_flow_pick(state, a)),
        Import::KeysDescribe => run(args, |a| caps::keys_describe(state, a)),
        Import::TokensScan => run(args, |()| Ok(caps::tokens_scan(state))),
        Import::DialogReader => run(args, |a| caps::dialog_reader(state, a)),
        Import::FileChooseKind => run(args, |a| caps::file_choose_kind(state, a)),
        Import::PkixPath => run(args, |a| caps::pkix_path(state, a)),
        Import::CoreModules => run(args, |()| core::core_modules(state)),
        Import::CoreBundles => run(args, |()| core::core_bundles(state)),
        Import::CoreInstallBundle => run(args, |a| core::core_install_bundle(state, a)),
        Import::CoreOpenWindow => run(args, |a| core::core_open_window(state, a)),
        Import::DialogCsr => run(args, |a| caps::dialog_csr(state, a)),
        Import::DialogImport => run(args, |a| caps::dialog_import(state, a)),
        Import::KeystoreNewKey => run(args, |a| caps::keystore_new_key(state, a)),
        Import::KeystoreInstallCert => run(args, |a| caps::keystore_install_cert(state, a)),
        Import::KeystoreChangePassword => run(args, |a| caps::keystore_change_password(state, a)),
        Import::TokensIdCard => run(args, |a| caps::tokens_id_card(state, a)),
        Import::DataRead => run(args, |a| caps::data_read(state, a)),
        Import::DataDecode => run(args, |a| caps::data_decode(state, a)),
        Import::DataEncode => run(args, |a| caps::data_encode(state, a)),
        Import::DataSignCms => run(args, |a| caps::data_sign_cms(state, a)),
        Import::DataSignXml => run(args, |a| caps::data_sign_xml(state, a)),
        Import::DataSignRaw => run(args, |a| caps::data_sign_raw(state, a)),
        Import::DataStamp => run(args, |a| caps::data_stamp(state, a)),
        Import::DataPageRead => run(args, |a| caps::data_page_read(state, a)),
    }
}

/// `call_locale`: the windows in `locale` until the call returns.
fn call_locale(state: &mut HostState, args: LocaleArgs) -> HostResult<()> {
    state.call.locale = match args.locale.as_str() {
        "ru" => Locale::Ru,
        "kk" => Locale::Kk,
        "en" => Locale::En,
        _ => {
            return Err(HostError::new(
                ErrorCode::Invalid,
                "the language is not ru, kk or en",
            ));
        }
    };
    Ok(())
}

/// `platform`: the operating system and its line separator.
fn platform() -> Platform {
    let os = if cfg!(windows) {
        Os::Windows
    } else if cfg!(target_os = "macos") {
        Os::Macos
    } else {
        Os::Linux
    };
    Platform {
        os,
        line_separator: line_separator().to_owned(),
    }
}

/// The system's line separator: `"\r\n"` on Windows, `"\n"` elsewhere.
pub(crate) fn line_separator() -> &'static str {
    if cfg!(windows) { "\r\n" } else { "\n" }
}

/// The offset from UTC of the system's time zone at `unix_ms`, in seconds; `0` if the
/// system cannot say.
#[cfg(windows)]
fn local_offset_seconds(unix_ms: i64) -> i32 {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{
        FileTimeToSystemTime, SystemTimeToFileTime, SystemTimeToTzSpecificLocalTime,
    };
    /// 100 ns intervals from 1601-01-01 to 1970-01-01.
    const EPOCH_DIFFERENCE: i64 = 116_444_736_000_000_000;
    let Some(ticks) = unix_ms
        .checked_mul(10_000)
        .and_then(|t| t.checked_add(EPOCH_DIFFERENCE))
        .filter(|t| *t >= 0)
    else {
        return 0;
    };
    let utc_file = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut utc: SYSTEMTIME = unsafe { std::mem::zeroed() };
    let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
    let mut local_file = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: valid pointers to initialized structures for the duration of the calls; a
    // null time zone is the system's current one.
    let converted = unsafe {
        FileTimeToSystemTime(&utc_file, &mut utc) != 0
            && SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) != 0
            && SystemTimeToFileTime(&local, &mut local_file) != 0
    };
    if !converted {
        return 0;
    }
    let local_ticks =
        (i64::from(local_file.dwHighDateTime) << 32) | i64::from(local_file.dwLowDateTime);
    // Both come from the same millisecond: the difference is whole seconds.
    ((local_ticks - ticks) / 10_000_000) as i32
}

/// The offset from UTC of the system's time zone at `unix_ms`, in seconds; `0` if the
/// system cannot say.
#[cfg(unix)]
fn local_offset_seconds(unix_ms: i64) -> i32 {
    let seconds = unix_ms.div_euclid(1000) as libc::time_t;
    // SAFETY: `tm` is plain data; `localtime_r` writes it and reads `seconds` only.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let converted = unsafe { !libc::localtime_r(&seconds, &mut tm).is_null() };
    if converted { tm.tm_gmtoff as i32 } else { 0 }
}

/// `f` on `args` decoded, its result encoded.
fn run<A: DeserializeOwned, R: Serialize>(
    args: &[u8],
    f: impl FnOnce(A) -> HostResult<R>,
) -> Vec<u8> {
    abi::encode(&abi::decode(args).and_then(f))
}

/// `log`: the text in the log as a field (quoted and escaped: it cannot forge a line), with
/// the plugin and the session.
fn log(state: &HostState, args: LogArgs) -> HostResult<()> {
    let mut message = args.message;
    if message.len() > MAX_LOG_LINE {
        let mut end = MAX_LOG_LINE;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
        message.push('…');
    }
    let plugin = state.session.plugin_id.as_str();
    let session = state.session.session;
    let text = message.as_str();
    match args.level {
        Level::Error => tracing::error!(plugin, session, text, "plugin log"),
        Level::Warn => tracing::warn!(plugin, session, text, "plugin log"),
        Level::Info => tracing::info!(plugin, session, text, "plugin log"),
        Level::Debug => tracing::debug!(plugin, session, text, "plugin log"),
    }
    Ok(())
}

/// `t` in Unix milliseconds.
pub(crate) fn unix_ms(t: OffsetDateTime) -> i64 {
    // Milliseconds of any OffsetDateTime fit an i64.
    (t.unix_timestamp_nanos() / 1_000_000) as i64
}

/// `random`: at most [`MAX_RANDOM`] bytes of the system's generator.
fn random(args: RandomArgs) -> HostResult<abi::Bytes> {
    if args.len > MAX_RANDOM {
        return Err(HostError::new(
            ErrorCode::Limit,
            format!("at most {MAX_RANDOM} random bytes at once"),
        ));
    }
    let mut bytes = vec![0; args.len as usize];
    getrandom::fill(&mut bytes)
        .map_err(|e| HostError::new(ErrorCode::Failed, format!("no random bytes: {e}")))?;
    Ok(abi::Bytes::from(bytes))
}

/// `cert_info`: the certificate's details, as the key dialog reads them.
fn cert_info(args: CertArgs) -> HostResult<CertInfo> {
    let cert = oncl_pki::cert::parse(&args.der)
        .map_err(|e| HostError::new(ErrorCode::Invalid, format!("not a certificate: {e}")))?;
    Ok(abi_cert_info(&cert, &args.der))
}

/// The ABI's details of `cert`, whose DER is `der`.
pub(crate) fn abi_cert_info(cert: &oncl_pki::cert::Certificate, der: &[u8]) -> CertInfo {
    let info = oncl_pki::info::cert_info(cert);
    CertInfo {
        subject_cn: info.subject_cn,
        iin: info.iin,
        bin: info.bin,
        organization: info.organization,
        serial_hex: info.serial_hex,
        not_before: unix_ms(info.not_before),
        not_after: unix_ms(info.not_after),
        ext_key_usages: info.ext_key_usages.into_iter().collect(),
        key_usage: KeyUsage {
            digital_signature: info.key_usage.digital_signature,
            non_repudiation: info.key_usage.non_repudiation,
            key_encipherment: info.key_usage.key_encipherment,
            key_agreement: info.key_usage.key_agreement,
        },
        signature_alg_oid: info.signature_alg_oid,
        spki_alg_oid: info.spki_alg_oid,
        pem: oncl_pki::pem::encode("CERTIFICATE", der),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtins::Inert;
    use crate::runtime::Trust;
    use oncl_pdk::abi::DataRef;

    /// The state of an instance with `capabilities`, keeping at most `max_kept` bytes.
    fn state(capabilities: Capabilities, max_kept: usize) -> HostState {
        let services = HostServices::new(
            Arc::new(Inert),
            Arc::new(Inert),
            Arc::new(Inert),
            oncl_token::Tokens::disabled(),
        );
        let session = SessionContext {
            session: 1,
            plugin_id: "test".to_owned(),
            plugin_name: crate::Localized {
                ru: String::new(),
                kk: String::new(),
                en: String::new(),
            },
            shared: Arc::default(),
            trust: Trust::Builtin,
        };
        HostState::new(
            wasmi::StoreLimitsBuilder::new().build(),
            services,
            session,
            Arc::new(capabilities),
            1 << 20,
            max_kept,
        )
    }

    fn read(state: &mut HostState, marker: &str) -> HostResult<abi::Bytes> {
        caps::data_read(
            state,
            DataRef {
                data: marker.to_owned(),
            },
        )
    }

    #[test]
    fn kept_data_goes_with_its_call() {
        let builtin = Capabilities {
            builtin: true,
            ..Capabilities::default()
        };
        let mut s = state(builtin, 1 << 20);
        s.begin_call(Some("https://a.kz".to_owned()), Locale::Ru);
        let first = s.call.data.as_ref().unwrap().prefix().to_owned();
        let marker = s.call.data.as_mut().unwrap().keep(b"doc".to_vec()).unwrap();
        assert_eq!(read(&mut s, &marker).unwrap().as_slice(), b"doc");
        s.end_call();
        assert!(s.call.data.is_none());
        assert!(read(&mut s, &marker).is_err());
        // The instance's next call, for another page: other markers, the old one refused.
        s.begin_call(Some("https://b.kz".to_owned()), Locale::Ru);
        assert_ne!(s.call.data.as_ref().unwrap().prefix(), first);
        assert!(read(&mut s, &marker).is_err());
        s.end_call();
        // A plugin's instance keeps nothing.
        let mut plugin = state(Capabilities::default(), 0);
        plugin.begin_call(None, Locale::Ru);
        assert!(plugin.call.data.is_none());
        assert!(read(&mut plugin, &marker).is_err());
    }
}
