//! The host side of the ABI: what an instance's store holds, the host functions as the
//! linker defines them, and the guest memory they read and write. Every host function reads
//! its CBOR argument from the guest, runs, and writes its CBOR [`HostResult`] into a buffer
//! of the guest's `oncl_alloc`.

use crate::caps::{self, KeyTable};
use crate::manifest::Capabilities;
use crate::runtime::{MAX_TRANSFER, SessionContext};
use oncl_basics::{Locale, OcspCache, Prompter, RecentPathStore};
use oncl_pdk::abi::{
    self, CertArgs, CertInfo, ErrorCode, HostError, HostResult, IMPORT_MODULE, Import, KeyUsage,
    Level, LogArgs, MAX_RANDOM, RandomArgs,
};
use oncl_pki::http::HttpTransport;
use oncl_pki::tsp::TsaProfile;
use serde::Serialize;
use serde::de::DeserializeOwned;
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
    guest: Option<(Memory, TypedFunc<i32, i32>)>,
}

impl HostState {
    pub(crate) fn new(
        limits: StoreLimits,
        services: HostServices,
        session: SessionContext,
        capabilities: Arc<Capabilities>,
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
            },
            keys: KeyTable::default(),
            guest: None,
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
        };
    }

    /// The request is answered.
    pub(crate) fn end_call(&mut self) {
        self.phase = Phase::Idle;
        self.call.origin = None;
    }

    /// Lets go of every key: the instance is spent.
    pub(crate) fn release_all(&mut self) {
        self.keys = KeyTable::default();
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

/// Defines the host function `import` in `linker`.
pub(crate) fn define(linker: &mut Linker<HostState>, import: Import) -> Result<(), wasmi::Error> {
    linker.func_wrap(
        IMPORT_MODULE,
        import.name(),
        move |caller: Caller<'_, HostState>, ptr: i32, len: i32| call(caller, import, ptr, len),
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
    if len as usize > MAX_TRANSFER {
        return Err(trap(format!(
            "the argument of {} is over {MAX_TRANSFER} bytes",
            import.name()
        )));
    }
    let args = read_guest(memory.data(&caller), ptr, len)?.to_vec();
    let reply = dispatch(caller.data_mut(), import, &args);
    if reply.len() > MAX_TRANSFER {
        return Err(trap(format!(
            "the result of {} is over {MAX_TRANSFER} bytes",
            import.name()
        )));
    }
    // Within MAX_TRANSFER, which fits an i32.
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
    }
}

/// `f` on `args` decoded, its result encoded.
fn run<A: DeserializeOwned, R: Serialize>(
    args: &[u8],
    f: impl FnOnce(A) -> HostResult<R>,
) -> Vec<u8> {
    abi::encode(&abi::decode(args).and_then(f))
}

/// `log`: the line in the log, with the plugin and the session.
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
    match args.level {
        Level::Error => tracing::error!(plugin, session, "{message}"),
        Level::Warn => tracing::warn!(plugin, session, "{message}"),
        Level::Info => tracing::info!(plugin, session, "{message}"),
        Level::Debug => tracing::debug!(plugin, session, "{message}"),
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
