//! The guest side of the ABI: the exports [`plugin!`](crate::plugin) generates and the
//! wrappers of the host functions. Only on `wasm32`.

use crate::Request;
use crate::abi::{
    self, ABI_VERSION, Bytes, CertArgs, HostResult, Import, Input, LogArgs, Output, RandomArgs,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::alloc::{Layout, alloc, dealloc};
use std::sync::Once;

/// The host functions, as the module imports them. Only the ones a plugin calls end up
/// among its imports.
mod imports {
    #[link(wasm_import_module = "oncl")]
    unsafe extern "C" {
        #[link_name = "log"]
        pub fn log(ptr: i32, len: i32) -> i64;
        #[link_name = "now"]
        pub fn now(ptr: i32, len: i32) -> i64;
        #[link_name = "random"]
        pub fn random(ptr: i32, len: i32) -> i64;
        #[link_name = "cert_info"]
        pub fn cert_info(ptr: i32, len: i32) -> i64;
        #[link_name = "keys_choose"]
        pub fn keys_choose(ptr: i32, len: i32) -> i64;
        #[link_name = "keys_sign_cms"]
        pub fn keys_sign_cms(ptr: i32, len: i32) -> i64;
        #[link_name = "keys_sign_raw"]
        pub fn keys_sign_raw(ptr: i32, len: i32) -> i64;
        #[link_name = "keys_sign_xml"]
        pub fn keys_sign_xml(ptr: i32, len: i32) -> i64;
        #[link_name = "keys_release"]
        pub fn keys_release(ptr: i32, len: i32) -> i64;
        #[link_name = "dialog_message"]
        pub fn dialog_message(ptr: i32, len: i32) -> i64;
        #[link_name = "dialog_confirm"]
        pub fn dialog_confirm(ptr: i32, len: i32) -> i64;
        #[link_name = "file_open"]
        pub fn file_open(ptr: i32, len: i32) -> i64;
        #[link_name = "file_save"]
        pub fn file_save(ptr: i32, len: i32) -> i64;
        #[link_name = "http_request"]
        pub fn http_request(ptr: i32, len: i32) -> i64;
        #[link_name = "reply_drop"]
        pub fn reply_drop(ptr: i32, len: i32) -> i64;
        #[link_name = "hash"]
        pub fn hash(ptr: i32, len: i32) -> i64;
        #[link_name = "cert_details"]
        pub fn cert_details(ptr: i32, len: i32) -> i64;
        #[link_name = "local_time"]
        pub fn local_time(ptr: i32, len: i32) -> i64;
        #[link_name = "platform"]
        pub fn platform(ptr: i32, len: i32) -> i64;
        #[link_name = "ca_list"]
        pub fn ca_list(ptr: i32, len: i32) -> i64;
        #[link_name = "ca_issuer"]
        pub fn ca_issuer(ptr: i32, len: i32) -> i64;
        #[link_name = "keys_select"]
        pub fn keys_select(ptr: i32, len: i32) -> i64;
        #[link_name = "keys_chain"]
        pub fn keys_chain(ptr: i32, len: i32) -> i64;
        #[link_name = "keys_terminals"]
        pub fn keys_terminals(ptr: i32, len: i32) -> i64;
        #[link_name = "keys_open"]
        pub fn keys_open(ptr: i32, len: i32) -> i64;
        #[link_name = "dialog_password"]
        pub fn dialog_password(ptr: i32, len: i32) -> i64;
        #[link_name = "keys_sign_cms_ex"]
        pub fn keys_sign_cms_ex(ptr: i32, len: i32) -> i64;
        #[link_name = "tsp_stamp"]
        pub fn tsp_stamp(ptr: i32, len: i32) -> i64;
        #[link_name = "tsp_request"]
        pub fn tsp_request(ptr: i32, len: i32) -> i64;
        #[link_name = "ocsp_fetch"]
        pub fn ocsp_fetch(ptr: i32, len: i32) -> i64;
        #[link_name = "crl_fetch"]
        pub fn crl_fetch(ptr: i32, len: i32) -> i64;
        #[link_name = "cms_verify"]
        pub fn cms_verify(ptr: i32, len: i32) -> i64;
        #[link_name = "keys_sign_xml_ex"]
        pub fn keys_sign_xml_ex(ptr: i32, len: i32) -> i64;
        #[link_name = "xml_verify"]
        pub fn xml_verify(ptr: i32, len: i32) -> i64;
        #[link_name = "http_request_ex"]
        pub fn http_request_ex(ptr: i32, len: i32) -> i64;
        #[link_name = "file_choose"]
        pub fn file_choose(ptr: i32, len: i32) -> i64;
        #[link_name = "file_open_ex"]
        pub fn file_open_ex(ptr: i32, len: i32) -> i64;
        #[link_name = "page_file_read"]
        pub fn page_file_read(ptr: i32, len: i32) -> i64;
        #[link_name = "page_file_write"]
        pub fn page_file_write(ptr: i32, len: i32) -> i64;
        #[link_name = "dialog_choice"]
        pub fn dialog_choice(ptr: i32, len: i32) -> i64;
        #[link_name = "settings_get"]
        pub fn settings_get(ptr: i32, len: i32) -> i64;
        #[link_name = "settings_put"]
        pub fn settings_put(ptr: i32, len: i32) -> i64;
        #[link_name = "shared_get"]
        pub fn shared_get(ptr: i32, len: i32) -> i64;
        #[link_name = "shared_put"]
        pub fn shared_put(ptr: i32, len: i32) -> i64;
        #[link_name = "keys_sign_xades"]
        pub fn keys_sign_xades(ptr: i32, len: i32) -> i64;
        #[link_name = "call_locale"]
        pub fn call_locale(ptr: i32, len: i32) -> i64;
        #[link_name = "core_modules"]
        pub fn core_modules(ptr: i32, len: i32) -> i64;
        #[link_name = "core_bundles"]
        pub fn core_bundles(ptr: i32, len: i32) -> i64;
        #[link_name = "core_install_bundle"]
        pub fn core_install_bundle(ptr: i32, len: i32) -> i64;
        #[link_name = "core_open_window"]
        pub fn core_open_window(ptr: i32, len: i32) -> i64;
    }
}

/// A host function's signature.
type HostFn = unsafe extern "C" fn(i32, i32) -> i64;

/// The import of `import`.
fn host_fn(import: Import) -> HostFn {
    match import {
        Import::Log => imports::log,
        Import::Now => imports::now,
        Import::Random => imports::random,
        Import::CertInfo => imports::cert_info,
        Import::KeysChoose => imports::keys_choose,
        Import::KeysSignCms => imports::keys_sign_cms,
        Import::KeysSignRaw => imports::keys_sign_raw,
        Import::KeysSignXml => imports::keys_sign_xml,
        Import::KeysRelease => imports::keys_release,
        Import::DialogMessage => imports::dialog_message,
        Import::DialogConfirm => imports::dialog_confirm,
        Import::FileOpen => imports::file_open,
        Import::FileSave => imports::file_save,
        Import::HttpRequest => imports::http_request,
        Import::ReplyDrop => imports::reply_drop,
        Import::Hash => imports::hash,
        Import::CertDetails => imports::cert_details,
        Import::LocalTime => imports::local_time,
        Import::Platform => imports::platform,
        Import::CaList => imports::ca_list,
        Import::CaIssuer => imports::ca_issuer,
        Import::KeysSelect => imports::keys_select,
        Import::KeysChain => imports::keys_chain,
        Import::KeysTerminals => imports::keys_terminals,
        Import::KeysOpen => imports::keys_open,
        Import::DialogPassword => imports::dialog_password,
        Import::KeysSignCmsEx => imports::keys_sign_cms_ex,
        Import::TspStamp => imports::tsp_stamp,
        Import::TspRequest => imports::tsp_request,
        Import::OcspFetch => imports::ocsp_fetch,
        Import::CrlFetch => imports::crl_fetch,
        Import::CmsVerify => imports::cms_verify,
        Import::KeysSignXmlEx => imports::keys_sign_xml_ex,
        Import::XmlVerify => imports::xml_verify,
        Import::HttpRequestEx => imports::http_request_ex,
        Import::FileChoose => imports::file_choose,
        Import::FileOpenEx => imports::file_open_ex,
        Import::PageFileRead => imports::page_file_read,
        Import::PageFileWrite => imports::page_file_write,
        Import::DialogChoice => imports::dialog_choice,
        Import::SettingsGet => imports::settings_get,
        Import::SettingsPut => imports::settings_put,
        Import::SharedGet => imports::shared_get,
        Import::SharedPut => imports::shared_put,
        Import::KeysSignXades => imports::keys_sign_xades,
        Import::CallLocale => imports::call_locale,
        Import::CoreModules => imports::core_modules,
        Import::CoreBundles => imports::core_bundles,
        Import::CoreInstallBundle => imports::core_install_bundle,
        Import::CoreOpenWindow => imports::core_open_window,
    }
}

/// Calls the host function `import` with `args` of its ABI type and decodes its result: the
/// ABI without the wrappers. A plugin that calls this imports every host function, so its
/// manifest must declare every capability.
pub fn call_host<A: Serialize, R: DeserializeOwned>(import: Import, args: &A) -> HostResult<R> {
    call(host_fn(import), args)
}

/// Calls `f` with `args` and decodes its result.
fn call<A: Serialize, R: DeserializeOwned>(f: HostFn, args: &A) -> HostResult<R> {
    let bytes = abi::encode(args);
    // wasm32: pointers and lengths fit an i32; the bytes outlive the call.
    let packed = unsafe { f(bytes.as_ptr() as i32, bytes.len() as i32) };
    let (ptr, len) = abi::unpack(packed);
    // SAFETY: the host wrote the result into a buffer of `len` bytes it got from
    // `oncl_alloc`, which is ours now.
    let reply = unsafe { take(ptr, len) };
    abi::decode::<HostResult<R>>(&reply)?
}

/// The buffer of `len` bytes at `ptr` that `oncl_alloc` returned, as a vector that frees it.
///
/// # Safety
///
/// `ptr` and `len` must be a buffer [`alloc_buffer`] returned and nothing else owns.
unsafe fn take(ptr: u32, len: u32) -> Vec<u8> {
    if ptr == 0 || len == 0 {
        return Vec::new();
    }
    let len = len as usize;
    // SAFETY: allocated by the global allocator with the layout of a `Vec<u8>` of capacity
    // `len` (size `len`, alignment 1), and fully written by the host.
    unsafe { Vec::from_raw_parts(ptr as *mut u8, len, len) }
}

/// `oncl_alloc`: `len` bytes, `0` for none.
fn alloc_buffer(len: i32) -> i32 {
    let Ok(len) = usize::try_from(len) else {
        return 0;
    };
    let Ok(layout) = Layout::from_size_align(len, 1) else {
        return 0;
    };
    if len == 0 {
        return 0;
    }
    // SAFETY: the layout has a non-zero size.
    unsafe { alloc(layout) as i32 }
}

/// `oncl_free`: gives back a buffer of `alloc_buffer`.
///
/// # Safety
///
/// `ptr` and `len` must be a buffer [`alloc_buffer`] returned and nothing else owns.
unsafe fn free_buffer(ptr: i32, len: i32) {
    let (Ok(len), false) = (usize::try_from(len), ptr == 0) else {
        return;
    };
    if let (Ok(layout), true) = (Layout::from_size_align(len, 1), len > 0) {
        // SAFETY: allocated with this layout by `alloc_buffer` (the caller's promise).
        unsafe { dealloc(ptr as *mut u8, layout) }
    }
}

/// `oncl_process` with `handler`.
///
/// # Safety
///
/// `ptr` and `len` must be a buffer [`alloc_buffer`] returned, holding the CBOR [`Input`],
/// which this takes over.
unsafe fn process_with(ptr: i32, len: i32, handler: fn(&Request) -> String) -> i64 {
    static PANIC_HOOK: Once = Once::new();
    PANIC_HOOK.call_once(|| {
        // A panic aborts the instance: its message goes to the core's log first.
        std::panic::set_hook(Box::new(|info| {
            let _ = host::log(abi::Level::Error, &format!("panic: {info}"));
        }));
    });
    // SAFETY: the caller's promise.
    let input = unsafe { take(ptr as u32, len as u32) };
    let input: Input = match abi::decode(&input) {
        Ok(input) => input,
        Err(e) => panic!("the core sent a malformed input: {e}"),
    };
    let response = handler(&Request::from_input(input));
    let output = abi::encode(&Output { response }).into_boxed_slice();
    let len = output.len() as u32;
    // The core reads it and gives it back with `oncl_free`, with this length.
    let ptr = Box::into_raw(output) as *mut u8 as u32;
    abi::pack(ptr, len)
}

/// What [`plugin!`](crate::plugin) expands to call. Not for direct use.
#[doc(hidden)]
pub mod __rt {
    use super::*;

    pub fn abi_version() -> i32 {
        ABI_VERSION as i32
    }

    pub fn alloc(len: i32) -> i32 {
        alloc_buffer(len)
    }

    /// # Safety
    ///
    /// As `oncl_free`.
    pub unsafe fn free(ptr: i32, len: i32) {
        unsafe { free_buffer(ptr, len) }
    }

    /// # Safety
    ///
    /// As `oncl_process`.
    pub unsafe fn process(ptr: i32, len: i32, handler: fn(&Request) -> String) -> i64 {
        unsafe { process_with(ptr, len, handler) }
    }
}

/// Exports `handler` as the plugin: `handler` gets each request and returns the reply sent
/// to the page. Also exports the ABI's `oncl_abi_version`, `oncl_alloc` and `oncl_free`.
///
/// ```ignore
/// fn handle(request: &oncl_pdk::Request) -> String {
///     request.text.clone()
/// }
/// oncl_pdk::plugin!(handle);
/// ```
#[macro_export]
macro_rules! plugin {
    ($handler:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn oncl_abi_version() -> i32 {
            $crate::__rt::abi_version()
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn oncl_alloc(len: i32) -> i32 {
            $crate::__rt::alloc(len)
        }

        /// # Safety
        ///
        /// The core gives back a buffer `oncl_alloc` returned.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn oncl_free(ptr: i32, len: i32) {
            unsafe { $crate::__rt::free(ptr, len) }
        }

        /// # Safety
        ///
        /// The core passes a buffer of `oncl_alloc` holding the input.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn oncl_process(ptr: i32, len: i32) -> i64 {
            unsafe { $crate::__rt::process(ptr, len, $handler) }
        }
    };
}

/// The basic host functions every plugin has.
pub mod host {
    use super::*;
    pub use crate::abi::{CertDetails, CertInfo, HashAlg, Level, Os, Platform};
    use crate::abi::{HashArgs, LocalTime, LocalTimeArgs};

    /// Writes `message` to OpenNCALayer's log, with the plugin's id.
    pub fn log(level: Level, message: &str) -> HostResult<()> {
        call(
            imports::log,
            &LogArgs {
                level,
                message: message.to_owned(),
            },
        )
    }

    /// The time, in Unix milliseconds.
    pub fn now() -> HostResult<i64> {
        call(imports::now, &())
    }

    /// `len` random bytes, at most [`abi::MAX_RANDOM`].
    pub fn random(len: u32) -> HostResult<Vec<u8>> {
        call::<_, Bytes>(imports::random, &RandomArgs { len }).map(Bytes::into_vec)
    }

    /// The details of the certificate `der`.
    pub fn cert_info(der: &[u8]) -> HostResult<CertInfo> {
        call(
            imports::cert_info,
            &CertArgs {
                der: Bytes::from(der.to_vec()),
            },
        )
    }

    /// Ends the request being answered with the connection dropped, without a reply: the
    /// page sees the socket close (code 1006), as for a request that is not JSON. The
    /// handler still returns its reply, which is not sent.
    pub fn reply_drop() -> HostResult<()> {
        call(imports::reply_drop, &())
    }

    /// The `alg` digest of `data`.
    pub fn hash(alg: HashAlg, data: &[u8]) -> HostResult<Vec<u8>> {
        let args = HashArgs {
            alg,
            data: Bytes::from(data.to_vec()),
        };
        call::<_, Bytes>(imports::hash, &args).map(Bytes::into_vec)
    }

    /// The details of the certificate `der` as Kalkan renders them.
    pub fn cert_details(der: &[u8]) -> HostResult<CertDetails> {
        call(
            imports::cert_details,
            &CertArgs {
                der: Bytes::from(der.to_vec()),
            },
        )
    }

    /// The offset from UTC of the system's time zone at `unix_ms`, in seconds.
    pub fn local_offset(unix_ms: i64) -> HostResult<i32> {
        call::<_, LocalTime>(imports::local_time, &LocalTimeArgs { unix_ms })
            .map(|t| t.offset_seconds)
    }

    /// The system the core runs on.
    pub fn platform() -> HostResult<Platform> {
        call(imports::platform, &())
    }

    /// The NCA CA certificates the core trusts, DER.
    pub fn ca_list() -> HostResult<Vec<Vec<u8>>> {
        call::<_, Vec<Bytes>>(imports::ca_list, &())
            .map(|certs| certs.into_iter().map(Bytes::into_vec).collect())
    }

    /// The CA certificate among [`ca_list`] that issued the certificate `der`, if any.
    pub fn ca_issuer(der: &[u8]) -> HostResult<Option<Vec<u8>>> {
        call::<_, Option<Bytes>>(
            imports::ca_issuer,
            &CertArgs {
                der: Bytes::from(der.to_vec()),
            },
        )
        .map(|issuer| issuer.map(Bytes::into_vec))
    }

    /// Shows OpenNCALayer's windows in `locale` until the call returns, instead of the
    /// language of [`crate::Request::locale`].
    pub fn call_locale(locale: crate::Locale) -> HostResult<()> {
        call(
            imports::call_locale,
            &crate::abi::LocaleArgs {
                locale: locale.code().to_owned(),
            },
        )
    }
}

/// The core's modules, bundles and windows (capability `builtin`: built-in modules only).
pub mod core {
    use super::{HostResult, call, imports};
    pub use crate::abi::{CoreBundles, CoreModules, Window};
    use crate::abi::{InstallBundleArgs, WindowArgs};

    /// The module names the core serves now: its built-in modules' and its plugins'.
    pub fn modules() -> HostResult<CoreModules> {
        call(imports::core_modules, &())
    }

    /// The core's version and the bundles its enabled plugins port.
    pub fn bundles() -> HostResult<CoreBundles> {
        call(imports::core_bundles, &())
    }

    /// The page asks to install the original bundle `symname`: whether a plugin porting it
    /// is offered to the user. `invalid` without the page's origin.
    pub fn install_bundle(symname: &str) -> HostResult<bool> {
        call(
            imports::core_install_bundle,
            &InstallBundleArgs {
                symname: symname.to_owned(),
            },
        )
    }

    /// Opens `window` in the background.
    pub fn open_window(window: Window) -> HostResult<()> {
        call(imports::core_open_window, &WindowArgs { window })
    }
}

/// The user's keys (capability `keys`).
pub mod keys {
    use super::*;
    pub use crate::abi::{
        Action, ChooseArgs, Filter, FilterMore, KeyOrder, KeySource, KeyUsageBit, OpenArgs,
        OpenOutcome, Password, SelectArgs,
    };
    pub use crate::abi::{
        C14n, CmsCerts, CmsContent, CmsOutcome, CoSign, NsBinding, Placement, RawAttribute,
        SignCmsExArgs, SignXmlExArgs, SignedAttrs, SigningTime, SigningTimeObject, TimeForm,
        TimeSource, Transform, XadesArgs, XadesLevel, XadesOutcome, XmlOutput,
    };
    use crate::abi::{
        Chosen, Handle, OpenedKey, SignCmsArgs, SignRawArgs, SignXmlArgs, TerminalsArgs,
    };

    /// A key the user chose: it stays usable until dropped.
    #[derive(Debug)]
    pub struct Key {
        handle: u32,
        alias: String,
        certificate: Vec<u8>,
    }

    impl From<Chosen> for Key {
        fn from(c: Chosen) -> Key {
            Key {
                handle: c.handle,
                alias: c.alias,
                certificate: c.certificate.into_vec(),
            }
        }
    }

    impl From<OpenedKey> for Key {
        fn from(k: OpenedKey) -> Key {
            Key {
                handle: k.handle,
                alias: k.alias,
                certificate: k.certificate.into_vec(),
            }
        }
    }

    /// Asks the user for a key: the storage dialog, then the key dialog. `None` if the user
    /// cancels.
    pub fn choose(args: &ChooseArgs) -> HostResult<Option<Key>> {
        let chosen: Option<Chosen> = call(imports::keys_choose, args)?;
        Ok(chosen.map(Key::from))
    }

    /// [`choose`] with more conditions and the order of the keys.
    pub fn select(args: &SelectArgs) -> HostResult<Option<Key>> {
        let chosen: Option<Chosen> = call(imports::keys_select, args)?;
        Ok(chosen.map(Key::from))
    }

    /// Opens every key of the store `args` names: the keys, in store order, or why not.
    pub fn open(args: &OpenArgs) -> HostResult<Result<Vec<Key>, OpenOutcome>> {
        Ok(match call::<_, OpenOutcome>(imports::keys_open, args)? {
            OpenOutcome::Opened(keys) => Ok(keys.into_iter().map(Key::from).collect()),
            other => Err(other),
        })
    }

    /// The readers of the token storage `storage`.
    pub fn terminals(storage: &str) -> HostResult<Vec<String>> {
        call(
            imports::keys_terminals,
            &TerminalsArgs {
                storage: storage.to_owned(),
            },
        )
    }

    impl Key {
        /// Its handle: the key in this instance only, until dropped; for [`call_host`].
        pub fn handle(&self) -> u32 {
            self.handle
        }

        /// Its alias in the key store.
        pub fn alias(&self) -> &str {
            &self.alias
        }

        /// Its certificate, DER.
        pub fn certificate(&self) -> &[u8] {
            &self.certificate
        }

        /// A CAdES signature of `data`, DER; `attached` puts the data in it, `timestamp`
        /// adds a time-stamp of the basics TSA.
        pub fn sign_cms(
            &self,
            data: &[u8],
            attached: bool,
            timestamp: bool,
        ) -> HostResult<Vec<u8>> {
            let args = SignCmsArgs {
                handle: self.handle,
                data: Bytes::from(data.to_vec()),
                attached,
                timestamp,
            };
            call::<_, Bytes>(imports::keys_sign_cms, &args).map(Bytes::into_vec)
        }

        /// A CMS signature as `args` says (its `handle` is this key's): the CMS, or the
        /// signed CMS's failed time-stamp.
        pub fn sign_cms_ex(&self, args: SignCmsExArgs) -> HostResult<CmsOutcome> {
            let args = SignCmsExArgs {
                handle: self.handle,
                ..args
            };
            call(imports::keys_sign_cms_ex, &args)
        }

        /// A signature of `data` with the key's algorithm (RSA: SHA-256).
        pub fn sign_raw(&self, data: &[u8]) -> HostResult<Vec<u8>> {
            let args = SignRawArgs {
                handle: self.handle,
                data: Bytes::from(data.to_vec()),
            };
            call::<_, Bytes>(imports::keys_sign_raw, &args).map(Bytes::into_vec)
        }

        /// `xml` with an enveloped XMLDSig: of the whole document, or of the element the
        /// XPath `element` selects, put into the element `parent` selects.
        pub fn sign_xml(
            &self,
            xml: &[u8],
            element: Option<&str>,
            parent: Option<&str>,
        ) -> HostResult<Vec<u8>> {
            let args = SignXmlArgs {
                handle: self.handle,
                xml: Bytes::from(xml.to_vec()),
                element: element.map(str::to_owned),
                parent: parent.map(str::to_owned),
            };
            call::<_, Bytes>(imports::keys_sign_xml, &args).map(Bytes::into_vec)
        }

        /// An XML signature as `args` says (its `handle` is this key's): the document.
        pub fn sign_xml_ex(&self, args: SignXmlExArgs) -> HostResult<Vec<u8>> {
            let args = SignXmlExArgs {
                handle: self.handle,
                ..args
            };
            call::<_, Bytes>(imports::keys_sign_xml_ex, &args).map(Bytes::into_vec)
        }

        /// A XAdES-BASELINE signature as `args` says (its `handle` is this key's).
        pub fn sign_xades(&self, args: XadesArgs) -> HostResult<XadesOutcome> {
            let args = XadesArgs {
                handle: self.handle,
                ..args
            };
            call(imports::keys_sign_xades, &args)
        }

        /// The key's certificate chain, DER, from its certificate up: the key store's
        /// certificates, then the CAs the core trusts.
        pub fn chain(&self) -> HostResult<Vec<Vec<u8>>> {
            call::<_, Vec<Bytes>>(
                imports::keys_chain,
                &Handle {
                    handle: self.handle,
                },
            )
            .map(|certs| certs.into_iter().map(Bytes::into_vec).collect())
        }
    }

    impl Drop for Key {
        fn drop(&mut self) {
            let _ = call::<_, ()>(
                imports::keys_release,
                &Handle {
                    handle: self.handle,
                },
            );
        }
    }
}

/// Dialogs (capability `dialogs`).
pub mod dialogs {
    use super::*;
    pub use crate::abi::{ChoiceArgs, MessageKind, PasswordArgs, SecretRef};
    use crate::abi::{ConfirmArgs, MessageArgs};

    /// Asks for a password the core keeps: its id, for [`crate::keys::Password::Secret`]
    /// of this instance; `None` if the user cancels.
    pub fn password(args: &PasswordArgs) -> HostResult<Option<SecretRef>> {
        call(imports::dialog_password, args)
    }

    /// Shows `text` with an OK button until the user closes it.
    pub fn message(kind: MessageKind, text: &str) -> HostResult<()> {
        call(
            imports::dialog_message,
            &MessageArgs {
                kind,
                text: text.to_owned(),
            },
        )
    }

    /// Asks a yes/no question: `true` for yes, `false` for no or a closed dialog.
    pub fn confirm(text: &str) -> HostResult<bool> {
        call(
            imports::dialog_confirm,
            &ConfirmArgs {
                text: text.to_owned(),
            },
        )
    }

    /// Asks with the plugin's buttons (and list): the button pressed, or with a list the
    /// option selected when the first button is pressed; `None` if closed (or, with a list,
    /// another button or no option).
    pub fn choice(args: &ChoiceArgs) -> HostResult<Option<u8>> {
        call(imports::dialog_choice, args)
    }
}

/// Files the user chooses (capability `files`).
pub mod files {
    use super::*;
    pub use crate::abi::{
        ChooseFileArgs, ChosenPath, FileFilter, FileMode, OpenedFile, PageRead, PageWrite,
    };
    use crate::abi::{PagePathArgs, PageWriteArgs, SaveArgs};

    /// The path and contents of a file the user chooses; `None` if the user cancels.
    pub fn open() -> HostResult<Option<(String, Vec<u8>)>> {
        let opened: Option<OpenedFile> = call(imports::file_open, &())?;
        Ok(opened.map(|f| (f.path, f.data.into_vec())))
    }

    /// Saves `data` where the user chooses, suggesting `name`: the path written; `None` if
    /// the user cancels.
    pub fn save(name: &str, data: &[u8]) -> HostResult<Option<String>> {
        call(
            imports::file_save,
            &SaveArgs {
                suggested_name: name.to_owned(),
                data: Bytes::from(data.to_vec()),
            },
        )
    }

    /// A file or folder the user chooses: its path and a file's size, nothing read; `None`
    /// if the user cancels.
    pub fn choose(args: &ChooseFileArgs) -> HostResult<Option<ChosenPath>> {
        call(imports::file_choose, args)
    }

    /// The path and contents of a file the user chooses in a chooser with `args`' title,
    /// file types and start folder; `None` if the user cancels.
    pub fn open_ex(args: &ChooseFileArgs) -> HostResult<Option<OpenedFile>> {
        call(imports::file_open_ex, args)
    }

    /// A file the page names (capability `page_files`), once the user allows it.
    pub fn page_read(path: &str) -> HostResult<PageRead> {
        call(
            imports::page_file_read,
            &PagePathArgs {
                path: path.to_owned(),
            },
        )
    }

    /// Writes `data` as `name` into the folder `dir` the page names (capability
    /// `page_files`), once the user allows it.
    pub fn page_write(dir: &str, name: &str, data: &[u8]) -> HostResult<PageWrite> {
        call(
            imports::page_file_write,
            &PageWriteArgs {
                dir: dir.to_owned(),
                name: name.to_owned(),
                data: Bytes::from(data.to_vec()),
            },
        )
    }
}

/// HTTPS requests to the manifest's prefixes (capability `http`). Redirects are not
/// followed: a 3xx reply comes back with its `location`.
pub mod http {
    use super::*;
    use crate::abi::HttpArgs;
    pub use crate::abi::HttpResponse;
    pub use crate::abi::{Header, HttpExArgs, Method};

    /// `GET url`.
    pub fn get(url: &str) -> HostResult<HttpResponse> {
        call(
            imports::http_request,
            &HttpArgs {
                method: Method::Get,
                url: url.to_owned(),
                content_type: None,
                body: Bytes::new(),
            },
        )
    }

    /// `POST url` with `body` of type `content_type`.
    pub fn post(url: &str, content_type: &str, body: &[u8]) -> HostResult<HttpResponse> {
        call(
            imports::http_request,
            &HttpArgs {
                method: Method::Post,
                url: url.to_owned(),
                content_type: Some(content_type.to_owned()),
                body: Bytes::from(body.to_vec()),
            },
        )
    }

    /// A request with headers, to the manifest's `http` prefixes, to the page's own origin
    /// when the manifest's `origins` list it (relative URLs resolved against it), or under
    /// an `http_insecure` prefix.
    pub fn request_ex(args: &HttpExArgs) -> HostResult<HttpResponse> {
        call(imports::http_request_ex, args)
    }
}

/// The plugin's settings, kept on disk across sessions and updates (capability
/// `settings`).
pub mod settings {
    use super::*;
    use std::collections::BTreeMap;

    /// The settings; empty if none were put.
    pub fn get() -> HostResult<BTreeMap<String, String>> {
        call(imports::settings_get, &())
    }

    /// Replaces the settings.
    pub fn put(settings: &BTreeMap<String, String>) -> HostResult<()> {
        call(imports::settings_put, settings)
    }
}

/// Values the plugin's instances (every session, every site) share in the process until
/// the plugin is reloaded (capability `shared`).
pub mod shared {
    use super::*;
    use crate::abi::{SharedKey, SharedPut};

    /// The value of `key`, if set and not expired.
    pub fn get(key: &str) -> HostResult<Option<Vec<u8>>> {
        let value: Option<Bytes> = call(
            imports::shared_get,
            &SharedKey {
                key: key.to_owned(),
            },
        )?;
        Ok(value.map(Bytes::into_vec))
    }

    /// Sets `key` to `value` (for `ttl_ms` milliseconds if given), or removes it.
    pub fn put(key: &str, value: Option<&[u8]>, ttl_ms: Option<u64>) -> HostResult<()> {
        call(
            imports::shared_put,
            &SharedPut {
                key: key.to_owned(),
                value: value.map(|v| Bytes::from(v.to_vec())),
                ttl_ms,
            },
        )
    }
}

/// Time-stamps, OCSP and CRL, requested by the core from the PKI hosts (`keys`).
pub mod pki {
    use super::*;
    use crate::abi::XmlVerifyArgs;
    pub use crate::abi::{
        CertStatusAbi, Check, CrlArgs, CrlOutcome, IssuerSel, NetFailure, NetKind, NetStage, Nonce,
        OcspArgs, OcspOutcome, PkiMethod, PkiUrl, Problem, Revocation, SignerReport, SignerSel,
        StampArgs, StampMode, StampOutcome, TokenForm, TsaChoice, TsaSpec, TspOutcome, TspReport,
        TspRequestArgs, VerifyArgs, VerifyAt, VerifyReport, XmlSigReport,
    };

    /// A report on the signers of a CMS.
    pub fn cms_verify(args: &VerifyArgs) -> HostResult<VerifyReport> {
        call(imports::cms_verify, args)
    }

    /// Every XML signature of `xml`, in document order: its certificate, whether it
    /// verifies.
    pub fn xml_verify(xml: &[u8]) -> HostResult<Vec<XmlSigReport>> {
        call(
            imports::xml_verify,
            &XmlVerifyArgs {
                xml: Bytes::from(xml.to_vec()),
            },
        )
    }

    /// Time-stamps signers of a CMS.
    pub fn stamp(args: &StampArgs) -> HostResult<StampOutcome> {
        call(imports::tsp_stamp, args)
    }

    /// A time-stamp of `imprint` (hashed with `tsa.hash`).
    pub fn tsp_request(tsa: &TsaSpec, imprint: &[u8]) -> HostResult<TspOutcome> {
        let args = TspRequestArgs {
            tsa: tsa.clone(),
            imprint: Bytes::from(imprint.to_vec()),
        };
        call(imports::tsp_request, &args)
    }

    /// An OCSP response about a certificate.
    pub fn ocsp_fetch(args: &OcspArgs) -> HostResult<OcspOutcome> {
        call(imports::ocsp_fetch, args)
    }

    /// The CRLs of a certificate and its status in them.
    pub fn crl_fetch(args: &CrlArgs) -> HostResult<CrlOutcome> {
        call(imports::crl_fetch, args)
    }
}
