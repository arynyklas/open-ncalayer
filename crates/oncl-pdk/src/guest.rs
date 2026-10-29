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
    pub use crate::abi::{CertInfo, Level};

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
}

/// The user's keys (capability `keys`).
pub mod keys {
    use super::*;
    pub use crate::abi::{Action, ChooseArgs, Filter};
    use crate::abi::{Chosen, Handle, SignCmsArgs, SignRawArgs, SignXmlArgs};

    /// A key the user chose: it stays usable until dropped.
    #[derive(Debug)]
    pub struct Key {
        handle: u32,
        alias: String,
        certificate: Vec<u8>,
    }

    /// Asks the user for a key: the storage dialog, then the key dialog. `None` if the user
    /// cancels.
    pub fn choose(args: &ChooseArgs) -> HostResult<Option<Key>> {
        let chosen: Option<Chosen> = call(imports::keys_choose, args)?;
        Ok(chosen.map(|c| Key {
            handle: c.handle,
            alias: c.alias,
            certificate: c.certificate.into_vec(),
        }))
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
    pub use crate::abi::MessageKind;
    use crate::abi::{ConfirmArgs, MessageArgs};

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
}

/// Files the user chooses (capability `files`).
pub mod files {
    use super::*;
    use crate::abi::{OpenedFile, SaveArgs};

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
}

/// HTTPS requests to the manifest's prefixes (capability `http`). Redirects are not
/// followed: a 3xx reply comes back with its `location`.
pub mod http {
    use super::*;
    pub use crate::abi::HttpResponse;
    use crate::abi::{HttpArgs, Method};

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
}
