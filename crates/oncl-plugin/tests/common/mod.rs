//! What the runtime, example and capability tests share: host services with a scripted
//! prompter, manifests, and guests written as WebAssembly text.

#![allow(dead_code)]

use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_basics::{Locale, OcspCache};
use oncl_pdk::abi::{self, HostResult, Import};
use oncl_pki::http::{GetOptions, HttpError, HttpReply, HttpTransport};
use oncl_pki::tsp::TsaProfile;
use oncl_plugin::{HostServices, Localized, Manifest, SessionContext};
use oncl_protocol::AddInfo;
use serde::de::DeserializeOwned;
use std::fmt::Write as _;
use std::sync::Arc;
use time::OffsetDateTime;
use time::macros::datetime;

/// The time the services' clock shows.
pub const NOW: OffsetDateTime = datetime!(2026-10-29 12:00 UTC);

pub fn clock() -> OffsetDateTime {
    NOW
}

/// No network.
pub struct Offline;

impl HttpTransport for Offline {
    fn get_with(&self, _: &str, _: GetOptions) -> Result<HttpReply, HttpError> {
        Err(HttpError("offline".to_owned()))
    }

    fn post_with(&self, _: &str, _: &str, _: &[u8], _: GetOptions) -> Result<HttpReply, HttpError> {
        Err(HttpError("offline".to_owned()))
    }
}

/// Services answering dialogs with `prompter`, without a network.
pub fn services_with(
    prompter: Arc<ScriptedPrompter>,
    http: Arc<dyn HttpTransport>,
) -> HostServices {
    HostServices {
        prompter,
        recent: Arc::new(MemoryRecentPath::new(None)),
        http,
        ocsp_cache: Arc::new(OcspCache::new()),
        tsa: TsaProfile::basics_default(),
        clock,
        locale: Arc::new(|| Locale::Ru),
    }
}

/// Services that cancel every dialog, without a network.
pub fn services() -> HostServices {
    services_with(
        Arc::new(ScriptedPrompter::new(Vec::<Step>::new())),
        Arc::new(Offline),
    )
}

pub const PLUGIN_ID: &str = "kz.example.test";

/// A session's context.
pub fn session(session: u64) -> SessionContext {
    SessionContext {
        session,
        plugin_id: PLUGIN_ID.to_owned(),
        plugin_name: Localized {
            ru: "Тестовый плагин".to_owned(),
            kk: "Сынақ плагині".to_owned(),
            en: "Test plugin".to_owned(),
        },
    }
}

/// A manifest with `capabilities` (the TOML of the `[capabilities]` table).
pub fn manifest(capabilities: &str) -> Manifest {
    Manifest::from_toml(&format!(
        r#"
id = "{PLUGIN_ID}"
version = "1.0.0"
min_core = "0.1.0"
modules = ["kz.example.Test"]

[name]
ru = "Тестовый плагин"
kk = "Сынақ плагині"
en = "Test plugin"

[capabilities]
{capabilities}
"#
    ))
    .unwrap()
}

/// A call with `origin`.
pub fn from(origin: &str) -> AddInfo {
    AddInfo {
        origin: Some(origin.to_owned()),
        session: 1,
    }
}

/// `bytes` as a WebAssembly text string.
pub fn wat_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for b in bytes {
        write!(out, "\\{b:02x}").unwrap();
    }
    out
}

/// The exports every test guest has besides `oncl_process`: a memory of `pages`, the ABI
/// version 1, a bump allocator from 64 KiB on and a free that does nothing.
pub fn standard_exports(pages: u32) -> String {
    format!(
        r#"
  (memory (export "memory") {pages})
  (global $heap (mut i32) (i32.const 65536))
  (func (export "oncl_abi_version") (result i32) (i32.const 1))
  (func (export "oncl_alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "oncl_free") (param i32 i32))
"#
    )
}

/// A guest answering every request with `response`.
pub fn answering(response: &str) -> String {
    let output = abi::encode(&abi::Output {
        response: response.to_owned(),
    });
    format!(
        r#"(module
{}
  (data (i32.const 1024) "{}")
  (func (export "oncl_process") (param i32 i32) (result i64)
    (i64.or (i64.shl (i64.const 1024) (i64.const 32)) (i64.const {})))
)"#,
        standard_exports(2),
        wat_bytes(&output),
        output.len()
    )
}

/// A guest whose `oncl_process` calls the host functions of `calls` in order, each with its
/// CBOR argument, and answers with the hexadecimal of the last one's CBOR result (decode it
/// with [`probe_result`]).
pub fn probe(calls: &[(Import, Vec<u8>)]) -> String {
    let mut imports = String::new();
    let mut data = String::new();
    let mut body = String::new();
    let mut at = 1024usize;
    let mut imported = Vec::new();
    for (import, args) in calls {
        if !imported.contains(import) {
            imported.push(*import);
            imports.push_str(&format!(
                "  (import \"oncl\" \"{0}\" (func ${0} (param i32 i32) (result i64)))\n",
                import.name()
            ));
        }
        data.push_str(&format!(
            "  (data (i32.const {at}) \"{}\")\n",
            wat_bytes(args)
        ));
        body.push_str(&format!(
            "    (local.set $r (call ${} (i32.const {at}) (i32.const {})))\n",
            import.name(),
            args.len()
        ));
        at += args.len();
    }
    assert!(at < 32768, "the arguments fit below the output");
    format!(
        r#"(module
{imports}{}
{data}
  (data (i32.const 32768) "0123456789abcdef")
  (func (export "oncl_process") (param i32 i32) (result i64)
    (local $r i64) (local $src i32) (local $len i32) (local $i i32) (local $b i32)
    (local $out i32) (local $hex i32)
{body}
    (local.set $src (i32.wrap_i64 (i64.shr_u (local.get $r) (i64.const 32))))
    (local.set $len (i32.wrap_i64 (local.get $r)))
    ;; Output {{ response: <hex> }}: map(1), "response", a text string of 4-byte length.
    (local.set $out (global.get $heap))
    (i32.store8 (local.get $out) (i32.const 0xa1))
    (i32.store8 offset=1 (local.get $out) (i32.const 0x68))
    (i64.store offset=2 (local.get $out) (i64.const 0x65736e6f70736572))
    (i32.store8 offset=10 (local.get $out) (i32.const 0x7a))
    (local.set $hex (i32.shl (local.get $len) (i32.const 1)))
    (i32.store8 offset=11 (local.get $out) (i32.shr_u (local.get $hex) (i32.const 24)))
    (i32.store8 offset=12 (local.get $out) (i32.shr_u (local.get $hex) (i32.const 16)))
    (i32.store8 offset=13 (local.get $out) (i32.shr_u (local.get $hex) (i32.const 8)))
    (i32.store8 offset=14 (local.get $out) (local.get $hex))
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $b (i32.load8_u (i32.add (local.get $src) (local.get $i))))
        (i32.store8 offset=15
          (i32.add (local.get $out) (i32.shl (local.get $i) (i32.const 1)))
          (i32.load8_u offset=32768 (i32.shr_u (local.get $b) (i32.const 4))))
        (i32.store8 offset=16
          (i32.add (local.get $out) (i32.shl (local.get $i) (i32.const 1)))
          (i32.load8_u offset=32768 (i32.and (local.get $b) (i32.const 15))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))
    (global.set $heap (i32.add (local.get $out) (i32.add (local.get $hex) (i32.const 15))))
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
      (i64.extend_i32_u (i32.add (local.get $hex) (i32.const 15)))))
)"#,
        standard_exports(64),
    )
}

/// The result a [`probe`] guest answered with.
pub fn probe_result<T: DeserializeOwned>(response: &str) -> HostResult<T> {
    let bytes: Vec<u8> = (0..response.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&response[i..i + 2], 16).unwrap())
        .collect();
    abi::decode::<HostResult<T>>(&bytes).unwrap()
}

/// The module of `wat`.
pub fn wasm(wat: &str) -> Vec<u8> {
    wat::parse_str(wat).unwrap()
}
