//! The runtime: modules checked against the ABI, requests within fuel and memory, guests
//! that break the ABI, and the basic host functions. Guests are WebAssembly text; what they
//! answer is CBOR made here with the ABI's own encoder.

mod common;

use common::*;
use oncl_pdk::abi::{
    self, Action, Bytes, CertArgs, CertInfo, ChooseArgs, Chosen, ConfirmArgs, ErrorCode, Filter,
    Handle, HostError, HostResult, HttpArgs, HttpResponse, Import, Input, KeyUsage, Level, LogArgs,
    MessageArgs, MessageKind, Method, OpenedFile, Output, RandomArgs, SaveArgs, SignCmsArgs,
    SignRawArgs, SignXmlArgs,
};
use oncl_plugin::{Engine, LoadError, MAX_MEMORY, PLUGIN_ERROR_REPLY, PluginError};
use std::io::Write;
use std::sync::{Arc, Mutex};

fn compile(wat: &str, capabilities: &str) -> Result<oncl_plugin::Compiled, LoadError> {
    Engine::new().compile(&manifest(capabilities), &wasm(wat))
}

fn start(wat: &str) -> oncl_plugin::Instance {
    compile(wat, "")
        .unwrap()
        .instantiate(&services(), session(1))
        .unwrap()
}

/// The answer of a guest that runs `body` in `oncl_process` (and then answers "unreachable").
fn running(body: &str, pages: u32) -> String {
    format!(
        r#"(module {}
  (func (export "oncl_process") (param i32 i32) (result i64) {body} (unreachable)))"#,
        standard_exports(pages)
    )
}

#[test]
fn echo_guest_answers() {
    let mut instance = start(&answering(r#"{"status":true,"body":"pong"}"#));
    for _ in 0..3 {
        assert_eq!(
            instance.process(r#"{"method":"ping"}"#, &from("https://a.kz")),
            Ok(r#"{"status":true,"body":"pong"}"#.to_owned())
        );
    }
}

#[test]
fn missing_export_is_rejected() {
    let wat = answering("x").replace(r#"(func (export "oncl_free") (param i32 i32))"#, "");
    assert_eq!(
        compile(&wat, "").err(),
        Some(LoadError::MissingExport("oncl_free"))
    );
    let wat = answering("x").replace(r#"(memory (export "memory") 2)"#, "(memory 2)");
    assert_eq!(
        compile(&wat, "").err(),
        Some(LoadError::MissingExport("memory"))
    );
}

#[test]
fn wrong_export_signature_is_rejected() {
    let wat = answering("x").replace(
        r#"(func (export "oncl_free") (param i32 i32))"#,
        r#"(func (export "oncl_free") (param i64 i32))"#,
    );
    assert_eq!(
        compile(&wat, "").err(),
        Some(LoadError::WrongExport("oncl_free"))
    );
    let wat = answering("x").replace(
        r#"(func (export "oncl_abi_version") (result i32) (i32.const 1))"#,
        r#"(global (export "oncl_abi_version") i32 (i32.const 1))"#,
    );
    assert_eq!(
        compile(&wat, "").err(),
        Some(LoadError::WrongExport("oncl_abi_version"))
    );
}

/// A guest importing `module`.`name` with `ty`.
fn importing(module: &str, name: &str, ty: &str) -> String {
    answering("x").replacen(
        "(module",
        &format!("(module (import \"{module}\" \"{name}\" (func {ty}))"),
        1,
    )
}

const HOST_FN: &str = "(param i32 i32) (result i64)";

#[test]
fn undeclared_capability_import_is_rejected() {
    for (name, capability) in [
        ("keys_choose", "keys = true"),
        ("keys_release", "keys = true"),
        ("dialog_confirm", "dialogs = true"),
        ("file_save", "files = true"),
        ("http_request", r#"http = ["https://a.kz/"]"#),
    ] {
        let wat = importing("oncl", name, HOST_FN);
        assert_eq!(
            compile(&wat, "").err(),
            Some(LoadError::Undeclared(format!("oncl.{name}"))),
            "{name}"
        );
        let compiled = compile(&wat, capability).unwrap();
        compiled.instantiate(&services(), session(1)).unwrap();
    }
    // The basic functions need no capability.
    for name in ["log", "now", "random", "cert_info"] {
        compile(&importing("oncl", name, HOST_FN), "").unwrap();
    }
}

#[test]
fn unknown_import_is_rejected() {
    for (module, name) in [
        ("env", "abort"),
        ("oncl", "exec"),
        ("wasi_snapshot_preview1", "fd_write"),
    ] {
        assert_eq!(
            compile(&importing(module, name, HOST_FN), "").err(),
            Some(LoadError::UnknownImport(format!("{module}.{name}")))
        );
    }
    assert_eq!(
        compile(&importing("oncl", "log", "(param i32) (result i64)"), "").err(),
        Some(LoadError::WrongImport("oncl.log".to_owned()))
    );
    let memory =
        answering("x").replacen("(module", r#"(module (import "oncl" "log" (memory 1))"#, 1);
    assert!(matches!(
        compile(&memory, "").err(),
        Some(LoadError::WrongImport(_) | LoadError::Invalid(_))
    ));
}

#[test]
fn start_function_is_rejected() {
    let wat = answering("x").replacen("(module", "(module (func $s) (start $s)", 1);
    assert!(matches!(
        compile(&wat, "").err(),
        Some(LoadError::Invalid(_))
    ));
}

#[test]
fn infinite_loop_runs_out_of_fuel() {
    let wat = running("(loop $l (br $l))", 2);
    let compiled = Engine::new()
        .with_process_fuel(20_000_000)
        .compile(&manifest(""), &wasm(&wat))
        .unwrap();
    let mut instance = compiled.instantiate(&services(), session(1)).unwrap();
    assert_eq!(
        instance.process("{}", &from("o")),
        Err(PluginError::OutOfFuel)
    );
    assert!(instance.is_poisoned());
    assert_eq!(
        instance.process("{}", &from("o")),
        Err(PluginError::Poisoned)
    );
    assert_eq!(
        PLUGIN_ERROR_REPLY,
        r#"{"success":false,"errorCode":"PLUGIN_ERROR"}"#
    );
    // Another instance of the same module starts afresh.
    let mut other = compiled.instantiate(&services(), session(2)).unwrap();
    assert_eq!(other.process("{}", &from("o")), Err(PluginError::OutOfFuel));
}

/// Pages of [`MAX_MEMORY`].
fn max_pages() -> u32 {
    u32::try_from(MAX_MEMORY / 65536).unwrap()
}

#[test]
fn memory_growth_over_limit_fails() {
    // From 2 pages to one page over the limit.
    let grow = format!("(drop (memory.grow (i32.const {})))", max_pages() - 1);
    let mut instance = start(&running(&grow, 2));
    assert_eq!(
        instance.process("{}", &from("o")),
        Err(PluginError::MemoryLimit)
    );
    // A memory declared over the limit is not instantiated.
    let compiled = compile(
        &answering("x").replace(
            r#"(memory (export "memory") 2)"#,
            &format!(r#"(memory (export "memory") {})"#, max_pages() + 1),
        ),
        "",
    )
    .unwrap();
    assert!(matches!(
        compiled.instantiate(&services(), session(1)).err(),
        Some(LoadError::Instantiate(_))
    ));
}

/// [`answering`] with `alloc` as the body of `oncl_alloc`.
fn with_alloc(alloc: &str) -> String {
    let standard = answering(r#"{"status":true}"#);
    let wat = standard.replace(
        r#"(local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))"#,
        &format!("{alloc})"),
    );
    assert_ne!(wat, standard, "the allocator is replaced");
    wat
}

#[test]
fn alloc_returning_zero_traps() {
    let mut instance = start(&with_alloc("(i32.const 0)"));
    assert!(
        matches!(instance.process("{}", &from("o")), Err(PluginError::Trap(e)) if e.contains("no buffer"))
    );
}

#[test]
fn alloc_returning_a_range_outside_memory_traps() {
    let mut instance = start(&with_alloc("(i32.const 131070)"));
    assert!(
        matches!(instance.process("{}", &from("o")), Err(PluginError::Trap(e)) if e.contains("outside"))
    );
}

#[test]
fn looping_allocator_runs_out_of_fuel() {
    let compiled = Engine::new()
        .with_process_fuel(5_000_000)
        .compile(
            &manifest(""),
            &wasm(&with_alloc("(loop $l (br $l)) (i32.const 0)")),
        )
        .unwrap();
    let mut instance = compiled.instantiate(&services(), session(1)).unwrap();
    assert_eq!(
        instance.process("{}", &from("o")),
        Err(PluginError::OutOfFuel)
    );
}

#[test]
fn host_function_called_from_alloc_traps() {
    // The allocator logs: the host is calling it, for the request or for a host function's
    // result, and a host function may not run then.
    let log = abi::encode(&LogArgs {
        level: Level::Info,
        message: "re-entered".to_owned(),
    });
    let wat = with_alloc(&format!(
        "(drop (call $log (i32.const 512) (i32.const {}))) (i32.const 65536)",
        log.len()
    ))
    .replacen(
        "(module",
        &format!(
            "(module (import \"oncl\" \"log\" (func $log (param i32 i32) (result i64))) (data (i32.const 512) \"{}\")",
            wat_bytes(&log)
        ),
        1,
    );
    let mut instance = start(&wat);
    assert!(
        matches!(instance.process("{}", &from("o")), Err(PluginError::Trap(e)) if e.contains("while the host was running"))
    );
}

#[test]
fn out_of_bounds_result_traps() {
    let wat = running("(return (i64.const 0x00fffff000000100))", 2);
    let mut instance = start(&wat);
    assert!(
        matches!(instance.process("{}", &from("o")), Err(PluginError::Trap(e)) if e.contains("outside"))
    );
    // A result over the transfer limit is refused before it is read.
    let wat = running("(return (i64.const 0x0000000020000000))", 2);
    let mut instance = start(&wat);
    assert_eq!(
        instance.process("{}", &from("o")),
        Err(PluginError::TooLarge)
    );
}

#[test]
fn malformed_output_is_a_plugin_error() {
    let wat = running(
        r#"(i32.store (i32.const 1024) (i32.const 0x01020304))
           (return (i64.or (i64.shl (i64.const 1024) (i64.const 32)) (i64.const 4)))"#,
        2,
    );
    let mut instance = start(&wat);
    assert!(matches!(
        instance.process("{}", &from("o")),
        Err(PluginError::Output(_))
    ));
}

#[test]
fn trap_poisons_the_instance() {
    let mut instance = start(&running("", 2));
    assert!(matches!(
        instance.process("{}", &from("o")),
        Err(PluginError::Trap(_))
    ));
    assert_eq!(
        instance.process("{}", &from("o")),
        Err(PluginError::Poisoned)
    );
}

#[test]
fn abi_version_mismatch_is_rejected() {
    let wat = answering("x").replace(
        r#"(func (export "oncl_abi_version") (result i32) (i32.const 1))"#,
        r#"(func (export "oncl_abi_version") (result i32) (i32.const 2))"#,
    );
    let compiled = compile(&wat, "").unwrap();
    assert!(matches!(
        compiled.instantiate(&services(), session(1)).err(),
        Some(LoadError::AbiVersion(2))
    ));
}

/// A tracing writer into a shared buffer.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn log_and_now_work() {
    let log = abi::encode(&LogArgs {
        level: Level::Warn,
        message: "hello from the guest".to_owned(),
    });
    let mut instance = start(&probe(&[
        (Import::Log, log.clone()),
        (Import::Now, abi::encode(&())),
    ]));
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer({
            let captured = captured.clone();
            move || captured.clone()
        })
        .with_ansi(false)
        .finish();
    let response = tracing::subscriber::with_default(subscriber, || {
        instance.process("{}", &from("o")).unwrap()
    });
    let now: i64 = probe_result(&response).unwrap();
    assert_eq!(i128::from(now), NOW.unix_timestamp_nanos() / 1_000_000);
    let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("hello from the guest"), "{logged}");
    assert!(logged.contains(PLUGIN_ID), "{logged}");
    assert!(logged.contains("WARN"), "{logged}");

    // The log call itself answers Ok.
    let mut instance = start(&probe(&[(Import::Log, log)]));
    let response = instance.process("{}", &from("o")).unwrap();
    assert_eq!(probe_result::<()>(&response), Ok(()));
}

#[test]
fn random_over_1024_is_limit_error() {
    let mut instance = start(&probe(&[(
        Import::Random,
        abi::encode(&RandomArgs { len: 1025 }),
    )]));
    let response = instance.process("{}", &from("o")).unwrap();
    let error = probe_result::<Bytes>(&response).unwrap_err();
    assert_eq!(error.code, ErrorCode::Limit);

    let mut instance = start(&probe(&[(
        Import::Random,
        abi::encode(&RandomArgs { len: 1024 }),
    )]));
    let response = instance.process("{}", &from("o")).unwrap();
    assert_eq!(probe_result::<Bytes>(&response).unwrap().len(), 1024);
}

#[test]
fn cert_info_reads_a_certificate() {
    let der = oncl_testkit::synthetic_cert("inter-gost2015");
    let mut instance = start(&probe(&[(
        Import::CertInfo,
        abi::encode(&CertArgs {
            der: Bytes::from(der.clone()),
        }),
    )]));
    let response = instance.process("{}", &from("o")).unwrap();
    let info: CertInfo = probe_result(&response).unwrap();
    let expected = oncl_pki::info::cert_info(&oncl_pki::cert::parse(&der).unwrap());
    assert_eq!(info.subject_cn, expected.subject_cn);
    assert_eq!(info.serial_hex, expected.serial_hex);
    assert_eq!(
        i128::from(info.not_after),
        expected.not_after.unix_timestamp_nanos() / 1_000_000
    );
    assert!(info.pem.starts_with("-----BEGIN CERTIFICATE-----"));

    let mut instance = start(&probe(&[(
        Import::CertInfo,
        abi::encode(&CertArgs {
            der: Bytes::from(b"not a certificate".to_vec()),
        }),
    )]));
    let response = instance.process("{}", &from("o")).unwrap();
    assert_eq!(
        probe_result::<CertInfo>(&response).unwrap_err().code,
        ErrorCode::Invalid
    );
}

#[test]
fn malformed_argument_is_invalid() {
    let mut instance = start(&probe(&[(Import::Random, vec![0xff, 0x00])]));
    let response = instance.process("{}", &from("o")).unwrap();
    assert_eq!(
        probe_result::<Bytes>(&response).unwrap_err().code,
        ErrorCode::Invalid
    );
}

/// `value` survives CBOR.
fn roundtrip<T>(value: T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    assert_eq!(abi::decode::<T>(&abi::encode(&value)), Ok(value));
}

#[test]
fn abi_types_roundtrip() {
    let bytes = || Bytes::from(vec![0, 1, 2, 255]);
    roundtrip(Input {
        request: "{}".to_owned(),
        origin: Some("https://a.kz".to_owned()),
        locale: "kk".to_owned(),
    });
    roundtrip(Output {
        response: "ok".to_owned(),
    });
    roundtrip::<HostResult<i64>>(Ok(-5));
    roundtrip::<HostResult<()>>(Err(HostError::new(ErrorCode::Denied, "no")));
    roundtrip(LogArgs {
        level: Level::Debug,
        message: "m".to_owned(),
    });
    roundtrip(RandomArgs { len: 7 });
    roundtrip(CertArgs { der: bytes() });
    roundtrip(CertInfo {
        subject_cn: Some("cn".to_owned()),
        iin: None,
        bin: Some("1".to_owned()),
        organization: None,
        serial_hex: "01".to_owned(),
        not_before: 1,
        not_after: 2,
        ext_key_usages: vec!["1.2".to_owned()],
        key_usage: KeyUsage {
            digital_signature: true,
            ..KeyUsage::default()
        },
        signature_alg_oid: "1.2.3".to_owned(),
        spki_alg_oid: "1.2.4".to_owned(),
        pem: "-----".to_owned(),
    });
    roundtrip(ChooseArgs {
        action: Action::KeyInfo,
        storages: vec!["PKCS12".to_owned()],
        filter: Filter {
            chain: Some(vec![bytes()]),
            allow_revoked: true,
            ..Filter::default()
        },
        detail: Some("d".to_owned()),
    });
    roundtrip::<Option<Chosen>>(Some(Chosen {
        handle: 3,
        alias: "a".to_owned(),
        certificate: bytes(),
    }));
    roundtrip(SignCmsArgs {
        handle: 1,
        data: bytes(),
        attached: true,
        timestamp: false,
    });
    roundtrip(SignRawArgs {
        handle: 1,
        data: bytes(),
    });
    roundtrip(SignXmlArgs {
        handle: 1,
        xml: bytes(),
        element: Some("//a".to_owned()),
        parent: None,
    });
    roundtrip(Handle { handle: 9 });
    roundtrip(MessageArgs {
        kind: MessageKind::Warning,
        text: "t".to_owned(),
    });
    roundtrip(ConfirmArgs {
        text: "t".to_owned(),
    });
    roundtrip::<Option<OpenedFile>>(Some(OpenedFile {
        path: "p".to_owned(),
        data: bytes(),
    }));
    roundtrip(SaveArgs {
        suggested_name: "n".to_owned(),
        data: bytes(),
    });
    roundtrip(HttpArgs {
        method: Method::Post,
        url: "https://a.kz/".to_owned(),
        content_type: Some("t".to_owned()),
        body: bytes(),
    });
    roundtrip(HttpResponse {
        status: 302,
        content_type: None,
        location: Some("/x".to_owned()),
        body: bytes(),
    });
}

#[test]
fn abi_encoding_details() {
    // Byte strings are CBOR byte strings (major type 2), not arrays of integers.
    let encoded = abi::encode(&CertArgs {
        der: Bytes::from(vec![1, 2, 3]),
    });
    assert!(
        encoded.windows(4).any(|w| w == [0x43, 1, 2, 3]),
        "{encoded:02x?}"
    );
    // Absent optional fields take their defaults.
    #[derive(serde::Serialize)]
    struct Bare {
        action: Action,
    }
    let args: ChooseArgs = abi::decode(&abi::encode(&Bare {
        action: Action::Sign,
    }))
    .unwrap();
    assert_eq!(args.filter, Filter::default());
    assert!(args.storages.is_empty() && args.detail.is_none());
    // One value, nothing after it.
    let mut trailing = abi::encode(&RandomArgs { len: 1 });
    trailing.push(0);
    assert_eq!(
        abi::decode::<RandomArgs>(&trailing).unwrap_err().code,
        ErrorCode::Invalid
    );
    assert_eq!(
        abi::unpack(abi::pack(0xdead_beef, 0x1234_5678)),
        (0xdead_beef, 0x1234_5678)
    );
    for import in Import::ALL {
        assert_eq!(Import::from_name(import.name()), Some(import));
    }
}
