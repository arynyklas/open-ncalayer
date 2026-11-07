//! Real WASM plugin processes: operator grants, key bindings, typed refusals.
mod support;
use oncl_pdk::abi::{self, Import};
use support::*;

const MANIFEST: &str = r#"id = "test.cli"
name.ru = "CLI synthetic"
name.kk = "CLI synthetic"
name.en = "CLI synthetic"
version = "1.0.0"
min_core = "0.1.0"
modules = ["test.cli.module"]
[capabilities]
keys = true
dialogs = true
"#;
/// Calls each import with fixed encoded arguments, then returns the last result.
fn wasm(calls: &[(Import, Vec<u8>)]) -> Vec<u8> {
    let (mut imports, mut data, mut body, mut seen, mut at) = (
        String::new(),
        String::new(),
        String::new(),
        Vec::new(),
        1024,
    );
    for (import, args) in calls {
        if !seen.contains(import) {
            seen.push(*import);
            imports.push_str(&format!(
                "(import \"oncl\" \"{0}\" (func ${0} (param i32 i32) (result i64)))",
                import.name()
            ));
        }
        let escaped: String = args.iter().map(|b| format!("\\{b:02x}")).collect();
        data.push_str(&format!("(data (i32.const {at}) \"{escaped}\")"));
        body.push_str(&format!(
            "(local.set $r (call ${} (i32.const {at}) (i32.const {})))",
            import.name(),
            args.len()
        ));
        at += args.len();
    }
    let heap = at.div_ceil(65536).max(1) * 65536;
    wat::parse_str(format!(r#"(module {imports}
      (memory (export "memory") 16 16)
      (global $heap (mut i32) (i32.const {heap}))
      (func (export "oncl_abi_version") (result i32) (i32.const 1))
      (func (export "oncl_alloc") (param $n i32) (result i32) (local $p i32)
        (local.set $p (global.get $heap))
        (global.set $heap (i32.add (local.get $p) (local.get $n))) (local.get $p))
      (func (export "oncl_free") (param i32 i32))
      {data} (data (i32.const 512) "0123456789abcdef")
      (func (export "oncl_process") (param i32 i32) (result i64)
        (local $r i64) (local $src i32) (local $len i32) (local $i i32) (local $b i32) (local $out i32) (local $hex i32)
        {body}
        (local.set $src (i32.wrap_i64 (i64.shr_u (local.get $r) (i64.const 32))))
        (local.set $len (i32.wrap_i64 (local.get $r)))
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
        (block $done (loop $next
          (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
          (local.set $b (i32.load8_u (i32.add (local.get $src) (local.get $i))))
          (i32.store8 offset=15 (i32.add (local.get $out) (i32.shl (local.get $i) (i32.const 1)))
            (i32.load8_u offset=512 (i32.shr_u (local.get $b) (i32.const 4))))
          (i32.store8 offset=16 (i32.add (local.get $out) (i32.shl (local.get $i) (i32.const 1)))
            (i32.load8_u offset=512 (i32.and (local.get $b) (i32.const 15))))
          (local.set $i (i32.add (local.get $i) (i32.const 1))) (br $next)))
        (i64.or (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
          (i64.extend_i32_u (i32.add (local.get $hex) (i32.const 15))))))"#)).unwrap()
}
fn decode(response: &str) -> Vec<u8> {
    let bytes: Vec<u8> = (0..response.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&response[i..i + 2], 16).unwrap())
        .collect();
    abi::decode::<abi::HostResult<abi::Bytes>>(&bytes)
        .unwrap()
        .unwrap()
        .into_vec()
}
struct Installed {
    _dir: tempfile::TempDir,
    manifest: std::path::PathBuf,
    module: std::path::PathBuf,
    args: std::path::PathBuf,
}
fn install(calls: &[(Import, Vec<u8>)]) -> Installed {
    install_with(MANIFEST, calls)
}
fn install_with(manifest_text: &str, calls: &[(Import, Vec<u8>)]) -> Installed {
    let dir = tempfile::tempdir().unwrap();
    let (manifest, module, args) = (
        dir.path().join("plugin.toml"),
        dir.path().join("plugin.wasm"),
        dir.path().join("args.json"),
    );
    std::fs::write(&manifest, manifest_text).unwrap();
    std::fs::write(&module, wasm(calls)).unwrap();
    std::fs::write(&args, b"{}").unwrap();
    Installed {
        _dir: dir,
        manifest,
        module,
        args,
    }
}
fn base<'a>(p: &'a Installed, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "plugin",
        "call",
        "--manifest",
        path(&p.manifest),
        "--module",
        path(&p.module),
        "--operation",
        "sign",
        "--caller",
        "cli-operator",
        "--args-file",
        path(&p.args),
        "--output",
        "-",
    ];
    args.extend(extra);
    args
}
#[test]
fn allowed_hash_runs_and_ungranted_hash_is_denied() {
    let p = install(&[(
        Import::Hash,
        abi::encode(&abi::HashArgs {
            alg: abi::HashAlg::Sha256,
            data: b"abc".to_vec().into(),
        }),
    )]);
    let result = run(&base(&p, &["--allow-import", "hash"]), b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let digest = decode(std::str::from_utf8(&result.stdout).unwrap().trim());
    assert_eq!(
        digest,
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    let denied = run(&base(&p, &[]), b"");
    assert_eq!(denied.status.code(), Some(1), "{denied:?}");
    assert!(String::from_utf8_lossy(&denied.stderr).contains("PermissionDenied"));
    assert!(denied.stdout.is_empty());
}
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn bound_key_signs_only_the_authorized_handle_with_strict_private_checks() {
    let w = world();
    let signed = install(&[(
        Import::KeysSignRaw,
        abi::encode(&abi::SignRawArgs {
            handle: 1,
            data: b"plugin message".to_vec().into(),
        }),
    )]);
    let mut extra = vec![
        "--allow-import",
        "keys_sign_raw",
        "--key",
        path(&w.rsa_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
        "--root",
        path(&w.root),
        "--pki-endpoint",
        &w.origin,
        "--as-of",
        "1793620800",
    ];
    let get = format!("GET={}/ocsp", w.origin);
    let post = format!("POST={}/ocsp", w.origin);
    extra.extend([
        "--plugin-pki-endpoint",
        &get,
        "--plugin-pki-endpoint",
        &post,
    ]);
    let result = run(&base(&signed, &extra), b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stderr).contains("applied=Applied succeeded=true"));
    let signature = decode(std::str::from_utf8(&result.stdout).unwrap().trim());
    w.pki
        .rsa
        .key
        .public_key()
        .verify(
            oncl_pki::key::SigAlg::RsaSha256,
            b"plugin message",
            &signature,
        )
        .unwrap();
    // The guest names a different handle: no key opens, no private use occurs.
    let other = install(&[(
        Import::KeysSignRaw,
        abi::encode(&abi::SignRawArgs {
            handle: 2,
            data: b"plugin message".to_vec().into(),
        }),
    )]);
    let denied = run(&base(&other, &extra), b"");
    assert_eq!(denied.status.code(), Some(1), "{denied:?}");
    let text = String::from_utf8_lossy(&denied.stderr);
    assert!(
        text.contains("PermissionDenied") && !text.contains("private_use"),
        "{text}"
    );
    // A bound key without --authorize or with an unlisted import never reaches the guest.
    extra.remove(extra.iter().position(|a| *a == "--authorize").unwrap());
    let unauthorized = run(&base(&signed, &extra), b"");
    assert_eq!(unauthorized.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unauthorized.stderr).contains("AuthorityRequired"));
}
/// A plugin operation that declares its key uses is ticketed by Core; the CLI has no
/// `--plugin-bytes` grant yet, so its key use is refused before the key is applied. The test
/// above (a plugin without declarations) is unchanged.
#[test]
fn declared_operation_key_use_is_refused_before_the_key() {
    let w = world();
    let manifest = r#"id = "test.cli"
name.ru = "CLI synthetic"
name.kk = "CLI synthetic"
name.en = "CLI synthetic"
version = "1.0.0"
min_core = "0.1.0-alpha.7"
modules = ["test.cli.module"]
[capabilities]
keys = true
[[operations]]
name = "sign"
module = "test.cli.module"
server = true
request = '{"module":"test.cli.module","method":"m","args":["{file:base64}"]}'
label = { ru = "а", kk = "ә", en = "a" }
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 4096
[operations.uses]
imports = ["keys_sign_raw"]
network = "pki"
[[operations.uses.key]]
kind = "raw"
content = "param:file"
"#;
    let declared = install_with(
        manifest,
        &[(
            Import::KeysSignRaw,
            abi::encode(&abi::SignRawArgs {
                handle: 1,
                data: b"plugin message".to_vec().into(),
            }),
        )],
    );
    let get = format!("GET={}/ocsp", w.origin);
    let post = format!("POST={}/ocsp", w.origin);
    let extra = [
        "--allow-import",
        "keys_sign_raw",
        "--key",
        path(&w.rsa_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
        "--root",
        path(&w.root),
        "--pki-endpoint",
        &w.origin,
        "--as-of",
        "1793620800",
        "--plugin-pki-endpoint",
        &get,
        "--plugin-pki-endpoint",
        &post,
    ];
    let denied = run(&base(&declared, &extra), b"");
    assert_eq!(denied.status.code(), Some(1), "{denied:?}");
    let text = String::from_utf8_lossy(&denied.stderr);
    assert!(
        text.contains("PermissionDenied") && !text.contains("private_use"),
        "{text}"
    );
    assert!(denied.stdout.is_empty());
    // The refusal is told to the operator with its stable subcode; the error itself is the
    // plain PermissionDenied the plugin saw.
    assert!(
        text.contains("plugin_refused") && text.contains("subcode=not-granted"),
        "{text}"
    );
    // A label the plugin does not declare is refused too: no key use at all.
    let mut other = base(&declared, &extra);
    let at = other.iter().position(|a| *a == "sign").unwrap();
    other[at] = "legacy";
    let denied = run(&other, b"");
    assert_eq!(denied.status.code(), Some(1), "{denied:?}");
    let text = String::from_utf8_lossy(&denied.stderr);
    assert!(
        text.contains("PermissionDenied") && !text.contains("private_use"),
        "{text}"
    );
}
#[test]
fn mandatory_prompt_is_typed_interaction_required_without_a_ui() {
    let p = install(&[(
        Import::DialogMessage,
        abi::encode(&abi::MessageArgs {
            kind: abi::MessageKind::Info,
            text: "hello".into(),
        }),
    )]);
    let result = run(&base(&p, &["--allow-import", "dialog_message"]), b"");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stderr).contains("InteractionRequired"));
    assert!(result.stdout.is_empty());
}
#[test]
fn unknown_import_name_is_rejected_before_any_file_io() {
    let result = run(
        &[
            "plugin",
            "call",
            "--manifest",
            "missing.toml",
            "--module",
            "missing.wasm",
            "--operation",
            "x",
            "--caller",
            "c",
            "--allow-import",
            "not_an_import",
            "--args-file",
            "missing.json",
            "--output",
            "-",
        ],
        b"",
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("InvalidCombination"));
}
