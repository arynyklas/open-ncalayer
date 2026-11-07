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
/// A plugin operation that declares its key uses is ticketed by Core; without
/// `--plugin-bytes` its key use is refused before the key is applied, with the typed subcode
/// `not-granted`. The test above (a plugin without declarations) is unchanged.
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
        text.contains("oncl: PermissionDenied; subcode=not-granted; applied=NotApplied")
            && !text.contains("private_use"),
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
        text.contains("oncl: PermissionDenied; subcode=not-declared; applied=NotApplied")
            && !text.contains("private_use"),
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

// --- MP8: validation against the declaration, `--plugin-bytes`, `--profile` -------------

const DECLARED: &str = r#"id = "test.cli"
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

[[operations]]
name = "manual-only"
module = "test.cli.module"
manual = true
server = false
request = '{"module":"test.cli.module","method":"m","args":["{file:base64}"]}'
label = { ru = "а", kk = "ә", en = "a" }
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 4096
[operations.uses]
imports = []
network = "none"
"#;
fn sign_raw_call() -> Vec<(Import, Vec<u8>)> {
    vec![(
        Import::KeysSignRaw,
        abi::encode(&abi::SignRawArgs {
            handle: 1,
            data: b"plugin message".to_vec().into(),
        }),
    )]
}
fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn profile_is_not_accepted_the_profile_comes_from_the_manifest() {
    let p = install_with(DECLARED, &sign_raw_call());
    let result = run(
        &base(&p, &["--allow-import", "keys_sign_raw", "--profile", "cms"]),
        b"",
    );
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(
        stderr(&result).contains("oncl: ProfileFromManifest"),
        "{}",
        stderr(&result)
    );
    assert!(result.stdout.is_empty());
}

#[test]
fn plugin_bytes_needs_a_key() {
    let p = install_with(DECLARED, &sign_raw_call());
    let result = run(
        &base(&p, &["--allow-import", "keys_sign_raw", "--plugin-bytes"]),
        b"",
    );
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(
        stderr(&result).contains("InvalidCombination"),
        "{}",
        stderr(&result)
    );
}

#[test]
fn an_import_beyond_the_declaration_is_refused_before_the_module_runs() {
    let p = install_with(DECLARED, &sign_raw_call());
    let result = run(&base(&p, &["--allow-import", "cms_verify"]), b"");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(
        stderr(&result)
            .contains("oncl: PermissionDenied; subcode=not-declared; applied=NotApplied"),
        "{}",
        stderr(&result)
    );
    assert!(result.stdout.is_empty());
}

#[test]
fn an_operation_that_is_not_for_the_cli_is_refused() {
    let p = install_with(DECLARED, &sign_raw_call());
    let mut args = base(&p, &["--allow-import", "hash"]);
    let at = args.iter().position(|a| *a == "sign").unwrap();
    args[at] = "manual-only";
    let result = run(&args, b"");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(
        stderr(&result).contains("subcode=not-declared"),
        "{}",
        stderr(&result)
    );
}

#[test]
fn no_allow_import_means_the_declared_imports_of_a_declared_operation() {
    let keyless = DECLARED
        .replace("imports = [\"keys_sign_raw\"]", "imports = [\"hash\"]")
        .replace(
            "[[operations.uses.key]]\nkind = \"raw\"\ncontent = \"param:file\"\n",
            "",
        );
    let p = install_with(
        &keyless,
        &[(
            Import::Hash,
            abi::encode(&abi::HashArgs {
                alg: abi::HashAlg::Sha256,
                data: b"abc".to_vec().into(),
            }),
        )],
    );
    let result = run(&base(&p, &[]), b"");
    assert_eq!(
        result.status.code(),
        Some(0),
        "{result:?} {}",
        stderr(&result)
    );
    let digest = decode(std::str::from_utf8(&result.stdout).unwrap().trim());
    assert_eq!(
        digest,
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

fn key_args<'a>(w: &'a World, get: &'a str, post: &'a str) -> Vec<&'a str> {
    vec![
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
        get,
        "--plugin-pki-endpoint",
        post,
    ]
}

#[test]
fn a_declared_key_use_runs_with_plugin_bytes_and_is_ticket_checked() {
    let w = world();
    let declared = install_with(DECLARED, &sign_raw_call());
    let (get, post) = (
        format!("GET={}/ocsp", w.origin),
        format!("POST={}/ocsp", w.origin),
    );
    let mut extra = key_args(&w, &get, &post);
    extra.push("--plugin-bytes");
    let result = run(&base(&declared, &extra), b"");
    assert_eq!(
        result.status.code(),
        Some(0),
        "{result:?} {}",
        stderr(&result)
    );
    assert!(
        stderr(&result).contains("applied=Applied succeeded=true"),
        "{}",
        stderr(&result)
    );
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
}

#[test]
fn plugin_bytes_does_not_cover_options_other_than_the_declared_profile() {
    let w = world();
    // A CMS use whose manifest profile is detached/no timestamp, called attached.
    let manifest = DECLARED
        .replace("imports = [\"keys_sign_raw\"]", "imports = [\"keys_sign_cms\"]")
        .replace(
            "kind = \"raw\"\ncontent = \"param:file\"",
            "kind = \"cms\"\ncontent = \"param:file\"\n[operations.uses.key.profile]\nattached = false\ntimestamp = \"none\"",
        );
    let attached = install_with(
        &manifest,
        &[(
            Import::KeysSignCms,
            abi::encode(&abi::SignCmsArgs {
                handle: 1,
                data: b"plugin message".to_vec().into(),
                attached: true,
                timestamp: false,
            }),
        )],
    );
    let (get, post) = (
        format!("GET={}/ocsp", w.origin),
        format!("POST={}/ocsp", w.origin),
    );
    let mut extra = key_args(&w, &get, &post);
    extra[1] = "keys_sign_cms";
    extra.push("--plugin-bytes");
    let result = run(&base(&attached, &extra), b"");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let text = stderr(&result);
    assert!(
        text.contains("oncl: PermissionDenied; subcode=options-mismatch; applied=NotApplied")
            && !text.contains("private_use"),
        "{text}"
    );
}

#[test]
fn a_plugin_without_declarations_ignores_plugin_bytes_with_a_warning() {
    let w = world();
    let signed = install(&sign_raw_call());
    let (get, post) = (
        format!("GET={}/ocsp", w.origin),
        format!("POST={}/ocsp", w.origin),
    );
    let mut extra = key_args(&w, &get, &post);
    extra.push("--plugin-bytes");
    let result = run(&base(&signed, &extra), b"");
    assert_eq!(
        result.status.code(),
        Some(0),
        "{result:?} {}",
        stderr(&result)
    );
    assert!(
        stderr(&result).contains("--plugin-bytes has no effect"),
        "{}",
        stderr(&result)
    );
}

#[test]
fn a_second_key_use_in_one_call_is_refused_and_the_first_stays_reported() {
    let w = world();
    let mut calls = sign_raw_call();
    calls.extend(sign_raw_call());
    let declared = install_with(DECLARED, &calls);
    let (get, post) = (
        format!("GET={}/ocsp", w.origin),
        format!("POST={}/ocsp", w.origin),
    );
    let mut extra = key_args(&w, &get, &post);
    extra.push("--plugin-bytes");
    let result = run(&base(&declared, &extra), b"");
    let text = stderr(&result);
    assert_eq!(result.status.code(), Some(1), "{text}");
    assert!(
        text.contains("oncl: PermissionDenied; subcode=key-use-spent; applied=Applied"),
        "{text}"
    );
    assert_eq!(text.matches("private_use").count(), 1, "{text}");
    assert!(result.stdout.is_empty());
}

// --- MP9: `plugin operations`, typed parameters ----------------------------------------

fn text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}
fn json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {output:?}"))
}
fn operations_args<'a>(p: &'a Installed, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["plugin", "operations", "--manifest", path(&p.manifest)];
    args.extend(extra);
    args
}

#[test]
fn operations_lists_the_declaration_for_an_operator() {
    let p = install_with(DECLARED, &sign_raw_call());
    let result = run(&operations_args(&p, &[]), b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let out = text(&result);
    for expected in [
        "plugin test.cli 1.0.0: 2 declared operation(s)",
        "operation sign\n",
        "  server: yes  manual: no\n",
        "  cli: yes\n",
        "  imports: keys_sign_raw\n",
        "  network: pki\n",
        "  param file: document (at most 4096 bytes)\n",
        "  key: raw, content param:file\n",
        "    signs with your key: a raw signature of the content\n",
        "operation manual-only\n",
        "  server: no  manual: yes\n",
        "  cli: no (not for the CLI: server = false)\n",
        "  key: none\n",
    ] {
        assert!(out.contains(expected), "{expected:?} missing in:\n{out}");
    }
    // Nothing is run and nothing is written: no module was named, stderr is silent.
    assert!(result.stderr.is_empty(), "{}", stderr(&result));
}

#[test]
fn operations_json_has_the_documented_fields() {
    let p = install_with(DECLARED, &sign_raw_call());
    let result = run(&operations_args(&p, &["--json"]), b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let report = json(&result);
    assert_eq!(report["code"], "Completed");
    assert_eq!(report["applied"], "NotApplied");
    assert_eq!(report["plugin"]["id"], "test.cli");
    assert_eq!(report["plugin"]["version"], "1.0.0");
    assert!(report.get("module").is_none());
    let sign = &report["operations"][0];
    assert_eq!(sign["name"], "sign");
    assert_eq!(sign["server"], true);
    assert_eq!(sign["manual"], false);
    assert_eq!(sign["runnable"], true);
    assert_eq!(sign["derived"], false);
    assert_eq!(sign["cli"], true);
    assert_eq!(sign["imports"], serde_json::json!(["keys_sign_raw"]));
    assert_eq!(sign["network"], serde_json::json!({"kind": "pki"}));
    assert_eq!(
        sign["params"],
        serde_json::json!([{"name": "file", "kind": "document", "max_bytes": 4096}])
    );
    assert_eq!(sign["keys"][0]["kind"], "raw");
    assert_eq!(sign["keys"][0]["content"], "param:file");
    assert_eq!(
        sign["keys"][0]["words"],
        "signs with your key: a raw signature of the content"
    );
    let manual = &report["operations"][1];
    assert_eq!(manual["name"], "manual-only");
    assert_eq!(manual["cli"], false);
    assert_eq!(manual["network"], serde_json::json!({"kind": "none"}));
    assert_eq!(manual["keys"], serde_json::json!([]));
}

#[test]
fn a_derived_operation_is_listed_as_not_runnable_and_refused_by_call() {
    let derived = DECLARED
        .replace(
            "imports = [\"keys_sign_raw\"]",
            "imports = [\"keys_sign_cms\"]",
        )
        .replace(
            "kind = \"raw\"\ncontent = \"param:file\"",
            "kind = \"cms\"\ncontent = \"derived\"",
        );
    let p = install_with(&derived, &[]);
    let listed = run(&operations_args(&p, &[]), b"");
    assert_eq!(listed.status.code(), Some(0), "{listed:?}");
    assert!(
        text(&listed).contains("  cli: no (not runnable: derived content)\n"),
        "{}",
        text(&listed)
    );
    let report = json(&run(&operations_args(&p, &["--json"]), b""));
    let sign = &report["operations"][0];
    assert_eq!(sign["derived"], true);
    assert_eq!(sign["runnable"], false);
    assert_eq!(sign["cli"], false);
    assert_eq!(sign["keys"][0]["content"], "derived");
    // `call` agrees with the listing: the operation does not exist for the CLI.
    let called = run(&base(&p, &["--allow-import", "keys_sign_cms"]), b"");
    assert_eq!(called.status.code(), Some(1), "{called:?}");
    assert!(
        stderr(&called)
            .contains("oncl: PermissionDenied; subcode=not-declared; applied=NotApplied"),
        "{}",
        stderr(&called)
    );
}

#[test]
fn operations_of_a_plugin_without_declarations_says_so() {
    let p = install(&[]);
    let result = run(&operations_args(&p, &[]), b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert!(
        text(&result).contains("declares no operations"),
        "{}",
        text(&result)
    );
    let report = json(&run(&operations_args(&p, &["--json"]), b""));
    assert_eq!(report["operations"], serde_json::json!([]));
}

#[test]
fn operations_wasm_checks_the_module_against_the_declaration() {
    let ok = install_with(DECLARED, &sign_raw_call());
    let result = run(&operations_args(&ok, &["--wasm", path(&ok.module)]), b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert!(text(&result).contains("module: ok"), "{}", text(&result));
    let report = json(&run(
        &operations_args(&ok, &["--wasm", path(&ok.module), "--json"]),
        b"",
    ));
    assert_eq!(report["module"], serde_json::json!({"ok": true}));
    // The operation declares keys_sign_raw; this module only imports hash.
    let other = install_with(
        DECLARED,
        &[(
            Import::Hash,
            abi::encode(&abi::HashArgs {
                alg: abi::HashAlg::Sha256,
                data: b"abc".to_vec().into(),
            }),
        )],
    );
    let failed = run(
        &operations_args(&other, &["--wasm", path(&other.module)]),
        b"",
    );
    assert_eq!(failed.status.code(), Some(1), "{failed:?}");
    assert!(
        text(&failed).contains("module: FAILED") && text(&failed).contains("keys_sign_raw"),
        "{}",
        text(&failed)
    );
    let report = json(&run(
        &operations_args(&other, &["--wasm", path(&other.module), "--json"]),
        b"",
    ));
    assert_eq!(report["code"], "InvalidInput");
    assert_eq!(report["module"]["ok"], false);
    assert!(
        report["module"]["error"]
            .as_str()
            .unwrap()
            .contains("keys_sign_raw")
    );
}

#[test]
fn operations_refuses_a_broken_manifest_and_a_missing_module() {
    let broken = install_with("id = \"x\"\n[[operations]]\nname = 1\n", &[]);
    let result = run(&operations_args(&broken, &[]), b"");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(result.stdout.is_empty());
    assert!(
        stderr(&result).contains("invalid plugin manifest"),
        "{}",
        stderr(&result)
    );
    let p = install_with(DECLARED, &sign_raw_call());
    let missing = run(
        &operations_args(
            &p,
            &["--wasm", path(&p.manifest.with_file_name("none.wasm"))],
        ),
        b"",
    );
    assert_eq!(missing.status.code(), Some(1), "{missing:?}");
    assert!(missing.stdout.is_empty());
}

#[test]
fn operations_is_a_local_command_only() {
    let p = install_with(DECLARED, &sign_raw_call());
    let result = run(
        &operations_args(&p, &["--endpoint", "https://127.0.0.1:1", "--token-stdin"]),
        b"token",
    );
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(result.stdout.is_empty());
    assert!(
        stderr(&result).contains("oncl: RemoteUnsupported"),
        "{}",
        stderr(&result)
    );
}

// Typed parameters. The module answers with the request it received, so stdout is the
// request Core built from the manifest's template.

const TYPED: &str = r#"id = "test.cli"
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
request = '{"module":"test.cli.module","method":"m","args":["{file:base64}","{note}","{mode}","{lang}","{strict}"]}'
label = { ru = "а", kk = "ә", en = "a" }
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 4096
[[operations.params]]
name = "note"
kind = "text"
max_chars = 20
[[operations.params]]
name = "mode"
kind = "choice"
choices = ["a", "b"]
[[operations.params]]
name = "lang"
kind = "locale"
[[operations.params]]
name = "strict"
kind = "flag"
[operations.uses]
imports = []
network = "none"
"#;
/// Answers with the hex of the input it is given (the ABI `Input`, whose `request` is what
/// Core built), in the response shape of `wasm`.
fn echo_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
      (memory (export "memory") 16 16)
      (global $heap (mut i32) (i32.const 65536))
      (func (export "oncl_abi_version") (result i32) (i32.const 1))
      (func (export "oncl_alloc") (param $n i32) (result i32) (local $p i32)
        (local.set $p (global.get $heap))
        (global.set $heap (i32.add (local.get $p) (local.get $n))) (local.get $p))
      (func (export "oncl_free") (param i32 i32))
      (data (i32.const 512) "0123456789abcdef")
      (func (export "oncl_process") (param $src i32) (param $len i32) (result i64)
        (local $i i32) (local $b i32) (local $out i32) (local $hex i32)
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
          (i64.extend_i32_u (i32.add (local.get $hex) (i32.const 15))))))"#,
    )
    .unwrap()
}
/// The request Core handed the module, out of the echoed input.
fn request_of(output: &std::process::Output) -> String {
    let input: abi::Input = abi::decode(&hex(text(output).trim())).unwrap();
    input.request
}
struct Typed {
    p: Installed,
    file: std::path::PathBuf,
}
fn typed_with(manifest: &str, document: &[u8]) -> Typed {
    let p = install_with(manifest, &[]);
    std::fs::write(&p.module, echo_wasm()).unwrap();
    let file = p.manifest.with_file_name("document.bin");
    std::fs::write(&file, document).unwrap();
    Typed { p, file }
}
fn typed() -> Typed {
    typed_with(TYPED, b"hello")
}
fn call_typed<'a>(t: &'a Typed, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "plugin",
        "call",
        "--manifest",
        path(&t.p.manifest),
        "--module",
        path(&t.p.module),
        "--operation",
        "sign",
        "--caller",
        "cli-operator",
        "--output",
        "-",
    ];
    args.extend(extra);
    args
}
fn file_arg(t: &Typed) -> String {
    format!("file={}", path(&t.file))
}

#[test]
fn typed_parameters_build_the_exact_request() {
    let t = typed();
    let file = file_arg(&t);
    let result = run(
        &call_typed(
            &t,
            &[
                "--param-file",
                &file,
                "--param",
                "note=say \"hi\"",
                "--param",
                "mode=b",
                "--param",
                "lang=kk",
                "--param-flag",
                "strict",
            ],
        ),
        b"",
    );
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    // Golden: compact, keys sorted, the document as standard base64, the text escaped, the
    // flag a JSON boolean; `module` and `method` are the manifest's.
    assert_eq!(
        request_of(&result),
        r#"{"args":["aGVsbG8=","say \"hi\"","b","kk",true],"method":"m","module":"test.cli.module"}"#
    );
    // A flag that is not named is off.
    let off = run(
        &call_typed(
            &t,
            &[
                "--param-file",
                &file,
                "--param",
                "note=n",
                "--param",
                "mode=a",
                "--param",
                "lang=ru",
            ],
        ),
        b"",
    );
    assert_eq!(off.status.code(), Some(0), "{off:?}");
    assert_eq!(
        request_of(&off),
        r#"{"args":["aGVsbG8=","n","a","ru",false],"method":"m","module":"test.cli.module"}"#
    );
}

#[test]
fn a_document_can_come_from_standard_input() {
    let t = typed();
    let result = run(
        &call_typed(
            &t,
            &[
                "--param-file",
                "file=-",
                "--param",
                "note=n",
                "--param",
                "mode=a",
                "--param",
                "lang=en",
            ],
        ),
        b"hello",
    );
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert!(
        request_of(&result).contains(r#""aGVsbG8=""#),
        "{}",
        request_of(&result)
    );
}

fn refusal(t: &Typed, extra: &[&str]) -> String {
    let result = run(&call_typed(t, extra), b"");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(result.stdout.is_empty(), "{}", text(&result));
    stderr(&result)
}
/// A complete, valid set of typed parameters; `replace` swaps the flag and value of the
/// parameter of that name, or drops it for `None`, so a case differs from the valid one by
/// exactly one fault.
fn complete(file: &str, replace: &[(&str, Option<(&str, &str)>)]) -> Vec<String> {
    let mut args = Vec::new();
    for (flag, name, value) in [
        ("--param-file", "file", file),
        ("--param", "note", "note=n"),
        ("--param", "mode", "mode=a"),
        ("--param", "lang", "lang=ru"),
    ] {
        match replace.iter().find(|(n, _)| *n == name) {
            Some((_, Some((flag, value)))) => args.extend([flag.to_string(), value.to_string()]),
            Some((_, None)) => {}
            None => args.extend([flag.to_owned(), value.to_owned()]),
        }
    }
    args
}
fn refuse_with(t: &Typed, extra: &[String]) -> String {
    let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
    refusal(t, &extra)
}
fn run_with(t: &Typed, extra: &[String]) -> std::process::Output {
    let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
    run(&call_typed(t, &extra), b"")
}

#[test]
fn a_document_over_its_declared_size_is_refused_before_anything_runs() {
    let big = typed_with(TYPED, &vec![7u8; 4097]);
    let line = refuse_with(&big, &complete(&file_arg(&big), &[]));
    assert!(
        line.contains("oncl: InputLimit; subcode=param-too-large; applied=NotApplied"),
        "{line}"
    );
    // Exactly the declared size is accepted.
    let fit = typed_with(TYPED, &vec![7u8; 4096]);
    let result = run_with(&fit, &complete(&file_arg(&fit), &[]));
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    // An empty document is not a document.
    let empty = typed_with(TYPED, b"");
    let line = refuse_with(&empty, &complete(&file_arg(&empty), &[]));
    assert!(
        line.contains("oncl: InvalidInput; subcode=param-invalid-value; applied=NotApplied"),
        "{line}"
    );
}

#[test]
fn bad_typed_parameters_are_refused_with_a_subcode() {
    let t = typed();
    let file = file_arg(&t);
    // (the parameter replaced or added, the refusal): one fault each.
    type Case<'a> = (&'a str, Option<(&'a str, &'a str)>, &'a str, &'a str);
    let cases: [Case; 7] = [
        (
            "bogus",
            Some(("--param", "bogus=1")),
            "InvalidInput",
            "unknown-param",
        ),
        (
            "file",
            Some(("--param", "file=text")),
            "InvalidInput",
            "param-wrong-kind",
        ),
        (
            "note",
            Some(("--param-file", "note=x")),
            "InvalidInput",
            "param-wrong-kind",
        ),
        (
            "mode",
            Some(("--param", "mode=c")),
            "InvalidInput",
            "param-invalid-value",
        ),
        (
            "lang",
            Some(("--param", "lang=de")),
            "InvalidInput",
            "param-invalid-value",
        ),
        (
            "note",
            Some(("--param", "note=aaaaaaaaaaaaaaaaaaaaa")),
            "InputLimit",
            "param-too-large",
        ),
        ("note", None, "InvalidInput", "missing-param"),
    ];
    for (name, replacement, code, subcode) in cases {
        let mut args = complete(&file, &[(name, replacement)]);
        if name == "bogus" {
            args.extend(["--param".to_owned(), "bogus=1".to_owned()]);
        }
        let line = refuse_with(&t, &args);
        assert!(
            line.contains(&format!(
                "oncl: {code}; subcode={subcode}; applied=NotApplied"
            )),
            "{name}: {line}"
        );
    }
    // An unknown document is refused before its file is opened.
    let mut unknown = complete(&file, &[]);
    unknown.extend([
        "--param-file".to_owned(),
        "bogus=does-not-exist.bin".to_owned(),
    ]);
    let line = refuse_with(&t, &unknown);
    assert!(line.contains("subcode=unknown-param"), "{line}");
    // Given twice.
    let mut twice = complete(&file, &[]);
    twice.extend(["--param".to_owned(), "mode=b".to_owned()]);
    let line = refuse_with(&t, &twice);
    assert!(
        line.contains("oncl: InvalidInput; subcode=duplicate-param; applied=NotApplied"),
        "{line}"
    );
}

#[test]
fn typed_and_free_arguments_do_not_mix_and_syntax_is_checked_first() {
    let t = typed();
    let free = t.p.args.clone();
    let file = file_arg(&t);
    for (extra, code) in [
        (
            vec!["--args-file", path(&free), "--param", "note=n"],
            "InvalidCombination",
        ),
        (
            vec!["--args-file", path(&free), "--param-flag", "strict"],
            "InvalidCombination",
        ),
        (vec!["--param", "Note=n"], "InvalidCombination"),
        (vec!["--param", "novalue"], "InvalidCombination"),
        (vec!["--param-file", "file="], "InvalidCombination"),
        (vec!["--param-flag", "a=b"], "InvalidCombination"),
        (
            vec!["--param-file", "file=-", "--param-file", "other=-"],
            "StdinConflict",
        ),
        (
            vec!["--param-file", &file, "--args-file", "-"],
            "InvalidCombination",
        ),
    ] {
        let line = refusal(&t, &extra);
        assert!(line.contains(&format!("oncl: {code}")), "{extra:?}: {line}");
    }
}

#[test]
fn a_plugin_without_declarations_still_takes_only_a_free_request() {
    let p = install(&[]);
    std::fs::write(&p.module, echo_wasm()).unwrap();
    std::fs::write(
        &p.args,
        br#"{"module":"test.cli.module","method":"m","args":[]}"#,
    )
    .unwrap();
    // Unchanged: the file is the request.
    let result = run(&base(&p, &[]), b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        request_of(&result),
        r#"{"module":"test.cli.module","method":"m","args":[]}"#
    );
    // Typed parameters, or no request at all, have nothing to be checked against.
    for extra in [
        vec!["--param", "a=1"],
        vec!["--param-file", "a=does-not-exist.bin"],
        vec![],
    ] {
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
            "--output",
            "-",
        ];
        args.extend(extra);
        let result = run(&args, b"");
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert!(
            stderr(&result)
                .contains("oncl: PermissionDenied; subcode=not-declared; applied=NotApplied"),
            "{}",
            stderr(&result)
        );
    }
}

#[test]
fn a_declared_operation_without_parameters_builds_its_request_from_the_template() {
    let plain = TYPED
        .replace(
            r#"request = '{"module":"test.cli.module","method":"m","args":["{file:base64}","{note}","{mode}","{lang}","{strict}"]}'"#,
            r#"request = '{"module":"test.cli.module","method":"m","args":[1]}'"#,
        )
        .split("[[operations.params]]")
        .next()
        .unwrap()
        .to_owned()
        + "[operations.uses]\nimports = []\nnetwork = \"none\"\n";
    let t = typed_with(&plain, b"x");
    let result = run(&call_typed(&t, &[]), b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        request_of(&result),
        r#"{"args":[1],"method":"m","module":"test.cli.module"}"#
    );
}

// Key use with typed parameters: the operator's `--plugin-bytes` is the consent, and the
// audit line says so.

fn signed_typed(w: &World) -> (Typed, String, String) {
    let t = typed_with(DECLARED, b"plugin message");
    std::fs::write(&t.p.module, wasm(&sign_raw_call())).unwrap();
    (
        t,
        format!("GET={}/ocsp", w.origin),
        format!("POST={}/ocsp", w.origin),
    )
}

#[test]
fn a_typed_key_use_needs_plugin_bytes_and_is_audited_without_the_document() {
    let w = world();
    let (t, get, post) = signed_typed(&w);
    let file = file_arg(&t);
    let key = key_args(&w, &get, &post);
    // No `--plugin-bytes`: the CLI does not ask, it refuses before the key is applied.
    let mut args = vec!["--param-file", file.as_str()];
    args.extend(&key);
    let denied = run(&call_typed(&t, &args), b"");
    assert_eq!(denied.status.code(), Some(1), "{denied:?}");
    let line = stderr(&denied);
    assert!(
        line.contains("oncl: PermissionDenied; subcode=not-granted; applied=NotApplied")
            && !line.contains("private_use")
            && !line.contains("plugin_use"),
        "{line}"
    );
    // With it, the use runs once and its trusted facts are recorded before the key is used.
    args.push("--plugin-bytes");
    let result = run(&call_typed(&t, &args), b"");
    assert_eq!(
        result.status.code(),
        Some(0),
        "{result:?} {}",
        stderr(&result)
    );
    let log = stderr(&result);
    let audit = log
        .lines()
        .find(|l| l.starts_with("oncl: plugin_use "))
        .unwrap_or_else(|| panic!("no audit line in {log}"));
    for expected in [
        "plugin=test.cli ",
        "version=1.0.0 ",
        "operation=sign ",
        "caller=local-operator ",
        "declared=true ",
        "grant=cli-plugin-bytes ",
        // What the plugin chose to sign, not the document parameter ("hello").
        "content_sha256=e27db2eacc6f55d9c4d97d05cd6f0050ed1637bf5e1e83fc367cc84c560646be ",
        "content_len=14 ",
        "prehashed=false ",
    ] {
        assert!(audit.contains(expected), "{expected:?} missing in {audit}");
    }
    assert!(
        !log.contains("cGx1Z2luIG1lc3NhZ2U"),
        "the document is never recorded"
    );
    let before = log.find("plugin_use").unwrap();
    let after = log.find("private_use").unwrap();
    assert!(before < after, "recorded before the key is used: {log}");
}

#[test]
fn help_lists_the_plugin_surface() {
    for (args, expected) in [
        (
            vec!["--help"],
            vec!["plugin", "Run a WASM plugin operation"],
        ),
        (
            vec!["plugin", "--help"],
            vec!["call", "operations", "--plugin-bytes"],
        ),
        (
            vec!["plugin", "call", "--help"],
            vec![
                "--param <PARAM>",
                "--param-file <PARAM_FILE>",
                "--param-flag <PARAM_FLAG>",
                "--plugin-bytes",
                "--args-file <ARGS_FILE>",
            ],
        ),
        (
            vec!["plugin", "operations", "--help"],
            vec!["--manifest <MANIFEST>", "--wasm <WASM>"],
        ),
    ] {
        let result = run(&args, b"");
        assert_eq!(result.status.code(), Some(0), "{args:?}: {result:?}");
        for needle in expected {
            assert!(text(&result).contains(needle), "{args:?}: {needle:?}");
        }
    }
}

#[test]
fn a_typed_key_use_signs_exactly_the_passed_bytes() {
    let w = world();
    let (t, get, post) = signed_typed(&w);
    // The module signs "plugin message"; the operator passed other bytes.
    std::fs::write(&t.file, b"another document").unwrap();
    let file = file_arg(&t);
    let key = key_args(&w, &get, &post);
    let mut args = vec!["--param-file", file.as_str()];
    args.extend(&key);
    args.push("--plugin-bytes");
    let denied = run(&call_typed(&t, &args), b"");
    assert_eq!(denied.status.code(), Some(1), "{denied:?}");
    let line = stderr(&denied);
    assert!(
        line.contains("oncl: PermissionDenied; subcode=content-mismatch; applied=NotApplied")
            && !line.contains("private_use"),
        "{line}"
    );
    // A free request binds the operation and options only, as documented.
    let free = run(
        &base(&t.p, &[key.as_slice(), &["--plugin-bytes"]].concat()),
        b"",
    );
    assert_eq!(free.status.code(), Some(0), "{free:?} {}", stderr(&free));
}
