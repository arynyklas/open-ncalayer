//! `cargo xtask plugin-ops-check`: synthetic manifests in a temporary workspace.

use std::fs;
use std::path::{Path, PathBuf};

use xtask::plugin_ops::{Options, Report, check};

const HEAD: &str = r#"
id = "kz.example.sign"
version = "1.0.0"
min_core = "0.1.0-alpha.7"
modules = ["example.sign"]

[name]
ru = "Подпись"
kk = "Қол қою"
en = "Sign"

[capabilities]
keys = true
http = ["https://api.example.kz/"]
"#;

const OP: &str = r#"
[[operations]]
name    = "sign-file"
module  = "example.sign"
manual  = true
server  = false
request = '{"module":"example.sign","method":"signFile","args":["{file:base64}"]}'
label   = { ru = "Подписать файл", kk = "Файлға қол қою", en = "Sign a file" }

[[operations.params]]
name = "file"
kind = "document"
max_bytes = 16777216

[operations.uses]
imports = ["keys_select", "keys_describe", "keys_sign_cms_ex", "hash"]
network = "pki"
interactive = ["keys_select"]

[[operations.uses.key]]
kind     = "cms_ex"
content  = "param:file"
max_uses = 1
[operations.uses.key.profile]
encapsulate  = false
cosign       = "never"
timestamp    = "basics"
certificates = "signer"
output       = "der"
"#;

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("plugins")).unwrap();
        fs::create_dir_all(dir.path().join("wasm")).unwrap();
        Env { dir }
    }
    fn plugin(&self, name: &str, text: &str) {
        let d = self.dir.path().join("plugins").join(name);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("plugin.toml"), text).unwrap();
    }
    fn wasm(&self, name: &str, imports: &[&str]) {
        let mut wat = String::from("(module\n");
        for i in imports {
            wat += &format!("(import \"oncl\" \"{i}\" (func (param i32 i32) (result i64)))\n");
        }
        wat += r#"(memory (export "memory") 2)
  (global $heap (mut i32) (i32.const 65536))
  (func (export "oncl_abi_version") (result i32) (i32.const 1))
  (func (export "oncl_alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $p))
  (func (export "oncl_free") (param i32 i32))
  (func (export "oncl_process") (param i32 i32) (result i64) (i64.const 0)))"#;
        fs::write(
            self.dir.path().join("wasm").join(format!("{name}.wasm")),
            wat::parse_str(wat).unwrap(),
        )
        .unwrap();
    }
    fn run(&self, require_wasm: bool) -> Report {
        let wasm_dir: PathBuf = self.dir.path().join("wasm");
        check(
            self.dir.path(),
            &Options {
                extra: &[],
                wasm_dir: &wasm_dir,
                require_wasm,
            },
        )
        .unwrap()
    }
}

fn with(op: &str) -> String {
    format!("{HEAD}{op}")
}

fn edit(from: &str, to: &str) -> String {
    assert!(OP.contains(from), "{from:?}");
    with(&OP.replacen(from, to, 1))
}

fn rules(report: &Report) -> Vec<&'static str> {
    report
        .plugins
        .iter()
        .flat_map(|p| p.errors.iter().map(|f| f.rule))
        .collect()
}

const ALL_IMPORTS: [&str; 4] = ["keys_select", "keys_describe", "keys_sign_cms_ex", "hash"];

#[test]
fn no_operations_is_clean() {
    let env = Env::new();
    env.plugin("plain", HEAD);
    let r = env.run(true);
    assert_eq!(r.exit_code(), 0);
    assert_eq!(r.plugins[0].status(), "no operations");
    assert!(r.to_text().contains("no operations"));
}

#[test]
fn valid_operation_with_matching_wasm_passes() {
    let env = Env::new();
    env.plugin("good", &with(OP));
    env.wasm("good", &ALL_IMPORTS);
    let r = env.run(true);
    assert_eq!(r.exit_code(), 0, "{}", r.to_text());
    assert_eq!(r.plugins[0].status(), "ok");
    assert_eq!((r.plugins[0].operations, r.plugins[0].runnable), (1, 1));
}

#[test]
fn derived_is_reported_blocked_with_exit_zero() {
    let env = Env::new();
    env.plugin(
        "derived",
        &edit(r#"content  = "param:file""#, r#"content  = "derived""#),
    );
    env.wasm("derived", &ALL_IMPORTS);
    let r = env.run(true);
    assert_eq!(r.exit_code(), 0, "{}", r.to_text());
    assert_eq!(r.plugins[0].status(), "blocked until MP3b");
    assert_eq!(r.plugins[0].derived, 1);
    assert_eq!(r.plugins[0].runnable, 0);
}

#[test]
fn missing_wasm_warns_by_default_and_errors_when_required() {
    let env = Env::new();
    env.plugin("nowasm", &with(OP));
    let r = env.run(false);
    assert_eq!(r.exit_code(), 0);
    assert_eq!(r.plugins[0].status(), "ok (warnings)");
    assert!(r.to_text().contains("WARNING"));
    assert!(r.to_text().contains("NOT checked"));
    let r = env.run(true);
    assert_eq!(r.exit_code(), 1);
    assert_eq!(rules(&r), ["wasm-missing"]);
}

#[test]
fn declared_import_the_module_lacks_is_an_error() {
    let env = Env::new();
    env.plugin("lacking", &with(OP));
    env.wasm(
        "lacking",
        &["keys_select", "keys_describe", "keys_sign_cms_ex"],
    );
    let r = env.run(false);
    assert_eq!(r.exit_code(), 1);
    assert_eq!(rules(&r), ["wasm-imports"]);
    assert!(r.plugins[0].errors[0].message.contains("hash"));
}

#[test]
fn each_invalid_class_is_reported_under_its_rule() {
    let cases: [(&str, String, &str); 9] = [
        (
            "max-uses",
            edit("max_uses = 1", "max_uses = 2"),
            "key-content",
        ),
        (
            "raw-with-cms-profile",
            edit(r#"kind     = "cms_ex""#, r#"kind     = "raw""#),
            "profile",
        ),
        (
            "stray-placeholder",
            edit(r#""{file:base64}""#, r#""{file:base64}","{ghost}""#),
            "request",
        ),
        (
            "unused-param",
            edit(r#""{file:base64}""#, r#""x""#),
            "placeholders",
        ),
        (
            "placeholder-in-method",
            edit(r#""method":"signFile""#, r#""method":"{file}""#),
            "request",
        ),
        (
            "label",
            edit(r#"en = "Sign a file""#, r#"en = """#),
            "label",
        ),
        ("duplicate", with(&format!("{OP}{OP}")), "duplicate-name"),
        ("flags", edit("manual  = true", "manual  = false"), "flags"),
        (
            "bad-profile",
            edit(r#"timestamp    = "basics""#, r#"timestamp    = "weekly""#),
            "profile",
        ),
    ];
    for (name, text, rule) in cases {
        let env = Env::new();
        env.plugin(name, &text);
        let r = env.run(false);
        assert_eq!(r.exit_code(), 1, "{name}: {}", r.to_text());
        assert!(
            rules(&r).contains(&rule),
            "{name}: expected {rule}, got {:?}",
            rules(&r)
        );
    }
}

#[test]
fn json_output_and_extra_paths() {
    let env = Env::new();
    env.plugin("plain", HEAD);
    let extra: &Path = &env.dir.path().join("extra");
    fs::create_dir_all(extra).unwrap();
    fs::write(extra.join("plugin.toml"), "not toml [").unwrap();
    let wasm_dir = env.dir.path().join("wasm");
    let r = check(
        env.dir.path(),
        &Options {
            extra: &[extra.to_path_buf()],
            wasm_dir: &wasm_dir,
            require_wasm: false,
        },
    )
    .unwrap();
    let j = r.to_json();
    assert_eq!(j["exit_code"], 1);
    assert_eq!(j["plugins"].as_array().unwrap().len(), 2);
    assert_eq!(j["plugins"][1]["errors"][0]["rule"], "manifest");
    assert_eq!(j["plugins"][0]["status"], "no operations");
}
