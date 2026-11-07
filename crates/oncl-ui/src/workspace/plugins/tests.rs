//! The Plugins page as the user meets it: the real Slint page, its real wiring, the real engine
//! over a synthetic authority and real synthetic plugins (WebAssembly modules that call the
//! host's real signing imports), with the workers' answers pumped on this thread. These are the
//! tests that catch a button that can never be pressed, a consent that confirms too early, a
//! result that says «done» when the key was not used.
//!
//! The synthetic modules sign fixed bytes (what the module's author compiled in), so a file the
//! user picks that is not those bytes is exactly the case of a plugin that signs something the
//! user did not approve: Core refuses it before the key is used.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oncl_core::plugins::{CallerContext, PackageHash, PluginConsentGuard, PluginRegistry};
use oncl_flows::Locale;
use oncl_pdk::abi::{self, Import};
use oncl_pki::http::HttpMethod;
use oncl_pki::key::SigAlg;
use oncl_plugin::{InstanceLimits, Manifest};
use oncl_token::Tokens;
use slint::ComponentHandle;
use slint::Model as _;
use slint::platform::{Key, WindowEvent};
use std::path::Path as StdPath;

use super::controller::Step;
use super::offer::{
    ManualListing, ManualPluginSource, OfferError, OfferedOperation, PluginEngineKit, PluginOffer,
    UnusablePlugin, WithoutOperations, plugin_offer,
};
use super::report::CallReport;
use super::run::{Decision, RunOutcome, RunSpec, run};
use super::texts::Texts;
use crate::signing::runner::ExtraTrust;
use crate::signing::testing::{PASSWORD, World, engine, now, world};
use crate::ui::PluginsState;
use crate::workspace::{DesktopEngineServices, Workspace, pump, test_workspace};

/// The bytes the synthetic modules sign: the document the user approves in the good cases.
pub(super) const DOC: &[u8] = b"the document the user approved";
/// Bytes the user may pick instead: not what the modules sign.
const OTHER: &[u8] = b"a document the user did not approve";

const EVIL: [&str; 3] = ["EVIL-NAME", "EVIL-LABEL", "EVIL-DESCRIPTION"];

fn manual() -> CallerContext {
    CallerContext::LocalOperator("manual-window".to_owned())
}

/// A module that makes `calls` in order and answers with the hex of the last result: the
/// shape of the core's own synthetic plugin.
fn wasm(calls: &[(Import, Vec<u8>)], extra: &[Import]) -> Vec<u8> {
    let mut imports = String::new();
    for import in extra {
        imports.push_str(&format!(
            "(import \"oncl\" \"{0}\" (func ${0} (param i32 i32) (result i64)))",
            import.name()
        ));
    }
    let mut data = String::new();
    let mut body = String::new();
    let mut seen: Vec<Import> = extra.to_vec();
    let mut at = 1024;
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
    wat::parse_str(format!(
        r#"(module {imports}
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
          (i64.extend_i32_u (i32.add (local.get $hex) (i32.const 15))))))"#
    ))
    .unwrap()
}

fn raw_call(data: &[u8]) -> (Import, Vec<u8>) {
    (
        Import::KeysSignRaw,
        abi::encode(&abi::SignRawArgs {
            handle: 1,
            data: data.to_vec().into(),
        }),
    )
}

fn cms_call(content: &[u8]) -> (Import, Vec<u8>) {
    let args = abi::SignCmsExArgs {
        handle: 1,
        content: abi::CmsContent::Data(content.to_vec().into()),
        encapsulate: false,
        cosign: abi::CoSign::Never,
        econtent_type: None,
        digest: None,
        attrs: abi::SignedAttrs {
            content_type: true,
            message_digest: true,
            signing_certificate_v2: true,
            signing_time: Some(abi::SigningTime {
                at: abi::TimeSource::Now,
                form: abi::TimeForm::Auto,
            }),
            extra: Vec::new(),
        },
        certificates: abi::CmsCerts::Signer,
        timestamp: None,
        output: abi::CmsOutput::Der,
    };
    (Import::KeysSignCmsEx, abi::encode(&args))
}

const KEY_IMPORTS: &str = r#""keys_describe", "keys_chain", "keys_release""#;

fn header(id: &str, version: &str) -> String {
    format!(
        r#"id = "{id}"
name.ru = "EVIL-NAME ru"
name.kk = "EVIL-NAME kk"
name.en = "EVIL-NAME en"
description.ru = "EVIL-DESCRIPTION"
description.kk = "EVIL-DESCRIPTION"
description.en = "EVIL-DESCRIPTION"
version = "{version}"
min_core = "0.1.0-alpha.7"
modules = ["{id}.module"]
[capabilities]
keys = true
"#
    )
}

fn raw_manifest() -> Manifest {
    Manifest::from_toml(&format!(
        r#"{}
[[operations]]
name = "sign-raw"
module = "test.raw.module"
manual = true
request = '{{"module":"test.raw.module","method":"m","args":["{{file:base64}}"]}}'
label = {{ ru = "EVIL-LABEL ru", kk = "EVIL-LABEL kk", en = "EVIL-LABEL en" }}
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 8192
[operations.uses]
imports = ["keys_sign_raw", {KEY_IMPORTS}]
network = "pki"
[[operations.uses.key]]
kind = "raw"
content = "param:file"

[[operations]]
name = "healthcheck"
module = "test.raw.module"
manual = true
request = '{{"module":"test.raw.module","method":"health","args":[]}}'
label = {{ ru = "EVIL-LABEL проверка", kk = "EVIL-LABEL тексеру", en = "EVIL-LABEL check" }}
[operations.uses]
imports = ["hash"]
"#,
        header("test.raw", "1.2.3")
    ))
    .unwrap()
}

fn cms_manifest() -> Manifest {
    Manifest::from_toml(&format!(
        r#"{}
[[operations]]
name = "sign-cms"
module = "test.cms.module"
manual = true
request = '{{"module":"test.cms.module","method":"m","args":["{{file:base64}}","{{note}}","{{mode}}","{{loud}}","{{lang}}"]}}'
label = {{ ru = "EVIL-LABEL ru", kk = "EVIL-LABEL kk", en = "EVIL-LABEL en" }}
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 8192
[[operations.params]]
name = "note"
kind = "text"
max_chars = 8
[[operations.params]]
name = "mode"
kind = "choice"
choices = ["fast", "slow"]
[[operations.params]]
name = "loud"
kind = "flag"
[[operations.params]]
name = "lang"
kind = "locale"
[operations.uses]
imports = ["keys_sign_cms_ex", {KEY_IMPORTS}]
network = "pki"
[[operations.uses.key]]
kind = "cms_ex"
content = "param:file"
[operations.uses.key.profile]
cosign = "never"
"#,
        header("test.cms", "0.9.0")
    ))
    .unwrap()
}

fn plain_manifest() -> Manifest {
    Manifest::from_toml(&header("test.plain", "1.0.0")).unwrap()
}

/// What the manual window's registry holds, and what its list says: built like the daemon builds
/// them, from the manifests and modules of the synthetic plugins.
fn registry_and_listing(origin: &str) -> (PluginRegistry, ManualListing) {
    let mut registry = PluginRegistry::new();
    let mut listing = ManualListing::default();
    // What the registry grants a `pki` operation: the world's revocation responder (the signer
    // is validated online before its key is used, by a GET under the responder's address: with
    // that method missing the request is denied and the whole call with it) and its time service.
    let pki = [
        (HttpMethod::Get, format!("{origin}/ocsp")),
        (HttpMethod::Post, format!("{origin}/ocsp")),
        (HttpMethod::Post, format!("{origin}/tsa")),
    ];
    for (manifest, module, hash) in [
        (
            raw_manifest(),
            wasm(&[raw_call(DOC)], &extra_imports(&raw_manifest())),
            [3u8; 32],
        ),
        (
            cms_manifest(),
            wasm(&[cms_call(DOC)], &extra_imports(&cms_manifest())),
            [4u8; 32],
        ),
    ] {
        registry
            .install(
                manifest.clone(),
                PackageHash::File(hash),
                &module,
                InstanceLimits {
                    max_memory: 1 << 20,
                    max_transfer: 1 << 16,
                    ..InstanceLimits::default()
                },
                Vec::new(),
            )
            .unwrap();
        for op in manifest.manual_operations() {
            let pki_endpoints: Vec<(HttpMethod, String)> =
                if matches!(op.uses().network(), oncl_plugin::operations::Network::Pki) {
                    pki.to_vec()
                } else {
                    Vec::new()
                };
            registry
                .allow_declared_with_pki(
                    &manifest.id,
                    op.name(),
                    manual(),
                    pki_endpoints.iter().map(|(m, u)| (*m, u.as_str())),
                    &["127.0.0.1"],
                )
                .unwrap();
            listing.operations.push(OfferedOperation {
                plugin_id: manifest.id.clone(),
                plugin_version: manifest.version.to_string(),
                plugin_name: manifest.name.clone(),
                operation: op.name().to_owned(),
                label: op.label().clone(),
                params: op.params().to_vec(),
                uses_key: !op.uses().keys().is_empty(),
                pki_endpoints,
            });
        }
    }
    let plain = plain_manifest();
    listing.without_operations.push(WithoutOperations {
        plugin_id: plain.id.clone(),
        plugin_version: plain.version.to_string(),
        plugin_name: plain.name.clone(),
    });
    listing.unusable.push(UnusablePlugin {
        plugin_id: "test.broken".to_owned(),
    });
    (registry, listing)
}

fn extra_imports(manifest: &Manifest) -> Vec<Import> {
    let mut all: Vec<Import> = Vec::new();
    for import in manifest
        .operations()
        .iter()
        .flat_map(|o| o.uses().imports().iter().copied())
    {
        if !all.contains(&import) {
            all.push(import);
        }
    }
    all
}

/// The page's plugin source: the synthetic plugins, an engine over the world's authority.
struct TestPlugins {
    kit: PluginEngineKit,
    origin: String,
}

impl ManualPluginSource for TestPlugins {
    fn offer(&self) -> Result<PluginOffer, OfferError> {
        let (registry, listing) = registry_and_listing(&self.origin);
        plugin_offer(registry, manual(), listing, &self.kit)
    }
}

pub(super) struct Rig {
    pub(super) w: World,
    pub(super) ws: Rc<Workspace>,
    /// Where the user's files are.
    pub(super) files: tempfile::TempDir,
}

use std::rc::Rc;

pub(super) fn kit(w: &World) -> PluginEngineKit {
    PluginEngineKit {
        http: w.http.clone(),
        extra: ExtraTrust {
            anchors: vec![w.root.clone()],
            origins: vec![w.origin.clone()],
        },
        clock: Arc::new(now),
        activity: None,
        spool: w.dir.path().join("spool-plugins"),
    }
}

pub(super) fn rig() -> Rig {
    let w = world();
    std::fs::create_dir_all(w.dir.path().join("spool-plugins")).unwrap();
    let (engine, guard) = engine(&w);
    let source = Arc::new(TestPlugins {
        kit: kit(&w),
        origin: w.origin.clone(),
    });
    let services = DesktopEngineServices {
        engine: Arc::new(engine),
        guard,
        tokens: Tokens::disabled(),
        clock: Arc::new(now),
        settings_path: w.dir.path().join("settings.json"),
        plugins: source,
    };
    let ws = test_workspace(services);
    {
        let mut st = ws.plugins.borrow_mut();
        st.arm_after = Duration::from_millis(40);
    }
    ws.ui.set_section(super::SECTION);
    ws.ui.invoke_section_changed(super::SECTION);
    let rig = Rig {
        w,
        ws,
        files: tempfile::tempdir().unwrap(),
    };
    until("the plugins are read", || {
        rig.ws.plugins.borrow().offer.is_some() && !rig.ws.ui.get_busy()
    });
    rig
}

pub(super) fn until(what: &str, mut ready: impl FnMut() -> bool) {
    let start = Instant::now();
    loop {
        pump();
        if ready() {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "timed out: {what}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn press(ws: &Rc<Workspace>, key: Key) {
    let text: slint::SharedString = key.into();
    ws.ui
        .window()
        .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
    ws.ui
        .window()
        .dispatch_event(WindowEvent::KeyReleased { text });
}

impl Rig {
    pub(super) fn ui(&self) -> PluginsState<'_> {
        self.ws.ui.global::<PluginsState>()
    }
    pub(super) fn step(&self) -> Step {
        self.ws.plugins.borrow().controller.step()
    }
    /// A file of the user's.
    pub(super) fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.files.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
    pub(super) fn guard(&self) -> Arc<PluginConsentGuard> {
        self.ws
            .plugins
            .borrow()
            .offer
            .as_ref()
            .expect("the plugins were read")
            .guard
            .clone()
    }
    pub(super) fn applications(&self) -> usize {
        self.guard().applications()
    }
    pub(super) fn arm(&self) {
        std::thread::sleep(Duration::from_millis(80));
        super::tick(&self.ws);
    }

    /// The list's group and row of an operation.
    fn position(&self, plugin: &str, operation: &str) -> (i32, i32) {
        let st = self.ws.plugins.borrow();
        let offer = st.offer.as_ref().unwrap();
        let groups = super::groups(&offer.listing);
        for (g, group) in groups.iter().enumerate() {
            if group.id != plugin {
                continue;
            }
            for (o, &i) in group.operations.iter().enumerate() {
                if offer.listing.operations[i].operation == operation {
                    return (g as i32, o as i32);
                }
            }
        }
        panic!("{plugin} {operation} is not listed");
    }

    /// Opens an operation from the list, by the page's own callback.
    pub(super) fn open(&self, plugin: &str, operation: &str) {
        let (g, o) = self.position(plugin, operation);
        self.ui().invoke_open_operation(g, o);
    }

    /// Fills the form of `sign-raw` with `file`, and the key store, and continues.
    pub(super) fn to_key_raw(&self, file: &Path) {
        self.open("test.raw", "sign-raw");
        assert_eq!(self.step(), Step::Form);
        self.ui()
            .invoke_field_text(0, file.display().to_string().into());
        self.ui()
            .set_store_path(self.w.store.display().to_string().into());
        self.ui().invoke_form_continue();
        assert_eq!(self.step(), Step::Key, "{}", self.ui().get_error());
    }

    /// The key store opened; its certificates listed.
    pub(super) fn unlocked(&self) {
        self.ui().set_password(PASSWORD.into());
        self.ui().invoke_unlock();
        until("the certificates are listed", || {
            !self.ws.ui.get_busy() && !self.ws.plugins.borrow().controller.candidates().is_empty()
        });
    }

    /// The page driven to the confirmation of `sign-raw` for `file`.
    pub(super) fn to_consent_raw(&self, file: &Path) {
        self.to_key_raw(file);
        self.unlocked();
        self.ui().invoke_cert_chosen(0);
        until("the confirmation is shown", || {
            self.ws.plugins.borrow().shown.is_some()
        });
        assert_eq!(self.step(), Step::Consent);
    }
}

fn locale_rig(rig: &Rig, l: Locale) {
    rig.ws.locale.set(l);
    super::render(&rig.ws);
}

fn model_strings(model: slint::ModelRc<slint::SharedString>) -> Vec<String> {
    model.iter().map(|s| s.to_string()).collect()
}

// ---- the list ----

#[test]
fn the_list_groups_operations_by_plugin_and_keeps_the_plugins_words_in_their_frames() {
    let rig = rig();
    for l in [Locale::Ru, Locale::Kk, Locale::En] {
        locale_rig(&rig, l);
        let t = Texts::of(l);
        let ui = rig.ui();
        assert_eq!(ui.get_step(), 0);
        let groups: Vec<_> = ui.get_groups().iter().collect();
        assert_eq!(groups.len(), 2, "two plugins offer operations");
        assert_eq!(
            groups[0].heading,
            t.plugin_heading
                .replace("{0}", "test.raw")
                .replace("{1}", "1.2.3")
        );
        // The plugin's own name is in the frame, and not in the host's heading.
        assert!(groups[0].name.contains("EVIL-NAME"));
        assert!(!groups[0].heading.contains("EVIL"));
        let ops: Vec<_> = groups[0].operations.iter().collect();
        assert_eq!(ops.len(), 2);
        assert_eq!(
            ops[0].heading,
            t.operation_heading.replace("{0}", "sign-raw")
        );
        assert!(!ops[0].heading.contains("EVIL"));
        assert!(ops[0].label.contains("EVIL-LABEL"));
        assert!(ops[0].can_open);
        assert_eq!(ops[0].key_line, t.key_use_yes);
        // An operation that does not use the key is listed and cannot be opened: what is
        // approved here is the use of the key.
        assert_eq!(ops[1].key_line, t.key_use_no);
        assert!(!ops[1].can_open);
        // The installed plugins with nothing for this window are told honestly, one line each.
        let hidden: Vec<_> = ui.get_hidden().iter().collect();
        assert_eq!(hidden.len(), 2);
        assert_eq!(
            hidden[0].line,
            t.without_ops
                .replace("{0}", "test.plain")
                .replace("{1}", "1.0.0")
        );
        assert!(
            hidden[0].name.contains("EVIL-NAME"),
            "the name is in its frame"
        );
        assert_eq!(hidden[1].line, t.unusable.replace("{0}", "test.broken"));
        assert_eq!(ui.get_hidden_why(), t.without_ops_why);
        assert_eq!(ui.get_list_note(), "");
    }
}

#[test]
fn a_program_without_plugins_says_so() {
    let w = world();
    let (engine, guard) = engine(&w);
    let services = DesktopEngineServices {
        engine: Arc::new(engine),
        guard,
        tokens: Tokens::disabled(),
        clock: Arc::new(now),
        settings_path: w.dir.path().join("settings.json"),
        plugins: Arc::new(super::NoManualPlugins),
    };
    let ws = test_workspace(services);
    ws.ui.set_section(super::SECTION);
    ws.ui.invoke_section_changed(super::SECTION);
    until("the answer", || {
        !ws.ui.get_busy() && ws.plugins.borrow().reading == super::Plugins::Unavailable
    });
    assert_eq!(
        ws.ui.global::<PluginsState>().get_list_note(),
        Texts::of(Locale::En).no_source
    );
    assert_eq!(ws.ui.global::<PluginsState>().get_groups().row_count(), 0);
}

// ---- the form ----

#[test]
fn the_form_is_built_from_the_declared_parameters() {
    let rig = rig();
    for l in [Locale::Ru, Locale::Kk, Locale::En] {
        locale_rig(&rig, l);
        let t = Texts::of(l);
        rig.open("test.cms", "sign-cms");
        assert_eq!(rig.step(), Step::Form);
        let fields: Vec<_> = rig.ui().get_fields().iter().collect();
        assert_eq!(fields.len(), 5);
        // The document: its limit is the declared one.
        assert_eq!(fields[0].kind, 0);
        assert_eq!(
            fields[0].label,
            t.doc_label.replace("{0}", "file").replace(
                "{1}",
                &crate::workspace::size(crate::workspace::Texts::of(l), 8192)
            )
        );
        assert_eq!(fields[1].kind, 1);
        assert_eq!(
            fields[1].label,
            t.text_label.replace("{0}", "note").replace("{1}", "8")
        );
        // A choice starts with no choice made, and offers exactly the declared ones.
        assert_eq!(fields[2].kind, 2);
        assert_eq!(
            model_strings(fields[2].choices.clone()),
            [t.choose_one, "fast", "slow"]
        );
        assert_eq!(fields[2].index, 0);
        assert_eq!(fields[3].kind, 3);
        assert!(!fields[3].flag);
        assert_eq!(fields[4].kind, 4);
        assert_eq!(fields[4].choices.row_count(), 3);
        // The plugin's label is in its frame under the caption.
        assert_eq!(
            rig.ui().get_label_caption(),
            crate::install_plugin::frame_caption(l)
        );
        assert!(rig.ui().get_label().contains("EVIL-LABEL"));
        assert!(!rig.ui().get_form_intro().contains("EVIL"));
        rig.ui().invoke_cancel();
        assert_eq!(rig.step(), Step::List);
    }
}

#[test]
fn a_form_with_a_missing_oversize_or_empty_file_is_refused_before_a_password_is_asked() {
    let rig = rig();
    let t = Texts::of(Locale::En);
    let store = rig.w.store.display().to_string();
    rig.open("test.raw", "sign-raw");
    rig.ui().set_store_path(store.as_str().into());
    // No file at all.
    rig.ui().invoke_form_continue();
    assert_eq!(rig.step(), Step::Form);
    assert_eq!(rig.ui().get_error(), t.e_no_path.replace("{0}", "file"));
    // A file that is not there.
    rig.ui().invoke_field_text(
        0,
        rig.files
            .path()
            .join("none.txt")
            .display()
            .to_string()
            .into(),
    );
    rig.ui().invoke_form_continue();
    assert_eq!(rig.ui().get_error(), t.e_unreadable.replace("{0}", "file"));
    // One byte over the declared 8192.
    let big = rig.file("big.bin", &vec![1; 8193]);
    rig.ui()
        .invoke_field_text(0, big.display().to_string().into());
    rig.ui().invoke_form_continue();
    assert!(
        rig.ui().get_error().contains("8.0 KiB"),
        "{}",
        rig.ui().get_error()
    );
    let empty = rig.file("empty.bin", b"");
    rig.ui()
        .invoke_field_text(0, empty.display().to_string().into());
    rig.ui().invoke_form_continue();
    assert_eq!(rig.ui().get_error(), t.e_empty.replace("{0}", "file"));
    // No key store.
    let ok = rig.file("ok.bin", DOC);
    rig.ui()
        .invoke_field_text(0, ok.display().to_string().into());
    rig.ui().set_store_path("".into());
    rig.ui().invoke_form_continue();
    assert_eq!(rig.ui().get_error(), t.e_no_store);
    assert_eq!(rig.step(), Step::Form);
    // Nothing was asked of the key, and nothing was used.
    assert_eq!(rig.applications(), 0);
}

#[test]
fn the_typed_values_of_the_other_parameters_are_checked() {
    let rig = rig();
    let t = Texts::of(Locale::En);
    let doc = rig.file("doc.bin", DOC);
    rig.open("test.cms", "sign-cms");
    rig.ui()
        .invoke_field_text(0, doc.display().to_string().into());
    rig.ui()
        .set_store_path(rig.w.store.display().to_string().into());
    // The text is longer than 8 characters.
    rig.ui().invoke_field_text(1, "123456789".into());
    rig.ui().invoke_form_continue();
    assert_eq!(
        rig.ui().get_error(),
        t.e_text_long.replace("{0}", "note").replace("{1}", "8")
    );
    rig.ui().invoke_field_text(1, "12345678".into());
    // No choice made.
    rig.ui().invoke_form_continue();
    assert!(
        rig.ui().get_error().contains("mode"),
        "{}",
        rig.ui().get_error()
    );
    rig.ui().invoke_field_choice(2, 2);
    rig.ui().invoke_field_flag(3, true);
    rig.ui().invoke_field_choice(4, 2);
    rig.ui().invoke_form_continue();
    assert_eq!(rig.step(), Step::Key, "{}", rig.ui().get_error());
}

// ---- the confirmation ----

#[test]
fn the_confirmation_shows_what_core_prepared_and_the_key_is_not_used() {
    let rig = rig();
    let doc = rig.file("акт.bin", DOC);
    rig.to_consent_raw(&doc);
    let ui = rig.ui();
    // The page is the confirmation; the worker waits and the page is not busy.
    assert_eq!(ui.get_step(), 3);
    assert!(rig.ws.ui.get_busy(), "the worker waits for the user");
    assert!(!ui.get_busy(), "but the page waits for Confirm");
    let trusted = model_strings(ui.get_c_trusted()).join("\n");
    assert!(trusted.contains("sign-raw"), "{trusted}");
    assert!(trusted.contains("test.raw"), "{trusted}");
    assert!(trusted.contains("1.2.3"), "{trusted}");
    assert_eq!(ui.get_c_package_sha().len(), 64);
    let file = model_strings(ui.get_c_file_lines()).join("\n");
    assert!(file.contains("акт.bin"), "{file}");
    assert!(file.contains(&DOC.len().to_string()), "{file}");
    use sha2::{Digest, Sha256};
    let expected: String = Sha256::digest(DOC)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(ui.get_c_file_sha(), expected.as_str());
    let key = model_strings(ui.get_c_key_lines()).join("\n");
    assert!(key.contains(&rig.w.leaf.alias), "{key}");
    assert_eq!(ui.get_c_fingerprint().len(), 64);
    // The plugin's words are in their frame only.
    assert!(ui.get_c_frame_name().contains("EVIL-NAME"));
    assert!(ui.get_c_frame_label().contains("EVIL-LABEL"));
    for text in [
        trusted,
        file,
        key,
        ui.get_c_lead().to_string(),
        ui.get_c_title().to_string(),
    ] {
        for evil in EVIL {
            assert!(!text.contains(evil), "{evil} in the host's text: {text}");
        }
    }
    // The button names the action and is not enabled before the quiet moment.
    assert_eq!(
        ui.get_confirm_label(),
        Texts::of(Locale::En)
            .confirm_label
            .replace("{0}", "sign-raw")
    );
    assert!(!ui.get_confirm_enabled());
    ui.invoke_confirm();
    assert_eq!(
        rig.step(),
        Step::Consent,
        "a press before arming does nothing"
    );
    assert_eq!(
        rig.applications(),
        0,
        "the key is not used before the confirmation"
    );
}

/// The window shown and active, as a user's window is: keys reach the focused control.
fn show(rig: &Rig) {
    rig.ws.ui.show().unwrap();
    rig.ws
        .ui
        .window()
        .dispatch_event(WindowEvent::WindowActiveChanged(true));
    rig.ws
        .ui
        .window()
        .set_size(slint::PhysicalSize::new(900, 580));
}

#[test]
fn enter_alone_does_not_confirm_the_default_is_cancel() {
    let rig = rig();
    show(&rig);
    let doc = rig.file("doc.bin", DOC);
    rig.to_consent_raw(&doc);
    rig.arm();
    assert!(
        rig.ui().get_confirm_enabled(),
        "armed: the button could be pressed"
    );
    // Enter alone, with nothing else done: the focus is on the default, «Cancel». The key is
    // never used and nothing is confirmed; the page is left.
    press(&rig.ws, Key::Return);
    assert_eq!(
        rig.step(),
        Step::List,
        "Enter alone on the confirmation cancels it"
    );
    until("the worker ends", || !rig.ws.ui.get_busy());
    assert_eq!(rig.applications(), 0);
    assert!(rig.ws.plugins.borrow().shown.is_none());
}

#[test]
fn escape_before_the_first_tab_cancels_the_confirmation_page() {
    let rig = rig();
    show(&rig);
    let doc = rig.file("doc.bin", DOC);
    rig.to_consent_raw(&doc);
    // Not armed yet, not a Tab pressed: Escape is the page's own way out.
    press(&rig.ws, Key::Escape);
    assert_eq!(rig.step(), Step::List);
    until("the worker ends", || !rig.ws.ui.get_busy());
    assert_eq!(rig.applications(), 0);
    assert!(rig.ws.plugins.borrow().shown.is_none());
    assert_eq!(rig.ui().get_c_file_sha(), "");
}

#[test]
fn escape_cancels_the_form_and_the_key_page_too() {
    let rig = rig();
    show(&rig);
    let doc = rig.file("doc.bin", DOC);
    rig.open("test.raw", "sign-raw");
    press(&rig.ws, Key::Escape);
    assert_eq!(rig.step(), Step::List);
    rig.to_key_raw(&doc);
    rig.unlocked();
    press(&rig.ws, Key::Escape);
    assert_eq!(rig.step(), Step::List);
    assert!(!rig.ws.plugins.borrow().controller.holds_secret());
}

#[test]
fn confirming_through_the_named_button_applies_the_key_once_and_says_so() {
    let rig = rig();
    let doc = rig.file("doc.bin", DOC);
    rig.to_consent_raw(&doc);
    rig.arm();
    assert!(rig.ui().get_confirm_enabled(), "armed at the confirmation");
    rig.ui().invoke_confirm();
    assert_eq!(rig.step(), Step::Running);
    assert!(!rig.ui().get_confirm_enabled(), "not while running");
    until("the run ends", || rig.step() == Step::Result);
    assert_eq!(rig.applications(), 1);
    let t = Texts::of(Locale::En);
    let ui = rig.ui();
    assert_eq!(ui.get_report_headline(), t.r_ok);
    assert_eq!(
        ui.get_report_tone(),
        0,
        "a verified applied call is success"
    );
    let rows: Vec<String> = ui
        .get_report_rows()
        .iter()
        .map(|r| r.text.to_string())
        .collect();
    assert!(rows.contains(&t.row_key_applied.to_owned()), "{rows:?}");
    assert!(rows.contains(&t.row_not_verified.to_owned()));
    // The reply is the plugin's, in its frame, and the result says it is not saved.
    let reply = ui.get_reply().to_string();
    assert!(!reply.is_empty());
    assert_eq!(ui.get_result_note(), t.no_save);
    for row in &rows {
        assert!(!row.contains(&reply), "the reply is in the host's rows");
    }
    // Independent oracle: the signature in the reply verifies, with the key's own public key,
    // over the bytes the user approved and over nothing else.
    let bytes: Vec<u8> = (0..reply.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&reply[i..i + 2], 16).unwrap())
        .collect();
    let signature = abi::decode::<abi::HostResult<abi::Bytes>>(&bytes)
        .unwrap()
        .unwrap()
        .into_vec();
    let public = rig.w.leaf.key.public_key();
    public
        .verify(SigAlg::RsaSha256, DOC, &signature)
        .expect("the signature is over the approved bytes");
    assert!(public.verify(SigAlg::RsaSha256, OTHER, &signature).is_err());
    // Nothing of the confirmation or the password stays on the page.
    assert!(rig.ws.plugins.borrow().shown.is_none());
    assert!(!rig.ws.plugins.borrow().controller.holds_secret());
    assert_eq!(rig.ui().get_password(), "");
}

#[test]
fn a_plugin_that_signs_other_bytes_than_the_approved_file_is_refused_before_the_key() {
    let rig = rig();
    // The module signs DOC; the user's file is OTHER: what the plugin would sign is not what
    // the user approved.
    let other = rig.file("other.bin", OTHER);
    rig.to_consent_raw(&other);
    rig.arm();
    rig.ui().invoke_confirm();
    until("the run ends", || rig.step() == Step::Result);
    assert_eq!(rig.applications(), 0, "the key was never applied");
    let t = Texts::of(Locale::En);
    let ui = rig.ui();
    assert!(
        ui.get_report_headline().contains(t.f_content),
        "{}",
        ui.get_report_headline()
    );
    assert_ne!(ui.get_report_tone(), 0);
    let rows: Vec<String> = ui
        .get_report_rows()
        .iter()
        .map(|r| r.text.to_string())
        .collect();
    assert!(rows.contains(&t.row_key_not_applied.to_owned()), "{rows:?}");
    assert_ne!(ui.get_report_headline(), t.r_ok);
}

#[test]
fn an_expired_approval_is_told_and_the_key_is_not_used() {
    let rig = rig();
    rig.ws.plugins.borrow_mut().approval_ttl = Duration::from_millis(1);
    let doc = rig.file("doc.bin", DOC);
    rig.to_consent_raw(&doc);
    rig.arm();
    std::thread::sleep(Duration::from_millis(30));
    rig.ui().invoke_confirm();
    until("the run ends", || rig.step() == Step::Result);
    let t = Texts::of(Locale::En);
    assert!(
        rig.ui().get_report_headline().contains(t.f_expired),
        "{}",
        rig.ui().get_report_headline()
    );
    assert_eq!(rig.applications(), 0);
    assert_ne!(rig.ui().get_report_tone(), 0);
    // «Prepare again» goes back to the form and asks for everything that is secret again.
    rig.ui().invoke_again();
    assert_eq!(rig.step(), Step::Form);
    assert!(!rig.ws.plugins.borrow().controller.holds_secret());
}

#[test]
fn a_cancel_at_every_step_leaves_nothing_and_uses_no_key() {
    let rig = rig();
    let doc = rig.file("doc.bin", DOC);
    // The form.
    rig.open("test.raw", "sign-raw");
    rig.ui().invoke_cancel();
    assert_eq!(rig.step(), Step::List);
    // The key page, with a password held.
    rig.to_key_raw(&doc);
    rig.unlocked();
    assert!(rig.ws.plugins.borrow().controller.holds_secret());
    rig.ui().invoke_cancel();
    assert_eq!(rig.step(), Step::List);
    assert!(!rig.ws.plugins.borrow().controller.holds_secret());
    assert!(rig.ws.plugins.borrow().controller.candidates().is_empty());
    // The confirmation: the waiting worker lets go, nothing runs.
    rig.to_consent_raw(&doc);
    rig.ui().invoke_cancel();
    assert_eq!(rig.step(), Step::List);
    until("the worker ends", || !rig.ws.ui.get_busy());
    assert!(
        !rig.ui().get_busy(),
        "the page is not left disabled by the ended job"
    );
    assert_eq!(rig.applications(), 0);
    assert!(rig.ws.plugins.borrow().shown.is_none());
    assert_eq!(
        rig.ui().get_c_file_sha(),
        "",
        "the confirmation's text is released"
    );
    // The result goes back to the list.
    rig.to_consent_raw(&doc);
    rig.arm();
    rig.ui().invoke_confirm();
    until("the run ends", || rig.step() == Step::Result);
    rig.ui().invoke_finish();
    assert_eq!(rig.step(), Step::List);
    assert_eq!(rig.applications(), 1);
}

#[test]
fn leaving_the_page_cancels_a_password_and_a_confirmation_that_wait() {
    let rig = rig();
    let doc = rig.file("doc.bin", DOC);
    rig.to_consent_raw(&doc);
    rig.ws.ui.set_section(6);
    rig.ws.ui.invoke_section_changed(6);
    assert_eq!(rig.step(), Step::List);
    until("the worker ends", || !rig.ws.ui.get_busy());
    assert_eq!(rig.applications(), 0);
    assert!(!rig.ws.plugins.borrow().controller.holds_secret());
}

#[test]
fn a_confirmation_left_idle_is_closed_by_itself() {
    let rig = rig();
    rig.ws.plugins.borrow_mut().consent_idle = Duration::from_millis(120);
    let doc = rig.file("doc.bin", DOC);
    rig.to_consent_raw(&doc);
    rig.arm();
    std::thread::sleep(Duration::from_millis(150));
    super::tick(&rig.ws);
    assert_eq!(rig.step(), Step::List);
    assert_eq!(rig.ui().get_error(), Texts::of(Locale::En).consent_idle);
    until("the worker ends", || !rig.ws.ui.get_busy());
    assert_eq!(rig.applications(), 0);
}

#[test]
fn a_key_page_left_idle_forgets_the_password() {
    let rig = rig();
    rig.ws.plugins.borrow_mut().key_idle = Duration::from_millis(100);
    let doc = rig.file("doc.bin", DOC);
    rig.to_key_raw(&doc);
    rig.unlocked();
    std::thread::sleep(Duration::from_millis(130));
    super::tick(&rig.ws);
    assert_eq!(rig.step(), Step::List);
    assert!(!rig.ws.plugins.borrow().controller.holds_secret());
    assert_eq!(rig.ui().get_error(), Texts::of(Locale::En).key_idle);
}

#[test]
fn a_wrong_password_is_told_and_no_confirmation_is_prepared() {
    let rig = rig();
    let doc = rig.file("doc.bin", DOC);
    rig.to_key_raw(&doc);
    rig.ui().set_password("wrong".into());
    rig.ui().invoke_unlock();
    until("the answer", || !rig.ws.ui.get_busy());
    assert_eq!(rig.step(), Step::Key);
    assert_eq!(rig.ui().get_error(), Texts::of(Locale::En).wrong_password);
    assert_eq!(rig.ui().get_password(), "", "the field was emptied at once");
    assert!(!rig.ws.plugins.borrow().controller.holds_secret());
    assert!(rig.ws.plugins.borrow().shown.is_none());
}

#[test]
fn a_key_store_swapped_after_the_list_is_refused_before_a_confirmation() {
    let rig = rig();
    let doc = rig.file("doc.bin", DOC);
    rig.to_key_raw(&doc);
    rig.unlocked();
    // Another key store under the same alias and password replaces the file.
    let other = crate::signing::testing::world();
    std::fs::copy(&other.store, &rig.w.store).unwrap();
    rig.ui().invoke_cert_chosen(0);
    until("the answer", || !rig.ws.ui.get_busy());
    assert_eq!(rig.step(), Step::Key);
    assert_eq!(rig.ui().get_error(), Texts::of(Locale::En).p_cert_mismatch);
    assert!(rig.ws.plugins.borrow().shown.is_none());
    assert_eq!(rig.applications(), 0);
}

#[test]
fn every_language_renders_the_whole_flow() {
    for l in [Locale::Ru, Locale::Kk, Locale::En] {
        let rig = rig();
        locale_rig(&rig, l);
        let doc = rig.file("doc.bin", DOC);
        rig.to_consent_raw(&doc);
        let t = Texts::of(l);
        assert_eq!(rig.ui().get_title(), t.consent_title);
        assert_eq!(
            rig.ui().get_confirm_label(),
            t.confirm_label.replace("{0}", "sign-raw")
        );
        assert!(model_strings(rig.ui().get_c_trusted())[0].contains("sign-raw"));
        rig.arm();
        rig.ui().invoke_confirm();
        until("the run ends", || rig.step() == Step::Result);
        assert_eq!(rig.ui().get_report_headline(), t.r_ok);
    }
}

// ---- the worker's side, without the page ----

#[test]
fn the_run_declines_without_a_decision_and_never_uses_the_key() {
    let rig = rig();
    let doc = rig.file("doc.bin", DOC);
    let offer = {
        let source = TestPlugins {
            kit: kit(&rig.w),
            origin: rig.w.origin.clone(),
        };
        Arc::new(source.offer().unwrap())
    };
    let operation = offer
        .listing
        .operations
        .iter()
        .find(|o| o.operation == "sign-raw")
        .unwrap()
        .clone();
    let fields = super::form::fields_of(&operation.params);
    let mut values = super::form::initial(&fields, Locale::En);
    values[0] = super::form::FieldValue::Text(doc.display().to_string());
    let typed = super::form::read(&fields, &values).unwrap();
    let cert = {
        let candidates =
            crate::signing::runner::open_key_store(&rig.w.store, PASSWORD, now()).unwrap();
        candidates[0].clone()
    };
    let spec = RunSpec {
        offer: Arc::clone(&offer),
        operation,
        fields,
        typed,
        store: rig.w.store.clone(),
        alias: cert.alias,
        certificate: cert.sha256.unwrap(),
        password: zeroize::Zeroizing::new(PASSWORD.to_owned()),
        ttl: Duration::from_secs(120),
        idle: Duration::from_secs(60),
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let control = Arc::new(crate::workspace::JobControl::default());
    let mut prepared = 0;
    // The decision channel closes: the user is gone.
    drop(tx);
    let outcome = run(spec, &control, &rx, |_| prepared += 1);
    assert!(matches!(outcome, RunOutcome::Declined), "{outcome:?}");
    assert_eq!(prepared, 1, "the confirmation was prepared and offered");
    assert_eq!(offer.guard.applications(), 0);
    let _ = Decision::Abort;
}

// ---- keeping the one confirmation in one place, and every control named ----

/// All Rust sources of the workspace outside `skip`, with their paths relative to the root.
fn sources(root: &StdPath, dir: &StdPath, skip: &[&str], out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if skip.iter().any(|s| rel.starts_with(s)) || rel.contains("/target") {
            continue;
        }
        if path.is_dir() {
            sources(root, &path, skip, out);
        } else if rel.ends_with(".rs") {
            out.push((
                rel,
                std::fs::read_to_string(&path)
                    .unwrap_or_default()
                    .replace("\r\n", "\n"),
            ));
        }
    }
}

/// The code of a source file: comment lines gone, and an inline test module (`#[cfg(test)] mod x {`)
/// with everything after it (the test modules of the workspace are at the end of their files).
fn code_of(text: &str) -> String {
    let mut cut = text.len();
    for (at, _) in text.match_indices("#[cfg(test)]") {
        let rest = text[at + "#[cfg(test)]".len()..].trim_start();
        if rest
            .lines()
            .next()
            .is_some_and(|l| l.starts_with("mod ") && l.trim_end().ends_with('{'))
        {
            cut = at;
            break;
        }
    }
    text[..cut]
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `UserConfirmation::after_user_confirmed` is the host's duty: the one who calls it says the
/// user confirmed. It is called in ONE place of the whole workspace (outside Core, which
/// defines it): `consent::user_confirmed`; and that function is called from ONE place: the
/// handler of the confirm button. A second call site, anywhere, fails this test.
#[test]
fn the_users_confirmation_is_made_in_one_place_only() {
    let root = oncl_testkit::workspace_root();
    let mut all = Vec::new();
    for dir in ["crates", "xtask"] {
        let dir = root.join(dir);
        if dir.exists() {
            sources(&root, &dir, &["crates/oncl-core/"], &mut all);
        }
    }
    assert!(all.len() > 100, "the scan found {} sources", all.len());
    let needle = concat!("after_user", "_confirmed(");
    let calls: Vec<(&str, usize)> = all
        .iter()
        .filter(|(rel, _)| !rel.ends_with("/tests.rs"))
        .map(|(rel, text)| (rel.as_str(), code_of(text).matches(needle).count()))
        .filter(|(_, n)| *n > 0)
        .collect();
    assert_eq!(
        calls,
        [("crates/oncl-ui/src/workspace/plugins/consent.rs", 1)],
        "the user's confirmation is made in exactly one place"
    );
    // The wrapper: defined there, called from the button's handler and nowhere else.
    let wrapper = concat!("consent::user_confirmed", "(");
    let users: Vec<(&str, usize)> = all
        .iter()
        .filter(|(rel, _)| !rel.ends_with("/tests.rs"))
        .map(|(rel, text)| (rel.as_str(), code_of(text).matches(wrapper).count()))
        .filter(|(_, n)| *n > 0)
        .collect();
    assert_eq!(
        users,
        [("crates/oncl-ui/src/workspace/plugins/mod.rs", 1)],
        "the wrapper is called from the confirm handler only"
    );
    // And that one call is inside `fn confirm`, after the controller let the press through.
    let (_, page) = all
        .iter()
        .find(|(rel, _)| rel == "crates/oncl-ui/src/workspace/plugins/mod.rs")
        .unwrap();
    let handler = page.split("fn confirm(open").nth(1).unwrap();
    let handler = &handler[..handler.find("\n}\n").unwrap()];
    assert!(handler.contains(wrapper));
    assert!(
        handler.find("Event::Confirm").unwrap() < handler.find(wrapper).unwrap(),
        "the confirmation is made after the controller's decision"
    );
}

/// Every control of the page says what it is to a screen reader, and no focus scope is a silent
/// stop of the Tab ring. The compiled components do not list their controls, so this reads the
/// source.
#[test]
fn every_control_of_the_page_is_named_and_no_focus_scope_is_a_silent_tab_stop() {
    let path = StdPath::new(env!("CARGO_MANIFEST_DIR")).join("ui/manual_plugins.slint");
    let text = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
    let block = |at: usize| {
        let mut depth = 0;
        for (i, c) in text[at..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &text[at..at + i];
                    }
                }
                _ => {}
            }
        }
        &text[at..]
    };
    let mut seen = 0;
    for kind in [
        "Button {",
        "CheckBox {",
        "ComboBox {",
        "LineEdit {",
        "TextEdit {",
        "StandardListView {",
    ] {
        for (at, _) in text.match_indices(kind) {
            seen += 1;
            assert!(
                block(at).contains("accessible-label"),
                "a {kind} without accessible-label near byte {at}"
            );
        }
    }
    assert!(seen >= 20, "the scan found {seen} controls");
    for (at, _) in text.match_indices("FocusScope {") {
        assert!(
            block(at).contains("focus-on-tab-navigation: false"),
            "a FocusScope that is a silent Tab stop near byte {at}"
        );
    }
    // The plugin's words are drawn only in a PluginFrame (or the reply's own frame).
    assert!(text.contains("PluginFrame"));
}

// ---- running, cancelling and closing ----

#[test]
fn a_window_is_not_closed_under_a_running_plugin() {
    let rig = rig();
    let doc = rig.file("doc.bin", DOC);
    rig.to_consent_raw(&doc);
    rig.arm();
    assert!(!crate::workspace::closing_is_blocked_for(&rig.ws));
    rig.ui().invoke_confirm();
    // The key may be applied: the window stays (until the run ends).
    assert_eq!(rig.step(), Step::Running);
    assert!(crate::workspace::closing_is_blocked_for(&rig.ws));
    until("the run ends", || rig.step() == Step::Result);
    assert!(!crate::workspace::closing_is_blocked_for(&rig.ws));
}

#[test]
fn a_cancel_of_a_running_plugin_has_an_exit_even_if_the_worker_is_silent() {
    let rig = rig();
    // A worker that never answers: the page is put at Running by hand.
    {
        use super::controller::Event;
        let mut st = rig.ws.plugins.borrow_mut();
        st.cancel_after = Duration::from_millis(60);
        st.controller.dispatch(Event::Select(0));
        st.controller.dispatch(Event::KeyStore("a".into()));
        st.controller
            .dispatch(Event::PasswordSubmitted(zeroize::Zeroizing::new(
                "p".into(),
            )));
        st.controller.dispatch(Event::Unlocked(vec![
            crate::signing::controller::Candidate {
                alias: "k".into(),
                sha256: Some([1; 32]),
                subject: "s".into(),
                unsuitable: None,
            },
        ]));
        st.controller.dispatch(Event::CertificateChosen(0));
        st.controller.dispatch(Event::Prepared);
        st.controller.dispatch(Event::Arm);
        st.controller.dispatch(Event::Confirm);
    }
    assert_eq!(rig.step(), Step::Running);
    rig.ws.ui.set_section(super::SECTION);
    super::cancel(&rig.ws);
    assert_eq!(
        rig.step(),
        Step::Running,
        "stays until the worker says how far it got"
    );
    std::thread::sleep(Duration::from_millis(100));
    slint::platform::update_timers_and_animations();
    assert_eq!(rig.step(), Step::Result, "the wait ended with a notice");
    let t = Texts::of(Locale::En);
    assert_eq!(rig.ui().get_report_headline(), t.r_cancel_slow);
    assert_ne!(rig.ui().get_report_tone(), 0);
    assert!(!crate::workspace::closing_is_blocked_for(&rig.ws));
}

#[test]
fn a_cms_operation_with_every_kind_of_parameter_signs_the_approved_file() {
    let rig = rig();
    let doc = rig.file("doc.bin", DOC);
    rig.open("test.cms", "sign-cms");
    rig.ui()
        .invoke_field_text(0, doc.display().to_string().into());
    rig.ui().invoke_field_text(1, "note-1".into());
    rig.ui().invoke_field_choice(2, 2);
    rig.ui().invoke_field_flag(3, true);
    rig.ui().invoke_field_choice(4, 1);
    rig.ui()
        .set_store_path(rig.w.store.display().to_string().into());
    rig.ui().invoke_form_continue();
    assert_eq!(rig.step(), Step::Key, "{}", rig.ui().get_error());
    rig.unlocked();
    rig.ui().invoke_cert_chosen(0);
    until("the confirmation is shown", || {
        rig.ws.plugins.borrow().shown.is_some()
    });
    let ui = rig.ui();
    // The kind of key use and the profile are said in words (the declared operation's lines).
    let trusted = model_strings(ui.get_c_trusted()).join("\n");
    assert!(trusted.contains("CMS"), "{trusted}");
    assert!(
        trusted.contains(&rig.w.origin.replace("http://", "")),
        "{trusted}"
    );
    // What the user entered is listed as entered, each value as it will be given.
    let inputs = model_strings(ui.get_c_inputs());
    assert_eq!(
        inputs,
        ["note = note-1", "mode = slow", "loud = yes", "lang = kk"]
    );
    rig.arm();
    rig.ui().invoke_confirm();
    until("the run ends", || rig.step() == Step::Result);
    assert_eq!(rig.applications(), 1);
    assert_eq!(rig.ui().get_report_headline(), Texts::of(Locale::En).r_ok);
    // The reply is long (a CMS): the page shows its first characters and counts the rest.
    assert_eq!(
        rig.ui().get_reply().chars().count(),
        super::report::MAX_REPLY_CHARS
    );
    assert!(!rig.ui().get_reply_cut().is_empty());

    // Independent oracle, from the same operation run without the page: the whole reply is a
    // CMS that verifies over the approved file and over nothing else.
    let report = direct_run(
        &rig,
        "test.cms",
        "sign-cms",
        &[
            super::form::FieldValue::Text(doc.display().to_string()),
            super::form::FieldValue::Text("note-1".into()),
            super::form::FieldValue::Index(Some(1)),
            super::form::FieldValue::Flag(true),
            super::form::FieldValue::Index(Some(1)),
        ],
    );
    assert_eq!(
        report.applied,
        oncl_pki::key::AppliedState::Applied,
        "{report:?}"
    );
    let reply = report.response.expect("a reply");
    let bytes: Vec<u8> = (0..reply.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&reply[i..i + 2], 16).unwrap())
        .collect();
    let abi::CmsOutcome::Signed(cms) = abi::decode::<abi::HostResult<abi::CmsOutcome>>(&bytes)
        .unwrap()
        .unwrap()
    else {
        panic!("the reply is not a CMS")
    };
    let signers = oncl_pki::cms::verify(&cms, Some(DOC)).unwrap();
    assert_eq!(signers.len(), 1);
    assert!(oncl_pki::cms::verify(&cms, Some(OTHER)).is_err());
}

/// Runs one operation on the worker's own function, with the user's confirmation made as the
/// page makes it, and returns what Core reported of the call.
fn direct_run(
    rig: &Rig,
    plugin: &str,
    operation: &str,
    values: &[super::form::FieldValue],
) -> CallReport {
    let source = TestPlugins {
        kit: kit(&rig.w),
        origin: rig.w.origin.clone(),
    };
    let offer = Arc::new(source.offer().unwrap());
    let operation = offer
        .listing
        .operations
        .iter()
        .find(|o| o.plugin_id == plugin && o.operation == operation)
        .unwrap()
        .clone();
    let fields = super::form::fields_of(&operation.params);
    let typed = super::form::read(&fields, values).unwrap();
    let cert =
        crate::signing::runner::open_key_store(&rig.w.store, PASSWORD, now()).unwrap()[0].clone();
    let spec = RunSpec {
        offer: Arc::clone(&offer),
        operation,
        fields,
        typed,
        store: rig.w.store.clone(),
        alias: cert.alias,
        certificate: cert.sha256.unwrap(),
        password: zeroize::Zeroizing::new(PASSWORD.to_owned()),
        ttl: Duration::from_secs(120),
        idle: Duration::from_secs(60),
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let control = Arc::new(crate::workspace::JobControl::default());
    match run(spec, &control, &rx, |prepared| {
        let confirmation = super::consent::user_confirmed(&prepared.summary);
        tx.send(Decision::Proceed(confirmation)).unwrap();
    }) {
        RunOutcome::Done(report) => report,
        other => panic!("{other:?}"),
    }
}

#[test]
fn closing_the_window_at_the_confirmation_lets_the_waiting_worker_go_and_uses_no_key() {
    let rig = rig();
    let doc = rig.file("doc.bin", DOC);
    rig.to_consent_raw(&doc);
    rig.arm();
    super::abandon(&rig.ws);
    rig.ws.controller.borrow_mut().close();
    // The worker saw the abort (or the cancelled operation) and ended: no plugin ran.
    let guard = rig.guard();
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(500) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(guard.applications(), 0);
    assert!(rig.ws.plugins.borrow().shown.is_none());
}

#[test]
fn the_runs_deadline_is_the_sdks_default_operation_timeout() {
    assert_eq!(
        super::offer::RUN_LIMIT,
        oncl_pki::resource::ResourceLimits::default().operation_timeout
    );
}
