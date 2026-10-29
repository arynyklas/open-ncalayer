//! The plugin service with a fake network serving a catalog signed by a key made for the
//! test and the example plugin's packages, a fake confirmation, and a sandbox data
//! directory.

use super::*;
use crate::update::tests::FakeTransport;
use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_basics::{Locale, OcspCache};
use oncl_pki::tsp::TsaProfile;
use oncl_plugin::{Engine, HostServices};
use oncl_protocol::DynamicModules;
use oncl_update::{PluginReplaces, Sha256};
use serde_json::json;
use std::io::Cursor;

const BASE: &str = "https://example.org/updates/v1";
const INDEX: &str = "https://example.org/updates/v1/stable.json";
const ID: &str = "io.github.arynyklas.openncalayer.example";
const MODULE: &str = "io.github.arynyklas.openncalayer.Example";
const ORIGIN: &str = "https://shop.kz";

fn v(s: &str) -> Version {
    Version::parse(s).unwrap()
}

fn core() -> Version {
    v(env!("CARGO_PKG_VERSION"))
}

/// The example's package at `version` (its manifest changed by `edit` too).
fn example_at(version: &str, edit: impl FnOnce(String) -> String) -> Vec<u8> {
    use std::io::Write;
    let manifest = edit(oncl_testkit::plugin::example_manifest().replacen(
        "version = \"0.1.0\"",
        &format!("version = \"{version}\""),
        1,
    ));
    let options = zip::write::SimpleFileOptions::default();
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("plugin.toml", options).unwrap();
    zip.write_all(manifest.as_bytes()).unwrap();
    zip.start_file("plugin.wasm", options).unwrap();
    zip.write_all(&oncl_testkit::read(oncl_testkit::plugin::example_wasm()))
        .unwrap();
    zip.finish().unwrap().into_inner()
}

fn example(version: &str) -> Vec<u8> {
    example_at(version, |m| m)
}

type Decide = Box<dyn FnOnce(bool) + Send>;

/// Answers every request with `answer`, or keeps it waiting (`None`).
#[derive(Default)]
struct FakeUi {
    answer: Mutex<Option<bool>>,
    requests: Mutex<Vec<InstallRequest>>,
    waiting: Mutex<Vec<Decide>>,
}

impl InstallUi for FakeUi {
    fn confirm(&self, request: InstallRequest, decide: Box<dyn FnOnce(bool) + Send>) {
        lock(&self.requests).push(request);
        match *lock(&self.answer) {
            Some(answer) => decide(answer),
            None => lock(&self.waiting).push(decide),
        }
    }
}

struct Key {
    pair: minisign::KeyPair,
    public: PublicKey,
}

impl Key {
    fn new() -> Key {
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let public = PublicKey::decode(&pair.pk.to_box().unwrap().into_string()).unwrap();
        Key { pair, public }
    }

    fn sign(&self, data: &[u8], comment: &str) -> Vec<u8> {
        minisign::sign(None, &self.pair.sk, Cursor::new(data), Some(comment), None)
            .unwrap()
            .into_string()
            .into_bytes()
    }
}

struct Sandbox {
    dir: tempfile::TempDir,
    transport: Arc<FakeTransport>,
    key: Key,
    ui: Arc<FakeUi>,
    notices: Arc<Mutex<Vec<PluginNotice>>>,
    modules: Arc<PluginModules>,
}

impl Sandbox {
    /// Updates on (or off), the stable channel; the user says yes.
    fn new(updates: bool) -> Sandbox {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("settings.json"),
            format!(r#"{{"updates": {{"enabled": {updates}, "channel": "stable"}}}}"#),
        )
        .unwrap();
        let services = HostServices {
            prompter: Arc::new(ScriptedPrompter::new(Vec::<Step>::new())),
            recent: Arc::new(MemoryRecentPath::new(None)),
            http: Arc::new(FakeTransport::default()),
            ocsp_cache: Arc::new(OcspCache::new()),
            tsa: TsaProfile::basics_default(),
            clock: OffsetDateTime::now_utc,
            locale: Arc::new(|| Locale::Ru),
        };
        let builtin = vec![oncl_basics::MODULE_NAME.to_owned()];
        Sandbox {
            dir,
            transport: Arc::new(FakeTransport::default()),
            key: Key::new(),
            ui: Arc::new(FakeUi {
                answer: Mutex::new(Some(true)),
                ..FakeUi::default()
            }),
            notices: Arc::default(),
            modules: Arc::new(PluginModules::new(
                Arc::new(Engine::new()),
                services,
                builtin,
            )),
        }
    }

    fn service_with(&self, keys: Vec<PublicKey>) -> Arc<PluginService> {
        let notices = Arc::clone(&self.notices);
        PluginService::new(PluginConfig {
            data_dir: self.dir.path().to_owned(),
            settings: self.dir.path().join("settings.json"),
            keys,
            base: BASE.to_owned(),
            core: core(),
            http: Arc::clone(&self.transport) as _,
            modules: Arc::clone(&self.modules),
            ui: Arc::clone(&self.ui) as _,
            notify: Arc::new(move |notice| lock(&notices).push(notice)),
        })
        .unwrap()
    }

    fn service(&self) -> Arc<PluginService> {
        self.service_with(vec![self.key.public.clone()])
    }

    /// Serves `bytes` as the package of `version` and the release describing it.
    fn release(&self, version: &str, bytes: &[u8]) -> PluginRelease {
        let url = format!("https://example.org/plugins/{ID}-{version}.onclp");
        self.transport.serve(&url, bytes);
        PluginRelease {
            id: ID.to_owned(),
            version: v(version),
            package: oncl_update::Package {
                url,
                sha256: Sha256::of(bytes),
                size: bytes.len() as u64,
            },
            min_core: v("0.1.0-alpha.2"),
            modules: vec![MODULE.to_owned()],
            replaces: Some(PluginReplaces {
                symname: "kz.example.echo".to_owned(),
                version: "1.0.0".to_owned(),
            }),
            name: PluginName {
                ru: "Пример плагина".to_owned(),
                kk: "Плагин үлгісі".to_owned(),
                en: "Example plugin".to_owned(),
            },
            rollout: 100,
            revoked: false,
        }
    }

    /// Publishes the stable catalog `seq` of `plugins`.
    fn publish(&self, seq: u64, plugins: Vec<PluginRelease>) {
        let generated = OffsetDateTime::now_utc() - time::Duration::hours(1);
        let index = Index {
            schema: 1,
            channel: Channel::Stable,
            seq,
            generated,
            expires: generated + time::Duration::days(14),
            core: Vec::new(),
            extension: None,
            plugins,
        };
        let body = serde_json::to_vec_pretty(&index).unwrap();
        let sig = self.key.sign(&body, &format!("channel=stable;seq={seq}"));
        self.transport.serve(INDEX, &body);
        self.transport.serve(&format!("{INDEX}.minisig"), &sig);
    }

    fn notices(&self) -> Vec<PluginNotice> {
        std::mem::take(&mut *lock(&self.notices))
    }

    fn requests(&self) -> Vec<InstallRequest> {
        std::mem::take(&mut *lock(&self.ui.requests))
    }

    fn store(&self) -> Store {
        Store::open(self.dir.path()).unwrap()
    }

    fn installed_version(&self) -> Option<Version> {
        self.store()
            .state()
            .plugins
            .get(ID)
            .map(|i| i.version.clone())
    }

    /// Installs `version` from the catalog `seq` offering it.
    fn installed_from_catalog(&self, service: &Arc<PluginService>, seq: u64, version: &str) {
        let release = self.release(version, &example(version));
        self.publish(seq, vec![release]);
        service.install_from_catalog(ID, None);
        assert_eq!(self.installed_version(), Some(v(version)));
        self.notices();
        self.requests();
    }

    /// The example's `count` in session 1.
    fn count(&self) -> serde_json::Value {
        let module = self.modules.module(MODULE).expect("the module is served");
        let reply = module.process(
            &json!({"module": MODULE, "class": "Example", "method": "count"}).to_string(),
            &AddInfo {
                origin: Some(ORIGIN.to_owned()),
                session: 1,
            },
        );
        serde_json::from_str::<serde_json::Value>(&reply).unwrap()["body"].clone()
    }
}

fn name() -> Localized {
    Localized {
        ru: "Пример плагина".to_owned(),
        kk: "Плагин үлгісі".to_owned(),
        en: "Example plugin".to_owned(),
    }
}

#[test]
fn install_from_catalog_confirmed() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let release = sandbox.release("0.1.0", &example("0.1.0"));
    sandbox.publish(1, vec![release]);
    let view = service.view();
    assert!(matches!(
        view.catalog,
        CatalogView::Missing { error: None, .. }
    ));

    service.install_from_catalog(ID, Some(ORIGIN.to_owned()));
    let requests = sandbox.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.origin.as_deref(), Some(ORIGIN));
    assert_eq!(request.name, name());
    assert_eq!(request.version, v("0.1.0"));
    assert_eq!(
        request.replaces.as_ref().unwrap().symname,
        "kz.example.echo"
    );
    assert!(
        request.capabilities.keys && request.capabilities.dialogs && request.capabilities.files
    );
    assert_eq!(request.capabilities.http.len(), 1);
    assert!(!request.local);
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Installed { name: name() }]
    );

    let installed = sandbox.store().state().plugins[ID].clone();
    assert_eq!(installed.source, Source::Catalog);
    assert!(installed.enabled);
    assert_eq!(sandbox.modules.names(), [MODULE]);
    assert_eq!(sandbox.count(), 1);
    let view = service.view();
    assert!(matches!(
        view.catalog,
        CatalogView::Ready {
            channel: Channel::Stable,
            checked: Some(_),
            error: None,
            ..
        }
    ));
    assert_eq!(view.installed.len(), 1);
    assert_eq!(view.installed[0].state, PluginState::Enabled);
    assert_eq!(view.installed[0].name, name());
    assert_eq!(
        view.installed[0].replaces.as_ref().unwrap().version,
        "1.0.0"
    );
    assert!(view.available.is_empty());
    // Installed: asked for again, nothing happens.
    service.install_from_catalog(ID, None);
    assert!(sandbox.requests().is_empty() && sandbox.notices().is_empty());
}

#[test]
fn install_declined_leaves_nothing() {
    let sandbox = Sandbox::new(true);
    *lock(&sandbox.ui.answer) = Some(false);
    let service = sandbox.service();
    sandbox.publish(1, vec![sandbox.release("0.1.0", &example("0.1.0"))]);
    service.install_from_catalog(ID, None);
    assert_eq!(sandbox.requests().len(), 1);
    assert!(sandbox.notices().is_empty());
    assert!(sandbox.store().state().plugins.is_empty());
    assert!(sandbox.modules.names().is_empty());
    let view = service.view();
    assert_eq!(view.available.len(), 1);
    assert_eq!(view.available[0].id, ID);
    assert_eq!(view.available[0].needed_by, None);
    // Not stuck "being installed": asked again.
    service.install_from_catalog(ID, None);
    assert_eq!(sandbox.requests().len(), 1);
    // While one waits for the user, another is not started.
    *lock(&sandbox.ui.answer) = None;
    service.install_from_catalog(ID, None);
    service.install_from_catalog(ID, None);
    assert_eq!(sandbox.requests().len(), 1);
    // The window closed: declined, and asked again next time.
    let waiting: Vec<_> = std::mem::take(&mut *lock(&sandbox.ui.waiting));
    drop(waiting);
    service.install_from_catalog(ID, None);
    assert_eq!(sandbox.requests().len(), 1);
    // Agreed late: installed.
    let decide = lock(&sandbox.ui.waiting).pop().unwrap();
    decide(true);
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Installed { name: name() }]
    );
    assert_eq!(sandbox.modules.names(), [MODULE]);
}

#[test]
fn package_hash_mismatch_fails() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    let mut release = sandbox.release("0.1.0", &example("0.1.0"));
    release.package.sha256 = Sha256::of(b"another file");
    sandbox.publish(1, vec![release]);
    service.install_from_catalog(ID, None);
    assert!(sandbox.requests().is_empty(), "the user is not asked");
    let notices = sandbox.notices();
    assert!(
        matches!(&notices[..], [PluginNotice::Failed { name: n, error }] if *n == name() && error.contains("sha256")),
        "{notices:?}"
    );
    let state = sandbox.store().state();
    assert!(state.plugins.is_empty());
    assert!(state.bad[ID].contains(&v("0.1.0")));
    // Marked bad: no longer offered.
    assert!(service.view().available.is_empty());
}

#[test]
fn manifest_mismatch_marks_bad() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    // The index says the package serves another module than its manifest does.
    let mut release = sandbox.release("0.1.0", &example("0.1.0"));
    release.modules = vec!["kz.example.Other".to_owned()];
    sandbox.publish(1, vec![release]);
    service.install_from_catalog(ID, None);
    assert!(sandbox.requests().is_empty());
    assert!(
        matches!(&sandbox.notices()[..], [PluginNotice::Failed { error, .. }] if error.contains("modules"))
    );
    assert!(sandbox.store().state().bad[ID].contains(&v("0.1.0")));

    // An update whose manifest is of another version: refused, the old one runs on.
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    sandbox.installed_from_catalog(&service, 1, "0.1.0");
    let release = sandbox.release("0.2.0", &example("0.1.0"));
    sandbox.publish(2, vec![release]);
    service.check_now();
    assert!(
        matches!(&sandbox.notices()[..], [PluginNotice::Failed { error, .. }] if error.contains("version"))
    );
    assert_eq!(sandbox.installed_version(), Some(v("0.1.0")));
    assert!(sandbox.store().state().bad[ID].contains(&v("0.2.0")));
    assert_eq!(sandbox.modules.names(), [MODULE]);
}

#[test]
fn update_applies_and_notifies_once() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    sandbox.installed_from_catalog(&service, 1, "0.1.0");
    assert_eq!(sandbox.count(), 1);
    assert_eq!(sandbox.count(), 2);
    let old = sandbox.release("0.1.0", &example("0.1.0"));
    let new = sandbox.release("0.2.0", &example("0.2.0"));
    sandbox.publish(2, vec![old, new]);
    service.check_now();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Updated {
            name: name(),
            version: v("0.2.0"),
        }]
    );
    assert!(sandbox.requests().is_empty(), "updates are not asked about");
    assert_eq!(sandbox.installed_version(), Some(v("0.2.0")));
    assert_eq!(sandbox.modules.loaded()[0].version, v("0.2.0"));
    // The session's next call runs on the new version.
    assert_eq!(sandbox.count(), 1);
    service.check_now();
    assert!(sandbox.notices().is_empty());
    // The old package file is gone.
    let packages: Vec<_> = std::fs::read_dir(sandbox.dir.path().join("plugins/packages"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(packages, [format!("{ID}-0.2.0.onclp").as_str()]);
}

#[test]
fn withdrawn_unloads_and_notifies_once() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    sandbox.installed_from_catalog(&service, 1, "0.1.0");
    let mut revoked = sandbox.release("0.1.0", &example("0.1.0"));
    revoked.revoked = true;
    sandbox.publish(2, vec![revoked]);
    service.check_now();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Withdrawn { name: name() }]
    );
    assert!(sandbox.modules.names().is_empty());
    assert!(sandbox.store().state().plugins[ID].withdrawn);
    assert_eq!(service.view().installed[0].state, PluginState::Withdrawn);
    service.check_now();
    assert!(sandbox.notices().is_empty());
    // A restart does not load it.
    let sandbox_modules = Arc::clone(&sandbox.modules);
    drop(service);
    let _again = sandbox.service();
    assert!(sandbox_modules.names().is_empty());
    // Turning it on does not load it either.
    _again.set_enabled(ID, true).unwrap();
    assert!(sandbox.modules.names().is_empty());
}

#[test]
fn downgrade_only_from_revoked() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    sandbox.installed_from_catalog(&service, 1, "0.2.0");
    let older = sandbox.release("0.1.0", &example("0.1.0"));
    let current = sandbox.release("0.2.0", &example("0.2.0"));
    sandbox.publish(2, vec![older.clone(), current.clone()]);
    service.check_now();
    assert!(sandbox.notices().is_empty());
    assert_eq!(sandbox.installed_version(), Some(v("0.2.0")));

    let mut revoked = current;
    revoked.revoked = true;
    sandbox.publish(3, vec![older, revoked]);
    service.check_now();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Updated {
            name: name(),
            version: v("0.1.0"),
        }]
    );
    assert_eq!(sandbox.installed_version(), Some(v("0.1.0")));
    assert_eq!(sandbox.modules.loaded()[0].version, v("0.1.0"));
}

/// The example's package in a file of the sandbox.
fn example_file(sandbox: &Sandbox, version: &str) -> PathBuf {
    let path = sandbox.dir.path().join(format!("example-{version}.onclp"));
    std::fs::write(&path, example(version)).unwrap();
    path
}

#[test]
fn local_plugin_is_not_updated() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    service.install_from_file(example_file(&sandbox, "0.1.0"));
    let requests = sandbox.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].local);
    assert_eq!(requests[0].origin, None);
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Installed { name: name() }]
    );
    assert_eq!(sandbox.store().state().plugins[ID].source, Source::Local);

    let mut revoked = sandbox.release("0.1.0", &example("0.1.0"));
    revoked.revoked = true;
    let newer = sandbox.release("0.2.0", &example("0.2.0"));
    sandbox.publish(1, vec![revoked, newer]);
    service.check_now();
    assert!(sandbox.notices().is_empty());
    assert_eq!(sandbox.installed_version(), Some(v("0.1.0")));
    assert_eq!(sandbox.modules.names(), [MODULE]);
    let view = service.view();
    assert_eq!(view.installed[0].source, Source::Local);
    assert_eq!(view.installed[0].state, PluginState::Enabled);
    // Installed: not offered.
    assert!(view.available.is_empty());
}

#[test]
fn disabled_updates_skip_schedule_but_allow_on_demand() {
    let sandbox = Sandbox::new(false);
    let service = sandbox.service();
    sandbox.publish(1, vec![sandbox.release("0.1.0", &example("0.1.0"))]);
    let wait = service.scheduled_check();
    assert!(wait >= CHECK_EVERY.0 && wait <= CHECK_EVERY.1);
    assert!(sandbox.transport.asked().is_empty(), "nothing downloaded");

    // On demand: the catalog is downloaded.
    service.install_from_catalog(ID, None);
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Installed { name: name() }]
    );
    let old = sandbox.release("0.1.0", &example("0.1.0"));
    let new = sandbox.release("0.2.0", &example("0.2.0"));
    sandbox.publish(2, vec![old, new]);
    let asked = sandbox.transport.asked().len();
    service.check_now();
    assert!(
        sandbox.transport.asked().len() > asked,
        "«Проверить сейчас» downloads"
    );
    assert!(sandbox.notices().is_empty());
    assert_eq!(
        sandbox.installed_version(),
        Some(v("0.1.0")),
        "but does not update"
    );
    assert_eq!(sandbox.store().state().last_seq[&Channel::Stable], 2);

    // Updates on: the scheduled check updates.
    std::fs::write(
        sandbox.dir.path().join("settings.json"),
        r#"{"updates": {"enabled": true, "channel": "stable"}}"#,
    )
    .unwrap();
    service.scheduled_check();
    assert_eq!(sandbox.installed_version(), Some(v("0.2.0")));
}

#[test]
fn no_keys_means_no_catalog_but_file_install_works() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service_with(Vec::new());
    sandbox.publish(1, vec![sandbox.release("0.1.0", &example("0.1.0"))]);
    assert_eq!(service.view().catalog, CatalogView::Unavailable);
    service.install_from_catalog(ID, None);
    assert!(matches!(
        &sandbox.notices()[..],
        [PluginNotice::Failed { .. }]
    ));
    assert!(
        service
            .catalog_offer_for_symname("kz.example.echo", Duration::from_secs(1))
            .is_none()
    );
    service.check_now();
    assert!(sandbox.transport.asked().is_empty());

    service.install_from_file(example_file(&sandbox, "0.1.0"));
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Installed { name: name() }]
    );
    assert_eq!(sandbox.modules.names(), [MODULE]);
    // A file that is not a package.
    let junk = sandbox.dir.path().join("junk.onclp");
    std::fs::write(&junk, b"not a zip").unwrap();
    service.install_from_file(junk);
    assert!(
        matches!(&sandbox.notices()[..], [PluginNotice::Failed { name, .. }] if name.en == "junk.onclp")
    );
}

#[test]
fn startup_loads_enabled_only() {
    let sandbox = Sandbox::new(true);
    let store = sandbox.store();
    let bytes = example("0.1.0");
    store
        .install(&Package::read(&bytes).unwrap(), &bytes, Source::Local)
        .unwrap();
    let other = example_at("1.0.0", |m| {
        m.replacen(&format!("id = \"{ID}\""), "id = \"kz.example.other\"", 1)
            .replacen(
                &format!("modules = [\"{MODULE}\"]"),
                "modules = [\"kz.example.Other\"]",
                1,
            )
    });
    store
        .install(&Package::read(&other).unwrap(), &other, Source::Local)
        .unwrap();
    store.set_enabled("kz.example.other", false).unwrap();
    let broken = example_at("1.0.0", |m| {
        m.replacen(&format!("id = \"{ID}\""), "id = \"kz.example.broken\"", 1)
            .replacen(
                &format!("modules = [\"{MODULE}\"]"),
                "modules = [\"kz.example.Broken\"]",
                1,
            )
    });
    store
        .install(&Package::read(&broken).unwrap(), &broken, Source::Local)
        .unwrap();
    // Changed on disk after its installation.
    let file = sandbox
        .dir
        .path()
        .join("plugins/packages/kz.example.broken-1.0.0.onclp");
    let mut changed = std::fs::read(&file).unwrap();
    changed.push(0);
    std::fs::write(&file, changed).unwrap();

    let service = sandbox.service();
    assert_eq!(sandbox.modules.names(), [MODULE]);
    let view = service.view();
    let states: Vec<(&str, &PluginState)> = view
        .installed
        .iter()
        .map(|p| (p.id.as_str(), &p.state))
        .collect();
    assert_eq!(
        states[0],
        (
            "io.github.arynyklas.openncalayer.example",
            &PluginState::Enabled
        )
    );
    assert!(matches!(
        states[1],
        ("kz.example.broken", PluginState::Error(_))
    ));
    assert_eq!(states[2], ("kz.example.other", &PluginState::Disabled));
    // Its name is read even though it is off.
    assert_eq!(view.installed[2].name, name());

    service.set_enabled("kz.example.other", true).unwrap();
    assert_eq!(sandbox.modules.names(), [MODULE, "kz.example.Other"]);
    service.set_enabled(ID, false).unwrap();
    assert_eq!(sandbox.modules.names(), ["kz.example.Other"]);
    service.remove("kz.example.other").unwrap();
    assert!(sandbox.modules.names().is_empty());
    assert!(service.remove("kz.example.other").is_err());
    assert!(service.set_enabled("kz.example.other", true).is_err());
}

#[test]
fn missing_module_offers_install() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    sandbox.publish(1, vec![sandbox.release("0.1.0", &example("0.1.0"))]);
    let page = AddInfo {
        origin: Some(ORIGIN.to_owned()),
        session: 3,
    };
    // No catalog in use yet: nothing is downloaded for it.
    sandbox.modules.missing(MODULE, &page);
    assert!(sandbox.notices().is_empty());
    assert!(sandbox.transport.asked().is_empty());

    service.check_now();
    sandbox.modules.missing("kz.example.Unknown", &page);
    assert!(sandbox.notices().is_empty());
    sandbox.modules.missing(MODULE, &page);
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Needed {
            origin: Some(ORIGIN.to_owned()),
            name: name(),
            id: ID.to_owned(),
        }]
    );
    let view = service.view();
    assert_eq!(view.available[0].needed_by, Some(Some(ORIGIN.to_owned())));
    // Installed: no longer needed, nor told.
    service.install_from_catalog(ID, Some(ORIGIN.to_owned()));
    sandbox.notices();
    let view = service.view();
    assert!(view.available.is_empty());
    assert_eq!(
        service
            .catalog_offer_for_symname("kz.example.echo", Duration::from_secs(1))
            .map(|r| r.id),
        Some(ID.to_owned())
    );
}

/// The notices, waited for until there are `n` (at most 30 s).
fn wait_for_notices(sandbox: &Sandbox, n: usize) -> Vec<PluginNotice> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while lock(&sandbox.notices).len() < n {
        assert!(
            std::time::Instant::now() < deadline,
            "{:?}",
            lock(&sandbox.notices)
        );
        thread::sleep(Duration::from_millis(10));
    }
    sandbox.notices()
}

#[test]
fn install_bundle_installs_the_port_in_the_background() {
    let sandbox = Sandbox::new(false);
    let service = sandbox.service();
    sandbox.publish(1, vec![sandbox.release("0.1.0", &example("0.1.0"))]);
    let bundles: &dyn Bundles = &*service;
    assert!(bundles.services().is_empty());
    assert!(bundles.bundles().is_empty());
    // Not in the catalog.
    assert!(!bundles.request_install("kz.example.other", ORIGIN));
    // In it, downloaded for the request (updates are off): installed once the user agrees.
    assert!(bundles.request_install("kz.example.echo", ORIGIN));
    assert_eq!(
        wait_for_notices(&sandbox, 1),
        [PluginNotice::Installed { name: name() }]
    );
    assert_eq!(sandbox.requests()[0].origin.as_deref(), Some(ORIGIN));
    assert_eq!(bundles.services(), [MODULE]);
    assert_eq!(
        bundles.bundles(),
        [("kz.example.echo".to_owned(), "1.0.0".to_owned())]
    );
    // Installed already.
    assert!(!bundles.request_install("kz.example.echo", ORIGIN));
    // Turned off: not reported, and still not offered.
    service.set_enabled(ID, false).unwrap();
    assert!(bundles.bundles().is_empty() && bundles.services().is_empty());
    assert!(!bundles.request_install("kz.example.echo", ORIGIN));
}

#[test]
fn install_bundle_without_a_catalog_finds_nothing() {
    let sandbox = Sandbox::new(true);
    // Nothing published: the download fails.
    let service = sandbox.service();
    assert!(!Bundles::request_install(
        &*service,
        "kz.example.echo",
        ORIGIN
    ));
    // Without keys nothing is downloaded at all.
    let sandbox = Sandbox::new(true);
    sandbox.publish(1, vec![sandbox.release("0.1.0", &example("0.1.0"))]);
    let service = sandbox.service_with(Vec::new());
    assert!(!Bundles::request_install(
        &*service,
        "kz.example.echo",
        ORIGIN
    ));
    assert!(sandbox.transport.asked().is_empty());
}
