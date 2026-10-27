//! The updater with a fake transport, installer and daemon, on a sandbox data directory, and
//! indexes signed by a key made for the test.

use super::*;
use oncl_pki::http::{GetOptions, HttpError, HttpReply};
use oncl_update::{Channel, CoreRelease, FlavorPackage, Index, Package, Sha256};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::Duration as TimeDuration;

/// Replies `200` with the body served at a URL, and refuses any other; records what was
/// asked: the URL, the size limit and whether only HTTPS was allowed.
#[derive(Default)]
pub(crate) struct FakeTransport {
    bodies: Mutex<BTreeMap<String, Vec<u8>>>,
    asked: Mutex<Vec<(String, u64, bool)>>,
}

impl FakeTransport {
    pub(crate) fn serve(&self, url: &str, body: &[u8]) {
        lock(&self.bodies).insert(url.to_owned(), body.to_vec());
    }

    pub(crate) fn asked(&self) -> Vec<(String, u64, bool)> {
        lock(&self.asked).clone()
    }
}

impl HttpTransport for FakeTransport {
    fn get(&self, url: &str) -> Result<HttpReply, HttpError> {
        self.get_with(url, GetOptions::default())
    }

    fn get_with(&self, url: &str, opts: GetOptions) -> Result<HttpReply, HttpError> {
        lock(&self.asked).push((url.to_owned(), opts.max_len, opts.https_only));
        let body = lock(&self.bodies)
            .get(url)
            .cloned()
            .ok_or_else(|| HttpError("connection refused".to_owned()))?;
        Ok(HttpReply {
            status: 200,
            content_type: None,
            body,
        })
    }

    fn post(&self, _: &str, _: &str, _: &[u8]) -> Result<HttpReply, HttpError> {
        Err(HttpError("no POST here".to_owned()))
    }
}

/// What the fakes saw, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Download(Version, bool),
    Apply(Version),
    Busy,
    Exit,
    Notice(Notice),
}

type Log = Arc<Mutex<Vec<Event>>>;

struct FakeInstaller {
    current: Version,
    log: Log,
    fail_download: bool,
    fail_apply: bool,
}

impl Installer for FakeInstaller {
    fn current(&self) -> Version {
        self.current.clone()
    }

    fn download(&self, target: &Target, downgrade: bool) -> Result<(), String> {
        lock(&self.log).push(Event::Download(target.version.clone(), downgrade));
        if self.fail_download {
            return Err("the package's sha256 does not match the update index".to_owned());
        }
        Ok(())
    }

    fn apply_on_exit(&self, target: &Target) -> Result<(), String> {
        if self.fail_apply {
            return Err("the updater did not start".to_owned());
        }
        lock(&self.log).push(Event::Apply(target.version.clone()));
        Ok(())
    }
}

/// A daemon busy for its first `busy` looks.
struct FakeHost {
    log: Log,
    busy: AtomicUsize,
}

impl Host for FakeHost {
    fn busy(&self) -> bool {
        lock(&self.log).push(Event::Busy);
        self.busy
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
    }

    fn notify(&self, notice: Notice) {
        lock(&self.log).push(Event::Notice(notice));
    }

    fn exit(&self) {
        lock(&self.log).push(Event::Exit);
    }
}

fn v(s: &str) -> Version {
    Version::parse(s).unwrap()
}

const BASE: &str = "https://example.org/updates/v1";
const INDEX: &str = "https://example.org/updates/v1/stable.json";

/// A release of `version` for Windows x64, with its full package only.
fn release(version: &str, rollout: u8, revoked: bool) -> CoreRelease {
    let name = format!("openncalayer-{version}-win-x64-full.nupkg");
    let flavor = FlavorPackage {
        full: Package {
            url: format!("https://example.org/v{version}/{name}"),
            sha256: Sha256::of(name.as_bytes()),
            size: name.len() as u64,
        },
        delta_from: BTreeMap::new(),
    };
    CoreRelease {
        version: v(version),
        flavors: BTreeMap::from([(Flavor::WinX64.as_str().to_owned(), flavor)]),
        rollout,
        revoked,
        notes_url: None,
    }
}

/// A key pair made for the test.
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

/// A sandbox: its data directory, the index server and the key the client trusts.
struct Sandbox {
    dir: tempfile::TempDir,
    transport: Arc<FakeTransport>,
    key: Key,
    log: Log,
}

impl Sandbox {
    fn new() -> Sandbox {
        Sandbox {
            dir: tempfile::tempdir().unwrap(),
            transport: Arc::new(FakeTransport::default()),
            key: Key::new(),
            log: Log::default(),
        }
    }

    /// Publishes the stable index `seq` of `core`, made `age` ago, signed by `key`.
    fn publish_by(&self, key: &Key, seq: u64, core: Vec<CoreRelease>, age: TimeDuration) {
        let generated = OffsetDateTime::now_utc() - age;
        let index = Index {
            schema: 1,
            channel: Channel::Stable,
            seq,
            generated,
            expires: generated + TimeDuration::days(30),
            core,
            extension: None,
            plugins: Vec::new(),
        };
        let body = serde_json::to_vec_pretty(&index).unwrap();
        let sig = key.sign(&body, &format!("channel=stable;seq={seq}"));
        self.transport.serve(INDEX, &body);
        self.transport.serve(&format!("{INDEX}.minisig"), &sig);
    }

    fn publish(&self, seq: u64, core: Vec<CoreRelease>) {
        self.publish_by(&self.key, seq, core, TimeDuration::days(1));
    }

    fn settings(&self, enabled: bool) {
        std::fs::write(
            self.dir.path().join("settings.json"),
            format!(r#"{{"updates": {{"enabled": {enabled}, "channel": "stable"}}}}"#),
        )
        .unwrap();
    }

    fn updater(&self, current: &str, busy: usize) -> Updater {
        self.updater_with(current, busy, false, false)
    }

    fn updater_with(
        &self,
        current: &str,
        busy: usize,
        fail_download: bool,
        fail_apply: bool,
    ) -> Updater {
        Updater::new(
            UpdaterConfig {
                data_dir: self.dir.path().to_owned(),
                settings: self.dir.path().join("settings.json"),
                base: BASE.to_owned(),
                keys: vec![self.key.public.clone()],
                flavor: Flavor::WinX64,
                idle_poll: Duration::from_millis(1),
            },
            Arc::clone(&self.transport) as _,
            Box::new(FakeInstaller {
                current: v(current),
                log: Arc::clone(&self.log),
                fail_download,
                fail_apply,
            }),
            Box::new(FakeHost {
                log: Arc::clone(&self.log),
                busy: AtomicUsize::new(busy),
            }),
        )
    }

    /// The events since the last call.
    fn events(&self) -> Vec<Event> {
        std::mem::take(&mut *lock(&self.log))
    }

    fn state(&self) -> State {
        State::load(self.dir.path()).unwrap()
    }

    fn pending(&self, from: &str, to: &str, started: Option<TimeDuration>) {
        let mut state = self.state();
        let now = OffsetDateTime::now_utc();
        state.pending_health = Some(PendingHealth {
            from: v(from),
            to: v(to),
            applied: now - TimeDuration::minutes(5),
            started: started.map(|ago| now - ago),
        });
        state.save(self.dir.path()).unwrap();
    }
}

fn available(version: &str, installing: bool) -> UpdateStatus {
    UpdateStatus::Available {
        version: version.to_owned(),
        installing,
    }
}

#[test]
fn an_update_is_found_downloaded_and_applied_once_the_daemon_is_idle() {
    let s = Sandbox::new();
    s.publish(
        3,
        vec![release("0.1.0", 100, false), release("0.2.0", 100, false)],
    );
    let u = s.updater("0.1.0", 2);

    let checked = u.check(false);
    assert_eq!(checked.status, available("0.2.0", true));
    assert!(!checked.retry_soon);
    assert_eq!(u.status(), available("0.2.0", true));
    assert_eq!(
        s.events(),
        [Event::Notice(Notice::Checked(available("0.2.0", true)))]
    );
    assert_eq!(s.state().last_seq, BTreeMap::from([(Channel::Stable, 3)]));
    // The index and its signature over HTTPS only, within their limits.
    assert_eq!(
        s.transport.asked(),
        [
            (INDEX.to_owned(), oncl_update::MAX_INDEX_LEN, true),
            (format!("{INDEX}.minisig"), 4096, true),
        ]
    );

    // A sign request runs: the update waits for it, and applies after.
    let plan = checked.plan.unwrap();
    assert_eq!((plan.downgrade, plan.rollback), (false, false));
    assert!(u.install(&plan));
    assert_eq!(
        s.events(),
        [
            Event::Download(v("0.2.0"), false),
            Event::Busy,
            Event::Busy,
            Event::Busy,
            Event::Apply(v("0.2.0")),
            Event::Exit,
        ]
    );
    let pending = s.state().pending_health.unwrap();
    assert_eq!((pending.from, pending.to), (v("0.1.0"), v("0.2.0")));
    assert_eq!(pending.started, None);

    // The same version found again is not told again.
    assert_eq!(u.check(false).status, available("0.2.0", true));
    assert_eq!(s.events(), []);
}

#[test]
fn the_new_version_confirms_its_health() {
    let s = Sandbox::new();
    s.pending("0.1.0", "0.2.0", None);
    let u = s.updater("0.2.0", 0);
    assert_eq!(u.startup(), Startup::Confirm);
    assert!(s.state().pending_health.unwrap().started.is_some());
    // Started again within the grace (e.g. it was quit at once): still its first chance.
    assert_eq!(u.startup(), Startup::Confirm);
    u.confirm_health();
    assert_eq!(s.state().pending_health, None);
    assert_eq!(s.events(), [Event::Notice(Notice::Updated(v("0.2.0")))]);
    // Nothing more to confirm.
    u.confirm_health();
    assert_eq!(u.startup(), Startup::Normal);
    assert_eq!(s.events(), []);
}

#[test]
fn a_version_that_did_not_prove_healthy_is_rolled_back_and_never_offered_again() {
    let s = Sandbox::new();
    s.publish(
        4,
        vec![release("0.1.0", 100, false), release("0.2.0", 100, false)],
    );
    s.pending("0.1.0", "0.2.0", Some(TimeDuration::minutes(2)));
    let bad = s.updater("0.2.0", 0);
    let startup = bad.startup();
    let Startup::RollBack(pending) = &startup else {
        panic!("{startup:?}");
    };
    assert_eq!((&pending.from, &pending.to), (&v("0.1.0"), &v("0.2.0")));
    assert!(s.state().bad.contains(&v("0.2.0")));

    // The full package of the version before, from the index; installed back at once.
    let plan = bad.rollback_plan(pending).unwrap();
    assert_eq!(plan.target.version, v("0.1.0"));
    assert_eq!(
        plan.target.full,
        release("0.1.0", 100, false).flavors["win-x64"].full
    );
    assert_eq!(plan.target.delta, None);
    assert!(plan.downgrade && plan.rollback);
    // Even with updates off.
    s.settings(false);
    assert!(bad.install(&plan));
    assert_eq!(
        s.events(),
        [
            Event::Download(v("0.1.0"), true),
            Event::Busy,
            Event::Apply(v("0.1.0")),
            Event::Exit,
        ]
    );
    let pending = s.state().pending_health.unwrap();
    assert_eq!((pending.from, pending.to), (v("0.2.0"), v("0.1.0")));

    // The version before starts and tells the user the update was rolled back.
    s.settings(true);
    let old = s.updater("0.1.0", 0);
    assert_eq!(old.startup(), Startup::Confirm);
    old.confirm_health();
    assert_eq!(
        s.events(),
        [Event::Notice(Notice::RolledBack {
            failed: v("0.2.0"),
            version: v("0.1.0"),
        })]
    );
    // 0.2.0 is not offered here again.
    assert_eq!(old.check(false).status, UpdateStatus::UpToDate);
    assert!(s.state().bad.contains(&v("0.2.0")));
}

#[test]
fn nothing_is_rolled_back_to_a_version_that_failed_too() {
    let s = Sandbox::new();
    let mut state = s.state();
    state.bad.insert(v("0.2.0"));
    state.save(s.dir.path()).unwrap();
    // The rollback from 0.2.0 to 0.1.0 did not prove healthy either.
    s.pending("0.2.0", "0.1.0", Some(TimeDuration::minutes(2)));
    let u = s.updater("0.1.0", 0);
    assert_eq!(u.startup(), Startup::Normal);
    let state = s.state();
    assert_eq!(state.pending_health, None);
    assert!(state.bad.contains(&v("0.1.0")) && state.bad.contains(&v("0.2.0")));
}

#[test]
fn an_update_that_did_not_install_is_forgotten() {
    let s = Sandbox::new();
    s.pending("0.1.0", "0.2.0", None);
    let u = s.updater("0.1.0", 0);
    assert_eq!(u.startup(), Startup::Normal);
    assert_eq!(s.state().pending_health, None);
    assert!(s.state().bad.is_empty());
}

#[test]
fn a_refused_index_changes_nothing_and_is_not_notified() {
    let s = Sandbox::new();
    let core = || vec![release("0.1.0", 100, false), release("0.2.0", 100, false)];
    let u = s.updater("0.1.0", 0);

    // Another key.
    s.publish_by(&Key::new(), 7, core(), TimeDuration::days(1));
    let checked = u.check(false);
    let UpdateStatus::Failed(e) = &checked.status else {
        panic!("{:?}", checked.status);
    };
    assert!(e.contains("does not match any trusted key"), "{e}");
    assert!(checked.plan.is_none() && !checked.retry_soon);
    assert!(
        s.state().last_seq.is_empty(),
        "seq is saved only once verified"
    );

    // A broken signature.
    s.publish(7, core());
    let mut body = lock(&s.transport.bodies)[INDEX].clone();
    body[10] ^= 1;
    s.transport.serve(INDEX, &body);
    assert!(matches!(u.check(false).status, UpdateStatus::Failed(_)));

    // An older seq than one accepted.
    s.publish(7, core());
    assert_eq!(u.check(false).status, available("0.2.0", true));
    s.publish(6, core());
    let checked = u.check(false);
    let UpdateStatus::Failed(e) = &checked.status else {
        panic!("{:?}", checked.status);
    };
    assert!(e.contains("older than the last seen 7"), "{e}");
    // The same seq again is the same index: accepted.
    s.publish(7, core());
    assert_eq!(u.check(false).status, available("0.2.0", true));

    // Not signed again within 30 days.
    s.publish_by(&s.key, 8, core(), TimeDuration::days(31));
    let UpdateStatus::Failed(e) = u.check(false).status else {
        panic!("not refused");
    };
    assert!(e.contains("expired"), "{e}");
    assert_eq!(s.state().last_seq[&Channel::Stable], 7);

    // Only the first offer of 0.2.0 was told; no failure was.
    assert_eq!(
        s.events(),
        [Event::Notice(Notice::Checked(available("0.2.0", true)))]
    );
}

#[test]
fn an_unreachable_index_is_tried_again_soon_and_quietly() {
    let s = Sandbox::new();
    let u = s.updater("0.1.0", 0);
    let checked = u.check(false);
    assert!(checked.retry_soon && checked.plan.is_none());
    assert!(matches!(checked.status, UpdateStatus::Failed(_)));
    assert_eq!(s.events(), []);
}

#[test]
fn a_revoked_current_version_moves_to_the_newest_one_not_revoked() {
    let s = Sandbox::new();
    // 0.1.0 is not in the rollout any more; it is still where a revoked 0.2.0 goes.
    s.publish(
        5,
        vec![release("0.1.0", 0, false), release("0.2.0", 100, true)],
    );
    let u = s.updater("0.2.0", 0);
    let checked = u.check(false);
    assert_eq!(checked.status, available("0.1.0", true));
    let plan = checked.plan.unwrap();
    assert!(plan.downgrade && !plan.rollback);
    assert!(u.install(&plan));
    assert_eq!(s.events()[1], Event::Download(v("0.1.0"), true));
}

#[test]
fn the_rollout_holds_a_version_back() {
    let s = Sandbox::new();
    s.publish(
        5,
        vec![release("0.1.0", 100, false), release("0.2.0", 0, false)],
    );
    let u = s.updater("0.1.0", 0);
    let checked = u.check(false);
    assert_eq!(checked.status, UpdateStatus::UpToDate);
    assert!(checked.plan.is_none());
    assert_eq!(s.events(), []);
}

#[test]
fn with_updates_off_only_a_check_now_looks_and_nothing_is_installed() {
    let s = Sandbox::new();
    s.settings(false);
    s.publish(
        5,
        vec![release("0.1.0", 100, false), release("0.2.0", 100, false)],
    );
    let u = s.updater("0.1.0", 0);
    let checked = u.check(false);
    assert_eq!(checked.status, UpdateStatus::NotChecked);
    assert!(s.transport.asked().is_empty());

    assert_eq!(u.check_now(), available("0.2.0", false));
    assert_eq!(*lock(&u.queued), None);
    assert_eq!(s.events(), [], "the window shows it; no notification");

    // A plan found with updates on goes to the updater's thread at once.
    s.settings(true);
    assert_eq!(u.check_now(), available("0.2.0", true));
    let far = SystemTime::now() + Duration::from_secs(3600);
    assert_eq!(u.next(far).unwrap().target.version, v("0.2.0"));

    // Turned off while the update waited: it is not applied.
    let plan = u.check(true).plan.unwrap();
    s.settings(false);
    assert!(!u.install(&plan));
    assert_eq!(s.state().pending_health, None);
}

#[test]
fn a_failed_download_or_apply_leaves_nothing_pending() {
    let s = Sandbox::new();
    s.publish(
        5,
        vec![release("0.1.0", 100, false), release("0.2.0", 100, false)],
    );
    let u = s.updater_with("0.1.0", 0, true, false);
    let plan = u.check(false).plan.unwrap();
    assert!(!u.install(&plan));
    assert!(matches!(u.status(), UpdateStatus::Failed(e) if e.contains("sha256")));
    assert_eq!(s.state().pending_health, None);

    let u = s.updater_with("0.1.0", 0, false, true);
    assert!(!u.install(&plan));
    assert_eq!(s.state().pending_health, None);
    assert!(!s.events().contains(&Event::Exit));
}

#[test]
fn a_broken_state_is_replaced() {
    let s = Sandbox::new();
    std::fs::create_dir_all(s.dir.path().join("update")).unwrap();
    std::fs::write(State::path(s.dir.path()), "not json").unwrap();
    s.publish(5, vec![release("0.1.0", 100, false)]);
    let u = s.updater("0.1.0", 0);
    assert_eq!(u.check(false).status, UpdateStatus::UpToDate);
    assert_eq!(s.state().last_seq[&Channel::Stable], 5);
}

#[test]
fn availability_needs_a_flavor_an_installation_and_keys() {
    let key = Key::new().public;
    let installed = || Ok::<_, String>(());
    let not_installed = || Err::<(), _>("not installed".to_owned());
    assert_eq!(
        availability(Ok(vec![key.clone()]), None, installed).err(),
        Some(UpdateStatus::NotInstalled)
    );
    assert_eq!(
        availability(Ok(vec![key.clone()]), Some(Flavor::LinuxX64), not_installed).err(),
        Some(UpdateStatus::NotInstalled)
    );
    assert_eq!(
        availability(Ok(Vec::new()), Some(Flavor::LinuxX64), installed).err(),
        Some(UpdateStatus::NoKeys)
    );
    assert_eq!(
        availability(
            Err(UpdateError::BadKey("x".to_owned())),
            Some(Flavor::LinuxX64),
            installed
        )
        .err(),
        Some(UpdateStatus::NoKeys)
    );
    let (keys, flavor, ()) = availability(Ok(vec![key]), Some(Flavor::Osx), installed).unwrap();
    assert_eq!((keys.len(), flavor), (1, Flavor::Osx));
    // Off: the window says why, and a check says the same.
    let off = UpdaterHandle::Off(UpdateStatus::NoKeys);
    assert_eq!(off.check_now(), UpdateStatus::NoKeys);
}

#[test]
fn checks_are_spread() {
    for _ in 0..100 {
        let d = jitter(CHECK_EVERY);
        assert!(CHECK_EVERY.0 <= d && d <= CHECK_EVERY.1, "{d:?}");
        let d = jitter(FIRST_CHECK);
        assert!(FIRST_CHECK.0 <= d && d <= FIRST_CHECK.1, "{d:?}");
    }
    assert_eq!(index_base(), INDEX_BASE);
}
