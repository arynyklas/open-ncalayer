//! The updater with a fake transport, installer and daemon, on a sandbox data directory, and
//! indexes signed by a key made for the test.

use super::*;
use oncl_pki::http::{GetOptions, HttpError, HttpReply};
use oncl_update::{Channel, CoreRelease, FlavorPackage, Index, Package, Sha256};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use time::Duration as TimeDuration;

/// Something done while a request is being answered.
type Hook = Box<dyn FnOnce() + Send>;

/// Replies `200` with the body served at a URL, and refuses any other; records what was
/// asked: the URL, the size limit and whether only HTTPS was allowed. A hook runs during the
/// next request.
#[derive(Default)]
pub(crate) struct FakeTransport {
    bodies: Mutex<BTreeMap<String, Vec<u8>>>,
    asked: Mutex<Vec<(String, u64, bool)>>,
    hook: Mutex<Option<Hook>>,
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
        let hook = lock(&self.hook).take();
        if let Some(hook) = hook {
            hook();
        }
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
    Hold,
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

/// A daemon busy for its first `busy` looks, that cannot hold requests the first `refuse`
/// times.
struct FakeHost {
    log: Log,
    busy: AtomicUsize,
    refuse: AtomicUsize,
}

impl Host for FakeHost {
    fn busy(&self) -> bool {
        lock(&self.log).push(Event::Busy);
        self.busy
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
    }

    fn hold(&self) -> bool {
        lock(&self.log).push(Event::Hold);
        self.refuse
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_err()
    }

    fn release(&self) {}

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

/// How a fake updater behaves.
#[derive(Clone, Copy, Default)]
struct Fakes {
    busy: usize,
    refuse_hold: usize,
    fail_download: bool,
    fail_apply: bool,
    /// The health check's grace and settle time, in milliseconds; 60 s and 5 ms by default.
    health: Option<(u64, u64)>,
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
        self.updater_with(
            current,
            Fakes {
                busy,
                ..Fakes::default()
            },
        )
    }

    fn updater_with(&self, current: &str, fakes: Fakes) -> Updater {
        let (grace, settle) = fakes.health.unwrap_or((60_000, 5));
        Updater::new(
            UpdaterConfig {
                data_dir: self.dir.path().to_owned(),
                settings: self.dir.path().join("settings.json"),
                base: BASE.to_owned(),
                keys: vec![self.key.public.clone()],
                flavor: Flavor::WinX64,
                idle_poll: Duration::from_millis(1),
                health_grace: Duration::from_millis(grace),
                health_settle: Duration::from_millis(settle),
            },
            Arc::clone(&self.transport) as _,
            Box::new(FakeInstaller {
                current: v(current),
                log: Arc::clone(&self.log),
                fail_download: fakes.fail_download,
                fail_apply: fakes.fail_apply,
            }),
            Box::new(FakeHost {
                log: Arc::clone(&self.log),
                busy: AtomicUsize::new(fakes.busy),
                refuse: AtomicUsize::new(fakes.refuse_hold),
            }),
        )
    }

    /// The events since the last call.
    fn events(&self) -> Vec<Event> {
        std::mem::take(&mut *lock(&self.log))
    }

    /// Waits up to 10 s for `event`; the events until then.
    fn wait_for(&self, event: &Event) -> Vec<Event> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !lock(&self.log).contains(event) {
            assert!(
                Instant::now() < deadline,
                "no {event:?} in {:?}",
                lock(&self.log)
            );
            thread::sleep(Duration::from_millis(5));
        }
        self.events()
    }

    fn state(&self) -> State {
        State::load(self.dir.path()).unwrap()
    }

    fn pending(&self, from: &str, to: &str, started: Option<TimeDuration>, rollback: bool) {
        let mut state = self.state();
        let now = OffsetDateTime::now_utc();
        state.pending_health = Some(PendingHealth {
            from: v(from),
            to: v(to),
            applied: now - TimeDuration::minutes(5),
            started: started.map(|ago| now - ago),
            // A run in progress at the last start: one crash already counted.
            crashes: u32::from(started.is_some()),
            rollback,
            attempts: u32::from(rollback),
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

fn two_releases() -> Vec<CoreRelease> {
    vec![release("0.1.0", 100, false), release("0.2.0", 100, false)]
}

#[test]
fn an_update_is_found_downloaded_and_applied_once_the_daemon_is_idle() {
    let s = Sandbox::new();
    s.publish(3, two_releases());
    let u = s.updater_with(
        "0.1.0",
        Fakes {
            busy: 2,
            refuse_hold: 1,
            ..Fakes::default()
        },
    );

    let checked = u.check(false, None);
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

    // A sign request runs: the update waits for it. A request comes in just as the update
    // is to be applied: it waits again. Then new requests are held back, and it applies.
    let plan = checked.plan.unwrap();
    assert_eq!((plan.downgrade, plan.rollback), (false, false));
    assert_eq!(u.install(&plan, true), Installed::Applied);
    assert_eq!(
        s.events(),
        [
            Event::Download(v("0.2.0"), false),
            Event::Busy,
            Event::Busy,
            Event::Busy,
            Event::Hold,
            Event::Busy,
            Event::Hold,
            Event::Apply(v("0.2.0")),
        ]
    );
    let pending = s.state().pending_health.unwrap();
    assert_eq!((pending.from, pending.to), (v("0.1.0"), v("0.2.0")));
    assert_eq!((pending.started, pending.rollback), (None, false));

    // The same version found again is not told again.
    assert_eq!(u.check(false, None).status, available("0.2.0", true));
    assert_eq!(s.events(), []);
}

#[test]
fn an_update_no_longer_offered_after_the_wait_is_not_applied() {
    let s = Sandbox::new();
    s.publish(3, two_releases());
    let u = s.updater("0.1.0", 0);
    let plan = u.check(false, None).plan.unwrap();
    // Revoked while the update waited.
    s.publish(
        4,
        vec![release("0.1.0", 100, false), release("0.2.0", 100, true)],
    );
    assert_ne!(u.install(&plan, true), Installed::Applied);
    assert!(!s.events().iter().any(|e| matches!(e, Event::Apply(_))));
    assert_eq!(s.state().pending_health, None);
}

#[test]
fn the_new_version_confirms_its_health() {
    let s = Sandbox::new();
    s.pending("0.1.0", "0.2.0", None, false);
    let u = Arc::new(s.updater("0.2.0", 0));
    assert_eq!(u.startup(), Startup::Confirm);
    assert!(s.state().pending_health.unwrap().started.is_some());
    u.watch_health(|| true);
    assert_eq!(
        s.wait_for(&Event::Notice(Notice::Updated(v("0.2.0")))),
        [Event::Notice(Notice::Updated(v("0.2.0")))]
    );
    assert_eq!(s.state().pending_health, None);
    // Nothing more to confirm.
    u.confirm_health();
    assert_eq!(u.startup(), Startup::Normal);
    assert_eq!(s.events(), []);

    // Updated from a version that failed before (not a rollback): «Обновлено».
    let mut state = s.state();
    state.bad.insert(v("0.1.0"));
    state.save(s.dir.path()).unwrap();
    s.pending("0.1.0", "0.2.0", Some(TimeDuration::ZERO), false);
    u.confirm_health();
    assert_eq!(s.events(), [Event::Notice(Notice::Updated(v("0.2.0")))]);
}

#[test]
fn a_version_that_ended_before_proving_healthy_is_rolled_back_at_its_next_start() {
    let s = Sandbox::new();
    s.publish(4, two_releases());
    // Two runs in a row ended without confirming its health or ending cleanly: its event
    // loop or its servers did not come up, and the process died.
    s.pending("0.1.0", "0.2.0", None, false);
    assert_eq!(s.updater("0.2.0", 0).startup(), Startup::Confirm);
    assert_eq!(s.updater("0.2.0", 0).startup(), Startup::Confirm);
    assert_eq!(s.state().pending_health.unwrap().crashes, 1);
    let bad = s.updater("0.2.0", 0);
    let startup = bad.startup();
    assert_eq!(
        startup,
        Startup::RollBack {
            failed: v("0.2.0"),
            to: v("0.1.0"),
        }
    );
    assert!(s.state().bad.contains(&v("0.2.0")));

    // Installed back at once, before anything else starts: no waiting, even with updates
    // off.
    s.settings(false);
    assert_eq!(
        bad.roll_back_now(&v("0.2.0"), &v("0.1.0")),
        RollBack::Applied
    );
    assert_eq!(
        s.events(),
        [Event::Download(v("0.1.0"), true), Event::Apply(v("0.1.0")),]
    );
    let pending = s.state().pending_health.unwrap();
    assert_eq!((pending.from, pending.to), (v("0.2.0"), v("0.1.0")));
    assert!(pending.rollback);

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
    assert_eq!(old.check(false, None).status, UpdateStatus::UpToDate);
    assert!(s.state().bad.contains(&v("0.2.0")));
}

#[test]
fn a_quick_quit_is_not_a_crash() {
    let s = Sandbox::new();
    s.pending("0.1.0", "0.2.0", None, false);
    for _ in 0..3 {
        let u = s.updater("0.2.0", 0);
        assert_eq!(u.startup(), Startup::Confirm);
        // «Выход» within seconds, before the health check confirmed it.
        u.ended_cleanly();
        let pending = s.state().pending_health.unwrap();
        assert_eq!((pending.started, pending.crashes), (None, 0));
    }
    assert!(s.state().bad.is_empty());
}

#[test]
fn a_crash_then_a_healthy_run_rolls_nothing_back() {
    let s = Sandbox::new();
    s.pending("0.1.0", "0.2.0", None, false);
    assert_eq!(s.updater("0.2.0", 0).startup(), Startup::Confirm);
    // Crashed; then ended cleanly: the count starts again.
    assert_eq!(s.updater("0.2.0", 0).startup(), Startup::Confirm);
    assert_eq!(s.state().pending_health.unwrap().crashes, 1);
    s.updater("0.2.0", 0).ended_cleanly();
    assert_eq!(s.state().pending_health.unwrap().crashes, 0);
    // Crashed once more: still one in a row.
    assert_eq!(s.updater("0.2.0", 0).startup(), Startup::Confirm);
    let u = s.updater("0.2.0", 0);
    assert_eq!(u.startup(), Startup::Confirm);
    assert_eq!(s.state().pending_health.unwrap().crashes, 1);
    // This run proves healthy.
    u.confirm_health();
    assert_eq!(s.state().pending_health, None);
    assert!(s.state().bad.is_empty());
    assert_eq!(s.events(), [Event::Notice(Notice::Updated(v("0.2.0")))]);
}

#[test]
fn a_version_marked_bad_is_rolled_back_even_after_a_clean_end() {
    let s = Sandbox::new();
    s.pending("0.1.0", "0.2.0", None, false);
    let u = s.updater("0.2.0", 0);
    assert_eq!(u.startup(), Startup::Confirm);
    // The health check ran out while it ran; the user quit before the rollback applied.
    u.health_failed();
    u.ended_cleanly();
    assert_eq!(
        s.updater("0.2.0", 0).startup(),
        Startup::RollBack {
            failed: v("0.2.0"),
            to: v("0.1.0"),
        }
    );
}

#[test]
fn the_updater_thread_installs_what_check_now_found() {
    let s = Sandbox::new();
    s.publish(3, two_releases());
    let u = Arc::new(s.updater("0.1.0", 0));
    Arc::clone(&u).spawn(None);
    assert_eq!(u.check_now(None), available("0.2.0", true));
    let events = s.wait_for(&Event::Exit);
    assert_eq!(
        events,
        [
            Event::Download(v("0.2.0"), false),
            Event::Busy,
            Event::Hold,
            Event::Apply(v("0.2.0")),
            Event::Exit,
        ]
    );
}

#[test]
fn the_updater_thread_gives_up_a_rollback_without_a_package_and_checks_at_once() {
    let s = Sandbox::new();
    s.publish(
        4,
        vec![release("0.2.0", 100, false), release("0.3.0", 100, false)],
    );
    s.pending("0.1.0", "0.2.0", Some(TimeDuration::minutes(2)), false);
    let u = Arc::new(s.updater("0.2.0", 0));
    let Startup::RollBack { failed, to } = u.startup() else {
        panic!("no rollback");
    };
    Arc::clone(&u).spawn(Some((failed, to)));
    let events = s.wait_for(&Event::Exit);
    assert_eq!(
        events[0],
        Event::Notice(Notice::NoRollback {
            failed: v("0.2.0"),
            version: v("0.1.0"),
        })
    );
    assert!(events.contains(&Event::Apply(v("0.3.0"))), "{events:?}");
}

/// A new version whose health check runs out: rolled back while it runs, by the updater's
/// thread, with `healthy` saying what the daemon does.
fn rolled_back_while_running(healthy: impl Fn() -> bool + Send + 'static) {
    let s = Sandbox::new();
    s.publish(4, two_releases());
    s.pending("0.1.0", "0.2.0", None, false);
    let u = Arc::new(s.updater_with(
        "0.2.0",
        Fakes {
            health: Some((300, 100)),
            ..Fakes::default()
        },
    ));
    assert_eq!(u.startup(), Startup::Confirm);
    u.watch_health(healthy);
    Arc::clone(&u).spawn(None);
    let events = s.wait_for(&Event::Exit);
    assert!(
        events.contains(&Event::Download(v("0.1.0"), true)),
        "{events:?}"
    );
    assert!(events.contains(&Event::Apply(v("0.1.0"))), "{events:?}");
    assert!(s.state().bad.contains(&v("0.2.0")));
    let pending = s.state().pending_health.unwrap();
    assert_eq!(
        (pending.from, pending.to, pending.rollback),
        (v("0.2.0"), v("0.1.0"), true)
    );
}

#[test]
fn a_version_whose_event_loop_never_runs_is_rolled_back() {
    rolled_back_while_running(|| false);
}

#[test]
fn a_version_whose_servers_stop_is_rolled_back() {
    let serving = Arc::new(AtomicBool::new(true));
    let stops = Arc::clone(&serving);
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(30));
        stops.store(false, Ordering::SeqCst);
    });
    rolled_back_while_running(move || serving.load(Ordering::SeqCst));
}

#[test]
fn a_rollback_the_installer_refuses_is_given_up() {
    let s = Sandbox::new();
    s.publish(4, two_releases());
    s.pending("0.1.0", "0.2.0", Some(TimeDuration::minutes(2)), false);
    let failing = s.updater_with(
        "0.2.0",
        Fakes {
            fail_apply: true,
            ..Fakes::default()
        },
    );
    let Startup::RollBack { failed, to } = failing.startup() else {
        panic!("no rollback");
    };
    assert_eq!(failing.roll_back_now(&failed, &to), RollBack::GaveUp);
    let state = s.state();
    assert_eq!(state.pending_health, None);
    assert!(state.bad.contains(&v("0.2.0")));
    failing.tell_deferred();
    assert!(s.events().contains(&Event::Notice(Notice::RollbackFailed {
        failed: v("0.2.0"),
        version: v("0.1.0"),
    })));
    // The bad version starts normally and serves.
    assert_eq!(s.updater("0.2.0", 0).startup(), Startup::Normal);
}

#[test]
fn a_rollback_the_installer_does_not_finish_is_tried_three_times() {
    let s = Sandbox::new();
    s.publish(4, two_releases());
    s.pending("0.1.0", "0.2.0", Some(TimeDuration::minutes(2)), false);
    // Each time the installer takes the rollback, fails after the exit and starts the bad
    // version again.
    for attempt in 1..=ROLLBACK_ATTEMPTS {
        let bad = s.updater("0.2.0", 0);
        let Startup::RollBack { failed, to } = bad.startup() else {
            panic!("no rollback at attempt {attempt}");
        };
        assert_eq!(bad.roll_back_now(&failed, &to), RollBack::Applied);
        assert_eq!(s.state().pending_health.unwrap().attempts, attempt);
    }
    assert_eq!(
        s.events()
            .iter()
            .filter(|e| matches!(e, Event::Apply(_)))
            .count(),
        3
    );
    // No fourth attempt: the bad version starts normally, and the user is told once.
    let bad = s.updater("0.2.0", 0);
    assert_eq!(bad.startup(), Startup::Normal);
    let state = s.state();
    assert_eq!(state.pending_health, None);
    assert!(state.bad.contains(&v("0.2.0")));
    assert_eq!(s.events(), []);
    bad.tell_deferred();
    bad.tell_deferred();
    assert_eq!(
        s.events(),
        [Event::Notice(Notice::RollbackFailed {
            failed: v("0.2.0"),
            version: v("0.1.0"),
        })]
    );
    assert_eq!(s.updater("0.2.0", 0).startup(), Startup::Normal);
}

#[test]
fn a_rollback_the_index_has_no_package_for_is_given_up_and_the_checks_go_on() {
    let s = Sandbox::new();
    // 0.1.0 is gone from the index; 0.3.0 fixes 0.2.0.
    s.publish(
        4,
        vec![release("0.2.0", 100, false), release("0.3.0", 100, false)],
    );
    s.pending("0.1.0", "0.2.0", Some(TimeDuration::minutes(2)), false);
    let u = s.updater("0.2.0", 0);
    let Startup::RollBack { failed, to } = u.startup() else {
        panic!("no rollback");
    };
    assert_eq!(u.roll_back_now(&failed, &to), RollBack::GaveUp);
    let state = s.state();
    assert_eq!(state.pending_health, None);
    assert!(state.bad.contains(&v("0.2.0")));
    // Told once, when the updater's thread starts (the tray is not up yet).
    assert_eq!(s.events(), []);
    let notice = Notice::NoRollback {
        failed: v("0.2.0"),
        version: v("0.1.0"),
    };
    assert_eq!(*lock(&u.deferred), std::slice::from_ref(&notice));
    u.tell_deferred();
    assert_eq!(s.events(), [Event::Notice(notice.clone())]);
    // No rollback any more at the next start; the next check offers the fix.
    assert_eq!(s.updater("0.2.0", 0).startup(), Startup::Normal);
    assert_eq!(u.check(false, None).status, available("0.3.0", true));

    // Given up while running: told at once.
    s.pending("0.1.0", "0.2.0", Some(TimeDuration::minutes(2)), false);
    assert_eq!(u.roll_back(&failed, &to, true), RollBack::GaveUp);
    assert!(s.events().contains(&Event::Notice(notice)));
}

#[test]
fn an_unreadable_index_retries_the_rollback() {
    let s = Sandbox::new();
    s.pending("0.1.0", "0.2.0", Some(TimeDuration::minutes(2)), false);
    let u = s.updater("0.2.0", 0);
    let Startup::RollBack { failed, to } = u.startup() else {
        panic!("no rollback");
    };
    assert_eq!(u.roll_back_now(&failed, &to), RollBack::Retry);
    assert!(s.state().pending_health.is_some());
}

#[test]
fn nothing_is_rolled_back_to_a_version_that_failed_too() {
    let s = Sandbox::new();
    let mut state = s.state();
    state.bad.insert(v("0.2.0"));
    state.save(s.dir.path()).unwrap();
    // The rollback from 0.2.0 to 0.1.0 did not prove healthy either.
    s.pending("0.2.0", "0.1.0", Some(TimeDuration::minutes(2)), true);
    let u = s.updater("0.1.0", 0);
    assert_eq!(u.startup(), Startup::Normal);
    let state = s.state();
    assert_eq!(state.pending_health, None);
    assert!(state.bad.contains(&v("0.1.0")) && state.bad.contains(&v("0.2.0")));
}

#[test]
fn an_update_that_did_not_install_is_forgotten() {
    let s = Sandbox::new();
    s.pending("0.1.0", "0.2.0", None, false);
    let u = s.updater("0.1.0", 0);
    assert_eq!(u.startup(), Startup::Normal);
    assert_eq!(s.state().pending_health, None);
    assert!(s.state().bad.is_empty());
}

#[test]
fn a_check_does_not_undo_what_other_threads_write_meanwhile() {
    let s = Sandbox::new();
    s.publish(9, two_releases());
    let u = s.updater("0.1.0", 0);
    // While the index downloads, an update is recorded (another thread's `install`).
    let dir = s.dir.path().to_owned();
    *lock(&s.transport.hook) = Some(Box::new(move || {
        let mut state = State::load(&dir).unwrap();
        state.pending_health = Some(PendingHealth {
            from: v("0.1.0"),
            to: v("0.2.0"),
            applied: OffsetDateTime::now_utc(),
            started: None,
            crashes: 0,
            rollback: false,
            attempts: 0,
        });
        state.save(&dir).unwrap();
    }));
    u.check_now(None);
    let state = s.state();
    assert_eq!(state.last_seq[&Channel::Stable], 9);
    assert!(state.pending_health.is_some(), "the recorded update stays");

    // While it downloads again (a new seq), the health is confirmed.
    s.publish(10, two_releases());
    let dir = s.dir.path().to_owned();
    *lock(&s.transport.hook) = Some(Box::new(move || {
        let mut state = State::load(&dir).unwrap();
        state.pending_health = None;
        state.save(&dir).unwrap();
    }));
    u.check_now(None);
    let state = s.state();
    assert_eq!(state.last_seq[&Channel::Stable], 10);
    assert_eq!(state.pending_health, None, "the confirmation stays");
}

#[test]
fn a_refused_index_changes_nothing_and_is_not_notified() {
    let s = Sandbox::new();
    let u = s.updater("0.1.0", 0);

    // Another key.
    s.publish_by(&Key::new(), 7, two_releases(), TimeDuration::days(1));
    let checked = u.check(false, None);
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
    s.publish(7, two_releases());
    let mut body = lock(&s.transport.bodies)[INDEX].clone();
    body[10] ^= 1;
    s.transport.serve(INDEX, &body);
    assert!(matches!(
        u.check(false, None).status,
        UpdateStatus::Failed(_)
    ));

    // An older seq than one accepted.
    s.publish(7, two_releases());
    assert_eq!(u.check(false, None).status, available("0.2.0", true));
    s.publish(6, two_releases());
    let checked = u.check(false, None);
    let UpdateStatus::Failed(e) = &checked.status else {
        panic!("{:?}", checked.status);
    };
    assert!(e.contains("older than the last seen 7"), "{e}");
    // The same seq again is the same index: accepted.
    s.publish(7, two_releases());
    assert_eq!(u.check(false, None).status, available("0.2.0", true));

    // Not signed again within 30 days.
    s.publish_by(&s.key, 8, two_releases(), TimeDuration::days(31));
    let UpdateStatus::Failed(e) = u.check(false, None).status else {
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
    let checked = u.check(false, None);
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
    let checked = u.check(false, None);
    assert_eq!(checked.status, available("0.1.0", true));
    let plan = checked.plan.unwrap();
    assert!(plan.downgrade && !plan.rollback);
    assert_eq!(u.install(&plan, true), Installed::Applied);
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
    let checked = u.check(false, None);
    assert_eq!(checked.status, UpdateStatus::UpToDate);
    assert!(checked.plan.is_none());
    assert_eq!(s.events(), []);
}

#[test]
fn with_updates_off_only_a_check_now_looks_and_nothing_is_installed() {
    let s = Sandbox::new();
    s.settings(false);
    s.publish(5, two_releases());
    let u = s.updater("0.1.0", 0);
    let checked = u.check(false, None);
    assert_eq!(checked.status, UpdateStatus::NotChecked);
    assert!(s.transport.asked().is_empty());

    assert_eq!(u.check_now(None), available("0.2.0", false));
    assert!(lock(&u.queue).plan.is_none());
    assert_eq!(s.events(), [], "the window shows it; no notification");

    // The form's unsaved settings: checked with them, but nothing is to be installed
    // until they are saved.
    let form = UpdateSettings {
        enabled: true,
        channel: Channel::Stable,
    };
    assert_eq!(u.check_now(Some(form)), available("0.2.0", false));
    assert!(lock(&u.queue).plan.is_none());
    s.settings(true);
    assert_eq!(u.check_now(Some(form)), available("0.2.0", true));
    let far = SystemTime::now() + Duration::from_secs(3600);
    let Job::Plan(plan) = u.next(far) else {
        panic!("no plan");
    };
    // Turned off again before it applied: not applied.
    s.settings(false);
    assert_ne!(u.install(&plan, true), Installed::Applied);
    assert_eq!(s.state().pending_health, None);
    s.settings(true);
    assert_eq!(u.install(&plan, true), Installed::Applied);
}

#[test]
fn a_failed_download_or_apply_leaves_nothing_pending() {
    let s = Sandbox::new();
    s.publish(5, two_releases());
    let u = s.updater_with(
        "0.1.0",
        Fakes {
            fail_download: true,
            ..Fakes::default()
        },
    );
    let plan = u.check(false, None).plan.unwrap();
    assert_ne!(u.install(&plan, true), Installed::Applied);
    assert!(matches!(u.status(), UpdateStatus::Failed(e) if e.contains("sha256")));
    assert_eq!(s.state().pending_health, None);

    let u = s.updater_with(
        "0.1.0",
        Fakes {
            fail_apply: true,
            ..Fakes::default()
        },
    );
    assert_ne!(u.install(&plan, true), Installed::Applied);
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
    assert_eq!(u.check(false, None).status, UpdateStatus::UpToDate);
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
    assert_eq!(off.check_now(None), UpdateStatus::NoKeys);
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
