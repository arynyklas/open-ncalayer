//! The management endpoint over the real transport: a maintainer holds the host while its
//! connection lives, and the host is let go however that connection ends.

use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use oncl_ipc::maintenance::{self, Client, Host, Reply};
use oncl_ipc::{Endpoint, bind, connect, endpoint, read_frame, write_frame};
use tempfile::TempDir;

/// Points `XDG_RUNTIME_DIR` at a private test directory, as the transport's own tests do.
#[cfg(unix)]
fn isolate_runtime_dir() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::sync::LazyLock;

    static ONCE: LazyLock<()> = LazyLock::new(|| {
        let probe = tempfile::tempdir().expect("probe tempdir");
        let uid = std::fs::metadata(probe.path())
            .expect("probe metadata")
            .uid();
        let dir = std::env::temp_dir().join(format!("oncl-ipc-rt-{uid}"));
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            assert_eq!(e.kind(), ErrorKind::AlreadyExists, "{}: {e}", dir.display());
        }
        // SAFETY: the `LazyLock` blocks every other test until the variable is set.
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", &dir) };
    });
    *ONCE;
}

fn unique_dir() -> TempDir {
    #[cfg(unix)]
    isolate_runtime_dir();
    tempfile::tempdir().expect("tempdir")
}

/// A host that is idle or busy as the test says and counts what it is asked.
#[derive(Default)]
struct FakeHost {
    busy: AtomicBool,
    held: AtomicBool,
    holds: AtomicUsize,
    releases: AtomicUsize,
}

impl Host for FakeHost {
    fn hold(&self) -> bool {
        if self.busy.load(Ordering::SeqCst) {
            return false;
        }
        let taken = self
            .held
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if taken {
            self.holds.fetch_add(1, Ordering::SeqCst);
        }
        taken
    }

    fn release(&self) {
        self.releases.fetch_add(1, Ordering::SeqCst);
        self.held.store(false, Ordering::SeqCst);
    }

    fn restart_args(&self) -> Vec<String> {
        vec!["run".into(), "--allow-no-wss".into()]
    }
}

/// The management server of a fresh data directory on `host`; the lease ends after
/// `max_lease` at the latest.
async fn serving(host: &Arc<FakeHost>, max_lease: Duration) -> (TempDir, Endpoint) {
    let dir = unique_dir();
    let ep = maintenance::endpoint(dir.path()).expect("endpoint");
    let listener = bind(&ep).await.expect("bind");
    tokio::spawn(maintenance::serve(listener, Arc::clone(host), max_lease));
    (dir, ep)
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn the_management_endpoint_is_not_the_relays() {
    let dir = unique_dir();
    let relay = endpoint(dir.path()).unwrap();
    let management = maintenance::endpoint(dir.path()).unwrap();
    assert_ne!(relay, management);
    assert_ne!(relay.to_string(), management.to_string());
    assert_eq!(management, maintenance::endpoint(dir.path()).unwrap());
    let other = unique_dir();
    assert_ne!(management, maintenance::endpoint(other.path()).unwrap());
    // Both can be served at once.
    let _relay = bind(&relay).await.expect("relay");
    let _management = bind(&management).await.expect("management");
}

#[tokio::test]
async fn an_idle_host_grants_the_hold_and_the_release_lets_go() {
    let host = Arc::new(FakeHost::default());
    let (_dir, ep) = serving(&host, Duration::from_secs(60)).await;
    let mut client = Client::connect(&ep).await.expect("connect");
    let Reply::Granted { restart, pid } = client.hold().await.expect("hold") else {
        panic!("an idle host refused the hold");
    };
    assert_eq!(restart, ["run", "--allow-no-wss"]);
    assert_eq!(pid, std::process::id(), "the server is this test process");
    assert!(host.held.load(Ordering::SeqCst));
    client.release().await.expect("release");
    assert!(!host.held.load(Ordering::SeqCst));
    assert_eq!(host.holds.load(Ordering::SeqCst), 1);
    assert_eq!(host.releases.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_busy_host_is_busy_and_nothing_is_held() {
    let host = Arc::new(FakeHost::default());
    host.busy.store(true, Ordering::SeqCst);
    let (_dir, ep) = serving(&host, Duration::from_secs(60)).await;
    let mut client = Client::connect(&ep).await.expect("connect");
    assert_eq!(client.hold().await.expect("hold"), Reply::Busy);
    assert!(!host.held.load(Ordering::SeqCst));
    assert_eq!(
        host.releases.load(Ordering::SeqCst),
        0,
        "nothing to give back"
    );
    // The same connection asks again once the host is idle.
    host.busy.store(false, Ordering::SeqCst);
    assert!(matches!(
        client.hold().await.expect("hold"),
        Reply::Granted { .. }
    ));
}

#[tokio::test]
async fn a_second_maintainer_is_busy_while_the_first_holds() {
    let host = Arc::new(FakeHost::default());
    let (_dir, ep) = serving(&host, Duration::from_secs(60)).await;
    let mut first = Client::connect(&ep).await.expect("connect");
    assert!(matches!(first.hold().await.unwrap(), Reply::Granted { .. }));
    let mut second = Client::connect(&ep).await.expect("connect");
    assert_eq!(second.hold().await.unwrap(), Reply::Busy);
    // The refused one must not give the first one's hold back, whether it asks to release
    // or just goes away.
    second.release().await.expect("release without a hold");
    drop(second);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(host.held.load(Ordering::SeqCst), "the first hold is kept");
    assert_eq!(host.releases.load(Ordering::SeqCst), 0);
    first.release().await.unwrap();
    assert!(!host.held.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_maintainer_that_disappears_does_not_leave_the_host_held() {
    let host = Arc::new(FakeHost::default());
    let (_dir, ep) = serving(&host, Duration::from_secs(60)).await;
    let mut client = Client::connect(&ep).await.expect("connect");
    assert!(matches!(
        client.hold().await.unwrap(),
        Reply::Granted { .. }
    ));
    // The installer is killed: its end of the connection closes without a release.
    drop(client);
    until("the host stays held after its maintainer died", || {
        !host.held.load(Ordering::SeqCst)
    })
    .await;
    assert_eq!(host.releases.load(Ordering::SeqCst), 1);
    // Another maintainer can hold at once.
    let mut next = Client::connect(&ep).await.expect("connect");
    assert!(matches!(next.hold().await.unwrap(), Reply::Granted { .. }));
}

#[tokio::test]
async fn a_lease_that_is_never_given_back_ends_by_itself() {
    let host = Arc::new(FakeHost::default());
    let (_dir, ep) = serving(&host, Duration::from_millis(300)).await;
    let mut client = Client::connect(&ep).await.expect("connect");
    assert!(matches!(
        client.hold().await.unwrap(),
        Reply::Granted { .. }
    ));
    // A maintainer that hangs holds nothing for ever.
    until("the lease did not end", || {
        !host.held.load(Ordering::SeqCst)
    })
    .await;
    let err = client.hold().await.expect_err("the connection is closed");
    assert!(
        matches!(
            err.kind(),
            ErrorKind::UnexpectedEof
                | ErrorKind::BrokenPipe
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn what_is_not_a_request_is_refused_and_holds_nothing() {
    let host = Arc::new(FakeHost::default());
    let (_dir, ep) = serving(&host, Duration::from_secs(60)).await;
    for garbage in [&b""[..], b"hello", b"ONCLM\x09\x01", b"ONCLM\x01\x7f"] {
        let mut stream = connect(&ep).await.expect("connect");
        write_frame(&mut stream, garbage).await.expect("write");
        let answer = read_frame(&mut stream).await;
        // A refusal frame, or the connection closed: never a grant. A reply is the magic,
        // the version, then the status: 1 is a grant.
        if let Ok(Some(frame)) = answer {
            assert_ne!(frame.get(6), Some(&1), "{garbage:?} was granted");
        }
    }
    assert!(!host.held.load(Ordering::SeqCst));
    assert_eq!(host.holds.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_hold_is_polled_until_the_host_is_idle_or_the_time_is_up() {
    let host = Arc::new(FakeHost::default());
    host.busy.store(true, Ordering::SeqCst);
    let (_dir, ep) = serving(&host, Duration::from_secs(60)).await;
    let mut client = Client::connect(&ep).await.expect("connect");
    let started = Instant::now();
    let reply = client
        .hold_within(Duration::from_millis(300), Duration::from_millis(20))
        .await
        .expect("a busy host is an answer, not an error");
    assert_eq!(reply, Reply::Busy);
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(!host.held.load(Ordering::SeqCst), "a timeout holds nothing");

    let freed = Arc::clone(&host);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        freed.busy.store(false, Ordering::SeqCst);
    });
    let reply = client
        .hold_within(Duration::from_secs(20), Duration::from_millis(20))
        .await
        .expect("hold");
    assert!(matches!(reply, Reply::Granted { .. }));
    assert!(host.held.load(Ordering::SeqCst));
}

#[tokio::test]
async fn without_a_server_the_connection_fails_clearly() {
    let dir = unique_dir();
    let ep = maintenance::endpoint(dir.path()).unwrap();
    let err = Client::connect(&ep).await.expect_err("no server");
    assert!(
        matches!(
            err.kind(),
            ErrorKind::NotFound | ErrorKind::ConnectionRefused
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn clients_that_vanish_while_connecting_do_not_end_the_endpoint() {
    let host = Arc::new(FakeHost::default());
    let (_dir, ep) = serving(&host, Duration::from_secs(60)).await;
    // Connect and drop at once, again and again: whatever that does to the listener, the
    // endpoint keeps serving the next honest client.
    for _ in 0..200 {
        drop(connect(&ep).await);
    }
    let mut client = Client::connect(&ep).await.expect("connect");
    assert!(matches!(
        client.hold().await.expect("hold"),
        Reply::Granted { .. }
    ));
}

/// A listener whose first accepts fail, as a transient transport error does.
struct Flaky {
    inner: oncl_ipc::IpcListener,
    failures: usize,
}

impl maintenance::Accept for Flaky {
    async fn accept(&mut self) -> std::io::Result<oncl_ipc::IpcStream> {
        if self.failures > 0 {
            self.failures -= 1;
            return Err(std::io::Error::other("injected accept error"));
        }
        self.inner.accept().await
    }
}

#[tokio::test]
async fn a_failed_accept_does_not_end_the_endpoint() {
    let host = Arc::new(FakeHost::default());
    let dir = unique_dir();
    let ep = maintenance::endpoint(dir.path()).expect("endpoint");
    let listener = Flaky {
        inner: bind(&ep).await.expect("bind"),
        failures: 3,
    };
    let served = tokio::spawn(maintenance::serve_on(
        listener,
        Arc::clone(&host),
        Duration::from_secs(60),
    ));
    let mut client = Client::connect(&ep).await.expect("connect");
    assert!(matches!(
        client.hold().await.expect("hold"),
        Reply::Granted { .. }
    ));
    assert!(!served.is_finished(), "the endpoint stopped");
}
