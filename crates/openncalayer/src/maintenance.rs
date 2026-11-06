//! What the running daemon answers to a maintainer on the management endpoint
//! ([`oncl_ipc::maintenance`]): the decision of its own updater.
//!
//! A maintainer that asks to hold the program gets exactly what [`crate::update::Host::hold`]
//! gives the updater: new requests are held back first, and only then is it looked at
//! whether a request is being answered or ended within the quiet time, or a window is open.
//! There is no second way to decide whether the program may be replaced; the gate is held by
//! one of them at a time, so the updater and an installer never replace it together.

use std::ffi::OsString;
use std::sync::Arc;

use oncl_ipc::maintenance::Host as IpcHost;

use crate::update::Host;

/// The only arguments a daemon is started again with: `run` and the flags of `run` that say
/// how it serves, in the order they were given. What the daemon was started with is not
/// repeated beyond that, so a maintainer cannot make the program run anything else.
const RUN_FLAGS: [&str; 2] = ["--allow-no-wss", "--no-tray"];

/// The arguments (after the program's name) to start the daemon again as it runs now, from
/// the `args` it was started with. A daemon that `tools` started is started as the relay
/// starts one.
pub fn restart_args(args: &[OsString]) -> Vec<String> {
    let mut restart = vec!["run".to_owned()];
    match args.first().and_then(|command| command.to_str()) {
        Some("run") => {
            for flag in &args[1..] {
                if let Some(flag) = flag.to_str().filter(|flag| RUN_FLAGS.contains(flag))
                    && !restart.iter().any(|known| known == flag)
                {
                    restart.push(flag.to_owned());
                }
            }
        }
        Some("tools") => restart.push("--allow-no-wss".to_owned()),
        _ => {}
    }
    restart
}

/// The daemon as the management endpoint holds it.
pub struct Maintenance {
    host: Arc<dyn Host>,
    restart: Vec<String>,
}

impl Maintenance {
    /// The daemon whose updater decides through `host`; `restart` are the arguments to start
    /// it again with ([`restart_args`]).
    pub fn new(host: Arc<dyn Host>, restart: Vec<String>) -> Maintenance {
        Maintenance { host, restart }
    }
}

impl IpcHost for Maintenance {
    fn hold(&self) -> bool {
        self.host.hold()
    }

    fn release(&self) {
        self.host.release();
    }

    fn restart_args(&self) -> Vec<String> {
        self.restart.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use oncl_ipc::maintenance::{self as ipc, Client, Reply};

    use super::*;
    use crate::update::{Host, Notice};

    /// The updater's host, as a test makes it idle or busy.
    #[derive(Default)]
    struct Updater {
        busy: AtomicBool,
        held: AtomicBool,
        holds: AtomicUsize,
        releases: AtomicUsize,
    }

    impl Host for Updater {
        fn busy(&self) -> bool {
            self.busy.load(Ordering::SeqCst) || self.held.load(Ordering::SeqCst)
        }

        fn hold(&self) -> bool {
            self.holds.fetch_add(1, Ordering::SeqCst);
            if self.busy.load(Ordering::SeqCst) {
                return false;
            }
            self.held
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        }

        fn release(&self) {
            self.releases.fetch_add(1, Ordering::SeqCst);
            self.held.store(false, Ordering::SeqCst);
        }

        fn notify(&self, _notice: Notice) {}

        fn exit(&self) {}
    }

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_daemon_is_started_again_only_as_run_with_the_flags_it_knows() {
        for (given, expected) in [
            (&[][..], &["run"][..]),
            (&["run"], &["run"]),
            (&["run", "--allow-no-wss"], &["run", "--allow-no-wss"]),
            (
                &["run", "--no-tray", "--allow-no-wss"],
                &["run", "--no-tray", "--allow-no-wss"],
            ),
            // A daemon that `tools` started is started as the relay starts it.
            (&["tools"], &["run", "--allow-no-wss"]),
            // Nothing a flag of another command or a stray argument could add is repeated.
            (&["run", "--evil", "x"], &["run"]),
            (&["tls", "issue"], &["run"]),
            (
                &["run", "--allow-no-wss", "--allow-no-wss"],
                &["run", "--allow-no-wss"],
            ),
        ] {
            assert_eq!(restart_args(&args(given)), expected, "{given:?}");
        }
    }

    #[tokio::test]
    async fn the_management_endpoint_decides_with_the_updaters_host() {
        let updater = Arc::new(Updater::default());
        let dir = tempfile::tempdir().unwrap();
        let ep = ipc::endpoint(dir.path()).unwrap();
        let listener = oncl_ipc::bind(&ep).await.unwrap();
        let host = Arc::new(Maintenance::new(
            Arc::clone(&updater) as Arc<dyn Host>,
            restart_args(&args(&["run", "--no-tray"])),
        ));
        tokio::spawn(ipc::serve(listener, host, Duration::from_secs(60)));

        updater.busy.store(true, Ordering::SeqCst);
        let mut installer = Client::connect(&ep).await.unwrap();
        assert_eq!(installer.hold().await.unwrap(), Reply::Busy);
        assert_eq!(
            updater.holds.load(Ordering::SeqCst),
            1,
            "the updater's own decision"
        );
        assert_eq!(updater.releases.load(Ordering::SeqCst), 0);

        updater.busy.store(false, Ordering::SeqCst);
        let Reply::Granted { restart, .. } = installer.hold().await.unwrap() else {
            panic!("an idle host refused");
        };
        assert_eq!(restart, ["run", "--no-tray"]);
        assert!(updater.held.load(Ordering::SeqCst));
        // While the installer holds, the updater's own wait sees a busy program.
        assert!(updater.busy());
        installer.release().await.unwrap();
        assert!(!updater.held.load(Ordering::SeqCst));
        assert_eq!(updater.releases.load(Ordering::SeqCst), 1);
    }
}

#[cfg(all(test, windows))]
mod data_dir_tests {
    /// What the installer entry computes is what the daemon's own `Paths::detect` computes:
    /// the management endpoint of one is the endpoint the other serves.
    #[test]
    fn the_installer_finds_the_data_directory_the_daemon_uses() {
        let daemon = crate::Paths::detect().unwrap().data;
        assert_eq!(oncl_winget_setup::data_dir().unwrap(), daemon);
        assert_eq!(
            oncl_ipc::maintenance::endpoint(&oncl_winget_setup::data_dir().unwrap()).unwrap(),
            oncl_ipc::maintenance::endpoint(&daemon).unwrap()
        );
    }
}
