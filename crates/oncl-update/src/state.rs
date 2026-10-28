//! `<data>/update/state.json`: what the updater keeps between runs.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

use oncl_pki::fsutil::{Access, write_atomically};
use semver::Version;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::index::Channel;

/// The updater's state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The highest `seq` accepted, by channel: [`crate::verify()`] refuses an index below it.
    #[serde(default)]
    pub last_seq: BTreeMap<Channel, u64>,
    /// This installation's random id, for its rollout buckets ([`crate::rollout_bucket`]);
    /// never sent anywhere. Drawn anew if missing.
    #[serde(with = "crate::hex::array", default = "random_install_id")]
    pub install_id: [u8; 16],
    /// Versions that failed their health check here; never offered again.
    #[serde(default)]
    pub bad: BTreeSet<Version>,
    /// An applied update whose new version has not yet proven healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_health: Option<PendingHealth>,
}

/// An update applied, from [`PendingHealth::from`] to [`PendingHealth::to`], not yet
/// confirmed by the new version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingHealth {
    /// The version before the update.
    pub from: Version,
    /// The version after it.
    pub to: Version,
    /// When the update was applied.
    #[serde(with = "time::serde::rfc3339")]
    pub applied: OffsetDateTime,
    /// When the run of the new version in progress started; cleared when it ends cleanly
    /// (asked to stop). Still set at a start means the run before crashed or hung.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub started: Option<OffsetDateTime>,
    /// Consecutive runs of the new version that crashed or hung before confirming its
    /// health; a clean end resets it.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub crashes: u32,
    /// The update goes back from a version that failed its health check.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rollback: bool,
    /// For a rollback: how many times it was handed to the installer.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub attempts: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl State {
    /// A state with nothing seen yet and a new random install id.
    pub fn fresh() -> State {
        State {
            last_seq: BTreeMap::new(),
            install_id: random_install_id(),
            bad: BTreeSet::new(),
            pending_health: None,
        }
    }

    /// `<data_dir>/update/state.json`.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("update").join("state.json")
    }

    /// The state stored in `data_dir`; [`State::fresh`] if there is none (save it to keep
    /// its install id). Missing members take their defaults, unknown ones are ignored.
    ///
    /// # Errors
    ///
    /// The file cannot be read, or is not a state ([`io::ErrorKind::InvalidData`]).
    pub fn load(data_dir: &Path) -> io::Result<State> {
        match std::fs::read(State::path(data_dir)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(State::fresh()),
            Err(e) => Err(e),
        }
    }

    /// Stores the state in `data_dir`, creating `update/` if needed; the file is replaced
    /// atomically ([`write_atomically`]).
    ///
    /// # Errors
    ///
    /// Any I/O error.
    pub fn save(&self, data_dir: &Path) -> io::Result<()> {
        let path = State::path(data_dir);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut body = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        body.push(b'\n');
        write_atomically(&path, &body, Access::Default)
    }
}

fn random_install_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).expect("operating system RNG failed");
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::macros::datetime;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn missing_file_is_a_fresh_state() {
        let dir = tempfile::tempdir().unwrap();
        let a = State::load(dir.path()).unwrap();
        assert!(a.last_seq.is_empty() && a.bad.is_empty() && a.pending_health.is_none());
        assert!(
            !dir.path().join("update").exists(),
            "loading writes nothing"
        );
        let b = State::load(dir.path()).unwrap();
        assert_ne!(a.install_id, b.install_id, "random until saved");
    }

    #[test]
    fn saved_state_loads_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = State::fresh();
        state.last_seq.insert(Channel::Beta, 42);
        state.last_seq.insert(Channel::Stable, 7);
        state.bad.insert(v("0.2.0-beta.1"));
        state.pending_health = Some(PendingHealth {
            from: v("0.1.0"),
            to: v("0.2.0"),
            applied: datetime!(2026-10-27 10:00 UTC),
            started: None,
            rollback: false,
            crashes: 0,
            attempts: 0,
        });
        state.save(dir.path()).unwrap();
        assert_eq!(State::load(dir.path()).unwrap(), state);

        let path = dir.path().join("update").join("state.json");
        assert_eq!(State::path(dir.path()), path);
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["last_seq"], json!({"stable": 7, "beta": 42}));
        assert_eq!(value["install_id"], crate::hex::encode(&state.install_id));
        assert_eq!(value["bad"], json!(["0.2.0-beta.1"]));
        assert_eq!(
            value["pending_health"],
            json!({"from": "0.1.0", "to": "0.2.0", "applied": "2026-10-27T10:00:00Z"})
        );
        if let Some(pending) = &mut state.pending_health {
            pending.started = Some(datetime!(2026-10-27 10:01 UTC));
            pending.rollback = true;
            pending.crashes = 1;
            pending.attempts = 2;
        }
        state.save(dir.path()).unwrap();
        assert_eq!(State::load(dir.path()).unwrap(), state);
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["pending_health"]["rollback"], json!(true));
        assert_eq!(value["pending_health"]["crashes"], json!(1));

        // Saving again replaces the file; no temporary file stays.
        state.pending_health = None;
        state.save(dir.path()).unwrap();
        assert_eq!(State::load(dir.path()).unwrap(), state);
        let names: Vec<_> = std::fs::read_dir(dir.path().join("update"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["state.json"]);
    }

    #[test]
    fn missing_members_default_and_unknown_ones_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("update")).unwrap();
        let id = "000102030405060708090a0b0c0d0e0f";
        std::fs::write(
            State::path(dir.path()),
            json!({"install_id": id, "later": 1}).to_string(),
        )
        .unwrap();
        let state = State::load(dir.path()).unwrap();
        assert_eq!(state.install_id, std::array::from_fn(|i| i as u8));
        assert!(state.last_seq.is_empty() && state.bad.is_empty());

        std::fs::write(State::path(dir.path()), "{}").unwrap();
        State::load(dir.path()).unwrap();
    }

    #[test]
    fn corrupt_state_is_invalid_data() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("update")).unwrap();
        for body in [
            "not json",
            r#"{"install_id": "short"}"#,
            r#"{"last_seq": {"nightly": 1}}"#,
            r#"{"bad": ["1.0"]}"#,
        ] {
            std::fs::write(State::path(dir.path()), body).unwrap();
            let err = State::load(dir.path()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{body}");
        }
    }
}
