//! The hashes recorded for versions already submitted to WinGet.
//!
//! A release asset can be replaced after it is published; the manifest of a version that
//! WinGet already knows must then not silently take the new hash. The maintainer commits an
//! entry for a version when its manifest is submitted (`winget-evidence.json` has it ready
//! made); from then on `generate` refuses the same version with another hash.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use super::Arch;

/// `winget/hash-ledger.json`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    /// Version → architecture (`x64`, `x86`) → lowercase SHA-256 of the installer submitted.
    pub versions: BTreeMap<String, BTreeMap<String, String>>,
}

/// A recorded version whose published bytes are not the recorded ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashChanged {
    /// The version.
    pub version: String,
    /// The architecture.
    pub arch: Arch,
    /// What was recorded.
    pub recorded: String,
    /// What the release serves now.
    pub now: String,
}

impl fmt::Display for HashChanged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "version {} was already submitted with the {} installer {}, the release now serves {}: a published version's installer is never replaced; release a new version",
            self.version, self.arch, self.recorded, self.now
        )
    }
}

impl std::error::Error for HashChanged {}

impl Ledger {
    /// Reads the ledger.
    ///
    /// # Errors
    ///
    /// The text is not a ledger.
    pub fn parse(json: &str) -> anyhow::Result<Ledger> {
        serde_json::from_str(json).context("the hash ledger is not valid")
    }

    /// Fails if `version` is recorded with another hash than `sha256` for any architecture.
    ///
    /// # Errors
    ///
    /// [`HashChanged`].
    pub fn check(&self, version: &str, sha256: &[(Arch, String)]) -> Result<(), HashChanged> {
        let Some(recorded) = self.versions.get(version) else {
            return Ok(());
        };
        for (arch, now) in sha256 {
            if let Some(before) = recorded.get(&arch.to_string())
                && before != now
            {
                return Err(HashChanged {
                    version: version.to_owned(),
                    arch: *arch,
                    recorded: before.clone(),
                    now: now.clone(),
                });
            }
        }
        Ok(())
    }

    /// The entry that records `version`.
    pub fn entry(version: &str, sha256: &[(Arch, String)]) -> Ledger {
        Ledger {
            versions: BTreeMap::from([(
                version.to_owned(),
                sha256
                    .iter()
                    .map(|(arch, sha)| (arch.to_string(), sha.clone()))
                    .collect(),
            )]),
        }
    }
}
