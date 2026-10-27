//! Which version of the core an installation moves to.

use std::collections::BTreeSet;

use semver::Version;
use sha2::Digest;

use crate::index::{CoreRelease, Flavor, FlavorPackage, Index, Package};

/// The version to move to, and its packages for the flavor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The version.
    pub version: Version,
    /// Its full package.
    pub full: Package,
    /// Its delta package from the current version, if the index has one.
    pub delta: Option<Package>,
    /// Its release notes.
    pub notes_url: Option<String>,
}

/// The outcome of [`choose`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choice {
    /// Nothing to do: no offered version is newer, and the current one is not revoked (or
    /// nothing else is offered).
    UpToDate,
    /// A newer version.
    Update(Target),
    /// An older version: the current one is revoked and no newer one is offered.
    Downgrade(Target),
}

/// The rollout bucket of an installation for `version`, `0..=99`: the first byte of
/// `sha256(install_id ‖ version)` scaled to 100. The version is offered when the bucket is
/// below its `rollout`, so `rollout: 0` offers it to none and `100` to all; each version
/// draws its own bucket, so the same installations are not always first.
pub fn rollout_bucket(install_id: &[u8; 16], version: &Version) -> u8 {
    let digest = sha2::Sha256::new()
        .chain_update(install_id)
        .chain_update(version.to_string().as_bytes())
        .finalize();
    // At most 255 * 100 / 256 = 99.
    (u16::from(digest[0]) * 100 / 256) as u8
}

/// Chooses the version the installation `install_id` of `flavor`, now on `current`, moves
/// to.
///
/// A version is offered if it is not revoked, not in `bad` (versions that failed their
/// health check here), has a package for `flavor` and the installation's
/// [`rollout_bucket`] is below its `rollout`. The newest offered version is an
/// [`Choice::Update`] if newer than `current`; if older, it is a [`Choice::Downgrade`]
/// only when the index revokes `current`, and nothing otherwise.
pub fn choose(
    index: &Index,
    current: &Version,
    flavor: Flavor,
    install_id: [u8; 16],
    bad: &BTreeSet<Version>,
) -> Choice {
    let offered = |release: &&CoreRelease| {
        !release.revoked
            && !bad.contains(&release.version)
            && rollout_bucket(&install_id, &release.version) < release.rollout
    };
    let newest = index
        .core
        .iter()
        .filter(offered)
        .filter_map(|release| release.package(flavor).map(|package| (release, package)))
        .max_by(|(a, _), (b, _)| a.version.cmp(&b.version));
    let Some((release, package)) = newest else {
        return Choice::UpToDate;
    };
    let current_revoked = index.release(current).is_some_and(|r| r.revoked);
    if release.version > *current {
        Choice::Update(target(release, package, current))
    } else if current_revoked && release.version < *current {
        Choice::Downgrade(target(release, package, current))
    } else {
        Choice::UpToDate
    }
}

fn target(release: &CoreRelease, package: &FlavorPackage, current: &Version) -> Target {
    Target {
        version: release.version.clone(),
        full: package.full.clone(),
        delta: package.delta_from.get(current).cloned(),
        notes_url: release.notes_url.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{Channel, Sha256};
    use std::collections::BTreeMap;
    use time::macros::datetime;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn package(name: &str) -> Package {
        Package {
            url: format!("https://example.org/{name}"),
            sha256: Sha256::of(name.as_bytes()),
            size: name.len() as u64,
        }
    }

    /// A release of `version` for Windows x64 only, with a delta from `0.1.0`.
    fn release(version: &str, rollout: u8, revoked: bool) -> CoreRelease {
        let flavor = FlavorPackage {
            full: package(&format!("{version}-full")),
            delta_from: BTreeMap::from([(v("0.1.0"), package(&format!("{version}-delta")))]),
        };
        CoreRelease {
            version: v(version),
            flavors: BTreeMap::from([(Flavor::WinX64.as_str().to_owned(), flavor)]),
            rollout,
            revoked,
            notes_url: Some(format!("https://example.org/{version}")),
        }
    }

    fn index(core: Vec<CoreRelease>) -> Index {
        Index {
            schema: 1,
            channel: Channel::Stable,
            seq: 1,
            generated: datetime!(2026-10-01 0:00 UTC),
            expires: datetime!(2026-10-31 0:00 UTC),
            core,
            extension: None,
            plugins: Vec::new(),
        }
    }

    const ID: [u8; 16] = [7; 16];

    fn pick(index: &Index, current: &str) -> Choice {
        choose(index, &v(current), Flavor::WinX64, ID, &BTreeSet::new())
    }

    fn version_of(choice: &Choice) -> (&'static str, String) {
        match choice {
            Choice::UpToDate => ("up to date", String::new()),
            Choice::Update(t) => ("update", t.version.to_string()),
            Choice::Downgrade(t) => ("downgrade", t.version.to_string()),
        }
    }

    #[test]
    fn rollout_bucket_is_sha256_of_id_and_version() {
        // Reference values: first byte of sha256(id ‖ version) * 100 / 256, computed apart.
        let id: [u8; 16] = std::array::from_fn(|i| i as u8);
        assert_eq!(rollout_bucket(&id, &v("0.1.0")), 89); // byte 230
        assert_eq!(rollout_bucket(&id, &v("0.2.0-beta.1")), 0); // byte 2
        assert_eq!(rollout_bucket(&[0xff; 16], &v("0.1.0")), 88); // byte 226
        // Every byte value maps into 0..=99.
        let buckets: BTreeSet<u8> = (0..=u8::MAX)
            .map(|n| rollout_bucket(&[n; 16], &v("1.0.0")))
            .collect();
        assert!(buckets.iter().all(|&b| b < 100));
    }

    #[test]
    fn rollout_offers_a_version_by_bucket() {
        let id: [u8; 16] = std::array::from_fn(|i| i as u8);
        let at = |rollout| {
            let idx = index(vec![
                release("0.1.0", 100, false),
                release("0.2.0", rollout, false),
            ]);
            version_of(&choose(
                &idx,
                &v("0.1.0"),
                Flavor::WinX64,
                id,
                &BTreeSet::new(),
            ))
        };
        // This installation's bucket for 0.2.0 is fixed; it is offered above it only.
        let bucket = rollout_bucket(&id, &v("0.2.0"));
        assert_eq!(at(bucket), ("up to date", String::new()));
        assert_eq!(at(bucket + 1), ("update", "0.2.0".to_owned()));
        assert_eq!(at(0), ("up to date", String::new()));
        assert_eq!(at(100), ("update", "0.2.0".to_owned()));

        // About `rollout` percent of installations get it.
        let idx = index(vec![release("0.2.0", 30, false)]);
        let updated = (0..1000u32)
            .filter(|n| {
                let mut id = [0u8; 16];
                id[..4].copy_from_slice(&n.to_le_bytes());
                let choice = choose(&idx, &v("0.1.0"), Flavor::WinX64, id, &BTreeSet::new());
                matches!(choice, Choice::Update(_))
            })
            .count();
        assert!((230..=370).contains(&updated), "{updated} of 1000");
    }

    #[test]
    fn newest_offered_version_is_the_update() {
        let idx = index(vec![
            release("0.2.0", 100, false),
            release("0.1.0", 100, false),
            release("0.3.0", 100, false),
        ]);
        let Choice::Update(t) = pick(&idx, "0.1.0") else {
            panic!("no update");
        };
        assert_eq!(t.version, v("0.3.0"));
        assert_eq!(t.full, package("0.3.0-full"));
        assert_eq!(t.delta, Some(package("0.3.0-delta")), "delta from 0.1.0");
        assert_eq!(t.notes_url.as_deref(), Some("https://example.org/0.3.0"));

        let Choice::Update(t) = pick(&idx, "0.2.0") else {
            panic!("no update");
        };
        assert_eq!(t.delta, None, "no delta from 0.2.0");
        assert_eq!(pick(&idx, "0.3.0"), Choice::UpToDate);
        assert_eq!(pick(&idx, "0.4.0-dev"), Choice::UpToDate, "newer than all");
    }

    #[test]
    fn revoked_bad_and_missing_flavor_versions_are_skipped() {
        let mut no_flavor = release("0.5.0", 100, false);
        no_flavor.flavors = BTreeMap::from([(
            Flavor::LinuxX64.as_str().to_owned(),
            no_flavor.flavors.remove(Flavor::WinX64.as_str()).unwrap(),
        )]);
        let idx = index(vec![
            release("0.1.0", 100, false),
            release("0.2.0", 100, false),
            release("0.3.0", 100, false),
            release("0.4.0", 100, true),
            no_flavor,
        ]);
        let bad = BTreeSet::from([v("0.3.0")]);
        let choice = choose(&idx, &v("0.1.0"), Flavor::WinX64, ID, &bad);
        assert_eq!(version_of(&choice), ("update", "0.2.0".to_owned()));
        let all_bad = BTreeSet::from([v("0.2.0"), v("0.3.0")]);
        let choice = choose(&idx, &v("0.1.0"), Flavor::WinX64, ID, &all_bad);
        assert_eq!(choice, Choice::UpToDate);
        // Linux sees 0.5.0.
        let choice = choose(&idx, &v("0.1.0"), Flavor::LinuxX64, ID, &BTreeSet::new());
        assert_eq!(version_of(&choice), ("update", "0.5.0".to_owned()));
    }

    #[test]
    fn revoked_current_version_moves_to_newest_not_revoked() {
        // Downgrade to the newest offered version.
        let idx = index(vec![
            release("0.1.0", 100, false),
            release("0.2.0", 100, false),
            release("0.3.0", 100, true),
        ]);
        assert_eq!(
            version_of(&pick(&idx, "0.3.0")),
            ("downgrade", "0.2.0".to_owned())
        );

        // An older version that is bad here or not rolled out to us is passed over.
        let bad = BTreeSet::from([v("0.2.0")]);
        let choice = choose(&idx, &v("0.3.0"), Flavor::WinX64, ID, &bad);
        let Choice::Downgrade(t) = choice else {
            panic!("no downgrade: {choice:?}");
        };
        assert_eq!(t.version, v("0.1.0"));
        assert_eq!(t.full, package("0.1.0-full"));
        assert_eq!(t.delta, None);
        let idx_unrolled = index(vec![
            release("0.1.0", 100, false),
            release("0.2.0", 0, false),
            release("0.3.0", 100, true),
        ]);
        assert_eq!(
            version_of(&pick(&idx_unrolled, "0.3.0")),
            ("downgrade", "0.1.0".to_owned())
        );

        // A newer version not revoked is an update, as usual.
        let idx = index(vec![
            release("0.2.0", 100, false),
            release("0.3.0", 100, true),
            release("0.4.0", 100, false),
        ]);
        assert_eq!(
            version_of(&pick(&idx, "0.3.0")),
            ("update", "0.4.0".to_owned())
        );

        // Nothing else offered: stay.
        let idx = index(vec![release("0.3.0", 100, true)]);
        assert_eq!(pick(&idx, "0.3.0"), Choice::UpToDate);
    }

    #[test]
    fn no_downgrade_from_a_version_not_revoked() {
        // The current version is listed and fine, or not listed at all (a newer local
        // build, or one dropped from the index): older versions are not offered.
        let idx = index(vec![
            release("0.1.0", 100, false),
            release("0.2.0", 100, false),
        ]);
        assert_eq!(pick(&idx, "0.2.0"), Choice::UpToDate);
        assert_eq!(pick(&idx, "0.2.5"), Choice::UpToDate);
        let idx = index(vec![
            release("0.1.0", 100, false),
            release("0.3.0", 100, false),
        ]);
        assert_eq!(
            version_of(&pick(&idx, "0.2.0")),
            ("update", "0.3.0".to_owned())
        );
        // Bad locally is not revoked: a bad current version does not downgrade here (the
        // health check rolls back on its own).
        let bad = BTreeSet::from([v("0.3.0")]);
        let choice = choose(&idx, &v("0.3.0"), Flavor::WinX64, ID, &bad);
        assert_eq!(choice, Choice::UpToDate);
    }
}
