//! `<data>/plugins/`: installed packages checked against their sums, the state file
//! replaced when damaged, and the catalog kept and verified again.

mod common;

use common::repackaged_example;
use oncl_plugin::{Package, Source, Store, StoreError};
use oncl_testkit::plugin::example_package;
use oncl_update::{Channel, Index, PublicKey, Version};
use std::io::Cursor;
use time::{Duration, OffsetDateTime};

const ID: &str = "io.github.arynyklas.openncalayer.example";

fn example() -> (Package, Vec<u8>) {
    let bytes = example_package();
    (Package::read(&bytes).unwrap(), bytes)
}

fn package_file(dir: &std::path::Path, version: &str) -> std::path::PathBuf {
    dir.join("plugins/packages")
        .join(format!("{ID}-{version}.onclp"))
}

#[test]
fn install_then_load_package() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store.install(&package, &bytes, Source::Catalog).unwrap();

    let state = store.state();
    let installed = &state.plugins[ID];
    assert_eq!(installed.version, package.manifest.version);
    assert_eq!(installed.sha256.0, package.sha256);
    assert_eq!(installed.source, Source::Catalog);
    assert!(installed.enabled && !installed.withdrawn);
    assert!(package_file(dir.path(), "0.1.0").is_file());

    let loaded = store.load_package(ID).unwrap();
    assert_eq!(loaded.manifest, package.manifest);
    assert_eq!(loaded.sha256, package.sha256);
    // The state is on disk: another store reads it.
    let again = Store::open(dir.path()).unwrap();
    assert_eq!(again.state(), state);
    assert!(again.load_package(ID).is_ok());
    assert!(matches!(
        again.load_package("kz.example.none"),
        Err(StoreError::NotInstalled(_))
    ));
    // Bytes that are not the package's file are refused.
    let err = store
        .install(&package, &bytes[..bytes.len() - 1], Source::Local)
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn tampered_package_is_not_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store.install(&package, &bytes, Source::Local).unwrap();
    let file = package_file(dir.path(), "0.1.0");
    let mut changed = std::fs::read(&file).unwrap();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    std::fs::write(&file, &changed).unwrap();
    assert!(matches!(store.load_package(ID), Err(StoreError::Tampered)));
    std::fs::remove_file(&file).unwrap();
    assert!(matches!(store.load_package(ID), Err(StoreError::Io(_))));
}

#[test]
fn corrupt_state_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let first = Store::open(dir.path()).unwrap().state();
    // A fresh state is saved at once: its install id is kept.
    assert_eq!(Store::open(dir.path()).unwrap().state(), first);
    let path = dir.path().join("plugins/state.json");
    std::fs::write(&path, b"{not json").unwrap();
    let store = Store::open(dir.path()).unwrap();
    assert!(store.state().plugins.is_empty());
    assert_ne!(store.state().install_id, first.install_id);
    // Replaced on disk.
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(saved["install_id"].as_str().unwrap().len(), 32);
    // A state that cannot be read for another reason is an error: a directory in its place.
    let other = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(other.path().join("plugins/state.json")).unwrap();
    assert!(Store::open(other.path()).is_err());
}

#[test]
fn remove_deletes_package() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store.install(&package, &bytes, Source::Catalog).unwrap();
    store.set_enabled(ID, false).unwrap();
    store.set_withdrawn(ID, true).unwrap();
    let installed = store.state().plugins[ID].clone();
    assert!(!installed.enabled && installed.withdrawn);
    // Installed again: still off, no longer withdrawn.
    store.install(&package, &bytes, Source::Catalog).unwrap();
    let installed = store.state().plugins[ID].clone();
    assert!(!installed.enabled && !installed.withdrawn);

    store.remove(ID).unwrap();
    assert!(!store.state().plugins.contains_key(ID));
    assert!(!package_file(dir.path(), "0.1.0").exists());
    assert_eq!(
        store.remove(ID).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        store.set_enabled(ID, true).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    store.mark_bad(ID, &Version::new(0, 1, 0)).unwrap();
    assert!(store.state().bad[ID].contains(&Version::new(0, 1, 0)));
}

#[test]
fn an_update_replaces_the_old_package_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (package, bytes) = example();
    store.install(&package, &bytes, Source::Catalog).unwrap();
    let newer = repackaged_example(|m| m.replacen("version = \"0.1.0\"", "version = \"0.2.0\"", 1));
    store
        .install(&Package::read(&newer).unwrap(), &newer, Source::Catalog)
        .unwrap();
    assert_eq!(store.state().plugins[ID].version, Version::new(0, 2, 0));
    assert!(!package_file(dir.path(), "0.1.0").exists());
    assert!(package_file(dir.path(), "0.2.0").is_file());
    assert_eq!(
        store.load_package(ID).unwrap().manifest.version,
        Version::new(0, 2, 0)
    );
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

    /// An empty index of the beta channel, `seq`, made at `generated`, and its signature.
    fn index(&self, seq: u64, generated: OffsetDateTime) -> (Vec<u8>, Vec<u8>) {
        let index = Index {
            schema: 1,
            channel: Channel::Beta,
            seq,
            generated,
            expires: generated + Duration::days(7),
            core: Vec::new(),
            extension: None,
            plugins: Vec::new(),
        };
        let body = serde_json::to_vec(&index).unwrap();
        let sig = minisign::sign(
            None,
            &self.pair.sk,
            Cursor::new(&body),
            Some(&format!("channel=beta;seq={seq}")),
            None,
        )
        .unwrap()
        .into_string()
        .into_bytes();
        (body, sig)
    }
}

#[test]
fn catalog_roundtrip_reverifies_and_expires() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let key = Key::new();
    let keys = [key.public.clone()];
    let now = OffsetDateTime::now_utc();
    assert!(store.load_catalog(Channel::Beta, &keys, now).is_none());

    let (index, sig) = key.index(5, now - Duration::hours(1));
    store.save_catalog(Channel::Beta, &index, &sig).unwrap();
    assert_eq!(store.state().last_seq[&Channel::Beta], 5);
    let loaded = store.load_catalog(Channel::Beta, &keys, now).unwrap();
    assert_eq!(loaded.seq, 5);
    // Another channel has none.
    assert!(store.load_catalog(Channel::Stable, &keys, now).is_none());
    // Another key does not verify it.
    assert!(
        store
            .load_catalog(Channel::Beta, &[Key::new().public], now)
            .is_none()
    );
    // Expired: not used.
    assert!(
        store
            .load_catalog(Channel::Beta, &keys, now + Duration::days(8))
            .is_none()
    );
    // A newer one raises last_seq; the old one put back is a rollback.
    let (newer, newer_sig) = key.index(7, now);
    store
        .save_catalog(Channel::Beta, &newer, &newer_sig)
        .unwrap();
    assert_eq!(store.state().last_seq[&Channel::Beta], 7);
    let catalog = dir.path().join("plugins/catalog");
    std::fs::write(catalog.join("beta.json"), &index).unwrap();
    std::fs::write(catalog.join("beta.json.minisig"), &sig).unwrap();
    assert!(store.load_catalog(Channel::Beta, &keys, now).is_none());
    // A changed index fails its signature.
    let mut changed = newer.clone();
    changed.push(b' ');
    std::fs::write(catalog.join("beta.json"), &changed).unwrap();
    std::fs::write(catalog.join("beta.json.minisig"), &newer_sig).unwrap();
    assert!(store.load_catalog(Channel::Beta, &keys, now).is_none());
}
