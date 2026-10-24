//! Test helpers shared by OpenNCALayer crates.
//!
//! Paths are resolved against the workspace root, so tests work regardless of
//! the current directory `cargo test` runs them from.

use std::path::{Path, PathBuf};

/// Root of the Cargo workspace (the directory holding the top-level `Cargo.toml`).
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("oncl-testkit lives at <root>/crates/oncl-testkit")
        .to_path_buf()
}

/// Path of a downloaded NCANode fixture: `target/fixtures/ncanode/<name>`.
///
/// # Panics
///
/// Panics if the file is missing; the fixtures are fetched by
/// `cargo xtask fetch-fixtures`.
pub fn ncanode(name: &str) -> PathBuf {
    let path = workspace_root().join("target/fixtures/ncanode").join(name);
    assert!(
        path.is_file(),
        "NCANode fixture {} is missing: run `cargo xtask fetch-fixtures`",
        path.display()
    );
    path
}

/// Path of a fixture committed to the repository: `fixtures/<rel>`.
pub fn fixture(rel: &str) -> PathBuf {
    workspace_root().join("fixtures").join(rel)
}

/// Reads a whole file, panicking with the path on failure.
pub fn read(path: impl AsRef<Path>) -> Vec<u8> {
    let path = path.as_ref();
    std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_root_holds_workspace_manifest() {
        let manifest = String::from_utf8(read(workspace_root().join("Cargo.toml"))).unwrap();
        assert!(manifest.contains("[workspace]"));
    }

    #[test]
    fn fixture_is_under_fixtures_dir() {
        assert_eq!(
            fixture("a/b.der"),
            workspace_root().join("fixtures").join("a/b.der")
        );
    }

    #[test]
    #[should_panic(expected = "run `cargo xtask fetch-fixtures`")]
    fn missing_ncanode_fixture_tells_how_to_fetch() {
        ncanode("no-such-fixture.bin");
    }
}
