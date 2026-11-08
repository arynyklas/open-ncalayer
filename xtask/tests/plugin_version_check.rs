//! `cargo xtask plugin-version-check` on a throwaway git repository.

use std::fs;
use std::path::Path;
use std::process::Command;

use xtask::plugin_version::check;

struct Repo {
    dir: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        let repo = Repo {
            dir: tempfile::tempdir().unwrap(),
        };
        repo.git(&["init", "-q"]);
        repo
    }
    fn root(&self) -> &Path {
        self.dir.path()
    }
    fn write(&self, path: &str, text: &str) {
        let file = self.root().join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, text).unwrap();
    }
    fn port(&self, name: &str, version: &str) {
        self.write(
            &format!("plugins/{name}/plugin.toml"),
            &format!("id = \"x.{name}\"\nversion = \"{version}\"\n"),
        );
        self.write(
            &format!("plugins/{name}/Cargo.toml"),
            &format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n"),
        );
        self.write(&format!("plugins/{name}/src/lib.rs"), "fn f() {}\n");
        self.write(&format!("plugins/{name}/registry.toml"), "# conformance\n");
    }
    fn commit(&self, message: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
    }
    fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(self.root())
            .args([
                "-c",
                "core.autocrlf=false",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    /// Two ports at 1.0.0, committed and tagged `plugins-20261101`.
    fn tagged() -> Self {
        let repo = Repo::new();
        repo.port("alpha", "1.0.0");
        repo.port("beta", "1.0.0");
        repo.commit("release");
        repo.git(&["tag", "plugins-20261101"]);
        repo
    }
}

#[test]
fn no_tag_is_a_notice_not_an_error() {
    let repo = Repo::new();
    repo.port("alpha", "1.0.0");
    repo.commit("first");
    let report = check(repo.root()).unwrap();
    assert_eq!(report.tag, None);
    assert_eq!(report.exit_code(), 0);
    assert!(report.to_text().contains("NOTICE"));
}

#[test]
fn nothing_changed_passes() {
    let repo = Repo::tagged();
    repo.write("docs/readme.md", "unrelated\n");
    repo.commit("docs");
    let report = check(repo.root()).unwrap();
    assert_eq!(report.tag.as_deref(), Some("plugins-20261101"));
    assert_eq!(report.checked, 2);
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn a_source_change_without_a_new_version_fails() {
    let repo = Repo::tagged();
    repo.write("plugins/alpha/src/lib.rs", "fn g() {}\n");
    repo.commit("change");
    let report = check(repo.root()).unwrap();
    assert_eq!(report.exit_code(), 1);
    assert_eq!(report.unbumped.len(), 1);
    assert_eq!(report.unbumped[0].port, "alpha");
    assert_eq!(report.unbumped[0].files, ["plugins/alpha/src/lib.rs"]);
    assert!(
        report
            .to_text()
            .contains("alpha changed since plugins-20261101")
    );
}

#[test]
fn a_manifest_or_cargo_change_without_a_new_version_fails() {
    let repo = Repo::tagged();
    repo.write(
        "plugins/beta/plugin.toml",
        "id = \"x.beta\"\nversion = \"1.0.0\"\nmin_core = \"0.1.0\"\n",
    );
    repo.write(
        "plugins/alpha/Cargo.toml",
        "[package]\nname = \"alpha\"\nversion = \"1.0.0\"\n[dependencies]\n",
    );
    repo.commit("change");
    let report = check(repo.root()).unwrap();
    let ports: Vec<_> = report.unbumped.iter().map(|u| u.port.as_str()).collect();
    assert_eq!(ports, ["alpha", "beta"]);
}

#[test]
fn a_change_with_a_new_version_passes() {
    let repo = Repo::tagged();
    repo.write("plugins/alpha/src/lib.rs", "fn g() {}\n");
    repo.port("alpha", "1.0.1");
    repo.write("plugins/alpha/src/lib.rs", "fn g() {}\n");
    repo.commit("change and bump");
    assert_eq!(check(repo.root()).unwrap().exit_code(), 0);
}

#[test]
fn an_uncommitted_change_counts_and_registry_text_does_not() {
    let repo = Repo::tagged();
    repo.write(
        "plugins/alpha/registry.toml",
        "# conformance text changed\n",
    );
    repo.commit("page");
    assert_eq!(check(repo.root()).unwrap().exit_code(), 0);
    repo.write("plugins/beta/src/lib.rs", "fn h() {}\n");
    let report = check(repo.root()).unwrap();
    assert_eq!(report.unbumped.len(), 1);
    assert_eq!(report.unbumped[0].port, "beta");
}

#[test]
fn a_new_port_and_the_latest_tag_are_taken_into_account() {
    let repo = Repo::tagged();
    repo.port("gamma", "0.1.0");
    repo.write("plugins/alpha/src/lib.rs", "fn g() {}\n");
    repo.port("alpha", "1.1.0");
    repo.write("plugins/alpha/src/lib.rs", "fn g() {}\n");
    repo.commit("new port, bump");
    repo.git(&["tag", "plugins-20261105"]);
    // After the newer tag, only changes since it count.
    repo.write("plugins/gamma/src/lib.rs", "fn z() {}\n");
    repo.commit("gamma again");
    let report = check(repo.root()).unwrap();
    assert_eq!(report.tag.as_deref(), Some("plugins-20261105"));
    assert_eq!(report.unbumped.len(), 1);
    assert_eq!(report.unbumped[0].port, "gamma");
}
