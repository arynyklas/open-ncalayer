//! The project site from the fixtures of `fixtures/registry` and from the repository's own
//! ports. The tests that run Zola download the pinned Zola once: they are `#[ignore]`d and
//! named `zola_…`: the `test` job of CI skips them, the `site` job runs them.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde_json::Value;
use sha2::{Digest, Sha256};
use xtask::registry::{Inputs, build, check, generate, site, zola};

fn root() -> PathBuf {
    oncl_testkit::workspace_root()
}

fn fixtures() -> PathBuf {
    root().join("fixtures/registry")
}

fn fixture_inputs() -> Inputs {
    Inputs {
        plugins: fixtures().join("plugins"),
        updates: Some(fixtures().join("updates/v1")),
        releases: Some(fixtures().join("releases.jsonl")),
        upstream: Some(fixtures().join("upstream")),
    }
}

/// Every file under `dir` and its sha256.
fn hashes(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                // The ports' build output is not an input.
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else {
                let digest = Sha256::digest(fs::read(&path).unwrap()).to_vec();
                out.insert(path, digest);
            }
        }
    }
    out
}

#[test]
fn generate_leaves_inputs_untouched() {
    let dirs = [fixtures(), root().join("plugins"), root().join("site")];
    let before: Vec<_> = dirs.iter().map(|d| hashes(d)).collect();
    let out = tempfile::tempdir().unwrap();
    generate(&root(), &fixture_inputs(), &out.path().join("fixtures")).unwrap();
    let committed = Inputs {
        plugins: root().join("plugins"),
        updates: None,
        releases: None,
        upstream: None,
    };
    generate(&root(), &committed, &out.path().join("committed")).unwrap();
    let after: Vec<_> = dirs.iter().map(|d| hashes(d)).collect();
    assert_eq!(before, after);
}

fn fixture_data() -> Value {
    let out = tempfile::tempdir().unwrap();
    generate(&root(), &fixture_inputs(), out.path()).unwrap();
    serde_json::from_slice(&fs::read(out.path().join("data/site.json")).unwrap()).unwrap()
}

#[test]
fn fixture_data_matches_expectations() {
    let data = fixture_data();
    let plugins = &data["plugins"];
    assert_eq!(plugins["alpha"]["original"]["state"], "same");
    assert_eq!(plugins["gamma"]["original"]["state"], "changed");
    assert_eq!(plugins["gamma"]["original"]["current"], "1.1");
    assert_eq!(plugins["hostile"]["original"]["state"], "removed");

    assert_eq!(plugins["alpha"]["channels"]["stable"]["version"], "1.0.0");
    assert_eq!(
        plugins["alpha"]["channels"]["beta"]["version"],
        "1.1.0-beta.1"
    );
    assert_eq!(plugins["alpha"]["channels"]["beta"]["rollout"], 25);
    assert_eq!(plugins["gamma"]["channels"], serde_json::json!({}));
    let hostile: Vec<&String> = plugins["hostile"]["channels"]
        .as_object()
        .unwrap()
        .keys()
        .collect();
    assert_eq!(hostile, ["beta"]);

    assert_eq!(data["channels"]["stable"]["seq"], 3);
    assert_eq!(data["channels"]["stable"]["core"], "0.2.0");
    assert_eq!(data["channels"]["beta"]["core"], "0.3.0-beta.1");
    assert_eq!(data["channels"]["beta"]["expires"], "2026-12-01");

    let releases = &data["releases"];
    assert_eq!(releases["available"], true);
    assert_eq!(releases["release"]["version"], "0.2.0");
    assert_eq!(releases["release"]["published"], "2026-10-20");
    assert_eq!(releases["release"]["assets"].as_array().unwrap().len(), 10);
    assert_eq!(releases["prerelease"]["version"], "0.3.0-beta.1");
    let kinds: Vec<&str> = releases["prerelease"]["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["kind"].as_str().unwrap())
        .collect();
    assert!(
        !kinds.contains(&"osx-pkg") && !kinds.contains(&"osx-zip"),
        "{kinds:?}"
    );

    let upstream = &data["upstream"];
    assert_eq!(upstream["available"], true);
    assert_eq!(upstream["version"], "1.4");
    let core = upstream["bundles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["symname"] == "kz.gov.pki.kalkan.xmldsig")
        .unwrap();
    assert_eq!(core["changed"], true);
    assert_eq!(upstream["history"][0]["url"], Value::Null);
    assert_eq!(upstream["history"].as_array().unwrap().len(), 2);
}

/// The pinned Zola, downloaded once for all tests.
static ZOLA: LazyLock<PathBuf> = LazyLock::new(|| zola::ensure(&root()).unwrap());

fn zola() -> &'static Path {
    &ZOLA
}

fn base_url() -> String {
    site::site_config(&root()).unwrap().base_url
}

fn built(inputs: &Inputs) -> (tempfile::TempDir, PathBuf) {
    let out = tempfile::tempdir().unwrap();
    let public = build(&root(), inputs, out.path(), Some(zola())).unwrap();
    (out, public)
}

fn read(public: &Path, page: &str) -> String {
    fs::read_to_string(public.join(page)).unwrap_or_else(|e| panic!("{page}: {e}"))
}

const LANG_PREFIXES: [&str; 3] = ["", "kk/", "en/"];

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_builds_from_committed_data() {
    let updates = root().join("updates/v1");
    let inputs = Inputs {
        plugins: root().join("plugins"),
        updates: updates.is_dir().then_some(updates),
        releases: None,
        upstream: None,
    };
    let (_out, public) = built(&inputs);
    let ports = xtask::registry::ports::load(&root().join("plugins")).unwrap();
    assert_eq!(ports.len(), 34);
    for port in &ports {
        for prefix in LANG_PREFIXES {
            let page = format!("{prefix}plugins/{}/index.html", port.short);
            assert!(public.join(&page).is_file(), "{page}");
        }
    }
    check(&public, &base_url()).unwrap();
}

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_builds_from_fixtures() {
    let (_out, public) = built(&fixture_inputs());
    assert!(!public.join("updates").exists());
    copy_tree(&fixtures().join("updates"), &public.join("updates"));
    let report = check(&public, &base_url()).unwrap();
    assert!(report.pages >= 22, "{report:?}");
    assert_eq!(
        fs::read(public.join("updates/v1/beta.json")).unwrap(),
        fs::read(fixtures().join("updates/v1/beta.json")).unwrap()
    );
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_escapes_hostile_fixture() {
    let (_out, public) = built(&fixture_inputs());
    let mut pages: Vec<String> = LANG_PREFIXES
        .iter()
        .flat_map(|p| {
            [
                format!("{p}plugins/hostile/index.html"),
                format!("{p}plugins/index.html"),
                format!("{p}upstream/index.html"),
            ]
        })
        .collect();
    pages.push("download/index.html".to_owned());
    for page in pages {
        let html = read(&public, &page);
        let lower = html.to_ascii_lowercase();
        assert!(!lower.contains("<script"), "{page}");
        assert!(!lower.contains("<img"), "{page}");
        if page.contains("hostile") || page.contains("plugins/index") || page.contains("upstream") {
            assert!(
                html.contains("&lt;script&gt;alert(1)&lt;&#x2F;script&gt;")
                    || html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
                "{page}"
            );
            assert!(html.contains("{{ config.base_url }}"), "{page}");
            assert!(html.contains("{% raw %}"), "{page}");
            // Every `onerror=` is inside escaped text, after an escaped `<img`.
            for (at, _) in html.match_indices("onerror=") {
                let before = &html[..at];
                let tag = before.rfind('<').unwrap_or(0);
                let escaped = before.rfind("&lt;img").unwrap_or(0);
                assert!(escaped > tag, "{page}: onerror= in markup");
            }
        }
    }
}

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_works_without_any_optional_input() {
    let inputs = Inputs {
        plugins: fixtures().join("plugins"),
        updates: None,
        releases: None,
        upstream: None,
    };
    let (_out, public) = built(&inputs);
    for prefix in LANG_PREFIXES {
        for page in ["download/index.html", "upstream/index.html"] {
            let html = read(&public, &format!("{prefix}{page}"));
            assert!(html.contains("class=\"nodata\""), "{prefix}{page}");
        }
    }
    let ru = read(&public, "download/index.html");
    assert!(ru.contains("Список релизов недоступен"), "{ru}");
    assert!(read(&public, "upstream/index.html").contains("Данных наблюдателя пока нет"));
}

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_catalog_anchor_for_every_port() {
    let (_out, public) = built(&fixture_inputs());
    for prefix in LANG_PREFIXES {
        let html = read(&public, &format!("{prefix}plugins/index.html"));
        for symname in ["kz.example.alpha", "kz.example.gamma", "kz.example.hostile"] {
            assert!(
                html.contains(&format!("<tr id=\"{symname}\">")),
                "{prefix}: {symname}"
            );
        }
        // The original's bundle without a port has its row too.
        assert!(html.contains("id=\"kz.example.unported\""), "{prefix}");
    }
}

#[test]
#[ignore = "downloads and runs Zola"]
fn zola_site_catalog_lists_unported_bundles_only_from_facts() {
    let (_out, public) = built(&fixture_inputs());
    assert!(read(&public, "plugins/index.html").contains("id=\"unported-caption\""));
    // The history alone says nothing about which bundles have no port.
    let upstream = tempfile::tempdir().unwrap();
    fs::copy(
        fixtures().join("upstream/index.json"),
        upstream.path().join("index.json"),
    )
    .unwrap();
    let inputs = Inputs {
        upstream: Some(upstream.path().to_path_buf()),
        ..fixture_inputs()
    };
    let (_out, public) = built(&inputs);
    for prefix in LANG_PREFIXES {
        let catalog = read(&public, &format!("{prefix}plugins/index.html"));
        assert!(!catalog.contains("unported-caption"), "{prefix}");
    }
    assert!(read(&public, "upstream/index.html").contains("2026-10-20"));
}
