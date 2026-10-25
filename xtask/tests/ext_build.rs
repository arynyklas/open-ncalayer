//! `cargo xtask ext build` produces both extensions: manifests filled from `oncl_ipc::ids` and
//! the workspace version, every referenced script present, archives with the same files.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use oncl_ipc::ids::{CHROMIUM_EXTENSION_KEY, FIREFOX_EXTENSION_ID, HOST_NAME};
use oncl_testkit::workspace_root;
use serde_json::Value;

const FILES: [&str; 5] = [
    "manifest.json",
    "background.js",
    "bridge.js",
    "host.js",
    "shim.js",
];

fn manifest(dir: &Path) -> (String, Value) {
    let text = fs::read_to_string(dir.join("manifest.json")).unwrap();
    let value = serde_json::from_str(&text).unwrap();
    (text, value)
}

/// Scripts a manifest names (background and content scripts).
fn referenced_scripts(manifest: &Value) -> Vec<String> {
    let background = &manifest["background"];
    let mut scripts: Vec<&Value> = background["scripts"]
        .as_array()
        .into_iter()
        .flatten()
        .collect();
    scripts.extend(background.get("service_worker"));
    for content in manifest["content_scripts"].as_array().unwrap() {
        scripts.extend(content["js"].as_array().unwrap());
    }
    scripts
        .into_iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn builds_both_extensions_from_the_shared_ids() {
    let out = tempfile::tempdir().unwrap();
    let packages = xtask::ext::build(&workspace_root(), out.path()).unwrap();
    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(
        packages.iter().map(|p| p.browser).collect::<Vec<_>>(),
        ["chromium", "firefox"]
    );

    for package in &packages {
        let (text, manifest) = manifest(&package.dir);
        assert!(
            !text.contains("{{"),
            "{}: unreplaced placeholder",
            package.browser
        );
        assert_eq!(manifest["version"], version, "{}", package.browser);
        for script in referenced_scripts(&manifest) {
            assert!(
                package.dir.join(&script).is_file(),
                "{}: {script}",
                package.browser
            );
        }
        let host = fs::read_to_string(package.dir.join("host.js")).unwrap();
        assert!(host.contains(&format!("const HOST_NAME = \"{HOST_NAME}\";")));

        let mut names: Vec<String> = fs::read_dir(&package.dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        let mut expected = FILES.map(String::from).to_vec();
        expected.sort();
        assert_eq!(names, expected, "{}", package.browser);

        let extension = if package.browser == "firefox" {
            "xpi"
        } else {
            "zip"
        };
        assert_eq!(
            package.archive,
            out.path().join(format!(
                "openncalayer-{}-{version}.{extension}",
                package.browser
            ))
        );
        let mut archive = zip::ZipArchive::new(File::open(&package.archive).unwrap()).unwrap();
        let archived: Vec<String> = archive
            .file_names()
            .map(|n| n.unwrap().into_owned())
            .collect();
        assert_eq!(archived, FILES, "{}", package.browser);
        for name in FILES {
            let mut bytes = Vec::new();
            archive
                .by_name(name)
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(bytes, fs::read(package.dir.join(name)).unwrap(), "{name}");
        }
    }

    let (_, chromium) = manifest(&packages[0].dir);
    assert_eq!(chromium["manifest_version"], 3);
    assert_eq!(chromium["key"], CHROMIUM_EXTENSION_KEY);
    assert_eq!(chromium["minimum_chrome_version"], "109");
    // The shim is registered at run time, so it is in the package without a manifest entry.
    assert!(packages[0].dir.join("shim.js").is_file());

    let (_, firefox) = manifest(&packages[1].dir);
    assert_eq!(firefox["manifest_version"], 2);
    let gecko = &firefox["browser_specific_settings"]["gecko"];
    assert_eq!(gecko["id"], FIREFOX_EXTENSION_ID);
    assert_eq!(gecko["strict_min_version"], "128.0");
}

/// Copies the files directly in `from` to `to`.
fn copy_files(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }
}

#[test]
fn ships_only_the_listed_scripts() {
    let root = tempfile::tempdir().unwrap();
    let extension = workspace_root().join("extension");
    for dir in ["manifests", "src"] {
        copy_files(
            &extension.join(dir),
            &root.path().join("extension").join(dir),
        );
    }
    let src = root.path().join("extension/src");
    fs::write(src.join("stray.js"), "// an untracked leftover\n").unwrap();
    fs::remove_file(src.join("host.js")).ok();

    let out = root.path().join("out");
    for package in xtask::ext::build(root.path(), &out).unwrap() {
        assert!(
            !package.dir.join("stray.js").exists(),
            "{}",
            package.browser
        );
        let archive = zip::ZipArchive::new(File::open(&package.archive).unwrap()).unwrap();
        let names: Vec<_> = archive
            .file_names()
            .map(|n| n.unwrap().into_owned())
            .collect();
        assert_eq!(names, FILES, "{}", package.browser);
    }
    // `host.js` is generated even when missing.
    assert!(src.join("host.js").is_file());

    // A listed script that is missing fails the build.
    fs::remove_file(src.join("shim.js")).unwrap();
    let error = xtask::ext::build(root.path(), &out).unwrap_err();
    assert!(format!("{error:#}").contains("shim.js"), "{error:#}");
}
