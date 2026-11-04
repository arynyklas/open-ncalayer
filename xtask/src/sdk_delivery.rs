//! `cargo xtask sdk …`: evidence for the SDK delivery (docs/dev/sdk.md).
//!
//! - `closure`: the normal-dependency closure of `oncl-core` for the minimal SDK, every feature
//!   and `full`; fails if any of them contains a UI, desktop, updater, server or async-runtime
//!   crate.
//! - `smoke`: packages the SDK chain ([`CHAIN`]) with `cargo package` (offline, verified,
//!   never uploaded), unpacks the `.crate` files, builds a separate consumer crate against the
//!   unpacked sources only, and runs it: a real CMS sign and verify without display, daemon,
//!   collector or listener.
//! - `licenses`: the licence inventory of the third-party crates of the SDK closure.
//!
//! Nothing here contacts a registry or publishes anything.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use clap::Subcommand;
use serde_json::Value;

/// The SDK chain in publication order: every crate comes after the crates it depends on.
/// `oncl-core` is the entry point; the rest is its transitive closure with every feature and
/// `oncl-plugin`'s `distribution` feature (through `oncl-update`).
pub const CHAIN: [&str; 12] = [
    "oncl-gost",
    "oncl-registry",
    "oncl-pki",
    "oncl-pdf",
    "oncl-protocol",
    "oncl-pdk",
    "oncl-xml",
    "oncl-token",
    "oncl-flows",
    "oncl-update",
    "oncl-plugin",
    "oncl-core",
];

/// Crates that must not appear in the normal-dependency closure of the SDK.
pub const FORBIDDEN: [&str; 24] = [
    "slint",
    "slint-build",
    "i-slint-core",
    "i-slint-backend-winit",
    "i-slint-renderer-skia",
    "winit",
    "tokio",
    "axum",
    "hyper",
    "hyper-util",
    "tokio-rustls",
    "tokio-tungstenite",
    "velopack",
    "tray-icon",
    "rfd",
    "webbrowser",
    "oncl-ui",
    "oncl-desktop",
    "oncl-api",
    "oncl-server",
    "oncl-cli",
    "openncalayer",
    "oncl-nmhost",
    "multer",
];

/// The feature sets whose closure is reported: `(label, features)`; the first is the minimal
/// SDK.
pub const FEATURE_SETS: [(&str, &str); 7] = [
    ("minimal", ""),
    ("tokens", "tokens"),
    ("xml", "xml"),
    ("pdf", "pdf"),
    ("jose", "jose"),
    ("plugins", "plugins"),
    ("full", "full"),
];

/// The inventory of the SDK's third-party crates, relative to the workspace root; it ships in
/// the `oncl-core` package.
pub const LICENSES_OUTPUT: &str = "crates/oncl-core/THIRD-PARTY.txt";

/// Source packages of the patched crates (`[patch.crates-io]` of the workspace) the SDK needs.
const PATCHED: [&str; 2] = ["hmac", "streebog"];

#[derive(Subcommand, Debug)]
pub enum SdkCommand {
    /// Print the dependency closure of `oncl-core` per feature and fail on UI, desktop,
    /// updater, server or async-runtime crates.
    Closure,
    /// Package the SDK chain offline, build a separate consumer from the unpacked source
    /// packages only and run a real sign and verify with it.
    Smoke {
        /// Keep the work directory (default: `<target>/sdk-smoke`, always recreated).
        #[arg(long)]
        keep: bool,
    },
    /// Write (or with `--check` compare) the licence inventory of the SDK closure.
    Licenses {
        /// Regenerate in memory and fail if the committed file differs.
        #[arg(long)]
        check: bool,
    },
}

/// Runs one `sdk` subcommand at the workspace root `root`.
///
/// # Errors
///
/// The subcommand's failure.
pub fn run(root: &Path, command: SdkCommand) -> anyhow::Result<()> {
    match command {
        SdkCommand::Closure => {
            print!("{}", closure_report(root)?);
            Ok(())
        }
        SdkCommand::Smoke { keep } => smoke(root, keep),
        SdkCommand::Licenses { check: false } => {
            let path = root.join(LICENSES_OUTPUT);
            fs::write(&path, licenses(root)?)
                .with_context(|| format!("writing {}", path.display()))?;
            println!("{}", path.display());
            Ok(())
        }
        SdkCommand::Licenses { check: true } => {
            let expected = licenses(root)?;
            if fs::read(root.join(LICENSES_OUTPUT)).ok().as_deref() != Some(expected.as_bytes()) {
                bail!("{LICENSES_OUTPUT} is stale: run `cargo xtask sdk licenses`");
            }
            println!("{LICENSES_OUTPUT} is up to date");
            Ok(())
        }
    }
}

fn cargo_bin() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

/// Runs `cargo <args>` in `dir`, returning stdout.
fn cargo(dir: &Path, args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new(cargo_bin())
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("running cargo {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "cargo {} failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8(out.stdout).context("cargo output is not UTF-8")
}

/// `(name, version)` of every line of `cargo tree --prefix none --format "{p}"`.
fn tree_crates(root: &Path, extra: &[&str]) -> anyhow::Result<BTreeSet<(String, String)>> {
    let mut args = vec![
        "tree",
        "--locked",
        "--offline",
        "--edges",
        "normal,no-proc-macro",
        "--prefix",
        "none",
        "--format",
        "{p}",
    ];
    args.extend_from_slice(extra);
    let mut set = BTreeSet::new();
    for line in cargo(root, &args)?.lines().filter(|l| !l.trim().is_empty()) {
        let mut words = line.split_whitespace();
        let (Some(name), Some(version)) = (words.next(), words.next()) else {
            bail!("unexpected `cargo tree` line {line:?}");
        };
        set.insert((name.to_owned(), version.trim_start_matches('v').to_owned()));
    }
    Ok(set)
}

/// The closure report (Markdown) of `oncl-core` per feature set.
///
/// # Errors
///
/// `cargo tree` fails, or some closure contains a [`FORBIDDEN`] crate.
pub fn closure_report(root: &Path) -> anyhow::Result<String> {
    let mut sets: BTreeMap<&str, BTreeSet<(String, String)>> = BTreeMap::new();
    for (label, features) in FEATURE_SETS {
        let mut extra = vec!["--package", "oncl-core", "--no-default-features"];
        if !features.is_empty() {
            extra.extend(["--features", features]);
        }
        sets.insert(label, tree_crates(root, &extra)?);
    }
    let mut out = String::from(
        "| feature set | crates | `oncl-*` crates | forbidden (UI/desktop/updater/server/async runtime) |\n\
         |---|---|---|---|\n",
    );
    let mut offending = Vec::new();
    for (label, _) in FEATURE_SETS {
        let set = &sets[label];
        let ours: Vec<&str> = set
            .iter()
            .map(|(n, _)| n.as_str())
            .filter(|n| n.starts_with("oncl-"))
            .collect();
        let forbidden: Vec<&str> = set
            .iter()
            .map(|(n, _)| n.as_str())
            .filter(|n| FORBIDDEN.contains(n))
            .collect();
        if !forbidden.is_empty() {
            offending.push(format!("{label}: {}", forbidden.join(", ")));
        }
        writeln!(
            out,
            "| {label} | {} | {} | {} |",
            set.len(),
            ours.join(", "),
            if forbidden.is_empty() {
                "none".to_owned()
            } else {
                forbidden.join(", ")
            }
        )?;
    }
    let minimal = &sets["minimal"];
    let full = &sets["full"];
    let added: Vec<String> = full
        .difference(minimal)
        .filter(|(n, _)| n.starts_with("oncl-"))
        .map(|(n, _)| n.clone())
        .collect();
    writeln!(
        out,
        "\n`oncl-*` crates `full` adds to the minimal SDK: {}",
        added.join(", ")
    )?;
    if !offending.is_empty() {
        bail!(
            "forbidden crates in the SDK closure:\n{}\n\n{out}",
            offending.join("\n")
        );
    }
    Ok(out)
}

fn target_directory(root: &Path) -> anyhow::Result<PathBuf> {
    let metadata: Value = serde_json::from_str(&cargo(
        root,
        &[
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
            "--locked",
        ],
    )?)
    .context("parsing `cargo metadata`")?;
    metadata["target_directory"]
        .as_str()
        .map(PathBuf::from)
        .context("`cargo metadata`: no target_directory")
}

fn copy_tree(from: &Path, to: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from).with_context(|| format!("reading {}", from.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "target" || name == ".git" {
            continue;
        }
        let (src, dst) = (entry.path(), to.join(&name));
        if entry.file_type()?.is_dir() {
            copy_tree(&src, &dst)?;
        } else {
            fs::copy(&src, &dst)
                .with_context(|| format!("copying {} to {}", src.display(), dst.display()))?;
        }
    }
    Ok(())
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Packages the chain with verification (each crate is built from its own unpacked tarball,
/// resolving its siblings from an overlay of the tarballs, offline), unpacks the `.crate`
/// files and builds and runs a separate consumer against them.
///
/// # Errors
///
/// A step fails: packaging, unpacking, the consumer's build or run, its output, or a closure
/// that contains a [`FORBIDDEN`] crate or a package outside the unpacked sources.
pub fn smoke(root: &Path, keep: bool) -> anyhow::Result<()> {
    let version = workspace_version(root)?;
    let work = target_directory(root)?.join("sdk-smoke");
    if work.exists() {
        fs::remove_dir_all(&work).with_context(|| format!("removing {}", work.display()))?;
    }
    let sources = work.join("sources");
    let consumer = work.join("consumer");
    fs::create_dir_all(&sources)?;
    fs::create_dir_all(consumer.join("src"))?;

    // 1. `cargo package` of the whole chain: verified builds, no upload, no registry.
    let package_dir = target_directory(root)?.join("package");
    if package_dir.exists() {
        fs::remove_dir_all(&package_dir)?;
    }
    let mut args: Vec<String> = ["package", "--offline", "--allow-dirty"]
        .map(str::to_owned)
        .to_vec();
    for name in PATCHED {
        args.push("--config".into());
        args.push(format!("patch.crates-io.{name}.path=\"vendor/{name}\""));
    }
    for name in CHAIN {
        args.push("--package".into());
        args.push(name.into());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    cargo(root, &refs).context("packaging the SDK chain")?;
    println!(
        "packaged and verified {} crates: {}",
        CHAIN.len(),
        CHAIN.join(" ")
    );

    // 2. Unpack the tarballs.
    for name in CHAIN {
        // Unpacked from a copy named without a path.
        // `tar` of either flavour: a bare file name relative to the working directory (a
        // drive letter would read as `host:path` for GNU tar).
        let local = format!("{name}-{version}.crate");
        fs::copy(package_dir.join(&local), sources.join(&local))?;
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&local)
            .current_dir(&sources)
            .status()
            .context("running tar")?;
        fs::remove_file(sources.join(&local))?;
        if !status.success() {
            bail!("tar failed on {local}");
        }
        let dir = sources.join(format!("{name}-{version}"));
        for forbidden in ["tests", "fixtures", "target"] {
            if dir.join(forbidden).exists() {
                bail!("{name}'s package contains {forbidden}/");
            }
        }
        for file in ["LICENSE", "NOTICE", "Cargo.toml"] {
            if !dir.join(file).is_file() {
                bail!("{name}'s package has no {file}");
            }
        }
    }

    // 3. The patched crates ship as source, as for any git/path consumer.
    for name in PATCHED {
        copy_tree(
            &root.join("vendor").join(name),
            &work.join("vendor").join(name),
        )?;
    }

    // 4. The consumer: its own workspace, only the unpacked packages as SDK source.
    let core = sources.join(format!("oncl-core-{version}"));
    let pki = sources.join(format!("oncl-pki-{version}"));
    let mut manifest = String::new();
    writeln!(
        manifest,
        "[package]\nname = \"sdk-consumer\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n\
         [workspace]\n\n[dependencies]\n\
         oncl-core = {{ path = \"{}\", default-features = false, features = [\"full\"] }}\n\
         oncl-pki = {{ path = \"{}\", features = [\"testing\"] }}\n\
         rcgen = {{ version = \"={}\", default-features = false, features = [\"ring\", \"pem\", \"crypto\", \"zeroize\"] }}\n\
         getrandom = \"={}\"\nder = \"={}\"\ntime = \"={}\"\n\n[patch.crates-io]",
        toml_path(&core),
        toml_path(&pki),
        locked_version(root, "rcgen")?,
        locked_version(root, "getrandom")?,
        locked_version(root, "der")?,
        locked_version(root, "time")?
    )?;
    for name in CHAIN.iter().filter(|name| **name != "oncl-core") {
        writeln!(
            manifest,
            "{name} = {{ path = \"{}\" }}",
            toml_path(&sources.join(format!("{name}-{version}")))
        )?;
    }
    for name in PATCHED {
        writeln!(
            manifest,
            "{name} = {{ path = \"{}\" }}",
            toml_path(&work.join("vendor").join(name))
        )?;
    }
    // RSA key generation and the GOST maths are very slow unoptimized.
    for name in [
        "rsa",
        "num-bigint-dig",
        "crypto-bigint",
        "oncl-gost",
        "streebog",
    ] {
        writeln!(manifest, "\n[profile.dev.package.{name}]\nopt-level = 3")?;
    }
    fs::write(consumer.join("Cargo.toml"), manifest)?;
    let support = core.join("examples/support/mod.rs");
    if !support.is_file() {
        bail!("the oncl-core package has no examples/support/mod.rs");
    }
    fs::write(
        consumer.join("src/main.rs"),
        include_str!("../sdk_consumer/main.rs.in").replace("@SUPPORT@", &toml_path(&support)),
    )?;
    // The workspace's lock file pins the third-party versions already in the local registry.
    fs::copy(root.join("Cargo.lock"), consumer.join("Cargo.lock"))?;

    let target = work.join("target");
    let run_in_consumer = |args: &[&str]| -> anyhow::Result<String> {
        let out = Command::new(cargo_bin())
            .args(args)
            .current_dir(&consumer)
            .env("CARGO_TARGET_DIR", &target)
            .env_remove("RUSTFLAGS")
            .output()
            .context("running cargo in the consumer")?;
        if !out.status.success() {
            bail!(
                "consumer: cargo {} failed ({}):\n{}\n{}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };

    // 5. Closure and provenance of the consumer.
    let metadata: Value = serde_json::from_str(&run_in_consumer(&[
        "metadata",
        "--format-version",
        "1",
        "--offline",
    ])?)?;
    let work_prefix = work.canonicalize()?;
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let (Some(name), Some(manifest_path)) =
            (package["name"].as_str(), package["manifest_path"].as_str())
        else {
            continue;
        };
        let local = package["source"].is_null();
        if local && name != "sdk-consumer" {
            let inside = Path::new(manifest_path)
                .canonicalize()
                .is_ok_and(|p| p.starts_with(&work_prefix));
            if !inside {
                bail!("{name} comes from outside the unpacked packages: {manifest_path}");
            }
        }
    }
    let tree = run_in_consumer(&[
        "tree",
        "--offline",
        "--edges",
        "normal,no-proc-macro",
        "--prefix",
        "none",
        "--format",
        "{p}",
    ])?;
    for line in tree.lines() {
        let name = line.split_whitespace().next().unwrap_or_default();
        if FORBIDDEN.contains(&name) {
            bail!("the consumer's closure contains {name}");
        }
    }
    println!(
        "consumer closure: {} crates, none of the forbidden UI/desktop/updater/server/runtime crates",
        tree.lines().filter(|l| !l.trim().is_empty()).count()
    );

    // 6. Build and run it: a real sign and verify.
    run_in_consumer(&["build", "--offline"])?;
    let output = run_in_consumer(&["run", "--offline", "--quiet"])?;
    if !output.contains("SDK-CONSUMER-OK") {
        bail!("the consumer did not report success:\n{output}");
    }
    print!("{output}");
    if !keep {
        fs::remove_dir_all(&work).ok();
    }
    Ok(())
}

fn workspace_version(root: &Path) -> anyhow::Result<String> {
    let text = fs::read_to_string(root.join("Cargo.toml"))?;
    let table: toml::Table = toml::from_str(&text)?;
    table
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .context("Cargo.toml: no [workspace.package] version")
}

/// The licence inventory of the SDK closure: the third-party crates (crates.io or patched
/// under `vendor/`) in the closure of `oncl-core` with every feature and of the
/// `oncl-plugin`/`oncl-update` source packages, on every target the project ships for, with
/// the licence texts of the programs' inventory ([`crate::licenses::render`]).
///
/// # Errors
///
/// `cargo` fails, a package is missing from the local registry, or a package has no licence
/// text.
pub fn licenses(root: &Path) -> anyhow::Result<String> {
    let mut wanted = BTreeSet::new();
    let queries: [&[&str]; 2] = [
        &["--package", "oncl-core", "--features", "full"],
        &["--package", "oncl-plugin", "--features", "distribution"],
    ];
    for query in queries {
        let mut extra: Vec<&str> = query.to_vec();
        for target in crate::licenses::TARGETS {
            extra.extend(["--target", target]);
        }
        wanted.extend(tree_crates(root, &extra)?);
    }
    let packages = crate::licenses::registry_packages(root)?;
    let crates = pick_packages(wanted, packages)?;
    let accepted = crate::licenses::accepted_licenses(root)?;
    let standard = crate::licenses::standard_texts(&root.join(crate::licenses::STANDARD_TEXTS))?;
    let rendered = crate::licenses::render(&crates, &accepted, &standard)?;
    let Some(start) = rendered.find(crate::licenses::CRATES_HEADER) else {
        bail!(
            "the rendered inventory has no {} section",
            crate::licenses::CRATES_HEADER
        );
    };
    Ok(format!(
        "OpenNCALayer SDK: third-party software\n\
         ======================================\n\
         \n\
         The SDK crates of the chain {} and an application that embeds `oncl-core` with all\n\
         features include the crates listed below, which are not part of OpenNCALayer: the\n\
         normal (non-build, non-proc-macro) dependencies on every platform the project ships\n\
         for. Each line names a crate, its version, its licence as an SPDX expression (\"A OR B\"\n\
         is a choice between licences), its repository and the numbers of its licence texts, which\n\
         follow the list. `hmac` and `streebog` are locally modified copies (see NOTICE).\n\
         \n\
         Generated by `cargo xtask sdk licenses`; do not edit.\n\
         \n{}",
        CHAIN.join(", "),
        &rendered[start..]
    ))
}

/// The inventory's packages: every third-party crate of `wanted` must be in `packages` (the
/// crates.io and `vendor/` packages of the lock file); `oncl-*` crates are ours and skipped.
///
/// # Errors
///
/// Names the crates that are in the closure but not in `packages`: an incomplete inventory
/// must not pass.
pub fn pick_packages(
    wanted: BTreeSet<(String, String)>,
    mut packages: std::collections::HashMap<(String, String), crate::licenses::Package>,
) -> anyhow::Result<Vec<crate::licenses::Package>> {
    let mut picked = Vec::new();
    let mut missing = Vec::new();
    for key in wanted {
        match packages.remove(&key) {
            Some(package) => picked.push(package),
            None if key.0.starts_with("oncl-") => {}
            None => missing.push(format!("{} {}", key.0, key.1)),
        }
    }
    if !missing.is_empty() {
        bail!(
            "closure crates missing from the registry/vendor packages: {}",
            missing.join(", ")
        );
    }
    Ok(picked)
}

/// Whether `path` holds exactly `expected` (the `--check` comparison).
#[must_use]
pub fn inventory_is_current(path: &Path, expected: &str) -> bool {
    fs::read(path).ok().as_deref() == Some(expected.as_bytes())
}

/// Problems with the publication chain, from `cargo metadata` of the real workspace: the set
/// of crates with `publish` enabled must be exactly [`CHAIN`], and every crate must come after
/// the chain crates it depends on (normal and build dependencies; dev-dependencies are dropped
/// by `cargo package`).
///
/// # Errors
///
/// `cargo metadata` fails.
pub fn chain_problems(root: &Path) -> anyhow::Result<Vec<String>> {
    let metadata: Value = serde_json::from_str(&cargo(
        root,
        &[
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
            "--locked",
        ],
    )?)?;
    let mut problems = Vec::new();
    let mut publishable = BTreeSet::new();
    let mut deps: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let Some(name) = package["name"].as_str() else {
            continue;
        };
        // `publish: null` means any registry; `[]` means none.
        if package["publish"].as_array().is_none_or(|p| !p.is_empty()) {
            publishable.insert(name.to_owned());
        }
        let normal = package["dependencies"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|d| d["kind"].as_str() != Some("dev"))
            .filter_map(|d| d["name"].as_str().map(str::to_owned))
            .collect();
        deps.insert(name.to_owned(), normal);
    }
    let chain: BTreeSet<String> = CHAIN.iter().map(|c| (*c).to_owned()).collect();
    for name in publishable.difference(&chain) {
        problems.push(format!("{name} is publishable but not in CHAIN"));
    }
    for name in chain.difference(&publishable) {
        problems.push(format!("{name} is in CHAIN but not publishable"));
    }
    for (index, name) in CHAIN.iter().enumerate() {
        for dep in deps.get(*name).into_iter().flatten() {
            if let Some(at) = CHAIN.iter().position(|c| c == dep)
                && at >= index
            {
                problems.push(format!(
                    "{name} depends on {dep}, which comes later in CHAIN"
                ));
            }
        }
    }
    Ok(problems)
}

/// The highest locked version of `name` in the workspace's `Cargo.lock`.
fn locked_version(root: &Path, name: &str) -> anyhow::Result<String> {
    let text = fs::read_to_string(root.join("Cargo.lock")).context("reading Cargo.lock")?;
    let lock: toml::Table = toml::from_str(&text).context("parsing Cargo.lock")?;
    let key = |v: &str| -> Vec<u64> {
        v.split(['.', '-', '+'])
            .map(|part| part.parse().unwrap_or(0))
            .collect()
    };
    lock.get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| p.get("name").and_then(toml::Value::as_str) == Some(name))
        .filter_map(|p| p.get("version").and_then(toml::Value::as_str))
        .max_by_key(|v| key(v))
        .map(str::to_owned)
        .with_context(|| format!("Cargo.lock has no package {name}"))
}
