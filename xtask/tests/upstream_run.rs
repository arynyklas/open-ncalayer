//! The whole cycle against the mock world: the emit directory, idempotence, repacks,
//! failures and what never leaves the work directory.

mod upstream_common;

use std::path::{Path, PathBuf};

use oncl_testkit::{fixture, read};
use upstream_common::{MockServer, Response, endpoints, serve_world};
use xtask::upstream::branch_layout::{Index, RunJson, is_entry_id};
use xtask::upstream::diff::{EntryKind, PluginLine};
use xtask::upstream::facts::{Facts, FetchStatus};
use xtask::upstream::http::Fetcher;
use xtask::upstream::run::{RunOptions, RunOutcome, files_under, run};
use xtask::upstream::sha256_hex;
use xtask::upstream::testkit::synthetic_issuers;
use xtask::upstream::unpack::{Limits, Tools};

/// 2026-10-31T12:00:00Z.
const NOW: i64 = 1_793_448_000;

struct Dirs {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Dirs {
    fn new() -> Dirs {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_owned();
        Dirs { _tmp: tmp, root }
    }

    fn state(&self) -> PathBuf {
        self.root.join("state")
    }

    fn emit(&self, n: u32) -> PathBuf {
        self.root.join(format!("emit{n}"))
    }
}

fn opts(server: &MockServer, state: &Path, work: &Path, emit: &Path) -> RunOptions {
    std::fs::create_dir_all(state).unwrap();
    RunOptions {
        state_dir: state.to_owned(),
        work: work.to_owned(),
        emit: emit.to_owned(),
        endpoints: endpoints(server),
        trusted: synthetic_issuers(),
        tools: Tools::default(),
        tool_versions: Default::default(),
        limits: Limits::default(),
        fetcher: Fetcher::for_tests(),
        now: time::OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
        github_output: None,
    }
}

/// Runs into `emit<n>` and copies the branch files of the emit into the state directory,
/// as the publisher would.
fn cycle(server: &MockServer, dirs: &Dirs, n: u32) -> RunOutcome {
    let emit = dirs.emit(n);
    let outcome = run(&opts(server, &dirs.state(), &dirs.root.join("work"), &emit)).unwrap();
    for rel in files_under(&emit).unwrap() {
        if rel == "run.json" {
            continue;
        }
        let dest = dirs.state().join(&rel);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::copy(emit.join(&rel), dest).unwrap();
    }
    outcome
}

fn index(dir: &Path) -> Index {
    serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap()
}

fn facts(dir: &Path) -> Facts {
    serde_json::from_slice(&std::fs::read(dir.join("latest/facts.json")).unwrap()).unwrap()
}

/// The manifest with the demo bundle at `file` (its hash) and `version`.
fn demo_at(file: &'static str, version: &'static str) -> impl FnOnce(String) -> String {
    move |json| {
        let sha = sha256_hex(&read(fixture(&format!("upstream/{file}"))));
        let start = json.find("\"symname\":\"kz.example.demo\"").unwrap();
        let end = start + json[start..].find('}').unwrap();
        let mut obj = json[start..end].to_owned();
        obj = obj.replace(
            "\"version\":\"1.0.0\"",
            &format!("\"version\":\"{version}\""),
        );
        let h = obj.find("\"hash\":\"").unwrap() + 8;
        obj.replace_range(h..h + 64, &sha);
        obj = obj.replace("bundle-a.jar", file);
        format!("{}{obj}{}", &json[..start], &json[end..])
    }
}

#[test]
fn baseline_run_emits_branch_files() {
    let server = MockServer::start();
    serve_world(&server, |j| j);
    let dirs = Dirs::new();
    let out = cycle(&server, &dirs, 1);
    assert!(out.changed);
    let id = out.entry.unwrap();
    assert!(is_entry_id(&id), "{id}");
    assert!(id.starts_with("2026-10-31-1.4-"));
    let files = files_under(&dirs.emit(1)).unwrap();
    for f in [
        "state.json".to_owned(),
        "latest/facts.json".to_owned(),
        "index.json".to_owned(),
        "run.json".to_owned(),
        format!("history/{id}/facts.json"),
        format!("history/{id}/diff.json"),
        format!("history/{id}/changes.json"),
    ] {
        assert!(files.contains(&f), "{f} not in {files:?}");
    }
    let index = index(&dirs.emit(1));
    assert_eq!(index.entries.len(), 1);
    let e = &index.entries[0];
    assert_eq!(e.kind, EntryKind::Baseline);
    assert!(e.issues.is_empty());
    assert_eq!(e.path, format!("history/{id}/"));
    let f = facts(&dirs.emit(1));
    assert_eq!(f.bundles["kz.example.demo"].fetch, FetchStatus::Ok);
    assert_eq!(f.distributions["dist:setupsh"].jars.len(), 1);
    assert_eq!(
        f.distributions["page:windows-64-bit"].unpack,
        xtask::upstream::facts::UnpackStatus::Skipped {
            reason: "no innounp".to_owned()
        }
    );
    assert!(f.distributions["page:linux"].jre.is_some());
    assert_eq!(
        f.distributions["fixed:tzdb.dat"]
            .meta
            .tzdb
            .as_ref()
            .unwrap()
            .versions,
        ["2026z"]
    );
    assert_eq!(
        std::fs::read(dirs.emit(1).join("latest/facts.json")).unwrap(),
        std::fs::read(dirs.emit(1).join(format!("history/{id}/facts.json"))).unwrap()
    );
}

#[test]
fn emit_writes_only_json() {
    let server = MockServer::start();
    serve_world(&server, |j| j);
    let dirs = Dirs::new();
    cycle(&server, &dirs, 1);
    let emitted = files_under(&dirs.emit(1)).unwrap();
    assert!(emitted.iter().all(|f| f.ends_with(".json")), "{emitted:?}");
    // The originals are in the work directory only.
    let work = files_under(&dirs.root.join("work")).unwrap();
    assert!(work.iter().any(|f| !f.ends_with(".json")));
    let jar = read(fixture("upstream/bundle-a.jar"));
    for f in &emitted {
        let bytes = std::fs::read(dirs.emit(1).join(f)).unwrap();
        assert!(
            !bytes
                .windows(64)
                .any(|w| jar.windows(64).take(1).any(|j| j == w))
        );
    }
}

#[test]
fn second_run_same_data_emits_nothing() {
    let server = MockServer::start();
    serve_world(&server, |j| j);
    let dirs = Dirs::new();
    cycle(&server, &dirs, 1);
    let out = cycle(&server, &dirs, 2);
    assert!(!out.changed, "{:?}", out.log);
    assert_eq!(files_under(&dirs.emit(2)).unwrap(), ["run.json"]);
}

#[test]
fn headers_only_change_makes_no_entry() {
    let server = MockServer::start();
    serve_world(&server, |j| j);
    let dirs = Dirs::new();
    cycle(&server, &dirs, 1);
    server.route(
        "GET",
        "/updates/installer.sh",
        Response::ok(read(fixture("upstream/installer.sh"))).header("ETag", "\"new\""),
    );
    let out = cycle(&server, &dirs, 2);
    assert!(out.entry.is_none());
    assert_eq!(
        files_under(&dirs.emit(2)).unwrap(),
        ["run.json", "state.json"]
    );
}

#[test]
fn bundle_change_makes_change_entry() {
    let server = MockServer::start();
    serve_world(&server, |j| j);
    server.route(
        "GET",
        "/updates/bundles/bundle-a-v2.jar",
        Response::ok(read(fixture("upstream/bundle-a-v2.jar"))),
    );
    let dirs = Dirs::new();
    cycle(&server, &dirs, 1);
    serve_world(&server, demo_at("bundle-a-v2.jar", "1.1.0"));
    let out = cycle(&server, &dirs, 2);
    assert!(out.entry.is_some(), "{:?}", out.log);
    let e = index(&dirs.emit(2)).entries.pop().unwrap();
    assert_eq!(e.kind, EntryKind::Change);
    assert_eq!(
        e.summary.plugins,
        [PluginLine {
            symname: "kz.example.demo".to_owned(),
            from: Some("1.0.0".to_owned()),
            to: Some("1.1.0".to_owned()),
            change: "changed".to_owned()
        }]
    );
    assert_eq!(index(&dirs.emit(2)).entries.len(), 2);
}

#[test]
fn repack_entry() {
    let server = MockServer::start();
    serve_world(&server, |j| j);
    let dirs = Dirs::new();
    cycle(&server, &dirs, 1);
    // The same URL serves the repacked JAR, the manifest gives its hash.
    serve_world(&server, |j| {
        let sha = sha256_hex(&read(fixture("upstream/bundle-a-repack.jar")));
        let old = sha256_hex(&read(fixture("upstream/bundle-a.jar")));
        j.replace(&old, &sha)
    });
    server.route(
        "GET",
        "/updates/bundles/bundle-a.jar",
        Response::ok(read(fixture("upstream/bundle-a-repack.jar"))),
    );
    cycle(&server, &dirs, 2);
    let e = index(&dirs.emit(2)).entries.pop().unwrap();
    assert_eq!(e.kind, EntryKind::Repack, "{e:?}");
}

#[test]
fn private_bundle_url_is_refused() {
    let server = MockServer::start();
    serve_world(&server, |j| j);
    let dirs = Dirs::new();
    cycle(&server, &dirs, 1);
    let f = facts(&dirs.emit(1));
    assert_eq!(f.bundles["kz.example.private"].fetch, FetchStatus::Refused);
    assert!(
        server
            .requests()
            .iter()
            .all(|r| !r.target.contains("x.jar"))
    );
}

#[test]
fn bundle_unreachable_after_three_runs() {
    let server = MockServer::start();
    serve_world(&server, |j| j);
    server.route(
        "GET",
        "/updates/bundles/bundle-a.jar",
        Response::status(503),
    );
    let dirs = Dirs::new();
    let mut seen = Vec::new();
    for n in 1..=3 {
        cycle(&server, &dirs, n);
        seen.push(facts(&dirs.state()).bundles["kz.example.demo"].fetch);
    }
    assert_eq!(
        seen,
        [
            FetchStatus::Pending,
            FetchStatus::Pending,
            FetchStatus::Unreachable
        ]
    );
}

#[test]
fn fetch_errors_do_not_echo_body() {
    let marker = "UNIQUE-BODY-MARKER-7f3a";
    let server = MockServer::start();
    serve_world(&server, |j| j);
    server.route(
        "GET",
        "/updates/installer.sh",
        Response::html(format!("<!doctype html><p>{marker}</p>").into_bytes())
            .header("Content-Type", "application/octet-stream"),
    );
    server.route(
        "GET",
        "/updates/lite.exe",
        Response {
            status: 500,
            headers: Vec::new(),
            body: marker.as_bytes().to_vec(),
        },
    );
    let dirs = Dirs::new();
    let out = cycle(&server, &dirs, 1);
    assert!(out.log.iter().all(|l| !l.contains(marker)), "{:?}", out.log);
    for f in files_under(&dirs.emit(1)).unwrap() {
        let text = std::fs::read_to_string(dirs.emit(1).join(&f)).unwrap();
        assert!(!text.contains(marker), "{f}");
    }
}

#[test]
fn bad_signature_run_alerts_without_facts_change() {
    let server = MockServer::start();
    serve_world(&server, |j| j);
    let dirs = Dirs::new();
    cycle(&server, &dirs, 1);
    let mut bad = upstream_common::signed(&upstream_common::manifest_json(&server, |j| j));
    let at = bad.windows(5).position(|w| w == b"\"1.4\"").unwrap();
    bad[at + 3] = b'5';
    server.route("GET", "/updates/ncalayer.der", Response::ok(bad));
    let out = cycle(&server, &dirs, 2);
    let run_json: RunJson =
        serde_json::from_slice(&std::fs::read(dirs.emit(2).join("run.json")).unwrap()).unwrap();
    assert_eq!(run_json.alerts.len(), 1);
    assert_eq!(run_json.alerts[0].kind.name(), "bad_signature");
    assert_eq!(out.alerts.len(), 1);
    assert!(!dirs.emit(2).join("latest/facts.json").exists());
}

#[test]
fn github_output_lines() {
    let server = MockServer::start();
    serve_world(&server, |j| j);
    let dirs = Dirs::new();
    let out_file = dirs.root.join("github_output");
    std::fs::write(&out_file, "before=1\n").unwrap();
    let mut o = opts(
        &server,
        &dirs.state(),
        &dirs.root.join("work"),
        &dirs.emit(1),
    );
    o.github_output = Some(out_file.clone());
    run(&o).unwrap();
    assert_eq!(
        std::fs::read_to_string(&out_file).unwrap(),
        "before=1\nchanged=true\nalert=false\n"
    );
}

fn page_ids(f: &Facts) -> Vec<String> {
    f.distributions
        .keys()
        .filter(|k| k.starts_with("page:"))
        .cloned()
        .collect()
}

#[test]
fn page_failure_keeps_page_distributions_until_three_strikes() {
    let server = MockServer::start();
    serve_world(&server, |j| j);
    let dirs = Dirs::new();
    cycle(&server, &dirs, 1);
    let pages = page_ids(&facts(&dirs.state()));
    assert_eq!(pages.len(), 4);
    let page = upstream_common::world_page();
    // One failure (503), one captcha-like page without links: no entry, links kept.
    server.route("GET", "/", Response::status(503));
    let out = cycle(&server, &dirs, 2);
    assert!(out.entry.is_none(), "{:?}", out.log);
    server.route(
        "GET",
        "/",
        Response::html(b"<html><p>captcha</p></html>".to_vec()),
    );
    let out = cycle(&server, &dirs, 3);
    assert!(out.entry.is_none(), "{:?}", out.log);
    assert_eq!(page_ids(&facts(&dirs.state())), pages);
    // The page is back: still no entry.
    server.route(
        "GET",
        "/",
        Response::html(page.clone().into_bytes()).header("Set-Cookie", "sid=synthetic; Path=/"),
    );
    let out = cycle(&server, &dirs, 4);
    assert!(out.entry.is_none(), "{:?}", out.log);
    assert_eq!(index(&dirs.state()).entries.len(), 1);
    // Three failures in a row: removed.
    server.route("GET", "/", Response::status(503));
    for n in 5..=6 {
        assert!(cycle(&server, &dirs, n).entry.is_none());
    }
    let out = cycle(&server, &dirs, 7);
    assert!(out.entry.is_some());
    assert!(page_ids(&facts(&dirs.state())).is_empty());
}

#[test]
fn failed_download_of_a_change_is_retried() {
    let server = MockServer::start();
    serve_world(&server, |j| j);
    let dirs = Dirs::new();
    cycle(&server, &dirs, 1);
    let old_sha = facts(&dirs.state()).distributions["page:windows-64-bit"]
        .sha256
        .clone();
    // A new Windows installer is published; its download fails once.
    let mut new = read(fixture("upstream/inno-like.exe"));
    new.extend_from_slice(b"new build");
    let mut sha1s: Vec<String> = upstream_common::PAGE_FILES
        .iter()
        .map(|(_, f)| upstream_common::sha1_hex(&read(fixture(&format!("upstream/{f}")))))
        .collect();
    sha1s[0] = upstream_common::sha1_hex(&new);
    let keys: Vec<String> = upstream_common::PAGE_FILES
        .iter()
        .map(|(c, _)| upstream_common::key(*c))
        .collect();
    let page = upstream_common::page_html(
        [&keys[0], &keys[1], &keys[2], &keys[3]],
        [&sha1s[0], &sha1s[1], &sha1s[2], &sha1s[3]],
    );
    server.route(
        "GET",
        "/",
        Response::html(page.into_bytes()).header("Set-Cookie", "sid=synthetic; Path=/"),
    );
    let target = format!("/download.php?key={}", keys[0]);
    server.route("HEAD", &target, Response::ok(new.clone()));
    server.route("GET", &target, Response::status(503));
    let out = cycle(&server, &dirs, 2);
    assert!(out.entry.is_none(), "{:?}", out.log);
    // An HTML page instead of the file: also a failure, the change still pending.
    server.route(
        "GET",
        &target,
        Response::html(read(fixture("upstream/error.html"))),
    );
    let out = cycle(&server, &dirs, 3);
    assert!(out.entry.is_none(), "{:?}", out.log);
    server.route("GET", &target, Response::ok(new.clone()));
    let out = cycle(&server, &dirs, 4);
    assert!(out.entry.is_some(), "{:?}", out.log);
    let d = &facts(&dirs.state()).distributions["page:windows-64-bit"];
    assert_eq!(d.sha256.as_deref(), Some(sha256_hex(&new).as_str()));
    assert_ne!(d.sha256, old_sha);
}
