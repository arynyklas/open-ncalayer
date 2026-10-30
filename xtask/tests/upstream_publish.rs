//! Publishing: the strict check of the emit directory, the `upstream` branch in a bare
//! `origin`, idempotent issues against a fake GitHub API, dispatch and alerts.

mod upstream_common;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use oncl_testkit::{fixture, read};
use serde_json::{Value, json};
use upstream_common::{MockServer, Recorded, Response, endpoints, serve_world};
use xtask::upstream::branch_layout::Index;
use xtask::upstream::github::Client;
use xtask::upstream::http::Fetcher;
use xtask::upstream::poll::AlertKind;
use xtask::upstream::publish::{
    Action, PublishOptions, alert, issues_for_entry, publish, validate_emit,
};
use xtask::upstream::report::{PortRef, key_marker};
use xtask::upstream::run::{RunOptions, files_under, run};
use xtask::upstream::sha256_hex;
use xtask::upstream::testkit::synthetic_issuers;
use xtask::upstream::unpack::{Limits, Tools};

// ---- A fake GitHub API ----

#[derive(Default)]
struct Hub {
    issues: Vec<Value>,
    labels: Vec<String>,
    comments: Vec<(u64, String)>,
    dispatches: Vec<Value>,
    fail_all: bool,
}

fn fake_github(server: &MockServer) -> Arc<Mutex<Hub>> {
    let hub = Arc::new(Mutex::new(Hub::default()));
    let h = Arc::clone(&hub);
    server.handler(move |r: &Recorded| {
        let mut hub = h.lock().unwrap();
        if hub.fail_all {
            return Some(Response::status(500));
        }
        let path = r.path().strip_prefix("/repos/o/r")?.to_owned();
        let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        let query = r.target.split_once('?').map_or("", |(_, q)| q);
        let param = |name: &str| {
            query
                .split('&')
                .find_map(|p| p.strip_prefix(&format!("{name}=")))
                .unwrap_or_default()
                .to_owned()
        };
        Some(match (r.method.as_str(), path.as_str()) {
            ("GET", "/issues") => {
                let label = param("labels");
                let page: usize = param("page").parse().unwrap_or(1);
                let items: Vec<Value> = hub
                    .issues
                    .iter()
                    .filter(|i| {
                        i["labels"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|l| l["name"] == label.as_str())
                    })
                    .skip((page - 1) * 100)
                    .take(100)
                    .cloned()
                    .collect();
                Response::json(200, &Value::Array(items))
            }
            ("POST", "/issues") => {
                let number = hub.issues.len() as u64 + 1;
                let labels: Vec<Value> = body["labels"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|l| json!({ "name": l }))
                    .collect();
                hub.issues.push(json!({
                    "number": number,
                    "title": body["title"],
                    "body": body["body"],
                    "state": "open",
                    "labels": labels,
                }));
                Response::json(201, &json!({ "number": number }))
            }
            ("PATCH", p) if p.starts_with("/issues/") => {
                let n: u64 = p["/issues/".len()..].parse().unwrap();
                let issue = hub.issues.iter_mut().find(|i| i["number"] == n).unwrap();
                if let Some(b) = body.get("body") {
                    issue["body"] = b.clone();
                }
                if let Some(s) = body.get("state") {
                    issue["state"] = s.clone();
                }
                Response::json(200, &json!({}))
            }
            ("POST", p) if p.ends_with("/comments") => {
                let n: u64 = p["/issues/".len()..p.len() - "/comments".len()]
                    .parse()
                    .unwrap();
                hub.comments
                    .push((n, body["body"].as_str().unwrap().to_owned()));
                Response::json(201, &json!({}))
            }
            ("GET", p) if p.starts_with("/labels/") => {
                let name = &p["/labels/".len()..];
                if hub.labels.iter().any(|l| l == name) {
                    Response::json(200, &json!({ "name": name }))
                } else {
                    Response::json(404, &json!({}))
                }
            }
            ("POST", "/labels") => {
                hub.labels.push(body["name"].as_str().unwrap().to_owned());
                Response::json(201, &json!({}))
            }
            ("POST", "/dispatches") => {
                hub.dispatches.push(body);
                Response::status(204)
            }
            _ => Response::status(404),
        })
    });
    hub
}

// ---- Git and the world ----

struct Setup {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    world: MockServer,
    github: MockServer,
    hub: Arc<Mutex<Hub>>,
    env: Vec<(OsString, OsString)>,
}

impl Setup {
    fn new() -> Setup {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_owned();
        let gitconfig = root.join("gitconfig");
        std::fs::write(
            &gitconfig,
            "[user]\n\tname = Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n",
        )
        .unwrap();
        let env = vec![
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                gitconfig.into_os_string(),
            ),
            (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        ];
        let world = MockServer::start();
        serve_world(&world, |j| j);
        world.route(
            "GET",
            "/updates/bundles/bundle-a-v2.jar",
            Response::ok(read(fixture("upstream/bundle-a-v2.jar"))),
        );
        let github = MockServer::start();
        let hub = fake_github(&github);
        let s = Setup {
            _tmp: tmp,
            root,
            world,
            github,
            hub,
            env,
        };
        s.git(&s.root, &["init", "-q", "--bare", "origin.git"]);
        s.git(&s.root, &["init", "-q", "repo"]);
        let repo = s.repo();
        std::fs::write(repo.join("README"), "main\n").unwrap();
        s.git(&repo, &["add", "README"]);
        s.git(&repo, &["commit", "-q", "-m", "main"]);
        s.git(&repo, &["remote", "add", "origin", "../origin.git"]);
        s
    }

    fn repo(&self) -> PathBuf {
        self.root.join("repo")
    }

    fn origin(&self) -> PathBuf {
        self.root.join("origin.git")
    }

    fn git(&self, dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn try_git(&self, dir: &Path, args: &[&str]) -> Option<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .output()
            .unwrap();
        out.status
            .success()
            .then(|| String::from_utf8(out.stdout).unwrap())
    }

    fn client(&self) -> Client {
        Client::new(&self.github.base, "o/r", "secret-token-value")
    }

    fn opts(&self, branch_dir: &str) -> PublishOptions {
        PublishOptions {
            repo_dir: self.repo(),
            branch_dir: self.root.join(branch_dir),
            remote: "origin".to_owned(),
            push: true,
            issues: true,
            dry_run: false,
            ports: vec![PortRef {
                short: "demo".to_owned(),
                symname: "kz.example.demo".to_owned(),
                version: "1.0.0".to_owned(),
            }],
            client: Some(self.client()),
            date: "2026-10-31".to_owned(),
            run_url: None,
            git_env: self.env.clone(),
        }
    }

    /// A run into `emit<n>` from the published branch (checked out into `state<n>`).
    fn emit(&self, n: u32) -> PathBuf {
        let state = self.root.join(format!("state{n}"));
        std::fs::create_dir_all(&state).unwrap();
        if let Some(tree) = self.try_git(
            &self.origin(),
            &["ls-tree", "-r", "--name-only", "upstream"],
        ) {
            for f in tree.lines() {
                let bytes = self.git(&self.origin(), &["show", &format!("upstream:{f}")]);
                let dest = state.join(f);
                std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                std::fs::write(dest, bytes).unwrap();
            }
        }
        let emit = self.root.join(format!("emit{n}"));
        run(&RunOptions {
            state_dir: state,
            work: self.root.join("work"),
            emit: emit.clone(),
            dry_run: true,
            endpoints: endpoints(&self.world),
            trusted: synthetic_issuers(),
            tools: Tools::default(),
            tool_versions: Default::default(),
            limits: Limits::default(),
            fetcher: Fetcher::for_tests(),
            now: time::OffsetDateTime::from_unix_timestamp(1_793_448_000).unwrap(),
            github_output: None,
        })
        .unwrap();
        emit
    }

    /// The world moves the demo plugin to 1.1.0.
    fn bump_demo(&self) {
        serve_world(&self.world, |json| {
            let old = sha256_hex(&read(fixture("upstream/bundle-a.jar")));
            let new = sha256_hex(&read(fixture("upstream/bundle-a-v2.jar")));
            json.replace(&old, &new)
                .replace("bundle-a.jar", "bundle-a-v2.jar")
                .replace(
                    "\"version\":\"1.0.0\",\"info\":\"synthetic plugin\"",
                    "\"version\":\"1.1.0\",\"info\":\"synthetic plugin\"",
                )
        });
    }

    fn commits(&self) -> Vec<String> {
        self.try_git(&self.origin(), &["rev-list", "upstream"])
            .map(|s| s.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    fn writes(&self) -> Vec<Recorded> {
        self.github
            .requests()
            .into_iter()
            .filter(|r| r.method != "GET")
            .collect()
    }
}

/// A baseline published, then the demo plugin bumped: the second emit has one plugin issue.
fn second_emit(s: &Setup) -> PathBuf {
    let first = s.emit(1);
    publish(&first, &s.opts("b1")).unwrap();
    s.bump_demo();
    s.emit(2)
}

#[test]
fn creates_then_skips_same_body() {
    let s = Setup::new();
    let emit = second_emit(&s);
    let first = publish(&emit, &s.opts("b2")).unwrap();
    assert_eq!(
        first.actions.values().collect::<Vec<_>>(),
        [&Action::Created(1)]
    );
    s.github.clear_requests();
    let again = publish(&emit, &s.opts("b3")).unwrap();
    assert_eq!(
        again.actions.values().collect::<Vec<_>>(),
        [&Action::Skipped(1)]
    );
    assert!(
        s.writes().iter().all(|r| !r.path().contains("/issues")),
        "{:?}",
        s.writes()
    );
    assert!(!again.committed);
}

#[test]
fn updates_changed_body_with_comment() {
    let s = Setup::new();
    let emit = second_emit(&s);
    s.hub.lock().unwrap().issues.push(json!({
        "number": 7, "title": "old", "state": "open",
        "body": format!("old text\n\n{}\n", key_marker("plugin:kz.example.demo:1.1.0")),
        "labels": [{ "name": "upstream-plugin" }],
    }));
    let r = publish(&emit, &s.opts("b2")).unwrap();
    assert_eq!(
        r.actions.values().collect::<Vec<_>>(),
        [&Action::Updated(7)]
    );
    let hub = s.hub.lock().unwrap();
    assert!(
        hub.issues[0]["body"]
            .as_str()
            .unwrap()
            .contains("1.0.0 → 1.1.0")
    );
    assert_eq!(hub.comments.len(), 1);
    assert!(hub.comments[0].1.starts_with("Обновлено 2026-10-31"));
}

#[test]
fn closed_issue_gets_comment_not_reopen() {
    let s = Setup::new();
    let emit = second_emit(&s);
    s.hub.lock().unwrap().issues.push(json!({
        "number": 7, "title": "old", "state": "closed",
        "body": format!("old text\n\n{}\n", key_marker("plugin:kz.example.demo:1.1.0")),
        "labels": [{ "name": "upstream-plugin" }],
    }));
    s.github.clear_requests();
    let r = publish(&emit, &s.opts("b2")).unwrap();
    assert_eq!(
        r.actions.values().collect::<Vec<_>>(),
        [&Action::Commented(7)]
    );
    assert!(s.writes().iter().all(|r| r.method != "PATCH"));
    assert_eq!(s.hub.lock().unwrap().issues[0]["state"], "closed");
}

#[test]
fn pull_requests_are_ignored() {
    let s = Setup::new();
    let emit = second_emit(&s);
    s.hub.lock().unwrap().issues.push(json!({
        "number": 1, "title": "a PR", "state": "open", "pull_request": {},
        "body": format!("x\n\n{}\n", key_marker("plugin:kz.example.demo:1.1.0")),
        "labels": [{ "name": "upstream-plugin" }],
    }));
    let r = publish(&emit, &s.opts("b2")).unwrap();
    assert_eq!(
        r.actions.values().collect::<Vec<_>>(),
        [&Action::Created(2)]
    );
}

#[test]
fn dry_run_makes_no_requests() {
    let s = Setup::new();
    let emit = s.emit(1);
    let mut o = s.opts("b1");
    o.dry_run = true;
    publish(&emit, &o).unwrap();
    assert!(s.writes().is_empty(), "{:?}", s.writes());
    assert!(s.commits().is_empty());
    // With an issue to make too.
    let first = s.emit(2);
    publish(&first, &s.opts("b2")).unwrap();
    s.bump_demo();
    let emit = s.emit(3);
    let before = s.commits();
    s.github.clear_requests();
    let mut o = s.opts("b3");
    o.dry_run = true;
    let r = publish(&emit, &o).unwrap();
    assert!(matches!(
        r.actions.values().next(),
        Some(Action::WouldCreate(_))
    ));
    assert!(s.writes().is_empty());
    assert_eq!(s.commits(), before);
}

#[test]
fn branch_first_run_creates_orphan_with_json_only() {
    let s = Setup::new();
    let emit = s.emit(1);
    let r = publish(&emit, &s.opts("b1")).unwrap();
    assert!(r.committed && r.pushed);
    let commits = s.commits();
    assert_eq!(commits.len(), 1);
    let parents = s.git(
        &s.origin(),
        &["rev-list", "--parents", "-n", "1", "upstream"],
    );
    assert_eq!(
        parents.split_whitespace().count(),
        1,
        "no parent: {parents}"
    );
    let files = s.git(&s.origin(), &["ls-tree", "-r", "--name-only", "upstream"]);
    assert!(files.lines().all(|f| f.ends_with(".json")), "{files}");
    assert!(files.lines().any(|f| f == "index.json"));
    assert!(!files.lines().any(|f| f == "run.json"));
}

#[test]
fn branch_holds_only_json() {
    let s = Setup::new();
    let emit = s.emit(1);
    std::fs::write(emit.join("x.bin"), b"original").unwrap();
    assert!(publish(&emit, &s.opts("b1")).is_err());
    assert!(s.commits().is_empty());
}

#[test]
fn publish_rejects_non_json_and_unknown_fields() {
    let s = Setup::new();
    let emit = s.emit(1);
    assert!(validate_emit(&emit).is_ok());
    // An unknown field.
    let path = emit.join("latest/facts.json");
    let good = std::fs::read(&path).unwrap();
    let mut v: Value = serde_json::from_slice(&good).unwrap();
    v["extra_field"] = json!(1);
    std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    assert!(validate_emit(&emit).is_err());
    std::fs::write(&path, &good).unwrap();
    // Unexpected paths.
    for bad in [
        "x.json",
        "history/../x.json",
        "history/not-an-id/facts.json",
        "latest/other.json",
    ] {
        let p = emit.join(bad);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"{}").unwrap();
        assert!(validate_emit(&emit).is_err(), "{bad}");
        std::fs::remove_file(&p).unwrap();
    }
    // History facts other than the latest.
    let id = files_under(&emit)
        .unwrap()
        .into_iter()
        .find(|f| f.starts_with("history/") && f.ends_with("/facts.json"))
        .unwrap();
    let mut other: Value = serde_json::from_slice(&good).unwrap();
    other["manifest"]["version"] = json!("9.9");
    std::fs::write(emit.join(&id), serde_json::to_vec_pretty(&other).unwrap()).unwrap();
    assert!(validate_emit(&emit).is_err());
    assert!(publish(&emit, &s.opts("b1")).is_err());
    assert!(s.commits().is_empty());
}

#[test]
fn no_facts_change_no_commit_no_dispatch() {
    let s = Setup::new();
    let first = s.emit(1);
    publish(&first, &s.opts("b1")).unwrap();
    let dispatched = s.hub.lock().unwrap().dispatches.len();
    let emit = s.emit(2);
    assert_eq!(files_under(&emit).unwrap(), ["run.json"]);
    let r = publish(&emit, &s.opts("b2")).unwrap();
    assert!(!r.committed && !r.dispatched);
    assert_eq!(s.hub.lock().unwrap().dispatches.len(), dispatched);
    assert_eq!(s.commits().len(), 1);
}

#[test]
fn push_then_dispatch() {
    let s = Setup::new();
    let emit = s.emit(1);
    let r = publish(&emit, &s.opts("b1")).unwrap();
    assert!(r.dispatched);
    let hub = s.hub.lock().unwrap();
    assert_eq!(hub.dispatches, [json!({ "event_type": "upstream" })]);
}

#[test]
fn issue_numbers_written_to_index() {
    let s = Setup::new();
    let emit = second_emit(&s);
    publish(&emit, &s.opts("b2")).unwrap();
    let index: Index =
        serde_json::from_str(&s.git(&s.origin(), &["show", "upstream:index.json"])).unwrap();
    let last = index.entries.last().unwrap();
    assert_eq!(last.issues.len(), 1);
    assert_eq!(last.issues[0].key, "plugin:kz.example.demo:1.1.0");
    assert_eq!(last.issues[0].number, 1);
    assert_eq!(last.issues[0].label, "upstream-plugin");
    // In the commit of the entry itself.
    let msg = s.git(&s.origin(), &["log", "-1", "--format=%s", "upstream"]);
    assert!(
        msg.trim().starts_with("chore(upstream): 2026-10-31-"),
        "{msg}"
    );
}

#[test]
fn rerun_after_failed_push_skips_issues_and_commits() {
    let s = Setup::new();
    let first = s.emit(1);
    publish(&first, &s.opts("b1")).unwrap();
    s.bump_demo();
    let emit = s.emit(2);
    let hook = s.origin().join("hooks").join("pre-receive");
    std::fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert!(publish(&emit, &s.opts("b2")).is_err());
    assert_eq!(s.commits().len(), 1);
    std::fs::remove_file(&hook).unwrap();
    let r = publish(&emit, &s.opts("b3")).unwrap();
    assert_eq!(
        r.actions.values().collect::<Vec<_>>(),
        [&Action::Skipped(1)]
    );
    assert_eq!(s.hub.lock().unwrap().issues.len(), 1);
    assert_eq!(s.commits().len(), 2);
}

#[test]
fn labels_created_once() {
    let s = Setup::new();
    let emit = second_emit(&s);
    publish(&emit, &s.opts("b2")).unwrap();
    assert_eq!(s.hub.lock().unwrap().labels.len(), 3);
    s.github.clear_requests();
    publish(&emit, &s.opts("b3")).unwrap();
    assert!(s.writes().iter().all(|r| r.path() != "/repos/o/r/labels"));
    assert_eq!(s.hub.lock().unwrap().labels.len(), 3);
}

#[test]
fn alert_dedup_by_day() {
    let s = Setup::new();
    let client = s.client();
    assert_eq!(
        alert(AlertKind::CollectFailed, "x", None, &client, "2026-10-31").unwrap(),
        Action::Created(1)
    );
    assert_eq!(
        alert(AlertKind::CollectFailed, "x", None, &client, "2026-10-31").unwrap(),
        Action::Skipped(1)
    );
    assert_eq!(
        alert(AlertKind::CollectFailed, "x", None, &client, "2026-11-01").unwrap(),
        Action::Created(2)
    );
}

#[test]
fn token_never_printed() {
    let s = Setup::new();
    s.hub.lock().unwrap().fail_all = true;
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["upstream", "alert", "--kind", "collect-failed"])
        .env("GITHUB_API_URL", &s.github.base)
        .env("GITHUB_REPOSITORY", "o/r")
        .env("GITHUB_TOKEN", "secret-token-value")
        .output()
        .unwrap();
    assert!(!out.status.success());
    for stream in [&out.stdout, &out.stderr] {
        assert!(!String::from_utf8_lossy(stream).contains("secret-token-value"));
    }
    assert!(String::from_utf8_lossy(&out.stderr).contains("status 500"));
}

#[test]
fn issues_only_mode_from_branch() {
    let s = Setup::new();
    let first = s.emit(1);
    publish(&first, &s.opts("b1")).unwrap();
    s.bump_demo();
    let emit = s.emit(2);
    let mut o = s.opts("b2");
    o.issues = false;
    publish(&emit, &o).unwrap();
    assert!(s.hub.lock().unwrap().issues.is_empty());
    let r = issues_for_entry(None, &s.opts("b3")).unwrap();
    assert_eq!(
        r.actions.values().collect::<Vec<_>>(),
        [&Action::Created(1)]
    );
    assert!(r.committed);
    let index: Index =
        serde_json::from_str(&s.git(&s.origin(), &["show", "upstream:index.json"])).unwrap();
    assert_eq!(index.entries.last().unwrap().issues.len(), 1);
}
