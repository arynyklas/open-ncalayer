//! The diff of facts and the texts of the issues (`fixtures/upstream/expected/*.md`,
//! `ONCL_BLESS=1` rewrites them).

use oncl_testkit::{fixture, read};
use xtask::upstream::diff::{EntryKind, PluginLine, diff};
use xtask::upstream::facts::{BundleUpdate, Facts, FetchStatus, Updates, merge};
use xtask::upstream::jar::{jar_entries, jar_facts};
use xtask::upstream::manifest::verify_and_parse;
use xtask::upstream::poll::AlertKind;
use xtask::upstream::report::{
    BODY_MAX, Issue, Label, PortRef, RenderCtx, key_of, render, render_alert,
};
use xtask::upstream::sha256_hex;
use xtask::upstream::testkit::synthetic_issuers;
use xtask::upstream::unpack::Limits;

const DEMO: &str = "kz.example.demo";

fn jar(name: &str) -> (String, xtask::upstream::facts::JarFacts) {
    let bytes = read(fixture(&format!("upstream/{name}")));
    let facts = jar_facts(
        &jar_entries(&bytes, &Limits::default()).unwrap(),
        bytes.len() as u64,
        &synthetic_issuers(),
    );
    (sha256_hex(&bytes), facts)
}

/// The facts of the synthetic manifest with `bundle-a.jar` and `app.jar` fetched.
fn base() -> Facts {
    let v = verify_and_parse(
        &read(fixture("upstream/manifest.der")),
        &synthetic_issuers(),
    )
    .unwrap();
    let (sha_a, a) = jar("bundle-a.jar");
    let (sha_app, app) = jar("app.jar");
    let ok = |sha: &str| BundleUpdate {
        fetch: FetchStatus::Ok,
        jar: Some(sha.to_owned()),
    };
    let mut facts = merge(
        None,
        &v,
        Updates {
            bundles: [
                (DEMO.to_owned(), ok(&sha_a)),
                ("kz.example.core".to_owned(), ok(&sha_app)),
                ("kz.example.ws".to_owned(), ok(&sha_app)),
                (
                    "kz.example.private".to_owned(),
                    BundleUpdate {
                        fetch: FetchStatus::Refused,
                        jar: None,
                    },
                ),
            ]
            .into(),
            distributions: Default::default(),
            jars: [(sha_a, a), (sha_app, app)].into(),
        },
    );
    // The fixtures' own hashes change when they are rebuilt; the texts must not.
    facts.manifest.sha256 = "11".repeat(32);
    facts.manifest.signer.sha256 = "22".repeat(32);
    for (name, b) in &mut facts.bundles {
        b.hash = sha256_hex(name.as_bytes());
    }
    facts
}

/// `facts` with the demo bundle's JAR replaced by `name` at `version`.
fn with_demo_jar(mut facts: Facts, name: &str, version: &str) -> Facts {
    let (sha, j) = jar(name);
    let b = facts.bundles.get_mut(DEMO).unwrap();
    b.version = version.to_owned();
    b.hash = sha256_hex(name.as_bytes());
    b.jar = Some(sha.clone());
    facts.jars.insert(sha, j);
    facts
}

fn ctx() -> RenderCtx {
    RenderCtx {
        repo: "example/open-ncalayer".to_owned(),
        entry_id: "2026-10-31-1.5-0123abcd".to_owned(),
        date: "2026-10-31".to_owned(),
        ports: vec![PortRef {
            short: "demo".to_owned(),
            symname: DEMO.to_owned(),
            version: "1.0.0".to_owned(),
        }],
    }
}

/// Compares `text` with `fixtures/upstream/expected/<name>.md`; `ONCL_BLESS=1` rewrites it.
fn expect(name: &str, text: &str) {
    let path = fixture(&format!("upstream/expected/{name}.md"));
    if std::env::var_os("ONCL_BLESS").is_some_and(|v| v == "1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}; run with ONCL_BLESS=1 and review the file",
            path.display()
        )
    });
    assert_eq!(
        text,
        expected,
        "{}: run with ONCL_BLESS=1 and review",
        path.display()
    );
}

fn one(issues: &[Issue], label: Label) -> &Issue {
    assert_eq!(issues.len(), 1, "{issues:#?}");
    assert_eq!(issues[0].label, label);
    &issues[0]
}

#[test]
fn first_run_baseline_has_no_issue() {
    let f = base();
    let d = diff(None, &f);
    assert!(d.baseline);
    assert_eq!(d.kind(), EntryKind::Baseline);
    assert!(render(&d, None, &f, &ctx()).is_empty());
}

#[test]
fn version_bump_core_issue() {
    let old = base();
    let mut new = old.clone();
    new.manifest.version = "1.5".to_owned();
    new.manifest.sha256 = "ab".repeat(32);
    let core = new.bundles.get_mut("kz.example.core").unwrap();
    core.version = "0.9.2".to_owned();
    core.hash = "cd".repeat(32);
    let d = diff(Some(&old), &new);
    assert_eq!(d.kind(), EntryKind::Change);
    let issues = render(&d, Some(&old), &new, &ctx());
    let issue = one(&issues, Label::Upstream);
    assert_eq!(issue.key, "core:1.5:0123abcd");
    assert_eq!(issue.title, "Оригинал NCALayer: 1.5 (2026-10-31)");
    expect("core-version-bump", &issue.body);
    let s = d.summary(Some(&old), &new);
    assert!(s.core.contains(&"NCALayer 1.4 → 1.5".to_owned()), "{s:?}");
    assert!(
        s.core.contains(&"kz.example.core 0.9 → 0.9.2".to_owned()),
        "{s:?}"
    );
}

#[test]
fn plugin_only_change_makes_plugin_issue_only() {
    let old = base();
    let new = with_demo_jar(old.clone(), "bundle-a-v2.jar", "1.1.0");
    let d = diff(Some(&old), &new);
    let issues = render(&d, Some(&old), &new, &ctx());
    let issue = one(&issues, Label::UpstreamPlugin);
    assert_eq!(issue.key, "plugin:kz.example.demo:1.1.0");
    assert!(
        issue
            .body
            .contains("verify(Ljava/lang/String;)Ljava/lang/String;")
    );
    assert!(issue.body.contains("VERIFY_FAILED"));
    assert!(
        issue
            .body
            .contains("Порт: `plugins/demo`, портирована версия 1.0.0.")
    );
    expect("plugin-changed", &issue.body);
    assert_eq!(
        d.summary(Some(&old), &new).plugins,
        [PluginLine {
            symname: DEMO.to_owned(),
            from: Some("1.0.0".to_owned()),
            to: Some("1.1.0".to_owned()),
            change: "changed".to_owned()
        }]
    );
}

#[test]
fn plugin_added_issue() {
    let old = base();
    let mut new = old.clone();
    let mut extra = new.bundles[DEMO].clone();
    extra.name = "Example extra".to_owned();
    extra.version = "2.0".to_owned();
    extra.info = "a new synthetic plugin".to_owned();
    new.bundles.insert("kz.example.extra".to_owned(), extra);
    let d = diff(Some(&old), &new);
    let issues = render(&d, Some(&old), &new, &ctx());
    let issue = one(&issues, Label::UpstreamPlugin);
    assert_eq!(issue.key, "plugin:kz.example.extra:2.0");
    assert!(issue.body.contains("Порта нет."));
    expect("plugin-added", &issue.body);
}

#[test]
fn repack_only_makes_no_issue() {
    let old = base();
    let new = with_demo_jar(old.clone(), "bundle-a-repack.jar", "1.0.0");
    let d = diff(Some(&old), &new);
    assert!(render(&d, Some(&old), &new, &ctx()).is_empty());
    assert_eq!(d.kind(), EntryKind::Repack);
    let s = d.summary(Some(&old), &new);
    assert!(s.notes.iter().any(|n| n.contains("перепакован")), "{s:?}");
    assert!(s.plugins.is_empty());
}

#[test]
fn manifest_resigned_only_makes_no_issue() {
    let old = base();
    let mut new = old.clone();
    new.manifest.sha256 = "ef".repeat(32);
    let d = diff(Some(&old), &new);
    assert!(d.manifest.resigned_only);
    assert!(render(&d, Some(&old), &new, &ctx()).is_empty());
    assert_eq!(d.kind(), EntryKind::Repack);
}

#[test]
fn reachability_change_is_note_only() {
    let old = base();
    let mut new = old.clone();
    new.bundles.get_mut(DEMO).unwrap().fetch = FetchStatus::Unreachable;
    let d = diff(Some(&old), &new);
    assert!(render(&d, Some(&old), &new, &ctx()).is_empty());
    assert!(
        d.notes.iter().any(|n| n.contains("unreachable")),
        "{:?}",
        d.notes
    );
    assert!(!d.is_empty());
}

#[test]
fn signer_change_warns() {
    let old = base();
    let mut new = old.clone();
    new.manifest.signer.serial = "0abc".to_owned();
    new.manifest.signer.sha256 = "12".repeat(32);
    let d = diff(Some(&old), &new);
    let issues = render(&d, Some(&old), &new, &ctx());
    let issue = one(&issues, Label::Upstream);
    assert!(issue.body.contains("Сменился сертификат подписи манифеста"));
}

#[test]
fn alert_bodies() {
    let bad = render_alert(
        AlertKind::BadSignature,
        "manifest CMS: signature of signer 0 does not verify",
        "2026-10-31",
        Some("https://github.com/example/open-ncalayer/actions/runs/1"),
    );
    assert_eq!(bad.key, "alert:bad_signature:2026-10-31");
    assert_eq!(bad.label, Label::UpstreamAlert);
    expect("alert-bad-signature", &bad.body);
    let unreachable = render_alert(
        AlertKind::ManifestUnreachable,
        "first run: network: timeout: connect",
        "2026-10-31",
        None,
    );
    expect("alert-unreachable", &unreachable.body);
}

#[test]
fn key_marker_is_last_line() {
    let old = base();
    let new = with_demo_jar(old.clone(), "bundle-a-v2.jar", "1.1.0");
    let d = diff(Some(&old), &new);
    for issue in render(&d, Some(&old), &new, &ctx()) {
        assert_eq!(key_of(&issue.body).as_deref(), Some(issue.key.as_str()));
        assert!(
            issue
                .body
                .ends_with(&format!("<!-- upstream-key: {} -->\n", issue.key))
        );
    }
    let alert = render_alert(AlertKind::CollectFailed, "x", "2026-10-31", None);
    assert_eq!(key_of(&alert.body).as_deref(), Some(alert.key.as_str()));
}

#[test]
fn markdown_in_facts_is_escaped() {
    let old = base();
    let mut new = old.clone();
    let demo = new.bundles.get_mut(DEMO).unwrap();
    demo.info = "a | b <script>alert(1)</script>\nsecond `line`".to_owned();
    demo.version = "1.0.1|x".to_owned();
    let d = diff(Some(&old), &new);
    let issues = render(&d, Some(&old), &new, &ctx());
    let body = &one(&issues, Label::UpstreamPlugin).body;
    assert!(!body.contains("<script>"), "{body}");
    assert!(body.contains("&lt;script&gt;"));
    assert!(body.contains("> a \\| b"));
    assert!(body.contains("> second 'line'"));
    // Every table row keeps its three cells.
    for line in body.lines().filter(|l| l.starts_with("| version")) {
        assert_eq!(line.matches(" | ").count() + 2, 4, "{line}");
    }
}

#[test]
fn long_diff_is_truncated_with_note() {
    let old = base();
    let mut new = with_demo_jar(old.clone(), "bundle-a-v2.jar", "1.1.0");
    let sha = new.bundles[DEMO].jar.clone().unwrap();
    let api = &mut new.jars.get_mut(&sha).unwrap().api;
    for n in 0..500 {
        api.classes.insert(
            format!("kz.example.demo.Generated{n:03}"),
            Default::default(),
        );
    }
    let d = diff(Some(&old), &new);
    let issues = render(&d, Some(&old), &new, &ctx());
    let body = &one(&issues, Label::UpstreamPlugin).body;
    assert!(body.chars().count() <= BODY_MAX);
    assert!(body.contains("… и ещё"), "{body}");
    let rows = body.lines().filter(|l| l.starts_with("| класс")).count();
    assert!(rows <= 50, "{rows}");
}

#[test]
fn summary_strings_are_plain() {
    let old = base();
    let mut new = with_demo_jar(old.clone(), "bundle-a-v2.jar", "1.1.0|`<b>`");
    new.manifest.version = "1.5 <i>".to_owned();
    new.bundles.get_mut("kz.example.core").unwrap().fetch = FetchStatus::Unreachable;
    let d = diff(Some(&old), &new);
    let s = d.summary(Some(&old), &new);
    let mut all: Vec<String> = s.core.clone();
    all.extend(s.distributions.clone());
    all.extend(s.notes.clone());
    for p in &s.plugins {
        all.push(p.symname.clone());
        all.extend(p.from.clone());
        all.extend(p.to.clone());
    }
    assert!(!all.is_empty());
    for line in all {
        assert!(!line.contains(['|', '`', '<', '\n']), "{line}");
    }
}

fn dist(
    sha: &str,
    unpack: xtask::upstream::facts::UnpackStatus,
) -> xtask::upstream::facts::DistFacts {
    xtask::upstream::facts::DistFacts {
        url: "https://example.test/f".to_owned(),
        page: None,
        label: None,
        filename: None,
        size: Some(1),
        sha256: Some(sha.repeat(64)),
        published_sha1: None,
        format: None,
        status: FetchStatus::Ok,
        unpack,
        files: Default::default(),
        jre: None,
        jars: Default::default(),
        embedded_manifests: Default::default(),
        meta: Default::default(),
    }
}

#[test]
fn uninventoried_distribution_change_is_not_a_repack() {
    use xtask::upstream::facts::UnpackStatus;
    use xtask::upstream::meta::TzdbMeta;
    let skipped = || UnpackStatus::Skipped {
        reason: "no innounp".to_owned(),
    };
    let mut old = base();
    let mut tz = dist("a", skipped());
    tz.meta.tzdb = Some(TzdbMeta {
        versions: vec!["2026a".to_owned()],
    });
    old.distributions
        .insert("fixed:tzdb.dat".to_owned(), tz.clone());
    old.distributions
        .insert("page:windows-64-bit".to_owned(), dist("a", skipped()));
    // A new tzdb.dat.
    let mut new = old.clone();
    let t = new.distributions.get_mut("fixed:tzdb.dat").unwrap();
    t.sha256 = Some("b".repeat(64));
    t.meta.tzdb = Some(TzdbMeta {
        versions: vec!["2026b".to_owned()],
    });
    let d = diff(Some(&old), &new);
    assert_eq!(d.kind(), EntryKind::Change);
    assert!(d.needs_core_issue());
    // A new installer innounp could not unpack.
    let mut new = old.clone();
    new.distributions
        .get_mut("page:windows-64-bit")
        .unwrap()
        .sha256 = Some("c".repeat(64));
    let d = diff(Some(&old), &new);
    assert_eq!(d.kind(), EntryKind::Change);
    assert_eq!(
        one(&render(&d, Some(&old), &new, &ctx()), Label::Upstream).label,
        Label::Upstream
    );
}

#[test]
fn mentions_references_and_links_are_neutralised() {
    let old = base();
    let mut new = with_demo_jar(old.clone(), "bundle-a-v2.jar", "1.1.0");
    let demo = new.bundles.get_mut(DEMO).unwrap();
    demo.name = "@octocat [x](https://example.com)".to_owned();
    demo.info = "Ask @octocat, see #1 and o/r#2, [x](https://example.com) ![i](https://example.com/i.png) *b* _c_ ~d~ \\[e]".to_owned();
    demo.csernum = "#3 @team".to_owned();
    let d = diff(Some(&old), &new);
    let issues = render(&d, Some(&old), &new, &ctx());
    let body = &one(&issues, Label::UpstreamPlugin).body;
    for live in [
        "@octocat", "@team", "#1", "#2", "#3", "[x](", "![i]", "*b*", "_c_", "~d~",
    ] {
        assert!(!body.contains(live), "{live} is live in:\n{body}");
    }
    assert!(body.contains("@\u{2060}octocat"));
    // Inside code spans the text stays as it is.
    assert!(
        body.contains("`verify(Ljava/lang/String;)Ljava/lang/String;`"),
        "{body}"
    );
    let alert = render_alert(
        AlertKind::BadSignature,
        "CN=@octocat [x](https://e.test)",
        "2026-10-31",
        None,
    );
    assert!(!alert.body.contains("@octocat") && !alert.body.contains("[x]("));
}

#[test]
fn code_spans_keep_angle_brackets() {
    let old = base();
    let mut new = old.clone();
    let sha = new.bundles[DEMO].jar.clone().unwrap();
    new.jars
        .get_mut(&sha)
        .unwrap()
        .api
        .classes
        .get_mut("kz.example.demo.DemoModule")
        .unwrap()
        .methods
        .insert("<init>(Ljava/lang/String;)V".to_owned());
    let b = new.bundles.get_mut(DEMO).unwrap();
    b.version = "1.0.1".to_owned();
    // A JAR of other bytes with this API.
    let j = new.jars[&sha].clone();
    new.jars.insert("ff".repeat(32), j);
    new.bundles.get_mut(DEMO).unwrap().jar = Some("ff".repeat(32));
    let d = diff(Some(&old), &new);
    let issues = render(&d, Some(&old), &new, &ctx());
    let body = &one(&issues, Label::UpstreamPlugin).body;
    assert!(body.contains("`<init>(Ljava/lang/String;)V`"), "{body}");
}
