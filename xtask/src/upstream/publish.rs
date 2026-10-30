//! `cargo xtask upstream publish`: an emit directory into the `upstream` branch and the
//! issues. The emit directory is not trusted: only the expected paths, JSON files within a
//! size limit and the exact schemas pass; the issues are rendered here from `diff.json` and
//! the facts, never taken from the directory. Issues are found by their `upstream-key`, so a
//! second run on the same data creates nothing.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use serde::de::DeserializeOwned;

use super::branch::{self, BRANCH, Branch};
use super::branch_layout::{
    HISTORY_FILES, INDEX, Index, IssueRef, LATEST, RUN, RunJson, STATE, history_dir, is_entry_id,
};
use super::diff::FactsDiff;
use super::facts::{Facts, key8};
use super::github::{Client, IssueState};
use super::poll::{AlertKind, Change};
use super::pretty_json;
use super::report::{Issue, PortRef, RenderCtx, render, render_alert};
use super::run::files_under;
use super::state::State;

/// Largest file accepted from an emit directory.
pub const EMIT_FILE_MAX: u64 = 64 << 20;

/// A history entry of an emit directory.
#[derive(Clone, Debug)]
pub struct HistoryEntry {
    /// `facts.json`.
    pub facts: Facts,
    /// Its bytes.
    pub facts_bytes: Vec<u8>,
    /// `diff.json`.
    pub diff: FactsDiff,
    /// `changes.json`.
    pub changes: Vec<Change>,
}

/// A checked emit directory.
#[derive(Clone, Debug, Default)]
pub struct Emit {
    /// `state.json`.
    pub state: Option<State>,
    /// `latest/facts.json` and its bytes.
    pub latest: Option<(Facts, Vec<u8>)>,
    /// `index.json`.
    pub index: Option<Index>,
    /// `run.json`.
    pub run: Option<RunJson>,
    /// History entries by id.
    pub history: BTreeMap<String, HistoryEntry>,
}

impl Emit {
    /// Whether it has files for the branch.
    pub fn has_branch_files(&self) -> bool {
        self.state.is_some()
            || self.latest.is_some()
            || self.index.is_some()
            || !self.history.is_empty()
    }
}

fn parse<T: DeserializeOwned>(bytes: &[u8], rel: &str) -> anyhow::Result<T> {
    serde_json::from_slice(bytes).with_context(|| format!("{rel} does not match its schema"))
}

/// Checks an emit directory; see the module documentation.
///
/// # Errors
///
/// An unexpected path, a file that is not JSON, too large, or does not match its schema,
/// history facts that are not the latest facts, a `key8` that does not match.
pub fn validate_emit(emit: &Path) -> anyhow::Result<Emit> {
    let mut out = Emit::default();
    let mut history_files: BTreeMap<String, BTreeMap<String, Vec<u8>>> = BTreeMap::new();
    for rel in files_under(emit)? {
        ensure!(rel.ends_with(".json"), "{rel}: not a JSON file");
        let path = emit.join(&rel);
        let meta = std::fs::symlink_metadata(&path)?;
        ensure!(meta.is_file(), "{rel}: not a regular file");
        ensure!(
            meta.len() <= EMIT_FILE_MAX,
            "{rel}: larger than {EMIT_FILE_MAX} bytes"
        );
        let bytes = std::fs::read(&path)?;
        match rel.as_str() {
            STATE => out.state = Some(parse(&bytes, &rel)?),
            LATEST => out.latest = Some((parse(&bytes, &rel)?, bytes)),
            INDEX => out.index = Some(parse(&bytes, &rel)?),
            RUN => out.run = Some(parse(&bytes, &rel)?),
            _ => {
                let parts: Vec<&str> = rel.split('/').collect();
                match parts.as_slice() {
                    ["history", id, file] if is_entry_id(id) && HISTORY_FILES.contains(file) => {
                        history_files
                            .entry((*id).to_owned())
                            .or_default()
                            .insert((*file).to_owned(), bytes);
                    }
                    _ => bail!("{rel}: unexpected path"),
                }
            }
        }
    }
    for (id, files) in history_files {
        let get = |f: &str| {
            files
                .get(f)
                .with_context(|| format!("history/{id}/{f} is missing"))
        };
        let facts_bytes = get("facts.json")?.clone();
        let entry = HistoryEntry {
            facts: parse(&facts_bytes, "facts.json")?,
            diff: parse(get("diff.json")?, "diff.json")?,
            changes: parse(get("changes.json")?, "changes.json")?,
            facts_bytes,
        };
        let k8 = key8(&entry.facts_bytes);
        ensure!(
            id.ends_with(&format!("-{k8}")),
            "history/{id}: key8 is not {k8}"
        );
        let (_, latest) = out
            .latest
            .as_ref()
            .with_context(|| format!("history/{id} without latest/facts.json"))?;
        ensure!(
            *latest == entry.facts_bytes,
            "history/{id}/facts.json is not latest/facts.json"
        );
        let index = out
            .index
            .as_ref()
            .with_context(|| format!("history/{id} without index.json"))?;
        let last = index.entries.last().context("index.json has no entries")?;
        ensure!(
            last.id == id && last.key8 == k8,
            "index.json does not end with {id}"
        );
        ensure!(last.path == history_dir(&id), "index.json: path of {id}");
        out.history.insert(id, entry);
    }
    ensure!(out.history.len() <= 1, "more than one new history entry");
    Ok(out)
}

/// What was done with an issue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Created.
    Created(u64),
    /// Body replaced (and a comment added).
    Updated(u64),
    /// Closed: commented only.
    Commented(u64),
    /// The same body: nothing.
    Skipped(u64),
    /// Dry run: would be created (its key).
    WouldCreate(String),
}

/// How to publish.
#[derive(Debug)]
pub struct PublishOptions {
    /// The repository (a checkout with the remote).
    pub repo_dir: PathBuf,
    /// Where the branch's worktree goes.
    pub branch_dir: PathBuf,
    /// The remote.
    pub remote: String,
    /// Push the branch.
    pub push: bool,
    /// Create and update issues.
    pub issues: bool,
    /// Write nothing anywhere: no commit, no push, only GET requests.
    pub dry_run: bool,
    /// The ports, for the plugin issues.
    pub ports: Vec<PortRef>,
    /// The GitHub client (none: no issues and no dispatch).
    pub client: Option<Client>,
    /// Today, `YYYY-MM-DD` (alerts and state commits).
    pub date: String,
    /// The URL of the workflow run, for alerts.
    pub run_url: Option<String>,
    /// Extra environment of the git commands.
    pub git_env: Vec<(OsString, OsString)>,
}

/// What a publication did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublishReport {
    /// Issues by key.
    pub actions: BTreeMap<String, Action>,
    /// A commit was made.
    pub committed: bool,
    /// It was pushed.
    pub pushed: bool,
    /// `repository_dispatch` was sent.
    pub dispatched: bool,
}

/// Creates, updates or skips `issue` by its key.
fn apply_issue(
    client: &Client,
    known: &mut BTreeMap<String, IssueState>,
    issue: &Issue,
    entry: Option<&str>,
    date: &str,
    dry_run: bool,
) -> anyhow::Result<Action> {
    Ok(match known.get(&issue.key) {
        None if dry_run => Action::WouldCreate(issue.key.clone()),
        None => {
            let number = client.create_issue(issue)?;
            known.insert(
                issue.key.clone(),
                IssueState {
                    number,
                    open: true,
                    body: issue.body.clone(),
                },
            );
            Action::Created(number)
        }
        Some(s) if s.body.trim_end() == issue.body.trim_end() => Action::Skipped(s.number),
        Some(s) if dry_run => Action::Skipped(s.number),
        Some(s) => {
            let note = match entry {
                Some(id) => format!("Обновлено {date}: факты записи {id}"),
                None => format!("Повторилось {date}"),
            };
            if s.open {
                client.update_body(s.number, &issue.body)?;
                client.comment(s.number, &note)?;
                Action::Updated(s.number)
            } else {
                client.comment(s.number, &note)?;
                Action::Commented(s.number)
            }
        }
    })
}

/// Publishes `emit`; see the module documentation.
///
/// # Errors
///
/// An invalid emit directory, git or API errors.
pub fn publish(emit: &Path, opts: &PublishOptions) -> anyhow::Result<PublishReport> {
    let checked = validate_emit(emit)?;
    let mut report = PublishReport::default();
    let issues_on = opts.issues && opts.client.is_some();
    let mut known = match (&opts.client, issues_on) {
        (Some(c), true) => c.issues_by_key()?,
        _ => BTreeMap::new(),
    };
    if issues_on && !opts.dry_run {
        opts.client.as_ref().expect("issues on").ensure_labels()?;
    }

    if checked.has_branch_files() && !opts.dry_run {
        let branch = branch::open(
            &opts.repo_dir,
            &opts.remote,
            BRANCH,
            &opts.branch_dir,
            &opts.git_env,
        )?;
        branch.apply(emit)?;
        let entry = checked.history.iter().next();
        let old_facts = entry.and_then(|(id, _)| previous_facts(&branch.dir, id));
        if let (Some((id, h)), true) = (entry, issues_on) {
            let client = opts.client.as_ref().expect("issues on");
            let refs = publish_entry_issues(
                client,
                &mut known,
                id,
                h,
                old_facts.as_ref(),
                opts,
                &mut report,
            )?;
            write_issue_refs(&branch, id, refs)?;
        }
        let message = match entry {
            Some((id, _)) => format!("chore(upstream): {id}"),
            None => format!("chore(upstream): state {}", opts.date),
        };
        report.committed = branch.commit(&message)?;
        finish(&branch, opts, &mut report)?;
    } else if let (Some((id, h)), true) = (checked.history.iter().next(), issues_on) {
        let client = opts.client.as_ref().expect("issues on");
        publish_entry_issues(client, &mut known, id, h, None, opts, &mut report)?;
    }

    if let (Some(run), Some(client), true) = (&checked.run, &opts.client, issues_on) {
        for alert in &run.alerts {
            if alert.kind == AlertKind::SignerChanged {
                continue;
            }
            let issue = render_alert(
                alert.kind,
                &alert.detail,
                &opts.date,
                opts.run_url.as_deref(),
            );
            let action = apply_issue(client, &mut known, &issue, None, &opts.date, opts.dry_run)?;
            println!("alert: {} {action:?}", issue.key);
            report.actions.insert(issue.key, action);
        }
    }
    Ok(report)
}

/// Push, then dispatch, after a commit.
fn finish(
    branch: &Branch,
    opts: &PublishOptions,
    report: &mut PublishReport,
) -> anyhow::Result<()> {
    if report.committed && opts.push {
        branch.push(&opts.remote)?;
        report.pushed = true;
        println!("publish: pushed {BRANCH}");
        if let Some(client) = &opts.client {
            client.dispatch("upstream")?;
            report.dispatched = true;
        }
    }
    Ok(())
}

fn publish_entry_issues(
    client: &Client,
    known: &mut BTreeMap<String, IssueState>,
    id: &str,
    h: &HistoryEntry,
    old: Option<&Facts>,
    opts: &PublishOptions,
    report: &mut PublishReport,
) -> anyhow::Result<Vec<IssueRef>> {
    let ctx = RenderCtx {
        repo: client.repo().to_owned(),
        entry_id: id.to_owned(),
        date: id[..10].to_owned(),
        ports: opts.ports.clone(),
    };
    let mut refs = Vec::new();
    for issue in render(&h.diff, old, &h.facts, &ctx) {
        let action = apply_issue(client, known, &issue, Some(id), &opts.date, opts.dry_run)?;
        println!("issue: {} {action:?}", issue.key);
        let number = match &action {
            Action::Created(n) | Action::Updated(n) | Action::Commented(n) | Action::Skipped(n) => {
                Some(*n)
            }
            Action::WouldCreate(_) => None,
        };
        if let Some(number) = number {
            refs.push(IssueRef {
                key: issue.key.clone(),
                number,
                label: issue.label.name().to_owned(),
            });
        }
        report.actions.insert(issue.key, action);
    }
    Ok(refs)
}

/// The facts of the entry before `id` in the branch's `index.json`.
fn previous_facts(dir: &Path, id: &str) -> Option<Facts> {
    let index: Index = serde_json::from_slice(&std::fs::read(dir.join(INDEX)).ok()?).ok()?;
    let pos = index.entries.iter().position(|e| e.id == id)?;
    let prev = &index.entries.get(pos.checked_sub(1)?)?.id;
    if !is_entry_id(prev) {
        return None;
    }
    let bytes = std::fs::read(dir.join(history_dir(prev)).join("facts.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Writes `refs` into the entry `id` of the branch's `index.json`.
fn write_issue_refs(branch: &Branch, id: &str, refs: Vec<IssueRef>) -> anyhow::Result<()> {
    let path = branch.dir.join(INDEX);
    let mut index: Index = serde_json::from_slice(&std::fs::read(&path)?)?;
    if let Some(e) = index.entries.iter_mut().find(|e| e.id == id) {
        e.issues = refs;
    }
    std::fs::write(&path, pretty_json(&index))?;
    Ok(())
}

/// The issues of an entry already in the branch (`entry`, else the last), published and
/// their numbers committed: the path after facts arrive by a pull request.
///
/// # Errors
///
/// git or API errors, an unknown entry.
pub fn issues_for_entry(
    entry: Option<&str>,
    opts: &PublishOptions,
) -> anyhow::Result<PublishReport> {
    let client = opts.client.as_ref().context("issues need GITHUB_TOKEN")?;
    let mut report = PublishReport::default();
    let branch = branch::open(
        &opts.repo_dir,
        &opts.remote,
        BRANCH,
        &opts.branch_dir,
        &opts.git_env,
    )?;
    let index: Index = serde_json::from_slice(
        &std::fs::read(branch.dir.join(INDEX)).context("the branch has no index.json")?,
    )?;
    let pos = match entry {
        Some(id) => index
            .entries
            .iter()
            .position(|e| e.id == id)
            .with_context(|| format!("no entry {id}"))?,
        None => index.entries.len().checked_sub(1).context("no entries")?,
    };
    let id = index.entries[pos].id.clone();
    ensure!(is_entry_id(&id), "entry id {id}");
    let read = |id: &str, f: &str| std::fs::read(branch.dir.join(history_dir(id)).join(f));
    let facts_bytes = read(&id, "facts.json")?;
    let h = HistoryEntry {
        facts: parse(&facts_bytes, "facts.json")?,
        diff: parse(&read(&id, "diff.json")?, "diff.json")?,
        changes: parse(&read(&id, "changes.json")?, "changes.json")?,
        facts_bytes,
    };
    let old = previous_facts(&branch.dir, &id);
    let mut known = client.issues_by_key()?;
    if !opts.dry_run {
        client.ensure_labels()?;
    }
    let refs = publish_entry_issues(client, &mut known, &id, &h, old.as_ref(), opts, &mut report)?;
    if opts.dry_run {
        return Ok(report);
    }
    write_issue_refs(&branch, &id, refs)?;
    report.committed = branch.commit(&format!("chore(upstream): issues of {id}"))?;
    finish(&branch, opts, &mut report)?;
    Ok(report)
}

/// The alert `kind` raised from the workflow (one issue per kind and day).
///
/// # Errors
///
/// API errors.
pub fn alert(
    kind: AlertKind,
    detail: &str,
    run_url: Option<&str>,
    client: &Client,
    date: &str,
) -> anyhow::Result<Action> {
    let mut known = client.issues_by_key()?;
    client.ensure_labels()?;
    let issue = render_alert(kind, detail, date, run_url);
    apply_issue(client, &mut known, &issue, None, date, false)
}
