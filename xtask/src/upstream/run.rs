//! `cargo xtask upstream run`: poll → download what changed into the work directory →
//! check, unpack, inventory → facts → diff → an emit directory that mirrors the changed files
//! of the `upstream` branch, plus `run.json`. The emit directory holds JSON only; the
//! originals stay in the work directory. The log names sources, sizes and hashes, never
//! bodies or tool output.
//!
//! A key of the download page serves one request, so each page link is downloaded with a
//! fresh one: right before, the page is read again in a new session (pinned to the address
//! that answered it) and the link with the same identity is taken. Only these downloads
//! change a page source's status; a failing or refused one is tried again on every run. A
//! failed download does not count towards its removal: only polls that do not find it on
//! the page do (see the poll).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use oncl_pki::cert::Certificate;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::artifact::{ArtifactError, check_artifact};
use super::branch_layout::{
    INDEX, INDEX_SCHEMA, Index, IndexEntry, LATEST, RUN, RunJson, STATE, ToolVersions, entry_id,
    history_dir,
};
use super::diff::diff;
use super::facts::{
    BundleUpdate, DistInput, Facts, FetchStatus, Updates, dist_facts, key8, merge, to_json,
};
use super::http::{FetchError, Fetcher, RequestCtx, Session, proxy_ignored};
use super::inventory::inventory;
use super::jar::{jar_entries, jar_facts};
use super::poll::{Alert, AlertKind, Change, ModReason, poll};
use super::sources::{Source, SourceKind, parse_download_page};
use super::state::{SourceStatus, State};
use super::unpack::{Limits, Tools, Unpacked, unpack};
use super::{BUNDLE_MAX, DIST_MAX, Endpoints, FAILURES_TO_REMOVE, PAGE_MAX, pretty_json};

/// What a run needs.
pub struct RunOptions {
    /// A checkout of the `upstream` branch, or an empty directory.
    pub state_dir: PathBuf,
    /// Where the originals are downloaded and unpacked.
    pub work: PathBuf,
    /// The emit directory (emptied first).
    pub emit: PathBuf,
    /// The sources.
    pub endpoints: Endpoints,
    /// The CAs of the manifest signer.
    pub trusted: Vec<Certificate>,
    /// External unpackers.
    pub tools: Tools,
    /// Their versions, for `run.json`.
    pub tool_versions: ToolVersions,
    /// Unpacking limits.
    pub limits: Limits,
    /// The HTTP client.
    pub fetcher: Fetcher,
    /// Now.
    pub now: OffsetDateTime,
    /// `$GITHUB_OUTPUT`: `changed=` and `alert=` lines are appended.
    pub github_output: Option<PathBuf>,
}

/// What a run did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunOutcome {
    /// Branch files were emitted.
    pub changed: bool,
    /// The new history entry.
    pub entry: Option<String>,
    /// Alerts (the signer-change note excluded).
    pub alerts: Vec<Alert>,
    /// The log lines (also printed).
    pub log: Vec<String>,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

fn write(emit: &Path, rel: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let path = emit.join(rel);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    std::fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))
}

/// Every file under `dir` (relative, `/`-separated).
pub fn files_under(dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    let mut stack = vec![dir.to_owned()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).with_context(|| format!("read {}", d.display()))? {
            let entry = entry?;
            let ty = entry.file_type()?;
            if ty.is_dir() {
                stack.push(entry.path());
            } else {
                let rel = entry.path();
                let rel = rel.strip_prefix(dir).expect("under dir");
                out.push(
                    rel.components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/"),
                );
            }
        }
    }
    out.sort();
    Ok(out)
}

struct Logger(Vec<String>);

impl Logger {
    fn line(&mut self, line: String) {
        println!("{line}");
        self.0.push(line);
    }
}

/// Runs the cycle; see the module documentation.
///
/// # Errors
///
/// Unreadable branch files, I/O of the work and emit directories, or a non-JSON file in the
/// emit directory.
pub fn run(opts: &RunOptions) -> anyhow::Result<RunOutcome> {
    let mut log = Logger(Vec::new());
    if let Some(note) = proxy_ignored() {
        log.line(note.to_owned());
    }
    let prev_state = State::load(&opts.state_dir)?;
    let prev_facts: Option<Facts> = read_json(&opts.state_dir.join(LATEST))?;
    let prev_latest = std::fs::read(opts.state_dir.join(LATEST)).ok();
    let mut index: Index = read_json(&opts.state_dir.join(INDEX))?.unwrap_or_default();
    let prev_state_bytes = std::fs::read(opts.state_dir.join(STATE)).ok();

    if opts.emit.exists() {
        std::fs::remove_dir_all(&opts.emit)
            .with_context(|| format!("empty {}", opts.emit.display()))?;
    }
    std::fs::create_dir_all(&opts.emit)?;
    let dl = opts.work.join("dl");
    if dl.exists() {
        std::fs::remove_dir_all(&dl).with_context(|| format!("empty {}", dl.display()))?;
    }
    std::fs::create_dir_all(&dl)?;

    let polled = poll(
        &prev_state,
        &opts.fetcher,
        &opts.endpoints,
        None,
        &opts.trusted,
    );
    for c in &polled.changes {
        let reason = match c {
            Change::Added { .. } => "added".to_owned(),
            Change::Removed { .. } => "removed".to_owned(),
            Change::Modified { reason, .. } => format!(
                "modified:{}",
                serde_json::to_value(reason)?.as_str().unwrap_or("")
            ),
        };
        log.line(format!("poll: {} {reason}", c.id()));
    }
    let alerts: Vec<Alert> = polled
        .alerts
        .iter()
        .filter(|a| a.kind != AlertKind::SignerChanged)
        .cloned()
        .collect();
    for a in &polled.alerts {
        log.line(format!("alert: {} {}", a.kind.name(), a.detail));
    }
    let mut next_state = polled.next.clone();
    let mut entry = None;

    if let Ok(verified) = &polled.manifest {
        let changed: BTreeMap<&str, &Change> = polled.changes.iter().map(|c| (c.id(), c)).collect();
        let mut updates = Updates::default();
        let mut n = 0usize;
        for source in &polled.sources {
            let change = changed.get(source.id.as_str()).copied();
            match &source.kind {
                SourceKind::Manifest => {}
                SourceKind::Bundle { symname } => {
                    let before = prev_facts.as_ref().and_then(|f| f.bundles.get(symname));
                    let retry = before.is_none_or(|b| {
                        b.fetch == FetchStatus::Pending
                            || !b.hash.eq_ignore_ascii_case(
                                source.expected_sha256.as_deref().unwrap_or(""),
                            )
                            || b.url != source.url
                    });
                    if change.is_none() && !retry {
                        continue;
                    }
                    n += 1;
                    let dest = dl.join(format!("{n}.jar"));
                    let (update, jar) =
                        fetch_bundle(opts, source, &dest, &mut next_state, &mut log);
                    if let Some((sha, facts)) = jar {
                        updates.jars.insert(sha, facts);
                    }
                    updates.bundles.insert(symname.clone(), update);
                }
                SourceKind::Dist { .. } | SourceKind::Page { .. } | SourceKind::Fixed => {
                    if matches!(change, Some(Change::Removed { .. })) {
                        updates.distributions.insert(source.id.clone(), None);
                        continue;
                    }
                    let known = prev_facts
                        .as_ref()
                        .and_then(|f| f.distributions.get(&source.id))
                        .is_some_and(|d| d.status == FetchStatus::Ok);
                    let page = matches!(source.kind, SourceKind::Page { .. });
                    let not_ok = next_state
                        .sources
                        .get(&source.id)
                        .is_some_and(|s| s.status != SourceStatus::Ok);
                    // A page link has no poll of its own: a failing or refused one is retried.
                    if not_ok && !page {
                        continue;
                    }
                    if change.is_none() && known && !not_ok {
                        continue;
                    }
                    n += 1;
                    let dest = dl.join(n.to_string());
                    let headers_only = known
                        && matches!(
                            change,
                            None | Some(Change::Modified {
                                reason: ModReason::Headers | ModReason::Content,
                                ..
                            })
                        );
                    let (url, ctx) = if page {
                        match fresh_link(opts, source) {
                            Ok(link) => link,
                            Err(e) => {
                                log.line(format!("fetch: {} failed: {e}", source.id));
                                forget_and_fail(&prev_state, &mut next_state, &source.id);
                                continue;
                            }
                        }
                    } else {
                        (source.url.clone(), RequestCtx::default())
                    };
                    if let Some(facts) = fetch_dist(
                        opts,
                        source,
                        &url,
                        &ctx,
                        &dest,
                        headers_only,
                        &prev_state,
                        &mut next_state,
                        &mut updates,
                        &mut log,
                    ) {
                        updates.distributions.insert(source.id.clone(), Some(facts));
                    }
                }
            }
        }
        // Distributions of the last facts whose source is gone: dropped from the manifest or
        // failed FAILURES_TO_REMOVE polls in a row (a page that failed once keeps its links).
        for (id, _) in prev_facts.iter().flat_map(|f| f.distributions.iter()) {
            let gone = next_state
                .sources
                .get(id)
                .is_none_or(|s| s.status == SourceStatus::Gone);
            if gone && !polled.sources.iter().any(|s| &s.id == id) {
                updates.distributions.insert(id.clone(), None);
            }
        }

        let facts = merge(prev_facts.as_ref(), verified, updates);
        let json = to_json(&facts);
        if prev_latest.as_deref() != Some(json.as_slice()) {
            let k8 = key8(&json);
            log.line(format!("facts: {k8}"));
            let d = diff(prev_facts.as_ref(), &facts);
            let date = opts.now.date().to_string();
            let id = entry_id(&date, &facts.manifest.version, &k8);
            let dir = history_dir(&id);
            write(&opts.emit, &format!("{dir}facts.json"), &json)?;
            write(&opts.emit, &format!("{dir}diff.json"), &pretty_json(&d))?;
            write(
                &opts.emit,
                &format!("{dir}changes.json"),
                &pretty_json(&polled.changes),
            )?;
            write(&opts.emit, LATEST, &json)?;
            index.schema = INDEX_SCHEMA;
            index.entries.retain(|e| e.id != id);
            index.entries.push(IndexEntry {
                id: id.clone(),
                date,
                observed: opts.now.format(&Rfc3339)?,
                version: facts.manifest.version.clone(),
                key8: k8,
                path: dir,
                kind: d.kind(),
                summary: d.summary(prev_facts.as_ref(), &facts),
                issues: Vec::new(),
            });
            write(&opts.emit, INDEX, &pretty_json(&index))?;
            entry = Some(id);
        }
    }

    let state_json = next_state.to_json();
    if prev_state_bytes.as_deref() != Some(state_json.as_slice()) {
        write(&opts.emit, STATE, &state_json)?;
    }
    let changed = entry.is_some() || prev_state_bytes.as_deref() != Some(state_json.as_slice());
    let run_json = RunJson {
        schema: INDEX_SCHEMA,
        changed,
        entry: entry.clone(),
        alerts: alerts.clone(),
        tools: opts.tool_versions.clone(),
    };
    write(&opts.emit, RUN, &pretty_json(&run_json))?;

    let stray: Vec<String> = files_under(&opts.emit)?
        .into_iter()
        .filter(|f| !f.ends_with(".json"))
        .collect();
    if !stray.is_empty() {
        bail!("non-JSON files in the emit directory: {stray:?}");
    }
    if let Some(out) = &opts.github_output {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(out)
            .with_context(|| format!("open {}", out.display()))?;
        writeln!(f, "changed={changed}")?;
        writeln!(f, "alert={}", !alerts.is_empty())?;
    }
    Ok(RunOutcome {
        changed,
        entry,
        alerts,
        log: log.0,
    })
}

/// Counts a failed download of a bundle: [`FetchStatus::Pending`] until the
/// [`FAILURES_TO_REMOVE`]th in a row, then [`FetchStatus::Unreachable`].
fn bundle_failure(state: &mut State, id: &str) -> FetchStatus {
    let entry = state.sources.entry(id.to_owned()).or_default();
    entry.failures += 1;
    if entry.failures >= FAILURES_TO_REMOVE {
        entry.status = SourceStatus::Gone;
        FetchStatus::Unreachable
    } else {
        entry.status = SourceStatus::Failing;
        FetchStatus::Pending
    }
}

fn fetch_bundle(
    opts: &RunOptions,
    source: &Source,
    dest: &Path,
    state: &mut State,
    log: &mut Logger,
) -> (BundleUpdate, Option<(String, super::facts::JarFacts)>) {
    let fail = |fetch| (BundleUpdate { fetch, jar: None }, None);
    let d = match opts
        .fetcher
        .download(&source.url, BUNDLE_MAX, &RequestCtx::default(), dest)
    {
        Ok(d) => d,
        Err(FetchError::RefusedAddress(_)) => {
            log.line(format!("fetch: {} refused", source.id));
            let entry = state.sources.entry(source.id.clone()).or_default();
            entry.status = SourceStatus::Refused;
            entry.failures = 0;
            return fail(FetchStatus::Refused);
        }
        Err(e) => {
            log.line(format!("fetch: {} failed: {e}", source.id));
            return fail(bundle_failure(state, &source.id));
        }
    };
    log.line(format!(
        "fetch: {} {} {}",
        source.id,
        d.size,
        &d.sha256[..16]
    ));
    match check_artifact(&d, source) {
        Err(ArtifactError::HashMismatch { .. }) => {
            log.line(format!("fetch: {} hash mismatch", source.id));
            let _ = std::fs::remove_file(dest);
            return fail(FetchStatus::HashMismatch);
        }
        Err(e) => {
            log.line(format!("fetch: {} refused file: {e}", source.id));
            let _ = std::fs::remove_file(dest);
            return fail(bundle_failure(state, &source.id));
        }
        Ok(_) => {}
    }
    let facts = std::fs::read(dest)
        .ok()
        .and_then(|bytes| {
            jar_entries(&bytes, &opts.limits)
                .ok()
                .map(|e| (bytes.len(), e))
        })
        .map(|(size, entries)| jar_facts(&entries, size as u64, &opts.trusted));
    let entry = state.sources.entry(source.id.clone()).or_default();
    entry.sha256 = Some(d.sha256.clone());
    entry.failures = 0;
    entry.status = SourceStatus::Ok;
    (
        BundleUpdate {
            fetch: FetchStatus::Ok,
            jar: Some(d.sha256.clone()),
        },
        facts.map(|f| (d.sha256, f)),
    )
}

/// The link of the page source `source` with a fresh key, and what its download goes with:
/// the page read again in a new session, so that one backend gone quiet fails one link only.
fn fresh_link(opts: &RunOptions, source: &Source) -> Result<(String, RequestCtx), String> {
    let ctx = RequestCtx {
        referer: None,
        session: Some(Arc::new(Mutex::new(Session::default()))),
    };
    let page = opts
        .fetcher
        .get(&opts.endpoints.page, PAGE_MAX, &ctx)
        .map_err(|e| format!("download page: {e}"))?;
    let url = parse_download_page(&String::from_utf8_lossy(&page.body), &opts.endpoints.page)
        .into_iter()
        .find(|link| source.id.strip_prefix("page:") == Some(link.slug.as_str()))
        .map(|link| link.url)
        .ok_or_else(|| "the link is gone from the download page".to_owned())?;
    Ok((
        url,
        RequestCtx {
            referer: Some(opts.endpoints.page.clone()),
            ..ctx
        },
    ))
}

/// What this poll saw of a source whose download did not succeed is forgotten, so that the
/// next poll reports the change again.
fn forget(prev: &State, state: &mut State, id: &str) {
    if let Some(entry) = state.sources.get_mut(id) {
        let seen = prev.sources.get(id).cloned().unwrap_or_default();
        entry.size = seen.size;
        entry.etag = seen.etag;
        entry.last_modified = seen.last_modified;
        entry.published_sha1 = seen.published_sha1;
        entry.manifest_hash = seen.manifest_hash;
        entry.sha256 = seen.sha256;
    }
}

/// A download of a distribution failed: [`forget`], and the failure is counted. For a page
/// link it is only marked failing: its `failures` count the polls that did not find it on
/// the page, and only they remove it.
fn forget_and_fail(prev: &State, state: &mut State, id: &str) {
    forget(prev, state, id);
    if let Some(entry) = state.sources.get_mut(id) {
        if id.starts_with("page:") {
            entry.status = SourceStatus::Failing;
        } else {
            super::poll::fail(entry, id);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn fetch_dist(
    opts: &RunOptions,
    source: &Source,
    url: &str,
    ctx: &RequestCtx,
    dest: &Path,
    headers_only: bool,
    prev: &State,
    state: &mut State,
    updates: &mut Updates,
    log: &mut Logger,
) -> Option<super::facts::DistFacts> {
    let page = matches!(source.kind, SourceKind::Page { .. });
    let d = match opts.fetcher.download(url, DIST_MAX, ctx, dest) {
        Ok(d) => d,
        // A page link is not requested by the poll: its download is what finds it refused.
        Err(FetchError::RefusedAddress(_)) if page => {
            log.line(format!("fetch: {} refused", source.id));
            forget(prev, state, &source.id);
            if let Some(entry) = state.sources.get_mut(&source.id) {
                entry.status = SourceStatus::Refused;
                entry.failures = 0;
            }
            return None;
        }
        Err(e) => {
            log.line(format!("fetch: {} failed: {e}", source.id));
            forget_and_fail(prev, state, &source.id);
            return None;
        }
    };
    log.line(format!(
        "fetch: {} {} {}",
        source.id,
        d.size,
        &d.sha256[..16]
    ));
    let before = prev.sources.get(&source.id).and_then(|s| s.sha256.clone());
    if let Some(entry) = state.sources.get_mut(&source.id) {
        entry.sha256 = Some(d.sha256.clone());
        if page {
            entry.size = Some(d.size);
        }
    }
    // A page source's status follows its downloads only.
    let page_ok = |state: &mut State| {
        if page && let Some(entry) = state.sources.get_mut(&source.id) {
            entry.failures = 0;
            entry.status = SourceStatus::Ok;
        }
    };
    // Checked first: content kept as unchanged still matches the manifest and the page.
    let format = match check_artifact(&d, source) {
        Ok(f) => f,
        Err(e) => {
            log.line(format!("fetch: {} refused file: {e}", source.id));
            let _ = std::fs::remove_file(dest);
            forget_and_fail(prev, state, &source.id);
            return None;
        }
    };
    page_ok(state);
    if headers_only && before.as_deref() == Some(d.sha256.as_str()) {
        log.line(format!("fetch: {} content unchanged", source.id));
        return None;
    }
    let work = dest.with_extension("d");
    let unpacked = unpack(&d.path, format, &work, &opts.tools, &opts.limits);
    let inv = match &unpacked {
        Ok(Unpacked::Tree(tree)) => match inventory(tree, &opts.limits) {
            Ok(inv) => Some(Ok(inv)),
            Err(e) => Some(Err(e.to_string())),
        },
        _ => None,
    };
    let unpacked_ref: Result<&Unpacked, String> = match (&unpacked, &inv) {
        (Err(e), _) => Err(e.to_string()),
        (_, Some(Err(e))) => Err(e.clone()),
        (Ok(u), _) => Ok(u),
    };
    match &unpacked_ref {
        Ok(Unpacked::Tree(_)) => log.line(format!("unpack: {} ok", source.id)),
        Ok(Unpacked::Skipped { reason }) => {
            log.line(format!("unpack: {} skipped:{reason}", source.id))
        }
        Err(e) => log.line(format!("unpack: {} failed:{e}", source.id)),
    }
    let (facts, jars) = dist_facts(
        &DistInput {
            source,
            page: page.then_some(opts.endpoints.page.as_str()),
            downloaded: Some(&d),
            format: Some(format),
            status: FetchStatus::Ok,
            unpacked: unpacked_ref,
            inventory: inv.as_ref().and_then(|i| i.as_ref().ok()),
        },
        &opts.trusted,
        &opts.limits,
    );
    updates.jars.extend(jars);
    Some(facts)
}
