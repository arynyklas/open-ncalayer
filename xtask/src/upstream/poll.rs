//! One poll of every source: the manifest (always fetched and verified), the download page
//! and HEAD of the distributions and fixed files. A failure counts; a source is removed only
//! after [`FAILURES_TO_REMOVE`] failures in a row, and a success resets the count. Bundles
//! follow the manifest, which is the authority on them: no request is made for them here.
//!
//! No request is made for the links of the page either: a `download.php?key=` key serves
//! one request only (HEAD included), so the run downloads each with a fresh key. A link is
//! judged by the SHA-1 published beside it; the page missing or the link absent from it
//! counts as a failure, otherwise only the run's downloads change its status and failures.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use oncl_pki::cert::Certificate;
use serde::{Deserialize, Serialize};

use super::artifact::{Format, TAIL_BYTES, detect_format};
use super::http::{FetchError, Fetcher, RequestCtx, Session};
use super::manifest::{Verified, verify_and_parse};
use super::sources::{PageLink, Source, SourceKind, discover, parse_download_page, without_query};
use super::state::{SourceState, SourceStatus, State};
use super::{Endpoints, FAILURES_TO_REMOVE, MANIFEST_MAX, PAGE_MAX};

/// A change of a source.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    /// New.
    Added {
        /// The source.
        id: String,
    },
    /// Gone.
    Removed {
        /// The source.
        id: String,
    },
    /// May have changed.
    Modified {
        /// The source.
        id: String,
        /// Why.
        reason: ModReason,
    },
}

impl Change {
    /// The source.
    pub fn id(&self) -> &str {
        match self {
            Change::Added { id } | Change::Removed { id } | Change::Modified { id, .. } => id,
        }
    }
}

/// Why a source may have changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModReason {
    /// The manifest's `hash` changed.
    ManifestHash,
    /// The SHA-1 on the page changed.
    PublishedSha1,
    /// Only the content can tell (downloaded every time).
    Content,
    /// Size, `ETag` or `Last-Modified` changed.
    Headers,
}

/// Something to raise as an alert.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alert {
    /// What.
    pub kind: AlertKind,
    /// Details (never bytes of a response).
    pub detail: String,
}

/// The kinds of alerts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// The manifest's signature or signer does not verify.
    BadSignature,
    /// The manifest cannot be fetched (on the first run, or several polls in a row).
    ManifestUnreachable,
    /// The manifest signer's certificate changed: a note, not a failure.
    SignerChanged,
    /// The collecting job failed.
    CollectFailed,
}

impl AlertKind {
    /// The name in keys and texts (`bad_signature`, …).
    pub fn name(self) -> &'static str {
        match self {
            AlertKind::BadSignature => "bad_signature",
            AlertKind::ManifestUnreachable => "manifest_unreachable",
            AlertKind::SignerChanged => "signer_changed",
            AlertKind::CollectFailed => "collect_failed",
        }
    }
}

/// Why the manifest is not available this time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PollFailure {
    /// It could not be fetched.
    Unreachable(String),
    /// It did not verify.
    BadSignature(String),
}

/// The outcome of a poll.
#[derive(Clone, Debug)]
pub struct PollResult {
    /// The next `state.json`.
    pub next: State,
    /// The verified manifest.
    pub manifest: Result<Verified, PollFailure>,
    /// Every source seen (empty without a manifest).
    pub sources: Vec<Source>,
    /// Changes, sorted.
    pub changes: Vec<Change>,
    /// Alerts.
    pub alerts: Vec<Alert>,
    /// The session of the page, for downloads of its links.
    pub session: Arc<Mutex<Session>>,
}

/// Polls every source; see the module documentation.
pub fn poll(
    prev: &State,
    fetcher: &Fetcher,
    endpoints: &Endpoints,
    prev_manifest: Option<&Verified>,
    trusted: &[Certificate],
) -> PollResult {
    let mut next = prev.clone();
    let mut changes = Vec::new();
    let mut alerts = Vec::new();
    let session = Arc::new(Mutex::new(Session::default()));
    let had_baseline = prev
        .sources
        .get("manifest")
        .is_some_and(|s| s.sha256.is_some());

    // An HTML page (error, captcha) with status 200 is a failed fetch, not a bad signature.
    let fetched = fetcher
        .get(&endpoints.manifest, MANIFEST_MAX, &RequestCtx::default())
        .map_err(|e| e.to_string())
        .and_then(|got| {
            let html_type = got
                .content_type
                .as_deref()
                .is_some_and(|t| t.trim().to_ascii_lowercase().starts_with("text/html"));
            let tail = &got.body[got.body.len().saturating_sub(TAIL_BYTES)..];
            if html_type || detect_format(&got.body, tail) != Format::Der {
                Err("not a DER manifest (an HTML page or another file)".to_owned())
            } else {
                Ok(got)
            }
        });
    let manifest = match fetched {
        Err(e) => {
            let entry = next.sources.entry("manifest".to_owned()).or_default();
            entry.url = endpoints.manifest.clone();
            // Capped, so that the state stops changing while the manifest stays unreachable.
            entry.failures = (entry.failures + 1).min(FAILURES_TO_REMOVE);
            entry.status = SourceStatus::Failing;
            if entry.failures >= FAILURES_TO_REMOVE || !had_baseline {
                alerts.push(Alert {
                    kind: AlertKind::ManifestUnreachable,
                    detail: if had_baseline {
                        format!("{FAILURES_TO_REMOVE} polls or more in a row: {e}")
                    } else {
                        format!("first run: {e}")
                    },
                });
            }
            Err(PollFailure::Unreachable(e))
        }
        Ok(got) => match verify_and_parse(&got.body, trusted) {
            Err(e) => {
                alerts.push(Alert {
                    kind: AlertKind::BadSignature,
                    detail: e.to_string(),
                });
                Err(PollFailure::BadSignature(e.to_string()))
            }
            Ok(v) => Ok(v),
        },
    };
    let Ok(verified) = manifest else {
        return PollResult {
            next,
            manifest,
            sources: Vec::new(),
            changes,
            alerts,
            session,
        };
    };

    if let Some(prev) = prev_manifest
        && prev.signer != verified.signer
    {
        alerts.push(Alert {
            kind: AlertKind::SignerChanged,
            detail: format!(
                "serial {} → {}, sha256 {} → {}",
                prev.signer.serial,
                verified.signer.serial,
                prev.signer.sha256,
                verified.signer.sha256
            ),
        });
    }
    {
        let before = prev.sources.get("manifest").and_then(|s| s.sha256.clone());
        match before {
            None => changes.push(Change::Added {
                id: "manifest".to_owned(),
            }),
            Some(b) if b != verified.sha256 => changes.push(Change::Modified {
                id: "manifest".to_owned(),
                reason: ModReason::Content,
            }),
            Some(_) => {}
        }
        next.sources.insert(
            "manifest".to_owned(),
            SourceState {
                url: endpoints.manifest.clone(),
                size: Some(verified.size),
                sha256: Some(verified.sha256.clone()),
                ..SourceState::default()
            },
        );
    }

    let page_ctx = RequestCtx {
        referer: None,
        session: Some(Arc::clone(&session)),
    };
    let page: Option<Vec<PageLink>> = fetcher
        .get(&endpoints.page, PAGE_MAX, &page_ctx)
        .ok()
        .map(|p| parse_download_page(&String::from_utf8_lossy(&p.body), &endpoints.page));
    let sources = discover(&verified, page.as_deref().unwrap_or_default(), endpoints);
    let seen: BTreeSet<&str> = sources.iter().map(|s| s.id.as_str()).collect();

    // Sources of the last poll not seen now.
    for (id, state) in &prev.sources {
        if seen.contains(id.as_str()) || id == "manifest" {
            continue;
        }
        if id.starts_with("page:") {
            // The page is not the authority: its absence counts as a failure.
            if let Some(change) = fail(next.sources.get_mut(id).expect("copied from prev"), id) {
                changes.push(change);
            }
        } else if state.status != SourceStatus::Gone {
            changes.push(Change::Removed { id: id.clone() });
            next.sources.remove(id);
        } else {
            next.sources.remove(id);
        }
    }

    for source in &sources {
        let before = prev
            .sources
            .get(&source.id)
            .filter(|s| s.status != SourceStatus::Gone);
        match &source.kind {
            SourceKind::Manifest => {}
            SourceKind::Bundle { .. } => {
                // A bundle's failures are of its download (counted by the run), not of the
                // manifest that lists it.
                let before = prev.sources.get(&source.id);
                let hash = source.expected_sha256.clone();
                let entry = next.sources.entry(source.id.clone()).or_default();
                match before {
                    None => changes.push(Change::Added {
                        id: source.id.clone(),
                    }),
                    Some(b) if b.manifest_hash != hash || b.url != source.url => {
                        changes.push(Change::Modified {
                            id: source.id.clone(),
                            reason: ModReason::ManifestHash,
                        });
                    }
                    Some(_) => {}
                }
                // A new JAR starts a new run of download failures.
                if before.is_none_or(|b| b.manifest_hash != hash || b.url != source.url) {
                    *entry = SourceState::default();
                }
                entry.url = source.url.clone();
                entry.manifest_hash = hash;
            }
            SourceKind::Page { published_sha1, .. } => {
                match before {
                    // New or back after removal: starts afresh.
                    None => {
                        changes.push(Change::Added {
                            id: source.id.clone(),
                        });
                        next.sources
                            .insert(source.id.clone(), SourceState::default());
                    }
                    // Whether its address is public now, only the run's download can tell.
                    Some(b) if b.status == SourceStatus::Refused => {}
                    Some(b) => {
                        if published_sha1.is_none() {
                            changes.push(Change::Modified {
                                id: source.id.clone(),
                                reason: ModReason::Content,
                            });
                        } else if b.published_sha1 != *published_sha1 {
                            changes.push(Change::Modified {
                                id: source.id.clone(),
                                reason: ModReason::PublishedSha1,
                            });
                        }
                    }
                }
                // Status and failures are left to the run's download.
                let entry = next.sources.entry(source.id.clone()).or_default();
                entry.url = without_query(&source.url);
                entry.etag = None;
                entry.last_modified = None;
                entry.published_sha1 = published_sha1.clone();
            }
            SourceKind::Dist { .. } | SourceKind::Fixed => {
                match head_ok(fetcher, &source.url, &RequestCtx::default()) {
                    Err(Refusal::Refused) => refuse(&mut next, source),
                    Err(Refusal::Failed) => {
                        // A known source keeps what was last seen of it, so that a change
                        // of the manifest is still reported once HEAD succeeds.
                        let known = next.sources.contains_key(&source.id);
                        let entry = next.sources.entry(source.id.clone()).or_default();
                        if !known {
                            entry.url = source.url.clone();
                            entry.manifest_hash = source.expected_sha256.clone();
                        }
                        if let Some(change) = fail(entry, &source.id) {
                            changes.push(change);
                        }
                    }
                    Ok(head) => {
                        match before {
                            Some(b) if b.status != SourceStatus::Refused => {
                                if b.manifest_hash != source.expected_sha256 || b.url != source.url
                                {
                                    changes.push(Change::Modified {
                                        id: source.id.clone(),
                                        reason: ModReason::ManifestHash,
                                    });
                                } else if b.size != head.content_length
                                    || b.etag != head.etag
                                    || b.last_modified != head.last_modified
                                {
                                    changes.push(Change::Modified {
                                        id: source.id.clone(),
                                        reason: ModReason::Headers,
                                    });
                                }
                            }
                            _ => changes.push(Change::Added {
                                id: source.id.clone(),
                            }),
                        }
                        let entry = next.sources.entry(source.id.clone()).or_default();
                        entry.url = source.url.clone();
                        entry.size = head.content_length;
                        entry.etag = head.etag;
                        entry.last_modified = head.last_modified;
                        entry.manifest_hash = source.expected_sha256.clone();
                        entry.failures = 0;
                        entry.status = SourceStatus::Ok;
                    }
                }
            }
        }
    }
    changes.sort();
    changes.dedup();
    PollResult {
        next,
        manifest: Ok(verified),
        sources,
        changes,
        alerts,
        session,
    }
}

enum Refusal {
    Refused,
    Failed,
}

/// HEAD of `url`; an HTML answer is a failure.
fn head_ok(fetcher: &Fetcher, url: &str, ctx: &RequestCtx) -> Result<super::http::Head, Refusal> {
    match fetcher.head(url, ctx) {
        Err(FetchError::RefusedAddress(_)) => Err(Refusal::Refused),
        Err(_) => Err(Refusal::Failed),
        Ok(head)
            if head
                .content_type
                .as_deref()
                .is_some_and(|t| t.trim().to_ascii_lowercase().starts_with("text/html")) =>
        {
            Err(Refusal::Failed)
        }
        Ok(head) => Ok(head),
    }
}

fn refuse(next: &mut State, source: &Source) {
    let entry = next.sources.entry(source.id.clone()).or_default();
    entry.url = without_query(&source.url);
    entry.manifest_hash = source.expected_sha256.clone();
    entry.status = SourceStatus::Refused;
    entry.failures = 0;
}

/// Counts a failure of a source: [`Change::Removed`] on the
/// [`FAILURES_TO_REMOVE`]th in a row.
pub fn fail(entry: &mut SourceState, id: &str) -> Option<Change> {
    if entry.status == SourceStatus::Gone {
        return None;
    }
    entry.failures += 1;
    if entry.failures >= FAILURES_TO_REMOVE {
        entry.status = SourceStatus::Gone;
        Some(Change::Removed { id: id.to_owned() })
    } else {
        entry.status = SourceStatus::Failing;
        None
    }
}
