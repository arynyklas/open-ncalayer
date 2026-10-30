//! Hardware tokens in the storage dialog: the readers holding a token of each family, as the
//! last scan saw them, and how a token's errors read as storage errors.

use crate::prompt::{OpenError, StorageKind};
use oncl_token::{ScanProblem, TokenError, Tokens};
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// A reader holding a token of a known family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderEntry {
    /// The token's storage.
    pub storage: StorageKind,
    /// The reader's name.
    pub reader: String,
}

/// Why a scan of the readers saw nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderProblem {
    /// The smart card service is not available.
    NoService,
    /// The smart card service failed.
    Failed,
}

/// What a scan saw: the readers holding tokens, in the service's order, and its problem.
type Seen = (Vec<ReaderEntry>, Option<ReaderProblem>);

/// The readers the storage dialog offers, scanned on request (the dialog's opening and its
/// refresh button), never in the background. Clones share the list; two lists are equal
/// when they are the same list.
#[derive(Clone)]
pub struct ReaderList(Arc<Inner>);

struct Inner {
    /// Where scans come from; `None` for a fixed list.
    tokens: Option<Arc<Tokens>>,
    last: Mutex<Seen>,
    rescans: AtomicUsize,
}

impl ReaderList {
    /// The readers of `tokens`, scanned once now. Blocks while the service answers.
    pub fn new(tokens: Arc<Tokens>) -> ReaderList {
        let seen = scan(&tokens);
        ReaderList(Arc::new(Inner {
            tokens: Some(tokens),
            last: Mutex::new(seen),
            rescans: AtomicUsize::new(0),
        }))
    }

    /// A list that always holds `entries` and `problem`: a reader chosen beforehand, or a
    /// test's.
    pub fn fixed(entries: Vec<ReaderEntry>, problem: Option<ReaderProblem>) -> ReaderList {
        ReaderList(Arc::new(Inner {
            tokens: None,
            last: Mutex::new((entries, problem)),
            rescans: AtomicUsize::new(0),
        }))
    }

    /// What the last scan saw.
    pub fn current(&self) -> (Vec<ReaderEntry>, Option<ReaderProblem>) {
        self.lock().clone()
    }

    /// Scans again and keeps the result: what it saw. Blocks while the service answers, so
    /// a user interface calls it off its event loop.
    pub fn rescan(&self) -> (Vec<ReaderEntry>, Option<ReaderProblem>) {
        self.0.rescans.fetch_add(1, Ordering::SeqCst);
        let Some(tokens) = &self.0.tokens else {
            return self.current();
        };
        let seen = scan(tokens);
        *self.lock() = seen.clone();
        seen
    }

    /// How many times [`ReaderList::rescan`] ran.
    pub fn rescans(&self) -> usize {
        self.0.rescans.load(Ordering::SeqCst)
    }

    /// The readers of the last scan holding a token of `storage`.
    pub fn readers_of(&self, storage: StorageKind) -> Vec<String> {
        self.lock()
            .0
            .iter()
            .filter(|e| e.storage == storage)
            .map(|e| e.reader.clone())
            .collect()
    }

    fn lock(&self) -> MutexGuard<'_, Seen> {
        self.0.last.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl PartialEq for ReaderList {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ReaderList {}

impl fmt::Debug for ReaderList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seen = self.lock();
        f.debug_struct("ReaderList")
            .field("readers", &seen.0)
            .field("problem", &seen.1)
            .finish()
    }
}

/// A scan of `tokens` as reader entries.
fn scan(tokens: &Tokens) -> Seen {
    let scan = tokens.scan();
    let entries = scan
        .present
        .into_iter()
        .filter_map(|p| {
            Some(ReaderEntry {
                storage: StorageKind::from_name(p.kind.storage_name())?,
                reader: p.reader,
            })
        })
        .collect();
    let problem = scan.problem.map(|p| match p {
        ScanProblem::NoService => ReaderProblem::NoService,
        ScanProblem::Failed(e) => {
            tracing::warn!(error = %e, "the smart card service failed");
            ReaderProblem::Failed
        }
    });
    (entries, problem)
}

/// A token's error as the storage dialog shows it.
pub(crate) fn open_error(e: &TokenError) -> OpenError {
    match e {
        TokenError::Disabled => OpenError::UnsupportedStorage,
        TokenError::NoService => OpenError::TokenService,
        TokenError::NoDevice | TokenError::WrongCard | TokenError::CardRemoved => {
            OpenError::TokenAbsent
        }
        TokenError::WrongPin { tries_left } => OpenError::WrongPin {
            tries_left: *tries_left,
        },
        TokenError::PinBlocked => OpenError::PinBlocked,
        TokenError::InvalidPin => OpenError::InvalidPin,
        TokenError::Card { .. } | TokenError::Malformed(_) | TokenError::Transport(_) => {
            OpenError::TokenFailure
        }
    }
}
