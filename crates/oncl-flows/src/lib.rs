//! What the core shows the built-in modules and the plugins: the [`Prompter`] dialogs, the
//! dialog-flow turn ([`lock_dialog_flow`]: dialog flows run one at a time process-wide, so a
//! second request waits for the first one's dialogs to finish), the key choice
//! ([`KeyChooser`], [`KeyFlow`]) with the keys checked against a chain and their OCSP
//! responders while the key dialog is up ([`LiveAvailability`], [`OcspCache`]), the rules
//! for paths a page names ([`PageFile`], [`page_path`], [`remember_chosen_path`]), and the
//! consent a token PIN from a page needs ([`PagePins`]).

pub mod capabilities;
mod filter;
mod keys;
mod live;
mod ocsp_cache;
mod page_file;
mod page_pin;
mod prompt;
#[cfg(feature = "testing")]
pub mod testing;
mod tokens;

pub use filter::{
    Availability, ChainPolicy, DisabledReason, FilterMore, KeyFilter, OCSP_DEADLINE, availabilities,
};
pub use keys::{
    FileRead, FlowOpen, KeyChecks, KeyChooser, KeyFlow, KeyOrder, KeyRequest, OpenedFlow,
    PasswordRules, Readers, StartPath, WrongPin, inner_password_ok,
};
pub use live::LiveAvailability;
pub use ocsp_cache::{ANSWER_FOR, OcspCache, UNREACHABLE_FOR};
pub use page_file::{
    MAX_CHOSEN_NETWORK_PATHS, MAX_PAGE_FILE, PageFile, PageFileError, is_device_path,
    is_network_path, page_path, remember_chosen_path,
};
pub use page_pin::{ASK_EVERY_TIME_AT, PagePins, PinFrom, PinRefusal, PinUse, page_pin_text};
pub use prompt::{
    Action, Busy, BusyPrompt, ChoiceAnswer, ChoicePrompt, ConfirmPrompt, CsrAnswer, CsrPrompt,
    FileKind, FilePrompt, ImportAnswer, ImportPrompt, KeyCandidate, KeyPrompt, Locale, MessageKind,
    MessagePrompt, OpenError, PasswordPrompt, PathFilter, PathMode, PathPrompt, Prompt, Prompter,
    ReaderPrompt, RecentPathStore, SavePrompt, StorageAnswer, StorageKind, StoragePrompt,
};
use std::sync::{Mutex, MutexGuard, PoisonError};
pub use tokens::{ReaderEntry, ReaderList, ReaderProblem};

/// Serializes dialog flows process-wide: the dialogs of two requests never
/// interleave, and a second request waits for the first instead of failing as busy.
static DIALOG_FLOW: Mutex<()> = Mutex::new(());

/// Takes the process-wide dialog-flow turn: a module showing these dialogs holds it for its
/// whole flow, so flows of different modules do not interleave.
pub fn lock_dialog_flow() -> MutexGuard<'static, ()> {
    DIALOG_FLOW.lock().unwrap_or_else(PoisonError::into_inner)
}
