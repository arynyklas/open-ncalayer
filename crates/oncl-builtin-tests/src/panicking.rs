//! A prompter that panics in a window, for the tests of what a host function's panic leaves
//! behind (the module's instance, the locks, the other connections).

use oncl_flows::testing::ScriptedPrompter;
use oncl_flows::{
    Busy, BusyPrompt, ChoiceAnswer, ChoicePrompt, ConfirmPrompt, CsrAnswer, CsrPrompt, FilePrompt,
    ImportAnswer, ImportPrompt, KeyPrompt, MessagePrompt, PasswordPrompt, PathPrompt, Prompt,
    Prompter, ReaderPrompt, SavePrompt, StorageAnswer, StoragePrompt,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

/// A [`ScriptedPrompter`] whose key windows panic, the first `panics` times; the later ones
/// are answered by the script.
pub struct PanicOnKey {
    inner: Arc<ScriptedPrompter>,
    panics: AtomicUsize,
}

impl PanicOnKey {
    /// `inner`, panicking in its first `panics` key windows.
    pub fn new(inner: Arc<ScriptedPrompter>, panics: usize) -> Self {
        PanicOnKey {
            inner,
            panics: AtomicUsize::new(panics),
        }
    }
}

impl Prompter for PanicOnKey {
    fn storage(&self, p: &StoragePrompt) -> Prompt<StorageAnswer> {
        self.inner.storage(p)
    }

    fn busy(&self, p: &BusyPrompt) -> Busy {
        self.inner.busy(p)
    }

    fn key(&self, p: &KeyPrompt) -> Prompt<usize> {
        if self
            .panics
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
        {
            panic!("the key window of the test panics");
        }
        self.inner.key(p)
    }

    fn csr(&self, p: &CsrPrompt) -> Prompt<CsrAnswer> {
        self.inner.csr(p)
    }

    fn import_cert(&self, p: &ImportPrompt) -> Prompt<ImportAnswer> {
        self.inner.import_cert(p)
    }

    fn file(&self, p: &FilePrompt) -> Prompt<PathBuf> {
        self.inner.file(p)
    }

    fn password(&self, p: &PasswordPrompt) -> Prompt<Zeroizing<String>> {
        self.inner.password(p)
    }

    fn message(&self, p: &MessagePrompt) -> Prompt<()> {
        self.inner.message(p)
    }

    fn confirm(&self, p: &ConfirmPrompt) -> Prompt<bool> {
        self.inner.confirm(p)
    }

    fn save_file(&self, p: &SavePrompt) -> Prompt<PathBuf> {
        self.inner.save_file(p)
    }

    fn choice(&self, p: &ChoicePrompt) -> Prompt<ChoiceAnswer> {
        self.inner.choice(p)
    }

    fn path(&self, p: &PathPrompt) -> Prompt<PathBuf> {
        self.inner.path(p)
    }

    fn reader(&self, p: &ReaderPrompt) -> Prompt<String> {
        self.inner.reader(p)
    }
}
