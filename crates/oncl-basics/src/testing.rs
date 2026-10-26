//! Test doubles (feature `testing`): a [`Prompter`] answering from a script and an in-memory
//! [`RecentPathStore`].

use crate::prompt::{
    CsrAnswer, CsrPrompt, FilePrompt, ImportAnswer, ImportPrompt, KeyPrompt, PasswordPrompt,
    Prompt, Prompter, RecentPathStore, StorageAnswer, StorageKind, StoragePrompt,
};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex, MutexGuard, PoisonError};
use zeroize::Zeroizing;

/// One scripted answer. Its `Debug` form is its kind alone: scripts carry passwords.
#[derive(Clone)]
pub enum Step {
    /// Answer a storage prompt with a PKCS#12 file.
    Storage {
        /// Key store file.
        path: PathBuf,
        /// Its password.
        password: String,
    },
    /// Cancel a storage prompt.
    CancelStorage,
    /// Answer a storage prompt with a JKS file.
    Jks {
        /// Key store file.
        path: PathBuf,
        /// Its password.
        password: String,
    },
    /// Pick candidate `n` in a key prompt.
    Key(usize),
    /// Cancel a key prompt.
    CancelKey,
    /// Answer a `generateCsr` prompt with PKCS#12 key files in `dir`.
    Csr {
        /// Folder for the key files.
        dir: PathBuf,
        /// The key file password (asked only without a `defaultPassword`; pass `""` then).
        password: String,
    },
    /// Cancel a `generateCsr` prompt.
    CancelCsr,
    /// Answer an `importCertificate` prompt.
    Import {
        /// Folder (or key file) holding the keys.
        dir: PathBuf,
        /// The new key file password.
        password: String,
    },
    /// Cancel an `importCertificate` prompt.
    CancelImport,
    /// Answer a file chooser with this path.
    File(PathBuf),
    /// Cancel a file chooser.
    CancelFile,
    /// Answer a password dialog.
    Password(String),
    /// Cancel a password dialog.
    CancelPassword,
    /// Wait on the barrier (without holding the prompter), then take the next step for the
    /// same prompt.
    Wait(Arc<Barrier>),
}

impl Step {
    /// The step's kind, for messages: never its password or path.
    fn kind(&self) -> &'static str {
        match self {
            Step::Storage { .. } => "Storage",
            Step::CancelStorage => "CancelStorage",
            Step::Jks { .. } => "Jks",
            Step::Key(_) => "Key",
            Step::CancelKey => "CancelKey",
            Step::Csr { .. } => "Csr",
            Step::CancelCsr => "CancelCsr",
            Step::Import { .. } => "Import",
            Step::CancelImport => "CancelImport",
            Step::File(_) => "File",
            Step::CancelFile => "CancelFile",
            Step::Password(_) => "Password",
            Step::CancelPassword => "CancelPassword",
            Step::Wait(_) => "Wait",
        }
    }
}

impl std::fmt::Debug for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())
    }
}

#[derive(Default)]
struct State {
    steps: VecDeque<Step>,
    storage_prompts: Vec<StoragePrompt>,
    key_prompts: Vec<KeyPrompt>,
    csr_prompts: Vec<CsrPrompt>,
    import_prompts: Vec<ImportPrompt>,
    file_prompts: Vec<FilePrompt>,
    password_prompts: Vec<PasswordPrompt>,
}

/// A [`Prompter`] answering from a queue of [`Step`]s and recording every prompt shown. An
/// empty queue cancels. Safe to share between threads.
///
/// # Panics
///
/// A prompt panics if the next step answers another kind of prompt.
pub struct ScriptedPrompter {
    state: Mutex<State>,
}

impl ScriptedPrompter {
    /// A prompter answering with `steps` in order.
    pub fn new(steps: Vec<Step>) -> Self {
        ScriptedPrompter {
            state: Mutex::new(State {
                steps: steps.into(),
                ..State::default()
            }),
        }
    }

    /// Storage prompts shown so far.
    pub fn storage_prompts(&self) -> Vec<StoragePrompt> {
        self.lock().storage_prompts.clone()
    }

    /// Key prompts shown so far.
    pub fn key_prompts(&self) -> Vec<KeyPrompt> {
        self.lock().key_prompts.clone()
    }

    /// `generateCsr` prompts shown so far.
    pub fn csr_prompts(&self) -> Vec<CsrPrompt> {
        self.lock().csr_prompts.clone()
    }

    /// `importCertificate` prompts shown so far.
    pub fn import_prompts(&self) -> Vec<ImportPrompt> {
        self.lock().import_prompts.clone()
    }

    /// File choosers shown so far.
    pub fn file_prompts(&self) -> Vec<FilePrompt> {
        self.lock().file_prompts.clone()
    }

    /// Password dialogs shown so far.
    pub fn password_prompts(&self) -> Vec<PasswordPrompt> {
        self.lock().password_prompts.clone()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records a prompt, then takes the next answering step, waiting out `Wait` steps with
    /// the state unlocked.
    fn next(&self, record: impl FnOnce(&mut State)) -> Option<Step> {
        let mut state = self.lock();
        record(&mut state);
        loop {
            match state.steps.pop_front() {
                Some(Step::Wait(barrier)) => {
                    drop(state);
                    barrier.wait();
                    state = self.lock();
                }
                step => return step,
            }
        }
    }
}

impl Prompter for ScriptedPrompter {
    fn storage(&self, p: &StoragePrompt) -> Prompt<StorageAnswer> {
        match self.next(|s| s.storage_prompts.push(p.clone())) {
            Some(Step::Storage { path, password }) => Prompt::Answer(StorageAnswer {
                storage: StorageKind::Pkcs12,
                path,
                password: Zeroizing::new(password),
            }),
            Some(Step::Jks { path, password }) => Prompt::Answer(StorageAnswer {
                storage: StorageKind::Jks,
                path,
                password: Zeroizing::new(password),
            }),
            Some(Step::CancelStorage) | None => Prompt::Cancelled,
            Some(step) => panic!(
                "ScriptedPrompter: storage prompt answered by {}",
                step.kind()
            ),
        }
    }

    fn key(&self, p: &KeyPrompt) -> Prompt<usize> {
        match self.next(|s| s.key_prompts.push(p.clone())) {
            Some(Step::Key(index)) => Prompt::Answer(index),
            Some(Step::CancelKey) | None => Prompt::Cancelled,
            Some(step) => panic!("ScriptedPrompter: key prompt answered by {}", step.kind()),
        }
    }

    fn csr(&self, p: &CsrPrompt) -> Prompt<CsrAnswer> {
        match self.next(|s| s.csr_prompts.push(p.clone())) {
            Some(Step::Csr { dir, password }) => Prompt::Answer(CsrAnswer {
                storage: StorageKind::Pkcs12,
                dir,
                password: Zeroizing::new(password),
            }),
            Some(Step::CancelCsr) | None => Prompt::Cancelled,
            Some(step) => panic!(
                "ScriptedPrompter: generateCsr prompt answered by {}",
                step.kind()
            ),
        }
    }

    fn import_cert(&self, p: &ImportPrompt) -> Prompt<ImportAnswer> {
        match self.next(|s| s.import_prompts.push(p.clone())) {
            Some(Step::Import { dir, password }) => Prompt::Answer(ImportAnswer {
                dir,
                new_password: Zeroizing::new(password),
            }),
            Some(Step::CancelImport) | None => Prompt::Cancelled,
            Some(step) => {
                panic!(
                    "ScriptedPrompter: importCertificate prompt answered by {}",
                    step.kind()
                )
            }
        }
    }

    fn file(&self, p: &FilePrompt) -> Prompt<PathBuf> {
        match self.next(|s| s.file_prompts.push(p.clone())) {
            Some(Step::File(path)) => Prompt::Answer(path),
            Some(Step::CancelFile) | None => Prompt::Cancelled,
            Some(step) => panic!("ScriptedPrompter: file chooser answered by {}", step.kind()),
        }
    }

    fn password(&self, p: &PasswordPrompt) -> Prompt<Zeroizing<String>> {
        match self.next(|s| s.password_prompts.push(p.clone())) {
            Some(Step::Password(password)) => Prompt::Answer(Zeroizing::new(password)),
            Some(Step::CancelPassword) | None => Prompt::Cancelled,
            Some(step) => panic!(
                "ScriptedPrompter: password dialog answered by {}",
                step.kind()
            ),
        }
    }
}

/// A [`RecentPathStore`] in memory.
pub struct MemoryRecentPath {
    initial: Option<PathBuf>,
    saved: Mutex<Option<PathBuf>>,
}

impl MemoryRecentPath {
    /// A store whose path is `initial` until something is saved.
    pub fn new(initial: Option<PathBuf>) -> Self {
        MemoryRecentPath {
            initial,
            saved: Mutex::new(None),
        }
    }

    /// The last path passed to [`RecentPathStore::save`].
    pub fn saved(&self) -> Option<PathBuf> {
        self.saved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RecentPathStore for MemoryRecentPath {
    fn load(&self) -> Option<PathBuf> {
        self.saved().or_else(|| self.initial.clone())
    }

    fn save(&self, p: &Path) {
        *self.saved.lock().unwrap_or_else(PoisonError::into_inner) = Some(p.to_path_buf());
    }
}
