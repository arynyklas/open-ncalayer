//! Test doubles (feature `testing`): a [`Prompter`] answering from a script and an in-memory
//! [`RecentPathStore`].

use crate::prompt::{
    Busy, BusyPrompt, ChoiceAnswer, ChoicePrompt, ConfirmPrompt, CsrAnswer, CsrPrompt, FilePrompt,
    ImportAnswer, ImportPrompt, KeyPrompt, MessagePrompt, PasswordPrompt, PathPrompt, Prompt,
    Prompter, ReaderPrompt, RecentPathStore, SavePrompt, StorageAnswer, StorageKind, StoragePrompt,
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
    /// Answer a storage prompt with a hardware token.
    Token {
        /// The token's storage.
        storage: StorageKind,
        /// Its reader.
        reader: String,
        /// Its PIN.
        pin: String,
    },
    /// Answer a reader prompt with this reader.
    Reader(String),
    /// Cancel a reader prompt.
    CancelReader,
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
    /// Close a message with OK.
    Message,
    /// Close a message's window.
    CancelMessage,
    /// Answer a yes/no question.
    Confirm {
        /// Yes.
        yes: bool,
    },
    /// Close a yes/no question's window.
    CancelConfirm,
    /// Answer a save dialog with this path.
    Save {
        /// Where to save.
        path: PathBuf,
    },
    /// Cancel a save dialog.
    CancelSave,
    /// Answer a plugin's choice: the button pressed and the option selected.
    Choice {
        /// The button.
        button: usize,
        /// The option, if any.
        option: Option<usize>,
    },
    /// Close a plugin's choice.
    CancelChoice,
    /// Answer a plugin's path chooser with this path.
    Path(PathBuf),
    /// Cancel a plugin's path chooser.
    CancelPath,
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
            Step::Token { .. } => "Token",
            Step::Reader(_) => "Reader",
            Step::CancelReader => "CancelReader",
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
            Step::Message => "Message",
            Step::CancelMessage => "CancelMessage",
            Step::Confirm { .. } => "Confirm",
            Step::CancelConfirm => "CancelConfirm",
            Step::Save { .. } => "Save",
            Step::CancelSave => "CancelSave",
            Step::Wait(_) => "Wait",
            Step::Choice { .. } => "Choice",
            Step::CancelChoice => "CancelChoice",
            Step::Path(_) => "Path",
            Step::CancelPath => "CancelPath",
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
    timeline: Vec<&'static str>,
    storage_prompts: Vec<StoragePrompt>,
    busy_prompts: Vec<BusyPrompt>,
    opened_key_prompts: Vec<KeyPrompt>,
    key_prompts: Vec<KeyPrompt>,
    csr_prompts: Vec<CsrPrompt>,
    import_prompts: Vec<ImportPrompt>,
    file_prompts: Vec<FilePrompt>,
    password_prompts: Vec<PasswordPrompt>,
    message_prompts: Vec<MessagePrompt>,
    confirm_prompts: Vec<ConfirmPrompt>,
    save_prompts: Vec<SavePrompt>,
    choice_prompts: Vec<ChoicePrompt>,
    path_prompts: Vec<PathPrompt>,
    reader_prompts: Vec<ReaderPrompt>,
}

/// A [`Prompter`] answering from a queue of [`Step`]s and recording every prompt shown. An
/// empty queue cancels. A key prompt is answered once its OCSP checks have settled, as a
/// user would pick from what the dialog ends up showing. Safe to share between threads.
///
/// # Panics
///
/// A prompt panics if the next step answers another kind of prompt.
pub struct ScriptedPrompter {
    state: Arc<Mutex<State>>,
}

impl ScriptedPrompter {
    /// A prompter answering with `steps` in order.
    pub fn new(steps: Vec<Step>) -> Self {
        ScriptedPrompter {
            state: Arc::new(Mutex::new(State {
                steps: steps.into(),
                ..State::default()
            })),
        }
    }

    /// What was shown so far, in order: `"storage"`, `"busy"`, `"busy closed"`, `"key"`,
    /// `"csr"`, `"import"`, `"file"`, `"password"`, `"message"`, `"confirm"`, `"save"`,
    /// `"choice"`, `"path"`, `"reader"`.
    pub fn timeline(&self) -> Vec<&'static str> {
        self.lock().timeline.clone()
    }

    /// Storage prompts shown so far.
    pub fn storage_prompts(&self) -> Vec<StoragePrompt> {
        self.lock().storage_prompts.clone()
    }

    /// Busy indicators shown so far.
    pub fn busy_prompts(&self) -> Vec<BusyPrompt> {
        self.lock().busy_prompts.clone()
    }

    /// Key prompts shown so far, as they opened: keys whose OCSP check was still running
    /// are [`crate::Availability::Pending`].
    pub fn opened_key_prompts(&self) -> Vec<KeyPrompt> {
        self.lock().opened_key_prompts.clone()
    }

    /// Key prompts answered so far, with the availabilities they settled on.
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

    /// Messages shown so far.
    pub fn message_prompts(&self) -> Vec<MessagePrompt> {
        self.lock().message_prompts.clone()
    }

    /// Yes/no questions shown so far.
    pub fn confirm_prompts(&self) -> Vec<ConfirmPrompt> {
        self.lock().confirm_prompts.clone()
    }

    /// Save dialogs shown so far.
    pub fn save_prompts(&self) -> Vec<SavePrompt> {
        self.lock().save_prompts.clone()
    }

    /// Plugins' choices shown so far.
    pub fn choice_prompts(&self) -> Vec<ChoicePrompt> {
        self.lock().choice_prompts.clone()
    }

    /// Plugins' path choosers shown so far.
    pub fn path_prompts(&self) -> Vec<PathPrompt> {
        self.lock().path_prompts.clone()
    }

    /// Reader prompts shown so far.
    pub fn reader_prompts(&self) -> Vec<ReaderPrompt> {
        self.lock().reader_prompts.clone()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    /// Records a prompt of `kind`, then takes the next answering step, waiting out `Wait`
    /// steps with the state unlocked.
    fn next(&self, kind: &'static str, record: impl FnOnce(&mut State)) -> Option<Step> {
        let mut state = self.lock();
        state.timeline.push(kind);
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

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Prompter for ScriptedPrompter {
    fn storage(&self, p: &StoragePrompt) -> Prompt<StorageAnswer> {
        match self.next("storage", |s| s.storage_prompts.push(p.clone())) {
            Some(Step::Storage { path, password }) => Prompt::Answer(StorageAnswer {
                storage: StorageKind::Pkcs12,
                path,
                password: Zeroizing::new(password),
                reader: None,
            }),
            Some(Step::Jks { path, password }) => Prompt::Answer(StorageAnswer {
                storage: StorageKind::Jks,
                path,
                password: Zeroizing::new(password),
                reader: None,
            }),
            Some(Step::Token {
                storage,
                reader,
                pin,
            }) => Prompt::Answer(StorageAnswer {
                storage,
                path: PathBuf::new(),
                password: Zeroizing::new(pin),
                reader: Some(reader),
            }),
            Some(Step::CancelStorage) | None => Prompt::Cancelled,
            Some(step) => panic!(
                "ScriptedPrompter: storage prompt answered by {}",
                step.kind()
            ),
        }
    }

    fn busy(&self, p: &BusyPrompt) -> Busy {
        let mut state = self.lock();
        state.timeline.push("busy");
        state.busy_prompts.push(p.clone());
        drop(state);
        let state = Arc::clone(&self.state);
        Busy::new(move || lock(&state).timeline.push("busy closed"))
    }

    fn key(&self, p: &KeyPrompt) -> Prompt<usize> {
        let step = self.next("key", |s| s.opened_key_prompts.push(p.clone()));
        let mut settled = p.clone();
        for (candidate, availability) in settled.candidates.iter_mut().zip(p.live.wait_settled()) {
            candidate.availability = availability;
        }
        self.lock().key_prompts.push(settled);
        match step {
            Some(Step::Key(index)) => Prompt::Answer(index),
            Some(Step::CancelKey) | None => Prompt::Cancelled,
            Some(step) => panic!("ScriptedPrompter: key prompt answered by {}", step.kind()),
        }
    }

    fn csr(&self, p: &CsrPrompt) -> Prompt<CsrAnswer> {
        match self.next("csr", |s| s.csr_prompts.push(p.clone())) {
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
        match self.next("import", |s| s.import_prompts.push(p.clone())) {
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
        match self.next("file", |s| s.file_prompts.push(p.clone())) {
            Some(Step::File(path)) => Prompt::Answer(path),
            Some(Step::CancelFile) | None => Prompt::Cancelled,
            Some(step) => panic!("ScriptedPrompter: file chooser answered by {}", step.kind()),
        }
    }

    fn password(&self, p: &PasswordPrompt) -> Prompt<Zeroizing<String>> {
        match self.next("password", |s| s.password_prompts.push(p.clone())) {
            Some(Step::Password(password)) => Prompt::Answer(Zeroizing::new(password)),
            Some(Step::CancelPassword) | None => Prompt::Cancelled,
            Some(step) => panic!(
                "ScriptedPrompter: password dialog answered by {}",
                step.kind()
            ),
        }
    }

    fn message(&self, p: &MessagePrompt) -> Prompt<()> {
        match self.next("message", |s| s.message_prompts.push(p.clone())) {
            Some(Step::Message) => Prompt::Answer(()),
            Some(Step::CancelMessage) | None => Prompt::Cancelled,
            Some(step) => panic!("ScriptedPrompter: message answered by {}", step.kind()),
        }
    }

    fn confirm(&self, p: &ConfirmPrompt) -> Prompt<bool> {
        match self.next("confirm", |s| s.confirm_prompts.push(p.clone())) {
            Some(Step::Confirm { yes }) => Prompt::Answer(yes),
            Some(Step::CancelConfirm) | None => Prompt::Cancelled,
            Some(step) => panic!("ScriptedPrompter: question answered by {}", step.kind()),
        }
    }

    fn save_file(&self, p: &SavePrompt) -> Prompt<PathBuf> {
        match self.next("save", |s| s.save_prompts.push(p.clone())) {
            Some(Step::Save { path }) => Prompt::Answer(path),
            Some(Step::CancelSave) | None => Prompt::Cancelled,
            Some(step) => panic!("ScriptedPrompter: save dialog answered by {}", step.kind()),
        }
    }

    fn choice(&self, p: &ChoicePrompt) -> Prompt<ChoiceAnswer> {
        match self.next("choice", |s| s.choice_prompts.push(p.clone())) {
            Some(Step::Choice { button, option }) => {
                Prompt::Answer(ChoiceAnswer { button, option })
            }
            Some(Step::CancelChoice) | None => Prompt::Cancelled,
            Some(step) => panic!("ScriptedPrompter: choice answered by {}", step.kind()),
        }
    }

    fn path(&self, p: &PathPrompt) -> Prompt<PathBuf> {
        match self.next("path", |s| s.path_prompts.push(p.clone())) {
            Some(Step::Path(path)) => Prompt::Answer(path),
            Some(Step::CancelPath) | None => Prompt::Cancelled,
            Some(step) => panic!("ScriptedPrompter: path chooser answered by {}", step.kind()),
        }
    }

    fn reader(&self, p: &ReaderPrompt) -> Prompt<String> {
        match self.next("reader", |s| s.reader_prompts.push(p.clone())) {
            Some(Step::Reader(reader)) => Prompt::Answer(reader),
            Some(Step::CancelReader) | None => Prompt::Cancelled,
            Some(step) => panic!(
                "ScriptedPrompter: reader prompt answered by {}",
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
