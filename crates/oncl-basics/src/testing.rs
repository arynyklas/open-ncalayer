//! Test doubles (feature `testing`): a [`Prompter`] answering from a script and an in-memory
//! [`RecentPathStore`].

use crate::prompt::{
    KeyPrompt, Prompt, Prompter, RecentPathStore, StorageAnswer, StorageKind, StoragePrompt,
};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex, MutexGuard, PoisonError};
use zeroize::Zeroizing;

/// One scripted answer.
#[derive(Debug, Clone)]
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
    /// Pick candidate `n` in a key prompt.
    Key(usize),
    /// Cancel a key prompt.
    CancelKey,
    /// Wait on the barrier (without holding the prompter), then take the next step for the
    /// same prompt.
    Wait(Arc<Barrier>),
}

#[derive(Default)]
struct State {
    steps: VecDeque<Step>,
    storage_prompts: Vec<StoragePrompt>,
    key_prompts: Vec<KeyPrompt>,
}

/// A [`Prompter`] answering from a queue of [`Step`]s and recording every prompt shown. An
/// empty queue cancels. Safe to share between threads.
///
/// # Panics
///
/// A prompt panics if the next step answers the other kind of prompt.
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
            Some(Step::CancelStorage) | None => Prompt::Cancelled,
            Some(step) => panic!("ScriptedPrompter: storage prompt answered by {step:?}"),
        }
    }

    fn key(&self, p: &KeyPrompt) -> Prompt<usize> {
        match self.next(|s| s.key_prompts.push(p.clone())) {
            Some(Step::Key(index)) => Prompt::Answer(index),
            Some(Step::CancelKey) | None => Prompt::Cancelled,
            Some(step) => panic!("ScriptedPrompter: key prompt answered by {step:?}"),
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
