//! The keyed hash behind every hashed structure that holds keys a page chooses: the key
//! index of [`JObject`](super::JObject), the duplicate check of the reader, and sets of
//! page strings in the modules. A page that knew the keys could choose keys that all
//! collide and make a linear read quadratic, so the keys are secret and change.
//!
//! Where the system has a source of randomness (every native target), each thread starts
//! with keys std draws from it. In a WebAssembly guest there is none: the host's `random`
//! is the source, and the guest SDK gives each call fresh keys through [`seed`] before the
//! plugin's code runs. An object keeps the keys it was made with, so its index stays right
//! whatever the keys are later.

// `SipHasher` is deprecated only because std does not promise its output; keys are all this
// needs from it, and its output stays inside the process.
use std::cell::Cell;
#[allow(deprecated)]
use std::hash::SipHasher;
use std::hash::{BuildHasher, RandomState};

/// A SipHash-2-4 with two secret 64-bit keys, as a [`BuildHasher`] for sets of page keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyHasher {
    keys: [u64; 2],
}

impl KeyHasher {
    /// A hasher with these keys.
    pub fn new(keys: [u64; 2]) -> KeyHasher {
        KeyHasher { keys }
    }

    /// A hasher with the keys of this thread's current call: see [`seed`].
    pub fn current() -> KeyHasher {
        KeyHasher::new(CURRENT.with(Cell::get))
    }

    /// The hash of a key.
    pub fn hash_key(&self, key: &str) -> u64 {
        self.hash_one(key)
    }
}

impl BuildHasher for KeyHasher {
    #[allow(deprecated)]
    type Hasher = SipHasher;

    #[allow(deprecated)]
    fn build_hasher(&self) -> SipHasher {
        SipHasher::new_with_keys(self.keys[0], self.keys[1])
    }
}

thread_local! {
    static CURRENT: Cell<[u64; 2]> = Cell::new(system_keys());
}

/// Keys from the system's randomness, which std draws once per process and counts up for
/// each `RandomState`. (Where there is none, in a guest on `wasm32-unknown-unknown`, std's
/// keys are the same for every instance: such code must [`seed`] before it reads a page.)
fn system_keys() -> [u64; 2] {
    let state = RandomState::new();
    [state.hash_one(0u8), state.hash_one(1u8)]
}

/// Makes `keys` the keys of the hashers and objects this thread makes from now on. The guest
/// SDK calls it with bytes of the host's `random` before each call; nothing else needs to.
pub fn seed(keys: [u64; 2]) {
    CURRENT.with(|current| current.set(keys));
}
