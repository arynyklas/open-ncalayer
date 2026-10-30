//! A smart card service of software readers: cards are inserted and removed by the test,
//! every exchange is recorded, and transactions of "other processes" can be held.

use super::SoftCard;
use crate::backend::{Backend, BackendError, Connection, Protocol, ReaderState};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

/// One command and the card's response, as the reader saw them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchange {
    /// Command APDU.
    pub command: Vec<u8>,
    /// Response (data and status word).
    pub response: Vec<u8>,
}

struct Reader {
    name: String,
    card: Option<Box<dyn SoftCard>>,
    /// Changes on every insertion and removal: a connection to an earlier card is dead.
    generation: u64,
    /// Changes on every reset of the card: a connection opened before sees
    /// [`BackendError::Reset`], as a PC/SC handle does after another handle's reset.
    resets: u64,
    /// Commands left before the card is pulled out.
    remove_after: Option<usize>,
    exchanges: Vec<Exchange>,
    /// The connection (or foreign holder) in a transaction.
    holder: Option<u64>,
}

impl Reader {
    /// Resets the card: its security state ends, the other connections see the reset.
    fn reset(&mut self) {
        if let Some(card) = self.card.as_mut() {
            card.reset();
            self.resets += 1;
        }
    }
}

struct State {
    readers: Vec<Reader>,
    service: bool,
    next_id: u64,
}

impl State {
    fn reader(&mut self, name: &str) -> Option<&mut Reader> {
        self.readers.iter_mut().find(|r| r.name == name)
    }

    fn id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn wait<'a>(&self, guard: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
        self.changed.wait(guard).unwrap_or_else(|e| e.into_inner())
    }

    fn release(&self, reader: &str, id: u64) {
        let mut state = self.lock();
        if let Some(r) = state.reader(reader)
            && r.holder == Some(id)
        {
            r.holder = None;
        }
        drop(state);
        self.changed.notify_all();
    }
}

/// The emulated smart card service.
pub struct EmulatorBackend {
    shared: Arc<Shared>,
}

impl Default for EmulatorBackend {
    fn default() -> EmulatorBackend {
        EmulatorBackend::new()
    }
}

impl EmulatorBackend {
    /// A running service without readers.
    pub fn new() -> EmulatorBackend {
        EmulatorBackend {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    readers: Vec::new(),
                    service: true,
                    next_id: 0,
                }),
                changed: Condvar::new(),
            }),
        }
    }

    /// The readers and cards of a configuration file (see [`super::read_config`]).
    ///
    /// # Errors
    ///
    /// As [`super::read_config`].
    pub fn from_config(text: &str, base: &std::path::Path) -> Result<EmulatorBackend, String> {
        let emu = EmulatorBackend::new();
        for reader in super::read_config(text, base)? {
            emu.add_reader(&reader.name);
            if let Some(spec) = reader.card {
                emu.insert(&reader.name, super::card(spec));
            }
        }
        Ok(emu)
    }

    /// Plugs in an empty reader.
    pub fn add_reader(&self, name: &str) {
        self.shared.lock().readers.push(Reader {
            name: name.to_owned(),
            card: None,
            generation: 0,
            remove_after: None,
            exchanges: Vec::new(),
            holder: None,
            resets: 0,
        });
    }

    fn with_reader<T>(&self, name: &str, f: impl FnOnce(&mut Reader) -> T) -> T {
        let mut state = self.shared.lock();
        let reader = state
            .reader(name)
            .unwrap_or_else(|| panic!("no emulated reader {name:?}"));
        let out = f(reader);
        drop(state);
        self.shared.changed.notify_all();
        out
    }

    /// Inserts `card` into `reader` (replacing a card in it).
    ///
    /// # Panics
    ///
    /// For an unknown reader; so do the other methods taking a reader.
    pub fn insert(&self, reader: &str, card: Box<dyn SoftCard>) {
        self.with_reader(reader, |r| {
            r.card = Some(card);
            r.generation += 1;
            r.remove_after = None;
        });
    }

    /// Pulls the card out of `reader`.
    pub fn remove(&self, reader: &str) {
        self.with_reader(reader, |r| {
            r.card = None;
            r.generation += 1;
            r.remove_after = None;
        });
    }

    /// Stops or starts the service: stopped, it reports [`BackendError::NoService`].
    pub fn set_service(&self, available: bool) {
        self.shared.lock().service = available;
    }

    /// The card of `reader` is pulled out after `apdus` more commands: the next one fails
    /// with [`BackendError::Removed`].
    pub fn remove_after(&self, reader: &str, apdus: usize) {
        self.with_reader(reader, |r| r.remove_after = Some(apdus));
    }

    /// The exchanges with the cards of `reader` so far.
    pub fn exchanges(&self, reader: &str) -> Vec<Exchange> {
        self.with_reader(reader, |r| r.exchanges.clone())
    }

    /// Forgets the exchanges of `reader`.
    pub fn clear_exchanges(&self, reader: &str) {
        self.with_reader(reader, |r| r.exchanges.clear());
    }

    /// Resets the card of `reader` as another process disconnecting with a reset does:
    /// connections opened before see [`BackendError::Reset`].
    pub fn reset_card(&self, reader: &str) {
        self.with_reader(reader, Reader::reset);
    }

    /// Holds a transaction on `reader` as another process would, until the guard is
    /// dropped; waits for a running one first.
    pub fn foreign_transaction(&self, reader: &str) -> TransactionGuard {
        let mut state = self.shared.lock();
        let id = state.id();
        loop {
            let r = state
                .reader(reader)
                .unwrap_or_else(|| panic!("no emulated reader {reader:?}"));
            if r.holder.is_none() {
                r.holder = Some(id);
                break;
            }
            state = self.shared.wait(state);
        }
        TransactionGuard {
            shared: self.shared.clone(),
            reader: reader.to_owned(),
            id,
        }
    }
}

/// A transaction of another process; ends on drop.
pub struct TransactionGuard {
    shared: Arc<Shared>,
    reader: String,
    id: u64,
}

impl Drop for TransactionGuard {
    fn drop(&mut self) {
        self.shared.release(&self.reader, self.id);
    }
}

impl Backend for EmulatorBackend {
    fn readers(&self) -> Result<Vec<ReaderState>, BackendError> {
        let state = self.shared.lock();
        if !state.service {
            return Err(BackendError::NoService);
        }
        if state.readers.is_empty() {
            return Err(BackendError::NoReaders);
        }
        Ok(state
            .readers
            .iter()
            .map(|r| ReaderState {
                name: r.name.clone(),
                atr: r.card.as_ref().map(|c| c.atr()),
            })
            .collect())
    }

    fn connect(&self, reader: &str) -> Result<Box<dyn Connection>, BackendError> {
        let mut state = self.shared.lock();
        if !state.service {
            return Err(BackendError::NoService);
        }
        let id = state.id();
        let r = state.reader(reader).ok_or(BackendError::UnknownReader)?;
        let card = r.card.as_ref().ok_or(BackendError::NoCard)?;
        Ok(Box::new(EmuConnection {
            shared: self.shared.clone(),
            reader: reader.to_owned(),
            generation: r.generation,
            resets: r.resets,
            id,
            atr: card.atr(),
            protocol: card.protocol(),
            reset_on_drop: false,
        }))
    }
}

struct EmuConnection {
    shared: Arc<Shared>,
    reader: String,
    generation: u64,
    resets: u64,
    id: u64,
    atr: Vec<u8>,
    protocol: Protocol,
    /// Disconnect with a reset.
    reset_on_drop: bool,
}

impl EmuConnection {
    /// The reader, its card still the one connected to; waits while another holder has a
    /// transaction.
    fn reader<'a>(
        &self,
        mut state: MutexGuard<'a, State>,
    ) -> Result<MutexGuard<'a, State>, BackendError> {
        loop {
            if !state.service {
                return Err(BackendError::NoService);
            }
            let r = state.reader(&self.reader).ok_or(BackendError::Removed)?;
            if r.generation != self.generation || r.card.is_none() {
                return Err(BackendError::Removed);
            }
            if r.resets != self.resets {
                return Err(BackendError::Reset);
            }
            match r.holder {
                Some(holder) if holder != self.id => state = self.shared.wait(state),
                _ => return Ok(state),
            }
        }
    }
}

impl Connection for EmuConnection {
    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn atr(&self) -> &[u8] {
        &self.atr
    }

    fn begin_transaction(&mut self) -> Result<(), BackendError> {
        let mut state = self.reader(self.shared.lock())?;
        let r = state.reader(&self.reader).expect("checked above");
        r.holder = Some(self.id);
        Ok(())
    }

    fn end_transaction(&mut self) -> Result<(), BackendError> {
        self.shared.release(&self.reader, self.id);
        Ok(())
    }

    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, BackendError> {
        let mut state = self.reader(self.shared.lock())?;
        let r = state.reader(&self.reader).expect("checked above");
        match r.remove_after {
            Some(0) => {
                r.card = None;
                r.generation += 1;
                r.remove_after = None;
                drop(state);
                self.shared.changed.notify_all();
                return Err(BackendError::Removed);
            }
            Some(n) => r.remove_after = Some(n - 1),
            None => {}
        }
        let response = r.card.as_mut().expect("checked above").process(apdu);
        r.exchanges.push(Exchange {
            command: apdu.to_vec(),
            response: response.clone(),
        });
        Ok(response)
    }

    fn reset_on_disconnect(&mut self) {
        self.reset_on_drop = true;
    }
}

impl Drop for EmuConnection {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        if let Some(r) = state.reader(&self.reader)
            && r.holder == Some(self.id)
        {
            r.holder = None;
        }
        // As pcsc-lite does, a disconnect with a reset waits for another connection's
        // transaction to end.
        if self.reset_on_drop {
            while let Some(r) = state.reader(&self.reader)
                && r.generation == self.generation
            {
                match r.holder {
                    Some(holder) if holder != self.id => state = self.shared.wait(state),
                    _ => {
                        r.reset();
                        break;
                    }
                }
            }
        }
        drop(state);
        self.shared.changed.notify_all();
    }
}
