//! The availability of a key list while its OCSP checks run: the key dialog opens with the
//! keys still being checked marked [`Availability::Pending`] and follows their results.

use crate::filter::Availability;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

/// Called with the index and new availability of each key that changes.
type Watcher = Box<dyn FnMut(usize, &Availability) + Send>;

/// The availability of each key of a list, in order, as it settles. Clones share the same
/// list; two are equal when they are the same list.
#[derive(Clone)]
pub struct LiveAvailability(Arc<Live>);

struct Live {
    state: Mutex<State>,
    settled: Condvar,
}

struct State {
    current: Vec<Availability>,
    settled: bool,
    watchers: Vec<Watcher>,
}

impl LiveAvailability {
    /// A list that does not change.
    pub fn settled(availabilities: Vec<Availability>) -> Self {
        Self::new(availabilities, true)
    }

    /// A list starting at `initial` that changes with [`Self::set`] until [`Self::settle`].
    pub(crate) fn changing(initial: Vec<Availability>) -> Self {
        Self::new(initial, false)
    }

    fn new(current: Vec<Availability>, settled: bool) -> Self {
        LiveAvailability(Arc::new(Live {
            state: Mutex::new(State {
                current,
                settled,
                watchers: Vec::new(),
            }),
            settled: Condvar::new(),
        }))
    }

    /// The availabilities now.
    pub fn current(&self) -> Vec<Availability> {
        self.lock().current.clone()
    }

    /// Whether they no longer change.
    pub fn is_settled(&self) -> bool {
        self.lock().settled
    }

    /// Waits until they no longer change (at most [`crate::OCSP_DEADLINE`] after the checks
    /// started), then returns them.
    pub fn wait_settled(&self) -> Vec<Availability> {
        let state = self
            .0
            .settled
            .wait_while(self.lock(), |s| !s.settled)
            .unwrap_or_else(PoisonError::into_inner);
        state.current.clone()
    }

    /// The availabilities now; `on_change` then gets every later change until they settle.
    /// It runs on the checking thread with the list locked, so it must not call back into
    /// the list.
    pub fn watch(
        &self,
        on_change: impl FnMut(usize, &Availability) + Send + 'static,
    ) -> Vec<Availability> {
        let mut state = self.lock();
        if !state.settled {
            state.watchers.push(Box::new(on_change));
        }
        state.current.clone()
    }

    /// Sets the availability of the key at `index`, telling the watchers if it changed.
    /// Nothing changes once settled.
    pub(crate) fn set(&self, index: usize, availability: Availability) {
        let mut state = self.lock();
        let state = &mut *state;
        if state.settled {
            return;
        }
        let Some(slot) = state.current.get_mut(index) else {
            return;
        };
        if *slot == availability {
            return;
        }
        *slot = availability;
        for watcher in &mut state.watchers {
            watcher(index, slot);
        }
    }

    /// Ends the changes: the watchers are released and the waiters woken.
    pub(crate) fn settle(&self) {
        let mut state = self.lock();
        state.settled = true;
        state.watchers.clear();
        drop(state);
        self.0.settled.notify_all();
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl PartialEq for LiveAvailability {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for LiveAvailability {}

impl fmt::Debug for LiveAvailability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        f.debug_struct("LiveAvailability")
            .field("current", &state.current)
            .field("settled", &state.settled)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use time::macros::datetime;

    #[test]
    fn watchers_see_changes_until_settled() {
        let live = LiveAvailability::changing(vec![Availability::Pending, Availability::Pending]);
        let (tx, rx) = mpsc::channel();
        let shown = live.watch(move |i, a| tx.send((i, a.clone())).unwrap());
        assert_eq!(shown, [Availability::Pending, Availability::Pending]);
        let revoked = Availability::Revoked {
            time: datetime!(2026-02-03 04:05:06 UTC),
        };
        live.set(1, revoked.clone());
        // No change, no call.
        live.set(1, revoked.clone());
        live.set(5, Availability::Enabled);
        live.set(0, Availability::Enabled);
        assert!(!live.is_settled());
        live.settle();
        // Settled: nothing changes any more.
        live.set(0, Availability::Expired);
        assert_eq!(
            rx.iter().collect::<Vec<_>>(),
            [(1, revoked.clone()), (0, Availability::Enabled)],
            "the watcher is released on settling"
        );
        assert!(live.is_settled());
        let late = live.watch(|_, _| panic!("no change after settling"));
        assert_eq!(late, [Availability::Enabled, revoked]);
    }

    #[test]
    fn waiters_wake_when_settled() {
        let live = LiveAvailability::changing(vec![Availability::Pending]);
        let waiter = thread::spawn({
            let live = live.clone();
            move || live.wait_settled()
        });
        live.set(0, Availability::Enabled);
        live.settle();
        assert_eq!(waiter.join().unwrap(), [Availability::Enabled]);
        let fixed = LiveAvailability::settled(vec![Availability::Expired]);
        assert_eq!(fixed.wait_settled(), [Availability::Expired]);
        assert_ne!(fixed, live);
        assert_eq!(live.clone(), live);
    }
}
