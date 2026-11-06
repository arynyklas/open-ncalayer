//! What the host is doing right now, for the one decision that must not be taken twice in two
//! ways: whether the program may be replaced or stopped.
//!
//! A host (the desktop daemon) counts the operations it answers through an [`ActivityGate`]:
//! every one holds an [`ActivityLease`] from its start to its end (a module request of a page,
//! a Core operation of the tools window or a plugin call). A maintainer (the updater, the
//! installer's bootstrapper) takes a [`MaintenanceLease`]: it holds new operations back, and
//! only then looks at whether the host is idle, so an operation that began between the
//! maintainer's first look and the hold is seen, not cut. Operations that arrive while the
//! gate is held wait for it ([`ActivityGate::begin`]) and end with the process that applies
//! the change.
//!
//! There is one gate per process and one maintainer at a time: a second hold is refused, so
//! the updater and the installer never replace the program together. Dropping a
//! [`MaintenanceLease`] lets operations through again, which is what makes a maintainer that
//! died (its connection closed, its thread unwound) not leave the host busy for good.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

/// How often an operation held back looks whether it may go on.
pub(crate) const HELD_POLL: Duration = Duration::from_millis(50);

/// The operations being answered by a host, and when the last one ended.
#[derive(Debug)]
pub struct ActivityGate {
    in_flight: AtomicUsize,
    last_end: Mutex<Option<Instant>>,
    /// New operations wait while this is set.
    held: AtomicBool,
}

impl Default for ActivityGate {
    fn default() -> Self {
        Self::new()
    }
}

/// A test seam: what runs between an operation's count and its look at `held`.
#[cfg(test)]
mod gap {
    use std::cell::RefCell;

    thread_local! {
        static HOOK: RefCell<Option<Box<dyn Fn()>>> = const { RefCell::new(None) };
    }

    pub(super) fn run() {
        HOOK.with_borrow(|hook| {
            if let Some(hook) = hook {
                hook();
            }
        });
    }

    pub(super) fn set(hook: Option<Box<dyn Fn()>>) {
        HOOK.with_borrow_mut(|slot| *slot = hook);
    }
}

/// An operation being answered, from [`ActivityGate::begin`] to its drop.
#[derive(Debug)]
#[must_use = "the operation counts as running only while this is alive"]
pub struct ActivityLease {
    gate: Arc<ActivityGate>,
}

/// The hold of an [`ActivityGate`] by a maintainer: new operations wait while it lives.
#[derive(Debug)]
#[must_use = "the hold ends when this is dropped"]
pub struct MaintenanceLease {
    gate: Arc<ActivityGate>,
}

impl ActivityGate {
    /// A gate nothing ever ran through.
    pub const fn new() -> ActivityGate {
        ActivityGate {
            in_flight: AtomicUsize::new(0),
            last_end: Mutex::new(None),
            held: AtomicBool::new(false),
        }
    }

    /// Counts an operation in; while the gate is held, waits first. The count goes up before
    /// `held` is read, and [`ActivityGate::hold`] sets `held` before it reads the count, so
    /// an operation either waits or is seen.
    ///
    /// Blocks the calling thread while the gate is held: call it where waiting is allowed.
    pub fn begin(self: &Arc<Self>) -> ActivityLease {
        loop {
            self.in_flight.fetch_add(1, Ordering::SeqCst);
            // The gap between the count and the look at `held`: a hold taken here must see
            // the count (and be refused). Tests run a hold exactly here.
            #[cfg(test)]
            gap::run();
            if !self.held.load(Ordering::SeqCst) {
                return ActivityLease {
                    gate: Arc::clone(self),
                };
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            while self.held.load(Ordering::SeqCst) {
                thread::sleep(HELD_POLL);
            }
        }
    }

    /// Holds new operations back; whether the activity is still [`ActivityGate::idle`] for
    /// `quiet`, looked at only after the hold is in place (with the time from `now` read
    /// then): an operation that ended while the caller was busy elsewhere, after its own
    /// look, still counts. If it is not idle, they are let through again. Refused (and
    /// nothing changes) while another maintainer holds the gate.
    pub fn hold(&self, quiet: Duration, now: impl FnOnce() -> Instant) -> bool {
        self.hold_unless(quiet, now, || false)
    }

    /// [`ActivityGate::hold`], which also lets go again if `blocked` says so. `blocked` is
    /// asked only once the hold is in place and the gate is idle, so what it looks at (a
    /// window of the desktop that is open) is seen with new operations already held back.
    pub fn hold_unless(
        &self,
        quiet: Duration,
        now: impl FnOnce() -> Instant,
        blocked: impl FnOnce() -> bool,
    ) -> bool {
        if self
            .held
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        // Given back if `now` or `blocked` unwinds, or says no.
        struct Undo<'a>(&'a ActivityGate, bool);
        impl Drop for Undo<'_> {
            fn drop(&mut self) {
                if !self.1 {
                    self.0.release();
                }
            }
        }
        let mut undo = Undo(self, false);
        if self.idle(quiet, now()) && !blocked() {
            undo.1 = true;
            return true;
        }
        false
    }

    /// [`ActivityGate::hold_unless`] as a lease: the hold ends when it is dropped. `None`
    /// if the gate cannot be held.
    pub fn maintenance(
        self: &Arc<Self>,
        quiet: Duration,
        now: impl FnOnce() -> Instant,
        blocked: impl FnOnce() -> bool,
    ) -> Option<MaintenanceLease> {
        self.hold_unless(quiet, now, blocked)
            .then(|| MaintenanceLease {
                gate: Arc::clone(self),
            })
    }

    /// Lets held operations through again.
    pub fn release(&self) {
        self.held.store(false, Ordering::SeqCst);
    }

    /// Whether a maintainer holds the gate.
    pub fn is_held(&self) -> bool {
        self.held.load(Ordering::SeqCst)
    }

    /// Whether no operation is being answered and none ended within `quiet` before `now`.
    pub fn idle(&self, quiet: Duration, now: Instant) -> bool {
        if self.in_flight.load(Ordering::SeqCst) > 0 {
            return false;
        }
        self.last_end()
            .is_none_or(|end| now.saturating_duration_since(end) >= quiet)
    }

    /// When the last operation ended, if one did.
    pub fn last_end(&self) -> Option<Instant> {
        *self.last_end.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for ActivityLease {
    fn drop(&mut self) {
        *self
            .gate
            .last_end
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        self.gate.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Drop for MaintenanceLease {
    fn drop(&mut self) {
        self.gate.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    const QUIET: Duration = Duration::from_secs(30);

    fn gate() -> Arc<ActivityGate> {
        Arc::new(ActivityGate::new())
    }

    #[test]
    fn activity_counts_requests_and_their_quiet() {
        let activity = gate();
        let now = Instant::now();
        assert!(activity.idle(QUIET, now), "nothing ever ran");
        let a = activity.begin();
        let b = activity.begin();
        assert!(!activity.idle(QUIET, now));
        drop(a);
        assert!(!activity.idle(QUIET, Instant::now()), "one still runs");
        drop(b);
        let ended = Instant::now();
        assert!(!activity.idle(QUIET, ended + Duration::from_secs(29)));
        assert!(activity.idle(QUIET, ended + QUIET));
    }

    #[test]
    fn held_requests_wait_and_a_running_one_prevents_the_hold() {
        let activity = gate();
        let running = activity.begin();
        let later = || Instant::now() + Duration::from_secs(3600);
        assert!(!activity.hold(QUIET, later), "a request is being answered");
        assert!(!activity.is_held());
        drop(running);
        assert!(activity.hold(QUIET, later));
        let waiting = Arc::clone(&activity);
        let request = thread::spawn(move || drop(waiting.begin()));
        thread::sleep(HELD_POLL * 3);
        assert!(!request.is_finished(), "a held request waits");
        assert!(
            activity.idle(QUIET, later()),
            "a waiting request is not counted"
        );
        activity.release();
        request.join().unwrap();
    }

    #[test]
    fn the_hold_looks_at_the_quiet_time_again() {
        let activity = gate();
        // The updater saw an idle daemon, then re-checked the index; meanwhile a request
        // came and went.
        assert!(activity.idle(QUIET, Instant::now()));
        drop(activity.begin());
        let ended = activity.last_end().expect("the request ended");
        // Within the quiet time of its end, up to its last moment: nothing is held.
        for after in [
            Duration::ZERO,
            Duration::from_secs(1),
            QUIET - Duration::from_millis(1),
        ] {
            assert!(!activity.hold(QUIET, || ended + after), "{after:?}");
            assert!(!activity.is_held(), "{after:?}");
        }
        // From the end of the quiet time on, the hold takes.
        assert!(activity.hold(QUIET, || ended + QUIET));
        assert!(activity.is_held());
    }

    #[test]
    fn what_blocks_is_looked_at_only_after_the_hold_is_in_place() {
        let activity = gate();
        let later = || Instant::now() + Duration::from_secs(3600);
        let seen_held = std::cell::Cell::new(None);
        // A window of the desktop that is open: the hold is let go, and the check ran
        // while the requests were already held back.
        let held = activity.hold_unless(QUIET, later, || {
            seen_held.set(Some(activity.is_held()));
            true
        });
        assert!(!held);
        assert_eq!(
            seen_held.get(),
            Some(true),
            "the check is made under the hold"
        );
        assert!(!activity.is_held(), "an open window gives the hold back");
        assert!(activity.hold_unless(QUIET, later, || false));
        assert!(activity.is_held());
    }

    #[test]
    fn a_hold_is_exclusive() {
        let activity = gate();
        let later = || Instant::now() + Duration::from_secs(3600);
        let first = activity.maintenance(QUIET, later, || false).expect("idle");
        assert!(
            !activity.hold(QUIET, later),
            "the updater cannot take what an installer holds"
        );
        assert!(activity.maintenance(QUIET, later, || false).is_none());
        assert!(
            activity.is_held(),
            "a refused hold does not give the first one back"
        );
        drop(first);
        assert!(!activity.is_held(), "the lease's end lets requests through");
        assert!(activity.maintenance(QUIET, later, || false).is_some());
    }

    #[test]
    fn a_dropped_lease_does_not_leave_the_gate_busy() {
        let activity = gate();
        let later = || Instant::now() + Duration::from_secs(3600);
        let lease = activity.maintenance(QUIET, later, || false).expect("idle");
        let waiting = Arc::clone(&activity);
        let request = thread::spawn(move || drop(waiting.begin()));
        thread::sleep(HELD_POLL * 3);
        assert!(!request.is_finished());
        // The holder dies without a word: its lease is dropped.
        drop(lease);
        request.join().unwrap();
    }

    #[test]
    fn a_hold_in_the_gap_between_an_operations_count_and_its_look_is_refused() {
        // Deterministic: the hold is attempted exactly between the two steps of `begin`.
        let activity = gate();
        let attempt = Arc::clone(&activity);
        let granted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = Arc::clone(&granted);
        gap::set(Some(Box::new(move || {
            seen.store(attempt.hold(Duration::ZERO, Instant::now), Ordering::SeqCst);
        })));
        let lease = activity.begin();
        gap::set(None);
        assert!(
            !granted.load(Ordering::SeqCst),
            "a hold was granted while an operation was starting: both would succeed"
        );
        assert!(!activity.is_held(), "the operation runs, nothing holds it");
        drop(lease);
    }

    #[test]
    fn begin_and_hold_never_both_succeed() {
        // A request either waits for the hold or is seen by it: while a maintainer holds the
        // gate, no request runs.
        use std::sync::atomic::AtomicBool;
        for _ in 0..200 {
            let activity = gate();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let running = Arc::new(AtomicBool::new(false));
            let requester = {
                let (activity, barrier, running) = (
                    Arc::clone(&activity),
                    Arc::clone(&barrier),
                    Arc::clone(&running),
                );
                thread::spawn(move || {
                    barrier.wait();
                    let lease = activity.begin();
                    running.store(true, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(1));
                    running.store(false, Ordering::SeqCst);
                    drop(lease);
                })
            };
            barrier.wait();
            let lease = activity.maintenance(Duration::ZERO, Instant::now, || false);
            if lease.is_some() {
                for _ in 0..3 {
                    assert!(
                        !running.load(Ordering::SeqCst),
                        "a request runs under a hold"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
            }
            drop(lease);
            requester.join().unwrap();
        }
    }
}
