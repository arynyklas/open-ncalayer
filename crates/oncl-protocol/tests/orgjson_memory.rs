//! What reading a frame costs in heap: allocations and the most held at once, counted by a
//! global allocator. One test measures at a time.

use oncl_protocol::orgjson::scan;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

struct Counting;

static HELD: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let held = HELD.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(held, Relaxed);
}

// SAFETY: every call goes to `System`; the counters only add up what it was asked.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        CALLS.fetch_add(1, Relaxed);
        grew(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        CALLS.fetch_add(1, Relaxed);
        grew(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        HELD.fetch_sub(layout.size(), Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        CALLS.fetch_add(1, Relaxed);
        if new_size >= layout.size() {
            grew(new_size - layout.size());
        } else {
            HELD.fetch_sub(layout.size() - new_size, Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// What `f` took beyond what was held when it began.
#[derive(Debug)]
struct Cost {
    /// Allocations and reallocations.
    calls: usize,
    /// The most held at once beyond the start, in bytes.
    peak: usize,
    time: Duration,
}

fn turn() -> MutexGuard<'static, ()> {
    static TURN: Mutex<()> = Mutex::new(());
    TURN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `f`'s cost; the caller holds the [`turn`].
fn measure<R>(f: impl FnOnce() -> R) -> (R, Cost) {
    let base = HELD.load(Relaxed);
    PEAK.store(base, Relaxed);
    let calls = CALLS.load(Relaxed);
    let start = Instant::now();
    let result = f();
    let cost = Cost {
        calls: CALLS.load(Relaxed) - calls,
        peak: PEAK.load(Relaxed).saturating_sub(base),
        time: start.elapsed(),
    };
    (result, cost)
}

const MIB: usize = 1 << 20;

/// `{"module":"m","x":[{},{},…]}` of about `len` bytes.
fn empty_objects(len: usize) -> String {
    format!(r#"{{"module":"m","x":[{}{{}}]}}"#, "{},".repeat(len / 3))
}

#[test]
fn skipped_objects_do_not_allocate() {
    // Objects the reader skips need no map: 64 MiB of `{}` took 22 million allocations.
    let _turn = turn();
    let text = empty_objects(8 * MIB);
    let (scanned, cost) = measure(|| scan(&text, "module").unwrap());
    assert_eq!(scanned.len, text.len());
    eprintln!("{} bytes of {{}}: {cost:?}", text.len());
    assert!(cost.calls < 100, "{cost:?}");
    assert!(cost.peak < MIB, "{cost:?}");
}
