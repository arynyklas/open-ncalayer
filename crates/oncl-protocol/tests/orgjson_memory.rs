//! What reading a frame costs in heap: allocations and the most held at once, counted by a
//! global allocator. One test measures at a time.

use oncl_protocol::orgjson::{JObject, JValue, SCAN_BUDGET_32_BIT, Scanned, scan, scan_within};
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
#[allow(dead_code, reason = "printed with Debug")]
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

/// The budget of a 32-bit target, on this one.
const BUDGET: usize = SCAN_BUDGET_32_BIT;

/// `scan_within` of `text` for `module`, within the 32-bit budget: the heap it holds never
/// goes over it, whatever the text is; whether it reads it to the end is `reads`.
fn scan_32_bit(what: &str, text: &str, reads: bool) -> Scanned {
    let (result, cost) = measure(|| scan_within(text, "module", BUDGET));
    eprintln!("{what}, {} bytes: {cost:?}", text.len());
    assert!(cost.peak <= BUDGET, "{what}: {cost:?}");
    match (result, reads) {
        (Ok(scanned), true) => scanned,
        (Err(_), false) => Scanned {
            value: None,
            len: 0,
        },
        (result, _) => panic!("{what}: {:?}", result.map(|s| s.len)),
    }
}

/// `{`, `head`, pairs `<key(i)>:0` joined by commas up to about `len` bytes, `}`.
fn pairs_of(head: &str, len: usize, key: impl Fn(usize) -> String) -> String {
    let mut text = String::with_capacity(len + 64);
    text.push('{');
    text.push_str(head);
    let mut i = 0;
    while text.len() < len {
        text.push_str(&key(i));
        text.push_str(":0,");
        i += 1;
    }
    text.push_str("\"z\":0}");
    text
}

#[test]
fn keys_of_a_frame_are_bounded_on_32_bit() {
    let _turn = turn();
    // The shapes that took 0.6 to 2.2 GiB beyond the frame, or aborted a process of 2 GiB:
    // many keys of any form. The reader refuses them within its budget.
    let len = 24 * MIB;
    scan_32_bit(
        "quoted keys",
        &pairs_of(r#""module":"m","#, len, |i| format!("\"a{i}\"")),
        false,
    );
    scan_32_bit(
        "unquoted keys",
        &pairs_of("module:m,", len, |i| format!("a{i}")),
        false,
    );
    scan_32_bit(
        "escaped keys",
        &pairs_of(r#""module":"m","#, len, |i| format!("\"\\u0061{i}\"")),
        false,
    );
    scan_32_bit(
        "keys of the module object",
        &format!(
            r#"{{"module":{}}}"#,
            pairs_of("", len, |i| format!("\"k{i}\""))
        ),
        false,
    );
    scan_32_bit(
        "objects as keys",
        &pairs_of(r#""module":"m","#, len, |i| format!("{{\"k{i}\":0}}")),
        false,
    );
    scan_32_bit(
        "one object of keys as a key",
        &format!(
            r#"{{"module":"m",{}:0}}"#,
            pairs_of("", len, |i| format!("\"k{i}\""))
        ),
        false,
    );
}

#[test]
fn one_long_key_is_bounded_on_32_bit() {
    let _turn = turn();
    let len = 24 * MIB;
    scan_32_bit(
        "an unquoted key",
        &format!("{{module:m,{}:0}}", "a".repeat(len)),
        false,
    );
    scan_32_bit(
        "an escaped key",
        &format!(r#"{{"module":"m","{}":0}}"#, "\\n".repeat(len / 2)),
        false,
    );
}

#[test]
fn a_module_container_is_not_built() {
    let _turn = turn();
    // `{"module":[{},{},…]}` took 1.7 GiB for 64 MiB, more than a process of 2 GiB has.
    let len = 48 * MIB;
    let array = format!(r#"{{"module":[{}{{}}]}}"#, "{},".repeat(len / 3));
    let scanned = scan_32_bit("an array of objects", &array, true);
    assert_eq!(scanned.len, array.len());
    assert_eq!(scanned.value, Some(JValue::Arr(Vec::new())));
    let strings = format!(r#"{{"module":[{}""]}}"#, r#""","#.repeat(len / 3));
    let scanned = scan_32_bit("an array of strings", &strings, true);
    assert_eq!(scanned.value, Some(JValue::Arr(Vec::new())));
    let nested = format!(r#"{{"module":{}0{}}}"#, "[".repeat(100), "]".repeat(100));
    let scanned = scan_32_bit("deep arrays", &nested, true);
    assert_eq!(scanned.value, Some(JValue::Arr(Vec::new())));
    // An object with few keys is read and dropped as well.
    let object = r#"{"x":1,"module":{"a":{"b":[1,2,{"c":3}]}},"y":2}"#;
    let scanned = scan_32_bit("an object", object, true);
    assert_eq!(scanned.value, Some(JValue::Obj(JObject::hash_map())));
    assert_eq!(scanned.len, object.len());
}

#[test]
fn what_pages_send_is_read_on_32_bit() {
    let _turn = turn();
    // A hundred thousand keys in one object, and as many in objects of three: no refusal.
    let one = pairs_of(r#""module":"m","#, 100_000 * 10, |i| format!("\"k{i}\""));
    let scanned = scan_32_bit("a hundred thousand keys", &one, true);
    assert_eq!(scanned.value, Some(JValue::from("m")));
    let many = format!(
        r#"{{"module":"m","x":[{}{{"a":0,"b":0,"c":0}}]}}"#,
        r#"{"a":0,"b":0,"c":0},"#.repeat(200_000)
    );
    let scanned = scan_32_bit("objects of three keys", &many, true);
    assert_eq!(scanned.len, many.len());
    // A module name and a document of megabytes.
    let name = "n".repeat(8 * MIB);
    let big = format!(r#"{{"module":"{name}","data":"{}"}}"#, "d".repeat(8 * MIB));
    let scanned = scan_32_bit("a long module name", &big, true);
    assert_eq!(scanned.value, Some(JValue::Str(name)));
    // Duplicates are found in every shape.
    for text in [
        r#"{"a":1,"a":2}"#,
        r#"{module:m,a:1,"a":2}"#,
        r#"{"module":"m","a":{"b":1,"b":2}}"#,
        r#"{"module":"m","\u0061":1,a:2}"#,
        r#"{"module":[{"k":1,"k":2}]}"#,
    ] {
        let message = scan_within(text, "module", BUDGET).unwrap_err();
        assert!(message.starts_with("Duplicate key"), "{text}: {message}");
    }
}
