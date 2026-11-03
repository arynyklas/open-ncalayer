//! What a built-in call costs in the core's heap before the module sees the request: a
//! request over what may be passed to the module is refused before it is copied, kept
//! or encoded, so a large frame does not grow the heap by gigabytes only to be dropped.

use oncl_builtin_tests::SOURCES;
use oncl_builtin_tests::basics::MODULE_NAME;
use oncl_flows::testing::{MemoryRecentPath, ScriptedPrompter};
use oncl_pki::tsp::MockTsa;
use oncl_plugin::{BuiltinLimits, Builtins, Engine as WasmEngine, HostServices};
use oncl_protocol::{AddInfo, Reply};
use oncl_testkit::{read, synthetic};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

struct Counting;

static HELD: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let held = HELD.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(held, Relaxed);
}

// SAFETY: every call goes to `System`; the counters only add up what it was asked.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grew(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        grew(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        HELD.fetch_sub(layout.size(), Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
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

const MIB: usize = 1 << 20;

/// Taken by every test: the counters are the process's.
fn turn() -> MutexGuard<'static, ()> {
    static TURN: Mutex<()> = Mutex::new(());
    TURN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The default limits of a 32-bit target, on any target.
fn limits_32_bit() -> BuiltinLimits {
    let mut limits = BuiltinLimits::default();
    limits.instance.max_memory = 16 * MIB;
    limits.instance.max_transfer = 16 * MIB;
    limits.instance.max_kept = 256 * MIB;
    limits.high_water = 8 * MIB;
    limits.max_live = 4;
    limits
}

fn services() -> HostServices {
    let tsa = synthetic("tsa-gost2015");
    let tsa = oncl_pki::pkcs12::load(&read(&tsa.path), &tsa.password)
        .unwrap()
        .remove(0);
    HostServices::interactive(
        Arc::new(ScriptedPrompter::new(Vec::new())),
        Arc::new(MemoryRecentPath::new(None)),
        Arc::new(MockTsa::new(tsa)),
        oncl_token::Tokens::disabled(),
    )
}

/// A `sign` request of basics whose `data` is `count` strings of `len` bytes, about
/// `count * (len + 3)` bytes.
fn batch(count: usize, len: usize) -> String {
    let doc = "d".repeat(len);
    let mut docs = String::with_capacity(count * (len + 3));
    for i in 0..count {
        if i > 0 {
            docs.push(',');
        }
        docs.push('"');
        docs.push_str(&doc);
        docs.push('"');
    }
    format!(
        r#"{{"module":"{MODULE_NAME}","method":"sign","args":{{"format":"xml","data":[{docs}],"signingParams":{{}},"signerParams":{{"extKeyUsageOids":[],"chain":[]}}}}}}"#
    )
}

/// The heap a call of `request` held beyond what was held before it, and its reply.
fn call(builtins: &Builtins, request: &str) -> (Reply, usize) {
    let module = builtins.module(MODULE_NAME).unwrap();
    let base = HELD.load(Relaxed);
    PEAK.store(base, Relaxed);
    let reply = module.process(request, &AddInfo::default());
    (reply, PEAK.load(Relaxed).saturating_sub(base))
}

fn loaded() -> Builtins {
    Builtins::load(
        &WasmEngine::new(),
        services(),
        SOURCES,
        limits_32_bit(),
        None,
    )
    .unwrap()
}

/// Requests longer than the module may be passed: the connection is dropped, and the
/// call has taken next to nothing.
#[test]
fn a_request_over_the_transfer_limit_costs_no_copy() {
    let _turn = turn();
    let builtins = loaded();
    for (what, count, len) in [
        // Too short to be kept: copied and encoded as it is.
        ("63-byte documents", 1 << 20, 63),
        // Kept in the core, each with its entry.
        ("64-byte documents", 1 << 20, 64),
        // More than a call may keep (256 MiB with each string's entry).
        ("1000-byte documents", 300_000, 1000),
    ] {
        let request = batch(count, len);
        assert!(request.len() > 16 * MIB);
        let (reply, peak) = call(&builtins, &request);
        eprintln!("{what}: {} bytes: heap +{} bytes", request.len(), peak);
        assert_eq!(reply, Reply::Drop, "{what}");
        assert!(peak < 4 * MIB, "{what}: heap grew by {peak} bytes");
    }
}

/// The frames of the largest message, measured: `cargo test -p oncl-builtin-tests --test
/// call_heap --release -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement"]
fn largest_frames() {
    let _turn = turn();
    let builtins = loaded();
    for (what, count, len) in [
        ("63-byte documents", 4 << 20, 63),
        ("64-byte documents", 4 << 20, 64),
        ("1000-byte documents", 256 << 10, 1000),
    ] {
        let request = batch(count, len);
        let (reply, peak) = call(&builtins, &request);
        eprintln!(
            "{what}: {} MiB: heap +{} MiB, {reply:?}",
            request.len() / MIB,
            peak / MIB
        );
    }
}
