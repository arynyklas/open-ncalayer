//! A moving test allocator observes live bytes immediately before deallocation.
//! It never reads freed/uninitialized memory: watched allocations are zero-filled.
use oncl_pki::{
    io::{MetadataInput, Source},
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    io::{self, Read},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
#[derive(Clone, Copy)]
struct Allocation {
    pointer: usize,
    size: usize,
}
#[derive(Clone, Copy)]
struct Audit {
    active: bool,
    fail_growth: bool,
    allocations: usize,
    dirty_retirements: usize,
    failed_allocations: usize,
    records: [Allocation; 32],
}
impl Audit {
    const fn empty() -> Self {
        Self {
            active: false,
            fail_growth: false,
            allocations: 0,
            dirty_retirements: 0,
            failed_allocations: 0,
            records: [Allocation {
                pointer: 0,
                size: 0,
            }; 32],
        }
    }
    fn live_bytes(self) -> usize {
        self.records
            .iter()
            .filter(|record| record.pointer != 0)
            .map(|record| record.size)
            .sum()
    }
}
thread_local! { static AUDIT: Cell<Audit> = const { Cell::new(Audit::empty()) }; }
struct MovingAllocator;
// SAFETY: unobserved calls delegate to System. Watched allocations use the same
// System allocator/layout; realloc preserves its prefix before deallocating the
// still-live old allocation. Observation happens before System.dealloc only.
unsafe impl GlobalAlloc for MovingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let watched = AUDIT
            .try_with(|state| state.get().active && layout.size() >= 4096)
            .unwrap_or(false);
        if !watched {
            return unsafe { System.alloc(layout) };
        }
        let fail = AUDIT.with(|state| {
            let mut audit = state.get();
            let fail = audit.fail_growth && layout.size() >= 8192;
            if fail {
                audit.fail_growth = false;
                audit.failed_allocations += 1;
                state.set(audit);
            }
            fail
        });
        if fail {
            return std::ptr::null_mut();
        }
        // Zero initialization makes observation of spare capacity defined too.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            AUDIT.with(|state| {
                let mut audit = state.get();
                let slot = audit
                    .records
                    .iter_mut()
                    .find(|record| record.pointer == 0)
                    .expect("bounded test allocation records");
                *slot = Allocation {
                    pointer: pointer as usize,
                    size: layout.size(),
                };
                audit.allocations += 1;
                state.set(audit);
            });
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = AUDIT.try_with(|state| {
            let mut audit = state.get();
            if audit.active
                && let Some(record) = audit
                    .records
                    .iter_mut()
                    .find(|record| record.pointer == pointer as usize)
            {
                let bytes = unsafe { std::slice::from_raw_parts(pointer, record.size) };
                if bytes.iter().any(|byte| *byte != 0) {
                    audit.dirty_retirements += 1;
                }
                *record = Allocation {
                    pointer: 0,
                    size: 0,
                };
                state.set(audit);
            }
        });
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let watched = AUDIT
            .try_with(|state| {
                let audit = state.get();
                audit.active
                    && audit
                        .records
                        .iter()
                        .any(|record| record.pointer == pointer as usize)
            })
            .unwrap_or(false);
        if !watched {
            return unsafe { System.realloc(pointer, layout, new_size) };
        }
        let replacement_layout = Layout::from_size_align(new_size, layout.align()).unwrap();
        let replacement = unsafe { self.alloc(replacement_layout) };
        if replacement.is_null() {
            return replacement;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(pointer, replacement, layout.size().min(new_size));
            self.dealloc(pointer, layout);
        }
        replacement
    }
}
#[global_allocator]
static ALLOCATOR: MovingAllocator = MovingAllocator;
struct Control(AtomicBool);
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.0.load(Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
struct SecretReader {
    remaining: usize,
    reads: usize,
    cancel_at: Option<usize>,
    control: Arc<Control>,
}
impl Read for SecretReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output.len().min(self.remaining);
        output[..count].fill(0xa5);
        self.remaining -= count;
        self.reads += 1;
        if self.cancel_at == Some(self.reads) {
            self.control.0.store(true, Ordering::SeqCst);
        }
        Ok(count)
    }
}
fn start(fail_growth: bool) {
    AUDIT.with(|state| {
        let mut audit = Audit::empty();
        audit.active = true;
        audit.fail_growth = fail_growth;
        state.set(audit);
    });
}
fn stop() -> Audit {
    AUDIT.with(|state| {
        let audit = state.get();
        state.set(Audit::empty());
        audit
    })
}
fn run(
    length: usize,
    hint: Option<u64>,
    limits: ResourceLimits,
    fail: bool,
    cancel_at: Option<usize>,
) -> (Result<(), ProcessingError>, Audit, u64) {
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let control = Arc::new(Control(AtomicBool::new(false)));
    let mut scope = budget.begin(limits, control.clone()).unwrap();
    let mut source = SecretReader {
        remaining: length,
        reads: 0,
        cancel_at,
        control,
    };
    start(fail);
    let result = MetadataInput::read(Source::sequential(&mut source, hint), &mut scope, 65536);
    let result = match result {
        Ok(input) => {
            let correct = input.as_bytes().len() == length
                && input.as_bytes().iter().all(|byte| *byte == 0xa5);
            drop(input);
            assert!(correct);
            Ok(())
        }
        Err(error) => Err(error),
    };
    let audit = stop();
    let consumed = scope.progress().bytes_in;
    drop(scope);
    assert!(
        budget
            .begin(
                ResourceLimits::default(),
                Arc::new(Control(AtomicBool::new(false)))
            )
            .is_ok()
    );
    (result, audit, consumed)
}
#[test]
fn moving_secret_intake_wipes_every_retired_buffer_and_grows_linearly() {
    for hint in [None, Some(32769)] {
        let (result, audit, consumed) = run(32769, hint, ResourceLimits::default(), false, None);
        result.unwrap();
        assert_eq!(consumed, 32769);
        assert_eq!(
            audit.dirty_retirements, 0,
            "secret prefixes must be wiped before every free"
        );
        assert!(
            audit.allocations <= if hint.is_some() { 1 } else { 6 },
            "growth must be bounded, not per-chunk copying"
        );
        assert_eq!(audit.live_bytes(), 0);
    }
}
#[test]
fn replacement_allocation_failure_wipes_old_secret_and_preserves_consumption() {
    let (result, audit, consumed) = run(32769, None, ResourceLimits::default(), true, None);
    assert!(matches!(result, Err(ProcessingError::MemoryLimit)));
    assert_eq!(audit.failed_allocations, 1);
    assert_eq!(consumed, 8192);
    assert_eq!(audit.dirty_retirements, 0);
    assert_eq!(audit.live_bytes(), 0);
}
#[test]
fn old_plus_new_capacity_is_admitted_before_any_replacement_allocation() {
    let limits = ResourceLimits {
        memory_bytes: 25_000,
        ..ResourceLimits::default()
    };
    let (result, audit, consumed) = run(32769, None, limits, false, None);
    assert!(matches!(result, Err(ProcessingError::MemoryLimit)));
    assert_eq!(consumed, 8192);
    assert_eq!(audit.allocations, 1);
    assert_eq!(audit.dirty_retirements, 0);
}
#[test]
fn consumed_multichunk_cancellation_wipes_all_current_and_retired_secret_bytes() {
    let (result, audit, consumed) = run(32769, None, ResourceLimits::default(), false, Some(3));
    assert!(matches!(result, Err(ProcessingError::Cancelled)));
    assert_eq!(consumed, 12288);
    assert_eq!(audit.dirty_retirements, 0);
    assert_eq!(audit.live_bytes(), 0);
}
#[test]
fn retained_capacity_and_original_scope_remain_charged_with_the_owner() {
    // Allow the real 200,704-byte old+new replacement peak, then probe the
    // smaller final retained capacity independently of that transient peak.
    let limits = ResourceLimits {
        memory_bytes: 250_000,
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let control = Arc::new(Control(AtomicBool::new(false)));
    let mut scope = budget.begin(limits, control.clone()).unwrap();
    let mut source = SecretReader {
        remaining: 32769,
        reads: 0,
        cancel_at: None,
        control,
    };
    start(false);
    let input =
        MetadataInput::read(Source::sequential(&mut source, None), &mut scope, 65536).unwrap();
    let live = AUDIT.with(|state| state.get().live_bytes());
    let probe = scope.reserve_memory(250_000 - 2 * live as u64).unwrap();
    assert!(matches!(
        scope.reserve_memory(1),
        Err(ProcessingError::MemoryLimit)
    ));
    drop(probe);
    drop(scope);
    assert!(matches!(
        budget.begin(
            ResourceLimits::default(),
            Arc::new(Control(AtomicBool::new(false)))
        ),
        Err(ProcessingError::CapacityExceeded)
    ));
    drop(input);
    let audit = stop();
    assert_eq!(audit.dirty_retirements, 0);
    assert_eq!(audit.live_bytes(), 0);
    assert!(
        budget
            .begin(
                ResourceLimits::default(),
                Arc::new(Control(AtomicBool::new(false)))
            )
            .is_ok()
    );
}
