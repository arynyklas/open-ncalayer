use oncl_pki::resource::{
    OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget,
};
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn limits() -> ResourceLimits {
    ResourceLimits {
        memory_bytes: 100,
        metadata_bytes: 50,
        ..ResourceLimits::default()
    }
}
#[test]
fn configuration_metadata_counts_as_ram_once_without_an_active_operation_slot() {
    let limits = limits();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let configuration = budget.reserve_configuration(30, 20).unwrap();
    let scope = budget.begin(limits.clone(), Arc::new(Control)).unwrap();
    assert!(matches!(
        budget.begin(limits, Arc::new(Control)),
        Err(ProcessingError::CapacityExceeded)
    ));
    let memory = scope.reserve_memory(50).unwrap();
    assert!(matches!(
        scope.reserve_memory(1),
        Err(ProcessingError::MemoryLimit)
    ));
    drop(memory);
    let metadata = scope.reserve_metadata(30).unwrap();
    assert!(matches!(
        scope.reserve_metadata(1),
        Err(ProcessingError::MetadataLimit)
    ));
    drop(metadata);
    drop(configuration);
    scope.reserve_memory(100).unwrap();
    scope.reserve_metadata(50).unwrap();
}
#[test]
fn configuration_grow_failure_is_atomic_and_does_not_release_prior_storage() {
    let budget = Arc::new(SharedBudget::new(limits()).unwrap());
    let mut configuration = budget.reserve_configuration(30, 20).unwrap();
    assert!(matches!(
        configuration.grow(51, 0),
        Err(ProcessingError::MemoryLimit)
    ));
    let exact = budget.reserve_configuration(50, 0).unwrap();
    drop(exact);
    assert!(matches!(
        configuration.grow(0, 31),
        Err(ProcessingError::MetadataLimit)
    ));
    let exact = budget.reserve_configuration(0, 30).unwrap();
    drop(exact);
    configuration.grow(10, 5).unwrap();
    let exact = budget.reserve_configuration(35, 0).unwrap();
    assert!(matches!(
        budget.reserve_configuration(1, 0),
        Err(ProcessingError::MemoryLimit)
    ));
    drop(exact);
    drop(configuration);
    budget.reserve_configuration(50, 50).unwrap();
}
#[test]
fn configuration_checked_overflow_changes_no_global_counters() {
    let budget = Arc::new(
        SharedBudget::new(ResourceLimits {
            memory_bytes: u64::MAX,
            metadata_bytes: u64::MAX,
            ..ResourceLimits::default()
        })
        .unwrap(),
    );
    assert!(matches!(
        budget.reserve_configuration(u64::MAX, 1),
        Err(ProcessingError::MemoryLimit)
    ));
    let mut configuration = budget.reserve_configuration(u64::MAX - 2, 1).unwrap();
    assert!(matches!(
        configuration.grow(1, 1),
        Err(ProcessingError::MemoryLimit)
    ));
    let last = budget.reserve_configuration(1, 0).unwrap();
    drop(last);
    drop(configuration);
    budget.reserve_configuration(u64::MAX, 0).unwrap();
}
#[test]
fn concurrent_configuration_owners_share_one_global_memory_limit() {
    let budget = Arc::new(SharedBudget::new(limits()).unwrap());
    let entered = Arc::new(Barrier::new(9));
    let release = Arc::new(Barrier::new(9));
    let successful = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let budget = budget.clone();
        let entered = entered.clone();
        let release = release.clone();
        let successful = successful.clone();
        threads.push(std::thread::spawn(move || {
            let reservation = budget.reserve_configuration(30, 0);
            if reservation.is_ok() {
                successful.fetch_add(1, Ordering::SeqCst);
            }
            entered.wait();
            release.wait();
            drop(reservation);
        }));
    }
    entered.wait();
    let count = successful.load(Ordering::SeqCst);
    release.wait();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(count, 3);
    budget.reserve_configuration(100, 0).unwrap();
    budget.begin(limits(), Arc::new(Control)).unwrap();
}
