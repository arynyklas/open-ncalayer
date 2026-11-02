use oncl_pki::{
    io::{FrozenInput, Region, Source, TemporaryStore},
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
};
use std::{
    io::{Cursor, Read},
    sync::Arc,
};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn scope(limits: ResourceLimits) -> ResourceScope {
    Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control))
        .unwrap()
}
#[test]
fn captured_bytes_are_immutable_and_intake_charged_once() {
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope(ResourceLimits {
        input_bytes: 6,
        ..ResourceLimits::default()
    });
    let mut source = Cursor::new(b"prefixabcdef".to_vec());
    source.set_position(6);
    let mut frozen =
        FrozenInput::capture(Source::seekable(&mut source, Some(1)), &store, &mut scope).unwrap();
    source.get_mut()[6..].fill(b'X');
    assert_eq!(scope.progress().bytes_in, 6);
    let mut view = frozen
        .reader(
            &[Region { offset: 1, len: 2 }, Region { offset: 5, len: 1 }],
            &scope,
        )
        .unwrap();
    let mut got = Vec::new();
    view.read_to_end(&mut got).unwrap();
    view.finish().unwrap();
    assert_eq!(got, b"bcf");
    assert_eq!(scope.progress().bytes_in, 6);
    drop(view);
    let mut other = super_scope();
    assert!(matches!(
        frozen.reader(&[Region { offset: 0, len: 1 }], &other),
        Err(ProcessingError::InvalidInput(_))
    ));
    assert!(
        frozen
            .reader(
                &[Region {
                    offset: u64::MAX,
                    len: 1
                }],
                &scope
            )
            .is_err()
    );
    let derived = frozen
        .derive_region(Region { offset: 0, len: 3 }, &scope, |encoded, output| {
            output.write_all(encoded)?;
            Ok(())
        })
        .unwrap();
    assert_eq!(derived.as_bytes(), b"abc");
    assert!(
        frozen
            .derive_region(Region { offset: 0, len: 1 }, &scope, |_, output| {
                output.write_all(b"too long")?;
                Ok(())
            })
            .is_err()
    );
    let _ = &mut other;
}
fn super_scope() -> ResourceScope {
    scope(ResourceLimits::default())
}
#[test]
fn sequential_capture_counts_actual_limit_plus_one() {
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope(ResourceLimits {
        input_bytes: 3,
        ..ResourceLimits::default()
    });
    let mut source = Cursor::new(b"abcdef");
    assert!(matches!(
        FrozenInput::capture(Source::sequential(&mut source, Some(1)), &store, &mut scope),
        Err(ProcessingError::InputLimit)
    ));
    assert_eq!(scope.progress().bytes_in, 4);
}

#[test]
fn derived_metadata_cannot_bind_another_snapshot_in_the_same_operation() {
    use oncl_pki::{
        http::{HttpError, HttpReply, HttpRequest, HttpTransport},
        pkix::CaSet,
        validation::{ValidationContext, ValidationPolicy},
    };
    struct Offline;
    impl HttpTransport for Offline {
        fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            panic!("unexpected network")
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope(ResourceLimits::default());
    let mut first = Cursor::new(b"abc");
    let mut second = Cursor::new(b"abc");
    let mut one =
        FrozenInput::capture(Source::sequential(&mut first, None), &store, &mut scope).unwrap();
    let mut two =
        FrozenInput::capture(Source::sequential(&mut second, None), &store, &mut scope).unwrap();
    let metadata = one
        .derive_region(Region { offset: 0, len: 3 }, &scope, |input, output| {
            output.write_all(input)?;
            Ok(())
        })
        .unwrap();
    let anchors = CaSet::new(vec![]);
    let validation = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: time::OffsetDateTime::UNIX_EPOCH,
        anchors: &anchors,
        intermediates: &[],
        http: &Offline,
    };
    assert!(matches!(
        oncl_pki::cms::stream::verify_snapshot_detached(
            &metadata,
            &mut two,
            &[Region { offset: 0, len: 3 }],
            &validation,
            &[],
            &mut scope
        ),
        Err(oncl_pki::cms::stream::StreamError::Processing(
            ProcessingError::InvalidInput("derived metadata belongs to another snapshot")
        ))
    ));
    for regions in [
        vec![Region { offset: 0, len: 0 }],
        vec![Region { offset: 0, len: 2 }, Region { offset: 1, len: 1 }],
        vec![Region {
            offset: u64::MAX,
            len: 2,
        }],
    ] {
        assert!(
            oncl_pki::cms::stream::verify_snapshot_detached(
                &metadata,
                &mut one,
                &regions,
                &validation,
                &[],
                &mut scope
            )
            .is_err()
        );
    }
}
