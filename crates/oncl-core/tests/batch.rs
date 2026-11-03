use oncl_core::batch::{BatchError, BatchItem, BatchOperation};
use oncl_core::{Action, Engine, EngineServices, ExecutionGrant, OperationPolicy};
use oncl_pki::{
    io::Source,
    key::HashAlg,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
};
use std::sync::Arc;
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
#[test]
fn hash_changed_source_rejects_old_approval() {
    let scratch = tempfile::tempdir().unwrap();
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_temporary_store(oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap()),
    )
    .unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut old = &b"confirmed"[..];
    let plan = engine
        .capture_batch(
            [BatchItem::new(
                "one",
                BatchOperation::Hash {
                    algorithm: HashAlg::Sha256,
                    input: Source::sequential(&mut old, None),
                },
            )],
            &mut ctx,
        )
        .unwrap();
    let authority = plan.authorize(&ctx).unwrap();
    let mut changed = &b"changed"[..];
    let replacement = engine
        .capture_batch(
            [BatchItem::new(
                "one",
                BatchOperation::Hash {
                    algorithm: HashAlg::Sha256,
                    input: Source::sequential(&mut changed, None),
                },
            )],
            &mut ctx,
        )
        .unwrap();
    assert!(matches!(
        engine.run_batch(replacement, authority, &mut ctx, |_| {}),
        Err(BatchError::ConsentMismatch)
    ));
}

#[derive(Default)]
struct Cancel(std::sync::atomic::AtomicBool);
impl OperationControl for Cancel {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.0.load(std::sync::atomic::Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
#[test]
fn hash_cancel_tracks_capture_progress_and_source_identity() {
    use oncl_core::batch::{BatchEvent, BatchOutcome, BatchReport};
    let scratch = tempfile::tempdir().unwrap();
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_temporary_store(oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap()),
    )
    .unwrap();
    let control = Arc::new(Cancel::default());
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            control.clone(),
        )
        .unwrap();
    let mut one = &b"abc"[..];
    let mut two = &b"def"[..];
    let plan = engine
        .capture_batch(
            [
                BatchItem::new(
                    "first",
                    BatchOperation::Hash {
                        algorithm: HashAlg::Sha256,
                        input: Source::sequential(&mut one, None),
                    },
                ),
                BatchItem::new(
                    "second",
                    BatchOperation::Hash {
                        algorithm: HashAlg::Sha256,
                        input: Source::sequential(&mut two, None),
                    },
                ),
            ],
            &mut ctx,
        )
        .unwrap();
    let approval = plan.authorize(&ctx).unwrap();
    let mut finished = 0;
    let report = engine
        .run_batch(plan, approval, &mut ctx, |event| {
            if let BatchEvent::ItemFinished { .. } = event {
                finished += 1;
                control.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        })
        .unwrap();
    assert_eq!(
        (report.attempted, report.completed, report.total, finished),
        (1, 1, 2, 2)
    );
    assert!(matches!(
        report.results()[0].outcome(),
        BatchOutcome::Completed(BatchReport::Hash(_))
    ));
    assert_eq!(
        (
            report.results()[0].sources()[0].bytes(),
            report.progress.bytes_in
        ),
        (3, 6)
    );
    assert_eq!(
        report.results()[0].sources()[0].sha256().as_bytes(),
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    assert!(matches!(
        report.results()[1].outcome(),
        BatchOutcome::NotRun
    ));
    assert_eq!(report.stop.unwrap().code(), oncl_core::ErrorCode::Cancelled);
}
#[test]
fn hash_local_read_failure_preserves_other_digest_results() {
    use oncl_core::batch::{BatchOutcome, BatchReport};
    struct Bad;
    impl std::io::Read for Bad {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("unavailable source"))
        }
    }
    let scratch = tempfile::tempdir().unwrap();
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_temporary_store(oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap()),
    )
    .unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut one = &b"abc"[..];
    let mut bad = Bad;
    let mut three = &b"def"[..];
    let plan = engine
        .capture_batch(
            [
                BatchItem::new(
                    "first",
                    BatchOperation::Hash {
                        algorithm: HashAlg::Sha256,
                        input: Source::sequential(&mut one, None),
                    },
                ),
                BatchItem::new(
                    "bad",
                    BatchOperation::Hash {
                        algorithm: HashAlg::Sha256,
                        input: Source::sequential(&mut bad, None),
                    },
                ),
                BatchItem::new(
                    "third",
                    BatchOperation::Hash {
                        algorithm: HashAlg::Sha256,
                        input: Source::sequential(&mut three, None),
                    },
                ),
            ],
            &mut ctx,
        )
        .unwrap();
    let approval = plan.authorize(&ctx).unwrap();
    let report = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert_eq!((report.attempted, report.completed), (3, 2));
    assert!(matches!(
        report.results()[0].outcome(),
        BatchOutcome::Completed(BatchReport::Hash(_))
    ));
    assert!(
        matches!(report.results()[1].outcome(), BatchOutcome::Failed(e) if e.code() == oncl_core::ErrorCode::Io)
    );
    assert!(matches!(
        report.results()[2].outcome(),
        BatchOutcome::Completed(BatchReport::Hash(_))
    ));
}

#[path = "../examples/sdk_probe/batch_fixture.rs"]
mod fixture;

#[test]
fn real_signatures_pin_source_at_guard_and_reuse_only_context_lease() {
    use oncl_core::{
        SignRequest,
        batch::{BatchOutcome, BatchReport},
        keys::KeyRequest,
    };
    use std::io::Read;
    use std::sync::{Mutex, atomic::Ordering};
    struct Mutable {
        data: Arc<Mutex<Vec<u8>>>,
        at: usize,
    }
    impl Read for Mutable {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            let data = self.data.lock().unwrap();
            let n = b.len().min(data.len().saturating_sub(self.at));
            b[..n].copy_from_slice(&data[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }
    let scratch = tempfile::tempdir().unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
        guard.clone(),
        provider.clone(),
        ResourceLimits::default(),
    );
    let key = fixture::selector("user-rsa-sign");
    let grant = ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]);
    let mut ctx = engine
        .begin(
            grant.clone(),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let data = Arc::new(Mutex::new(b"confirmed source".to_vec()));
    let mut source = Mutable {
        data: data.clone(),
        at: 0,
    };
    let changed = data.clone();
    *guard.hook.lock().unwrap() = Some(Box::new(move || {
        *changed.lock().unwrap() = b"changed at guard".to_vec()
    }));
    let mut second = &b"second source"[..];
    let mut first_out = vec![];
    let mut second_out = vec![];
    let plan = engine
        .capture_batch(
            [
                BatchItem::new(
                    "one",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut source, None),
                        output: &mut first_out,
                    },
                ),
                BatchItem::new(
                    "two",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut second, None),
                        output: &mut second_out,
                    },
                ),
            ],
            &mut ctx,
        )
        .unwrap();
    assert_eq!(provider.opens.load(Ordering::SeqCst), 1);
    let approval = plan.authorize(&ctx).unwrap();
    *data.lock().unwrap() = b"changed after approval before run".to_vec();
    let summary = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert_eq!(
        (summary.completed, guard.applied.load(Ordering::SeqCst)),
        (2, 2)
    );
    assert!(
        matches!(summary.results()[0].outcome(), BatchOutcome::Completed(BatchReport::Sign(r)) if r.applied == oncl_core::keys::AppliedState::Applied)
    );
    let public = fixture::raw("user-rsa-sign").key.public_key();
    public
        .verify(
            oncl_pki::key::SigAlg::RsaSha256,
            b"confirmed source",
            &first_out,
        )
        .unwrap();
    assert!(
        public
            .verify(
                oncl_pki::key::SigAlg::RsaSha256,
                b"changed at guard",
                &first_out
            )
            .is_err()
    );
    public
        .verify(
            oncl_pki::key::SigAlg::RsaSha256,
            b"second source",
            &second_out,
        )
        .unwrap();
    drop((summary, ctx));
    let mut independent = engine
        .begin(grant, OperationPolicy::strict_online(), Arc::new(Control))
        .unwrap();
    let mut third = &b"third"[..];
    let mut out = vec![];
    let plan = engine
        .capture_batch(
            [BatchItem::new(
                "third",
                BatchOperation::Sign {
                    request: SignRequest::raw_message(KeyRequest::new(
                        &key,
                        Some(fixture::PASSWORD),
                    )),
                    input: Source::sequential(&mut third, None),
                    output: &mut out,
                },
            )],
            &mut independent,
        )
        .unwrap();
    assert_eq!(provider.opens.load(Ordering::SeqCst), 2);
    drop(plan);
}

#[test]
fn postuse_guard_failures_keep_applied_and_stop_new_private_use() {
    use oncl_core::{SignRequest, batch::BatchOutcome, keys::KeyRequest};
    use std::sync::atomic::Ordering;
    for expected in [oncl_core::ErrorCode::AuditFailed, oncl_core::ErrorCode::Io] {
        let scratch = tempfile::tempdir().unwrap();
        let guard = Arc::new(fixture::Guard::default());
        let provider = Arc::new(fixture::Provider::default());
        guard.audit_fail.store(
            expected == oncl_core::ErrorCode::AuditFailed,
            Ordering::SeqCst,
        );
        guard
            .finish_io_fail
            .store(expected == oncl_core::ErrorCode::Io, Ordering::SeqCst);
        let engine = fixture::engine(
            oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
            guard.clone(),
            provider,
            ResourceLimits::default(),
        );
        let key = fixture::selector("user-rsa-sign");
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
                OperationPolicy::strict_online(),
                Arc::new(Control),
            )
            .unwrap();
        let mut one = &b"abc"[..];
        let mut two = &b"def"[..];
        let mut out1 = vec![];
        let mut out2 = vec![];
        let plan = engine
            .capture_batch(
                [
                    BatchItem::new(
                        "one",
                        BatchOperation::Sign {
                            request: SignRequest::raw_message(KeyRequest::new(
                                &key,
                                Some(fixture::PASSWORD),
                            )),
                            input: Source::sequential(&mut one, None),
                            output: &mut out1,
                        },
                    ),
                    BatchItem::new(
                        "two",
                        BatchOperation::Sign {
                            request: SignRequest::raw_message(KeyRequest::new(
                                &key,
                                Some(fixture::PASSWORD),
                            )),
                            input: Source::sequential(&mut two, None),
                            output: &mut out2,
                        },
                    ),
                ],
                &mut ctx,
            )
            .unwrap();
        let approval = plan.authorize(&ctx).unwrap();
        let summary = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
        assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
        assert!(
            matches!(summary.results()[0].outcome(), BatchOutcome::Failed(e) if e.code() == expected && e.applied_state() == oncl_core::keys::AppliedState::Applied)
        );
        assert!(matches!(
            summary.results()[1].outcome(),
            BatchOutcome::NotRun
        ));
        assert_eq!(summary.stop.as_ref().unwrap().code(), expected);
        assert!(out2.is_empty());
        assert_eq!(
            guard.finished.lock().unwrap()[0]
                .batch_item()
                .unwrap()
                .get(),
            0
        );
    }
}

#[test]
fn guard_failure_is_terminal_even_with_element_local_error_code() {
    use oncl_core::{SignRequest, batch::BatchOutcome, keys::KeyRequest};
    use std::sync::atomic::Ordering;
    let scratch = tempfile::tempdir().unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    guard.preuse_local_error.store(true, Ordering::SeqCst);
    let engine = fixture::engine(
        oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
        guard.clone(),
        provider.clone(),
        ResourceLimits::default(),
    );
    let key = fixture::selector("user-rsa-sign");
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut one = &b"abc"[..];
    let mut two = &b"def"[..];
    let mut out1 = vec![];
    let mut out2 = vec![];
    let plan = engine
        .capture_batch(
            [
                BatchItem::new(
                    "one",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut one, None),
                        output: &mut out1,
                    },
                ),
                BatchItem::new(
                    "two",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut two, None),
                        output: &mut out2,
                    },
                ),
            ],
            &mut ctx,
        )
        .unwrap();
    let approval = plan.authorize(&ctx).unwrap();
    let summary = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert!(
        matches!(summary.results()[0].outcome(), BatchOutcome::Failed(e) if e.code() == oncl_core::ErrorCode::ValidationRequired)
    );
    assert!(matches!(
        summary.results()[1].outcome(),
        BatchOutcome::NotRun
    ));
    assert!(out1.is_empty() && out2.is_empty());
    let mut denied = &b"later"[..];
    let mut denied_out = vec![];
    assert!(
        matches!(engine.sign(SignRequest::raw_message(KeyRequest::new(&key, Some(fixture::PASSWORD))), Source::sequential(&mut denied, None), &mut denied_out, &mut ctx), Err(e) if e.code() == oncl_core::ErrorCode::PermissionDenied)
    );
    assert_eq!(provider.opens.load(Ordering::SeqCst), 1);
    assert_eq!(guard.before.load(Ordering::SeqCst), 1);
    drop((summary, ctx));
    let mut independent = engine
        .begin(
            ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut actual = &b"independent"[..];
    let mut actual_out = vec![];
    engine
        .sign(
            SignRequest::raw_message(KeyRequest::new(&key, Some(fixture::PASSWORD))),
            Source::sequential(&mut actual, None),
            &mut actual_out,
            &mut independent,
        )
        .unwrap();
    assert_eq!(provider.opens.load(Ordering::SeqCst), 2);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
}

#[test]
fn changed_source_requires_new_authority() {
    use oncl_core::{SignRequest, keys::KeyRequest};
    use std::sync::atomic::Ordering;
    for case in ["bytes", "profile", "key", "composition"] {
        let scratch = tempfile::tempdir().unwrap();
        let guard = Arc::new(fixture::Guard::default());
        let provider = Arc::new(fixture::Provider::default());
        let engine = fixture::engine(
            oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
            guard.clone(),
            provider.clone(),
            ResourceLimits::default(),
        );
        let key = fixture::selector("user-rsa-sign");
        let other_key = fixture::selector("user-gost2015-sign");
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([Action::Sign]).with_keys([key.key_id(), other_key.key_id()]),
                OperationPolicy::strict_online(),
                Arc::new(Control),
            )
            .unwrap();
        let mut original = &b"confirmed"[..];
        let mut original_out = vec![];
        let plan = engine
            .capture_batch(
                [BatchItem::new(
                    "one",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut original, None),
                        output: &mut original_out,
                    },
                )],
                &mut ctx,
            )
            .unwrap();
        let original_number = plan.plan_id();
        let view = plan.items().next().unwrap();
        assert_eq!(view.keys.len(), 1);
        assert_eq!(view.keys[0].key(), &key.key_id());
        assert_eq!(view.signing_profile, Some(oncl_core::SignProfile::Raw));
        let authority = plan.authorize(&ctx).unwrap();
        let mut changed = if case == "bytes" {
            &b"changed"[..]
        } else {
            &b"confirmed"[..]
        };
        let mut changed_out = vec![];
        let selected = if case == "key" { &other_key } else { &key };
        let request = if case == "profile" {
            SignRequest::cms_create(
                vec![KeyRequest::new(selected, Some(fixture::PASSWORD))],
                true,
            )
        } else {
            SignRequest::raw_message(KeyRequest::new(selected, Some(fixture::PASSWORD)))
        };
        let changed_plan = engine
            .capture_batch(
                [BatchItem::new(
                    if case == "composition" {
                        "different-id"
                    } else {
                        "one"
                    },
                    BatchOperation::Sign {
                        request,
                        input: Source::sequential(&mut changed, None),
                        output: &mut changed_out,
                    },
                )],
                &mut ctx,
            )
            .unwrap();
        assert!(changed_plan.plan_id() > original_number);
        let opens = provider.opens.load(Ordering::SeqCst);
        let mut events = 0;
        assert!(
            matches!(
                engine.run_batch(changed_plan, authority, &mut ctx, |_| events += 1),
                Err(BatchError::ConsentMismatch)
            ),
            "{case}"
        );
        assert_eq!(
            (
                guard.before.load(Ordering::SeqCst),
                guard.applied.load(Ordering::SeqCst),
                events
            ),
            (0, 0, 0),
            "{case}"
        );
        assert_eq!(provider.opens.load(Ordering::SeqCst), opens);
        drop(plan);
        assert!(original_out.is_empty() && changed_out.is_empty());
    }
}

#[test]
fn foreign_context_rejected_and_retained_results_keep_original_root() {
    let scratch = tempfile::tempdir().unwrap();
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits {
            max_in_flight: 2,
            ..ResourceLimits::default()
        })
        .with_temporary_store(oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap()),
    )
    .unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut foreign = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut input = &b"abc"[..];
    let plan = engine
        .capture_batch(
            [BatchItem::new(
                "one",
                BatchOperation::Hash {
                    algorithm: HashAlg::Sha256,
                    input: Source::sequential(&mut input, None),
                },
            )],
            &mut ctx,
        )
        .unwrap();
    assert!(matches!(
        plan.authorize(&foreign),
        Err(BatchError::ConsentMismatch)
    ));
    let approval = plan.authorize(&ctx).unwrap();
    assert!(matches!(
        engine.run_batch(plan, approval, &mut foreign, |_| panic!("foreign callback")),
        Err(BatchError::ConsentMismatch)
    ));
    drop(foreign);
    let mut input = &b"abc"[..];
    let plan = engine
        .capture_batch(
            [BatchItem::new(
                "one",
                BatchOperation::Hash {
                    algorithm: HashAlg::Sha256,
                    input: Source::sequential(&mut input, None),
                },
            )],
            &mut ctx,
        )
        .unwrap();
    let approval = plan.authorize(&ctx).unwrap();
    let report = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    drop(ctx);
    let admitted = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    assert!(
        matches!(engine.begin(ExecutionGrant::new([Action::Hash]), OperationPolicy::strict_online(), Arc::new(Control)), Err(e) if e.code() == oncl_core::ErrorCode::CapacityExceeded)
    );
    drop(report);
    let third = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    drop((admitted, third));
}

#[test]
fn batch_admission_is_bounded_and_rejects_duplicate_ids_without_reading_duplicate() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Inspect]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let names: Vec<String> = (0..1030).map(|n| n.to_string()).collect();
    let count = AtomicUsize::new(0);
    let result = engine.capture_batch(
        names.iter().map(|name| {
            count.fetch_add(1, Ordering::SeqCst);
            BatchItem::new(
                name,
                BatchOperation::Inspect {
                    request: oncl_core::InspectRequest::certificate(),
                    input: None,
                },
            )
        }),
        &mut ctx,
    );
    assert!(
        matches!(result, Err(BatchError::Operation(e)) if e.code() == oncl_core::ErrorCode::InvalidInput)
    );
    assert_eq!(count.load(Ordering::SeqCst), 1025);
    struct Untouched;
    impl std::io::Read for Untouched {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("duplicate or unauthorized source read")
        }
    }
    let scratch = tempfile::tempdir().unwrap();
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_temporary_store(oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap()),
    )
    .unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut empty = &b""[..];
    let mut duplicate = Untouched;
    let result = engine.capture_batch(
        [
            BatchItem::new(
                "same",
                BatchOperation::Hash {
                    algorithm: HashAlg::Sha256,
                    input: Source::sequential(&mut empty, None),
                },
            ),
            BatchItem::new(
                "same",
                BatchOperation::Hash {
                    algorithm: HashAlg::Sha256,
                    input: Source::sequential(&mut duplicate, None),
                },
            ),
        ],
        &mut ctx,
    );
    assert!(
        matches!(result, Err(BatchError::Operation(e)) if e.code() == oncl_core::ErrorCode::InvalidInput)
    );
}

#[test]
fn shared_output_quota_preserves_first_signature_and_stops_third_private_use() {
    use oncl_core::{
        SignRequest,
        batch::BatchOutcome,
        keys::{AppliedState, KeyRequest},
    };
    use std::sync::atomic::Ordering;
    let scratch = tempfile::tempdir().unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
        guard.clone(),
        provider,
        ResourceLimits {
            output_bytes: 300,
            ..ResourceLimits::default()
        },
    );
    let key = fixture::selector("user-rsa-sign");
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut one = &b"abc"[..];
    let mut two = &b"def"[..];
    let mut three = &b"ghi"[..];
    let mut out1 = vec![];
    let mut out2 = vec![];
    let mut out3 = vec![];
    let plan = engine
        .capture_batch(
            [
                BatchItem::new(
                    "one",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut one, None),
                        output: &mut out1,
                    },
                ),
                BatchItem::new(
                    "two",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut two, None),
                        output: &mut out2,
                    },
                ),
                BatchItem::new(
                    "three",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut three, None),
                        output: &mut out3,
                    },
                ),
            ],
            &mut ctx,
        )
        .unwrap();
    let approval = plan.authorize(&ctx).unwrap();
    let summary = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert_eq!((summary.completed, summary.attempted), (1, 2));
    assert!(matches!(
        summary.results()[0].outcome(),
        BatchOutcome::Completed(_)
    ));
    assert!(
        matches!(summary.results()[1].outcome(), BatchOutcome::Failed(e) if e.code() == oncl_core::ErrorCode::OutputLimit && e.applied_state() == AppliedState::Applied)
    );
    assert!(matches!(
        summary.results()[2].outcome(),
        BatchOutcome::NotRun
    ));
    assert_eq!(guard.applied.load(Ordering::SeqCst), 2);
    assert_eq!(
        summary.stop.as_ref().unwrap().code(),
        oncl_core::ErrorCode::OutputLimit
    );
    fixture::raw("user-rsa-sign")
        .key
        .public_key()
        .verify(oncl_pki::key::SigAlg::RsaSha256, b"abc", &out1)
        .unwrap();
    assert!(out3.is_empty());
    let mut more = &b"later"[..];
    let mut more_out = vec![];
    assert!(
        matches!(engine.sign(SignRequest::raw_message(KeyRequest::new(&key, Some(fixture::PASSWORD))), Source::sequential(&mut more, None), &mut more_out, &mut ctx), Err(e) if e.code() == oncl_core::ErrorCode::PermissionDenied)
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 2);
}

#[test]
fn secret_container_inspection_never_spools_or_requires_document_store() {
    use oncl_core::{
        InspectRequest,
        batch::{BatchOutcome, BatchReport},
    };
    let fixture = oncl_testkit::synthetic("multi-gost2015");
    let bytes = oncl_testkit::read(fixture.path);
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits {
        temp_bytes: 0,
        ..ResourceLimits::default()
    }))
    .unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Inspect]).with_metadata_aliases([
                "2174a152307df0e311ee3c01e07f7ecad448780c",
                "b8a0dd2f7728b2381484dd51a0ee85785b1f5343",
            ]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut input = bytes.as_slice();
    let plan = engine
        .capture_batch(
            [BatchItem::new(
                "secret-container",
                BatchOperation::Inspect {
                    request: InspectRequest::container(Some(&fixture.password)),
                    input: Some(Source::sequential(&mut input, None)),
                },
            )],
            &mut ctx,
        )
        .unwrap();
    assert!(plan.items().next().unwrap().sources.is_empty());
    let approval = plan.authorize(&ctx).unwrap();
    let summary = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert!(
        matches!(summary.results()[0].outcome(), BatchOutcome::Completed(BatchReport::Inspect(r)) if !r.entries().is_empty())
    );
}

#[test]
fn audit_ordinals_cover_multi_key_items_gaps_and_reset_for_nonbatch_calls() {
    use oncl_core::{SignRequest, keys::KeyRequest};
    let scratch = tempfile::tempdir().unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
        guard.clone(),
        provider,
        ResourceLimits::default(),
    );
    let key = fixture::selector("user-rsa-sign");
    let other = fixture::selector("user-gost2015-sign");
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Hash, Action::Sign])
                .with_keys([key.key_id(), other.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut hash1 = &b"hash gap 0"[..];
    let mut sign1 = &b"two keys"[..];
    let mut hash2 = &b"hash gap 2"[..];
    let mut sign2 = &b"one key"[..];
    let mut cms = vec![];
    let mut raw = vec![];
    let plan = engine
        .capture_batch(
            [
                BatchItem::new(
                    "gap-zero",
                    BatchOperation::Hash {
                        algorithm: HashAlg::Sha256,
                        input: Source::sequential(&mut hash1, None),
                    },
                ),
                BatchItem::new(
                    "multi",
                    BatchOperation::Sign {
                        request: SignRequest::cms_create(
                            vec![
                                KeyRequest::new(&key, Some(fixture::PASSWORD)),
                                KeyRequest::new(&other, Some(fixture::PASSWORD)),
                            ],
                            true,
                        ),
                        input: Source::sequential(&mut sign1, None),
                        output: &mut cms,
                    },
                ),
                BatchItem::new(
                    "gap-two",
                    BatchOperation::Hash {
                        algorithm: HashAlg::Sha256,
                        input: Source::sequential(&mut hash2, None),
                    },
                ),
                BatchItem::new(
                    "single",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut sign2, None),
                        output: &mut raw,
                    },
                ),
            ],
            &mut ctx,
        )
        .unwrap();
    let approval = plan.authorize(&ctx).unwrap();
    let summary = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert_eq!(summary.completed, 4);
    let ordinals = |events: &[oncl_core::keys::KeyUseEvent]| {
        events
            .iter()
            .map(|e| e.batch_item().map(|n| n.get()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        ordinals(&guard.events.lock().unwrap()),
        [Some(1), Some(1), Some(3)]
    );
    assert_eq!(
        ordinals(&guard.finished.lock().unwrap()),
        [Some(1), Some(1), Some(3)]
    );
    let mut outside = &b"outside batch"[..];
    let mut output = vec![];
    engine
        .sign(
            SignRequest::raw_message(KeyRequest::new(&key, Some(fixture::PASSWORD))),
            Source::sequential(&mut outside, None),
            &mut output,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(
        ordinals(&guard.events.lock().unwrap()),
        [Some(1), Some(1), Some(3), None]
    );
    assert_eq!(
        ordinals(&guard.finished.lock().unwrap()),
        [Some(1), Some(1), Some(3), None]
    );
    fixture::raw("user-rsa-sign")
        .key
        .public_key()
        .verify(oncl_pki::key::SigAlg::RsaSha256, b"outside batch", &output)
        .unwrap();
}

#[test]
fn audit_ordinal_is_restored_when_guard_panics_and_host_reuses_context() {
    use oncl_core::{OperationError, SignRequest, keys::*};
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };
    struct PanicOnce {
        first: AtomicBool,
        events: Mutex<Vec<Option<u16>>>,
    }
    impl KeyUseGuard for PanicOnce {
        fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
            self.events
                .lock()
                .unwrap()
                .push(event.batch_item().map(|i| i.get()));
            if self.first.swap(false, Ordering::SeqCst) {
                panic!("synthetic host guard panic");
            }
            Ok(KeyUseReceipt::new(event.clone()))
        }
        fn finish(&self, _: KeyUseReceipt, _: KeyUseOutcome) -> Result<(), OperationError> {
            Ok(())
        }
    }
    let guard = Arc::new(PanicOnce {
        first: AtomicBool::new(true),
        events: Mutex::new(vec![]),
    });
    let scratch = tempfile::tempdir().unwrap();
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_keys(Arc::new(fixture::Provider::default()), guard.clone())
            .with_temporary_store(oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap())
            .with_validation(fixture::validation()),
    )
    .unwrap();
    let key = fixture::selector("user-rsa-sign");
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut input = &b"approved"[..];
    let mut output = vec![];
    let plan = engine
        .capture_batch(
            [BatchItem::new(
                "one",
                BatchOperation::Sign {
                    request: SignRequest::raw_message(KeyRequest::new(
                        &key,
                        Some(fixture::PASSWORD),
                    )),
                    input: Source::sequential(&mut input, None),
                    output: &mut output,
                },
            )],
            &mut ctx,
        )
        .unwrap();
    let approval = plan.authorize(&ctx).unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| engine.run_batch(
            plan,
            approval,
            &mut ctx,
            |_| {}
        )))
        .is_err()
    );
    assert!(output.is_empty());
    let mut outside = &b"outside"[..];
    let mut outside_output = vec![];
    engine
        .sign(
            SignRequest::raw_message(KeyRequest::new(&key, Some(fixture::PASSWORD))),
            Source::sequential(&mut outside, None),
            &mut outside_output,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(*guard.events.lock().unwrap(), [Some(0), None]);
    fixture::raw("user-rsa-sign")
        .key
        .public_key()
        .verify(
            oncl_pki::key::SigAlg::RsaSha256,
            b"outside",
            &outside_output,
        )
        .unwrap();
}

#[test]
fn nested_detached_add_source_is_frozen_through_approval_and_guard() {
    use oncl_core::{SignRequest, VerifyRequest, keys::KeyRequest};
    use std::{io::Read, sync::Mutex};
    struct Mutable {
        data: Arc<Mutex<Vec<u8>>>,
        at: usize,
    }
    impl Read for Mutable {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let data = self.data.lock().unwrap();
            let n = out.len().min(data.len().saturating_sub(self.at));
            out[..n].copy_from_slice(&data[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }
    let scratch = tempfile::tempdir().unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
        guard.clone(),
        provider,
        ResourceLimits::default(),
    );
    let key = fixture::selector("user-rsa-sign");
    let first = fixture::selector("user-gost2015-sign");
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign, Action::Verify])
                .with_keys([key.key_id(), first.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut original = &b"confirmed detached"[..];
    let mut cms = vec![];
    engine
        .sign(
            SignRequest::cms_create(
                vec![KeyRequest::new(&first, Some(fixture::PASSWORD))],
                false,
            ),
            Source::sequential(&mut original, None),
            &mut cms,
            &mut ctx,
        )
        .unwrap();
    let data = Arc::new(Mutex::new(b"confirmed detached".to_vec()));
    let mut detached = Mutable {
        data: data.clone(),
        at: 0,
    };
    let changed = data.clone();
    *guard.hook.lock().unwrap() = Some(Box::new(move || {
        *changed.lock().unwrap() = b"guard replacement".to_vec()
    }));
    let mut container = cms.as_slice();
    let mut output = vec![];
    let plan = engine
        .capture_batch(
            [BatchItem::new(
                "detached-add",
                BatchOperation::Sign {
                    request: SignRequest::cms_add(
                        vec![KeyRequest::new(&key, Some(fixture::PASSWORD))],
                        Some(Source::sequential(&mut detached, None)),
                    ),
                    input: Source::sequential(&mut container, None),
                    output: &mut output,
                },
            )],
            &mut ctx,
        )
        .unwrap();
    assert_eq!(plan.items().next().unwrap().sources.len(), 2);
    let approval = plan.authorize(&ctx).unwrap();
    *data.lock().unwrap() = b"after approval replacement".to_vec();
    let summary = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert_eq!(summary.completed, 1);
    let mut signed = output.as_slice();
    let mut confirmed = &b"confirmed detached"[..];
    let report = engine
        .verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut signed, None),
            Some(Source::sequential(&mut confirmed, None)),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.verdict, oncl_pki::validation::Verdict::Valid);
    assert_eq!(report.signers.len(), 2);
    let mut signed = output.as_slice();
    let mut changed = &b"after approval replacement"[..];
    let report = engine
        .verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut signed, None),
            Some(Source::sequential(&mut changed, None)),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.verdict, oncl_pki::validation::Verdict::Invalid);
}

#[cfg(feature = "jose")]
#[test]
fn feature_gated_jose_batch_uses_real_operations_and_original_input_quota() {
    use oncl_core::{
        batch::{BatchJoseOperation, BatchOutcome, BatchReport},
        jose::{JoseProfile, JwsSerialization, JwsVerifyRequest},
        keys::KeyRequest,
    };
    let scratch = tempfile::tempdir().unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
        guard.clone(),
        provider,
        ResourceLimits {
            temp_bytes: 0,
            ..ResourceLimits::default()
        },
    );
    let (key, cert) = fixture::selector_with_certificate("user-rsa-sign");
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign, Action::Verify]).with_keys([key.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let profile = JoseProfile::new(JwsSerialization::Compact, false);
    let mut reference = vec![];
    engine
        .jws_create(
            profile,
            vec![KeyRequest::new(&key, Some(fixture::PASSWORD))],
            b"reference",
            &mut reference,
            &mut ctx,
        )
        .unwrap();
    let mut output = vec![];
    let plan = engine
        .capture_batch(
            [
                BatchItem::new(
                    "jws-sign",
                    BatchOperation::Jose(BatchJoseOperation::Create {
                        profile,
                        keys: vec![KeyRequest::new(&key, Some(fixture::PASSWORD))],
                        payload: b"confirmed jose",
                        output: &mut output,
                    }),
                ),
                BatchItem::new(
                    "jws-verify",
                    BatchOperation::Jose(BatchJoseOperation::Verify {
                        request: JwsVerifyRequest {
                            profile,
                            certificate: Some(&cert),
                        },
                        input: &reference,
                        detached: None,
                    }),
                ),
            ],
            &mut ctx,
        )
        .unwrap();
    assert_eq!(plan.items().next().unwrap().sources.len(), 1);
    let approval = plan.authorize(&ctx).unwrap();
    let summary = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert_eq!(summary.completed, 2);
    assert_eq!(
        summary.results()[0].applied_state(),
        oncl_core::keys::AppliedState::Applied
    );
    assert!(
        matches!(summary.results()[1].outcome(), BatchOutcome::Completed(BatchReport::JwsVerify(r)) if r.verdict() == oncl_pki::validation::Verdict::Valid)
    );
    assert_eq!(summary.progress.bytes_in, 23 + reference.len() as u64);
    assert!(
        !format!("{:?}", summary.results()[1].outcome()).contains("cmVmZXJlbmNl"),
        "batch Debug must not expose the source's encoded payload"
    );
    let verified = engine
        .jws_verify(
            JwsVerifyRequest {
                profile,
                certificate: Some(&cert),
            },
            &output,
            None,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(verified.verdict(), oncl_pki::validation::Verdict::Valid);
}

#[test]
fn existing_bounded_validation_is_dispatched_without_hiding_local_bad_cms() {
    use oncl_core::batch::BatchOutcome;
    let scratch = tempfile::tempdir().unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
        guard,
        provider,
        ResourceLimits::default(),
    );
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Validate, Action::Hash]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    let mut input = &b"abc"[..];
    let plan = engine
        .capture_batch(
            [
                BatchItem::new(
                    "bad-cms",
                    BatchOperation::ValidateCms {
                        input: b"not CMS",
                        detached: None,
                    },
                ),
                BatchItem::new(
                    "hash",
                    BatchOperation::Hash {
                        algorithm: HashAlg::Sha256,
                        input: Source::sequential(&mut input, None),
                    },
                ),
            ],
            &mut ctx,
        )
        .unwrap();
    let approval = plan.authorize(&ctx).unwrap();
    let report = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert!(
        matches!(report.results()[0].outcome(), BatchOutcome::Failed(error) if error.code() == oncl_core::ErrorCode::InvalidInput)
    );
    assert!(matches!(
        report.results()[1].outcome(),
        BatchOutcome::Completed(_)
    ));
    assert_eq!((report.attempted, report.completed), (2, 1));
    assert_eq!(report.progress.bytes_in, 10);
}

#[test]
fn foreign_already_counted_source_is_rejected_before_key_provider() {
    use oncl_core::{SignRequest, keys::KeyRequest};
    use oncl_pki::io::{FrozenInput, Region, TemporaryStore};
    use std::sync::atomic::Ordering;
    let scratch = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(scratch.path()).unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        store.clone(),
        guard.clone(),
        provider.clone(),
        ResourceLimits {
            max_in_flight: 2,
            ..ResourceLimits::default()
        },
    );
    let key = fixture::selector("user-rsa-sign");
    let mut legitimate = engine
        .begin(
            ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut foreign = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut bytes = &b"foreign original root"[..];
    let mut frozen = FrozenInput::capture(
        Source::sequential(&mut bytes, None),
        &store,
        foreign.resources(),
    )
    .unwrap();
    let region = Region {
        offset: 0,
        len: frozen.len(),
    };
    let mut reader = frozen.reader(&[region], foreign.resources()).unwrap();
    let mut output = vec![];
    let result = engine.capture_batch(
        [BatchItem::new(
            "foreign",
            BatchOperation::Sign {
                request: SignRequest::raw_message(KeyRequest::new(&key, Some(fixture::PASSWORD))),
                input: reader.source(),
                output: &mut output,
            },
        )],
        &mut legitimate,
    );
    assert!(matches!(result, Err(BatchError::ConsentMismatch)));
    assert_eq!(
        (
            provider.opens.load(Ordering::SeqCst),
            guard.before.load(Ordering::SeqCst)
        ),
        (0, 0)
    );
    let mut actual = &b"legitimate"[..];
    let mut actual_output = vec![];
    engine
        .sign(
            SignRequest::raw_message(KeyRequest::new(&key, Some(fixture::PASSWORD))),
            Source::sequential(&mut actual, None),
            &mut actual_output,
            &mut legitimate,
        )
        .unwrap();
    fixture::raw("user-rsa-sign")
        .key
        .public_key()
        .verify(
            oncl_pki::key::SigAlg::RsaSha256,
            b"legitimate",
            &actual_output,
        )
        .unwrap();
}

#[test]
fn confirmed_key_file_replacement_does_not_replace_pinned_certificate_or_key() {
    use der::Encode;
    use oncl_core::{
        SignRequest,
        keys::{KeyRequest, KeySelector},
    };
    use std::sync::atomic::Ordering;
    let scratch = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let path = keys.path().join("selected.p12");
    let (selected_container, selected_certificate) =
        fixture::container_with_certificate("user-rsa-sign");
    std::fs::write(&path, selected_container).unwrap();
    let selector = KeySelector::file(&path, None).unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
        guard.clone(),
        provider.clone(),
        ResourceLimits::default(),
    );
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign]).with_keys([selector.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut input = &b"selected certificate source"[..];
    let mut output = vec![];
    let plan = engine
        .capture_batch(
            [BatchItem::new(
                "selected",
                BatchOperation::Sign {
                    request: SignRequest::raw_message(KeyRequest::new(
                        &selector,
                        Some(fixture::PASSWORD),
                    )),
                    input: Source::sequential(&mut input, None),
                    output: &mut output,
                },
            )],
            &mut ctx,
        )
        .unwrap();
    let mut hash = oncl_pki::digest::HashState::new(HashAlg::Sha256);
    hash.update(&selected_certificate.to_der().unwrap());
    assert_eq!(
        plan.items().next().unwrap().keys[0].certificate_sha256(),
        &hash.finish()
    );
    let approval = plan.authorize(&ctx).unwrap();
    let (replacement, _) = fixture::container_with_certificate("user-gost2015-sign");
    std::fs::write(&path, replacement).unwrap();
    let summary = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert_eq!(summary.completed, 1);
    assert_eq!(
        (
            provider.opens.load(Ordering::SeqCst),
            guard.applied.load(Ordering::SeqCst)
        ),
        (1, 1)
    );
    fixture::raw("user-rsa-sign")
        .key
        .public_key()
        .verify(
            oncl_pki::key::SigAlg::RsaSha256,
            b"selected certificate source",
            &output,
        )
        .unwrap();
    assert!(
        fixture::raw("user-gost2015-sign")
            .key
            .public_key()
            .verify(
                oncl_pki::key::SigAlg::Gost2015_512,
                b"selected certificate source",
                &output
            )
            .is_err()
    );
}

#[test]
fn cancel_after_first_item() {
    use oncl_core::{
        SignRequest,
        batch::{BatchEvent, BatchOutcome},
        keys::KeyRequest,
    };
    use std::sync::atomic::Ordering;
    let scratch = tempfile::tempdir().unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
        guard.clone(),
        provider,
        ResourceLimits::default(),
    );
    let key = fixture::selector("user-rsa-sign");
    let control = Arc::new(Cancel::default());
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
            OperationPolicy::strict_online(),
            control.clone(),
        )
        .unwrap();
    let mut first = &b"first actual signature"[..];
    let mut second = &b"not signed"[..];
    let mut out1 = vec![];
    let mut out2 = vec![];
    let plan = engine
        .capture_batch(
            [
                BatchItem::new(
                    "first",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut first, None),
                        output: &mut out1,
                    },
                ),
                BatchItem::new(
                    "second",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut second, None),
                        output: &mut out2,
                    },
                ),
            ],
            &mut ctx,
        )
        .unwrap();
    let approval = plan.authorize(&ctx).unwrap();
    let mut finished = 0;
    let report = engine
        .run_batch(plan, approval, &mut ctx, |event| {
            if let BatchEvent::ItemFinished { completed, .. } = event {
                finished += 1;
                if completed == 1 {
                    control.0.store(true, Ordering::SeqCst);
                }
            }
        })
        .unwrap();
    assert_eq!(
        (report.attempted, report.completed, report.total, finished),
        (1, 1, 2, 2)
    );
    assert!(matches!(
        report.results()[0].outcome(),
        BatchOutcome::Completed(_)
    ));
    assert_eq!(
        report.results()[0].applied_state(),
        oncl_core::keys::AppliedState::Applied
    );
    assert!(matches!(
        report.results()[1].outcome(),
        BatchOutcome::NotRun
    ));
    assert_eq!(
        report.results()[1].applied_state(),
        oncl_core::keys::AppliedState::NotApplied
    );
    assert_eq!(
        report.stop.as_ref().unwrap().code(),
        oncl_core::ErrorCode::Cancelled
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    fixture::raw("user-rsa-sign")
        .key
        .public_key()
        .verify(
            oncl_pki::key::SigAlg::RsaSha256,
            b"first actual signature",
            &out1,
        )
        .unwrap();
    assert!(out2.is_empty());
}

#[test]
fn one_failure_keeps_known_results() {
    use oncl_core::{
        SignRequest, VerifyRequest,
        batch::{BatchOutcome, BatchReport},
        keys::KeyRequest,
    };
    use std::sync::atomic::Ordering;
    struct Bad;
    impl std::io::Read for Bad {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("unavailable public source"))
        }
    }
    let scratch = tempfile::tempdir().unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
        guard.clone(),
        provider.clone(),
        ResourceLimits::default(),
    );
    let key = fixture::selector("user-rsa-sign");
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign, Action::Verify]).with_keys([key.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut reference_data = &b"reference"[..];
    let mut reference = vec![];
    engine
        .sign(
            SignRequest::cms_create(vec![KeyRequest::new(&key, Some(fixture::PASSWORD))], true),
            Source::sequential(&mut reference_data, None),
            &mut reference,
            &mut ctx,
        )
        .unwrap();
    let mut first = &b"abc"[..];
    let mut verify = reference.as_slice();
    let mut bad = Bad;
    let mut last = &b"def"[..];
    let mut out1 = vec![];
    let mut bad_out = vec![];
    let mut out2 = vec![];
    let plan = engine
        .capture_batch(
            [
                BatchItem::new(
                    "first-sign",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut first, None),
                        output: &mut out1,
                    },
                ),
                BatchItem::new(
                    "verify",
                    BatchOperation::Verify {
                        request: VerifyRequest::cms(),
                        input: Source::sequential(&mut verify, None),
                        detached: None,
                    },
                ),
                BatchItem::new(
                    "bad",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut bad, None),
                        output: &mut bad_out,
                    },
                ),
                BatchItem::new(
                    "last-sign",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut last, None),
                        output: &mut out2,
                    },
                ),
            ],
            &mut ctx,
        )
        .unwrap();
    let approval = plan.authorize(&ctx).unwrap();
    let report = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert_eq!(
        (report.attempted, report.completed, report.total),
        (4, 3, 4)
    );
    assert!(report.stop.is_none());
    assert!(matches!(
        report.results()[0].outcome(),
        BatchOutcome::Completed(_)
    ));
    assert!(
        matches!(report.results()[1].outcome(), BatchOutcome::Completed(BatchReport::Verify(r)) if r.verdict == oncl_pki::validation::Verdict::Valid)
    );
    assert!(
        matches!(report.results()[2].outcome(), BatchOutcome::Failed(e) if e.code() == oncl_core::ErrorCode::Io)
    );
    assert!(matches!(
        report.results()[3].outcome(),
        BatchOutcome::Completed(_)
    ));
    assert_eq!(
        (
            provider.opens.load(Ordering::SeqCst),
            guard.applied.load(Ordering::SeqCst)
        ),
        (1, 3)
    );
    let public = fixture::raw("user-rsa-sign").key.public_key();
    public
        .verify(oncl_pki::key::SigAlg::RsaSha256, b"abc", &out1)
        .unwrap();
    public
        .verify(oncl_pki::key::SigAlg::RsaSha256, b"def", &out2)
        .unwrap();
    assert!(bad_out.is_empty());
}

#[test]
fn unavailable_authorized_key_is_a_known_local_item_failure() {
    use oncl_core::{
        SignRequest,
        batch::BatchOutcome,
        keys::{KeyId, KeyRequest, KeySelector},
    };
    use std::sync::atomic::Ordering;
    struct Untouched;
    impl std::io::Read for Untouched {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("source of unavailable key must not be consumed")
        }
    }
    let scratch = tempfile::tempdir().unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
        guard.clone(),
        provider,
        ResourceLimits::default(),
    );
    let key = fixture::selector("user-rsa-sign");
    let missing = KeySelector::named(KeyId::new("authorized-but-unavailable").unwrap());
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign]).with_keys([key.key_id(), missing.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut first = &b"first"[..];
    let mut unavailable = Untouched;
    let mut last = &b"last"[..];
    let mut first_out = vec![];
    let mut missing_out = vec![];
    let mut last_out = vec![];
    let plan = engine
        .capture_batch(
            [
                BatchItem::new(
                    "first",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut first, None),
                        output: &mut first_out,
                    },
                ),
                BatchItem::new(
                    "missing",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(&missing, None)),
                        input: Source::sequential(&mut unavailable, None),
                        output: &mut missing_out,
                    },
                ),
                BatchItem::new(
                    "last",
                    BatchOperation::Sign {
                        request: SignRequest::raw_message(KeyRequest::new(
                            &key,
                            Some(fixture::PASSWORD),
                        )),
                        input: Source::sequential(&mut last, None),
                        output: &mut last_out,
                    },
                ),
            ],
            &mut ctx,
        )
        .unwrap();
    let approval = plan.authorize(&ctx).unwrap();
    let summary = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert_eq!((summary.attempted, summary.completed), (3, 2));
    assert!(
        matches!(summary.results()[1].outcome(), BatchOutcome::Failed(error) if error.code() == oncl_core::ErrorCode::KeyNotFound)
    );
    assert!(summary.stop.is_none());
    assert_eq!(guard.applied.load(Ordering::SeqCst), 2);
    assert!(missing_out.is_empty());
    let public = fixture::raw("user-rsa-sign").key.public_key();
    public
        .verify(oncl_pki::key::SigAlg::RsaSha256, b"first", &first_out)
        .unwrap();
    public
        .verify(oncl_pki::key::SigAlg::RsaSha256, b"last", &last_out)
        .unwrap();
}

#[test]
fn replacing_full_scope_before_confirmation_or_execution_requires_new_consent() {
    for before_approval in [true, false] {
        let scratch = tempfile::tempdir().unwrap();
        let engine = Engine::new(
            EngineServices::hash_only(ResourceLimits {
                max_in_flight: 2,
                ..ResourceLimits::default()
            })
            .with_temporary_store(oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap()),
        )
        .unwrap();
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                Arc::new(Control),
            )
            .unwrap();
        let mut other = engine
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                Arc::new(Control),
            )
            .unwrap();
        let mut input = &b"original scope"[..];
        let plan = engine
            .capture_batch(
                [BatchItem::new(
                    "one",
                    BatchOperation::Hash {
                        algorithm: HashAlg::Sha256,
                        input: Source::sequential(&mut input, None),
                    },
                )],
                &mut ctx,
            )
            .unwrap();
        let genuine = ctx.resources().shared_view();
        *ctx.resources() = genuine;
        let authority = plan.authorize(&ctx).unwrap();
        *ctx.resources() = other.resources().shared_view();
        if before_approval {
            assert!(matches!(
                plan.authorize(&ctx),
                Err(BatchError::ConsentMismatch)
            ));
        }
        let mut callbacks = 0;
        assert!(matches!(
            engine.run_batch(plan, authority, &mut ctx, |_| callbacks += 1),
            Err(BatchError::ConsentMismatch)
        ));
        assert_eq!(callbacks, 0);
    }
}

#[test]
fn successful_private_output_followed_by_batch_finalization_cancel_remains_applied() {
    use oncl_core::{
        SignRequest,
        batch::{BatchOutcome, BatchReport},
        keys::{AppliedState, KeyRequest},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct SweepControl {
        count: AtomicUsize,
        fail_at: AtomicUsize,
    }
    impl OperationControl for SweepControl {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            let index = self.count.fetch_add(1, Ordering::SeqCst);
            if index >= self.fail_at.load(Ordering::SeqCst) {
                Err(ProcessingError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    let key = fixture::selector("user-rsa-sign");
    let public = fixture::raw("user-rsa-sign").key.public_key();
    let mut observed_checkpoints = None;
    let mut complete_failed_signature_cases = 0;
    let mut fault_cases = 0;
    // First measure a genuine no-fault run; sweep every observed checkpoint,
    // rather than pinning an incidental call count or stack/symbol spelling.
    let mut target = None;
    loop {
        let scratch = tempfile::tempdir().unwrap();
        let guard = Arc::new(fixture::Guard::default());
        let engine = fixture::engine(
            oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
            guard.clone(),
            Arc::new(fixture::Provider::default()),
            ResourceLimits::default(),
        );
        let control = Arc::new(SweepControl {
            count: AtomicUsize::new(0),
            fail_at: AtomicUsize::new(usize::MAX),
        });
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([Action::Hash, Action::Sign]).with_keys([key.key_id()]),
                OperationPolicy::strict_online(),
                control.clone(),
            )
            .unwrap();
        let mut prior = &b"prior"[..];
        let mut actual = &b"actually signed"[..];
        let mut later = &b"later signed"[..];
        let mut output = vec![];
        let mut later_output = vec![];
        let plan = engine
            .capture_batch(
                [
                    BatchItem::new(
                        "prior",
                        BatchOperation::Hash {
                            algorithm: HashAlg::Sha256,
                            input: Source::sequential(&mut prior, None),
                        },
                    ),
                    BatchItem::new(
                        "actual",
                        BatchOperation::Sign {
                            request: SignRequest::raw_message(KeyRequest::new(
                                &key,
                                Some(fixture::PASSWORD),
                            )),
                            input: Source::sequential(&mut actual, None),
                            output: &mut output,
                        },
                    ),
                    BatchItem::new(
                        "later",
                        BatchOperation::Sign {
                            request: SignRequest::raw_message(KeyRequest::new(
                                &key,
                                Some(fixture::PASSWORD),
                            )),
                            input: Source::sequential(&mut later, None),
                            output: &mut later_output,
                        },
                    ),
                ],
                &mut ctx,
            )
            .unwrap();
        let authority = plan.authorize(&ctx).unwrap();
        control.count.store(0, Ordering::SeqCst);
        control
            .fail_at
            .store(target.unwrap_or(usize::MAX), Ordering::SeqCst);
        let report = engine.run_batch(plan, authority, &mut ctx, |_| {}).unwrap();
        let used = guard.applied.load(Ordering::SeqCst);
        if target.is_none() {
            assert_eq!(report.completed, 3);
            assert!(report.stop.is_none());
            assert_eq!(used, 2);
            public
                .verify(
                    oncl_pki::key::SigAlg::RsaSha256,
                    b"actually signed",
                    &output,
                )
                .unwrap();
            public
                .verify(
                    oncl_pki::key::SigAlg::RsaSha256,
                    b"later signed",
                    &later_output,
                )
                .unwrap();
            observed_checkpoints = Some(control.count.load(Ordering::SeqCst));
            assert!(observed_checkpoints.unwrap() > 0);
            target = Some(0);
            continue;
        }
        fault_cases += 1;
        assert_eq!(
            report.stop.as_ref().unwrap().code(),
            oncl_core::ErrorCode::Cancelled
        );
        let mut reported_applications = 0;
        let mut saw_failure_or_notrun = false;
        for (index, result) in report.results().iter().enumerate() {
            if result.applied_state() == AppliedState::Applied {
                reported_applications += 1;
            }
            match result.outcome() {
                BatchOutcome::Failed(error) => {
                    assert_eq!(error.code(), oncl_core::ErrorCode::Cancelled);
                    assert!(!saw_failure_or_notrun);
                    saw_failure_or_notrun = true;
                    if index == 1
                        && result.applied_state() == AppliedState::Applied
                        && public
                            .verify(
                                oncl_pki::key::SigAlg::RsaSha256,
                                b"actually signed",
                                &output,
                            )
                            .is_ok()
                    {
                        complete_failed_signature_cases += 1;
                        assert!(matches!(
                            report.results()[0].outcome(),
                            BatchOutcome::Completed(BatchReport::Hash(_))
                        ));
                        assert!(matches!(
                            report.results()[2].outcome(),
                            BatchOutcome::NotRun
                        ));
                        assert!(later_output.is_empty());
                        assert_eq!(used, 1);
                    }
                }
                BatchOutcome::NotRun => {
                    saw_failure_or_notrun = true;
                    assert_eq!(result.applied_state(), AppliedState::NotApplied);
                }
                BatchOutcome::Completed(_) => assert!(!saw_failure_or_notrun),
            }
        }
        assert_eq!(
            reported_applications, used,
            "every actual key use must retain Applied"
        );
        if used > 0 {
            assert!(matches!(
                report.results()[0].outcome(),
                BatchOutcome::Completed(BatchReport::Hash(_))
            ));
        }
        let next = target.unwrap() + 1;
        if next == observed_checkpoints.unwrap() {
            break;
        }
        target = Some(next);
    }
    assert_eq!(fault_cases, observed_checkpoints.unwrap());
    println!("checkpoint_sweep observed={} faults={} complete_verified_failed_signature_cases={}", observed_checkpoints.unwrap(), fault_cases, complete_failed_signature_cases);
    assert!(
        complete_failed_signature_cases > 0,
        "sweep must cover a failed item with a complete independently valid actual signature"
    );
}

#[test]
fn borrowed_capture_charges_mixed_aggregate_before_dispatch_and_cancel() {
    use oncl_core::batch::BatchOutcome;
    let scratch = tempfile::tempdir().unwrap();
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits {
            input_bytes: 6,
            ..ResourceLimits::default()
        })
        .with_temporary_store(oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap()),
    )
    .unwrap();
    let control = Arc::new(Cancel::default());
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Hash, Action::Validate]),
            OperationPolicy::offline_report(),
            control.clone(),
        )
        .unwrap();
    let mut source = &b"abc"[..];
    let plan = engine
        .capture_batch(
            [
                BatchItem::new(
                    "source",
                    BatchOperation::Hash {
                        algorithm: HashAlg::Sha256,
                        input: Source::sequential(&mut source, None),
                    },
                ),
                BatchItem::new(
                    "borrowed",
                    BatchOperation::ValidateCms {
                        input: b"def",
                        detached: None,
                    },
                ),
            ],
            &mut ctx,
        )
        .unwrap();
    assert_eq!(ctx.resources().progress().bytes_in, 6);
    let approval = plan.authorize(&ctx).unwrap();
    control.0.store(true, std::sync::atomic::Ordering::SeqCst);
    let result = engine.run_batch(plan, approval, &mut ctx, |_| {}).unwrap();
    assert_eq!(result.progress.bytes_in, 6);
    assert!(
        result
            .results()
            .iter()
            .all(|r| matches!(r.outcome(), BatchOutcome::NotRun))
    );
}

#[test]
fn borrowed_capture_rejects_known_aggregate_overflow_without_scanning_new_item() {
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits {
        input_bytes: 5,
        ..ResourceLimits::default()
    }))
    .unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Validate]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    let result = engine.capture_batch(
        [
            BatchItem::new(
                "first",
                BatchOperation::ValidateCms {
                    input: b"abc",
                    detached: None,
                },
            ),
            BatchItem::new(
                "second",
                BatchOperation::ValidateCms {
                    input: b"def",
                    detached: None,
                },
            ),
        ],
        &mut ctx,
    );
    assert!(
        matches!(result,Err(BatchError::Operation(e)) if e.code()==oncl_core::ErrorCode::InputLimit)
    );
    assert_eq!(ctx.resources().progress().bytes_in, 3);
}

#[cfg(feature = "jose")]
#[test]
fn jose_rebound_scope_is_rejected_before_private_dispatch() {
    use oncl_core::{
        batch::BatchJoseOperation,
        jose::{JoseProfile, JwsSerialization},
        keys::KeyRequest,
    };
    use std::sync::atomic::Ordering;
    let scratch = tempfile::tempdir().unwrap();
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        oncl_pki::io::TemporaryStore::new(scratch.path()).unwrap(),
        guard.clone(),
        provider.clone(),
        ResourceLimits {
            max_in_flight: 2,
            ..ResourceLimits::default()
        },
    );
    let key = fixture::selector("user-rsa-sign");
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut other = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut output = vec![];
    let plan = engine
        .capture_batch(
            [BatchItem::new(
                "jose",
                BatchOperation::Jose(BatchJoseOperation::Create {
                    profile: JoseProfile::new(JwsSerialization::Compact, false),
                    keys: vec![KeyRequest::new(&key, Some(fixture::PASSWORD))],
                    payload: b"bound",
                    output: &mut output,
                }),
            )],
            &mut ctx,
        )
        .unwrap();
    let approval = plan.authorize(&ctx).unwrap();
    let opens = provider.opens.load(Ordering::SeqCst);
    *ctx.resources() = other.resources().shared_view();
    assert!(matches!(
        plan.authorize(&ctx),
        Err(BatchError::ConsentMismatch)
    ));
    assert!(matches!(
        engine.run_batch(plan, approval, &mut ctx, |_| panic!("rebound callback")),
        Err(BatchError::ConsentMismatch)
    ));
    assert_eq!(provider.opens.load(Ordering::SeqCst), opens);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert!(output.is_empty());
}

#[test]
fn cancellation_during_borrowed_capture_retains_consumed_chunk_total() {
    struct AfterChunk;
    impl OperationControl for AfterChunk {
        fn checkpoint(&self, p: Progress) -> Result<(), ProcessingError> {
            if p.bytes_in > 0 {
                Err(ProcessingError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Validate]),
            OperationPolicy::offline_report(),
            Arc::new(AfterChunk),
        )
        .unwrap();
    let bytes = vec![1u8; oncl_pki::resource::IO_CHUNK_BYTES + 1];
    assert!(
        matches!(engine.capture_batch([BatchItem::new("borrowed",BatchOperation::ValidateCms{input:&bytes,detached:None})],&mut ctx),Err(BatchError::Operation(e)) if e.code()==oncl_core::ErrorCode::Cancelled)
    );
    assert_eq!(
        ctx.resources().progress().bytes_in,
        oncl_pki::resource::IO_CHUNK_BYTES as u64
    );
}

#[cfg(feature = "jose")]
#[test]
fn oversized_jose_capture_is_refused_before_any_scan_checkpoint() {
    use oncl_core::{
        batch::BatchJoseOperation,
        jose::{JoseProfile, JwsSerialization, MAX_CONTAINER_BYTES},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Count(AtomicUsize);
    impl OperationControl for Count {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let control = Arc::new(Count(AtomicUsize::new(0)));
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::offline_report(),
            control.clone(),
        )
        .unwrap();
    let bytes = vec![b'a'; MAX_CONTAINER_BYTES + 1];
    let before = control.0.load(Ordering::SeqCst);
    let result = engine.capture_batch(
        [BatchItem::new(
            "oversized",
            BatchOperation::Jose(BatchJoseOperation::Verify {
                request: oncl_core::jose::JwsVerifyRequest {
                    profile: JoseProfile::new(JwsSerialization::Compact, false),
                    certificate: None,
                },
                input: &bytes,
                detached: None,
            }),
        )],
        &mut ctx,
    );
    assert!(
        matches!(result,Err(BatchError::Operation(e)) if e.code()==oncl_core::ErrorCode::InvalidInput)
    );
    assert_eq!(ctx.resources().progress().bytes_in, 0);
    assert!(
        control.0.load(Ordering::SeqCst) - before < 5,
        "no per-chunk scan checkpoints"
    );
}
