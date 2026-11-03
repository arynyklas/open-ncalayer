use oncl_core::keys::{KeyId, KeyRequest, KeySelector, KeySources};
use oncl_core::{
    Action, Engine, EngineServices, ErrorCode, ExecutionGrant, InspectRequest, OperationPolicy,
};
use oncl_pki::{
    info::InspectionLimits,
    io::Source,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
};
use std::{
    io::{self, Read},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn engine() -> Engine {
    Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap()
}
fn begin(engine: &Engine, grant: ExecutionGrant) -> oncl_core::OperationContext {
    engine
        .begin(grant, OperationPolicy::strict_online(), Arc::new(Control))
        .unwrap()
}
fn grant() -> ExecutionGrant {
    ExecutionGrant::new([Action::Inspect]).with_metadata_aliases([
        "2174a152307df0e311ee3c01e07f7ecad448780c",
        "b8a0dd2f7728b2381484dd51a0ee85785b1f5343",
    ])
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
#[test]
fn aliases_without_private_export() {
    let fixture = oncl_testkit::synthetic("multi-gost2015");
    let bytes = oncl_testkit::read(&fixture.path);
    let engine = engine();
    let mut ctx = begin(&engine, grant());
    let mut input = bytes.as_slice();
    let report = engine
        .inspect(
            &InspectRequest::container(Some(&fixture.password)),
            Some(Source::sequential(&mut input, Some(bytes.len() as u64))),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(
        report
            .entries()
            .iter()
            .map(|entry| entry.alias())
            .collect::<Vec<_>>(),
        [
            Some("2174a152307df0e311ee3c01e07f7ecad448780c"),
            Some("b8a0dd2f7728b2381484dd51a0ee85785b1f5343")
        ]
    );
    // OpenSSL 3.5.4 pkcs12 -legacy / x509 -sha256 independently derived.
    assert_eq!(
        report
            .entries()
            .iter()
            .map(|entry| hex(entry.fingerprint().unwrap().as_bytes()))
            .collect::<Vec<_>>(),
        [
            "93f6890c86d85a58bffa1b96155ec99444576c4b06673aa7dbaeb0a6ed7e18bc",
            "3aee53d80dc45f3aff3d086a219baf3592406c4abbb3d25f2f4748103e4dd8c9"
        ]
    );
    assert_eq!(ctx.resources().progress().bytes_in, bytes.len() as u64);
    assert_eq!(ctx.resources().progress().bytes_out, 0);
}
#[test]
fn metadata_permission_is_distinct_from_private_signing() {
    let engine = engine();
    let mut ctx = begin(&engine, ExecutionGrant::new([Action::Sign]));
    assert_eq!(
        engine
            .inspect(&InspectRequest::certificate(), None, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    drop(ctx);
    let selector = KeySelector::inline(vec![], None);
    let mut ctx = begin(
        &engine,
        ExecutionGrant::new([Action::Inspect]).with_keys([selector.key_id()]),
    );
    assert_eq!(
        engine
            .signer(&KeyRequest::new(&selector, None), &mut ctx)
            .err()
            .unwrap()
            .code(),
        ErrorCode::PermissionDenied
    );
}
#[test]
fn alias_grant_and_required_secret_precede_any_container_read() {
    for (granted, password, expected) in [
        (
            ExecutionGrant::new([Action::Inspect]),
            None,
            ErrorCode::PermissionDenied,
        ),
        (grant(), None, ErrorCode::SecretRequired),
    ] {
        let engine = engine();
        let mut ctx = begin(&engine, granted);
        let mut input = &b"secret container"[..];
        let error = engine
            .inspect(
                &InspectRequest::container(password),
                Some(Source::sequential(&mut input, None)),
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(error.code(), expected);
        assert_eq!(input, b"secret container");
        assert_eq!(ctx.resources().progress().bytes_in, 0);
    }
}
#[test]
fn filtered_pkcs12_catalog_never_returns_foreign_aliases_or_certificates() {
    let fixture = oncl_testkit::synthetic("multi-gost2015");
    let bytes = oncl_testkit::read(&fixture.path);
    let engine = engine();
    let mut ctx = begin(
        &engine,
        ExecutionGrant::new([Action::Inspect])
            .with_metadata_aliases(["b8a0dd2f7728b2381484dd51a0ee85785b1f5343"]),
    );
    let mut input = bytes.as_slice();
    let report = engine
        .inspect(
            &InspectRequest::container(Some(&fixture.password)),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.entries().len(), 1);
    assert_eq!(
        report.entries()[0].alias(),
        Some("b8a0dd2f7728b2381484dd51a0ee85785b1f5343")
    );
    assert_eq!(
        hex(report.entries()[0].fingerprint().unwrap().as_bytes()),
        "3aee53d80dc45f3aff3d086a219baf3592406c4abbb3d25f2f4748103e4dd8c9"
    );
}
#[test]
fn jks_private_and_certificate_only_entries_are_public_and_authenticated() {
    let bytes = oncl_testkit::read(oncl_testkit::fixture("jks/rsa.jks"));
    let engine = engine();
    for (password, expected) in [("Qwerty12", true), ("wrong", false)] {
        let mut ctx = begin(
            &engine,
            ExecutionGrant::new([Action::Inspect])
                .with_metadata_aliases(["openncalayer-rsa", "synthetic-root-rsa"]),
        );
        let mut input = bytes.as_slice();
        let result = engine.inspect(
            &InspectRequest::container(Some(password)),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        );
        if expected {
            let report = result.unwrap();
            assert_eq!(
                report
                    .entries()
                    .iter()
                    .map(|entry| entry.alias())
                    .collect::<Vec<_>>(),
                [Some("openncalayer-rsa"), Some("synthetic-root-rsa")]
            );
            let originals = oncl_pki::jks::entries(&bytes).unwrap();
            use der::Encode;
            for entry in report.entries() {
                let original = originals
                    .iter()
                    .find(|item| Some(item.alias.as_str()) == entry.alias())
                    .unwrap();
                let cert = match &original.kind {
                    oncl_pki::jks::JksEntryKind::PrivateKey { chain } => &chain[0],
                    oncl_pki::jks::JksEntryKind::TrustedCert(cert) => cert.as_ref(),
                };
                assert_eq!(
                    entry.certificate_der(),
                    Some(cert.to_der().unwrap().as_slice())
                );
            }
        } else {
            assert_eq!(result.unwrap_err().code(), ErrorCode::InvalidInput);
        }
    }
}
#[test]
fn named_and_exact_source_metadata_do_not_need_a_private_provider_or_guard() {
    let fixture = oncl_testkit::synthetic("user-rsa-sign");
    let bytes = oncl_testkit::read(&fixture.path);
    let selector = KeySelector::inline(
        bytes,
        Some("460569d78dda2a142a2d8f23389bba378ccd7e53".into()),
    );
    let id = KeyId::new("I01 host slot").unwrap();
    let sources = KeySources::new()
        .with_named(id.clone(), selector.clone())
        .unwrap();
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_metadata_provider(Arc::new(sources)),
    )
    .unwrap();
    for selector in [selector, KeySelector::named(id)] {
        let mut ctx = begin(
            &engine,
            ExecutionGrant::new([Action::Inspect]).with_keys([selector.key_id()]),
        );
        let request = KeyRequest::new(&selector, Some(&fixture.password));
        let report = engine
            .inspect(&InspectRequest::named_key(&request), None, &mut ctx)
            .unwrap();
        assert_eq!(report.entries().len(), 1);
        assert_eq!(
            report.entries()[0].alias(),
            Some("460569d78dda2a142a2d8f23389bba378ccd7e53")
        );
    }
}
struct ProviderCalls(Arc<AtomicUsize>);
impl oncl_core::ReadMetadataProvider for ProviderCalls {
    fn inspect(
        &self,
        _: &KeyRequest<'_>,
        _: &InspectionLimits,
        _: &mut oncl_core::OperationContext,
    ) -> Result<oncl_pki::info::PublicMetadata, oncl_core::OperationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(oncl_core::OperationError::SecretRequired)
    }
}
#[test]
fn wrong_named_key_grant_is_rejected_before_secret_or_provider() {
    let calls = Arc::new(AtomicUsize::new(0));
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_metadata_provider(Arc::new(ProviderCalls(calls.clone()))),
    )
    .unwrap();
    let selector = KeySelector::named(KeyId::new("forbidden").unwrap());
    let request = KeyRequest::new(&selector, None);
    let mut ctx = begin(
        &engine,
        ExecutionGrant::new([Action::Inspect]).with_keys([KeyId::new("other").unwrap()]),
    );
    assert_eq!(
        engine
            .inspect(&InspectRequest::named_key(&request), None, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[test]
fn certificate_info_is_keyless_and_honest_about_unsupported_algorithm_oids() {
    let issuer = {
        let f = oncl_testkit::synthetic("root-gost2015.key");
        oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
            .unwrap()
            .remove(0)
    };
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&issuer.cert);
    spec.public_key.algorithm.oid = der::asn1::ObjectIdentifier::new_unwrap("1.2.3.19.999");
    let cert = oncl_pki::testing::issue_cert(&issuer, spec);
    use der::Encode;
    let bytes = cert.to_der().unwrap();
    let engine = engine();
    let mut ctx = begin(&engine, ExecutionGrant::new([Action::Inspect]));
    let mut input = bytes.as_slice();
    let report = engine
        .inspect(
            &InspectRequest::certificate(),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(
        report.entries()[0].public_key_algorithm_oid(),
        Some("1.2.3.19.999")
    );
    assert_eq!(
        report.entries()[0].certificate_der(),
        Some(bytes.as_slice())
    );
}
#[test]
fn secret_container_never_needs_or_debits_a_temporary_store() {
    let f = oncl_testkit::synthetic("multi-gost2015");
    let bytes = oncl_testkit::read(&f.path);
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits {
        temp_bytes: 0,
        ..ResourceLimits::default()
    }))
    .unwrap();
    let mut ctx = begin(&engine, grant());
    let mut input = bytes.as_slice();
    assert_eq!(
        engine
            .inspect(
                &InspectRequest::container(Some(&f.password)),
                Some(Source::sequential(&mut input, None)),
                &mut ctx
            )
            .unwrap()
            .entries()
            .len(),
        2
    );
}
#[test]
fn scoped_public_metadata_retains_root_after_context_and_engine_drop() {
    let bytes = oncl_testkit::read(oncl_testkit::fixture("synthetic/root-rsa.cer"));
    let engine = engine();
    let mut ctx = begin(&engine, ExecutionGrant::new([Action::Inspect]));
    let mut input = bytes.as_slice();
    let report = engine
        .inspect(
            &InspectRequest::certificate(),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        )
        .unwrap();
    drop(ctx);
    assert_eq!(
        engine
            .begin(
                ExecutionGrant::new([Action::Inspect]),
                OperationPolicy::strict_online(),
                Arc::new(Control)
            )
            .unwrap_err()
            .code(),
        ErrorCode::CapacityExceeded
    );
    assert_eq!(
        report.entries()[0].certificate_der(),
        Some(bytes.as_slice())
    );
    drop(report);
    drop(begin(&engine, ExecutionGrant::new([Action::Inspect])));
}
struct CancelRead {
    control: Arc<AtomicBool>,
    bytes: &'static [u8],
}
impl Read for CancelRead {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output.len().min(self.bytes.len());
        output[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        self.control.store(true, Ordering::SeqCst);
        Ok(count)
    }
}
struct Cancel(Arc<AtomicBool>);
impl OperationControl for Cancel {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.0.load(Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
#[test]
fn post_read_cancel_accounts_consumed_bytes_before_returning_original_cause() {
    let engine = engine();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Inspect]),
            OperationPolicy::strict_online(),
            Arc::new(Cancel(cancel.clone())),
        )
        .unwrap();
    let mut input = CancelRead {
        control: cancel,
        bytes: b"certificate consumed before cancel",
    };
    assert_eq!(
        engine
            .inspect(
                &InspectRequest::certificate(),
                Some(Source::sequential(&mut input, None)),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::Cancelled
    );
    assert_eq!(ctx.resources().progress().bytes_in, 34);
}
#[test]
fn unknown_length_input_counts_overflow_probe_once_and_remains_terminal() {
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits {
        input_bytes: 3,
        ..ResourceLimits::default()
    }))
    .unwrap();
    let mut ctx = begin(&engine, ExecutionGrant::new([Action::Inspect]));
    let mut input = &b"abcde"[..];
    assert_eq!(
        engine
            .inspect(
                &InspectRequest::certificate(),
                Some(Source::sequential(&mut input, None)),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::InputLimit
    );
    assert_eq!(ctx.resources().progress().bytes_in, 4);
    assert_eq!(input, b"e");
    let mut empty = &b""[..];
    assert_eq!(
        engine
            .inspect(
                &InspectRequest::certificate(),
                Some(Source::sequential(&mut empty, None)),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::InputLimit
    );
}
#[test]
fn high_work_small_pkcs12_is_resource_refusal_with_explicit_host_override() {
    let f = oncl_testkit::synthetic("user-rsa-sign");
    let entry = oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0);
    use der::Encode;
    let bytes = oncl_pki::pkcs12::write(
        &[oncl_pki::pkcs12::WriteEntry {
            alias: "work-bound".into(),
            pkcs8_der: entry.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(entry.cert.to_der().unwrap()),
        }],
        &[],
        "work password",
        &oncl_pki::pkcs12::WriteOptions {
            iterations: 10_001,
            ..oncl_pki::pkcs12::WriteOptions::default()
        },
        &mut |bytes| bytes.fill(0x19),
    )
    .unwrap();
    for (profile, expected) in [
        (InspectionLimits::default(), false),
        (
            InspectionLimits {
                kdf_iterations: 20_000,
                aggregate_kdf_iterations: 200_000,
                ..InspectionLimits::default()
            },
            true,
        ),
    ] {
        let engine = Engine::new(
            EngineServices::hash_only(ResourceLimits::default()).with_inspection_limits(profile),
        )
        .unwrap();
        let mut ctx = begin(
            &engine,
            ExecutionGrant::new([Action::Inspect]).with_metadata_aliases(["work-bound"]),
        );
        let mut input = bytes.as_slice();
        let result = engine.inspect(
            &InspectRequest::container(Some("work password")),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        );
        if expected {
            assert_eq!(result.unwrap().entries()[0].alias(), Some("work-bound"));
        } else {
            assert_eq!(result.unwrap_err().code(), ErrorCode::MetadataLimit);
        }
    }
}
#[test]
fn authentic_public_snapshot_inspection_counts_intake_once() {
    use oncl_pki::io::{FrozenInput, Region, TemporaryStore};
    let bytes = oncl_testkit::read(oncl_testkit::fixture("synthetic/root-rsa.cer"));
    let scratch = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(scratch.path()).unwrap();
    let engine = engine();
    let mut ctx = begin(&engine, ExecutionGrant::new([Action::Inspect]));
    let mut input = bytes.as_slice();
    let mut frozen = FrozenInput::capture(
        Source::sequential(&mut input, None),
        &store,
        ctx.resources(),
    )
    .unwrap();
    let mut reader = frozen
        .reader(
            &[Region {
                offset: 0,
                len: bytes.len() as u64,
            }],
            ctx.resources(),
        )
        .unwrap();
    let report = engine
        .inspect(
            &InspectRequest::certificate(),
            Some(reader.source()),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(ctx.resources().progress().bytes_in, bytes.len() as u64);
    assert_eq!(report.bytes_in(), 0);
}
#[cfg(feature = "tokens")]
#[test]
fn token_metadata_uses_public_driver_reads_without_private_signer_or_pin_cache() {
    use der::Encode;
    use oncl_token::{
        TokenKind, Tokens,
        emulator::{CardSpec, EmuKey, EmulatorBackend, card},
        execution::{TokenDeviceId, TokenGateRegistry},
    };
    let f = oncl_testkit::synthetic("user-rsa-sign");
    let entry = oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0);
    let expected = entry.cert.to_der().unwrap();
    let other_fixture = oncl_testkit::synthetic("user-gost2004-sign");
    let other_entry = oncl_pki::pkcs12::load(
        &oncl_testkit::read(other_fixture.path),
        &other_fixture.password,
    )
    .unwrap()
    .remove(0);
    let other_expected = other_entry.cert.to_der().unwrap();
    assert_ne!(expected, other_expected);
    let backend = Arc::new(EmulatorBackend::new());
    backend.add_reader("I01 reader");
    backend.insert(
        "I01 reader",
        card(CardSpec::new(
            TokenKind::Kaztoken,
            "123456",
            vec![EmuKey { entry: other_entry }, EmuKey { entry }],
        )),
    );
    let sources = KeySources::new().with_tokens(
        Tokens::new(backend.clone(), true),
        Arc::new(TokenGateRegistry::new(1, 0).unwrap()),
    );
    let selector = KeySelector::token(
        TokenDeviceId::new("I01 reader").unwrap(),
        TokenKind::Kaztoken,
        f.aliases[0].clone(),
    );
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_metadata_provider(Arc::new(sources)),
    )
    .unwrap();
    let request = KeyRequest::new(&selector, Some("123456"));
    let mut ctx = begin(&engine, ExecutionGrant::new([Action::Inspect]));
    assert_eq!(
        engine
            .inspect(&InspectRequest::named_key(&request), None, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert!(backend.exchanges("I01 reader").is_empty());
    drop(ctx);
    for (alias, certificate) in [
        (f.aliases[0].as_str(), expected.as_slice()),
        (other_fixture.aliases[0].as_str(), other_expected.as_slice()),
    ] {
        let selected = KeySelector::token(
            TokenDeviceId::new("I01 reader").unwrap(),
            TokenKind::Kaztoken,
            alias.to_owned(),
        );
        let request = KeyRequest::new(&selected, Some("123456"));
        let mut ctx = begin(
            &engine,
            ExecutionGrant::new([Action::Inspect]).with_keys([selected.key_id()]),
        );
        let report = engine
            .inspect(&InspectRequest::named_key(&request), None, &mut ctx)
            .unwrap();
        assert_eq!(report.entries().len(), 1);
        assert_eq!(report.entries()[0].alias(), Some(alias));
        assert_eq!(report.entries()[0].certificate_der(), Some(certificate));
        assert_eq!(
            report.entries()[0].fingerprint().unwrap().as_bytes(),
            oncl_pki::key::HashAlg::Sha256.digest(certificate)
        );
    }
    assert!(
        !backend
            .exchanges("I01 reader")
            .iter()
            .any(|exchange| exchange.command.get(1) == Some(&0x2a))
    );
}

struct ForeignMetadata(std::sync::Mutex<Option<oncl_pki::info::PublicMetadata>>);
impl oncl_core::ReadMetadataProvider for ForeignMetadata {
    fn inspect(
        &self,
        _: &KeyRequest<'_>,
        _: &InspectionLimits,
        _: &mut oncl_core::OperationContext,
    ) -> Result<oncl_pki::info::PublicMetadata, oncl_core::OperationError> {
        Ok(self.0.lock().unwrap().take().unwrap())
    }
}
#[test]
fn provider_report_from_foreign_operation_cannot_enter_this_response() {
    let budget =
        Arc::new(oncl_pki::resource::SharedBudget::new(ResourceLimits::default()).unwrap());
    let foreign = budget
        .begin(ResourceLimits::default(), Arc::new(Control))
        .unwrap();
    let bytes = oncl_testkit::read(oncl_testkit::fixture("synthetic/root-rsa.cer"));
    let metadata = oncl_pki::info::PublicMetadata::certificate(&bytes, &foreign).unwrap();
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default()).with_metadata_provider(Arc::new(
            ForeignMetadata(std::sync::Mutex::new(Some(metadata))),
        )),
    )
    .unwrap();
    let selector = KeySelector::named(KeyId::new("foreign scope").unwrap());
    let mut ctx = begin(
        &engine,
        ExecutionGrant::new([Action::Inspect]).with_keys([selector.key_id()]),
    );
    let request = KeyRequest::new(&selector, None);
    assert_eq!(
        engine
            .inspect(&InspectRequest::named_key(&request), None, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidInput
    );
}

#[test]
fn structural_signature_metadata_does_not_require_or_assert_trust() {
    use oncl_pki::cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec};
    let f = oncl_testkit::synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0);
    let mut cms = cms::sign_spec(
        &key,
        &[],
        &SignSpec {
            content: Content::Data(b"I01 structural CMS"),
            encapsulate: true,
            cosign: CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs: AttrSpec::cades(time::macros::datetime!(2026-11-02 12:00 UTC)),
            certificates: CertSpec::Chain,
        },
    )
    .unwrap();
    // An invalid signature still has structural metadata. This operation must
    // not silently become crypto verification or require network/key services.
    *cms.last_mut().unwrap() ^= 1;
    let engine = engine();
    let mut ctx = begin(&engine, ExecutionGrant::new([Action::Inspect]));
    let mut input = cms.as_slice();
    let report = engine
        .inspect(
            &InspectRequest::cms_metadata(),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.kind(), oncl_core::InspectionKind::SignatureMetadata);
    let facts = report.cms().unwrap();
    assert_eq!(facts.signer_count(), 1);
    assert_eq!(facts.content_len(), 18);
    assert!(!facts.detached());
    assert!(report.entries().is_empty());
    assert_eq!(report.bytes_in(), cms.len() as u64);
}
#[test]
fn macless_pkcs12_inspection_reports_integrity_not_present() {
    use der::{Decode, Encode, Reader};
    let f = oncl_testkit::synthetic("multi-gost2015");
    let original = oncl_testkit::read(f.path);
    let outer = der::asn1::AnyRef::from_der(&original).unwrap();
    let mut reader = der::SliceReader::new(outer.value()).unwrap();
    let mut body = reader.tlv_bytes().unwrap().to_vec();
    body.extend_from_slice(reader.tlv_bytes().unwrap());
    let bytes = der::asn1::Any::new(der::Tag::Sequence, body)
        .unwrap()
        .to_der()
        .unwrap();
    let engine = engine();
    let mut ctx = begin(&engine, grant());
    let mut input = bytes.as_slice();
    let report = engine
        .inspect(
            &InspectRequest::container(Some(&f.password)),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(
        report.container_integrity(),
        Some(oncl_pki::info::MetadataIntegrity::NotPresent)
    );
    assert_eq!(report.entries().len(), 2);
}

#[test]
fn pkcs12_public_projection_never_imports_the_private_backend() {
    let cert = oncl_testkit::read(oncl_testkit::fixture("synthetic/root-rsa.cer"));
    let bytes = oncl_pki::pkcs12::write(
        &[oncl_pki::pkcs12::WriteEntry {
            alias: "public-only".into(),
            pkcs8_der: b"not an importable private key".to_vec(),
            cert_der: Some(cert.clone()),
        }],
        &[],
        "inspection integrity",
        &oncl_pki::pkcs12::WriteOptions::default(),
        &mut |bytes| bytes.fill(0x19),
    )
    .unwrap();
    assert!(oncl_pki::pkcs12::load(&bytes, "inspection integrity").is_err());
    let engine = engine();
    let mut ctx = begin(
        &engine,
        ExecutionGrant::new([Action::Inspect]).with_metadata_aliases(["public-only"]),
    );
    let mut input = bytes.as_slice();
    let report = engine
        .inspect(
            &InspectRequest::container(Some("inspection integrity")),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.entries()[0].alias(), Some("public-only"));
    assert_eq!(report.entries()[0].certificate_der(), Some(cert.as_slice()));
    assert_eq!(
        report.container_integrity(),
        Some(oncl_pki::info::MetadataIntegrity::PasswordMacVerified)
    );
}
fn authenticated_jks(certificates: u32, include_certificate: bool) -> Vec<u8> {
    // Java JKS v2 with one alias, an intentionally non-importable protected key,
    // and a real public certificate. The SHA1 integrity digest is genuine.
    let mut bytes = Vec::new();
    for value in [0xfeedfeed_u32, 2, 1, 1] {
        bytes.extend(value.to_be_bytes());
    }
    bytes.extend(10u16.to_be_bytes());
    bytes.extend(b"public-jks");
    bytes.extend(0u64.to_be_bytes());
    bytes.extend(1u32.to_be_bytes());
    bytes.push(0);
    bytes.extend(certificates.to_be_bytes());
    if include_certificate {
        let cert = oncl_testkit::read(oncl_testkit::fixture("synthetic/root-rsa.cer"));
        bytes.extend(5u16.to_be_bytes());
        bytes.extend(b"X.509");
        bytes.extend((cert.len() as u32).to_be_bytes());
        bytes.extend(cert);
    }
    let mut hash = oncl_pki::digest::HashState::new(oncl_pki::key::HashAlg::Sha1);
    for unit in "integrity".encode_utf16() {
        hash.update(&unit.to_be_bytes());
    }
    hash.update(b"Mighty Aphrodite");
    hash.update(&bytes);
    bytes.extend_from_slice(hash.finish().as_bytes());
    bytes
}
#[test]
fn jks_public_projection_skips_invalid_protected_key_and_bounds_nested_count() {
    for (count, include, expected) in [(1, true, true), (u32::MAX, false, false)] {
        let bytes = authenticated_jks(count, include);
        assert!(oncl_pki::jks::load(&bytes, "integrity").is_err());
        let engine = engine();
        let mut ctx = begin(
            &engine,
            ExecutionGrant::new([Action::Inspect]).with_metadata_aliases(["public-jks"]),
        );
        let mut input = bytes.as_slice();
        let result = engine.inspect(
            &InspectRequest::container(Some("integrity")),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        );
        if expected {
            let report = result.unwrap();
            assert_eq!(report.entries()[0].alias(), Some("public-jks"));
            assert_eq!(
                report.container_integrity(),
                Some(oncl_pki::info::MetadataIntegrity::PasswordMacVerified)
            );
        } else {
            assert_eq!(result.unwrap_err().code(), ErrorCode::MetadataLimit);
        }
    }
}
#[test]
fn metadata_snapshot_from_foreign_scope_is_rejected_before_intake() {
    use oncl_pki::io::{FrozenInput, Region, TemporaryStore};
    let bytes = oncl_testkit::read(oncl_testkit::fixture("synthetic/root-rsa.cer"));
    let scratch = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(scratch.path()).unwrap();
    let original = engine();
    let mut original_ctx = begin(&original, ExecutionGrant::new([Action::Inspect]));
    let mut input = bytes.as_slice();
    let mut frozen = FrozenInput::capture(
        Source::sequential(&mut input, None),
        &store,
        original_ctx.resources(),
    )
    .unwrap();
    let mut reader = frozen
        .reader(
            &[Region {
                offset: 0,
                len: bytes.len() as u64,
            }],
            original_ctx.resources(),
        )
        .unwrap();
    let engine = engine();
    let mut ctx = begin(&engine, ExecutionGrant::new([Action::Inspect]));
    assert_eq!(
        engine
            .inspect(
                &InspectRequest::certificate(),
                Some(reader.source()),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::InvalidInput
    );
    assert_eq!(ctx.resources().progress().bytes_in, 0);
}

#[test]
fn one_shot_container_control_failure_keeps_its_original_typed_cause() {
    struct Once {
        at: usize,
        calls: AtomicUsize,
        fired: AtomicBool,
    }
    impl OperationControl for Once {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.at {
                self.fired.store(true, Ordering::SeqCst);
                Err(ProcessingError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    let f = oncl_testkit::synthetic("multi-gost2015");
    let bytes = oncl_testkit::read(f.path);
    let mut exhausted = false;
    // Fault every actual control boundary until an invocation completes before
    // that boundary. No source locations or implementation call count is pinned.
    for at in 1..512 {
        let engine = engine();
        let control = Arc::new(Once {
            at,
            calls: AtomicUsize::new(0),
            fired: AtomicBool::new(false),
        });
        let mut ctx = match engine.begin(grant(), OperationPolicy::strict_online(), control.clone())
        {
            Ok(ctx) => ctx,
            Err(error) => {
                assert_eq!(error.code(), ErrorCode::Cancelled);
                continue;
            }
        };
        let mut input = bytes.as_slice();
        match engine.inspect(
            &InspectRequest::container(Some(&f.password)),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        ) {
            Err(error) => assert_eq!(error.code(), ErrorCode::Cancelled, "control boundary {at}"),
            Ok(report) => {
                assert!(
                    !control.fired.load(Ordering::SeqCst),
                    "one-shot failure was discarded at boundary {at}"
                );
                assert_eq!(report.entries().len(), 2);
                exhausted = true;
                break;
            }
        }
    }
    assert!(
        exhausted,
        "fault injection must cover the whole completed operation"
    );
}
