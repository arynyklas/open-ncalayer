//! C02 tests-first API contract. Controller owns RED/GREEN; no user keys.
use der::asn1::AnyRef;
use der::{Decode, Encode, Reader, SliceReader};
use oncl_pki::{
    cms::{
        self,
        stream::{self, CmsSignRequest, CmsSignServices},
    },
    digest::{DigestValue, HashState},
    io::{Source, TemporaryStore},
    key::{DigestSigner, HashAlg, SigAlg},
    pkcs12::{KeyEntry, load},
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
};
use oncl_testkit::{read, synthetic};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Cursor, Read},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
const DATA: &[u8] = b"abc";
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
fn entry(name: &str) -> KeyEntry {
    let f = synthetic(name);
    load(&read(f.path), &f.password).unwrap().remove(0)
}
struct Witness {
    entry: KeyEntry,
    calls: Arc<AtomicUsize>,
}
impl DigestSigner for Witness {
    fn certificate(&self) -> &oncl_pki::cert::Certificate {
        &self.entry.cert
    }
    fn algorithm(&self) -> SigAlg {
        DigestSigner::algorithm(&self.entry)
    }
    fn sign_digest(&mut self, digest: &DigestValue) -> Result<Vec<u8>, oncl_pki::key::KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        DigestSigner::sign_digest(&mut self.entry, digest)
    }
}
fn witness(name: &str) -> Witness {
    Witness {
        entry: entry(name),
        calls: Arc::new(AtomicUsize::new(0)),
    }
}
fn create(name: &str, attached: bool, data: &[u8]) -> Vec<u8> {
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut signer = witness(name);
    let mut out = vec![];
    stream::sign(
        &CmsSignRequest::create(attached),
        Source::sequential(&mut Cursor::new(data), None),
        None,
        &mut [&mut signer],
        &CmsSignServices::new(None, Some(&store)),
        &mut out,
        &scope(ResourceLimits::default()),
    )
    .unwrap();
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    out
}
fn children(bytes: &[u8]) -> Vec<Vec<u8>> {
    let value = AnyRef::from_der(bytes).unwrap();
    let mut reader = SliceReader::new(value.value()).unwrap();
    let mut result = vec![];
    while !reader.is_finished() {
        result.push(reader.decode::<AnyRef<'_>>().unwrap().to_der().unwrap());
    }
    result
}
fn signer_infos(bytes: &[u8]) -> Vec<Vec<u8>> {
    let ci = children(bytes);
    let explicit = children(&ci[1]);
    let sd = children(&explicit[0]);
    children(sd.last().unwrap())
}
fn has_digest(bytes: &[u8], expected: &[u8]) -> bool {
    bytes.windows(expected.len()).any(|w| w == expected)
}
#[test]
fn detached_and_attached_have_same_digest() {
    // Breaks if attached framing enters the document hash or issuer OID chooses the key algorithm.
    let expected = Sha256::digest(DATA);
    for name in ["user-rsa-sign", "user-gost2004-sign", "user-gost2015-sign"] {
        let attached = create(name, true, DATA);
        let detached = create(name, false, DATA);
        assert_eq!(cms::verify(&attached, None).unwrap().len(), 1);
        assert_eq!(cms::verify(&detached, Some(DATA)).unwrap().len(), 1);
        assert!(cms::verify(&detached, Some(b"abd")).is_err());
        if name == "user-rsa-sign" {
            assert!(has_digest(&signer_infos(&attached)[0], &expected));
            assert!(has_digest(&signer_infos(&detached)[0], &expected));
        }
        let mut extracted = vec![];
        stream::extract(
            Source::sequential(&mut Cursor::new(&attached), None),
            &mut extracted,
            &mut scope(ResourceLimits::default()),
        )
        .unwrap();
        assert_eq!(extracted, DATA);
    }
}
#[test]
fn prehash_is_not_double_hashed() {
    // Independent SHA-256 document oracle plus existing public message verifier.
    let mut signer = witness("user-rsa-sign");
    let public = signer.entry.key.public_key();
    let mut out = vec![];
    stream::sign_raw(
        Source::sequential(&mut Cursor::new(DATA), None),
        &mut signer,
        &mut out,
        &scope(ResourceLimits::default()),
    )
    .unwrap();
    let hash = DigestValue::from_bytes(HashAlg::Sha256, &Sha256::digest(DATA)).unwrap();
    public
        .verify_digest(SigAlg::RsaSha256, &hash, &out)
        .unwrap();
    public.verify(SigAlg::RsaSha256, DATA, &out).unwrap();
    assert!(
        public
            .verify(SigAlg::RsaSha256, hash.as_bytes(), &out)
            .is_err()
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
}
#[test]
fn raw_real_software_algorithms_verify_message_and_digest() {
    for name in ["user-rsa-sign", "user-gost2004-sign", "user-gost2015-sign"] {
        let mut signer = witness(name);
        let alg = signer.algorithm();
        let public = signer.entry.key.public_key();
        let mut out = vec![];
        stream::sign_raw(
            Source::sequential(&mut Cursor::new(DATA), None),
            &mut signer,
            &mut out,
            &scope(ResourceLimits::default()),
        )
        .unwrap();
        public.verify(alg, DATA, &out).unwrap();
        let mut state = HashState::new(alg.hash_alg());
        state.update(DATA);
        public.verify_digest(alg, &state.finish(), &out).unwrap();
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn unknown_length_attached_requires_host_store_before_key_use() {
    let mut signer = witness("user-rsa-sign");
    let mut out = vec![];
    assert!(
        stream::sign(
            &CmsSignRequest::create(true),
            Source::sequential(&mut Cursor::new(DATA), None),
            None,
            &mut [&mut signer],
            &CmsSignServices::new(None, None),
            &mut out,
            &scope(ResourceLimits::default())
        )
        .is_err()
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert!(out.is_empty());
}
struct Generated {
    position: u64,
    length: u64,
}
impl Read for Generated {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min((self.length - self.position) as usize);
        for (i, b) in out[..n].iter_mut().enumerate() {
            *b = ((self.position + i as u64)
                .wrapping_mul(131)
                .wrapping_add((self.position + i as u64) / 257)
                % 251) as u8;
        }
        self.position += n as u64;
        Ok(n)
    }
}
#[test]
fn internal_snapshot_is_not_final_output_and_chunks_adapt_to_work_budget() {
    // 3 MiB non-padding document exceeds work budget; output quota admits one document, not two.
    let length = 3 * 1024 * 1024;
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let limits = ResourceLimits {
        memory_bytes: 256 * 1024,
        output_bytes: length + 65536,
        input_bytes: length,
        temp_bytes: length + 65536,
        ..ResourceLimits::default()
    };
    let resources = scope(limits);
    let mut signer = witness("user-rsa-sign");
    let mut out = vec![];
    stream::sign(
        &CmsSignRequest::create(true),
        Source::sequential(
            &mut Generated {
                position: 0,
                length,
            },
            None,
        ),
        None,
        &mut [&mut signer],
        &CmsSignServices::new(None, Some(&store)),
        &mut out,
        &resources,
    )
    .unwrap();
    assert_eq!(resources.progress().bytes_in, length);
    assert_eq!(resources.progress().bytes_out, out.len() as u64);
    cms::verify(&out, None).unwrap();
}
#[test]
fn spool_quota_rejects_before_key_use() {
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let limits = ResourceLimits {
        temp_bytes: 2,
        ..ResourceLimits::default()
    };
    let mut signer = witness("user-rsa-sign");
    let mut out = vec![];
    assert!(
        stream::sign(
            &CmsSignRequest::create(true),
            Source::sequential(&mut Cursor::new(DATA), None),
            None,
            &mut [&mut signer],
            &CmsSignServices::new(None, Some(&store)),
            &mut out,
            &scope(limits)
        )
        .is_err()
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert!(out.is_empty());
}
#[test]
fn detached_and_raw_do_not_require_temporary_storage() {
    let mut signer = witness("user-rsa-sign");
    let mut out = vec![];
    stream::sign(
        &CmsSignRequest::create(false),
        Source::sequential(&mut Cursor::new(DATA), None),
        None,
        &mut [&mut signer],
        &CmsSignServices::new(None, None),
        &mut out,
        &scope(ResourceLimits::default()),
    )
    .unwrap();
    cms::verify(&out, Some(DATA)).unwrap();
}

#[test]
fn source_stage_never_debits_output_or_publishes() {
    use oncl_pki::io::Region;
    for data in [b"".as_slice(), DATA] {
        let parent = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(parent.path()).unwrap();
        let limits = ResourceLimits {
            output_bytes: 0,
            ..ResourceLimits::default()
        };
        let mut resources = scope(limits);
        let mut staged = store.stage_source(&mut resources).unwrap();
        staged.write_chunk(data).unwrap();
        assert_eq!(resources.progress().bytes_out, 0);
        let mut replay = [0; 8];
        let n = staged
            .read_region(
                Region {
                    offset: 0,
                    len: data.len() as u64,
                },
                &mut replay,
            )
            .unwrap();
        assert_eq!(&replay[..n], data);
        let mut external = vec![];
        assert!(staged.copy_to(&mut external).is_err());
        assert!(external.is_empty());
        let mut staged = store.stage_source(&mut resources).unwrap();
        staged.write_chunk(data).unwrap();
        let destination = parent.path().join("forbidden");
        assert!(staged.commit(&destination).is_err());
        assert!(!destination.exists());
    }
}
#[test]
fn empty_and_small_attached_output_budget_counts_only_caller_bytes() {
    for data in [b"".as_slice(), DATA] {
        let expected = create("user-rsa-sign", true, data).len() as u64;
        let parent = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(parent.path()).unwrap();
        let limits = ResourceLimits {
            output_bytes: expected,
            ..ResourceLimits::default()
        };
        let resources = scope(limits);
        let mut signer = witness("user-rsa-sign");
        let mut output = vec![];
        stream::sign(
            &CmsSignRequest::create(true),
            Source::sequential(&mut Cursor::new(data), None),
            None,
            &mut [&mut signer],
            &CmsSignServices::new(None, Some(&store)),
            &mut output,
            &resources,
        )
        .unwrap();
        assert_eq!(resources.progress().bytes_out, expected);
        assert_eq!(resources.progress().bytes_in, data.len() as u64);
    }
}
struct Changing {
    cursor: Cursor<Vec<u8>>,
    changed: bool,
}
impl Read for Changing {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.cursor.read(out)
    }
}
impl std::io::Seek for Changing {
    fn seek(&mut self, position: std::io::SeekFrom) -> io::Result<u64> {
        if matches!(position, std::io::SeekFrom::Start(0))
            && self.cursor.position() != 0
            && !self.changed
        {
            self.cursor.get_mut()[0] ^= 1;
            self.changed = true;
        }
        std::io::Seek::seek(&mut self.cursor, position)
    }
}
#[test]
fn changing_seekable_source_never_returns_invalid_success() {
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut source = Changing {
        cursor: Cursor::new(DATA.to_vec()),
        changed: false,
    };
    let mut signer = witness("user-rsa-sign");
    let mut output = vec![];
    let result = stream::sign(
        &CmsSignRequest::create(true),
        Source::seekable(&mut source, Some(3)),
        None,
        &mut [&mut signer],
        &CmsSignServices::new(None, Some(&store)),
        &mut output,
        &scope(ResourceLimits::default()),
    );
    let report = result.unwrap();
    assert_eq!(report.applied, oncl_pki::key::AppliedState::Applied);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    cms::verify(&output, None).unwrap();
    let mut extracted = vec![];
    stream::extract(
        Source::sequential(&mut Cursor::new(&output), None),
        &mut extracted,
        &mut scope(ResourceLimits::default()),
    )
    .unwrap();
    assert_eq!(extracted, DATA);
}

#[test]
fn signer_count_is_bounded_before_any_application() {
    for count in [0, 65] {
        let mut keys: Vec<_> = (0..count).map(|_| witness("user-rsa-sign")).collect();
        let counters: Vec<_> = keys.iter().map(|key| key.calls.clone()).collect();
        let mut signers: Vec<&mut dyn DigestSigner> = keys
            .iter_mut()
            .map(|key| key as &mut dyn DigestSigner)
            .collect();
        let mut output = vec![];
        assert!(
            stream::sign(
                &CmsSignRequest::create(false),
                Source::sequential(&mut Cursor::new(DATA), None),
                None,
                &mut signers,
                &CmsSignServices::new(None, None),
                &mut output,
                &scope(ResourceLimits::default())
            )
            .is_err()
        );
        assert!(
            counters
                .iter()
                .all(|count| count.load(Ordering::SeqCst) == 0)
        );
        assert!(output.is_empty());
    }
}
#[test]
fn default_profile_is_definite_der_not_silent_indefinite_ber() {
    let output = create("user-rsa-sign", true, DATA);
    assert_eq!(output[0], 0x30);
    assert_ne!(output[1], 0x80);
    AnyRef::from_der(&output).unwrap();
}

#[test]
fn explicit_staged_output_is_debited_once_and_publication_is_explicit() {
    for data in [b"".as_slice(), DATA] {
        let expected = create("user-rsa-sign", true, data).len() as u64;
        let parent = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(parent.path()).unwrap();
        let limits = ResourceLimits {
            output_bytes: expected,
            ..ResourceLimits::default()
        };
        let mut resources = scope(limits);
        let mut output = store.stage(&mut resources).unwrap();
        let mut signer = witness("user-rsa-sign");
        let report = stream::sign_staged(
            &CmsSignRequest::create(true),
            Source::sequential(&mut Cursor::new(data), None),
            None,
            &mut [&mut signer],
            &CmsSignServices::new(None, Some(&store)),
            &mut output,
            &resources,
        )
        .unwrap();
        assert_eq!(report.bytes_out, expected);
        assert_eq!(resources.progress().bytes_out, expected);
        assert_eq!(output.len(), expected);
        let destination = parent.path().join("complete.p7s");
        assert!(!destination.exists());
        output.commit(&destination).unwrap();
        cms::verify(&std::fs::read(&destination).unwrap(), None).unwrap();
    }
}
#[test]
fn staged_output_admission_checks_exact_operation_role_and_emptiness_before_use() {
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let limits = ResourceLimits {
        max_in_flight: 2,
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut resources = budget.begin(limits.clone(), Arc::new(Control)).unwrap();
    let mut foreign = budget.begin(limits, Arc::new(Control)).unwrap();
    for mode in 0..3 {
        let mut target = if mode == 0 {
            store.stage(&mut foreign).unwrap()
        } else if mode == 1 {
            store.stage_source(&mut resources).unwrap()
        } else {
            let mut stage = store.stage(&mut resources).unwrap();
            stage.write_chunk(b"x").unwrap();
            stage
        };
        let mut signer = witness("user-rsa-sign");
        let before = resources.progress();
        assert!(
            stream::sign_raw_staged(
                Source::sequential(&mut Cursor::new(DATA), None),
                &mut signer,
                &mut target,
                &resources
            )
            .is_err()
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
        assert_eq!(resources.progress(), before);
    }
}
#[test]
fn staged_temp_failure_after_private_application_poisoned_artifact_stays_unpublished() {
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let limits = ResourceLimits {
        temp_bytes: 1,
        ..ResourceLimits::default()
    };
    let mut resources = scope(limits);
    let mut output = store.stage(&mut resources).unwrap();
    let mut signer = witness("user-rsa-sign");
    let error = stream::sign_raw_staged(
        Source::sequential(&mut Cursor::new(DATA), None),
        &mut signer,
        &mut output,
        &resources,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        stream::StreamError::AfterKeyUse {
            applied: oncl_pki::key::AppliedState::Applied,
            ..
        }
    ));
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    let destination = parent.path().join("must-not-publish");
    assert!(output.commit(&destination).is_err());
    assert!(!destination.exists());
}

#[test]
fn detached_output_container_budget_never_subtracts_unencapsulated_payload() {
    let encoded_len = create("user-rsa-sign", false, DATA).len() as u64;
    // DER's short/long length boundary and documents larger than their CMS
    // metadata. Detached output never contains any of these document bytes.
    for length in [0, 1, 127, 128, 4096, 19_018] {
        let data: Vec<u8> = (0..length)
            .map(|index| ((index * 131 + index / 257) % 251) as u8)
            .collect();
        let limits = ResourceLimits {
            input_bytes: length as u64,
            output_bytes: encoded_len,
            container_bytes: encoded_len,
            ..ResourceLimits::default()
        };
        let resources = scope(limits);
        let mut signer = witness("user-rsa-sign");
        let mut output = vec![];
        let result = stream::sign(
            &CmsSignRequest::create(false),
            Source::sequential(&mut Cursor::new(&data), None),
            None,
            &mut [&mut signer],
            &CmsSignServices::new(None, None),
            &mut output,
            &resources,
        );
        assert!(result.is_ok(), "detached length {length}: {result:?}");
        let report = result.unwrap();
        assert_eq!(report.applied, oncl_pki::key::AppliedState::Applied);
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(report.bytes_in, length as u64);
        assert_eq!(report.bytes_out, encoded_len);
        assert_eq!(output.len() as u64, encoded_len);
        assert_eq!(cms::verify(&output, Some(&data)).unwrap().len(), 1);
    }
}

fn conflicting_signer_pair(same_key: bool) -> (Witness, Witness) {
    let issuer = entry("inter-gost2015.key");
    let mut first = witness("user-rsa-sign");
    let mut second = witness(if same_key {
        "user-rsa-sign"
    } else {
        "user-gost2004-sign"
    });
    let mut first_spec = oncl_pki::testing::TestCertSpec::from_cert(&first.entry.cert);
    first_spec.serial = vec![0x63, 0x02];
    let mut second_spec = oncl_pki::testing::TestCertSpec::from_cert(&second.entry.cert);
    second_spec.serial = first_spec.serial.clone();
    if same_key {
        second_spec.subject =
            oncl_pki::testing::TestCertSpec::from_cert(&entry("user-gost2004-sign").cert).subject;
    }
    first.entry.cert = oncl_pki::testing::issue_cert(&issuer, first_spec);
    second.entry.cert = oncl_pki::testing::issue_cert(&issuer, second_spec);
    assert_eq!(
        first.entry.cert.tbs_certificate().issuer(),
        second.entry.cert.tbs_certificate().issuer()
    );
    assert_eq!(
        first.entry.cert.tbs_certificate().serial_number(),
        second.entry.cert.tbs_certificate().serial_number()
    );
    assert_ne!(
        first.entry.cert.to_der().unwrap(),
        second.entry.cert.to_der().unwrap()
    );
    assert_eq!(
        first.entry.key.public_key() == second.entry.key.public_key(),
        same_key
    );
    (first, second)
}

#[test]
fn create_rejects_conflicting_issuer_serial_before_either_real_signer_is_applied() {
    for same_key in [false, true] {
        let (mut first, mut second) = conflicting_signer_pair(same_key);
        let parent = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(parent.path()).unwrap();
        let mut resources = scope(ResourceLimits::default());
        let mut output = store.stage(&mut resources).unwrap();
        let result = stream::sign_staged(
            &CmsSignRequest::create(false),
            Source::sequential(&mut Cursor::new(DATA), None),
            None,
            &mut [&mut first, &mut second],
            &CmsSignServices::new(None, None),
            &mut output,
            &resources,
        );
        assert!(
            result.is_err(),
            "conflicting certificates admitted; same_key={same_key}"
        );
        assert_eq!(first.calls.load(Ordering::SeqCst), 0);
        assert_eq!(second.calls.load(Ordering::SeqCst), 0);
        assert_eq!(output.len(), 0);
        let destination = parent.path().join("conflicting.p7s");
        assert!(output.commit(&destination).is_err());
        assert!(!destination.exists());
    }
}
