//! C01 review I2/I3: real signed inputs and pinned local HTTP, isolated System
//! live-allocation witness. Controller owns RED/GREEN; no production hooks.
use der::asn1::{AnyRef, ObjectIdentifier, OctetString};
use der::{Decode, Reader, SliceReader};
use oncl_core::{
    Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationError, OperationPolicy,
    ValidationServices, VerifyRequest,
};
use oncl_pki::{
    cert::Certificate,
    cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec},
    http::{GetOptions, HttpRequest, HttpTransport, MAX_RESPONSE_LEN, UreqTransport},
    io::Source,
    ocsp::{self, MockOcsp},
    pkcs12::{KeyEntry, load},
    pkix::CaSet,
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
    validation::{CheckStatus, NetworkPolicy, Verdict},
};
use oncl_testkit::{read, synthetic};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    io::{self, Cursor, Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use time::{OffsetDateTime, macros::datetime};

// All tests in this integration binary serialize fixture setup and measured
// work. Process-wide accounting also covers cross-thread frees of objects
// allocated before the span (e.g. the local server's response bodies).
static SERIAL: Mutex<()> = Mutex::new(());
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);
struct MeasuredSystem;
fn allocated(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::SeqCst) + bytes;
    if ACTIVE.load(Ordering::SeqCst) {
        PEAK.fetch_max(live, Ordering::SeqCst);
    }
}
fn freed(bytes: usize) {
    LIVE.fetch_sub(bytes, Ordering::SeqCst);
}
// SAFETY: requests are delegated unchanged to System. Atomic counters allocate
// nothing; no pointer/header is read or rewritten, including after deallocation.
// Every successful allocation is counted from process start; LIVE is never
// reset at a measurement boundary, so preexisting-object frees cannot underflow.
unsafe impl GlobalAlloc for MeasuredSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: identical allocator contract to the caller.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: identical allocator contract to the caller.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        freed(layout.size());
        // SAFETY: caller supplies the live allocation's original layout.
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, bytes: usize) -> *mut u8 {
        // SAFETY: caller supplies a live pointer, matching layout and valid size.
        let result = unsafe { System.realloc(pointer, layout, bytes) };
        if !result.is_null() {
            if bytes >= layout.size() {
                allocated(bytes - layout.size());
            } else {
                freed(layout.size() - bytes);
            }
        }
        // Failed realloc retains the old allocation and changes no count.
        result
    }
}
#[global_allocator]
static ALLOCATOR: MeasuredSystem = MeasuredSystem;
struct Span;
impl Drop for Span {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::SeqCst);
    }
}
fn measured<T>(work: impl FnOnce() -> T) -> (T, usize) {
    assert!(!ACTIVE.load(Ordering::SeqCst));
    let baseline = LIVE.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    ACTIVE.store(true, Ordering::SeqCst);
    let span = Span;
    let result = work();
    let peak = PEAK.load(Ordering::SeqCst).saturating_sub(baseline);
    drop(span);
    (result, peak)
}

const NOW: OffsetDateTime = datetime!(2026-11-02 12:00 UTC);
const CLAIM: OffsetDateTime = datetime!(2025-06-01 10:00 UTC);
const DOCUMENT: &[u8] = b"C01 real signed small input; host trust and HTTP are independent sizes";
#[derive(Default)]
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
fn entry(name: &str) -> KeyEntry {
    let fixture = synthetic(name);
    load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0)
}
fn signed(key: &KeyEntry) -> Vec<u8> {
    cms::sign_spec(
        key,
        &[],
        &SignSpec {
            content: Content::Data(DOCUMENT),
            encapsulate: true,
            cosign: CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs: AttrSpec::cades(CLAIM),
            certificates: CertSpec::Signer,
        },
    )
    .unwrap()
}
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        let length = body.len().to_be_bytes();
        let first = length.iter().position(|byte| *byte != 0).unwrap();
        out.push(0x80 | (length.len() - first) as u8);
        out.extend_from_slice(&length[first..]);
    }
    out.extend_from_slice(body);
    out
}
fn replace_uris(input: &[u8], uri: &[u8]) -> Vec<u8> {
    let any = AnyRef::from_der(input).unwrap();
    let body = if input[0] == 0x86 {
        uri.to_vec()
    } else if input[0] & 0x20 != 0 {
        let mut reader = SliceReader::new(any.value()).unwrap();
        let mut body = vec![];
        while !reader.is_finished() {
            body.extend(replace_uris(reader.tlv_bytes().unwrap(), uri));
        }
        body
    } else {
        any.value().to_vec()
    };
    tlv(input[0], &body)
}
fn local_leaf(root: &KeyEntry, origin: &str) -> KeyEntry {
    let mut key = entry("user-gost2015-sign");
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&key.cert);
    // The original directly root-issued fixture has NO AIA or CRL pointers.
    // Rewriting its existing extensions alone therefore never reaches HTTP.
    // Copy only the real validation fixture's status extension shapes; keep
    // this leaf's own SPKI/AKI/usage and genuinely reissue it under this root.
    let template = entry("inter-user-gost2015-sign");
    let pointers: Vec<_> = oncl_pki::testing::TestCertSpec::from_cert(&template.cert)
        .extensions
        .into_iter()
        .filter(|extension| {
            matches!(
                extension.extn_id.to_string().as_str(),
                "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
            )
        })
        .collect();
    assert_eq!(
        pointers.len(),
        2,
        "validation fixture must provide both actual status extension shapes"
    );
    spec.extensions.retain(|extension| {
        !matches!(
            extension.extn_id.to_string().as_str(),
            "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    spec.extensions.extend(pointers);
    for extension in &mut spec.extensions {
        let target = match extension.extn_id.to_string().as_str() {
            "1.3.6.1.5.5.7.1.1" => Some(format!("{origin}/ocsp")),
            "2.5.29.31" => Some(format!("{origin}/crl")),
            _ => None,
        };
        if let Some(target) = target {
            extension.extn_value = OctetString::new(replace_uris(
                extension.extn_value.as_bytes(),
                target.as_bytes(),
            ))
            .unwrap();
        }
    }
    key.cert = oncl_pki::testing::issue_cert(root, spec);
    assert_eq!(ocsp::ocsp_url(&key.cert), Some(format!("{origin}/ocsp")));
    assert_eq!(
        oncl_pki::crl::crl_urls(&key.cert),
        vec![format!("{origin}/crl")]
    );
    key
}
fn services(anchors: Vec<Certificate>, network: NetworkPolicy) -> ValidationServices {
    ValidationServices::new(
        CaSet::new(anchors),
        vec![],
        Arc::new(UreqTransport::default()),
        network,
        Arc::new(|| NOW),
    )
}
fn begin(
    engine: &Engine,
    policy: OperationPolicy,
    control: Arc<Control>,
) -> oncl_core::OperationContext {
    engine
        .begin(ExecutionGrant::new([Action::Verify]), policy, control)
        .unwrap()
}

#[test]
fn small_cms_large_host_trust_is_borrowed_or_refused_before_per_operation_copy() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    const MEMORY: u64 = 2 * 1024 * 1024;
    let root = entry("root-gost2015.key");
    let document = signed(&entry("user-gost2015-sign"));
    // Distinct genuine self-issued renewal certificates using the fixture CA
    // key. Opaque noncritical public extensions model a large host trust store;
    // this is not a document-size/RSS/padding acceptance demonstration.
    let mut anchors = vec![root.cert.clone()];
    let public_extension = tlv(4, &vec![0x5a; 256 * 1024]);
    for serial in 1..=24u32 {
        let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&root.cert);
        spec.serial = (0x4010_0000 + serial).to_be_bytes().to_vec();
        let mut extension = spec.extensions[0].clone();
        extension.extn_id = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.5.2");
        extension.critical = false;
        extension.extn_value = OctetString::new(public_extension.clone()).unwrap();
        spec.extensions.push(extension);
        anchors.push(oncl_pki::testing::issue_cert(&root, spec));
    }
    let limits = ResourceLimits {
        memory_bytes: MEMORY,
        metadata_bytes: 128 * 1024,
        ..ResourceLimits::default()
    };
    let engine = Engine::new(EngineServices::hash_only(limits).with_validation(services(
        anchors,
        NetworkPolicy::only_endpoints(Vec::<String>::new()).unwrap(),
    )))
    .unwrap();
    let mut ctx = begin(
        &engine,
        OperationPolicy::offline_report(),
        Arc::new(Control::default()),
    );
    let (result, peak) = measured(|| {
        engine.verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut Cursor::new(&document), None),
            None,
            &mut ctx,
        )
    });
    assert!(
        peak <= MEMORY as usize,
        "operation allocated {peak} bytes for a small CMS under {MEMORY}-byte scope; host-owned anchors were prepared before this span"
    );
    match result {
        Ok(report) => {
            assert_eq!(report.signers[0].signature, CheckStatus::Passed);
            assert_eq!(report.signers[0].chain, CheckStatus::Passed);
            assert_eq!(report.verdict, Verdict::Indeterminate); // offline status absent
        }
        Err(error) => assert!(
            matches!(
                error.code(),
                ErrorCode::MemoryLimit | ErrorCode::MetadataLimit
            ),
            "unrelated refusal: {error:?}"
        ),
    }
}

struct LocalStatus {
    listener: TcpListener,
    address: SocketAddr,
    origin: String,
}
impl LocalStatus {
    fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        Self {
            listener,
            address,
            origin: format!("http://status.c01.test:{}", address.port()),
        }
    }
    fn policy(&self) -> NetworkPolicy {
        NetworkPolicy::only_endpoints([&self.origin])
            .unwrap()
            .with_resolved_endpoint(&self.origin, vec![self.address])
            .unwrap()
    }
    fn serve(self, ocsp: Vec<u8>, crl: Vec<u8>, cancel: Option<Arc<Control>>) -> Server {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let hits = Arc::new(AtomicUsize::new(0));
        let calls = hits.clone();
        let absolute_form = Arc::new(AtomicBool::new(false));
        let absolute_request = absolute_form.clone();
        let worker = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            while !stopped.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                let (mut socket, _) = match self.listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(_) => break,
                };
                // Windows accepted sockets can inherit the listener's mode.
                // A timeout does not turn a nonblocking stream into blocking.
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while request.len() < 16 * 1024
                    && !request.windows(4).any(|bytes| bytes == b"\r\n\r\n")
                {
                    match socket.read(&mut buffer) {
                        Ok(0) => break,
                        Err(error) => {
                            eprintln!("C01 test HTTP header read failed: {error}");
                            break;
                        }
                        Ok(count) => request.extend_from_slice(&buffer[..count]),
                    }
                }
                if !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    eprintln!("C01 test HTTP incomplete headers: {} bytes", request.len());
                    continue;
                }
                let first = String::from_utf8_lossy(&request);
                let target = first.split_whitespace().nth(1).unwrap_or("");
                let path = if let Some(authority) = target.strip_prefix("http://") {
                    absolute_request.store(true, Ordering::SeqCst);
                    authority
                        .find('/')
                        .map(|offset| &authority[offset..])
                        .unwrap_or("/")
                } else {
                    target
                };
                let (body, content_type) = if path.starts_with("/ocsp/") {
                    (&ocsp, "application/ocsp-response")
                } else if path == "/crl" {
                    (&crl, "application/pkix-crl")
                } else {
                    eprintln!(
                        "C01 test HTTP unhandled request: {}",
                        first.lines().next().unwrap_or("")
                    );
                    continue;
                };
                calls.fetch_add(1, Ordering::SeqCst);
                eprintln!(
                    "C01 test HTTP request={} response={content_type} length={}",
                    first.lines().next().unwrap_or(""),
                    body.len()
                );
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if let Err(error) = socket.write_all(headers.as_bytes()) {
                    eprintln!("C01 test HTTP response header write failed: {error}");
                    continue;
                }
                if let Some(control) = &cancel {
                    control.0.store(true, Ordering::SeqCst);
                }
                // Early admission failures may close the socket before the body
                // finishes. BrokenPipe is expected, not a fake server success.
                if let Err(error) = socket.write_all(body) {
                    eprintln!(
                        "C01 test HTTP response body write failed ({} bytes requested): {error}",
                        body.len()
                    );
                }
            }
        });
        Server {
            stop,
            hits,
            absolute_form,
            worker: Some(worker),
        }
    }
}
struct Server {
    stop: Arc<AtomicBool>,
    hits: Arc<AtomicUsize>,
    absolute_form: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}
fn near_cap_body() -> Vec<u8> {
    // A legitimate DER TLV tree of typed INTEGERs, but not an OCSPResponse or
    // CertificateList. Invalid status input still must be admitted before its
    // body/BER tree/owned decode allocations. No sparse file or huge allocation.
    tlv(
        0x30,
        &[2, 1, 1].repeat((MAX_RESPONSE_LEN as usize - 8192) / 3),
    )
}
#[derive(Clone, Copy)]
enum Route {
    Ocsp,
    Crl,
}
fn status_case(
    route: Route,
    limits: ResourceLimits,
    global: Option<(ResourceLimits, u64)>,
    expected: ErrorCode,
) {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let local = LocalStatus::bind();
    let network = local.policy();
    let root = entry("root-gost2015.key");
    let key = local_leaf(&root, &local.origin);
    let document = signed(&key);
    let body = near_cap_body();
    let try_later = vec![0x30, 3, 0x0a, 1, 3];
    let server = match route {
        Route::Ocsp => local.serve(body, try_later, None),
        Route::Crl => local.serve(try_later, body, None),
    };
    let mut busy: Option<ResourceScope> = None;
    let mut held = None;
    let mut allowed = limits.memory_bytes;
    let mut configured = EngineServices::hash_only(limits.clone());
    if let Some((global, occupied)) = global {
        allowed = global.memory_bytes - occupied;
        let shared = Arc::new(SharedBudget::new(global.clone()).unwrap());
        let holder = shared.begin(global, Arc::new(Control::default())).unwrap();
        held = Some(holder.reserve_memory(occupied).unwrap());
        busy = Some(holder);
        configured = configured.with_shared_budget(shared);
    }
    let engine =
        Engine::new(configured.with_validation(services(vec![root.cert], network))).unwrap();
    let mut ctx = begin(
        &engine,
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let (result, peak) = measured(|| {
        engine.verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut Cursor::new(&document), None),
            None,
            &mut ctx,
        )
    });
    assert!(
        peak <= allowed as usize,
        "live operation allocation {peak} exceeded remaining local/global admission {allowed}"
    );
    let error = result.expect_err("authorized status body/decode resource refusal must not become completed Unavailable/Indeterminate");
    assert_eq!(error.code(), expected, "wrong fatal category: {error:?}");
    drop(ctx);
    drop(held);
    drop(busy);
    drop(server);
}

#[test]
fn near_cap_pinned_ocsp_body_obeys_original_memory_scope_and_stays_fatal() {
    status_case(
        Route::Ocsp,
        ResourceLimits {
            memory_bytes: 1024 * 1024,
            metadata_bytes: 256 * 1024 * 1024,
            ..ResourceLimits::default()
        },
        None,
        ErrorCode::MemoryLimit,
    );
}
#[test]
fn near_cap_pinned_crl_fallback_obeys_original_memory_scope_and_stays_fatal() {
    status_case(
        Route::Crl,
        ResourceLimits {
            memory_bytes: 1024 * 1024,
            metadata_bytes: 256 * 1024 * 1024,
            ..ResourceLimits::default()
        },
        None,
        ErrorCode::MemoryLimit,
    );
}
#[test]
fn status_body_and_decode_metadata_limit_is_not_unavailable_revocation() {
    status_case(
        Route::Ocsp,
        ResourceLimits {
            memory_bytes: 256 * 1024 * 1024,
            metadata_bytes: 128 * 1024,
            ..ResourceLimits::default()
        },
        None,
        ErrorCode::MetadataLimit,
    );
}
#[test]
fn live_status_honors_remaining_shared_budget_not_only_larger_local_limit() {
    status_case(
        Route::Ocsp,
        ResourceLimits {
            max_in_flight: 2,
            memory_bytes: 8 * 1024 * 1024,
            metadata_bytes: 256 * 1024 * 1024,
            ..ResourceLimits::default()
        },
        Some((
            ResourceLimits {
                max_in_flight: 2,
                memory_bytes: 1536 * 1024,
                metadata_bytes: 256 * 1024 * 1024,
                ..ResourceLimits::default()
            },
            512 * 1024,
        )),
        ErrorCode::MemoryLimit,
    );
}

#[test]
fn permitted_large_invalid_body_is_real_network_input_not_a_resource_failure() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let local = LocalStatus::bind();
    let network = local.policy();
    let root = entry("root-gost2015.key");
    let key = local_leaf(&root, &local.origin);
    let document = signed(&key);
    let server = local.serve(near_cap_body(), near_cap_body(), None);
    let limits = ResourceLimits {
        memory_bytes: 256 * 1024 * 1024,
        metadata_bytes: 256 * 1024 * 1024,
        ..ResourceLimits::default()
    };
    let engine = Engine::new(
        EngineServices::hash_only(limits.clone())
            .with_validation(services(vec![root.cert], network)),
    )
    .unwrap();
    let mut ctx = begin(
        &engine,
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let (result, peak) = measured(|| {
        engine.verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut Cursor::new(&document), None),
            None,
            &mut ctx,
        )
    });
    assert!(peak <= limits.memory_bytes as usize);
    let report = result.unwrap();
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    assert_eq!(report.signers[0].chain, CheckStatus::Passed);
    assert_eq!(report.signers[0].revocation, CheckStatus::Unavailable);
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert!(
        server.hits.load(Ordering::SeqCst) >= 2,
        "both pinned OCSP and CRL routes must actually serve response bodies"
    );
}

#[test]
fn small_current_issuer_bound_ocsp_remains_valid_without_a_huge_fixed_reserve() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let local = LocalStatus::bind();
    let network = local.policy();
    let root = entry("root-gost2015.key");
    let key = local_leaf(&root, &local.origin);
    let document = signed(&key);
    let mut responder = entry("ocsp-gost2015");
    responder.cert = oncl_pki::testing::issue_cert(
        &root,
        oncl_pki::testing::TestCertSpec::from_cert(&responder.cert),
    );
    let request = ocsp::request_der(&key.cert, &root.cert);
    let body = MockOcsp::new(responder)
        .with_now(NOW)
        .send(&HttpRequest::post(
            "http://fixture.invalid",
            Some("application/ocsp-request"),
            &request,
            GetOptions::default(),
        ))
        .unwrap()
        .body;
    // Prove the public synthetic response is current, genuinely signed and
    // bound to this actual issuer/leaf before testing its real HTTP delivery.
    // The production online check uses request_der(None): no nonce is omitted.
    let checked = ocsp::check_embedded_issuer_bound(
        &body,
        &key.cert,
        &root.cert,
        &CaSet::new(vec![root.cert.clone()]),
        NOW,
    )
    .expect("genuine current OCSP fixture must independently validate before HTTP");
    assert_eq!(checked.status, ocsp::CertStatus::Good);
    let server = local.serve(body, vec![], None);
    let limits = ResourceLimits {
        memory_bytes: 4 * 1024 * 1024,
        metadata_bytes: 1024 * 1024,
        ..ResourceLimits::default()
    };
    let engine = Engine::new(
        EngineServices::hash_only(limits.clone())
            .with_validation(services(vec![root.cert], network)),
    )
    .unwrap();
    let mut ctx = begin(
        &engine,
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let (result, peak) = measured(|| {
        engine.verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut Cursor::new(&document), None),
            None,
            &mut ctx,
        )
    });
    assert!(peak <= limits.memory_bytes as usize);
    let report = result.unwrap();
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    assert_eq!(report.signers[0].revocation, CheckStatus::Passed);
    assert_eq!(report.verdict, Verdict::Valid);
    assert!(server.hits.load(Ordering::SeqCst) >= 1);
}

#[test]
fn cancellation_during_real_pinned_status_body_remains_typed_not_unavailable() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let local = LocalStatus::bind();
    let network = local.policy();
    let root = entry("root-gost2015.key");
    let key = local_leaf(&root, &local.origin);
    let document = signed(&key);
    let control = Arc::new(Control::default());
    let server = local.serve(vec![0x30, 3, 0x0a, 1, 3], vec![], Some(control.clone()));
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_validation(services(vec![root.cert], network)),
    )
    .unwrap();
    let mut ctx = begin(&engine, OperationPolicy::strict_online(), control);
    let result = engine.verify(
        &VerifyRequest::cms(),
        Source::sequential(&mut Cursor::new(&document), None),
        None,
        &mut ctx,
    );
    assert!(matches!(
        result,
        Err(OperationError::Processing(ProcessingError::Cancelled))
    ));
    assert!(server.hits.load(Ordering::SeqCst) >= 1);
}

#[test]
fn layered_transports_deduplicate_exact_scope_clones_but_not_distinct_operations() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let local = LocalStatus::bind();
    let network = local.policy();
    let url = format!("{}/ocsp/transport-budget", local.origin);
    let expected = vec![0x71; 48 * 1024];
    let server = local.serve(expected.clone(), vec![], None);
    let limits = ResourceLimits {
        memory_bytes: 256 * 1024,
        metadata_bytes: 256 * 1024,
        ..ResourceLimits::default()
    };
    let shared = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let scope = shared
        .begin(limits.clone(), Arc::new(Control::default()))
        .unwrap();
    let transport = UreqTransport::default();
    let inner = oncl_pki::http::deadline::DeadlineTransport::new(&transport, &network, &scope);
    let outer = oncl_pki::http::deadline::DeadlineTransport::new(&inner, &network, &scope);
    let request = HttpRequest::get(
        &url,
        GetOptions {
            max_len: 64 * 1024,
            ..GetOptions::default()
        },
    );
    let response = outer
        .send_scoped(&request)
        .expect("same operation clones must not double-charge actual body/realloc capacity");
    assert_eq!(response.body(), expected);
    outer.finish().unwrap();
    inner.finish().unwrap();
    drop(response);
    drop(outer);
    drop(inner);
    drop(scope);
    drop(shared);

    let global = ResourceLimits {
        max_in_flight: 2,
        memory_bytes: 2 * 1024 * 1024,
        metadata_bytes: 2 * 1024 * 1024,
        ..ResourceLimits::default()
    };
    let shared = Arc::new(SharedBudget::new(global).unwrap());
    let a = shared
        .begin(
            ResourceLimits {
                max_in_flight: 2,
                ..limits.clone()
            },
            Arc::new(Control::default()),
        )
        .unwrap();
    let b = shared
        .begin(
            ResourceLimits {
                max_in_flight: 2,
                memory_bytes: 96 * 1024,
                ..limits
            },
            Arc::new(Control::default()),
        )
        .unwrap();
    let inner = oncl_pki::http::deadline::DeadlineTransport::new(&transport, &network, &b);
    let outer = oncl_pki::http::deadline::DeadlineTransport::new(&inner, &network, &a);
    assert!(outer.send_scoped(&request).is_err());
    assert!(
        matches!(outer.finish(), Err(ProcessingError::MemoryLimit)),
        "distinct operation B's smaller quota must survive to A even with the same SharedBudget"
    );
    assert!(
        matches!(inner.finish(), Err(ProcessingError::MemoryLimit)),
        "inner wrapper must retain the same concrete resource cause, not only the outer wrapper"
    );
    assert!(server.hits.load(Ordering::SeqCst) >= 2);
}

#[test]
fn layered_transports_preserve_inner_cancellation_and_earlier_deadline() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let local = LocalStatus::bind();
    let network = local.policy();
    let url = format!("{}/ocsp/layered-control", local.origin);
    let _server = local.serve(vec![0x30, 3, 0x0a, 1, 3], vec![], None);
    let transport = UreqTransport::default();
    for expired in [false, true] {
        let global = ResourceLimits {
            max_in_flight: 2,
            ..ResourceLimits::default()
        };
        let shared = Arc::new(SharedBudget::new(global.clone()).unwrap());
        let a = shared
            .begin(global.clone(), Arc::new(Control::default()))
            .unwrap();
        let control = Arc::new(Control::default());
        let b = shared
            .begin(
                ResourceLimits {
                    operation_timeout: if expired {
                        Duration::from_nanos(1)
                    } else {
                        Duration::from_secs(10)
                    },
                    ..global
                },
                control.clone(),
            )
            .unwrap();
        let inner = oncl_pki::http::deadline::DeadlineTransport::new(&transport, &network, &b);
        let outer = oncl_pki::http::deadline::DeadlineTransport::new(&inner, &network, &a);
        if expired {
            while !b.deadline().is_expired() {
                std::hint::spin_loop();
            }
        } else {
            control.0.store(true, Ordering::SeqCst);
        }
        assert!(
            outer
                .send_scoped(&HttpRequest::get(&url, GetOptions::default()))
                .is_err()
        );
        if expired {
            assert!(matches!(
                outer.finish(),
                Err(ProcessingError::DeadlineExceeded)
            ));
            assert!(matches!(
                inner.finish(),
                Err(ProcessingError::DeadlineExceeded)
            ));
        } else {
            assert!(matches!(outer.finish(), Err(ProcessingError::Cancelled)));
            assert!(matches!(inner.finish(), Err(ProcessingError::Cancelled)));
        }
    }
}

#[test]
fn layered_transports_do_not_replace_outer_authorized_address_pins() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let local = LocalStatus::bind();
    let outer_policy = local.policy();
    let inner_policy = NetworkPolicy::only_endpoints([&local.origin])
        .unwrap()
        .with_resolved_endpoint(
            &local.origin,
            vec![SocketAddr::from(([127, 0, 0, 2], local.address.port()))],
        )
        .unwrap();
    let url = format!("{}/ocsp/layered-pins", local.origin);
    let server = local.serve(vec![0x30, 3, 0x0a, 1, 3], vec![], None);
    let limits = ResourceLimits::default();
    let shared = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let scope = shared.begin(limits, Arc::new(Control::default())).unwrap();
    let transport = UreqTransport::default();
    let inner = oncl_pki::http::deadline::DeadlineTransport::new(&transport, &inner_policy, &scope);
    let outer = oncl_pki::http::deadline::DeadlineTransport::new(&inner, &outer_policy, &scope);
    assert!(
        outer
            .send_scoped(&HttpRequest::get(&url, GetOptions::default()))
            .is_err()
    );
    outer.finish().unwrap();
    inner.finish().unwrap();
    assert_eq!(server.hits.load(Ordering::SeqCst), 0);
}

#[test]
fn legacy_manual_proxy_status_keeps_absolute_form_and_admits_body_decode() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    for memory in [4 * 1024 * 1024, 256 * 1024 * 1024] {
        let local = LocalStatus::bind();
        let proxy = format!("http://{}", local.address);
        let root = entry("root-gost2015.key");
        let key = local_leaf(&root, &local.origin);
        let document = signed(&key);
        let server = local.serve(near_cap_body(), near_cap_body(), None);
        let transport = UreqTransport::with_proxy(oncl_pki::http::ProxySetting::Manual(proxy));
        let anchors = CaSet::new(vec![root.cert]);
        let limits = ResourceLimits {
            memory_bytes: memory,
            metadata_bytes: 256 * 1024 * 1024,
            operation_timeout: Duration::from_secs(10),
            ..ResourceLimits::default()
        };
        let shared = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        let scope = shared.begin(limits, Arc::new(Control::default())).unwrap();
        let context = oncl_pki::validation::ValidationContext {
            policy: oncl_pki::validation::ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &anchors,
            intermediates: &[],
            http: &transport,
        };
        let (result, peak) =
            measured(|| oncl_pki::validation::validate_cms(&document, None, &context, &scope));
        assert!(
            peak <= memory as usize,
            "actual legacy proxy body/decode allocated {peak} beyond {memory}"
        );
        if memory == 4 * 1024 * 1024 {
            assert!(matches!(
                result,
                Err(oncl_pki::validation::ValidationError::Processing(
                    ProcessingError::MemoryLimit
                ))
            ));
            assert!(server.hits.load(Ordering::SeqCst) >= 1);
        } else {
            let report = result.unwrap();
            assert_eq!(report.signers[0].signature, CheckStatus::Passed);
            assert_eq!(report.signers[0].chain, CheckStatus::Passed);
            assert_eq!(report.signers[0].revocation, CheckStatus::Unavailable);
            assert_eq!(report.verdict, Verdict::Indeterminate);
            assert!(server.hits.load(Ordering::SeqCst) >= 2);
        }
        assert!(
            server.absolute_form.load(Ordering::SeqCst),
            "legacy Manual proxy route must actually send the absolute URI to the proxy, not bypass it with pinned/direct routing"
        );
    }
}
