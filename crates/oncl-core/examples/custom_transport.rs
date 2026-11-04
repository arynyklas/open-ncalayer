//! Plugs a host-written HTTP transport into the SDK.
//!
//! PKI network access (CRL downloads, OCSP, RFC 3161 time-stamps) goes through the
//! `oncl_pki::http::HttpTransport` trait. The default `UreqTransport` is only one implementation:
//! an embedding application that has its own HTTP stack, proxy rules, mTLS or test double
//! implements `send` and hands it to `ValidationServices`. The transport is trusted host code,
//! not a sandbox: the SDK limits what may be requested (`NetworkPolicy`, the operation deadline,
//! response size in `GetOptions`) but cannot preempt a `send` that ignores its options.
//!
//! This example counts requests, enforces its own host allow-list, answers CRL downloads from an
//! in-process distribution point (no network), and then switches the "network" off to show that
//! strict signing fails closed: the key is never applied when revocation status cannot be
//! established, and the audit guard sees no use.
//!
//! ```text
//! cargo run -p oncl-core --example custom_transport
//! ```
mod support;

use oncl_core::keys::KeyRequest;
use oncl_core::{Action, ErrorCode, ExecutionGrant, OperationPolicy, SignRequest};
use oncl_pki::http::{HttpError, HttpErrorKind, HttpMethod, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::io::Source;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use support::{AuditGuard, NeverCancelled, PASSWORD};

/// The host's transport. A real one would call its own HTTP client inside `send`.
struct HostTransport {
    /// What answers a CRL download; stands in for the host's HTTP client.
    upstream: Arc<dyn HttpTransport>,
    requests: AtomicUsize,
    online: AtomicBool,
}

impl HttpTransport for HostTransport {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        if !self.online.load(Ordering::SeqCst) {
            return Err(HttpError::new(
                HttpErrorKind::Connect,
                "host network is down",
            ));
        }
        // The host's own policy, on top of the SDK's `NetworkPolicy`.
        if !request.url.starts_with(support::CRL_ORIGIN) {
            return Err(HttpError::other("host policy: origin not allowed"));
        }
        // Honour the request's limits: a transport that ignores them defeats the SDK's bounds.
        let reply = match request.method {
            HttpMethod::Get => self.upstream.send(request)?,
            // OCSP and RFC 3161 are POSTs; this host serves neither.
            HttpMethod::Post => return Err(HttpError::other("POST is not served here")),
        };
        if reply.body.len() as u64 > request.opts.max_len {
            return Err(HttpError::other("reply exceeds the request's max_len"));
        }
        Ok(reply)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = support::work_dir(None, "transport");
    let pki = support::open_or_create(&dir);
    let transport = Arc::new(HostTransport {
        upstream: Arc::new(pki.crl_responder()),
        requests: AtomicUsize::new(0),
        online: AtomicBool::new(true),
    });
    let guard = Arc::new(AuditGuard::default());
    let engine = support::engine(&pki, guard.clone(), transport.clone());
    let key = pki.user_key();

    let sign = |ctx: &mut oncl_core::OperationContext| {
        let mut data = &b"custom transport demo"[..];
        engine.sign(
            SignRequest::cms_create(vec![KeyRequest::new(&key, Some(PASSWORD))], false),
            Source::sequential(&mut data, Some(21)),
            &mut Vec::new(),
            ctx,
        )
    };
    let begin = || {
        engine.begin(
            ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(NeverCancelled),
        )
    };

    // 1. Network up: the CRL comes through the host's transport and signing succeeds.
    let mut ctx = begin()?;
    let bytes_out = sign(&mut ctx)?.bytes_out;
    let used = transport.requests.load(Ordering::SeqCst);
    println!("online: signed, {bytes_out} CMS bytes, {used} transport request(s)");
    assert!(
        used >= 1,
        "revocation status travelled through the host transport"
    );
    assert_eq!(guard.lines.lock().unwrap().len(), 2);
    // The default budget admits one operation at a time: drop the context (and any report)
    // before the next admission.
    drop(ctx);

    // 2. Network down: strict validation cannot establish status, so the key is not applied.
    transport.online.store(false, Ordering::SeqCst);
    let mut ctx = begin()?;
    let error = sign(&mut ctx).expect_err("status unavailable");
    println!(
        "offline: refused with {:?} ({:?})",
        error.code(),
        error.applied_state()
    );
    assert_ne!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        error.applied_state(),
        oncl_core::keys::AppliedState::NotApplied,
        "no private key use without validated status"
    );
    assert_eq!(
        guard.lines.lock().unwrap().len(),
        2,
        "no second audited use"
    );
    Ok(())
}
