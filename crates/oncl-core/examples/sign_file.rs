//! Signs a file with a detached CMS (CAdES-compatible `SignedData`) through the SDK, no desktop,
//! daemon, display or listener involved.
//!
//! ```text
//! cargo run -p oncl-core --example sign_file -- [WORKDIR [FILE]]
//! cargo run -p oncl-core --example verify_file -- WORKDIR FILE
//! ```
//!
//! The first run issues a throwaway RSA PKI into `WORKDIR` (see `support`) and writes
//! `FILE.p7s` next to the document. `verify_file` then checks that signature. Without arguments
//! a fresh directory under the system temporary directory and a sample document are used.
//!
//! What the embedding host provides, and the SDK never takes from the wire or from a UI:
//! the grant (`ExecutionGrant`: which actions and which key ids), the key container and its
//! password, trust anchors and the status transport (`ValidationServices`), the clock, the key
//! use guard that audits the private-key application, and cancellation.
mod support;

use oncl_core::keys::KeyRequest;
use oncl_core::{Action, ExecutionGrant, OperationPolicy, SignRequest};
use oncl_pki::io::Source;
use std::{fs::File, sync::Arc};
use support::{AuditGuard, NeverCancelled, PASSWORD};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let dir = support::work_dir(args.next(), "sign");
    let pki = support::open_or_create(&dir);
    let file = match args.next() {
        Some(file) => file.into(),
        None => {
            let sample = dir.join("document.txt");
            std::fs::write(
                &sample,
                b"A document signed through the OpenNCALayer SDK.\n",
            )?;
            sample
        }
    };

    // The CA's CRL distribution point stands in for the network.
    let transport: Arc<dyn oncl_pki::http::HttpTransport> =
        Arc::new(oncl_pki::http::RouteTransport::new(vec![(
            support::CRL_ORIGIN.to_owned(),
            Arc::new(pki.crl_responder()),
        )]));
    let guard = Arc::new(AuditGuard::default());
    let engine = support::engine(&pki, guard.clone(), transport);

    let key = pki.user_key();
    let mut ctx = engine.begin(
        ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
        OperationPolicy::strict_online(),
        Arc::new(NeverCancelled),
    )?;

    let mut input = File::open(&file)?;
    let len = input.metadata()?.len();
    let mut signature = Vec::new();
    let report = engine.sign(
        // `false`: a detached signature; the document stays a separate file.
        SignRequest::cms_create(vec![KeyRequest::new(&key, Some(PASSWORD))], false),
        Source::sequential(&mut input, Some(len)),
        &mut signature,
        &mut ctx,
    )?;

    let mut out = file.clone().into_os_string();
    out.push(".p7s");
    std::fs::write(&out, &signature)?;
    println!(
        "signed {} bytes of {} -> {} ({} bytes of CMS); work dir {}",
        report.bytes_in,
        file.display(),
        std::path::Path::new(&out).display(),
        report.bytes_out,
        dir.display()
    );
    assert_eq!(guard.lines.lock().unwrap().len(), 2, "one audited key use");
    Ok(())
}
