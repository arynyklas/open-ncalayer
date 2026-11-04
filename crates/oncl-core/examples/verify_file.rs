//! Verifies a detached CMS signature made by `sign_file`: integrity, anchored chain, validity
//! and mandatory revocation status are reported separately, and the process exits non-zero
//! unless the verdict is `Valid`.
//!
//! ```text
//! cargo run -p oncl-core --example sign_file -- WORKDIR FILE
//! cargo run -p oncl-core --example verify_file -- WORKDIR FILE
//! ```
//!
//! Verification needs no key, no key-use guard and no temporary store, only the host's trust,
//! transport and clock. Altering `FILE` after signing makes the verdict `Invalid`.
mod support;

use oncl_core::{Action, ExecutionGrant, OperationPolicy, VerifyRequest};
use oncl_pki::{io::Source, validation::Verdict};
use std::{fs::File, process::ExitCode, sync::Arc};
use support::{AuditGuard, NeverCancelled};

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(dir), Some(file)) = (args.next(), args.next()) else {
        eprintln!("usage: verify_file WORKDIR FILE  (run sign_file with the same arguments first)");
        return Ok(ExitCode::from(2));
    };
    let dir = std::path::PathBuf::from(dir);
    let pki = support::DemoPki::open(&dir);
    let transport: Arc<dyn oncl_pki::http::HttpTransport> =
        Arc::new(oncl_pki::http::RouteTransport::new(vec![(
            support::CRL_ORIGIN.to_owned(),
            Arc::new(pki.crl_responder()),
        )]));
    let engine = support::engine(&pki, Arc::new(AuditGuard::default()), transport);
    let mut ctx = engine.begin(
        ExecutionGrant::new([Action::Verify]),
        OperationPolicy::strict_online(),
        Arc::new(NeverCancelled),
    )?;

    let mut signature_path = std::ffi::OsString::from(&file);
    signature_path.push(".p7s");
    let mut signature = File::open(&signature_path)?;
    let mut document = File::open(&file)?;
    let report = engine.verify(
        &VerifyRequest::cms(),
        Source::sequential(&mut signature, None),
        Some(Source::sequential(&mut document, None)),
        &mut ctx,
    )?;

    println!("verdict: {:?} at {}", report.verdict, report.checked_at);
    for (index, signer) in report.signers.iter().enumerate() {
        println!("signer {index}: {signer:?}");
    }
    Ok(if report.verdict == Verdict::Valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}
