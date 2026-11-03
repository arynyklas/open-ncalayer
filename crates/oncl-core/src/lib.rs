//! Runtime-independent streaming SDK. Only complete operation families are exposed.
//!
//! ```
//! use oncl_core::{Action, Engine, EngineServices, ExecutionGrant, OperationPolicy};
//! use oncl_pki::{io::Source, key::HashAlg};
//! use oncl_pki::resource::{OperationControl, ProcessingError, Progress, ResourceLimits};
//! use std::sync::Arc;
//! struct HostControl;
//! impl OperationControl for HostControl {
//!     fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> { Ok(()) }
//! }
//! let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default()))?;
//! let mut ctx = engine.begin(ExecutionGrant::new([Action::Hash]),
//!     OperationPolicy::strict_online(), Arc::new(HostControl))?;
//! let mut input = &b"abc"[..];
//! let report = engine.hash(HashAlg::Sha256, Source::sequential(&mut input, Some(3)), &mut ctx)?;
//! assert_eq!(report.bytes_in, 3);
//! # Ok::<(), oncl_core::OperationError>(())
//! ```
//!
//! # Resource and ownership contract
//!
//! One engine creates one aggregate budget, not one per invocation. Multiple
//! engines in an application can share an `Arc<oncl_pki::resource::SharedBudget>`.
//! Each operation also enforces its own input/container/framing/output and live
//! memory/temp/metadata limits. Hash uses a reserved buffer of at most 256 KiB
//! and fixed SHA/GOST states; it never reads a document into memory wholesale.
//! The default control profile admits 10_737_418_240 document bytes, accounts
//! 1_073_741_824 live buffer bytes, 68_719_476_736 scratch bytes and 67_108_864
//! metadata bytes. These are accounting limits, not evidence of process RSS.
//!
//! Contexts are owned and Send. Grants come from trusted host code, not wire
//! deserialization. Move a context into its worker; retain its root lease for a
//! pending response/output. Dropping a request cannot release live worker or
//! artifact reservations. A finite monotonic deadline starts at admission and is
//! never restarted. Host cancellation and deadline errors differ from each other
//! and from any future signature verdict. Synchronous I/O must provide its own
//! interruptibility; the SDK checks before/after calls but cannot preempt them.
//!
//! Staged document output is unpublished until explicit `commit` or `copy_to`.
//! No key/password spooling, persistent document queue, or temporary store is
//! required by the hash-only engine. See `oncl_pki::io` for private spool and
//! same-filesystem no-clobber publication semantics.
//!
//! # Scoped explicit-prehash private operations
//!
//! Configure `EngineServices::with_keys` with a real `keys::KeySources` (or a
//! trusted host `KeyProvider`) and an explicit `KeyUseGuard`. Grant the particular
//! source/alias IDs and `Action::SignDigest`, and explicitly opt into
//! `OperationPolicy::allow_prehashed` before calling `Engine::signer`.
//! File/inline PKCS#12 and JKS, immutable host-named sources, and optional `tokens`
//! are supported. Password/PIN requests have no Debug/serialization; unlocked
//! leases and token secrets belong to the context, never a desktop-global cache.
//! A signer borrows the context, exports no private material, and rechecks host
//! consent/audit before every application, including through the PKI DigestSigner
//! trait. Errors retain NotApplied/Applied/Unknown independently of delivery.
//!
//! This explicit caller-prehash authority is not a shortcut for future internally
//! hashed document-format operations. Strict and offline private use both require
//! real ValidationServices: current anchored chain, validity, key usage and
//! mandatory revocation are checked before each guard/key application. Missing
//! or unavailable required validation fails closed, without changing legacy WSS.
//! Native token calls remain cooperative: workers retain their original resource
//! root until native return. `sdk_probe keys` uses synthetic fixtures only.
//!
//! # Bounded shared validation
//!
//! Configure `EngineServices::with_validation` with host anchors, untrusted chain
//! candidates, clock and approved PKI endpoints. `Action::Validate` authorizes
//! `Engine::validate_cms` for bounded existing CMS containers. `Action::Verify`
//! authorizes `Engine::verify(VerifyRequest::cms(), Source, ...)` for sequential
//! or seekable DER/BER with bounded metadata, without buffering eContent.
//! Reports distinguish signature integrity, anchored chain, validity, mandatory
//! revocation, TSA proof and claimed time. `Action::Extract` authorizes raw CMS
//! extraction without verification; arbitrary sinks may retain partial output.
//! OfflineReport never fetches live status or calls unavailable status Valid.
//! Historical proof also requires current status evidence for the TSA's anchored
//! path, evaluated at genTime; a crypto-only token is not trusted proof.
//! Owned validation results expose `ScopedSigners`: an immutable, non-Clone
//! collection that owns its result/reason capacity and original reservations.
//! Moving that whole collection preserves its memory/metadata and admission
//! lifetime; raw mutable vectors and independent permits are not exposed.
//! Drop the completed context and the last scoped collection owner before a
//! separate admission under a single-operation budget. Retained results are
//! not free memory, including after their enclosing report has been discarded.
//! Actual Ureq DNS-name endpoints require operator-supplied SocketAddr pins;
//! literal-IP endpoints pin themselves. Redirects need their own authorization.
//! Custom transports are trusted host code, not a sandbox. Scoped PKI transport
//! caps network waits to the original operation deadline; it cannot forcibly
//! preempt arbitrary host HttpTransport code that ignores synchronous limits.
//!
//! # Source-bound signing
//! `SignRequest` is consumed by `Engine::sign`: CMS Create/Add and raw message
//! signing require `Action::Sign`, not prehash permission. Explicit raw digests
//! require `SignDigest` plus `allow_prehashed` and report ProvidedDigest provenance.
//! New private operations always run strict host validation. Attached signing and
//! Add use only an explicit host `TemporaryStore`; hash-only services stay pure.
//! Arbitrary writers may retain a prefix on failure. Use `Engine::sign_staged`
//! for an empty same-operation output artifact: it chooses one output-accounting
//! owner, never a writer adapter that double debits a stage. No artifact publishes
//! implicitly; commit only a completed result. Errors preserve prior key use.
//!
//! # CAdES baseline signatures
//! `SignRequest::cades_create` and `SignRequest::cades_add` take explicit
//! `oncl_pki::evidence::EvidenceLimits` independently of TSA issuance settings.
//! `VerifyRequest::cades` takes the required minimum and the same explicit reader
//! limits. Configure host validation/trust/network and temporary storage for
//! these operations. Baseline B creation, carried verification and B co-signing
//! do not require `CadesConfiguration`. Acquiring T/LT/LTA requires an explicit
//! `EngineServices::with_cades`; absence is `MissingCadesConfiguration` before
//! private application, not missing validation or an algorithm fallback.
//!
//! `Engine::extend` / `extend_staged` require the separate non-private
//! `Action::Extend`. `ExtendRequest::cms` carries the target, optional detached
//! source, public validation material and reader limits. Extension checks all
//! existing signatures/proofs, preserves original signed fields/signature
//! octets, and never applies a local private key. New signing/co-signing remains
//! guarded and reports Applied/Unknown truthfully after a private-use failure.
//! The container level is the verified minimum across all signers; each scoped
//! signer reports its own level. A bad present archive never becomes Valid B/T.
//!
//! The archive profile is EN 319 122-1 V1.3.1 archiveTimestampV3
//! (`0.4.0.1733.2.4`) with ATSHashIndexV3 (`0.4.0.19122.1.5`), currently SHA-256
//! only. It is not historical v2 CAdES-A. RSA and GOST source signatures use
//! their existing actual backends; SHA-256 archive hashing does not change the
//! source signature algorithm. Signing-time is a claim, not proof of existence.
//! TSA signature, anchored path and fresh status at the verified proof time are
//! mandatory. Indexed bytes and predecessor proofs are checked against one
//! common bounded evidence store; unrelated later root additions are not
//! silently promoted into protected evidence.
//!
//! `cargo run -p oncl-core --example sdk_probe -- --case C03 --out <directory>`
//! runs a bounded synthetic loopback TSA/OCSP/CRL exercise and emits only public
//! RSA B/T/LT/LTA, detached/multisigner, extension/Add and negative artifacts.
//! This is not a full 10-GiB/RSS or platform-matrix acceptance run.

mod cades;
mod context;
mod engine;
mod error;
pub mod keys;
#[cfg(feature = "pdf")]
mod pades;
mod policy;
mod report;
mod request;
mod sign;

pub use cades::{CadesConfiguration, ExtendRequest};
pub use context::{OperationContext, OperationId};
pub use engine::{Engine, EngineServices, HashReport};
pub use error::{ErrorCode, OperationError};
pub use policy::{Action, ExecutionGrant, OperationPolicy};
pub use report::{ExtractionReport, ValidationServices, VerificationReport};
pub use request::{SignProfile, SignRequest, VerifyProfile, VerifyRequest};
pub use sign::{OperationReport, SignProvenance};
