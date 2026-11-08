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
//! # Embedding
//!
//! The SDK needs no display session, daemon, listener, collector or updater. Depend on it by
//! git or path until a registry release exists (see `README.md`), with `features = ["full"]`
//! or only the features you use (`tokens`, `xml`, `pdf`, `jose`, `plugins`). The host supplies
//! the grant, key sources and the audit `KeyUseGuard`, trust anchors, an
//! `oncl_pki::http::HttpTransport`, the clock and cancellation; nothing is taken from a
//! request or a desktop setting. Runnable examples: `sign_file` and `verify_file` (detached CMS,
//! strict validation) and `custom_transport` (a host-written HTTP transport; with no network
//! strict signing fails closed before the key is applied). Semver, error stability, limits and
//! migration notes are in `docs/dev/sdk.md`.
//!
//! # Resource and ownership contract
//!
//! One engine creates one aggregate budget, not one per invocation. Multiple
//! engines in an application can share an `Arc<oncl_pki::resource::SharedBudget>`.
//! Each operation also enforces its own input/container/framing/output and live
//! memory/temp/metadata limits. Hash uses a reserved buffer of at most 256 KiB
//! and fixed SHA/GOST states; it never reads a document into memory wholesale.
//! The default control profile guarantees 1_073_741_824 document bytes (a larger
//! document is refused with an input-limit error), accounts 1_073_741_824 live
//! buffer bytes, 8_589_934_592 scratch bytes and 67_108_864 metadata bytes. These are accounting limits, not evidence of process RSS.
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
//! With the optional `xml` feature, `VerifyRequest::xml()` verifies an immutable
//! UTF-8 Source through indexed streaming C14N and every signer/reference, using
//! the same host validation services and original scope. Configure an explicit
//! TemporaryStore. `VerifyRequest::xml_kalkan()` selects existing Kalkan byte
//! compatibility explicitly; neither request chooses trust anchors or URL policy.
//! `VerificationReport::xml` owns immutable certificate/region/reference facts and
//! their reservations. Canonical hash work and evidence intake do not debit final
//! output; external evidence delivery and canonical writes do. This adds verify
//! only: default CMS behavior and SignRequest families remain unchanged.
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
//! This is not a full 1-GiB/RSS or platform-matrix acceptance run.
//!
//! # Bounded JOSE (`jose` feature)
//!
//! `Engine::jws_create`, `jws_add`, and `jws_verify` accept explicit
//! `jose::JoseProfile` serialization/detachment and bounded borrowed bytes.
//! Compact, flattened/general JSON and detached base64url payloads use RS256 or
//! the pinned `ECGOST3410-2015-512` profile. Add verifies every old signature and
//! host trust before opening new keys; private work uses `Action::Sign`, never a
//! prehashed privilege. Legacy AcBank wire formatting is unchanged.
//!
//! `jwt_encode`, `jwt_decode_unverified`, and `jwt_verify` are distinct operations.
//! Decode needs `Action::Extract` and never reports verification. Verify needs
//! `Action::Verify` plus a trusted `jose::JwtValidationPolicy::new(fixed_now)`:
//! exp is required, leeway is zero, `now == exp` is invalid, `now == nbf` is valid.
//! Representable negative NumericDates/clocks follow those same boundaries;
//! iat is type/range-checked, not an inferred freshness policy.
//! Expected issuer/audience, clock, roots, algorithm/key authority and network
//! policy come only from the host. Crypto, certificate trust and claims are
//! reported separately; valid crypto cannot hide invalid claims/unknown status.
//!
//! Payload/header/claims/container bounds and unsupported extensions are
//! documented in `jose`. Parsed/reported buffers retain original quota/root guards.
//! Signature/x5c collection admission rejects the ninth entry before parsing it.
//! Token candidate limits do not cap the host root store: admitted PKIX borrows
//! configured roots and charges actual key scratch/selected copies to the scope.
//! These bounded token APIs do not claim large
//! XML/PDF or whole-platform acceptance.
//! `cargo run -p oncl-core --features jose --example sdk_probe -- --case J01 --out <directory>`
//! emits public standard JWS/JWT/Add/detached artifacts and runs independent
//! OpenSSL RS256 positive/negative controls (OpenSSL must be on PATH).
//!
//! # Public inspection and standalone timestamps
//!
//! `Engine::inspect` requires `Action::Inspect`, never signing permission.
//! Certificate and CMS structural inspection need no key provider, temporary
//! store, validation services or network. Container inspection additionally
//! requires exact host-granted aliases and a borrowed password; secrets are
//! read into bounded zeroizing memory only, never `TemporaryStore`. PKCS#12
//! metadata checks a present MAC/opens encrypted safes without decrypting or
//! importing private-key bags; absent MAC is explicitly `NotPresent`.
//! JKS skips protected keys entirely.
//! Known-length secret intake reserves a fallible replacement of that bounded
//! capacity; unknown-length intake grows geometrically. Old and new live
//! capacities are admitted together, and the old owner is explicitly wiped
//! before deallocation. Retained capacity remains charged to the original scope.
//!
//! `EngineServices::with_metadata_provider` configures a separate
//! `ReadMetadataProvider`; `keys::KeySources` implements it. Exact source/named
//! key grants are checked before the provider, secret or card. Named IDs refer
//! to immutable host slots, not client-asserted certificate fingerprints.
//! The optional token path reads only the authorized slot's public certificate
//! in a fresh scoped transaction, with no `TokenKey`/PIN cache or signing guard.
//! Every returned metadata owner is checked against the original operation.
//!
//! Host `InspectionLimits` defaults bound each KDF to 10,000 iterations and
//! aggregate derivations to 100,000 iteration-block units, at most 64 safes,
//! 4096 bags/entries, 1024 salt bytes and 4096 password UTF-8 bytes. A validated
//! `with_inspection_limits` host profile may explicitly increase work up to
//! the existing legacy iteration ceiling. Resource refusal is MetadataLimit,
//! not an assertion that the store is malformed. Legacy load policy is unchanged.
//! Password encodings are admitted before allocation, bag counts before owned
//! collections, and KDF work before derivation; checkpoints separate bounded
//! synchronous KDF calls. Such calls can overshoot a deadline by one admitted
//! KDF, not promise hard-real-time preemption. Conservative 64x input plus fixed
//! decode/output admission is retained with immutable public metadata.
//!
//! `stamp(StampRequest::new(TsaSpec), Source, output, ctx)` needs the separate
//! `Action::Stamp` and real host `ValidationServices`; the explicit spec has
//! no implicit TSA endpoint. Host network policy/pins still authorize it.
//! Carried `verify_stamp` needs only validation services, `VerifyStamp`, and
//! an explicit expectation request, never issuance configuration. Both reuse
//! TSP cryptography and F03/F04 anchored path/current status at genTime.
//! No local user private key or auto-consent guard is used. HTTP body/decode
//! admission and fatal resource/cancel/deadline causes retain the same root.
//! Ordinary TSA transport failures retain their HTTP cause and report `Io`;
//! malformed tokens and nonce/policy/imprint protocol failures remain InvalidInput.
//!
//! A timestamp report distinguishes token signature/EKU/path/validity/current
//! revocation, expectation checks, current host clock, genTime, algorithm and
//! document imprint. Absent data is `NotProvided`/Indeterminate, never Matched
//! or a viewed-document claim. Retained canonical tokens/facts/metadata expose
//! borrowed immutable buffers only, without Clone/Default or detachable permits.
//! An issuance followed by output failure may already have happened remotely:
//! no exactly-once or rollback assertion is made. Arbitrary sinks may retain a
//! prefix; token input is not charged as document output.
//!
//! `cargo run -p oncl-core --example sdk_probe -- --case I01 --out <directory>`
//! exercises real loopback pinned HTTP TSA/OCSP/CRL and file Sources, emits only
//! public artifacts, and checks original/altered/untrusted controls with OpenSSL.
//! This synthetic RSA/RFC3161 check is not NCA trust, hardware or V01 large-file
//! XML/PDF/RSS/platform acceptance.

//! # Closed, sequential batches
//!
//! `Engine::capture_batch` admits at most 1024 uniquely named typed items
//! (IDs are 1..=128 UTF-8 bytes). It consumes at most one additional iterator
//! element to reject an oversized plan, never an unbounded queue. Public document
//! readers, including nested detached Add/extension and timestamp token/data
//! readers, become immutable `FrozenInput` snapshots in the explicit host store.
//! JOSE/already-bounded CMS byte APIs retain immutable borrows instead of copying
//! documents. Key containers/passwords are never document-spooled: inspection
//! prepares only bounded public metadata under the original inspection grant.
//!
//! Capture resolves permitted signing keys into this context's opaque leases
//! before confirmation, pinning the exact certificate rather than reopening a
//! file/slot after confirmation. `CapturedBatch::items` lends source SHA-256/byte
//! identities, action/profile and exact key/certificate bindings for host review.
//! Only the trusted host calls `CapturedBatch::authorize`; do not map this to
//! an untrusted request flag or auto-answer a desktop confirmation. The resulting
//! non-Clone approval is bound to this exact closed plan/engine/operation/root.
//! `run_batch(plan, approval, ctx, emit)` consumes both. Pairing an old approval
//! with recaptured bytes, requests, keys, order or IDs is `ConsentMismatch`
//! before execution I/O/private use. Neither value permits replacement inputs.
//!
//! Capture, confirmation, dispatch and retained results share the original
//! aggregate quotas, deadline, control and root; no item starts a fresh context.
//! Approval and run compare the complete original scope identity, rejecting safe
//! resource-scope replacement before callbacks or admission. Borrowed CMS/JOSE
//! capture checks concrete format caps and remaining aggregate allowance before
//! scanning, charges each captured chunk, and lends only a private exact-slice,
//! original-scope replay proof during closed dispatch. Result slots are admitted
//! during capture, so cancellation before run still returns explicit NotRun facts.
//! A final source checkpoint after successful signing preserves actual Applied
//! state and the original execution cause instead of implying a private rollback.
//! Progress is cumulative resource intake/output, including prior capture;
//! authenticated replay is not charged again. Existing format reports retain
//! their resource-delta semantics; `BatchItemResult::sources` separately retains
//! the exact complete captured source sizes/digests. The run's total is the
//! actual closed plan length, not a guessed iterator size hint.
//!
//! Results distinguish completed reports (including Invalid verification),
//! actual errors with NotApplied/Applied/Unknown, and explicit NotRun items.
//! Local malformed/unavailable inputs preserve earlier results and can continue;
//! quota/control/guard/audit failures stop the batch and permanently stop new
//! private use in that context. Hash/verification remain independent of private
//! authority. A new legitimate context never inherits an unlocked lease or this
//! local stop latch. No rollback, retry, idempotency or exactly-once is promised.
//! Result/event collections keep their original reservations/root. Event
//! callbacks borrow immutable results; use the shared control for cancellation.
//! Audit events expose only the closed zero-based `BatchItemOrdinal`, identical
//! across every signer in that item, and None for nonbatch use. Correlation is
//! restored before callbacks and even when trusted host guard code unwinds.
//!
//! `sdk_probe --case B01 --out <directory>` exercises actual files, mixed CMS
//! sign/verify plus an unavailable source, cancellation after the first real
//! output, exact private/key-open counts, absent unexecuted outputs, and positive
//! and altered-negative OpenSSL controls. It is not large-file/platform or NCA
//! trust acceptance.
//!
pub mod activity;
pub mod batch;
mod cades;
mod context;
mod engine;
mod error;
mod inspect;
#[cfg(feature = "jose")]
pub mod jose;
pub mod keys;
mod output;
#[cfg(feature = "pdf")]
mod pades;
#[cfg(feature = "plugins")]
pub mod plugins;
mod policy;
mod report;
mod request;
mod sign;
mod timestamp;
#[cfg(feature = "xml")]
mod xml;

pub use cades::{CadesConfiguration, ExtendRequest};
pub use context::{OperationContext, OperationId};
pub use engine::{Engine, EngineServices, HashReport, OperationAdmission};
pub use error::{ErrorCode, OperationError};
pub use inspect::{
    InspectRequest, InspectionKind, InspectionReport, ReadMetadataProvider, SignatureMetadata,
};
pub use policy::{Action, ExecutionGrant, OperationPolicy};
pub use report::{ExtractionReport, ValidationServices, VerificationReport};
pub use request::{SignProfile, SignRequest, VerifyProfile, VerifyRequest};
pub use sign::{OperationReport, SignProvenance};
pub use timestamp::{StampRequest, StampVerifyRequest, TimestampReport};
