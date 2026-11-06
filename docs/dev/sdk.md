# The Rust SDK: embedding, features, stability, publication readiness

`oncl-core` is the embeddable SDK of OpenNCALayer: typed, streaming signing, verification,
validation, inspection and time-stamping over files and byte streams, with trust, keys, clock,
network, audit and resource limits owned by the host application. It has no UI, daemon,
listener, collector, installer or self-update and needs no display session. The standalone
`oncl` CLI and the `oncl-server` HTTP service are consumers of the same engine, not parts of the
SDK closure.

This page is the contract of the SDK as delivered. The design is in
[`../design/platform.md`](../design/platform.md); the crate README is
[`../../crates/oncl-core/README.md`](../../crates/oncl-core/README.md).

## 1. Using it today (no registry release)

Nothing is published to crates.io, and the documentation never asks you to `cargo add` a
registry version. Whether the `oncl-*` crate names are free or owned on crates.io has **not**
been verified. Depend on a reviewed tag or commit by path or git. The SDK is built against two
locally modified RustCrypto crates (`vendor/streebog`, `vendor/hmac`: additive secret-input
variants), so the consumer carries the same `[patch.crates-io]`:

```toml
[dependencies]
oncl-core = { path = "open-ncalayer/crates/oncl-core", features = ["full"] }

[patch.crates-io]
streebog = { path = "open-ncalayer/vendor/streebog" }
hmac = { path = "open-ncalayer/vendor/hmac" }
```

For git, give every entry the same `git` URL and `rev`. `cargo xtask sdk smoke` (section 7)
builds a consumer exactly this way, from unpacked source packages instead of the workspace.

## 2. Features and dependency closure

`oncl-core` has no default features (`--no-default-features` is the minimal SDK). The closure is
the normal, non-proc-macro dependency graph reported by `cargo xtask sdk closure`
(`cargo tree -p oncl-core --no-default-features [--features F] -e normal`, Windows host):

| feature set | crates | `oncl-*` crates in it |
|---|---|---|
| minimal | 92 | oncl-core, oncl-gost, oncl-pki, oncl-registry |
| `tokens` | 99 | + oncl-token |
| `xml` | 95 | + oncl-xml |
| `pdf` | 95 | + oncl-pdf |
| `jose` | 97 | (no further `oncl-*` crate; adds base64, serde, serde_json) |
| `plugins` (implies `xml`) | 149 | + oncl-flows, oncl-pdk, oncl-plugin, oncl-protocol, oncl-token, oncl-xml |
| `full` | 150 | all of the above, + oncl-pdf |

No set contains Slint, winit, tokio, axum, hyper, velopack, tray-icon, rfd, webbrowser or any
`oncl-ui`, `oncl-desktop`, `oncl-api`, `oncl-server`, `oncl-cli`, `openncalayer`, `oncl-nmhost`;
`cargo xtask sdk closure` fails if one appears. `oncl-update` is not in `full`: it enters only
through `oncl-plugin`'s own `distribution` feature (the plugin package store), which is a
separate opt-in of that crate and is checked separately (its tests, and its place in the
publish chain below).

| feature | what it adds |
|---|---|
| (minimal) | hashing, CMS/CAdES B/T/LT/LTA, PKI validation, keys from files / inline PKCS#12 / JKS / host-named slots, batches, inspection, standalone time-stamps |
| `tokens` | hardware tokens and ID cards as key sources |
| `xml` | XMLDSig, XAdES, WS-Security sign / add / verify |
| `pdf` | PAdES sign / verify |
| `jose` | JWS and JWT create / add / verify |
| `plugins` | headless WebAssembly plugin host (runtime only, operator grants) |
| `full` | all of the above |

Encryption and decryption are not part of the SDK yet: they wait for the Kazakhstan GOST
encryption backend and are not replaced by an RSA-only path.

## 3. The embedding API in one page

An application builds one `Engine` and admits one context per operation:

```text
EngineServices::hash_only(limits)            // host services, nothing global
    .with_keys(provider, guard)              // key sources + the audit guard
    .with_validation(ValidationServices)     // trust anchors, status transport, clock
    .with_temporary_store(store)             // only for operations that must stage bytes
    .with_cades(...) / .with_plugins(...)    // optional
Engine::new(services)?
engine.begin(ExecutionGrant, OperationPolicy, Arc<dyn OperationControl>)? -> OperationContext
engine.sign / verify / hash / inspect / extend / stamp / ... (request, Source, output, &mut ctx)
```

The seams the host owns (none is read from the wire, a UI or a desktop setting):

| seam | type | notes |
|---|---|---|
| permission | `ExecutionGrant` | actions and key ids, from trusted host code only |
| keys | `KeyProvider` (`keys::KeySources` for files/inline/named/tokens) | secrets are borrowed, zeroized, never spooled |
| audit | `KeyUseGuard` | `before_use` must record durably **before** the private key is applied; failing refuses the use; `finish` records the outcome |
| trust, status | `ValidationServices` (anchors, intermediates, `HttpTransport`, `NetworkPolicy`, clock) | strict policies fail closed without status |
| transport | `oncl_pki::http::HttpTransport` | CRL / OCSP / RFC 3161; `UreqTransport` is only the default; see example `custom_transport` |
| clock | `Arc<dyn Fn() -> OffsetDateTime>` | injected, so verdicts are reproducible |
| cancellation, progress | `OperationControl` | checkpoints; blocking I/O must be interruptible by the host |
| temporary storage | `TemporaryStore` | bounded, private; never holds keys or passwords |

Runnable examples (`cargo run -p oncl-core --example <name>`; they issue a throwaway RSA PKI at
run time, use no network and commit no key):

- `sign_file [WORKDIR [FILE]]` and `verify_file WORKDIR FILE`: a detached CMS signature under
  strict validation; `verify_file` exits 1 for an altered document.
- `custom_transport`: a host `HttpTransport` plugged into validation; with the network down the
  strict signature is refused with `NotApplied`.

`tests/examples.rs` runs these as real processes, so they cannot rot.

## 4. Result and error contracts

**Verdict.** `Verdict::{Valid, Invalid, Indeterminate}` is the answer about a signature, never an
execution failure. A report separates signature integrity, anchored chain, validity,
revocation, timestamp proof and claimed signing time (`CheckStatus::{Passed, Failed,
Unavailable, NotApplicable}`); missing evidence is `Unavailable`/`Indeterminate`, never
`Valid`. Cancellation, deadline and resource errors are errors, not verdicts.

**AppliedState.** Every failure after a private-key operation may have started carries
`NotApplied`, `Applied` or `Unknown` (`OperationError::applied_state`). The SDK never promises
rollback, retry or exactly-once: a time-stamp already issued remotely, or a signature computed
before the output sink failed, stays as it happened. A guard that fails in `finish` after the
key was applied reports `Applied`.

**Errors.** `OperationError` (the typed error) and `ErrorCode` (`OperationError::code`, stable
machine-readable categories, never inferred from messages) are public. Stability stance for the
pre-1.0 alphas: hosts must match `ErrorCode` with a wildcard arm. Today neither enum is
`#[non_exhaustive]`, so adding a variant is a source-breaking change; it is listed in the
migration notes of the release that makes it. Making both `#[non_exhaustive]` is the intended
change for the first release that needs a new code; it is deliberately not done inside this
delivery because it also changes every in-workspace consumer's matches. Variant `Display`
text is for logs, not for control flow.

**Reports own their reservations.** Results retained by the host (`ScopedSigners`, staged
output, batch results) keep their memory/metadata reservations and the original operation
scope; drop them before the next admission under the default single-operation budget (the
examples do).

## 5. Limits

`ResourceLimits::default()` (the engine's default profile; the host may change it):

| limit | default |
|---|---|
| operations in flight | 1 |
| document input | 10_737_418_240 bytes (10 GiB) |
| container (CMS/XML/PDF structure) | 1_073_741_824 |
| framing | 67_108_864 |
| output | 11_878_268_928 |
| live accounted memory | 1_073_741_824 (1 GiB) |
| scratch (temporary storage) | 68_719_476_736 |
| metadata | 67_108_864 |
| operation deadline | 300 s from admission, never restarted |

These are accounting limits, not measurements of process RSS. Format-specific limits (batch
size 1024 items, 8 signatures per JOSE token, inspection KDF iterations 10_000, ...) are
documented on the corresponding modules. Legacy NCALayer plugin interfaces keep their own
contractual string/Base64 limits; these SDK limits do not extend to them implicitly.

## 6. Semver, versions and migration

- The version is shared by all SDK crates and applications (`[workspace.package]`). Plugins keep
  their own versions.
- Before 1.0 (`0.1.0-alpha.N`) any alpha may break the public API of any SDK crate. Every break
  needs a version bump and a migration note below; internal modules are not stable contracts
  just because they are `pub` for the workspace.
- The SDK version is the **next unreleased** version at the time of the change, read from the
  tags and manifests, not guessed. The newest tag is `v0.1.0-alpha.6` (182 commits behind this
  tree), so this tree is `0.1.0-alpha.7`. A bump changes together: `[workspace.package]
  version`, the `=0.1.0-alpha.N` pins of the SDK chain in `[workspace.dependencies]` (needed by
  `cargo package`), the four built-in `plugin.toml` (`version`, `min_core`), the lock files
  (`Cargo.lock`, `plugins/Cargo.lock`, `crates/oncl-pdk/example/Cargo.lock`) and the README
  status line when it names the release. A pin that disagrees with the workspace version makes
  the whole workspace fail to resolve (`failed to select a version for the requirement
  oncl-gost = "=0.1.0-alpha.8"`), so a forgotten pin cannot ship.

Migration notes:

| from → to | change |
|---|---|
| 0.1.0-alpha.6 → 0.1.0-alpha.7 | `oncl-core`, `oncl-xml` and `oncl-pdf` first appear as SDK crates (absent from alpha.6): there is no earlier public surface to migrate from. `oncl-pki` embeds the NCA roots from its own `roots/` directory (same bytes as `fixtures/nca/prod`, checked by a test) and `testing-data/` instead of reading `fixtures/` outside the crate; no API change. `oncl-core` gains the `full` feature. |

## 7. Publication readiness (and what is not claimed)

The SDK chain, in publication order (each crate after the crates it depends on):

`oncl-gost` → `oncl-registry` → `oncl-pki` → `oncl-pdf` → `oncl-protocol` → `oncl-pdk` →
`oncl-xml` → `oncl-token` → `oncl-flows` → `oncl-update` → `oncl-plugin` → `oncl-core`

It is the set reachable from `oncl-core` with every feature plus `oncl-plugin`'s `distribution`
feature (`oncl-update`). These crates carry `description`, `license` (Apache-2.0),
`repository`, `rust-version`, `keywords`, `categories`, an `include` list (sources, the data the
build embeds, `LICENSE`, `NOTICE`; no tests, fixtures, corpora, scripts or oracles; `oncl-core`
also ships `README.md`, its three examples and `THIRD-PARTY.txt`) and `publish = true`.
Everything else (`oncl-ui`, `oncl-desktop`, `oncl-api`, `oncl-server`, `oncl-cli`,
`openncalayer`, `oncl-nmhost`, `oncl-tls`, `oncl-trust`, `oncl-ipc`, the built-in modules, their
build and test crates, the Windows 7 shims, `oncl-testkit`, `oncl-port-tests`, the plugins)
stays `publish = false` through the workspace default.

Verification that needs no registry and no upload (`cargo xtask sdk smoke`):

1. `cargo package --offline` of the whole chain, **with** verification: each crate is built from
   its own packed tarball while its siblings resolve from cargo's local overlay of the tarballs.
   It needs `--config patch.crates-io.hmac.path=…` and `…streebog.path=…` (below).
2. The `.crate` files are unpacked; the smoke checks that no `tests/`, `fixtures/` or `target/`
   is inside and that `LICENSE`/`NOTICE` are.
3. A separate crate (own `[workspace]`, own lock file) depends on `oncl-core` (`full`) and
   `oncl-pki` by path into the unpacked sources, with `[patch.crates-io]` onto the other
   unpacked crates and the patched `hmac`/`streebog`. Its `cargo metadata` must contain no
   local package outside the unpacked sources; its `cargo tree` must contain none of the
   forbidden UI/desktop/updater/server/runtime crates; it is then built and run: a real CMS
   sign and verify, an altered document refused, and offline signing refused with `NotApplied`.
   No display, daemon, collector or listener exists in that process.

What is **not** verified and not claimed:

- **Upload is blocked.** `oncl-gost`/`oncl-pki` need the additive
  `secret-input` feature of the modified `streebog` and `hmac`; crates.io's versions do not
  have it, so `cargo package` of `oncl-gost` without the patch config fails ("`hmac` does not
  have that feature"); `cargo publish` packages first, so it is expected to stop there (not
  run: nothing here publishes). Before any release these must
  be published under names we control or upstreamed, and the manifests changed accordingly.
  This is a decision, not part of this delivery.
- Registry availability and ownership of the crate names are unchecked.
- `cargo publish --dry-run` against the real registry, the upload and the post-upload checks
  stay with the separately authorised publication.
- The consumer smoke runs on the host platform only; the Linux/macOS/Win7 matrix and the 10 GiB
  / 1 GiB acceptance runs are separate gates.

Commands: `cargo xtask sdk closure`, `cargo xtask sdk smoke [--keep]`,
`cargo xtask sdk licenses [--check]`.

**Guarded by `cargo test -p xtask --test sdk_delivery`** (no network, no build, only
`cargo metadata`/`cargo tree`): the set of crates with `publish` enabled equals
`xtask::sdk_delivery::CHAIN` and the chain is in dependency order; no feature closure of
`oncl-core` contains Slint, winit, tokio, axum, hyper, velopack or any other forbidden crate;
`THIRD-PARTY.txt` is current (a stale copy is detected); a closure crate missing from the
registry map is an error naming it, never a silent omission.

**Heavy gate, explicit invocation (for the release/CI owner; not wired into any workflow
here):** from the workspace root on a host with the registry cache populated
(`cargo fetch --locked`), `cargo run -p xtask -- sdk smoke` (exit 0 and a final
`SDK-CONSUMER-OK` line; `--keep` leaves `target/sdk-smoke` for inspection). It needs `tar` on
`PATH` (GNU or bsdtar) and builds in minutes (RSA key generation, `oncl-core` with `full`).

## 8. Licences and notices

Every chain crate ships `LICENSE` (Apache-2.0) and `NOTICE`. `oncl-pki/roots/` embeds the NCA
production CA certificates (public documents; the rights to the certificates belong to their
issuer and are not licensed under Apache-2.0; `fixtures/README.md`); `testing-data/` is a
synthetic key. `crates/oncl-core/THIRD-PARTY.txt` lists the third-party crates of the SDK
closure (crates.io and the patched `vendor/` copies, every shipped platform, plugin
`distribution` included) with their licence texts, generated by `cargo xtask sdk licenses`
and compared by `--check`. The programs' separate inventory is `cargo xtask licenses`.

## Evidence limits and large embedded CRLs (D1)

`oncl_pki::evidence::EvidenceLimits` gained three public fields (a source break for
struct literals; every in-tree literal was migrated):

| Field | Meaning |
|---|---|
| `max_crl_bytes` | aggregate spool admission of CRL evidence |
| `max_crl_item_bytes` | per CRL, never above `crl::MAX_CRL_LEN` (64 MiB) |
| `max_total_bytes` | aggregate over every evidence category, CRLs included |

`max_bytes`/`max_item_bytes` now apply to non-CRL evidence only. To keep the old
admission of a literal, set `max_crl_bytes = max_total_bytes = max_bytes` and
`max_crl_item_bytes = max_item_bytes`. Decoded certificates, OCSP answers and tokens keep
their amplified RAM/metadata charge; a CRL over `crl::MAX_BER_CRL_LEN` (1 MiB) must be DER,
is scanned in place by `crl::serial_status` and is charged once; a smaller one may be BER,
is normalized into a tree and keeps the amplified charge. `EvidenceStore::collect_base64`
admits an evidence item from base64 text with decoded-size quotas, for XML carriers.

Hosts: the CLI admits CRLs up to 32 MiB (16/1 MiB for other evidence, 48 MiB total) and a
document-sized coverage ceiling. `oncl-server` (2 MiB per CRL) and `oncl-ui` (1 MiB) keep
the earlier bounds and therefore refuse sign/extend with a complete NCA CRL (about 20 MB);
a host that wants it sets the `max_crl_*` fields. A host that also bounds PDF evidence
separately should derive that bound from `EvidenceLimits.max_total_bytes`. PDF DSS evidence
streams are read as regions: they are no longer limited by `PdfLimits::max_object_bytes`,
only by the scope's container and memory accounting and the evidence quotas.

Scope of D1: offline verification/inspection of CMS/CAdES with an embedded complete CRL.
Not covered: online CRL download (`crl::fetch_for`, still decoded in full at 128x), operator
CRL files (`--evidence-crl` is limited to 256 KiB per file), PAdES-LT of real NCANode files
(separate structural guards in `oncl-pdf`), XAdES-LT (XML element cap and DOM
materialization of `EncapsulatedCRLValue`).
