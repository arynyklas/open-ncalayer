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

**Profile findings.** A CAdES/PAdES profile request (`cades-b`, `pades-t`, ...) asks for more
than integrity. When the signature itself verifies but the CMS misses a baseline requirement,
the signer keeps `signature = Passed` and carries `ValidationReason::Profile(ProfileViolation)`:
no signing-time in a CAdES signature, a signing-time in a PAdES one (EN 319 142-1 table 1;
Kalkan writes one), a content type other than id-data, or no signing-certificate attribute.
Such a signer is `Invalid` at that profile and claims no `ades_level`. Digest, ESS or
signature-value problems stay `Signature(..)` failures and are reported alongside, never
replaced. The generic `pdf`/`cms` profiles do not ask for the baseline and judge the same
bytes by integrity and trust only.

**AppliedState.** Every failure after a private-key operation may have started carries
`NotApplied`, `Applied` or `Unknown` (`OperationError::applied_state`). The SDK never promises
rollback, retry or exactly-once: a time-stamp already issued remotely, or a signature computed
before the output sink failed, stays as it happened. A guard that fails in `finish` after the
key was applied reports `Applied`.

**Errors.** `OperationError` (the typed error) and `ErrorCode` (`OperationError::code`, stable
machine-readable categories, never inferred from messages) are public. Stability stance for the
pre-1.0 alphas: hosts must match `ErrorCode` with a wildcard arm. Today neither enum is
`#[non_exhaustive]`, nor are `ValidationReason` and `ProfileViolation`; adding a variant
(as `ValidationReason::Profile` was) is a source-breaking change; it is listed in the
migration notes of the release that makes it. Making these enums `#[non_exhaustive]` is the
intended change for the first release that needs a new code; it is deliberately not done inside this
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
| document input | 1_073_741_824 bytes (1 GiB) |
| container (CMS/XML/PDF structure) | 1_073_741_824 |
| framing | 67_108_864 |
| output | 2_214_592_512 (input + container + framing) |
| live accounted memory | 1_073_741_824 (1 GiB) |
| scratch (temporary storage) | 8_589_934_592 |
| metadata | 67_108_864 |
| operation deadline | 300 s from admission, never restarted |

A document above 1 GiB is refused with the typed `InputLimit` error; hosts may raise `input_bytes`, but only 1 GiB is guaranteed. These are accounting limits, not measurements of process RSS. Format-specific limits (batch
size 1024 items, 8 signatures per JOSE token, inspection KDF iterations 10_000, ...) are
documented on the corresponding modules. Legacy NCALayer plugin interfaces keep their own
contractual string/Base64 limits; these SDK limits do not extend to them implicitly.

**Signed results and `container_bytes`.** `input_bytes` bounds the document, not the signature: a signed result of a document that was exactly at `input_bytes` may exceed it by classified container bytes only, never past `container_bytes` or the format's own bound, and the SDK reads such a result again from any `Source` (a file, a socket, an HTTP upload). A host that must take the whole upload before it starts work (`oncl-server`) spools that input with `FrozenInput::capture_wire`, which charges neither allowance (it holds at most the remaining document allowance plus the remaining `container_bytes`, narrowed by an optional maximum) and hands the engine `FrozenInput::wire_reader`, an external seekable source of known length: the engine charges and classifies the wire exactly as for a file, so the accounting is the one of the SDK and the CLI. It never gives the engine an admitted snapshot of such bytes (`FrozenInput::reader` refuses them; `wire_inspection_reader` is a same-operation replay for the host's own checks). A role that is not a document at all, such as validation evidence with its own bounds, may be spooled the same way with a maximum. The server's `container_bytes` key (default 1 GiB) is the engine's `ResourceLimits::container_bytes`; the wire ceiling of a request with a signed `input` is `input_bytes + container_bytes + framing_bytes + 64 KiB` (see `docs/user/http-api.md`).

**Receiving input without a slot.** A host that is handed the bytes of a request while it waits for a slow client should not hold one of the engine's `max_in_flight` slots (or a thread) for that wait. `Engine::admit_intake` is `Engine::admit` without the slot: memory, temporary disk, metadata, the document, container and framing allowances, the deadline and the control are charged exactly as for an admission, and `OperationAdmission::occupy_slot` (or, at the latest, `Engine::begin_admitted`) takes the slot once the input is in, failing with the same `CapacityExceeded` (nothing changes, so the call may be repeated) when every slot is taken. The host bounds the number of such operations itself. Two incremental forms of the one-call APIs take the bytes in pieces: `oncl_pki::io::InputSpool` (`document` for `FrozenInput::capture`, `wire` for `FrozenInput::capture_wire`; `push` per piece, `finish` for the `FrozenInput`) and `oncl_pki::digest::HashStream` (`hash_source`); each piece is accounted, bounded (N+1 probe at the limit, `InputLimit`) and checked against the operation's control and deadline as in the one-call form, with one difference in memory: the one-call form charges its 256 KiB chunk buffer to the operation, `InputSpool` holds no buffer and charges no memory for it (a piece is written straight through, at most `IO_CHUNK_BYTES` per write). A host that gathers pieces before it pushes them owns that buffer and charges it itself: `oncl-server` reserves `IO_CHUNK_BYTES` once per request with `ResourceScope::reserve_memory` and pushes 256 KiB at a time (it also flushes what it holds before it waits for the client, so the pace rules never charge the disk time to the client). `oncl-server` uses all three for its upload phase (see `docs/user/server.md`).

**CAdES accounting.** `cms::ades` verification, extension and co-signing (and the plain CMS co-sign) read the signature wire once, with the classifying CMS parser, while they spool it: the SignedData structure (headers, certificates, revocation values, signer infos and their timestamp tokens) is container and is bounded by `container_bytes`; only the content is document. A detached content is read separately and charged to `input_bytes`. A detached document the host already admitted (a `FrozenInput` reader, as the `oncl-server` spool is) is replayed and not charged again, by verify, extend and co-sign alike. An attached CAdES result is therefore document + signature: a document of exactly `input_bytes` verifies, extends and co-signs again, one byte more is `InputLimit`, and a signature structure the container allowance cannot hold is `ContainerLimit` (or `InputLimit` when the whole attached wire is already past `input_bytes + container_bytes` at intake), before any key use. The evidence the engine copies out of the wire (certificates, status, timestamp tokens) is charged to `container_bytes` again, and extend and co-sign also charge the structure they write to it (a probe: verify 7081, extend to LT 17429 container bytes), so the container allowance must hold the structure plus that evidence and output structure; evidence is also bounded by `EvidenceLimits`. The spool is temporary storage (`TempLimit`) of up to `input_bytes + container_bytes` plus one chunk. The plain `cms` profile (`cms::stream::verify`/`extract`) has always read the wire this way; before this rule the CAdES path charged the whole wire to `input_bytes`, which refused a document at the limit.

**Container surcharge for signed PDFs.** The document allowance above is not the whole
bound of a signed-PDF readback: reading a PDF that already carries signatures may exceed
the document allowance by a bounded surcharge. The cap is
`min(container_bytes, (max_revisions - 1) * 4 * max_object_bytes + PdfLimits::max_evidence_bytes)`
(`crates/oncl-pdf/src/verify.rs`, `lib.rs`): about 188 MiB at the defaults, with
`PdfLimits::max_evidence_bytes` defaulting to 128 MiB. `max_evidence_bytes` is a PDF-layer
field; no shipped host (CLI, server, desktop) derives it from
`EvidenceLimits.max_total_bytes` yet, so every shipped host keeps the 128 MiB default.

### Plugin registry and declared operations (`plugins`)

`PluginRegistry::install(manifest, package, wasm, limits, policy)` records a `PackageHash`
with the plugin. `PackageHash::File` is the SHA-256 of the whole package file as read by
`oncl_plugin::Package::read`; `PackageHash::Loose` (`plugins::loose_package_hash(manifest_toml,
wasm)`, what the CLI and server use, which load manifest and module separately) is a
domain-separated hash of those two inputs. The kinds never compare equal and encode with
different tags (`PackageHash::canonical`); a loose hash is not a package-file hash and
nothing verifies either against the module: the registry takes the value as given. A host
that loads through `oncl_plugin::Store` (the `distribution` feature, not enabled by this
crate) must take manifest, module and `File(package.sha256)` from one `Package` value.
`BuiltinInfo::sha256` (the module alone) is neither kind. A registered plugin's identity for
audit is `PluginIdentity { id, package, version }` and never its manifest name
(`Engine::plugin_identity`).

A plugin without `[[operations]]` is unchanged: its grants and `PluginPermission::with_keys`
pin the key exactly. For a plugin that declares operations, `PluginRegistry::allow_declared`
(and `allow_declared_with_pki`) adds a registry policy built from the manifest only: the
declared imports for one `(plugin, operation, caller)` and **any** key. The chosen key is
checked on the per-call grant side (`PluginPermission::with_keys` there), which never accepts
the declared policy for a key. The declared `network` is enforced: `none` takes no endpoint,
`pki` takes only endpoints on the PKI hosts the host passes (normally
`oncl_plugin::NCA_PKI_HOSTS`, subdomains included), and `network = [urls]` operations are not
runnable in the manual window in this release (`PluginRequestError::NetworkUnsupported`, not
listed). Whether a caller kind may use an operation's `manual` or `server` flavour is the
wiring host's check.

`Engine::plugin_operations` lists `Manifest::manual_operations` (without URL networks).
`Engine::plugin_request` builds the exact request text the module receives from the parsed
JSON template (any JSON object; each whole-string placeholder value at any depth is replaced,
never a key, never part of a string) and typed `PluginParam` values, never by pasting text: the final length is
computed first and refused above the plugin's `max_transfer` (`ErrorCode::InputLimit`)
before anything is substituted, then written once into a buffer of that size. Documents are
standard base64 and never empty; a text is counted in characters like its declared limit and,
when a key profile reads it as an XPath, checked with `Source::check_value`. A text that is the signed content may hold no control character but `\n` and `\t` and no bidirectional or invisible one (`InvalidValue`; the window passes the same `&str` it renders). A key operation must declare `network = "pki"`, and a text param may be the content of any key kind (its UTF-8 bytes). The text is not
normalized. The output is compact JSON with object keys sorted (the template's key order is
not kept), integers as written; a template number that is not an `i64`/`u64` is refused
(`InvalidTemplate`) rather than re-printed. Undeclared, non-manual, `derived` and URL-network
operations and bad parameters are refused with `PluginRequestError`, always `NotApplied`,
before any key is used. Consent is not part of this API; the key-use ticket, its guard and the
approved manual call (below) follow.

#### Key-use ticket and `PluginConsentGuard` (`plugins`)

A plugin whose manifest declares any `[[operations]]` is called through `plugin_call` only under
a declared operation name, whoever chose the label (manual window, server grant, CLI flag): any
other label is refused before the module runs (`PermissionDenied`, `NotApplied`,
`OperationContext::plugin_refusal() == Some(TicketRefusal::UndeclaredOperation)`). The server
skips (and logs an error for) a grant naming an undeclared operation of such a plugin, and the
CLI refuses the call. A plugin without declarations is unchanged. A call under a declared name
is ticketed. For each of `keys_sign_raw/cms/cms_ex/xml/xml_ex/
xades` Core decodes the arguments once, builds a `plugins::PluginUse` from that same decoded
value and parks it in the operation context; `AuthorizedSigner::sign_digest` moves it into the
`KeyUseEvent` (`KeyUseEvent::plugin()`, `None` for every document use and for plugin
operations without declarations). The ticket names the plugin identity (`id`, `PackageHash`,
version), the declared operation, the caller, the signature kind, the handle and `KeyId` of
the one bound key, a `ContentBinding` (SHA-256 and length of the bytes signed; `prehashed`
for a CMS `Digest` input) and `options_sha256`. The options hash is the SHA-256 of
`oncl_plugin::operations::Profile::encode` over a profile built from the actual arguments, the
very encoder `KeyUse::options_sha256` uses for the declared profile. Arguments no profile can
express (a co-signed CMS, `attrs.extra`, `econtent_type`, a `digest` choice, `Extra`
certificates, a custom TSA, a non-default signingTime, XML `signature_id`/signing-time
object, XML `transforms` that are not a checked list, a XAdES chain) are refused before the key is opened. XML `transforms` are accepted only as a checked list: `enveloped` first, then at most one
canonicalisation (an empty list and any other order are refused); the list is part of the
options hash. `cosign = Auto` is
forced to `Never` first, so the ticket's content is the effective content. An import whose kind
the operation does not declare, or whose declared content is `derived`, is refused. A declared
operation binds at most one key; every key-taking import (`keys_describe`, `keys_chain`,
`keys_release`, the signing imports) answers any other handle with the one `PermissionDenied`,
and `keys_release` of the bound handle is idempotent. A ticket allows exactly one use
(`max_uses = 1`).

`KeyUseEvent::plugin()` exists only with the `plugins` feature of `oncl-core`; the featureless
`KeyUseEvent::is_plugin()` says whether the event carries a ticket (always `false` without the
feature). A `KeyUseGuard` of a host that registers plugins with declared operations MUST refuse
every event for which `is_plugin()` is true unless it is the plugin guard (a document guard that
ignores it would authorize a ticketed use as a document use); `oncl-server`, `oncl-cli` and
`oncl-ui`'s `ConsentGuard` do.

`PluginConsentGuard` (a `KeyUseGuard`) is the guard of a plugin engine. `before_use` refuses
(`PermissionDenied`, key not applied; the reason is recorded per `OperationId` in a bounded log of
`REFUSAL_LOG` entries: `refusals(id)`, `take_refusals(id)`, `refusal_log()`) unless the event carries a
ticket and the guard holds an unexpired `PluginApproval` for the same invocation, plugin
identity, operation, caller, key and handle with one unspent `ApprovedUse` whose kind, content
and options hash equal the ticket's; the use is then spent. With no approval it refuses
everything, and a document key use (no ticket) too: give documents their own engine. A
`PluginApproval` (not `Clone`, not `Deserialize`, no public constructor) is issued by Core
(below); its nonce is accepted once. The server (`DurableAuditGuard`) and CLI (`Authority`)
guards refuse every ticketed use until their own grants exist (`plugin_bytes` in MP8/MP9);
plugins without declarations are unchanged.

#### Manual window: consent summary, approval, approved call (`plugins`)

Three Core steps, in this order (`docs/design/manual-plugins.md` 4.2, 4.3, 4.8). Both
`plugin_prepare` and `plugin_call_approved` take the same `ManualCall { plugin_id, operation,
params, key: &PluginKeyBinding, caller: &CallerContext }`:

1. `Engine::plugin_prepare(&ManualCall, &mut OperationContext)` returns a `PluginPrepared` or a
   `PluginPrepareError` (always `NotApplied`). It opens the key once (a token login or key-store
   decryption happens at this point, and again in the call), so the host collects the secret
   BEFORE showing the consent and puts it in the binding's key request; a failed open is
   `KeyUnavailable` without its cause.
   It validates the parameters like `plugin_request`, freezes what is signed (the bytes of the
   bound parameter, SHA-256 and length; for a `cms_ex` profile whose `content_form` is `digest`
   the digest Core itself computes with the hash algorithm of the bound key's signature
   algorithm, by the same function the signer later uses: GOST 34.311, Streebog or SHA-2 by
   the certificate and the context's policy, never a digest a plugin names), and the options
   (`KeyUse::options_sha256` with the `param:` sources of the profile filled from the typed
   text parameters: the very encoder the ticket side uses). `caller` must be a
   `CallerContext::LocalOperator` (the manual window has no origin) and the key binding must
   carry its public metadata (`with_public_metadata`: alias and certificate). The metadata
   is the host's statement about the key it signs with: Core shows it and gives it to the plugin
   (`BoundKey`, `keys_describe`) and `plugin_prepare` compares its certificate with the one the
   key store holds for the key (`CertificateMismatch`).
   `PluginPrepared::summary()` is a `ConsentSummary`: the **trusted** description to render
   (identity `{id, PackageHash, version}`, operation name, kind, number of uses, the declared
   profile with the user's text resolved, the options hash, the content parameter name, length,
   SHA-256 and prehashed digest, the key's alias, serial, subject CN, SHA-256 fingerprint and
   `not_after`, and the PKI endpoints the host registered). It holds no plugin text (`name`,
   `description`, `label` stay in the plugin's own frame); `key.alias` and `key.subject_cn` are
   the host's and the certificate's strings and must be escaped by the renderer.
2. `UserConfirmation::after_user_confirmed(&ConsentSummary)` is the only way to make the token
   `PluginPrepared::approve(confirmation, ttl)` takes. **Host duty:** call it only from the
   handler of the user's own action on the confirm control, after rendering that very summary;
   never auto-confirm, never ahead of time, never from a stored answer (nothing is stored). It
   names the SHA-256 of the summary shown, so confirming one summary approves no other. The
   token is neither `Clone` nor `Copy`. `approve` returns the `PluginApproval`: kind, content
   binding and options hash from the prepare step, one use (`max_uses = 1`), the invocation of
   the context it was prepared with, a deadline `ttl` on the monotonic clock from now (`None` is
   `APPROVAL_TTL` = 120 s; a longer ask is cut to it, zero is refused), and a nonce of 16
   bytes of the operating system's CSPRNG (an RNG failure issues nothing).
3. `Engine::plugin_call_approved(&ManualCall, PluginApproval, &ManualHost, &mut OperationContext)
   -> ApprovedCall` runs the module in the manual window. It re-derives the use from the parameters it is handed **now** and refuses,
   before the module runs, an approval that is not for exactly them (another document, text,
   key or handle, caller, operation, invocation, expired): the module never sees a document
   the user did not approve. Then it builds the request (`plugin_request`), grants the approval
   to the engine's `PluginConsentGuard`, and runs `oncl_plugin::Compiled::call_manual` with a
   fresh `BoundInteraction` (the `BoundKey` is built from the very `PluginKeyBinding` the
   backend signs with; the clock is the validation clock read at the call; the transport and
   `OcspCache` are the host's, from `ManualHost`; no origin). The guard stays the authoritative
   check at the key use. The approval is revoked when the call ends (a `Drop`, so also on a
   trap, an error and a panic). The engine must be built with
   `EngineServices::with_plugin_keys(provider, Arc<PluginConsentGuard>)`: its only key guard is
   that one (`with_keys` clears it and an approved call then refuses with
   `TicketRefusal::NoGuard`); one approved call runs at a time (`Busy`). Keep documents on
   another engine: the desktop `ConsentGuard` refuses a ticketed event and the plugin guard
   refuses an event without one.

The approval binds the SHA-256 of the signer certificate: `ApprovedUse` and `PluginUse` carry
it, `ConsentSummary.key.fingerprint_sha256` shows it, `plugin_prepare` opens the key once and
refuses (`CertificateMismatch`) if the key store's certificate is not the binding's metadata,
and at the signing point `AuthorizedSigner` stamps the ticket with the fingerprint of the
certificate its key lease holds; the guard (and the fast check of `plugin_call_approved`)
refuse another with `TicketRefusal::CertificateChanged`, key not applied. The alias is display
only and is not compared. The prehash algorithm uses the same strict selection as the signer.
Operational notes: give each engine its own `PluginConsentGuard` (one approval slot); a call
refused as `Busy` consumes its approval (the user confirms again); hosts MUST set a deadline on
the context given to `plugin_call_approved` (a plugin holds the in-flight slot until the
deadline or its fuel ends); the approval deadline is a monotonic `Instant`, which may not
advance while the system is suspended.

`ApprovedCall` is the honest outcome: `result()`/`response()` (the module's reply string),
`applied()` (`Applied` also when the module failed after the key use, `Unknown` when the
application itself did not report, `NotApplied` for every refusal) and `refusals()` (the
typed `TicketRefusal`s of this invocation: from the guard, or from the checks before the
module ran, plus `NoGuard`, `Busy`, `Replayed`, `UndeclaredOperation`, `Caller`).

#### Refusal subcodes and audit facts (`plugins`)

`ErrorCode` is unchanged. Next to it every plugin refusal has a `PluginRefusalCode` (stable,
`#[non_exhaustive]`): `id()` is a kebab-case string (`content-mismatch`, `package-changed`,
`approval-expired`, `not-declared`, `not-granted`, ...) that is **never reused or renumbered**;
`ALL` lists every subcode in append-only order and a test pins the full list of ids, so a change
is deliberate. `error_code()` is the `ErrorCode` the refusal is reported with (always the one
`OperationError::code` gives: `PermissionDenied` for ticket, caller and declaration refusals,
`InputLimit`/`InvalidInput` for parameters, `UnsupportedAlgorithm`, `MissingKeyProvider`, `Io`).
Every reason has one: `From<TicketRefusal>`, `From<&PluginRequestError>`,
`From<&PluginPrepareError>`, `From<ApprovalIssueError>`, `From<ApprovalRejected>` and the
`subcode()` method of each. `TicketRefusal::NotGranted` is for a server or CLI key use that no
operator grant covers; `TicketRefusal::AuditFactTooLong` for a use whose version or grant id
cannot be audited (over 255 bytes), refused before the journal is touched.
`DurableAuditGuard::with_plugin_policy` returns `io::Result<Self>` (an error if the guard was
already shared).

Where a host reads it: `ApprovedCall::subcode()` (the first guard refusal, else the reason the
call could not be prepared; `None` when nothing was refused, also after an error that came after
the key was applied), `OperationContext::plugin_refusal_code()` (an undeclared label refused in
`plugin_call`), and for a server whose guard is `DurableAuditGuard`
`take_plugin_refusals(operation_id)` mapped with `PluginRefusalCode::from`. **The plugin never
sees a subcode**: its own error is the bare `PermissionDenied`, with no text that names the reason.

`PluginAuditRecord::from_ticket(&PluginUse, nonce, grant_id)` is what the audit of a use names:
plugin `{id, package kind + sha256, version}`, operation, `PluginUse::digest()` (the ticket
digest), the SHA-256 of the approval nonce (domain-separated; never the nonce), content SHA-256
and length, whether the content is a prehashed digest, options SHA-256, the caller kind (not its
name), `declared` and the operator `grant_id`. No document bytes, parameters or secrets.
`PluginConsentGuard` emits it as a `tracing` event (`target = "oncl::plugin_audit"`) when a use is
authorised, and a refusal with its `subcode` and ticket digest as a `warn` event; refusals that
never reach a guard (a request or prepare error, an approval the call refuses) are `warn` events of
the same target with the `subcode`. The durable form is in `docs/user/server.md` (audit).

`PluginApproval::new`, `ApprovedUse::new` and the other constructors are not public. With the
`testing` feature of `oncl-core` (never part of a release) `PluginApproval::for_tests`,
`ApprovedUse::for_tests`, `PluginUse::for_tests` and `KeyUseEvent::with_plugin_ticket_for_tests`
forge what Core never would, for tests of guards. A release build never enables `testing`: the
release programs are built with `-p`, but `cargo build --workspace --all-targets` and
`cargo test` unify the dev-dependencies' `testing` into the same binaries, so CI runs
`cargo xtask check-release-features`. It reads `cargo tree -p <openncalayer|oncl-cli|oncl-server|oncl-ui>
-e normal -f "{p} [{f}]"` (the features resolved for the normal tree, without dev-dependencies)
and fails if any crate shows `testing`.

## 6. Semver, versions and migration

- The version is shared by all SDK crates and applications (`[workspace.package]`). Plugins keep
  their own versions.
- Before 1.0 (`0.1.0-alpha.N`) any alpha may break the public API of any SDK crate. Every break
  needs a version bump and a migration note below; internal modules are not stable contracts
  just because they are `pub` for the workspace.
- The SDK version is the **next unreleased** version at the time of the change, read from the
  tags and manifests, not guessed. The newest tag is `v0.1.0-alpha.6`, and this tree is
  `0.1.0-alpha.7`, which is not released. A bump changes together: `[workspace.package]
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
- The consumer smoke runs on the host platform only; the Linux/macOS/Win7 matrix and the 1 GiB
  / 1 GiB acceptance run are separate gates.

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

`EvidenceLimits::validate` rejects a zero `max_crl_bytes`, `max_crl_item_bytes` or
`max_total_bytes` with `EvidenceError::InvalidLimits` (as it rejects a zero `max_bytes`). It
does not order the three: intake takes the minimum of the item cap, the CRL aggregate and the
total, and clamps the item cap to `MAX_CRL_LEN`, so a cap above another is just not the binding
one. `EvidenceLimits::intersect` is the one field-by-field minimum of two sets, used by
`oncl-core` and `oncl-xml`.

`max_bytes`/`max_item_bytes` now apply to non-CRL evidence only. To keep the old
admission of a literal, set `max_crl_bytes = max_total_bytes = max_bytes` and
`max_crl_item_bytes = max_item_bytes`. Decoded certificates, OCSP answers and tokens keep
their amplified RAM/metadata charge; a CRL over `crl::MAX_BER_CRL_LEN` (1 MiB) must be DER,
is scanned in place by `crl::serial_status` and is charged once; a smaller one may be BER,
is normalized into a tree and keeps the amplified charge. `EvidenceStore::collect_base64`
admits an evidence item from base64 text with decoded-size quotas, for XML carriers.

Hosts: the CLI admits CRLs up to 32 MiB (16/1 MiB for other evidence, 48 MiB total) and a
document-sized coverage ceiling (the output ceiling); `oncl-server` has the same coverage
ceiling (its `max_coverage_bytes` is the operation output ceiling, not `input_bytes`: a PAdES
LT -> LTA timestamp covers the whole signed document, which at the full allowance already
exceeds `input_bytes`). `oncl-server` (2 MiB per CRL) and `oncl-ui` (1 MiB) keep
the earlier bounds and therefore refuse sign/extend with a complete NCA CRL (about 20 MB);
a host that wants it sets the `max_crl_*` fields. A host that also bounds PDF evidence
separately should derive that bound from `EvidenceLimits.max_total_bytes` (no shipped host
does yet; see the container surcharge in section 5). PDF DSS evidence
streams are read as regions: they are no longer limited by `PdfLimits::max_object_bytes`,
only by the scope's container and memory accounting and the evidence quotas.

Scope of D1: offline verification of CMS/CAdES and, with the XML slice below, of XAdES with
an embedded complete CRL. Not covered: online CRL download (`crl::fetch_for`, still decoded
in full at 128x), operator CRL files (`--evidence-crl` is limited to 256 KiB per file),
PAdES-LT online fetch, and the SIGN side of XAdES (below). The structural PAdES guards
(trailer `/ID`, object-0 free head) are fixed; PAdES-LT verification of real NCANode files is
bounded by the DSS region reading and the container surcharge cap (section 5, Limits).

### XAdES with a complete CRL (verify side)

NCANode/Kalkan XAdES-LT writes the complete NCA CRL (about 20 MB, 27 MB of base64 with `&#13;`
line ends) into `xades:EncapsulatedCRLValue`. `XmlVerifyProfile::max_metadata_bytes` now bounds
structural markup only: the text of `EncapsulatedX509Certificate/OCSPValue/CRLValue` leaves is
recorded as source extents by the scan, subtracted from the property it sits in, and streamed
through `EvidenceStore::collect_base64` (entity references and CDATA decoded on the fly, 16 KiB
buffers) so the decoded bytes are charged to `max_crl_item_bytes`/`max_crl_bytes`/
`max_total_bytes` before they are stored. No `String`, DOM or base64 `Vec` of a leaf exists.
`validate_unsigned_layout` decides from structure recorded by the scan, and the archive
timestamp representation takes the canonical text spans of each leaf from the canonical
renderer (`canonical_stream::stage_with_leaves`), not from parsing the rendered bytes. The text
of a valid leaf is bounded by the evidence quotas on its decoded bytes only: a leaf made of
whitespace decodes to nothing and is bounded just by the input size (it is streamed, never
held). WSSE-embedded XAdES keeps the old extent bound (`70 x max_metadata_bytes` per
`Signature`), so a CRL over about 17 MB inside a SOAP envelope is still refused.

Host-visible changes: host-configured `EvidenceLimits` are no longer clipped by the metadata
cap (`effective_limits`: the cap only scales the defaults of a host that configured nothing,
so the same holds on the sign and extend paths (`effective_limits` is shared); an unconfigured SDK host still refuses a CRL over 256 KiB with `EvidenceError::Limit`);
`VerifyRequest::xades_with_limits` is the XAdES counterpart of `cades`/`pades`, and the CLI
uses it with its 32 MiB CRL quota; the readback of a scanned (DER, over 1 MiB) CRL is charged
as memory only, not also as metadata (the XML index admission is 56 MiB of the 64 MiB default
metadata budget). `oncl-server` and `oncl-ui` pass no XAdES limits and keep refusing.

Not covered (SIGN side): `xades::source::material_xml`/`complete_signature`, `sign.rs`,
`xades.rs` and `references/extension.rs` still build the unsigned properties as `String`s
bounded by `max_metadata_bytes`, so signing or extending a XAdES-LT/LTA with a CRL over
256 KiB is refused with `MetadataLimit`. The design that remains: write the generated
properties to a staged artifact (their canonical form under exclusive C14N equals the text
they are generated as, so the archive coverage and its leaf spans need no parse; prove with
a differential test against `canonical_stream`), and assemble head + staged unsigned + tail.

## Embedded status of LT/LTA is judged at the proof time

Revocation status carried by a signature (OCSP answers, CRLs of CAdES/PAdES/XAdES `LT`
and `LTA`) is evidence for verifying long after it was issued. It used to be judged against
the verifier's clock (`nextUpdate`, `ALLOWED_PERIOD`, responder certificate validity at
`now`), so a document that verified `Valid` at signing turned `Indeterminate` after a few
minutes, for any size. The rule now lives once in `oncl-pki` (`ocsp::check_embedded_at_proof`,
`crl::serial_status_at_proof`, selected by `validation::offline_revocation`; `pkix::Currency`
is the switch) and CAdES, XAdES and PAdES all use it.

**Rule.** When a proof time `P` is verified, an embedded OCSP answer or CRL about a path
certificate is accepted when everything that was checked before still passes (CertID, issuer
binding, signature, responder chain and OCSPSigning/no-check, `unknown` is refused, a CRL
is a complete CRL of the issuer) and:

* fresh at `P` (EN 319 102-1 5.2.5.4: maximum freshness `nextUpdate - thisUpdate` unless a
  constraint says otherwise): with a `nextUpdate` (every CRL, an OCSP answer that has one)
  the answer is fresh iff `P < nextUpdate`, so a 35-day CA CRL issued hours before the proof
  is good; without one (NCA OCSP) iff `P - CLOCK_SKEW < thisUpdate` (300 s, exclusive);
* `thisUpdate <= now + CLOCK_SKEW` (a CRL: `thisUpdate <= now`): never from the verifier's
  future;
* the responder certificate chains **as of `thisUpdate`** (not `now`);
* `nextUpdate` and `ALLOWED_PERIOD` are not compared with `now`.

`P` is the genTime of the signature time-stamp (`T`, `LT`) — for a PAdES document
time-stamp that is the first proof — and, for `LTA`, the same signature time-stamp: the
archive time-stamps protect the evidence but do not move `P` (a status embedded after the
signature time-stamp and before the archive time-stamp must stay acceptable). A time-stamp
authority certificate's own embedded status is judged the same way with that token's genTime
as its `P`. Without a proof time (level `B`, a missing or invalid timestamp) `at` is `now`
and the old rule is kept; status fetched online is always judged current at `now`.

Unchanged: the signer and chain certificates are judged valid **at `P`** (they already were:
`certificate_facts` and the anchored path use `P`); revoked at or before `P` is `Invalid`;
revoked after `P` leaves the signature valid and reports `RevokedAfterProvenTime`.

**All acceptable statuses count (selection).** For one certificate every embedded OCSP answer
and CRL that passes the checks above is evaluated, in no particular order (the count is bounded
by the evidence store limits). Any acceptable `revoked` revokes: the earliest revocation time
among them is reported (at or before `P`: `Invalid`/`Revoked`; after `P`:
`RevokedAfterProvenTime`). `Good` needs at least one acceptable `good` and no `revoked`;
otherwise the status stays `Unavailable`. An unacceptable status (stale, wrong issuer or
responder, other certificate, `unknown`) is ignored as before and never turns `Unavailable`
into `Good`. A `good` answer listed first no longer hides a later `revoked` one.
The status fetched online (`check_path_revocation`) uses ONE source per certificate (the CRL
is fetched only when OCSP gave neither `good` nor `revoked`). That is a residual weakness, not
a fix: an OCSP `good` from a responder is accepted without consulting a CRL that may say
`revoked`. EN 319 102-1 requires acceptable status information, not every available source, so
this is a policy choice, recorded as open. Also, `offline_revocation` has no work/deadline
checkpoint inside the status loop (a bound by the evidence store limits only; the worst case
equals the old no-acceptable-status case).

**Standard basis (ETSI EN 319 102-1 V1.3.1, read from the published text).** 5.2.5.4 (Revocation
freshness checker): status is fresh when `issuance time > validation time - maximum accepted
freshness`; 5.5.4 step 6 reruns the checker with the *best-signature-time* when the status
was not fresh against the current time; 5.5.4 step 4a: a revocation time after the
best-signature-time does not invalidate the signature, one at or before it is
`INDETERMINATE/REVOKED_NO_POE`; 5.2.6.4 (X.509 certificate validation) runs the checker with
the validation time and does not check the issuer's CRL-signing certificate against it. The
`nextUpdate - thisUpdate` default of 5.2.5.4 step 1 is used for answers that carry a
`nextUpdate`; for NCA OCSP answers, which carry none, the freshness is the constraint
`CLOCK_SKEW` (the standard says FAILED without nextUpdate unless a constraint is given).

**Replay window.** The window in which an attacker holding a pre-revocation "good" answer can
use it is the answer's own validity, `nextUpdate - thisUpdate`: up to 35 days for an NCA CRL
(300 s for an answer without `nextUpdate`). The archive time-stamp / proof of existence of an
`LTA` does not narrow it: `P` is the signature time-stamp's genTime, and the archive
time-stamps only protect what was embedded. This is the standard's default and the old
rule's window at signing time.

**Not verified / deliberate differences.** (0) No real-PKI proof: the pinned NCANode LT fixtures never reach a proof time here, so the NCA cadence (35-day root CRL issued hours before the timestamp) is tested with the recorded production CRL (`tests/crl.rs`) and a synthetic 35-day CRL, not with a Valid real document; the plain-CMS offline path is covered by `oncl-core` `offline_cms_status_is_judged_at_the_proof_time_not_the_host_clock`; P is the LAST passing signature time-stamp where the standard (5.5.4 step 3b) takes the earliest (conservative, pre-existing). (1) 5.6.2.2.4 step 2a also asks for a proof of
existence of the revocation information at or before the control time; for `LTA` this is the
archive time-stamp binding the evidence, which is checked by the evidence graph, for `LT`
it is not requested (nothing but the signature time-stamp exists), as in 5.5.4. (2) The
strict `>` and the 300 s freshness are choices within the constraint the standard leaves to
the validation policy, not values it prescribes. (3) Revoked-at-or-before-`P` is `Invalid`
here; the standard says `INDETERMINATE/REVOKED_NO_POE` (stricter, unchanged). (4) The standard's
chain-model rule for key-compromise revocation after `P` of a CA is not modelled.

## Dense PDFs: the cross-reference budget (D4, D6)

`PdfLimits::max_objects` (default 4096) bounds object-GRAPH walks only: the AcroForm field
count, DSS evidence items, the members of one object stream, the signature-view traversal.
It is no longer a document size ceiling. A document's size in objects is bounded by
`PdfLimits::max_xref_entries` (default 4 Mi entries over ALL revisions), and every entry is
paid for:

| What | Cost |
|---|---|
| cross-reference row (any revision) | 16 bytes of operation memory, reserved as the row is read (steps of at most 65 536 rows), never up front |
| run of consecutive object numbers | 32 bytes (at worst one per entry) |
| a classic xref table / an xref stream | read in 64 KiB chunks / inflated incrementally (PNG predictor included) straight into rows; the decoded table is never held, `max_object_bytes` and `max_decoded_bytes` no longer apply to it, the inflated size is bounded by the declared rows and `max_decode_work` |

Refused before any row is allocated: a declared count past the remaining budget, and a
count the rest of the file cannot hold (classic). Trailing or missing xref-stream data is
detected only after the rows that are present were read and charged (it is a malformed
document, refused all the same, before key use). Past the budget the
refusal is `PdfError::Limit("xref entries")` (limit+1 exact, over all revisions); a
memory quota that cannot hold the rows is `MemoryLimit`; both happen while reading, before
any private key use (`NotApplied`). A classic table is accepted independently of where the
64 KiB read chunks fall: a subsection header or entry cut by a chunk end is re-read from a
fresh chunk (also when its last token reaches the chunk end, where a number may be cut), so acceptance of ordinary entries does not depend on the alignment; a unit starting at a chunk start is accepted when it ends before that 64 KiB chunk does, and refused otherwise. A subsection header surrounded by more than a chunk of blanks can still be refused depending on the alignment (it fails closed; not a real-world layout).

Not charged (bounded transients): the 64 KiB read chunk, the inflate/predictor row buffers
(`RowReader`, one predictor row of at most `max_object_bytes`), and the copy made while the
row vector grows (at most one step, 1 MiB, above the charged capacity).

Hosts that pre-flight a PAdES update add the rows with
`budget::PriorSignatures::xref_entries` → `budget::PlanInputs::xref_entries`
(`budget::xref_memory` is the upper bound used by `plan_memory`); the server does so.
`budget::reader` no longer scales with `max_revisions`.

Measured (debug build, real `oncl` process, `scripts/pdf-dense/gen_dense_pdf.py`, three
revisions, cross-checked with pyHanko; its signature of the signed output is intact over the
entire file): 1 M objects classic xref (123 MB) signs in 3.2 s at a peak working set of
43 MB; 1 M objects as object streams + Flate/PNG xref streams (58 MB) 1.9 s at 44 MB; 4 M
objects (the default ceiling) 13.5 s at 135 MB.
