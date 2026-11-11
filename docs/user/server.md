# Standalone HTTP service

`oncl-server` is independent of desktop settings, dialogs, OS vaults, trust-store
installation and autostart. Starting it without a subcommand does not open a
socket. `serve` requires an explicit private configuration file; HTTP is disabled
unless `enabled = true` or the operator supplies `--enable-api`.

## Private operator namespace and tokens

Create a dedicated directory owned only by the service account. The existing
private-filesystem policy verifies owner-only permissions/ACLs, refuses links and
foreign files, and never repairs permissions of existing objects. The config,
API-token file and key/PIN mount files must be private regular single-link files
in such a directory. Do not use a desktop data directory.

```text
oncl-server token-create --directory /private/oncl-operator --name client.token
```

The command creates the private directory if absent, writes a new OS-CSPRNG
256-bit token exclusively to `client.token`, synchronizes it, and prints **only**
its verifier. It refuses to overwrite an existing token file. Treat the token
file as a password; supply its content to the client's secret-input facility,
not command-line arguments or logs. The verifier is HMAC-SHA-256 with a fixed
versioned domain key; verification uses ring's constant-time fixed-size MAC
verification. Config persists only token ID, verifier and ACL, never plaintext
tokens. Neither tokens nor key/PIN/password-bearing types implement open Debug.

Write `server.toml` in the private operator directory (replace the verifier and
absolute journal directory):

```toml
enabled = false
bind = "127.0.0.1:13579"
audit_directory = "/private/oncl-audit"
recover_audit = false
max_in_flight = 2
# max_uploads = 8   # unset: min(8, total_temp / (input_bytes + container_bytes)); an explicit value may not exceed that bound
blocking_workers = 2
queue_capacity = 2
admission_wait_ms = 1000
operation_timeout_ms = 300000
upload_idle_timeout_ms = 30000
upload_min_bytes_per_second = 1024
max_connections = 32
header_timeout_ms = 5000
input_bytes = 1073741824
container_bytes = 1073741824   # signature/envelope surcharge of a signed `input`; lower it with input_bytes, see http-api.md
memory_per_operation = 268435456
total_memory = 536870912
temp_per_operation = 8589934592
total_temp = 17179869184
framing_bytes = 67108864
metadata_bytes = 67108864   # default 64 MiB; raise for batches of XML/PDF signatures
# Optional, required for multipart public-document snapshots:
# scratch_directory = "/private/oncl-scratch"
inline_pkcs12 = false

[[tokens]]
id = "accounting-service"
verifier = "<64 lowercase hexadecimal verifier characters>"
actions = ["hash"]   # also: "batch" is the separate right for POST /v1/batch
keys = []
```

```text
oncl-server serve --config /private/oncl-operator/server.toml --enable-api
```

Without explicit hosts, a loopback listener accepts exactly its bound socket
address as the HTTP `Host` authority, including the actual port. Configure
`hosts = ["localhost:13579"]` if clients use that name. There are no implicit
wildcards or `Origin`-based privileges. IPv6 loopback requires an explicit IPv6
bind. Configuration is strict: unknown fields and unsafe limits are rejected.
`enabled = false` exits without opening the journal, TLS keys, or a listener.

Ctrl-C requests graceful shutdown. For a supervisor-owned pipe,
`--shutdown-stdin` explicitly enables one operator-control reader: newline or EOF
stops the listener, cancels connections and waits for actual admitted workers to
return. This pipe is not a network admin API. No unrelated listener/service is
stopped; persistent audit files are retained, not deleted at shutdown.

## Actual API

Only these routes exist:

* `POST /v1/hash`: raw binary request body, SHA-256, authenticated hash ACL.
* `POST /v1/operations`: typed JSON-small or metadata-first multipart hashing,
  verification, signing and binary streaming extraction; see [the HTTP contract](http-api.md).
* `POST /v1/batch`: ordered batch of operations; needs the separate `batch` right.
* `GET /v1/openapi.json`: the published contract; authenticated like `/health`.
* `GET /health`: authenticated hash ACL; reports the actual local audit health.

Send `Authorization: Bearer <token-file-content>`, the configured `Host`, and the
document as a streaming body. A successful hash of the three bytes `abc` is:

```json
{"operation_id":1,"algorithm":"sha256","digest":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","bytes_in":3}
```

The operation ID varies. Content-Length is optional; unknown-length chunked input
is counted by the original Core resource scope, including the N+1 oversize probe.
No document-sized body collection or spool is used for hashing. Malformed or
truncated framing never yields a successful hash. Query parameters, key selectors,
method-override headers, mismatched `X-Oncl-Operation` and request trailers are
rejected; the route never dispatches another operation named by a payload.
Request targets must be exact origin-form paths, without a URI scheme or
authority. Absolute-form URLs are rejected even when their authority matches the
Host header. Methods are exact: POST for hash and GET for health; HEAD is not a
GET alias. Application path/method rejections retain HTTP 404/405 and use the
`InvalidRequest`/`NotApplied` envelope. HTTP syntax that Hyper cannot parse may
be rejected at the transport layer without an application JSON envelope.


Errors contain a stable `code` and `applied`. This hash endpoint always reports
`NotApplied` (no private key is used): bad authorization is HTTP 403, malformed
requests HTTP 400, resource byte limits HTTP 413, exhausted admission/queue
`CapacityExceeded` HTTP 503, and `DeadlineExceeded` HTTP 504. There is no hidden
retry or durable document queue. The HTTP contract also has signing and extension
routes (`POST /v1/operations`, `POST /v1/batch`; see [the HTTP contract](http-api.md)),
which need the token's `sign`/`extend`/`batch` right and a named operator key. There
are no encryption/decryption routes (they wait for the Kazakhstani GOST backend) and no
admin endpoints.

## Explicit LAN exposure

Non-loopback binds require an explicit exposure mode and exact allowed hosts.
There are two distinct choices:

```toml
bind = "0.0.0.0:13579"
hosts = ["signing.internal:13579"]
exposure = { mode = "tls", certificate = "/operator/server.crt", private_key = { directory = "/private/oncl-operator", name = "server.key" } }
```

This is real rustls TLS using an operator-supplied PEM certificate chain and
owner-only PEM private-key mount. It neither creates nor installs a CA. Configure
client trust explicitly; do not disable certificate verification.

Alternatively, use a TLS-terminating reverse proxy on a protected backend network:

```toml
bind = "0.0.0.0:13579"
hosts = ["signing.internal"]
exposure = { mode = "trusted_proxy", peers = ["192.0.2.10"] }
```

Only an allowlisted **actual socket peer IP** can use that backend listener.
`Forwarded`, `X-Forwarded-For`, `Origin`, URL fields and roles never establish
proxy trust or replace the individual API token. Protect the proxy-to-service
network with host/network policy; trusted-proxy mode is not TLS on that hop. A
nonallowlisted peer is refused even if it supplies a forged forwarding chain.
Configured and actual IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) normalize to
the same IPv4 peer. Native and IPv4-compatible IPv6 remain distinct; normalization
does not widen a loopback bind or trust a nearby address. Unspecified peers,
including mapped unspecified IPv4, cannot be allowlist entries.


## Named operator keys and audit

The service composes one Engine, one aggregate SharedBudget, one bounded executor,
real `KeySources`, a physical-reader TokenGateRegistry and the accepted durable
ONCLAU02 audit guard. Operator configuration can bind file-backed PKCS#12/JKS or
supported tokens to opaque names; client DTOs cannot contain server paths.

```toml
[[keys]]
source = "file"
name = "corporate-signing"
path = "/operator/corporate.p12"
# alias = "signing" # omit only for a single-entry container
secret = { directory = "/private/oncl-operator", name = "container.password" }

# Token alternative (exact existing storage kind and actual PC/SC reader):
# [[keys]]
# source = "token"
# name = "card-signing"
# reader = "Operator PCSC Reader"
# kind = "AKKaztokenStore"
# alias = "signing"
# secret = { directory = "/private/oncl-operator", name = "card.pin" }
```

These are the SDK/provider bindings behind the HTTP signing routes. A private-operation
caller must hold the action and exact named-key ACL and bind
its authenticated principal to the original operation before private use. The
durable guard synchronizes BEGIN before the actual key call. A FINAL failure after
private use remains Applied/Unknown and blocks further private work; output is not
published as success. No allow-all guard or second audit journal is installed.
Strict server policy remains strict. Public verification defaults to an empty
trust set and denied PKI network, not a fabricated trusted verdict. Private (signing)
operations are separate routes with their own rights, never reachable through a public
verification request.

A newly created journal starts healthy. An existing journal requires an explicit
operator `recover_audit = true` restart; recovery rejects complete corruption,
foreign/old journal formats and live ownership. It does not silently migrate or
repair another journal. Audit identity/lock/rotation/quota and opaque actor/key
labels retain the audit library's existing semantics.

### Plugin records in the audit journal

The journal format stays `ONCLAU02`, 160-byte checksummed frames, and a journal that contains no
plugin ticket is **byte-identical** to what earlier versions wrote. The same version reads every
journal an earlier version wrote (tested with a journal produced by the previous code). Plugin
operations that declare their key uses (`[[operations]]` in the manifest, "declared") add two
frame kinds, which **an earlier version cannot read** (it reports the journal as damaged and asks
for operator inspection): do not run an older server over a journal that holds them.

* **Use (authorised).** Before the `BEGIN` of the key use, one to a few `PluginDetail` frames
  carry: plugin id, package hash (kind `1` file / `2` loose, and SHA-256), version, operation
  name, the ticket digest, the SHA-256 of the approval nonce when a user approved (never the nonce),
  the content SHA-256 and length, whether the content was a prehashed digest, the options SHA-256,
  the caller kind (`browser` / `local-operator` / `service-client`), `declared`, and the operator
  grant that covered it. They are written in the same single write and sync as the `BEGIN`, so a
  crash between them leaves details with no `BEGIN`: the use never began, the key was not applied.
  Key id and principal are the journal's existing opaque labels on the `BEGIN`. The `FINAL` is the
  existing one: `Applied`, `NotApplied` or `Unknown` honestly; no `FINAL` is `Unknown`.
* **Refusal.** A ticketed key use that is refused writes the same `PluginDetail` frames and a
  `PluginRefusal` frame, carrying the stable subcode id (for example `content-mismatch`,
  `not-granted`, `no-consent-guard`). It writes **no `BEGIN`**: the key was not applied. At most
  four refusals per operation are journaled (a plugin that keeps asking cannot push earlier
  records out); all are also logged as `warn` events (target `oncl::plugin_audit`). The caller
  receives `PermissionDenied`; the subcode is for the operator and, where the HTTP contract
  exposes it, the API client, never the plugin.

Plugins without declarations are unchanged: no ticket, no plugin record (the absence of one is
`declared=false`). No document bytes, parameters, secrets or nonces are ever journaled.
`DurableAuditGuard::plugin_records()` reads these records back for tools.

Things an operator should know:

* **Refusal journaling is best-effort.** It is skipped (the refusal is only logged) when the
  journal is not healthy, when a key use is pending and the segment is full, at the quota, when
  the operation is not bound (unauthenticated or unauthorised requests never write), after the
  fourth refusal of one operation, or when the facts cannot be encoded. It never blocks or
  changes the answer. A use whose facts cannot be journaled (a plugin version or grant id over
  255 bytes) is refused as `audit-fact-too-long` with the key not applied, before the journal is
  touched, and does not affect audit health. Manifest versions are limited to 64 characters;
  a plugin id, a grant's token and its operation to 64 bytes each (so on the server the
  `audit-fact-too-long` check is in practice a defensive one).
* **The content digest is new in the journal.** Earlier journals held only opaque labels; a
  plugin record holds the SHA-256 of the signed content and its length (the design requires it).
  It identifies a document to anyone who can read the journal and guess it; protect the audit
  directory like the keys' secrets directory. It is logged only at `debug` level.
* **Torn multi-frame writes.** A use is several frames written at once; on power loss the
  filesystem may persist later frames without earlier ones. That leaves a hole in the journal,
  which is damage: `open` itself fails and the server does not start (`recover_audit` is not even reached), never a misread `BEGIN`. A cleanly cut tail (a crash before the last write finished) is not a hole: it is repaired by `recover_audit = true` and `plugin_records()` stays readable afterwards.
* **Rolling back.** An older server over a journal that holds plugin frames ends in
  `fatal_corruption` and will not start. Before rolling back, archive or rotate the journal (move
  the whole audit directory away; keep it for inspection) so the older server begins a new one.
* **Format rule for future readers.** Frame kinds `0x80` and above are reserved for records a
  reader that does not know them may skip (the sequence number still counts). Kinds `0x00..0x7f`
  must be understood or the journal is damaged, as today. Nothing uses `0x80` yet, and
  `ONCLAU02` is not bumped; this does not help binaries that are already shipped, and the
  current reader implements no skipping: it treats every kind it does not know as damage.
* **Subcode ids differ from design 4.8** by design: `NotDeclared`, `PackageChanged`,
  `OptionsMismatch`, `ApprovalExpired` are `not-declared`, `package-changed`, `options-mismatch`,
  `approval-expired`; `KeyUseNotApproved` is split into `approval-missing`, `ticket-missing`,
  `ticket-uses`, `key-use-spent`, `key-mismatch`, `operation-mismatch`, `kind-mismatch`,
  `action-mismatch`, `content-mismatch`, `caller-mismatch`, `operation-id-mismatch`,
  `certificate-changed`, `approval-replayed`, `busy`; `manual=false` is `not-manual`; new are
  `not-granted`, `no-consent-guard`, `audit-fact-too-long`, `unknown-plugin`, `derived-unsupported`
  and the request/prepare ids (the prepare ids include `resource-budget` and `no-temporary-store`, raised by the
  manual window's budget check before any key is opened; 49 ids in all). `PlanUnavailable`, `PreviewTooLarge` and `ImportNotDeclared` are not
  implemented (no code path yet).

Inline PKCS#12 keys are available over HTTP only with a double opt-in: the global
`inline_pkcs12 = true` and the token's own `inline_pkcs12 = true` right (both off
by default; see [the HTTP contract](http-api.md), "Keys and secret roles"). The host
grants only the exact immutable inline selector identity computed from the received
container and alias (`AccessPolicy::authorize_inline`), which cannot authorize a File/Token
selector; no wildcard/source identity from a client becomes a grant. The Core
provider accounts secret containers in bounded memory, never document scratch.
`KeySelector::is_inline` exposes classification only, not secret bytes or paths.

## Plugins

A WASM plugin is installed by the operator (`[[plugins]]`: code availability only) and is
reached through one exact `[[plugins.permissions]]` grant per (token, operation); the caller
identity is the token. The full reference is in [the HTTP contract](http-api.md), "Plugin
configuration reference"; the sample is in `deploy/server/server.example.toml`.

```toml
[[plugins]]
id = "vendor.sign"
manifest = "/private/plugins/sign.toml"
wasm = "/private/plugins/sign.wasm"

[[plugins.permissions]]
token = "accounting-service"
operation = "sign-file"            # a declared operation with `server = true`
imports = ["keys_sign_cms_ex"]     # ⊆ the declared imports; empty = all declared
keys = ["corporate-signing"]       # operator-named keys, also in the token's keys
plugin_bytes = true                # the plugin / its client chooses what the key signs
```

* **Plugins that declare their operations** (`[[operations]]` in `plugin.toml`): the grant
  must stay within the declaration (an operation with `server = true`, imports among the declared
  ones, keys only for a declared key use, `pki_endpoints` only for `network = "pki"`); a wider
  grant is **skipped with an `oncl-server: error:` line** and the rest of the server runs. Core
  forces the declared signature options on every call. Because the server cannot tie the signed
  bytes to a document, **any key use needs `plugin_bytes = true`** in the grant; without it the
  use is refused before any `BEGIN` and before the key; a refusal record may be written (`PermissionDenied`, subcode
  `not-granted`, `NotApplied`). A grant with keys but without `plugin_bytes` starts with a
  warning that every key use will be refused; so does a `plugin_bytes` grant of an operation whose key profile names a `param:`. Every start-up skip and warning line is also a `tracing` event (target `oncl::plugin_grants`), and one summary line says how many grants were skipped. With `plugin_bytes = true` on any grant, `audit_segment_bytes` must be at least 4640 (29 frames of 160 bytes: one plugin use writes its detail chunks, its `BEGIN` and reserves its `FINAL`s in one segment); a smaller value is a configuration error. A single use that still does not fit its segment is refused as `audit-fact-too-long` before the journal is touched (the key is not applied and audit health stays healthy). One request (one operation id) can use a key once; a second plugin item or signature in it fails `key-use-spent`. The use is spent only once the audit journal has accepted it: a use the journal refuses (a closed binding, a full or failed journal) does not spend it, and the plugin's retry is decided again. Operations whose profile names a `param:` cannot use keys on the server (`options-mismatch`).
* **Plugins without declarations** (all packages before their manifests carry declarations, and
  third-party ones): nothing changes. The grant is the operator's labels, the options are **not**
  enforced, the audit says `declared=false`, and each such grant logs
  `oncl-server: warning: grant without declaration ...` at start-up. `plugin_bytes` is
  accepted there and has no effect (warned).
* `plugin_bytes = true` without `keys` is refused by configuration validation.
* The audit record of a declared key use (plugin id, package hash, version, operation, ticket
  digest, content and options hashes, `declared`, the grant) and of a refused one is described
  above under "Plugin records in the audit journal"; the `grant` is
  `<token>:<plugin>:<operation>`. Refusals reach the client as the `subcode` of the error
  answer ([error subcodes](http-api.md)).

### Operator guidance for plugin grants

* **Today there is nothing to grant.** The shipped plugins declare 30 operations in total, all
  `manual = true` and none `server = true` (see [the manual-window guide](manual-plugins.md)); a
  server grant for them is skipped with an `oncl-server: error:` line. Grants apply to
  third-party plugins that declare `server = true`, and to plugins without declarations.
* **What `plugin_bytes = true` means.** You accept that the client (and the plugin) chooses the
  bytes that the named key signs: the server cannot bind the content to a document. The
  declared profile is still forced (kind, options, one use per request), the caller must be the
  granted token, the key one of the grant's `keys`, and the package the one installed. The request itself must also pass the token's rights: a `plugin` item that names keys needs the token's `sign` right and every named key in the token's `keys`, in addition to the exact operator grant (otherwise 403, nothing runs). Give
  `plugin_bytes` only to a token whose client you trust with that key.
* **Read the start-up log.** A skipped grant (`oncl-server: error: ... grant skipped: ...`), a
  grant with keys but no `plugin_bytes` (every key use will be refused) and a grant of a plugin
  without declarations (`warning: grant without declaration ...`: options are not enforced)
  each print one line. A skipped grant does not stop the server; check the log after every
  configuration or plugin change.
* **Audit fields of a key use.** Per plugin key use the journal holds: plugin id, package hash
  (kind `1` package file or `2` loose manifest+module, and SHA-256), version, operation, the
  ticket digest, the SHA-256 of the approval nonce (absent for an operator grant), the content
  SHA-256 and length, whether the content was a prehashed digest, the options SHA-256, the caller
  kind, `declared`, and the grant (`<token>:<plugin>:<operation>`); then the usual `BEGIN` and
  `FINAL`. No `FINAL` means `Unknown`: treat the key as possibly used. A refusal holds the same
  facts plus the subcode and no `BEGIN` (best effort, at most four per operation).
  `DurableAuditGuard::plugin_records()` reads them back.
* **The desktop manual window is not in this journal.** The window writes no `ONCLAU02` file; the
  key uses and refusals of the manual window go to the `tracing` target `oncl::plugin_audit`.
* **Rolling back the server.** Before running an older server again, move the whole audit
  directory away (see "Rolling back" above): a journal that holds plugin frames makes the older
  server stop with `fatal_corruption`.
* **Limits of the configuration** (at most 16 plugins, 256 grants per plugin, 8 keys and 16 PKI
  endpoints per grant, ids of 64 bytes; defaults `max_memory` 1 MiB and `max_transfer` 256 KiB)
  are listed in [the HTTP contract](http-api.md).

## Revocation and bounds

A standalone config/ACL change takes effect by graceful restart. Embedding trusted
hosts can revoke identities through `AccessPolicy::revoke` or atomically replace
the checked ACL through `AccessPolicy::replace`; no network request can invoke
either method. A generation change invalidates all previously authenticated Principal
objects for minting *new* grants. Already admitted work retains its original
immutable grant and truthful outcome; revocation does not claim rollback.

Admission precedes body reading, in two steps. A request that carries a body first takes one
of the `max_uploads` upload slots (below) and is then received: waiting for the client and
spooling the documents run without a `max_in_flight` slot and without a native worker.
Only when the whole body has been accepted does the operation take its `max_in_flight` slot,
its audit binding and a native worker: worker/queue slots are acquired before
`spawn_blocking`, and no more than `blocking_workers` native closures run. Queued
owned contexts retain the initial scope/deadline; queue expiry is explicit.
Disconnect/cancel stops waiting and cooperative intake, but a native call's slot
and resources remain owned until that actual call returns. Response bytes retain
the original context/reservation until their network ownership ends. The whole
operation has one finite deadline, not a new timeout at each stage.
The same original early deadline/control and disconnect owner continue through
the real response body and transport. Deferred first polling refuses expired
success bytes; an original-deadline timer aborts pending transport output, and
actual write/flush checkpoints also refuse expired bytes already buffered by
Hyper. Accept/header bounds may shorten, never extend, the operation deadline.
After headers have been sent, expiry is a transport abort, not a promised new
JSON error/status. Timers do not make retained Bytes clones/slices or a running
native operation free: their actual final owners must still release them.

**Aborted response streams.** When a failure ends a response stream that has started (the
server decided `200` and began streaming; how much of the head and the first frames reached
the client varies), the server cuts the response without a terminal record, because no JSON
error can follow. Which failures: a resource, deadline or cancellation failure of the first
operation that applied no key (`MetadataLimit`, `OutputLimit`, `MemoryLimit`, `TempLimit`,
`CapacityExceeded`, ...), one the stream itself observes between frames, and a failure while
building the stream's own frames or terminal record. The client sees only a lost response
(`ResponseLost`) and cannot tell these apart; **the cause is visible only on the server**,
and the protocol and the clients are unchanged. For every such stream the server writes
exactly one line to stderr (and the same facts as a `tracing` event, target
`oncl::stream_abort`, level `error`; the standalone binary installs no `tracing`
subscriber, so there the stderr line is the log):

```
oncl-server: stream aborted: operation=1 route=operations item=0 kind=sign code=metadata_limit cause=MetadataLimit applied=not_applied elapsed_ms=6 bytes_in=0 bytes_out=218
```

| Field | Meaning |
|---|---|
| `operation` | the operation id (the `operation_id` of the progress frames and, for a private operation, of the audit journal's records) |
| `route` | `operations` or `batch` |
| `item`, `kind` | manifest index and operation kind (the closed `oncl.operation.kind` values) of the item that was running; `none` before the first item |
| `code` | the closed `oncl.error.code` value of the typed cause (`metadata_limit`, `output_limit`, `memory_limit`, `temp_limit`, `capacity_exceeded`, `deadline_exceeded`, `cancelled`, `invalid_request`, …) |
| `cause` | the name of the typed failure variant (`MetadataLimit`, `OutputLimit`, …); never its message |
| `applied` | `not_applied`, `applied` or `unknown`: the key-application state of the items that finished before the abort |
| `elapsed_ms` | milliseconds from the start of the response stream |
| `bytes_in`, `bytes_out` | the byte counts of the latest progress snapshot |

Every value is a number or a closed name. No error text, item id, part or file name,
document content, key, password, token, URL or path is ever written (tests assert this
with recognisable values in the request). The same abort increments the counter
`oncl.stream.aborted`. Not covered: a client that disconnects, and a transport abort by the
connection's own deadline timer, which end the body without a typed failure of the
stream. The audit journal is not changed by an abort. A `BEGIN` exists only for a private
key use and the failures of the first kind above come before any key is applied, so there is
no `BEGIN` to finalise; a stream-level failure after a key use leaves the `BEGIN` and the
`FINAL` that the key use itself wrote (`applied`, `succeeded`), and the log line says
`applied=applied`. A `FINAL` has no field for an error code and the frame format is not
changed for this, so the journal never names the abort cause; the log line does, and its
`operation` is the journal's `operation_id`.

**Uploads.** Receiving a request body is a phase of its own with its own limit,
`max_uploads` (unset: 8, or less when `total_temp` holds fewer spools, see below; 1 .. 256). A request that carries a body (`POST /v1/hash`,
`/v1/operations`, `/v1/batch`) takes one upload slot after authentication and before it reads
any byte of the body, and keeps it while it waits for the client, spools its documents to the
scratch directory and, once the body is complete, waits for a `max_in_flight` slot. A client
that stalls mid-body therefore holds one upload slot, its spool and its temp and memory
reservations, and **nothing else**: no `max_in_flight` slot, no `blocking_workers` worker, no
audit binding. Requests without a body (`GET /health`, `GET /v1/openapi.json`) never take an
upload slot, and a request that finds every upload slot taken waits up to `admission_wait_ms`
(a free slot goes to the oldest waiter) and gets `503 CapacityExceeded`/`NotApplied` only if none
freed in that time, before its body is read (Hyper sends `100 Continue` only when the body
is first read, so an `Expect: 100-continue` client sees the refusal instead). The same holds
when every `max_in_flight` slot is busy: before it takes an upload slot the request checks that
an operation slot is free, waits for one up to `admission_wait_ms` (the upload-slot wait takes
the rest of that time, not a second one) and otherwise gets the same `503` without a body byte
read, as it did before the upload phase existed. That check is best effort: a slot can be
taken meanwhile, and the wait after the body (below) stays authoritative. Every exit of the
phase frees the upload slot, the spool and its temp reservation: the end of the body when
the operation has its `max_in_flight` slot (until then a queued operation keeps the upload slot,
see below), a client that disconnects, the idle timeout or minimum rate (below), the operation
deadline, a cancellation, a shutdown and any refusal (such as `InputLimit`).

The phase takes a slot of its own, not one more native worker: waiting for the client is
asynchronous. Received pieces (one Hyper frame: not bounded by the 32 KiB parser buffer, 49,152 and 57,344 bytes were observed, and charged as 64 KiB: a nominal charge, not a measured guarantee; Hyper's read-buffer growth stops at 65,536 bytes, and a larger frame would be under-charged silently) are gathered
into a 256 KiB buffer, charged to the operation's memory budget once per request, and written
to the spool in one short blocking section per 256 KiB, one at a time per upload, on the runtime's
blocking pool. What is gathered is written before the server waits for the client again (so
what the server has received from a stalled client is in the spool, and the disk time is not
charged to the client by the pace rules below), and at the end of each document. "Received"
is what the multipart parser has handed over: it withholds up to the boundary length minus 1
trailing bytes of a document while they could begin a boundary (when they contain `\r`), so
the last few bytes of what a client sent may not be in the spool yet. That pool holds
`blocking_workers + max_uploads` threads so that a long operation cannot keep uploads from
progressing. The hash route (`POST /v1/hash`) hashes each received piece where it arrives, on
the runtime's own threads (a CPU section of one frame), without any spool; a hash upload that
stalls thus holds an upload slot and no worker either.

`max_uploads` is 1 .. 256 and at most `total_temp / (input_bytes + container_bytes)` (integer
division; with the defaults 16 GiB / 2 GiB = 8): every upload must be able to reserve the
largest spool it may need (a signed input spools up to `input_bytes + container_bytes`) in the
shared temp budget at the same time.

* **Unset (the default).** The effective value is `min(8, max(1, total_temp / (input_bytes +
  container_bytes)))`. When the budget lowers it below 8 the server says so once at start, on
  stderr: ``oncl-server: `max_uploads` is not set; lowered from 8 to N because total_temp holds
  M spool(s) of input_bytes + container_bytes``. A `total_temp` smaller than one spool is
  allowed (effective value 1): a larger upload is then refused with `TempLimit`.
* **Set explicitly.** A value of 0, above 256 or above the bound is refused at start, and the
  message names the key and the bound (`` `max_uploads` must be 1..=256 and at most N ``).

The temp budget still bounds every spool: an upload that cannot reserve more is refused with
`TempLimit` as before.

**Migration note (`max_uploads`).** Nothing breaks for an existing configuration: a
`server.toml` that does not set `max_uploads` keeps starting whatever its `total_temp`,
`input_bytes` and `container_bytes` are; the only difference is that the effective default can
be lower than 8 when `total_temp` is small (for example 4 with `total_temp` 8 GiB and the default
allowances), which the start-up line above reports. Before this change a body occupied a native
worker while it arrived, so the upload phase had no limit of its own; setting `max_uploads`
yourself is only needed to go *below* the default or, with a larger `total_temp`, above 8.

**Waiting for an operation slot.** `max_in_flight` bounds the operations that run at
once. A request whose body has been accepted waits up to `admission_wait_ms`, polling every
10 ms with no order guarantee between waiters, for one of them, and gets `503
CapacityExceeded`/`NotApplied` only if none freed in that time (nothing was applied, the
spool is deleted). It keeps its upload slot and its spool until it has the `max_in_flight`
slot, so operations queued here count against `max_uploads` too. The operation deadline starts at the
request's admission to the upload phase and also covers the upload; `admission_wait_ms` is not
part of it, but the deadline keeps running. An admitted operation waits for a free native
worker for at most the same `admission_wait_ms`; with `blocking_workers >= max_in_flight` (the
default) that second wait does not normally arise.

**Stalled and crawling uploads.** An upload that stops must not hold its upload slot and
spool for the whole `operation_timeout_ms` (default 300 s: `max_uploads` silent clients would
block every body-carrying route for five minutes). Every wait for the next body chunk
(hash body, JSON, multipart metadata and documents, the epilogue) is governed by two rules.
Only time spent waiting *for the client* counts, never time spent hashing, spooling or
queueing, so a slow server is never charged to a client.

* `upload_idle_timeout_ms` (default 30 000, 1 000 .. 86 400 000): a wait that delivers no
  byte for that long ends the request.
* `upload_min_bytes_per_second` (default 1 024, `0` = off): idle timeout alone would let a
  client that sends one byte every 29 s keep the slot until the operation deadline. So each
  idle-timeout-long window of waiting must deliver at least this many bytes per second, or
  the request ends. 1 KiB/s is about 8 kbit/s, below any link that can legitimately move a
  document; the rule judges only whole windows, so a client that sends 64 KiB every 25 s
  passes while one byte per second does not. The value may be at most 1 GiB/s. Under
  server-terminated TLS a record (up to 16 KiB) must arrive whole, so keep the idle timeout
  above 16 KiB divided by your slowest legitimate link rate (a 1 s idle timeout refuses
  clients slower than about 16 KiB/s).

Either rule ends the request with the existing `504 DeadlineExceeded`/`NotApplied`: it
happens during intake, before any private key is used, so no audit binding or `BEGIN` is
written, the spool is deleted and the upload slot is free immediately. No new error code
exists. Neither rule replaces the operation deadline, which still bounds a healthy transfer: a
1 GiB upload over a slow link needs `operation_timeout_ms` raised to cover it, not these two
values. A client that keeps delivering at least the minimum rate, without a silence longer
than the idle timeout, is never stopped by them.

**What a stalled upload still costs.** A stalled client no longer starves the service of
workers or operation slots (other requests complete at once next to it), but it does hold
one of the `max_uploads` slots until the idle timeout: with `max_uploads` authenticated clients
stalled at once, every other body-carrying request waits `admission_wait_ms` and gets `503
CapacityExceeded` until a stall ends, while `/health` stays up. The operations that already run
are **not** isolated from the spools: they draw on the same `total_temp` and `total_memory`
budgets. Stalled uploads hold their spools (up to `input_bytes + container_bytes` each) and a
256 KiB gathering buffer each, so `max_uploads` stalled uploads can hold all of `total_temp`
(8 x 2 GiB at the defaults) and a running operation that then needs temp space can be refused
with `TempLimit`. There is no per-token upload limit: one token (one leaked token) can take
every upload slot. A blocking spool write that is still running when its client disconnects
finishes on its own and keeps its buffer (up to 256 KiB, charged until the request ends, so
up to that much uncharged for the duration of one write); such writes can exceed `max_uploads`
writers for that moment, bounded by the pool unless the disk stalls. Lower `upload_idle_timeout_ms` (never below the slowest legitimate link, see
above) and raise `max_uploads` as far as the temp budget allows to widen the margin. A
client that sends exactly the minimum rate holds an upload slot for the whole
`operation_timeout_ms`; on a LAN raise `upload_min_bytes_per_second` to tens of KiB/s. The
reverse direction is not governed either: a client that never reads a large response pins
its in-flight slot until the operation deadline.


There are also finite pre-auth connection/header/TLS-handshake limits. HTTP/1
header count is capped at 64 and a connection's parser buffer at 32 KiB. These
network buffers/runtime overhead are separate from Core's aggregate document
working-memory accounting; resource counters are not a claim about total RSS.
A connection that has been answered keeps its `max_connections` permit, and nothing of its
operation, until the client closes its side or the staged close ends, at most one second
after the answer (see [the HTTP contract](http-api.md)): with `max_connections` clients that
keep their sockets open after an answer, the next connection is not accepted for up to that
second.
The server stack is optional/server-only: minimal SDK crates and desktop/Win7
build closures do not depend on Axum/Hyper, and static CRT/toolchain policy is
unchanged. This Windows-host acceptance is not a Linux/macOS/Win7 runtime result
or the later 1-GiB XML/PDF resource-harness gate.

## Explicit PKI roots and endpoint pins

Verification has no implicit document trust store and denies outbound PKI by
default. Configure trusted certificate files and exact address-pinned origins in
the private operator configuration, never in request metadata:

```toml
[pki]
anchors = ["/operator/roots/root.der"]
intermediates = ["/operator/roots/intermediate.der"]

[[pki.endpoints]]
origin = "https://ca.example:443"
addresses = ["203.0.113.10:443"]
```

Each file is one DER/PEM certificate, at most 1 MiB; total configured certificate
bytes are capped at 16 MiB, with at most 256 anchors and 256 intermediates. Keep
these operator trust files protected against modification. Origins have at most
16 explicit addresses each, at most 128 origins; a literal host cannot be silently
repinned to another IP/port. The SDK's actual network policy validates these pins.
No incoming URL, certificate-carried root or JSON policy flag installs trust.
TLS listener certificates and document-validation roots are separate settings.
The service does not install certificates in the OS/browser trust stores.

## Optional OTLP telemetry

The service can export operational **metrics and traces** to an operator-chosen OTLP
collector. It is **off by default**: with no `[telemetry]` table, or with
`enabled = false`, the process starts no export thread, builds no exporter and opens
no connection to any collector. OTLP **logs are not implemented**; local technical
logs and the audit journal stay separate mechanisms. The SDK crates, the CLI and the
desktop application never contain this code or its dependencies.

```toml
[telemetry]
enabled = true
endpoint = "http://127.0.0.1:4318"   # OTLP/HTTP base URL; /v1/traces and /v1/metrics are appended
service_name = "oncl-server"         # `service.name` resource attribute (operator value)
metrics = true
traces = true
trace_sample_ratio = 1.0             # traces only; metrics are never sampled
export_interval_ms = 10000           # metric interval and span batch delay (100 .. 3 600 000)
export_timeout_ms = 3000             # hard bound of one export HTTP call (100 .. 60 000)
connect_timeout_ms = 1000            # <= export_timeout_ms
queue_size = 2048                    # queued, not yet exported spans (16 .. 65 536)
batch_size = 512                     # <= queue_size
shutdown_timeout_ms = 5000           # bound of the final flush (100 .. 60 000)
# headers = { authorization = "Bearer <collector credential>" }   # at most 8, operator secret; https or loopback only
# ca_file = "/private/oncl-operator/collector-ca.pem"             # https only: the collector's CA (PEM)
```

An enabled configuration is validated at startup (`http`/`https` URL without user
info, query or fragment; at least one of `metrics`/`traces`; header names are tokens,
never `host`/`content-*`/`connection`/…, values are printable ASCII). **`headers`
(a collector credential) are refused unless the endpoint is `https` or its host is
loopback (`localhost`, `127.0.0.0/8`, `::1`)**, so a credential never crosses the
network in cleartext. `ca_file` requires `https`. An invalid configuration refuses to
start the service, with a generic error that never echoes header values. Unknown
keys are rejected.

### Transport and boundedness

* **OTLP/HTTP with protobuf bodies**, one POST per export, no gRPC, no compression, no
  redirects, no environment proxy. The client is the workspace `ureq` (rustls with
  ring). `https` verifies the collector against the built-in web PKI roots, or, with
  `ca_file`, only against the PEM CA certificates (at most 8, 1 MiB) in that file;
  the operator PKI trust set above is not used for it. `OTEL_*` and proxy environment
  variables are not configuration: the endpoint and timeout come from this table, any
  header the environment would add is dropped by the transport, and compression
  requests (`OTEL_EXPORTER_OTLP_*COMPRESSION`) are ignored (payloads stay plain
  protobuf). The collector endpoint is operator-trusted egress and is **not** subject
  to the `[[pki.endpoints]]` pinning.
* **Two named threads, no more:** `oncl-otlp-traces` (span worker) and
  `OpenTelemetry.Metrics.PeriodicReader` (metric reader), one per enabled signal. A
  short-lived `oncl-otlp-shutdown` thread exists only during shutdown. No operation
  thread ever touches the network: producers `try_send` into a fixed-size queue
  (`queue_size`) and never wait.
* **Drop accounting, not blocking.** A full queue, a failed export or a post-failure
  back-off drops the affected spans and counts them. The count is visible in
  `Telemetry::stats()` and, once a collector answers again, as the metric
  `oncl.telemetry.dropped{oncl.signal=spans|metrics}`. Metric points are aggregated in
  place (closed dimensions below), so only their *export* can fail, never their memory.
* **No retry storms.** One attempt per batch; after a failure the worker backs off
  (`export_interval_ms · 2^n`, at most 30 s) and discards what it would have sent.
  A hanging collector blocks only the export thread, for at most `export_timeout_ms`.
* **Bounded shutdown.** `serve` ends with a flush limited to `shutdown_timeout_ms`;
  a dead or hanging collector cannot keep the process open longer. An export still
  inside its (hard-timeout) HTTP call at the deadline is abandoned, not waited for.
* **Audit is separate and untouched.** Trace sampling (`trace_sample_ratio`), drops,
  a down collector or a failed exporter cannot remove, delay or replace a mandatory
  audit record, and OTLP is never evidence that audit was written. Audit health stays
  its own guard and `/health` signal.

### Safe vocabulary (what can leave the process)

Every attribute is a value of a small closed type (`SafeAttr`); there is no constructor
from a string, path, identifier or error text, no automatic body/header
instrumentation, no request/client/key/token identifier, and no metric label with
unbounded cardinality. Resource attributes are only `service.name` and `service.version`;
the instrumentation scope is `oncl-server`; spans carry no events, links or exemplars.

| Attribute | Values |
|---|---|
| `oncl.route` | `hash`, `operations`, `batch` |
| `oncl.operation.kind` | `hash`, `verify`, `extract`, `sign`, `extend`, `jws_sign`, `jws_add`, `jws_verify`, `jwt_encode`, `jwt_decode`, `jwt_verify`, `plugin`, `inspect`, `stamp`, `verify_stamp` |
| `oncl.operation.family` | (sign only) `cms`, `cades`, `pdf`, `pades`, `xml`, `xades`, `wsse`, `xml_legacy`, `xades_legacy` |
| `oncl.outcome` | `ok`, `rejected` (refused before work), `failed`, `aborted` |
| `oncl.error.code` | the stable public error codes (`permission_denied`, `invalid_request`, `capacity_exceeded`, `deadline_exceeded`, `audit_unavailable`, `validation_failed`, `operation_failed`, …) |
| `oncl.key.applied` | `not_applied`, `applied`, `unknown` |
| `http.response.status_code` | the status of the response head (`200`, `400`, `403`, `404`, `408`, `413`, `422`, `500`, `503`, `504`) |
| `oncl.delivery` | `complete`, `aborted` |
| `oncl.stage` | `wait`, `run` |
| `oncl.signal` | `spans`, `metrics` |

Spans (`oncl.request` is the root; the others are its children in the same trace):
`oncl.request` (route, outcome, error code, status, delivery), `oncl.admission`
(request start to executor hand-off: for a request with a body this includes receiving the
body, the wait for an upload slot and the wait for an operation slot, so it is dominated by
the client's upload time, not by queueing), `oncl.executor.wait`, `oncl.executor.run`,
`oncl.operation` (one per executed item: kind, family, outcome, error code, key
applied state), `oncl.delivery` (response body delivery).

Metrics: counters `oncl.requests`, `oncl.operations`, `oncl.key.uses` (counts of
operations that applied or may have applied a private key; **no key identity**),
`oncl.stream.aborted` (response streams the server cut short after the head, by route,
`oncl.error.code` and `oncl.key.applied`; see "Aborted response streams" above),
`oncl.executor.rejected`, `oncl.telemetry.dropped`; histograms in seconds
`oncl.request.duration`, `oncl.admission.duration` (includes the upload, see above),
`oncl.executor.duration`,
`oncl.operation.duration`, `oncl.delivery.duration`, and `oncl.response.size` (bytes);
gauges `oncl.requests.in_flight`, `oncl.executor.running`, `oncl.executor.queued`.

### Limits of the guarantees

* Health and OpenAPI requests and transport-level failures before a request reaches a
  route (malformed HTTP, connection limits) are not observed.
* A streamed response's head status is `200` even if a later item fails; the per-item
  outcomes are the `oncl.operation` spans and the `oncl.operations` counter, and the
  request outcome becomes `failed` when any item failed. Items of `/v1/batch` have no
  per-item duration (the SDK runs the closed batch as a unit), so they appear only in
  the `oncl.operations`/`oncl.key.uses` counters and the request outcome, not as spans.
* Durations, response sizes and the timing of requests are exported and can reveal
  coarse activity patterns to the collector operator; trace/span ids are random and
  not derived from any request value. Treat the collector as part of the service's
  trust boundary and protect `headers`.
* Drops under a slow or down collector are expected and counted; telemetry is not a
  delivery guarantee and is never an audit record.
* TLS to the collector verifies the certificate always (never skipped). The default
  trust is the built-in web roots; `ca_file` replaces it with the operator's own CA.
  Revocation checking and client certificates (mTLS) are not supported.
* An incoming `traceparent`/`tracestate` header is ignored: every request starts its
  own trace, so a client can neither join, force nor suppress sampling of a trace.

## Package, service and container (operations)

`oncl-server` ships as an archive of its own, `oncl-server-<version>-<flavor>.zip` (Windows: `win-x64`, `win-x86`, `win7-x64`, `win7-x86`) or `.tar.gz` (`linux-x64`, built against glibc 2.28; `osx`, universal), next to the separate `oncl-<version>-<flavor>` command-line archive. Neither is part of the OpenNCALayer desktop package, and nothing in them installs, enables or starts anything: no installer, no autostart, no trust-store change, no self-update. An archive holds the program, `README.md`, `server.example.toml` (the API **disabled**, no token, key or secret), `docs/`, `THIRD-PARTY.txt` (the licences of the third-party code of exactly that flavor: the Unix flavors add AWS-LC, which the Windows flavors do not contain), `LICENSE`, `NOTICE`, and on Linux `deploy/openncalayer-server.service` and `deploy/Dockerfile`. It holds no certificate, key, password, token or test file. The maintainer builds, gates and smoke-tests the archives with `cargo xtask package platform` (`cargo xtask package platform --help`); that command uploads and publishes nothing.

**Updating is the operator's act**: unpack the newer archive, replace the program and restart the service (or rebuild the image from the newer archive). The program never contacts an update server. Replacing it does not touch the configuration, key containers or the audit journal.

### What the packaged programs were checked to do

`cargo xtask package platform` unpacks the archives it just made into an empty directory and starts the **unpacked** programs, without a GUI: `oncl --version`, `oncl hash` of a file and of stdin against an independent SHA-256, `oncl verify` refusing a file that is not a signature; then `oncl-server` without a subcommand and `serve` with the shipped example configuration, which must end by themselves while their control pipe stays open, with the operating system's socket table showing no listener on the configured port and a connection to it refused; then the explicit opt-in on loopback (a token from `token-create`, a named synthetic RSA key, loopback OCSP/CRL of a synthetic PKI, `--enable-api`), where the socket table shows exactly one loopback listener of the server process, `oncl --endpoint … sign` makes a CMS signature that `oncl verify` reports `Valid` and `extract` returns the document, the audit journal exists, and a newline on `--shutdown-stdin` stops the service and closes the port. `cargo xtask package platform-smoke` repeats only this part on archives that already exist.

### Linux service account and systemd

The unit is a file you copy; copying it does not enable or start the service, and `ConditionPathExists` keeps it from starting before a configuration exists.

```sh
tar -xzf oncl-server-<version>-linux-x64.tar.gz
cd oncl-server-<version>-linux-x64
sudo useradd --system --user-group --home-dir /var/lib/oncl-server --no-create-home --shell /usr/sbin/nologin oncl-server
sudo install -m 0755 oncl-server /usr/local/bin/oncl-server
sudo install -d -m 0700 -o oncl-server -g oncl-server /etc/oncl-server
sudo install -m 0600 -o oncl-server -g oncl-server server.example.toml /etc/oncl-server/server.toml
sudo install -m 0644 deploy/openncalayer-server.service /etc/systemd/system/openncalayer-server.service
sudo systemctl daemon-reload
```

The unit runs as `oncl-server` with `NoNewPrivileges`, an empty capability set, `ProtectSystem=strict` (only `/var/lib/oncl-server`, its state directory, and `/etc/oncl-server` are writable: the private-file API opens the configuration read-write), `PrivateTmp`, `PrivateDevices`, `PrivateUsers`, no address family but IPv4/IPv6, a system-call filter, `MemoryMax=1G` (about twice `total_memory`: the HTTP stack and framing are outside the document budget), `TasksMax`, no core dumps and `UMask=0077`. `systemd-analyze security` rates it 1.1 (OK). It sets `KillSignal=SIGINT` because the service drains admitted operations on SIGINT only; SIGTERM ends it at once (exit 143). With the example configuration (`enabled = false`) `systemctl start openncalayer-server` ends at once with `disabled: no listener` in the journal and opens no listener. The service starts listening only after you configure a token, enable the API and run `sudo systemctl enable --now openncalayer-server` yourself.

`recover_audit`: a journal that exists is reopened only with `recover_audit = true`; after a clean stop a restart with `false` is refused. A service that restarts (`Restart=on-failure`, a reboot) therefore keeps `recover_audit = true` once it is enabled; the first start creates the journal and is unaffected.

### Token provisioning

Run the real subcommand as the service account. It creates a new 256-bit token file in the private directory, refusing to overwrite one, and prints only its verifier:

```sh
sudo -u oncl-server /usr/local/bin/oncl-server token-create --directory /etc/oncl-server --name accounting.token
# verifier=<64 hexadecimal characters>
```

Put the verifier, never the token, into `server.toml`, and write that file as the service account with `umask 077`: a configuration that anyone else can read or replace is refused.

```sh
sudo -u oncl-server sh -c 'umask 077 && cat > /etc/oncl-server/server.toml' <<'EOF'
enabled = true
bind = "127.0.0.1:13579"
audit_directory = "/var/lib/oncl-server/audit"
recover_audit = true
scratch_directory = "/var/lib/oncl-server/scratch"

[[tokens]]
id = "accounting"
verifier = "<the verifier printed above>"
actions = ["hash", "verify"]
keys = []
EOF
```

Deliver `accounting.token` to that client over a channel you trust, into an owner-only directory on the client (`install -d -m 0700 ~/.oncl`, then a file written with `umask 077`; the client refuses a readable token file), and pass it with `--token-file`. Remove it from the server afterwards (`sudo -u oncl-server rm /etc/oncl-server/accounting.token`): the server only needs the verifier. Rotating a token is creating a new one, replacing its verifier and restarting.

The client stages what it downloads (OCSP, CRLs) in its working directory unless `--temporary-directory` says otherwise, and on Unix it refuses a directory that others can reach: run `oncl` from an owner-only directory when it verifies against online PKI.

**Windows.** The private-file check requires files with a protected ACL holding exactly one inheritable entry for the owner; `icacls` and PowerShell `Set-Acl` cannot produce it (measured). Use the program itself, which creates such files through the same private-file API, never overwrites, and prints only the name and size:

```bat
oncl-server install-file --directory %ProgramData%\oncl-operator --name server.toml --input server.toml
oncl-server install-file --directory %ProgramData%\oncl-operator --name corporate.p12 --input corporate.p12
type corporate.password | oncl-server install-file --directory %ProgramData%\oncl-operator --name corporate.password
oncl-server token-create --directory %ProgramData%\oncl-operator --name accounting.token
oncl-server serve --config %ProgramData%\oncl-operator\server.toml --enable-api
```

`--directory` is created owner-only if absent or must already be private; `--name` is one plain file name (no path, drive, stream or reserved device name such as `NUL`); input is at most 16 MiB; a refused name or oversized input creates nothing (not even the directory); if writing the file fails, the file is removed and a directory created by this command is left empty, and a failure of the final directory sync leaves the completed file in place. The same command works on Linux in place of `install -m 0600`. Delete the plain source files afterwards.

### TLS provisioning (LAN exposure)

A non-loopback bind needs `hosts` and either real TLS or a trusted proxy ([Explicit LAN exposure](#explicit-lan-exposure)). The service creates no CA and installs no certificate. Create the key as the service account, owner-only, and a request for your CA to sign:

```sh
sudo -u oncl-server sh -c 'umask 077 && install -d -m 0700 /etc/oncl-server/tls && cd /etc/oncl-server/tls && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server.key && openssl req -new -key server.key -subj "/CN=signing.internal" -addext "subjectAltName=DNS:signing.internal" -out server.csr'
```

Install the certificate chain your CA returns (PEM, server certificate first) as `/etc/oncl-server/tls/server.crt`. For a laboratory without a CA, a self-signed **end-entity** certificate (`CA:FALSE`; the default `openssl req -x509` certificate is `CA:TRUE` and the client refused it as a server certificate, `TlsFailed`) that clients then trust explicitly is enough. It is not a production certificate:

```sh
sudo -u oncl-server sh -c 'umask 077 && cd /etc/oncl-server/tls && openssl req -x509 -key server.key -days 365 -subj "/CN=signing.internal" -addext "subjectAltName=DNS:signing.internal,IP:127.0.0.1" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=serverAuth" -out server.crt'
```

```toml
bind = "0.0.0.0:13579"
hosts = ["signing.internal:13579"]
exposure = { mode = "tls", certificate = "/etc/oncl-server/tls/server.crt", private_key = { directory = "/etc/oncl-server/tls", name = "server.key" } }
```

The client trusts exactly that certificate: `oncl --endpoint https://signing.internal:13579 --ca-file server.crt --token-file ~/.oncl/accounting.token hash --algorithm sha256 --input document.bin`. Without `--ca-file` it fails (`TlsFailed`); there is no flag that skips verification.

### Container

`deploy/Dockerfile` builds the image **from the release archive** (no source, no download) on a Debian 12 slim pinned by digest, as a non-root user (uid/gid 10001) with no configuration inside it. Build from a directory that holds the archive:

```sh
tar -xzf oncl-server-<version>-linux-x64.tar.gz
docker build -f oncl-server-<version>-linux-x64/deploy/Dockerfile --build-arg VERSION=<version> -t oncl-server:<version> .
```

Mounts are explicit: `/etc/oncl-server` (private configuration, key containers, TLS key) and `/var/lib/oncl-server` (the audit journal `audit/` and `scratch/`, created by the service at its first start: mount a **volume** so the journal outlives the container, and do not create `audit/` yourself; an existing empty one is refused). The private-file rules hold inside the container, so prepare the volumes as the image's own user (uid 10001, mode 0700) and never mount a home directory:

```sh
docker volume create oncl-config
docker volume create oncl-state
docker run --rm -i --user 10001:10001 -v oncl-config:/etc/oncl-server --entrypoint sh oncl-server:<version> -c 'umask 077 && cat > /etc/oncl-server/server.toml' < server.toml
docker run --rm --user 10001:10001 -v oncl-config:/etc/oncl-server oncl-server:<version> token-create --directory /etc/oncl-server --name accounting.token
docker run -d --name oncl-server --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 1g --memory-swap 1g --pids-limit 256 --tmpfs /tmp:rw,size=64m,mode=1777,noexec,nosuid \
  -v oncl-config:/etc/oncl-server -v oncl-state:/var/lib/oncl-server \
  -p 127.0.0.1:13579:13579 oncl-server:<version>
```

(Put a TLS key into the volume the same way: `… --entrypoint sh … -c 'umask 077 && mkdir -p /etc/oncl-server/tls && cat > /etc/oncl-server/tls/server.key' < server.key`, and read the token out with `--entrypoint cat`.) Inside the container `bind` must be `0.0.0.0:13579` with `hosts` equal to the authority clients use, and TLS or `trusted_proxy`; `-p 127.0.0.1:…` publishes it on the host's loopback only. With the example configuration the container prints `disabled: no listener` and exits 0. Never use `--privileged`. The image sets `STOPSIGNAL SIGINT`, so `docker stop` drains admitted operations (give it `--time` beyond `operation_timeout_ms`; the default Docker grace is 10 s). `--memory 1g` is the container budget for the example's `total_memory`; scratch space is bounded by `total_temp`, so size the `oncl-state` volume for it or lower `temp_per_operation` and `total_temp`. Lowering `total_temp` also lowers the number of bodies received at once: with `max_uploads` unset the server uses `min(8, total_temp / (input_bytes + container_bytes))` (at least 1) and logs the lowered value once at start, while an explicit `max_uploads` above that bound is refused at start (see "Uploads" above). The image's `HEALTHCHECK` only tests that the port (`ONCL_HEALTH_PORT`, default 13579) accepts a TCP connection from inside the container: the authenticated `GET /health` needs a token, which the image must not hold, so probe it from your monitoring with a token that has the `hash` right.

### Not done / not exercised here

* The programs and archives are not signed (no Authenticode, no notarization) and nothing is published to a registry, release or browser store: the release workflow builds the archives as workflow artifacts only.
* The macOS packaging path (universal check, tar.gz) and the CycloneDX SBOM job were not executed; Windows 7 packages were import-gated and started on Windows 10, not on Windows 7 itself.
