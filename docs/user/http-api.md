# Typed HTTP request contract

The standalone service exposes `POST /v1/operations` in addition to the original
raw `POST /v1/hash`. Both require the individual bearer token and exact configured
Host authority described in [server.md](server.md). There are no NCANode
compatibility aliases, request-controlled filesystem paths, trust roots, grants,
limits, method overrides, administrative actions, retries or stored jobs.

## JSON-small

Use `Content-Type: application/json`. The complete encoded entity is limited to
65,536 bytes independently of the document limit. Document values are UTF-8 text,
not base64 encodings of large files. Duplicate document names, unknown fields,
unused parts, duplicate item/part identifiers and mismatched item ownership are
errors. Item and part identifiers contain 1–128 ASCII letters, digits, `_` or `-`.

```json
{
  "metadata": {
    "items": [
      {"id":"invoice","operation":{"kind":"hash","algorithm":"sha256","input":"source"}}
    ],
    "parts": [
      {"name":"source","item_id":"invoice","role":"document"}
    ]
  },
  "documents": {"source":"abc"}
}
```

The typed `hash` operation's explicit algorithm is one of
`sha1`, `sha256`, `sha512`, `gost34311`, `streebog256`, `streebog512`; an algorithm
is not inferred from a filename or document contents. A hash request needs the
`hash` action and cannot select a key. Hashing SHA-1 is not signing permission.

`verify` requires the distinct `verify` token action before document intake. Its
metadata is `{"kind":"verify","profile":"cms","input":"signature"}`; optional
`detached` names a second declared public document. Available SDK profiles are
`cms`, `cades_b`, `cades_t`, `cades_lt`, `cades_lta`, `pdf`, `pades_b`, `pades_t`,
`pades_lt`, `pades_lta`, `xml`, and `xml_kalkan`. These select the actual verifier,
not a filename guess. No wire roots, validation mode or network privileges are
accepted. The service's default trust set is empty and PKI network is denied;
this does not promote a valid cryptographic signature to trusted validity.

A cryptographically invalid signature is a completed HTTP 200 result with
`kind:"verification"` and `verdict:"Invalid"`, not HTTP 500. Results carry actual
per-signer signature, chain, validity, revocation, timestamp and key-usage checks,
the host policy, checked time and time basis. Diagnostic reasons are explanatory
text, not additional authorization or a replacement for the typed check fields. A signature
that is cryptographically intact but misses a CAdES/PAdES baseline rule (for example the
signing-time attribute Kalkan writes into a PAdES CMS, which EN 319 142-1 forbids) shows
every check `Passed` or `Unavailable`, a `Profile(...)` reason and `verdict:"Invalid"`; read
the verdict and the reasons together, not the six checks alone.

## Metadata-first multipart

Use `Content-Type: multipart/form-data; boundary=<boundary>`. Boundary length is
1–70 ASCII characters from the multipart boundary alphabet. The first field must
have `Content-Disposition: form-data; name="metadata"`, no filename, and contain
only the `metadata` object from the JSON example, limited to 65,536 encoded bytes.
It is parsed before the host resolves the action and grants authority. No extra
authority header or duplicate metadata copy is required.

After this first field, send each declared part once using its declared name:

```text
--example-boundary\r\n
Content-Disposition: form-data; name="metadata"\r\n
\r\n
{"items":[{"id":"invoice","operation":{"kind":"hash","algorithm":"sha256","input":"source"}}],"parts":[{"name":"source","item_id":"invoice","role":"document"}]}\r\n
--example-boundary\r\n
Content-Disposition: form-data; name="source"; filename="invoice.bin"\r\n
Content-Type: application/octet-stream\r\n
\r\n
<actual binary document bytes>\r\n
--example-boundary--\r\n
```

Here `\r\n` denotes actual CRLF bytes, not the four printable characters.
Unknown, duplicate, missing or late-changing fields are refused. The current hash
operation accepts only `document` roles; a `secret` role, including a secret with
a document filename/content type, cannot be reclassified into a hash document.
A Content-Disposition filename is untrusted display metadata, never a filesystem
name. Public documents are immutable, randomly named owner-only SDK snapshots in
the explicit operator `scratch_directory`; no spool is created from filenames.
The directory must be private if already present. Scratch disappears when its
last owner is released and is not an archive or a persistent queue.

Content-Length is optional. Actual bytes are counted, including unknown-length
chunked uploads and overflow probes. Wire chunks may split every delimiter and
CRLF; a legal 64-KiB wire chunk is not rejected merely because of its chunk size.
Document bytes and framing overhead have separate quotas. Closing-delimiter
read-ahead and remaining HTTP entity bytes are also counted, so an oversized
epilogue cannot borrow an unused document allowance or wait out an advertised
tail before being refused.
Raw framing is now observed at the pinned parser's existing byte-consumption
transitions, including proven partial headers and preambles, before further body
waiting or header-map allocation. An over-budget complete or partial part header
is `FramingLimit`/413 even when its document body is never sent. Exhausting the
separate header admission cap is `MetadataLimit`/413; malformed/truncated framing
remains `InvalidRequest`/400. The first owned transport/resource/control cause is
shared immutably through parser, field-reader, worker and terminal-status
selection, including when worker delivery is delayed past the original deadline.
It is never inferred from error text or replaced by a later cancellation.

**Document allowance and signed results.** `input_bytes` bounds a document, and a document one
byte past it is `InputLimit`/413. The `input` part of a `verify`, `extend`, `extract` or `sign`
item may already be a signed result (a document plus the signature, revision or envelope bytes
that this service or another signer added), so it may exceed `input_bytes` by those container
bytes only, and never past `container_bytes` (default 1 GiB, the SDK default) or the bound the
format itself has (for example about 188 MiB of appended PDF revisions). The server spools such
a part as unclassified wire of at most `input_bytes + container_bytes` without charging the
document allowance, and the engine then reads it as it reads any file given to the SDK or the
CLI: it classifies the signature bytes, charges `input_bytes` for the document part and the
container allowance for the rest, so a signed result of a document that was exactly at
`input_bytes` is accepted again by the service that produced it, and a parsable document part one byte
past `input_bytes` is still `InputLimit`, signed or not (unparsable garbage in that role is
`InvalidRequest`/400, because the engine cannot classify it). The wire ceiling of a request with such
an input is `input_bytes + container_bytes + framing_bytes + 64 KiB` (the metadata part); the
ceiling of every other multipart request is `input_bytes + framing_bytes + 64 KiB`, and `/v1/hash` takes a raw body of at most `input_bytes`.
Every other document part (a detached payload, an inspected container, JOSE input) stays within
`input_bytes` at once. Evidence parts (`certificate`, `ocsp`, `crl`) are validation material, not
documents: each is bounded at 1 MiB and the engine's evidence limits, and none is charged to the
document allowance, exactly as the CLI reads evidence files. The oversize refusal of a signed
input is found by the engine after the response status is chosen, so a streamed request reports
it as a failed final record with `InputLimit` and `NotApplied`, never as a dropped stream. CAdES
follows the same rule for verify, extend and `add`: an attached result is document + signature,
and a detached signature (the `input` part) is container only, its detached payload being a
document of at most `input_bytes` of its own, so the signature and a payload of exactly
`input_bytes` are accepted together.

Scratch and sizing. Lowering `input_bytes` requires lowering `container_bytes` too. At the
defaults one `input` part of a verify, extend, extract or sign item is spooled up to
`input_bytes + container_bytes` (2 GiB) before the engine refuses an unsupported document, and
the engine then copies about `input_bytes` (a CAdES verify, extend or add copies the wire again
while it parses it, up to `input_bytes + container_bytes` plus one 256 KiB chunk before a
hostile wire is refused, so up to about 4 GiB at the defaults together with the upload
spool), so a hostile upload can write several GiB to
the scratch before it is refused; this is bounded by `temp_per_operation`, `total_temp`,
`max_uploads` (the bodies being received) and `max_in_flight`. Measured peaks: signing a
document at the limit holds about 3x `input_bytes`
of scratch, and verifying a signed result about 2x. Rule of thumb:
`temp_per_operation >= 3 * (input_bytes + container_bytes)`. The configuration does not check
this rule, only that an explicit `max_uploads` lets every upload spool its largest input at once:
`max_uploads <= total_temp / (input_bytes + container_bytes)` (unset, `max_uploads` is
`min(8, max(1, that bound))`). A request declaring a length past the ceiling is refused at once with `InputLimit`; an
upload without a declared length is counted and refused with `FramingLimit` when the wire passes
the ceiling. A sign or extend item takes at most 64 evidence references (more is
`InvalidRequest`, before any part is read). `container_bytes` must be positive and
`input_bytes + container_bytes + framing_bytes + 64 KiB` must fit in 64 bits.

The implementation uses pinned `multer` 3.1.0 for multipart parsing. Its feeder
admits at most 8,192 new bytes while parsing unknown-role headers/preamble, in
addition to at most one previous 4,096-byte data chunk and boundary suffix. It
forces cooperative polling so an always-ready upload is not collected into the
parser. Header count is additionally bounded by the parser; metadata fixes the
exact permitted names and total part count. The actual standalone Hyper read
buffer is capped at 32,768 bytes; per-connection HTTP/TLS transport overhead is
separate from the SDK working-buffer reservations. Per-request parser, decoded
metadata and retained ingress allocations are admitted before allocation. This
is not a claim of the 1-GiB XML/PDF resource acceptance gate.

## Result and errors

A completed typed hash response has `Content-Type: application/json`:

```json
{"type":"final","operation_id":1,"status":"completed","results":[{"item_id":"invoice","applied":"NotApplied","result":{"kind":"hash","algorithm":"sha256","digest":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","bytes_in":3}}]}
```

The operation ID varies; item IDs echo the validated metadata. Item `bytes_in`
counts the actual document bytes, including immutable uploaded snapshots; replay
does not debit the original input quota a second time. Only a complete terminal
result is success.

## Streaming artifact responses

`extract` is an actual SDK structural CMS-content extraction operation, not a
signature-validation assertion. Its request metadata is
`{"kind":"extract","input":"container"}` with the referenced public document.
It requires the distinct `extract` token action and configured private scratch.

Requests containing extraction return `multipart/mixed` with a random boundary.
JSON `progress` parts contain actual operation ID and coalesced byte counters;
they are not success receipts. Binary `artifact` parts carry a server-generated
`Content-ID` and exact `Content-Length`. The JSON `final` part links the extraction
result's `artifact` ID to those bytes and is the sole completed-result authority.
There are no callback URLs, stored jobs or follow-up artifact paths.

The server completes bounded input staging before starting this response, so a
blocking upload-then-read client need not consume output concurrently with upload.
SDK processing remains in the admitted native worker. That worker materializes
bounded public output and releases its permit; socket backpressure never keeps a
PKI worker occupied. Delivery reads one admitted 256-KiB region at a time through
the SAME bounded executor. Its opaque task accepts only a finished artifact and
the actual matching output owner, never an arbitrary caller-supplied scope.
The original context, root, output files and reservations remain attached to all
actual response-byte clones/slices until their final drop.

Small progress/final metadata and MIME framing have actual output accounting;
SDK-produced artifact bytes are not charged a second time by the disk adapter.
The private disk adapter reserves temporary storage before file growth, caps a
write quantum, records successful partial writes and checks flush/sync/extent
before making an artifact readable. Header/nonce ownership authorizes deletion
only of its own generated files; incomplete or failed output is never published.

A client must stage artifact bytes and require the final result, closing MIME
delimiter AND successful completion of the HTTP entity before publishing. An
execution/read/deadline failure after headers can abort transport; a valid prefix
or a progress part is never partial success. No terminal result means no publish,
not a claim that a prior private effect was rolled back.

Before a completed response, execution failures use the stable `code` and
`applied` envelope from the raw service: 403 PermissionDenied, 400 InvalidRequest,
413 byte/resource limit, 503 CapacityExceeded/AuditUnavailable, or 504
DeadlineExceeded (also for an upload that stalls or falls below the minimum upload rate,
see [the server guide](server.md)). An error answer may add an optional `subcode` string next
to `code` (see "Error subcodes" below). Hashing never applies a private key. Authentication occurs
before body intake. Receiving the body is a phase of its own with its own limit
(`max_uploads`): a request takes an upload slot before its first body byte is read, and
neither waiting for a slow client nor spooling the documents takes a `max_in_flight` slot, a
native worker or an audit binding, so a stalled upload leaves every other request unaffected
except for that one upload slot. `503 CapacityExceeded` means that no upload slot (before the
body is read) or, once the whole body was accepted, no operation slot freed within the
server's `admission_wait_ms`; nothing was applied. The original admission root starts before
bounded metadata intake, then the host consumes that same root into an authorized operation
context. Queueing, SDK work, response ownership and actual network writes retain
the original deadline and shared budgets. Dropping a response does not make a
still-running worker free, and retaining/cloning response bytes retains their
original reservation/root until the actual final drop.

## Operation families

All operations use the same `metadata` envelope (JSON-small or metadata-first
multipart). `GET /v1/openapi.json` (authenticated like `/health`) publishes the
OpenAPI 3.1 description with request and response examples that are parsed and
serialized by the real DTOs. Each token needs the matching action:

| `kind` | Token action | Output |
|---|---|---|
| `hash` | `hash` | JSON |
| `verify` (`cms`, `cades_*`, `pdf`, `pades_*`, `xml`, `xml_kalkan`, `xades_*`) | `verify` | JSON; Invalid is a completed HTTP 200 report |
| `extract` | `extract` | `multipart/mixed` artifact |
| `sign` (`cms`, `cades_b/t/lt/lta`, `pdf`, `pades_b/t/lt/lta`, `xml`, `xades_b/t`, `wsse`, `xml_legacy`, `xades_legacy_b/t`; there is no `xades_lt/lta` sign profile; `mode` `create`/`add` for CMS/CAdES; XML takes optional `target`/`parent`/`signature_id` element IDs) | `sign` plus per-key right | `multipart/mixed` artifact |
| `extend` (`cades_t/lt/lta`, `pades_t/lt/lta`, `xades_lt/lta`) | `extend` (keyless; no provider/audit use) | `multipart/mixed` artifact |
| `jws_sign`, `jws_add`, `jwt_encode` | `sign` plus per-key right | `multipart/mixed` artifact |
| `jws_verify`, `jwt_verify` | `verify` | JSON; signature, host trust and claims reported separately |
| `jwt_decode` | `extract` | JSON; `verified` is always `false` |
| `inspect` (`certificate`, `cms`, `container`, `named`) | `inspect` (`named` also needs that key right) | JSON |
| `plugin` | the exact operator grant for (token, plugin, operation); a plugin item that names keys also needs the token's `sign` right and each key in the token's `keys` (and in the grant's `keys`), else 403 | JSON |
| `stamp` | `stamp` | `multipart/mixed` token artifact |
| `verify_stamp` | `verify_stamp` | JSON |

Multiple items on `/v1/operations` execute sequentially under one original deadline
and budget (independent items, one all-or-nothing terminal record). The closed SDK
batch with explicit host approval and per-item records is `POST /v1/batch` (below).
There are no encryption/decryption routes: the applicable GOST envelope backend is an
external prerequisite and is not replaced by an RSA-only or generic Unsupported
route.

`sign` profiles also include `wsse` (SOAP Body signature, `soap` = `soap11`/`soap12`,
optional `body_id`), `xml_legacy` (Kalkan wire layout; `element`/`xpath_parent` XPaths,
`signature_method`/`digest_method` URIs, which must fit the key; the Kalkan default
follows the certificate's *signature* algorithm) and `xades_legacy_b`. `verify` accepts
`wsse`. Unsupported field/profile combinations are refused from metadata alone (400)
before any key, secret or document is touched. `xades_legacy_t` signs with a host TSA
(policy OID required, see below).

`plugin` calls an operator-installed plugin operation through `Engine::plugin_call`
with the original admitted context. Installation is not authority: each
(token, plugin, operation) needs an operator `[[plugins.permissions]]` entry listing
the allowed host imports, named keys and exact GET PKI status URLs; the caller identity
is the token, never a request or payload `origin`. A plugin that **declares** its operations
(`[[operations]]` in its manifest) is held to the declaration: Core forces the declared
signature options (a request cannot add attributes, a custom TSA and the like), `cosign`
is never, and a key use needs the grant's explicit `plugin_bytes = true` (below); the
unrefused use is audited with its ticket. A plugin **without** declarations is unchanged. Mandatory dialogs fail with
`InteractionRequired` (403), a denied nested import is `PermissionDenied`, key use is
audited and reported `Applied`/`Unknown`. Token (PC/SC) keys are operator named keys;
they fail closed (NotApplied, no BEGIN) without a reader/card and card transactions
on one device never overlap.

## Error subcodes

An error answer (an HTTP error before the headers, `error` of a failed `final` record,
`error` of a failed batch item) is `{"code": ..., "applied": ...}` and, **only when the
refusal has a precise reason**, `"subcode": "<id>"`:

```json
{"code":"PermissionDenied","applied":"NotApplied","subcode":"not-granted"}
```

* The field is **additive**: `ErrorCode` (the 19 stable codes) and the statuses are unchanged,
  an error without a reason is byte-for-byte what it was, and `subcode` is never required.
  The OpenAPI schema lists it and keeps `additionalProperties: false` for what a server may
  send. The Rust client (`oncl_api`) ignores unknown fields and drops a non-string subcode, so
  older and newer peers interoperate; a client built before this change that still rejects
  unknown fields fails to parse a plugin refusal that carries one (code and `applied` are lost
  with it), so upgrade clients with the server.
* The id matches `^[A-Za-z][A-Za-z0-9_-]{0,63}$` (the ids the server emits are lowercase
  kebab-case; the pattern is the wire bound). `InteractionRequired` carries no subcode. It is **opaque and
  open**: new ids may appear, treat unknown ones as the plain `code`. It is a reason, never a
  message, and never contains document, key or parameter bytes. A value outside the pattern
  is dropped by the client (the typed `code` survives).
* Today only plugin refusals carry one. A refusal is **always `NotApplied`** except
  `key-use-spent` (a second key use in one request (one `OperationId`; two plugin items of one request count together): the first use is real and stays
  reported `Applied`). The ids a server answer carries in practice for a plugin operation:

| `subcode` | `code` | Meaning |
|---|---|---|
| `not-granted` | `PermissionDenied` | The operation declares a key use and the grant has no `plugin_bytes = true`; or no grant covers the ticketed use |
| `options-mismatch` | `PermissionDenied` | The plugin asked for signature options other than the declared profile (or a profile that names a parameter, which a server cannot match) |
| `package-changed` | `PermissionDenied` | The plugin package is not the installed one |
| `key-mismatch` | `PermissionDenied` | The key is not one the grant names |
| `kind-mismatch` | `PermissionDenied` | The signature kind is not a declared key use |
| `caller-mismatch` | `PermissionDenied` | The ticket's caller is not a service-client token (not reachable through HTTP: a token without a matching grant is `not-granted`) |
| `ticket-uses` | `PermissionDenied` | The ticket allows other than exactly one use |
| `key-use-spent` | `PermissionDenied` | One request tried to use a key twice (`applied` is `Applied`) |
| `not-declared` | `PermissionDenied` | The operation is not declared by the plugin (a server grant for it is skipped at start-up, so a request normally gets a plain 403 without a subcode; the `oncl plugin` CLI reports this id) |

Other ids of the same family (`PluginRefusalCode`, `oncl_core::plugins`, 49 ids, each with its
meaning) belong mostly to the desktop manual window; the complete table is in
[the manual-window guide](manual-plugins.md#отказы-как-читать-код-на-странице) and the SDK guide.

The Rust client (`oncl_api::client::ClientError`) exposes it as `server_subcode`
(`Option<String>`, already validated, safe to print); its `describe()` becomes
`PermissionDenied; subcode=not-granted`. The `oncl` CLI prints
`oncl: PermissionDenied; subcode=not-granted; applied=NotApplied` and adds `subcode` to the
failed row of a `batch --json` report; without a reason the line is exactly as before.

## Keys and secret roles

A signing item names keys as either `{"source":"named","name":"..."}` (operator
configured alias; the token must list that exact name in `keys`) or
`{"source":"inline","container":"<part>","password":"<part>","alias":"..."}`.
Inline use needs both the global `inline_pkcs12 = true` and the token's
`inline_pkcs12 = true`; the host then grants only the exact immutable InlineID
computed from the received container and alias. There is no client file path,
token reader, certificate fingerprint or PIN-cache selection.

Parts with `role:"secret"` are bounded fixed-capacity zeroizing memory (container
4 MiB, password 4096 bytes). They are declared first and must be sent before every
`document` part, are never written to the document spool or response, and keep that
role whatever filename or Content-Type the wire part carries. Secrets are refused
in JSON-small. Network and parser transport buffers outside the service-owned
secret owner are not wiped. Container inspection uses the same secret roles and
shows only aliases the token's `metadata_aliases` lists.

## Audit and Applied state

Before the key is applied the service writes a durable audit BEGIN bound to the
authenticated principal and the exact key label; a FINAL follows. Audit failure
before use is a typed `AuditUnavailable`/`NotApplied` failure. If a failure follows
a possible key application, the terminal record reports `Applied` or `Unknown`; no
rollback, retry or exactly-once guarantee is given. Closed audit bindings remain
as tombstones (the closed operation id can never rebind) until the original
deadline or until every owner of that operation (context, worker, response,
artifact) has been dropped, whichever is first, so completed requests do not
consume the bounded binding table.

## Evidence parts, rights order and statuses

`sign` and `extend` accept `evidence`: `[{"kind":"certificate|ocsp|crl","input":"<document part>"}]`
(at most 64 public DER parts of up to 1 MiB each). LT/LTA levels need caller-acquired
OCSP/CRL material (`PAdES extension requires acquired status material` is a typed
`InvalidRequest` failure otherwise); evidence is never a trust anchor. PAdES-LT/LTA
and large evidence need a larger per-operation memory budget than the default (the
default metadata budget is 64 MiB);
that need is refused before the audit BEGIN (see "Resource and material profiles").

Rights are checked in this order: token action, then (before any secret byte is
reserved or read) the per-key right, the global/token inline right and the
`metadata_aliases` grant; an inline key without a `password` part is refused
(400) before any binding or document capture. The exact InlineID is authorized after
the bounded container has been read. `hash` accepts only `document` roles.

Statuses before response headers: 400 InvalidRequest, 403 PermissionDenied, 404
unknown route (there are no plugin-route, encryption or NCANode routes; `/v1/batch`
exists) or `KeyNotFound` (Core could not resolve a key selector the token is
allowed to use; the token's key right is checked first, so a name outside the
token's `keys` is 403, never a 404 existence oracle), 405 with
`Allow`, 408 Cancelled, 413 resource limits, 422 ValidationFailed/OperationFailed,
500 Internal, 503 CapacityExceeded/AuditUnavailable/MissingConfiguration, 504
DeadlineExceeded. The two 404 causes differ by the JSON `code` (`InvalidRequest` on
`NotApplied` for a route, `KeyNotFound` for a key). After headers only the terminal `final` record or a transport
abort can report failure.

Progress parts are coalesced from a single latest-value channel (at most one frame
per observed change, never queued per checkpoint); each frame is charged as output
and metadata under the original scope, so a long operation cannot create unbounded
progress traffic.

## Resource and material profiles (refused before any key use)

- `cades_lt/lta` and `pades_lt/lta` (sign and `extend`) and `xades_lt/lta` (extend) need
  caller-acquired status material: `evidence` with at least one `ocsp` or `crl` part,
  otherwise 400 before any secret, key or document is touched.
- XAdES LT/LTA are available only as **sign `xades_t`, then keyless `extend` to `xades_lt`,
  then `xades_lta`**: there is no `xades_lt/lta` sign profile (the SDK XML sign request
  carries no status material). The chain is exercised over HTTP with the lxml oracle;
  extension never uses a key.
- `pades_lt/lta` need the update plan's memory and metadata. The need is computed from
  `oncl_pdf::budget::plan_memory` / `plan_metadata` (the reservation formulas the PDF
  reader, update plan, signer and verify view use) and from inputs known before the key
  opens: the PDF's existing signature contents, the request's evidence part sizes and the
  operator trust-set size, plus named host reservations (4 I/O chunk buffers, 64 KiB
  metadata, one evidence copy). It is probed against the request's ORIGINAL scope after
  the body is taken; if it does not fit: 413 `MemoryLimit` or `MetadataLimit`,
  `NotApplied`, before the audit BEGIN. At the default limits and the small test evidence
  the threshold is about 380 MiB, so the default 256 MiB `memory_per_operation` refuses
  PAdES LT/LTA; several MiB of CRL evidence needs on the order of 600 MiB and 72 MiB of
  metadata. This is **empirically sufficient for the tested fixtures and evidence shapes**
  (sweeps with 1 MiB steps near the transitions never produced a BEGIN followed by a
  resource failure); it is not a proof for every PDF or evidence shape. Shared-budget
  exhaustion by other requests at runtime, or an input shape outside the tested ones, can
  still fail after use; such a failure is reported with its real `Applied`/`Unknown` state.
  A PDF the PDF layer cannot read (malformed, or a non-PAdES signature SubFilter) is a
  400 `InvalidRequest` before the BEGIN; a document that would exceed the signature-count
  limit with the new signature is 413 `InputLimit`; deadline, cancellation and capacity
  keep their own typed codes in the preflight.
- Signing PAdES B/T/LT/LTA onto a PDF that already carries valid signatures is supported
  (old revisions stay byte-identical; the new signature must itself reach the requested
  level; LT/LTA also elevate the old signers, so the evidence must validate them too). A
  document with an already-invalid signature is refused 400 before any key use.
- `xades_t` / `xades_legacy_t` need a host TSA with a policy OID (`[pki.tsa] policy`),
  because the SDK binds the TSA policy for XAdES T/LT/LTA; without it: 503
  `MissingConfiguration`, `NotApplied`, no BEGIN. CAdES/PAdES T accept a TSA without
  policy.

Authorization is re-run as a pre-execution check after the whole body has been taken,
before the worker starts private use: a token revoked, a key right removed or a policy
generation changed during a long upload gets 403 without BEGIN or key use. A change made
after that check (while the operation is already running) is not observed: the residual
window is the execution itself, which the audit BEGIN/FINAL records.

## Plugin configuration reference

```toml
[[plugins]]
id = "vendor.example"            # must equal the manifest id
manifest = "/private/plugins/vendor.example.toml"   # <= 64 KiB
wasm = "/private/plugins/vendor.example.wasm"       # <= 16 MiB
max_memory = 1048576             # <= oncl-plugin MAX_MEMORY; default 1 MiB
max_transfer = 262144            # <= oncl-plugin MAX_TRANSFER; default 256 KiB

[[plugins.permissions]]          # one per (token, operation); duplicates are refused
token = "accounting-service"     # the caller identity: a configured token id
operation = "run"
imports = ["hash", "keys_sign_raw"]   # exact host imports (Import::name())
keys = ["ops-key"]                    # operator-named keys, also in the token's keys
pki_endpoints = ["http://pki.example/ocsp"]   # exact GET URLs for nested validation
plugin_bytes = false                  # default; see below
```

`plugin_bytes = true` is the operator's explicit acceptance that **the plugin (or its
client) chooses the bytes the granted key signs**. The server cannot bind the content to a
document (`args` is free JSON; typed parameters and document parts are a later stage), so
a key use of a *declared* operation is refused (`PermissionDenied`, subcode `not-granted`,
`NotApplied`, before any `BEGIN` and before the key; a refusal record may be written) unless the grant carries it. It needs at
least one `keys` entry (validation refuses `plugin_bytes = true` without a key) and has no
effect for a plugin without declarations (the server logs a warning). Even then the use
must match the declaration exactly: the ticket's plugin, package hash, operation, the
token as caller, a named key of the grant, the declared kind and the declared options
(`options-mismatch` otherwise) and it must be the request's only key use (a second plugin item or a second signature in the same request is `key-use-spent`).

**Limit:** an operation whose declared profile names a parameter (`param:` sources, such as an XML element typed by the user) cannot use a key on the server: the server has no value to match, so the use is always refused as `options-mismatch`. The shipped plugins under `plugins/` declare 30 operations, but none declares `server = true`: no shipped operation can be granted on the server (or run by `oncl plugin call`); the server skips such a grant with an error in the log and the CLI refuses it with `not-declared`.

At start-up a grant of a declared plugin is checked against the manifest and **skipped with
an error in the log** (the other grants and the server keep running) when it is wider than the
declaration: an operation the plugin does not declare (the error lists the declared ones) or
declares without `server = true` or whose content is `derived` (not runnable); an import outside `uses.imports` (an empty `imports` list
means all declared imports); `keys` or `plugin_bytes` for an operation with no key use;
`pki_endpoints` without `network = "pki"`. A grant naming an import that does not exist, an
unknown token or a duplicate (token, operation) still fails the configuration. A grant of a
plugin without declarations is kept as before with a start-up warning that its signature
options are not enforced.

Configuration bounds (a violation fails the configuration): at most 16 `[[plugins]]` and 256
permissions per plugin; a plugin `id`, a grant's `token` and `operation` at most 64 bytes (the
plugin `id` must equal the manifest's, a duplicate plugin id is refused); `imports` at most 72,
`keys` at most 8, `pki_endpoints` at most 16 of at most 2048 bytes each. On the server the
`pki_endpoints` are GET only (the CLI also takes `POST=`).

Plugin outputs (`take_output` staged files) and bound input files are **not exposed** by
HTTP: the SDK supports them through the original context, but no request-to-file
binding contract has been designed or reviewed, so `file_*` imports are never granted.
Dialog imports always fail with `InteractionRequired`.

## Containers

Inline and named key containers are exercised as PKCS#12 only. JKS containers are
read-only in this project (no JKS writer exists), so a JKS container chained to a
loopback CA with status endpoints cannot be produced for a strict-validation signing
test; JKS signing over HTTP is therefore not evidenced.

## Terminal records for streamed responses

`final` has `status` `completed` or `failed`. A `failed` record carries
`error: {code, applied}` and withholds every artifact of the request (there is no
partial success); prior items' `applied` values stay visible in `results`. Resource,
deadline and cancellation failures that never applied a key abort the transport as
before. A stream without a `completed` final record is not a result.

## Closed batch (`POST /v1/batch`)

The request is the same metadata-first multipart (or JSON-small) envelope as
`/v1/operations`: `items` (1..1024, unique IDs, manifest order is execution order) and
`parts` (secret roles first, then documents). Every item kind of the table above is
accepted **except `plugin`** (the SDK batch has no plugin operation; 400). The
metadata carries no approval, grant or authority flag: unknown fields are rejected.

Authority, all decided by the operator policy and never by the payload:

1. **Before any document or secret byte is read**: the token needs the separate
   `batch` right (`actions = [..., "batch"]`; it is not an SDK action and grants
   nothing else) AND, for **every** item, that item's operation action, named-key
   right, inline right or `metadata_aliases`. One ungranted item refuses the whole
   batch (403, nothing runs, no key is opened, no secret is read).
2. After the body is taken the same function is run again (revocation, policy
   generation), then every source is captured as an immutable snapshot
   (`Engine::capture_batch`; keys are resolved to a lease and certificate but **no
   private key is applied**).
3. The host approval (`BatchApproval`) is produced by the service only if the captured
   plan equals, item by item, the composition the operator policy authorized: ids and
   order, action, signing profile, the resolved key IDs and the captured source sizes.
   A different plan (or an approval made for another plan) is refused with 403 before
   any private use. The approval is single use and bound to the original operation.
4. Execution (`run_batch_with_outputs`) uses the ORIGINAL admitted context; each
   private use is audited with the batch item ordinal (`BEGIN`/`FINAL` per item).

Response: always `multipart/mixed` (the status is decided at approval; refusals before
that are typed JSON errors with `NotApplied`): coalesced `progress` parts that also
report the batch position (`items`: `total`, `finished`, `current` `{index,item_id}`),
one `artifact` part per **finished** output, and a mandatory last `final` part,
`type = "batch_final"`:

- `status`: `completed` (every item completed; an `Invalid` verification is a
  completed item with `verdict = "Invalid"`), `partial` (some item failed or did not
  run) or `failed` (nothing could run).
- `items[]` in manifest order, each with `item_id`, `index`, `outcome` (`completed`,
  `failed`, `not_run`), `applied` (`NotApplied`/`Applied`/`Unknown`), `verdict`,
  `error {code, applied}` for failed items, `result` for completed items (same
  result families as `/v1/operations`; `artifact` is the Content-ID of finished output
  only) and `sources` (SHA-256 and length of the exact captured bytes).
- A failing item never erases completed items' results, artifacts or `applied` facts.
  Item-local failures (unreadable source, missing key) let later items run. After a
  terminal stop (quota, audit failure, deadline or cancel during an item) the later
  items are `not_run` and `stop` says why (`kind` `item`/`control`, `code`,
  `item_index`). There are no retries, idempotency keys or rollback.
- Output bytes are accounted once by the SDK staged output; the service copies each
  finished staged output into its owned artifact store (temporary disk is briefly
  held twice for that item) and the artifact keeps the original root, deadline and
  scratch accounting until its last network slice is dropped.
- Completed XML/PDF reports keep their bounded metadata reservation until the batch
  ends (SDK ownership; `/v1/operations` releases it per item). A batch of several XML
  or PDF signatures therefore needs a proportionally larger per-operation
  `metadata_bytes` (measured: three plain XML signatures plus one XAdES-B fit in
  96 MiB, one XML signature plus a second one does not fit in 64 MiB). When it is
  exhausted the item fails with `MetadataLimit` and its honest Applied state, later
  items are `not_run` and earlier artifacts stand.
- The original deadline covers upload, queue, every item and delivery. If it expires
  (or the client disconnects) mid-batch no byte may leave afterwards, so the response
  is **aborted without a terminal record** (a missing final is an unknown outcome,
  never success); the durable audit journal holds the per-item facts, and the native
  worker keeps the original root until it returns. A deadline that expires while the
  client is still uploading is a typed `504 DeadlineExceeded` (`NotApplied`) before
  any header.

## Test oracles

The real-socket tests use independent tools. `openssl` and `python` (with `lxml` and
`cryptography`) are found on `PATH`. The PAdES test needs a Python environment with
`pyhanko`, `pyhanko-certvalidator` and `cryptography`: set `ONCL_PYHANKO_PYTHON` to that
environment's python executable. If it is unset or missing that test fails with this
explanation (it is never skipped).

## Operator configuration (summary)

`[pki]` adds `anchors`, `intermediates`, address-pinned `endpoints`, an optional
`[pki.tsa]` (`url`, optional `policy`, `timeout_ms`, `skew_ms`) required for
`*_t/lt/lta` signing and `stamp`, and `[pki.jwt]` (`expected_issuer`,
`expected_audience`). Tokens gain the actions `extend`, `inspect`, `stamp`,
`verify_stamp`, `batch` and `metadata_aliases`. None of these are request fields. Private
operations use strict validation: they need configured anchors and reachable
revocation evidence, otherwise they fail before the key is applied.

Encryption additionally requires the real external GOST backend contract. No
1-GiB/RSS or platform-matrix claim is made by this document.

## Reference client

`oncl_api::client::ApiClient` (feature `client` of `oncl-api`, `ureq` + `rustls` only) is the reference client of this contract and the transport of `oncl --endpoint` ([cli.md](cli.md#remote-mode---endpoint)). It writes the metadata-first multipart request as a bounded stream (secrets first, document bodies streamed with an exact declared length or chunked), sends `Expect: 100-continue`, never follows a redirect, and reads `multipart/mixed` by part `Content-Length` with a bounded reader. A response is a result only when `final`, the closing delimiter and the end of the HTTP entity were received; otherwise the outcome is `ResponseLost` with `Unknown` (private key possible) or `NotApplied`, with no retry. Its owned response mirror (`client::wire`) is checked against every published OpenAPI example (`tests/client.rs`).

The client checks stated artifact lengths only where the server enforces them (extraction, timestamp token, JWS/JWT creation; never batch items), and its `ExecuteOptions.control` is polled every 50 ms so a stop reports `Unknown` only when a key-capable body was fully sent.
