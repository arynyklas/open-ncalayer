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
text, not additional authorization or a replacement for the typed check fields.

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

The implementation uses pinned `multer` 3.1.0 for multipart parsing. Its feeder
admits at most 8,192 new bytes while parsing unknown-role headers/preamble, in
addition to at most one previous 4,096-byte data chunk and boundary suffix. It
forces cooperative polling so an always-ready upload is not collected into the
parser. Header count is additionally bounded by the parser; metadata fixes the
exact permitted names and total part count. The actual standalone Hyper read
buffer is capped at 32,768 bytes; per-connection HTTP/TLS transport overhead is
separate from the SDK working-buffer reservations. Per-request parser, decoded
metadata and retained ingress allocations are admitted before allocation. This
is not a claim of the 10-GiB XML/PDF resource acceptance gate.

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
DeadlineExceeded. Hashing never applies a private key. Authentication occurs
before body intake; the original admission root starts before bounded metadata
intake, then the host consumes that same root into an authorized operation
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
| `sign` (`cms`, `cades_b/t/lt/lta`, `pdf`, `pades_b/t/lt/lta`, `xml`, `xades_b/t/lt/lta`; `mode` `create`/`add` for CMS/CAdES; XML takes optional `target`/`parent`/`signature_id` element IDs) | `sign` plus per-key right | `multipart/mixed` artifact |
| `extend` (`cades_t/lt/lta`, `pades_t/lt/lta`) | `extend` (keyless; no provider/audit use) | `multipart/mixed` artifact |
| `jws_sign`, `jws_add`, `jwt_encode` | `sign` plus per-key right | `multipart/mixed` artifact |
| `jws_verify`, `jwt_verify` | `verify` | JSON; signature, host trust and claims reported separately |
| `jwt_decode` | `extract` | JSON; `verified` is always `false` |
| `inspect` (`certificate`, `cms`, `container`, `named`) | `inspect` (`named` also needs that key right) | JSON |
| `plugin` | exact operator grant only | JSON |
| `stamp` | `stamp` | `multipart/mixed` token artifact |
| `verify_stamp` | `verify_stamp` | JSON |

Multiple items execute sequentially under one original deadline and budget. There
are no encryption/decryption routes: the applicable GOST envelope backend is an
external prerequisite and is not replaced by an RSA-only or generic Unsupported
route. SDK closed-batch capture/approval (`run_batch`, which would add per-item
audit ordinals) is not exposed yet; items here run sequentially without it.

`sign` profiles also include `wsse` (SOAP Body signature, `soap` = `soap11`/`soap12`,
optional `body_id`), `xml_legacy` (Kalkan wire layout; `element`/`xpath_parent` XPaths,
`signature_method`/`digest_method` URIs, which must fit the key; the Kalkan default
follows the certificate's *signature* algorithm) and `xades_legacy_b`. `verify` accepts
`wsse`. Unsupported field/profile combinations are refused from metadata alone (400)
before any key, secret or document is touched. `xades_legacy_t` is not available.

`plugin` calls an operator-installed plugin operation through `Engine::plugin_call`
with the original admitted context. Installation is not authority: each
(token, plugin, operation) needs an operator `[[plugins.permissions]]` entry listing
the allowed host imports, named keys and exact GET PKI status URLs; the caller identity
is the token, never a request or payload `origin`. Mandatory dialogs fail with
`InteractionRequired` (403), a denied nested import is `PermissionDenied`, key use is
audited and reported `Applied`/`Unknown`. Token (PC/SC) keys are operator named keys;
they fail closed (NotApplied, no BEGIN) without a reader/card and card transactions
on one device never overlap.

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
and large evidence need more than the default 256 MiB per-operation memory budget on
this build (a `MemoryLimit` after key use is reported as `Applied`).

Rights are checked in this order: token action, then (before any secret byte is
reserved or read) the per-key right, the global/token inline right and the
`metadata_aliases` grant; an inline key without a `password` part is refused
(400) before any binding or document capture. The exact InlineID is authorized after
the bounded container has been read. `hash` accepts only `document` roles.

Statuses before response headers: 400 InvalidRequest, 403 PermissionDenied, 404
unknown route (there are no batch, plugin, encryption or NCANode routes), 405 with
`Allow`, 408 Cancelled, 413 resource limits, 422 ValidationFailed/OperationFailed,
500 Internal, 503 CapacityExceeded/AuditUnavailable/MissingConfiguration, 504
DeadlineExceeded. After headers only the terminal `final` record or a transport
abort can report failure.

Progress parts are coalesced from a single latest-value channel (at most one frame
per observed change, never queued per checkpoint); each frame is charged as output
and metadata under the original scope, so a long operation cannot create unbounded
progress traffic.

## Resource and material profiles (refused before any key use)

- `cades_lt/lta` and `pades_lt/lta` (sign and `extend`) and `xades_lt/lta` (extend) need
  caller-acquired status material: `evidence` with at least one `ocsp` or `crl` part,
  otherwise 400 before any secret, key or document is touched.
- XAdES LT/LTA are produced as **sign `xades_t`, then keyless `extend` to `xades_lt`, then
  `xades_lta`** (the SDK XML sign request carries no status material, so there is no
  `xades_lt/lta` sign profile). The chain is exercised over HTTP with the lxml oracle;
  extension never uses a key.
- `pades_lt/lta` need the update plan's memory. The need is computed by
  `oncl_pdf::budget::plan_memory` (the same functions the PDF reader, update plan and
  signer reserve with, plus a fixed host working margin) and probed against the request's
  ORIGINAL scope after secret intake; if it does not fit: 413 `MemoryLimit`,
  `NotApplied`, before the audit BEGIN. At the default 1 MiB object limit this is about
  330 MiB, so the default 256 MiB `memory_per_operation` refuses PAdES LT/LTA. A sweep
  over memory profiles shows requests are either refused up front or complete; none
  writes a BEGIN and then fails for memory. Shared-budget exhaustion by other requests at
  runtime can still fail after use and is then reported `Applied`.
- `xades_t` / `xades_legacy_t` need a host TSA with a policy OID (`[pki.tsa] policy`),
  because the SDK binds the TSA policy for XAdES T/LT/LTA; without it: 503
  `MissingConfiguration`, `NotApplied`, no BEGIN. CAdES/PAdES T accept a TSA without
  policy.

Authorization is re-run after the whole body has been taken and immediately before
private use: a token revoked, a key right removed or a policy generation changed during
a long upload gets 403 without BEGIN or key use.

## Plugin configuration reference

```toml
[[plugins]]
id = "vendor.example"            # must equal the manifest id
manifest = "/private/plugins/vendor.example.toml"   # <= 64 KiB
wasm = "/private/plugins/vendor.example.wasm"       # <= 16 MiB
max_memory = 1048576             # <= oncl-plugin MAX_MEMORY
max_transfer = 262144            # <= oncl-plugin MAX_TRANSFER

[[plugins.permissions]]          # one per (token, operation); duplicates are refused
token = "accounting-service"     # the caller identity: a configured token id
operation = "run"
imports = ["hash", "keys_sign_raw"]   # exact host imports (Import::name())
keys = ["ops-key"]                    # operator-named keys, also in the token's keys
pki_endpoints = ["http://pki.example/ocsp"]   # exact GET URLs for nested validation
```

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

## Operator configuration (summary)

`[pki]` adds `anchors`, `intermediates`, address-pinned `endpoints`, an optional
`[pki.tsa]` (`url`, optional `policy`, `timeout_ms`, `skew_ms`) required for
`*_t/lt/lta` signing and `stamp`, and `[pki.jwt]` (`expected_issuer`,
`expected_audience`). Tokens gain the actions `extend`, `inspect`, `stamp`,
`verify_stamp` and `metadata_aliases`. None of these are request fields. Private
operations use strict validation: they need configured anchors and reachable
revocation evidence, otherwise they fail before the key is applied.

Encryption additionally requires the real external GOST backend contract. No
10-GiB/RSS or platform-matrix claim is made by this document.
