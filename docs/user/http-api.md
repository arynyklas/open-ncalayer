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
retained through parser and synchronous field-reader boundaries, never inferred
from error text or replaced by a later cancellation.

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
result is success. This transport does not advertise an unused progress stream
or binary-artifact protocol.

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

The full Task24 private/signature/timestamp/plugin/artifact/batch HTTP acceptance
is not asserted by these public operations. Encryption additionally
requires the real external GOST backend contract; there are no fabricated
`encrypt`/`decrypt` routes returning generic Unsupported success.
