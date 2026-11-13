# Platform acceptance: 1 GiB / 1 GiB proof (`cargo xtask platform-proof`)

```text
cargo xtask platform-proof --document-bytes 1073741824 --max-rss-bytes 1073741824 \
  --scratch-bytes 17179869184 --out <dir> [--scratch-dir <dir>] [--surface sdk|cli|http|all] \
  [--jobs N] [--only <id>…] [--resume] [--reuse-data] [--skip-build]
```

The gate is separate from the normal suite: `cargo test -p xtask --test platform_large` runs only small
deterministic cases (generator, OS measurement, parsing, a lxml/pyHanko check of the generator).
A big run that was not done is **not** a pass.

## What it does

1. Preflight: `--out` and `--scratch-dir` must be on a fixed local drive (removable, network, optical
   are refused) with at least `--scratch-bytes` (plus the data) free. Not enough room is `BLOCKED`.
2. Reference validation on small instances before any large file: lxml canonicalization of every
   `Id` element and of the whole XML document, pyHanko (revisions, page tree, object streams, embedded
   file) and, when `ONCL_PY_TOOLS` names pikepdf/pypdf/pdfminer, qpdf/pypdf/pdfminer on the PDF.
3. Independent reference generator (`xtask/src/platform/generate*`): XML records in a non-canonical
   lexical form with canonical form produced by a second code path (`Id`, namespaces, xml:lang, CDATA,
   char refs, comments, PIs; the SOAP form has none), SOAP with the signed Body after 45 % of the
   document, PDF with a three-level page tree, classic xref plus two incremental revisions with xref
   streams (8-byte offsets) and object streams, and a framed pseudo-random byte stream. Sizes are exact.
4. Real programs, release builds, as separate processes: `sdk_probe large` (SDK), `oncl` (CLI), `oncl-server`
   with `oncl --endpoint` as its client (HTTP). Peak working set and peak private bytes come from the OS
   (Windows `GetProcessMemoryInfo` + job object; Linux `/proc/<pid>/status`), never from a buffer
   counter. PASS needs the stricter of the two ≤ `--max-rss-bytes` for every process.
5. Independent verification of results: openssl (CMS), lxml + cryptography (XMLDSig digests against the
   generator's canonical digests and the RSA SignatureValue), hashlib + asn1crypto + cryptography +
   pyHanko (PDF ByteRange arithmetic, digest of the covered bytes, signature, untouched original prefix).
   GOST has no independent oracle on this machine; those cases are SDK-verified with a tamper contrast.
6. Matrix per surface: hash (known and unknown length, the document-size boundary, limit+1; the 2/4 GiB boundaries are run only when `--document-bytes` is raised above the 1 GiB guarantee), CMS detached and
   attached (output above the document size read back by extract/verify/openssl), GOST CMS, XMLDSig far reference,
   whole document, GOST, WSSE Body in the second half of the document, unknown-length XML, cancellation, temp quota, PDF
   (dense many-object and compact), PAdES-B, CAdES/PAdES/XAdES T→LT→LTA, output limit, key-application
   counts (SDK guard, server audit journal), scratch cleanup.
7. The overload family (real `oncl-server`, small shared budgets, OTLP gauges collected by the harness; see
   "The overload cases" below): `overload-profile`, `overload-slot-release`, `overload-token-apdu`, and
   the diagnostic `http-progress-frame-rate` (run only when named with `--only`).

## The overload cases

Since the upload phase (`docs/user/server.md`, "Uploads") a body is received under one of `max_uploads`
upload slots, and only the completed body takes a `max_in_flight` slot and a native worker. The cases are
therefore built on **observed server state, not on clocks**: a wave of clients starts when the previous wave has
produced the state it was meant to produce (`xtask/src/platform/large/barrier.rs`). What the harness reads is
one of three things:

* what the server did to the client: with `Expect: 100-continue` Hyper writes `100 Continue` only when the
  handler first polls the body, which the server does only after the request holds its upload slot, so the
  receipt of `100 Continue` means "this client holds an upload slot" (`http_raw::Probe::continued`); an
  answer or close (`Probe::answered`); a stalled client that the harness lets go by disconnecting
  (`Probe::release`), so a stall lasts exactly as long as the plan wants;
* what the server did to the disk: its spool files in the scratch directory (a spool holds what the SERVER
  received, not what the client wrote into a socket);
* what the server exported: its OTLP gauges, read as the second export after the change
  (`otlp::second_sample_after`: the first may have been read just before the change).

Every barrier has a time-out, and the time-out is a failure that names what never happened. Every client has a
*plan* (`clients::Plan`): completes, refused `503 CapacityExceeded`/`NotApplied`, ends by its own disconnect, or is
ended by the server (`504 DeadlineExceeded`/`NotApplied`); no wave puts more clients into the upload phase than
`max_uploads` can hold, except the one probe that is meant to be refused, so the answer of every client is fixed
by the plan and not by arrival order. `max_uploads` is explicit in the profiles (the default follows
`total_temp / (input_bytes + container_bytes)`), and the budgets leave room for the concurrent signatures of a
wave (`total_memory`, `metadata_bytes`). Measured on the first run of the redesign: with the default 64 MiB
`metadata_bytes`, three of four concurrent signatures of the 8 MiB test document were aborted by the server
at their start with `MetadataLimit` (the documented stream abort of a resource failure before any key use: the
client sees only a lost response). That is the budget doing its work, but it would decide *which* client
completes, so the profile raises `metadata_bytes` (512 MiB) and `total_memory` (1 GiB) and leaves the refusals to
the upload slots, whose count is exact.

* **`overload-profile`** (`max_in_flight 4`, `blocking_workers 4`, `max_uploads 6`, upload idle timeout and
  operation deadline far beyond the run):
  1. *Five stalled uploads* (one slot short; more than `max_in_flight` and `blocking_workers`): the exported gauges
     show no running or queued operation; **(a)** a small request and a CPU-bound signature are admitted and
     complete (the signature is checked by the independent oracle) while the stalls are still stalled.
  2. *Every upload slot taken* (a sixth stall, after a CPU-bound signature was admitted): **(b)** a further
     upload is refused `503 CapacityExceeded`/`NotApplied` before its body (no `100 Continue`, no byte sent)
     after `admission_wait_ms`; `/health` is answered `200` throughout; the operation admitted earlier completes.
  3. *Disconnect*: **(c)** every spool is deleted, the server sees no request in flight, and six new stalled
     uploads each take a slot at once (a leaked slot would leave one of them unparked: the barrier fails).
  4. *A storm*: a 1 GiB upload and a disconnecting upload in progress, four concurrent CPU-bound signatures and
     three small requests next to them; all complete or end as planned, the 1 GiB digest is right.
  5. *The idle rule*, on a second server (`upload_idle_timeout_ms 3000`, `max_uploads 2`): two stalled uploads
     are ended by the server with `504 DeadlineExceeded`/`NotApplied` after about the idle timeout and never held
     to the operation deadline; **(c)** both slots are free afterwards and the next request completes.
  Over the whole run: every client got an end, no 500 or untyped close, a key never applied on a refusal, the
  shared scratch empty, gauges exported, peak running within `blocking_workers` (and the signatures did run), peak
  queued within `queue_capacity` (the queue stays empty by construction: `blocking_workers >= max_in_flight`, the
  documented default shape, so no admitted signature waits for a worker), shared temp within `total_temp`,
  `/health` answerable, a request after the storm with the right digest, graceful stop, a FINAL for every BEGIN,
  empty scratch after the stop.
* **`overload-slot-release`** (`max_in_flight 2`, `blocking_workers 2`, `max_uploads 4`, deadline 20 s, idle
  timeout 120 s): two uploads stall against `max_in_flight = 2`; two CPU-bound signatures complete next to them (the
  stalls hold no in-flight slot and no worker). Then two stalls that only the operation deadline ends: the server
  ends them with `504 DeadlineExceeded` at about the deadline, all four upload slots are free again and the next
  signature completes.
* **`overload-token-apdu`**: sixteen concurrent signatures on two software cards, three times over, through the
  service library with a counting card backend (not the standalone binary); APDU exchanges and card
  transactions never overlap per reader, OpenSSL verifies the signatures, the audit has a FINAL for every
  BEGIN. `max_uploads` is 8 (explicit; `total_temp` 16 GiB).
* **`http-progress-frame-rate`**: one 1 GiB CPU-bound signature with a raw client that keeps the response;
  records progress-frame traffic and checks that the entity completes without a transport abort. It is a single
  request and does not depend on the upload phase.

History: the first `overload-profile` assumed that a stalled upload holds a worker and an in-flight slot. Its
retunes (workers 4, admission wait 8 s, uploads at 3 s, abandoned uploads aborted after 64 MiB) narrowed a
timing race between the clients but could not remove it: under `--jobs 2` the abandoned uploads held their slots
past `admission_wait_ms` and all CPU-bound clients were refused. After the upload phase the case failed outright
(the default `max_uploads` of `3 GiB / 2 GiB = 1` was taken by a stalled upload and every other client was
refused), and `overload-slot-release` passed on the strength of a late client only. Both were redesigned as above.

## Limits of the proof (state them in every report)

* Encryption/decryption (G01/G02) is externally blocked: no case, no substitute.
* The standalone `oncl-server` uses system PC/SC only and this stand has no virtual reader: per-device APDU
  overlap is measured on the same service library hosted by `platform-token-host` with a counting
  software card. It is labelled as such and is not the standalone binary.
* Windows x64 only unless run elsewhere; page cache effects: reads through `ReadFile` do not enter the
  process working set, mapped pages do; both peaks are reported.
* The report (`report.json`) holds environment, program hashes, artifact digests, per-case checks,
  per-process peaks, durations and temp peaks.

## Status (2026-11-13): 1 GiB gate results

The guaranteed document size is **1 GiB** (user scope change of 2026-11-11, superseding 10 GiB). The
control-process memory budget stays 1 GiB. These are the ledger facts; no claim is made beyond them.

* **The 10 GiB gate was never passed and is withdrawn by the scope change.** It is history, not a result of the current contract. Its only run (build `0c0cb19`, 2026-11, resumed after an outage; durable report stopped at about 39,900 s with 37 completed cases) exposed production defects, now fixed (the numbering D1-D4 is separate from the D1-D6 of `platform-interop.md`):
  * **D1** (PDF/CMS output): own-output `InputLimit` of a signed PDF readback. Fixed by the container surcharge (`6d3ba57e`, f4359257).
  * **D2** (XAdES-T): `InvalidInput` after key use. Root cause: the host clock was sampled before the carried-proof passes; fixed by sampling after (`2736f787`, `66eb1e36`). The throughput cost (every carried proof re-reads the whole source; about 21,000 s at 10 GiB) was not fixed.
  * **D3** (HTTP signing): `ResponseLost`, unthrottled progress frames consumed the output allowance; fixed by the progress throttle (`cba9f224`, merged `31854c17`).
  * **D4** (dense PDF): the cross-reference budget; fixed by `a07d2832` (see "Dense PDFs" in `docs/dev/sdk.md`).
  * **D7** (server): a stalled or crawling upload held an admission slot; fixed (`902ed9f1`: `upload_idle_timeout_ms`, `upload_min_bytes_per_second`).
* The 2 GiB rerun on `efc785ed` (history, before the scope change) passed PDF compact and dense, PAdES-B and levels, CAdES levels and XML far-reference / whole-document / WSSE; `cms-attached` had its OpenSSL oracle replaced above `INT_MAX` by a decomposition. Peak working set and private bytes were at or below about 20 MiB.
* **The 1 GiB gate has been run.** A full `cargo xtask platform-proof` run with the defaults above (`--jobs 1 --reuse-data`, 42,946 s; the report stays outside the repository) passed **70/70** on tree `9a1f0181` (SDK 23, CLI 22, HTTP 25); the maximum peak working set of any process was 20.4 MiB against the 1 GiB limit. Later changes to `oncl-server` (staged close of refused connections, the executor's drop order, intake) are covered only for HTTP: the 12 HTTP cases that exercise them (`overload-profile`, `overload-slot-release`, `overload-token-apdu`, `cms-sign-limit-plus-one`, `hash-limit-plus-one`, `xml-temp-quota`, `xml-cancel`, `http-progress-frame-rate`, `cms-attached`, `pdf-compact-sign`, `xml-whole-document`, `hash-unknown-length`) were rerun on `e99a90a2`, the commit released as `0.1.0-alpha.7`, and passed (12/12, in two runs of 7 and 5 cases; maximum peak working set 20.4 MiB). The other HTTP cases and all SDK and CLI cases were **not** rerun on that commit; their evidence is the 70/70 run on `9a1f0181`. That the server change cannot affect SDK and CLI cases is an inference, not a check. The overload family (see "The overload cases") was redesigned before the full run and also passed three runs alone and three under artificial CPU and disk contention. Not done at all: encrypt/decrypt (G01/G02), which is externally blocked and has no case.
