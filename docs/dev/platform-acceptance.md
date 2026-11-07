# Platform acceptance: 10 GiB / 1 GiB proof (`cargo xtask platform-proof`)

```text
cargo xtask platform-proof --document-bytes 10737418240 --max-rss-bytes 1073741824 \
  --scratch-bytes 68719476736 --out <dir> [--scratch-dir <dir>] [--surface sdk|cli|http|all] \
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
6. Matrix per surface: hash (known and unknown length, 2/4 GiB boundaries, limit+1), CMS detached and
   attached (output above 10 GiB read back by extract/verify/openssl), GOST CMS, XMLDSig far reference,
   whole document, GOST, WSSE Body after 4 GiB, unknown-length XML, cancellation, temp quota, PDF
   (dense many-object and compact), PAdES-B, CAdES/PAdES/XAdES T→LT→LTA, output limit, key-application
   counts (SDK guard, server audit journal), scratch cleanup.
7. `overload-profile` (real `oncl-server`, small shared budgets, OTLP gauges collected by the harness) and
   `overload-token-apdu`.

## Limits of the proof (state them in every report)

* Encryption/decryption (G01/G02) is externally blocked: no case, no substitute.
* The standalone `oncl-server` uses system PC/SC only and this stand has no virtual reader: per-device APDU
  overlap is measured on the same service library hosted by `platform-token-host` with a counting
  software card. It is labelled as such and is not the standalone binary.
* Windows x64 only unless run elsewhere; page cache effects: reads through `ReadFile` do not enter the
  process working set, mapped pages do; both peaks are reported.
* The report (`report.json`) holds environment, program hashes, artifact digests, per-case checks,
  per-process peaks, durations and temp peaks.

## Status (2026-11-07, tree `0.1.0-alpha.7`): the gate is NOT passed

These are the ledger facts; no claim is made beyond them.

* **Verdict: FAIL / no PASS.** The only 10 GiB run (build `0c0cb19`, before the fixes below) was resumed after an outage; its durable report had stopped at about 39,900 s with 37 completed cases. It exposed four production defects (labelled D1–D4 here; this numbering is separate from the D1–D6 of `platform-interop.md`), none of which is accepted as a pass:
  * **D1** (PDF/CMS output): own-output `InputLimit` of a signed PDF readback. Fixed by the container surcharge (`6d3ba57e`, f4359257).
  * **D2** (XAdES-T): `InvalidInput` after key use at about 21,000 s. Root cause: the host clock was sampled before the carried-proof passes, so the online OCSP answer left its 300 s window; fixed by sampling after (`2736f787`, `66eb1e36`). The throughput cost is **not** fixed: XAdES-T at 10 GiB took about 21,000 s against about 900 s for PDF, because every carried proof re-reads the whole source.
  * **D3** (HTTP signing): `ResponseLost`. Root cause confirmed on a diagnostic run: unthrottled progress frames (about 1.48 MB/s) consumed the operation output allowance (aborted after exactly 11,878,268,140 response bytes, BEGIN=0). Fixed by the progress throttle (`cba9f224`, merged `31854c17`).
  * **D4** (dense PDF): the cross-reference budget. Fixed by `a07d2832` (documented in `docs/dev/sdk.md`, "Dense PDFs").
* A later defect, **D7** (server: a stalled or crawling upload held an admission slot), was found by `overload-profile` and fixed (`902ed9f1`: `upload_idle_timeout_ms`, `upload_min_bytes_per_second`).
* **2 GiB rerun on `efc785ed`** passes: PDF compact and dense, PAdES-B and its levels, CAdES levels, XML far-reference / whole-document / WSSE. `cms-attached` at 2 GiB has its independent OpenSSL oracle replaced above `INT_MAX` by a decomposition (OpenSSL stops with `asn1_d2i_read_bio: too long`). Peak working set and private bytes stayed at or below about 20 MiB in every measured process.
* **OPEN (not done):**
  * the **10 GiB re-confirmation** after the fixes (D2, D3 and the LT/LTA levels on the current tip); no full 10 GiB gate has been run on the tip;
  * the **`overload-profile` re-measure**: it failed with D7, which is fixed but was not re-measured;
  * XAdES-T throughput at 10 GiB (see D2 above);
  * encrypt/decrypt (G01/G02) has no case: it is externally blocked.

