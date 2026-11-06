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
