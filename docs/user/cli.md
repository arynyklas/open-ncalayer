# Standalone local CLI (`oncl`)

`cargo run -p oncl-cli -- …` runs the independent SDK consumer. By default it is purely local: it does not start the desktop, an HTTP server, a daemon or a browser session. With an explicit `--endpoint` it is instead a streaming client of the `oncl-server` HTTP contract (see [Remote mode](#remote-mode---endpoint)); there is no discovery and no implicit fallback between the two.

**Task25 is not complete.** Open items are listed at the end. Encryption/decryption additionally require the genuine G01/G02 SDK backend; no `encrypt`/`decrypt` command and no RSA-only substitute exists.

## Commands

| Command | What it does |
|---|---|
| `hash --algorithm sha256\|gost2004\|gost2015-512 --input -` | Streaming digest of a file or stdin |
| `sign --profile …` | Source-bound private signing (see below) |
| `verify --profile …` | Verification with host trust; detached via `--detached` |
| `extract` | Raw CMS content; **unverified** |
| `inspect --profile certificate\|container\|cms` | Public metadata only |
| `extend --profile cms\|xml\|pdf --level b\|t\|lt\|lta` | Keyless evidence extension |
| `timestamp acquire\|verify` | Standalone RFC 3161 token |
| `jws sign\|verify`, `jwt encode\|verify\|decode` | RS256 / ECGOST3410-2015-512 JOSE |
| `plugin call` | Runtime-only WASM invocation with operator grants |
| `batch run` | Ordered mixed batch from a JSON manifest |

Sign profiles: `cms`, `raw`, `digest-sha256|gost2004|gost2015-512`, `xml`, `wsse`, `pdf`, and `cades-`/`xades-`/`pades-` with `b`, `t`, `lt`, `lta`. Verify profiles: `cms`, `xml`, `xml-kalkan`, `wsse`, `pdf`, and the same level families. Profiles and algorithms are never inferred from file names or untrusted tokens.

Example (Git Bash):

```sh
printf abc | cargo run -p oncl-cli -- hash --algorithm sha256 --input -
```

prints `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`. `--input -` claims stdin for exactly one role; two stdin roles fail before any I/O.

## Private signing, secrets and authority

```text
oncl sign --profile cms --detached --input document.bin --output signature.der \
  --key signer.p12 --secret-file secrets/signer.secret --authorize \
  --root operator-root.der --pki-endpoint https://pki.example.test
```

* `--authorize` is the explicit confirmation of this exact source, profile, key and destination. A password is not authority. There is no unlocked cache across invocations, and strict certificate/revocation validation always precedes private use (`--offline` only affects the verification policy, never signing).
* Key source: `--key` (PKCS#12 or JKS; `--alias` when several entries exist) **or** `--token-reader NAME --token-kind … --token-alias …` (real PC/SC; exercised against the software emulator only, never a physical token — absent readers fail closed with no output).
* Secrets never appear as arguments. Use `--secret-file` inside an existing **owner-only directory** (the SDK verifies directory and file owner/ACL, link count, reparse points and refuses to repair) or `--secret-interactive` (fixed zeroizing buffers; refused when stdin is a document or not a terminal). Files accept at most 4097 raw bytes / 4096 password bytes and one trailing LF/CRLF; nothing is truncated. Process tests cover unprotected directory, oversized, absent and directory secrets (all refused with no private use); the symlink case needs a privilege this machine lacks and was not exercised.
* Interactive input: Backspace removes a scalar, Ctrl-U clears, Ctrl-W removes a word, Ctrl-C cancels. Terminal modes are restored on normal/error/unwind. No-echo, restoration and Ctrl-C are proven on a real Windows ConPTY (see below). Forced termination or a blocked native read cannot guarantee immediate cancellation or restoration.
* The default `rpassword 7.5.4`/`rtoolbox 0.0.6` reader was deliberately not used: it grows a `String` and only erases its current length, so retired/truncated copies are not zeroized.

## Trust, network and time

Trust comes only from the operator: `--root`, `--intermediate`, `--pki-endpoint` (exact origins; literal IPs pin themselves), `--pki-pin 'http://host:port=IP:port'` for DNS origins (no ambient DNS), `--tsa-url` (+ `--tsa-policy OID`, required for XAdES) for evidence acquisition; CAdES/PAdES/XAdES T/LT/LTA are proven, `--as-of <Unix seconds>` for an explicit clock (default: host UTC). Document-carried certificates are never anchors. All configuration reads share one memory budget: at most 1024 certificate files, 64 endpoints/pins and `--configuration-bytes` (default 16 MiB) of encoded certificates, with every duplicate charged.

## Reports, exits and output

| Exit | Meaning |
|---:|---|
| 0 | Completed, or verification `Valid` |
| 2 | Verification `Invalid` |
| 3 | Verification `Indeterminate` (for example `--offline`, unavailable status) |
| 4 | Batch incomplete (failed or not-run items) |
| 1 | Execution, input, resource, permission or usage failure |
| 130 | Cooperative cancellation (Ctrl-C/Ctrl-Break) |

A deadline (`--timeout-seconds`) is exit **1** `DeadlineExceeded` for every single command and exit **4** for a batch (partial). The batch report's top-level `code` is `Completed`, `Partial`, `Cancelled` or `DeadlineExceeded`; a report that cannot be delivered after a stop is diagnosed on stderr (`report_delivery_failed_after_stop`) and never changes 130/4.

`--json` writes the report to stdout; `--report <new path>` stages a separate report. Binary `--output -` together with JSON stdout is rejected before any I/O. Usage errors withhold argument values. Artifacts are staged and published no-clobber; an existing destination or the source is never replaced. Report quota, serialization and file synchronization are admitted **before** the document is published; physical report I/O afterwards can still fail and is reported truthfully (document and report are not one atomic transaction, and a private signature is never rolled back).

Verified process behaviour (real binary, loopback OCSP/TSA, synthetic keys): strict RSA and GOST-2015 sign → `Valid` (0); `--offline` → 3; altered data → 2; independent OpenSSL verifies the RSA CMS and the RS256 JWS signature; CAdES-T acquires a loopback timestamp and verifies at level T.

## JWS/JWT, WS-Security, plugins, batch

* `jws sign|verify --serialization compact|flattened|general [--detached]`; `jwt encode|verify|decode`. `jwt verify` takes `--issuer`, `--audience`, `--leeway-seconds` and the host clock; `jwt decode` is explicitly unverified. JWS payload ≤ 256 KiB, claims ≤ 64 KiB.
* `sign|verify --profile wsse` with `--soap-version soap11|soap12`, `--wsse-role`, `--wsse-required-header`, `--wsse-timestamp-required`, `--wsse-timestamp-max-lifetime` (verification), and for signing `--wsse-token-reference ncanode-x509-key-identifier|binary-security-token`, `--wsse-token-id`, `--wsse-body-id`, `--wsse-timestamp-id|created|expires`. Misplaced options are rejected before I/O.
* `plugin call --manifest plugin.toml --module plugin.wasm --operation OP --caller LABEL --allow-import NAME … --args-file args.json --output -`: installation is not authority. The operator names the caller (`LocalOperator`), operation, exact imports, an optional bound key (`--key … --key-handle N --authorize`) and exact PKI bases (`--plugin-pki-endpoint GET=url`). Guest data cannot add imports, keys or origins; mandatory prompts return the typed `InteractionRequired`; there is no GUI.
* `batch run --manifest batch.json [--key … --secret-file …] --authorize`: items `hash`, `sign` (`cms|cms-detached|raw`), `verify` (optional `detached`), `extract`, each with unique `id`. The whole manifest is admitted before any source or key I/O; destinations must not exist and an output may not feed another item. Each completed output is published when its item completes, so a later failure or cancellation keeps earlier files. A bad source fails only that item. Exit 0/2/3 by worst verification, 4 for any failed/not-run item, 130 for cancellation.

Real Ctrl-Break delivery to an owned child process group (Windows) exits 130; reads remain cooperative.

## Legacy XML (`XmlSignSpec` / `XadesSpec`) options

`sign --profile xml|xades-b|xades-t|xades-lt --legacy` selects the guarded Kalkan/NCALayer-compatible facade (same strict pre-private validation, same guard). Typed options, each mapped to one SDK field: `--legacy-element`, `--legacy-parent`, `--legacy-namespace PREFIX=URI`, `--legacy-other-prefix-uri`, `--legacy-placement document-element|first-child`, `--legacy-signature-method|--legacy-digest-method rsa-sha256|gost2004|gost2015-512`, `--legacy-signed-info-c14n`, `--legacy-transform enveloped|inclusive|…` (enveloped first and once, at most one canonicalization), `--signature-id`, `--legacy-signing-time-id|--legacy-signing-time|--legacy-signing-time-reference`, `--legacy-line-breaks`, `--legacy-base64-line-breaks on|off`, `--legacy-output as-is|serialize` with `--legacy-xml-declaration`, `--legacy-standalone-no`, `--legacy-keep-outer-whitespace`, and for XAdES `--legacy-chain CERT.der` (public issuers, ≤16 files of ≤16 KiB). Unsupported combinations (legacy CMS/PDF/WSSE/XAdES-LTA, `--add`, `--target-id`, XML options on XAdES, a TSA-level without `--tsa-url`, bad namespace bindings, control characters) are `InvalidCombination`/`TsaRequired` before any I/O. No option accepts a key path, an algorithm URI or a free-form transform. XAdES T/LT/LTA (baseline and legacy) need `--tsa-url` **and** `--tsa-policy OID` (`TsaPolicyRequired` before any I/O otherwise; a token whose policy differs from the requested one is rejected after key use, reported `applied=Applied`); baseline XAdES also needs `--signature-id`.

## Named key sources

`--key-name NAME --key-config keys.json` (sign, jws/jwt, batch, plugin) resolves NAME through an operator JSON file (no secrets, ≤64 KiB, ≤64 entries, unknown fields denied, relative paths resolve against the file). The file selects which container or reader a granted name reaches, so it is read **like a secret file**: from an owner-only directory through the SDK ownership/ACL/link checks, regular files only, its bytes charged to the one shared configuration budget, read in checkpointed chunks:

```json
{"keys":[{"source":"file","name":"main","path":"signer.p12","alias":null},
         {"source":"token","name":"card","reader":"<PC/SC reader>","kind":"kaztoken","alias":"<key alias>"}]}
```

The name is the authorized key id (`named:NAME`); the container path/reader never appears on the command line, and `--key-name` conflicts with `--key`/`--token-reader`. `inspect --profile named-key --key-name … --key-config … --secret-file …` reads public metadata of a named file/JKS/PKCS#12/token source through a read-only provider (no guard, no private use).

## Token sources and the software emulator

`--token-reader` (real PC/SC) and named token entries are exercised in tests against the repository's software tokens: build with `--features token-emulator` and set `ONCL_TOKEN_EMULATOR=<oncl-token emulator config.toml>`. The variable exists only in that feature (never in releases); an unreadable file is a refusal, never a fallback. No physical token was used.

## Cancellation, deadline and terminal reports

A non-stop partial batch whose report cannot be delivered (closed stdout, unwritable `--report`) exits **1** (execution failure); only a cancellation or deadline stop keeps 130/4 over a report failure.

A batch stopped by Ctrl-C/Ctrl-Break or `--timeout-seconds` still emits its terminal report (per-item `Completed|Failed|NotRun`, `applied`, `published`, hash `digest`) from memory reserved before the first private use; exit 130 for cancellation, **4** for a deadline. A `--report` file written after a stop is created no-clobber directly, not staged. The interrupted item is `Failed` with code `Cancelled`/`DeadlineExceeded`. Batch exit priority: 130 > 4 > 2 > 3 > 0. A Ctrl-C at the interactive secret prompt is `Cancelled` (130).

## Measured basis of the certificate metadata charge

Each host certificate file is charged `CERTIFICATE_METADATA_FACTOR = 16` metadata bytes per encoded byte before it is parsed. Measured retained heap of `parse` over 11 real NCA production + 10 real NCA test + 5 synthetic certificates is at most 4.9× (`tests/config_budget.rs`, counting allocator); 1008 real roots fit the default 64 MiB metadata limit (`tests/local.rs`).

## Not done / not exercised (exact bounds)

* **Disk-full:** a genuinely full volume cannot be created on the test machine (not elevated: no VHD/diskpart; C: and X: have GBs free). The same write/publish error paths are exercised by a read-only stdout handle, a pipe closed mid-stream, fragmented slow stdout reads, and a real NTFS ACL that refuses new files after private use (single sign and batch).
* **Terminals:** no-echo, mode restoration and Ctrl-C are proven on a Windows ConPTY only. The Unix `termios` path and Linux/macOS signals are unexecuted. Win7/x86, Linux/macOS, 10 GiB/4 GiB/RSS are not measured.
* **Evidence:** CAdES-LT/LTA and PAdES-LT/LTA signing and keyless `extend` through the CLI are proven (below). Operator material is supplied with `--evidence-certificate`, `--evidence-ocsp`, `--evidence-crl` (public DER files, at most 64 each, ≤256 KiB each, ≤8 MiB total, charged to the shared configuration reservation before any document or key I/O; only valid with CAdES/PAdES sign and `extend`). CAdES-LT/LTA sign and keyless `extend` B→T→LT→LTA plus LTA renewal are proven on the loopback PKI (OCSP responses must be produced after the timestamp and not after `--as-of`; `--tsa-url` + `--tsa-policy` required). LT/LTA sign without certificate+OCSP/CRL material is `EvidenceMaterialRequired` before any I/O; material the SDK finds insufficient is only detected after key use and is reported `applied=Applied`. PAdES-LT/LTA signing and keyless PDF `extend` (T→LT→LTA) are proven the same way and verified independently with pyHanko (signature intact/valid/trusted from DSS-only revocation material with revocation required and fetching disabled; DSS contents and DocTimeStamp; a tampered byte makes the CLI exit 2 and pyHanko reject).
* **JKS** signing is proven strictly (Valid, exit 0; OpenSSL oracle) for a JKS written by Java `keytool` and for one written by a test-only Python writer (`tests/support/jks_write.py`) whose output `keytool` lists and converts (an independent reader of the Sun key protector). GOST has no independent math oracle on this machine (OpenSSL and Python lack GOST R 34.10/34.11; the XML oracle only checks GOST structure): SDK sign + SDK verify with negative contrast. The guarded legacy XML facade refuses a GOST-2015 signer (`InvalidInput`, before private use; baseline XML with GOST works).
* The symlink secret case needs a privilege the test user lacks. Publication needs a same-volume hard-link-capable destination (FAT/exFAT/SMB fail after private use). Plugin WASM memory is hard-capped at 1 MiB. `--pki-pin` is a DNS *address* pin, not a PIN secret.
* `inspect --profile container` needs `--alias`. G01/G02 encryption/decryption is an external prerequisite; no command exists.

## Oracle environments for the tests

The CLI tests use independent oracles and fail (they never skip) when one is missing:

* `ONCL_OPENSSL` — path to an OpenSSL executable. Default search: `openssl` on `PATH`, then (Windows) `Git/usr/bin/openssl.exe` under `ProgramFiles` / `ProgramW6432`.
* `ONCL_PYHANKO_PYTHON` — path to a Python interpreter with `pyhanko` and `pyhanko-certvalidator` installed. There is no default; create one with `python -m venv oracle-env` and `oracle-env/bin/pip install pyhanko pyhanko-certvalidator` (`Scripts/` on Windows), then point the variable at its `python`.

## Remote mode (`--endpoint`)

`oncl --endpoint https://signing.internal:13579 --token-file client.token --ca-file ca.pem sign --profile cms --key-name corporate-signing --authorize --input doc.bin --output doc.p7s` runs the operation on the server described in [server.md](server.md) / [http-api.md](http-api.md). The client is `oncl_api::client::ApiClient` (feature `client` of `oncl-api`; `ureq` + `rustls` only, no Tokio/axum/hyper).

* **Paths.** Every local path is read and written by the client. Documents are streamed from files/stdin as request parts (known `Content-Length` when available, chunked for stdin); results are staged in the destination's private directory and published no-clobber exactly like local runs. The server never opens a client path: the request has no path field, and a path in any string field is refused (`remote::server_cannot_open_client_path`).
* **Commits.** A result is published only after the **terminal `final` record, the closing multipart delimiter and the end of the HTTP entity** were all received. A response cut anywhere before that (before/inside an artifact, before/inside the final record, a polite end without final, a missing closing delimiter, a missing terminal chunk) publishes nothing, leaves no temporary file, prints `oncl: ResponseLost; applied=Unknown` (`NotApplied` for keyless operations) and exits 1. **There is no automatic retry, idempotency key, rollback or exactly-once promise**: the server may well have applied the key (its audit journal says so). Earlier files at other paths (earlier batch outputs included) are never touched.
* **`applied`.** The server starts a private operation only after it took the whole request body. A failure while the body was still being sent is `NotApplied`; a lost response after the last body byte is `Unknown` when the request could use a private key; a typed refusal or terminal record reports the server's own value.
* **Token.** `--token-file PATH` (an owner-only directory, same rules and 4096-byte limit as `--secret-file`) or `--token-stdin` (stdin is then not a document). Never argv, never an environment variable; it is not part of any diagnostic, report or error (tests grep stdout, stderr and every client file for it), and error messages never contain a response body, only a stable code, the HTTP status and the server's typed code.
* **Transport.** `https://` uses the built-in webpki roots; `--ca-file` (PEM bundle or DER, repeatable) *replaces* them for a private server (trust exactly that CA or the server's own certificate). There is no flag to skip verification. `http://` is accepted for `localhost`/`127.0.0.0/8`/`::1` only; any other plain-http host needs `--allow-plain-http` (token and documents travel unencrypted: a protected backend network behind a trusted proxy). Redirects are never followed and ambient proxy variables are ignored.
* **Keys.** `--key-name NAME` references an operator key on the server (no secret from the client). Key material leaves the process only with `--key PATH --secret-file … --inline-key` (and `inspect --profile container … --inline-key`): the container and password travel as `secret` parts, memory only on the client side too, and the server needs `inline_pkcs12` globally and per token. Token readers (`--token-reader`) and `--key-config` are local devices/files and are refused.
* **Authority stays with the operator.** Trust roots, validation policy, PKI network, clock, TSA, JWT issuer/audience and plugin installation are server configuration. `--root`, `--intermediate`, `--pki-endpoint`, `--pki-pin`, `--tsa-url`, `--tsa-policy`, `--offline`, `--as-of`, `--configuration-bytes`, `timestamp acquire --tsa/--algorithm`, `timestamp verify --policy-oid`, `jwt verify --issuer/--audience/--leeway-seconds`, `inspect --alias` and every `plugin` command are refused with `RemoteUnsupported` before any I/O instead of being ignored. `sign` still requires `--authorize`.
* **Families.** `hash`, `verify`, `extract`, `sign` (cms, cades-*, xml, wsse with `--soap-version`/`--wsse-body-id`, xades-b/t, pdf, pades-*, and `--legacy` xml/xades-b/xades-t with element/parent/signature/digest method), `extend` (cms/pdf t|lt|lta, xml lt|lta), `inspect`, `timestamp`, `jws`, `jwt` and `batch run`. `raw`/`digest-*` signing and XAdES LT/LTA signing are not profiles of the contract (use `xades-t` then keyless `extend`). Evidence is sent from `--evidence-certificate/-ocsp/-crl` as public document parts.
* **Reports and exits** are the local ones (0 completed/`Valid`, 2 `Invalid`, 3 `Indeterminate`, 4 incomplete batch, 1 failure, 130 cancellation). `remote_matches_local_verdict` compares verdict, policy and every per-signer check of the same signatures verified locally and remotely. Differences: the wire carries no PDF/XML structure details and no top-level AdES level (omitted, not invented); `time_basis` is the variant (`time_basis_unix` has the instant); `bytes_in` is the document bytes this client sent and `bytes_out` the artifact it received; `timestamp` facts are an object. `jwt decode` writes the payload text the server decoded (the server replaces invalid UTF-8).
* **Batch.** The manifest is read here; a source that cannot be opened fails only its own item. Outputs are staged in one store (the shared destination directory, otherwise `--temporary-directory`/`.`, which must be on the destinations' volume) and linked into place after the final record, one row per item (`published` per output). The server runs the closed `/v1/batch` (needs the token's `batch` right).
* **Limits of this client.** If the server closes the connection while the client is still uploading (for example a refusal after metadata on a large body), the typed answer may be lost to the reset: the outcome is then a transport failure with `applied=NotApplied` (the body was incomplete). Cancellation and the deadline (`--timeout-seconds`) are polled every 50 ms while waiting, so Ctrl-C ends a call to a server that never answers with exit 130 within seconds (`remote_signal.rs`); the abandoned exchange ends with the process and nothing is retried. Not exercised: Linux/macOS, Win7, 10/4 GiB documents or RSS, pinned-key TLS (only a CA/leaf file), `jws add`/`cms add`/`wsse` over the remote path (the wire fields are mapped but have no remote CLI test), PAdES LT/LTA and PDF/XML remote signing through the CLI (covered at the HTTP level by `oncl-api` tests).
* Encryption/decryption: no command and no wire route exists (G01/G02 are external); this client adds none.
* **Integrity of the answer.** Every artifact named by the final record must be received, once, with the exact length the record states: extraction (`bytes_written`) and timestamp tokens (`bytes_out` is the token length). A well-framed part of the wrong size publishes nothing (`ProtocolViolation: artifact length differs from the final record`, exit 1, `NotApplied` for keyless operations, `Unknown` when a key could have been applied). The same holds for JWS/JWT creation (`bytes_out`, enforced by the server with `writer.finish(report.bytes_out)`: oncl-server `dispatch.rs:1326`, `1371`, `1391`, `artifact.rs:190`). CMS/CAdES/XML/PDF signing and extension are not compared: the server takes the artifact length from the staged output (`dispatch.rs:1144-1148`) and does not enforce the record's `bytes_out`, an SDK counter (measured: 8250 for a 1561-byte CMS), so only identity and count are checked there and reports use the exact received length.
* **`--allow-plain-http` warning.** Every run that uses it against a non-loopback `http://` host prints `oncl: warning: --allow-plain-http sends the API token and every document over an unencrypted, unauthenticated connection …` on stderr (never the token). Without the flag such an endpoint is refused before any connection (`PlainHttpRefused`).
* **Batch destinations.** When outputs are not all in one directory, a real hard link is created and removed in every destination directory *before any request* (`DestinationNotLinkable`, `NotApplied`), so a key is never used for a result that cannot be linked into place. Verified with an unusable directory and with two real directories; a second volume is not available on the test machine, and the probe tests the capability itself, so another volume is refused the same way (not exercised).
* **Redirects and proxies.** A 3xx answer is never followed (the bearer token is never forwarded: `UnexpectedStatus (HTTP 307)`), and `HTTP_PROXY`/`ALL_PROXY` are ignored (tests record that neither the redirect target nor the ambient proxy is ever contacted). A connection reset while the body is still being sent is `NotApplied`: the service takes the whole multipart body (and re-checks authority) before a worker may use a key (`crates/oncl-server/src/service/operations.rs` and `operations/intake.rs`).
