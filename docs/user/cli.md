# Standalone local CLI (`oncl`)

`cargo run -p oncl-cli -- …` runs the independent local SDK consumer. It does not start the desktop, an HTTP server, a daemon, or a browser session. The workspace version also applies to this binary.

**Task25 acceptance is not complete.** This checkpoint exposes hash, source-bound CMS/raw/XML/PDF signing and their implemented AdES profiles, format verification, CMS extraction, public inspection, public evidence extension, and standalone timestamps. The CLI still needs JOSE/JWT dispatch, plugin invocation, mixed typed batch manifests, named/token key selection, host DNS-address-pin options, legacy XML selector/profile options, and their complete process/oracle acceptance. The SDK's typed staged and owned-batch output mechanisms are implemented separately; their existence does not mean a CLI batch command exists.

Encryption/decryption additionally require the genuine G01/G02 SDK backend, documentation, and vectors. WS-Security awaits the parent-reviewed X05 API. Those are external prerequisites, not RSA-only substitutes or fake commands. No `encrypt`, `decrypt`, `plugin`, `batch`, or remote `--endpoint` placeholder is registered.

## Working commands

```text
oncl hash --algorithm sha256 --input -
oncl verify --profile cms --input signature.der --detached document.bin --offline --json
oncl extract --input attached.der --output extracted.bin
oncl inspect --profile certificate --input certificate.der --json
oncl inspect --profile cms --input signature.der --json
oncl inspect --profile container --input certificate.p12 --alias signing --secret-file drive_C:\private\key.secret --json
```

For example, in Git Bash:

```sh
printf abc | cargo run -p oncl-cli -- hash --algorithm sha256 --input -
```

The SHA-256 result is:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

`--input -` claims stdin for exactly one document role. A detached document and signature cannot both claim stdin. Hashing streams the source; it does not buffer the entire document or require a temporary directory, key provider, trust store, network, or runtime.

Hash algorithms are `sha256`, `gost2004` (the existing GOST 34.311 profile), and `gost2015-512` (Streebog-512). Algorithms are not inferred from filenames.

## Private signing and secrets

```text
oncl sign --profile cms --input document.bin --output signature.der --key certificate.p12 --secret-file drive_C:\private\key.secret --authorize --root operator-root.der --pki-endpoint http://127.0.0.1:49152
oncl sign --profile raw --input document.bin --output signature.raw --key certificate.p12 --secret-file drive_C:\private\key.secret --authorize --root operator-root.der --pki-endpoint http://127.0.0.1:49152
```

The loopback endpoint in these examples is an **operator-supplied synthetic PKI responder**, not a service launched by `oncl`. For real signing, configure genuine operator-approved roots, intermediates, and reachable status endpoints. Strict certificate and revocation validation is mandatory before private use; `--offline` does not bypass it. A key password is not signing authority: `--authorize` additionally authorizes the requested action, source, profile, key, and destination for this invocation. There is no unlocked cross-operation cache.

Key files are PKCS#12 or JKS as supported by the SDK; use `--alias` when the container has multiple entries. No command exports a private key.

Create the secret file **inside an existing owner-only directory**, using the OS account's protected permissions. The SDK verifies the directory and opened file, including owner/ACL policy, link count, and symlink/reparse constraints; it does not repair insecure files. Supply a password obtained from a synthetic fixture's manifest through this protected file, not by copying it into command arguments. Do not put secrets in shell history, environment variables, or batch arguments.

Secret files admit at most 4097 raw bytes and 4096 UTF-8 password bytes. One final LF or CRLF is removed. Consequently a 4096-byte password can use LF but cannot also fit CRLF under the raw-file bound. Unexpected extra bytes, malformed UTF-8, and oversized files fail rather than truncating a password. Secret buffers and the final string are zeroized, including spare allocation capacity; keys/passwords are never document spool contents.

`--secret-interactive` requests a real no-echo terminal instead of a secret file. It is refused when stdin is a document or is not a terminal. The bounded editor accepts at most 4097 raw UTF-8 input bytes including editing/terminator bytes, with at most 4096 password bytes; Enter completes input, EOF does not. Backspace removes a complete scalar; Ctrl-U clears; Ctrl-W removes the last word; Ctrl-C cancels. Removed bytes are wiped. Windows uses Unicode console reads without changing its codepage. Exact terminal mode is restored on ordinary return/error/unwind. Forced termination, blocked native reads, or console destruction cannot guarantee immediate cancellation/restoration. **A real terminal/PTY acceptance run remains outstanding; do not treat compilation or bounded-editor tests as no-echo certification.**

The pinned `rpassword 7.5.4`/`rtoolbox 0.0.6` input path was not reused: its growing `String` and current-length-only erasure do not meet this task's retired/truncated-buffer requirement. This CLI instead uses fixed zeroizing byte/scalar buffers and one fallible final secret-string allocation.

Signing profiles currently registered: `cms`, `raw`, `digest-sha256`, `digest-gost2004`, `digest-gost2015-512`, `xml`, `pdf`, and `cades-…`/`xades-…`/`pades-…` with `b`, `t`, `lt`, `lta` suffixes. Digest profiles read **raw digest bytes**, explicitly grant `SignDigest`, and do not upgrade ordinary document signing to prehash authority. `--add` selects the actual supported CMS/XML Add path; `--detached` creates detached CMS; `--detached-input` supplies CMS Add's detached content. XML IDs use `--target-id`, `--parent-id`, and `--signature-id`.

Higher AdES acquisition requires SDK TSA configuration. This checkpoint does not yet expose its complete CLI configuration, so no successful T/LT/LTA acquisition is claimed merely because those typed profile names are parsed.

## Trust, reports, and exit states

`--root` and `--intermediate` accept explicit host DER certificates. Document-carried certificates never become trust anchors. `--pki-endpoint` limits permitted origins; literal IP origins pin themselves. DNS origins without approved resolved pins cannot silently fall back to ambient DNS. The CLI DNS-pin option is still outstanding. Transport proxy use is disabled in this composition.

`--as-of <Unix-seconds>` explicitly selects a fixed host verification clock. Otherwise the host UTC clock remains dynamic. `--offline` produces `OfflineReport`; unavailable mandatory evidence is not a mathematical-signature-only `Valid`. An untrusted chain is Invalid, whereas absent required status on an otherwise trusted path can be Indeterminate.

| Exit | Meaning |
|---:|---|
| 0 | Completed non-validation command, or completed verification with `Valid` |
| 2 | Completed verification with `Invalid` |
| 3 | Completed verification with `Indeterminate` |
| 1 | Execution, input, resource, permission, or usage failure |
| 130 | Cooperative cancellation, with the actual key application state retained |

Exit 4 is reserved by Task25 for incomplete/partial batches; the CLI batch adapter and its exact cancellation behavior are not yet implemented or accepted. Do not interpret this checkpoint as exercising exit 4 or real process-signal exit 130.

`--json` sends the report to stdout. `--report <new-path>` stages a separate JSON report. Human artifact-command diagnostics go to stderr. Binary `--output -` plus JSON stdout is rejected before document/key I/O; use a separate report path instead. Usage errors deliberately withhold raw argument values, including unknown options and invalid enum values, to avoid echoing attempted secret arguments.

Verification reports retain their admitted SDK owners while being serialized into a bounded writer. Inspection/extraction are structural and never claim signature validity. Reports are limited to 1 MiB. `--output-limit` is an operation output quota, including emitted report bytes, not a document-only allowance.

File artifacts are staged on the destination filesystem and explicitly published no-clobber only after successful production. Existing destinations, including the source itself, are never replaced. A failed operation does not publish its partial stage. Stdio can retain an unsuccessful prefix after an I/O/cancellation failure and must be accepted only with the final process status. Document output and a separate report are not a cross-file atomic transaction: a completely published artifact can remain if subsequent report publication fails; no rollback or exactly-once private-key claim is made.

`--timeout-seconds` is finite/nonzero and covers intake and operation control. Native synchronous reads/crypto remain cooperative; cancellation cannot free their actual resources before return. Defaults are accounting limits, not measured 10-GiB/RSS, Win7, or physical-token acceptance evidence.
