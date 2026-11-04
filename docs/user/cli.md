# Standalone local CLI (`oncl`)

`cargo run -p oncl-cli -- …` runs the independent local SDK consumer. It does not start the desktop, an HTTP server, a daemon or a browser session, and it has no remote `--endpoint` placeholder.

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
  --key signer.p12 --secret-file drive_C:\private\key.secret --authorize \
  --root operator-root.der --pki-endpoint https://pki.example.test
```

* `--authorize` is the explicit confirmation of this exact source, profile, key and destination. A password is not authority. There is no unlocked cache across invocations, and strict certificate/revocation validation always precedes private use (`--offline` only affects the verification policy, never signing).
* Key source: `--key` (PKCS#12 or JKS; `--alias` when several entries exist) **or** `--token-reader NAME --token-kind … --token-alias …` (real PC/SC; exercised against the software emulator only, never a physical token — absent readers fail closed with no output).
* Secrets never appear as arguments. Use `--secret-file` inside an existing **owner-only directory** (the SDK verifies directory and file owner/ACL, link count, reparse points and refuses to repair) or `--secret-interactive` (fixed zeroizing buffers; refused when stdin is a document or not a terminal). Files accept at most 4097 raw bytes / 4096 password bytes and one trailing LF/CRLF; nothing is truncated. Process tests cover unprotected directory, oversized, absent and directory secrets (all refused with no private use); the symlink case needs a privilege this machine lacks and was not exercised.
* Interactive input: Backspace removes a scalar, Ctrl-U clears, Ctrl-W removes a word, Ctrl-C cancels. Terminal modes are restored on normal/error/unwind. No-echo, restoration and Ctrl-C are proven on a real Windows ConPTY (see below). Forced termination or a blocked native read cannot guarantee immediate cancellation or restoration.
* The default `rpassword 7.5.4`/`rtoolbox 0.0.6` reader was deliberately not used: it grows a `String` and only erases its current length, so retired/truncated copies are not zeroized.

## Trust, network and time

Trust comes only from the operator: `--root`, `--intermediate`, `--pki-endpoint` (exact origins; literal IPs pin themselves), `--pki-pin 'http://host:port=IP:port'` for DNS origins (no ambient DNS), `--tsa-url` (+ `--tsa-policy OID` for XAdES/PAdES evidence) for evidence acquisition; only CAdES-T, PAdES-T and XAdES T/LT/LTA are proven, `--as-of <Unix seconds>` for an explicit clock (default: host UTC). Document-carried certificates are never anchors. All configuration reads share one memory budget: at most 1024 certificate files, 64 endpoints/pins and `--configuration-bytes` (default 16 MiB) of encoded certificates, with every duplicate charged.

## Reports, exits and output

| Exit | Meaning |
|---:|---|
| 0 | Completed, or verification `Valid` |
| 2 | Verification `Invalid` |
| 3 | Verification `Indeterminate` (for example `--offline`, unavailable status) |
| 4 | Batch incomplete (failed or not-run items) |
| 1 | Execution, input, resource, permission or usage failure |
| 130 | Cooperative cancellation (Ctrl-C/Ctrl-Break) |

`--json` writes the report to stdout; `--report <new path>` stages a separate report. Binary `--output -` together with JSON stdout is rejected before any I/O. Usage errors withhold argument values. Artifacts are staged and published no-clobber; an existing destination or the source is never replaced. Report quota, serialization and file synchronization are admitted **before** the document is published; physical report I/O afterwards can still fail and is reported truthfully (document and report are not one atomic transaction, and a private signature is never rolled back).

Verified process behaviour (real binary, loopback OCSP/TSA, synthetic keys): strict RSA and GOST-2015 sign → `Valid` (0); `--offline` → 3; altered data → 2; independent OpenSSL verifies the RSA CMS and the RS256 JWS signature; CAdES-T acquires a loopback timestamp and verifies at level T.

## JWS/JWT, WS-Security, plugins, batch

* `jws sign|verify --serialization compact|flattened|general [--detached]`; `jwt encode|verify|decode`. `jwt verify` takes `--issuer`, `--audience`, `--leeway-seconds` and the host clock; `jwt decode` is explicitly unverified. JWS payload ≤ 256 KiB, claims ≤ 64 KiB.
* `sign|verify --profile wsse` with `--soap-version soap11|soap12`, `--wsse-role`, `--wsse-required-header`, `--wsse-timestamp-required`, `--wsse-timestamp-max-lifetime` (verification), and for signing `--wsse-token-reference ncanode-x509-key-identifier|binary-security-token`, `--wsse-token-id`, `--wsse-body-id`, `--wsse-timestamp-id|created|expires`. Misplaced options are rejected before I/O.
* `plugin call --manifest plugin.toml --module plugin.wasm --operation OP --caller LABEL --allow-import NAME … --args-file args.json --output -`: installation is not authority. The operator names the caller (`LocalOperator`), operation, exact imports, an optional bound key (`--key … --key-handle N --authorize`) and exact PKI bases (`--plugin-pki-endpoint GET=url`). Guest data cannot add imports, keys or origins; mandatory prompts return the typed `InteractionRequired`; there is no GUI.
* `batch run --manifest batch.json [--key … --secret-file …] --authorize`: items `hash`, `sign` (`cms|cms-detached|raw`), `verify` (optional `detached`), `extract`, each with unique `id`. The whole manifest is admitted before any source or key I/O; destinations must not exist and an output may not feed another item. Each completed output is published when its item completes, so a later failure or cancellation keeps earlier files. A bad source fails only that item. Exit 0/2/3 by worst verification, 4 for any failed/not-run item, 130 for cancellation.

Real Ctrl-Break delivery to an owned child process group (Windows) exits 130; reads remain cooperative.

## Legacy XML (`XmlSignSpec` / `XadesSpec`) options

`sign --profile xml|xades-b|xades-t|xades-lt --legacy` selects the guarded Kalkan/NCALayer-compatible facade (same strict pre-private validation, same guard). Typed options, each mapped to one SDK field: `--legacy-element`, `--legacy-parent`, `--legacy-namespace PREFIX=URI`, `--legacy-other-prefix-uri`, `--legacy-placement document-element|first-child`, `--legacy-signature-method|--legacy-digest-method rsa-sha256|gost2004|gost2015-512`, `--legacy-signed-info-c14n`, `--legacy-transform enveloped|inclusive|…` (enveloped first and once, at most one canonicalization), `--signature-id`, `--legacy-signing-time-id|--legacy-signing-time|--legacy-signing-time-reference`, `--legacy-line-breaks`, `--legacy-base64-line-breaks on|off`, `--legacy-output as-is|serialize` with `--legacy-xml-declaration`, `--legacy-standalone-no`, `--legacy-keep-outer-whitespace`, and for XAdES `--legacy-chain CERT.der` (public issuers, ≤16 files of ≤16 KiB). Unsupported combinations (legacy CMS/PDF/WSSE/XAdES-LTA, `--add`, `--target-id`, XML options on XAdES, a TSA-level without `--tsa-url`, bad namespace bindings, control characters) are `InvalidCombination`/`TsaRequired` before any I/O. No option accepts a key path, an algorithm URI or a free-form transform. XAdES T/LT (baseline and legacy) need `--tsa-url` **and** `--tsa-policy OID`; baseline XAdES also needs `--signature-id`.

## Named key sources

`--key-name NAME --key-config keys.json` (sign, jws/jwt, batch, plugin) resolves NAME through an operator JSON file (no secrets, ≤64 KiB, ≤64 entries, unknown fields denied, relative paths resolve against the file):

```json
{"keys":[{"source":"file","name":"main","path":"signer.p12","alias":null},
         {"source":"token","name":"card","reader":"<PC/SC reader>","kind":"kaztoken","alias":"<key alias>"}]}
```

The name is the authorized key id (`named:NAME`); the container path/reader never appears on the command line, and `--key-name` conflicts with `--key`/`--token-reader`. `inspect --profile named-key --key-name … --key-config … --secret-file …` reads public metadata of a named file/JKS/PKCS#12/token source through a read-only provider (no guard, no private use).

## Token sources and the software emulator

`--token-reader` (real PC/SC) and named token entries are exercised in tests against the repository's software tokens: build with `--features token-emulator` and set `ONCL_TOKEN_EMULATOR=<oncl-token emulator config.toml>`. The variable exists only in that feature (never in releases); an unreadable file is a refusal, never a fallback. No physical token was used.

## Cancellation, deadline and terminal reports

A batch stopped by Ctrl-C/Ctrl-Break or `--timeout-seconds` still emits its terminal report (per-item `Completed|Failed|NotRun`, `applied`, `published`, hash `digest`) from memory reserved before the first private use; exit 130 for cancellation, **4** for a deadline. A `--report` file written after a stop is created no-clobber directly, not staged. The interrupted item is `Failed` with code `Cancelled`/`DeadlineExceeded`. Batch exit priority: 130 > 4 > 2 > 3 > 0. A Ctrl-C at the interactive secret prompt is `Cancelled` (130).

## Measured basis of the certificate metadata charge

Each host certificate file is charged `CERTIFICATE_METADATA_FACTOR = 16` metadata bytes per encoded byte before it is parsed. Measured retained heap of `parse` over 11 real NCA production + 10 real NCA test + 5 synthetic certificates is at most 4.9× (`tests/config_budget.rs`, counting allocator); 1008 real roots fit the default 64 MiB metadata limit (`tests/local.rs`).

## Not done / not exercised (exact bounds)

* **Disk-full:** a genuinely full volume cannot be created on the test machine (not elevated: no VHD/diskpart; C: and X: have GBs free). The same write/publish error paths are exercised by a read-only stdout handle, a pipe closed mid-stream, fragmented slow stdout reads, and a real NTFS ACL that refuses new files after private use (single sign and batch).
* **Terminals:** no-echo, mode restoration and Ctrl-C are proven on a Windows ConPTY only. The Unix `termios` path and Linux/macOS signals are unexecuted. Win7/x86, Linux/macOS, 10 GiB/4 GiB/RSS are not measured.
* **Evidence:** CAdES/PAdES LT/LTA signing and keyless `extend` through the CLI fail (`InvalidInput`, before private use) because the CLI supplies no `ValidationMaterial` (certificates/OCSP/CRLs) option; only CAdES-T, PAdES-B/T, XAdES B/T/LT/LTA (baseline and legacy B/T/LT) and standalone timestamps are proven. Higher levels are not claimed.
* **JKS** key files are proven for public metadata only (strict signing needs a PKI chain the JKS fixture does not have). GOST has no independent oracle on this machine (OpenSSL lacks the GOST engine): SDK sign + SDK verify with negative contrast, for a GOST-rooted chain including OCSP responder, TSA, CAdES-T and JWS/JWT.
* The symlink secret case needs a privilege the test user lacks. Publication needs a same-volume hard-link-capable destination (FAT/exFAT/SMB fail after private use). Plugin WASM memory is hard-capped at 1 MiB. `--pki-pin` is a DNS *address* pin, not a PIN secret.
* `inspect --profile container` needs `--alias`. G01/G02 encryption/decryption is an external prerequisite; no command exists.
