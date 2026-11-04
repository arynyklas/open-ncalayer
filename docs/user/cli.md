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
* Key source: `--key` (PKCS#12 or JKS; `--alias` when several entries exist) **or** `--token-reader NAME --token-kind … --token-alias …` (real PC/SC; experimental; **not exercised against a physical or emulated token** here — absent readers fail closed with no output).
* Secrets never appear as arguments. Use `--secret-file` inside an existing **owner-only directory** (the SDK verifies directory and file owner/ACL, link count, reparse points and refuses to repair) or `--secret-interactive` (fixed zeroizing buffers; refused when stdin is a document or not a terminal). Files accept at most 4097 raw bytes / 4096 password bytes and one trailing LF/CRLF; nothing is truncated. Process tests cover unprotected directory, oversized, absent and directory secrets (all refused with no private use); the symlink case needs a privilege this machine lacks and was not exercised.
* Interactive input: Backspace removes a scalar, Ctrl-U clears, Ctrl-W removes a word, Ctrl-C cancels. Terminal modes are restored on normal/error/unwind. **No real terminal/PTY no-echo run has been performed.** Forced termination or a blocked native read cannot guarantee immediate cancellation or restoration.
* The default `rpassword 7.5.4`/`rtoolbox 0.0.6` reader was deliberately not used: it grows a `String` and only erases its current length, so retired/truncated copies are not zeroized.

## Trust, network and time

Trust comes only from the operator: `--root`, `--intermediate`, `--pki-endpoint` (exact origins; literal IPs pin themselves), `--pki-pin 'http://host:port=IP:port'` for DNS origins (no ambient DNS), `--tsa-url` for CAdES T/LT/LTA acquisition, `--as-of <Unix seconds>` for an explicit clock (default: host UTC). Document-carried certificates are never anchors. All configuration reads share one memory budget: at most 1024 certificate files, 64 endpoints/pins and `--configuration-bytes` (default 16 MiB) of encoded certificates, with every duplicate charged.

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

## Not done / not exercised

Legacy `XmlSignSpec`/`XadesSpec` host options; named-alias key sources; a token emulator or physical-token run; PTY/console no-echo certification; disk-full and fragmented-write injection beyond the closed-stdout test; Win7/x86, Linux/macOS, 10 GiB/4 GiB and RSS measurements. `inspect --profile container` needs `--alias`. G01/G02 encryption is an external prerequisite.
