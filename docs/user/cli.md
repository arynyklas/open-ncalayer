# Standalone local CLI (`oncl`)

`cargo run -p oncl-cli -- …` runs the independent SDK consumer. By default it is purely local: it does not start the desktop, an HTTP server, a daemon or a browser session. With an explicit `--endpoint` it is instead a streaming client of the `oncl-server` HTTP contract (see [Remote mode](#remote-mode---endpoint)); there is no discovery and no implicit fallback between the two.

Encryption/decryption would require the external G01/G02 SDK backend: no `encrypt`/`decrypt` command and no RSA-only substitute exists. What is not covered is listed under [Known limits](#known-limits).

## Package (no installer)

`oncl` is published as an archive of its own, `oncl-<version>-<flavor>.zip` (Windows: `win-x64`, `win-x86`, and `win7-x64`/`win7-x86` for Windows 7 SP1) or `oncl-<version>-<flavor>.tar.gz` (`linux-x64`, built against glibc 2.28; `osx`, universal). It is **not** part of the OpenNCALayer desktop package: no installer, no update channel, no autostart, nothing written outside the paths you name. The archive holds the program, `README.md`, `docs/cli.md`, `THIRD-PARTY.txt` (the licences of exactly the third-party code of that flavor, AWS-LC included on Linux/macOS only), `LICENSE` and `NOTICE`; it holds no certificate, key, token or test file. Updating means unpacking a newer archive.

```sh
tar -xzf oncl-<version>-linux-x64.tar.gz
./oncl-<version>-linux-x64/oncl --version
printf abc | ./oncl-<version>-linux-x64/oncl hash --algorithm sha256 --input -
```

On Windows unpack the `.zip` (Explorer or `tar -xf oncl-<version>-win-x64.zip`) and run `oncl.exe` from that folder; the program needs no Visual C++ redistributable. The maintainer's command that builds, checks and smoke-tests the archives is `cargo xtask package platform` (`cargo xtask package platform --help`).

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
| `plugin call` | Runtime-only WASM invocation with operator grants ([Plugins](#plugins-oncl-plugin)) |
| `plugin operations` | The operations a plugin manifest declares, for writing grants; optional module check |
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

`oncl verify --profile cms --input <signature.p7s> --root <NCA root>` is the only CMS signature checker of the project: it replaced the daemon's `openncalayer cms-verify` (removed, with its `crl/` cache path and its default embedded NCA CA set). The differences are intentional: there is no implicit default trust set (pass the NCA roots you trust with `--root`), the input is DER or BER — or, with the explicit `--pem` flag (CMS profile only, at most 16 MiB of text, exactly one `CMS` or `PKCS7` block and nothing around it, decoded before parsing; the demo page's text area gives PEM, its `.p7s` file DER) — validation is always strict (the NCALayer compatibility policy, `OperationPolicy::ncalayer_compatibility()`, is a choice of an embedding host and has no command-line switch), the report is per check, and an unproven signing time or unavailable revocation data is `Indeterminate` (exit 3).

With `--profile cades-*` or `pades-*` a signature that verifies but misses a baseline rule is reported with a `Profile(SigningTimeForbidden|SigningTimeMissing|ContentTypeNotData|SigningCertificateMissing)` reason: the signature check stays `Passed`, the verdict is `Invalid` (exit 2) and no `ades_level` is claimed. Kalkan's own PAdES carries a signing-time attribute, which EN 319 142-1 table 1 forbids, so it is reported this way under `pades-*` while `--profile pdf` judges the same bytes by integrity and trust only.

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

## JWS/JWT, WS-Security, plugins, batch

* `jws sign|verify --serialization compact|flattened|general [--detached]`; `jwt encode|verify|decode`. `jwt verify` takes `--issuer`, `--audience`, `--leeway-seconds` and the host clock; `jwt decode` is explicitly unverified. JWS payload ≤ 256 KiB, claims ≤ 64 KiB.
* `sign|verify --profile wsse` with `--soap-version soap11|soap12`, `--wsse-role`, `--wsse-required-header`, `--wsse-timestamp-required`, `--wsse-timestamp-max-lifetime` (verification), and for signing `--wsse-token-reference ncanode-x509-key-identifier|binary-security-token`, `--wsse-token-id`, `--wsse-body-id`, `--wsse-timestamp-id|created|expires`. Misplaced options are rejected before I/O.
* `plugin call` / `plugin operations`: runtime-only plugin invocation and the listing of a manifest's declared operations; installation is not authority. Flags, typed parameters, consent, audit, refusals and exit codes are in [Plugins](#plugins-oncl-plugin).
* `batch run --manifest batch.json [--key … --secret-file …] --authorize`: items `hash`, `sign` (`cms|cms-detached|raw`), `verify` (optional `detached`), `extract`, each with unique `id`. The whole manifest is admitted before any source or key I/O; destinations must not exist and an output may not feed another item. Each completed output is published when its item completes, so a later failure or cancellation keeps earlier files. A bad source fails only that item. Exit 0/2/3 by worst verification, 4 for any failed/not-run item, 130 for cancellation.

Real Ctrl-Break delivery to an owned child process group (Windows) exits 130; reads remain cooperative.

## Plugins (`oncl plugin`)

```text
oncl plugin operations --manifest plugin.toml [--wasm plugin.wasm] [--json]
oncl plugin call       --manifest plugin.toml --module plugin.wasm --operation OP --caller LABEL
                       --output - [--allow-import NAME …] [request] [key and grants]
```

Installation is not authority. The operator, who runs the command, names the caller (a `LocalOperator` label), the operation, the exact imports, the key and the PKI bases; the plugin cannot widen any of them. There is no GUI, no browser origin and **no prompt**: a mandatory dialog of the plugin returns the typed `InteractionRequired`, and nothing asks for consent. Both commands are local only; with `--endpoint` they are refused with `RemoteUnsupported` before any I/O.

### `plugin operations`: what is declared

Lists the `[[operations]]` of a manifest (`Manifest::operations()` of `oncl-plugin`, the parser that `plugin call` and `cargo xtask plugin-ops-check` use), so that grants can be written without reading the TOML. It opens no key and runs nothing.

| Flag | Meaning |
|---|---|
| `--manifest PATH` | The plugin's `plugin.toml` (at most 64 KiB) |
| `--wasm PATH` | Also compile this module (at most 16 MiB) against the manifest: every import an operation declares must be an import of the module, every import of the module must be declared by a capability (the library check of `plugin-ops-check`). Exit 1 when it does not fit |
| `--json`, `--report PATH` | The report as JSON (global flags; `--report` creates a new file and prints nothing) |

```text
$ oncl plugin operations --manifest plugins/example/plugin.toml
plugin test.cli 1.0.0: 2 declared operation(s)
operation sign
  label: "a"
  server: yes  manual: no
  cli: yes
  imports: keys_sign_raw
  network: pki
  param file: document (at most 4096 bytes)
  key: raw, content param:file
    signs with your key: a raw signature of the content
operation manual-only
  label: "a"
  server: no  manual: yes
  cli: no (not for the CLI: server = false)
  imports: none
  network: none
  param file: document (at most 4096 bytes)
  key: none
```

`cli:` says whether `plugin call` can run the operation: it needs `server = true` and content that the host can run. An operation with `derived` content is shown as `cli: no (not runnable: derived content)`: no host runs it yet and `plugin call` refuses it (`subcode=not-declared`). The key-use and profile words are the host's English texts of the install window (what the core forces on the signature); the `label` and any `plugin's xpath` are the plugin's own untrusted text and are printed quoted and escaped. A plugin without `[[operations]]` prints `declares no operations`.

JSON (`code` is `Completed`, or `InvalidInput` when `--wasm` does not fit; `applied` is always `NotApplied`; optional fields are omitted when absent):

| Field | Meaning |
|---|---|
| `code`, `applied` | as above |
| `plugin` | `{id, version}` |
| `operations[]` | one object per declared operation, in manifest order |
| `operations[].name`, `.label` | the operation name; the plugin's English label (untrusted) |
| `.server`, `.manual` | the declared flags |
| `.runnable`, `.derived` | `runnable` is `false` exactly when `derived` is `true` (derived content) |
| `.cli` | `server` and `runnable`: the operation `plugin call` accepts |
| `.imports` | the declared host imports (the most `--allow-import` may name) |
| `.network` | `{"kind":"none"}`, `{"kind":"pki"}` or `{"kind":"urls","urls":[…]}` |
| `.params[]` | `{name, kind}` with `kind` `document` (`max_bytes`), `text` (`max_chars`), `choice` (`choices`), `flag` or `locale` |
| `.keys[]` | one per key use: `kind` (`raw`, `cms`, `cms_ex`, `xml`, `xml_ex`, `xades`), `content` (`param:<name>` or `derived`), `words`, and `profile` (the forced options in words, when there are any to say) |
| `.xpaths` | the plugin's own XPaths of the profile (untrusted), when there are any |
| `module` | with `--wasm`: `{ok}` and, when `false`, `error` (the library's reason) |

### `plugin call`: flags

| Flag | Meaning |
|---|---|
| `--manifest`, `--module` | The manifest (≤ 64 KiB) and module (≤ 16 MiB) of the one plugin installed for this process |
| `--operation OP` | The operation: a declared one with `server = true`, or, for a plugin without declarations, the label the operator grants |
| `--caller LABEL` | The operator label recorded as the caller (never an origin, never taken from the plugin) |
| `--allow-import NAME` | Exact host imports granted (repeatable, known names only, at most 80). For a declared operation they must be among its declared imports; none given means all declared. For a plugin without declarations none given means none |
| `--output PATH\|-` | Where the response is written (never overwrites; `-` is stdout, which cannot be combined with `--json` on stdout) |
| `--args-file PATH\|-` | A **free** JSON request (≤ 256 KiB): what a plugin without declarations takes, and what a declared operation still accepts (the operator trusts the request, as before) |
| `--param NAME=VALUE` | A typed `text`, `choice` or `locale` parameter of a declared operation (repeatable) |
| `--param-file NAME=PATH\|-` | A `document` parameter read from a file (`-` is stdin; at most one stdin source per command) |
| `--param-flag NAME` | A `flag` parameter set to true; a declared flag that is not named is false |
| `--key PATH [--alias A]` or `--key-name N --key-config FILE` | The key bound as handle `--key-handle` (default 1); see [Named key sources](#named-key-sources) |
| `--secret-file PATH` \| `--secret-interactive` | The key password, as for `sign` |
| `--authorize` | Required with a key: confirms this exact key use |
| `--plugin-bytes` | The operator's consent to a key use of a declared operation (below); needs a key |
| `--plugin-pki-endpoint GET=URL` / `POST=URL` | Exact PKI bases the plugin's key validation may reach (≤ 16; needs a declared `network = "pki"`) |
| `--profile` | **Not accepted** (`oncl: ProfileFromManifest`): the signature profile of a declared operation is the manifest's, forced by Core |

Global flags (`--json`, `--report`, trust and `--timeout-seconds`) behave as for the other commands. `--args-file` and any `--param*` flag cannot be combined (`InvalidCombination`); a malformed `NAME=VALUE`, a name that is not `^[a-z][a-z0-9_]{0,31}$`, more than 16 parameters of a kind, two stdin sources (`StdinConflict`) or a stdin source with `--secret-interactive` are usage errors that withhold the values and open nothing.

### Typed parameters

For a declared operation without `--args-file`, Core builds the request from the manifest's template exactly as the manual window does (`Engine::plugin_server_request`; `module` and `method` come from the manifest alone, each whole-string placeholder is replaced by the typed value, a document as standard base64, keys sorted, compact). Everything is checked before any secret is read or key opened, and an operation with no parameters needs no flag at all:

* every declared parameter must be given once (a flag may be left out: false); an undeclared name is `unknown-param`, a repeated one `duplicate-param`, a missing one `missing-param`;
* a document comes only from `--param-file` and a text, choice or locale only from `--param` (`param-wrong-kind` otherwise); a choice must be one of the declared `choices`, a locale `ru`, `kk` or `en`, a text at most `max_chars` characters (a valid absolute XPath when a profile reads it; and, when it is the signed content, free of control characters other than `\n` and `\t` and of bidirectional or invisible ones, so `\r` is refused too) (`param-invalid-value` / `param-too-large`);
* a document file is read only for a declared document and never past its declared `max_bytes` (nor the 256 KiB request limit): a larger file is `InputLimit`, `subcode=param-too-large`, and an empty one `param-invalid-value`;
* the whole request must fit 256 KiB (`request-too-large`).

A text parameter that a key profile reads (`element = "param:xpath"`) is also what the `--plugin-bytes` grant is matched with: the grant covers exactly the profile with that value, so a plugin that signs with another element is `options-mismatch`.

A plugin **without** `[[operations]]` is unchanged: it takes only `--args-file`, and `--param*` or a missing `--args-file` is refused (`PermissionDenied`, `subcode=not-declared`) because there is nothing to check them against. `--plugin-bytes` has no effect on it (a warning says so).

`plugin call` runs only an operation with `server = true`. The plugins shipped in `plugins/` declare 30 operations, all `manual = true` for the desktop's manual window ([guide](manual-plugins.md)) and none `server = true`, so `oncl plugin call` refuses every one of them with `subcode=not-declared`; `plugin operations` still lists them.

### Consent and audit

The CLI never prompts. For a declared operation Core issues a ticket for every key use and checks it against the declaration (one use, the declared kind and options), and because the CLI cannot bind the bytes the plugin signs to a document, a key use needs `--plugin-bytes`: **the operator who runs the command is the consenting party**, and the flag says that they accept that the plugin chooses the bytes the key signs (with a free `--args-file` the grant binds the operation, kind and options only, and the plugin decides what it signs; with typed parameters it also binds the content: the ticket's content must equal the exact bytes passed for the parameter the key use is bound to, a text as UTF-8 and a document as the file bytes, otherwise the use is refused before the key with `subcode=content-mismatch`. A digest-form bound use cannot be computed before the key is opened and is refused with `subcode=content-binding-unavailable`). Without it the use is refused before the key is applied (`subcode=not-granted`). `--plugin-bytes` covers one use of the declared kind with exactly the declared options (the options a profile reads from a `--param` are those values); a deviation is `options-mismatch`, a second use in one call `key-use-spent`.

The CLI keeps no journal; stderr is the operator's record. Before the key is used, an authorised key use of a declared operation writes one line (the trusted facts of Core's ticket; never the document, a parameter value, a secret or a nonce), then the usual `private_use` line after it:

```text
oncl: plugin_use operation_id=7 plugin=test.cli version=1.0.0 package=2:<sha256 of manifest+module> operation=sign caller=local-operator declared=true grant=cli-plugin-bytes content_sha256=<sha256 of the bytes signed> content_len=14 prehashed=false options_sha256=<sha256 of the forced options> ticket=<sha256 digest of the ticket>
oncl: private_use operation_id=7 applied=Applied succeeded=true
```

`grant=cli-plugin-bytes` is the consent (an interactive approval would have a nonce hash instead); `package=2:…` is the loose package hash (kind 2) of the two files you named. A refused key use writes `oncl: plugin_refused operation_id=… subcode=… plugin=… operation=…` instead, with no key use.

### Exit codes, refusals and the failure line

| Exit | Meaning |
|---:|---|
| 0 | Completed (`plugin operations`: listed, and the module fits when `--wasm` is given) |
| 1 | Any refusal or failure, including every usage error and `--wasm` that does not fit |
| 130 | Cancelled (Ctrl-C/Ctrl-Break) |

A failure prints `oncl: <code>; subcode=<id>; applied=<NotApplied|Applied|Unknown>` on stderr (`subcode=` only when the refusal has one) and nothing on stdout. A refused plugin command never prints a JSON report: the `subcode` JSON field belongs to the items of `batch run` and to the HTTP error of `oncl-server`; here the failure line is the contract, and the exit code and `applied` are those of every command. Stable subcodes of `plugin call`:

| Code | `subcode` | Cause |
|---|---|---|
| `PermissionDenied` | `not-declared` | The operation is not declared, not `server = true` or derived; an import beyond the declaration; typed parameters (or no `--args-file`) for a plugin without declarations; a name the plugin calls that is not declared |
| `PermissionDenied` | `no-key-use` | `--key` for an operation that declares no key use |
| `PermissionDenied` | `network-not-declared` | `--plugin-pki-endpoint` without `network = "pki"` |
| `PermissionDenied` | `not-granted` | A key use without `--plugin-bytes` (or not the granted plugin or operation) |
| `PermissionDenied` | `key-mismatch` | A key use of another key than the one the command opened (as on the server; the one use is not spent) |
| `PermissionDenied` | `content-mismatch`, `content-binding-unavailable` | Typed parameters: the plugin signs other bytes than the ones passed, or the bound use is digest-form |
| `PermissionDenied` | `options-mismatch`, `kind-mismatch`, `key-use-spent`, … | The key use differs from the declaration (see [the design](../design/manual-plugins.md) §4.8 for the whole list); the key was not applied except for `key-use-spent` (the first use stays `Applied`) |
| `InvalidInput` | `unknown-param`, `duplicate-param`, `missing-param`, `param-wrong-kind`, `param-invalid-value`, `invalid-template` | A typed parameter is wrong (above) |
| `InputLimit` | `param-too-large`, `request-too-large` | A parameter over its declared size, or a request over 256 KiB |

### Examples

A declared operation with a document parameter and a key (Git Bash; the manifest declares `sign` with `server = true`, `param file` a document, `keys_sign_raw` and `network = "pki"`):

```sh
oncl plugin operations --manifest plugin.toml                    # what may I grant?
oncl plugin call --manifest plugin.toml --module plugin.wasm \
  --operation sign --caller ops-laptop --output signature.b64 \
  --param-file file=statement.pdf \
  --key signer.p12 --secret-file secrets/signer.secret --authorize --plugin-bytes \
  --root nca-root.der --pki-endpoint https://pki.example.test \
  --plugin-pki-endpoint GET=https://pki.example.test/ocsp --plugin-pki-endpoint POST=https://pki.example.test/ocsp
```

A keyless declared operation with typed text, choice and flag parameters:

```sh
oncl plugin call --manifest plugin.toml --module plugin.wasm --operation note \
  --caller ops-laptop --output - \
  --param text='hello' --param pick=two --param lang=kk --param-flag on
```

A plugin without declarations (unchanged: the operator names the label and the imports, the request is free):

```sh
oncl plugin call --manifest plugin.toml --module plugin.wasm --operation hash \
  --caller ops-laptop --allow-import hash --args-file request.json --output -
```

`plugin call --json` prints `{operation_id, code: "Completed", applied, response_bytes}` after the response artifact is written (the response itself goes to `--output`).

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

## Known limits

* **Terminals:** no-echo, mode restoration and Ctrl-C are proven on a Windows ConPTY only; the Unix `termios` path and Linux/macOS signals have not been executed.
* **XAdES level claims.** An XAdES-LT/LTA claim (`ades_level`, and the `xades-lt`/`xades-lta` verify profiles) needs the signature timestamp, revocation values AND `CertificateValues` holding every certificate of the signer's path above the leaf, trust anchor included (ETSI EN 319 132-1 §5.4.2); `sign --profile xades-lt` emits them. A document without them is claimed `T` (`xades-lt` refuses it with `InvalidInput`). This is stricter than CAdES/PAdES, whose LT claim today needs only the timestamp plus revocation status: the asymmetry is deliberate for now. The check covers the signer's path only; the timestamp authority's path and its `TimeStampValidationData` completeness are not part of the claim. `sign --profile xml --add` over a signature whose reference covers the new signature's position (whole document, enclosing element or Manifest member, unless it drops signatures) is refused before the key is used (`InvalidInput; applied=NotApplied`).
* **XAdES with a complete CA CRL.** `verify --profile xades-b|t|lt|lta` admits an embedded CRL up to the CLI's 32 MiB per-CRL quota (48 MiB in total): an NCANode/Kalkan XAdES-LT of about 27 MB (the complete NCA CRL as base64) yields a report (signature `Passed`, chain/revocation graded by the host's `--root`/`--as-of` exactly as for XAdES-T) instead of `MetadataLimit`. A CRL not issued by the signer's issuer gives no revocation status; one listing the signer revokes it. Signing or extending a XAdES-LT/LTA with a CRL over 256 KiB is not supported (`MetadataLimit`); see `docs/dev/sdk.md`.
* **Long-term status (`lt`/`lta`).** Revocation status embedded in a signature is judged at the time the signature timestamp proves, not at your clock: with `--as-of` or the host clock moved later, a CAdES/PAdES/XAdES `lt`/`lta` document stays judged by what was fresh at that proven time, provided the signer's and the chain's certificates were valid then (this is not promised for the NCANode test fixtures, whose timestamps do not verify here). Status that carries a `nextUpdate` is fresh while the proven time precedes it; status without one (NCA OCSP) must be issued within 300 s before it. Status issued after your verification time (OCSP: more than 300 s after), already past its `nextUpdate` at the proven time, untrusted, revoked at or before the proven time, or about another certificate is refused. A signature without a verified timestamp (`b`) is judged at the current time, as is status the verifier fetches itself. Rule and standard references: `docs/dev/sdk.md`.
* **Evidence:** CAdES-LT/LTA and PAdES-LT/LTA signing and keyless `extend` through the CLI are proven (below). Operator material is supplied with `--evidence-certificate`, `--evidence-ocsp`, `--evidence-crl` (public DER files, at most 64 each, ≤256 KiB each, ≤8 MiB total, charged to the shared configuration reservation before any document or key I/O; only valid with CAdES/PAdES sign and `extend`). CAdES-LT/LTA sign and keyless `extend` B→T→LT→LTA plus LTA renewal are proven on the loopback PKI (an OCSP response without `nextUpdate` must have been produced at most 300 s before the timestamp, otherwise it must carry a `nextUpdate` beyond it, and no response may be produced after `--as-of`; `--tsa-url` + `--tsa-policy` required). LT/LTA sign without certificate+OCSP/CRL material is `EvidenceMaterialRequired` before any I/O; material the SDK finds insufficient is only detected after key use and is reported `applied=Applied`. PAdES-LT/LTA signing and keyless PDF `extend` (T→LT→LTA) are proven the same way and verified independently with pyHanko (signature intact/valid/trusted from DSS-only revocation material with revocation required and fetching disabled; DSS contents and DocTimeStamp; a tampered byte makes the CLI exit 2 and pyHanko reject).
* **JKS** signing works with the same strict validation as PKCS#12 (`--alias` selects an entry); GOST signing is checked by the SDK itself, not by an independent GOST oracle. The guarded legacy XML facade refuses a GOST-2015 signer (`InvalidInput`, before private use; baseline XML with GOST works).
* Publication needs a same-volume, hard-link-capable destination (FAT/exFAT/SMB fail after private use). Plugin WASM memory is hard-capped at 1 MiB. `--pki-pin` is a DNS *address* pin, not a PIN secret.
* `inspect --profile container` needs `--alias`. Encryption/decryption does not exist (G01/G02 are external); no command is provided.

## `--json` report fields

`--json` prints one JSON object. Common keys: `operation_id` (number), `code` (`Completed` on success), `applied` (`NotApplied`, `Applied` or `Unknown`: whether a private key was used). Values marked *text* are the Rust `Debug` rendering of an SDK enum or struct: they are stable enough to read but change with the SDK enum (see the SDK guide); script on `code`, `applied`, `verdict` and the exit code, not on those texts.

| Command | Fields |
|---|---|
| `hash` | `operation_id`, `code`, `applied`, `digest` (lowercase hex), `bytes_in` |
| `sign`, `extend` (written output) | `operation_id`, `code`, `applied` (*text*), `profile` (*text*), `provenance` (*text*), `bytes_in`, `bytes_out`, `signer_count`; `xml` (*text*) only when the operation produced an XML report |
| `extract` | `operation_id`, `code`, `applied` (`NotApplied`), `bytes_out`, `verified` (always `false`) |
| `verify` | `operation_id`, `code`, `applied` (always `NotApplied`), `verdict` (`Valid`/`Invalid`/`Indeterminate`), `policy` (*text*), `checked_at` (Unix seconds), `ades_level` (*text* or `null`), `signers`; `xml` / `pdf` (*text*) when the document is XML / PDF |
| `signers[]` | `signature`, `chain`, `validity`, `revocation`, `timestamp`, `key_usage`, `time_basis` (all *text*), `claimed_signing_time` (Unix seconds or `null`), `ades_level` (*text* or `null`), `reasons` (*text*) |
| `inspect` | `operation_id`, `code`, `applied` (`NotApplied`), `kind` (*text*), `container_integrity` (*text* or `null`), `entries`; `cms` (*text*) for a CMS |
| `entries[]` | `alias`, `certificate_sha256`, `subject_cn`, `serial_hex`, `signature_algorithm_oid`, `public_key_algorithm_oid`, `not_before`, `not_after` (Unix seconds); each may be `null` |
| `batch run` | `operation_id`, `code` (`Completed`/`Partial`/`Cancelled`/`DeadlineExceeded`), `attempted`, `completed`, `total`, `stop` (text or `null`), `items[]` |
| `items[]` | `id`, `status` (`Completed`/`Failed`/`NotRun`), `code`, `subcode` (remote failed items with a precise reason), `applied`, `verdict` (verify items), `published` (items with an output), `digest` `{algorithm, hex}` (hash items) |

Optional fields are omitted, not `null`, when absent. `timestamp`, `jws`, `jwt` and `plugin call` print their own smaller reports (`operation_id`, `code`, `applied` plus byte counters, `profile`, `verdict`, `policy` or `facts` as relevant); `plugin operations` prints the report described under [Plugins](#plugins-oncl-plugin). The table is derived from the report structures in `crates/oncl-cli/src/reports.rs`, `local.rs`, `public.rs` and `batch.rs`.

## Remote mode (`--endpoint`)

`oncl --endpoint https://signing.internal:13579 --token-file client.token --ca-file ca.pem sign --profile cms --key-name corporate-signing --authorize --input doc.bin --output doc.p7s` runs the operation on the server described in [server.md](server.md) / [http-api.md](http-api.md). The client is `oncl_api::client::ApiClient` (feature `client` of `oncl-api`; `ureq` + `rustls` only, no Tokio/axum/hyper).

* **Paths.** Every local path is read and written by the client. Documents are streamed from files/stdin as request parts (known `Content-Length` when available, chunked for stdin); results are staged in the destination's private directory and published no-clobber exactly like local runs. The server never opens a client path: the request has no path field, and a path in any string field is refused (`remote::server_cannot_open_client_path`).
* **Commits.** A result is published only after the **terminal `final` record, the closing multipart delimiter and the end of the HTTP entity** were all received. A response cut anywhere before that (before/inside an artifact, before/inside the final record, a polite end without final, a missing closing delimiter, a missing terminal chunk) publishes nothing, leaves no temporary file, prints `oncl: ResponseLost; applied=Unknown` (`NotApplied` for keyless operations) and exits 1. **There is no automatic retry, idempotency key, rollback or exactly-once promise**: the server may well have applied the key (its audit journal says so). Earlier files at other paths (earlier batch outputs included) are never touched.
* **`applied`.** The server starts a private operation only after it took the whole request body. A failure while the body was still being sent is `NotApplied`; a lost response after the last body byte is `Unknown` when the request could use a private key; a typed refusal or terminal record reports the server's own value.
* **Token.** `--token-file PATH` (an owner-only directory, same rules and 4096-byte limit as `--secret-file`) or `--token-stdin` (stdin is then not a document). Never argv, never an environment variable; it is not part of any diagnostic, report or error (tests grep stdout, stderr and every client file for it), and error messages never contain a response body, only a stable code, the HTTP status and the server's typed code.
* **Transport.** `https://` uses the built-in webpki roots; `--ca-file` (PEM bundle or DER, repeatable) *replaces* them for a private server (trust exactly that CA or the server's own certificate). There is no flag to skip verification. `http://` is accepted for `localhost`/`127.0.0.0/8`/`::1` only; any other plain-http host needs `--allow-plain-http` (token and documents travel unencrypted: a protected backend network behind a trusted proxy). Redirects are never followed and ambient proxy variables are ignored.
* **Keys.** `--key-name NAME` references an operator key on the server (no secret from the client). Key material leaves the process only with `--key PATH --secret-file … --inline-key` (and `inspect --profile container … --inline-key`): the container and password travel as `secret` parts, memory only on the client side too, and the server needs `inline_pkcs12` globally and per token. Token readers (`--token-reader`) and `--key-config` are local devices/files and are refused.
* **Authority stays with the operator.** Trust roots, validation policy, PKI network, clock, TSA, JWT issuer/audience and plugin installation are server configuration. `--root`, `--intermediate`, `--pki-endpoint`, `--pki-pin`, `--tsa-url`, `--tsa-policy`, `--offline`, `--as-of`, `--configuration-bytes`, `timestamp acquire --tsa/--algorithm`, `timestamp verify --policy-oid`, `jwt verify --issuer/--audience/--leeway-seconds`, `inspect --alias` and every `plugin` command are refused with `RemoteUnsupported` before any I/O instead of being ignored. `sign` still requires `--authorize`. Any option the wire does not carry is refused before any I/O with `RemoteUnsupported`: the WS-Security options beyond `--soap-version`/`--wsse-body-id` (`--wsse-role`, `--wsse-required-header`, `--wsse-timestamp-*`, `--wsse-token-reference`, `--wsse-token-id`) and the legacy-XML options beyond element, parent, signature and digest method (namespaces, placement, c14n, transforms, signing-time, line-break, declaration, output and chain options); so are `--token-reader` and `--key-config`.
* **Families.** `hash`, `verify`, `extract`, `sign` (cms, cades-*, xml, wsse with `--soap-version`/`--wsse-body-id`, xades-b/t, pdf, pades-*, and `--legacy` xml/xades-b/xades-t with element/parent/signature/digest method), `extend` (cms/pdf t|lt|lta, xml lt|lta), `inspect`, `timestamp`, `jws`, `jwt` and `batch run`. `raw`/`digest-*` signing and XAdES LT/LTA signing are not profiles of the contract (use `xades-t` then keyless `extend`). Evidence is sent from `--evidence-certificate/-ocsp/-crl` as public document parts.
* **Refusal reasons.** A typed refusal of the service that carries a `subcode` is printed as `oncl: <code>; subcode=<id>; applied=<state>` (the client validates the id against its published pattern; a malformed one is dropped, never printed). Plugin commands are not available remotely.
* **Reports and exits** are the local ones (0 completed/`Valid`, 2 `Invalid`, 3 `Indeterminate`, 4 incomplete batch, 1 failure, 130 cancellation). Verdict, policy and every per-signer check of a signature verified remotely match the local run. Differences: the wire carries no PDF/XML structure details and no top-level AdES level (omitted, not invented); `time_basis` is the variant (`time_basis_unix` has the instant); `bytes_in` is the document bytes this client sent and `bytes_out` the artifact it received; `timestamp` facts are an object. `jwt decode` writes the payload text the server decoded (the server replaces invalid UTF-8).
* **Batch.** The manifest is read here; a source that cannot be opened fails only its own item. Outputs are staged in one store (the shared destination directory, otherwise `--temporary-directory`/`.`, which must be on the destinations' volume) and linked into place after the final record, one row per item (`published` per output). The server runs the closed `/v1/batch` (needs the token's `batch` right).
* **Limits of this client.** A server that answers while the client is still uploading (for example a refusal after metadata on a large body) keeps the connection open and reads and discards what the client still sends, for at most one second and about 8 MiB, so a client that finishes within that bound reads the typed answer. A client that sends on past it is reset, and the typed answer may be lost to the reset: the outcome is then a transport failure with `applied=NotApplied` (the body was incomplete). Cancellation and the deadline (`--timeout-seconds`) are polled every 50 ms while waiting, so Ctrl-C ends a call to a server that never answers with exit 130 within seconds (`applied=Unknown` when a key could have been used and the body was fully sent, `NotApplied` otherwise); the abandoned exchange ends with the process and nothing is retried. Not exercised: Linux/macOS, Win7, 1 GiB documents or RSS, pinned-key TLS (only a CA/leaf file), `jws add`/`cms add`/`wsse` over the remote path (the wire fields are mapped but have no remote CLI test), PAdES LT/LTA and PDF/XML remote signing through the CLI (covered at the HTTP level by `oncl-api` tests).
* Encryption/decryption: no command and no wire route exists (G01/G02 are external); this client adds none.
* **Integrity of the answer.** Every artifact named by the final record must be received, once, with the exact length the record states: extraction (`bytes_written`) and timestamp tokens (`bytes_out` is the token length). A well-framed part of the wrong size publishes nothing (`ProtocolViolation: artifact length differs from the final record`, exit 1, `NotApplied` for keyless operations, `Unknown` when a key could have been applied). The same holds for JWS/JWT creation (`bytes_out`, enforced by the server when it finishes the artifact writer with the report's `bytes_out`). CMS/CAdES/XML/PDF signing and extension are not compared: the server takes the artifact length from the staged output and does not enforce the record's `bytes_out`, an SDK counter (measured: 8250 for a 1561-byte CMS), so only identity and count are checked there and reports use the exact received length.
* **`--allow-plain-http` warning.** Every run that uses it against a non-loopback `http://` host prints `oncl: warning: --allow-plain-http sends the API token and every document over an unencrypted, unauthenticated connection …` on stderr (never the token). Without the flag such an endpoint is refused before any connection (`PlainHttpRefused`).
* **Batch destinations.** When outputs are not all in one directory, a real hard link is created and removed in every destination directory *before any request* (`DestinationNotLinkable`, `NotApplied`), so a key is never used for a result that cannot be linked into place. Verified with an unusable directory and with two real directories; the probe tests the capability itself, so a destination on another volume that cannot take hard links is refused the same way.
* **Redirects and proxies.** A 3xx answer is never followed (the bearer token is never forwarded: `UnexpectedStatus (HTTP 307)`), and `HTTP_PROXY`/`ALL_PROXY` are ignored (tests record that neither the redirect target nor the ambient proxy is ever contacted). A connection reset while the body is still being sent (for example for a client that sends on past the one second and about 8 MiB the server keeps reading after an early answer) is `NotApplied`: the service takes the whole multipart body (and re-checks authority) before a worker may use a key (`crates/oncl-server/src/service/operations.rs` and `operations/intake.rs`).
