# oncl-core

The embeddable Rust SDK of [OpenNCALayer](https://github.com/arynyklas/open-ncalayer): typed,
streaming signing, verification, validation, inspection and time-stamping operations over files
and byte streams, with explicit host-owned trust, keys, clock, network, audit and resource
limits. It has no UI, daemon, listener, installer or self-update, and needs no display session.

Status: **pre-1.0 (`0.1.0-alpha.*`)**. Breaking changes are allowed between alphas and are listed
in the migration notes of [`docs/dev/sdk.md`](../../docs/dev/sdk.md). The crates are **not
published to crates.io**: depend on them by git or path (below), never by `cargo add` of a
registry version. Whether the `oncl-*` names are available or owned on crates.io has not been
verified.

## Using it before a registry release

By path, from a checkout of the repository at a tag or commit you have reviewed:

```toml
[dependencies]
oncl-core = { path = "open-ncalayer/crates/oncl-core", features = ["full"] }
oncl-pki = { path = "open-ncalayer/crates/oncl-pki" }

# The SDK is built against locally modified `streebog` and `hmac` (additive secret-input
# variants): a consumer outside the workspace must carry the same patch.
[patch.crates-io]
streebog = { path = "open-ncalayer/vendor/streebog" }
hmac = { path = "open-ncalayer/vendor/hmac" }
```

or by git, pinned to a commit (the patch section then points at the same repository):

```toml
[dependencies]
oncl-core = { git = "https://github.com/arynyklas/open-ncalayer", rev = "<commit>", features = ["full"] }

[patch.crates-io]
streebog = { git = "https://github.com/arynyklas/open-ncalayer", rev = "<commit>" }
hmac = { git = "https://github.com/arynyklas/open-ncalayer", rev = "<commit>" }
```

The minimal SDK is `default-features = false` (the same as the default): CMS/CAdES, hashing,
PKI validation, file/inline PKCS#12 and JKS key sources, host-named keys, batches and
inspection. Optional features:

| feature   | adds                                                                    |
|-----------|-------------------------------------------------------------------------|
| `tokens`  | hardware tokens and ID cards as key sources (`oncl-token`)              |
| `xml`     | XMLDSig / XAdES / WS-Security sign, add, verify (`oncl-xml`)            |
| `pdf`     | PAdES sign and verify (`oncl-pdf`)                                      |
| `jose`    | JWS / JWT create, add, verify                                           |
| `plugins` | headless WebAssembly plugin host (implies `xml`)                        |
| `full`    | all of the above; still no UI, desktop, updater, server or async runtime |

## Examples

Each example really runs (`cargo run -p oncl-core --example <name>`); they issue a throwaway RSA
PKI at run time and need no network:

- `sign_file [WORKDIR [FILE]]` — detached CMS signature of a file with a PKCS#12 key under strict
  validation; the key use is audited by a host `KeyUseGuard`.
- `verify_file WORKDIR FILE` — verifies it; exits non-zero unless the verdict is `Valid`.
- `custom_transport` — a host-written `HttpTransport` plugged into validation; with the "network"
  down, strict signing fails closed before the private key is applied.

The older `sdk_probe` example is an acceptance probe with oracle comparisons, not an embedding
guide.

## Contract in one page

- `Engine` is built from `EngineServices` (host services) and admits operations with
  `Engine::begin(ExecutionGrant, OperationPolicy, control)`. Grants come from trusted host code,
  never from a request on the wire.
- Private-key use goes through `KeyUseGuard`: `before_use` must durably record the use before the
  key is applied, and a failure refuses it. Errors carry `AppliedState` (`NotApplied`, `Applied`,
  `Unknown`); the SDK never promises rollback or exactly-once.
- Reports separate signature integrity, anchored chain, validity, revocation, timestamp proof and
  claimed time (`Verdict`); missing evidence is never reported as valid.
- Limits: 1 GiB of document bytes and 1 GiB of accounted live buffers per operation by
  default; a document above 1 GiB is refused (accounting limits, not RSS measurements); see `docs/dev/sdk.md` for the full list,
  the semver and error-stability stance, and the publication-readiness status.

Apache-2.0; see `LICENSE` and `NOTICE`.
