# Standalone HTTP service

`oncl-server` is independent of desktop settings, dialogs, OS vaults, trust-store
installation and autostart. Starting it without a subcommand does not open a
socket. `serve` requires an explicit private configuration file; HTTP is disabled
unless `enabled = true` or the operator supplies `--enable-api`.

## Private operator namespace and tokens

Create a dedicated directory owned only by the service account. The existing
private-filesystem policy verifies owner-only permissions/ACLs, refuses links and
foreign files, and never repairs permissions of existing objects. The config,
API-token file and key/PIN mount files must be private regular single-link files
in such a directory. Do not use a desktop data directory.

```text
oncl-server token-create --directory /private/oncl-operator --name client.token
```

The command creates the private directory if absent, writes a new OS-CSPRNG
256-bit token exclusively to `client.token`, synchronizes it, and prints **only**
its verifier. It refuses to overwrite an existing token file. Treat the token
file as a password; supply its content to the client's secret-input facility,
not command-line arguments or logs. The verifier is HMAC-SHA-256 with a fixed
versioned domain key; verification uses ring's constant-time fixed-size MAC
verification. Config persists only token ID, verifier and ACL, never plaintext
tokens. Neither tokens nor key/PIN/password-bearing types implement open Debug.

Write `server.toml` in the private operator directory (replace the verifier and
absolute journal directory):

```toml
enabled = false
bind = "127.0.0.1:13579"
audit_directory = "/private/oncl-audit"
recover_audit = false
max_in_flight = 2
blocking_workers = 2
queue_capacity = 2
admission_wait_ms = 1000
operation_timeout_ms = 300000
max_connections = 32
header_timeout_ms = 5000
input_bytes = 10737418240
memory_per_operation = 268435456
total_memory = 536870912
temp_per_operation = 34359738368
total_temp = 68719476736
metadata_bytes = 1048576
framing_bytes = 67108864
# Optional, required for multipart public-document snapshots:
# scratch_directory = "/private/oncl-scratch"
inline_pkcs12 = false

[[tokens]]
id = "accounting-service"
verifier = "<64 lowercase hexadecimal verifier characters>"
actions = ["hash"]
keys = []
```

```text
oncl-server serve --config /private/oncl-operator/server.toml --enable-api
```

Without explicit hosts, a loopback listener accepts exactly its bound socket
address as the HTTP `Host` authority, including the actual port. Configure
`hosts = ["localhost:13579"]` if clients use that name. There are no implicit
wildcards or `Origin`-based privileges. IPv6 loopback requires an explicit IPv6
bind. Configuration is strict: unknown fields and unsafe limits are rejected.
`enabled = false` exits without opening the journal, TLS keys, or a listener.

Ctrl-C requests graceful shutdown. For a supervisor-owned pipe,
`--shutdown-stdin` explicitly enables one operator-control reader: newline or EOF
stops the listener, cancels connections and waits for actual admitted workers to
return. This pipe is not a network admin API. No unrelated listener/service is
stopped; persistent audit files are retained, not deleted at shutdown.

## Actual API

Only these routes exist:

* `POST /v1/hash`: raw binary request body, SHA-256, authenticated hash ACL.
* `POST /v1/operations`: typed JSON-small or metadata-first multipart hashing and
  verification; see [the HTTP request contract](http-api.md).
* `GET /health`: authenticated hash ACL; reports the actual local audit health.

Send `Authorization: Bearer <token-file-content>`, the configured `Host`, and the
document as a streaming body. A successful hash of the three bytes `abc` is:

```json
{"operation_id":1,"algorithm":"sha256","digest":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","bytes_in":3}
```

The operation ID varies. Content-Length is optional; unknown-length chunked input
is counted by the original Core resource scope, including the N+1 oversize probe.
No document-sized body collection or spool is used for hashing. Malformed or
truncated framing never yields a successful hash. Query parameters, key selectors,
method-override headers, mismatched `X-Oncl-Operation` and request trailers are
rejected; the route never dispatches another operation named by a payload.
Request targets must be exact origin-form paths, without a URI scheme or
authority. Absolute-form URLs are rejected even when their authority matches the
Host header. Methods are exact: POST for hash and GET for health; HEAD is not a
GET alias. Application path/method rejections retain HTTP 404/405 and use the
`InvalidRequest`/`NotApplied` envelope. HTTP syntax that Hyper cannot parse may
be rejected at the transport layer without an application JSON envelope.


Errors contain a stable `code` and `applied`. This hash endpoint always reports
`NotApplied` (no private key is used): bad authorization is HTTP 403, malformed
requests HTTP 400, resource byte limits HTTP 413, exhausted admission/queue
`CapacityExceeded` HTTP 503, and `DeadlineExceeded` HTTP 504. There is no hidden
retry or durable document queue. No signing/encryption/admin endpoints are
advertised by this service version.

## Explicit LAN exposure

Non-loopback binds require an explicit exposure mode and exact allowed hosts.
There are two distinct choices:

```toml
bind = "0.0.0.0:13579"
hosts = ["signing.internal:13579"]
exposure = { mode = "tls", certificate = "/operator/server.crt", private_key = { directory = "/private/oncl-operator", name = "server.key" } }
```

This is real rustls TLS using an operator-supplied PEM certificate chain and
owner-only PEM private-key mount. It neither creates nor installs a CA. Configure
client trust explicitly; do not disable certificate verification.

Alternatively, use a TLS-terminating reverse proxy on a protected backend network:

```toml
bind = "0.0.0.0:13579"
hosts = ["signing.internal"]
exposure = { mode = "trusted_proxy", peers = ["192.0.2.10"] }
```

Only an allowlisted **actual socket peer IP** can use that backend listener.
`Forwarded`, `X-Forwarded-For`, `Origin`, URL fields and roles never establish
proxy trust or replace the individual API token. Protect the proxy-to-service
network with host/network policy; trusted-proxy mode is not TLS on that hop. A
nonallowlisted peer is refused even if it supplies a forged forwarding chain.
Configured and actual IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) normalize to
the same IPv4 peer. Native and IPv4-compatible IPv6 remain distinct; normalization
does not widen a loopback bind or trust a nearby address. Unspecified peers,
including mapped unspecified IPv4, cannot be allowlist entries.


## Named operator keys and audit

The service composes one Engine, one aggregate SharedBudget, one bounded executor,
real `KeySources`, a physical-reader TokenGateRegistry and the accepted durable
ONCLAU02 audit guard. Operator configuration can bind file-backed PKCS#12/JKS or
supported tokens to opaque names; client DTOs cannot contain server paths.

```toml
[[keys]]
source = "file"
name = "corporate-signing"
path = "/operator/corporate.p12"
# alias = "signing" # omit only for a single-entry container
secret = { directory = "/private/oncl-operator", name = "container.password" }

# Token alternative (exact existing storage kind and actual PC/SC reader):
# [[keys]]
# source = "token"
# name = "card-signing"
# reader = "Operator PCSC Reader"
# kind = "AKKaztokenStore"
# alias = "signing"
# secret = { directory = "/private/oncl-operator", name = "card.pin" }
```

These are actual SDK/provider bindings, not future HTTP signing routes. A host
private-operation caller must hold the action and exact named-key ACL and bind
its authenticated principal to the original operation before private use. The
durable guard synchronizes BEGIN before the actual key call. A FINAL failure after
private use remains Applied/Unknown and blocks further private work; output is not
published as success. No allow-all guard or second audit journal is installed.
Strict server policy remains strict. Public verification defaults to an empty
trust set and denied PKI network, not a fabricated trusted verdict. Private HTTP
routes are not advertised by these public operations.

A newly created journal starts healthy. An existing journal requires an explicit
operator `recover_audit = true` restart; recovery rejects complete corruption,
foreign/old journal formats and live ownership. It does not silently migrate or
repair another journal. Audit identity/lock/rotation/quota and opaque actor/key
labels retain the audit library's existing semantics.

Inline PKCS#12 transport is not exposed by S02. The provider is off by default;
SDK hosts can enable it only with both operator configuration and a per-token
`inline_pkcs12 = true` right, using `AccessPolicy::authorize_inline` for the actual
immutable inline selector identity. That method cannot authorize a File/Token
selector, and no wildcard/source identity from a client becomes a grant. The Core
provider accounts secret containers in bounded memory, never document scratch.
`KeySelector::is_inline` exposes classification only, not secret bytes or paths.

## Revocation and bounds

A standalone config/ACL change takes effect by graceful restart. Embedding trusted
hosts can revoke identities through `AccessPolicy::revoke` or atomically replace
the checked ACL through `AccessPolicy::replace`; no network request can invoke
either method. A generation change invalidates all previously authenticated Principal
objects for minting *new* grants. Already admitted work retains its original
immutable grant and truthful outcome; revocation does not claim rollback.

Document admission precedes body reading. Worker/queue slots are acquired before
`spawn_blocking`, and no more than `blocking_workers` native closures run. Queued
owned contexts retain the initial scope/deadline; queue expiry is explicit.
Disconnect/cancel stops waiting and cooperative intake, but a native call's slot
and resources remain owned until that actual call returns. Response bytes retain
the original context/reservation until their network ownership ends. The whole
operation has one finite deadline, not a new timeout at each stage.
The same original early deadline/control and disconnect owner continue through
the real response body and transport. Deferred first polling refuses expired
success bytes; an original-deadline timer aborts pending transport output, and
actual write/flush checkpoints also refuse expired bytes already buffered by
Hyper. Accept/header bounds may shorten, never extend, the operation deadline.
After headers have been sent, expiry is a transport abort, not a promised new
JSON error/status. Timers do not make retained Bytes clones/slices or a running
native operation free: their actual final owners must still release them.


There are also finite pre-auth connection/header/TLS-handshake limits. HTTP/1
header count is capped at 64 and a connection's parser buffer at 32 KiB. These
network buffers/runtime overhead are separate from Core's aggregate document
working-memory accounting; resource counters are not a claim about total RSS.
The server stack is optional/server-only: minimal SDK crates and desktop/Win7
build closures do not depend on Axum/Hyper, and static CRT/toolchain policy is
unchanged. This Windows-host acceptance is not a Linux/macOS/Win7 runtime result
or the later 10-GiB XML/PDF resource-harness gate.
