# oncl-server {{VERSION}} ({{FLAVOR}})

`oncl-server` is the standalone OpenNCALayer HTTP service. It is **independent of the
desktop application** and ships as its own package; this archive holds the program, an
example configuration and the operations files. **Nothing here opens a socket by
itself:** the HTTP API is disabled until the operator writes a private configuration and
enables it explicitly (`enabled = true` or `serve --enable-api`), and the service never
installs trust, autostart or an updater.

## Quickstart (first run, nothing is listening)

```sh
oncl-server --version
oncl-server serve --config /etc/oncl-server/server.toml
# disabled: no listener      <- with the example configuration (`enabled = false`)
```

`server.example.toml` is the starting point: copy it into the owner-only operator
directory, then follow `docs/server.md`: create a token

```sh
oncl-server token-create --directory /etc/oncl-server --name client.token
# prints verifier=<64 hex characters>; put it under [[tokens]] in server.toml
```

and enable the API on loopback (`oncl-server serve --config ... --enable-api`). A client
is `oncl --endpoint http://127.0.0.1:13579 --token-file client.token ...` from the `oncl`
package. LAN exposure needs TLS or a trusted reverse proxy, configured explicitly.

{{WINDOWS_PROVISIONING}}## Contents

| File | What it is |
|---|---|
| `{{EXE}}` | the program |
| `server.example.toml` | example configuration, API disabled, no secret in it |
{{DEPLOY_ROWS}}| `docs/server.md`, `docs/http-api.md` | operation, TLS, tokens, the HTTP contract |
| `THIRD-PARTY.txt` | licences of the third-party code in this build |
| `LICENSE`, `NOTICE` | Apache-2.0 and notices |

Not included, by design: no certificate, key, password, token or test file.
Encryption / decryption routes do not exist (they need the Kazakhstani GOST backend).
Updating is replacing the program and restarting the service; it never updates itself.
