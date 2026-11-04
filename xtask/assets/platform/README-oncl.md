# oncl {{VERSION}} ({{FLAVOR}})

`oncl` is the standalone OpenNCALayer command line: hash, sign, verify, extract, inspect,
extend, timestamp, JWS/JWT, plugin calls and batches. It is **independent of the desktop
application**: it starts no daemon, no HTTP server and no browser session, installs
nothing and writes nothing outside the paths you name. This archive is a plain program, not
an installer; it is separate from the OpenNCALayer desktop package and from `oncl-server`.

## Quickstart

Unpack the archive anywhere and run the program from that folder:

```sh
oncl --version
printf abc | oncl hash --algorithm sha256 --input -
# ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
oncl verify --profile cms --input signature.p7s --root nca-root.der
```

There is no implicit trust store: pass the roots you trust with `--root`. Private keys
come from PKCS#12/JKS files or a smart-card reader you name, passwords only from an
owner-only secret file or the terminal, never from arguments. Signing needs
`--authorize`, the explicit confirmation of the exact operation.

With `--endpoint https://host:13579 --token-file client.token --ca-file ca.pem` the same
commands are a client of an `oncl-server` (a separate package).

Full reference: `docs/cli.md` in this archive.

## Contents

| File | What it is |
|---|---|
| `{{EXE}}` | the program |
| `docs/cli.md` | commands, exit codes, remote mode |
| `THIRD-PARTY.txt` | licences of the third-party code in this build |
| `LICENSE`, `NOTICE` | Apache-2.0 and notices |

Not included, by design: no certificate, key, token or test file, and no encryption /
decryption command (it needs the Kazakhstani GOST backend, which does not exist yet).
