# OpenNCALayer

[Русский](README.md)

OpenNCALayer is an open-source Rust replacement for NCALayer, the signing daemon used by Kazakhstan's e-government services. Sites (egov.kz, public procurement, banks, e-document systems) that talk to the original over `wss://127.0.0.1:13579` are meant to work with OpenNCALayer unchanged: same protocol, same modules.

OpenNCALayer is an independent project and is not affiliated with the National Certification Authority of the Republic of Kazakhstan (NCA RK).

## Status

Early development; there are no release builds yet. The first end-to-end slice (P1) is in place: a site using [ncalayer-js-client](https://github.com/sigex-kz/ncalayer-js-client) gets a CMS signature over `wss://127.0.0.1:13579`.

P1 provides:
- the `kz.gov.pki.knca.basics` module, method `sign`, formats `cms` and `raw`;
- PKCS#12 keys (`.p12`, `.pfx`): GOST 2004, GOST 2015-512, RSA;
- attached and detached signatures, co-signing, NCA timestamps (TSP);
- storage and key selection dialogs (Russian, Kazakh, English);
- a command-line TLS wizard: `openncalayer tls init|import|status` ([guide, in Russian](docs/user/tls.md));
- signature checking: `openncalayer cms-verify`;
- a self-test page at `https://127.0.0.1:13579/` and a demo page at `https://127.0.0.1:13579/demo/`.

Manual browser test results: [`docs/dev/smoke-p1.md`](docs/dev/smoke-p1.md) (in Russian).

### Deviations of P1 from the original

The first three are closed in P3/P4.
- `signerParams.chain` is ignored: there is no PKIX or OCSP, so revoked keys are not rejected.
- Only the `PKCS12` storage works. The other storages are listed in the dialog but unavailable.
- basics formats are `cms` and `raw` only; `xml` answers `INVALID_SIGNING_PARAMS`.
- The original's password strength check for keys with EKU `1.2.398.3.3.4.2*` is not implemented in P1.
- `NCALAYERPORT` is honoured in any session; the original honours it only in RDP/Citrix/xrdp sessions. The value must be within `13579..=13679`.
- TLS 1.2 and 1.3; the original speaks only TLS 1.2.
- With `decode`, base64 in `data` is checked before the dialog is shown; the original checks it afterwards. The error code is the same.
- Key validity dates in the key dialog are shown in UTC, not local time.

Documentation is written in Russian:
- [`docs/user/tls.md`](docs/user/tls.md) — the OpenNCALayer certificate: issuing, trusting, removing, re-issuing;
- [`docs/design/roadmap.md`](docs/design/roadmap.md) — decisions and roadmap;
- [`docs/original/architecture.md`](docs/original/architecture.md) — architecture of the original NCALayer.

## Build and run

You need `rustup`: the Rust version is pinned in `rust-toolchain.toml` and installed automatically. On Linux the dialogs need the fontconfig, xkbcommon, Wayland and GTK 3 development packages (Debian and Ubuntu: `libfontconfig1-dev libxkbcommon-dev libwayland-dev libgtk-3-dev`).

```sh
cargo build --release -p openncalayer
```

The binary is `target/release/openncalayer` (`openncalayer.exe` on Windows).

```sh
openncalayer tls init   # issue the certificate and print how to trust the CA
openncalayer run        # start the server; plain `openncalayer` does the same
```

1. After `tls init`, trust the CA as the printed instructions say. Per-OS details are in [`docs/user/tls.md`](docs/user/tls.md).
2. Start `openncalayer run` and open `https://127.0.0.1:13579/`: the page must load without a certificate warning.
3. At `https://127.0.0.1:13579/demo/` you can sign a text or a file and download the `.p7s`.
4. To check a signature: `openncalayer cms-verify signature.p7s`; for a detached signature, `openncalayer cms-verify signature.p7s --content <data file>`.

Exit codes of `run`:
- 2 — TLS is not set up;
- 3 — the port is taken, for example by the original NCALayer.

The original and OpenNCALayer cannot run at the same time: both need port 13579.

Data lives in `%APPDATA%\OpenNCALayer` (Windows), `~/Library/Application Support/OpenNCALayer` (macOS) or `${XDG_DATA_HOME:-~/.local/share}/openncalayer` (Linux). Inside:
- `tls/` — certificates;
- `logs/openncalayer.YYYY-MM-DD.log` — logs, a new file every day;
- `settings.json` — the path of the last chosen key file.

The `ONCL_DATA_DIR` variable overrides the data directory. Set it during development (for example `ONCL_DATA_DIR=target/oncl-data`) so your real profile stays untouched.

## Development

```sh
cargo build --workspace
cargo xtask fetch-fixtures   # NCANode test data → target/fixtures/ncanode/
cargo test --workspace --all-features
```

`cargo xtask fetch-fixtures` downloads [NCANode](https://github.com/ncanode-kz/NCANode) test files from a pinned commit and verifies their sha256. These files are never committed. A repeated run downloads nothing when the files are already in place.

The test keys in `fixtures/synthetic/` are synthetic, password `Qwerty12`. They work on the demo page.

Tests prefixed with `live_` call real NCA services and are skipped by default:

```sh
cargo test --workspace --all-features -- --ignored live_
```

Before submitting changes:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

`web/demo/vendor/ncalayer-client.js` is `package/ncalayer-client.js` from the npm package `ncalayer-js-client@1.6.1`, unmodified (MIT, sha256 `bdf2015c3e422eed70ccf38eef3246af67a0d38639e6b70fe6b8655a2fa03489`). The `demo_assets_served` test checks the sha256 of the file the server sends.

## License

[Apache-2.0](LICENSE); see also [NOTICE](NOTICE). `web/demo/vendor/ncalayer-client.js` is MIT, see [`web/demo/vendor/LICENSE`](web/demo/vendor/LICENSE).
