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
- signature checking: `openncalayer cms-verify` — signatures and timestamps; certificate chains, validity periods and revocation are not checked;
- a self-test page at `https://127.0.0.1:13579/` and a demo page at `https://127.0.0.1:13579/demo/`.

The second phase (P2) adds a browser extension: with it, sites work with OpenNCALayer without a trusted CA (see [Browser extension](#browser-extension)).

Manual browser test results: [`docs/dev/smoke-p1.md`](docs/dev/smoke-p1.md) and [`docs/dev/smoke-p2.md`](docs/dev/smoke-p2.md) (in Russian).

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

To run on Linux you also need:
- `libxkbcommon-x11-0`: without it the signing dialogs cannot open and `openncalayer run` exits with an error (`libxkbcommon-dev` does not install it);
- `xdg-desktop-portal` with a backend (for example `xdg-desktop-portal-gtk`) or `zenity` for the «Обзор…» (Browse) button; without them the system file dialog does not open (the log has the rfd error), and the key file path can still be typed in.

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
4. To check a signature: `openncalayer cms-verify signature.p7s`; for a detached signature, `openncalayer cms-verify signature.p7s --content <data file>`. `OK` means the signatures and timestamps are mathematically valid; certificate chains, validity periods and revocation are not checked (the `not checked: …` line before `OK`).

Exit codes of `run`:
- 2 — TLS is not set up;
- 3 — the port is taken, for example by the original NCALayer;
- 4 — OpenNCALayer with the same data directory is already running in this session.

With `--allow-no-wss` (how the extension's relay starts the daemon) codes 2 and 3 do not occur: the daemon logs a warning and serves only the extension.

The original and OpenNCALayer cannot both serve `wss` at the same time: both need port 13579. The extension does not need the port.

Data lives in `%APPDATA%\OpenNCALayer` (Windows), `~/Library/Application Support/OpenNCALayer` (macOS) or `${XDG_DATA_HOME:-~/.local/share}/openncalayer` (Linux). Inside:
- `tls/` — certificates;
- `logs/openncalayer.YYYY-MM-DD.log` — logs, a new file every day;
- `settings.json` — the path of the last chosen key file.

The `ONCL_DATA_DIR` variable overrides the data directory. Set it during development (for example `ONCL_DATA_DIR=target/oncl-data`) so your real profile stays untouched.

## Browser extension

The extension replaces a page's `WebSocket` to `127.0.0.1`, `localhost` and `[::1]` on ports 13579–13679 and passes the messages to OpenNCALayer over native messaging. The browser starts a small relay, `nmhost`, and the relay starts the daemon (`openncalayer run --allow-no-wss`) unless it is already running. This path needs neither the certificate nor port 13579: `wss` and a trusted CA are now needed only for sites in browsers without the extension.

There are no packages yet; build the extension from source:

```sh
cargo build --release -p openncalayer -p oncl-nmhost
cargo xtask ext build   # → target/extension/
```

`ext build` writes the unpacked extensions `chromium/` and `firefox/` to `target/extension/`, next to `openncalayer-chromium-<version>.zip` and the unsigned `openncalayer-firefox-<version>.xpi`.

Installation:
1. `openncalayer nm install` registers the native messaging host `io.github.arynyklas.openncalayer`:
   - copies the `nmhost` relay (by default the one next to `openncalayer`; another file with `--relay <file>`) to `%LOCALAPPDATA%\OpenNCALayer\nmhost.exe` (Windows) or into the data directory (macOS, Linux);
   - writes `nmhost.json` next to it with the absolute paths of the data directory and the `openncalayer` binary;
   - writes the host manifests: on macOS and Linux for the browsers it finds (Chrome, Chromium, Edge, Brave, Yandex Browser, Firefox); on Windows always `%LOCALAPPDATA%\OpenNCALayer\nm\{chromium,firefox}.json` and the keys `HKCU\Software\{Google\Chrome,Chromium,Microsoft\Edge,Mozilla}\NativeMessagingHosts\io.github.arynyklas.openncalayer`.

   The command never touches certificates. Check with `openncalayer nm status` (exit code 1 if anything is missing); remove with `openncalayer nm uninstall` (the data directory stays).
2. Chrome, Edge, Yandex Browser: the extensions page (`chrome://extensions`, `edge://extensions`) → "Developer mode" → "Load unpacked" → the `target/extension/chromium` directory or the unpacked `openncalayer-chromium-<version>.zip`. The extension id must be `cmdaoegbcpdhoamhgmibpgpnlojopcal`: the host accepts no other id.
3. Firefox (128 or later): for now only a temporary install — `about:debugging` → "This Firefox" → "Load Temporary Add-on…" → `target/extension/firefox/manifest.json`; the add-on is gone after a Firefox restart. Only an AMO-signed (unlisted) XPI installs permanently: Firefox refuses the unsigned `.xpi`.
4. Reload the open tabs of the sites.

Good to know:
- `nm install` resolves the data directory like `run` does, honouring `ONCL_DATA_DIR`. After moving the `openncalayer` binary or changing the data directory, run `nm install` again.
- A repeated `nm install` replaces the relay by renaming: relays the browser is running keep working with the old file. Old `nmhost.old-*` files are removed by the next `nm install`. `nm uninstall` cannot delete a relay the browser is holding: close the browser and run the command again.
- A daemon started by the relay runs until the session ends. If TLS is set up and port 13579 is free, the same daemon serves `wss` too; otherwise the log has a warning and the daemon serves only the extension.
- Through the extension, the site origin that modules see comes from the browser, not from the page.
- If the host is not installed or the daemon does not start, the extension gives the page its own `WebSocket`, i.e. the original NCALayer if it is running. While the host is installed, sites go to OpenNCALayer even when the original is running: to return to the original, run `nm uninstall` or disable the extension.

Linux, Firefox from snap and Flatpak:
- `nm install` detects Firefox by `~/.mozilla` or `~/.config/mozilla`. Snap Firefox keeps its profile under `~/snap/firefox/`, so the command may skip Firefox ("пропущен"). Then create the directory with `mkdir -p ~/.mozilla` and run `nm install` again: the manifest goes to `~/.mozilla/native-messaging-hosts/`, where snap Firefox 135 or later reads it through xdg-desktop-portal.
- Flatpak Firefox starts native messaging hosts only through `xdg-native-messaging-proxy` on the host system. OpenNCALayer neither installs it nor changes Flatpak permissions: set this up by hand.
- Neither has been tested.

### Deviations and limits of the extension (P2)

- Firefox ESR 115 (the last Firefox for Windows 7) is not supported until P6: the shim needs `world: "MAIN"` in content scripts, available since Firefox 128.
- Chrome 109 (the last Chrome for Windows 7) is the declared minimum but has not been tested.
- Safari is not supported.
- Sockets a site opens from a Web Worker are not replaced: they still need `wss` and the CA.
- The native messaging paths of Yandex Browser and Opera are untested. On Windows they read Chrome's registry key; on Linux the Yandex Browser manifest goes to `~/.config/yandex-browser/NativeMessagingHosts/`.

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

The browser extension:

```sh
node --test "extension/test/*.test.mjs"   # extension tests, Node 22 or later
cargo xtask ext build                     # → target/extension/
```

End-to-end check of the extension in Chrome for Testing and Firefox (Linux only; browsers and drivers are downloaded to `target/browsers/`):

```sh
cargo build --release -p openncalayer --features e2e-prompter -p oncl-nmhost
cargo xtask ext build
cargo xtask ext-e2e --download
```

Without `--download` the paths come from `ONCL_CHROME`, `ONCL_CHROMEDRIVER`, `ONCL_FIREFOX` and `ONCL_GECKODRIVER`. The browsers run with throwaway profiles in `target/ext-e2e/`, and the host is registered there too (`nm install --sandbox`). The `e2e-prompter` feature replaces the signing dialogs with a script from the `ONCL_E2E_PROMPTER` file; regular builds do not have it.

Before submitting changes:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
```

`web/demo/vendor/ncalayer-client.js` is `package/ncalayer-client.js` from the npm package `ncalayer-js-client@1.6.1`, unmodified (MIT, sha256 `bdf2015c3e422eed70ccf38eef3246af67a0d38639e6b70fe6b8655a2fa03489`). The `demo_assets_served` test checks the sha256 of the file the server sends. The server sends the client's license next to it: `/demo/vendor/LICENSE`.

## License

© 2026 Aryn Yklas.

[Apache-2.0](LICENSE); see also [NOTICE](NOTICE). `web/demo/vendor/ncalayer-client.js` is MIT, see [`web/demo/vendor/LICENSE`](web/demo/vendor/LICENSE).
