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
- signature checking: `openncalayer cms-verify` — signatures, timestamps, certificate chains up to the NCA roots, validity periods and revocation (OCSP, CRL);
- a self-test page at `https://127.0.0.1:13579/` and a demo page at `https://127.0.0.1:13579/demo/`.

The second phase (P2) adds a browser extension: with it, sites work with OpenNCALayer without a trusted CA (see [Browser extension](#browser-extension)).

The third phase (P3) checks keys in the key dialog as the original does. The key certificate's chain is built to the embedded NCA roots or to the CAs of `signerParams.chain`; `chain: []` turns the check off. The anchor is a self-signed CA of the set or, as in the original, the topmost CA of the set found, so a `chain` of an intermediate CA alone works too. Revocation is checked with the NCA OCSP responder. A key without a chain is unavailable. A revoked key is marked «revoked DD.MM.YYYY» and is unavailable too, unless `signingParams` has `allowRevoked` (which the `raw` format ignores). As in the original, the NCA test PKI is not embedded: test-environment sites must pass `chain`.

Manual browser test results: [`docs/dev/smoke-p1.md`](docs/dev/smoke-p1.md) and [`docs/dev/smoke-p2.md`](docs/dev/smoke-p2.md) (in Russian).

### Deviations of P1 from the original

The first two are closed in P4.
- Only the `PKCS12` storage works. The other storages are listed in the dialog but unavailable.
- basics formats are `cms` and `raw` only; `xml` answers `INVALID_SIGNING_PARAMS`.
- The original's password strength check for keys with EKU `1.2.398.3.3.4.2*` is not implemented in P1.
- `NCALAYERPORT` is honoured in any session; the original honours it only in RDP/Citrix/xrdp sessions. The value must be within `13579..=13679`.
- TLS 1.2 and 1.3; the original speaks only TLS 1.2.
- With `decode`, base64 in `data` is checked before the dialog is shown; the original checks it afterwards. The error code is the same.
- Key validity dates in the key dialog are shown in UTC, not local time.

### Deviations of P3 from the original

- When the CA set has several CAs of the same name (the embedded set has `ncagost` and `ncagost18`, `ncarsa` and `ncarsa18`), the chain goes through the one whose signature verifies. The original keeps CAs by DN, so the last CA of a name hides the others.
- The chain's anchor is checked like any CA: validity, `basicConstraints.cA`, `keyCertSign`. The original (Java PKIX) does not check the anchor.
- The OCSP status of all keys of a store is checked at once, within 6 s in total. The original checks the keys one after another, 5 s each. A key not checked within that time stays available, as on a network error.
- A key unavailable for another reason (EKU, IIN, BIN, serial number) is not checked with OCSP: the dialog shows those reasons. The original puts its «REVOKED» mark on such keys too.
- The dialog shows the revocation date, in UTC: «revoked DD.MM.YYYY». The original's mark has no date: «REVOKED».
- The OCSP responder is also found `byKey` (the SHA-1 of its key); the original understands only `byName`. A response's `thisUpdate` may be ahead of the computer's clock by up to 300 s; the original requires `thisUpdate < now` strictly.

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
4. To check a signature: `openncalayer cms-verify signature.p7s`; for a detached signature, `openncalayer cms-verify signature.p7s --content <data file>`. It checks the signatures and timestamps, the certificate chains of the signer and of the TSA through the embedded NCA certificates (`--chain <CA file>` replaces them; repeatable, and a PEM file may hold several certificates), validity periods and revocation: the signer by OCSP, intermediate CAs by CRL (cached in `crl/` of the data directory). Only a verified timestamp proves when the signature was made: validity and revocation are judged at its `genTime`, and without one at the current time; `signingTime` is the signer's own claim and is only printed. A revocation after the timestamp does not invalidate the signature: `OK` comes with the line `revocation: revoked … after signing (…)`. The last line is `OK`, `FAIL: <reason>`, `INDETERMINATE: revocation data unavailable` (everything else holds, but no revocation data could be obtained) or `INDETERMINATE: no proof of signing time` (the certificate is expired or revoked now, and the signature would only hold at the claimed `signingTime`). The exit code is 0 only for `OK`. With `--offline` revocation is not checked and the line `not checked: revocation` precedes `OK`.

Exit codes of `run`:
- 2 — TLS is not set up;
- 3 — the port is taken, for example by the original NCALayer;
- 4 — OpenNCALayer with the same data directory is already running in this session.

With `--allow-no-wss` (how the extension's relay starts the daemon) no wss startup failure (codes 2, 3 and 1) stops the daemon: it logs a warning and serves only the extension.

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
- A repeated `nm install` replaces the relay by renaming: relays the browser is running keep working with the old file. Old `nmhost.old-*` files are removed by the next `nm install`. On Windows `nm uninstall` cannot delete a relay the browser is holding (the relay line says «занят запущенным процессом», exit code 1): close the browser and run the command again. On macOS and Linux the file is removed at once.
- A daemon started by the relay runs until the session ends. If TLS is set up and port 13579 is free, the same daemon serves `wss` too; otherwise the log has a warning and the daemon serves only the extension.
- Through the extension, the site origin that modules see comes from the browser, not from the page.
- If the host is not installed or the daemon does not start, the extension gives the page its own `WebSocket`, i.e. the original NCALayer if it is running. While the host is installed, sites go to OpenNCALayer even when the original is running. To return to the original, run `nm uninstall` and restart the browser (or stop the daemon), or disable the extension: right after `nm uninstall` the browser keeps using the relay and daemon already running.

Linux, Firefox from snap and Flatpak:
- `nm install` detects Firefox by `~/.mozilla` or `~/.config/mozilla`. Snap Firefox keeps its profile under `~/snap/firefox/`, so the command may skip Firefox ("пропущен"). Then create the directory with `mkdir -p ~/.mozilla` and run `nm install` again: the manifest goes to `~/.mozilla/native-messaging-hosts/`, where snap Firefox 135 or later reads it through xdg-desktop-portal.
- Flatpak Firefox starts native messaging hosts only through `xdg-native-messaging-proxy` on the host system. OpenNCALayer neither installs it nor changes Flatpak permissions: set this up by hand.
- Neither has been tested.

### Deviations and limits of the extension (P2)

- Firefox ESR 115 (the last Firefox for Windows 7) is not supported until P6: the shim needs `world: "MAIN"` in content scripts, available since Firefox 128.
- Chrome 109 (the last Chrome for Windows 7) is the declared minimum but has not been tested.
- Safari is not supported.
- Sockets a site opens from a Web Worker are not replaced: they still need `wss` and the CA.
- Through the extension, one tab holds at most 256 open sockets and all tabs of a profile together at most 4096 (the daemon's limit). A socket over the limit is closed at once with code 1006, like a refused connection.
- The native messaging paths of Yandex Browser and Opera are untested. On Windows they read Chrome's registry key; on Linux the Yandex Browser manifest goes to `~/.config/yandex-browser/NativeMessagingHosts/`.

## Development

```sh
cargo build --workspace
cargo xtask fetch-fixtures   # NCANode test data → target/fixtures/ncanode/
cargo test --workspace --all-features
```

`cargo xtask fetch-fixtures` downloads [NCANode](https://github.com/ncanode-kz/NCANode) test files from a pinned commit and verifies their sha256. These files are never committed. A repeated run downloads nothing when the files are already in place.

The test keys in `fixtures/synthetic/` are synthetic, password `Qwerty12`. They work on the demo page. By default the demo sends `chain: []`, so synthetic and NCANode test keys are available. The «synthetic test root» choice sends `root-gost2015`: keys of the other roots and of the intermediate CA become unavailable.

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
