# OpenNCALayer

[Русский](README.md)

OpenNCALayer is an open-source Rust replacement for NCALayer, the signing daemon used by Kazakhstan's e-government services. Sites (egov.kz, public procurement, banks, e-document systems) that talk to the original over `wss://127.0.0.1:13579` are meant to work with OpenNCALayer unchanged: same protocol, same modules.

OpenNCALayer is an independent project and is not affiliated with the National Certification Authority of the Republic of Kazakhstan (NCA RK).

## Status

Early development. The first end-to-end slice (P1) is in progress: CMS signatures with a PKCS#12 key (GOST 2004, GOST 2015-512, RSA) with an NCA timestamp through the `kz.gov.pki.knca.basics` module. There are no release builds yet.

Documentation is written in Russian:
- [`docs/design/roadmap.md`](docs/design/roadmap.md) — decisions and roadmap;
- [`docs/original/architecture.md`](docs/original/architecture.md) — architecture of the original NCALayer.

## Development

You need `rustup`: the Rust version is pinned in `rust-toolchain.toml` and installed automatically.

```sh
cargo build --workspace
cargo xtask fetch-fixtures   # NCANode test data → target/fixtures/ncanode/
cargo test --workspace --all-features
```

`cargo xtask fetch-fixtures` downloads [NCANode](https://github.com/ncanode-kz/NCANode) test files from a pinned commit and verifies their sha256. These files are never committed. A repeated run downloads nothing when the files are already in place.

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

## License

[Apache-2.0](LICENSE); see also [NOTICE](NOTICE).
