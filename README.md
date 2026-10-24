# OpenNCALayer

[English](README.en.md)

OpenNCALayer — открытая замена NCALayer на Rust. Сайты (egov.kz, госзакупки, банки, ЭДО), которые работают с оригиналом через `wss://127.0.0.1:13579`, должны работать с OpenNCALayer без изменений: тот же протокол, те же модули.

OpenNCALayer — независимый проект и не связан с НУЦ РК.

## Статус

Ранняя разработка. Сейчас реализуется первый сквозной срез (P1): CMS-подпись ключом PKCS#12 (ГОСТ 2004, ГОСТ 2015‑512, RSA) с меткой времени НУЦ через модуль `kz.gov.pki.knca.basics`. Готовых сборок пока нет.

Документы:
- [`docs/design/roadmap.md`](docs/design/roadmap.md) — решения и дорожная карта;
- [`docs/original/architecture.md`](docs/original/architecture.md) — архитектура оригинального NCALayer.

## Разработка

Нужен `rustup`: версия Rust закреплена в `rust-toolchain.toml` и ставится автоматически.

```sh
cargo build --workspace
cargo xtask fetch-fixtures   # тестовые данные NCANode → target/fixtures/ncanode/
cargo test --workspace --all-features
```

`cargo xtask fetch-fixtures` скачивает тестовые файлы [NCANode](https://github.com/ncanode-kz/NCANode) с закреплённого коммита и проверяет их sha256. Эти файлы не коммитятся. Повторный запуск ничего не качает, если файлы на месте.

Тесты с пометкой `live_` обращаются к настоящим сервисам НУЦ и по умолчанию не запускаются:

```sh
cargo test --workspace --all-features -- --ignored live_
```

Перед отправкой изменений:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

## Лицензия

[Apache-2.0](LICENSE), см. также [NOTICE](NOTICE).
