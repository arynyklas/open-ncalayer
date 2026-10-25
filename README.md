# OpenNCALayer

[English](README.en.md)

OpenNCALayer — открытая замена NCALayer на Rust. Сайты (egov.kz, госзакупки, банки, ЭДО), которые работают с оригиналом через `wss://127.0.0.1:13579`, должны работать с OpenNCALayer без изменений: тот же протокол, те же модули.

OpenNCALayer — независимый проект и не связан с НУЦ РК.

## Статус

Ранняя разработка, готовых сборок пока нет. Собран первый сквозной срез (P1): сайт, использующий [ncalayer-js-client](https://github.com/sigex-kz/ncalayer-js-client), получает CMS-подпись через `wss://127.0.0.1:13579`.

Что есть в P1:
- модуль `kz.gov.pki.knca.basics`, метод `sign`, форматы `cms` и `raw`;
- ключи PKCS#12 (`.p12`, `.pfx`): ГОСТ 2004, ГОСТ 2015‑512, RSA;
- подпись с вложенными данными и без, со-подпись, метка времени НУЦ (TSP);
- окна выбора хранилища и ключа (русский, казахский, английский);
- мастер TLS в командной строке: `openncalayer tls init|import|status` ([инструкция](docs/user/tls.md));
- проверка подписи: `openncalayer cms-verify` — подписи и метки времени; цепочки сертификатов, сроки действия и отзыв не проверяются;
- страница самопроверки `https://127.0.0.1:13579/` и демо-страница `https://127.0.0.1:13579/demo/`.

Результаты ручной проверки в браузерах — [`docs/dev/smoke-p1.md`](docs/dev/smoke-p1.md).

### Отличия P1 от оригинала

Первые три закрываются в P3/P4.
- `signerParams.chain` игнорируется: нет PKIX и OCSP, отозванные ключи не отсекаются.
- Работает только хранилище `PKCS12`. Остальные хранилища показаны в окне, но недоступны.
- Форматы basics — только `cms` и `raw`; `xml` отвечает `INVALID_SIGNING_PARAMS`.
- Проверка стойкости пароля для ключей с EKU `1.2.398.3.3.4.2*`, которая есть в оригинале, в P1 не реализована.
- `NCALAYERPORT` учитывается в любой сессии, у оригинала — только в RDP/Citrix/xrdp. Значение должно быть в диапазоне `13579..=13679`.
- TLS 1.2 и 1.3, у оригинала — только 1.2.
- base64 в `data` при `decode` проверяется до показа окна, у оригинала — после. Код ошибки тот же.
- Даты действия ключа в окне выбора показываются в UTC, а не в местном времени.

Документы:
- [`docs/user/tls.md`](docs/user/tls.md) — сертификат OpenNCALayer: выпуск, установка, удаление, перевыпуск;
- [`docs/design/roadmap.md`](docs/design/roadmap.md) — решения и дорожная карта;
- [`docs/original/architecture.md`](docs/original/architecture.md) — архитектура оригинального NCALayer.

## Сборка и запуск

Нужен `rustup`: версия Rust закреплена в `rust-toolchain.toml` и ставится автоматически. На Linux для окон нужны пакеты разработки fontconfig, xkbcommon, Wayland и GTK 3 (в Debian и Ubuntu: `libfontconfig1-dev libxkbcommon-dev libwayland-dev libgtk-3-dev`).

Для запуска на Linux нужны:
- `libxkbcommon-x11-0` — без неё окна подписи не открываются, и `openncalayer run` завершается с ошибкой (`libxkbcommon-dev` её не ставит);
- `xdg-desktop-portal` с бэкендом (например, `xdg-desktop-portal-gtk`) или `zenity` — для кнопки «Обзор…»; без них системный диалог выбора файла не открывается (в журнале — ошибка rfd), путь к файлу ключа можно ввести вручную.

```sh
cargo build --release -p openncalayer
```

Бинарь: `target/release/openncalayer` (`openncalayer.exe` в Windows).

```sh
openncalayer tls init   # выпустить сертификат и напечатать инструкцию по установке CA
openncalayer run        # запустить сервер; `openncalayer` без команды делает то же
```

1. После `tls init` установите CA по напечатанной инструкции. Подробности по каждой ОС — в [`docs/user/tls.md`](docs/user/tls.md).
2. Запустите `openncalayer run` и откройте `https://127.0.0.1:13579/`: страница должна открыться без предупреждения о сертификате.
3. На `https://127.0.0.1:13579/demo/` можно подписать текст или файл и скачать `.p7s`.
4. Проверить подпись: `openncalayer cms-verify signature.p7s`, для подписи без вложенных данных — `openncalayer cms-verify signature.p7s --content <файл данных>`. `OK` значит, что подписи и метки времени математически верны; цепочки сертификатов, сроки действия и отзыв не проверяются (строка `not checked: …` перед `OK`).

Коды выхода `run`:
- 2 — TLS не настроен;
- 3 — порт занят, например оригинальным NCALayer.

Одновременно оригинал и OpenNCALayer работать не могут: обоим нужен порт 13579.

Данные хранятся в `%APPDATA%\OpenNCALayer` (Windows), `~/Library/Application Support/OpenNCALayer` (macOS) или `${XDG_DATA_HOME:-~/.local/share}/openncalayer` (Linux). Внутри:
- `tls/` — сертификаты;
- `logs/openncalayer.YYYY-MM-DD.log` — журналы, новый файл каждый день;
- `settings.json` — путь к последнему выбранному файлу ключа.

Переменная `ONCL_DATA_DIR` заменяет каталог данных. При разработке задавайте её (например, `ONCL_DATA_DIR=target/oncl-data`), чтобы не трогать свой настоящий профиль.

## Разработка

```sh
cargo build --workspace
cargo xtask fetch-fixtures   # тестовые данные NCANode → target/fixtures/ncanode/
cargo test --workspace --all-features
```

`cargo xtask fetch-fixtures` скачивает тестовые файлы [NCANode](https://github.com/ncanode-kz/NCANode) с закреплённого коммита и проверяет их sha256. Эти файлы не коммитятся. Повторный запуск ничего не качает, если файлы на месте.

Тестовые ключи в `fixtures/synthetic/` синтетические, пароль `Qwerty12`. Их можно использовать на демо-странице.

Тесты с пометкой `live_` обращаются к настоящим сервисам НУЦ и по умолчанию не запускаются:

```sh
cargo test --workspace --all-features -- --ignored live_
```

Перед отправкой изменений:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
```

`web/demo/vendor/ncalayer-client.js` — файл `package/ncalayer-client.js` из npm-пакета `ncalayer-js-client@1.6.1` без изменений (MIT, sha256 `bdf2015c3e422eed70ccf38eef3246af67a0d38639e6b70fe6b8655a2fa03489`). Тест `demo_assets_served` сверяет sha256 файла, который отдаёт сервер. Лицензию клиента сервер отдаёт рядом с ним: `/demo/vendor/LICENSE`.

## Лицензия

[Apache-2.0](LICENSE), см. также [NOTICE](NOTICE). `web/demo/vendor/ncalayer-client.js` — MIT, см. [`web/demo/vendor/LICENSE`](web/demo/vendor/LICENSE).
