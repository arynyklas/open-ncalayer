# Разработка и сборка

Сборка из исходников, запуск, тесты и проверки перед отправкой изменений. Выпуск версии и подпись индекса — в [`release.md`](release.md); встраивание SDK — в [`sdk-overview.md`](sdk-overview.md) и [`sdk.md`](sdk.md).

## Сборка и запуск

Нужен `rustup`: версия Rust закреплена в `rust-toolchain.toml` и ставится автоматически. На Linux для окон нужны пакеты разработки fontconfig, xkbcommon, Wayland и GTK 3 (в Debian и Ubuntu: `libfontconfig1-dev libxkbcommon-dev libwayland-dev libgtk-3-dev`).

Для запуска на Linux нужны:
- `libxkbcommon-x11-0` — без неё окна подписи не открываются, и `openncalayer run` завершается с ошибкой (`libxkbcommon-dev` её не ставит);
- `xdg-desktop-portal` с бэкендом (например, `xdg-desktop-portal-gtk`) или `zenity` — для кнопки «Обзор…»; без них системный диалог выбора файла не открывается (в журнале — ошибка rfd), путь к файлу ключа можно ввести вручную.

```sh
cargo build --release -p openncalayer
```

Бинарь: `target/release/openncalayer` (`openncalayer.exe` в Windows).

Основной путь — мастер «Сертификат для браузера…» в меню значка (раздел [«Мастер TLS»](../user/desktop.md#мастер-tls)). Из командной строки:

```sh
openncalayer tls init   # выпустить сертификат и напечатать инструкцию по установке CA
openncalayer run        # запустить сервер со значком; `openncalayer` без команды делает то же
```

1. Выпустите сертификат в мастере или командой `tls init` и установите CA кнопкой мастера или по напечатанной инструкции. Подробности по каждой ОС — в [`docs/user/tls.md`](../user/tls.md).
2. Запустите `openncalayer run` и откройте `https://127.0.0.1:13579/` (или `https://127.0.0.1:13579/openncalayer/selftest`): страница должна открыться без предупреждения о сертификате.
3. На `https://127.0.0.1:13579/demo/` можно подписать текст или файл и скачать `.p7s`.
4. Проверить подпись: `oncl verify --profile cms --input signature.p7s --root <корневой сертификат НУЦ>` (демо-страница сохраняет `.p7s` в DER; `oncl verify` читает DER или BER, а PEM — только с явным ключом `--pem`: один блок `CMS`/`PKCS7`, не больше 16 МиБ текста; корни по умолчанию не подставляются); для подписи без вложенных данных добавьте `--detached <файл данных>`, а `--offline` отключает проверку отзыва. Проверяются подписи и метки времени, цепочки сертификатов подписанта и TSA через переданные вами корни, срок действия и отзыв; печатается отчёт по каждой проверке, код выхода 0 только для результата `Valid`. Подробности — в [`docs/user/cli.md`](../user/cli.md).

Коды выхода `run`:
- 2 — TLS не настроен;
- 3 — порт занят, например оригинальным NCALayer;
- 4 — OpenNCALayer с тем же каталогом данных уже запущен в этом сеансе.

Коды 2 и 3 возможны только без значка: `--no-tray`, значок не показался, пропал на первом проходе цикла окон (macOS) или его не принял StatusNotifierWatcher в течение минуты после запуска (Linux). И то лишь пока wss выключен: демон, проблему которого к этому времени устранили (оригинал остановлен из уведомления, сертификат сохранён), продолжает работать без значка. Со значком `run` при ненастроенном TLS или занятом порте продолжает работать для расширения, значок показывает проблему, а wss запускается в том же процессе, когда мастер сохранит сертификат или порт освободится. Демон, запущенный пользователем или нашим автозапуском, при запуске показывает уведомление и сам занимает освободившийся порт (проверка раз в 30 секунд).

С флагом `--allow-no-wss` (так relay расширения запускает демон) любая ошибка запуска wss (коды 2, 3 и 1) не останавливает демон: он пишет предупреждение в журнал и работает только для расширения. Освободившийся порт такой демон сам не занимает: wss он запускает только после действия пользователя в значке или мастере TLS (остановить оригинал, сохранить сертификат).

Одновременно оригинал и OpenNCALayer по `wss` работать не могут: обоим нужен порт 13579. Расширению порт не нужен.

Данные хранятся в `%APPDATA%\OpenNCALayer` (Windows), `~/Library/Application Support/OpenNCALayer` (macOS) или `${XDG_DATA_HOME:-~/.local/share}/openncalayer` (Linux). Внутри:
- `tls/` — сертификаты;
- `logs/openncalayer.YYYY-MM-DD.log` — журналы, новый файл каждый день;
- `settings.json` — настройки (`locale`, `autostart`, `proxy`) и путь к последнему выбранному файлу ключа;
- `original-autostart.json` и `original-autostart/` — журнал и перенесённые записи автозапуска оригинала;
- `installation.json` — какая версия и из какого места встроена в систему (раздел [«Установка»](../user/install.md#установка)).

Переменная `ONCL_DATA_DIR` заменяет каталог данных. При разработке задавайте её (например, `ONCL_DATA_DIR=target/oncl-data`), чтобы не трогать свой настоящий профиль.

## Разработка

```sh
cargo build --workspace
cargo xtask fetch-fixtures   # тестовые данные NCANode → target/fixtures/ncanode/
cargo test --workspace --all-features
```

`cargo xtask fetch-fixtures` скачивает тестовые файлы [NCANode](https://github.com/ncanode-kz/NCANode) с закреплённого коммита и проверяет их sha256. Эти файлы не коммитятся. Повторный запуск ничего не качает, если файлы на месте.

Тестовые ключи в `fixtures/synthetic/` синтетические, пароль `Qwerty12`. Их можно использовать на демо-странице. По умолчанию демо отправляет `chain: []`, поэтому синтетические и тестовые ключи NCANode доступны. Вариант «синтетический тестовый корень» передаёт `root-gost2015`: ключи других корней и промежуточного CA становятся недоступны.

Тесты с пометкой `live_` обращаются к настоящим сервисам НУЦ и по умолчанию не запускаются:

```sh
cargo test --workspace --all-features -- --ignored live_
```

Это `live_test_tsa` (тестовый TSP НУЦ), `live_ocsp_nca_test_certificate` (тестовый OCSP НУЦ, нужен `cargo xtask fetch-fixtures`) и `live_crl_nca_root_gost_2022` (CRL промышленного `crl.root.gov.kz`). Они зависят от внешних сервисов, поэтому CI запускает их только по расписанию и вручную (`workflow_dispatch`, job `live`), а единичный сбой сети стоит перезапустить. Тестовый RSA-ответчик OCSP НУЦ на стандартные запросы (и от OpenSSL тоже) отвечает `malformedRequest`, поэтому живой OCSP проверяется на ГОСТ-сертификате.

Расширение браузера:

```sh
node --test "extension/test/*.test.mjs"   # тесты расширения, Node 22 и новее
cargo xtask ext build                     # → target/extension/
```

Сквозная проверка расширения в Chrome for Testing, Firefox и Firefox ESR 115 (только Linux, браузеры и драйверы скачиваются в `target/browsers/`):

```sh
cargo build --release -p openncalayer --features e2e-prompter -p oncl-nmhost
cargo xtask ext build
cargo xtask ext-e2e --download
```

Без `--download` пути берутся из `ONCL_CHROME`, `ONCL_CHROMEDRIVER`, `ONCL_FIREFOX`, `ONCL_FIREFOX_ESR` и `ONCL_GECKODRIVER`; один браузер — `--browser chromium|firefox|firefox-esr`. Firefox ESR 115 нужна системная библиотека `libdbus-glib-1-2`. Браузеры запускаются с одноразовыми профилями в `target/ext-e2e/`, хост регистрируется там же (`nm install --sandbox`). Фича `e2e-prompter` заменяет окна подписи сценарием из файла `ONCL_E2E_PROMPTER`; в обычных сборках её нет. Шаг сценария не того вида, что открывшееся окно (ответ окна ключа на окно хранилища), не роняет вызов: окно отменяется, а в журнал пишется строка `… the window is cancelled`; страница получает обычный ответ на отмену, соединение остаётся открытым. Сценарий 8 удаляет расширение из открытой страницы (только Firefox; в ESR 115 он проверяет описанное выше ограничение).

Тесты встроенных модулей (`cargo test -p oncl-builtin-tests`) идут и без маркеров: при `ONCL_TEST_NO_MARKERS=1` ядро не заменяет длинные строки запроса маркерами, модуль читает их как есть, и все тесты проходят так же. Тест `markers` сверяет ответы с маркерами и без них для каждой строки запросов покрытых методов, увеличенной до 20 000 байт (и для пачки документов длиннее 1 МиБ).

Проверка наших подписей XMLDSig и CMS в NCANode (Kalkan), только Linux, нужен Docker: `cargo xtask fetch-fixtures && cargo xtask interop-ncanode`. Образ, порядок запуска и последний результат описаны в [`docs/dev/interop-ncanode.md`](interop-ncanode.md).

Сборки для Windows 7 SP1 (только в Windows, нужен закреплённый nightly):

```sh
rustup toolchain install nightly-2026-08-12 --profile minimal --component rust-src
cargo xtask win7 --arch all   # → target/win7/x64/, target/win7/x86/
```

`cargo xtask win7` собирает `openncalayer.exe` и `nmhost.exe` для `x86_64-win7-windows-msvc` и `i686-win7-windows-msvc` (`-Zbuild-std`, статический CRT — VC++ redist не нужен) и кладёт рядом две DLL, которых нет в Windows 7: `combase.dll` переадресует `CoTaskMemFree` и `CoCreateFreeThreadedMarshaler` в `ole32.dll`, а в `api-ms-win-core-winrt-error-l1-1-0.dll` функции `RoOriginateErrorW` и `RoOriginateError` ничего не делают. Windows 8 и новее эти копии не загружают: `combase.dll` там — known DLL, а имена `api-ms-win-*` разрешаются через схему API set.

Затем работает гейт импортов, он же `cargo xtask check-imports <exe>…`:
- импорт DLL или функции из списка заведомо отсутствующих в Windows 7 — ошибка (декорированные имена x86 тоже ловятся). Это denylist: импорт из Windows 8+ вне списка он пропустит, сверка с экспортами Windows 7 SP1 (allowlist) появится с лабораторией проекта;
- импорт из `combase.dll` или `api-ms-win-core-winrt-error-l1-1-0.dll` допустим, только если DLL с этим именем лежит рядом с exe и экспортирует ровно это имя; новый импорт, например `combase!CoTaskMemAlloc`, не пройдёт, пока DLL его не экспортирует;
- сами эти DLL той же разрядности, что и exe, и импортируют и переадресуют только в `kernel32.dll` и `ole32.dll`, по недекорированным именам;
- `nmhost.exe` должен обходиться без них: `nm install` копирует relay отдельно от программы.

В Windows `cargo xtask win7` после гейта запускает сборку из `target/win7/<arch>/`: `--help`, `nm install` и `nm status` в песочнице, `tls init`, затем `run` до ответа на `GET /` по HTTPS. Каталог данных — во временном каталоге под `target/win7-smoke/`. В CI это блокирующий job `win7` (x64 и x86 на Windows Server 2025); проверки в самой Windows 7 появятся с лабораторией проекта. `--target-dir <каталог>` — свой каталог сборки cargo вместо `target/`: job `win7` кэширует его целиком, потому что rust-cache выбрасывает стандартную библиотеку `-Zbuild-std`, а без неё пересобирается всё.

Перед отправкой изменений:

```sh
# не `--all`: он форматирует и подключённые по path крейты `vendor/`, оставленные как в оригинале
cargo fmt --check $(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | "-p", .name')
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
cargo xtask licenses --check   # сторонние лицензии окна «О программе» свежие
```

`web/demo/vendor/ncalayer-client.js` — файл `package/ncalayer-client.js` из npm-пакета `ncalayer-js-client@1.6.1` без изменений (MIT, sha256 `bdf2015c3e422eed70ccf38eef3246af67a0d38639e6b70fe6b8655a2fa03489`). Тест `demo_assets_served` сверяет sha256 файла, который отдаёт сервер. Лицензию клиента сервер отдаёт рядом с ним: `/demo/vendor/LICENSE`.

`vendor/i-slint-backend-winit` — пакет `i-slint-backend-winit` 1.18.1 с crates.io (бэкенд winit из Slint) с изменениями, в сборке через `[patch.crates-io]`. Изменено одно место — размер шрифта по умолчанию на Windows (`windows_message_font_height` в `lib.rs`, его вызывает `bind_context`). `SystemParametersInfoForDpi` (Windows 10 1607 и новее) ищется через `GetProcAddress`; без неё вызывается `SystemParametersInfoW(SPI_GETNONCLIENTMETRICS)`, и высота пересчитывается из системного DPI в 96. В `Cargo.toml` добавлена фича `Win32_System_LibraryLoader` крейта `windows`. Так Win7-сборка не импортирует функцию, которой нет в Windows 7, а Windows 10/11 получают тот же вызов, что и раньше. Лицензия Slint Royalty-free 2.0 разрешает изменять программу и распространять изменённую копию в составе приложения (разделы 1–2); уведомления о лицензии в файлах сохранены. Тест `locked_slint_winit_backend_is_the_patched_copy` падает, если обновление Slint оставит патч неиспользованным; при обновлении копию заменяют новым пакетом и переносят правку.

`vendor/velopack` — пакет `velopack` 1.3.39-g8d2844f с crates.io (коммит `8d2844f`, MIT) с изменениями, в сборке через `[patch.crates-io]`. Изменены два места: `src/sources/mod.rs` добавляет в `UpdateSource` метод `verify_full_package` (по умолчанию — проверка размера и контрольной суммы самого Velopack), а `download_updates` в `src/manager.rs` проверяет им полный пакет, который уже лежит на диске (не прошедший удаляется и скачивается заново), и пакет, собранный из дельты, — до переименования и до извлечения из него `Squirrel.exe` (Update.exe); не прошедший заменяется скачиванием полного пакета. Наш `IndexSource` принимает файл, если он совпадает с полным пакетом подписанного индекса по sha256 и размеру или содержит те же файлы (`contents_sha256` индекса). `vendor/velopack/LICENSE` — лицензия репозитория Velopack на этом коммите: в пакете crates.io её нет. Тест `locked_velopack_is_the_patched_copy` падает, если `Cargo.lock` перестал брать эту копию.

## Сайт проекта: локальная сборка

Собрать локально: `cargo xtask registry build` (Zola 0.23.6 скачивается в `target/tools/` и сверяется по sha256; результат — `target/site/public`, проверка ссылок и правил страниц — сразу после сборки, отдельно — `cargo xtask registry check <каталог>`). Посмотреть: `target/tools/zola-v0.23.6/zola --root target/site/src serve`. Тесты сборки сайта с Zola называются `zola_…` и по умолчанию не запускаются (`cargo test -p xtask --test registry_site -- --ignored zola_`); в CI их запускает job `site`. Исходники — в `site/` (конфигурация, шаблоны, стили, тексты); страницы портов и `data/site.json` генерируются в `target/site/src` и не коммитятся.
