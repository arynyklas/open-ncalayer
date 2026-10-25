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

Второй этап (P2) добавляет расширение браузера: через него сайты работают с OpenNCALayer без установки CA (раздел [«Расширение браузера»](#расширение-браузера)).

Результаты ручной проверки в браузерах — [`docs/dev/smoke-p1.md`](docs/dev/smoke-p1.md) и [`docs/dev/smoke-p2.md`](docs/dev/smoke-p2.md).

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
- 3 — порт занят, например оригинальным NCALayer;
- 4 — OpenNCALayer с тем же каталогом данных уже запущен в этом сеансе.

С флагом `--allow-no-wss` (так relay расширения запускает демон) любая ошибка запуска wss (коды 2, 3 и 1) не останавливает демон: он пишет предупреждение в журнал и работает только для расширения.

Одновременно оригинал и OpenNCALayer по `wss` работать не могут: обоим нужен порт 13579. Расширению порт не нужен.

Данные хранятся в `%APPDATA%\OpenNCALayer` (Windows), `~/Library/Application Support/OpenNCALayer` (macOS) или `${XDG_DATA_HOME:-~/.local/share}/openncalayer` (Linux). Внутри:
- `tls/` — сертификаты;
- `logs/openncalayer.YYYY-MM-DD.log` — журналы, новый файл каждый день;
- `settings.json` — путь к последнему выбранному файлу ключа.

Переменная `ONCL_DATA_DIR` заменяет каталог данных. При разработке задавайте её (например, `ONCL_DATA_DIR=target/oncl-data`), чтобы не трогать свой настоящий профиль.

## Расширение браузера

Расширение подменяет на странице `WebSocket` к `127.0.0.1`, `localhost` и `[::1]` на портах 13579–13679 и передаёт сообщения OpenNCALayer через native messaging. Браузер запускает маленький relay `nmhost`, а relay — демон (`openncalayer run --allow-no-wss`), если тот ещё не запущен. Сертификат и порт 13579 этому пути не нужны: `wss` и установленный CA теперь нужны только сайтам в браузерах без расширения.

Готовых пакетов пока нет, расширение собирается из исходников:

```sh
cargo build --release -p openncalayer -p oncl-nmhost
cargo xtask ext build   # → target/extension/
```

`ext build` кладёт в `target/extension/` распакованные расширения `chromium/` и `firefox/`, а рядом — `openncalayer-chromium-<версия>.zip` и неподписанный `openncalayer-firefox-<версия>.xpi`.

Установка:
1. `openncalayer nm install` — регистрирует хост native messaging `io.github.arynyklas.openncalayer`:
   - копирует relay `nmhost` (по умолчанию — лежащий рядом с `openncalayer`, другой путь — `--relay <файл>`) в `%LOCALAPPDATA%\OpenNCALayer\nmhost.exe` (Windows) или в каталог данных (macOS, Linux);
   - пишет рядом `nmhost.json` с абсолютными путями каталога данных и бинаря `openncalayer`;
   - пишет манифесты хоста: в macOS и Linux — для найденных браузеров (Chrome, Chromium, Edge, Brave, Yandex Browser, Firefox), в Windows — всегда `%LOCALAPPDATA%\OpenNCALayer\nm\{chromium,firefox}.json` и ключи `HKCU\Software\{Google\Chrome,Chromium,Microsoft\Edge,Mozilla}\NativeMessagingHosts\io.github.arynyklas.openncalayer`.

   Сертификаты команда не трогает. Проверка — `openncalayer nm status` (код 1, если чего-то не хватает), удаление — `openncalayer nm uninstall` (каталог данных остаётся).
2. Chrome, Edge, Yandex Browser: страница расширений (`chrome://extensions`, `edge://extensions`) → «Режим разработчика» → «Загрузить распакованное расширение» → каталог `target/extension/chromium` или распакованный `openncalayer-chromium-<версия>.zip`. Id расширения должен быть `cmdaoegbcpdhoamhgmibpgpnlojopcal`: расширение с другим id хост не принимает.
3. Firefox (128 и новее): пока только временная установка — `about:debugging` → «Этот Firefox» → «Загрузить временное дополнение…» → `target/extension/firefox/manifest.json`; дополнение пропадает при перезапуске Firefox. Постоянно ставится только подписанный AMO XPI (unlisted): неподписанный `.xpi` Firefox не установит.
4. Перезагрузите открытые вкладки сайтов.

Что важно знать:
- `nm install` берёт каталог данных так же, как `run`, с учётом `ONCL_DATA_DIR`. После переноса бинаря `openncalayer` или смены каталога данных повторите `nm install`.
- Повторный `nm install` заменяет relay переименованием: копии relay, запущенные браузером, работают дальше со старым файлом. Старые файлы `nmhost.old-*` удаляются при следующем `nm install`. В Windows `nm uninstall` не может удалить relay, пока браузер его держит (строка relay «занят запущенным процессом», код 1): закройте браузер и повторите команду. В macOS и Linux файл удаляется сразу.
- Демон, запущенный relay, работает до конца сеанса. Если TLS настроен и порт 13579 свободен, тот же демон обслуживает и `wss`; иначе в журнале — предупреждение, и демон работает только для расширения.
- Origin сайта, который получают модули, через расширение берётся у браузера, а не у страницы.
- Если хост не установлен или демон не запускается, расширение отдаёт странице её обычный `WebSocket`, то есть оригинальный NCALayer, если он запущен. Пока хост установлен, сайты идут в OpenNCALayer, даже когда оригинал запущен. Чтобы вернуться к оригиналу, выполните `nm uninstall` и перезапустите браузер (или завершите демон) либо отключите расширение: сразу после `nm uninstall` браузер продолжает работать через уже запущенные relay и демон.

Linux, Firefox из snap и Flatpak:
- `nm install` находит Firefox по `~/.mozilla` или `~/.config/mozilla`. Профиль Firefox из snap лежит в `~/snap/firefox/`, и команда может пропустить Firefox («пропущен»). Тогда создайте каталог `mkdir -p ~/.mozilla` и повторите `nm install`: манифест ляжет в `~/.mozilla/native-messaging-hosts/`, откуда Firefox из snap 135 и новее читает его через xdg-desktop-portal.
- Firefox из Flatpak запускает хосты native messaging только через `xdg-native-messaging-proxy` на хост-системе. OpenNCALayer его не ставит и права Flatpak не меняет: это настраивается вручную.
- Оба варианта не проверялись.

### Отличия и ограничения расширения (P2)

- Firefox ESR 115 (последний Firefox для Windows 7) не поддерживается до P6: шиму нужен `world: "MAIN"` в content scripts, он есть с Firefox 128.
- Chrome 109 (последний Chrome для Windows 7) заявлен минимальной версией, но не проверялся.
- Safari не поддерживается.
- Сокеты, которые сайт открывает из Web Worker, не подменяются: для них по-прежнему нужны `wss` и CA.
- Одна вкладка держит через расширение не больше 256 открытых сокетов, все вкладки профиля вместе — не больше 4096 (у демона). Сокет сверх лимита сразу закрывается с кодом 1006, как при отказе в соединении.
- Пути native messaging для Yandex Browser и Opera не проверены. В Windows они читают ключ реестра Chrome; в Linux для Yandex Browser манифест пишется в `~/.config/yandex-browser/NativeMessagingHosts/`.

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

Расширение браузера:

```sh
node --test "extension/test/*.test.mjs"   # тесты расширения, Node 22 и новее
cargo xtask ext build                     # → target/extension/
```

Сквозная проверка расширения в Chrome for Testing и Firefox (только Linux, браузеры и драйверы скачиваются в `target/browsers/`):

```sh
cargo build --release -p openncalayer --features e2e-prompter -p oncl-nmhost
cargo xtask ext build
cargo xtask ext-e2e --download
```

Без `--download` пути берутся из `ONCL_CHROME`, `ONCL_CHROMEDRIVER`, `ONCL_FIREFOX` и `ONCL_GECKODRIVER`. Браузеры запускаются с одноразовыми профилями в `target/ext-e2e/`, хост регистрируется там же (`nm install --sandbox`). Фича `e2e-prompter` заменяет окна подписи сценарием из файла `ONCL_E2E_PROMPTER`; в обычных сборках её нет.

Перед отправкой изменений:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
```

`web/demo/vendor/ncalayer-client.js` — файл `package/ncalayer-client.js` из npm-пакета `ncalayer-js-client@1.6.1` без изменений (MIT, sha256 `bdf2015c3e422eed70ccf38eef3246af67a0d38639e6b70fe6b8655a2fa03489`). Тест `demo_assets_served` сверяет sha256 файла, который отдаёт сервер. Лицензию клиента сервер отдаёт рядом с ним: `/demo/vendor/LICENSE`.

## Лицензия

© 2026 Aryn Yklas.

[Apache-2.0](LICENSE), см. также [NOTICE](NOTICE). `web/demo/vendor/ncalayer-client.js` — MIT, см. [`web/demo/vendor/LICENSE`](web/demo/vendor/LICENSE).
