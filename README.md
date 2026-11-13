# OpenNCALayer

OpenNCALayer — открытая замена NCALayer на Rust. Сайты (egov.kz, госзакупки, банки, ЭДО), которые работают с оригиналом через `wss://127.0.0.1:13579`, должны работать с OpenNCALayer без изменений: тот же протокол, те же модули.

OpenNCALayer — независимый проект и не связан с НУЦ РК.

## Статус

Ранняя разработка. Выпускаются предварительные версии `0.1.0-alpha.N` ([Releases](https://github.com/arynyklas/OpenNCALayer/releases)); stable-релиза пока нет. Что надёжно и что нет:

- **Работает:** протокол оригинала для файловых хранилищ (вход на eGov проверен на Windows 11 в Chrome — и через `wss` с установленным CA, и через расширение), проверка сертификатов НУЦ, расширение браузера, программа в области уведомлений.
- **Экспериментально:** токены и удостоверение личности (выключены по умолчанию, проверены только на программных эмуляторах), плагины-порты модулей оригинала и подпись из окна «Инструменты» (настоящим ключом и службами НУЦ не проверена), установщики на macOS (не проверялись), самообновление по подписанному индексу (канал `beta`: реализовано и проверено тестами и проверкой индекса в CI; на выпущенной сборке «Проверить обновления» не прогонялось, более новой версии ещё нет).
- **Нет:** шифрования и расшифрования, WinGet-пакета (подробности в [`docs/dev/winget.md`](docs/dev/winget.md)), stable-канала обновлений.

Подробно о границах — в [`docs/user/compatibility.md`](docs/user/compatibility.md), [`docs/user/tokens.md`](docs/user/tokens.md) и [`docs/user/plugins.md`](docs/user/plugins.md).

## С чего начать

**Я пользователь сайта (egov, госзакупки…).** Поставьте программу и настройте доступ браузера:
1. Скачайте установщик со страницы [«Загрузка»](https://arynyklas.github.io/OpenNCALayer/download/) сайта проекта или из [Releases](https://github.com/arynyklas/OpenNCALayer/releases): Windows — `openncalayer-<версия>-win-x64-setup.exe` (32-битная — `win-x86`; Windows 7 SP1 — `win7-*`), macOS — `openncalayer-<версия>-osx.pkg`, Linux — `openncalayer-<версия>-linux-x64.AppImage`, Arch Linux — пакет AUR `openncalayer-bin` появится только для релизов без суффикса; пока все выпуски предварительные, в AUR пакета нет.
2. Либо установите расширение браузера ([`docs/user/browser-extension.md`](docs/user/browser-extension.md)) — сертификат тогда не нужен, либо выпустите сертификат мастером «Сертификат для браузера…» в меню значка ([`docs/user/tls.md`](docs/user/tls.md)).
3. Если вы выбрали сертификат, откройте `https://127.0.0.1:13579/openncalayer/selftest`: страница должна открыться без предупреждения о сертификате. С расширением эта проверка не нужна.

Подробности по каждой ОС, удаление и Windows 7 — в [`docs/user/install.md`](docs/user/install.md).

**Я разработчик, интегратор.** Три независимых способа использовать ту же подпись и проверку без десктопа:
- SDK `oncl-core` — встраиваемая Rust-библиотека (не в crates.io, подключается по path или git): [`docs/dev/sdk-overview.md`](docs/dev/sdk-overview.md), контракты — [`docs/dev/sdk.md`](docs/dev/sdk.md);
- CLI `oncl` — подпись, проверка, хеширование, метки времени: [`docs/user/cli.md`](docs/user/cli.md);
- HTTP-сервис `oncl-server` — API выключен, пока оператор не включит его: [`docs/user/server.md`](docs/user/server.md), [`docs/user/http-api.md`](docs/user/http-api.md).

Архивы `oncl` и `oncl-server` workflow релиза собирает только как артефакты запуска (`platform-*`), к релизу они не прикладываются, и в списке файлов `0.1.0-alpha.7` их нет: собирайте из исходников ([`docs/dev/development.md`](docs/dev/development.md)).

## Что умеет сейчас

| Возможность | Состояние |
|---|---|
| Подпись CMS, `raw` и XML (XMLDSig) ключами PKCS#12 (`.p12`, `.pfx`) и JKS (только чтение): ГОСТ 2004, ГОСТ 2015-512, RSA | работает |
| Создание ключей и запросов на сертификат, установка выданных сертификатов | работает для файловых хранилищ |
| Проверка ключей в окне выбора: цепочка до корней НУЦ, OCSP, дата отзыва | работает |
| Расширение браузера (Chromium; Firefox 115 и новее) | работает; в Firefox — временная установка |
| Значок в области уведомлений, настройки, мастер TLS, окно инструментов | работает |
| Обновление по подписанному индексу | реализовано, канал `beta`; на выпущенной сборке не проверено |
| Сборки для Windows 7 SP1 (x64, x86) | есть; проверены в лаборатории проекта и в CI |
| Плагины: порты сторонних модулей оригинала (WebAssembly) | каталог в канале `beta`; установка из каталога или из файла `.onclp` |
| Токены и удостоверение личности | экспериментально, выключено по умолчанию |
| Шифрование и расшифрование | нет |

## Документация

Пользователям:
- [`docs/user/install.md`](docs/user/install.md) — готовые сборки, установщики, Windows 7, сайт проекта;
- [`docs/user/desktop.md`](docs/user/desktop.md) — значок, настройки, мастер TLS, оригинальный NCALayer;
- [`docs/user/tls.md`](docs/user/tls.md) — сертификат OpenNCALayer: выпуск, установка, удаление, перевыпуск;
- [`docs/user/browser-extension.md`](docs/user/browser-extension.md) — расширение браузера;
- [`docs/user/updates.md`](docs/user/updates.md) — обновления;
- [`docs/user/compatibility.md`](docs/user/compatibility.md) — модули и отличия от оригинала;
- [`docs/user/plugins.md`](docs/user/plugins.md) и [`docs/user/manual-plugins.md`](docs/user/manual-plugins.md) — плагины и подпись из окна «Инструменты»;
- [`docs/user/tokens.md`](docs/user/tokens.md) — токены (экспериментально);
- [`docs/user/cli.md`](docs/user/cli.md), [`docs/user/server.md`](docs/user/server.md), [`docs/user/http-api.md`](docs/user/http-api.md) — `oncl` и `oncl-server`.

Разработчикам:
- [`docs/dev/development.md`](docs/dev/development.md) — сборка, запуск, тесты, проверки перед отправкой изменений;
- [`docs/dev/sdk-overview.md`](docs/dev/sdk-overview.md), [`docs/dev/sdk.md`](docs/dev/sdk.md), [`docs/dev/audit.md`](docs/dev/audit.md) — SDK и журнал аудита;
- [`docs/dev/release.md`](docs/dev/release.md) — выпуск версии и подпись индекса: инструкция мейнтейнера;
- [`docs/dev/upstream-watch.md`](docs/dev/upstream-watch.md) — наблюдатель за оригиналом: ветка `upstream`, issues, резервный путь;
- [`docs/design/roadmap.md`](docs/design/roadmap.md) — решения и дорожная карта; [`docs/design/update-index.md`](docs/design/update-index.md), [`docs/design/plugins.md`](docs/design/plugins.md), [`docs/design/tokens.md`](docs/design/tokens.md) — устройство;
- [`docs/original/architecture.md`](docs/original/architecture.md) — архитектура оригинального NCALayer.

Сайт проекта — [arynyklas.github.io/OpenNCALayer](https://arynyklas.github.io/OpenNCALayer/): каталог плагинов, загрузка и история оригинала (на русском, казахском и английском).

## Лицензия

© 2026 Aryn Yklas.

[Apache-2.0](LICENSE), см. также [NOTICE](NOTICE). `web/demo/vendor/ncalayer-client.js` — MIT, см. [`web/demo/vendor/LICENSE`](web/demo/vendor/LICENSE). `vendor/velopack` — изменённая копия Velopack, MIT, см. [`vendor/velopack/LICENSE`](vendor/velopack/LICENSE). `vendor/i-slint-backend-winit` — изменённая копия бэкенда winit из Slint, используется по LicenseRef-Slint-Royalty-free-2.0, см. [`vendor/i-slint-backend-winit/LICENSES`](vendor/i-slint-backend-winit/LICENSES).
