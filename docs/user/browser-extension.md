# Расширение браузера

Расширение подменяет на странице `WebSocket` к `127.0.0.1`, `localhost` и `[::1]` на портах 13579–13679 и передаёт сообщения OpenNCALayer через native messaging. Браузер запускает маленький relay `nmhost`, а relay — демон (`openncalayer run --allow-no-wss`), если тот ещё не запущен. Сертификат и порт 13579 этому пути не нужны: `wss` и установленный CA теперь нужны только сайтам в браузерах без расширения.

Готовые файлы расширения лежат в [Releases](https://github.com/arynyklas/OpenNCALayer/releases): `openncalayer-chromium-<версия>.zip` и `openncalayer-firefox-<версия>.xpi` (неподписанный: в Firefox он ставится только временно, см. ниже). Расширение можно и собрать из исходников:

```sh
cargo build --release -p openncalayer -p oncl-nmhost
cargo xtask ext build   # → target/extension/
```

`ext build` кладёт в `target/extension/` распакованные расширения `chromium/` и `firefox/`, а рядом — `openncalayer-chromium-<версия>.zip` и неподписанный `openncalayer-firefox-<версия>.xpi`.

Установка:
1. `openncalayer nm install` — регистрирует хост native messaging `io.github.arynyklas.openncalayer` (установщики и первый запуск установленной копии делают это сами, раздел [«Установка»](install.md#установка)):
   - копирует relay `nmhost` (по умолчанию — лежащий рядом с `openncalayer`, другой путь — `--relay <файл>`) в `%LOCALAPPDATA%\OpenNCALayer\nmhost.exe` (Windows) или в каталог данных (macOS, Linux);
   - пишет рядом `nmhost.json` с абсолютными путями каталога данных и бинаря `openncalayer` (у AppImage — путь к самому файлу `.AppImage`);
   - пишет манифесты хоста: в macOS и Linux — для найденных браузеров (Chrome, Chromium, Edge, Brave, Yandex Browser, Firefox), в Windows — всегда `%LOCALAPPDATA%\OpenNCALayer\nm\{chromium,firefox}.json` и ключи `HKCU\Software\{Google\Chrome,Chromium,Microsoft\Edge,Mozilla}\NativeMessagingHosts\io.github.arynyklas.openncalayer`.

   Сертификаты команда не трогает. Проверка — `openncalayer nm status` (код 1, если чего-то не хватает), удаление — `openncalayer nm uninstall` (каталог данных остаётся).
2. Chrome, Edge, Yandex Browser: страница расширений (`chrome://extensions`, `edge://extensions`) → «Режим разработчика» → «Загрузить распакованное расширение» → каталог `target/extension/chromium` или распакованный `openncalayer-chromium-<версия>.zip`. Id расширения должен быть `cmdaoegbcpdhoamhgmibpgpnlojopcal`: расширение с другим id хост не принимает.
3. Firefox (115 и новее, в том числе ESR 115 — последний Firefox для Windows 7): пока только временная установка — `about:debugging` → «Этот Firefox» → «Загрузить временное дополнение…» → `target/extension/firefox/manifest.json`; дополнение пропадает при перезапуске Firefox. Постоянно ставится только подписанный AMO XPI (unlisted): неподписанный `.xpi` Firefox не установит.
4. Перезагрузите открытые вкладки сайтов.

Что важно знать:
- `nm install` берёт каталог данных так же, как `run`, с учётом `ONCL_DATA_DIR`. После переноса бинаря `openncalayer` или смены каталога данных повторите `nm install`.
- Повторный `nm install` заменяет relay переименованием: копии relay, запущенные браузером, работают дальше со старым файлом. Старые файлы `nmhost.old-*` удаляются при следующем `nm install`. В Windows `nm uninstall` не может удалить relay, пока браузер его держит (строка relay «занят запущенным процессом», код 1): закройте браузер и повторите команду. В macOS и Linux файл удаляется сразу.
- Демон, запущенный relay, работает до конца сеанса. Если TLS настроен и порт 13579 свободен, тот же демон обслуживает и `wss`; иначе в журнале — предупреждение, и демон работает только для расширения, пока пользователь не остановит оригинал или не сохранит сертификат в мастере.
- Origin сайта, который получают модули, через расширение берётся у браузера, а не у страницы.
- Если хост не установлен или демон не запускается, расширение отдаёт странице её обычный `WebSocket`, то есть оригинальный NCALayer, если он запущен. Пока хост установлен, сайты идут в OpenNCALayer, даже когда оригинал запущен. Чтобы вернуться к оригиналу, выполните `nm uninstall` и перезапустите браузер (или завершите демон) либо отключите расширение: сразу после `nm uninstall` браузер продолжает работать через уже запущенные relay и демон. После отключения расширения открытые вкладки в Chromium и Firefox 128 и новее сами переходят на обычный `WebSocket`, но только для новых сокетов и `fetch`; в Firefox ESR 115 их нужно перезагрузить (см. ниже). Сокет, который уже был открыт через расширение, на оригинал не переключается: в Firefox 128 и новее при следующем `send` страница получает `error` и `close` с кодом 1006 (как браузер, не изнутри `send`, а следующей задачей), и ждущий ответа запрос завершается ошибкой; сокет, который только ждёт сообщений, ничего не получает и остаётся открытым, пока страница его не закроет или снова не обратится к NCALayer (новый сокет, `fetch` или `send`). В Chromium это поведение e2e не проверяет.
- В Firefox до 128 (ESR 115) content scripts не умеют `world: "MAIN"`. Там шим работает как обычный content script: подменяет `WebSocket` и `fetch` страницы через Xray (`window.wrappedJSObject`, `exportFunction`, `cloneInto`) и передаёт кадры мосту напрямую, без событий на `document`. В Firefox 128 и новее шим, как и в Chromium, работает в мире страницы.
- Firefox ESR 115: после отключения, удаления, перезагрузки или обновления расширения перезагрузите открытые вкладки. До перезагрузки `WebSocket` и `fetch` в них бросают `TypeError: can't access dead object` — на любых сайтах, не только NCALayer. Firefox уничтожает content script вместе с функциями, которые он отдал странице, и не даёт ему ничего сделать перед этим.

Linux, Firefox из snap и Flatpak:
- `nm install` находит Firefox по `~/.mozilla` или `~/.config/mozilla`. Профиль Firefox из snap лежит в `~/snap/firefox/`, и команда может пропустить Firefox («пропущен»). Тогда создайте каталог `mkdir -p ~/.mozilla` и повторите `nm install`: манифест ляжет в `~/.mozilla/native-messaging-hosts/`, откуда Firefox из snap 135 и новее читает его через xdg-desktop-portal.
- Firefox из Flatpak запускает хосты native messaging только через `xdg-native-messaging-proxy` на хост-системе. OpenNCALayer его не ставит и права Flatpak не меняет: это настраивается вручную.
- Оба варианта не проверялись.

## Отличия и ограничения расширения

- Подкласс `WebSocket` страницы (`class X extends WebSocket`) для адреса NCALayer создаёт обычный `WebSocket`, а не экземпляр `X`, во всех браузерах: такой сокет делает расширение. В Firefox ESR 115 так же и для любого другого адреса: функцию, которую content script отдал странице, Firefox вызывает с ней самой в `new.target`, и класс страницы до шима не доходит.
- В Firefox ESR 115 после отключения, удаления или обновления расширения открытые вкладки нужно перезагрузить: до этого `WebSocket` и `fetch` в них не работают.
- Chrome 109 (последний Chrome для Windows 7) заявлен минимальной версией, но не проверялся.
- Safari не поддерживается.
- Сокеты, которые сайт открывает из Web Worker, не подменяются: для них по-прежнему нужны `wss` и CA.
- Одна вкладка держит через расширение не больше 256 открытых сокетов, все вкладки профиля вместе — не больше 4096 (у демона). Сокет сверх лимита сразу закрывается с кодом 1006, как при отказе в соединении.
- Пути native messaging для Yandex Browser и Opera не проверены. В Windows они читают ключ реестра Chrome; в Linux для Yandex Browser манифест пишется в `~/.config/yandex-browser/NativeMessagingHosts/`.
