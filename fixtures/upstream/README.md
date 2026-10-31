# Фикстуры наблюдателя за оригиналом

Синтетические файлы для тестов `cargo xtask upstream` (`xtask/tests/upstream_*.rs`). Всё здесь написано и собрано нами; ни одного файла оригинального NCALayer и ни одной его части здесь нет. Как и другие синтетические фикстуры, файлы распространяются под лицензией репозитория (Apache-2.0).

| Файл | Содержимое |
|---|---|
| `manifest.json` | синтетический манифест по форме `ncalayer.der`: обёртка `{"ncalayer": {…}}`, `syspkgs` строкой через запятую, 5 `disturls` (3 пустые), 4 бандла (2 с `required: true`, один с URL на частный адрес) |
| `download-page.html` | страница загрузок нашего сочинения с разметкой таблицы загрузок: ссылки `download.php?key={{key_…}}` и опубликованные после них SHA-1 `{{sha1_…}}` (тесты подставляют значения) |
| `error.html` | страница ошибки нашего сочинения, которую сайт мог бы отдать со статусом 200 вместо файла |
| `src/` | наши Java-исходники бандлов и лаунчера |
| `bundle-a.jar` | бандл `kz.example.demo` 1.0.0: `DemoModule` (метод `sign` с аннотацией `NCALayerMethod`, константы `SIGN_ERROR`, `http://tsp.example.invalid/`, порт 13579), `Activator`, библиотечный класс `com.thirdparty.lib.Util`, `natives/linux-x86-64/libdemo.so` (8 байт), `keystores/trusted.jks` (доверенный `../synthetic/root-rsa.cer`), `keystores/local.jks` (ключ RSA `demo-key`, пароль `Qwerty12`), `MANIFEST.MF` с OSGi-заголовками |
| `bundle-a-repack.jar` | те же записи в обратном порядке и с другой датой |
| `bundle-a-v2.jar` | версия 1.1.0: добавлен метод `verify(String)` и константа `VERIFY_FAILED` |
| `app.jar` | «лаунчер»: `kz.example.launcher.Main`, `ncalayer.der` (синтетический манифест той же формы, подписанный до подстановки хешей) и `trusted.jks` |
| `installer.sh` | текстовый заголовок нашего сочинения, дополненный до 4096 байт, и `app.jar` |
| `lite.exe` | `MZ`, заполнитель, строка `go1.0-synthetic` и gzip-поток программы (`MZ` + 512 байт + `app.jar`) — подобие Go-дроппера |
| `dist.zip` | `NCALayer/ncalayer.sh` (= `installer.sh`) и синтетический JRE: `jre/release`, `jre/bin/java`, `jre/lib/rt.jar` (пустой ZIP) |
| `inno-like.exe`, `msi-like.msi`, `fake.dmg` | только сигнатуры форматов (Inno Setup, OLE, трейлер `koly`), для распознавания формата |
| `tzdb.dat` | формат `TZDB` с одной версией `2026z` |
| `manifest.der` | `manifest.json`, подписанный CMS (ГОСТ 34.10-2015-512) синтетическим подписантом `CN=NCALayer, O=OpenNCALayer synthetic, C=KZ`, выпущенным `../synthetic/root-gost2015` |

## Пересоздание

Нужны JDK 17 или новее (`javac`, `jar` с `--date`, `keytool`), `gzip`, `sha256sum` и `cargo`. Скрипт пересобирает JAR и дистрибутивы, подставляет их sha256 в `manifest.json` и подписывает его (`cargo xtask upstream make-fixtures`):

```sh
LANG=C.UTF-8 bash fixtures/upstream/make.sh
```

Ключи `keytool` случайны, поэтому `bundle-a*.jar` и всё, что от них зависит, меняется при каждом пересоздании; подпись ГОСТ рандомизирована, поэтому `manifest.der` не воспроизводится байт в байт; тест `committed_manifest_matches_json` сверяет его содержимое с `manifest.json`.
