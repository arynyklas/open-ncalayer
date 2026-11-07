# Порты плагинов в окне ручных инструментов: как собрать wasm и прогнать тесты

Тесты `crates/oncl-core/tests/plugin_ports_manual.rs` прогоняют **настоящие wasm-модули портов** (`plugins/<порт>`) через **настоящий путь ручного вызова** `oncl-core` (дизайн — [manual-plugins.md](../design/manual-plugins.md), инвентаризация — [manual-plugins-inventory.md](../design/manual-plugins-inventory.md)) с **настоящим синтетическим ключом**. Для каждой объявленной `[[operations]]` операции они проверяют, что вызов завершился `Applied`, что ответ порта разбирается как документированный, и что подпись **верна по независимому оракулу**. Объявление, которое отличается от того, что модуль реально передаёт в ключевой импорт, Core отвергает (`options-mismatch`, до ключа): поэтому прогон — это и доказательство объявления.

## Одна команда

```text
cargo xtask plugin-ports-manual [--wasm-dir <каталог>] [--no-build] [фильтр…]
```

Шаги: (1) `cargo build --release --locked --target wasm32-unknown-unknown --workspace` в `plugins/` (в `target/plugin-build`, сеть не нужна: `vendor/`, `Cargo.lock`; ≈ 35 с); (2) `plugin-ops-check --require-wasm` (импорты каждой операции против импортов модуля); (3) `cargo test -p oncl-core --features plugins --test plugin_ports_manual -- --ignored [фильтр…]` с `ONCL_PLUGIN_WASM_DIR`. Фильтр — часть имени теста (`rating1c`, `network`).

Тесты помечены `#[ignore = "needs the built port wasm…"]`: без модулей они не имеют смысла, а обычный `cargo test` не должен собирать 34 модуля. **В CI они не пропускаются**: задача `test` запускает `cargo test --workspace --all-features -- --include-ignored`, и тесты сами собирают `plugins/` в `target/plugin-ports` (как `oncl-port-tests`), если `ONCL_PLUGIN_WASM_DIR` не задан; затем шаг «Plugin operations lint» проверяет импорты по этим модулям с `--require-wasm`. Модули нет — тест падает с сообщением, а не пропускается.

## Окружение

| Переменная | Что |
|---|---|
| `ONCL_PLUGIN_WASM_DIR` | Каталог с `oncl_port_<порт>.wasm` (`-` → `_`). Не задана — тесты собирают `plugins/` сами (`oncl_testkit::plugin::ports_built`). |
| `ONCL_OPENSSL` | OpenSSL 3 с `cms` (иначе `openssl` в `PATH`, на Windows — Git for Windows). Оракул CMS и сырой подписи. |
| `ONCL_PYHANKO_PYTHON` | Python с `lxml` и `cryptography` (иначе `python3`/`python`). Оракул XML-DSig (`tests/support/oracle/xmldsig_verify.py`). Нужного окружения нет — тест падает, не пропускается. |

## Что проверяет оракул

* **CMS**: `oncl_pki::cms::verify` над одобренным документом (и **не** над другим), и `openssl cms -verify -binary -noverify` над ним же (и отказ над другим); сертификат подписанта в CMS — ключа; вложенное содержимое (attached) побайтно равно документу; метка времени — по наличию `signatureTimeStampToken` в отчёте.
* **raw**: RSA PKCS#1 v1.5 SHA-256 открытым ключом сертификата в репозитории **и** `openssl pkeyutl -verify -rawin -digest sha256`.
* **XML**: `oncl_xml::verify` и `xmldsig_verify.py` (lxml: каноникализация, дайджест каждого `Reference` после его преобразований, подпись `SignedInfo` RSA-ключом сертификата, сертификат `KeyInfo` — ключа); структура: какой элемент подписан, куда вставлена подпись, документ без подписи равен исходному; оракул обязан отказать изменённому документу. GOST-подписи оракул не проверяет (`unsupported`): ключи ГОСТ — только репозиторные верификаторы.

## Харнесс (`tests/support/ports.rs`)

Для всех волн; подключается `#[path = "support/ports.rs"] mod ports;`.

```rust
run_port_operation(port, operation, params, &RunOptions) -> PortRun
try_run_port_operation(…) -> Result<PortRun, PluginPrepareError>
RunOptions { tamper: Option<Box<dyn Fn(&str) -> String>>, key: Option<&'static str> }   // RunOptions::tampered(op, from, to)
PortRun { call: ApprovedCall, summary: ConsentSummary, request: String, cert, applications, http_log }
assert_applied(&run) / assert_refused_before_the_key(&run) / reply_json(&run) / from_base64(..)
oracle::verify_cms(cms, content, &cert, attached) -> CmsFacts
oracle::verify_raw_rsa(&cert, data, signature)
oracle::verify_xml(signed, &cert, n) -> XmlFacts;  oracle::assert_xml_rejected(doc, &cert)
```

Что делает `run_port_operation`: читает `plugins/<порт>/plugin.toml` и модуль; ставит их в `PluginRegistry` (`PackageHash::Loose` через `loose_package_hash`) с теми же `InstanceLimits`, что должен иметь рабочий стол (см. ниже); регистрирует политику объявленных операций `allow_declared_with_pki` с эндпоинтами **(то, что показали прогоны; проводка рабочего стола на tip выдаёт только POST и `InstanceLimits::default()` — её правит MP7b, после чего харнесс переключается на общее определение в одном месте)** — GET и POST для OCSP и TSA (`DEFAULT_OCSP`, `DEFAULT_TSA`); готовит ключ (фикстура `user-rsa-sign`, сертификат перевыпущен временным корнем, AIA — OCSP-ответчик по умолчанию, ответчики OCSP и TSA — моки под тем же корнем, часы — `NOW` фикстур); затем `plugin_prepare` → `ConsentSummary` → `UserConfirmation::after_user_confirmed` (публичный конструктор: единственный способ, как делает его интерфейс) → `approve` → `plugin_call_approved`. Ничего со стороны плагина не подменяется.

Негативный тест на порт: `RunOptions::tampered(операция, "поле = значение", "поле = другое")` правит манифест (ТАМПЕР), и вызов обязан быть отвергнут `options-mismatch` (`TicketRefusal::Options`), `NotApplied`, ключ не применён.

## Как добавить порт

1. В `plugins/<порт>/plugin.toml`: `[[operations]]` (форма — [plugins.md](../design/plugins.md)), `min_core` ≥ `operations_min_core()`, версия плагина и `Cargo.toml` (и `plugins/Cargo.lock`) поднимается; хеши `plugins/workspace/registry.toml` не трогаются (выпуск — MP11).
2. Запрос в шаблоне — **ровно** то, что шлёт страница (§8 инвентаризации); профиль — **ровно** то, что порт передаёт в ключевой импорт; `imports` — только реально вызываемые (лишний отвергает `plugin-ops-check`, недостающий — `Denied` на вызове), `network = "pki"` у любой операции с ключом.
3. Файл `tests/plugin_ports_manual/<порт>.rs` + `mod` в `plugin_ports_manual.rs`: по тесту на операцию (положительный с оракулом) и негативный с `tampered`.
4. `cargo xtask plugin-ports-manual <порт>`.

## Настройки хоста, которые прогон показал обязательными

Те же значения должна иметь проводка рабочего стола (`crates/openncalayer/src/plugins/manual.rs`):

* `InstanceLimits { max_memory: 128 МиБ, max_transfer: 16 МиБ, .. }`: умолчания (1 ГиБ / 256 МиБ) вместе с `ResourceLimits::default()` дают `Processing(MemoryLimit)` — вызов резервирует `8 × max_transfer + max_memory`.
* `ResourceLimits { metadata_bytes: 256 МиБ, .. }`: XML-подпись Kalkan резервирует ≈ 61 МиБ метаданных, бюджет по умолчанию — 64 МиБ (иначе `AfterKeyUse(MetadataLimit)`: ключ применён, ответа нет).
* `EngineServices::with_temporary_store` (XML), `with_validation` (онлайн-проверка подписанта), `with_plugin_keys`.
* Эндпоинты `network = "pki"`: GET и POST для OCSP и TSA — подписанта проверяют GET-запросом к OCSP из сертификата, метку времени Kalkan берут GET-запросом.
* Операция с `uses.key` без `network = "pki"` не подписывает никогда (`network.rs`).

Волна 1: `rating1c` (7 операций). Волна 2: `fhs` (`sign-xml`, `sign-text`: `args` — объект), `esf-osdkz` (`sign-plain-data`: корневой запрос, `raw` над текстом; Core отказывает на управляющих/bidi/невидимых символах).

Волна 3: `energy` (4 операции `sign-cms-*`), `eproc` (2), `efactoring` и `market` (по 5: `sign-text-*` ×4, `sign-xml`), `dogovor24` (`sign-cms`). `qiwi.signXml` и `efactoring.xml` с элементом не объявлены: порт передаёт `transforms`, которых профиль не выражает (инвентаризация §9, W3-1/W3-2; пробы `qiwi.rs`, `efactoring.rs`). Общие таблицы негативных тестов (подмена профиля, удаление импорта) — `plugin_ports_manual/wave3_kit.rs`.

## Границы проверок (что оракулы НЕ доказывают)

* Метка времени: проверяется наличие `signatureTimeStampToken` в CMS (отчёт `oncl_pki::cms::report`), но сам токен независимым инструментом не проверяется.
* GOST: ключи ГОСТ проверяют только верификаторы репозитория; `openssl`, `xmldsig_verify.py` — только RSA. В тестах волны 1 ГОСТ-ключ не используется (метка «сырая подпись» без «ГОСТ»).
* `create-raw-sign` проверяет RSA PKCS#1 v1.5 SHA-256.
* Оракул XML отвергает неизвестные преобразования, неоднозначный `Id` (два элемента с одним `Id`) и подпись без ссылок (`the_xml_oracle_rejects_wrapping_shapes`).
* `sign-xml-element`: оба XPath (`tbs`, `parent`) — абсолютные и вводятся текстом; подписываемый элемент обязан иметь атрибут `Id`; форма оригинала «tbs с пустым parent» не покрыта (родитель обязателен: профиль `placement = parent` ⇔ задан `parent`).
* `create-raw-sign` не имеет опций, поэтому негативный тест подмены профиля для него невозможен; остальные 6 операций покрыты.
* `PluginRegistry::install` сам не ограничивает размер wasm (`MAX_WASM` = 16 МиБ проверяет только `Package::read`): хост, ставящий модуль не из пакета, обязан проверить размер сам.
