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

Что делает `run_port_operation`: читает `plugins/<порт>/plugin.toml` и модуль; ставит их в `PluginRegistry` (`PackageHash::Loose` через `loose_package_hash`) с `ManualLimits::desktop()` — тем же определением, что у проводки рабочего стола (`oncl_core::plugins::ManualLimits`, см. ниже; `RunOptions.limits` подставляет другие); регистрирует политику объявленных операций `allow_declared_with_pki` с эндпоинтами `oncl_plugin::NCA_PKI_ENDPOINTS` (одна константа и у проводки рабочего стола) — GET и POST для OCSP и TSA (`DEFAULT_OCSP`, `DEFAULT_TSA`); готовит ключ (фикстура `user-rsa-sign`, сертификат перевыпущен временным корнем, AIA — OCSP-ответчик по умолчанию, ответчики OCSP и TSA — моки под тем же корнем, часы — `NOW` фикстур); затем `plugin_prepare` → `ConsentSummary` → `UserConfirmation::after_user_confirmed` (публичный конструктор: единственный способ, как делает его интерфейс) → `approve` → `plugin_call_approved`. Ничего со стороны плагина не подменяется.

Негативный тест на порт: `RunOptions::tampered(операция, "поле = значение", "поле = другое")` правит манифест (ТАМПЕР), и вызов обязан быть отвергнут `options-mismatch` (`TicketRefusal::Options`), `NotApplied`, ключ не применён.

## Как добавить порт

1. В `plugins/<порт>/plugin.toml`: `[[operations]]` (форма — [plugins.md](../design/plugins.md)), `min_core` ≥ `operations_min_core()`, версия плагина и `Cargo.toml` (и `plugins/Cargo.lock`) поднимается; хеши `plugins/workspace/registry.toml` не трогаются (выпуск — MP11).
2. Запрос в шаблоне — **ровно** то, что шлёт страница (§8 инвентаризации); профиль — **ровно** то, что порт передаёт в ключевой импорт; `imports` — только реально вызываемые (лишний отвергает `plugin-ops-check`, недостающий — `Denied` на вызове), `network = "pki"` у любой операции с ключом.
3. Файл `tests/plugin_ports_manual/<порт>.rs` + `mod` в `plugin_ports_manual.rs`: по тесту на операцию (положительный с оракулом) и негативный с `tampered`.
4. `cargo xtask plugin-ports-manual <порт>`.

## Лимиты рабочего стола (`ManualLimits::desktop()`)

Одно определение для проводки (`crates/openncalayer/src/plugins/manual.rs`: `ManualLimits::desktop().instance` при установке каждого плагина) и для харнесса: `oncl_core::plugins::ManualLimits`. Умолчания SDK не менялись (библиотека консервативна).

Что показал прогон реальных портов (отладочная сборка, лимиты с запасом, пики из временной инструментации):

| операция | метаданные сверх `max_transfer` | линейная память гостя | ответ |
|---|---|---|---|
| `sign-xml`, `sign-xml-element` (1 КиБ…64 КиБ) | ≈ 65,0 МБ, от документа не зависит (XML ex и XAdES B/T/LT — то же) | 1,2–1,7 МБ | 3,5–67 КБ |
| CMS и raw: 1 КиБ | 2,4 МБ | 1,2 МБ | 2,2–5,7 КБ |
| CMS и raw: 1 МиБ | 135 МБ | отделённая 9–11 МБ, с вложением 14,5 МБ | вложенная CMS 1,33 × документ |
| CMS и raw: 4 МиБ | 539 МБ | 32–40 МБ, с вложением 53 МБ | |
| CMS и raw: 12 МиБ | 1,61 ГБ | 98–123 МБ, с вложением 153 МБ | 16,0 МиБ |

* Метаданные CMS/raw = `max_transfer` + 128 × документ + 2,2 МБ: каждый ключевой импорт допускает свои аргументы по 128 байт метаданных на байт (`host_call_metadata`). XML: ≈ 65 МБ — проверка подписанного документа после подписи (`oncl_xml::verification_metadata_bound`), от размера документа не зависит.
* Память гостя ≤ 12,1 байт на байт документа (вложенная CMS) + 3 МиБ; передача — документ в base64 (запрос) и 4/3 документа в ответе: **16 МиБ передачи не вмещает документ в 12 МиБ** (ответ 16,0 МиБ).
* Сверх этого вызов резервирует `8 × max_transfer + max_memory` памяти и `max_transfer` метаданных (`call_scratch`). Метаданные считаются и в память.

`manual_call_budget(лимиты, вид, длина)` суммирует это с запасом (аргументы +4 КиБ, CMS/raw +4 МиБ, XML — граница `verification_metadata_bound`, +8 МиБ памяти); `Engine::plugin_prepare` / `plugin_call_approved` берут и тут же отдают эти резервы из бюджета контекста и при нехватке отказывают **до ключа и до согласия** подкодом `resource-budget` (нет временного хранилища для XML — `no-temporary-store`). Раньше недобор метаданных у XML-подписи Kalkan давал `AfterKeyUse(MetadataLimit)` — ключ применён, ответа нет.

### Выбор `max_document` (память процесса, а не бюджеты на бумаге)

Бюджеты — учётные потолки, не выделенная память; платформа обещает ограниченный объём ОЗУ (контрольный процесс: 1 ГиБ). Измерено: пик рабочего набора процесса теста (psutil, отладочная сборка, весь харнесс с фикстурами и самим документом) при вложенной CMS документа максимального размера (`limits::the_attached_cms_of_the_largest_document_signs` с `ONCL_PORT_MAX_DOC_MIB`; базовая линия — малый документ — 20 МиБ):

| `max_document` (размер, под который считаются лимиты) | передача | линейная память | бюджет метаданных | бюджет памяти | резерв по модели вложенной CMS, `CmsEx` (память / метаданные; бюджеты считаются по самому большому вызову — `XmlEx`, поэтому метаданных в них больше) | пик рабочего набора | запас до 1 ГиБ по бюджету памяти |
|---|---|---|---|---|---|---|---|
| 2 МиБ | 5 МиБ | 60 МиБ | 384 МиБ | 512 МиБ | 374 / 266 МиБ | 62 МиБ | 2,0× |
| **4 МиБ** | 9 МиБ | 112 МиБ | **704 МиБ** | **896 МиБ** | 718 / 526 МиБ | 104 МиБ | 1,14× |
| 8 МиБ | 17 МиБ | 216 МиБ | 1280 МиБ | 1664 МиБ | 1406 / 1046 МиБ | 247 МиБ | бюджет 1,6 ГиБ > 1 ГиБ |
| 16 МиБ | 33 МиБ | 424 МиБ | 2368 МиБ | 3136 МиБ | 2782 / 2086 МиБ | 458 МиБ | бюджет 3,1 ГиБ — втрое выше |

Выбор: **64-бит — 4 МиБ**. Реальный рабочий набор и при 16 МиБ (458 МиБ) укладывается в 1 ГиБ, но учётные потолки 8–16 МиБ (1,6–3,1 ГиБ) превышают бюджет машины, а модель «128 байт метаданных на байт» не мы выбирали; меньший предел документа с ясным отказом (`resource-budget`, либо `RequestTooLarge` у самого шаблона — до согласия) лучше многогибибайтных потолков. Форма операции принимает документ до объявленного в манифесте `max_bytes` (по умолчанию 16 МиБ), а рабочий стол отказывает выше своего предела. **32-бит — 512 КиБ**: `oncl_plugin::MAX_MEMORY` там 16 МиБ (память гостя 12,1 × 0,5 МиБ + 3 МиБ ≈ 9 МиБ), передача 2 МиБ, бюджеты метаданных и памяти по 192 МиБ.

**`max_document` — не жёсткий предел.** Это размер, под который считаются лимиты; реально документ допускает предполётная проверка по бюджету: при 4 МиБ принимаются документы примерно до 5,3 МиБ (вложенная CMS на 5 МиБ подписывается по-настоящему). Форма Плагинов сужает объявленный в манифесте `max_bytes` до `ManualLimits::desktop().max_document`, чтобы отказ был ясным до выбора файла, а подпись под полем показывает действующий предел. Отказ по размеру документа — `InputLimit` (подкод `resource-budget`); если бюджеты не вмещают даже модуль с пустым документом (движок настроен неверно) — `MemoryLimit` с тем же подкодом.

**Бюджеты 704/896 МиБ — потолки учёта одного движка, а не выделенная память**: измеренный пик рабочего набора при 4 МиБ — около 104 МиБ. Движок документов держит свой бюджет в 1 ГиБ; сумма потолков двух движков больше 1 ГиБ, но реальной памяти сверх измеренного они не добавляют (потолки не выделяются).

**Движок окна Плагинов обязан брать `ManualLimits::desktop().resources`** (со своим `operation_timeout`): с умолчаниями SDK любая XML-операция и любой CMS-документ крупнее ≈ 0,4 МиБ отказываются как `resource-budget`. Страница Плагинов (`oncl_ui::plugin_offer`, `engine_limits()`) так и делает; движок документов (`main.rs`, `desktop_limits()`: 24 часа и умолчания бюджетов) плагинов не держит, ему они не нужны. Предполётная проверка не держит резерв после себя: что никто не займёт место между ней и применением ключа, обеспечивает `max_in_flight = 1`. В сумму `manual_call_budget` входит и ответ модуля (`max_transfer` памяти), поэтому узел с большой передачей и малым документом не проскакивает.

Итоговые значения `ManualLimits::desktop()` (64-бит): `max_document` 4 МиБ, `max_transfer` 9 МиБ, `max_memory` 112 МиБ, `metadata_bytes` 704 МиБ, `memory_bytes` 896 МиБ, остальное — умолчания `ResourceLimits` (`operation_timeout` 5 минут: хост, ждущий пользователя внутри операции, удлиняет его сам, `ResourceLimits { operation_timeout, ..ManualLimits::desktop().resources }`), `fuel` умолчание SDK. `ManualLimits::for_max_document` выводит всё из размера документа: передача = (4/3 документа + 16 КиБ) × 1,5, память = 2 × (13 × документ + 4 МиБ) (но не выше `MAX_MEMORY`), бюджеты = `manual_call_budget` самого большого XML-вызова × 1,1, с округлением вверх.

Проверки: `limits::every_cms_and_raw_operation_signs_a_document_at_the_limit` (все четыре CMS и raw на документе в 4 МиБ, оракулы openssl и репозитория), `the_estimate_signs_and_one_byte_less_is_refused_before_the_key` (все 7 операций: ровно по модели подписывают, на байт меньше метаданных или памяти — `resource-budget` до ключа), `the_default_metadata_budget_refuses_an_xml_signature_before_the_key`, `a_document_over_the_limit_is_refused_before_the_key`, `an_engine_without_a_temporary_store_refuses_xml_before_the_key`.

Прочие настройки, которые показал прогон:

* `EngineServices::with_temporary_store` (XML; без него — `no-temporary-store` до ключа), `with_validation` (онлайн-проверка подписанта), `with_plugin_keys`. Временное хранилище рабочего окна — `TemporaryStore::new(spool)` в том же каталоге `data/spool`, что у движка документов (`desktop_engine`: замок владельца и очистка устаревшего при старте).
* Эндпоинты `network = "pki"`: GET и POST для OCSP и TSA (`oncl_plugin::NCA_PKI_ENDPOINTS`) — подписанта проверяют GET-запросом к OCSP из сертификата, метку времени Kalkan берут GET-запросом; проводка выдавала только POST.
* Операция с `uses.key` без `network = "pki"` не подписывает никогда (`network.rs`).
* Исправлена ошибка `oncl-plugin`: `StoreLimits` с `trap_on_grow_failure` обрывала `memory.grow`, не хватившую топлива на конце кусочка (возобновляемая ситуация), как `MemoryLimit` — вызов портов падал или нет в зависимости от длины документа (350 КБ — падает, 400 КБ — нет, независимо от `max_memory`). `GuestLimits` не считает `OutOfFuel` отказом роста; тест `memory_growth_crossing_a_fuel_slice_is_resumed_not_a_memory_limit`.

Волна 1: `rating1c` (7 операций). `fhs` и `esf-osdkz` не объявлены: шаблон `[[operations]]` не выражает форму их запроса (инвентаризация §8–9); пробы `fhs.rs` и `esf_osdkz.rs` фиксируют поведение порта на ближайшем шаблоне.

## Границы проверок (что оракулы НЕ доказывают)

* Метка времени: проверяется наличие `signatureTimeStampToken` в CMS (отчёт `oncl_pki::cms::report`), но сам токен независимым инструментом не проверяется.
* GOST: ключи ГОСТ проверяют только верификаторы репозитория; `openssl`, `xmldsig_verify.py` — только RSA. В тестах волны 1 ГОСТ-ключ не используется (метка «сырая подпись» без «ГОСТ»).
* `create-raw-sign` проверяет RSA PKCS#1 v1.5 SHA-256.
* Оракул XML отвергает неизвестные преобразования, неоднозначный `Id` (два элемента с одним `Id`) и подпись без ссылок (`the_xml_oracle_rejects_wrapping_shapes`).
* `sign-xml-element`: оба XPath (`tbs`, `parent`) — абсолютные и вводятся текстом; подписываемый элемент обязан иметь атрибут `Id`; форма оригинала «tbs с пустым parent» не покрыта (родитель обязателен: профиль `placement = parent` ⇔ задан `parent`).
* `create-raw-sign` не имеет опций, поэтому негативный тест подмены профиля для него невозможен; остальные 6 операций покрыты.
* `PluginRegistry::install` сам не ограничивает размер wasm (`MAX_WASM` = 16 МиБ проверяет только `Package::read`): хост, ставящий модуль не из пакета, обязан проверить размер сам.
