# Плагины в окне ручных инструментов: модель разрешений

**Статус:** проект для решения пользователя (вариант A выбран: плагины остаются в ручном окне, модель разрешений переделывается). Кода нет. База: ветка платформы, tip `08891678`.
**Связано:** [плагины](plugins.md), [платформа §8.3](platform.md), план `docs/superpowers/plans/2026-11-02-platform.md` (Task 21, Task 30), отчёты U03 `platform-ui-task-30/{report,rereview2}.md`.
**Решение за один абзац:** гибрид. (1) Манифест плагина получает `[[operations]]`: имя операции, типизированные параметры, явный список импортов, виды применения ключа и откуда берутся подписываемые байты. (2) Хост (не плагин) строит запрос из шаблона и выдаёт `PluginPermission` на вызов только в пределах объявления. (3) Каждое применение ключа плагином привязано к дайджесту, который пользователь увидел в окне согласия: байты равны замороженному документу (`bound`) либо воспроизведены детерминированным прогоном-планом и показаны в Core-построенном превью (`derived`). (4) `KeysSignRaw` над байтами, которые плагин выдумал сам, в ручном окне не предлагается. (5) ABI WASM не меняется (`ABI_VERSION = 1`), 34 порта не пересобираются, меняются их `plugin.toml`.

---

## 1. Конфликт (что именно сломано и где)

Задача U03 «плагины в ручном окне» остановлена владельцем и ревьюером (`report.md:176-181`, `rereview2.md` §4). Проверено по исходникам tip-а; номера строк — этого worktree.

| # | Факт | Где |
|---|---|---|
| C1 | Разрешение — точный host-issued кортеж `(plugin_id, operation, CallerContext, imports, keys, files, endpoints, pki_endpoints)`; нет `Deserialize`, нет wildcard | `crates/oncl-core/src/plugins.rs:27-38`, `matches` `:87-91`, `permits` `:92-94` |
| C2 | Авторизация двойная: нужно совпадение и в grant операции, и в политике реестра; ключ дополнительно через `grant.allows_key` | `plugins.rs:329-342` (`Backend::authorize`), `:513-533` (`plugin_call`), `:559-576` (фильтр импортов) |
| C3 | Манифест не знает операций: только `modules` (имена WSS-модулей) и булевы `Capabilities` (`keys, dialogs, files, key_files, page_files, settings, shared, builtin` + префиксы http/origins) | `crates/oncl-plugin/src/manifest.rs:52-54`, `:114-143` |
| C4 | `call_headless` принимает только `request: &str`; **строки операции в нём нет**. `operation` — метка хоста в `PluginCall`, плагину не передаётся; `request` — собственный WSS-JSON плагина | `crates/oncl-plugin/src/headless.rs:134-145`; `plugins.rs:179-182`, `:599-606` |
| C5 | Таблицы «capability → Import» нет. Импорты назначает оператор: CLI — `--allow-import/--key/--plugin-pki-endpoint/--caller` (`crates/oncl-cli/src/plugin.rs:140-150`, вызов `:253`), сервер — `PluginGrant{token,operation,imports[],keys[],pki_endpoints[]}` (`crates/oncl-server/src/config.rs:175-185`, сборка `crates/oncl-server/src/service.rs:322-360`). Единственная связь манифест↔импорт — пересечение при компиляции (`Compiled::imports()`) |
| C6 | Headless жёстко отвергает все интерактивные импорты (`Dialog*`, `KeysChoose/Select/FlowOpen/FlowPick`, `File{Open,Save,Choose,ChooseKind,OpenEx}`, `CoreOpenWindow`, `Keystore*`) как `InteractionRequired` | `headless.rs:105-130` |
| C7 | Подписывающих импортов не один, а шесть: `KeysSignRaw` (`plugins.rs:368-410`), `KeysSignCms/CmsEx` (`plugins/cms.rs:61-98`), `KeysSignXml/XmlEx/Xades` (`plugins/xml.rs:73-140`). **Во всех подписываемое содержимое выбирает плагин** (`args.data`, `args.content`, `xml`). Уточнение к U03 («только `KeysSignRaw`»): структуру CMS/XML строит Core, но содержимое — плагин |
| C8 | Гард применения ключа не отличает плагин от документа: `KeyUseEvent{operation_id, key_id, action, batch_item}` (`crates/oncl-core/src/keys.rs:434-439`), плагин применяет ключ как `Action::Sign` (`policy.rs:8-12`). Десктопный `ConsentGuard` разрешает «N применений ключа K для operation O и Action::Sign» (`crates/oncl-ui/src/signing/runner.rs:60-125`), т.е. выданное для плагина согласие покрыло бы любые байты, а согласие вида `UserConsent` привязано к `items` (`crates/oncl-ui/src/signing/controller.rs:69-110`), которых у плагина нет |
| C9 | У ручного вызова нет Origin: `encode_input(request, caller.browser_origin(), ..)` (`headless.rs:144-145`); `CallerContext::LocalOperator(String)` даёт `None`. Порты, проверяющие сайт (`qoltanba` и др.), ответят `INVALID_ORIGIN`. Подставлять Origin нельзя (Task 21, `plan:396`) |
| C10 | Окна интерактивного (WSS) пути показывают текст плагина (`detail`) в доверенной области (`plugins.md`, «keys_choose … в окнах видны сайт, название плагина и detail»). Для ручного окна это недопустимо (`plan:508`: «тексты плагина не переписывают trusted область») |
| C11 | В `oncl-ui` исполнения плагинов нет; зависимость от `oncl-core/plugins` уже в замыкании бинаря (отчёт U03 §5) |

**Итог конфликта.** Ручному окну нужно, чтобы *пользователь* одобрил применение ключа, видя *что* подписывается. Сегодня (C1–C5) разрешение хост выдаёт вслепую относительно содержимого, манифест ничего не объявляет, подписываемые байты выбирает плагин (C7), гард их не видит (C8), а большинство портов не работают без диалогов и Origin (C6, C9). Операции нет ни в ABI, ни в манифесте, поэтому окну нечего показать и не к чему привязать согласие.

Инвентаризация портов (грубо, `grep` исходников `plugins/*/`; в MP0 заменяется точным `Compiled::imports()`): `plugin.toml` — 34, у всех `keys = true`, 35 имён `modules`; `sign_cms_ex` — 26, `sign_xml` — 18, `sign_xml_ex` — 9, `sign_cms` — 4, `sign_xades` — 1; **`sign_raw` — 7** (`acbank, arta, devart, esf-osdkz, rating1c, taxtech, uchet-esf`); выбор ключа диалогом `keys::select` — 18, `keys::choose` — 4.

## 2. Инварианты (что решение обязано держать)

1. **Пользователь, а не манифест и не плагин, одобряет применение ключа.** Манифест — верхняя граница (что плагин *может* запросить), одобрение — отдельный акт для каждого вызова.
2. **Текст доверенной области строит хост**: id и локализованное `name` плагина, перечисление импортов/ключа/файлов/адресов из объявления, SHA-256 и имена документов, превью байтов, построенное Core. Ни `label`, ни `args`, ни `detail` плагина не попадают в доверенную область; `label` показывается только в рамке «от плагина».
3. **Согласие привязано к байтам**: каждое применение ключа плагином сверяется с дайджестом из согласия *до* `Engine::sign` (порядок как в `plugins.rs:380-384`). Расхождение — `PermissionDenied`, `AppliedState::NotApplied`.
4. **Согласие не переживает вызов**: ни постоянных ручных grant, ни переноса между операциями/ключами/версиями пакета.
5. **Серверу/CLI не нужен человек, но и не нужен автоответ**: grant оператора — точный и валидируется против объявления; интерактивные импорты по-прежнему `InteractionRequired`.
6. **Нет нового доверия к плагину**: рабочий WASM по-прежнему ограничен `InstanceLimits`, fuel, бюджетом ресурсов Core.

## 3. Модели

Общая терминология: **объявление** — `[[operations]]` манифеста; **план** — прогон WASM без применения ключа, фиксирующий, что плагин собирается подписать; **одобрение** — `PluginApproval`, результат согласия.

### Модель A — операционные гранты + согласие по дайджесту (объявление + план)

Суть: манифест объявляет операции; хост строит запрос; для `derived`-содержимого запускается план; пользователь одобряет список «ключ × вид × дайджест»; реальный вызов проверяет каждое применение.

- **Что видит и подтверждает пользователь.** Страница согласия (хост): `<name плагина>` v`<version>` (`id`, SHA-256 пакета); операция `<name>` и рамка «от плагина: <label>»; файлы: имя + размер + SHA-256 каждого параметра `document`; ключ: alias + серийный/отпечаток сертификата + субъект; **каждое применение ключа** одной строкой: `<вид: CMS|CMS+TSA|XML|XAdES-T|raw>`, `документ <имя> (SHA-256 …)` для `bound` либо `данные, составленные плагином: N байт, SHA-256 …`, Core-превью (до 8 КиБ экранированного текста/hex: начало и конец); сеть: перечень объявленных адресов; фраза «плагин получит подпись». Кнопки «Подписать»/«Отмена»; подпись — только после ввода пароля ключа в уже существующем потоке окна.
- **Что может плагин.** Только импорты, перечисленные в объявлении ∩ `Compiled::imports()` ∩ интерактив, который Core отвечает сам (§3.5); применять ключ — только видом из объявления, только на байты из одобрения, не чаще указанного числа раз.
- **Чего не может.** Выбрать другой ключ, подписать другие байты, вызвать импорт вне объявления, сменить операцию, увидеть секрет/путь, показать текст в доверенной области.
- **`KeysSignRaw`.** `bound` (байты равны замороженному параметру) — допускается; `derived` — в ручном окне **не предлагается** (см. решение R4, вопрос Q1). Привязка raw к виду «документ» делает raw честным: пользователь видит файл, который подписывается как есть.
- **Headless/сервер.** Grant оператора ⊆ объявление; для `derived` требуется явный флаг `plugin_bytes = true` в `PluginGrant` (оператор сознательно разрешает «плагин выбирает байты»); `bound` проверяется на самом вызове по входным частям запроса. Плана и человека нет, автоответа нет.
- **Аудит.** BEGIN/FINAL применения ключа несут plugin id, SHA-256 пакета, имя операции, вид, SHA-256 и длину содержимого, caller.
- **Совместимость.** Меняются только `plugin.toml` (+`min_core`), ABI и wasm не меняются.
- **Минусы.** Самая сложная реализация (план, детерминизация времени/random, превью); пользователь всё же оценивает `derived`-байты по превью — предел честности.

### Модель B — только хост-подписание: плагин возвращает типизированный запрос

Суть: плагины не вызывают `keys_sign_*`; они возвращают `SignRequest{documents|refs, profile}`, хост подписывает через фасады Core и обычную страницу согласия — тот же путь, что у встроенных инструментов (`UserConsent.items/profile`, `controller.rs:69-110`).

- **Что видит пользователь.** Ровно то же, что для встроенного Sign: документы, формат и опции, ключ. Согласие строится по `profile`, а не по тексту плагина.
- **Что может плагин.** Готовить входы (разбор, XML-шаблон, PDF-отчёт) и потреблять выходы (ответ).
- **Raw.** Невозможен по построению: нет импорта; байты для подписи — это документы/refs, которые видит пользователь.
- **Headless/сервер.** Аналогично: плагин возвращает запрос, сервер подписывает по grant (action/ключ), без автоответа.
- **Аудит.** Максимально чистый: единственный источник применения ключа — хост, plugin id в BEGIN/FINAL как контекст.
- **Совместимость.** **Ломает ABI и все 34 порта.** Порты — порты NCALayer-модулей: `keys_select` → `sign_cms_ex` → дальнейшая логика с результатом подписи (CAdES-T → `tsp_stamp`, добавление отчёта и т.п.; 26 портов зовут `sign_cms_ex` посреди логики). Нужен ABI v2 с двухфазным протоколом (`oncl_prepare` → хост подписывает → `oncl_finish(signatures)`), переписывание каждого порта и всех `oncl-port-tests` (паритет с оригиналом). Порты, где подписанное нужно плагину для следующего шага (многошаговые), не укладываются в «вернуть запрос».
- **Вердикт.** Лучшая модель безопасности, неприемлемая цена для существующих портов сейчас; годится как целевой ABI v2.

### Модель C (рекомендуемая) — гибрид A + B там, где B дёшево

То же, что A, плюс правило «чем меньше доверия — тем ближе к B»:

1. Для видов `cms, cms_ex, xml, xml_ex, xades` Core уже строит контейнер: согласие описывает его **так же, как B** (профиль/формат/опции от Core, а не от плагина). Плагин поставляет только содержимое, и оно привязано (`bound`) или показано (`derived`).
2. `raw` — **только `bound`**. Операции портов, где raw строится из вычисленных байт (JWS-подобные `acbank`, `esf-osdkz` и др.), в ручном окне недоступны, пока для них нет B-входа (ABI v2, MP8, не блокирует эту работу). Серверу/CLI они остаются доступными через явный `plugin_bytes = true`.
3. ABI v2 (B) — отдельное будущее изменение; манифест A (`kind=…`, `content=…`) спроектирован так, чтобы операция позже переехала на `sign_request` без изменения интерфейса окна.

**Рекомендация: C.** Причины: ABI/wasm не трогаются (34 порта сохраняют паритет и тесты); согласие строится хостом из объявления и из Core-превью; raw над придуманными байтами в ручном окне невозможен; деградация — отказ до применения ключа, а не молчаливый allow.

### Сводная таблица

| | A | B | C (рек.) |
|---|---|---|---|
| ABI/wasm 34 портов | без изменений | ABI v2, переписать все | без изменений |
| Манифест | `[[operations]]` | `[[operations]]` + typed sign | как A |
| Привязка к байтам | дайджест (bound/derived) | по построению | дайджест, raw только bound |
| Plugin-chosen raw в ручном окне | отказ/запрет | невозможен | отказ |
| Сложность | высокая (план) | очень высокая | высокая |
| Порты в ручном окне | кроме derived-raw и origin-only | после переписывания | кроме derived-raw и origin-only |

## 3.5 Интерактивные импорты в ручном окне (общая часть A/C)

Порты зовут `keys::select` (18) и `keys::choose` (4) — без них не работают (C6). Решение: в ручном режиме Core отвечает на ключевой выбор **ключом, который пользователь уже выбрал в окне хоста**; никакого автосогласия на применение:

- `Mode::Manual` задаётся хостом при `PluginBindings::with_interaction(&dyn PluginInteraction)`; без него поведение прежнее (`InteractionRequired`, C6).
- `KeysSelect/KeysChoose/KeysFlowOpen/KeysFlowPick` → Core оценивает фильтр плагина (`Filter/FilterMore`, те же функции, что в `oncl-flows`) против сертификата выбранного ключа: подходит — возвращает `Chosen{handle, alias, certificate}` для единственного привязанного ключа; не подходит — `None` («отмена окна», плагин сам выдаёт свою ошибку). Секрет и путь хранилища плагину не передаются (как в интерактивном пути).
- `DialogMessage/DialogConfirm/DialogChoice` → через `PluginInteraction` рисуются в рамке «текст плагина» (обычный текст, не разметка, длина ограничена); ответ пользователя **не является согласием на подпись**.
- `DialogPassword/DialogReader/DialogCsr/DialogImport`, `File*`, `CoreOpenWindow`, `Keystore*` — по-прежнему `InteractionRequired` (документы приходят параметрами, пароли — через поток ключа хоста).
- Сервер/CLI: `PluginInteraction` не передаётся — C6 без изменений.

## 4. Рекомендуемая модель в деталях (C)

### 4.1 Манифест

Новая таблица, `deny_unknown_fields` как у остального манифеста; формат версионируется `min_core` пакета (старое ядро отвергает неизвестное поле, `manifest.rs:66,103`). Пример (порт `qoltanba`):

```toml
min_core = "0.1.0-alpha.7"            # поднимается там, где есть [[operations]]

[[operations]]
name    = "sign-file"                  # ^[a-z][a-z0-9-]{0,31}$, уникально в плагине
module  = "kz.btsdigital.qoltanba.CMSSignUtil"   # одно из `modules`
manual  = true                         # показывать в ручном окне
server  = false                        # разрешить grant сервера/CLI
request = '{"module":"kz.btsdigital.qoltanba.CMSSignUtil","method":"signFileBytes","args":["{file:base64}"]}'
label   = { ru = "Подписать файл", kk = "Файлға қол қою", en = "Sign a file" }   # только рамка «от плагина», ≤ 80 симв.

[[operations.params]]
name = "file"
kind = "document"                      # document | text | choice | flag | locale
max_bytes = 16777216                   # ≤ InstanceLimits.max_transfer / 4 (base64)

[operations.uses]
imports  = ["keys_select", "keys_describe", "keys_sign_cms_ex", "ocsp_fetch", "hash"]   # ⊆ Compiled::imports()
network  = "pki"                       # none | pki | [exact endpoints]
interactive = ["keys_select"]          # ⊆ imports; только отвечаемые Core (§3.5)

[[operations.uses.key]]
kind    = "cms_ex"                     # raw | cms | cms_ex | xml | xml_ex | xades
content = "param:file"                 # param:<имя> -> bound | "derived"
max_uses = 1
```

Правила проверки при разборе (в `Manifest::from_toml`, ошибка → пакет не устанавливается):

- `request` — валидный JSON после подстановки пробных значений; плейсхолдеры `{<param>[:base64|:text]}` — только объявленные параметры, ровно один раз на документ; запрос после подстановки максимума ≤ `max_transfer` (иначе операция недоступна, честный лимит, а не усечение).
- `uses.imports ⊆ Compiled::imports()` проверяет установка (WASM известен), `interactive ⊆ {keys_select, keys_choose, keys_flow_open, keys_flow_pick, dialog_message, dialog_confirm, dialog_choice}`.
- Любой `key`-импорт в `imports` требует соответствующей строки `[[uses.key]]`: `keys_sign_raw`→`raw`, `keys_sign_cms`→`cms`, `keys_sign_cms_ex`→`cms_ex` и т.д.; `Capabilities.keys = true` обязателен.
- `content = "param:x"` — `x` имеет `kind=document` (для `xml/xml_ex/xades` допустим `text`); `raw` с `derived` в манифесте **синтаксически допустим**, но помечает операцию `manual`-недоступной (линтер `xtask` требует `manual = false`).
- `network = "pki"` — только PKI-хосты ядра (список `plugins.md`); произвольные адреса — перечень точных URL, перекрываемых `capabilities.http`.

### 4.2 Типы и функции Core (`oncl-core`, feature `plugins`)

```text
PluginOperation        { name, module, params, uses: Uses }        // из manifest, неизменяемо
Uses                   { imports, interactive, network, keys: Vec<KeyUseDecl> }
KeyUseDecl             { kind: KeyUseKind, content: Content, max_uses }
Content                { Param(String) | Derived }
PluginApproval         { package_sha256, operation, caller, key: KeyId,
                         uses: Vec<ApprovedUse>, clock_ms, random_seed: [u8;32],
                         inputs: Vec<(String, [u8;32])> }             // не Deserialize; строится только Core из PluginPlan + UserConsent
ApprovedUse            { kind, content_sha256: [u8;32], content_len: u64, options_sha256: [u8;32] }
PluginPlan             { uses: Vec<PlannedUse>, complete: bool, preview: Vec<PreviewLine> }
Engine::plugin_operations(plugin_id) -> &[PluginOperation]
Engine::plugin_request(plugin_id, op, &[ParamValue]) -> Result<String, ..>  // host-built request
Engine::plugin_plan(call, bindings, ctx) -> Result<PluginPlan, OperationError> // без ключа, без побочных эффектов
Engine::plugin_call_approved(call, bindings, &PluginApproval, ctx) -> Result<PluginResult, OperationError>
Action::PluginSign                                                         // новый вид, отличный от Action::Sign (C8)
KeyUseEvent::plugin() -> Option<&PluginUse{ plugin_id, package_sha256, operation, kind, content_sha256, content_len }>
```

`PluginPermission` сохраняется как есть (C1) и остаётся единственным способом авторизации импортов; новые типы лишь **строят** разрешение:

- `PluginPermission::from_operation(&PluginOperation, caller, keys, files, endpoints)` — импорты берутся из `uses.imports`, не вводятся оператором; оператор/хост может **сузить**, не расширить (`debug_assert`/ошибка при попытке).
- `PluginRegistry::install` требует `permissions ⊆ declared` для плагинов с `[[operations]]`; плагин без объявлений принимает старые permissions (WSS/интерактив), но в ручное окно и серверные grant, требующие `operation`, не попадает (R3).
- `Backend::authorize` для ключевых импортов дополнительно требует, чтобы в `PluginApproval` нашёлся неисчерпанный `ApprovedUse` с совпадающими `kind` и `content_sha256` (пересчитывается Core по фактическим `args`, не по заявлению плагина), и `Action::PluginSign` в `ExecutionGrant` (`ConsentGuard.allow(op, key, PluginSign, n)`; `Sign`-гранты на плагин не распространяются).
- Для `bound`-применений дайджест сравнивается с дайджестом замороженного параметра `inputs`; для `derived` — с `ApprovedUse` из плана.

### 4.3 План (derived) и детерминизм

`plugin_plan` — прогон того же WASM тем же `call_headless`, но с `PlanBackend`:

- ключевые импорты: записывают `PlannedUse{kind, sha256(content), len, options}` (Core считает по декодированным `args`) и возвращают **правдоподобную заглушку** (нулевая подпись нужной длины), без вызова `Engine::sign`;
- запрещены с ошибкой `PlanDenied` (план → `complete=false`): сеть (`http*`, `ocsp/crl/tsp*`), запись файлов, `settings_put`, `shared_put`, интерактив;
- разрешены чистые: `hash`, `cert_info/details`, `cms_verify` над входами, `xml_verify`, `log` (без вывода), `now`, `random`, `local_time`;
- `now/local_time` возвращают `clock_ms` из одобрения, `random` — поток HKDF из `random_seed` (свежие 32 байта на согласие, CSPRNG; в реальном прогоне те же значения): прогон воспроизводим, поэтому дайджесты плана и реального вызова совпадают, если плагин не использует скрытые зависимости;
- лимиты: те же `InstanceLimits`, fuel и бюджет `ctx`; один план на согласие;
- плагин, чьё содержимое подписи зависит от результата предыдущей подписи или сети (`complete=false` или реальный дайджест отличается), **не одобряется**: ручное окно показывает «операция не может быть показана для подтверждения» (`ErrorCode::PermissionDenied`, подкод `PlanUnavailable`), ключ не применялся.

Реальный вызов: `now/random` подменяются теми же значениями; сеть разрешена по объявлению; первое же применение ключа с неодобренным `(kind, sha256, options)` или сверх `max_uses` → отказ `KeyUseNotApproved`, `NotApplied`.

### 4.4 Что видит пользователь (текст строит хост; ru/kk/en)

```text
Плагин «Qoltanba (порт OpenNCALayer)» 1.0.0-beta.4   io.github…qoltanba   пакет 9f3c…a1
Операция: sign-file   [от плагина: «Подписать файл»]
Будет использован ключ: Иванов И. · серийный 5c…  · отпечаток 8e…  (КНЦ, до 2027-02-01)
Файл: акт.pdf · 1 482 311 байт · SHA-256 3a7d…
Применений ключа: 1
  1. CMS (CAdES) с меткой времени НУЦ — документ «акт.pdf» (SHA-256 3a7d… совпадает с выбранным файлом)
Сеть: ocsp.pki.gov.kz, tsp.pki.gov.kz
Плагин получит подписанные данные и вернёт ответ.
[Отмена]  [Подписать]
```

Для `derived`: `2. XML (XMLDSig) — данные, составленные плагином: 8 412 байт, SHA-256 b1…; превью: ⟨начало 4 КиБ⟩ … ⟨конец 4 КиБ⟩` (красная рамка, строка «это не файл, который вы выбрали»). Превью — Core-функция `preview_bytes(kind, bytes)` (экранирует управляющие/bidi-символы, для XML — по тексту; для бинарных — hex). Рамка «от плагина» — обычный текст ≤ 80 симв.

### 4.5 Совместимость с 34 портами и миграция

- **ABI/wasm**: не меняются (`ABI_VERSION = 1`, `oncl-pdk/src/abi.rs:50`).
- **`plugin.toml` (34 шт.)**: добавляются `[[operations]]` и поднимается `min_core`; изменение `registry.toml`/хешей пакетов (`plugins/workspace/registry.toml`). Операции объявляются **по факту прогона** (MP0): сначала те, что `bound`/structured и не требуют Origin; остальные остаются WSS-only без записи в манифест.
- **Origin-порты** (C9): операции не объявляются `manual`, пока порт не работает без Origin (проверка в MP0 по каждому методу под `LocalOperator`). Origin не подставляется.
- **Установленные ранее плагины** (устаревший манифест без `operations`): продолжают работать по WSS/интерактивному пути; в ручном окне и серверных grant, которые требуют `operation`, их операций нет (**deny by default** до установки версии с объявлением). Установка/обновление показывает пользователю список объявленных операций и видов применения ключа (расширение `install_plugin.rs`); смена `package_sha256` делает старые объявления неприменимыми.
- **Серверные grants (`config.rs:175`)**: grant на `operation`, которой нет в объявлении, пропускается с ошибкой в журнале на старте (сервис продолжает работу, grant не создаётся); `PluginGrant` получает `plugin_bytes: bool` (по умолчанию `false`) для `derived`; `imports` в конфиге становится сужением объявленных (пустой список = все объявленные).
- **CLI**: `oncl plugin --operation` и `--allow-import` валидируются против объявления; `--plugin-bytes` для derived.

### 4.6 Отказы (типизированно, `NotApplied` до применения ключа)

| Причина | `ErrorCode` | Подкод | Ключ |
|---|---|---|---|
| Операции нет в объявлении / `manual=false` | `PermissionDenied` | `NotDeclared` | не применялся |
| Пакет изменился после согласия | `PermissionDenied` | `PackageChanged` | не применялся |
| Импорт вне объявления | `PermissionDenied` | `ImportNotDeclared` | не применялся |
| Вид/дайджест вне одобрения, сверх `max_uses` | `PermissionDenied` | `KeyUseNotApproved` | не применялся (проверка до `Engine::sign`) |
| План невозможен (сеть/зависимость от подписи) | `PermissionDenied` | `PlanUnavailable` | не применялся |
| Интерактив вне §3.5 / без `PluginInteraction` | `InteractionRequired` | имя импорта | не применялся |
| Origin требуется, а его нет | ответ плагина (`INVALID_ORIGIN`) | — | не применялся |
| Ошибка после применения (TSA, сеть) | как сейчас (`AfterKeyUse`) | — | `Applied`/`Unknown` честно |

## 5. Аудит

- BEGIN: на каждое применение ключа плагином — `plugin_id`, `package_sha256`, `operation`, `caller` (`LocalOperator("desktop-manual")` | `ServiceClient(token id)` | `Browser{origin}`), `kind`, `content_sha256`, `content_len`, `bound|derived`, `consent_id` (ручное) или `grant_id` (сервер), `key_id`. Источник — расширенное `KeyUseEvent` (§4.2) и существующий `KeyUseGuard::before_use/finish` (`runner.rs:107-130`) и аудит сервера (`crates/oncl-server/src/audit.rs`).
- FINAL: `applied`, `succeeded`, код ошибки. Нет FINAL после падения процесса — `Unknown` (как уже сделано в `audit.rs`).
- В аудит не пишутся байты содержимого и превью, только дайджесты.

## 6. Таблица атак (вредоносный плагин)

| Атака | Защита | Остаточный риск |
|---|---|---|
| Подписать выбранные плагином байты | `ApprovedUse(sha256)` сверяется Core по фактическим `args` до `Engine::sign` (§4.2); `raw` только `bound` | `derived` — пользователь видит превью: оценка человека, не доказательство |
| Подмена операции (плагин заявляет «check», подписывает) | Операцию и шаблон запроса выбирает хост из манифеста; импорт/вид вне объявления → `ImportNotDeclared`/`KeyUseNotApproved`. Объявление, показывающее «подпись», — часть согласия; заявленный `label` только в рамке | Плагин может объявить честный `sign`, но лживый `label` — пользователь видит рамку «от плагина», доверенные строки генерирует хост |
| Confused deputy между операциями | `PluginPermission` на `(plugin_id, operation, caller)` (C1) и `ApprovedUse.operation`; одобрение A не покрывает B (тест) | — |
| TOCTOU согласие→вызов (файл, пакет, сертификат) | Параметры замораживаются один раз (`FrozenInput`, `plugins.rs:260`), дайджест считается по замороженным байтам, не по пути; `package_sha256` сверяется; `now/random` детерминированы | Аппаратный токен/хранилище подменены между согласием и вызовом: сверяется отпечаток сертификата (как `StoreChanged` в `runner.rs:~500`) |
| Расхождение план↔реальный вызов (плагин ведёт себя иначе второй раз) | Реальное применение сверяется с одобрением, любое отличие — отказ до ключа | Плагин может «подписать меньше, чем одобрено» — безопасно; может не подписать вовсе — отказ/ошибка плагина |
| Инъекция текста в UI (`label`, `detail`, диалоги, `response`) | Доверенные строки — из объявления и Core; `label`/диалоги плагина — plain text, ≤ длин, bidi/управляющие экранируются, рамка «от плагина», `response` не рендерится в доверенной области | Социальная инженерия внутри рамки «от плагина» |
| Исчерпание ресурсов (план, цикл, память, подписи) | Тот же `InstanceLimits`/fuel/бюджет Core; один план; `max_uses`; лимит `request ≤ max_transfer`; потолок размера превью и числа `[[uses.key]]` (≤ 8) | План удваивает CPU на вызов; ограничен лимитом fuel |
| Подмена ключа/handle | Ключ выбирает пользователь; `PluginKeyBinding` один; `KeysSelect` отвечает только им (§3.5) | — |
| Скрытая сеть в плане (утечка до согласия) | В плане сеть/файлы/shared запрещены (`PlanDenied`) | — |
| Повтор одобрения | `PluginApproval` не `Clone`, потребляется вызовом; `consent_id` разовый | — |
| Серверный grant шире объявления | Валидация при старте; без `plugin_bytes` `derived` недоступен | Оператор сознательно разрешил — его ответственность |

## 7. Ruled decisions (приняты, не требуют ответа)

- **R1.** ABI не меняется; изменения — манифест + Core + UI. B/ABI v2 — отдельный будущий план (MP8).
- **R2.** Согласие не сохраняется; запрос подтверждения — на каждый вызов. Причина: инвариант 4.
- **R3.** Плагин без `[[operations]]` не виден ручному окну и серверным grant, которые требуют `operation`; WSS/интерактивный путь не меняется. Причина: deny-by-default, нет миграции вслепую.
- **R4.** Plugin-derived `raw` в ручном окне запрещён; derived `cms/xml/xades` — разрешён с превью (вопрос Q1 — только про его допустимость в принципе).
- **R5.** Ручной Origin не подставляется; Origin-порты — WSS-only до проверки в MP0.
- **R6.** Диалоги плагина в ручном окне допустимы (`DialogMessage/Confirm/Choice`) в рамке «от плагина», но никогда не равны согласию на подпись.
- **R7.** Серверный grant без пригодного объявления пропускается (не валит сервер), с ошибкой в журнале.
- **R8.** `Action::PluginSign` вводится отдельно от `Sign` (иначе гард C8 не различает).
- **R9.** Размер документа параметра ограничен `max_transfer/4` (base64); большие документы плагинами в ручном окне не обрабатываются — честный `InputLimit`.
- **R10.** Заглушка подписи в плане нулевая нужной длины; если плагин её проверяет, `PlanUnavailable`.

## 8. Вопросы, требующие решения пользователя

**Q1. Разрешать ли `derived`-содержимое (CMS/XML/XAdES, составленное самим плагином) в ручном окне, с превью и дайджестом, или только `bound` (подписывается ровно выбранный файл)?**
Рекомендация: разрешать с превью (иначе ~половина портов недоступна в ручном окне: XML-порты `esf-osdkz`, `taxtech` и др. строят XML сами). Альтернатива «только bound» проще (нет плана и детерминизма, MP3b выпадает) и безопаснее, но урезает функциональность.

**Q2. Охват портов первой поставки: все 34 сразу (MP6, ~6 PR по 6 портов) или «витрина» из 5–6 портов (`qoltanba` и ещё по одному на каждый вид: CMS, XML, XAdES, bound-raw, derived-XML), остальные — позже?**
Рекомендация: витрина, затем волны. Причина: каждый порт требует прогона под `LocalOperator` (Origin, интерактив) и паритет-теста; ошибка в объявлении безопасна (отказ), но стоит времени ревью.

Остальное решено в §7.

## 9. План реализации

### 9.1 Файлы и модули

| Область | Файлы |
|---|---|
| Манифест | `crates/oncl-plugin/src/manifest.rs` (+ `Operation, Param, Uses, KeyUseDecl`, разбор/проверка), `package.rs`, `store.rs` (хранить `package_sha256`), `plugins/workspace/registry.toml`, `docs/design/plugins.md` |
| Хост-типы Core | `crates/oncl-core/src/plugins.rs` (`from_operation`, `plugin_request`, `plugin_plan`, `plugin_call_approved`, `PluginApproval`), `plugins/plan.rs` (новый), `plugins/{cms,xml}.rs` (вычисление дайджеста применения), `keys.rs` (`KeyUseEvent::plugin`), `policy.rs` (`Action::PluginSign`), `error.rs` (подкоды) |
| Runtime | `crates/oncl-plugin/src/headless.rs` (`PluginInteraction`, детерминированные `now/random`, режим плана), `host.rs` без изменений ABI |
| UI | `crates/oncl-ui/src/workspace/{operations.rs,tools.rs}` (страница «Плагины»), `workspace/plugins.rs` (новый: список операций, параметры, консент, раннер), `signing/runner.rs` (`ConsentGuard` для `PluginSign`), `signing/controller.rs` (`PluginConsent`), `ui/workspace.slint`/`plugins.slint`, `install_plugin.rs` (показ операций) |
| Сервер/CLI | `crates/oncl-server/src/{config.rs,service.rs,audit.rs}`, `service/operations/dispatch.rs:1500-1540`, `crates/oncl-cli/src/plugin.rs` |
| Порты | `plugins/*/plugin.toml` (34), `plugins/workspace/registry.toml`, `crates/oncl-port-tests/tests/` |
| Инструмент | `xtask` (`plugin-ops-check`: линтер объявлений) |
| Документы | `docs/design/plugins.md`, `docs/design/platform.md §8.3`, план (поправка §9.4), `docs/user/…` |

### 9.2 Тесты (поведенческие)

Core (`crates/oncl-core/tests/plugin_manual.rs`, на реальном synthetic WASM как `plugin_access.rs`):

- `undeclared_operation_is_denied` / `import_outside_declaration_is_denied`
- `forged_operation_name`: guest подставляет другую `operation` в запросе — Core игнорирует; согласие операции A не позволяет вызвать B
- `a_b_a_swap`: согласие на документ A; между планом и вызовом путь заменён на B и возвращён на A — применён ключ к замороженным байтам A или отказ; мутация «дайджест по пути» убивается
- `key_use_with_other_bytes_is_not_applied`: плагин подписывает не то, что одобрено → `KeyUseNotApproved`, `NotApplied`, счётчик `applications() == 0`
- `raw_over_plugin_bytes_is_refused_in_manual`
- `plan_has_no_side_effects`: сеть/файл/settings/shared в плане → `PlanDenied`, счётчики хоста нулевые
- `plan_equals_call_bytes_with_deterministic_clock_and_random`
- `package_changed_after_consent`
- `approval_is_single_use`, `max_uses_enforced`
- `selection_answers_only_bound_key`: `keys_select` возвращает только привязанный ключ; несовпавший фильтр → `None`
- `dialog_answer_is_not_consent`
- `manual_call_has_no_origin`: порт с проверкой Origin отвечает `INVALID_ORIGIN`, ключ не применён

Сервер/CLI: `grant_outside_declaration_is_skipped_with_error`, `derived_needs_plugin_bytes_flag`, `unattended_interaction_required_unchanged`, аудит BEGIN/FINAL содержит plugin id/operation/digest.

UI: консент-текст строится только из объявления/Core (мутация: подстановка `label` в доверенную строку убивается), `preview` экранирует bidi, окно закрывается в состоянии `Running` по тем же правилам, что подпись, и тест `confirm → swap → run` (как C3 U03).

Порты: для каждого `manual` порта один тест под `LocalOperator` через `plugin_call_approved` (реальная операция, не эхо) + сверка независимым верификатором (OpenSSL/lxml как в `plan` Task 30 smoke).

### 9.3 Стадии (независимо ревьюируемые)

| Задача | Содержание | Владелец (outline брифа) | Зависит |
|---|---|---|---|
| **MP0** | Инвентаризация: `Compiled::imports()` каждого из 34 wasm; для каждого метода — интерактив, ключевые виды, Origin под `LocalOperator`; таблица `docs/design/manual-plugins-inventory.md`. Без кода продукта. | один агент, read-only + тестовый прогон | — |
| **MP1** | Схема `[[operations]]`, парсинг и проверки (§4.1), `package_sha256`, `min_core`; тесты отказов (дубликаты, плейсхолдеры, imports ⊄ compiled) | `oncl-plugin`: manifest/package/store | — |
| **MP2** | `PluginPermission::from_operation`, `install` с `⊆ declared`, `plugin_request`, сервер/CLI-валидация grant, `plugin_bytes`; deny-by-default миграция | `oncl-core` + `oncl-server` + `oncl-cli` | MP1 |
| **MP3a** | `Action::PluginSign`, расширение `KeyUseEvent`, `PluginApproval`, bound-проверка до `Engine::sign`, подкоды, аудит | `oncl-core` | MP2 |
| **MP3b** | `plugin_plan`, `PlanBackend`, детерминизм `now/random`, превью `preview_bytes` (derived); пропуск при Q1=bound-only | `oncl-core` + `oncl-plugin/headless.rs` | MP3a |
| **MP4** | `PluginInteraction`, Core-ответ `KeysSelect/Choose/Flow*`, диалоги в рамке; без интерфейса — прежнее поведение | `oncl-plugin/headless.rs` + `oncl-core` | MP2 |
| **MP5** | Страница «Плагины» в ручном окне: список операций, параметры, консент-страница, раннер, отчёт; `install_plugin.rs` показывает операции | `oncl-ui` (+ slint) | MP3a, MP4 (и MP3b) |
| **MP6** | Объявления портов (по волнам по ≤ 6; витрина первой, Q2), паритет-тесты, регистрация | один агент на волну | MP0, MP1, MP3a |
| **MP7** | Документация: `plugins.md`, `platform.md §8.3`, user-доки; правка плана (§9.4); smoke нативного окна | один агент | MP5 |
| **MP8** (отдельно, не блокирует) | ABI v2 `oncl_prepare/oncl_finish` (модель B) для derived-raw портов | отдельный план | — |

Каждая задача: RED-тест → GREEN → фокусные `cargo test -p …`; общий CI-прогон один раз в конце, как в плане.

### 9.4 Точная поправка плана

В `docs/superpowers/plans/2026-11-02-platform.md`, Task 30, второй пункт: заменить блок **`[ОТКРЫТО, 2026-11-05: … manual-plugins остановлены на дизайн-решении … рекомендация ревью — (C) не предлагать plugins в окне инструментов и …]`** на:

> **[ПЕРЕНАЗНАЧЕНО, 2026-11-07: «поддерживаемые plugins» в ручном окне исполняются по `docs/design/manual-plugins.md` (вариант A, гибрид): операции в манифесте, согласие по дайджесту, raw над байтами плагина не предлагается; задачи MP0–MP7. Task 30 в части plugins закрывается после MP5/MP7; остальные пункты Task 30 от этого не зависят.]**

и добавить после Task 30 раздел:

> ### Task 30P — MP0–MP7: плагины в ручном окне
> **Files:** `crates/oncl-plugin/src/{manifest,package,store,headless}.rs`, `crates/oncl-core/src/{plugins.rs,plugins/plan.rs,keys.rs,policy.rs,error.rs}`, `crates/oncl-ui/src/workspace/plugins.rs`, `crates/oncl-server/src/{config,service,audit}.rs`, `crates/oncl-cli/src/plugin.rs`, `plugins/*/plugin.toml`, `docs/design/{plugins,platform}.md`.
> **Interfaces:** `[[operations]]` манифеста; `PluginOperation`, `Engine::plugin_request/plugin_plan/plugin_call_approved`, `PluginApproval`, `Action::PluginSign`; ABI `ABI_VERSION = 1` не меняется.
> - [ ] MP0 инвентаризация портов; MP1 схема манифеста; MP2 grants ⊆ объявление, deny-by-default; MP3a/b привязка применения ключа к дайджесту и план; MP4 Core-ответ ключевого выбора; MP5 страница; MP6 порты волнами; MP7 документация и smoke.
> - [ ] RED/GREEN: тесты §9.2 документа дизайна, включая `a_b_a_swap`, `key_use_with_other_bytes_is_not_applied`, `forged_operation_name`; мутации «дайджест по пути», «`label` в доверенной строке» убиваются.
> - [ ] Не подставлять Origin; не сохранять согласие; plugin-chosen `raw` в ручном окне не предлагать; не менять ABI.

В строке «Не выбранные функции … plugin-form schema …» (`plan:630`) добавить пояснение: `[[operations.params]]` — типизированные параметры одной операции (документ, текст, выбор, флаг), а не конструктор форм настроек плагина; невыбранная «plugin-form schema» остаётся невыбранной.

## 10. Риски и оговорки

- Оценка `derived` превью — человеческая. Если пользователь ответит на Q1 «только bound», MP3b и детерминизм не делаются.
- Доля портов, годных к ручному окну без Origin и без недетерминированных зависимостей, неизвестна до MP0 ([ПРЕДПОЛОЖЕНИЕ]: часть XML-портов проверяет сайт).
- Подкоды ошибок требуют согласования с публичным контрактом `oncl-api` (`ErrorCode` стабилен): подкод — поле, а не новый код.
- Номера строк в таблице C1–C11 привязаны к tip `08891678`; при исполнении сверять.
