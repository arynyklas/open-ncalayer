# Плагины в окне ручных инструментов: модель разрешений

**Статус:** проект, ревизия 2 (после ревью `review1.md`; решения пользователя и родителя учтены, открытых вопросов нет). Кода нет. База: ветка платформы, tip `08891678`.
**Связано:** [плагины](plugins.md), [платформа §8.3](platform.md), план `docs/superpowers/plans/2026-11-02-platform.md` (Task 21, Task 30), отчёты U03 `platform-ui-task-30/{report,rereview2}.md`.

**Решение.** Вариант A пользователя (плагины остаются в ручном окне) реализуется гибридом C:
1. Манифест получает `[[operations]]`: шаблон запроса, типизированные параметры, явный список импортов и **профиль применения ключа** (виды, фиксированные опции, откуда содержимое).
2. Запрос плагину строит **хост** по шаблону; плагин сам операцию не выбирает.
3. Каждое применение ключа плагином проходит единственную авторитетную проверку в `KeyUseGuard::before_use` по «билету» (`PluginUse`), который Core выписывает из тех же декодированных `args`, что идут в движок. Билет сверяется с одобрением: вид, SHA-256 содержимого, дайджест опций.
4. Опции подписи в одобрение входят **всегда**: Core принуждает их к профилю из манифеста (плагин отклониться от профиля не может), а согласие рисуется из профиля.
5. `max_uses = 1` везде в ручном окне; `Digest`/`raw` — только `bound`; диалоги плагина запрещены; Origin не подставляется.
6. Этапы: сначала путь `bound`; путь `derived` (план-прогон, MP3b) — отдельный более поздний выпуск по итогам MP0.
7. ABI (`ABI_VERSION = 1`) и wasm 34 портов не меняются; меняются их `plugin.toml`.

**Что изменилось против ревизии 1:** §1 исправлены C5/C11 и добавлены факты (C12–C14); §3.5 диалоги запрещены, `keys::terminals`; §4.1 новый пример и профиль опций; §4.2 билет вместо `Action::PluginSign`, ключ вызова в статической политике; §4.3 план: allow-list, `now`, TTL; §4.4 полное превью или отказ; §4.5 сервер/CLI: модель доверия оператора и судьба существующих грантов; §4.7 отказы; §6 таблица атак +9 строк; §7 решения R1–R14; §8 вопросов нет; §9 стадии MP0–MP13 и поправка Task 30P.

---

## 1. Конфликт (что именно сломано и где)

Задача U03 «плагины в ручном окне» остановлена (`report.md:176-181`, `rereview2.md` §4). Номера строк — этого worktree.

| # | Факт | Где |
|---|---|---|
| C1 | Разрешение — точный host-issued кортеж `(plugin_id, operation, CallerContext, imports, keys, files, endpoints, pki_endpoints)`; нет `Deserialize`, нет wildcard | `crates/oncl-core/src/plugins.rs:27-38`, `matches` `:87-91`, `permits` `:92-94` |
| C2 | Авторизация двойная: и grant операции, и политика реестра, зафиксированная при `install`; ключ дополнительно через `grant.allows_key` | `plugins.rs:329-342`, `:513-533`, `:559-576`; `install` `:142-176` |
| C3 | Манифест не знает операций: `modules` и булевы `Capabilities` (`keys, dialogs, files, key_files, page_files, settings, shared, builtin` + префиксы). Разбор строгий (`deny_unknown_fields` у `RawManifest`, `RawCapabilities`) | `crates/oncl-plugin/src/manifest.rs:52-54`, `:114-143`, `:605`, `:621` |
| C4 | `call_headless` принимает только `request: &str`; строки операции в нём нет. `operation` — метка хоста в `PluginCall`; плагину уходит только `Input{request, origin, locale="ru"}` | `crates/oncl-plugin/src/headless.rs:134-145`; `plugins.rs:179-182`, `:599-606`; `crates/oncl-pdk/src/abi.rs:116` |
| C5 | Связь манифест↔импорт есть: каждый импорт требует булев флаг (`Import::capability()`, `declares()`), проверяется при `compile`. Нет только **per-operation** таблицы. Импорты операции назначает оператор: CLI `--allow-import/--key/--plugin-pki-endpoint/--caller` (`crates/oncl-cli/src/plugin.rs:140-150`, вызов `:253`), сервер `PluginGrant{token,operation,imports[],keys[],pki_endpoints[]}` (`crates/oncl-server/src/config.rs:175-185`, `service.rs:322-360`) | `crates/oncl-plugin/src/runtime.rs:249-265` |
| C6 | Headless жёстко отвергает интерактивные импорты (`Dialog*`, `KeysChoose/Select/FlowOpen/FlowPick`, `File*`, `CoreOpenWindow`, `Keystore*`) как `InteractionRequired` | `headless.rs:105-130` |
| C7 | Подписывающих импортов шесть: `KeysSignRaw` (`plugins.rs:368-410`), `KeysSignCms/CmsEx` (`plugins/cms.rs:61-98`), `KeysSignXml/XmlEx/Xades` (`plugins/xml.rs:73-140`). Во всех содержимое выбирает плагин. Помимо содержимого плагин задаёт **опции**: у CMS `content = Data \| Digest` (`abi.rs:1505-1510`; `Digest` → `Action::SignDigest`, нужен `allow_prehashed`, `cms.rs:102-117`), `cosign` (`Auto` — CMS в содержимом подписывается вторым подписантом), `attrs.extra` (произвольные подписанные атрибуты), `econtent_type`, `timestamp = Custom(TsaSpec)` (`abi.rs:1600-1628`, `:1748-1755`); у XML — `element/parent/placement/signature_method` (`abi.rs:2229-2326`); у XAdES — `level/tsa/chain`. Простой `KeysSignCms` жёстко ставит `CoSign::Auto` (`cms.rs:66-72`) |
| C8 | Единственная точка применения ключа — `AuthorizedSigner::sign_digest` (`crates/oncl-core/src/keys.rs:585-640`); событие `KeyUseEvent{operation_id,key_id,action,batch_item}` (`keys.rs:433-439`) не знает ни плагина, ни содержимого; плагин применяет ключ как `Action::Sign`/`SignDigest` (`policy.rs:5-25`, `cms.rs:102-111`). Дайджест, который подписывает ключ, — дайджест подписываемых атрибутов/`SignedInfo` (содержит время подписи), а не содержимого. Десктопный `ConsentGuard` разрешает «N применений ключа K для операции O и действия A» (`crates/oncl-ui/src/signing/runner.rs:60-125`), согласие `UserConsent` привязано к `items` документов (`controller.rs:69-110`), которых у плагина нет |
| C9 | У ручного вызова нет Origin: `encode_input(request, caller.browser_origin(), ..)` (`headless.rs:144-145`); `CallerContext::LocalOperator(String)` даёт `None`. Подставлять Origin нельзя (`plan:396`). Порты с проверкой сайта отвечают `INVALID_ORIGIN` на пустой Origin (например `qoltanba`: `plugins/qoltanba/src/lib.rs:171-177`) |
| C10 | Окна интерактивного (WSS) пути показывают текст плагина (`detail`) в доверенной области (`plugins.md`, раздел `keys`); для ручного окна недопустимо |
| C11 | Desktop WSS работает через `oncl_plugin::PluginModules` (`crates/openncalayer/src/plugins.rs`), а не через `oncl_core::plugins::PluginRegistry` (последний — только `oncl-cli`, `oncl-server`, `oncl-core`). `oncl-ui` включает у `oncl-core` лишь `xml, pdf, jose` (`crates/oncl-ui/Cargo.toml:17`): `plugins` для ручного окна нужно добавить явно |
| C12 | Хеш пакета есть в `store.rs` (`Installed.sha256`, `Package.sha256`, `store.rs:50,156-175`; `package.rs:35,73`), но `PluginRegistry::install(manifest, wasm, limits, policy)` его не принимает и не хранит (`plugins.rs:142-176`): сверять `package_sha256` из одобрения не с чем |
| C13 | Сервер: `Operation::Plugin{plugin, operation, args, keys}` — `args` целиком клиентский JSON (`crates/oncl-api/src/dto.rs:142-149`, OpenAPI `openapi.rs:214`, `dispatch.rs:1500-1540`); ключ плагина авторизуется токеном как `Action::Sign` (`dispatch.rs:221`, `:239`) |
| C14 | Каталожное обновление плагина идёт без запроса, если `capabilities.added_over(old)` пусто (`manifest.rs:196`, `crates/openncalayer/src/plugins.rs:1015`); `[[operations]]` в `Capabilities` не входит |

**Итог.** Ручному окну нужно, чтобы пользователь одобрил применение ключа, видя *что* и *как* подписывается. Сегодня разрешение хост выдаёт слепо относительно содержимого и опций (C7), манифест операций не знает (C3), гард событие не различает (C8), клиент/плагин сам формирует запрос (C4, C13), а большинство портов не работают без диалогов и Origin (C6, C9).

**Операция — это не имя.** Операция = (шаблон запроса, строящийся хостом) + (набор импортов) + (профиль применения ключа). Строку `operation` в `PluginCall` плагин не видит; защиту дают (а) host-built `request`, (б) импорты ⊆ объявление, (в) проверка применения ключа в `before_use`. Тест `forged_operation_name` проверяет именно это, а не «имя».

Инвентаризация портов (грубо, grep по `plugins/*/`; в MP0 заменяется точным `Compiled::imports()`): `plugin.toml` — 34, у всех `keys = true`, 35 имён `modules`; `sign_cms_ex` — 25, `sign_xml` — 18, `sign_xml_ex` — 9, `sign_cms` — 4, `sign_xades` — 1; `sign_raw` — 7 (`acbank, arta, devart, esf-osdkz, rating1c, taxtech, uchet-esf`); выбор ключа `keys::select` — 18, `keys::choose` — 4. Упоминание `origin` в `src` есть почти у каждого порта; доля пригодных к ручному окну без Origin неизвестна до MP0 и, по грубой оценке, заметно меньше половины.

## 2. Инварианты

1. Применение ключа одобряет **пользователь**; манифест — верхняя граница, одобрение — акт каждого вызова.
2. Доверенная область (страница согласия) состоит только из полей, которые плагин не контролирует: `id`, `package_sha256`, `version`, данные ключа/сертификата, имена и SHA-256 документов, профиль подписи из Core, объявленные адреса. **`name`, `description`, `label` манифеста — поля автора плагина**; они показываются лишь в рамке «от плагина» (plain text, ≤ 80 символов, bidi/управляющие экранируются).
3. Согласие привязано к вид + содержимое + **опции**; проверка до применения ключа (билет в `before_use`, §4.2).
4. Согласие не переживает вызов (разовое, TTL, привязано к `OperationId`).
5. Серверу/CLI человек не нужен, но автоответа нет; grant точный.
6. Нет нового доверия к WASM: `InstanceLimits`, fuel, бюджет Core.
7. Никакого произвольного UI плагина: `Dialog*` в ручном окне запрещены (`plan:499`, `platform.md:252`).

## 3. Модели

### Модель A — операционные гранты + согласие по дайджесту
Объявление в манифесте; хост строит запрос; применение ключа сверяется с одобрением (содержимое + опции); для `derived` содержимого — план-прогон и превью. Пользователь видит документ/ключ/профиль подписи/сеть. Плагин может только объявленные импорты и один вид применения с одобренными байтами. `raw` — только `bound`. Сервер: grant ⊆ объявление. ABI не меняется. Минус: сложная реализация `derived`.

### Модель B — хост-подписание (плагин возвращает типизированный запрос)
Плагины не зовут `keys_sign_*`; хост подписывает через фасады Core и обычную страницу согласия. Лучшая безопасность, но требует ABI v2 (`oncl_prepare/oncl_finish`) и переписывания всех 34 портов: 25 портов зовут `sign_cms_ex` посреди логики. Неприемлема сейчас; целевой ABI v2 (MP13).

### Модель C (выбрана) — гибрид
A как основа; ближе к B там, где это дёшево: (1) для CMS/XML/XAdES структуру и профиль подписи строит Core, описание согласия — из профиля, как у встроенных инструментов; (2) `raw` и `Digest` — только `bound`; (3) `derived` — отдельный поздний этап (MP3b) с жёсткими условиями (§4.4); (4) операция в манифесте проектируется так, чтобы позднее переехать на `sign_request` (B) без смены интерфейса окна.

| | A | B | C |
|---|---|---|---|
| ABI/wasm | без изменений | v2, переписать 34 | без изменений |
| Привязка | содержимое + опции | по построению | содержимое + опции, raw/Digest только bound |
| Порты в окне | кроме unsupported (MP0) | после переписывания | кроме unsupported (MP0) |

### 3.5 Ключевой выбор и интерактив в ручном окне
Порты зовут `keys::select` (18) и `keys::choose` (4). Это не «UI плагина», а выбор ключа, который в ручном окне уже сделал пользователь:
- `KeysSelect/KeysChoose/KeysFlowOpen/KeysFlowPick` → Core оценивает фильтр плагина (`Filter/FilterMore`, те же функции `oncl-flows`) против сертификата выбранного пользователем ключа; подходит — `Chosen{handle, alias, certificate}` для единственного привязанного ключа (секрет и путь хранилища плагину не передаются); не подходит — `None`.
- `KeysTerminals` → `[]`; `TokensScan` → «токены выключены»; `KeysOpen` и прочее, что в Core headless даёт `PermissionDenied` (`plugins/capabilities.rs:203`, трап), — порт с такими вызовами **unsupported** (причина — в таблице MP0, не молчаливо).
- **`Dialog*`, `File*`, `CoreOpenWindow`, `Keystore*` — запрещены** (`InteractionRequired`, как в C6). Порт, которому они нужны, unsupported с причиной.
- `PluginInteraction` (UI-трейт) нужен только для выбора ключа; никакого рендера текста плагина в нём нет.
- Сервер/CLI: `PluginInteraction` не передаётся, поведение C6 без изменений.

## 4. Рекомендуемая модель в деталях

### 4.1 Манифест

Новая таблица в `RawManifest` (`deny_unknown_fields` отвергает её в старом ядре; `min_core` пакета поднимается). Пример ниже **иллюстративный** (вымышленный плагин `example.sign`, не порт; реальные операции портов определит MP0 — `qoltanba` в ручном окне недоступен из-за Origin, его метод `signFileBytes` имеет арность 2 и читает хранилище, `plugins/qoltanba/src/lib.rs:103-106, 270`):

```toml
min_core = "0.1.0-alpha.7"

[[operations]]
name    = "sign-file"                       # ^[a-z][a-z0-9-]{0,31}$, уникально
module  = "example.sign"                    # из `modules`
manual  = true                              # показывать в ручном окне
server  = false                             # допускать grant сервера/CLI
request = '{"module":"example.sign","method":"signFile","args":["{file:base64}"]}'   # арность — как у метода плагина
label   = { ru = "Подписать файл", kk = "Файлға қол қою", en = "Sign a file" }      # только рамка «от плагина»

[[operations.params]]
name = "file"
kind = "document"                           # document | text | choice | flag | locale
max_bytes = 16777216

[operations.uses]
imports = ["keys_select", "keys_describe", "keys_sign_cms_ex", "hash"]   # ⊆ Compiled::imports()
network = "pki"                             # none | pki | [точные URL]
interactive = ["keys_select"]               # ⊆ {keys_select, keys_choose, keys_flow_open, keys_flow_pick}

[[operations.uses.key]]
kind     = "cms_ex"                         # raw | cms | cms_ex | xml | xml_ex | xades
content  = "param:file"                     # param:<имя> => bound; "derived" => только после MP3b
max_uses = 1                                # единственно допустимое значение в ручном окне
[operations.uses.key.profile]               # профиль опций; Core принуждает (см. ниже)
encapsulate = false
cosign      = "never"
timestamp   = "basics"                      # none | basics | kalkan   (Custom запрещён)
certificates = "signer"
output      = "der"
```

**Профиль опций — решение по условию (1).** Выбран вариант «объявленный профиль, который Core принуждает», а не «план для каждой операции»: план остаётся только для `derived`-содержимого. Правила:
- Профиль — типизированная структура соответствующего вида. Поля вне белого списка (`attrs.extra`, произвольный `econtent_type`, `timestamp = Custom`, `Digest` с чужим алгоритмом, `signature_method` вне известных) в профиль не входят вовсе, а значения опций в реальном `args` плагина обязаны **совпасть** с профилем (канонический байтовый вид опций → `options_sha256`), иначе отказ до ключа (`OptionsMismatch`). Незаданное в профиле поле означает значение по умолчанию Core, и отклонение от него — тоже отказ.
- Допустимые варианты поля: `fixed` (константа) либо `param:<имя>` (для XPath `element/parent` у XML — текст, введённый пользователем и показанный в согласии).
- `cosign` в профиле только `never`; для простого `KeysSignCms` в одобренном режиме Core подставляет `CoSign::Never` вместо `Auto` (документируемое отличие от унаследованной семантики: ручное окно подписывает байты выбранного файла как есть, даже если это CMS). Это закрывает расхождение «подписано не то, что показано» при `cosign: Auto` (внутреннее содержимое ≠ `args.content`).
- `max_uses = 1`; многоподписные операции в ручном окне не поддерживаются (unsupported с причиной «несколько подписей»).
- **`CmsContent::Digest`:** запрещён для `derived`; для `bound` Core сам считает дайджест замороженного документа алгоритмом ключа (ГОСТ 34.311/Стрибог/SHA-2 по сертификату, как `cms_spec` и проверка `digest.algorithm() == alg.hash_alg()`, `keys.rs:~615`) и требует побайтового равенства с `args` — показывается имя документа и этот дайджест (не SHA-256). Это возможно только при `allow_prehashed` политики контекста; ручное окно включает его для плагинного контекста.

**Ревизия MP1b:** (контракт текста: Core отвергает в `text`-содержимом `InvalidValue` любой символ, кроме `\n` и `\t`, если он управляющий, bidi или невидимый; UI нормализует CRLF в LF при снимке формы и передаёт тот же `&str` и рендереру, и `PluginParam::Text`;) шаблон — любой JSON-объект (массив `args`, объект `args` или ключи прямо в корне, как у реальных портов), плейсхолдеры только значения целиком, `module`/`method` фиксированы; `text` — содержимое любого вида (UTF-8-байты); ключевая операция обязана объявить `network = "pki"`; см. `docs/design/plugins.md`.

Проверки при разборе: `request` — JSON-объект со строгими пределами, плейсхолдеры (целые строки-значения) только объявленных параметров, максимум ≤ `max_transfer` (иначе операция недоступна, честный `InputLimit`); `uses.imports ⊆ Compiled::imports()` проверяет установка (WASM известен); любой ключевой импорт требует строки `[[uses.key]]` соответствующего вида и `Capabilities.keys = true`; `content = "param:x"` — `x` типа `document` или `text` (для любого вида; подписываются UTF-8-байты текста, в котором нет управляющих символов кроме `
`/`	` и невидимых/bidi); `raw` с `derived` запрещён линтером; число `[[uses.key]]` ≤ 8; `network = "pki"` — только PKI-хосты ядра.

### 4.2 Типы и точки проверки (Core)

```text
PluginOperation, Uses, KeyUseDecl{kind, content: Param|Derived, max_uses:1, profile}
PluginApproval  { package_sha256, version, operation, caller, operation_id, key: KeyId, ttl_deadline,
                  uses: [ApprovedUse], inputs: [(param, sha256)], clock_ms?, random_seed? }  // не Clone, не Deserialize
ApprovedUse     { kind, content_sha256|prehashed_digest, content_len, options_sha256 }
PluginUse       { plugin_id, package_sha256, operation, kind, content_sha256, options_sha256 }   // «билет»
OperationContext.plugin_ticket: Option<PluginUse>          // только Core-бэкенд плагина кладёт его
KeyUseEvent.plugin: Option<PluginUse>                      // берётся из ctx.plugin_ticket.take() в sign_digest
PluginPermission::declared(plugin_id, operation, caller)   // KeyScope::Declared, только из реестра
Engine::plugin_operations / plugin_request / plugin_call_approved / (MP3b) plugin_plan
```

**Единственная авторитетная проверка — `KeyUseGuard::before_use`** (`keys.rs:634`) — на билете, а не на дайджесте движка (дайджест движка — дайджест подписываемых атрибутов с временем подписи, C8; восстановить из него содержимое нельзя). Построение билета:
1. Бэкенд плагина (`cms.rs`, `xml.rs`, `plugins.rs`) один раз декодирует `args` в типизированную структуру; из **этой же структуры** считает вид, SHA-256 эффективного содержимого (после принудительного `cosign=Never`; для `Digest` — сам дайджест) и `options_sha256` по каноническому кодированию, сверяет опции с профилем.
2. Кладёт билет в `ctx.plugin_ticket` и передаёт ту же структуру в движок (`engine.sign(...)`); `AuthorizedSigner::sign_digest` создаёт `KeyUseEvent`, забирая билет (`take()` — одноразовый).
3. `PluginConsentGuard::before_use` (десктоп) / серверный гард разрешает применение только если `event.plugin == Some(t)`, `t` совпадает с неисчерпанным `ApprovedUse`, `max_uses` не исчерпан, TTL не истёк, `operation_id` совпадает, `package_sha256` совпадает с установленным. События без билета в плагинном движке — отказ; события **с** билетом в документном `ConsentGuard` — отказ (у плагина отдельный экземпляр движка/гарда, так что согласие на документ не покрывает плагин и наоборот).
4. Предварительная сверка в бэкенде (`Backend::authorize`) — только быстрый отказ без побочных эффектов; решает гард. Отказ приходит до `Engine::sign`, ключ не применён, `NotApplied`.

**Без `Action::PluginSign` (ревизия 1 отозвана).** Новое действие ломало бы токены (`dispatch.rs:221`, токены хранят `Action::Sign`). Вместо него: флаг-билет в контексте и отдельный гард. Токены не меняются; миграции токенов нет.

**Ключ вызова и статическая политика реестра (условие 9).** `install(policy)` фиксирует `PluginPermission` раз и навсегда, а `permits(import, Some(key))` требует ключ в `p.keys` (`plugins.rs:92-94`). Для плагинов с операциями политика реестра строится из объявления как `KeyScope::Declared` (конструктор доступен только `PluginRegistry`): хост-сторона проверяет `(plugin_id, operation, caller)`, импорт ∈ объявленные, вид применения ∈ объявленные и **не проверяет конкретный ключ**. Конкретный ключ проверяется второй, пер-вызовной стороной, которую строит UI: `ExecutionGrant::with_keys([выбранный])` + `plugin_permissions([PluginPermission::from_operation(..).with_keys([выбранный])])` (`policy.rs:93-110`). Обе стороны по-прежнему обязательны (C2). `KeyScope::Exact` — прежнее поведение для плагинов без объявлений.

**Хеш пакета (C12).** `PluginRegistry::install` получает `package_sha256` (из `store.rs`) и хранит в `Installed`; `plugin_call_approved` сверяет с `PluginApproval.package_sha256`. Подмена wasm/манифеста между согласием и вызовом → `PackageChanged`.

### 4.3 Реальный вызов и заморозка
Документы замораживает UI-раннер **до** построения `request` (чтение один раз в память/spool с подсчётом SHA-256, как у документного Sign; сравнение по дайджесту замороженных байт, не по пути). `FrozenInput` (`plugins.rs:260`, для `page_file_*`) не участвует. Параметр подставляется в шаблон из замороженных байт; `request` после подстановки ≤ `max_transfer`. Сертификат ключа сверяется по отпечатку (как `StoreChanged`, `runner.rs:505`). Для `bound` `inputs[param]` — SHA-256 замороженного документа, а `ApprovedUse.content_sha256` берётся из него (для `Digest` — дайджест алгоритмом ключа).

### 4.4 `derived` (MP3b, отдельный поздний выпуск; решается после MP0)
Условия (ограничения от решения родителя):
- `max_uses = 1`; `raw` и `CmsContent::Digest` для `derived` запрещены; допустимы только виды `cms/cms_ex/xml/xml_ex/xades`, содержимое — валидный UTF-8 текст.
- **Превью полное или отказ**: Core показывает **всё** содержимое экранированным текстом, если оно ≤ `PREVIEW_MAX = 64 КиБ`; больше — отказ `PreviewTooLarge` (ключ не применён). Никакого «начала и конца». В превью: управляющие и bidi-символы заменены видимыми метками, длинные строки переносятся, прокрутка полная; показывается также SHA-256 и размер.
- **План-прогон** (`plugin_plan`): тот же WASM, тот же `call_headless`, но `PlanBackend` с **allow-list по умолчанию «запретить»**. Разрешено: `hash`, `cert_info`, `cert_details`, `keys_describe`, `keys_chain`, `keys_release`, `xml_verify`, `platform`, `call_locale`, `now`, `local_time`, `random`, `log` (вывод отбрасывается). Запрещено (трап → `PlanUnavailable`): всё остальное, в том числе `cms_verify` (сеть и часы), `settings_get/put`, `shared_get/put`, `ca_list/ca_issuer/pkix_path` и PKI-запросы, `http*`, `page_file_*`, `core_modules`, интерактив. Трап в headless необратим для плагина (`headless.rs:88-103`), перехватить отказ он не может.
- Ключевые импорты в плане записывают билет и возвращают нулевую заглушку подписи нужной длины, не вызывая `Engine::sign`; плагин, который проверяет заглушку или строит дальнейшее по ней, получает расхождение и **отказ при реальном применении** (билет не совпал, ключ не применён: `max_uses = 1`, второго применения нет, поэтому «отказ после частичного применения» невозможен).
- **Детерминизм и часы.** План и реальный вызов получают одинаковые `now/local_time` (`clock_ms`, берётся при согласии) и один и тот же `random` (HKDF от свежих 32 байт на согласие). `clock_ms` в реальном вызове заморожен; `now()` не двигается, поэтому плагин, который «ждёт» по `now()`, упирается в fuel/deadline и падает трапом (границы — существующие `InstanceLimits.fuel` и дедлайн контекста). Возраст одобрения ограничен TTL = 120 с (`ApprovalExpired`), чтобы замороженное время не расходилось с реальным дольше TTL.
- Бюджет: план и реальный вызов выполняются последовательно и не удерживают резерв одновременно (`plugins.rs:552-556`: до `max_transfer·8 + max_memory` на вызов); «двойной запуск» — это 2× fuel, ограниченный дедлайном; повторный план на то же согласие запрещён.

### 4.5 Что видит пользователь (текст строит хост; ru/kk/en)

```text
Плагин id: example.sign   версия 1.0.0   пакет SHA-256 9f3c…a1          ← доверенные поля
Операция: sign-file       [от плагина: «Подписать файл»]                ← рамка «от плагина»
Ключ: Иванов И. · серийный 5c… · отпечаток 8e… (до 2027-02-01)
Файл «акт.pdf» · 1 482 311 байт · SHA-256 3a7d…
Применение ключа: 1 раз
  CMS (CAdES): отсоединённая; метка времени НУЦ; сопись нет; доп. атрибутов нет      ← из профиля Core
  Подписывается файл «акт.pdf» как есть (SHA-256 совпадает)
Сеть: ocsp.pki.gov.kz, tsp.pki.gov.kz. Плагин может передать данные только по этим адресам; документ может быть отправлен на разрешённые хосты.
[Отмена]  [Подписать]
```
Страница доступна с клавиатуры (порядок фокуса, Enter не подтверждает подпись до фокуса на «Подписать», масштаб/DPI, экранные читатели), как документное согласие. Результат (`response` плагина) показывается как plain text в рамке «от плагина»; место и имя сохранения выбирает хост (`PluginOutputBinding`), не плагин.

### 4.6 Совместимость с 34 портами и миграция
- ABI и wasm не меняются. Меняются `plugins/*/plugin.toml` (+`min_core`), хеши в `plugins/workspace/registry.toml`, и **выпуск 34 новых версий пакетов через подписанный индекс обновлений** (MP11), а не «правка файла».
- **Охват: все порты, которые могут работать** (решение родителя). MP0 строит таблицу «порт × метод → supported | unsupported(причина)». Причины unsupported перечисляются явно: требует Origin (`INVALID_ORIGIN`); использует `Dialog*`/`File*`; `keys::open/terminals`-ветка без ответа; несколько подписей за вызов; `raw` над вычисляемыми байтами (derived-raw); зависимость от состояния между вызовами (`shared/settings`). Unsupported порты показываются в окне с причиной (не скрываются, Origin не подставляется).
- **Старые установленные версии** (без `[[operations]]`) работают по WSS как раньше; в ручном окне операций у них нет.
- **Каталожные обновления (C14).** `added_over` расширяется: появление/изменение `[[operations]]` с `uses.key`, расширение `imports/network`, смена профиля — считается добавленной возможностью и **требует явного согласия установки** (`install_plugin.rs`); автообновление с пустым `added_over` не может молча добавить операцию с применением ключа.

### 4.7 Сервер, CLI, существующие гранты (условие 7)
Решено: **модель доверия оператора для свободного `args` остаётся** (typed params + document parts в `dto.rs`/OpenAPI — отдельный будущий этап MP8b, не блокирует). Что значит «grant ⊆ объявление» при свободном `args`:
- Для плагинов **с** `[[operations]]`: `PluginGrant.operation` обязана быть объявленной с `server = true`; `imports ⊆ uses.imports` (пустой список = все объявленные); `keys` разрешены лишь если операция объявляет применение ключа; **профиль опций принуждается Core так же, как в ручном окне** (клиент не может добавить `attrs.extra`, `Custom` TSA и т. п.); `cosign=never` и `Digest`-запрет те же. Привязать содержимое к документу сервер не может (нет типизированных параметров), поэтому для любого применения ключа обязателен явный флаг `plugin_bytes = true` в `PluginGrant` (оператор принимает «содержимое выбирает клиент/плагин», как сегодня), и билет `PluginUse` пишется в аудит. `args` по-прежнему свободный JSON клиента; хост не строит `request`, поэтому сервер защищён **импортами, профилем и ключами**, а не шаблоном.
- Для плагинов **без** объявлений (все 34 до MP6, сторонние): поведение сервера/CLI **не меняется** — grant по меткам оператора, как сейчас; в аудит пишется `declared=false`, на старте — предупреждение «grant без объявления: профиль опций не принуждается». Это ответ на «что станет с существующими грантами портов до MP6»: они продолжают работать как раньше (deny-by-default уже обеспечен точным grant).
- После обновления плагина до версии с объявлениями грант на неопределённую в ней `operation` **пропускается** с ошибкой в журнале (имена объявленных операций указаны), остальные работают.
- Токены не меняются (`Action::Sign` как сегодня, `dispatch.rs:221`). Серверный `KeyUseGuard` получает те же правила билета (п. 4.2.3).
- CLI: `--operation`/`--allow-import` валидируются против объявления; `--plugin-bytes`; `--profile` не принимается (профиль берётся из манифеста).
- CLI, MP9: `oncl plugin operations --manifest [--wasm]` перечисляет объявленные операции (имя, `server`/`manual`, импорты, сеть, применение ключа и профиль словами; `derived` — «не запускается»), чтобы оператор писал гранты, не читая TOML; для объявленной операции без `--args-file` запрос строит Core из шаблона по типизированным `--param`/`--param-file`/`--param-flag` (`Engine::plugin_server_request`, как в ручном окне), без параметров флаг `false`; CLI никогда не спрашивает согласия — согласие даёт оператор флагом `--plugin-bytes`, а в stderr пишется строка `plugin_use` (доверенные факты билета, `grant=cli-plugin-bytes`) до применения ключа. Подробности — `docs/user/cli.md`, «Plugins».

### 4.8 Отказы (типизированно)
Подкод — поле рядом с кодом (контракт `oncl-api::ErrorCode` стабилен; MP8 добавляет структуру «код+подкод» в DTO/OpenAPI/клиент).

| Причина | `ErrorCode` | Подкод | Ключ |
|---|---|---|---|
| Операция не объявлена / `manual=false` | `PermissionDenied` | `NotDeclared` | не применялся |
| Пакет изменился | `PermissionDenied` | `PackageChanged` | не применялся |
| Импорт вне объявления | `PermissionDenied` | `ImportNotDeclared` | не применялся |
| Опции не по профилю | `PermissionDenied` | `OptionsMismatch` | не применялся |
| Билет вне одобрения / TTL / уже использован | `PermissionDenied` | `KeyUseNotApproved` / `ApprovalExpired` | не применялся (до `Engine::sign`) |
| План невозможен / превью > 64 КиБ / не текст | `PermissionDenied` | `PlanUnavailable` / `PreviewTooLarge` | не применялся |
| Интерактив вне §3.5 | `InteractionRequired` | имя импорта | не применялся |
| Origin нужен | ответ плагина | — | не применялся |
| Ошибка **после** применения (TSA, сеть) | как сейчас (`AfterKeyUse`) | — | `Applied`/`Unknown` честно |

Реализованные id подкодов (MP3a-3, `PluginRefusalCode`) — kebab-case и мельче таблицы: `NotDeclared`→`not-declared`, `PackageChanged`→`package-changed`, `OptionsMismatch`→`options-mismatch`, `ApprovalExpired`→`approval-expired`; `KeyUseNotApproved` разбит на `approval-missing`, `ticket-missing`, `ticket-uses`, `key-use-spent`, `key-mismatch`, `operation-mismatch`, `kind-mismatch`, `action-mismatch`, `content-mismatch`, `caller-mismatch`, `operation-id-mismatch`, `certificate-changed`, `approval-replayed`, `busy`; `manual=false` — `not-manual`; добавлены `not-granted`, `no-consent-guard`, `audit-fact-too-long`; `ImportNotDeclared`, `PlanUnavailable`, `PreviewTooLarge` не реализованы (нет путей кода; MP3b/MP8).

Утверждение «отказ всегда до ключа» верно потому, что применений ровно одно (`max_uses = 1`): все проверки предшествуют первому и единственному применению; поэтому не бывает состояния «первая подпись применена, вторая отклонена».

## 5. Аудит
BEGIN на применение ключа: `plugin_id`, `package_sha256`, `version`, `operation`, `caller`, `kind`, `content_sha256` (или дайджест `Digest`), `options_sha256`, `bound|derived`, `consent_id` (ручное) / `grant_id` + `declared` (сервер), `key_id`. FINAL: `applied`, `succeeded`, код. Нет FINAL → `Unknown`. Источник — `KeyUseEvent.plugin` и `KeyUseGuard::before_use/finish` (`runner.rs:107-130`, `crates/oncl-server/src/audit.rs`). Байты и превью в аудит не пишутся.

## 6. Таблица атак (вредоносный плагин / клиент)

| Атака | Защита | Остаточный риск |
|---|---|---|
| Подписать выбранные плагином байты | билет сверяется в `before_use` с `ApprovedUse` (SHA-256 содержимого); `raw`/`Digest` только `bound` | `derived` — оценка человека по полному превью (этап MP3b) |
| Опции подписи вне показанного (`attrs.extra`, `econtent_type`, `cosign`, custom TSA, XML `placement/signature_method`, XAdES `level`) | профиль принуждается Core; `options_sha256` входит в билет; `cosign=never` | — |
| `CmsContent::Digest` (содержимое неизвестно хосту) | для `bound` Core считает дайджест документа алгоритмом ключа; для `derived` запрещён | — |
| Сопись/вложенный CMS: `args.content` ≠ реально подписанное | `cosign` принудительно `never`; билет по эффективному содержимому | — |
| Спуфинг операции (плагин «check» подписывает) | `request` строит хост; импорты/вид ⊆ объявление; билет | Лживый `label` виден лишь в рамке «от плагина» |
| Спуфинг доверенной области именем плагина (`Manifest.name` у автора) | доверенны только `id`, `package_sha256`, `version`; `name/label/description` — в рамке «от плагина» | Социальная инженерия внутри рамки |
| Confused deputy между операциями | `PluginPermission(plugin_id, operation, caller)` + `ApprovedUse.operation` | — |
| TOCTOU согласие→вызов (файл, пакет, сертификат, часы) | заморозка документа до сборки `request`; сверка по дайджесту замороженных байт; `package_sha256`; отпечаток сертификата; TTL 120 с; `clock_ms` | A→B→A закрыт сверкой байт, а не пути |
| Тихое каталожное обновление добавляет операцию с ключом | `added_over` расширен (C14): `[[operations]]` с `uses.key` требует явного согласия установки | — |
| Повтор/подмена одобрения | не `Clone`, одноразовое, привязано к `OperationId`, TTL | — |
| Подмена ключа/handle; `keys::terminals`/`keys_open` | единственный привязанный ключ; `terminals` → `[]`; `keys_open` → порт unsupported (трап до ключа) | — |
| Диалоги/UI плагина как согласие | `Dialog*` запрещены; ключевой выбор отвечает Core | — |
| Отправка документа плагином по сети | в согласии: сеть и адреса, явная фраза «документ может быть отправлен на разрешённые хосты»; адреса — точный список или PKI-хосты; в плане сеть запрещена | Разрешённый хост (`*.gov.kz`) получает данные — решает пользователь, читая согласие |
| UI-инъекция (`label`, `response`, превью) | plain text, длины ограничены, bidi/управляющие экранированы; `response` в рамке | — |
| Исчерпание ресурсов (двойной запуск, превью огромное) | один план; 2× fuel под дедлайном; план и вызов не держат резерв одновременно; превью ≤ 64 КиБ или отказ; `request ≤ max_transfer` | Ограниченный CPU |
| Результат: плагин навязывает путь сохранения | место и имя выбирает хост (`PluginOutputBinding`) | — |
| Серверный клиент подсовывает опции/метод в свободный `args` | профиль принуждается Core; импорты/ключи по гранту; для ключа нужен `plugin_bytes`; метод в `args` оператор доверяет | Оператор принял «содержимое выбирает клиент» |
| Серверный grant шире объявления | валидация при загрузке; недоговорный grant пропускается | — |

## 7. Решения (ruled)
- **R1.** ABI не меняется; B/ABI v2 — MP13, отдельно.
- **R2.** Согласие не хранится; каждый вызов подтверждается заново.
- **R3.** Deny-by-default для ручного окна: плагин без `[[operations]]` в нём не виден. Серверные/CLI-гранты плагинов без объявлений не меняются (§4.7).
- **R4.** `raw` и `Digest` — только `bound`. `derived` — только MP3b, при `max_uses=1`, виды текста, полное превью ≤ 64 КиБ.
- **R5.** Origin не подставляется; Origin-порты — unsupported с причиной.
- **R6.** `Dialog*` запрещены (пересмотрено, ревизия 1 разрешала).
- **R7.** Охват: все порты, которые могут работать, по MP0; unsupported перечислены с причиной.
- **R8.** `Action::PluginSign` не вводится: билет + отдельный гард; токены не меняются.
- **R9.** `max_uses = 1` во всех операциях ручного окна.
- **R10.** Опции — профиль из манифеста, принуждаемый Core; `cosign=never`; `Custom` TSA и `attrs.extra` запрещены.
- **R11.** Единственная авторитетная проверка — `before_use` по билету; проверка в бэкенде лишь предварительная.
- **R12.** Хеш пакета передаётся в `PluginRegistry::install`; политика реестра — `KeyScope::Declared`, ключ — в пер-вызовном grant.
- **R13.** Каталожное обновление с изменёнными `[[operations]]` — повторное согласие (`added_over` расширен).
- **R14.** Сервер: свободный `args`, профиль принуждается, `plugin_bytes=true` обязателен; типизированные параметры сервера — MP8b, позже.
- **R15 (по итогам MP0, `manual-plugins-inventory.md`).** Порты, передающие `cosign=Auto` в `keys_sign_cms_ex`, в ручном окне работают с `cosign=Never`: Core принудительно заменяет `Auto` на `Never` (иначе правило «опции = профиль» отвергло бы все годные CMS-методы); осознанное отличие от унаследованной семантики записано, на странице согласия показывается фактический профиль.
- **R16.** MP3b (`derived`) НЕ запускается: по инвентаризации только `fhs.signFile` заблокирован исключительно `DERIVED`, и тот же результат даёт `fhs.signText` с файлом как документом. Пересмотр — только по новому решению.
- **R17.** `esf-osdkz.auth` (подпись challenge для входа) в первом выпуске ручного окна НЕ включается: это действие «аутентификация», а не «подписать документ» (кнопка называет действие; отдельная модель согласия нужна позже). Профили ESEDO (5 методов) — позже, отдельным решением.
- **R18.** `reply_drop` (освобождение буфера ответа, импортируют 33 порта) в ручном окне разрешён и безвреден (иначе все порты падают); состояние между вызовами не сохраняется (свежий экземпляр на вызов) — порты с такой зависимостью unsupported.
- **R19.** Объявления `[[operations]]` нужны только 9 портам (rating1c, dogovor24, efactoring, market, energy, eproc, esf-osdkz (без `auth`), fhs, qiwi), а не 34 (MP6 уже, по MP0); остальные 25 портов в ручном окне не имеют операций, причины — в таблице инвентаризации.

## 8. Вопросы пользователю
Нет. Q1/Q2 решены (derived со строгими условиями, поэтапно; охват — все пригодные порты по MP0).

## 9. План реализации

### 9.1 Файлы и модули
| Область | Файлы |
|---|---|
| Манифест | `crates/oncl-plugin/src/manifest.rs` (`RawManifest` + `Operation/Param/Uses/KeyUseDecl/Profile`, `added_over`), `package.rs`, `store.rs`, `plugins/workspace/registry.toml`, `docs/design/plugins.md` |
| Core | `crates/oncl-core/src/plugins.rs` (`install` с хешем, `KeyScope`, `from_operation`, `plugin_request`, `plugin_call_approved`), `plugins/{approval,plan}.rs` (новые), `plugins/{cms,xml}.rs`, `keys.rs` (`KeyUseEvent.plugin`, билет в `sign_digest`), `context.rs` (`plugin_ticket`), `error.rs` (подкоды) |
| Runtime | `crates/oncl-plugin/src/headless.rs` (`PluginInteraction`, `now/random`, режим плана) |
| Desktop wiring | `crates/openncalayer/src/plugins.rs` (построение `PluginRegistry` из `Store`, хеш пакета, обновление при смене версии, `added_over`), `crates/openncalayer/Cargo.toml`, `crates/oncl-ui/Cargo.toml` (`oncl-core/plugins`; размер бинаря) |
| UI | `crates/oncl-ui/src/workspace/{operations.rs,tools.rs,plugins.rs}`, `signing/{runner.rs,controller.rs}` (`PluginConsentGuard`, `PluginConsent`), `ui/{workspace,plugins}.slint`, `install_plugin.rs` |
| API/сервер/CLI | `crates/oncl-api/src/{dto.rs,openapi.rs,client.rs}` (подкоды, `plugin_bytes`), `crates/oncl-server/src/{config.rs,service.rs,audit.rs}`, `service/operations/dispatch.rs`, `crates/oncl-cli/src/plugin.rs`, `docs/user/{http-api,cli,server}.md` |
| Порты/выпуск | `plugins/*/plugin.toml` (34), `registry.toml`, `crates/oncl-port-tests/tests/`, подписанный индекс обновлений (`update-index.md`) |
| Инструмент | `xtask` (`plugin-ops-check`) |

### 9.2 Тесты (поведенческие)
Core (`crates/oncl-core/tests/plugin_manual.rs`, реальный synthetic WASM):
`undeclared_operation_is_denied`, `import_outside_declaration_is_denied`, `forged_operation_name` (операцию задаёт хост-`request`, плагин её не видит и не выбирает), `a_b_a_swap` (A→B→A: подписывается замороженный A или отказ; мутация «дайджест по пути» убивается), `key_use_with_other_bytes_is_not_applied` (`applications()==0`), `options_outside_profile_are_refused` (`attrs.extra`, `econtent_type`, `Custom` TSA, `placement`, XAdES level — по отдельному кейсу; мутация «опции не в билете» убивается), `cosign_auto_is_forced_never_and_cannot_mislead`, `prehashed_bound_uses_key_algorithm_digest`, `prehashed_derived_refused`, `raw_over_plugin_bytes_refused`, `ticket_without_event_is_refused` и `document_guard_refuses_plugin_ticket`, `approval_is_single_use`, `approval_expired`, `package_changed_after_consent` (хеш в `install`), `declared_policy_with_per_call_key` (ключ только из grant вызова), `selection_answers_only_bound_key`, `terminals_answers_empty_and_keys_open_traps`, `dialogs_are_interaction_required`, `manual_call_has_no_origin`. MP3b: `plan_has_no_side_effects`, `plan_allowlist_denies_by_default` (cms_verify, settings_get, shared_get, ca_list), `plan_equals_call_bytes_with_frozen_clock`, `now_loop_hits_fuel`, `preview_over_limit_refused`, `derived_multi_use_refused`.
Сервер/CLI: `declared_plugin_grant_enforces_profile`, `server_key_use_needs_plugin_bytes`, `undeclared_plugin_grants_unchanged`, `grant_for_unknown_operation_is_skipped`, `tokens_unchanged`, аудит BEGIN/FINAL содержит билет.
UI: консент-текст строится из объявления/профиля Core (мутация «`name` или `label` в доверенной строке» убивается), превью экранирует bidi, `confirm → swap → run`, фокус/Enter/DPI страницы согласия, закрытие окна в `Running`.
Установка/каталог: `catalog_update_adding_key_operation_requires_consent`.
Порты: на каждый supported порт один тест через `plugin_call_approved` (реальная операция) + независимый верификатор; для unsupported — тест, что причина отображается.

### 9.3 Стадии (независимо ревьюируемые)
| Задача | Содержание | Владелец (outline брифа) | Зависит |
|---|---|---|---|
| **MP0** | Инвентаризация: `Compiled::imports()` 34 wasm; по каждому методу — интерактив, ключевые виды, опции, число подписей, Origin под `LocalOperator`, состояние; таблица supported/unsupported с причинами в `docs/design/manual-plugins-inventory.md`; решение о запуске MP3b | read-only + прогон | — |
| **MP1** | Схема `[[operations]]`, профиль, проверки разбора, `added_over`, `min_core` | `oncl-plugin` manifest/package | — |
| **MP2** | `install` с `package_sha256`, `KeyScope::Declared`, `from_operation`, `plugin_request`, deny-by-default | `oncl-core` plugins | MP1 |
| **MP3a-1** | `ctx.plugin_ticket`, `KeyUseEvent.plugin`, `PluginConsentGuard`, серверный гард; отказ документного гарда на билет | `oncl-core` keys/context | MP2 |
| **MP3a-2** | `PluginApproval`, принуждение профиля, `cosign=never`, `bound` и `Digest`-bound, TTL, `max_uses=1` | `oncl-core` approval | MP3a-1 |
| **MP3a-3** | Подкоды (`oncl-core` ошибки + контракт DTO), аудит BEGIN/FINAL | `oncl-core` + `oncl-server` audit | MP3a-2 |
| **MP3b** | `plugin_plan`, allow-list, детерминизм, полное превью ≤ 64 КиБ; **отдельный выпуск**, старт после MP0 | `oncl-core` + `oncl-plugin` | MP3a-3, MP0 |
| **MP4** | `PluginInteraction` (ключевой выбор по привязанному ключу, `terminals`, запрет диалогов) | `oncl-plugin/headless.rs` | MP2 (параллельно MP1–MP2 допустимо) |
| **MP5a** | Страница «Плагины»: список операций (+unsupported с причиной), параметры, раннер, отчёт | `oncl-ui` | MP3a-2, MP4, MP7 |
| **MP5b** | Страница согласия (доверенные поля, профиль, сеть) и доступность (фокус/Enter/DPI/screen reader) | `oncl-ui` + slint | MP5a |
| **MP5c** (сделано) | `install_plugin.rs`: показ операций; повторное согласие при смене `[[operations]]` | `oncl-ui` | MP1 |
| **MP6** | Объявления портов волнами ≤ 6, по MP0; тесты портов | по агенту на волну | MP0, MP1, MP2, MP3a-3, MP4 (+MP3b для derived-операций) |
| **MP7** | Desktop: `openncalayer/src/plugins.rs` (реестр из `Store`, хеш, обновление), feature `oncl-core/plugins` для `oncl-ui/openncalayer`, размер бинаря | `openncalayer` | MP2 |
| **MP8** | `oncl-api` DTO/OpenAPI/клиент: подкоды, `plugin_bytes`; сервер/CLI-валидация против объявления; `docs/user` | `oncl-api/server/cli` | MP3a-3 |
| **MP8b** (позже, не блокирует) | Типизированные параметры и document parts для серверной операции плагина | отдельный план | MP8 |
| **MP9** | CLI `oncl plugin`: валидация, `--plugin-bytes`, тесты | `oncl-cli` | MP8 |
| **MP10** | `cargo xtask plugin-ops-check` (линтер объявлений: imports ⊆ compiled, `max_uses=1`, raw/derived, плейсхолдеры) | `xtask` | MP1 |
| **MP11** | Выпуск 34 новых версий пакетов: `registry.toml`, хеши, подписанный индекс (`update-index.md`) | релизный агент | MP6 |
| **MP12** | Документация (`plugins.md`, `platform.md §8.3`, user-доки), нативный smoke | один агент | MP5b, MP11 |
| **MP13** (отдельно) | ABI v2 `oncl_prepare/oncl_finish` (модель B) для derived-raw | отдельный план | — |

Каждая задача: RED-тест → GREEN → фокусные `cargo test -p …`; общий CI один раз в конце, как в плане.

### 9.4 Точная поправка плана
В `docs/superpowers/plans/2026-11-02-platform.md`, Task 30, **второй** пункт чек-листа (строка `plan:495`): блок `**[ОТКРЫТО, 2026-11-05: …]**` заменить (от маркера `**[ОТКРЫТО, 2026-11-05:` до закрывающего `]**` пункта) на:

> **[ПЕРЕНАЗНАЧЕНО, 2026-11-07: «поддерживаемые plugins» в ручном окне исполняются по `docs/design/manual-plugins.md` (вариант A, гибрид C): операции и профиль подписи в манифесте, билет применения ключа в `KeyUseGuard::before_use`, `bound` первым, `derived` отдельным этапом; диалоги плагина запрещены; Origin не подставляется; непригодные порты перечисляются с причиной. Задачи MP0–MP12 (Task 30P). Encrypt/decrypt/recipients по-прежнему исключены до G01/G02.]**

Добавить после Task 30:

> ### Task 30P — MP0–MP12: плагины в ручном окне
> **Files:** `crates/oncl-plugin/src/{manifest,package,store,headless}.rs`, `crates/oncl-core/src/{plugins.rs,plugins/{approval,plan}.rs,keys.rs,context.rs,error.rs}`, `crates/oncl-ui/src/workspace/plugins.rs`, `crates/oncl-ui/ui/plugins.slint`, `crates/openncalayer/src/plugins.rs`, `crates/oncl-api/src/{dto,openapi,client}.rs`, `crates/oncl-server/src/{config,service,audit}.rs`, `crates/oncl-cli/src/plugin.rs`, `plugins/*/plugin.toml`, `xtask`, `docs/design/{plugins,platform}.md`, `docs/user/*`.
> **Interfaces:** `[[operations]]` манифеста с профилем подписи; `PluginApproval`, `PluginUse` (билет), `Engine::plugin_request/plugin_call_approved/plugin_plan`; ABI `ABI_VERSION = 1` и токены не меняются.
> - [ ] MP0 инвентаризация (supported/unsupported с причинами) → MP1 схема → MP2 реестр/хеш/`KeyScope::Declared` → MP3a-1/2/3 билет, одобрение, профиль, подкоды, аудит → MP4 ключевой выбор → MP7 desktop wiring → MP5a/b/c UI и доступность → MP8/MP9 API/сервер/CLI → MP10 линтер → MP6 порты волнами → MP11 выпуск пакетов → MP12 документация и smoke. MP3b (`derived`) — отдельный поздний выпуск по итогам MP0.
> - [ ] RED/GREEN: тесты §9.2 документа дизайна (`a_b_a_swap`, `key_use_with_other_bytes_is_not_applied`, `options_outside_profile_are_refused`, `forged_operation_name`, `catalog_update_adding_key_operation_requires_consent`); мутации «дайджест по пути», «опции не в билете», «`name`/`label` в доверенной строке» убиваются.
> - [ ] Не подставлять Origin; не сохранять согласие; `Dialog*` запрещены; `raw`/`Digest` только `bound`; не менять ABI и токены.

В строке «Не выбранные функции … plugin-form schema …» (`plan:630`) добавить пояснение: `[[operations.params]]` — типизированные параметры одной операции, а не конструктор форм настроек плагина.

## 10. Риски и оговорки
- Доля портов, годных к ручному окну, мала или неизвестна до MP0 (Origin/диалоги/`keys::open`); возможна ситуация, когда в первом выпуске supported — единицы портов. Решение «все пригодные» не сужается.
- `derived` (MP3b) — оценка человека по полному превью; выпуск откладывается до MP0 и может не состояться, если пригодных derived-портов нет.
- Подкоды ошибок меняют публичный контракт `oncl-api` (поле, а не новый код) и требуют обновления OpenAPI/клиента (MP8).
- `cosign=never` для простого `KeysSignCms` — осознанное отличие от унаследованной семантики `Auto` в ручном окне.
- Номера строк привязаны к tip `08891678`; при исполнении сверять.
