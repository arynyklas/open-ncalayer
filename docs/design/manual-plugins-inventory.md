# MP0 — инвентаризация портов: что из 34 плагинов может работать в окне ручных инструментов

**Статус:** результат стадии MP0 (`docs/design/manual-plugins.md` §9.3). База: ветка `feat/platform-sdk-apps`, tip `ea0af85e`. Кода продукта не менялось. Язык документа — русский, как у дизайна; идентификаторы и имена файлов — как в репозитории.

Таблица **порт × метод → supported | unsupported(причина)** построена по реальным данным: секция импортов 34 собранных wasm-модулей (уровень доказательства **W**, самый сильный), чтение исходников пути каждого метода (**S**), существующие тесты портов, которые при сборке этого коммита проходят (**T**), и вызов-граф-скрипт по именам функций (**G**, слабый; только для строк «не подписывает», помеченных `G`). Прогон реального headless-пути `oncl-core` с синтетическим ключом **не выполнялся** (см. §2.3): вместо него — существующие тесты `oncl-port-tests` на интерактивной среде (`Harness::call` — свежий экземпляр на вызов, диалоги по сценарию, `origin = None`), они зелёные на этом коммите.

## 0. Итог в цифрах

- Портов (wasm-пакетов): **34** (35 имён `modules`: у `documentolog` два). Методов (операций, видимых WSS-вызывающему, включая диспетчерские ветки): **166**.
- **supported** (полностью или с условиями шаблона): **15** метод(ов) в **9** портах: `dogovor24`, `efactoring`, `energy`, `eproc`, `esf-osdkz`, `fhs`, `market`, `qiwi`, `rating1c`.
- **unsupported:** **59** метод(ов). **Не подписывают** (нет применения ключа; в окне не предлагаются, показаны для полноты): **92**.
- Портов без единого supported-метода: **25** из 34 (см. §4.3).

## 1. Метод и уровни доказательства

| Уровень | Что означает |
|---|---|
| **W** | Факт есть в секции импортов wasm (импорт `oncl::<имя>`): прямой разбор бинарника скриптом `scripts/mp0_wasm_imports.py`. Показывает, что порт *может* вызвать эту функцию хоста; не показывает, *на каком методе*. |
| **S** | Прочитан исходник пути метода (диспетчер → функция → вызываемые хост-функции). Номера строк указаны. |
| **T** | Есть существующий тест порта (`crates/oncl-port-tests/tests/*`), подтверждающий поведение; тесты `clones`, `ecc`, `medium` выполнены на этом коммите (97 ок). |
| **G** | Только имена в вызов-графе (грубое приближение, завышает набор вызовов). Используется лишь в строках «не подписывает». |

**Как собраны wasm.** `cd plugins && cargo build --release --locked --target wasm32-unknown-unknown --workspace` (цель `wasm32-unknown-unknown` установлена; сеть не потребовалась, `vendor/` и `Cargo.lock` есть): 34 `oncl_port_*.wasm`, 30 с лишним секунд. Это сборка без `--remap-path-prefix` из `cargo xtask plugin pack` (xtask/src/plugin.rs:117-139); набор импортов от этого не зависит. Импорты читает `python scripts/mp0_wasm_imports.py <каталог>/wasm32-unknown-unknown/release`: то, что возвращает `Compiled::imports()` (`crates/oncl-plugin/src/runtime.rs:350`: «in the order of its import section»; модуль `oncl`, имена — `Import::name()` в `crates/oncl-pdk/src/abi.rs`). Все 34 модуля импортируют только из `oncl`; все имена известны ABI.

## 2. Факты рантайма, от которых зависит вердикт

Это то, что реально делает хост, а не то, что предполагает дизайн. Все номера строк — этого worktree.

| # | Факт | Где | Следствие для окна ручных инструментов |
|---|---|---|---|
| F1 | `call_headless` создаёт **новый экземпляр** модуля на каждый вызов (`Guest::new(self, state)`), «ничего не переживает вызов» | `crates/oncl-plugin/src/headless.rs:132-156` (комментарий `:132-133`, `Guest::new` — `:156`) | Любое состояние плагина в памяти wasm (`thread_local!`, `static Mutex`) между двумя вызовами теряется. В WSS экземпляр живёт на сессию (`crates/oncl-plugin/src/modules.rs:1-18`), поэтому порты вида «`selectKey` → `sign`» работают по WSS и **не работают** вызов за вызовом. Дизайн упоминает только `shared_get/put` и `settings`; **in-instance state — отдельная и главная причина** (порты: arta, buhta, devart, doodocs, skf, taxtech и др.). |
| F2 | `requires_interaction`: `Dialog*`, `KeysChoose/Select/FlowOpen/FlowPick`, `File*`, `CoreOpenWindow`, `Keystore*` → `InteractionRequired` до диспетча | `headless.rs:105-131`, проверка в `dispatch` — `:88-104` | Как C6. Ключевые `select/choose` получат ответ Core (MP4); `Dialog*`/`File*` остаются запретом. |
| F3 | Backend Core обслуживает только: Hash, KeysSignRaw (`plugins.rs:346-410`), Shared, Now, Log, Settings, PageFile, Http, KeysSign{Cms,CmsEx,Xml,XmlEx,Xades}, CmsVerify, Ca*/Ocsp/Crl/Tsp*, KeysDescribe/Chain/Release, плюс «публичные» Random/CertInfo/CertDetails/XmlVerify/Platform/LocalTime (`headless.rs:194-209`). **Всё прочее — `PermissionDenied`** (`crates/oncl-core/src/plugins/capabilities.rs:203`): `keys_open`, `keys_terminals`, `reply_drop`, `call_locale`, `core_*`, `tokens_*`. | `capabilities.rs:38-205` | `reply_drop` (его линкуют **33 из 34** портов; вызывается только на нечитаемый запрос) и `call_locale` в дизайне §3.5 не упомянуты; `keys_terminals` дизайн отвечает `[]` (MP4). Для supported-портов `reply_drop` достижим только при нечитаемом `request`, который строит хост. |
| F4 | `page_file_read` отдаёт только **заранее привязанный вход** с именем = точному пути; `page_file_write` принимает `dir`/`name` **без** `/ \ : NUL` и расширение из `page_files_ext`, и только заранее привязанный выход | `capabilities.rs:206-285` (`safe` — `:243-250`) | Порты, требующие «диска страницы» (`arta.signFilePath`, `ezsigner.signFilePath`), зовут `page_file_write` с диском-путём (`drive_C:\…`), который отвергается **после** применения ключа: честный отказ до ключа невозможен. |
| F5 | У ручного вызова нет Origin: `encode_input(request, caller.browser_origin(), "ru", None)`; `LocalOperator` даёт `None` | `headless.rs:144-145` | Порты, читающие `request.origin`: ровно **7 из 34** (см. §3, колонка Origin). Остальные 27 Origin не читают (`grep -E '\.origin\b|origin:'` по `plugins/*/src`). |
| F6 | Язык окна для плагина в headless фиксирован `"ru"` | `headless.rs:144-145` | Влияет только на тексты диалогов/ответов; для supported-методов не критично. |

### 2.1 Классы импортов (применяются к секции импортов каждого порта)

| Класс | Импорты | Политика окна ручных инструментов (дизайн §3.5) |
|---|---|---|
| A | `keys_select`, `keys_choose`, `keys_release`, `keys_describe`, `keys_chain` | разрешены; выбор отвечает Core для единственного привязанного ключа |
| T | `keys_terminals` | `[]`; порт, у которого **успех** требует непустого списка считывателей, — unsupported (TERMINALS) |
| SIGN | `keys_sign_raw`, `keys_sign_cms`, `keys_sign_cms_ex`, `keys_sign_xml`, `keys_sign_xml_ex`, `keys_sign_xades` | по одному применению ключа; профиль принуждает Core |
| F | `dialog_*`, `file_*`, `keys_open`, `page_file_*` | запрещены; если нужны на успешном пути — unsupported |
| NET | `ocsp_fetch`, `tsp_stamp`, `tsp_request`, `crl_fetch`, `ca_*`, `pkix_path` (PKI); `http_request_ex` (произвольный http(s)) | в согласии показывается сеть; произвольный `http_request_ex` — отдельное решение |
| ST | `shared_*`, `settings_*` | состояние между вызовами: в headless недоступно |
| V | `cms_verify`, `xml_verify` | локальная проверка (`xml_verify` разрешён; `cms_verify` в плане запрещён) |
| нейтральные | `log`, `now`, `random`, `cert_info`, `cert_details`, `hash`, `local_time`, `platform`, `reply_drop` | см. F3 про `reply_drop` |

### 2.2 Матрица импортов портов (уровень **W**)

Колонки: выбор ключа (sel), терминалы (term), виды подписи (sign), диалоги (dlg), файлы/page-file (file), `keys_open` (open), сеть (net), состояние (state), читает ли порт `request.origin` (origin: **yes** — читает). «Supported / всего» — число методов из §3.

| Порт | modules | sel | term | sign | dlg | file | open | net | state | origin | supported / sign-методов |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `acbank` | `kz.acbank.business.api.ncalayer.module` | keys_select |  | raw | choice message |  |  |  | shared_get shared_put |  | 0 / 2 |
| `arta` | `kz.arta.synergy.signmodule` | keys_select | yes | cms_ex raw xml_ex |  | file_choose page_file_read page_file_write |  | ocsp_fetch |  |  | 0 / 4 |
| `bas` | `kz.bas.nca.multiSignService` | keys_select |  | cms_ex |  |  |  | ocsp_fetch tsp_stamp |  |  | 0 / 1 |
| `buhta` | `com.buhta.cert.ncamodule` | keys_select |  | cms_ex xml_ex |  |  |  |  |  | yes | 0 / 3 |
| `devart` | `kz.devart.bundle.Devart` | keys_select | yes | cms_ex raw xml |  |  |  | ocsp_fetch tsp_stamp |  |  | 0 / 1 |
| `documentolog` | `kz.documentolog.agent.SignService`, `kz.documentolog.agent.KalkanService` |  | yes | cms_ex xml_ex | choice password | file_choose | keys_open | http_request_ex |  |  | 0 / 4 |
| `dogovor24` | `kz.dogovor24.module` | keys_select |  | cms_ex |  |  |  | ocsp_fetch |  |  | 1 / 3 |
| `doodocs` | `kz.doodocs.moduleservice.SampleBundle` |  |  | cms_ex |  |  | keys_open |  |  |  | 0 / 2 |
| `efactoring` | `EFactoringSign` | keys_choose |  | cms_ex xml_ex | choice |  |  |  |  |  | 2 / 2 |
| `energy` | `kz.energy.sign.SignEnergy` | keys_select |  | cms_ex | message |  |  |  | settings_get settings_put |  | 1 / 1 |
| `eot` | `kz.gov.pki.eot.SignModule` | keys_select | yes | cms_ex |  |  |  | ca_issuer ocsp_fetch |  |  | 0 / 1 |
| `eproc` | `kz.sapa.eproc.osgi.EprocModule` | keys_select | yes | xml |  |  |  |  |  |  | 1 / 1 |
| `esf-osdkz` | `com.osdkz.esf.signer.esfSigner` | keys_select | yes | raw |  |  |  |  |  |  | 2 / 3 |
| `eup` | `kz.nitec.eup.eupsigner` | keys_select |  | cms_ex |  |  |  | ocsp_fetch |  |  | 0 / 1 |
| `ezsigner` | `kz.gov.pki.cms.CMSSignUtil` | keys_select | yes | cms_ex |  | file_choose page_file_read page_file_write |  | ca_issuer ocsp_fetch |  |  | 0 / 1 |
| `fhs` | `kz.fhs.cabinet.FHSCabinetSigner` | keys_select |  | cms_ex xml | choice | file_choose | keys_open | http_request_ex |  |  | 2 / 5 |
| `idocs` | `kz.idocs` | keys_select |  | cms_ex |  |  |  | ca_list ocsp_fetch |  |  | 0 / 1 |
| `k2sign` | `K2Sign` | keys_choose |  | cms_ex | message | file_open_ex |  | http_request_ex |  | yes | 0 / 2 |
| `knp` | `kz.inessoft.kgd.knp.ncalayer.KNPModuleService` |  | yes | xml_ex |  |  | keys_open | http_request_ex |  | yes | 0 / 1 |
| `market` | `MarketSign` | keys_choose |  | cms_ex xml_ex | choice |  |  |  |  |  | 2 / 2 |
| `metadoc` | `kz.metadoc.NCAModule` | keys_select | yes | cms_ex xml_ex | password | file_choose | keys_open | ca_issuer ocsp_fetch tsp_stamp |  |  | 0 / 2 |
| `motiw` | `ru.motiw.ModuleService` | keys_select | yes | cms_ex |  |  | keys_open |  |  |  | 0 / 1 |
| `nursign` | `NURSign` | keys_choose |  | cms_ex xml_ex | message | file_open_ex |  | http_request_ex |  | yes | 0 / 6 |
| `qiwi` | `kz.qiwi.osgi.SecurityUtils` | keys_select |  | xml_ex |  |  |  |  |  |  | 1 / 1 |
| `qoltanba` | `kz.btsdigital.qoltanba.CMSSignUtil` | keys_select | yes | cms_ex |  |  |  | ca_issuer ocsp_fetch |  | yes | 0 / 1 |
| `rating1c` | `kz.rating1c.edo.signUtils` | keys_select | yes | cms_ex raw xml_ex |  |  |  |  |  |  | 3 / 6 |
| `simourg` | `kz.Simourg.SimBASEModule` | keys_select | yes | cms_ex | choice |  |  | ca_list ocsp_fetch tsp_stamp |  |  | 0 / 2 |
| `skf` | `org.skf.osgi.SKFModule` |  | yes | xades | choice | file_choose | keys_open | http_request_ex ocsp_fetch |  |  | 0 / 1 |
| `taxtech` | `kz.digital.taxtech.documents.multisign.NCAModule` | keys_select |  | cms_ex raw xml |  |  |  |  |  | yes | 0 / 1 |
| `thundercrypt` | `asia.dbt.thundercrypt.osgi.ThunderCryptModule` |  |  | cms_ex | password |  | keys_open | ca_issuer crl_fetch ocsp_fetch tsp_request tsp_stamp |  |  | 0 / 1 |
| `uchet` | `kz.uchet.signUtil.commonUtils` | keys_select | yes | cms_ex xml_ex | message password | file_choose file_open_ex page_file_read page_file_write | keys_open | ca_issuer http_request_ex ocsp_fetch |  |  | 0 / 6 |
| `uchet-esf` | `kz.uchet.esfSignUtil` |  |  | raw xml |  |  | keys_open |  |  |  | 0 / 2 |
| `workspace` | `kz.workspace.Signer` | keys_select | yes | cms_ex | password |  | keys_open | ocsp_fetch tsp_stamp |  |  | 0 / 1 |
| `xdox` | `kz.xdox.signerbundle` | keys_select | yes | cms_ex |  |  |  | pkix_path |  | yes | 0 / 2 |

Число портов с импортом (из 34): `keys_release` 34, `log` 34, `random` 34, `reply_drop` 33, `keys_sign_cms_ex` 27, `keys_select` 24, `cert_info` 23, `cert_details` 22, `keys_terminals` 17, `now` 15, `ocsp_fetch` 15, `keys_open` 11, `keys_sign_xml_ex` 11, `local_time` 8, `dialog_choice` 7, `file_choose` 7, `http_request_ex` 7, `keys_sign_raw` 7, `ca_issuer` 6, `cms_verify` 6, `tsp_stamp` 6, `dialog_message` 5, `dialog_password` 5, `keys_sign_xml` 5, `keys_choose` 4, `platform` 4, `file_open_ex` 3, `hash` 3, `page_file_read` 3, `page_file_write` 3, `ca_list` 2, `keys_chain` 2, `xml_verify` 2, `crl_fetch` 1, `keys_sign_xades` 1, `pkix_path` 1, `settings_get` 1, `settings_put` 1, `shared_get` 1, `shared_put` 1, `tsp_request` 1.

### 2.3 Что не выполнялось

- **Headless-прогон реального `oncl-core` с синтетическим ключом не выполнен.** Путь `plugin_call_approved` (MP2/MP3a) и `PluginInteraction` (MP4) ещё не существуют; сегодняшний `call_headless` отвергает `keys::select` как `InteractionRequired` (F2), поэтому прогон портов через него невозможен без кода MP4. Это не обход требования, а нереализованная предпосылка.
- Вместо него выполнены существующие тесты `oncl-port-tests` (`cargo test -p oncl-port-tests --test clones --test ecc --test medium`: 97 passed) и прицельно `xdox_origin_substring_check`, `nursign_missing_origin_drops`, `k2_missing_origin_drops`. `heavy.rs` не запускался; на него ссылки уровня **T** указывают как на существующие тесты (`buhta_missing_origin_drops`, `qoltanba_origin_check`), а не как на выполненные мной.
- Все вердикты для supported-портов — это вердикт «по коду пути метода»; ни один не подтверждён подписью через будущий ручной путь.

## 3. Таблица «порт × метод → вердикт»

Обозначения вердиктов: **supported** — вызов работает как есть на привязанном ключе без `Dialog*/File*/keys::open`, без Origin, без состояния между вызовами, одна подпись, содержимое = аргумент; **supported\*** — то же, но при условиях (в колонке «Условия»: значения параметров шаблона, которые выбирает хост; `cosign=Auto` приводится к `Never`; диалог достижим только на пути ошибки, где трап `InteractionRequired` просто завершает вызов ошибкой); **unsupported** — причина(ы) из списка ниже; **no-sign** — метод не применяет ключ для подписи (информационный; в окне не предлагается).

Коды причин: `ORIGIN` — needs a page Origin (absent under LocalOperator; never faked); `DIALOG` — Dialog* import on the success path; `KEYS_OPEN` — keys::open with a path/bytes + password from the request (design 3.5: PermissionDenied); `STATE` — needs in-instance state left by an earlier call of the same session (fresh instance per manual call); `OPTIONS` — signing options outside the whitelist profile (attrs.extra/ESEDO, econtent_type, Custom TSA); `MULTI` — more than one signature per call (max_uses = 1); `FILE` — File*/page_file_* needed; `DERIVED` — signed bytes computed or fetched by the plugin (not an argument); `COSIGN` — cosign = Into(cms) (co-signing a CMS from the request); `HTTP` — arbitrary http(s) call outside the PKI allow-list that the success path needs (vendor licence server); `TERMINALS` — token-storage gate on keys::terminals, which the design answers [].

Колонки: `Импорты` — host-функции на пути метода (по чтению исходника); `Вид/опции` — вид ключевого применения и опции, **выбираемые плагином**; `Подписей` — число применений ключа за вызов; `Origin`; `State` — состояние между вызовами; `Содержимое` — bound (аргумент) или derived (вычислено/получено плагином); `Док-во` — уровень и якоря `файл:строка` (пути относительно `plugins/` или `crates/`).

| Порт | Метод | Вердикт | Причина / условия | Импорты метода | Вид / опции | Подписей | Origin | State | Содержимое | Док-во |
|---|---|---|---|---|---|---|---|---|---|---|
| `acbank` | `healthcheck` | **no-sign** |  | shared_get | - | 0 | no | reads shared window mark | - | S: acbank/src/lib.rs:122 |
| `acbank` | `signJsonWithJws` | **unsupported** | `DIALOG`, `MULTI`, `DERIVED` | dialog_choice (window loop), keys_select, keys_sign_raw xN, shared_put/get | raw; one raw signature per item over the plugin-built JWS signing input (header.payload) | N=len(signableItems) | no | shared_put/get window mark (re-entry guard) | derived (JWS input built from item JSON) | W+S: acbank/src/lib.rs:281, acbank/src/lib.rs:238 |
| `acbank` | `multiSignJsonWithJws` | **unsupported** | `DIALOG`, `MULTI`, `DERIVED` | dialog_choice (window loop), keys_select, keys_sign_raw xN, shared_put/get | raw; one raw signature per item over the plugin-built JWS signing input (header.payload) | N=len(signableItems) | no | shared_put/get window mark (re-entry guard) | derived (JWS input built from item JSON) | W+S: acbank/src/lib.rs:281, acbank/src/lib.rs:238 |
| `arta` | `getActiveTokens` | **no-sign** |  | keys_terminals | - | 0 | no | no | - | W+S: arta/src/port.rs:179 |
| `arta` | `checkModuleAvailability` | **no-sign** |  | - | - | 0 | no | no | - | S: arta/src/port.rs:189 |
| `arta` | `getKeyInfo` | **no-sign** |  | keys_select(Action::KeyInfo), keys_terminals | - | 0 | no | WRITES STATE (selected key kept in thread_local STATE) | - | W+S: arta/src/port.rs:260, arta/src/port.rs:99 |
| `arta` | `getFullKeyInfo` | **no-sign** |  | keys_select(KeyInfo) | - | 0 | no | writes state | - | W+S: arta/src/port.rs:278 |
| `arta` | `signFilePath` | **unsupported** | `STATE`, `FILE`, `DERIVED`; after the key use the output dir (contains ':' and separators) is rejected by write_bound_file | page_file_read, page_file_write, keys_sign_cms_ex | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | READS STATE (STATE.selected from getKeyInfo) | derived (file read by page path) | W+S+T: arta/src/port.rs:317, arta/src/port.rs:297, oncl-core/src/capabilities.rs:243 |
| `arta` | `signBase64File` | **unsupported** | `STATE`; without state the plugin swallows the error and answers code 200 with an empty responseObject (sign_base64_file) — a fake success | keys_sign_cms_ex | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | READS STATE | bound (base64 arg 0) | W+S+T: arta/src/port.rs:354, oncl-port-tests/tests/clones.rs:2038 |
| `arta` | `signDocument` | **unsupported** | `STATE` | keys_sign_raw, (digest object with fileNames: ocsp_fetch + keys_sign_cms_ex) | raw (+cms_ex ESEDO); INFO: no signing; SIGN: raw over dataForSign; with digest.fileNames also an ESEDO CMS with Custom TSA | >=1 (2 with fileNames) | no | READS STATE | bound (dataForSign) + derived (ESEDO) | W+S: arta/src/port.rs:372 |
| `arta` | `showFileChooser` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: arta/src/port.rs:512 |
| `arta` | `signXML` | **unsupported** | `STATE` | keys_sign_xml_ex | xml_ex; placement=FirstChildOfDocument, c14n Inclusive, transforms Enveloped+C14N-with-comments, sig/digest URIs by cert (rsa_sha256\|gost2004; GOST2015 -> default), strip_whitespace, declaration+standalone=no | 1 | no | READS STATE; null on failure | bound (xml arg 0) | W+S: arta/src/port.rs:552, arta/src/port.rs:561 |
| `bas` | `sign (single op, args=[b64,fileNames])` | **unsupported** | `OPTIONS` | keys_select, ocsp_fetch, keys_sign_cms_ex, tsp_stamp | cms_ex + tsp_stamp; econtent_type=1.3.6.1.4.1.6801.11.1.9, attrs.extra = 5 ESEDO attrs incl. OCSP response, signingTime UTCTime, ts=TsaChoice::Custom (tsp_stamp Replace/Append) | 1 | no | no | bound data (arg 0) but attrs carry network-derived bytes | W+S: bas/src/lib.rs:44, bas/src/lib.rs:108 |
| `buhta` | `call#1 SELECT_SIGN_CERT` | **unsupported** | `ORIGIN`, `STATE` | keys_select | - | 0 | YES (presence, any value): drops the connection | WRITES STATE (SELECTED uuid -> key) | - | W+S+T: buhta/src/lib.rs:118, buhta/src/lib.rs:41, oncl-port-tests/tests/heavy.rs:89 |
| `buhta` | `call#2 SIGN_DOCUMENT` | **unsupported** | `ORIGIN` | keys_select, keys_sign_cms_ex \| keys_sign_xml_ex | cms_ex (file) / xml_ex (xml); file: encapsulate=attached(param), cosign=Auto, ts=Kalkan, std attrs; xml: placement DocumentElement, URIs by key alg, enveloped | 1 | YES (presence) | may read SELECTED (sign.cert uuid) or select by tin | bound (document in payload protobuf/JSON) | W+S+T: buhta/src/lib.rs:118, buhta/src/lib.rs:289, buhta/src/lib.rs:331 |
| `buhta` | `call#3 BULK_SIGN_DOCUMENT` | **unsupported** | `ORIGIN`, `MULTI` | as handler 2 | cms_ex / xml_ex; as handler 2 | N=documents.len() | YES (presence) | as handler 2 | bound | W+S+T: buhta/src/lib.rs:118, buhta/src/lib.rs:298 |
| `devart` | `getSignerInfo` | **no-sign** | `STATE` | keys_select, keys_terminals | - | 0 | no | WRITES STATE (static SIGNERS token -> key) | - | W+S: devart/src/lib.rs:309, devart/src/lib.rs:85 |
| `devart` | `signDevart` | **unsupported** | `STATE`, `MULTI`, `OPTIONS` | keys_sign_raw (ESF), keys_sign_xml (XML), keys_sign_cms_ex + tsp_stamp (CMS), ocsp_fetch | raw / xml / cms_ex; CMS: cosign Never or Into(existing CMS), attrs without scv2, ts via tsp_stamp Custom TSA per signer; ESF raw; XML default | N=len(dataList) | no | READS STATE (token from getSignerInfo) | bound per item | W+S: devart/src/lib.rs:525, devart/src/lib.rs:657, devart/src/lib.rs:724 |
| `devart` | `extractFromCms` | **no-sign** |  | - | - | 0 | no | no | - | S: devart/src/lib.rs:768 |
| `documentolog` | `SignService.browseKeyStore` | **no-sign** | `DIALOG`, `FILE` | dialog_password, dialog_choice, file_choose, keys_terminals | - | 0 | no | writes STATE (kept password) | - | W+S: documentolog/src/lib.rs:209 |
| `documentolog` | `KalkanService.browseKeyStore` | **no-sign** | `DIALOG`, `FILE` | dialog_password, dialog_choice, file_choose, keys_terminals | - | 0 | no | writes STATE (kept password) | - | W+S: documentolog/src/lib.rs:209 |
| `documentolog` | `SignService.getKeys` | **no-sign** | `DIALOG`, `KEYS_OPEN` | dialog_password, keys_open | - | 0 | no | writes STATE (password) | - | W+S: documentolog/src/lib.rs:314 |
| `documentolog` | `KalkanService.getKeys` | **no-sign** | `DIALOG`, `KEYS_OPEN` | dialog_password, keys_open | - | 0 | no | writes STATE (password) | - | W+S: documentolog/src/lib.rs:314 |
| `documentolog` | `SignService.getSPAndSign / sign` | **unsupported** | `DIALOG`, `KEYS_OPEN`, `DERIVED`, `OPTIONS` | http_request_ex (challenge + order + document), dialog_password, keys_open, keys_sign_cms_ex / keys_sign_xml_ex | cms_ex (ESEDO / simple / CAdES) / xml_ex; ESEDO attrs.extra; Digest content (server digest); XML FirstChild enveloped | 1 | no (http origin only) | STATE (password) | derived (digest or document URL from the server's order) | W+S: documentolog/src/lib.rs:547, documentolog/src/lib.rs:440 |
| `documentolog` | `SignService.getSSAndSign` | **unsupported** | `DIALOG`, `KEYS_OPEN`, `DERIVED`, `OPTIONS` | http_request_ex (challenge + order + document), dialog_password, keys_open, keys_sign_cms_ex / keys_sign_xml_ex | cms_ex (ESEDO / simple / CAdES) / xml_ex; ESEDO attrs.extra; Digest content (server digest); XML FirstChild enveloped | 1 | no (http origin only) | STATE (password) | derived (digest or document URL from the server's order) | W+S: documentolog/src/lib.rs:547, documentolog/src/lib.rs:440 |
| `documentolog` | `KalkanService.createCMSEsedoSignature` | **unsupported** | `DIALOG`, `KEYS_OPEN`, `DERIVED`, `OPTIONS` | http_request_ex (sign_string_url), dialog_password, keys_open, keys_sign_cms_ex | cms_ex; ESEDO attrs.extra (file names, OCSP from page), attached=param | 1 | no | STATE (password) | derived (document downloaded from page URL) | W+S: documentolog/src/lib.rs:504 |
| `documentolog` | `KalkanService.createCMSSimpleSignature` | **unsupported** | `DIALOG`, `KEYS_OPEN`, `DERIVED` | http_request_ex, dialog_password, keys_open, keys_sign_cms_ex | cms_ex; encapsulate=param, cosign Never, certs=Chain, signs the BASE64 TEXT of the downloaded data | 1 | no | STATE (password) | derived (downloaded, then base64-encoded) | W+S: documentolog/src/lib.rs:504, documentolog/src/lib.rs:472 |
| `documentolog` | `KalkanService.init` | **no-sign** |  | - | - | 0 | no | no | - | S: documentolog/src/lib.rs:147 |
| `documentolog` | `KalkanService.getCertInfo` | **no-sign** | `KEYS_OPEN` | keys_open, dialog_password | - | 0 | no | STATE (password) | - | S: documentolog/src/lib.rs:147 |
| `documentolog` | `KalkanService.getSubjectDN` | **no-sign** | `KEYS_OPEN` | keys_open, dialog_password | - | 0 | no | STATE (password) | - | S: documentolog/src/lib.rs:147 |
| `documentolog` | `KalkanService.getCurrentUser` | **no-sign** |  | - | - | 0 | no | no | - | S: documentolog/src/lib.rs:147 |
| `documentolog` | `KalkanService.getCurrentStoragePath` | **no-sign** |  | - | - | 0 | no | no | - | S: documentolog/src/lib.rs:147 |
| `dogovor24` | `signCMS (args=[b64])` | **supported*** | key is selected before the method name is read; requires cert EKU present and without clientAuth (plugin check) | keys_select, keys_sign_cms_ex (+ Kalkan TSA inside the sign call), cert_info, random | cms_ex; encapsulate=true, cosign=Auto (coerce to Never), ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (base64 arg 0) | W+S+T: dogovor24/src/lib.rs:161, dogovor24/src/lib.rs:83, oncl-port-tests/tests/medium.rs:1984 |
| `dogovor24` | `batchSignCMS (args=[b64...])` | **unsupported** | `MULTI` | as signCMS | cms_ex; as signCMS, one signature per element | N=args.len() (1 element == signCMS) | no | no | bound | W+S: dogovor24/src/lib.rs:137 |
| `dogovor24` | `signEsedo (args=[b64,fileNames])` | **unsupported** | `OPTIONS` | ocsp_fetch, keys_sign_cms_ex | cms_ex; ESEDO attrs.extra (file names, ESEDO marker, signer DN, OCSP response), detached, Generalized signingTime, no TSA | 1 | no | no | bound data; attrs carry network data | W+S+T: dogovor24/src/lib.rs:49, dogovor24/src/lib.rs:205 |
| `doodocs` | `auth` | **unsupported** | `KEYS_OPEN`, `STATE` | keys_open (KeySource::Bytes + password text), cert_info, now | - | 0 | no | WRITES STATE (static SESSION signer, 5 min) | - | W+S: doodocs/src/lib.rs:129, doodocs/src/lib.rs:41 |
| `doodocs` | `createCAdESFromBase64` | **unsupported** | `STATE`, `KEYS_OPEN` | keys_sign_cms_ex | cms_ex; encapsulate=attached(param), cosign=Auto, ts=Kalkan, std attrs | 1 | no | READS STATE (SESSION from auth) | bound | W+S: doodocs/src/lib.rs:181, doodocs/src/lib.rs:247 |
| `doodocs` | `logOut` | **no-sign** |  | now | - | 0 | no | state only | - | S: doodocs/src/lib.rs:167 |
| `doodocs` | `isAuthorized` | **no-sign** |  | now | - | 0 | no | state only | - | S: doodocs/src/lib.rs:167 |
| `efactoring` | `version` | **no-sign** |  | - | - | 0 | no | no | - | S: efactoring/src/lib.rs:47 |
| `efactoring` | `text {data, attach?, has_timestamp?}` | **supported*** | the retry dialog (dialog_choice) traps with InteractionRequired: a failed signing ends the call as a host error instead of the plugin's retry window | keys_choose, keys_sign_cms_ex; dialog_choice only on failure | cms_ex; encapsulate=param attach (template: false), cosign=Auto (coerce Never), ts=Kalkan iff has_timestamp (template: true), attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (text param, UTF-8 bytes) | W+S+T: efactoring/src/lib.rs:64, efactoring/src/lib.rs:221, efactoring/src/lib.rs:250, oncl-port-tests/tests/ecc.rs:118 |
| `efactoring` | `xml {data, sign_element?, signature_parent_element?}` | **supported*** | XPaths are page text: in the window they must be typed params shown in the consent | keys_choose, keys_sign_xml_ex; dialog_choice only on failure | xml_ex; no element: placement DocumentElement; with element: placement Parent + element/parent XPaths (params), SOAP-ENV ns, c14n Exclusive, transforms Enveloped+C14N-with-comments; strip_whitespace, no line breaks, no declaration | 1 | no | no | bound (data, source must be 'local') | W+S+T: efactoring/src/lib.rs:86, efactoring/src/lib.rs:146 |
| `efactoring` | `binary` | **no-sign** | never signs: after the key dialog answers CANCEL or the failed-download window | keys_choose; dialog_choice | - | 0 | no | no | - | S: efactoring/src/lib.rs:122 |
| `energy` | `ping` | **no-sign** |  | - | - | 0 | no | no | - | S: energy/src/lib.rs:44 |
| `energy` | `getKeyInfo` | **no-sign** |  | keys_select(KeyInfo), settings_get/put | - | 0 | no | WRITES SETTINGS (alias record) | - | W+S: energy/src/lib.rs:97, energy/src/lib.rs:145 |
| `energy` | `sign {data:[{id,name,base64}], encapsulate?, isDigested?, tsaProfile?, alias?}` | **supported*** | dialog_message is reached only on failure (ALIAS_MISMATCH/SIGNING_ERROR/UNKNOWN_ERROR) -> trap | keys_select, keys_sign_cms_ex; dialog_message on error paths only | cms_ex; encapsulate=param (default true), cosign=Auto (Never if isDigested), content Data (Digest iff isDigested -> template false), ts=Kalkan iff tsaProfile, certs=Default(Signer), attrs ct+md+scv2+signingTime | N=len(data) (template: 1) | no | alias given -> REMEMBERED (static) and alias-mismatch dialog (template: omit alias) | bound (base64 of data[0]) | W+S+T: energy/src/lib.rs:162, energy/src/lib.rs:236, energy/src/lib.rs:26, oncl-port-tests/tests/medium.rs:538 |
| `eot` | `signCmsWithSignedAttrs(storage,keyType,b64,flag,fileNames)` | **unsupported** | `OPTIONS` | keys_select, keys_terminals(token only), ca_issuer, ocsp_fetch, keys_sign_cms_ex | cms_ex; content=Digest(arg: the page's digest), ESEDO attrs.extra incl. OCSP BasicResponse, detached, ts=Kalkan | 1 | no | no | Digest of an argument (page computed) | W+S: eot/src/lib.rs:37, eot/src/lib.rs:123 |
| `eproc` | `version` | **no-sign** |  | - | - | 0 | no | no | - | S: eproc/src/lib.rs:92 |
| `eproc` | `signXml {uid,chain?,storageName,keyType,xml,tbsElementXPath?,signatureParentElementXPath?}` | **supported*** | template: storageName=PKCS12 (no terminals call), keyType=SIGNATURE (bound key must have KNCA type SIGNATURE) | keys_select (+keys_terminals for token storages), keys_sign_xml, random | xml (keys_sign_xml, Core defaults); whole document, or element tbs with signature in parent (typed XPath params); no options chosen by the plugin | 1 | no | chain token = static CHAIN, only an optimisation (template: chain empty) | bound (xml param) | W+S: eproc/src/lib.rs:128, eproc/src/lib.rs:210, eproc/src/lib.rs:166 |
| `esf-osdkz` | `signPlainData {storageName,data}` | **supported*** | signs arbitrary text with a raw signature: the consent must show the text (design: raw only bound) | keys_select, keys_sign_raw, cert_details, cert_info | raw; raw signature of data's UTF-8 bytes, Action::Sign, filter KNCA=SIGNATURE; refuses algs other than gost2004/gost2015_512/rsa_sha256 | 1 | no | no | bound (data string) | W+S: esf-osdkz/src/lib.rs:112, esf-osdkz/src/lib.rs:227 |
| `esf-osdkz` | `auth {storageName,data}` | **supported*** | Action::Authenticate (a login challenge): the design has no ruling for Authenticate-kind use in the manual window | keys_select, keys_sign_raw | raw; raw signature of data; Action::Authenticate; AUTHENTICATION key, else SIGNATURE+GOST2015 fallback | 1 | no | no | bound (data string) | W+S: esf-osdkz/src/lib.rs:163 |
| `esf-osdkz` | `signPlainDataMap {storageName,data:{k:v..}}` | **unsupported** | `MULTI` | keys_select, keys_sign_raw xN | raw; one raw signature per map value | N=len(data) | no | no | bound | W+S: esf-osdkz/src/lib.rs:125 |
| `eup` | `sign (single op, args=[b64,fileNames])` | **unsupported** | `OPTIONS` | keys_select, ocsp_fetch, keys_sign_cms_ex | cms_ex; ESEDO attrs.extra incl. OCSP response, detached, Generalized time, no TSA | 1 | no | no | bound data; attrs carry network data | W+S: eup/src/lib.rs:46, eup/src/lib.rs:130 |
| `ezsigner` | `changeLang` | **no-sign** |  | - | - | 0 | no | LANG thread_local | - | S: ezsigner/src/port.rs:112 |
| `ezsigner` | `getMessage` | **no-sign** |  | - | - | 0 | no | no | - | S: ezsigner/src/port.rs:118 |
| `ezsigner` | `getDirectoryPath` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: ezsigner/src/port.rs:132 |
| `ezsigner` | `getFilePath` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: ezsigner/src/port.rs:148 |
| `ezsigner` | `signFilePath(filePath,fileDir,storageName)` | **unsupported** | `FILE`, `DERIVED`; the key is applied before page_file_write, whose dir (a drive path with ':' and separators) is rejected by write_bound_file: after-key failure | platform, page_file_read, keys_select, keys_terminals, ocsp_fetch, ca_issuer, keys_sign_cms_ex, page_file_write | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | LANG only | derived (file read by page path, Windows drive paths only) | W+S: ezsigner/src/port.rs:189, ezsigner/src/port.rs:171, oncl-core/src/capabilities.rs:243 |
| `fhs` | `getTradeCabBundleVersion` | **no-sign** |  | - | - | 0 | no | no | - | S: fhs/src/lib.rs:145 |
| `fhs` | `getCertificatePath` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: fhs/src/lib.rs:158 |
| `fhs` | `getCertificateInfo` | **no-sign** | `KEYS_OPEN` | keys_open (path+password) | - | 0 | no | no | - | W+S: fhs/src/lib.rs:193, fhs/src/lib.rs:180 |
| `fhs` | `signTextV2 {base64data,path,password}` | **unsupported** | `KEYS_OPEN` | keys_open, keys_sign_cms_ex | cms_ex; encapsulate=false, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (base64data) | W+S: fhs/src/lib.rs:363, fhs/src/lib.rs:180 |
| `fhs` | `signXmlV2 {xml,path,password}` | **unsupported** | `KEYS_OPEN` | keys_open, keys_sign_xml | xml; Core defaults | 1 | no | no | bound (xml) | W+S: fhs/src/lib.rs:397 |
| `fhs` | `signXml {xml} (V1)` | **supported*** | dialog_choice only on failure -> trap | keys_select (storages V1_STORAGES), keys_sign_xml; dialog_choice on failure only | xml; Core defaults, whole document | 1 | no | no | bound (xml) | W+S: fhs/src/lib.rs:463, fhs/src/lib.rs:444, fhs/src/lib.rs:427 |
| `fhs` | `signText {base64data} (V1)` | **supported*** | dialog_choice only on failure -> trap | keys_select, keys_sign_cms_ex; dialog_choice on failure only | cms_ex; encapsulate=false, cosign=Auto (coerce Never), ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (base64data) | W+S: fhs/src/lib.rs:505, fhs/src/lib.rs:312 |
| `fhs` | `signFile {url} (V1)` | **unsupported** | `DERIVED` | http_request_ex (GET url), keys_select, keys_sign_cms_ex | cms_ex; encapsulate=false, cosign=Auto, ts=Kalkan | 1 | no (http origin allow-list only) | no | derived (document downloaded from the page's URL) | W+S: fhs/src/lib.rs:477 |
| `idocs` | `sign {name,data}` | **unsupported** | `OPTIONS` | keys_select, ca_list, ocsp_fetch, keys_sign_cms_ex | cms_ex; ESEDO attrs.extra (name as file name, OCSP response of NCA GOST 2022 issuer), GOST2015-512 digest profile | 1 | no | no | bound data; attrs carry network data | W+S: idocs/src/lib.rs:57, idocs/src/lib.rs:182 |
| `k2sign` | `version` | **no-sign** | `ORIGIN`; the origin is read before `type`: even `version` drops without it | http_request_ex, cms_verify, dialog_message | - | 0 | YES (presence; also used as base URL) | no | - | W+S+T: k2sign/src/lib.rs:70, k2sign/src/lib.rs:1, oncl-port-tests/tests/ecc.rs:1309 |
| `k2sign` | `login` | **unsupported** | `ORIGIN`, `DERIVED`; the origin is read before `type`: even `version` drops without it | keys_choose, keys_sign_cms_ex, http_request_ex (upload) | cms_ex; encapsulate=false, cosign=Auto, ts=Kalkan iff has_tsa, std attrs | 1 | YES (presence; also used as base URL) | no | login: sessionId text; file: downloaded or user-picked file | W+S+T: k2sign/src/lib.rs:70, k2sign/src/lib.rs:106, oncl-port-tests/tests/ecc.rs:1309 |
| `k2sign` | `file` | **unsupported** | `ORIGIN`, `DERIVED`, `FILE`; the origin is read before `type`: even `version` drops without it | keys_choose, keys_sign_cms_ex, http_request_ex (upload) | cms_ex; encapsulate=false, cosign=Auto, ts=Kalkan iff has_tsa, std attrs | 1 | YES (presence; also used as base URL) | no | login: sessionId text; file: downloaded or user-picked file | W+S+T: k2sign/src/lib.rs:70, k2sign/src/lib.rs:132, oncl-port-tests/tests/ecc.rs:1309 |
| `k2sign` | `verify` | **no-sign** | `ORIGIN`; the origin is read before `type`: even `version` drops without it | http_request_ex, cms_verify, dialog_message | - | 0 | YES (presence; also used as base URL) | no | - | W+S+T: k2sign/src/lib.rs:70, k2sign/src/lib.rs:217, oncl-port-tests/tests/ecc.rs:1309 |
| `k2sign` | `verifyAll` | **no-sign** | `ORIGIN`; the origin is read before `type`: even `version` drops without it | http_request_ex, cms_verify, dialog_message | - | 0 | YES (presence; also used as base URL) | no | - | W+S+T: k2sign/src/lib.rs:70, k2sign/src/lib.rs:231, oncl-port-tests/tests/ecc.rs:1309 |
| `knp` | `info` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:41 |
| `knp` | `getAuthAccounts` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:42 |
| `knp` | `getStorageType` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:43 |
| `knp` | `getStorageDevicesByType` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:44 |
| `knp` | `hardwarePair` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:45 |
| `knp` | `attachDeviceToAccount` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:46 |
| `knp` | `getCertificates` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:47 |
| `knp` | `accountStatus` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:49 |
| `knp` | `getAgreementText` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:50 |
| `knp` | `signAgreement` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:51 |
| `knp` | `cancelAgreement` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:52 |
| `knp` | `changeAgreement` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:53 |
| `knp` | `signUp` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:54 |
| `knp` | `confirmSignUp` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:55 |
| `knp` | `resetPassword` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:56 |
| `knp` | `confirmResetPassword` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:57 |
| `knp` | `changeConfirmationType` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:58 |
| `knp` | `confirmChangeConfirmationType` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:60 |
| `knp` | `changePassword` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:63 |
| `knp` | `confirmChangePassword` | **no-sign** | `ORIGIN`; SmartAuth account commands; no key signature | http_request_ex (SmartAuth at origin base URL) | - | 0 | YES (presence; base URL of SmartAuth calls) | no | - | W+S: knp/src/lib.rs:80, knp/src/lib.rs:64 |
| `knp` | `signDocument {storageType/path/password,xml,outputFormat}` | **unsupported** | `ORIGIN`, `KEYS_OPEN` | keys_open (keys.rs), keys_terminals, keys_sign_xml_ex | xml_ex; by keys.rs::sign_xml | 1 | YES (presence) | no | bound (xml) | W+S: knp/src/lib.rs:80, knp/src/lib.rs:262, knp/src/keys.rs:51 |
| `market` | `version` | **no-sign** |  | - | - | 0 | no | no | - | S: market/src/lib.rs:41 |
| `market` | `text {data, attach?, has_timestamp?}` | **supported*** | dialog_choice on failure -> trap | keys_choose, keys_sign_cms_ex; dialog_choice on failure only | cms_ex; encapsulate=param attach (template false), cosign=Auto (coerce Never), ts=Kalkan iff has_timestamp, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (text param) | W+S+T: market/src/lib.rs:59, market/src/lib.rs:150, oncl-port-tests/tests/ecc.rs:118 |
| `market` | `xml {data}` | **supported*** | dialog_choice on failure -> trap | keys_choose, keys_sign_xml_ex; dialog_choice on failure only | xml_ex; whole document, default placement, strip_whitespace, no line breaks, no declaration | 1 | no | no | bound (xml) | W+S+T: market/src/lib.rs:82, market/src/lib.rs:105 |
| `metadoc` | `getKeyInfo(storage)` | **no-sign** |  | keys_select(KeyInfo), keys_terminals | - | 0 | no | no | - | W+S: metadoc/src/port.rs:223 |
| `metadoc` | `getModuleVersion` | **no-sign** |  | - | - | 0 | no | no | - | S: metadoc/src/port.rs:179 |
| `metadoc` | `getKeyInfoByFilePathAndPassword` | **no-sign** | `KEYS_OPEN` | keys_open | - | 0 | no | no | - | W+S: metadoc/src/port.rs:268 |
| `metadoc` | `getFilePath` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: metadoc/src/port.rs:249 |
| `metadoc` | `signXml {keyType,filePath\|tokenName,password?,xml}` | **unsupported** | `KEYS_OPEN` | keys_open; dialog_password iff password blank; keys_sign_xml_ex | xml_ex; whole document (sign_xml(.., '', '')) | 1 | no | no | bound (xml) | W+S: metadoc/src/port.rs:363, metadoc/src/port.rs:289 |
| `metadoc` | `(any other method name) sign {dataForSign,filesNames,hashed?,...}` | **unsupported** | `KEYS_OPEN`, `OPTIONS`, `DIALOG` | keys_open, dialog_password iff password blank, ca_issuer, ocsp_fetch, keys_sign_cms_ex, tsp_stamp, cms_verify | cms_ex + tsp; ESEDO attrs.extra, hashed -> Digest, Custom TSA, post-sign self check | 1 | no | no | bound/Digest of arg, attrs network-derived | W+S: metadoc/src/port.rs:403, metadoc/src/port.rs:442 |
| `motiw` | `getStoragesList` | **no-sign** |  | keys_terminals | - | 0 | no | no | - | W+S: motiw/src/lib.rs:254 |
| `motiw` | `getContainerList` | **no-sign** |  | keys_terminals | - | 0 | no | no | - | W+S: motiw/src/lib.rs:269 |
| `motiw` | `getCertificateList` | **no-sign** | `KEYS_OPEN` | keys_open | - | 0 | no | no | - | G: motiw/src/lib.rs:326 |
| `motiw` | `verify` | **no-sign** |  | cms_verify | - | 0 | no | no | - | W+S: motiw/src/lib.rs:414 |
| `motiw` | `showStorageKey` | **no-sign** |  | keys_select(KeyInfo) | - | 0 | no | no | - | W+S: motiw/src/lib.rs:164 |
| `motiw` | `sign(storage,container,password,alias,data,format,attach)` | **unsupported** | `KEYS_OPEN` | keys_open (token reader + password), keys_sign_cms_ex | cms_ex; encapsulate=attach(arg), cosign=Auto, ts=Kalkan iff format>1, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (base64 arg 4) | W+S: motiw/src/lib.rs:340 |
| `nursign` | `version` | **no-sign** | `ORIGIN`; every error path also calls dialog_message | - | - | 0 | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, oncl-port-tests/tests/ecc.rs:648 |
| `nursign` | `text` | **unsupported** | `ORIGIN`; every error path also calls dialog_message | keys_choose, keys_sign_cms_ex\|keys_sign_xml_ex, http_request_ex, file_open_ex (file), dialog_message (every error) | cms_ex; cms: cosign=Auto, ts=Kalkan (text) / none (binary,file), encapsulate=true(text)/false; xml: whole document | 1 | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, nursign/src/lib.rs:112, oncl-port-tests/tests/ecc.rs:648 |
| `nursign` | `multitext` | **unsupported** | `ORIGIN`, `MULTI`; every error path also calls dialog_message | keys_choose, keys_sign_cms_ex\|keys_sign_xml_ex, http_request_ex, file_open_ex (file), dialog_message (every error) | cms_ex; cms: cosign=Auto, ts=Kalkan (text) / none (binary,file), encapsulate=true(text)/false; xml: whole document | N | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, nursign/src/lib.rs:124, oncl-port-tests/tests/ecc.rs:648 |
| `nursign` | `binary` | **unsupported** | `ORIGIN`; every error path also calls dialog_message | keys_choose, keys_sign_cms_ex\|keys_sign_xml_ex, http_request_ex, file_open_ex (file), dialog_message (every error) | cms_ex; cms: cosign=Auto, ts=Kalkan (text) / none (binary,file), encapsulate=true(text)/false; xml: whole document | 1 | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, nursign/src/lib.rs:148, oncl-port-tests/tests/ecc.rs:648 |
| `nursign` | `xml` | **unsupported** | `ORIGIN`; every error path also calls dialog_message | keys_choose, keys_sign_cms_ex\|keys_sign_xml_ex, http_request_ex, file_open_ex (file), dialog_message (every error) | xml_ex; cms: cosign=Auto, ts=Kalkan (text) / none (binary,file), encapsulate=true(text)/false; xml: whole document | 1 | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, nursign/src/lib.rs:183, oncl-port-tests/tests/ecc.rs:648 |
| `nursign` | `multixml` | **unsupported** | `ORIGIN`, `MULTI`; every error path also calls dialog_message | keys_choose, keys_sign_cms_ex\|keys_sign_xml_ex, http_request_ex, file_open_ex (file), dialog_message (every error) | xml_ex; cms: cosign=Auto, ts=Kalkan (text) / none (binary,file), encapsulate=true(text)/false; xml: whole document | N | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, nursign/src/lib.rs:200, oncl-port-tests/tests/ecc.rs:648 |
| `nursign` | `file` | **unsupported** | `ORIGIN`, `FILE`, `DERIVED`; every error path also calls dialog_message | keys_choose, keys_sign_cms_ex\|keys_sign_xml_ex, http_request_ex, file_open_ex (file), dialog_message (every error) | cms_ex; cms: cosign=Auto, ts=Kalkan (text) / none (binary,file), encapsulate=true(text)/false; xml: whole document | 1 | YES (presence; host allow-list and relative URLs) | no | data arg, or file at upload_url (download), or picked file | W+S+T: nursign/src/lib.rs:70, nursign/src/lib.rs:221, oncl-port-tests/tests/ecc.rs:648 |
| `qiwi` | `signXml [callID, xml]` | **supported*** | algorithm URIs depend on the key: the profile must accept Kalkan's URIs of the key (default) — for GOST 2015 keys the plugin asks GOST 2004 URIs, which the core's `known URIs fitting the key` rule may refuse (abi.rs SignXmlExArgs.signature_method) | keys_select, keys_sign_xml_ex, xml_verify, now | xml_ex; placement=FirstChildOfDocument, c14n Inclusive, transforms Enveloped+C14N-with-comments, signature/digest URIs by cert signature alg (RSA-SHA1, RSA-SHA256, else GOST 2004 URIs, GOST 2015 included), strip_whitespace=false, declaration+standalone=no | 1 | no | SESSION (static) is only a 20-minute key cache; first call selects | bound (xml arg 1) | W+S+T: qiwi/src/lib.rs:104, qiwi/src/lib.rs:145, oncl-port-tests/tests/medium.rs:1342 |
| `qiwi` | `logOut` | **no-sign** |  | - | - | 0 | no | clears SESSION | - | S: qiwi/src/lib.rs:84 |
| `qoltanba` | `signFileBytes(data,storage)` | **unsupported** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | keys_select, keys_terminals, ca_issuer, ocsp_fetch, keys_sign_cms_ex, cms_verify | cms_ex; encapsulate=true?, cosign=Auto, ts=Kalkan, std attrs | 1 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | bound (base64 arg 0) | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `qoltanba` | `checkCMSBytes` | **no-sign** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | - | - | 0 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | - | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `qoltanba` | `visualCMS` | **no-sign** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | - | - | 0 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | - | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `qoltanba` | `extractSignedFileBytes` | **no-sign** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | - | - | 0 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | - | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `qoltanba` | `changeLang` | **no-sign** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | - | - | 0 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | - | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `qoltanba` | `getMessage` | **no-sign** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | - | - | 0 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | - | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `qoltanba` | `getJson` | **no-sign** | `ORIGIN`; any request that names a method gets INVALID_ORIGIN under an absent Origin | - | - | 0 | YES: https://qoltanba.kz or a subdomain (site-specific check) | LANG thread_local | - | W+S+T: qoltanba/src/lib.rs:171, qoltanba/src/lib.rs:201, oncl-port-tests/tests/heavy.rs:2690 |
| `rating1c` | `getActiveTokens` | **no-sign** |  | keys_terminals | - | 0 | no | no | - | W+S: rating1c/src/port.rs:83 |
| `rating1c` | `getKeyInfo` | **no-sign** |  | keys_select(KeyInfo) | - | 0 | no | no | - | W+S: rating1c/src/port.rs:186 |
| `rating1c` | `TestConnect` | **no-sign** |  | - | - | 0 | no | no | - | S: rating1c/src/port.rs:93 |
| `rating1c` | `TestKeyOwner` | **no-sign** |  | keys_select(KeyInfo) | - | 0 | no | no | - | W+S: rating1c/src/port.rs:196 |
| `rating1c` | `signXml(storage,keyType,xml,tbsXPath,parentXPath,BIN)` | **supported** | template: storage=PKCS12, keyType=SIGNATURE, BIN=''; bound cert must pass the plugin's validity check (expired -> error) | keys_select (+keys_terminals for token storages), keys_sign_xml_ex | xml_ex; via legacy::sign_xml: no tbs -> placement DocumentElement; tbs+parent -> Parent (XPath params); strip_whitespace, no line breaks, no declaration | 1 | no | no | bound (xml arg 2) | W+S+T: rating1c/src/port.rs:213, common/legacy/src/guest.rs:37, oncl-port-tests/tests/clones.rs:214 |
| `rating1c` | `signXmls(storage,keyType,xmls[],...)` | **unsupported** | `MULTI` | as signXml | xml_ex; as signXml per document | N=len(xmls) | no | no | bound | W+S: rating1c/src/port.rs:222 |
| `rating1c` | `createCmsFromBase64(storage,keyType,b64,attached,withTSA,BIN)` | **supported*** |  | keys_select, keys_sign_cms_ex | cms_ex; encapsulate=attached(param), cosign=Auto via Default (coerce Never), ts=Kalkan iff withTSA, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (base64 arg 2) | W+S+T: rating1c/src/port.rs:244, rating1c/src/port.rs:236, common/legacy/src/lib.rs:149 |
| `rating1c` | `createCmsesFromBase64(storage,keyType,b64s[],...)` | **unsupported** | `MULTI` | as createCmsFromBase64 | cms_ex; per element | N=len(base64s) | no | no | bound | W+S: rating1c/src/port.rs:252 |
| `rating1c` | `createRawSignFromBase64(storage,keyType,b64,BIN)` | **supported** |  | keys_select, keys_sign_raw, cert_details | raw; raw signature of decoded base64 (SHA256withRSA for RSA, key's own for GOST) | 1 | no | no | bound (base64 arg 2) | W+S+T: rating1c/src/port.rs:281, rating1c/src/port.rs:266 |
| `rating1c` | `createRawsSignFromBase64(storage,keyType,b64s[],BIN)` | **unsupported** | `MULTI` | as createRawSignFromBase64 | raw; per element | N=len(base64s) | no | no | bound | W+S: rating1c/src/port.rs:291 |
| `simourg` | `salemAit` | **no-sign** |  | - | - | 0 | no | no | - | S: simourg/src/lib.rs:158 |
| `simourg` | `createCMSSignatureWithTspFromBase64[storage,keyType,b64,attached,fileNames]` | **unsupported** | `DIALOG`, `OPTIONS` | keys_select, dialog_choice (confirm window on EVERY signing), ca_list, ocsp_fetch, keys_sign_cms_ex | cms_ex; ESEDO attrs.extra incl. checked OCSP answer, encapsulate=attached, ts=Kalkan | 1 | no | no | bound data; attrs network-derived | W+S: simourg/src/lib.rs:223, simourg/src/lib.rs:307 |
| `simourg` | `createCMSForEsedo[storage,keyType,b64,-,fileNames]` | **unsupported** | `DIALOG`, `OPTIONS` | keys_select, dialog_choice, ocsp_fetch, keys_sign_cms_ex, tsp_stamp x2 | cms_ex + 2 stamps; ESEDO attrs.extra, Custom GOST TSA stamp then Kalkan stamp | 1 | no | no | bound data; attrs network-derived | W+S: simourg/src/lib.rs:359 |
| `skf` | `getBundleVersion` | **no-sign** |  | - | - | 0 | no | no | - | S: skf/src/lib.rs:249 |
| `skf` | `myLoadSlotList` | **no-sign** | `DIALOG` | keys_terminals, dialog_choice | - | 0 | no | no | - | W+S: skf/src/lib.rs:290 |
| `skf` | `myBrowseKeyStore` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: skf/src/lib.rs:336 |
| `skf` | `getKeys` | **no-sign** | `KEYS_OPEN` | keys_open (storage+path+password), http_request_ex (CA list) | - | 0 | no | WRITES STATE (Skf.key) | - | W+S: skf/src/lib.rs:520 |
| `skf` | `signXades(canSign,docNum,url,mime,session)` | **unsupported** | `STATE`, `KEYS_OPEN`, `DERIVED` | http_request_ex (document at url), ocsp_fetch, keys_sign_xades | xades; XAdES with options chosen by the plugin | 1 | no (http allow-list) | READS STATE (key from getKeys) | derived (document downloaded from url) | W+S: skf/src/lib.rs:723, skf/src/lib.rs:85 |
| `taxtech` | `version` | **no-sign** |  | - | - | 0 | no (UNDEFINED origin tolerated) | no | - | S: taxtech/src/lib.rs:105 |
| `taxtech` | `selectKey` | **no-sign** | `STATE` | keys_select | - | 0 | tolerant: origin None -> 'UNDEFINED' | WRITES STATE (static HOLDER) | - | W+S+T: taxtech/src/lib.rs:191, taxtech/src/lib.rs:147 |
| `taxtech` | `selectedKeyInfo` | **no-sign** | `STATE` | - | - | 0 | tolerant | READS STATE | - | W+S: taxtech/src/lib.rs:308 |
| `taxtech` | `reset` | **no-sign** |  | - | - | 0 | tolerant | clears state | - | S: taxtech/src/lib.rs:112 |
| `taxtech` | `sign {format xml\|cms\|raw, data, signingParams}` | **unsupported** | `STATE`, `MULTI`; fresh instance -> KEY_NOT_SELECTED | keys_sign_xml \| keys_sign_cms_ex \| keys_sign_raw | xml / cms_ex / raw; xml: default per document (N docs); cms: Digest if digested, cosign Auto/Never, ts Kalkan; raw: first doc | xml: N docs; cms/raw: 1 | tolerant: origin None -> 'UNDEFINED'; holder.origin must equal | READS STATE (HOLDER from selectKey, origin-bound) | bound | W+S+T: taxtech/src/lib.rs:317, oncl-port-tests/tests/medium.rs:170 |
| `thundercrypt` | `sign {keyType file\|token, dataForSign,...} (SignNLClass.sign or legacy top-level)` | **unsupported** | `DIALOG`, `KEYS_OPEN`, `OPTIONS` | dialog_password, keys_open, ocsp_fetch, crl_fetch, tsp_stamp, tsp_request, cms_verify, keys_sign_cms_ex, keys_chain, hash | cms_ex + stamp + LTA upgrade; ESEDO attrs.extra, Custom TSA, post-sign verification, optional B-LTA upgrade | 1 | no | no | bound data; attrs network-derived | W+S: thundercrypt/src/lib.rs:310, thundercrypt/src/lib.rs:397, thundercrypt/src/lib.rs:336 |
| `uchet` | `test` | **no-sign** |  | - | - | 0 | no | no | - | S: uchet/src/port.rs:127 |
| `uchet` | `getVersion` | **no-sign** |  | - | - | 0 | no | no | - | S: uchet/src/port.rs:132 |
| `uchet` | `getMessage` | **no-sign** |  | - | - | 0 | no | no | - | S: uchet/src/port.rs:137 |
| `uchet` | `getFilePath` | **no-sign** | `FILE` | file_choose | - | 0 | no | no | - | W+S: uchet/src/port.rs:183 |
| `uchet` | `checkCMS` | **no-sign** | `FILE` | page_file_read, cms_verify | - | 0 | no | no | - | W+S: uchet/src/port.rs:217 |
| `uchet` | `checkCMSFromWeb` | **no-sign** |  | http_request_ex, cms_verify | - | 0 | relative_to_origin when the URL is relative | no | - | W+S: uchet/src/port.rs:227 |
| `uchet` | `signXml(storage,keyType,xml,tbs,parent)` | **unsupported** | `TERMINALS`; storage 'PKCS12' throws (Outcome::Thrown); any token storage hits keys::terminals -> [] -> STORAGE_EMPTY; only a 'JKS' storage name could pass, which depends on how MP4 matches `storages` against the bound key | keys_select, keys_terminals, keys_sign_xml_ex | xml_ex; as rating1c legacy::sign_xml | 1 | no | no | bound (xml arg 2) | W+S: uchet/src/port.rs:149, common/legacy/src/guest.rs:208 |
| `uchet` | `signXmlApi(keyPath,password,xml)` | **unsupported** | `KEYS_OPEN` | keys_open, keys_sign_xml_ex | xml_ex; whole document (declaration prepended by the plugin) | 1 | no | no | bound (xml arg 2) | W+S: uchet/src/port.rs:412, uchet/src/port.rs:429 |
| `uchet` | `signFile(4)` | **unsupported** | `KEYS_OPEN`, `DIALOG`, `FILE`, `DERIVED` | page_file_read, file_open_ex, dialog_password, keys_open, keys_terminals, ocsp_fetch (check_cert), keys_sign_cms_ex, page_file_write | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | derived (file read by page path) | W+S: uchet/src/port.rs:461, uchet/src/port.rs:475, uchet/src/port.rs:532 |
| `uchet` | `signFilePath(3)` | **unsupported** | `KEYS_OPEN`, `DIALOG`, `FILE`, `DERIVED` | page_file_read, file_open_ex, dialog_password, keys_open, keys_terminals, ocsp_fetch (check_cert), keys_sign_cms_ex, page_file_write | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | derived (file read by page path) | W+S: uchet/src/port.rs:469, uchet/src/port.rs:475, uchet/src/port.rs:532 |
| `uchet` | `signFileFromDiskAndSaveToDiskApi(signToken,filePath,fileDir,keyPath,keyPassword,storageName)` | **unsupported** | `KEYS_OPEN`, `FILE`, `DERIVED`, `HTTP`; vendor licence call: arbitrary http endpoint outside the PKI allow-list | http_request_ex (POST signToken to http://ncalayer.uchet.kz:8080), page_file_read, keys_open, ocsp_fetch, keys_sign_cms_ex, page_file_write | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | derived (file read by page path) | W+S: uchet/src/port.rs:687, uchet/src/port.rs:630, uchet/src/port.rs:475 |
| `uchet` | `signFileAndReturnBase64Api(signToken,fileBase64,keyPath,keyPassword,storageName)` | **unsupported** | `KEYS_OPEN`, `HTTP`; vendor licence call: arbitrary http endpoint outside the PKI allow-list; would also be blocked if the window allows only PKI network | http_request_ex (POST signToken to http://ncalayer.uchet.kz:8080), keys_open, ocsp_fetch (check_cert), keys_sign_cms_ex | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, attrs ct+md+scv2+signingTime(Now,Auto), certs=Signer, digest=cert's, output=DER | 1 | no | no | bound (base64 arg 1) | W+S: uchet/src/port.rs:702, uchet/src/port.rs:630, uchet/src/port.rs:601 |
| `uchet-esf` | `signXml {args:{pkcsPath,pkcsPassword,data}}` | **unsupported** | `KEYS_OPEN` | keys_open (page path + password), keys_sign_xml | xml; Core defaults, whole document | 1 | no | no | bound (data) | W+S: uchet-esf/src/lib.rs:70, uchet-esf/src/lib.rs:47 |
| `uchet-esf` | `signEsfList {args:{pkcsPath,pkcsPassword,esfList[]}}` | **unsupported** | `KEYS_OPEN`, `MULTI` | keys_open, keys_sign_raw xN | raw; raw per list item | N=len(esfList) | no | no | bound | W+S: uchet-esf/src/lib.rs:83 |
| `workspace` | `getKaztokenKeys` | **no-sign** | `DIALOG`, `KEYS_OPEN` | dialog_password, keys_terminals, keys_open | - | 0 | no | no | - | W+S: workspace/src/lib.rs:146 |
| `workspace` | `sign {files[],fileNames,isKaztoken,issuerCert,...}` | **unsupported** | `OPTIONS`, `MULTI` | keys_select, ocsp_fetch, keys_sign_cms_ex, tsp_stamp (attachments) | cms_ex + stamp; card: ESEDO attrs.extra + OCSP; each attachment: attached ESEDO attrs + Custom TSA; 1 + (files.len()-1) signatures | 1 + (len(files)-1) | no | RUNNING flag only | bound (base64 files) | W+S: workspace/src/lib.rs:93, workspace/src/lib.rs:258 |
| `xdox` | `CREATECMS {storageName,params:{ncaManifest}}` | **unsupported** | `ORIGIN` | keys_select, keys_terminals, pkix_path, keys_sign_cms_ex | cms_ex; encapsulate=true, cosign=Auto, ts=Kalkan, std attrs | 1 | YES: origin must contain 'xdox.kz' (unanchored substring) | no | bound (ncaManifest text) | W+S+T: xdox/src/lib.rs:23, xdox/src/lib.rs:114, oncl-port-tests/tests/clones.rs:610 |
| `xdox` | `ADDSIGNERTOCMS {storageName,params:{ncaManifest,cms}}` | **unsupported** | `ORIGIN`, `COSIGN` | as CREATECMS | cms_ex; cosign=Into(page's cms), detached, only the new signer time-stamped | 1 | YES (as above) | no | bound manifest + page CMS | W+S+T: xdox/src/lib.rs:23, xdox/src/lib.rs:128 |

## 4. Сводка

### 4.1 Вердикты

| Вердикт | Методов |
|---|---|
| supported | 2 |
| supported* | 13 |
| unsupported | 59 |
| no-sign | 92 |
| всего | 166 |

### 4.2 Гистограмма причин unsupported

`primary` — первая (самая жёсткая) причина строки; `в любой` — строка помечена причиной, возможно вместе с другими; `только она` — строка заблокирована только этой причиной (если её снять, метод станет supported*, см. §4.5).

| Причина | primary | в любой | только она |
|---|---|---|---|
| `ORIGIN` — needs a page Origin (absent under LocalOperator; never faked) | 15 | 15 | 6 |
| `DIALOG` — Dialog* import on the success path | 9 | 12 | 0 |
| `KEYS_OPEN` — keys::open with a path/bytes + password from the request (design 3.5: PermissionDenied) | 13 | 21 | 6 |
| `STATE` — needs in-instance state left by an earlier call of the same session (fresh instance per manual call) | 8 | 10 | 3 |
| `OPTIONS` — signing options outside the whitelist profile (attrs.extra/ESEDO, econtent_type, Custom TSA) | 6 | 14 | 5 |
| `MULTI` — more than one signature per call (max_uses = 1) | 5 | 14 | 5 |
| `FILE` — File*/page_file_* needed | 1 | 7 | 0 |
| `DERIVED` — signed bytes computed or fetched by the plugin (not an argument) | 1 | 16 | 1 |
| `COSIGN` — cosign = Into(cms) (co-signing a CMS from the request) | 0 | 1 | 0 |
| `HTTP` — arbitrary http(s) call outside the PKI allow-list that the success path needs (vendor licence server) | 0 | 2 | 0 |
| `TERMINALS` — token-storage gate on keys::terminals, which the design answers [] | 1 | 1 | 1 |

По портам (порт целиком без supported-метода; главная причина):

| Порт | главная причина | остальные |
|---|---|---|
| `acbank` | `DIALOG` | `MULTI`, `DERIVED` |
| `arta` | `STATE` | `FILE`, `DERIVED` |
| `bas` | `OPTIONS` |  |
| `buhta` | `ORIGIN` | `STATE`, `MULTI` |
| `devart` | `STATE` | `MULTI`, `OPTIONS` |
| `documentolog` | `DIALOG` | `KEYS_OPEN`, `DERIVED`, `OPTIONS` |
| `doodocs` | `KEYS_OPEN` | `STATE` |
| `eot` | `OPTIONS` |  |
| `eup` | `OPTIONS` |  |
| `ezsigner` | `FILE` | `DERIVED` |
| `idocs` | `OPTIONS` |  |
| `k2sign` | `ORIGIN` | `DERIVED`, `FILE` |
| `knp` | `ORIGIN` | `KEYS_OPEN` |
| `metadoc` | `KEYS_OPEN` | `OPTIONS`, `DIALOG` |
| `motiw` | `KEYS_OPEN` |  |
| `nursign` | `ORIGIN` | `MULTI`, `FILE`, `DERIVED` |
| `qoltanba` | `ORIGIN` |  |
| `simourg` | `DIALOG` | `OPTIONS` |
| `skf` | `STATE` | `KEYS_OPEN`, `DERIVED` |
| `taxtech` | `STATE` | `MULTI` |
| `thundercrypt` | `DIALOG` | `KEYS_OPEN`, `OPTIONS` |
| `uchet` | `KEYS_OPEN` | `FILE`, `DERIVED`, `DIALOG`, `HTTP`, `TERMINALS` |
| `uchet-esf` | `KEYS_OPEN` | `MULTI` |
| `workspace` | `OPTIONS` | `MULTI` |
| `xdox` | `ORIGIN` | `COSIGN` |

### 4.3 Порты, пригодные для первого релиза

Порт входит, если у него есть хотя бы один **supported/supported\*** метод по таблице §3 (порядок — от простого к сложному):

| Порт | Методы в окне | Подписи / опции | Условия |
|---|---|---|---|
| `rating1c` | `signXml`, `createCmsFromBase64`, `createRawSignFromBase64` | cms_ex; raw; xml_ex | -; template: storage=PKCS12, keyType=SIGNATURE, BIN=''; bound cert must pass the plugin's validity check (expired -> error) |
| `dogovor24` | `signCMS` | cms_ex | key is selected before the method name is read; requires cert EKU present and without clientAuth (plugin check) |
| `efactoring` | `text`, `xml` | cms_ex; xml_ex | XPaths are page text: in the window they must be typed params shown in the consent; the retry dialog (dialog_choice) traps with InteractionRequired: a failed signing ends the call as a host error instead of the plugin's retr |
| `energy` | `sign` | cms_ex | dialog_message is reached only on failure (ALIAS_MISMATCH/SIGNING_ERROR/UNKNOWN_ERROR) -> trap |
| `eproc` | `signXml` | xml (keys_sign_xml, Core defaults) | template: storageName=PKCS12 (no terminals call), keyType=SIGNATURE (bound key must have KNCA type SIGNATURE) |
| `esf-osdkz` | `signPlainData`, `auth` | raw | Action::Authenticate (a login challenge): the design has no ruling for Authenticate-kind use in the manual window; signs arbitrary text with a raw signature: the consent must show the text (design: raw only bound) |
| `fhs` | `signXml`, `signText` | cms_ex; xml | dialog_choice only on failure -> trap |
| `market` | `text`, `xml` | cms_ex; xml_ex | dialog_choice on failure -> trap |
| `qiwi` | `signXml` | xml_ex | algorithm URIs depend on the key: the profile must accept Kalkan's URIs of the key (default) — for GOST 2015 keys the plugin asks GOST 2004  |

**Критерий полноты первого релиза, по методам.** supported — rating1c (3 метода, без оговорок, но `cosign=Auto` у CMS), eproc, esf-osdkz (2 + `auth` с вопросом про Authenticate), dogovor24, qiwi (только ключи RSA-SHA256/ГОСТ 2004), efactoring/market/fhs/energy (диалог только на ошибке: ошибка подписи = ошибка вызова).

Условия шаблона, общие для всех supported\* строк: (а) хост строит `request` с фиксированными необязательными параметрами (`alias` у energy не задаётся, `isDigested=false`, число документов 1, `storageName=PKCS12`, `keyType=SIGNATURE`, `BINControl=""`); (б) ключ, привязанный пользователем, должен удовлетворять фильтру плагина (`knca_types`, EKU) — иначе `keys::select` вернёт `None` и порт ответит «отмена»; (в) `cosign=Auto` → `Never` (§4.5, вопрос R-A); (г) в согласии нужно показать **параметры-тексты** (XPath `element/parent` у efactoring/rating1c/eproc, текст для `text`-методов) как параметры, а не как «содержимое».

### 4.4 Рекомендация по MP3b (`derived`)

**Не начинать MP3b.** Доказательства по таблице §3:

- Строк с причиной `DERIVED`: **16**; из них заблокированы **только** ею: **1** — `fhs.signFile`.
- Все остальные derived-методы заблокированы ещё и более жёсткой причиной (`ORIGIN`, `DIALOG`, `KEYS_OPEN`, `STATE`, `FILE`): снятие `DERIVED` без неё ничего не даёт.
- Единственный «чисто derived» метод `fhs.signFile{url}` (V1) подписывает **скачанный по URL страницы документ** (`http_request_ex`), то есть двоичные данные произвольного размера; MP3b по правилам дизайна допускает только текстовое содержимое с полным превью ≤ 64 КиБ, и `max_uses = 1`. Пользователь в ручном окне уже владеет файлом: тот же результат даёт `fhs.signText{base64data}` (supported\*) с самим файлом как bound-аргументом.
- derived-**raw** (`acbank` JWS: подписывается собранная плагином строка `header.payload`) заблокирован ещё `DIALOG` и `MULTI`; для него дизайн и так указывает MP13.
- Цена MP3b (план-прогон, allow-list, заморозка часов/`random`, 2× fuel, превью) несоразмерна одному методу. **Рекомендация: исключить MP3b из плана до появления порта с derived-методом, не заблокированным другими причинами; MP6 (объявления портов) выполнять только в режиме `bound`.**

### 4.5 «Что если»: какие причины стоит снять и сколько это даёт

Метод считается разблокированным, если его причины ⊆ снимаемому набору. Подсчёт — по строкам `unsupported` таблицы §3. Это **не предложение изменить дизайн**, а информация для решения родителя; текущий дизайн (R5, R6, §3.5, R10) эти причины не снимает.

| Сценарий | Разблокируется методов | Какие |
|---|---|---|
| снять `OPTIONS`: профиль «ESEDO», где Core сам строит `attrs.extra` по именам файлов и OCSP (хост знает и то и другое) | 5 | `bas.sign`, `dogovor24.signEsedo`, `eot.signCmsWithSignedAttrs`, `eup.sign`, `idocs.sign` |
| `keys::open` отвечает привязанным ключом (путь/пароль игнорируются) | 6 | `fhs.signTextV2`, `fhs.signXmlV2`, `metadoc.signXml`, `motiw.sign`, `uchet.signXmlApi`, `uchet-esf.signXml` |
| держать экземпляр между вызовами сессии ручного окна (снять `STATE`) | 3 | `arta.signBase64File`, `arta.signDocument`, `arta.signXML` |
| разрешить `MULTI` (несколько подписей, одно согласие) | 5 | `dogovor24.batchSignCMS`, `esf-osdkz.signPlainDataMap`, `rating1c.signXmls`, `rating1c.createCmsesFromBase64`, `rating1c.createRawsSignFromBase64` |
| `ORIGIN`: невозможно по R5 (Origin не подставляется) | 6 | `buhta.call#2`, `nursign.text`, `nursign.binary`, `nursign.xml`, `qoltanba.signFileBytes`, `xdox.CREATECMS` |
| снять `DERIVED` (MP3b) | 1 | `fhs.signFile` |
| `keys::open` + `OPTIONS` | 11 | `bas.sign`, `dogovor24.signEsedo`, `eot.signCmsWithSignedAttrs`, `eup.sign`, `fhs.signTextV2`, `fhs.signXmlV2`, `idocs.sign`, `metadoc.signXml`, `motiw.sign`, `uchet.signXmlApi`, `uchet-esf.signXml` |
| `STATE` + `MULTI` | 9 | `arta.signBase64File`, `arta.signDocument`, `arta.signXML`, `dogovor24.batchSignCMS`, `esf-osdkz.signPlainDataMap`, `rating1c.signXmls`, `rating1c.createCmsesFromBase64`, `rating1c.createRawsSignFromBase64`, `taxtech.sign` |

Замечания: (1) `OPTIONS` разблокирует методы с **разными** ESEDO-вариантами (разные формы времени, DN, OCSP, `econtent_type`, `Digest`) — это набор разных профилей, а не один; (2) `keys::open` «привязанным ключом» меняет смысл ввода пароля и пути страницы — это ослабляет R2/инвариант «секрет не уходит плагину» только если пароль берётся из запроса, но порт получит пароль от страницы, которой в ручном окне нет; (3) сохранение экземпляра (`STATE`) противоречит свойству F1 «ничего не переживает вызов» и модели «согласие не переживает вызов»; (4) `MULTI` даёт только списочные варианты уже поддерживаемых методов.

## 5. Поправки к `docs/design/manual-plugins.md` §1 и смежным местам

Сверка утверждений ревизии 2 с реальным анализом (`design/manual-plugins` @ `6bdea19b`). Номера — как в документе дизайна.

| # | Утверждение дизайна | Что показал анализ | Поправка |
|---|---|---|---|
| D1 | §1 «Инвентаризация…»: `sign_cms_ex` — 25, `sign_xml` — 18, `sign_xml_ex` — 9, `sign_cms` — 4, `sign_xades` — 1, `sign_raw` — 7 | Секция импортов wasm: `keys_sign_cms_ex` — **27**, `keys_sign_xml` — **5**, `keys_sign_xml_ex` — **11**, `keys_sign_cms` — **0** (ни один порт не линкует), `keys_sign_xades` — 1 (`skf`), `keys_sign_raw` — 7 (тот же список: acbank, arta, devart, esf-osdkz, rating1c, taxtech, uchet-esf). | Заменить на wasm-счёт; убрать `sign_cms` как вид у портов. Следствие: «простого `KeysSignCms` с `cosign: Auto`» (§4.1, §6) в портах нет — вопрос `Auto→Never` относится к `keys_sign_cms_ex` (27 портов), см. D6. |
| D2 | §1 и §3.5: `keys::select` — 18, `keys::choose` — 4 | `keys_select` — **24** порта, `keys_choose` — 4 (efactoring, k2sign, market, nursign). | Обновить числа. |
| D3 | §1: «Упоминание `origin` в `src` есть почти у каждого порта; доля пригодных … заметно меньше половины» | `request.origin` читают **7** портов из 34 (buhta, k2sign, knp, nursign, qoltanba, taxtech, xdox); остальные упоминают слово лишь в `relative_to_origin`/комментариях. Из 7 только taxtech терпит `None` (`UNDEFINED`). Доля пригодных (**9 из 34**) мала **не из-за Origin**: главные причины — `STATE`, `KEYS_OPEN`, `DIALOG`, `OPTIONS` (§4.2). | Исправить формулировку; убрать «Origin» как главную причину. |
| D4 | §1 (C9) и §3.5: порты «без Origin» отвечают `INVALID_ORIGIN` | Верно только для `qoltanba`; `buhta`, `k2sign`, `knp`, `nursign` **обрывают соединение** (`reply_drop`) на отсутствии Origin (до разбора), `xdox` отвечает `That module can be used only on https://xdox.kz`, `taxtech` Origin не требует. | Перечислить поведение по портам (таблица §3, колонка Origin). |
| D5 | §1/§3.5: остальные причины unsupported — `Dialog*/File*`, `keys::open/terminals`, несколько подписей, `raw`-derived, `shared/settings` | Не названа **главная** причина: состояние **в памяти экземпляра** между вызовами сессии (F1). Она одна блокирует `arta.sign*`, `taxtech.sign`, `devart.signDevart`, `doodocs.createCAdES`, `skf.signXades`. `shared/settings` (acbank, energy.getKeyInfo) почти не влияют. Не названы также: ESEDO-опции (`attrs.extra` + `econtent_type` + Custom TSA) как причина у 11 портов (12 с `arta.signDocument`), и `keys::terminals`-ворота (uchet.signXml). | Добавить в список причин §4.6 и в таблицу §6: `STATE`, `OPTIONS(ESEDO)`, `TERMINALS`. |
| D6 | §4.1: «`cosign` в профиле только `never`; Core подставляет `Never` вместо `Auto`» (фраза про простой `KeysSignCms`); общее правило «значения опций в реальном `args` обязаны совпасть с профилем, иначе `OptionsMismatch`» | Плагины передают `CoSign::Auto` в **`keys_sign_cms_ex`** (dogovor24, efactoring, market, energy, fhs, rating1c) — то есть формально `Auto ≠ never`. Если правило совпадения применить буквально, **все** supported CMS-методы получат `OptionsMismatch`. | Дизайн должен прямо сказать: для `cms_ex` значение `Auto` приводится к `Never` (как для `cms`), либо профиль допускает `Auto` как «`Never` по построению». Нужен ruling (R-A). |
| D7 | §3.5: `KeysTerminals → []` без оговорок | Ворота `keys::terminals` стоят **перед** выбором ключа у token-ветки legacy-`select` (`plugins/common/legacy/src/guest.rs`): пустой список → `STORAGE_EMPTY`. `uchet.signXml` бросает исключение для `PKCS12`, поэтому его token-ветка недостижима. Остальные порты с `keys_terminals` в supported (rating1c, eproc, esf-osdkz) обходятся шаблоном `storageName=PKCS12`. | Зафиксировать, что шаблон обязан подставлять `PKCS12` (или `JKS`), и описать, как Core сопоставляет `SelectArgs.storages` с привязанным ключом (Q-B). |
| D8 | §3.5: «`KeysOpen` и прочее, что в Core headless даёт `PermissionDenied`» | Подтверждено (`capabilities.rs:203`), но «прочее» включает **`reply_drop`** (линкуют 33 порта) и **`call_locale`**; дизайн их не называет. Для supported-портов `reply_drop` достижим только на нечитаемом запросе. | Добавить `reply_drop` в список «нейтральных» (Core трапит или игнорирует) и в `uses.imports`. |
| D9 | §4.1: пример с `qoltanba`, «метод `signFileBytes` арность 2, читает хранилище, `lib.rs:103-106, 270`» | Ссылки верны (`qoltanba/src/lib.rs:103-106`, `:270`), вывод верен; уточнение: недоступен весь `qoltanba` (любой метод с именем → `INVALID_ORIGIN`). | Без правки; можно уточнить. |
| D10 | §6/§9.1: порты правятся «34 `plugin.toml`» | Объявления нужны только для **9** портов с supported-методами; остальные 25 в окне показываются как unsupported с причиной (R7) и `plugin.toml` не меняют. | Уточнить MP6/MP11: 9 портов, не 34; «выпуск 34 версий» → выпуск версий только для портов с объявлениями (остальные — только если нужно показать причину; тогда причина — в реестре хоста, а не в манифесте). |
| D11 | §4.1: `Digest` — «для bound Core сам считает дайджест … и требует побайтового равенства с `args`» | `eot.signCmsWithSignedAttrs` — `ContentMode::Digest`: аргумент и есть дайджест, посчитанный страницей; `energy.sign` при `isDigested=true` и `taxtech.sign cms digested` — то же. | Для `Digest`-операций шаблон должен принимать **документ**, а хост — подставлять в `args` дайджест (параметр `kind=document`, плейсхолдер `{file:digest}`); в §4.1 такой плейсхолдер не описан. |

**Подтверждённые утверждения (без поправок):** `plugin.toml` — 34, у всех `keys = true`, 35 имён `modules`; `sign_xades` — 1; `sign_raw` — те же 7 портов; C6 (`requires_interaction`) и C9 (`encode_input`, `LocalOperator` → `None`); C7 (`KeysSignRaw` — `plugins.rs:368-410`); `qoltanba/src/lib.rs:171-177` (`INVALID_ORIGIN`).

## 6. Решения, нужные от родителя

- **R-A (cosign).** `cosign=Auto` в `keys_sign_cms_ex` у 6 supported-портов: привести к `Never` (документировать отличие) или считать `OptionsMismatch` (тогда supported\* CMS-методов нет). Рекомендация: приводить, как и для простого CMS в §4.1.
- **R-B (storages).** Как Core сопоставляет `SelectArgs.storages`/`knca_types` с привязанным ключом: достаточно ли `storageName=PKCS12` при привязанном **токен**-ключе (тогда token-ключи работают без `keys::terminals`)?
- **R-C (Authenticate).** `esf-osdkz.auth` подписывает произвольный текст-вызов (`Action::Authenticate`); допустимо ли это в ручном окне, или `auth` — unsupported по смыслу.
- **R-D (ESEDO).** 5 методов (bas, dogovor24.signEsedo, eot, eup, idocs) заблокированы только `attrs.extra`-профилем ESEDO; решить, добавлять ли профили «ESEDO» (по варианту на порт) отдельным этапом.
- **R-E (reply_drop).** Разрешить `reply_drop` как нейтральный (игнор) или трапить; для supported-портов безразлично.

## 7. Воспроизведение

```text
cd plugins
cargo build --release --locked --target wasm32-unknown-unknown --workspace      # 34 модуля
python ../scripts/mp0_wasm_imports.py <CARGO_TARGET_DIR>/wasm32-unknown-unknown/release          # импорты по портам
python ../scripts/mp0_wasm_imports.py <CARGO_TARGET_DIR>/wasm32-unknown-unknown/release --json   # то же, JSON
cargo test -p oncl-port-tests --test clones --test ecc --test medium            # существующие тесты портов (корень репозитория)
```

Строки таблицы §3 — результат чтения исходников (уровень **S**); якорь `файл:строка` указывает на функцию/константу, определяющую вердикт. Для сверки: открыть якорь и убедиться, что (а) диспетчер приводит к этой функции, (б) перечисленные импорты есть в секции импортов порта (`scripts/mp0_wasm_imports.py`).

