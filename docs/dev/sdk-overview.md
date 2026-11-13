# SDK: обзор и платформенные изменения

Встраивание `oncl-core`, изменения платформы (CAdES, `oncl-server`), плагины в SDK и описание проверок PDF и XML. Контракты SDK, semver и миграция — в [`sdk.md`](sdk.md); журнал durable-аудита — в [`audit.md`](audit.md). Идентификаторы `P01`–`P03`, `X03`–`X05`, `C03`, `L01` ниже — имена случаев исполняемого `sdk_probe` (`--case`).

## Встраивание (не в crates.io)

`oncl-core` — встраиваемый SDK: потоковые подпись, проверка, валидация, инспекция и метки
времени; доверие, ключи, часы, сеть, аудит и лимиты ресурсов задаёт хозяин приложения. Ему не
нужны ни графическая сессия, ни демон, ни слушающий порт, ни самообновление. **Ничего не
опубликовано в crates.io** (свободны ли имена `oncl-*`, не проверялось): подключайте проверенный
коммит по path или git и тот же `[patch.crates-io]` для изменённых `streebog` и `hmac`:

```toml
[dependencies]
oncl-core = { path = "OpenNCALayer/crates/oncl-core", features = ["full"] }

[patch.crates-io]
streebog = { path = "OpenNCALayer/vendor/streebog" }
hmac = { path = "OpenNCALayer/vendor/hmac" }
```

Features: без них (минимальный SDK: CMS/CAdES, хеширование, PKI-валидация, файлы ключей,
пакеты), `tokens`, `xml`, `pdf`, `jose`, `plugins` и `full` — всё сразу; ни одно не тянет Slint,
desktop, апдейтер, сервер или асинхронный рантайм (проверяет `cargo xtask sdk closure`).
Исполняемые примеры выпускают одноразовую PKI и не ходят в сеть:
`cargo run -p oncl-core --example sign_file`, `--example verify_file -- <каталог> <файл>` и
`--example custom_transport` (транспорт HTTP хозяина; без сети строгая подпись отклоняется до
применения ключа). Semver, контракты ошибок и лимитов, заметки о миграции и готовность к
публикации (цепочка упакованных исходников проверяется офлайн `cargo xtask sdk smoke`; загрузка
заблокирована изменёнными `hmac`/`streebog` и не выполнялась) — в
[`docs/dev/sdk.md`](sdk.md). Сторонние лицензии замыкания SDK —
[`crates/oncl-core/THIRD-PARTY.txt`](../../crates/oncl-core/THIRD-PARTY.txt).

## Изменения платформы

Rust SDK добавляет отдельные CAdES B/T/LT/LTA: `SignRequest::cades_create` /
`cades_add`, `VerifyRequest::cades` и `Engine::extend` / `extend_staged`.
Читатель получает явные `EvidenceLimits`, доверие и сеть задаёт только хозяин.
Для получения новых меток T+ нужна `CadesConfiguration`; проверка уже вложенных
доказательств и со-подпись B её не требуют. Достройка требует отдельного
`Action::Extend`, сохраняет подписанные поля и не использует закрытый ключ.
Уровень контейнера — проверенный минимум по всем подписантам.

Архивный профиль — EN 319 122-1 V1.3.1 `archiveTimestampV3` +
`ATSHashIndexV3`, пока только SHA-256 для архивного хеша, не старый v2 CAdES-A.
Это не меняет старые WSS/CLI-контракты. Локальная проверка:
`cargo run -p oncl-core --example sdk_probe -- --case C03 --out target/c03-public`.
Она выпускает только публичные синтетические RSA-артефакты всех четырёх
уровней, attached/detached, несколько подписантов и изменённые архивы для
независимого оракула; не заменяет полный стенд 1 ГиБ/RSS и desktop-матрицу.

`oncl-server` — самостоятельный сервис и библиотека. Бинарь `oncl-server` имеет
подкоманды `serve`, `token-create` и `install-file`; HTTP API **выключен по
умолчанию** (`enabled = false`, включается в `server.toml` или `--enable-api`),
доступ — по токенам с правами на отдельные действия, TLS и OTLP включаются
только оператором (OTLP — по явному согласию). Описание:
[`docs/user/server.md`](../user/server.md) (настройка, токены, пределы),
[`docs/user/http-api.md`](../user/http-api.md) (маршруты, ошибки),
[`docs/dev/platform-interop.md`](platform-interop.md) (сверка с NCANode) и
[`docs/dev/platform-acceptance.md`](platform-acceptance.md) (приёмка V01,
статус). Шифрования и расшифрования (encrypt/decrypt, G01/G02) в SDK, CLI и HTTP
нет: оно зависит от внешней части и не реализовано. WinGet-пакета нет
(в `winget/hash-ledger.json` нет ни одной версии); установка — из Releases.
Журнал durable-аудита хозяина-библиотеки описан в [`audit.md`](audit.md).

## Плагины в SDK

Rust SDK (`oncl-core`, feature `plugins`) выполняет WebAssembly через scoped headless
host: установка плагина не даёт права вызова. Хозяин явно связывает caller,
operation, вложенные ABI-методы, ключи, замороженные источники/неопубликованные
результаты и сетевые endpoints; полномочия пересекаются с манифестом и host policy.
Raw/CMS/XML/XAdES-подписи используют исходный `OperationContext` и guard, обязательный диалог
даёт `InteractionRequired` без UI-lock. Пакеты, каталог и updater доступны только
с отдельной feature `oncl-plugin/distribution`, которую выбирает desktop; settings
остаются в runtime. Проверка с настоящим WASM и независимым OpenSSL:
`cargo run -p oncl-core --features plugins,tokens --example sdk_probe -- --case L01 --out target/l01-smoke`.
Это ограниченный ABI smoke, не приёмка 1 ГиБ/RSS, токенов НУЦ или desktop-матрицы.
PKI-права задают HTTP-метод и точный base URL, включая внутреннюю проверку
сертификата перед подписью. Производный GET разрешён только по provenance
штатного PKI-энкодера от этого base URL; origin/prefix wildcard и redirect
не расширяют полномочия. Цепочки сертификатов и предсказуемые DER/Base64/PEM
результаты проходят admission исходных квот до применения ключа; preflight
не списывает выходные байты. Headless `log` подтверждается без записи guest payload.

`KeysSignXml`, `KeysSignXmlEx` и `KeysSignXades` вызывают реальные guarded legacy
фасады Core с исходными селекторами XPath/namespace/layout; T/LT требуют совпадающего
host TSA и фактических baseline evidence. Публичная цепочка из guest не становится
trust anchor, а legacy default алгоритма не обходит соответствие реальному ключу.
Размер serialized XML проверяется до private use по исходной квоте и временному
ABI target; поздний trap/TSA failure сохраняет `Applied`, не публикуя префикс.
L01 также запускает bounded libxml2/cryptography oracle (Python `lxml`, `cryptography`):
проверка RSA, всех references и отрицательной мутации; это не PKIX/GOST/NCA-сертификация.

## PDF и PAdES

Низкоуровневый `oncl-pdf` и опциональная фича `oncl-core/pdf` проверяют существующие
подписи PDF (`VerifyRequest::pdf()`) и добавляют невидимую detached CMS-подпись
в настоящую incremental PDF-ревизию (`SignRequest::pdf(key, PdfSignProfile)`).
PAdES B/T/LT/LTA доступны отдельным явным профилем, описанным ниже. Для операций
нужен явно настроенный `TemporaryStore`: исходные байты один раз копируются в закрытый
source-role snapshot, а xref, object streams, incremental `/Prev` и подписанные
ByteRange читаются с ограниченными буферами. Snapshot учитывает фактический ввод,
не доверяет подсказке длины и исключает подмену файла между разбором и хешированием.
Отчёт связывает каждого подписанта с защищённой ревизией, точным исключённым
токеном `Contents` и фактом последующих изменений; криптографическая корректность
не заменяет полную политику доверия F03. Неподдерживаемый формат не считается Valid.
Происхождение метаданных подтверждают только закрытые преобразования SDK
`SnapshotEncoding::{Identity,PdfByteString}`, а не декодер вызывающей стороны.
Повторный capture подлинного snapshot Source той же операции не увеличивает
`bytes_in`; чужая операция отклоняется до I/O. Новые копии удерживают реальные
live-резервы scratch и памяти; Drop копии освобождает её дисковую ёмкость.
Повторное чтение сохраняет исходные deadline/control и ограниченные упорядоченные
диапазоны, а не получает новую операцию или новый лимит времени.
Проверка: `cargo test -p oncl-pdf --test verify`; runtime smoke:
`cargo run -p oncl-core --features pdf --example sdk_probe -- --case P01 --out target/p01-smoke`.
Smoke использует настоящий RSA-PDF, подписанный внешним pyHanko; изменения внутри
подписанной ревизии и отдельное последующее обновление — отрицательные контроли.
Виртуальный тест xref выше 4 ГиБ проверяет только арифметику/seek, а не готовность
содержательных 1-ГиБ PDF или предел RSS 1 ГиБ: эти измерения остаются гейтом V01.
P02 сохраняет весь исходный байтовый префикс, страницы, поля формы и цепочку
`/Prev`; новые xref streams используют 8-байтовые offsets, в том числе за пределом
десяти десятичных цифр. Перед Add проверяются все предыдущие подписи и покрытие
последней ревизии: unsigned последующее обновление нельзя «узаконить» новой
подписью. Сертификационные/field-lock permission transforms и XFA честно
отклоняются, а не обходятся. `PdfSignProfile::new(bytes)` задаёт конечный reservation
CMS (по умолчанию 16 КиБ). Перед private use тот же ASN.1 encoder вычисляет точный
DER-размер с фактическими сертификатом/атрибутами и фиксированной длиной RSA/ГОСТ
подписи: заведомо малая ёмкость отклоняется NotApplied, без guard/private use.
Неожиданно oversized ответ backend после настоящего применения ключа остаётся
Applied-ошибкой с непубликуемым staging, без скрытого повтора.
Core требует обычное `Action::Sign`, текущую strict validation и guard;
`SignDigest`/`allow_prehashed` не дают права подписи PDF.
Для исторического bare `%%EOF`/CR `revision_end` остаётся точным концом подписанного
ByteRange; отдельные `parser_revision_end` и `PdfEndpointScope` показывают
физически прочитанный EOL и допустимую историческую границу. Последняя подпись
по-прежнему обязана покрывать точный текущий extent; произвольный whitespace,
`%%EOFX` и неполный EOF не становятся допустимыми signed endpoints.
Закрытый `PdfSignatureOutput` работает только с пустым live OUTPUT staging той же
операции: append учитывает output/temp один раз, ByteRange фиксируется до хеша,
затем изменяется только зарегистрированный hex `Contents`. Он не открывает
`File`, произвольный seek/patch или mutable доступ к FrozenInput. `shared_view()`
ResourceScope — ещё один handle той же операции, со всеми общими счётчиками,
deadline/control и admission lease, а не новая квота для другого запроса.
Проверка P02: `cargo test -p oncl-pdf --features testing --test sign`; smoke:
`cargo run -p oncl-core --features pdf --example sdk_probe -- --case P02 --out target/p02-smoke`.
Smoke публикует только source/once/twice-signed PDF, публичные сертификаты и отчёт:
четыре внешне созданные страницы, содержательный RGB XObject больше 3 МиБ, два
разных RSA-ключа, проверка обеих подписей и отрицательный контроль covered mutation.
Независимые pyHanko/OpenSSL/poppler и полный 1-ГиБ/RSS/платформенный стенд —
разные гейты; этот smoke не подменяет последние.

P03: `SignRequest::pades(key, profile, level, material, evidence_limits)`,
`VerifyRequest::pades(required, evidence_limits)` и
`ExtendRequest::pdf(level, pdf_limits).with_evidence_limits(evidence_limits)`
используют настоящие `ETSI.CAdES.detached`, CMS SignatureTimeStamp, общие DSS/VRI
и RFC3161 DocumentTimeStamp. Профиль соответствует
[EN 319 142-1 V1.2.1, 5.4.2/5.4.3 и 6.3 n), q), r)–y)](https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf).
Новая T-подпись получает CMS timestamp над реальным signatureValue; достройка
ранее выпущенной B использует document timestamp над фактическими ByteRange,
не меняя старый `Contents` или исходный байтовый префикс. LTA требует последующего
проверенного timestamp, покрывающего DSS и предыдущие доказательства. Уровень —
проверенный минимум всех подписантов, а не запрошенное значение или наличие токена.
Историческое время выдаёт только общий F04 после проверки imprint, TSA crypto/EKU,
host trust и актуального статуса цепочки TSA; PDF `/M` не даёт proof of existence.

Extend требует отдельное `Action::Extend`; его Core-путь вообще не открывает
KeyProvider, не запрашивает секреты и не выполняет local private use. Новая подпись
по-прежнему требует `Action::Sign`, strict validation и guard. Для получения
новых timestamps используется явно заданная host `CadesConfiguration` как общий
AdES acquisition config; B и проверка уже перенесённых доказательств не требуют
TSA issuance config. Корни, часы, pins и сетевая политика не берутся из PDF.
После первой подписи проверяется конечная whitelist изменений: только DSS/VRI,
сертификаты/статусы и добавление signature/timestamp fields; изменение страниц,
контента, исходных объектов, permissions или посторонних catalog/trailer данных
не становится допустимым от новой ревизии или timestamp. Старые объекты (и с ними 
прежние доказательства и timestamps) остаются байт-в-байт; VRI проверяется только
на уровне ключей (ключ VRI старой подписи не удаляется, а его содержимое может
быть перенаправлено на другие объекты); 
DSS может быть пересказан новыми объектами (например, свежий OCSP), как делает NCANode. 
Поле подписи/timestamp (`/FT /Sig`, настоящий `/V`) допускается и как невидимый widget (`/F 132`) нулевой площади с пустым 
appearance, если страница меняется только добавлением этого widget в `/Annots`. 
Профиль `pdf` не судит DocTimeStamp как подписанта и не отказывает из-за него;
при этом пропущенный DocTimeStamp не проверяется на ByteRange/Contents: искажённый или
не покрывающий документ токен в общем профиле молча игнорируется.
Верификация всех подписей PDF использует один operation-owned набор общего
DSS/timestamp evidence и один F04 PreparedEvidence: общие сертификаты и декодирование
токенов не копируются заново для каждого подписанта. Каждая source CMS сохраняет
свою проверку фактического digest/SID/ESS и inclusion graph; imprint, время, trust
и актуальный статус цепочки TSA проверяются для каждого доказательства.
Поддерживаемый DSS использует прямые ссылки на DER streams без фильтров;
другие кодировки и неподдерживаемые permission transforms явно отклоняются.
OUTPUT renewal — только append в новом transaction epoch, без старых patch slots;
ошибка, включая отмену при самом входе в resume/sealed snapshot, навсегда запрещает
публикацию даже после снятия host-флага отмены. Чужие/SOURCE artifacts не портятся.
Счётчики исходного ввода и конечного вывода не дебетуют повторно внутренние replay/проверки.

Проверка P03: `cargo test -p oncl-pdf --features testing --test ades`; smoke:
`cargo run -p oncl-core --features pdf --example sdk_probe -- --case P03 --out target/p03-smoke`.
Он выполняет настоящие RSA/ГОСТ-2004/ГОСТ-2015-512 операции с loopback TSA/OCSP/CRL,
все четыре уровня, renewal, B→T, несколько подписантов и отрицательные DSS/token
контроли. Независимая проверка новых RSA-PDF (включая archive validation и tamper)
в окружении с pyHanko 0.38+:
`python crates/oncl-core/examples/sdk_probe/pades_oracle.py --out target/p03-smoke`.
Это не квалифицированная/NCA-сертификация, независимая ГОСТ-матрица или замена
содержательным 1-ГиБ PDF (границы 2/4 ГиБ — арифметические пробы выше гарантии), RSS и платформенным гейтам V01.

## XML, XAdES и WS-Security

Опциональная фича `oncl-core/xml` добавляет UTF-8 Source sign/Add/verify и
keyless evidence extension: `SignRequest::xml/xades`, `VerifyRequest::xml/xades`,
`ExtendRequest::xml`. Явный `VerifyRequest::xml_kalkan()` сохраняет прежние байты
Kalkan. Нужны host-настройки `ValidationServices` и `TemporaryStore`; TSA задаёт
общий `CadesConfiguration`, запрос не расширяет корни или сетевую политику.
`oncl-xml::verify_source` проверяет каждый SignedInfo, сертификат, SignatureValue
и Reference; отчёт хранит scoped per-signer факты, SHA-256 реального сертификата
и точные диапазоны покрытых узлов. Один canonical writer обслуживает bounded DOM
и индексированный raw-span Source; большого DOM/RAM-буфера нет. Канонические
References могут храниться в учтённом TemporaryStore до открытия ключа.
Поддерживаются inclusive/exclusive C14N с вариантами comments, InclusiveNamespaces,
ID/percent-URI, однозначные XPointer location paths, ограниченные Manifest и
namespace-bound XPath-фильтр `not(ancestor-or-self::ds:Signature)`. Enveloped
исключает текущую подпись; прежнее исключение последующих подписей включено только
в `KalkanLegacy`. Неоднозначные IDs/KeyInfo/X509Data и неподдерживаемые трансформации
отклоняются; изменение неподписанного узла не приписывается подписи.
XAdES B/T/LT/LTA использует F03/F04, а не наличие timestamp-элемента.
SignatureTimeStamp 1.3.2 покрывает целый канонический SignatureValue; выбран
недистрибутивный ArchiveTimeStamp 1.4.1 из ETSI EN 319 132-1 V1.2.1 §5.5.2.2:
все преобразованные References, SignedInfo/SignatureValue/KeyInfo, предыдущие
unsigned properties и прочие Objects в установленном порядке. Extend/renewal
проверяет все старые и новые proofs и не требует KeyProvider или Sign guard.
Минимальный проверенный уровень возвращается только при Valid. Поддержан один
SignatureTimeStamp и несколько ArchiveTimeStamp renewal; каждый proof проверяется.
Независимые повторные SignatureTimeStamp, другие версии и распределённое archive
coverage отклоняются явно, а не превращаются в lower-level Valid.
Новые baseline-подписи содержат подписанный DataObjectFormat/MimeType для каждой
data Reference; ObjectReference связан с Reference@Id, а не ID подписанных данных.
Прежний bounded XAdES остаётся математически проверяемым, но без обязательных
baseline-свойств не получает достигнутый baseline-уровень. Keyless LTA renewal
обновляет устаревшие публичные статусы только после проверки всех прежних proofs
и до выпуска архива, покрывающего весь текущий evidence; финальная проверка
защищённого archive prefix не ослаблена.
`oncl-xml::sign_spec_source` даёт bounded `XmlSignSpec` через DigestSigner и
исходный ResourceScope; старые XPath/placement/output/layout/лимиты сохранены,
builder и canonical writer общие. Source sign не строит DOM большого документа;
Add сохраняет прежние подписи, но стандартная whole-document reference может
быть нарушена последующим Add. WS-Security использует тот же индекс и canonical writer.
Внутренние hash/evidence replay не расходуют финальную output-квоту; внешний
`copy_entry` списывает каждую доставку. OUTPUT-derived captures остаются OUTPUT,
а отмена/ошибка закрытого output transaction запрещает публикацию после очистки
сигнала отмены.
Core `SignRequest::xml_legacy` сохраняет bounded wire-контракт XmlSignSpec через
исходный AuthorizedSigner. `SignRequest::xades_legacy` принимает bounded XadesSpec
и создаёт полный B/T/LT общим evidence kernel, не раскрывая raw key; TSA должен
совпадать с явной host-конфигурацией. Селекторы и канонические References
подготавливаются до открытия ключа.
Выбранные LT request chain и публичный host material совместно проверяются по
encoded размеру/числу до capture и ключа, без предварительного копирования/DER.
B/T сохраняют совместимость и не сериализуют request chain.
`capture_signed_input` сохраняет SHA-256 неизменяемого signed wire и закрытую
роль format-reader для approval/replay в той же операции. Signed intake
необратимо считает фактический wire progress, отдельно классифицируя ограниченный
реальный signature overhead. Прикладные Objects, fake metadata, whitespace и PI
остаются document bytes. Кредит сериализации получают только распознанные parser
bounded declaration/BOM и раскрытие пустого parent, содержащего лишь подписи;
это не утверждение о первоначальном написании документа. Обычные original-input
и hash consumers отклоняют classified format readers.
Signature layout проверяется сразу по framing/work-лимитам; ёмкость сохраняемой
геометрии резервируется до роста, без лимита на число узлов документа.
Динамический Core берёт trusted host clock после фактического TSA-ответа;
финальная XML-проверка использует один поздний момент для всех signers.
Прямые fixed-as-of API сохраняют прежнюю семантику и монотонные deadlines.

Проверки: `cargo test -p oncl-xml --features testing`; runtime:
`cargo run -p oncl-core --features xml --example sdk_probe -- --case X03 --out target/x03-smoke`.
Probe создаёт содержательный XML с двумя настоящими подписями и защищённой ссылкой
более 64 МиБ, проверяет дальнюю mutation и положительный неподписанный контроль,
записывает отдельные per-signer артефакты. Независимый bounded oracle:
`python crates/oncl-core/examples/sdk_probe/xml_oracle.py --out target/x03-smoke`
(lxml/libxml2 и cryptography; exact C14N/digests и RSA math, не ГОСТ и не trust).
Это не гейт содержательных 1 ГиБ/пикового RSS 1 ГиБ — он остаётся в V01.

X04 выполняет настоящие sign/Add/LTA над содержательной ссылкой более 64 МиБ,
проверяет content/evidence mutation и число private uses, а bounded matrix
покрывает B/T/LT/LTA/renewal через Core. PKI — только явно закреплённый loopback:
`cargo run -p oncl-core --features xml --release --example sdk_probe -- --case X04 --out target/x04-smoke`.
Независимый oracle:
`python crates/oncl-core/examples/sdk_probe/xml_xades_oracle.py --out target/x04-smoke`
сравнивает точные canonical/archive bytes, RSA XML/CMS math, RFC3161 nonce,
issuer-bound synthetic RSA status, порядок/покрытие и отрицательные контроли.
Это bounded direct-root профиль, не универсальный PKIX/XAdES validator и не
независимое доказательство ГОСТ, 1 ГиБ или RSS.

X05 добавляет `oncl_xml::wsse::{SourceWsseSignProfile, WsseVerifyProfile}` и Core
`SignRequest::wsse` / `VerifyRequest::wsse`, включая approved batch Create/Add.
Используемый Body — единственный прямой Body настоящего SOAP 1.1/1.2 Envelope,
с одним глобально уникальным WSU Id. Каждый signer проверяется относительно
этого региона: whole-document math, перенесённый старый Body, неподписанная
подмена, ID aliases, неверный namespace и token из другого recipient не дают
утверждения о покрытии. Host выбирает Security actor/role, обязательные прямые
прикладные headers и политику подписанного UTC Created/Expires. Timestamp —
только signed freshness claim, не proof of existence и не replay prevention.
Поддержаны полный сертификат в KeyIdentifier (фактический pinned NCANode variant)
и стандартный локальный BinarySecurityToken/STR Reference. Remote tokens,
SKI/issuer-serial lookup, шифрование, SAML и неизвестные recognized Security proofs
явно не поддержаны. Новые подписи — RSA-SHA256, ГОСТ-2004 и ГОСТ-2015/512 через
прежние строгие host PKI/algorithm/key authority.
Только bounded recognized Security framing, типизированные token/Timestamp и
необходимая вставка WSU Id получают format accounting; обычные headers и Body
остаются прикладными байтами. Остальные lexical bytes сохраняются.
Scoped `XmlVerificationFacts::wsse()` возвращает реальные per-signer Body/header/
Timestamp coverage; `read_used_soap_body` читает только байты исходного scope.
Host не может выбрать `role/none` для обработки. Прикладные Header/Body/Envelope
в чужом namespace не являются SOAP-контейнерами. Unicode Id одинаково записываются
и проверяются как однозначные bare fragments. Комментарии/PI в типизированных
token/Timestamp и лишний текст Timestamp явно отклоняются, а не становятся
бесплатными metadata. Проверяется фактическая raw-длина Security и содержащего
только Security Header вместе с суммарным framing, не нормализованный lexer buffer.
`wsse::sign_prepared` обязательно проверяет явное host time до применения ключа.
У convenience `wsse::sign_source` нет clock authority: Timestamp-bearing input/
profile требует prepared API с trusted ValidationContext. Неподдержанное требование
генерации EN baseline и заведомо невозможные layout/reference limits отклоняются
до provider. Проверка существующих carried XAdES proofs сохранена; генератор WSSE
не приписывает себе EN baseline properties.
Предварительный размер считает тот же signature emitter через checked UTF-8 sink
с потоковым XML attribute escaping. References заимствуют допущенные Id: полная
escaped подпись и копии строк Id ради подсчёта не создаются. Временные descriptor/
token buffers допускаются до allocation. Известный из profile отказ по размеру
происходит до Core/B01 intake, provider и private use, без повышения metadata caps; metadata
reservation уже учитывает live RAM.

Runtime: `cargo run -p oncl-core --features xml --example sdk_probe -- --case X05 --out target/x05-smoke`.
Probe покрывает содержательный SOAP Body более 64 МиБ, RSA и GOST Add, все три
алгоритма на bounded случаях, настоящий pinned loopback PKI и mutation/wrapping.
Независимый bounded oracle (жёсткий DOM cap 1 МиБ):
`python crates/oncl-core/examples/sdk_probe/wsse_oracle.py target/x05-smoke`;
сначала скопируйте `target/fixtures/ncanode/wsse-ncanode.xml` (после `cargo xtask fetch-fixtures`) в output как
`pinned-ncanode.xml`. Он независимо сверяет libxml2 exclusive C14N, SHA-256 и RSA
math внешнего pinned fixture и нового RSA fixture. GOST canonical decomposition
не является независимой проверкой GOST math, просроченный внешний fixture —
только math, не trusted Valid. Нет Java/Kalkan runtime, production-сертификации,
измеренного RSS либо приёмки 1 ГиБ: эти платформенные гейты остаются в V01.
