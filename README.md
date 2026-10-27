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
- проверка подписи: `openncalayer cms-verify` — подписи, метки времени, цепочки сертификатов до корней НУЦ, сроки действия и отзыв (OCSP, CRL);
- страница самопроверки `https://127.0.0.1:13579/` и демо-страница `https://127.0.0.1:13579/demo/`.

Второй этап (P2) добавляет расширение браузера: через него сайты работают с OpenNCALayer без установки CA (раздел [«Расширение браузера»](#расширение-браузера)).

Третий этап (P3) проверяет ключи в окне выбора так же, как оригинал. Цепочка сертификата ключа строится до встроенных корней НУЦ или до CA из `signerParams.chain`; `chain: []` отключает проверку. Якорь — самоподписанный CA набора или, как у оригинала, верхний найденный CA набора, поэтому `chain` из одного промежуточного CA тоже работает. Отзыв проверяется по OCSP НУЦ. Ключ без цепочки недоступен. Отозванный ключ помечается «отозван ДД.ММ.ГГГГ» и тоже недоступен, если в `signingParams` нет `allowRevoked` (для формата `raw` он не действует). Тестовая PKI НУЦ не встроена, как и у оригинала: сайтам тестовой среды нужен явный `chain`.

Четвёртый этап (P4) завершает протокол оригинала: модули `basics`, `commonUtils`, `Applet` (подмножество) и `accessory`, подпись XML (XMLDSig), создание ключей и запросов на сертификат, установка выданных сертификатов, хранилище `JKS` только на чтение (раздел [«Модули»](#модули)).

Результаты ручной проверки — [`docs/dev/smoke-p1.md`](docs/dev/smoke-p1.md), [`docs/dev/smoke-p2.md`](docs/dev/smoke-p2.md), [`docs/dev/smoke-p3.md`](docs/dev/smoke-p3.md) и [`docs/dev/smoke-p4.md`](docs/dev/smoke-p4.md).

Документы:
- [`docs/user/tls.md`](docs/user/tls.md) — сертификат OpenNCALayer: выпуск, установка, удаление, перевыпуск;
- [`docs/design/roadmap.md`](docs/design/roadmap.md) — решения и дорожная карта;
- [`docs/original/architecture.md`](docs/original/architecture.md) — архитектура оригинального NCALayer.

### Модули

Модули отвечают так же, как одноимённые модули оригинала: форма ответов, коды и тексты ошибок, порядок проверок. Политика безопасности — тоже как у оригинала: согласия по origin нет, а методы, которые оригинал выполняет без окна, и здесь работают без окна. Это `getActiveTokens` и `changeLocale` модуля commonUtils, `getBundles` и `getServices` модуля accessory и в модуле Applet — `loadSlotList`, `getPublicPartInfo`, `getTryCount`, `resetStorage`, а для файловых хранилищ также методы, которые пишут файлы ключей: `genKeyPairAndGetPKCS10` создаёт их в папке, которую назвала страница, `setX509CertToKeyStore` и `setX509CertToKeyStoreAndChangePassword` перезаписывают файлы ключей в такой папке, `changePassword` — файл ключей, который назвала страница. `installBundle` модуля accessory тоже отвечает без окна, но только потому, что ничего не устанавливает (D21); оригинал перед установкой модуля спрашивает подтверждение. Отличия — в разделе [«Отличия P4 от оригинала»](#отличия-p4-от-оригинала).

- `kz.gov.pki.knca.basics`:
  - `sign` — форматы `cms`, `raw` и `xml`. Для входа на eGov (`format:"xml"`) ответ — `{"status":true,"body":{"result":["<подписанный XML>"]}}`, как у оригинала;
  - `PKIEssentials` (запрос с `"class":"PKIEssentials"`): `generateCsr` создаёт ключи в папке, которую выбирает пользователь, и возвращает запросы на сертификат (`{"pems":[…]}`); `importCertificate` записывает выданные НУЦ сертификаты к этим ключам и меняет пароль файлов ключей с `defaultPassword` на введённый пользователем (`{"result":true}`). Отмена — `{}`.
- `kz.gov.pki.knca.commonUtils`: `getActiveTokens`, `getKeyInfo`, `signXml`, `signXmls`, `createCMSSignatureFromBase64`, `createCMSSignatureFromFile`, `createCAdESFromBase64`, `createCAdESFromFile`, `createCAdESFromBase64Hash`, `applyCAdEST`, `showFileChooser`, `changeLocale`. Ответ — `{"code":"200"|"500","message"?,"responseObject"?,"uuid"?}`. Окна модуля — на русском, пока страница не вызовет `changeLocale` (`ru`, `kk`, `en`); выбранный язык действует для всех страниц.
- `kz.gov.pki.knca.applet.Applet` — устаревший модуль; подмножество для файловых хранилищ (раздел [«Applet»](#applet)). Отвечает и на запросы без `module`, как оригинал.
- `kz.gov.pki.ncalayerservices.accessory`: `getBundles`, `getServices` (модули демона), `installBundle`, `showBundleManager`, `showSettings`, `showKeystoreExplorer`, `showAdesSigning`, `showAdesValidation`.

Хранилища:
- `PKCS12` (`.p12`, `.pfx`) — чтение и запись;
- `JKS` — только чтение, ключи RSA и ГОСТ;
- токены (`AK…Store`) до P14 отвечают так, будто устройства не подключены: в окнах `basics` они недоступны, commonUtils отвечает `storage.empty`, Applet — `EMPTY_SLOT`, `getActiveTokens` — `[]`.

Подпись XML (`basics` с `format:"xml"`, `signXml` и `signXmls` commonUtils, `signXml` Applet) имеет форму, которую строит Kalkan:
- весь документ: `ds:Signature` — последний дочерний элемент корня; одна `Reference URI=""` с преобразованиями enveloped-signature и Canonical XML с комментариями; SignedInfo канонизируется по Canonical XML 1.0;
- элемент (непустой `tbsElementXPath` в commonUtils): у элемента должен быть атрибут `Id`, иначе — ошибка с текстом Kalkan; `Reference URI="#<Id>"` с одним преобразованием Canonical XML с комментариями; SignedInfo — Exclusive XML Canonicalization; подпись кладётся в элемент `signatureParentElementXPath`;
- алгоритм — по алгоритму подписи сертификата: ГОСТ 34.10-2015-512, ГОСТ 34.310-2004 или sha256RSA, с URI алгоритмов Kalkan;
- каждый вызов дописывает новую подпись; DOCTYPE и внешние сущности запрещены.

Ключи и запросы на сертификат (`generateCsr`; `genKeyPairAndGetPKCS10` Applet — с отличиями, см. [«Applet»](#applet)):
- алгоритмы `params[].algorithm`: ГОСТ 34.10-2015-512 (`1.2.398.3.10.1.1.2.3.2`), ГОСТ 34.310-2004 (`1.2.398.3.10.1.1.1.2`), sha256RSA (`1.2.840.113549.1.1.11`) длиной 2048, 3072 или 4096 бит;
- файл ключа — `<папка>/<префикс><идентификатор ключа>.p12` (`GOST512_`, `GOSTKNCA_`, `RSA256_`), PKCS#12 в профиле Kalkan, ключ без сертификата; идентификатор — SHA-1 от BIT STRING открытого ключа;
- запрос — PKCS#10 в PEM: subject из `dn`, SAN (`subjectAltNames` и `email`) и расширение KeyStoreInfo (`1.2.398.3.3.5`) с путём папки ключей;
- `importCertificate` ищет файл ключа по SubjectKeyIdentifier сертификата в папке, записывает к ключу сертификат (файл с сертификатом аутентификации не ГОСТ 2015 переименовывается в `AUTH_<имя>`), затем меняет пароль.

Подписи XMLDSig и CMS и наши файлы ключей проверены в NCANode (Kalkan): [`docs/dev/interop-ncanode.md`](docs/dev/interop-ncanode.md).

### Проверка сертификатов

Доверие задаётся только встроенными сертификатами НУЦ и `signerParams.chain`, как у оригинала. Хранилища доверия ОС и браузеров не читаются.

Встроенные сертификаты — 10 CA промышленной PKI НУЦ из [`fixtures/nca/prod/`](fixtures/nca/prod/), вшиты в бинарь (`crates/oncl-pki/src/roots.rs`): `rcagost`, `ncagost`, `ncagost18`, `rcagost22`, `ncagost22`, `rcarsa`, `rcarsa20`, `ncarsa`, `ncarsa18`, `ncarsa22`. Суммы sha256 — в `fixtures/nca/SHA256SUMS`, тест сверяет с ними встроенные байты. Тестовая PKI НУЦ (`fixtures/nca/test/`) не встроена, как и у оригинала: сайтам тестовой среды и тестам нужен явный `chain`.

`signerParams.chain` в `basics.sign`:
- поля нет или `null` — встроенный набор НУЦ;
- `[]` — ни цепочка, ни OCSP не проверяются (так делает демо-страница по умолчанию);
- массив строк — набор CA вместо встроенного. Каждая строка — сертификат в PEM или base64 DER, пробелы и переводы строк допускаются. Строку, которая не разбирается, сайт получает как `CERTIFICATE_PARSING_FAILURE` до показа окна. Элемент не строка (число, `null`) — `INVOCATION_ERROR`, как у оригинала (Java `ClassCastException`/`NullPointerException`).

Цепочка строится от сертификата ключа вверх по набору CA по правилам RFC 5280 §6.1: подписи, сроки всех сертификатов, `basicConstraints.cA` и `pathLen` издателей, `keyCertSign` (если есть `keyUsage`), неизвестные критические расширения. Политики сертификатов и `nameConstraints` не обрабатываются. Имена сравниваются побайтно. Издатель — CA набора с тем же именем, чья подпись сходится; при нескольких кандидатах первым пробуется тот, чей `subjectKeyIdentifier` равен `authorityKeyIdentifier` сертификата. Сроки проверяются на текущий момент, а для любого просроченного ключа — на его `notAfter`: цепочка такого ключа строится, ключ показывается просроченным, и его отзыв всё равно проверяется.

Отзыв ключа проверяется по OCSP, если у ключа построена цепочка, он не отключён по другой причине (EKU, ИИН, БИН, серийный номер; просроченный ключ проверяется), сертификат конечный и в его AIA есть адрес OCSP: GET-запрос с SHA-1 `CertID` без nonce, таймаут 5 с, общий срок на хранилище 6 с. Ответ принимается, если у ответчика (`byName` или `byKey`) на текущий момент строится полная цепочка до якоря того же набора CA, он имеет EKU `OCSPSigning` и `id-pkix-ocsp-nocheck`, подпись сходится, `CertID` совпадает и ответ свежий. Ключ отключает только статус `revoked`. Без сети, при таймауте, плохом ответе или статусе `unknown` ключ остаётся доступным, причина пишется в журнал (`warn`): без сети OCSP подпись не блокирует.

`openncalayer cms-verify` проверяет готовую подпись (пункт 4 раздела [«Сборка и запуск»](#сборка-и-запуск)): цепочки до встроенных CA или `--chain`, отзыв подписанта по OCSP, промежуточных CA — по CRL из `cRLDistributionPoints` (кэш `<каталог данных>/crl/`, CRL не качается заново до `nextUpdate`). `INDETERMINATE` значит: всё проверенное верно, но вывод сделать нельзя — сведения об отзыве недоступны или момент подписи ничем не доказан.

### Отличия P1 от оригинала

- Токены (`AK…Store`) недоступны до P14. Файловые хранилища: в P1 — только `PKCS12`, с P4 также `JKS` (только чтение).
- Проверка стойкости пароля для ключей с EKU `1.2.398.3.3.4.2*`, которая есть в оригинале, в P1 не реализована.
- `NCALAYERPORT` учитывается в любой сессии, у оригинала — только в RDP/Citrix/xrdp. Значение должно быть в диапазоне `13579..=13679`.
- TLS 1.2 и 1.3, у оригинала — только 1.2.
- base64 в `data` при `decode` проверяется до показа окна, у оригинала — после. Код ошибки тот же.
- Даты действия ключа в окне выбора показываются в UTC, а не в местном времени.

### Отличия P3 от оригинала

- Если в наборе CA несколько CA с одинаковым именем (например, CA перевыпущен с тем же subject и новым ключом), цепочка строится через тот, чья подпись сходится. Оригинал хранит CA по DN, и последний одноимённый CA скрывает остальные.
- Якорь цепочки проверяется как любой CA: срок действия, `basicConstraints.cA`, `pathLen`, `keyCertSign`, неизвестные критические расширения. Оригинал (Java PKIX) якорь не проверяет.
- OCSP всех ключей хранилища проверяется одновременно, с общим сроком 6 с. Оригинал проверяет ключи по очереди, по 5 с на каждый. Ключ, не проверенный за этот срок, остаётся доступным, как и при ошибке сети.
- Для ключа, недоступного по другой причине (EKU, ИИН, БИН, серийный номер), OCSP не запрашивается: окно показывает эти причины. Оригинал ставит метку «ОТОЗВАН» и на таких ключах.
- Окно показывает дату отзыва: «отозван ДД.ММ.ГГГГ», в UTC. У оригинала метка без даты — «ОТОЗВАН».
- Ответчик OCSP находится и по `byKey` (SHA-1 его ключа), оригинал понимает только `byName`. `thisUpdate` ответа может опережать часы компьютера не больше чем на 300 с. Оригинал требует строго `thisUpdate < now`.
- CRL проверяется только для промежуточных CA и только в `cms-verify` (в `basics` у оригинала CRL нет). Delta CRL и CRL с `issuingDistributionPoint` не принимаются. У `ncagost`, `ncagost18`, `ncarsa` и `ncarsa18` два зеркала CRL, `crl.root.gov.kz` и `crl1.root.gov.kz` (у `ncagost18` и `ncarsa18` — в одной строке `… URL=…`); OpenNCALayer пробует оба. На момент проверки (дата — в [`docs/dev/smoke-p3.md`](docs/dev/smoke-p3.md)) ни одно зеркало не отдавало свежий CRL этих CA, и `cms-verify` сообщал их отзыв как недоступный.
- Политики сертификатов и `nameConstraints` в цепочке не проверяются (у сертификатов НУЦ `nameConstraints` нет).

### Отличия P4 от оригинала

#### Подпись XML

Пункты ниже — для `basics` (`format:"xml"`). commonUtils и Applet подписывают тем же кодом: байты документа, ограничения входа и отказ от sha1RSA у них те же, а коды ошибок — свои.
- Байты документа сохраняются, включая декларацию `<?xml …?>`, пробелы и порядок атрибутов. Элемент `ds:Signature` дописывается последним дочерним элементом корня. Оригинал пересериализует документ без декларации (`omit-xml-declaration`). Подпись проверяется одинаково, но строка ответа отличается.
- Ограничения входа, которых у оригинала нет: не больше 64 МиБ, не больше 256 уровней вложенности, ограничены число узлов, атрибутов и объявлений пространств имён, а также объём канонизации. Документ сверх ограничений получает `UNABLE_TO_PARSE_XML`, как и любая ошибка разбора. Текст ошибки разбора свой, у оригинала — сообщение SAX.
- Атрибут с префиксом и локальным именем `xmlns` (`a:xmlns`, `xml:xmlns`) — ошибка разбора, `UNABLE_TO_PARSE_XML`. Наш разборщик принял бы его за объявление пространства имён по умолчанию, а оригинал (Xerces) отвергает `a:xmlns` с необъявленным префиксом и считает обычным атрибутом `a:xmlns` с объявленным префиксом и `xml:xmlns`, так что подпись разошлась бы с Kalkan.
- Сертификат с подписью sha1RSA не подписывает (`UNKNOWN_ALGORITHM`, как для cms). Оригинал подписывает его по rsa-sha1.
- Документ, где до корневого элемента стоит комментарий или инструкция обработки, подписывается. Оригинал на нём падает (`SIGNING_FAILURE`): он вставляет подпись в первый узел документа.

XPath в `signXml` и `signXmls` commonUtils — подмножество: абсолютный путь из имён элементов в том виде, как они записаны в документе (с префиксом), каждый шаг с необязательным `[n]`, разделители `/` и `//` (`/root/body[2]`, `//data`), не больше 32 шагов. Префикс `SOAP-ENV` означает пространство имён SOAP 1.1, как у Kalkan. Выражение вне подмножества получает `{"code":"500","message":"unsupported XPath expression \"…\""}`, путь длиннее 32 шагов — `XPath expression "…" has more than 32 steps`. Оригинал понимает весь XPath 1.0.

#### Хранилища и пути страницы

Хранилище `JKS` (Java KeyStore) открывается для подписи в `basics` и `commonUtils`, только на чтение: ключи в него не записываются (`generateCsr` и `importCertificate` работают только с PKCS#12). Читаются ключи RSA и ГОСТ.

Пути, которые называет страница, не могут указывать на сеть: файлы `createCAdESFromFile` и `createCMSSignatureFromFile`, папки и файлы ключей модуля Applet, начальная папка `showFileChooser` обоих модулей, папка `keystorePath`, которую `importCertificate` подставляет в окно. UNC-пути (`\\host\…`, `//host/…`, `\\?\UNC\…`; в Linux и macOS — пути, начинающиеся с `//`) отклоняются до любого обращения к файловой системе: иначе демон без окна подключился бы к узлу, который выбрала страница (в Windows — с учётными данными пользователя). Ответ — код оригинала для ненайденного файла: `file.not_found` в commonUtils; в Applet — `KEYSTORE_FILE_NOT_FOUND` (`setX509CertToKeyStore`), `CHANGEPASS_COMMON` (`changePassword`), `COMMON` (`genKeyPairAndGetPKCS10`). `signXml` Applet и `importCertificate` не подставляют такой путь в окно, а выбор папки или файла открывается в папке по умолчанию. Оригинал открывает любой путь.

Токены не поддерживаются до P14 (раздел [«Модули»](#модули)).

#### `PKIEssentials`: `generateCsr` и `importCertificate`

- sha1RSA (`1.2.840.113549.1.1.5`) не генерируется: `UNKNOWN_ALGORITHM` (правило P1 против SHA-1). RSA другой длины, чем 2048, 3072 или 4096 бит, — тоже `UNKNOWN_ALGORITHM`; оригинал генерирует RSA любой длины.
- `params` проверяются до окна: ошибка в элементе или алгоритме даёт код оригинала, но окно не открывается. Оригинал сначала показывает окно.
- Один запрос создаёт не больше 16 ключей: при большем числе `params` ответ — `INVOCATION_ERROR` с `java.lang.IllegalArgumentException: too many keys requested`, до окна. У оригинала ограничения нет.
- Без `defaultPassword` окно `generateCsr` спрашивает пароль файлов ключей с подтверждением; окно оригинала в этом случае подтвердить нельзя.
- Ключи создаются только в существующей папке, заданной абсолютным путём; иначе — `CSR_GENERATING_FAILURE`.
- Шаблон нового пароля в `importCertificate` проверяется до записи первого сертификата: при `WRONG_PASSWORD_PATTERN` ни один файл не меняется. Оригинал сначала записывает сертификат.
- Один запрос `importCertificate` устанавливает не больше 16 сертификатов: при большем числе `certificates` ответ — `INVOCATION_ERROR` с `java.lang.IllegalArgumentException: too many certificates`, до окна. У оригинала ограничения нет.
- `JKS` и токены показаны в обоих окнах, но выбрать их нельзя.
- Файлы ключей пишутся через временный файл в той же папке. В Linux и macOS у них права `0600`; в Windows файл получает права папки, и явные права, выданные старому файлу, не сохраняются.
- Путь файла ключей, последний компонент которого `.` или `..` (в Windows `…\key.p12\a\..` открывает `key.p12`), не перезаписывается: ошибка ввода-вывода (`CERTIFICATE_IMPORTING_FAILURE`; в Applet — коды оригинала для ошибки записи, например `CHANGEPASS_COMMON`). Оригинал записывает файл по такому пути.

#### commonUtils

Модуль `kz.gov.pki.knca.commonUtils`:
- Токены — как описано в разделе [«Модули»](#модули), так отвечает и оригинал без подключённых устройств.
- `createCAdESFromFile` и `createCMSSignatureFromFile` показывают в обоих окнах полный нормализованный путь к файлу, который назвала страница. Читается только обычный файл на диске размером не больше 64 МиБ; больший файл получает `file.too_large: files over 64 MiB are not signed`. Ответ `file.not_found` получают папка, а также: в Linux и macOS — FIFO и устройства; в Windows — пути пространства устройств (`\\.\…`, `\\?\…`, кроме `\\?\C:\…` и `\\?\UNC\…`), именованные каналы, устройства вроде `NUL` и `CON` и любой открытый объект, который не является файлом на диске. Оригинал читает любой путь без ограничения размера.
- `getKeyInfo` открывает окна с действием «Информация о ключе» и кнопкой «Отправить», как у оригинала.
- Выбор файла (`showFileChooser`) открывается поверх других окон в небольшом окне с адресом запросившего сайта.
- Неверный пароль и хранилище без ключей нужного `keyType` снова открывают окно хранилища с ошибкой (тексты об отсутствии ключей — оригинала). Оригинал показывает ошибку в своём окне ключей. Просроченные ключи доступны, как у оригинала, но окно их не помечает.
- Тексты, которые оригинал формирует сам, совпадают: `action.canceled`, `storage.*`, `file.not_found`, `NoSuchMethodException …`, `UNKNOWN_ALGORITHM`, `CMS_NO_ENCAPSULATED_DATA`, `ISSUER_CERT_NOT_FOUND`, сообщения Kalkan об элементе XML, сообщения Java о base64. Ошибки разбора XML и CMS, TSP и построения цепочки — свои; для цепочки — после префикса `java.security.cert.CertPathBuilderException: `.
- Аргумент неверного типа всегда даёт `argument type mismatch`. JRE оригинала после 15 вызовов метода отвечает `java.lang.ClassCastException@<хэш>`.
- `signXml` сохраняет байты документа, как и `basics`. Пустой `signatureParentElementXPath` при непустом `tbsElementXPath` кладёт подпись в корень, у оригинала это ошибка XPath. Ненайденный родитель подписи даёт сообщение, у оригинала ответ без `message` (`NullPointerException`).

#### Applet

Модуль `kz.gov.pki.knca.applet.Applet` (устаревший; на запросы без `module` отвечает он):
- Реализовано подмножество для файловых хранилищ `PKCS12` и `JKS` (только чтение): `showFileChooser`, `browseKeyStore`, `setPassword`, `getTryCount`, `genKeyPairAndGetPKCS10`, `setX509CertToKeyStore`, `setX509CertToKeyStoreAndChangePassword`, `changePassword`, `signXml`. `loadSlotList`, `getPublicPartInfo`, `deleteEntry` и `resetStorage` отвечают, как оригинал без устройств. `genExt`, `getProvider`, `setProvider` и `showTokenChooser` отвечают `java.lang.NoSuchMethodException. Method: <имя>`.
- Токены до P14 отвечают `EMPTY_SLOT` (`browseKeyStore` — `TOKEN_CHOOSE_CANCEL`, `deleteEntry` и `resetStorage` — `COMMON`), окон не открывают. `changePassword` для токена, как оригинал без устройства, сначала проверяет новый PIN по правилу хранилища: пустой или с недопустимыми символами или длиной — `CHANGEPASS_INCORRECT_NEWPASS_PATTERN`, удостоверение личности и облачное хранилище — `UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION`; с верным PIN — `CHANGEPASS_COMMON` (устройства нет). `loadSlotList` всегда отвечает `EMPTY_SLOT`, в том числе для `PKCS12` и неизвестного имени: оригинал проверяет имя, только когда карта вставлена.
- `genKeyPairAndGetPKCS10` генерирует ключи ГОСТ 34.310-2004 и sha256RSA длиной 2048, 3072 или 4096 бит, иначе `GENKEY_UNKNOWN_ALG`. Оригинал генерирует также sha1RSA, ГОСТ GammaTech и RSA любой длины (ГОСТ 2015 не генерирует и он). Идентификатор ключа — как у апплета оригинала: SHA-1 от всего `SubjectPublicKeyInfo` (у `generateCsr` — от BIT STRING открытого ключа). Это псевдоним, `localKeyId` и имя файла ключа, SubjectKeyIdentifier запроса и `secondResult`. Ключи создаются только в существующей локальной папке, заданной абсолютным путём, иначе `COMMON`; в `JKS` не записываются (`UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION`). Значения, которые Kalkan записывает без проверки, дают `GENKEY_COMMON`: dNSName не из ASCII (например, CN кириллицей при непустом `subjectAlternativeNames`), `E` и `DC` не из ASCII, `SERIALNUMBER` и `C` с символами вне PrintableString. Оригинал записывает их искажёнными или в неверном типе строки.
- Один запрос `genKeyPairAndGetPKCS10` создаёт не больше 16 ключей: при большем числе элементов `keyLengths` ответ — `GENKEY_COMMON`, до генерации первого ключа. Оригинал без ограничения и без окна создаёт столько файлов ключей, сколько просит страница.
- Один запрос `setX509CertToKeyStore` или `setX509CertToKeyStoreAndChangePassword` устанавливает не больше 16 сертификатов: при большем числе сертификатов в списке через `<@>` ответ — `SETCERT_COMMON`, до обращения к файлам. Оригинал без ограничения и без окна перезаписывает файл ключей на каждый сертификат.
- `setX509CertToKeyStore`, как оригинал, сначала проверяет сертификат (SubjectKeyIdentifier, KeyStoreInfo — `SETCERT_COMMON`), затем папку. Ключ ищется только в папке: файл или несуществующий путь — `SETCERT_COMMON`. Папку называет страница, поэтому в ней просматриваются не больше 4096 записей и пробуются не больше 64 файлов ключей (первых по имени); ключ за этими пределами — `KEYSTORE_FILE_NOT_FOUND`. FIFO и файлы больше 64 МиБ пропускаются; это правило действует и для `importCertificate` в `basics`, но папку, выбранную пользователем, `importCertificate` просматривает целиком, как оригинал. `JKS` — `SETCERT_COMMON`. Файл ключей с другим паролем — `KEYSTORE_FILE_NOT_FOUND`, как у оригинала, поэтому `SETCERT_WRONG_PASSWORD`, `BLOCKED_KEYSTORE_PASSWORD` и `UNKNOWN_KNCA_CERTIFICATE_TYPE` для файлов не возникают ни у оригинала, ни у нас.
- `changePassword` и `signXml` читают файл ключей по правилам commonUtils для путей страницы: только локальный обычный файл на диске размером не больше 64 МиБ. Файл, который в окне `signXml` выбрал пользователь, читается по тем же правилам, но может лежать в сетевой папке: отклоняются только пути, которые назвала страница. `changePassword` читает файл один раз.
- `signXml` открывает окно хранилища с путём страницы (пользователь может выбрать другой файл), затем окно выбора ключа; кнопки «Удалить ключ» нет. Пустой пароль («Пустое поле»), пароль `INAUTH`/`INSIGN` не по правилу внутренних систем (тексты оригинала), неверный пароль и хранилище без ключей нужного `keyType` снова открывают окно хранилища. Если документ не подписывается (например, не XML), окно ключей остаётся открытым и показывает ошибку; закрыть его можно только отменой — `SIGN_CANCEL`. Окно оригинала в этом случае тоже остаётся открытым, но ошибку не показывает. Байты документа сохраняются, как в `basics`.
- Окно `setPassword` показывает адрес запросившего сайта, а текст страницы — простым текстом (оригинал показывает его как HTML).

#### accessory

- `getBundles` перечисляет фреймворк оригинала (`org.apache.felix.framework`), его основные бандлы, функции которых реализует OpenNCALayer, с версиями из текущего манифеста обновлений оригинала, и сам OpenNCALayer (`io.github.arynyklas.openncalayer`). Оригинал перечисляет все установленные бандлы, включая модули других поставщиков.
- `installBundle` с непустым `symname` и заголовком `Origin` всегда отвечает `BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED`, без окна: портов модулей других поставщиков до P11 нет (D21). Оригинал для модуля, который можно установить, сначала спрашивает подтверждение. Запрос пишется в журнал; с P5 значок OpenNCALayer показывает уведомление со ссылкой на список плагинов `https://arynyklas.github.io/open-ncalayer/plugins/` (не чаще раза в 10 минут; сама страница появится в P12). Без заголовка `Origin` ответ — `org.json.JSONException: JSONObject["origin"] is not a string.`, как у оригинала.
- `showBundleManager`, `showSettings`, `showKeystoreExplorer`, `showAdesSigning` и `showAdesValidation` отвечают `{}`, как оригинал, но окно не открывается: запрос только пишется в журнал. Окна настроек и модулей появятся в P5.

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

1. После `tls init` установите CA по напечатанной инструкции или кнопкой в мастере «Сертификат для браузера…» (меню значка OpenNCALayer; там же — mkcert, свой сертификат и проверка доверия). Подробности по каждой ОС — в [`docs/user/tls.md`](docs/user/tls.md).
2. Запустите `openncalayer run` и откройте `https://127.0.0.1:13579/` (или `https://127.0.0.1:13579/openncalayer/selftest`): страница должна открыться без предупреждения о сертификате.
3. На `https://127.0.0.1:13579/demo/` можно подписать текст или файл и скачать `.p7s`.
4. Проверить подпись: `openncalayer cms-verify signature.p7s`, для подписи без вложенных данных — `openncalayer cms-verify signature.p7s --content <файл данных>`. Проверяются подписи и метки времени, цепочки сертификатов подписанта и TSA через встроенные сертификаты НУЦ (`--chain <файл CA>` заменяет их; можно указать несколько раз, PEM-файл может содержать несколько сертификатов), срок действия и отзыв: подписанта — по OCSP, промежуточных CA — по CRL (кэш в `crl/` каталога данных). Момент подписи доказывает только проверенная метка времени: срок действия и отзыв проверяются на её `genTime`, а без метки — на текущий момент; `signingTime` — заявление самого подписанта, оно только печатается. Отзыв после метки времени подпись не портит: `OK` вместе со строкой `revocation: revoked … after signing (…)`. Последняя строка — `OK`, `FAIL: <причина>`, `INDETERMINATE: revocation data unavailable` (всё остальное верно, но сведений об отзыве получить не удалось) или `INDETERMINATE: no proof of signing time` (сертификат сейчас просрочен или отозван, а подпись была бы верна только на заявленный `signingTime`). Код выхода 0 только для `OK`. С `--offline` отзыв не проверяется, перед `OK` стоит строка `not checked: revocation`.

Коды выхода `run`:
- 2 — TLS не настроен;
- 3 — порт занят, например оригинальным NCALayer;
- 4 — OpenNCALayer с тем же каталогом данных уже запущен в этом сеансе.

С флагом `--allow-no-wss` (так relay расширения запускает демон) любая ошибка запуска wss (коды 2, 3 и 1) не останавливает демон: он пишет предупреждение в журнал и работает только для расширения. Освободившийся порт такой демон сам не занимает: wss он запускает только после действия пользователя в значке или мастере TLS (остановить оригинал, сохранить сертификат).

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
- Демон, запущенный relay, работает до конца сеанса. Если TLS настроен и порт 13579 свободен, тот же демон обслуживает и `wss`; иначе в журнале — предупреждение, и демон работает только для расширения, пока пользователь не остановит оригинал или не сохранит сертификат в мастере.
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

Тестовые ключи в `fixtures/synthetic/` синтетические, пароль `Qwerty12`. Их можно использовать на демо-странице. По умолчанию демо отправляет `chain: []`, поэтому синтетические и тестовые ключи NCANode доступны. Вариант «синтетический тестовый корень» передаёт `root-gost2015`: ключи других корней и промежуточного CA становятся недоступны.

Тесты с пометкой `live_` обращаются к настоящим сервисам НУЦ и по умолчанию не запускаются:

```sh
cargo test --workspace --all-features -- --ignored live_
```

Это `live_test_tsa` (тестовый TSP НУЦ), `live_ocsp_nca_test_certificate` (тестовый OCSP НУЦ, нужен `cargo xtask fetch-fixtures`), `live_crl_nca_root_gost_2022` (CRL промышленного `crl.root.gov.kz`) и `live_cms_verify_command_without_revocation_services` (`cms-verify` при несуществующих адресах OCSP и CRL; нужен только DNS). Они зависят от внешних сервисов, поэтому CI запускает их только по расписанию и вручную (`workflow_dispatch`, job `live`), а единичный сбой сети стоит перезапустить. Тестовый RSA-ответчик OCSP НУЦ на стандартные запросы (и от OpenSSL тоже) отвечает `malformedRequest`, поэтому живой OCSP проверяется на ГОСТ-сертификате.

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

Проверка наших подписей XMLDSig и CMS в NCANode (Kalkan), только Linux, нужен Docker: `cargo xtask fetch-fixtures && cargo xtask interop-ncanode`. Образ, порядок запуска и последний результат описаны в [`docs/dev/interop-ncanode.md`](docs/dev/interop-ncanode.md).

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
