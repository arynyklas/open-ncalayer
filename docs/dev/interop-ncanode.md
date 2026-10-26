# Interop с NCANode (Kalkan)

`cargo xtask interop-ncanode` проверяет наши подписи XMLDSig и CMS и наши файлы ключей в [NCANode](https://github.com/ncanode-kz/NCANode): сервер проверяет их через Kalkan, как это делают сервисы, принимающие подписи NCALayer. Команда работает только в Linux. В Windows она печатает «interop с NCANode запускается в Linux» и завершается с кодом 0.

## Образ

| | |
|---|---|
| Образ | `malikzh/ncanode@sha256:052222f30ac73d9f0060a5c80c572723d25dd84e21073435795a10db254c02b8` |
| Версия | NCANode 3.5.1 (тег Docker Hub `3.5.1`, релиз GitHub `3.5.1`), KalkanCrypt 0.7.5 |
| Коммит | `0adab29a7d30c181d70e8cc6b4f243122f50c3b8`, тот же, с которого `cargo xtask fetch-fixtures` берёт тестовые файлы |

Digest закреплён в `xtask/src/ncanode/container.rs` (`IMAGE`). Чтобы обновить образ, нужно поменять digest там и в этой таблице, а также `NCANODE_COMMIT` в `xtask/src/fetch.rs`. После обновления проверьте, что контроли (см. ниже) по-прежнему получают `SIG_CRYPTO_FAILURE`, а хорошие подписи — ожидаемую оценку сертификата. Правило прохождения опирается на порядок проверок в `AdesVerificationService.grade()`: сначала значение подписи, потом сертификат.

NCANode запускается с настройками по умолчанию: промышленные корни, CRL и OCSP НУЦ. При старте он скачивает сертификаты и CRL с `pki.gov.kz`, `root.gov.kz` и `crl.pki.gov.kz`/`crl.root.gov.kz`, так что нужна сеть. Если скачать сертификат НУЦ не удалось, NCANode завершается. В WSL это время от времени случается то с одним, то с другим сертификатом (`pki.gov.kz/cert/nca_gost.crt`, `root.gov.kz/cert/root_gost_2020.cer`): загрузка падает с `Cannot download file`. При этом `curl` из WSL и `wget` из контейнера того же образа сразу после такого сбоя скачивали `nca_gost.crt` за доли секунды. Тогда xtask печатает журнал контейнера и запускает его заново, всего до пяти попыток. 2026-10-26 в WSL так заканчивался примерно каждый второй старт; NCANode поднимался со второй или третьей попытки.

Кэш NCANode (`/app/cache`) хранится в томе Docker `oncl-ncanode-cache` и переживает запуски. Уже скачанные сертификаты НУЦ NCANode берёт из кэша (`CaService`), поэтому следующая попытка или следующий запуск качает меньше. Исключение — `nca_gost.crt`: он просрочен (`notAfter` 2025-06-25), и NCANode скачивает его заново при каждом старте.

### Образ и том вне `target/`

Образ (около 700 МБ) и том `oncl-ncanode-cache` — скачанные данные, которые лежат вне `target/`, в хранилище Docker. Это осознанное исключение из правила «скачанное — только в git-ignored каталогах вроде `target/`», принятое для этой команды:
- образ объявляет `VOLUME /app/cache`, так что без именованного тома каждый запуск оставлял бы анонимный том;
- NCANode работает в контейнере от root, поэтому bind mount в `target/` оставил бы там файлы root, которые `cargo clean` не удалит.

Где они лежат, зависит от движка Docker. С `docker.io` внутри дистрибутива — в `/var/lib/docker` этого дистрибутива. С Docker Desktop и интеграцией WSL (так проверялось, см. «Результат») — в хранилище Docker Desktop на Windows-хосте, а не в дистрибутиве Ubuntu. Удалить их можно так:

```sh
docker volume rm oncl-ncanode-cache
docker image rm malikzh/ncanode@sha256:052222f30ac73d9f0060a5c80c572723d25dd84e21073435795a10db254c02b8
```

## Запуск

Нужен Docker. В Debian или Ubuntu (в том числе в WSL) он ставится и запускается от root:

```sh
apt-get install -y docker.io
service docker start
```

Пользователь должен входить в группу `docker`. В CI раннер `ubuntu-24.04` уже содержит Docker. Затем:

```sh
cargo xtask fetch-fixtures     # тестовые ключи NCANode → target/fixtures/ncanode/
cargo xtask interop-ncanode
```

Контейнер называется `oncl-ncanode-interop` и слушает случайный порт на `127.0.0.1`. После проверки контейнер удаляется, а том с кэшем и образ остаются (как их удалить — выше). Контейнер с тем же именем, оставшийся от прерванного запуска, удаляется перед стартом.

Если `docker pull` падает с `docker-credential-desktop.exe: executable file not found` (в WSL остался `~/.docker/config.json` от Docker Desktop), образ можно скачать с пустым конфигом: `DOCKER_CONFIG=<пустой каталог> docker pull <образ>`. Сама команда после этого скачивать образ уже не будет.

В CI команда запускается только в job `live` (по расписанию и вручную), не на каждый push.

## Что проверяется

Ключи:
- синтетические `fixtures/synthetic/user-{gost2015,gost2004,rsa}-sign.p12`;
- тестовые ключи NCANode (из `WithTestData.groovy`, `cargo xtask fetch-fixtures`):
  - `individual_valid_2015.p12` — ГОСТ 2015-512, пароль `Aa123456`, истёк 2023-07-28;
  - `ceo_sign_revoked_2004.p12` (`KEY_CEO_SIGN_REVOKED_2004`) — ГОСТ 34.310-2004, издатель `ҰКО 3.0 (GOST TEST)`, пароль `Qwerty12`, истёк 2023-01-18;
  - `individual_valid_sign_2004.p12` (`KEY_INDIVIDUAL_VALID_SIGN_2004`) — несмотря на имя, это RSA-2048 / sha256WithRSA, издатель `ҰКО 3.0 (RSA TEST)`, пароль `Qwerty12`, истёк 2022-01-18. В таблице — «NCANode RSA».

Подписываем в процессе (`oncl_pki::xmldsig`, `oncl_pki::cms`), а результат отправляем в HTTP API NCANode.

| Проверка | Как |
|---|---|
| XML, весь документ | `sign_enveloped` → `/xml/verify`. Документ неудобный: BOM, декларация, комментарии, CRLF, пространство имён по умолчанию, `xml:lang`, атрибуты не по порядку, пустой элемент, кириллица |
| XML, элемент `#payload` | `sign_element("//data")` → `/xml/verify` (с DTD, см. ниже) |
| CMS attached / detached | `cms::sign` → `/cms/verify` (для detached — с `data`) |
| XML, две подписи | синтетические ГОСТ 2015, затем RSA → `/xml/verify`. Проверяется число подписантов (2) и оценка **первой** подписи: вторую NCANode не оценивает (см. ниже) |
| CMS, соподпись | синтетические ГОСТ 2015, затем RSA → `/cms/verify`, 2 подписанта, оценка каждого |
| Контроли | NCANode обязан ответить `INVALID/SIG_CRYPTO_FAILURE` на: изменённый документ (ГОСТ 2015, синтетический); изменённый элемент `#payload` с DTD (ГОСТ 2015, синтетический); изменённый элемент `#e1` с DTD (ключ NCANode ГОСТ 2015); испорченный `DigestValue` (ключ NCANode ГОСТ 2004); изменённое значение подписи CMS (синтетический ГОСТ 2015 и ключ NCANode ГОСТ 2004) |
| Digest против Kalkan | Kalkan подписывает тот же вход тем же ключом (`/xml/sign`), и `DigestValue` новой ссылки должен совпасть с нашим. Входы: неудобный документ целиком (все три ключа NCANode); тот же документ с нашей подписью (вторая подпись покрывает первую); элемент `#e1` под двумя разными `xml:lang`. Затем наш `verify` должен принять документ, который подписал Kalkan |
| `#e1` под двумя `xml:lang` | наша подпись элемента → `/xml/verify` |
| Наш файл ключа: ключ без сертификата | генерируем ключ (ГОСТ 2015, ГОСТ 2004, RSA; `oncl_pki::keygen`), строим на него CSR (`oncl_pki::csr`) и пишем ключ в `<PREFIX><keyId>.p12` (`keystore::create_key_file`, пароль `Default1`) → `/pkcs12/aliases`: Kalkan открывает файл и видит ровно один alias — keyId |
| Наш файл ключа: сертификат установлен | синтетический ключ того же алгоритма выпускает сертификат на CSR (субъект, ключ и расширения запроса, SKI = keyId); `keystore::install_certificate`, затем `keystore::change_password` на `Interop12`, как в `importCertificate` → `/pkcs12/info`: Kalkan находит в файле сертификат с нашим серийным номером |
| Наш файл ключа: Kalkan подписывает CMS | `/cms/sign` с этим файлом → `/cms/verify`: подпись Kalkan нашим ключом проверяется, 1 подписант, `INDETERMINATE/CHAIN_INCOMPLETE` |

Подпись CSR в NCANode проверить нельзя: у него нет метода для PKCS#10, а `/x509/verify` принимает подписанные данные строкой UTF-8, которой `CertificationRequestInfo` не является. Подпись CSR проверяет сам xtask (нашим кодом, открытым ключом из запроса) перед выпуском сертификата. Что Kalkan читает сгенерированный ключ, показывает строка «Kalkan подписывает CMS». Что Kalkan принимает подписи, которые делает `PrivateKey::sign` (им же подписывается CSR), показывают строки 1–12.

### Как читать результат

NCANode оценивает подпись по порядку (`AdesVerificationService.grade()`). Сначала проверяется значение подписи и дайджесты ссылок: при неудаче — `INVALID/SIG_CRYPTO_FAILURE`. Потом проверяется сертификат: срок, доверенный издатель, отзыв. Ни один ключ здесь не строит цепочку до действующего корня НУЦ: у синтетических корни свои, тестовые сертификаты NCANode просрочены. Поэтому `valid` всегда `false`.

Проверка пройдена, только если NCANode вернул ровно ожидаемую оценку и ожидаемое число подписантов:
- хорошая подпись синтетическим ключом — `INDETERMINATE/CHAIN_INCOMPLETE`;
- хорошая подпись ключом NCANode — `INDETERMINATE/OUT_OF_BOUNDS_NO_POE` (срок истёк; для отозванного ГОСТ 2004 срок проверяется раньше отзыва);
- контроль — `INVALID/SIG_CRYPTO_FAILURE`.

До оценки сертификата NCANode доходит только после того, как значение подписи сошлось, так что `OK` в колонке `signature` значит, что Kalkan принял подпись. Контроли показывают обратное на тех же путях: с DTD для элементов, на просроченных ключах NCANode, для XML и CMS. Колонка `signature`: `OK` — хорошая подпись с ожидаемой оценкой, `rejected, expected` — контроль отвергнут, как и должен, `UNEXPECTED` — любая другая оценка (в колонке оценки тогда дописано, какая ожидалась), `ERROR` — запрос не удался.

Особенности NCANode, которые учитывает команда:
- `/xml/verify` не регистрирует атрибуты `Id`, поэтому не находит `URI="#id"` и отвечает `SIG_CRYPTO_FAILURE` даже на подпись элемента, которую сделал сам Kalkan через `/xml/sign` с `referenceUri`. Поэтому в подписанный документ, который уходит в `/xml/verify`, xtask вставляет внутреннее подмножество DTD `<!DOCTYPE root [<!ATTLIST data Id ID #IMPLIED>]>`. Каноническую форму оно не меняет. С таким DTD подпись Kalkan проверяется (`OUT_OF_BOUNDS_NO_POE`), и наша тоже, а изменённый элемент отвергается (строки 28–29).
- В `/xml/verify` подпись ищется как `ds:Signature` среди детей корня и снимается через `root.removeChild`. Поэтому NCANode проверяет только подписи с префиксом `ds:`, вставленные в корень. Наши подписи такие и есть.
- Для XML с несколькими подписями NCANode возвращает оценку только первой по документу подписи (проверяет он с последней), а `valid` — по всем. Поэтому строка 25 называется «count, 1st graded»: она проверяет число подписантов и оценку первой подписи, но не вторую. Вторую подпись покрывают строка 9 (Kalkan принимает нашу RSA-подпись) и строка 36 (наш digest документа, уже несущего подпись, совпадает с Kalkan).

Правило Kalkan для `xml:*` в Canonical XML подтверждено: при наследовании от опущенных предков побеждает **внешнее** значение (`crates/oncl-pki/src/xmldsig/c14n.rs`). Это показывают строки 37–38: digest элемента `<e Id="e1">` под `<r xml:lang="ru">` → `<m xml:lang="kk">` совпадает с digest Kalkan, и NCANode принимает нашу подпись этого элемента.

Строки «our key file» (39–47): `opened` в колонке `signature` значит, что ответ NCANode совпал с ожидаемым (для «key alone» — список alias из одного keyId, для «certificate installed» — серийный номер выпущенного сертификата, как его печатает NCANode: `BigInteger.toString(16)`), `UNEXPECTED` — что не совпал (ожидаемое значение дописано в последнюю колонку). Строка «Kalkan signs CMS» читается как остальные строки CMS. Ключи генерируются заново при каждом запуске, поэтому keyId и серийные номера в таблице каждый раз другие.

## Результат — 2026-10-26

WSL2 Ubuntu 24.04, Docker 29.3.1 (движок Docker Desktop, интеграция с WSL), образ выше. Строки 1–38 — первый запуск: в нём NCANode дважды завершился на загрузке `pki.gov.kz/cert/nca_gost.crt` и поднялся с третьей попытки. Строки 39–47 добавлены вместе с генерацией ключей и запускались там же: прошли все 47 проверок, строки 1–38 совпали с таблицей. Итоговая проверка P4 (2026-10-27, та же среда, итоговый код ветки) снова дала 47 из 47; таблица совпала, кроме идентификаторов ключей в строках 39–47: ключи генерируются при каждом запуске.

```
#  | check                                 | key                                 | signature          | valid | NCANode grade / detail
-- | ------------------------------------- | ----------------------------------- | ------------------ | ----- | --------------------------------------------------------------
1  | XML document                          | synthetic GOST 2015                 | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
2  | XML element #payload                  | synthetic GOST 2015                 | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
3  | CMS attached                          | synthetic GOST 2015                 | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
4  | CMS detached                          | synthetic GOST 2015                 | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
5  | XML document                          | synthetic GOST 2004                 | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
6  | XML element #payload                  | synthetic GOST 2004                 | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
7  | CMS attached                          | synthetic GOST 2004                 | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
8  | CMS detached                          | synthetic GOST 2004                 | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
9  | XML document                          | synthetic RSA                       | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
10 | XML element #payload                  | synthetic RSA                       | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
11 | CMS attached                          | synthetic RSA                       | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
12 | CMS detached                          | synthetic RSA                       | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
13 | XML document                          | NCANode GOST 2015                   | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
14 | XML element #payload                  | NCANode GOST 2015                   | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
15 | CMS attached                          | NCANode GOST 2015                   | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
16 | CMS detached                          | NCANode GOST 2015                   | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
17 | XML document                          | NCANode GOST 2004                   | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
18 | XML element #payload                  | NCANode GOST 2004                   | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
19 | CMS attached                          | NCANode GOST 2004                   | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
20 | CMS detached                          | NCANode GOST 2004                   | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
21 | XML document                          | NCANode RSA                         | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
22 | XML element #payload                  | NCANode RSA                         | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
23 | CMS attached                          | NCANode RSA                         | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
24 | CMS detached                          | NCANode RSA                         | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
25 | XML 2 signatures: count, 1st graded   | synthetic GOST 2015 + synthetic RSA | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
26 | CMS co-signed                         | synthetic GOST 2015 + synthetic RSA | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE; INDETERMINATE/CHAIN_INCOMPLETE
27 | control: XML document altered         | synthetic GOST 2015                 | rejected, expected | false | INVALID/SIG_CRYPTO_FAILURE
28 | control: XML element #payload altered | synthetic GOST 2015                 | rejected, expected | false | INVALID/SIG_CRYPTO_FAILURE
29 | control: XML element #e1 altered      | NCANode GOST 2015                   | rejected, expected | false | INVALID/SIG_CRYPTO_FAILURE
30 | control: XML DigestValue altered      | NCANode GOST 2004                   | rejected, expected | false | INVALID/SIG_CRYPTO_FAILURE
31 | control: CMS signature altered        | synthetic GOST 2015                 | rejected, expected | false | INVALID/SIG_CRYPTO_FAILURE
32 | control: CMS signature altered        | NCANode GOST 2004                   | rejected, expected | false | INVALID/SIG_CRYPTO_FAILURE
33 | Kalkan digest: XML document           | NCANode GOST 2015                   | digest = Kalkan    | -     | our verify of Kalkan's XML: OK (1)
34 | Kalkan digest: XML document           | NCANode GOST 2004                   | digest = Kalkan    | -     | our verify of Kalkan's XML: OK (1)
35 | Kalkan digest: XML document           | NCANode RSA                         | digest = Kalkan    | -     | our verify of Kalkan's XML: OK (1)
36 | Kalkan digest: over our signature     | NCANode GOST 2015                   | digest = Kalkan    | -     | our verify of Kalkan's XML: OK (2)
37 | Kalkan digest: #e1 under 2 xml:lang   | NCANode GOST 2015                   | digest = Kalkan    | -     | our verify of Kalkan's XML: OK (1)
38 | XML element #e1 under 2 xml:lang      | NCANode GOST 2015                   | OK                 | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
39 | our key file: key alone               | generated GOST 2015                 | opened             | -     | [["62debbcdc0511396fb3e52164e150bbd299bf1a9"]]
40 | our key file: certificate installed   | generated GOST 2015                 | opened             | -     | 62debbcdc0511396
41 | our key file: Kalkan signs CMS        | generated GOST 2015                 | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
42 | our key file: key alone               | generated GOST 2004                 | opened             | -     | [["c05a8a29170f6f411a0e2f16d55bf2f3f91dba9a"]]
43 | our key file: certificate installed   | generated GOST 2004                 | opened             | -     | 405a8a29170f6f41
44 | our key file: Kalkan signs CMS        | generated GOST 2004                 | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
45 | our key file: key alone               | generated RSA                       | opened             | -     | [["772c970ac20fa6c609385bf0b67a7229444a2f43"]]
46 | our key file: certificate installed   | generated RSA                       | opened             | -     | 772c970ac20fa6c6
47 | our key file: Kalkan signs CMS        | generated RSA                       | OK                 | false | INDETERMINATE/CHAIN_INCOMPLETE
47 of 47 checks passed
```

Kalkan принял все наши подписи: синтетическими ключами и ключами НУЦ ГОСТ 2015, ГОСТ 34.310-2004 и RSA. Все контроли отвергнуты, все пять digest совпали с Kalkan, и наш `verify` принял подписи Kalkan всеми тремя алгоритмами. Исправлять код XMLDSig и CMS не понадобилось.

Наши файлы ключей Kalkan открывает для всех трёх алгоритмов: файл с одним ключом (без сертификата, как его пишет `generateCsr`) — с alias = keyId, файл после установки сертификата и смены пароля — с этим сертификатом при ключе. Kalkan подписывает ключом из нашего файла, и подпись проверяется: кодирование ключей в PKCS#8 и профиль PKCS#12 Kalkan понимает.
