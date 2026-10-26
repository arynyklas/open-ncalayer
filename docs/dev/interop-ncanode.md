# Interop с NCANode (Kalkan)

`cargo xtask interop-ncanode` проверяет наши подписи XMLDSig и CMS в [NCANode](https://github.com/ncanode-kz/NCANode): сервер проверяет их через Kalkan, как это делают сервисы, принимающие подписи NCALayer. Команда работает только в Linux. В Windows она печатает «interop с NCANode запускается в Linux» и завершается с кодом 0.

## Образ

| | |
|---|---|
| Образ | `malikzh/ncanode@sha256:052222f30ac73d9f0060a5c80c572723d25dd84e21073435795a10db254c02b8` |
| Версия | NCANode 3.5.1 (тег Docker Hub `3.5.1`, релиз GitHub `3.5.1`), KalkanCrypt 0.7.5 |
| Коммит | `0adab29a7d30c181d70e8cc6b4f243122f50c3b8`, тот же, с которого `cargo xtask fetch-fixtures` берёт тестовые файлы |

Digest закреплён в `xtask/src/ncanode.rs` (`IMAGE`). Чтобы обновить образ, нужно поменять digest там и в этой таблице, а также `NCANODE_COMMIT` в `xtask/src/fetch.rs`.

NCANode запускается с настройками по умолчанию: промышленные корни, CRL и OCSP НУЦ. При старте он скачивает сертификаты и CRL с `pki.gov.kz`, `root.gov.kz` и `crl.pki.gov.kz`/`crl.root.gov.kz`, так что нужна сеть. Если скачать сертификат НУЦ не удалось, NCANode завершается. В WSL это время от времени случается то с одним, то с другим сертификатом (`pki.gov.kz/cert/nca_gost.crt`, `root.gov.kz/cert/root_gost_2020.cer`): загрузка падает с `Cannot download file`. При этом `curl` из WSL и `wget` из контейнера того же образа сразу после такого сбоя скачивали `nca_gost.crt` за доли секунды. Тогда xtask печатает журнал контейнера и запускает его заново, всего до пяти попыток. На 2026-10-26 примерно каждый второй старт в WSL заканчивался так, и вторая попытка проходила.

Кэш NCANode (`/app/cache`) хранится в томе Docker `oncl-ncanode-cache` и переживает запуски. Уже скачанные сертификаты НУЦ NCANode берёт из кэша (`CaService`), поэтому следующая попытка или следующий запуск качает меньше. Исключение — `nca_gost.crt`: он просрочен (`notAfter` 2025-06-25), и NCANode скачивает его заново при каждом старте. Очистить кэш: `docker volume rm oncl-ncanode-cache`.

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

Контейнер называется `oncl-ncanode-interop` и слушает случайный порт на `127.0.0.1`. После проверки контейнер удаляется, а том с кэшем остаётся. Контейнер с тем же именем, оставшийся от прерванного запуска, удаляется перед стартом.

Если `docker pull` падает с `docker-credential-desktop.exe: executable file not found` (в WSL остался `~/.docker/config.json` от Docker Desktop), образ можно скачать с пустым конфигом: `DOCKER_CONFIG=<пустой каталог> docker pull <образ>`. Сама команда после этого скачивать образ уже не будет.

В CI команда запускается только в job `live` (по расписанию и вручную), не на каждый push.

## Что проверяется

Ключи:
- синтетические `fixtures/synthetic/user-{gost2015,gost2004,rsa}-sign.p12`;
- тестовые ключи NCANode `individual_valid_2015.p12` (ГОСТ 2015) и `individual_valid_sign_2004.p12` (ГОСТ 2004).

Подписываем в процессе (`oncl_pki::xmldsig`, `oncl_pki::cms`), а результат отправляем в HTTP API NCANode.

| Проверка | Как |
|---|---|
| XML, весь документ | `sign_enveloped` → `/xml/verify`. Документ неудобный: BOM, декларация, комментарии, CRLF, пространство имён по умолчанию, `xml:lang`, атрибуты не по порядку, пустой элемент, кириллица |
| XML, элемент `#payload` | `sign_element("//data")` → `/xml/verify` |
| CMS attached / detached | `cms::sign` → `/cms/verify` (для detached — с `data`) |
| XML, две подписи | ГОСТ 2015, затем RSA → `/xml/verify`, ожидается 2 подписанта |
| CMS, соподпись | ГОСТ 2015, затем RSA → `/cms/verify`, ожидается 2 подписанта |
| Контроли | изменённый подписанный документ и изменённое значение подписи CMS: NCANode обязан ответить `SIG_CRYPTO_FAILURE` |
| Digest против Kalkan | Kalkan подписывает тот же вход тем же ключом (`/xml/sign`, тестовый ключ ГОСТ 2015), и `DigestValue` новой ссылки должен совпасть с нашим. Входы: неудобный документ целиком; тот же документ с нашей подписью (вторая подпись покрывает первую); элемент `#e1` под двумя разными `xml:lang`. Затем наш `verify` должен принять документ, который подписал Kalkan |
| `#e1` под двумя `xml:lang` | наша подпись элемента → `/xml/verify` |

### Как читать результат

NCANode оценивает подпись по порядку. Сначала проверяется значение подписи: при неудаче — `INVALID/SIG_CRYPTO_FAILURE`, без сертификата — `NO_SIGNING_CERTIFICATE_FOUND`. Потом проверяется сертификат: срок, доверенный издатель, отзыв. Ни один ключ здесь не строит цепочку до действующего корня НУЦ: у синтетических корни свои, тестовые сертификаты NCANode просрочены. Поэтому `valid` всегда `false`. Проверка считается пройденной, если оценка дошла до сертификата: колонка `signature` = `OK`. Колонка `valid` и оценка NCANode выводятся как есть. Ожидаемые оценки:
- для синтетических ключей — `INDETERMINATE/CHAIN_INCOMPLETE`;
- для тестовых ключей NCANode — `INDETERMINATE/OUT_OF_BOUNDS_NO_POE` (просрочен).

Особенности NCANode, которые учитывает команда:
- `/xml/verify` не регистрирует атрибуты `Id`, поэтому не находит `URI="#id"` и отвечает `SIG_CRYPTO_FAILURE` даже на подпись элемента, которую сделал сам Kalkan через `/xml/sign` с `referenceUri`. Поэтому в подписанный документ, который уходит в `/xml/verify`, xtask вставляет внутреннее подмножество DTD `<!DOCTYPE root [<!ATTLIST data Id ID #IMPLIED>]>`. Каноническую форму оно не меняет. С таким DTD подпись Kalkan проверяется (`OUT_OF_BOUNDS_NO_POE`), и наша тоже.
- В `/xml/verify` подпись ищется как `ds:Signature` среди детей корня и снимается через `root.removeChild`. Поэтому NCANode проверяет только подписи с префиксом `ds:`, вставленные в корень. Наши подписи такие и есть.
- Для XML с несколькими подписями NCANode возвращает оценку только первой по документу подписи (проверяет он с последней), а `valid` — по всем. Что вторая подпись покрывает первую, подтверждает строка «Kalkan digest: over our signature».

Правило Kalkan для `xml:*` в Canonical XML подтверждено: при наследовании от опущенных предков побеждает **внешнее** значение (`crates/oncl-pki/src/xmldsig/c14n.rs`). Это показывают строки 27–28: digest элемента `<e Id="e1">` под `<r xml:lang="ru">` → `<m xml:lang="kk">` совпадает с digest Kalkan.

## Результат — 2026-10-26

WSL2 Ubuntu 24.04, Docker 29.3.1 (движок Docker Desktop, интеграция с WSL), образ выше. Из трёх последних запусков в двух первый старт NCANode оборвался на загрузке сертификата НУЦ, и NCANode поднялся со второй попытки. Таблица во всех трёх одна и та же.

```
#  | check                               | key                                 | signature       | valid | NCANode grade / detail
-- | ----------------------------------- | ----------------------------------- | --------------- | ----- | --------------------------------------------------------------
1  | XML document                        | synthetic GOST 2015                 | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
2  | XML element #payload                | synthetic GOST 2015                 | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
3  | CMS attached                        | synthetic GOST 2015                 | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
4  | CMS detached                        | synthetic GOST 2015                 | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
5  | XML document                        | synthetic GOST 2004                 | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
6  | XML element #payload                | synthetic GOST 2004                 | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
7  | CMS attached                        | synthetic GOST 2004                 | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
8  | CMS detached                        | synthetic GOST 2004                 | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
9  | XML document                        | synthetic RSA                       | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
10 | XML element #payload                | synthetic RSA                       | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
11 | CMS attached                        | synthetic RSA                       | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
12 | CMS detached                        | synthetic RSA                       | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
13 | XML document                        | NCANode GOST 2015                   | OK              | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
14 | XML element #payload                | NCANode GOST 2015                   | OK              | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
15 | CMS attached                        | NCANode GOST 2015                   | OK              | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
16 | CMS detached                        | NCANode GOST 2015                   | OK              | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
17 | XML document                        | NCANode GOST 2004                   | OK              | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
18 | XML element #payload                | NCANode GOST 2004                   | OK              | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
19 | CMS attached                        | NCANode GOST 2004                   | OK              | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
20 | CMS detached                        | NCANode GOST 2004                   | OK              | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
21 | XML document, 2 signatures          | synthetic GOST 2015 + synthetic RSA | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE
22 | CMS co-signed                       | synthetic GOST 2015 + synthetic RSA | OK              | false | INDETERMINATE/CHAIN_INCOMPLETE; INDETERMINATE/CHAIN_INCOMPLETE
23 | control: XML document altered       | synthetic GOST 2015                 | FAIL, expected  | false | INVALID/SIG_CRYPTO_FAILURE
24 | control: CMS signature altered      | synthetic GOST 2015                 | FAIL, expected  | false | INVALID/SIG_CRYPTO_FAILURE
25 | Kalkan digest: XML document         | NCANode GOST 2015                   | digest = Kalkan | -     | our verify of Kalkan's XML: OK (1)
26 | Kalkan digest: over our signature   | NCANode GOST 2015                   | digest = Kalkan | -     | our verify of Kalkan's XML: OK (2)
27 | Kalkan digest: #e1 under 2 xml:lang | NCANode GOST 2015                   | digest = Kalkan | -     | our verify of Kalkan's XML: OK (1)
28 | XML element #e1 under 2 xml:lang    | NCANode GOST 2015                   | OK              | false | INDETERMINATE/OUT_OF_BOUNDS_NO_POE
28 of 28 checks passed
```

Kalkan принял все наши подписи, и все три digest совпали, так что исправлять код XMLDSig и CMS не понадобилось.

Проверку сгенерированного нами `.p12` (загрузка в NCANode и проверка подписи CSR) добавим следующим шагом.
