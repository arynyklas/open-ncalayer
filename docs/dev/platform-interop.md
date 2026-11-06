# Независимая interop-матрица платформы

`cargo xtask platform-interop --out target/platform-interop` прогоняет **собранный `oncl`** (процесс, не SDK в памяти) против независимых проверяющих и пишет `report.json` / `report.md` (версии инструментов, digest образа и фикстур, строка на каждый случай, дефекты, ожидающие семейства). Запуск только в Linux: NCANode работает из закреплённого образа в Docker. В Windows матрица не выполняется, нулевой код «только Linux» запуском не считается.

Состав матрицы — `fixtures/platform/coverage.toml`: capability → случаи → дескрипторы проверяющих (инструмент, версия, закрепление) → ожидаемая оценка. Тест `xtask/tests/platform_interop.rs` падает, если маршрут закреплённого OpenAPI NCANode (commit `0adab29a…`, sha256 `openapi.yml` в `pins`) не относится ни к одной capability, у capability нет случая, у случая нет строки, у строки нет случая или проверяющий не описан. Пока в `[[pending]]` есть семейства без случаев, тест `no_capability_is_left_without_cases` красный, а прогон завершается `INCOMPLETE`; сейчас `[[pending]]` пуст. Красная строка с `defect = "Dn"` — не отсутствие покрытия: тест `defect_markers_reference_reproductions_and_grades_are_defined` требует для каждой такой строки воспроизведение в `[[defect]]`, а любую строку — определённую ожидаемую оценку.

## Проверяющие

| id | что | роль |
|---|---|---|
| `ncanode` | NCANode 3.5.1 (Kalkan), образ по digest | единственный независимый ГОСТ 2004 / 2015-512 и RSA для CMS/CAdES, XMLDSig/XAdES, PAdES; уровни AdES |
| `openssl` 3.x | `cms -verify` с путём до корня, `cms -sign`, `pkcs12 -legacy` | RSA CMS/CAdES |
| `pyhanko` 0.38.0 | PAdES: целостность, доверие, DSS, метки документа | RSA PDF |
| `lxml`, `cryptography`, `asn1crypto` | каноническая форма XML, RSA над SignedInfo / signedAttrs, разбор BER/DER, токены RFC 3161, разбор ByteRange | RSA и структура |

Окружение Python: `ONCL_PYHANKO_PYTHON` (venv с `pyHanko==0.38.0 pyhanko-certvalidator==0.33.0 lxml gostcrypto`). `ONCL_OPENSSL` — путь к OpenSSL. Контейнер и том NCANode: `ONCL_NCANODE_CONTAINER`, `ONCL_NCANODE_CACHE_VOLUME` (по умолчанию как у `interop-ncanode`; общий том не меняется, если задать свой). `cargo xtask fetch-fixtures` берёт `openapi.yml`, CAdES/PAdES/XAdES-образцы NCANode; ничего из этого не коммитится.

Отсутствующий инструмент или другая версия, чем в дескрипторе, даёт строку `BLOCKED` с точной причиной, а не подмену.

## Оценки

Оценка строки — набор `ключ=значение`, по одному на проверяющего. `crypto=ok`: все проверяющие, способные проверить значение подписи и дайджесты, их приняли; `crypto=failure`: контрпример (изменены подписанные данные или подпись) отвергнут всеми. Оценка сертификата не смешивается с криптографической: `ours=Valid` — строгий прогон против loopback-PKI с корнем RSA, `ncanode=INDETERMINATE/CHAIN_INCOMPLETE` — NCANode не знает наших корней, `OUT_OF_BOUNDS_NO_POE` — просроченные тестовые ключи NCANode. Строка проходит, только если оценка совпала с ожидаемой дословно.

Известные ограничения проверяющих, не наше желаемое поведение:
- `/xml/verify` NCANode не регистрирует атрибуты `Id` (к документу добавляется внутренний DTD) и оценивает первую подпись;
- Kalkan объявляет `…#WithComments`, но считает дайджест без комментариев (случаи NCANode используют документ без комментария, иначе lxml расходится);
- правило Kalkan для `xml:*` в Canonical XML отличается от W3C (поэтому документ без `xml:*`);
- `/x509/verify` и `/pkcs12/info` складывают цепочку в `valid`, поэтому не различают хорошую и плохую подпись (оценка — OpenSSL);
- NCANode не делает CAdES-LTA на просроченных ключах (HTTP 500); `/cms/extend` до LTA отвечает 500; `/pdf/extend` не строит LT/LTA для цепочки не НУЦ (400 «no OCSP or CRL data available») и не расширяет до T (400 «supports only LT and LTA»);
- уровень PAdES у NCANode считается по документу, не по подписи (`detectLevel`: любой `/DocTimeStamp` даёт LTA): поэтому он читает наши шаги T и LT в `pades-extend-ours-*` как LTA (наш `extend --level t` добавляет метку документа); это ограничение оракула, не дефект;
- `/wsse/verify` отвечает HTTP 200 `valid=false` и для хорошего, и для испорченного сообщения (цепочка в `valid`), поэтому ГОСТ-строки WS-Security «наша подпись → NCANode» помечены BLOCKED; RSA судят lxml + cryptography;
- WSSE: NCANode принимает только SOAP 1.1 и только `KeyIdentifier` (BinarySecurityToken и SOAP 1.2 — HTTP 500);
- `/x509/verify` одинаково отвечает `valid=false` на хорошую и изменённую сырую подпись (строка `x509-verify-ncanode-discrimination`), сырые ГОСТ-подписи судить нечем;
- JWS/JWT: NCANode называет ГОСТ-алгоритмы `GG2015`/`GG2004`, у `oncl` — `ECGOST3410-2015-512` (идентификатор NCALayer/AcBank из `oncl-builtin-commonutils`): взаимно не проверяются (`jws-gost2015-name-mismatch`), независимой проверки нашей ГОСТ-подписи JOSE нет (BLOCKED); `/jwt/decode` сверяет `exp`/`nbf` с реальными часами NCANode;
- любой LT от NCANode содержит полный CRL НУЦ (около 20 МБ) — см. дефект D1.

## Производственные дефекты

Матрица записывает их в `[[defect]]` с точным воспроизведением; строки с `defect = "Dn"` остаются красными, пока дефект не исправлен (ожидаемая оценка там — пометка, не подгонка под вывод `oncl`). Когда строка проходит, прогон требует убрать пометку.

## Большие артефакты

Декомпозиция вместо пересылки 10 ГиБ в JSON/DOM: `oracle.py pdf-byterange` считает дайджест по ByteRange потоково (hashlib / gostcrypto Streebog) и сверяет его с CMS внутри `/Contents`, проверяет RSA-подпись и токен; для отсоединённого CMS `openssl cms -verify -content` читает данные потоком. Собственный парсер `oncl` внешним проверяющим не используется. Строки `large-*` (размер `--large-bytes`, по умолчанию 1,1 ГиБ; каталог `--scratch`, не диск C:) генерируют содержательные входы (псевдослучайный файл; XML из миллионов элементов в канонической форме; PDF из десятков тысяч страниц с собственными потоками), подписывают их `oncl` (рекомендуется release-сборка `--oncl`) и судят независимо: поток дайджеста точно подписанных байт + внешняя проверка signedAttrs / SignedInfo / подписи CMS; изменённый бит в середине должен отвергаться. 4 и 10 ГиБ не заявляются и не измерялись; RSS не измерялся (это V01).

## Запуск (WSL)

```sh
cargo xtask fetch-fixtures
cargo xtask interop-openssl
cargo xtask interop-ncanode
cargo xtask platform-interop --out target/platform-interop      # --case <префикс>, --list, --hold-world
```
`--hold-world` поднимает loopback-PKI, пишет пути в `world.env` и держит её, пока не закроется stdin: для ручного воспроизведения строки.

## Большие артефакты: scratch

Каталог `--scratch` должен быть на файловой системе с обычным POSIX-вводом-выводом. Каталог на диске Windows, смонтированном в WSL (9p), даёт на 100 МиБ XML 1820 с против 57 с на ext4 (замер этого прогона), поэтому 1,1 ГиБ XML там не укладывается в 3500 с. Рекомендуемый вариант без записи на C:: ext4-образ на другом диске (`truncate -s 12G img; mkfs.ext4 img; mount -o loop img <точка монтирования>` от root).

## Дефект D6 (PDF с большим числом страниц)

`large-pdf-signature-rsa` (8000+ страниц) падает с `MetadataLimit`, а тот же объём в 1 МиБ потоках подписывается и проверяется; граница лежит между 32 МиБ (около 2000 страниц) и 128 МиБ (около 8000 страниц).
