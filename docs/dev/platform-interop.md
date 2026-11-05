# Независимая interop-матрица платформы

`cargo xtask platform-interop --out target/platform-interop` прогоняет **собранный `oncl`** (процесс, не SDK в памяти) против независимых проверяющих и пишет `report.json` / `report.md` (версии инструментов, digest образа и фикстур, строка на каждый случай, дефекты, ожидающие семейства). Запуск только в Linux: NCANode работает из закреплённого образа в Docker. В Windows матрица не выполняется, нулевой код «только Linux» запуском не считается.

Состав матрицы — `fixtures/platform/coverage.toml`: capability → случаи → дескрипторы проверяющих (инструмент, версия, закрепление) → ожидаемая оценка. Тест `xtask/tests/platform_interop.rs` падает, если маршрут закреплённого OpenAPI NCANode (commit `0adab29a…`, sha256 `openapi.yml` в `pins`) не относится ни к одной capability, у capability нет случая, у случая нет строки, у строки нет случая или проверяющий не описан. Пока в `[[pending]]` есть семейства без случаев, тест `no_capability_is_left_without_cases` красный, а прогон завершается `INCOMPLETE`.

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
- NCANode не делает CAdES-LTA на просроченных ключах (HTTP 500), `/cms/extend` до LTA и `/pdf/extend` отвечают ошибкой;
- любой LT от NCANode содержит полный CRL НУЦ (около 20 МБ) — см. дефект D1.

## Производственные дефекты

Матрица записывает их в `[[defect]]` с точным воспроизведением; строки с `defect = "Dn"` остаются красными, пока дефект не исправлен (ожидаемая оценка там — пометка, не подгонка под вывод `oncl`). Когда строка проходит, прогон требует убрать пометку.

## Большие артефакты

Декомпозиция вместо пересылки 10 ГиБ в JSON/DOM: `oracle.py pdf-byterange` считает дайджест по ByteRange потоково (hashlib / gostcrypto Streebog) и сверяет его с CMS внутри `/Contents`, проверяет RSA-подпись и токен; для отсоединённого CMS `openssl cms -verify -content` читает данные потоком. Собственный парсер `oncl` внешним проверяющим не используется. Многогигабайтные прогоны ещё не выполнены (`[[pending]] large`).

## Запуск (WSL)

```sh
cargo xtask fetch-fixtures
cargo xtask interop-openssl
cargo xtask interop-ncanode
cargo xtask platform-interop --out target/platform-interop      # --case <префикс>, --list, --hold-world
```
`--hold-world` поднимает loopback-PKI, пишет пути в `world.env` и держит её, пока не закроется stdin: для ручного воспроизведения строки.
