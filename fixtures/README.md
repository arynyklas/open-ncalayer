# Тестовые фикстуры

В репозитории лежат только публичные данные и синтетические тестовые ключи. Ниже — откуда взялась каждая группа фикстур и на каких условиях она используется.

## `nca/` — сертификаты НУЦ РК (коммитятся)

Публичные сертификаты удостоверяющих центров Национального удостоверяющего центра Республики Казахстан (корневой УЦ и НУЦ, ГОСТ и RSA, поколения 2015–2022).

- **Происхождение.** Извлечены из хранилищ доверия `cacerts.jks` и `cacerts_test.jks`, которые поставляются с оригинальным NCALayer в бандле `knca_provider_util` (пароль JKS — `knca`). Те же сертификаты НУЦ публикует на [pki.gov.kz](https://pki.gov.kz) для свободной загрузки и установки.
- **Раскладка.**
  - `nca/prod/` — промышленная PKI (`cacerts.jks`).
  - `nca/test/` — тестовая PKI (`cacerts_test.jks`).
  - Имена файлов совпадают с алиасами в JKS: `ncagost18.der` — алиас `ncagost18` и т. д.
- **Целостность.** `nca/SHA256SUMS` — суммы sha256 в формате `sha256sum`. Проверка из каталога `fixtures/nca`: `sha256sum -c SHA256SUMS`.
- **Лицензионный статус.** Сертификаты УЦ — публичные документы. Они содержат только открытые ключи и предназначены для свободного распространения: без них нельзя проверить ни одну подпись НУЦ. Секретов в них нет. Права на сами сертификаты принадлежат НУЦ РК; под лицензию Apache-2.0 этого репозитория они не попадают.
- **Назначение.** Interop-векторы:
  - `crates/oncl-gost/tests/kz.rs` проверяет подпись каждого из 9 ГОСТ-сертификатов ключом его издателя:
    - ГОСТ 34.310-2004: `prod/ncagost`, `prod/ncagost18`, `prod/rcagost`, `test/ncagosttest2018`, `test/rcagosttest2018`;
    - ГОСТ 34.10-2015-512: `prod/ncagost22`, `prod/rcagost22`, `test/ncagosttest2022`, `test/rcagosttest2022`.
  - `crates/oncl-pki/tests/cert_verify.rs` проверяет через `cert::verify_signature` все 16 сертификатов, ГОСТ и RSA. Издатель ищется по DN.
- **Встроенные корни.** Все 10 сертификатов `nca/prod/` вшиваются в бинарь (`crates/oncl-pki/src/roots.rs`, `include_bytes!`) — это набор CA по умолчанию для `signerParams.chain` и `cms-verify`. Тест сверяет их с `SHA256SUMS`, поэтому файл в `nca/prod/` меняется только вместе с суммой. `nca/test/` не встраивается.

## `nca-ocsp/` — ответ тестового OCSP НУЦ (коммитится)

Один записанный ответ тестового ответчика НУЦ `http://test.pki.gov.kz/ocsp/` о тестовом сертификате NCANode `individual_valid_2015` (издатель — `nca/test/ncagosttest2022`). Это публичные данные: подписанный статус публичного тестового сертификата и сертификат ответчика. Секретов в нём нет.

- `individual_valid_2015.req.der` — запрос `openssl ocsp -issuer ncagosttest2022.pem -cert <лист> -no_nonce -reqout …` (OpenSSL 3.0.13). Тест сверяет с ним `ocsp::request_der` байт в байт.
- `individual_valid_2015.resp.der` — ответ на этот запрос по GET-биндингу НУЦ (`curl http://test.pki.gov.kz/ocsp/<urlencode(base64(запрос))>`), записан 2026-10-26: `good`, thisUpdate = producedAt = `20261026000150Z`, без nextUpdate, ответчик `CN=OCSP` выпущен `ncagosttest2022` (срок до 2029-03-09). `crates/oncl-pki/tests/ocsp.rs` проверяет его офлайн на фиксированный момент внутри окна `ALLOWED_PERIOD`; лист берётся из `target/fixtures/ncanode/`.

## `nca-crl/` — CRL корневого ГОСТ-УЦ НУЦ (коммитится)

- `gost2015_2022.crl` — CRL `НЕГІЗГІ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (GOST) 2022` (`nca/prod/rcagost22`) из точки распространения CRL сертификата `nca/prod/ncagost22`: `curl http://crl.root.gov.kz/gost2015_2022.crl`, записан 2026-10-26 (`Content-Type: application/pkix-crl`, 471 байт, sha256 `4e8038f34a1c216f352c7861b94ef99b5464bfb566a0737ef0140597ac1f8380`). CRL v2, подпись ГОСТ 34.10-2015-512, thisUpdate `2026-10-02 05:12:41 UTC`, nextUpdate `2026-11-06 05:12:41 UTC`, расширения CRL Number (63) и authorityKeyIdentifier, отозванных сертификатов нет. Публичные данные. `crates/oncl-pki/tests/crl.rs` проверяет его офлайн на фиксированные моменты: подпись ключом `rcagost22`, границы thisUpdate/nextUpdate, издателя и статус `ncagost22`.

## `ocsp/` — эталонный OCSP-запрос OpenSSL (коммитится)

- `openssl-request-inter-user-gost2015-sign.der` — `openssl ocsp -issuer inter-gost2015.pem -cert inter-user-gost2015-sign.pem -no_nonce -reqout …` (OpenSSL 3.0.13; лист извлечён `openssl pkcs12 -legacy -nokeys -clcerts` из `synthetic/inter-user-gost2015-sign.p12`). Тест сверяет с ним `ocsp::request_der` байт в байт. Синтетические данные, лицензия репозитория. Пересоздаётся той же командой после `cargo xtask gen-fixtures`, если меняется синтетический PKI.

## `upstream/` — синтетика наблюдателя за оригиналом (коммитится)

Синтетический манифест `ncalayer.der` и (с ним) дистрибутивы и бандлы, собранные из наших исходников, для тестов `cargo xtask upstream`. Состав и пересоздание — в [`upstream/README.md`](upstream/README.md). Файлов оригинального NCALayer там нет.

## `target/fixtures/ncanode/` — фикстуры NCANode (не коммитятся)

Тестовые PKCS#12-ключи и сопутствующие файлы проекта [NCANode](https://github.com/ncanode-kz/NCANode), лицензия MIT.

- Скачиваются командой `cargo xtask fetch-fixtures` с закреплённого коммита (`NCANODE_COMMIT` в `xtask/src/fetch.rs`). Каждый файл проверяется по sha256.
- Кладутся только в `target/`, в репозиторий не попадают.
- Это тестовые ключи тестовой PKI НУЦ: подписи ими юридической силы не имеют.

## Синтетические ключи (генерируются)

Ключи и контейнеры, которые генерируют `cargo xtask gen-fixtures` и `fixtures/openssl/make.sh`. Это синтетические данные проекта, они распространяются под лицензией репозитория (Apache-2.0). Настоящих пользовательских ключей в репозитории нет и не будет.

- `openssl/` — RSA-ключ и три контейнера PKCS#12 от OpenSSL: кириллический пароль, пустой пароль, PBES2 с явным PRF. Состав и пересоздание описаны в [`openssl/README.md`](openssl/README.md).
- `synthetic/` — синтетический PKI по образцу НУЦ, генерирует `cargo xtask gen-fixtures` (код — `xtask/src/fixtures/`). Вся случайность берётся из одного `ChaCha20Rng` с фиксированным зерном, поэтому файлы воспроизводятся байт в байт. `cargo xtask gen-fixtures --check` (и тест `xtask/tests/fixtures_fresh.rs`) пересобирает их в памяти и сравнивает с закоммиченными. Файлы не редактируются вручную: правится генератор, затем `cargo xtask gen-fixtures`.
  - Корни (самоподписанные `.cer`): `root-gost2015` (ГОСТ 34.10-2015-512), `root-gost2004` (ГОСТ 34.310-2004), `root-rsa` (RSA-2048, sha256WithRSA).
  - Контейнеры PKCS#12 (пароль `Qwerty12`, alias = hex(SKI) сертификата, как у Kalkan), у каждого свои ключи:

    | Файл | Корень | Содержимое |
    |---|---|---|
    | `user-gost2015-sign.p12` | `root-gost2015` | физлицо, подпись: EKU emailProtection + `1.2.398.3.3.4.1.1`, KU digitalSignature + nonRepudiation |
    | `user-gost2015-auth.p12` | `root-gost2015` | физлицо, аутентификация: EKU clientAuth + `1.2.398.3.3.4.1.1`, KU digitalSignature + keyAgreement |
    | `legacy-gost2015-auth.p12` | `root-gost2015` | как `user-gost2015-auth`, но EKU только `1.2.398.3.3.4.1.1` |
    | `user-gost2004-sign.p12` | `root-gost2004` | профиль `user-gost2015-sign` на ГОСТ 34.310-2004 |
    | `user-rsa-sign.p12` | `root-rsa` | профиль `user-gost2015-sign` на RSA-2048 |
    | `legal-gost2015-sign.p12` | `root-gost2015` | руководитель юрлица (`O`, `OU=BIN…`), EKU `1.2.398.3.3.4.1.2.1`; серийник со старшим битом (DER INTEGER начинается с `00`) |
    | `expired-gost2015-sign.p12` | `root-gost2015` | профиль `user-gost2015-sign`, срок 2020-01-01…2021-01-01 |
    | `multi-gost2015.p12` | `root-gost2015` | два entry: профили `user-gost2015-sign` и `user-gost2015-auth` |
    | `tsa-gost2015.p12` | `root-gost2015` | служба меток времени: EKU timeStamping (critical), KU digitalSignature |
    | `pbes2-noprf-gost2015.p12` | `root-gost2015` | профиль `user-gost2015-sign`; ключ и сертификаты под PBES2 без PRF (Kalkan читает как HMAC-SHA256) и AES-256-CBC |

    Остальные контейнеры — в профиле Kalkan: ключи 3DES, сертификаты RC2-40, 1024 итерации. Срок действия, кроме `expired-…`, — 2025-01-01…2099-12-31.
  - PKI для проверки сертификатов (PKIX, OCSP, CRL). Генерируется после всех объектов выше, поэтому они от неё не меняются. Адреса в домене `.test` не разрешаются: тесты подменяют транспорт.
    - Промежуточные CA (`.cer`, ГОСТ 34.10-2015-512), выпущены `root-gost2015`:
      - `inter-gost2015.cer` — subject `CN=SYNTHETIC NCA (GOST) 2015, C=KZ` (в DER порядок CN, C, как у НУЦ); `basicConstraints` cA, pathLen 0 (critical); KU keyCertSign + cRLSign (critical); CDP `http://crl.synthetic.test/root-gost2015.crl`.
      - `inter-gost2015-twin.cer` — тот же subject и те же расширения, другой ключ и серийник: для построения цепочки при одноимённых CA.
    - Контейнеры PKCS#12 (пароль `Qwerty12`, профиль Kalkan):

      | Файл | Издатель | Содержимое |
      |---|---|---|
      | `inter-user-gost2015-sign.p12` | `inter-gost2015` | профиль `user-gost2015-sign`; AIA OCSP `http://ocsp.synthetic.test`, CDP `http://crl.synthetic.test/inter-gost2015.crl` |
      | `inter-revoked-gost2015-sign.p12` | `inter-gost2015` | как `inter-user-gost2015-sign`, свой ключ и серийник; тесты объявляют его отозванным в ответах OCSP и в CRL |
      | `inter-expired-gost2015-sign.p12` | `inter-gost2015` | как `inter-user-gost2015-sign`, срок 2025-01-01…2026-01-01: уже истёк, но лежит внутри срока CA, поэтому цепочка строится на момент `notAfter` |
      | `ocsp-gost2015.p12` | `inter-gost2015` | ответчик OCSP: KU digitalSignature (critical), EKU OCSPSigning, `id-pkix-ocsp-nocheck` (значение — DER NULL `05 00`) |
      | `ocsp-nocheckless-gost2015.p12` | `inter-gost2015` | как `ocsp-gost2015`, но без `id-pkix-ocsp-nocheck` |
      | `inter-gost2015.key.p12` | `root-gost2015` | ключ и сертификат `inter-gost2015.cer`: им тесты подписывают CRL промежуточного CA |
      | `root-gost2015.key.p12` | `root-gost2015` | ключ и сертификат `root-gost2015.cer` (самоподписанный): им тесты подписывают CRL корня |
      | `inter-noaki-gost2015-sign.p12` | `inter-gost2015` | как `inter-user-gost2015-sign`, но без `authorityKeyIdentifier`: от одноимённого `inter-gost2015-twin` издателя отличает только подпись. Генерируется последним |
  - `fixtures.toml` — описание контейнеров (пароль, корень, издатель — `.cer` выпустившего CA, alias в порядке загрузки) для `oncl_testkit::synthetic` и `synthetic_all`. Сертификаты `.cer` читает `oncl_testkit::synthetic_cert`.
