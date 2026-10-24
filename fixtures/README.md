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
  - `fixtures.toml` — описание контейнеров (пароль, корень, alias в порядке загрузки) для `oncl_testkit::synthetic` и `synthetic_all`.
