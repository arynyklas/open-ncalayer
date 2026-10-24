# Фикстуры OpenSSL

Синтетический RSA-ключ и контейнеры PKCS#12, созданные OpenSSL. По ним `crates/oncl-pki/tests/pkcs12.rs` проверяет, что контейнеры OpenSSL открываются по правилам Kalkan. Ключ сгенерирован для тестов и нигде больше не используется. Как и другие синтетические фикстуры, файлы распространяются под лицензией репозитория (Apache-2.0).

| Файл | Содержимое | Пароль |
|---|---|---|
| `rsa.pk8.der` | RSA-2048, PKCS#8 DER без шифрования | — |
| `rsa.cer` | самоподписанный сертификат этого ключа (DER, SHA-256, с SubjectKeyIdentifier) | — |
| `rsa-cyrillic.p12` | `openssl pkcs12 -export -legacy`: ключ 3DES, сертификаты RC2-40, MAC HMAC-SHA1 | `Пароль123` |
| `rsa-empty.p12` | то же, пустой пароль: OpenSSL кодирует его как `00 00`, поэтому нужен «двойной ноль» | пустой |
| `rsa-modern.p12` | `openssl pkcs12 -export` без `-legacy`: PBES2 (PBKDF2 с явным PRF `hmacWithSHA256`, AES-256-CBC), MAC SHA-256 | `Qwerty12` |

У всех контейнеров `friendlyName` = `openssl-rsa`.

`rsa.pk8.der` и `rsa.cer` — вход для теста записи `write_read_roundtrip_all_pbes`.

## Пересоздание

Нужен OpenSSL 3.x с провайдером `legacy`: без него не работает RC2-40 для `-legacy`. Скрипт перезаписывает все файлы новым случайным ключом:

```sh
bash fixtures/openssl/make.sh
```

На Windows скрипт запускается из Git Bash: в `/mingw64/bin/openssl` провайдер `legacy` есть. Скрипт отключает преобразование путей MSYS (`MSYS_NO_PATHCONV=1`) и передаёт пароли через файлы, чтобы кириллица дошла до OpenSSL в UTF-8.
