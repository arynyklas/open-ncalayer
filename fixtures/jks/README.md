# Фикстуры JKS

Синтетические хранилища Java KeyStore (формат Sun JKS, версия 2), созданные `keytool`. По ним `crates/oncl-pki/tests/jks.rs` проверяет чтение JKS, а тесты `basics` и `commonUtils` — подпись ключом из JKS. Ключи сгенерированы для тестов и нигде больше не используются. Как и другие синтетические фикстуры, файлы распространяются под лицензией репозитория (Apache-2.0).

| Файл | Содержимое | Пароль |
|---|---|---|
| `rsa.jks` | ключ RSA-2048 (`openncalayer-rsa`) с самоподписанным сертификатом SHA-256 (keyUsage digitalSignature, nonRepudiation; SubjectKeyIdentifier) и доверенный сертификат `synthetic-root-rsa` (`../synthetic/root-rsa.cer`) | `Qwerty12` |
| `rsa-cyrillic.jks` | то же с другим ключом | `Пароль123` |

Пароль хранилища и пароль ключа совпадают: NCALayer открывает JKS одним паролем.

Ключи GOST `keytool` в JKS не пишет. Тесты GOST собирают JKS сами по формату из декомпиляции Kalkan (`JavaKeyStore`, `KeyProtector`).

## Пересоздание

Нужен `keytool` из JDK или JRE (например, пакет `openjdk-17-jre-headless`) и локаль UTF-8, чтобы кириллический пароль дошёл до `keytool` как задуман. Скрипт перезаписывает оба файла новыми случайными ключами:

```sh
LANG=C.UTF-8 bash fixtures/jks/make.sh
```
