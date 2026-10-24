#!/usr/bin/env bash
# Regenerates the synthetic OpenSSL fixtures in this directory (see README.md).
#
# Needs OpenSSL 3.x with the legacy provider (RC2-40 for `-legacy`). On Windows run it from
# Git Bash, whose /mingw64/bin/openssl ships the provider.
set -euo pipefail

cd "$(dirname "$0")"
# Git Bash must not rewrite `-subj /C=…` into a Windows path; the scratch directory is
# relative for the same reason (a native openssl.exe cannot open /tmp/…).
export MSYS_NO_PATHCONV=1
tmp="$(mktemp -d ./.tmp.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

openssl version
openssl list -providers -provider legacy -provider default | grep -q 'OpenSSL Legacy Provider'

# RSA-2048 key and a self-signed certificate; `req -x509` adds a SubjectKeyIdentifier.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/key.pem"
openssl req -new -x509 -key "$tmp/key.pem" -sha256 -days 3650 \
    -subj "/C=KZ/O=OpenNCALayer/CN=OpenNCALayer synthetic RSA" -out "$tmp/cert.pem"

# Unencrypted copies for the PKCS#12 writer round-trip test.
openssl pkcs8 -topk8 -nocrypt -in "$tmp/key.pem" -outform DER -out rsa.pk8.der
openssl x509 -in "$tmp/cert.pem" -outform DER -out rsa.cer

# Passwords go through files so that the Cyrillic one reaches OpenSSL as UTF-8 regardless of
# how the platform passes command-line arguments.
printf '%s\n' 'Пароль123' >"$tmp/cyrillic.pw"
printf '%s\n' 'Qwerty12' >"$tmp/modern.pw"

export_p12() {
    local out="$1"
    shift
    openssl pkcs12 -export -inkey "$tmp/key.pem" -in "$tmp/cert.pem" -name "openssl-rsa" \
        "$@" -out "$out"
}

# Legacy profile: 3DES key, RC2-40 certificates, HMAC-SHA1 MAC.
export_p12 rsa-cyrillic.p12 -legacy -passout "file:$tmp/cyrillic.pw"
export_p12 rsa-empty.p12 -legacy -passout pass:
# Modern profile: PBES2 + PBKDF2 with an explicit hmacWithSHA256 PRF + AES-256-CBC, MAC SHA-256.
export_p12 rsa-modern.p12 -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 \
    -passout "file:$tmp/modern.pw"

openssl pkcs12 -in rsa-cyrillic.p12 -info -noout -legacy -passin "file:$tmp/cyrillic.pw"
openssl pkcs12 -in rsa-empty.p12 -info -noout -legacy -passin pass:
openssl pkcs12 -in rsa-modern.p12 -info -noout -passin "file:$tmp/modern.pw"
