#!/usr/bin/env bash
# Regenerates the synthetic JKS fixtures in this directory (see README.md).
#
# Needs `keytool` from a JDK or JRE (e.g. `openjdk-17-jre-headless`) and a UTF-8 locale, so
# that the Cyrillic password reaches keytool as the intended characters.
set -euo pipefail

cd "$(dirname "$0")"

# RSA-2048 signing key (digitalSignature + nonRepudiation: Kalkan's SIGNATURE type) with a
# self-signed SHA-256 certificate; keytool adds a SubjectKeyIdentifier. Store and key share
# the password, as NCALayer opens them. The synthetic RSA root goes in as a trusted entry.
genkey() {
    local store="$1" password="$2"
    keytool -genkeypair -storetype JKS -keystore "$store" -storepass "$password" \
        -keypass "$password" -alias openncalayer-rsa -keyalg RSA -keysize 2048 \
        -sigalg SHA256withRSA -validity 3650 \
        -dname "CN=OpenNCALayer synthetic JKS RSA, O=OpenNCALayer, C=KZ" \
        -ext KeyUsage:critical=digitalSignature,nonRepudiation
    keytool -importcert -noprompt -storetype JKS -keystore "$store" -storepass "$password" \
        -alias synthetic-root-rsa -file ../synthetic/root-rsa.cer
}

genkey rsa.jks Qwerty12
genkey rsa-cyrillic.jks 'Пароль123'
keytool -list -storetype JKS -keystore rsa.jks -storepass Qwerty12
