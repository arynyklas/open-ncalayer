#!/usr/bin/env bash
# Regenerates the synthetic fixtures of the upstream watcher in this directory (see
# README.md): bundles and distributions built from our sources in src/, then the SHA-256 of
# each written into manifest.json, which is signed into manifest.der.
#
# Needs a JDK 17 or newer (javac, jar with --date, keytool), gzip, sha256sum and cargo.
set -euo pipefail

cd "$(dirname "$0")"

date=2026-01-01T00:00:00Z
build=.build
rm -rf "$build"
mkdir -p "$build"
trap 'rm -rf "$build"' EXIT

zeros() { head -c "$1" /dev/zero; }

# Classes.
mapfile -t demo_sources < <(find src/demo -name '*.java' | sort)
javac --release 8 -nowarn -d "$build/demo" "${demo_sources[@]}"
javac --release 8 -nowarn -cp "$build/demo" -d "$build/demo-v2" src/demo-v2/kz/example/demo/DemoModule.java
javac --release 8 -nowarn -d "$build/launcher" src/launcher/kz/example/launcher/Main.java

# Keystores and a native library inside the demo bundle.
mkdir -p "$build/demo/keystores" "$build/demo/natives/linux-x86-64"
keytool -importcert -noprompt -storetype JKS -keystore "$build/demo/keystores/trusted.jks" \
    -storepass changeit -alias synthetic-root-rsa -file ../synthetic/root-rsa.cer
keytool -genkeypair -storetype JKS -keystore "$build/demo/keystores/local.jks" \
    -storepass Qwerty12 -keypass Qwerty12 -alias demo-key -keyalg RSA -keysize 2048 \
    -validity 3650 -dname "CN=OpenNCALayer synthetic demo, O=OpenNCALayer, C=KZ"
printf '\177ELF\002\001\001\000' > "$build/demo/natives/linux-x86-64/libdemo.so"

bundle_manifest() {
    cat <<MF
Manifest-Version: 1.0
Bundle-ManifestVersion: 2
Bundle-Name: Example demo
Bundle-SymbolicName: kz.example.demo;singleton:=true
Bundle-Version: $1
Bundle-Activator: kz.example.demo.Activator
Import-Package: kz.example.annotations,org.json;version="[1.0,2.0)",org.osgi.framework;version="[1.8,2.0)",javax.net.ssl,javax.security.auth.x500
MF
}
bundle_manifest 1.0.0 > "$build/a.mf"
bundle_manifest 1.1.0 > "$build/a2.mf"

jar --create --date="$date" --file bundle-a.jar --manifest "$build/a.mf" -C "$build/demo" .

# The same entries in reverse order with other timestamps.
reversed=()
while IFS= read -r f; do
    reversed+=(-C "$build/demo" "$f")
done < <(cd "$build/demo" && find . -type f | sed 's#^\./##' | sort -r)
jar --create --date=2026-02-02T00:00:00Z --file bundle-a-repack.jar --manifest "$build/a.mf" "${reversed[@]}"

cp -r "$build/demo" "$build/demo2"
cp "$build/demo-v2/kz/example/demo/DemoModule.class" "$build/demo2/kz/example/demo/DemoModule.class"
jar --create --date="$date" --file bundle-a-v2.jar --manifest "$build/a2.mf" -C "$build/demo2" .

# The launcher with a manifest of its own and the trusted keystore.
cargo xtask upstream make-fixtures --embedded "$build/launcher/ncalayer.der"
cp "$build/demo/keystores/trusted.jks" "$build/launcher/trusted.jks"
printf 'Manifest-Version: 1.0\nMain-Class: kz.example.launcher.Main\n' > "$build/app.mf"
jar --create --date="$date" --file app.jar --manifest "$build/app.mf" -C "$build/launcher" .

# installer.sh: a script header of 4096 bytes, then the launcher.
printf '#!/bin/sh\n# Synthetic installer header of the OpenNCALayer upstream watcher fixtures.\nexit 0\n' \
    > "$build/header"
header_size=$(wc -c < "$build/header")
zeros $((4096 - header_size)) | tr '\0' '\n' >> "$build/header"
cat "$build/header" app.jar > installer.sh

# lite.exe: a stand-in Go program carrying a gzip stream of a program carrying the launcher.
{ printf 'MZ'; zeros 512; cat app.jar; } > "$build/inner.exe"
gzip -n -c "$build/inner.exe" > "$build/inner.exe.gz"
{ printf 'MZ'; zeros 1024; printf 'go1.0-synthetic'; cat "$build/inner.exe.gz"; } > lite.exe

# dist.zip: the installer and a Java runtime.
mkdir -p "$build/dist/NCALayer/jre/bin" "$build/dist/NCALayer/jre/lib"
cp installer.sh "$build/dist/NCALayer/ncalayer.sh"
printf 'JAVA_VERSION="1.8.0_000"\nIMPLEMENTOR="Synthetic"\nOS_ARCH="amd64"\n' > "$build/dist/NCALayer/jre/release"
printf '\177ELF\002\001\001\000' > "$build/dist/NCALayer/jre/bin/java"
{ printf 'PK\005\006'; zeros 18; } > "$build/dist/NCALayer/jre/lib/rt.jar"
jar --create --no-manifest --date="$date" --file dist.zip -C "$build/dist" NCALayer

# Files only for format detection.
{ printf 'MZ'; zeros 254; printf 'Inno Setup Setup Data (6.5.2)'; zeros 256; } > inno-like.exe
{ printf '\320\317\021\340\241\261\032\341'; zeros 1528; } > msi-like.msi
{ zeros 1024; printf 'koly'; zeros 508; } > fake.dmg
printf '\001\000\004TZDB\000\001\000\0052026z' > tzdb.dat

# The hashes of the manifest, then its signature.
set_hash() {
    local sha
    sha=$(sha256sum "$2" | cut -d' ' -f1)
    sed -E -i "s#(\"url\":\"[^\"]*/$1\",\"hash\":\")[0-9a-f]*#\\1$sha#g" manifest.json
}
set_hash bundles/app.jar app.jar
set_hash bundles/bundle-a.jar bundle-a.jar
set_hash updates/installer.sh installer.sh
set_hash updates/lite.exe lite.exe
cargo xtask upstream make-fixtures
