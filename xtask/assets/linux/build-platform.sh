#!/bin/bash
# The Linux build of `cargo xtask package platform-build --flavor linux-x64`, in the glibc
# 2.28 container (xtask::package::linux::IMAGE) with the workspace at /src: the pinned
# rustup and the toolchain of rust-toolchain.toml build `oncl` and `oncl-server` (and xtask)
# against glibc 2.28. Out: target/platform/linux-x64/{oncl,oncl-server}.
# ONCL_VERSION is the release's version; ONCL_BUILD_CACHE, if set, keeps the toolchain and
# cargo's files (a Docker volume); HOST_UID/HOST_GID give the results back to the user who
# ran Docker. With ONCL_PLATFORM_DIST (a directory in /src) the container also runs
# `xtask package platform` on them: the gates, the archives and the smoke of the unpacked
# archives, here, as a clean glibc 2.28 system without a GUI.
set -euo pipefail

: "${ONCL_VERSION:?the version of the release}"
cache="${ONCL_BUILD_CACHE:-/src/target/glibc228}"
out=/src/target/platform/linux-x64

export CARGO_HOME="$cache/cargo" RUSTUP_HOME="$cache/rustup"
if [ ! -x "$CARGO_HOME/bin/rustup" ]; then
    curl --proto '=https' --tlsv1.2 -sSfL -o /tmp/rustup-init \
        https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init
    echo "20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c  /tmp/rustup-init" |
        sha256sum -c -
    chmod +x /tmp/rustup-init
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none
fi
export PATH="$CARGO_HOME/bin:$PATH"
# The checkout belongs to another user: git (the build's commit id) must still read it.
(cd / && git config --global --add safe.directory /src)

cd /src
# The licence texts of a package come from the cargo registry's unpacked sources.
cargo fetch --locked
cargo build --locked --release --target-dir "$cache/target" \
    -p oncl-cli -p oncl-server -p xtask
mkdir -p "$out"
install -m 755 "$cache/target/release/oncl" "$cache/target/release/oncl-server" "$out/"

if [ -n "${ONCL_PLATFORM_DIST:-}" ]; then
    "$cache/target/release/xtask" package platform --flavor linux-x64 --bin "$out" \
        --version "$ONCL_VERSION" --dist "$ONCL_PLATFORM_DIST"
fi

if [ -n "${HOST_UID:-}" ]; then
    chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" /src/target/platform
    if [ -n "${ONCL_PLATFORM_DIST:-}" ]; then
        chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$ONCL_PLATFORM_DIST"
    fi
    if [ -z "${ONCL_BUILD_CACHE:-}" ]; then
        chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$cache"
    fi
fi
