#!/bin/bash
# The Linux build of `cargo xtask package linux-build`, in the glibc 2.28 container
# (xtask::package::linux::IMAGE) with the workspace at /src: the pinned rustup and the
# toolchain of rust-toolchain.toml build the daemon, the relay and xtask against glibc 2.28,
# then `xtask package appdir` lays out and checks the AppDir. Out: target/linux-x64/
# (openncalayer, nmhost, OpenNCALayer.AppDir). ONCL_VERSION is the release's version;
# ONCL_BUILD_CACHE, if set, keeps the toolchain and cargo's files (a Docker volume);
# HOST_UID/HOST_GID give the results back to the user who ran Docker.
set -euo pipefail

: "${ONCL_VERSION:?the version of the release}"
cache="${ONCL_BUILD_CACHE:-/src/target/glibc228}"
out=/src/target/linux-x64
# The development files the build needs (fontconfig is linked, wayland-sys asks pkg-config),
# at the versions of AlmaLinux 8.10; libxkbcommon and libxkbcommon-x11 are bundled into the
# AppImage.
dnf install -y --setopt=install_weak_deps=False \
    fontconfig-devel-2.13.1-4.el8 \
    libxkbcommon-devel-0.9.1-1.el8 \
    libxkbcommon-x11-0.9.1-1.el8 \
    wayland-devel-1.21.0-1.el8

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
# The checkout belongs to another user: git (the build's commit id) must still read it. Set
# from outside it: a linked worktree's .git points to a path of the host.
(cd / && git config --global --add safe.directory /src)

cd /src
cargo build --locked --release --target-dir "$cache/target" \
    -p openncalayer -p oncl-nmhost -p xtask
mkdir -p "$out"
install -m 755 "$cache/target/release/openncalayer" "$cache/target/release/nmhost" "$out/"
"$cache/target/release/xtask" package appdir --bin "$out" --version "$ONCL_VERSION" \
    --out "$out/OpenNCALayer.AppDir"

if [ -n "${HOST_UID:-}" ]; then
    chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$out"
    if [ -z "${ONCL_BUILD_CACHE:-}" ]; then
        chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$cache"
    fi
fi
