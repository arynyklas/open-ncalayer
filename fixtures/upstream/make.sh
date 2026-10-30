#!/usr/bin/env bash
# Regenerates the synthetic fixtures of the upstream watcher in this directory (see
# README.md), then signs manifest.json into manifest.der.
set -euo pipefail

cd "$(dirname "$0")"

cargo xtask upstream make-fixtures
