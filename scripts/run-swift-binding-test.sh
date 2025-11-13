#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN="${TOOLCHAIN:-1.91.0}"
BINDINGS_DIR="$ROOT_DIR/crates/mdk-uniffi/bindings/swift"
LIB_DIR="$ROOT_DIR/target/debug"
OUT_BIN="$ROOT_DIR/target/mdk-swift-binding-test"

echo "→ Building host MDK library with toolchain ${TOOLCHAIN}..."
cargo +"$TOOLCHAIN" build -p mdk-uniffi >/dev/null

export DYLD_LIBRARY_PATH="$LIB_DIR:${DYLD_LIBRARY_PATH:-}"

echo "→ Compiling Swift smoke test…"
mkdir -p "$ROOT_DIR/target"
xcrun swiftc \
    -I "$BINDINGS_DIR" \
    -Xcc "-fmodule-map-file=$BINDINGS_DIR/mdk_uniffiFFI.modulemap" \
    -L "$LIB_DIR" \
    -lmdk_uniffi \
    "$ROOT_DIR/crates/mdk-uniffi/bindings/swift/mdk_uniffi.swift" \
    "$ROOT_DIR/scripts/swift-binding-test.swift" \
    -o "$OUT_BIN"

echo "→ Running Swift smoke test…"
"$OUT_BIN"
