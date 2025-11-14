#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN="${TOOLCHAIN:-1.91.0}"
BINDINGS_DIR="$ROOT_DIR/crates/mdk-uniffi/bindings/swift"
IOS_DIR="$ROOT_DIR/ios-artifacts"
SWIFT_PKG="$ROOT_DIR/swift/MDKPackage"
LIB_PATH="$ROOT_DIR/target/debug/libmdk_uniffi.dylib"

run() {
    echo "→ $*"
    "$@"
}

# Ensure toolchain/targets
run rustup toolchain install "$TOOLCHAIN"
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    run rustup target add --toolchain "$TOOLCHAIN" "$target"
    run cargo +"$TOOLCHAIN" build -p mdk-uniffi --release --target "$target"
done

# Build host library for binding generation
run cargo +"$TOOLCHAIN" build -p mdk-uniffi

# Generate Swift bindings
rm -rf "$BINDINGS_DIR"
mkdir -p "$BINDINGS_DIR"
run cargo +"$TOOLCHAIN" run --bin uniffi-bindgen --manifest-path "$ROOT_DIR/crates/mdk-uniffi/Cargo.toml" generate \
    -l swift \
    --library "$LIB_PATH" \
    --out-dir "$BINDINGS_DIR"
cp "$LIB_PATH" "$BINDINGS_DIR/libmdk_uniffi.dylib"

# Prep iOS artifacts (headers + xcframework)
rm -rf "$IOS_DIR"
mkdir -p "$IOS_DIR/headers"
cp "$BINDINGS_DIR/mdk_uniffiFFI.h" "$IOS_DIR/headers/"
run xcodebuild -create-xcframework \
    -library "$ROOT_DIR/target/aarch64-apple-ios/release/libmdk_uniffi.a" -headers "$IOS_DIR/headers" \
    -library "$ROOT_DIR/target/aarch64-apple-ios-sim/release/libmdk_uniffi.a" -headers "$IOS_DIR/headers" \
    -output "$IOS_DIR/mdk_uniffi.xcframework"

# Assemble Swift package
rm -rf "$SWIFT_PKG"
mkdir -p "$SWIFT_PKG/Sources/MDKBindings" "$SWIFT_PKG/Sources/mdk_uniffiFFI/include" "$SWIFT_PKG/Binary"
cp "$BINDINGS_DIR/mdk_uniffi.swift" "$SWIFT_PKG/Sources/MDKBindings/"
cp "$BINDINGS_DIR/mdk_uniffiFFI.h" "$SWIFT_PKG/Sources/mdk_uniffiFFI/include/"
cp "$BINDINGS_DIR/mdk_uniffiFFI.modulemap" "$SWIFT_PKG/Sources/mdk_uniffiFFI/include/module.modulemap"
cat <<'STUB' > "$SWIFT_PKG/Sources/mdk_uniffiFFI/mdk_uniffiFFI.c"
#include "mdk_uniffiFFI.h"
STUB
cp -R "$IOS_DIR/mdk_uniffi.xcframework" "$SWIFT_PKG/Binary/"

cat <<'PKG' > "$SWIFT_PKG/Package.swift"
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MDKPackage",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(name: "MDKBindings", targets: ["MDKBindings"])
    ],
    targets: [
        .binaryTarget(
            name: "mdk_uniffiLib",
            path: "Binary/mdk_uniffi.xcframework"
        ),
        .target(
            name: "mdk_uniffiFFI",
            dependencies: ["mdk_uniffiLib"],
            path: "Sources/mdk_uniffiFFI",
            publicHeadersPath: "include"
        ),
        .target(
            name: "MDKBindings",
            dependencies: ["mdk_uniffiFFI"],
            path: "Sources/MDKBindings",
            linkerSettings: [
                .linkedLibrary("sqlite3"),
                .linkedLibrary("c++")
            ]
        )
    ]
)
PKG

printf "\n✓ Swift package ready at %s\n" "$SWIFT_PKG"
