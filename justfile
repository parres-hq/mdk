#!/usr/bin/env just --justfile

default:
    @just --list

# Run tests with all features (default)
test:
    cargo test --all-features --all-targets
    cargo test --all-features --doc

# Run tests without optional features
test-no-features:
    cargo test --all-targets --no-default-features

# Run tests with only mip04 feature
test-mip04:
    cargo test --all-targets --no-default-features --features mip04

# Run all test combinations (like CI)
test-all:
    @echo "Testing with all features..."
    @just test
    @echo "Testing without optional features..."
    @just test-no-features
    @echo "Testing with mip04 feature only..."
    @just test-mip04

# Check clippy for all feature combinations (uses stable by default)
lint:
    @bash scripts/check-clippy.sh

# Check clippy without features (for individual testing)
lint-no-features:
    cargo clippy --all-targets --no-default-features --no-deps -- -D warnings

# Check clippy with mip04 feature only (for individual testing)
lint-mip04:
    cargo clippy --all-targets --no-default-features --features mip04 --no-deps -- -D warnings

# Check fmt (uses stable by default)
fmt:
    @bash scripts/check-fmt.sh

# Check docs (uses stable by default)
docs:
    @bash scripts/check-docs.sh

# Quick check with stable (fast for local development)
check:
    @bash scripts/check-all.sh
    @just test-all

# Pre-commit check: runs both stable and MSRV checks
precommit:
    @echo "=========================================="
    @echo "Running pre-commit checks (stable + MSRV)"
    @echo "=========================================="
    @echo ""
    @echo "→ Checking with stable Rust..."
    @bash scripts/check-all.sh stable
    @echo ""
    @echo "→ Checking with MSRV (1.90.0)..."
    @bash scripts/check-msrv.sh
    @echo ""
    @echo "→ Running tests..."
    @just test-all
    @echo ""
    @echo "=========================================="
    @echo "✓ All pre-commit checks passed!"
    @echo "=========================================="

# Full comprehensive check including all feature combinations (same as check for now)
check-full:
    @just check

_build-uniffi:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building mdk-uniffi library..."
    cargo build --lib -p mdk-uniffi
    just _build-uniffi-android aarch64-linux-android aarch64-linux-android21-clang
    just _build-uniffi-android armv7-linux-androideabi armv7a-linux-androideabi21-clang
    if [ "{{os()}}" = "macos" ]; then
        just _build-uniffi-ios aarch64-apple-ios
        just _build-uniffi-ios aarch64-apple-ios-sim
    fi

_build-uniffi-ios TARGET:
    cargo build --lib -p mdk-uniffi --target {{TARGET}} --release

_build-uniffi-android TARGET CLANG_PREFIX:
    #!/usr/bin/env bash
    set -euo pipefail
    NDK_HOST=$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
    NDK_PREBUILT="${NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/${NDK_HOST}"

    TARGET_UPPER=$(echo "{{TARGET}}" | tr '[:lower:]-' '[:upper:]_')
    TARGET_UNDER=$(echo "{{TARGET}}" | tr '-' '_')

    export CC_${TARGET_UNDER}="${NDK_PREBUILT}/bin/{{CLANG_PREFIX}}"
    export AR_${TARGET_UNDER}=llvm-ar
    export CARGO_TARGET_${TARGET_UPPER}_LINKER="${NDK_PREBUILT}/bin/{{CLANG_PREFIX}}"

    cargo build --lib -p mdk-uniffi --target {{TARGET}} --release

uniffi-bindgen: _build-uniffi (gen-binding "python") (gen-binding-kotlin) (gen-binding "ruby")
    @if [ "{{os()}}" = "macos" ]; then just gen-binding-swift; fi


lib_filename := if os() == "windows" {
    "mdk_uniffi.dll"
} else if os() == "macos" {
    "libmdk_uniffi.dylib"
} else {
    "libmdk_uniffi.so"
}

gen-binding lang:
    @echo "Generating {{lang}} bindings..."
    cd crates/mdk-uniffi && cargo run --bin uniffi-bindgen generate \
        -l {{lang}} \
        --library ../../target/debug/{{lib_filename}} \
        --out-dir bindings/{{lang}}
    cp target/debug/{{lib_filename}} crates/mdk-uniffi/bindings/{{lang}}/{{lib_filename}}
    @echo "✓ Bindings generated in crates/mdk-uniffi/bindings/{{lang}}/"

gen-binding-kotlin: (gen-binding "kotlin")
    cp target/aarch64-linux-android/release/libmdk_uniffi.so crates/mdk-uniffi/bindings/kotlin/libmdk_uniffi.arm64-v8a.so
    cp target/armv7-linux-androideabi/release/libmdk_uniffi.so crates/mdk-uniffi/bindings/kotlin/libmdk_uniffi.armeabi-v7a.so
    @echo "✓ Android libs copied"

gen-binding-swift: (gen-binding "swift")
    @echo "Creating iOS artifacts..."
    mkdir -p ios-artifacts/headers
    cp crates/mdk-uniffi/bindings/swift/mdk_uniffiFFI.h ios-artifacts/headers/
    xcodebuild -create-xcframework \
        -library target/aarch64-apple-ios/release/libmdk_uniffi.a -headers ios-artifacts/headers \
        -library target/aarch64-apple-ios-sim/release/libmdk_uniffi.a -headers ios-artifacts/headers \
        -output ios-artifacts/mdk_uniffi.xcframework
    
    @echo "Assembling Swift package..."
    rm -rf swift/MDKPackage
    mkdir -p swift/MDKPackage/Sources/{MDKBindings,mdk_uniffiFFI/include} swift/MDKPackage/Binary
    cp crates/mdk-uniffi/bindings/swift/mdk_uniffi.swift swift/MDKPackage/Sources/MDKBindings/
    cp crates/mdk-uniffi/bindings/swift/mdk_uniffiFFI.{h,modulemap} swift/MDKPackage/Sources/mdk_uniffiFFI/include/
    echo '#include "mdk_uniffiFFI.h"' > swift/MDKPackage/Sources/mdk_uniffiFFI/mdk_uniffiFFI.c
    cp -R ios-artifacts/mdk_uniffi.xcframework swift/MDKPackage/Binary/
    cp crates/mdk-uniffi/src/swift/Package.swift swift/MDKPackage/Package.swift
    @echo "✓ Swift package ready at swift/MDKPackage"

test-swift-bindings:
    @bash scripts/run-swift-binding-test.sh
