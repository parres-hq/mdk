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

_build-uniffi needs_android="false":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building mdk-uniffi library..."
    cargo build --release --lib -p mdk-uniffi
    if [ "{{needs_android}}" = "true" ]; then
        just _build-uniffi-android aarch64-linux-android aarch64-linux-android21-clang
        just _build-uniffi-android armv7-linux-androideabi armv7a-linux-androideabi21-clang
        just _build-uniffi-android x86_64-linux-android x86_64-linux-android21-clang
    fi
    if [ "{{os()}}" = "macos" ]; then
        just _build-uniffi-ios aarch64-apple-ios
        just _build-uniffi-ios aarch64-apple-ios-sim
    fi

_build-uniffi-ios TARGET:
    cargo build --release --lib -p mdk-uniffi --target {{TARGET}}

_build-uniffi-android TARGET CLANG_PREFIX:
    #!/usr/bin/env bash
    set -euo pipefail
    NDK_HOST=$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
    NDK_PREBUILT="${NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/${NDK_HOST}"
    LLVM_BIN="${NDK_PREBUILT}/bin"

    TARGET_UPPER=$(echo "{{TARGET}}" | tr '[:lower:]-' '[:upper:]_')
    TARGET_UNDER=$(echo "{{TARGET}}" | tr '-' '_')

    export CC_${TARGET_UNDER}="${LLVM_BIN}/{{CLANG_PREFIX}}"
    export AR_${TARGET_UNDER}="${LLVM_BIN}/llvm-ar"
    export CARGO_TARGET_${TARGET_UPPER}_LINKER="${LLVM_BIN}/{{CLANG_PREFIX}}"

    cargo build --lib -p mdk-uniffi --target {{TARGET}}

uniffi-bindgen: (gen-binding "python") gen-binding-kotlin gen-binding-ruby
    @if [ "{{os()}}" = "macos" ]; then just gen-binding-swift; fi


lib_filename := if os() == "windows" {
    "mdk_uniffi.dll"
} else if os() == "macos" {
    "libmdk_uniffi.dylib"
} else {
    "libmdk_uniffi.so"
}

gen-binding lang: _build-uniffi
    @echo "Generating {{lang}} bindings..."
    cd crates/mdk-uniffi && cargo run --bin uniffi-bindgen generate \
        -l {{lang}} \
        --library ../../target/release/{{lib_filename}} \
        --out-dir bindings/{{lang}}
    cp target/release/{{lib_filename}} crates/mdk-uniffi/bindings/{{lang}}/{{lib_filename}}
    @echo "✓ Bindings generated in crates/mdk-uniffi/bindings/{{lang}}/"

gen-binding-kotlin: (_build-uniffi "true") (gen-binding "kotlin")
    #!/usr/bin/env bash
    set -euo pipefail
    BINDINGS_DIR="crates/mdk-uniffi/bindings/kotlin"
    PROJECT_DIR="crates/mdk-uniffi/src/kotlin"
    
    mkdir -p "$PROJECT_DIR/src/main/jniLibs/arm64-v8a"
    mkdir -p "$PROJECT_DIR/src/main/jniLibs/armeabi-v7a"
    # mkdir -p "$PROJECT_DIR/src/main/jniLibs/x86-64"
    
    cp target/aarch64-linux-android/debug/libmdk_uniffi.so "$PROJECT_DIR/src/main/jniLibs/arm64-v8a/libmdk_uniffi.so"
    cp target/armv7-linux-androideabi/debug/libmdk_uniffi.so "$PROJECT_DIR/src/main/jniLibs/armeabi-v7a/libmdk_uniffi.so"
    # cp target/x86_64-linux-android/debug/libmdk_uniffi.so "$PROJECT_DIR/src/main/jniLibs/x86-64/libmdk_uniffi.so"
    rm -f "$BINDINGS_DIR/libmdk_uniffi.so"
    echo "✓ Kotlin bindings generated and moved to Android project"

build-android-lib: gen-binding-kotlin
    @echo "Building Android AAR..."
    cd crates/mdk-uniffi/src/kotlin && ./gradlew build
    @echo "✓ Android library built"

gen-binding-swift: (gen-binding "swift")
    @echo "Creating iOS xcframework..."
    mkdir -p ios-artifacts/headers
    cp crates/mdk-uniffi/bindings/swift/mdk_uniffiFFI.h ios-artifacts/headers/
    xcodebuild -create-xcframework \
        -library target/aarch64-apple-ios/release/libmdk_uniffi.a -headers ios-artifacts/headers \
        -library target/aarch64-apple-ios-sim/release/libmdk_uniffi.a -headers ios-artifacts/headers \
        -output ios-artifacts/mdk_uniffi.xcframework
    @echo "✓ Swift bindings and xcframework ready"

gen-binding-ruby: (gen-binding "ruby")
    #!/usr/bin/env bash
    set -euo pipefail
    RUBY_BINDING="$(pwd)/crates/mdk-uniffi/bindings/ruby/mdk_uniffi.rb"
    if [ ! -f "$RUBY_BINDING" ]; then
        echo "Ruby binding not found at $RUBY_BINDING" >&2
        exit 1
    fi
    sed -i '/^module MdkUniffiError$/,/^end$/c\
    module MdkUniffiError\
      class Storage < StandardError; end\
      class Mdk < StandardError; end\
      class InvalidInput < StandardError; end\
    end' "$RUBY_BINDING"
    echo "✓ Ruby binding patched (MdkUniffiError classes)"
