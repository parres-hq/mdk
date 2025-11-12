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
    @echo "Building mdk-uniffi library..."
    cargo build --lib -p mdk-uniffi
    # android (most common)
    NDK_HOME="${NDK_HOME:-/opt/android-ndk}" CC_aarch64_linux_android="${NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang" AR_aarch64_linux_android=llvm-ar CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang" cargo build --lib -p mdk-uniffi --target aarch64-linux-android --release
    # android (older devices)
    NDK_HOME="${NDK_HOME:-/opt/android-ndk}" CC_armv7_linux_androideabi="${NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang" AR_armv7_linux_androideabi=llvm-ar CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="${NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang" cargo build --lib -p mdk-uniffi --target armv7-linux-androideabi --release

uniffi-bindgen: _build-uniffi (gen-binding "python") (gen-binding-kotlin) (gen-binding "swift") (gen-binding "ruby")

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
        --library ../../target/debug/libmdk_uniffi.so \
        --out-dir bindings/{{lang}}
    cp target/debug/libmdk_uniffi.so crates/mdk-uniffi/bindings/{{lang}}/libmdk_uniffi.so
    @echo "✓ Bindings generated in crates/mdk-uniffi/bindings/{{lang}}/"

gen-binding-kotlin: (gen-binding "kotlin")
    cp target/aarch64-linux-android/release/libmdk_uniffi.so crates/mdk-uniffi/bindings/kotlin/libmdk_uniffi.arm64-v8a.so
    cp target/armv7-linux-androideabi/release/libmdk_uniffi.so crates/mdk-uniffi/bindings/kotlin/libmdk_uniffi.armeabi-v7a.so
    @echo "✓ Android libs copied"