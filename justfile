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

uniffi-bindgen: _build-uniffi (gen-binding "python") (gen-binding "kotlin") (gen-binding "swift") (gen-binding "ruby")

lib_path := if os() == "windows" {
    "../../target/debug/mdk_uniffi.dll"
} else if os() == "macos" {
    "../../target/debug/libmdk_uniffi.dylib"
} else {
    "../../target/debug/libmdk_uniffi.so"
}

gen-binding lang:
    @echo "Generating {{lang}} bindings..."
    cd crates/mdk-uniffi && cargo run --bin uniffi-bindgen generate \
        -l {{lang}} \
        --library {{lib_path}} \
        --out-dir bindings/{{lang}}
    @echo "✓ Bindings generated in crates/mdk-uniffi/bindings/{{lang}}/"