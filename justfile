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

# Check clippy for all feature combinations
lint:
    @bash scripts/check-clippy.sh

# Check clippy without features (for individual testing)
lint-no-features:
    cargo clippy --all-targets --no-default-features --no-deps -- -D warnings

# Check clippy with mip04 feature only (for individual testing)
lint-mip04:
    cargo clippy --all-targets --no-default-features --features mip04 --no-deps -- -D warnings

# Check fmt
fmt:
    @bash scripts/check-fmt.sh

# Check docs
docs:
    @bash scripts/check-docs.sh

# Check all (comprehensive like CI)
check:
    @bash scripts/check-all.sh
    @just test-all

# Full comprehensive check including all feature combinations
check-full:
    @echo "Running format checks..."
    @just fmt
    @echo "Running documentation checks..."
    @just docs
    @echo "Running clippy checks for all feature combinations..."
    @just lint
    @echo "Running tests for all feature combinations..."
    @just test-all

