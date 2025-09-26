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

# Check clippy
lint:
    @bash scripts/check-clippy.sh

# Check clippy without features
lint-no-features:
    cargo clippy --all-targets --no-default-features --no-deps -- -D warnings

# Check clippy with mip04 feature only
lint-mip04:
    cargo clippy --all-targets --no-default-features --features mip04 --no-deps -- -D warnings

# Check clippy for all feature combinations
lint-all:
    @echo "Checking clippy with all features..."
    @just lint
    @echo "Checking clippy without optional features..."
    @just lint-no-features
    @echo "Checking clippy with mip04 feature only..."
    @just lint-mip04

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

# Full comprehensive check including all feature combinations for clippy
check-full:
    @echo "Running format checks..."
    @just fmt
    @echo "Running documentation checks..."
    @just docs
    @echo "Running clippy checks for all feature combinations..."
    @just lint-all
    @echo "Running tests for all feature combinations..."
    @just test-all

