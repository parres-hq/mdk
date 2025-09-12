#!/usr/bin/env just --justfile

default:
    @just --list

# Run tests
test:
    cargo test --all-features --all-targets
    cargo test --all-features --doc

# Check clippy
lint:
    @bash scripts/check-clippy.sh

# Check fmt
fmt:
    @bash scripts/check-fmt.sh

# Check docs
docs:
    @bash scripts/check-docs.sh

# Check all
check:
    @bash scripts/check-all.sh
    @just test

