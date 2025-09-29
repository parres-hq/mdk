#!/bin/bash

set -euo pipefail

version="1.85.0"

# Install toolchain
cargo +$version --version || rustup install $version

# Install clippy
cargo +$version clippy --version || rustup component add clippy --toolchain $version

echo "Checking clippy with all features..."
cargo +$version clippy --all-targets --all-features --no-deps -- -D warnings

echo "Checking clippy without optional features..."
cargo +$version clippy --all-targets --no-default-features --no-deps -- -D warnings

echo "Checking clippy with mip04 feature only..."
cargo +$version clippy --all-targets --no-default-features --features mip04 --no-deps -- -D warnings

echo "All clippy checks passed!"
echo
