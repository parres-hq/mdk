#!/bin/bash

set -euo pipefail

# Default to stable for fast local checks
version="${1:-stable}"

# Install/update toolchain
if [ "$version" != "stable" ]; then
    cargo +$version --version || rustup install $version
    cargo +$version clippy --version || rustup component add clippy --toolchain $version
else
    # Always update stable to match CI
    echo "Updating stable toolchain to match CI..."
    rustup update stable
    cargo +$version clippy --version || rustup component add clippy --toolchain $version
fi

echo "Checking clippy with $version..."
echo ""

echo "With all features..."
cargo +$version clippy --all-targets --all-features --no-deps -- -D warnings

echo "Without optional features..."
cargo +$version clippy --all-targets --no-default-features --no-deps -- -D warnings

echo "With mip04 feature only..."
cargo +$version clippy --all-targets --no-default-features --features mip04 --no-deps -- -D warnings

echo "All clippy checks passed for $version!"
echo
