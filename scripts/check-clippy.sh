#!/bin/bash

set -euo pipefail

version="1.85.0"

# Install toolchain
cargo +$version --version || rustup install $version

# Install clippy
cargo +$version clippy --version || rustup component add clippy --toolchain $version

echo "Checking clippy"
cargo +$version clippy --all-targets --all-features --no-deps -- -D warnings
echo
