#!/bin/bash

set -euo pipefail

version="1.85.0"

# Install toolchain
cargo +$version --version || rustup install $version

# Ensure rustdoc is available (installed with the toolchain)
rustdoc +$version --version >/dev/null

echo "Checking docs"
RUSTDOCFLAGS="-D warnings" cargo +$version doc --no-deps --all-features --document-private-items
echo

