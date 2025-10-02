#!/bin/bash

set -euo pipefail

# Default to stable for fast local checks
version="${1:-stable}"

# Install toolchain
if [ "$version" != "stable" ]; then
    cargo +$version --version || rustup install $version
else
    cargo +$version --version || rustup update stable
fi

# Ensure rustdoc is available (installed with the toolchain)
rustdoc +$version --version >/dev/null

echo "Checking docs with $version"
RUSTDOCFLAGS="-D warnings" cargo +$version doc --no-deps --all-features --document-private-items
echo

