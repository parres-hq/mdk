#!/bin/bash

set -euo pipefail

# Default to stable for fast local checks
version="${1:-stable}"
flags=""

# Check if "check" is passed as a second argument (after version)
if [[ "$#" -gt 1 && "$2" == "check" ]] || [[ "$#" -eq 1 && "$1" == "check" ]]; then
    if [[ "$1" == "check" ]]; then
        version="stable"
    fi
    flags="--check"
fi

# Install toolchain
if [ "$version" != "stable" ]; then
    cargo +$version --version || rustup install $version
    cargo +$version fmt --version || rustup component add rustfmt --toolchain $version
else
    cargo +$version --version || rustup update "$version"
    cargo +$version fmt --version || rustup component add rustfmt --toolchain "$version"
fi

echo "Checking fmt with $version"

# Check workspace crates
cargo +$version fmt --all -- --config format_code_in_doc_comments=true $flags

echo
