#!/bin/bash

set -euo pipefail

# MSRV (Minimum Supported Rust Version) - should match Cargo.toml rust-version
msrv="1.90.0"

echo "========================================"
echo "Running MSRV checks with Rust $msrv"
echo "========================================"
echo ""

./scripts/check-fmt.sh "$msrv"
./scripts/check-docs.sh "$msrv"
./scripts/check-clippy.sh "$msrv"

echo "========================================"
echo "All MSRV checks passed!"
echo "========================================"

