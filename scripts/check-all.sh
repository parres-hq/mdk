#!/bin/bash

set -euo pipefail

# Default to stable for fast local checks
# Pass version as argument: ./scripts/check-all.sh 1.90.0
version="${1:-stable}"

echo "========================================"
echo "Running all checks with Rust $version"
echo "========================================"
echo ""

./scripts/check-fmt.sh "$version"
./scripts/check-docs.sh "$version"
./scripts/check-clippy.sh "$version"
