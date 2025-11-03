#!/usr/bin/env bash
set -e

# Extract coverage percentage from cargo-llvm-cov output
# Usage: ./extract-coverage.sh <lcov-file>

LCOV_FILE="${1:-coverage/lcov.info}"

if [ ! -f "$LCOV_FILE" ]; then
    echo "Error: LCOV file not found: $LCOV_FILE" >&2
    exit 1
fi

# Extract coverage percentage from lcov.info
# Calculate: (lines hit / total lines) * 100
LINES_HIT=$(grep -E "^DA:" "$LCOV_FILE" | grep -v ",0$" | wc -l)
TOTAL_LINES=$(grep -E "^DA:" "$LCOV_FILE" | wc -l)

if [ "$TOTAL_LINES" -eq 0 ]; then
    echo "0.0"
    exit 0
fi

# Calculate percentage with 2 decimal places
COVERAGE=$(awk "BEGIN {printf \"%.2f\", ($LINES_HIT / $TOTAL_LINES) * 100}")

echo "$COVERAGE"
