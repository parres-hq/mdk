#!/usr/bin/env bash
set -e

# MDK Test Coverage Script
# Generates test coverage reports for the entire workspace

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
HTML_FLAG=""
OUTPUT_DIR="coverage"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --html)
            HTML_FLAG="--html"
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --html              Generate HTML coverage report"
            echo "  --help              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                  # Generate text summary"
            echo "  $0 --html           # Generate HTML report"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Run '$0 --help' for usage information"
            exit 1
            ;;
    esac
done

# Check if cargo-llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo -e "${YELLOW}cargo-llvm-cov is not installed.${NC}"
    echo ""
    echo "To install, run:"
    echo "  cargo install cargo-llvm-cov"
    echo ""
    exit 1
fi

echo -e "${BLUE}=== MDK Test Coverage ===${NC}"
echo ""

# Clean previous coverage data
echo -e "${BLUE}Cleaning previous coverage data...${NC}"
cargo llvm-cov clean --workspace

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Run coverage
echo -e "${BLUE}Running tests with coverage instrumentation...${NC}"
echo ""

if [ -n "$HTML_FLAG" ]; then
    # Generate HTML report
    cargo llvm-cov --all-features --workspace --html --output-dir "$OUTPUT_DIR"
    echo ""
    echo -e "${GREEN}✓ HTML coverage report generated${NC}"
    echo -e "  Open: ${BLUE}$OUTPUT_DIR/html/index.html${NC}"
else
    # Generate text summary
    cargo llvm-cov --all-features --workspace
fi

echo ""
echo -e "${GREEN}✓ Coverage check complete${NC}"
