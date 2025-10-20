#!/bin/bash
# Code coverage script for roughenough2

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Running code coverage for roughenough2...${NC}"

# Check if cargo-llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo -e "${RED}cargo-llvm-cov is not installed!${NC}"
    echo "Install it with: cargo install cargo-llvm-cov"
    exit 1
fi

# Default to HTML output
OUTPUT_FORMAT="html"
FEATURES=""
OPEN_REPORT=true
CLEAN_FIRST=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --lcov)
            OUTPUT_FORMAT="lcov"
            OPEN_REPORT=false
            shift
            ;;
        --json)
            OUTPUT_FORMAT="json"
            OPEN_REPORT=false
            shift
            ;;
        --all-features)
            FEATURES="--features online-linux-krs,online-ssh-agent"
            shift
            ;;
        --no-open)
            OPEN_REPORT=false
            shift
            ;;
        --clean)
            CLEAN_FIRST=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --lcov          Generate lcov format output"
            echo "  --json          Generate JSON format output"
            echo "  --all-features  Enable all optional features"
            echo "  --no-open       Don't open HTML report in browser"
            echo "  --clean         Clean coverage data before running"
            echo "  -h, --help      Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Clean if requested
if [ "$CLEAN_FIRST" = true ]; then
    echo -e "${YELLOW}Cleaning previous coverage data...${NC}"
    cargo llvm-cov clean --workspace
fi

# Run coverage based on output format
case $OUTPUT_FORMAT in
    html)
        echo -e "${YELLOW}Generating HTML coverage report...${NC}"
        cargo llvm-cov --workspace $FEATURES --html
        REPORT_PATH="target/llvm-cov/html/index.html"
        echo -e "${GREEN}HTML coverage report generated at: $REPORT_PATH${NC}"
        
        # Open report in browser if requested
        if [ "$OPEN_REPORT" = true ]; then
            if command -v xdg-open &> /dev/null; then
                xdg-open "$REPORT_PATH"
            elif command -v open &> /dev/null; then
                open "$REPORT_PATH"
            else
                echo -e "${YELLOW}Could not open browser automatically. Please open: $REPORT_PATH${NC}"
            fi
        fi
        ;;
    lcov)
        echo -e "${YELLOW}Generating lcov coverage report...${NC}"
        cargo llvm-cov --workspace $FEATURES --lcov --output-path lcov.info
        echo -e "${GREEN}LCOV coverage report generated at: lcov.info${NC}"
        ;;
    json)
        echo -e "${YELLOW}Generating JSON coverage report...${NC}"
        cargo llvm-cov --workspace $FEATURES --json --output-path coverage.json
        echo -e "${GREEN}JSON coverage report generated at: coverage.json${NC}"
        ;;
esac

# Show summary
echo ""
echo -e "${GREEN}Coverage summary:${NC}"
cargo llvm-cov --workspace $FEATURES --no-report --summary-only