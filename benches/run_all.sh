#!/usr/bin/env bash
#
# Run all exarch benchmarks and generate combined report.
#
# Usage:
#   ./run_all.sh [--quick]
#
# Options:
#   --quick     Run fewer iterations for faster results
#   --rust-only Run only Rust benchmarks
#   --compare   Run only comparison benchmarks (Python/Node.js)
#
# Output:
#   - Criterion HTML reports in target/criterion/
#   - Combined markdown report in benches/BENCHMARK_RESULTS.md
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_FILE="$SCRIPT_DIR/BENCHMARK_RESULTS.md"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

# Parse arguments
QUICK=false
RUST_ONLY=false
COMPARE_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK=true
            shift
            ;;
        --rust-only)
            RUST_ONLY=true
            shift
            ;;
        --compare)
            COMPARE_ONLY=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "============================================================"
echo "Exarch Benchmark Suite"
echo "============================================================"
echo ""
echo "Project root: $PROJECT_ROOT"
echo "Fixtures dir: $FIXTURES_DIR"
echo "Output file:  $OUTPUT_FILE"
echo ""

# Check if fixtures exist
if [[ ! -d "$FIXTURES_DIR" ]] || [[ -z "$(ls -A "$FIXTURES_DIR" 2>/dev/null)" ]]; then
    echo "Generating benchmark fixtures..."
    "$SCRIPT_DIR/fixtures/generate_fixtures.sh" "$FIXTURES_DIR"
    echo ""
fi

# Initialize output file
cat > "$OUTPUT_FILE" << 'EOF'
# Exarch Benchmark Results

Generated automatically by `run_all.sh`.

## Performance Targets (from CLAUDE.md)

| Operation | Target | Status |
|-----------|--------|--------|
| TAR extraction | 500 MB/s | TBD |
| ZIP extraction | 300 MB/s | TBD |
| Path validation | < 1 us | TBD |
| Symlink validation | < 5 us | TBD |
| Format detection | < 10 us | TBD |

---

EOF

# Run Rust benchmarks
if [[ "$COMPARE_ONLY" != true ]]; then
    echo "============================================================"
    echo "Running Rust Criterion Benchmarks"
    echo "============================================================"
    echo ""

    cd "$PROJECT_ROOT"

    # Core crate benchmarks
    echo "Running exarch-core benchmarks..."
    cd "$PROJECT_ROOT/crates/exarch-core"

    if [[ "$QUICK" == true ]]; then
        echo "Running extraction benchmarks (quick)..."
        cargo bench --bench extraction -- --quick
        echo ""
        echo "Running creation benchmarks (quick)..."
        cargo bench --bench creation -- --quick
        echo ""
        echo "Running validation benchmarks (quick)..."
        cargo bench --bench validation -- --quick
        echo ""
        echo "Running progress benchmarks (quick)..."
        cargo bench --bench progress -- --quick
    else
        echo "Running extraction benchmarks..."
        cargo bench --bench extraction
        echo ""
        echo "Running creation benchmarks..."
        cargo bench --bench creation
        echo ""
        echo "Running validation benchmarks..."
        cargo bench --bench validation
        echo ""
        echo "Running progress benchmarks..."
        cargo bench --bench progress
    fi

    cd "$PROJECT_ROOT"

    # Add Rust benchmark summary to output
    cat >> "$OUTPUT_FILE" << 'EOF'
## Rust Criterion Benchmarks

Detailed HTML reports are available at:
- `target/criterion/report/index.html`

### Key Results

See individual benchmark HTML reports for detailed analysis with:
- Statistical confidence intervals
- Regression detection
- Throughput measurements
- Flamegraphs (if enabled)

---

EOF

    echo ""
    echo "Rust benchmarks complete."
    echo "HTML report: $PROJECT_ROOT/target/criterion/report/index.html"
    echo ""
fi

# Run Python comparison benchmarks
if [[ "$RUST_ONLY" != true ]]; then
    echo "============================================================"
    echo "Running Python Comparison Benchmarks"
    echo "============================================================"
    echo ""

    # Check if Python exarch is available
    if python3 -c "import exarch" 2>/dev/null; then
        PYTHON_ITERATIONS=5
        if [[ "$QUICK" == true ]]; then
            PYTHON_ITERATIONS=2
        fi

        python3 "$SCRIPT_DIR/compare_python.py" "$FIXTURES_DIR" -i "$PYTHON_ITERATIONS" -o "$SCRIPT_DIR/python_results.md"

        if [[ -f "$SCRIPT_DIR/python_results.md" ]]; then
            echo "" >> "$OUTPUT_FILE"
            cat "$SCRIPT_DIR/python_results.md" >> "$OUTPUT_FILE"
            echo "" >> "$OUTPUT_FILE"
            echo "---" >> "$OUTPUT_FILE"
        fi

        echo "Python benchmarks complete."
    else
        echo "Skipping Python benchmarks: exarch not installed."
        echo "Install with: cd crates/exarch-python && maturin develop --release"

        cat >> "$OUTPUT_FILE" << 'EOF'
## Python Comparison Benchmarks

Skipped: exarch Python package not installed.
Install with: `cd crates/exarch-python && maturin develop --release`

---

EOF
    fi
    echo ""

    echo "============================================================"
    echo "Running Node.js Comparison Benchmarks"
    echo "============================================================"
    echo ""

    # Check if Node.js exarch is available
    if node -e "require('./crates/exarch-node')" 2>/dev/null || node -e "require('exarch-rs')" 2>/dev/null; then
        NODE_ITERATIONS=5
        if [[ "$QUICK" == true ]]; then
            NODE_ITERATIONS=2
        fi

        node "$SCRIPT_DIR/compare_node.js" "$FIXTURES_DIR" "$NODE_ITERATIONS" -o "$SCRIPT_DIR/node_results.md"

        if [[ -f "$SCRIPT_DIR/node_results.md" ]]; then
            echo "" >> "$OUTPUT_FILE"
            cat "$SCRIPT_DIR/node_results.md" >> "$OUTPUT_FILE"
            echo "" >> "$OUTPUT_FILE"
        fi

        echo "Node.js benchmarks complete."
    else
        echo "Skipping Node.js benchmarks: exarch-rs not built."
        echo "Build with: cd crates/exarch-node && npm run build"

        cat >> "$OUTPUT_FILE" << 'EOF'
## Node.js Comparison Benchmarks

Skipped: exarch-rs Node.js package not built.
Build with: `cd crates/exarch-node && npm run build`

EOF
    fi
    echo ""
fi

# Add metadata
cat >> "$OUTPUT_FILE" << EOF

---

## Benchmark Environment

- **Date**: $(date -Iseconds)
- **OS**: $(uname -s) $(uname -r)
- **Architecture**: $(uname -m)
- **Rust**: $(rustc --version 2>/dev/null || echo "not available")
- **Python**: $(python3 --version 2>/dev/null || echo "not available")
- **Node.js**: $(node --version 2>/dev/null || echo "not available")

## How to Run

\`\`\`bash
# Generate fixtures (required first time)
./benches/fixtures/generate_fixtures.sh

# Run all benchmarks
./benches/run_all.sh

# Quick run (fewer iterations)
./benches/run_all.sh --quick

# Rust benchmarks only
./benches/run_all.sh --rust-only

# Comparison benchmarks only
./benches/run_all.sh --compare
\`\`\`

## Files

- \`benches/extraction.rs\` - Extraction benchmarks
- \`benches/creation.rs\` - Archive creation benchmarks
- \`benches/validation.rs\` - Security validation benchmarks
- \`benches/compare_python.py\` - Python comparison
- \`benches/compare_node.js\` - Node.js comparison
- \`benches/fixtures/\` - Test archives
EOF

echo "============================================================"
echo "Benchmark Suite Complete"
echo "============================================================"
echo ""
echo "Results written to: $OUTPUT_FILE"
echo ""
echo "View Criterion HTML report:"
echo "  open $PROJECT_ROOT/target/criterion/report/index.html"
echo ""
