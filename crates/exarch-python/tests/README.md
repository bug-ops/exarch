# Python Integration Tests

## Overview

This directory contains Python integration tests for the exarch-python bindings.

## Running Tests

### Prerequisites

1. Build the Python extension module:
   ```bash
   cd crates/exarch-python
   maturin develop
   ```

2. Install pytest:
   ```bash
   pip install pytest
   ```

### Execute Tests

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_security_config.py

# Run with verbose output
pytest -v tests/
```

## Test Status

Tests use `pytest.importorskip("exarch")` at module level, so they are skipped
only when the compiled extension module isn't built yet (`maturin develop`)
and run for real otherwise. Fixture archives are generated on the fly by
fixtures in `conftest.py` (e.g. `sample_tar_gz`); malicious CVE-regression
fixtures live in `tests/fixtures/` and are generated via
`tests/fixtures/generate_fixtures.py`.

## TODO

- [ ] Integrate with CI pipeline
- [ ] Add more comprehensive test cases
- [ ] Add property-based tests with Hypothesis
