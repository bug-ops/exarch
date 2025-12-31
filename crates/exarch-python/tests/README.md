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

Currently, all tests are skipped with `pytest.skip()` because they require:

1. The compiled Python extension module (`maturin develop`)
2. Test fixture archives in `tests/fixtures/`

## TODO

- [ ] Add test fixture archives (test.tar.gz, malicious.zip, etc.)
- [ ] Integrate with CI pipeline
- [ ] Add more comprehensive test cases
- [ ] Add property-based tests with Hypothesis
