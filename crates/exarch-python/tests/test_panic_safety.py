"""End-to-end regression test for issue #395.

Verifies that a Rust panic inside a `catch_unwind`-guarded call path surfaces
as a catchable Python exception through the real compiled extension module,
rather than aborting the interpreter process. This requires the extension to
be built with the `panic-injection` Cargo feature (opt-in; CI's test-python
job enables it, published wheels never do) so the test is skipped when the
hook isn't present.
"""

import pytest

import exarch


def test_panic_is_converted_to_python_exception_not_process_abort():
    if not hasattr(exarch, "_trigger_panic_for_testing"):
        pytest.skip("extension built without the panic-injection feature")

    with pytest.raises(RuntimeError, match="Internal panic"):
        exarch._trigger_panic_for_testing()
