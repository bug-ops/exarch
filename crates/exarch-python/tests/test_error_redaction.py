"""End-to-end regression test for issue #464.

Release builds redact `ArchiveError::Io` messages down to their
`std::io::ErrorKind` description, which collapses every `io::Error::other`
call site to the useless string "other error". Those call sites now wrap
their detail in `exarch_core::IoContext` so the actionable, path-free context
survives redaction while the dynamic detail does not.

The redaction itself is unit-tested in `exarch-core`'s `error::redaction`
module, where it now lives; those tests are gated on `debug_assertions`, so
CI's debug `cargo nextest` run only covers the debug branch. This module is
where the release-mode behaviour is asserted against the compiled extension.
"""

import errno
import os
import sys

import pytest

import exarch


def _redaction_active(temp_dir):
    """Report whether the compiled extension redacts host paths.

    Redaction is gated on `#[cfg(not(debug_assertions))]`, so it is active in
    the release wheels CI tests but not in a local `maturin develop` debug
    build. Probed through the public API via `SourceNotFound`, whose path is
    reduced to a bare filename only when redaction is on.
    """
    missing = temp_dir / "probe-dir" / "missing.tar.gz"
    with pytest.raises(OSError) as excinfo:
        exarch.create_archive(str(temp_dir / "probe.tar.gz"), [str(missing)])
    return "probe-dir" not in str(excinfo.value)


@pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX permission bits do not gate directory reads"
)
def test_unreadable_source_names_the_source_without_leaking_host_detail(temp_dir):
    source = temp_dir / "confidential-source"
    source.mkdir()
    (source / "payload.txt").write_text("data")
    os.chmod(source, 0o000)

    if os.access(source, os.R_OK):
        os.chmod(source, 0o755)
        pytest.skip("mode 000 does not block reads for this user (running as root?)")

    try:
        with pytest.raises(exarch.SourceNotAccessibleError) as excinfo:
            exarch.create_archive(str(temp_dir / "out.tar.gz"), [str(source)])
    finally:
        os.chmod(source, 0o755)

    message = str(excinfo.value)
    assert "confidential-source" in message, f"lost the source name, got: {message!r}"

    err = excinfo.value
    assert err.errno == errno.EACCES
    assert os.path.basename(err.filename) == "confidential-source"
    assert err.strerror, "strerror must stay informative"

    if _redaction_active(temp_dir):
        assert err.filename == "confidential-source"
        assert str(temp_dir) not in message, f"host path leaked in release build, got: {message!r}"
        assert "Permission denied" not in message, (
            f"raw OS detail leaked in release build, got: {message!r}"
        )
