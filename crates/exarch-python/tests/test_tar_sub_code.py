"""Tests for the ``sub_code`` attribute of ``InvalidArchiveError`` and ``SecurityViolationError``."""

import gzip
import tarfile

import pytest

import exarch

CAP_PLUS = 5 * 1024 * 1024


def _tar_bytes(size_field=b"00000000005\0"):
    info = tarfile.TarInfo("a.txt")
    info.size = 5
    header = bytearray(info.tobuf(tarfile.USTAR_FORMAT)[:512])
    header[124:136] = size_field
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}\0 ".encode()
    return bytes(header) + b"alpha".ljust(512, b"\0") + b"\0" * 1024


def _extract(temp_dir, name, data):
    archive = temp_dir / name
    archive.write_bytes(data)
    out = temp_dir / "out"
    with pytest.raises(exarch.ArchiveError) as caught:
        exarch.extract_archive(archive, out)
    return caught.value


def test_non_canonical_header_is_tar_ambiguity(temp_dir):
    error = _extract(temp_dir, "a.tar", _tar_bytes(b"+0000000005\0"))

    assert isinstance(error, exarch.InvalidArchiveError)
    assert error.sub_code == "TAR_AMBIGUITY"


def test_junk_after_the_gzip_member_is_tar_trailer(temp_dir):
    error = _extract(temp_dir, "a.tar.gz", gzip.compress(_tar_bytes()) + b"\0\0\0garbage")

    assert isinstance(error, exarch.InvalidArchiveError)
    assert error.sub_code == "TAR_TRAILER"


def test_over_cap_tail_is_a_security_violation_with_tar_trailer(temp_dir):
    data = gzip.compress(_tar_bytes()) + gzip.compress(bytes(CAP_PLUS))

    error = _extract(temp_dir, "big.tar.gz", data)

    assert isinstance(error, exarch.SecurityViolationError)
    assert error.sub_code == "TAR_TRAILER"
    assert error.relaxable_by == "max_tar_metadata_bytes"


def test_plain_corrupt_archive_has_no_sub_code(temp_dir):
    error = _extract(temp_dir, "junk.tar", b"A" * 2048)

    assert isinstance(error, exarch.InvalidArchiveError)
    assert error.sub_code is None


def test_plain_violation_has_no_sub_code(temp_dir):
    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive("bad\0name.tar", temp_dir)

    assert caught.value.sub_code is None


def test_class_defaults_are_none():
    assert exarch.InvalidArchiveError.sub_code is None
    assert exarch.SecurityViolationError.sub_code is None
    assert exarch.ZipInconsistencyError.sub_code is None
