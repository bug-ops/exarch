"""Tests for the ZIP structure policy (``zip_consistency``)."""

import zipfile

import pytest

exarch = pytest.importorskip("exarch")


@pytest.fixture
def cloaked_zip(temp_dir):
    """A ZIP whose local header names the entry ``tample.txt``, central ``sample.txt``."""
    path = temp_dir / "cloaked.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("sample.txt", b"payload")
    data = bytearray(path.read_bytes())
    data[data.index(b"sample.txt")] = ord("t")
    path.write_bytes(bytes(data))
    return path


@pytest.fixture
def duplicate_zip(temp_dir):
    path = temp_dir / "duplicate.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("a.txt", b"first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("a.txt", b"EVIL")
    return path


def test_policy_defaults_to_enforce():
    assert exarch.SecurityConfig().zip_consistency == "enforce"
    assert exarch.SecurityConfig.permissive().zip_consistency == "enforce"


def test_policy_builder_and_setter():
    config = exarch.SecurityConfig().with_zip_consistency("ignore")
    assert config.zip_consistency == "ignore"
    config.zip_consistency = "enforce"
    assert config.zip_consistency == "enforce"


@pytest.mark.parametrize("value", ["off", "Enforce", "", "true"])
def test_policy_rejects_other_strings(value):
    with pytest.raises(ValueError, match="zip_consistency must be one of"):
        exarch.SecurityConfig().with_zip_consistency(value)
    with pytest.raises(ValueError, match="zip_consistency must be one of"):
        exarch.SecurityConfig().zip_consistency = value


def test_extract_rejects_cloaked_zip_before_writing(cloaked_zip, temp_dir):
    out = temp_dir / "out"
    with pytest.raises(exarch.ZipInconsistencyError) as caught:
        exarch.extract_archive(str(cloaked_zip), str(out))
    assert isinstance(caught.value, exarch.SecurityViolationError)
    assert isinstance(caught.value, exarch.ArchiveError)
    assert not out.exists()


def test_list_rejects_cloaked_zip(cloaked_zip):
    with pytest.raises(exarch.ZipInconsistencyError):
        exarch.list_archive(str(cloaked_zip))


def test_ignore_keeps_the_central_directory_interpretation(cloaked_zip, temp_dir):
    config = exarch.SecurityConfig().with_zip_consistency("ignore")
    out = temp_dir / "out"
    exarch.extract_archive(str(cloaked_zip), str(out), config)
    assert (out / "sample.txt").exists()
    assert exarch.list_archive(str(cloaked_zip), config).total_entries == 1


def test_verify_reports_header_mismatch(cloaked_zip):
    report = exarch.verify_archive(str(cloaked_zip))
    assert report.status == "FAIL"
    assert "Header Mismatch" in {issue.category for issue in report.issues}

    relaxed = exarch.SecurityConfig().with_zip_consistency("ignore")
    assert exarch.verify_archive(str(cloaked_zip), relaxed).status == "PASS"


def test_verify_counts_duplicate_records(duplicate_zip):
    report = exarch.verify_archive(str(duplicate_zip))
    assert report.total_entries == 2
    assert report.status == "FAIL"
    assert "Duplicate Entry" in {issue.category for issue in report.issues}

    relaxed = exarch.SecurityConfig().with_zip_consistency("ignore")
    assert exarch.verify_archive(str(duplicate_zip), relaxed).total_entries == 2


def _stored_zip(path, names):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        for name in names:
            archive.writestr(name, name.encode())
    return path


def test_uncounted_records_and_hidden_headers_are_reported(temp_dir):
    path = _stored_zip(temp_dir / "count.zip", ["benign.txt", "hidden.sh"])
    data = bytearray(path.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    data[eocd + 8 : eocd + 12] = (1).to_bytes(2, "little") * 2
    path.write_bytes(bytes(data))

    report = exarch.verify_archive(str(path))
    assert report.total_entries == 2
    assert report.status == "FAIL"
    assert "Hidden Entry" in {issue.category for issue in report.issues}
    with pytest.raises(exarch.ZipInconsistencyError):
        exarch.list_archive(str(path))

    relaxed = exarch.SecurityConfig().with_zip_consistency("ignore")
    assert exarch.list_archive(str(path), relaxed).total_entries == 1
    assert exarch.verify_archive(str(path), relaxed).status == "PASS"


def test_unparseable_local_header_is_rejected_then_extracts_when_ignored(temp_dir):
    path = temp_dir / "ut.zip"
    info = zipfile.ZipInfo("a.txt")
    info.extra = b"UT\x09\x00\x01" + bytes(8)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, b"hello")
    data = bytearray(path.read_bytes())
    data[data.index(b"UT\x09\x00") + 4] = 0x07
    path.write_bytes(bytes(data))

    out = temp_dir / "out"
    with pytest.raises(exarch.ZipInconsistencyError):
        exarch.extract_archive(str(path), str(out))
    assert not out.exists()

    relaxed = exarch.SecurityConfig().with_zip_consistency("ignore")
    exarch.extract_archive(str(path), str(out), relaxed)
    assert (out / "a.txt").read_bytes() == b"hello"


def test_oversized_link_target_is_reported_not_retained(temp_dir):
    import io
    import tarfile

    path = temp_dir / "links.tar"
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo("target")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))
        link = tarfile.TarInfo("h")
        link.type = tarfile.LNKTYPE
        link.linkname = "a" * 100_000
        archive.addfile(link)

    config = exarch.SecurityConfig().with_allow_hardlinks()
    report = exarch.verify_archive(str(path), config)
    assert report.status == "FAIL"
    assert any("file name too long" in issue.message for issue in report.issues)
    with pytest.raises(exarch.InvalidArchiveError, match="too long"):
        exarch.list_archive(str(path))
