"""Opt-in payload integrity check of verify_archive (#623)."""

import zipfile
from pathlib import Path

import pytest

import exarch

PAYLOAD = b"MARKER-PAYLOAD-BYTES"


def _stored_zip(path: Path, corrupt: bool = False) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("data.txt", PAYLOAD)
    if corrupt:
        raw = bytearray(path.read_bytes())
        raw[raw.index(b"MARKER")] ^= 0x01
        path.write_bytes(bytes(raw))
    return path


def test_verification_options_defaults():
    options = exarch.VerificationOptions()

    assert options.integrity_check is False
    assert options.decompression_budget is None


def test_with_integrity_check_defaults_to_500_mib():
    options = exarch.VerificationOptions().with_integrity_check()

    assert options.integrity_check is True
    assert options.decompression_budget == 500 * 1024 * 1024


def test_with_integrity_check_accepts_explicit_budget():
    options = exarch.VerificationOptions().with_integrity_check(1024)

    assert options.decompression_budget == 1024


@pytest.mark.parametrize("budget", [0, -1])
def test_non_positive_budget_is_rejected(budget):
    with pytest.raises(ValueError):
        exarch.VerificationOptions().with_integrity_check(budget)


def test_default_verify_skips_integrity(temp_dir):
    archive = _stored_zip(temp_dir / "bad.zip", corrupt=True)

    report = exarch.verify_archive(archive)

    assert report.integrity_status == "SKIPPED"
    assert report.status == "PASS"


def test_clean_archive_integrity_ok(temp_dir):
    archive = _stored_zip(temp_dir / "ok.zip")
    options = exarch.VerificationOptions().with_integrity_check()

    report = exarch.verify_archive(archive, options=options)

    assert report.integrity_status == "OK"
    assert report.status == "PASS"


def test_corrupt_crc_fails_integrity(temp_dir):
    archive = _stored_zip(temp_dir / "bad.zip", corrupt=True)
    options = exarch.VerificationOptions().with_integrity_check()

    report = exarch.verify_archive(archive, options=options)

    assert report.integrity_status == "FAILED"
    assert report.status == "FAIL"
    assert any(issue.category == "Corrupt Data" for issue in report.issues)


def test_budget_exhaustion_is_incomplete(temp_dir):
    archive = _stored_zip(temp_dir / "ok.zip")
    options = exarch.VerificationOptions().with_integrity_check(1)

    report = exarch.verify_archive(archive, options=options)

    assert report.integrity_status == "INCOMPLETE"
    assert report.status == "WARNING"
    assert any(issue.category == "Integrity Incomplete" for issue in report.issues)


def test_repr_mentions_state():
    assert "integrity_check=False" in repr(exarch.VerificationOptions())


def test_solid_7z_is_incomplete_until_solid_archives_are_allowed():
    fixture = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "solid.7z"
    options = exarch.VerificationOptions().with_integrity_check()

    report = exarch.verify_archive(fixture, options=options)
    assert report.integrity_status == "INCOMPLETE"
    assert report.status == "WARNING"

    config = exarch.SecurityConfig().with_allow_solid_archives(True)
    assert exarch.verify_archive(fixture, config, options).integrity_status == "OK"
