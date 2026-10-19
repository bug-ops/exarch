"""Wire values of the closed-set report enums exposed as plain strings."""

import exarch


def test_list_archive_reports_format_and_entry_types(sample_tar_gz):
    manifest = exarch.list_archive(str(sample_tar_gz))

    assert manifest.format == "TarGz"
    assert {e.entry_type for e in manifest.entries} == {"File", "Directory"}


def test_verify_archive_reports_exact_status_spellings(sample_tar_gz):
    report = exarch.verify_archive(str(sample_tar_gz))

    assert report.status == "PASS"
    assert report.integrity_status == "SKIPPED"
    assert report.security_status == "OK"
