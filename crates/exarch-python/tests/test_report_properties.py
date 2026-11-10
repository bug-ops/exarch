"""Report values read as properties, like their Node counterparts (#1160)."""

import exarch


def test_creation_report_ratios_are_properties(temp_dir):
    source = temp_dir / "src"
    source.mkdir()
    (source / "a.txt").write_bytes(b"a" * 4096)

    report = exarch.create_archive(temp_dir / "out.tar.gz", [source])

    assert isinstance(report.compression_ratio, float)
    assert isinstance(report.compression_percentage, float)


def test_verification_report_verdicts_are_properties(sample_tar_gz):
    report = exarch.verify_archive(sample_tar_gz)

    assert report.is_safe is True
    assert report.has_critical_issues is False
