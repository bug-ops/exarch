"""Wire values of the closed-set report enums exposed as plain strings."""

import io
import tarfile

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


def _tar_with_internal_symlink(path):
    with tarfile.open(path, "w:gz") as tar:
        data = b"data"
        target = tarfile.TarInfo(name="target.txt")
        target.size = len(data)
        tar.addfile(target, io.BytesIO(data))
        link = tarfile.TarInfo(name="link.txt")
        link.type = tarfile.SYMTYPE
        link.linkname = "target.txt"
        tar.addfile(link)


def test_verify_archive_honours_symlink_policy(temp_dir):
    archive = temp_dir / "links.tar.gz"
    _tar_with_internal_symlink(archive)

    assert exarch.verify_archive(str(archive)).status == "FAIL"

    config = exarch.SecurityConfig().with_allow_symlinks(True)
    assert exarch.verify_archive(str(archive), config).status == "PASS"
