"""New core refusals as Python sees them: name collisions and truncated data."""

import io
import tarfile

import pytest

import exarch


def test_creation_refuses_two_sources_with_one_entry_name(temp_dir):
    first = temp_dir / "one"
    second = temp_dir / "two"
    for directory in (first, second):
        directory.mkdir()
        (directory / "same.txt").write_bytes(b"x")
    output = temp_dir / "out.tar"

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.create_archive(output, [first / "same.txt", second / "same.txt"])

    assert info.value.setting == "source_paths"
    assert info.value.code == "INVALID_CONFIGURATION"
    assert not output.exists()


def test_truncated_tar_member_is_an_invalid_archive_not_an_io_error(temp_dir):
    archive = temp_dir / "full.tar"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("big.bin")
        info.size = 4096
        tar.addfile(info, io.BytesIO(b"y" * 4096))
    truncated = temp_dir / "cut.tar"
    truncated.write_bytes(archive.read_bytes()[: 512 + 1024])

    with pytest.raises(exarch.InvalidArchiveError) as info:
        exarch.extract_archive(truncated, temp_dir / "out")

    assert info.value.code == "INVALID_ARCHIVE"
    assert info.value.sub_code == "TAR_READER"
