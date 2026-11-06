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


def test_creation_collision_carries_the_name_and_both_sources(temp_dir):
    first = temp_dir / "one"
    second = temp_dir / "two"
    for directory in (first, second):
        directory.mkdir()
        (directory / "same.txt").write_bytes(b"x")

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.create_archive(temp_dir / "out.tar", [first / "same.txt", second / "same.txt"])

    collision = info.value.collision
    assert isinstance(collision, exarch.NameCollision)
    assert collision.name == "same.txt"
    assert collision.first.endswith("same.txt")
    assert collision.second.endswith("same.txt")
    assert info.value.protected_path is None


@pytest.mark.parametrize("destination", ["archive_dir", "cwd"])
def test_atomic_replace_refusal_names_what_the_destination_is(temp_dir, destination, monkeypatch):
    archive = temp_dir / "a.tar"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("f.txt")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    options = exarch.ExtractionOptions().with_staging("atomic_replace")
    other = temp_dir / "elsewhere"
    other.mkdir()
    if destination == "cwd":
        monkeypatch.chdir(other)
        target = other
        expected = {"working_directory", "archive_ancestor"}
    else:
        target = temp_dir
        expected = {"archive_ancestor"}

    with pytest.raises(exarch.InvalidConfigurationError) as raised:
        exarch.extract_archive(archive, target, None, options)

    assert raised.value.setting == "output_path"
    assert raised.value.protected_path in expected
    assert raised.value.collision is None


def test_a_hardlink_to_a_collided_target_is_refused_as_ambiguous(temp_dir):
    archive = temp_dir / "amb.tar"
    with tarfile.open(archive, "w") as tar:
        for name in ("a/f", "b/f"):
            info = tarfile.TarInfo(name)
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        link = tarfile.TarInfo("c/link")
        link.type = tarfile.LNKTYPE
        link.linkname = "a/f"
        tar.addfile(link)
    config = exarch.SecurityConfig().with_allow_hardlinks().with_strip_components(1)

    with pytest.raises(exarch.SecurityViolationError) as info:
        exarch.extract_archive(archive, temp_dir / "out", config)

    assert info.value.sub_code == "LINK_TARGET"
