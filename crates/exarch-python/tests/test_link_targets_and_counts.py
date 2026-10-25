"""7z symlink targets stay unread by `list_archive`, and links count against
`max_file_count` in `extract_archive` (issues #718, #719)."""

import io
import tarfile
from pathlib import Path

import exarch
import pytest

# Written with sevenz-rust2: `a.txt` and a Unix-mode symlink `link` -> `a.txt`.
SYMLINK_7Z = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "symlink-mode.7z"


def _tar_with_symlinks(path, count):
    with tarfile.open(path, "w") as tar:
        for i in range(count):
            link = tarfile.TarInfo(name=f"link{i}")
            link.type = tarfile.SYMTYPE
            link.linkname = "target"
            tar.addfile(link)
    return path


def test_7z_list_archive_leaves_symlink_targets_unset():
    manifest = exarch.list_archive(str(SYMLINK_7Z))

    link = next(e for e in manifest.entries if e.entry_type == "Symlink")
    assert link.path == "link"
    assert link.symlink_target is None


def test_extract_counts_symlinks_against_max_file_count(temp_dir):
    archive = _tar_with_symlinks(temp_dir / "links.tar", 3)
    config = exarch.SecurityConfig().with_allow_symlinks(True).with_max_file_count(2)

    with pytest.raises(exarch.QuotaExceededError):
        exarch.extract_archive(str(archive), str(temp_dir / "out"), config)


def test_extract_accepts_symlinks_at_max_file_count(temp_dir):
    archive = _tar_with_symlinks(temp_dir / "links.tar", 2)
    config = exarch.SecurityConfig().with_allow_symlinks(True).with_max_file_count(2)

    exarch.extract_archive(str(archive), str(temp_dir / "out"), config)

    assert sorted(p.name for p in (temp_dir / "out").iterdir()) == ["link0", "link1"]


def test_extract_does_not_count_directories_against_max_file_count(temp_dir):
    archive = temp_dir / "dirs.tar"
    with tarfile.open(archive, "w") as tar:
        for name in ("a", "b", "c"):
            tar.addfile(_dir_info(name))
        data = b"x"
        info = tarfile.TarInfo(name="a/f.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    config = exarch.SecurityConfig().with_max_file_count(1)

    exarch.extract_archive(str(archive), str(temp_dir / "out"), config)

    assert (temp_dir / "out" / "a" / "f.txt").exists()


def _dir_info(name):
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE
    return info
