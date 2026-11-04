"""7z symlink targets stay unread by `list_archive`, and links count against
`max_file_count` in `extract_archive` (issues #718, #719)."""

import io
import sys
import tarfile
from pathlib import Path

import pytest

import exarch

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


def test_7z_list_archive_leaves_symlink_targets_unread():
    manifest = exarch.list_archive(str(SYMLINK_7Z))

    link = next(e for e in manifest.entries if e.entry_type == "Symlink")
    assert isinstance(link, exarch.ArchiveSymlink)
    assert link.path == "link"
    assert isinstance(link.target, exarch.UnreadLinkTarget)
    assert link.target.state == "unread"


def test_tar_list_archive_records_link_targets_and_only_files_have_a_size(temp_dir):
    archive = _tar_with_symlinks(temp_dir / "links.tar", 1)

    entries = {e.path: e for e in exarch.list_archive(str(archive)).entries}

    link = next(e for e in entries.values() if isinstance(e, exarch.ArchiveSymlink))
    assert isinstance(link.target, exarch.RecordedLinkTarget)
    assert (link.target.state, link.target.path) == ("recorded", "target")
    assert not hasattr(link, "size")
    assert not hasattr(link, "is_symlink")
    for entry in entries.values():
        assert isinstance(entry, exarch.ArchiveEntry)
        assert hasattr(entry, "size") == isinstance(entry, exarch.ArchiveFile)


def test_verify_issue_carries_the_typed_refusal(temp_dir):
    archive = _tar_with_symlinks(temp_dir / "links.tar", 1)

    report = exarch.verify_archive(str(archive))

    issue = next(i for i in report.issues if i.code == "SECURITY_VIOLATION")
    assert issue.sub_code == "LINK_POLICY"
    assert issue.relaxable_by == "symlinks"
    assert issue.mode is None
    assert not hasattr(issue, "context")


def test_verify_executable_finding_carries_its_mode(temp_dir):
    archive = temp_dir / "exec.tar"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("run.sh")
        info.size = 1
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(b"x"))

    report = exarch.verify_archive(str(archive))

    issue = next(i for i in report.issues if i.category == "Executable File")
    assert issue.code is None
    assert issue.mode == 0o755


@pytest.mark.skipif(sys.platform == "win32", reason="non-UTF-8 names need a Unix filesystem")
def test_non_utf8_entry_names_are_not_listed_lossily(temp_dir):
    archive = temp_dir / "raw.tar"
    with tarfile.open(archive, "w", encoding="utf-8", errors="surrogateescape") as tar:
        for raw in ("a\udcff", "a\udcfe"):
            info = tarfile.TarInfo(raw)
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))

    names = [e.path for e in exarch.list_archive(str(archive)).entries]

    assert len(set(names)) == len(names) == 2
    assert all("\ufffd" not in name for name in names)


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
