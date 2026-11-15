"""Warnings and the exceptions that carry them survive pickle (#1207)."""

import pickle
import shutil
import subprocess

import pytest

import exarch

SEVEN_ZIP = shutil.which("7zz") or shutil.which("7z")

REVIVED = [
    (exarch._revive_extraction_warning, ("root_access_narrowed", "m")),
    (exarch._revive_anti_items_skipped_warning, ("m", 3)),
    (exarch._revive_backup_cleanup_failed_warning, ("m", "p", "verified", "PermissionDenied", "r")),
    (exarch._revive_root_access_narrowed_warning, ("m", "acl_unreadable")),
    (exarch._revive_creation_warning, ("directory_not_synced", "m")),
    (exarch._revive_zip_ratio_over_default_limit_warning, ("m", 2, 100.0, 250.5)),
    (exarch._revive_zip_ratio_check_failed_warning, ("m", "r")),
    (exarch._revive_directory_not_synced_warning, ("m", "PermissionDenied")),
]


def _fields(warning):
    names = [n for n in dir(warning) if not n.startswith("_")]
    return type(warning), {n: getattr(warning, n) for n in names}


@pytest.mark.parametrize(("revive", "args"), REVIVED)
def test_every_warning_class_round_trips(revive, args):
    warning = revive(*args)

    revived = pickle.loads(pickle.dumps(warning))

    assert _fields(revived) == _fields(warning)
    assert str(revived) == str(warning)


def test_revive_rejects_unknown_tokens():
    with pytest.raises(ValueError):
        exarch._revive_root_access_narrowed_warning("m", "nope")
    with pytest.raises(ValueError):
        exarch._revive_extraction_warning("nope", "m")
    with pytest.raises(ValueError):
        exarch._revive_directory_not_synced_warning("m", "nope")


def test_exception_carrying_warnings_pickles():
    warnings = [revive(*args) for revive, args in REVIVED[:4]]
    err = exarch.ArchiveError("partial")
    err.warnings = warnings

    revived = pickle.loads(pickle.dumps(err))

    assert [_fields(w) for w in revived.warnings] == [_fields(w) for w in warnings]


@pytest.mark.skipif(SEVEN_ZIP is None, reason="needs the 7z command-line tool")
def test_real_anti_item_warning_pickles(temp_dir):
    src = temp_dir / "src"
    src.mkdir()
    (src / "a").write_text("a")
    (src / "b").write_text("b")
    base = temp_dir / "base.7z"
    diff = temp_dir / "diff.7z"
    subprocess.run([SEVEN_ZIP, "a", str(base), "a", "b"], cwd=src, check=True, capture_output=True)
    (src / "a").unlink()
    subprocess.run(
        [SEVEN_ZIP, "u", str(base), f"-up0q3r2x2y2z0w2!{diff}", "*"],
        cwd=src,
        check=True,
        capture_output=True,
    )

    report = exarch.extract_archive(diff, temp_dir / "out")

    (warning,) = report.warnings
    revived = pickle.loads(pickle.dumps(warning))
    assert isinstance(revived, exarch.AntiItemsSkippedWarning)
    assert revived.count == warning.count == 1
    assert revived.message == warning.message


def test_skipped_constructor_rejects_inconsistent_states():
    skip = exarch.Skip("duplicate", "a")
    with pytest.raises(ValueError):
        exarch.Skipped({"excluded": 1}, [skip])
    with pytest.raises(ValueError):
        exarch.Skipped({"duplicate": 100}, [skip] * 65)
    with pytest.raises(ValueError):
        exarch.Skipped({"duplicate": 1}, [skip, skip])
    with pytest.raises(ValueError):
        exarch.Skipped({"duplicate": 0}, [])

    assert exarch.Skipped({"duplicate": 70}, [skip]).total == 70
