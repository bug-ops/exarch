"""extract_archive_to_callback: verified entries delivered one by one (#823)."""

import io
import tarfile

import pytest

import exarch


def _tar(entries) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload, kind, linkname in entries:
            info = tarfile.TarInfo(name=name)
            info.type = kind
            info.mode = 0o644
            if kind == tarfile.REGTYPE:
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            else:
                info.linkname = linkname
                archive.addfile(info)
    return buffer.getvalue()


def _file(name: str, payload: bytes):
    return (name, payload, tarfile.REGTYPE, "")


def _links_config():
    return exarch.SecurityConfig().with_allow_symlinks(True).with_allow_hardlinks(True)


def test_every_entry_kind_is_delivered_in_order():
    data = _tar(
        [
            ("d", b"", tarfile.DIRTYPE, ""),
            _file("d/a.txt", b"alpha"),
            ("s", b"", tarfile.SYMTYPE, "d/a.txt"),
            ("h", b"", tarfile.LNKTYPE, "d/a.txt"),
        ]
    )
    seen = []

    report = exarch.extract_archive_to_callback(data, seen.append, _links_config())

    assert [(e.path, e.kind) for e in seen] == [
        ("d", "directory"),
        ("d/a.txt", "file"),
        ("s", "symlink"),
        ("h", "hardlink"),
    ]
    assert seen[1].data == b"alpha"
    assert seen[1].mode == 0o644
    assert seen[2].target == "d/a.txt"
    assert seen[3].target == "d/a.txt"
    assert seen[3].data is None
    assert report.files_extracted >= 1


def test_return_value_of_the_callback_is_ignored():
    seen = []

    def on_entry(entry):
        seen.append(entry.path)
        return False

    exarch.extract_archive_to_callback(_tar([_file("a", b"1"), _file("b", b"2")]), on_entry)

    assert seen == ["a", "b"]


class _Boom(Exception):
    pass


def test_a_raising_callback_is_reraised_unchanged_and_stops_extraction():
    calls = []
    error = _Boom("stop here")

    def on_entry(entry):
        calls.append(entry.path)
        raise error

    data = _tar([_file("a", b"1"), _file("b", b"2"), _file("c", b"3")])

    with pytest.raises(_Boom) as info:
        exarch.extract_archive_to_callback(data, on_entry)

    assert info.value is error
    assert calls == ["a"]
    assert not hasattr(info.value, "progress_callback_error")
    assert info.value.__cause__ is None


def test_raise_on_a_later_entry_aborts_the_rest():
    calls = []

    def on_entry(entry):
        calls.append(entry.path)
        if entry.path == "b":
            raise _Boom

    data = _tar([_file("a", b"1"), _file("b", b"2"), _file("c", b"3")])

    with pytest.raises(_Boom):
        exarch.extract_archive_to_callback(data, on_entry)

    assert calls == ["a", "b"]


def test_a_file_object_exception_propagates_unchanged():
    class Failing(io.BytesIO):
        def read(self, size=-1):
            raise OSError("disk gone")

    with pytest.raises(OSError, match="disk gone"):
        exarch.extract_archive_to_callback(Failing(b"x"), lambda entry: None)


def test_file_object_input_with_a_callback():
    data = _tar([_file("a", b"1")])
    seen = []

    exarch.extract_archive_to_callback(io.BytesIO(data), lambda e: seen.append(e.path))

    assert seen == ["a"]


def test_a_non_callable_is_a_type_error():
    with pytest.raises(TypeError):
        exarch.extract_archive_to_callback(_tar([_file("a", b"1")]), "nope")


def test_security_checks_still_apply():
    data = _tar([_file("../escape", b"x")])
    seen = []

    with pytest.raises(exarch.PathTraversalError):
        exarch.extract_archive_to_callback(data, seen.append)

    assert seen == []


def test_oversized_file_is_refused_before_delivery():
    config = exarch.SecurityConfig().with_max_file_size(10)
    seen = []

    with pytest.raises(exarch.QuotaExceededError):
        exarch.extract_archive_to_callback(
            _tar([_file("big", b"x" * 100)]), seen.append, config
        )

    assert seen == []


def test_unknown_format_and_path_model_are_value_errors():
    data = _tar([_file("a", b"1")])

    with pytest.raises(ValueError):
        exarch.extract_archive_to_callback(data, lambda e: None, format="nope")
    with pytest.raises(ValueError):
        exarch.extract_archive_to_callback(data, lambda e: None, path_model="nope")


def test_atomic_options_are_refused():
    options = exarch.ExtractionOptions().with_atomic(True)

    with pytest.raises(Exception):
        exarch.extract_archive_to_callback(
            _tar([_file("a", b"1")]), lambda e: None, options=options
        )
