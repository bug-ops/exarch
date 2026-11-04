"""Boundary values, docs and runtime aliases promised by exarch.pyi."""

import io
import tarfile

import pytest

import exarch

BEYOND_FLOAT = 10**400


def test_ratio_refuses_bool():
    config = exarch.SecurityConfig()
    with pytest.raises(TypeError):
        config.max_compression_ratio = True
    with pytest.raises(TypeError):
        config.with_max_compression_ratio(False)


@pytest.mark.parametrize("bad", [BEYOND_FLOAT, -BEYOND_FLOAT, float("nan"), float("inf"), 0, -1.5])
def test_ratio_refusals_are_typed(bad):
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.SecurityConfig().max_compression_ratio = bad

    assert info.value.setting == "max_compression_ratio"
    assert info.value.code == "INVALID_CONFIGURATION"


def test_non_integer_gets_a_clear_type_error():
    with pytest.raises(TypeError, match="expected an int, got float"):
        exarch.SecurityConfig().max_file_size = 1.5


def test_index_only_objects_are_accepted_as_integers():
    class Index:
        def __index__(self) -> int:
            return 4096

    config = exarch.SecurityConfig()
    config.max_file_size = Index()

    assert config.max_file_size == 4096


def test_typing_aliases_are_importable():
    assert exarch.AnyMemoryEntry is not None
    assert exarch.MemoryFile in exarch.AnyMemoryEntry.__args__
    assert exarch.ArchiveSymlink in exarch.AnyArchiveEntry.__args__
    assert exarch.RecordedLinkTarget in exarch.AnyLinkTarget.__args__
    assert exarch.ProgressCallbackFn is not None


def test_create_archive_doc_mentions_overwrite_and_format():
    for function in (exarch.create_archive, exarch.create_archive_with_progress):
        doc = function.__doc__
        assert "overwrite" in doc
        assert "format" in doc


def test_atomic_extraction_into_a_non_empty_directory_is_an_io_error(tmp_path):
    archive = tmp_path / "a.tar"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("f.txt")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    out = tmp_path / "out"
    out.mkdir()
    (out / "keep").write_text("k")
    options = exarch.ExtractionOptions().with_atomic(True)

    with pytest.raises(OSError) as info:
        exarch.extract_archive(archive, out, None, options)

    assert not isinstance(info.value, exarch.OutputExistsError)
    assert info.value.code == "IO_ERROR"
    assert sorted(p.name for p in out.iterdir()) == ["keep"]


def test_atomic_extraction_replaces_an_empty_directory(tmp_path):
    archive = tmp_path / "a.tar"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("f.txt")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    out = tmp_path / "out"
    out.mkdir()
    options = exarch.ExtractionOptions().with_atomic(True)

    exarch.extract_archive(archive, out, None, options)

    assert [p.name for p in out.iterdir()] == ["f.txt"]


def test_seven_z_cannot_be_created():
    with pytest.raises(ValueError):
        exarch.create_archive_to_bytes([], "SevenZ")


def test_class_level_code_is_absent():
    assert not hasattr(exarch.ArchiveError, "code")
