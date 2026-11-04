"""Every exarch exception carries `code`; five codes have dual-base classes."""

import pytest

import exarch

DUAL_CLASSES = [
    (exarch.OutputExistsError, FileExistsError),
    (exarch.SourceNotFoundError, FileNotFoundError),
    (exarch.SourceNotAccessibleError, PermissionError),
    (exarch.InvalidConfigurationError, ValueError),
    (exarch.InvalidCompressionLevelError, ValueError),
]


@pytest.mark.parametrize(("cls", "builtin"), DUAL_CLASSES)
def test_dual_classes_derive_from_archive_error_and_the_builtin(cls, builtin):
    assert issubclass(cls, exarch.ArchiveError)
    assert issubclass(cls, builtin)
    assert cls.__mro__.index(exarch.ArchiveError) < cls.__mro__.index(builtin)
    assert cls.__module__ == "exarch"


def test_source_not_found_keeps_os_error_handlers_working(tmp_path):
    with pytest.raises(exarch.SourceNotFoundError) as info:
        exarch.create_archive(str(tmp_path / "x.tar"), [str(tmp_path / "missing")])

    assert info.value.code == "SOURCE_NOT_FOUND"
    assert isinstance(info.value, FileNotFoundError)


def test_invalid_configuration_carries_the_setting():
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.extract_archive_to_memory(b"", max_bytes=0)

    assert info.value.code == "INVALID_CONFIGURATION"
    assert info.value.setting == "max_bytes"
    assert isinstance(info.value, ValueError)


def test_invalid_compression_level_is_its_own_class(tmp_path):
    config = exarch.CreationConfig()
    with pytest.raises(exarch.InvalidCompressionLevelError) as info:
        config.compression_level = 99
        exarch.create_archive(str(tmp_path / "x.tar.gz"), [str(tmp_path)], config)

    assert info.value.code == "INVALID_COMPRESSION_LEVEL"
    assert isinstance(info.value, ValueError)


def test_code_is_set_on_security_errors():
    with pytest.raises(exarch.ArchiveError) as info:
        exarch.extract_archive_to_memory(b"not an archive")

    assert info.value.code == "UNKNOWN_FORMAT"
