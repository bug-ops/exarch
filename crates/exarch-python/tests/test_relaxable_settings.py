"""Settings an error names in `relaxable_by` are settable, and listing options (#1056)."""

import io
import tarfile

import pytest

pytest.importorskip("exarch")
import exarch  # noqa: E402

MTIME = 1_700_000_000


def _tar_with_mtime(path):
    with tarfile.open(path, "w") as tar:
        data = b"payload"
        info = tarfile.TarInfo(name="file.txt")
        info.size = len(data)
        info.mtime = MTIME
        tar.addfile(info, io.BytesIO(data))
    return path


def test_every_relaxable_setting_has_a_property_or_builder():
    config = exarch.SecurityConfig()
    assert config.allow_windows_reserved_names is False
    assert config.max_tar_metadata_bytes == 4 * 1024 * 1024
    assert config.max_decoder_memory == 256 * 1024 * 1024
    assert config.max_solid_compression_ratio is None


def test_builders_and_properties_agree():
    config = (
        exarch.SecurityConfig()
        .with_allow_windows_reserved_names()
        .with_max_tar_metadata_bytes(1024)
        .with_max_decoder_memory(2048)
        .with_allow_solid_archives()
        .with_max_solid_compression_ratio(250.0)
    )
    assert config.allow_windows_reserved_names is True
    assert config.max_tar_metadata_bytes == 1024
    assert config.max_decoder_memory == 2048
    assert config.max_solid_compression_ratio == 250.0
    assert config.with_allow_windows_reserved_names(False).allow_windows_reserved_names is False


def test_properties_are_assignable():
    config = exarch.SecurityConfig().with_allow_solid_archives()
    config.max_tar_metadata_bytes = 4096
    config.max_decoder_memory = 8192
    config.max_solid_compression_ratio = 10.0
    assert (config.max_tar_metadata_bytes, config.max_decoder_memory) == (4096, 8192)
    assert config.max_solid_compression_ratio == 10.0


@pytest.mark.parametrize(
    ("setter", "setting"),
    [
        ("with_max_tar_metadata_bytes", "max_tar_metadata_bytes"),
        ("with_max_decoder_memory", "max_decoder_memory"),
    ],
)
@pytest.mark.parametrize("bad", [0, -1])
def test_byte_limits_refuse_zero_and_negative(setter, setting, bad):
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        getattr(exarch.SecurityConfig(), setter)(bad)
    assert info.value.setting == setting


def test_solid_ratio_needs_solid_archives_and_a_finite_ratio():
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.SecurityConfig().with_max_solid_compression_ratio(10.0)
    assert info.value.setting == "max_solid_compression_ratio"

    allowed = exarch.SecurityConfig().with_allow_solid_archives()
    for ratio in (0.0, -1.0, float("inf"), float("nan")):
        with pytest.raises(exarch.InvalidConfigurationError) as info:
            allowed.with_max_solid_compression_ratio(ratio)
        assert info.value.setting == "max_solid_compression_ratio"


def test_solid_ratio_keeps_the_block_memory_limit():
    config = (
        exarch.SecurityConfig()
        .with_allow_solid_archives()
        .with_max_solid_block_memory(1024)
        .with_max_solid_compression_ratio(5.0)
    )
    assert config.max_solid_block_memory == 1024


def test_list_options_defaults_and_builder():
    options = exarch.ListOptions()
    assert options.stored_targets is False
    assert options.with_stored_targets().stored_targets is True
    assert options.with_stored_targets(False).stored_targets is False
    assert exarch.ListOptions.default().stored_targets is False
    assert "stored_targets=False" in repr(exarch.ListOptions())


def test_list_functions_take_list_options(tmp_path):
    archive = _tar_with_mtime(tmp_path / "a.tar")
    options = exarch.ListOptions().with_stored_targets()
    assert exarch.list_archive(archive, options=options).total_entries == 1
    data = archive.read_bytes()
    assert exarch.list_archive_bytes(data, options=options).total_entries == 1
    assert exarch.list_archive_bytes_with_progress(data, options=options).total_entries == 1


def test_manifest_entry_exposes_its_modification_time(tmp_path):
    manifest = exarch.list_archive(_tar_with_mtime(tmp_path / "a.tar"))
    [entry] = manifest.entries
    assert entry.modified == pytest.approx(MTIME)
