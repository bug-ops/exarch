"""Settings an error names in `relaxable_by` are settable, and listing options (#1056)."""

import io
import re
import tarfile
from pathlib import Path

import pytest

pytest.importorskip("exarch")
import exarch  # noqa: E402

MTIME = 1_700_000_000

PYI = (Path(__file__).resolve().parents[1] / "exarch.pyi").read_text()


def _tar_with_mtime(path):
    with tarfile.open(path, "w") as tar:
        data = b"payload"
        info = tarfile.TarInfo(name="file.txt")
        info.size = len(data)
        info.mtime = MTIME
        tar.addfile(info, io.BytesIO(data))
    return path


NODE_DTS = (Path(__file__).resolve().parents[2] / "exarch-node" / "index.d.ts").read_text()


def _node_security_config_surface():
    """Builder and getter names of Node's generated `SecurityConfig`, in snake case."""
    block = re.search(r"export declare class SecurityConfig \{(.*?)\n\}\n", NODE_DTS, re.S)
    assert block, "SecurityConfig class not found in index.d.ts"

    def snake(name):
        return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()

    builders = {snake(n) for n in re.findall(r"^  with([A-Z]\w*)\(", block[1], re.M)}
    getters = {snake(n) for n in re.findall(r"^  get ([a-z]\w*)\(\)", block[1], re.M)}
    return builders, getters


LIST_BUILDERS_AS_PROPERTIES = {
    "with_allowed_extensions": "allowed_extensions",
    "with_banned_components": "banned_path_components",
    "with_exclude_patterns": "exclude_patterns",
    "with_include_patterns": "include_patterns",
}


def test_python_security_config_covers_every_setting_node_exposes():
    builders, getters = _node_security_config_surface()
    assert {"max_decoder_memory", "compressed_member_allowance"} <= builders
    python = dir(exarch.SecurityConfig)
    missing = sorted(
        [
            f"with_{name}"
            for name in builders
            if f"with_{name}" not in python and f"with_{name}" not in LIST_BUILDERS_AS_PROPERTIES
        ]
        + [prop for prop in LIST_BUILDERS_AS_PROPERTIES.values() if prop not in python]
        + [name for name in getters if name not in python]
    )
    assert not missing, f"Python SecurityConfig lacks what Node exposes: {missing}"


def test_every_policy_setting_an_error_can_name_is_settable():
    literal = re.search(r"^_PolicySetting = Literal\[(.*?)\]", PYI, re.M)
    assert literal, "_PolicySetting not found in exarch.pyi"
    policy = set(re.findall(r'"(\w+)"', literal[1]))
    assert policy
    spellings = {
        "symlinks": "allow_symlinks",
        "hardlinks": "allow_hardlinks",
        "solid_archives": "allow_solid_archives",
        "banned_components": "banned_path_components",
        "max_path_depth": "max_path_depth",
        "windows_reserved_names": "allow_windows_reserved_names",
        "max_tar_metadata_bytes": "max_tar_metadata_bytes",
    }
    assert policy == set(spellings), "a relaxable setting was added: map it to its property"
    config = exarch.SecurityConfig()
    for property_name in spellings.values():
        assert hasattr(config, property_name), property_name


def test_compressed_member_allowance_defaults_and_is_settable():
    config = exarch.SecurityConfig()
    assert config.compressed_member_allowance == 10_000
    assert config.with_compressed_member_allowance(500).compressed_member_allowance == 500
    config.compressed_member_allowance = 7
    assert config.compressed_member_allowance == 7


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
        ("with_compressed_member_allowance", "compressed_member_allowance"),
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
    assert options.stored_targets == "skip"
    assert options.with_stored_targets("read").stored_targets == "read"
    assert options.with_stored_targets("skip").stored_targets == "skip"
    assert exarch.ListOptions.default().stored_targets == "skip"
    assert 'stored_targets="skip"' in repr(exarch.ListOptions())


def test_list_options_reject_an_unknown_stored_targets_token():
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.ListOptions().with_stored_targets("maybe")
    assert info.value.setting == "stored_targets"


def test_list_functions_take_list_options(tmp_path):
    archive = _tar_with_mtime(tmp_path / "a.tar")
    options = exarch.ListOptions().with_stored_targets("read")
    assert exarch.list_archive(archive, options=options).total_entries == 1
    data = archive.read_bytes()
    assert exarch.list_archive_bytes(data, options=options).total_entries == 1
    assert exarch.list_archive_bytes_with_progress(data, options=options).total_entries == 1


def test_manifest_entry_exposes_its_modification_time(tmp_path):
    manifest = exarch.list_archive(_tar_with_mtime(tmp_path / "a.tar"))
    [entry] = manifest.entries
    assert entry.modified == pytest.approx(MTIME)


def test_with_stored_targets_requires_its_argument():
    with pytest.raises(TypeError):
        exarch.ListOptions().with_stored_targets()


def test_report_counts_are_properties(tmp_path):
    archive = _tar_with_mtime(tmp_path / "a.tar")
    report = exarch.extract_archive(archive, tmp_path / "out")
    assert report.total_items == report.files_extracted + report.directories_created
    assert report.has_warnings is False


def test_sink_options_defaults_come_from_core():
    options = exarch.SinkOptions()
    assert (options.existing_files, options.decode_reuse, options.decode_reuse_limit) == (
        "skip",
        "off",
        None,
    )
    assert exarch.SinkOptions(decode_reuse="memory").decode_reuse_limit == 32 * 1024 * 1024


def test_creation_report_counts_are_properties(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.txt").write_text("hello")
    report = exarch.create_archive(tmp_path / "out.tar", [source])
    assert report.total_items == (
        report.files_added + report.directories_added + report.symlinks_added
    )
    assert report.total_items >= 1
    assert report.has_warnings is False


def test_sink_options_explicit_values_are_kept():
    options = exarch.SinkOptions(
        existing_files="refuse", decode_reuse="temp_file", decode_reuse_limit=1024
    )
    assert options.existing_files == "refuse"
    assert options.decode_reuse == "temp_file"
    assert options.decode_reuse_limit == 1024
    assert exarch.SinkOptions(existing_files="overwrite").existing_files == "overwrite"
