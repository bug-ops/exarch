"""Integer limits are parsed by core: one error class, `setting`, no OverflowError."""

import pytest

import exarch

BEYOND_I128 = 1 << 200

SECURITY_SETTERS = [
    ("max_file_size", "max_file_size"),
    ("max_total_size", "max_total_size"),
    ("max_file_count", "max_file_count"),
    ("max_path_depth", "max_path_depth"),
]


def _refused(callable_):
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        callable_()
    assert info.value.code == "INVALID_CONFIGURATION"
    assert isinstance(info.value, ValueError)
    return info.value


@pytest.mark.parametrize(("attr", "setting"), SECURITY_SETTERS)
@pytest.mark.parametrize("bad", [0, -1, -BEYOND_I128, BEYOND_I128, 1 << 70])
def test_security_property_setters_refuse_bad_integers(attr, setting, bad):
    config = exarch.SecurityConfig()

    err = _refused(lambda: setattr(config, attr, bad))

    assert err.setting == setting


@pytest.mark.parametrize(("attr", "setting"), SECURITY_SETTERS)
def test_security_builders_refuse_bad_integers(attr, setting):
    config = exarch.SecurityConfig()

    for bad in (0, -1, BEYOND_I128, -BEYOND_I128):
        err = _refused(lambda: getattr(config, f"with_{attr}")(bad))
        assert err.setting == setting


@pytest.mark.parametrize("attr", [a for a, _ in SECURITY_SETTERS])
def test_bool_is_not_an_integer(attr):
    with pytest.raises(TypeError):
        setattr(exarch.SecurityConfig(), attr, True)


def test_valid_limits_are_applied_and_read_back():
    config = exarch.SecurityConfig()
    config.max_file_size = 1024
    config.max_total_size = 2048
    config.max_file_count = 7

    assert (config.max_file_size, config.max_total_size, config.max_file_count) == (
        1024,
        2048,
        7,
    )


def test_parallel_decode_memory_names_its_setting():
    config = exarch.SecurityConfig()
    for bad in (0, -5, BEYOND_I128):
        err = _refused(lambda: setattr(config, "parallel_decode_memory", bad))
        assert err.setting == "parallel_decode_memory"

    config.parallel_decode_memory = None
    assert config.parallel_decode_memory is None


def test_solid_block_memory_names_its_setting():
    config = exarch.SecurityConfig().with_allow_solid_archives(True)

    err = _refused(lambda: setattr(config, "max_solid_block_memory", -1))

    assert err.setting == "max_solid_block_memory"


def test_integrity_budget_names_its_setting():
    for bad in (0, -5, BEYOND_I128):
        err = _refused(lambda: exarch.VerificationOptions().with_integrity_check(bad))
        assert err.setting == "decompression_budget"

    options = exarch.VerificationOptions().with_integrity_check(4096)
    assert options.decompression_budget == 4096


def test_creation_max_file_size_accepts_none_and_refuses_bad_integers():
    config = exarch.CreationConfig()
    config.max_file_size = None
    assert config.max_file_size is None

    for bad in (0, -1, BEYOND_I128):
        err = _refused(lambda: setattr(config, "max_file_size", bad))
        assert err.setting == "max_file_size"


@pytest.mark.parametrize("bad", [0, 10, -1, BEYOND_I128, -BEYOND_I128])
def test_compression_level_out_of_range_is_its_own_class(bad):
    with pytest.raises(exarch.InvalidCompressionLevelError) as info:
        exarch.CreationConfig().with_compression_level(bad)

    assert info.value.code == "INVALID_COMPRESSION_LEVEL"
    assert isinstance(info.value, ValueError)


def test_compression_level_beyond_i64_but_within_i128_reads_as_a_phrase():
    with pytest.raises(exarch.InvalidCompressionLevelError, match="got an out-of-range integer"):
        exarch.CreationConfig().with_compression_level(2**70)


def test_compression_level_beyond_64_bits_reads_as_a_phrase():
    with pytest.raises(exarch.InvalidCompressionLevelError, match="got an out-of-range integer"):
        exarch.CreationConfig().with_compression_level(BEYOND_I128)


def test_max_bytes_uses_the_same_parser():
    for bad in (0, -1, BEYOND_I128):
        err = _refused(lambda: exarch.extract_archive_to_memory(b"", max_bytes=bad))
        assert err.setting == "max_bytes"
