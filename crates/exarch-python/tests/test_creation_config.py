"""Integration tests for CreationConfig compression level handling."""

import pytest

pytest.importorskip("exarch")
from exarch import CreationConfig  # noqa: E402


class TestCompressionLevel:
    def test_default_is_six(self):
        assert CreationConfig().compression_level == 6

    def test_builder_and_setter_accept_the_whole_scale(self):
        for level in range(1, 10):
            assert CreationConfig().with_compression_level(level).compression_level == level
            config = CreationConfig()
            config.compression_level = level
            assert config.compression_level == level

    @pytest.mark.parametrize("level", [0, 10, 200, 256, -1, 2**40])
    def test_out_of_range_is_a_value_error(self, level):
        with pytest.raises(ValueError):
            CreationConfig().with_compression_level(level)
        config = CreationConfig()
        with pytest.raises(ValueError):
            config.compression_level = level
        assert config.compression_level == 6

    def test_none_resets_to_six(self):
        config = CreationConfig().with_compression_level(9)
        config.compression_level = None
        assert config.compression_level == 6


class TestMaxFileSize:
    def test_default_is_unbounded(self):
        assert CreationConfig().max_file_size is None

    def test_builder_and_setter_round_trip(self):
        assert CreationConfig().with_max_file_size(1024).max_file_size == 1024
        config = CreationConfig()
        config.max_file_size = 2048
        assert config.max_file_size == 2048

    def test_none_removes_the_limit(self):
        config = CreationConfig().with_max_file_size(1024).with_max_file_size(None)
        assert config.max_file_size is None
        config = CreationConfig().with_max_file_size(1024)
        config.max_file_size = None
        assert config.max_file_size is None

    def test_zero_is_refused_and_names_its_setting(self):
        with pytest.raises(ValueError, match="max_file_size") as caught:
            CreationConfig().with_max_file_size(0)
        assert caught.value.setting == "max_file_size"
        config = CreationConfig().with_max_file_size(1024)
        with pytest.raises(ValueError, match="max_file_size"):
            config.max_file_size = 0
        assert config.max_file_size == 1024
