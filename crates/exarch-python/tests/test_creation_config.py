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

    @pytest.mark.parametrize("level", [0, 10, 200])
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
