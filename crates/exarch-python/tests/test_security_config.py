"""Integration tests for SecurityConfig Python API."""

import pytest

# TODO: Import exarch module once the extension is built
# from exarch import SecurityConfig


class TestSecurityConfig:
    """Test SecurityConfig Python bindings."""

    def test_default_values(self):
        """Test default configuration values."""
        pytest.skip("Requires compiled Python extension module")
        # config = SecurityConfig()
        # assert config.max_file_size == 50 * 1024 * 1024
        # assert config.max_total_size == 500 * 1024 * 1024
        # assert config.max_compression_ratio == 100.0
        # assert config.max_file_count == 10_000

    def test_builder_pattern(self):
        """Test builder pattern method chaining."""
        pytest.skip("Requires compiled Python extension module")
        # config = (SecurityConfig()
        #     .max_file_size(100_000_000)
        #     .max_total_size(1_000_000_000)
        #     .allow_symlinks(True))
        # assert config.max_file_size == 100_000_000
        # assert config.max_total_size == 1_000_000_000

    def test_permissive(self):
        """Test permissive configuration."""
        pytest.skip("Requires compiled Python extension module")
        # config = SecurityConfig.permissive()
        # assert config.preserve_permissions is True

    def test_repr(self):
        """Test string representation."""
        pytest.skip("Requires compiled Python extension module")
        # config = SecurityConfig()
        # repr_str = repr(config)
        # assert "SecurityConfig" in repr_str
        # assert "max_file_size" in repr_str

    def test_compression_ratio_validation(self):
        """Test compression ratio validation."""
        pytest.skip("Requires compiled Python extension module")
        # config = SecurityConfig()
        #
        # # Should accept valid values
        # config.max_compression_ratio(150.0)
        #
        # # Should reject invalid values
        # with pytest.raises(ValueError):
        #     config.max_compression_ratio(float('inf'))
        #
        # with pytest.raises(ValueError):
        #     config.max_compression_ratio(float('nan'))
        #
        # with pytest.raises(ValueError):
        #     config.max_compression_ratio(-10.0)

    def test_extension_validation(self):
        """Test extension string validation."""
        pytest.skip("Requires compiled Python extension module")
        # config = SecurityConfig()
        #
        # # Should accept valid extension
        # config.add_allowed_extension(".txt")
        #
        # # Should reject null bytes
        # with pytest.raises(ValueError, match="null bytes"):
        #     config.add_allowed_extension(".txt\x00")
        #
        # # Should reject overly long strings
        # with pytest.raises(ValueError, match="maximum length"):
        #     config.add_allowed_extension("x" * 300)
