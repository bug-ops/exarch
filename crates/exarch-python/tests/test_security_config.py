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
        # assert config.max_path_depth == 32
        # assert config.preserve_permissions is False
        # assert config.max_solid_block_memory == 512 * 1024 * 1024

    def test_allow_getters_default_deny(self):
        """Test that allow_* getters return False by default (secure-by-default)."""
        pytest.skip("Requires compiled Python extension module")
        # config = SecurityConfig()
        # assert config.allow_symlinks is False
        # assert config.allow_hardlinks is False
        # assert config.allow_absolute_paths is False
        # assert config.allow_world_writable is False
        # assert config.allow_solid_archives is False

    def test_allow_getters_reflect_builder_state(self):
        """Test that allow_* getters return correct values after builder calls."""
        pytest.skip("Requires compiled Python extension module")
        # config = (SecurityConfig()
        #     .with_allow_symlinks(True)
        #     .with_allow_hardlinks(True)
        #     .with_allow_absolute_paths(True)
        #     .with_allow_world_writable(True)
        #     .with_allow_solid_archives(True))
        # assert config.allow_symlinks is True
        # assert config.allow_hardlinks is True
        # assert config.allow_absolute_paths is True
        # assert config.allow_world_writable is True
        # assert config.allow_solid_archives is True

    def test_allow_getters_can_be_disabled(self):
        """Test that allow_* getters reflect False after explicit disable."""
        pytest.skip("Requires compiled Python extension module")
        # config = SecurityConfig().with_allow_symlinks(False)
        # assert config.allow_symlinks is False

    def test_permissive_allow_getters(self):
        """Test that SecurityConfig.permissive() returns True for all allow_* getters."""
        pytest.skip("Requires compiled Python extension module")
        # config = SecurityConfig.permissive()
        # assert config.allow_symlinks is True
        # assert config.allow_hardlinks is True
        # assert config.allow_absolute_paths is True
        # assert config.allow_world_writable is True
        # assert config.allow_solid_archives is True

    def test_numeric_property_getters_defaults(self):
        """Test that numeric property getters return correct default values."""
        pytest.skip("Requires compiled Python extension module")
        # config = SecurityConfig()
        # assert config.max_file_size == 50 * 1024 * 1024
        # assert config.max_total_size == 500 * 1024 * 1024
        # assert config.max_compression_ratio == 100.0
        # assert config.max_file_count == 10_000
        # assert config.max_path_depth == 32
        # assert config.preserve_permissions is False
        # assert config.max_solid_block_memory == 512 * 1024 * 1024

    def test_numeric_property_setters(self):
        """Test that numeric property setters update values correctly."""
        pytest.skip("Requires compiled Python extension module")
        # config = SecurityConfig()
        # config.max_file_size = 100_000_000
        # assert config.max_file_size == 100_000_000
        # config.max_total_size = 2_000_000_000
        # assert config.max_total_size == 2_000_000_000
        # config.max_compression_ratio = 200.0
        # assert config.max_compression_ratio == 200.0
        # config.max_file_count = 20_000
        # assert config.max_file_count == 20_000
        # config.max_path_depth = 64
        # assert config.max_path_depth == 64
        # config.preserve_permissions = True
        # assert config.preserve_permissions is True
        # config.max_solid_block_memory = 256 * 1024 * 1024
        # assert config.max_solid_block_memory == 256 * 1024 * 1024

    def test_builder_pattern(self):
        """Test builder pattern method chaining."""
        pytest.skip("Requires compiled Python extension module")
        # config = (SecurityConfig()
        #     .with_max_file_size(100_000_000)
        #     .with_max_total_size(1_000_000_000)
        #     .with_allow_symlinks(True))
        # assert config.max_file_size == 100_000_000
        # assert config.max_total_size == 1_000_000_000
        # assert config.allow_symlinks is True

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
        # config.with_max_compression_ratio(150.0)
        #
        # # Should reject invalid values
        # with pytest.raises(ValueError):
        #     config.with_max_compression_ratio(float('inf'))
        #
        # with pytest.raises(ValueError):
        #     config.with_max_compression_ratio(float('nan'))
        #
        # with pytest.raises(ValueError):
        #     config.with_max_compression_ratio(-10.0)

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
