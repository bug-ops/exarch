"""Integration tests for SecurityConfig Python API."""

import pytest

pytest.importorskip("exarch")
from exarch import InvalidConfigurationError, SecurityConfig  # noqa: E402


class TestSecurityConfig:
    """Test SecurityConfig Python bindings."""

    def test_default_values(self):
        """Test default configuration values."""
        config = SecurityConfig()
        assert config.max_file_size == 50 * 1024 * 1024
        assert config.max_total_size == 500 * 1024 * 1024
        assert config.max_compression_ratio == 100.0
        assert config.max_file_count == 10_000
        assert config.max_path_depth == 32
        assert config.preserve_permissions is False
        assert config.max_solid_block_memory is None
        assert config.with_allow_solid_archives().max_solid_block_memory == 512 * 1024 * 1024

    def test_allow_getters_default_deny(self):
        """Test that allow_* getters return False by default (secure-by-default)."""
        config = SecurityConfig()
        assert config.allow_symlinks is False
        assert config.allow_hardlinks is False
        assert config.allow_absolute_paths is False
        assert config.allow_world_writable is False
        assert config.allow_solid_archives is False

    def test_allow_getters_reflect_builder_state(self):
        """Test that allow_* getters return correct values after builder calls."""
        config = (
            SecurityConfig()
            .with_allow_symlinks(True)
            .with_allow_hardlinks(True)
            .with_allow_absolute_paths(True)
            .with_allow_world_writable(True)
            .with_allow_solid_archives(True)
        )
        assert config.allow_symlinks is True
        assert config.allow_hardlinks is True
        assert config.allow_absolute_paths is True
        assert config.allow_world_writable is True
        assert config.allow_solid_archives is True

    def test_allow_getters_can_be_disabled(self):
        """Test that allow_* getters reflect False after explicit disable."""
        config = SecurityConfig().with_allow_symlinks(True).with_allow_symlinks(False)
        assert config.allow_symlinks is False

    def test_permissive_allow_getters(self):
        """Test that SecurityConfig.permissive() returns True for all allow_* getters."""
        config = SecurityConfig.permissive()
        assert config.allow_symlinks is True
        assert config.allow_hardlinks is True
        assert config.allow_absolute_paths is True
        assert config.allow_world_writable is True
        assert config.allow_solid_archives is True

    def test_numeric_property_getters_defaults(self):
        """Test that numeric property getters return correct default values."""
        config = SecurityConfig()
        assert config.max_file_size == 50 * 1024 * 1024
        assert config.max_total_size == 500 * 1024 * 1024
        assert config.max_compression_ratio == 100.0
        assert config.max_file_count == 10_000
        assert config.max_path_depth == 32
        assert config.preserve_permissions is False
        assert config.max_solid_block_memory is None
        assert config.with_allow_solid_archives().max_solid_block_memory == 512 * 1024 * 1024

    def test_numeric_property_setters(self):
        """Test that numeric property setters update values correctly."""
        config = SecurityConfig()
        config.max_file_size = 100_000_000
        assert config.max_file_size == 100_000_000
        config.max_total_size = 2_000_000_000
        assert config.max_total_size == 2_000_000_000
        config.max_compression_ratio = 200.0
        assert config.max_compression_ratio == 200.0
        config.max_file_count = 20_000
        assert config.max_file_count == 20_000
        config.max_path_depth = 64
        assert config.max_path_depth == 64
        config.preserve_permissions = True
        assert config.preserve_permissions is True
        with pytest.raises(ValueError) as excinfo:
            config.max_solid_block_memory = 256 * 1024 * 1024
        assert excinfo.value.setting == "max_solid_block_memory"
        config.with_allow_solid_archives()
        config.max_solid_block_memory = 256 * 1024 * 1024
        assert config.max_solid_block_memory == 256 * 1024 * 1024

    def test_builder_pattern(self):
        """Test builder pattern method chaining."""
        config = (
            SecurityConfig()
            .with_max_file_size(100_000_000)
            .with_max_total_size(1_000_000_000)
            .with_allow_symlinks(True)
        )
        assert config.max_file_size == 100_000_000
        assert config.max_total_size == 1_000_000_000
        assert config.allow_symlinks is True

    def test_permissive(self):
        """Test permissive configuration."""
        config = SecurityConfig.permissive()
        assert config.preserve_permissions is True

    def test_repr(self):
        """Test string representation."""
        config = SecurityConfig()
        repr_str = repr(config)
        assert "SecurityConfig" in repr_str
        assert "max_file_size" in repr_str

    def test_compression_ratio_validation(self):
        """Test compression ratio validation."""
        config = SecurityConfig()

        # Should accept valid values
        config.with_max_compression_ratio(150.0)

        # Should reject invalid values
        with pytest.raises(ValueError):
            config.with_max_compression_ratio(float("inf"))

        with pytest.raises(ValueError):
            config.with_max_compression_ratio(float("nan"))

        with pytest.raises(ValueError):
            config.with_max_compression_ratio(-10.0)

    def test_extension_validation(self):
        """Test extension string validation."""
        config = SecurityConfig()

        # Should accept valid extension
        config.add_allowed_extension(".txt")

        # Should reject null bytes
        with pytest.raises(ValueError, match="null bytes"):
            config.add_allowed_extension(".txt\x00")

        # Should reject overly long strings
        with pytest.raises(ValueError, match="maximum length"):
            config.add_allowed_extension("x" * 300)

        # Should reject empty strings
        with pytest.raises(ValueError, match="empty"):
            config.add_allowed_extension("")

    def test_extension_is_normalized_and_unusable_values_are_refused(self):
        """A dotted extension is stored without its dot; unusable ones fail."""
        config = SecurityConfig()
        config.add_allowed_extension(".TXT")
        assert config.allowed_extensions == ["txt"]

        for raw in (" gz", "tar.gz", "a/b", "..txt"):
            with pytest.raises(ValueError):
                config.add_allowed_extension(raw)

        with pytest.raises(ValueError):
            config.allowed_extensions = ["ok", "tar.gz"]

    def test_allowed_extensions_reads_none_for_any_and_none_is_the_only_clear(self):
        """An empty list is refused; None allows every extension again."""
        config = SecurityConfig()
        assert config.allowed_extensions is None

        with pytest.raises(InvalidConfigurationError) as info:
            config.allowed_extensions = []
        assert info.value.setting == "allowed_extension"
        assert info.value.code == "INVALID_CONFIGURATION"
        assert config.allowed_extensions is None

        config.allowed_extensions = ["txt"]
        with pytest.raises(InvalidConfigurationError):
            config.allowed_extensions = []
        assert config.allowed_extensions == ["txt"]

        config.allowed_extensions = None
        assert config.allowed_extensions is None
        assert config.is_extension_allowed("anything")

    def test_allowed_extensions_round_trips_its_own_getter(self):
        config = SecurityConfig().add_allowed_extension("gz")
        config.allowed_extensions = config.allowed_extensions
        assert config.allowed_extensions == ["gz"]

    def test_banned_component_validation(self):
        """Test banned path component string validation."""
        config = SecurityConfig()

        # Should accept valid component
        config.add_banned_component("node_modules")

        # Should reject null bytes
        with pytest.raises(ValueError, match="null bytes"):
            config.add_banned_component("bad\x00component")

        # Should reject overly long strings
        with pytest.raises(ValueError, match="maximum length"):
            config.add_banned_component("x" * 300)

        # Should reject empty strings
        with pytest.raises(ValueError, match="empty"):
            config.add_banned_component("")

    def test_banned_component_refuses_separators_and_dots(self):
        """A component that can never equal one path component is refused."""
        config = SecurityConfig()
        for raw in ("a/b", "a\\b", ".", ".."):
            with pytest.raises(ValueError):
                config.add_banned_component(raw)


@pytest.mark.parametrize(
    ("apply", "setting"),
    [
        (lambda c: c.with_max_file_size(0), "max_file_size"),
        (lambda c: c.with_max_total_size(0), "max_total_size"),
        (lambda c: c.with_max_file_count(0), "max_file_count"),
        (lambda c: c.with_max_path_depth(0), "max_path_depth"),
        (lambda c: c.with_max_solid_block_memory(0), "max_solid_block_memory"),
        (lambda c: c.with_max_compression_ratio(0.0), "max_compression_ratio"),
        (lambda c: c.with_max_compression_ratio(float("nan")), "max_compression_ratio"),
        (lambda c: c.with_max_compression_ratio(float("inf")), "max_compression_ratio"),
    ],
)
def test_refused_limit_names_its_setting(apply, setting):
    with pytest.raises(ValueError, match=setting) as caught:
        apply(SecurityConfig())

    assert caught.value.setting == setting


@pytest.mark.parametrize(
    "name",
    ["max_file_size", "max_total_size", "max_file_count", "max_path_depth"],
)
def test_refused_zero_assignment_names_its_setting(name):
    config = SecurityConfig()

    with pytest.raises(ValueError, match=name) as caught:
        setattr(config, name, 0)

    assert caught.value.setting == name


def test_refused_ratio_assignment_names_its_setting():
    config = SecurityConfig()

    with pytest.raises(ValueError, match="max_compression_ratio") as caught:
        config.max_compression_ratio = float("nan")

    assert caught.value.setting == "max_compression_ratio"
