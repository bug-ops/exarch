"""Tests for the 7z parallel decode memory setting (``parallel_decode_memory``)."""

import pytest

exarch = pytest.importorskip("exarch")

MIB = 1024 * 1024


def test_defaults():
    assert exarch.SecurityConfig().parallel_decode_memory == 128 * MIB
    assert exarch.SecurityConfig.permissive().parallel_decode_memory == 1024 * MIB


def test_builder_setter_and_none():
    config = exarch.SecurityConfig().with_parallel_decode_memory(256 * MIB)
    assert config.parallel_decode_memory == 256 * MIB
    config.parallel_decode_memory = None
    assert config.parallel_decode_memory is None
    config.parallel_decode_memory = 64 * MIB
    assert config.parallel_decode_memory == 64 * MIB
    assert exarch.SecurityConfig().with_parallel_decode_memory(None).parallel_decode_memory is None


@pytest.mark.parametrize("value", [0, -1, 2**70])
def test_non_positive_and_oversized_are_value_errors(value):
    with pytest.raises(ValueError, match="parallel_decode_memory must be positive"):
        exarch.SecurityConfig().with_parallel_decode_memory(value)
    with pytest.raises(ValueError, match="parallel_decode_memory must be positive"):
        exarch.SecurityConfig().parallel_decode_memory = value
