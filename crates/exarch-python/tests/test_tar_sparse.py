"""Tests for the old GNU sparse TAR policy (``tar_sparse``)."""

import pytest

import exarch

BLOCK = 512


def _octal(value):
    return f"{value:011o}\0".encode()


def _header(name, typeflag, size):
    header = bytearray(BLOCK)
    header[: len(name)] = name.encode()
    header[100:108] = b"0000644\0"
    header[108:124] = b"0000000\x000000000\0"
    header[124:136] = _octal(size)
    header[136:148] = _octal(0)
    header[156] = typeflag
    header[257:265] = b"ustar  \0"
    return header


def _seal(header):
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}\0 ".encode()
    return bytes(header)


def sparse_tar(slot_after_end=False):
    """A sparse ``hole.bin`` (5 stored bytes, real size 1000) and a regular ``after.txt``."""
    sparse = _header("hole.bin", ord("S"), 5)
    sparse[386:398] = _octal(0)
    sparse[398:410] = _octal(5)
    hole_at = 434 if slot_after_end else 410
    sparse[hole_at : hole_at + 12] = _octal(1000)
    sparse[hole_at + 12 : hole_at + 24] = _octal(0)
    sparse[483:495] = _octal(1000)
    after = _header("after.txt", ord("0"), 5)
    data = _seal(sparse) + b"hello".ljust(BLOCK, b"\0")
    data += _seal(after) + b"after".ljust(BLOCK, b"\0")
    return data + b"\0" * (2 * BLOCK)


@pytest.fixture
def sparse_archive(temp_dir):
    path = temp_dir / "sparse.tar"
    path.write_bytes(sparse_tar())
    return path


def test_policy_defaults_to_refuse():
    assert exarch.SecurityConfig().tar_sparse == "refuse"
    assert exarch.SecurityConfig.permissive().tar_sparse == "refuse"


def test_policy_builder_and_setter():
    config = exarch.SecurityConfig().with_tar_sparse("expand")
    assert config.tar_sparse == "expand"
    config.tar_sparse = "refuse"
    assert config.tar_sparse == "refuse"


@pytest.mark.parametrize("value", ["off", "Expand", "", "true"])
def test_policy_rejects_other_strings(value):
    with pytest.raises(exarch.InvalidConfigurationError, match="not one of the allowed values"):
        exarch.SecurityConfig().with_tar_sparse(value)
    with pytest.raises(exarch.InvalidConfigurationError, match="not one of the allowed values"):
        exarch.SecurityConfig().tar_sparse = value


def test_invalid_policy_names_its_setting():
    with pytest.raises(exarch.InvalidConfigurationError) as caught:
        exarch.SecurityConfig().with_tar_sparse("off")
    assert caught.value.setting == "tar_sparse"


def test_sparse_entry_is_refused_by_default(sparse_archive, temp_dir):
    out = temp_dir / "out"
    with pytest.raises(exarch.InvalidArchiveError) as caught:
        exarch.extract_archive(sparse_archive, out)
    assert caught.value.sub_code == "TAR_AMBIGUITY"
    assert not (out / "hole.bin").exists()
    with pytest.raises(exarch.InvalidArchiveError):
        exarch.list_archive(sparse_archive)
    with pytest.raises(exarch.InvalidArchiveError):
        exarch.verify_archive(sparse_archive)


def test_sparse_entry_expands_to_its_real_size(sparse_archive, temp_dir):
    config = exarch.SecurityConfig().with_tar_sparse("expand")
    out = temp_dir / "out"

    exarch.extract_archive(sparse_archive, out, config)

    content = (out / "hole.bin").read_bytes()
    assert content == b"hello" + bytes(995)
    assert (out / "after.txt").read_bytes() == b"after"
    sizes = {entry.path: entry.size for entry in exarch.list_archive(sparse_archive, config).entries}
    assert sizes["hole.bin"] == 1000
    assert exarch.verify_archive(sparse_archive, config).status == "PASS"


def test_real_size_counts_against_the_file_limit(sparse_archive, temp_dir):
    config = exarch.SecurityConfig().with_tar_sparse("expand").with_max_file_size(999)
    with pytest.raises(exarch.QuotaExceededError):
        exarch.extract_archive(sparse_archive, temp_dir / "out", config)


def test_ambiguous_map_stays_refused_under_expand(temp_dir):
    path = temp_dir / "ambiguous.tar"
    path.write_bytes(sparse_tar(slot_after_end=True))
    config = exarch.SecurityConfig().with_tar_sparse("expand")
    with pytest.raises(exarch.InvalidArchiveError) as caught:
        exarch.extract_archive(path, temp_dir / "out", config)
    assert caught.value.sub_code == "TAR_AMBIGUITY"
