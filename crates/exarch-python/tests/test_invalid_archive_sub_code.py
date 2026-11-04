"""``sub_code`` of the typed ``InvalidArchiveError`` families (#887)."""

import io
import struct
import tarfile
import zipfile
import zlib

import pytest

import exarch


def _tar_of(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for info, data in entries:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


def _link(name, kind, target):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    return info


def _extract(temp_dir, name, data, config, options=None):
    archive = temp_dir / name
    archive.write_bytes(data)
    with pytest.raises(exarch.InvalidArchiveError) as caught:
        exarch.extract_archive(archive, temp_dir / "out", config, options)
    return caught.value


def test_hardlink_to_a_missing_target_is_link_target(temp_dir):
    data = _tar_of([(_link("h", tarfile.LNKTYPE, "nothere"), None)])
    config = exarch.SecurityConfig().with_allow_hardlinks()

    error = _extract(temp_dir, "absent.tar", data, config)

    assert error.sub_code == "LINK_TARGET"
    assert "hardlink target does not exist" in str(error)


def test_symlink_without_a_target_is_link_target(temp_dir):
    data = _tar_of([(_link("s", tarfile.SYMTYPE, ""), None)])
    config = exarch.SecurityConfig().with_allow_symlinks()

    error = _extract(temp_dir, "nolink.tar", data, config)

    assert error.sub_code == "LINK_TARGET"
    assert "symlink missing target" in str(error)


def test_duplicate_hardlink_is_duplicate_entry(temp_dir):
    target = tarfile.TarInfo("t")
    target.size = 1
    data = _tar_of(
        [
            (target, b"x"),
            (_link("h", tarfile.LNKTYPE, "t"), None),
            (_link("h", tarfile.LNKTYPE, "t"), None),
        ]
    )
    config = exarch.SecurityConfig().with_allow_hardlinks()
    options = exarch.ExtractionOptions().with_skip_duplicates(False)

    error = _extract(temp_dir, "dup.tar", data, config, options)

    assert error.sub_code == "DUPLICATE_ENTRY"


def test_forged_zip_compressed_size_is_declared_size(temp_dir):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("a.txt", b"hello")
    raw = bytearray(buffer.getvalue())
    forged = struct.pack("<I", 0x7FFFFFF0)
    raw[18:22] = forged
    central = raw.find(b"PK\x01\x02")
    raw[central + 20 : central + 24] = forged

    error = _extract(temp_dir, "forged.zip", bytes(raw), exarch.SecurityConfig())

    assert error.sub_code == "DECLARED_SIZE"


def test_zip_without_an_end_record_is_zip_reader(temp_dir):
    error = _extract(
        temp_dir, "no_eocd.zip", b"PK\x03\x04" + bytes(60), exarch.SecurityConfig()
    )

    assert error.sub_code == "ZIP_READER"
    assert "failed to open ZIP archive" in str(error)


def _gzip_with_bad_second_block(data, split):
    gz = bytearray(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff")
    for index, block in enumerate((data[:split], data[split:])):
        length = len(block)
        gz.append(1 if index == 1 else 0)
        gz += struct.pack("<H", length)
        gz += struct.pack("<H", length if index == 1 else ~length & 0xFFFF)
        gz += block
    gz += struct.pack("<II", zlib.crc32(data), len(data))
    return bytes(gz)


def test_invalid_deflate_block_under_an_integrity_check_is_integrity(temp_dir):
    entry = tarfile.TarInfo("a")
    entry.size = 30_000
    archive = temp_dir / "bad.tar.gz"
    archive.write_bytes(_gzip_with_bad_second_block(_tar_of([(entry, b"q" * 30_000)]), 10_000))
    options = exarch.VerificationOptions().with_integrity_check()

    with pytest.raises(exarch.InvalidArchiveError) as caught:
        exarch.verify_archive(archive, exarch.SecurityConfig(), options)

    assert caught.value.sub_code == "INTEGRITY"
    assert "integrity check failed" in str(caught.value)
