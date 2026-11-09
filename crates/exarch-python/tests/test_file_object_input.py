"""Binary file objects as `data` of the in-memory functions (#789)."""

import io
import tarfile
import zipfile

import pytest

import exarch


def _tar(mode: str = "w") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        data = b"alpha"
        info = tarfile.TarInfo(name="a.txt")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("a.txt", b"alpha")
    return buffer.getvalue()


class _Stream(io.RawIOBase):
    """A forward-only reader: `seekable()` is false."""

    def __init__(self, data: bytes) -> None:
        self._inner = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def readinto(self, buffer) -> int:
        return self._inner.readinto(buffer)


class _NoSeekableAttr:
    """Has `read` only: `seekable` is missing, so it is a plain stream."""

    def __init__(self, data: bytes) -> None:
        self._inner = io.BytesIO(data)

    def read(self, size: int) -> bytes:
        return self._inner.read(size)


class _Failing(io.BytesIO):
    """Raises on the `n`-th `read`, and counts the calls after that."""

    def __init__(self, data: bytes, exc: BaseException, fail_on: int = 1) -> None:
        super().__init__(data)
        self.exc = exc
        self.fail_on = fail_on
        self.reads = 0
        self.after_failure = 0

    def read(self, size: int = -1) -> bytes:
        self.reads += 1
        if self.reads > self.fail_on:
            self.after_failure += 1
        if self.reads >= self.fail_on:
            raise self.exc
        return super().read(size)


@pytest.mark.parametrize("data", [_tar(), _tar("w:gz"), _tar("w:bz2"), _tar("w:xz"), _zip()])
def test_seekable_file_matches_bytes(data):
    from_bytes = exarch.list_archive_bytes(data)
    from_file = exarch.list_archive_bytes(io.BytesIO(data))
    assert [e.path for e in from_file.entries] == [e.path for e in from_bytes.entries]


def test_extract_and_verify_accept_a_file():
    data = _tar("w:gz")
    result = exarch.extract_archive_to_memory(io.BytesIO(data))
    assert [(e.path, e.data) for e in result.entries] == [("a.txt", b"alpha")]
    assert exarch.verify_archive_bytes(io.BytesIO(data)).is_safe()


def test_progress_variants_accept_a_file():
    seen = []
    exarch.list_archive_bytes_with_progress(
        io.BytesIO(_tar()), progress=lambda path, total, current, written: seen.append(path)
    )
    assert seen == ["a.txt"]
    result = exarch.extract_archive_to_memory_with_progress(io.BytesIO(_tar()))
    assert len(result.entries) == 1
    assert exarch.verify_archive_bytes_with_progress(io.BytesIO(_tar())).is_safe()


def test_archive_starts_at_the_current_position():
    prefix = b"junk"
    for data in (_tar("w:gz"), _zip()):
        buffer = io.BytesIO(prefix + data)
        buffer.seek(len(prefix))
        manifest = exarch.list_archive_bytes(buffer)
        assert [e.path for e in manifest.entries] == ["a.txt"]


@pytest.mark.parametrize("make", [_Stream, _NoSeekableAttr])
def test_stream_reads_tar_family(make):
    manifest = exarch.list_archive_bytes(make(_tar("w:gz")))
    assert [e.path for e in manifest.entries] == ["a.txt"]
    manifest = exarch.list_archive_bytes(make(_tar("w:gz")), format="TarGz")
    assert [e.path for e in manifest.entries] == ["a.txt"]


@pytest.mark.parametrize("fmt", [None, "Zip"])
def test_stream_refuses_zip(fmt):
    with pytest.raises(Exception, match="seekable reader"):
        exarch.list_archive_bytes(_Stream(_zip()), format=fmt)


def test_read_error_propagates_unchanged():
    error = OSError("network down")
    reader = _Failing(_tar("w:gz"), error)
    with pytest.raises(OSError, match="network down") as info:
        exarch.list_archive_bytes(reader)
    assert info.value is error


def test_failure_is_sticky():
    reader = _Failing(_tar("w:gz") * 2, RuntimeError("boom"), fail_on=2)
    with pytest.raises(RuntimeError, match="boom"):
        exarch.extract_archive_to_memory(reader)
    assert reader.after_failure == 0


def test_bytearray_input():
    manifest = exarch.list_archive_bytes(bytearray(_tar("w:gz")))
    assert [e.path for e in manifest.entries] == ["a.txt"]


def test_failure_after_a_short_read_is_sticky():
    class Short:
        def __init__(self, data):
            self._inner = io.BytesIO(data)
            self.calls = 0

        def read(self, size):
            self.calls += 1
            if self.calls == 3:
                raise OSError("late failure")
            return self._inner.read(min(size, 7))

    reader = Short(_tar("w:gz"))
    with pytest.raises(OSError, match="late failure"):
        exarch.list_archive_bytes(reader)
    assert reader.calls == 3


def test_seek_before_the_base_position_is_a_value_error():
    class Backwards(io.BytesIO):
        def seek(self, offset, whence=0):
            super().seek(offset, whence)
            return 0

    buffer = Backwards(b"junk" + _zip())
    io.BytesIO.seek(buffer, 4)
    with pytest.raises(ValueError, match="before the start of the archive"):
        exarch.list_archive_bytes(buffer)


def test_verify_does_not_turn_a_read_error_into_a_verdict():
    reader = _Failing(_tar("w:gz"), KeyboardInterrupt(), fail_on=2)
    with pytest.raises(KeyboardInterrupt):
        exarch.verify_archive_bytes(reader)


def test_reader_error_wins_over_progress_error():
    reader = _Failing(_tar("w:gz"), OSError("reader"), fail_on=2)

    def progress(*_args):
        raise ValueError("progress")

    with pytest.raises(OSError, match="reader"):
        exarch.list_archive_bytes_with_progress(reader, progress=progress)


def test_seekable_raising_propagates():
    class Raising(io.BytesIO):
        def seekable(self):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        exarch.list_archive_bytes(Raising(_tar()))


def test_tell_raising_propagates():
    class Raising(io.BytesIO):
        def tell(self):
            raise OSError("no tell")

    with pytest.raises(OSError, match="no tell"):
        exarch.list_archive_bytes(Raising(_tar()))


@pytest.mark.parametrize("chunk", ["text", None, 5])
def test_non_bytes_read_result_is_a_type_error(chunk):
    class Bad:
        def read(self, size):
            return chunk

    with pytest.raises(TypeError, match="bytes"):
        exarch.list_archive_bytes(Bad())


def test_oversized_read_result_is_a_value_error():
    class Greedy:
        def read(self, size):
            return b"x" * (size + 1)

    with pytest.raises(ValueError, match="more bytes than requested"):
        exarch.list_archive_bytes(Greedy())


def test_object_without_read_is_a_type_error():
    with pytest.raises(TypeError, match="binary file object"):
        exarch.list_archive_bytes(object())
