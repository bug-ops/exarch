//! Binary file objects as archive input.

use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;

use exarch_core::ArchiveReader;
use exarch_core::formats::detect::ArchiveType;
use pyo3::exceptions::PyTypeError;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;

/// The first exception a file object raised, kept so it can be raised to the
/// caller instead of the `io::Error` the core saw.
#[derive(Clone, Default)]
pub struct FailureSlot(Arc<Mutex<Option<PyErr>>>);

impl FailureSlot {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<PyErr>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stores `err` unless an earlier failure is held, and returns the
    /// `io::Error` for the core. The kind is never `Interrupted` or
    /// `WouldBlock`, so `read_exact` and `io::copy` cannot retry into Python.
    pub fn record(&self, err: PyErr) -> io::Error {
        let io_error = io::Error::other(format!("file object failed: {err}"));
        self.lock().get_or_insert(err);
        io_error
    }

    fn ensure_clear(&self) -> io::Result<()> {
        self.lock()
            .is_none()
            .ok_or_else(|| io::Error::other("file object failed earlier"))
    }

    /// Replaces `result` by the recorded failure, if any: the core turns read
    /// errors into verdicts, and an exception from the file object must not.
    pub fn surface<T>(&self, result: PyResult<T>) -> PyResult<T> {
        let failure = self.lock().take();
        failure.map_or(result, Err)
    }
}

/// A Python binary file object and the slot that holds what it raised.
struct PyHandle {
    obj: Py<PyAny>,
    failure: FailureSlot,
}

impl PyHandle {
    fn read_py(&self, py: Python<'_>, buf: &mut [u8]) -> PyResult<usize> {
        let chunk = self.obj.bind(py).call_method1("read", (buf.len(),))?;
        let chunk: PyBackedBytes = chunk.extract().map_err(|_| {
            PyTypeError::new_err(
                "file object read() must return bytes (is it opened in binary mode?)",
            )
        })?;
        let target = buf.get_mut(..chunk.len()).ok_or_else(|| {
            PyValueError::new_err("file object read() returned more bytes than requested")
        })?;
        target.copy_from_slice(&chunk);
        Ok(chunk.len())
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.failure.ensure_clear()?;
        Python::attach(|py| self.read_py(py, buf)).map_err(|err| self.failure.record(err))
    }
}

/// A seekable Python binary file object read as an archive.
///
/// The archive starts at the object's position when it was passed in, which
/// is offset 0 for the core. A failed `read` or `seek` is sticky: no later call
/// reaches Python.
pub struct SeekableFile {
    handle: PyHandle,
    base: u64,
}

impl SeekableFile {
    fn seek_py(&self, py: Python<'_>, pos: SeekFrom) -> PyResult<u64> {
        let (offset, whence) = match pos {
            SeekFrom::Start(n) => (i128::from(self.base) + i128::from(n), 0_u8),
            SeekFrom::Current(n) => (i128::from(n), 1),
            SeekFrom::End(n) => (i128::from(n), 2),
        };
        let at: u64 = self
            .handle
            .obj
            .bind(py)
            .call_method1("seek", (offset, whence))?
            .extract()?;
        at.checked_sub(self.base)
            .ok_or_else(|| PyValueError::new_err("seek before the start of the archive"))
    }
}

impl Read for SeekableFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handle.read(buf)
    }
}

impl Seek for SeekableFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.handle.failure.ensure_clear()?;
        Python::attach(|py| self.seek_py(py, pos)).map_err(|err| self.handle.failure.record(err))
    }
}

/// A forward-only Python binary file object. It has no `Seek` implementation,
/// so a seek on it cannot be attempted, let alone fail at run time.
pub struct StreamFile {
    handle: PyHandle,
}

impl Read for StreamFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handle.read(buf)
    }
}

/// A Python binary file object, seekable or forward-only, chosen once when
/// the object is received.
pub enum FileInput {
    /// A file object whose `seekable()` is true.
    Seekable(SeekableFile),
    /// A file object without `seekable()`, or whose `seekable()` is false.
    Stream(StreamFile),
}

impl FileInput {
    fn new(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        if !obj.hasattr("read")? {
            return Err(PyTypeError::new_err(
                "data must be bytes or a binary file object",
            ));
        }
        // Only a missing `seekable` means a plain stream; an exception from it
        // (KeyboardInterrupt included) propagates.
        let seekable = if obj.hasattr("seekable")? {
            obj.call_method0("seekable")?.is_truthy()?
        } else {
            false
        };
        let handle = PyHandle {
            obj: obj.clone().unbind(),
            failure: FailureSlot::default(),
        };
        if seekable {
            let base = obj.call_method0("tell")?.extract()?;
            Ok(Self::Seekable(SeekableFile { handle, base }))
        } else {
            Ok(Self::Stream(StreamFile { handle }))
        }
    }

    fn failure(&self) -> &FailureSlot {
        match self {
            Self::Seekable(file) => &file.handle.failure,
            Self::Stream(file) => &file.handle.failure,
        }
    }
}

/// The `data` argument of the in-memory functions: bytes, or a binary file
/// object.
pub enum ArchiveInput {
    /// The archive bytes.
    Bytes(PyBackedBytes),
    /// A binary file object, read as the archive.
    File(FileInput),
}

impl<'a, 'py> FromPyObject<'a, 'py> for ArchiveInput {
    type Error = PyErr;

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        obj.extract::<PyBackedBytes>().map_or_else(
            |_| FileInput::new(&obj).map(Self::File),
            |bytes| Ok(Self::Bytes(bytes)),
        )
    }
}

impl ArchiveInput {
    /// The slot that holds what the file object raises; empty for bytes.
    pub fn failure_slot(&self) -> FailureSlot {
        match self {
            Self::Bytes(_) => FailureSlot::default(),
            Self::File(file) => file.failure().clone(),
        }
    }

    /// The reader for the archive: of the stated `format`, or detected. A file
    /// object that is not seekable reads TAR family formats only.
    pub fn into_reader(
        self,
        format: Option<ArchiveType>,
    ) -> exarch_core::Result<ArchiveReader<'static>> {
        match (self, format) {
            (Self::Bytes(bytes), format) => ArchiveReader::from_bytes(bytes, format),
            (Self::File(FileInput::Seekable(file)), Some(format)) => {
                Ok(ArchiveReader::of_type(file, format))
            }
            (Self::File(FileInput::Seekable(file)), None) => ArchiveReader::detect(file),
            (Self::File(FileInput::Stream(file)), Some(format)) => {
                ArchiveReader::of_stream(file, format)
            }
            (Self::File(FileInput::Stream(file)), None) => ArchiveReader::detect_stream(file),
        }
    }
}
