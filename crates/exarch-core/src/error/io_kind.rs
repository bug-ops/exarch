//! Stable names for `std::io::ErrorKind`.

use std::io::ErrorKind;

use crate::closed_enum::closed_enum;

closed_enum! {
    /// The kind of an I/O failure, spelled the same in every front end.
    ///
    /// `std::io::ErrorKind`'s `Display` text is not a stable contract and the
    /// enum itself is `#[non_exhaustive]`; this is the closed subset exarch
    /// reports, so Python, Node and the CLI emit identical tokens. A kind
    /// without an entry, and `ErrorKind::Other`, is [`Other`](Self::Other).
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::IoKind;
    /// use std::io::ErrorKind;
    ///
    /// assert_eq!(IoKind::from(ErrorKind::PermissionDenied).as_str(), "PermissionDenied");
    /// assert_eq!(IoKind::from(ErrorKind::HostUnreachable), IoKind::Other);
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum IoKind {
        /// `ErrorKind::NotFound`.
        NotFound => "NotFound",
        /// `ErrorKind::PermissionDenied`.
        PermissionDenied => "PermissionDenied",
        /// `ErrorKind::AlreadyExists`.
        AlreadyExists => "AlreadyExists",
        /// `ErrorKind::NotADirectory`.
        NotADirectory => "NotADirectory",
        /// `ErrorKind::IsADirectory`.
        IsADirectory => "IsADirectory",
        /// `ErrorKind::DirectoryNotEmpty`.
        DirectoryNotEmpty => "DirectoryNotEmpty",
        /// `ErrorKind::ReadOnlyFilesystem`.
        ReadOnlyFilesystem => "ReadOnlyFilesystem",
        /// `ErrorKind::StorageFull`.
        StorageFull => "StorageFull",
        /// `ErrorKind::QuotaExceeded`.
        QuotaExceeded => "QuotaExceeded",
        /// `ErrorKind::FileTooLarge`.
        FileTooLarge => "FileTooLarge",
        /// `ErrorKind::InvalidInput`.
        InvalidInput => "InvalidInput",
        /// `ErrorKind::InvalidData`.
        InvalidData => "InvalidData",
        /// `ErrorKind::InvalidFilename`.
        InvalidFilename => "InvalidFilename",
        /// `ErrorKind::TimedOut`.
        TimedOut => "TimedOut",
        /// `ErrorKind::Interrupted`.
        Interrupted => "Interrupted",
        /// `ErrorKind::UnexpectedEof`.
        UnexpectedEof => "UnexpectedEof",
        /// `ErrorKind::WriteZero`.
        WriteZero => "WriteZero",
        /// `ErrorKind::Unsupported`.
        Unsupported => "Unsupported",
        /// `ErrorKind::CrossesDevices`.
        CrossesDevices => "CrossesDevices",
        /// `ErrorKind::TooManyLinks`.
        TooManyLinks => "TooManyLinks",
        /// `ErrorKind::ResourceBusy`.
        ResourceBusy => "ResourceBusy",
        /// `ErrorKind::BrokenPipe`.
        BrokenPipe => "BrokenPipe",
        /// `ErrorKind::OutOfMemory`.
        OutOfMemory => "OutOfMemory",
        /// `ErrorKind::WouldBlock`.
        WouldBlock => "WouldBlock",
        /// `ErrorKind::Other`, and any kind without an entry here.
        Other => "Other",
    }
}

impl From<ErrorKind> for IoKind {
    fn from(kind: ErrorKind) -> Self {
        use ErrorKind as K;
        match kind {
            K::NotFound => Self::NotFound,
            K::PermissionDenied => Self::PermissionDenied,
            K::AlreadyExists => Self::AlreadyExists,
            K::NotADirectory => Self::NotADirectory,
            K::IsADirectory => Self::IsADirectory,
            K::DirectoryNotEmpty => Self::DirectoryNotEmpty,
            K::ReadOnlyFilesystem => Self::ReadOnlyFilesystem,
            K::StorageFull => Self::StorageFull,
            K::QuotaExceeded => Self::QuotaExceeded,
            K::FileTooLarge => Self::FileTooLarge,
            K::InvalidInput => Self::InvalidInput,
            K::InvalidData => Self::InvalidData,
            K::InvalidFilename => Self::InvalidFilename,
            K::TimedOut => Self::TimedOut,
            K::Interrupted => Self::Interrupted,
            K::UnexpectedEof => Self::UnexpectedEof,
            K::WriteZero => Self::WriteZero,
            K::Unsupported => Self::Unsupported,
            K::CrossesDevices => Self::CrossesDevices,
            K::TooManyLinks => Self::TooManyLinks,
            K::ResourceBusy => Self::ResourceBusy,
            K::BrokenPipe => Self::BrokenPipe,
            K::OutOfMemory => Self::OutOfMemory,
            K::WouldBlock => Self::WouldBlock,
            _ => Self::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_named_kind_round_trips_through_its_spelling() {
        for kind in IoKind::ALL {
            assert_eq!(kind.as_str(), kind.to_string());
        }
        assert_eq!(IoKind::ALL.len(), 25);
    }

    #[test]
    fn an_unlisted_kind_is_other() {
        assert_eq!(IoKind::from(ErrorKind::AddrInUse), IoKind::Other);
        assert_eq!(IoKind::from(ErrorKind::Other), IoKind::Other);
    }
}
