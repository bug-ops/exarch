//! Anonymous spool files used to hold decoded archive bytes.
//!
//! A spool is an unnamed temporary file created by [`open_spool`]. Its
//! [`SpoolBacking`] says whether writing to it consumes memory (tmpfs, ramfs,
//! a FreeBSD `md` memory disk) so callers can cap a RAM-backed spool at the
//! RAM budget instead of the disk budget.
//!
//! # Platform detection limits
//!
//! - Linux and Android: `fstatfs` `f_type` matched against the tmpfs and ramfs
//!   magics.
//! - FreeBSD and macOS: `fstatfs` filesystem type name and mounted-from source;
//!   `tmpfs` and `/dev/md<digits>` are RAM.
//! - macOS RAM disks made with `hdiutil attach ram://` appear as an ordinary
//!   `/dev/disk<N>` device and are classified as [`SpoolBacking::Disk`].
//!   Telling them apart needs `IOKit`, i.e. another `unsafe` FFI surface; the
//!   crate keeps `unsafe` to a few scoped, audited modules and does not add one
//!   for this. A temporary directory on such a disk therefore holds the spool
//!   in memory outside the decoder budget, bounded only by the reuse limit. The
//!   reverse error (a disk reported as memory, as for a vnode-backed FreeBSD
//!   `md` disk) only lowers the spool's capacity, which is why the classifiers
//!   lean towards [`SpoolBacking::Ram`].
//! - Every other target, and a failed `fstatfs`, report [`SpoolBacking::Disk`].
//! - WASI has no temporary directory, so [`open_spool`] returns `None`.

use std::fs::File;

/// Where a spool's bytes live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpoolBacking {
    /// A disk-backed filesystem, or one that could not be classified.
    #[cfg(not(target_os = "wasi"))]
    Disk,
    /// Memory (tmpfs or ramfs): every byte spooled counts against RAM.
    Ram,
}

impl SpoolBacking {
    /// Classifies the filesystem `file` lives on.
    ///
    /// Linux, Android, FreeBSD and Apple targets are classified; a failed
    /// `fstatfs` and every other target report [`Self::Disk`].
    #[cfg(not(target_os = "wasi"))]
    fn of(file: &File) -> Self {
        cfg_select! {
            any(target_os = "linux", target_os = "android") => rustix::fs::fstatfs(file)
                .map_or(Self::Disk, |stat| {
                    Self::from_fs_type(i128::from(stat.f_type))
                }),
            any(target_vendor = "apple", target_os = "freebsd") => rustix::fs::fstatfs(file)
                .map_or(Self::Disk, |stat| {
                    Self::from_mount(
                        c_chars_until_nul(&stat.f_fstypename),
                        c_chars_until_nul(&stat.f_mntfromname),
                    )
                }),
            _ => {
                let _ = file;
                Self::Disk
            }
        }
    }

    /// The most bytes a spool on this backing may hold: `disk` in general, and
    /// no more than `ram` where every spooled byte occupies memory.
    pub(crate) fn capacity(self, disk: u64, ram: u64) -> u64 {
        match self {
            #[cfg(not(target_os = "wasi"))]
            Self::Disk => disk,
            Self::Ram => disk.min(ram),
        }
    }

    /// Maps a `statfs` `f_type` to a backing. The width and signedness of
    /// `f_type` vary by architecture, so only its low 32 bits are compared.
    #[cfg(any(target_os = "linux", target_os = "android", test))]
    fn from_fs_type(f_type: i128) -> Self {
        // NOTE: the kernel's `TMPFS_MAGIC` and `RAMFS_MAGIC` from
        // `linux/magic.h`, spelled here so the mapping runs on every host;
        // libc defines only the first, and a Linux test pins it to libc's.
        const TMPFS_MAGIC: i128 = 0x0102_1994;
        const RAMFS_MAGIC: i128 = 0x8584_58f6;
        let low = f_type & 0xFFFF_FFFF;
        if low == TMPFS_MAGIC || low == RAMFS_MAGIC {
            Self::Ram
        } else {
            Self::Disk
        }
    }

    /// Maps a BSD mount's filesystem type name and mounted-from source to a
    /// backing: `tmpfs`, and a FreeBSD `md` memory disk (`/dev/md<digits>` with
    /// any suffix such as `p1` or `.eli`).
    ///
    /// A vnode-backed `md` disk is also reported as memory; that only lowers
    /// the capacity, so a wrong answer never risks memory.
    #[cfg(any(target_vendor = "apple", target_os = "freebsd", test))]
    fn from_mount(
        mut fs_type: impl Iterator<Item = u8>,
        mut mounted_from: impl Iterator<Item = u8>,
    ) -> Self {
        let is_md_disk = mounted_from
            .by_ref()
            .take(b"/dev/md".len())
            .eq(b"/dev/md".iter().copied())
            && mounted_from
                .next()
                .is_some_and(|byte| byte.is_ascii_digit());
        if fs_type.by_ref().eq(b"tmpfs".iter().copied()) || is_md_disk {
            Self::Ram
        } else {
            Self::Disk
        }
    }
}

/// The bytes of a NUL-terminated `c_char` field, up to the first NUL.
///
/// `c_char` is `i8` on some targets and `u8` on others, so the bytes are taken
/// by reinterpretation rather than by a cast.
#[cfg(any(target_vendor = "apple", target_os = "freebsd", test))]
fn c_chars_until_nul(field: &[std::ffi::c_char]) -> impl Iterator<Item = u8> {
    field
        .iter()
        .map(|c| c.to_ne_bytes()[0])
        .take_while(|byte| *byte != 0)
}

/// An anonymous spool file and where its bytes live.
#[derive(Debug)]
pub(crate) struct TempSpool {
    file: File,
    backing: SpoolBacking,
}

impl TempSpool {
    /// Whether writing to the file consumes memory.
    pub(crate) const fn backing(&self) -> SpoolBacking {
        self.backing
    }

    /// The unnamed temporary file.
    pub(crate) fn into_file(self) -> File {
        self.file
    }

    /// A spool over `file`, classified by the filesystem it lives on.
    #[cfg(not(target_os = "wasi"))]
    fn new(file: File) -> Self {
        let backing = SpoolBacking::of(&file);
        Self { file, backing }
    }

    /// An anonymous spool forced to report `backing`, for tests that must
    /// exercise the RAM path on a host whose temporary directory is on disk.
    #[cfg(test)]
    pub(crate) fn with_backing(backing: SpoolBacking) -> Option<Self> {
        Some(Self {
            file: tempfile::tempfile().ok()?,
            backing,
        })
    }
}

/// Opens the anonymous spool, or `None` where none can be created.
///
/// WASI has no temporary directory and `std::env::temp_dir` panics there, so
/// no temporary file is attempted on that target.
pub(crate) fn open_spool() -> Option<TempSpool> {
    cfg_select! {
        target_os = "wasi" => None,
        _ => tempfile::tempfile().ok().map(TempSpool::new),
    }
}

#[cfg(test)]
mod spool_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::path::Path;

    #[test]
    fn c_chars_stop_at_the_first_nul() {
        let field = |bytes: &[u8]| -> Vec<std::ffi::c_char> {
            bytes
                .iter()
                .map(|b| std::ffi::c_char::from_ne_bytes([*b]))
                .collect()
        };
        let bytes = |bytes: &[u8]| c_chars_until_nul(&field(bytes)).collect::<Vec<u8>>();
        assert_eq!(bytes(b"tmpfs\0junk"), b"tmpfs");
        assert_eq!(bytes(b"tmpfs"), b"tmpfs");
        assert_eq!(bytes(b""), b"");
        assert_eq!(bytes(b"\0tmpfs"), b"");
        assert_eq!(bytes(&[0xff, 0x80, 0]), [0xff, 0x80]);
    }

    #[test]
    fn fs_type_magics_classify_on_every_host() {
        assert_eq!(SpoolBacking::from_fs_type(0x0102_1994), SpoolBacking::Ram);
        assert_eq!(SpoolBacking::from_fs_type(0x8584_58f6), SpoolBacking::Ram);
        assert_eq!(
            SpoolBacking::from_fs_type(i128::from(0x8584_58f6_u32.cast_signed())),
            SpoolBacking::Ram,
            "a sign-extended 32-bit f_type"
        );
        assert_eq!(SpoolBacking::from_fs_type(0xEF53), SpoolBacking::Disk);
        assert_eq!(SpoolBacking::from_fs_type(0), SpoolBacking::Disk);
    }

    #[test]
    fn mounts_classify_on_every_host() {
        let cases: [(&[u8], &[u8], SpoolBacking); 11] = [
            (b"tmpfs", b"tmpfs", SpoolBacking::Ram),
            (b"tmpfs", b"", SpoolBacking::Ram),
            (b"ufs", b"/dev/md0", SpoolBacking::Ram),
            (b"ufs", b"/dev/md12", SpoolBacking::Ram),
            (b"ufs", b"/dev/md0p1", SpoolBacking::Ram),
            (b"zfs", b"/dev/md0.eli", SpoolBacking::Ram),
            (b"ufs", b"/dev/mdx", SpoolBacking::Disk),
            (b"ufs", b"/dev/md", SpoolBacking::Disk),
            (b"apfs", b"/dev/disk3s1", SpoolBacking::Disk),
            (b"tmpfsx", b"/dev/ada0p2", SpoolBacking::Disk),
            (b"", b"", SpoolBacking::Disk),
        ];
        for (fs_type, from, expected) in cases {
            assert_eq!(
                SpoolBacking::from_mount(fs_type.iter().copied(), from.iter().copied()),
                expected,
                "{fs_type:?} {from:?}"
            );
        }
    }

    #[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
    #[test]
    fn a_default_temp_file_on_a_bsd_is_disk() {
        let file = tempfile::tempfile().unwrap();
        assert_eq!(SpoolBacking::of(&file), SpoolBacking::Disk);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_tmpfs_magic_matches_libc() {
        assert_eq!(
            SpoolBacking::from_fs_type(i128::from(libc::TMPFS_MAGIC)),
            SpoolBacking::Ram
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_file_in_dev_shm_is_ram_backed() {
        let dir = Path::new("/dev/shm");
        if !dir.is_dir() {
            assert!(
                std::env::var_os("CI").is_none(),
                "/dev/shm is missing on a CI host"
            );
            eprintln!("skipped: /dev/shm is not a directory on this host");
            return;
        }
        let file = tempfile::tempfile_in(dir).unwrap();
        assert_eq!(SpoolBacking::of(&file), SpoolBacking::Ram);
    }

    /// The workflow in `.github/workflows/freebsd.yml` mounts a tmpfs and
    /// exports its path; the test fails, not skips, when it is run without.
    #[cfg(target_os = "freebsd")]
    #[test]
    #[ignore = "needs a tmpfs mount: set EXARCH_TEST_TMPFS_DIR (freebsd.yml does)"]
    fn a_file_on_a_freebsd_tmpfs_is_ram_backed() {
        let Some(dir) = std::env::var_os("EXARCH_TEST_TMPFS_DIR") else {
            panic!("EXARCH_TEST_TMPFS_DIR must name a mounted tmpfs");
        };
        let file = tempfile::tempfile_in(dir).unwrap();
        assert_eq!(SpoolBacking::of(&file), SpoolBacking::Ram);
    }
}
