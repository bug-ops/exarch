//! A source mtime beyond the ZIP DOS range is stored as the nearest
//! representable date, 2107-12-31 23:59:58 (#1263); a pre-1980 mtime keeps
//! clamping to 1980-01-01.

#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

use std::fs::File;
use std::fs::FileTimes;
use std::io::Cursor;
use std::num::NonZeroUsize;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use exarch_core::CreationConfig;
use exarch_core::Parallelism;
use exarch_core::create_archive;
use tempfile::TempDir;
use zip::ZipArchive;

const YEAR_2200: u64 = 7_258_118_400;
const DAY: u64 = 86_400;

fn stored_time(mtime: SystemTime, config: &CreationConfig) -> zip::DateTime {
    let src = TempDir::new().unwrap();
    let file = src.path().join("a.txt");
    std::fs::write(&file, b"payload").unwrap();
    File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_times(FileTimes::new().set_modified(mtime))
        .unwrap();
    let out = TempDir::new().unwrap();
    let archive = out.path().join("out.zip");

    create_archive(&archive, &[src.path()], config).unwrap();

    let mut zip = ZipArchive::new(Cursor::new(std::fs::read(&archive).unwrap())).unwrap();
    zip.by_index(0).unwrap().last_modified().unwrap()
}

fn parallel() -> CreationConfig {
    CreationConfig::default().with_parallelism(Parallelism::Threads(NonZeroUsize::new(2).unwrap()))
}

fn ymdhms(time: zip::DateTime) -> (u16, u8, u8, u8, u8, u8) {
    (
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
    )
}

#[test]
fn modified_time_above_2107_clamps_to_the_last_representable_date() {
    let far = UNIX_EPOCH + Duration::from_secs(YEAR_2200);

    for config in [CreationConfig::default(), parallel()] {
        let stored = stored_time(far, &config);

        assert_eq!(ymdhms(stored), (2107, 12, 31, 23, 59, 58), "{config:?}");
    }
}

#[test]
fn modified_time_before_1980_clamps_to_the_first_representable_date() {
    let early = UNIX_EPOCH + Duration::from_secs(DAY);

    for config in [CreationConfig::default(), parallel()] {
        let stored = stored_time(early, &config);

        assert_eq!(ymdhms(stored), (1980, 1, 1, 0, 0, 0), "{config:?}");
    }
}
