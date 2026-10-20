//! Link targets over the host's name limits are not kept in memory (#655).
//!
//! Many hardlinks whose PAX `linkpath` is 1 MiB would hold gigabytes in the
//! manifest if each target were retained. Peak heap usage is measured with a
//! counting allocator: it must stay near one target, not scale with their
//! number. Its own test binary because `#[global_allocator]` is process-wide.

#![allow(clippy::unwrap_used)]

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use exarch_core::IssueCategory;
use exarch_core::SecurityConfig;
use exarch_core::VerificationStatus;
use exarch_core::verify_archive;
use tempfile::TempDir;

const TARGET_BYTES: usize = 1024 * 1024;
const LINKS: usize = 64;

fn pax_linkpath_record(target: &[u8]) -> Vec<u8> {
    let base = "linkpath".len() + target.len() + 3;
    let mut len = base + 1;
    loop {
        let candidate = len.to_string().len() + base;
        if candidate == len {
            break;
        }
        len = candidate;
    }
    let mut record = format!("{len} linkpath=").into_bytes();
    record.extend_from_slice(target);
    record.push(b'\n');
    record
}

fn hardlink_archive() -> Vec<u8> {
    let target = vec![b'a'; TARGET_BYTES];
    let record = pax_linkpath_record(&target);
    let mut builder = tar::Builder::new(Vec::new());
    for i in 0..LINKS {
        let mut pax = tar::Header::new_ustar();
        pax.set_path("PaxHeaders/link").unwrap();
        pax.set_entry_type(tar::EntryType::XHeader);
        pax.set_size(record.len() as u64);
        pax.set_cksum();
        builder.append(&pax, &record[..]).unwrap();

        let mut link = tar::Header::new_ustar();
        link.set_path(format!("h{i}")).unwrap();
        link.set_entry_type(tar::EntryType::Link);
        link.set_size(0);
        link.set_cksum();
        builder.append(&link, &[][..]).unwrap();
    }
    builder.into_inner().unwrap()
}

#[test]
fn oversized_link_targets_are_not_retained() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("links.tar");
    std::fs::write(&path, hardlink_archive()).unwrap();
    let config = SecurityConfig::default()
        .with_allow_hardlinks(true)
        .with_max_tar_metadata_bytes(8 * 1024 * 1024);

    let _profiler = dhat::Profiler::builder().testing().build();
    let report = verify_archive(&path, &config).unwrap();
    let peak = dhat::HeapStats::get().max_bytes;

    assert_eq!(report.status(), VerificationStatus::Fail);
    let reported = report
        .issues()
        .iter()
        .filter(|i| i.category == IssueCategory::InvalidArchive)
        .count();
    assert_eq!(reported, LINKS);
    // Retaining every target would need LINKS x 1 MiB = 64 MiB.
    assert!(
        peak < 16 * TARGET_BYTES,
        "peak heap {peak} bytes grows with the number of oversized targets"
    );
}
