---
aliases:
  - ZIP Header Consistency
  - Zip Cloaking Hardening
tags:
  - sdd
  - spec
  - security
  - zip
  - rust
  - typestate
created: 2026-10-19
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[003-config-api/spec]]"
  - "[[005-cli/spec]]"
  - "[[006-python-bindings/spec]]"
  - "[[007-node-bindings/spec]]"
  - "[[014-config-typestate-validation/spec]]"
  - "[[016-sanitized-mode-and-non-exhaustive-enums/spec]]"
---

# Feature: ZIP Header Consistency Validation

> [!info] Metadata
> **Subsystem**: exarch-core / formats (`formats::zip`), inspection (`inspection::list`, `inspection::verify`, `inspection::report`), config (`SecurityConfig`); mapping layers in `exarch-cli`, `exarch-python`, `exarch-node`
> **MSRV**: Rust 1.98.0
> **Origin**: #637 (new issue)
> **Type / priority**: enhancement (hardening), P2
> **Status**: implemented with #637, #654 and #655 (see section 11 for decisions, deviations and residuals)
> **Baseline**: reproduced on commit cf4cfea with default configuration and `zip` 9.0.5 (locked)

## 1. Overview

### Problem Statement

A ZIP archive stores each entry's metadata twice: in a local file header (LFH) immediately before the entry data, and in the central directory header (CDFH) at the end of the archive. Extractors disagree about which copy is authoritative. Random-access readers (CPython `zipfile`, `unzip`, exarch) follow the central directory; streaming readers (for example the `zip` crate's `ZipStreamReader`) follow the LFHs. An archive whose two copies disagree is therefore interpreted differently by different tools. This class of attack is known as "Zip Cloaking" (CWE-436, Interpretation Conflict); the upstream `zip` crate published GHSA-m665-v7pm-7grj on 2026-10-17 and shipped an opt-in fix in 9.0.5.

`exarch-core` opens ZIP archives with `ZipArchive::new` (`formats::zip`, `ZipArchive::new` around line 265; `inspection::list`) and never enables the crate's header-consistency validation. The archive is silently accepted. Because exarch uses random-access reading only, its own extraction is internally consistent (it follows the central directory), so this is **not** a direct path traversal. The defect is a parser differential and silent acceptance of structurally inconsistent archives, which weakens `exarch verify` and `exarch list` as security gates: a "PASS" from exarch does not describe what other extractors will do with the same bytes.

Reproduced on HEAD cf4cfea with the default configuration:

1. **Name mismatch.** One entry with LFH name `cron_worker.sh` and CDFH name `doc_report.pdf`.
   - `exarch list` prints `doc_report.pdf`; `exarch verify` prints PASS / Security OK; `exarch extract` writes `doc_report.pdf` containing the LFH entry's payload and exits 0.
   - CPython `zipfile` rejects the same archive with `BadZipFile: File name in directory 'doc_report.pdf' and header b'cron_worker.sh' differ`.
   - A streaming (LFH-driven) extractor would write `cron_worker.sh` instead.
2. **Duplicate names.** Two entries both named `a.txt` (first benign, second EVIL).
   - `exarch list` shows 1 entry; `exarch verify` prints `Total entries: 1` and PASS; `exarch extract` silently writes the last entry (EVIL).
   - CPython `namelist()` shows both entries. The entry count under-reports the archive.

The upstream crate exposes `ZipArchive::validate_header_consistency()` (whole-archive check) and `ZipReadOptions::enforce_header_consistency(bool)` used with `ZipArchive::by_index_with_options` (per-entry check). Together they compare LFH against CDFH on file name, UnicodePath extra field, compression method, encryption flag, data-descriptor flag, modification time, and data-descriptor sizes/CRC, and reject duplicate names and overlapping entries.

### Goal

By default (subject to the default-policy decision in section 9), a ZIP archive whose local and central headers disagree, that contains duplicate entry names, or that contains overlapping entries is rejected by `extract` and flagged by `list` and `verify` with typed, machine-readable diagnostics, and `verify` reports the true number of entries in the archive. The behavior is governed by a typed policy enum on `SecurityConfig`, uniformly exposed through the CLI, Python and Node bindings.

### Out of Scope

- Adding an LFH-driven streaming ZIP reader to exarch (exarch stays random-access only)
- Other formats (TAR duplicate-member handling, 7z) — separate concerns, separate specs if needed
- Real integrity checking in `verify` (CRC / decompression verification) — tracked by #623 and #599; this spec only adds *structural* consistency checks and the honest entry count
- The honest-status reporting and typed report enums already shipped in #624; this spec builds on them and does not duplicate them
- Repairing or normalizing inconsistent archives
- ZIP64 / spanned-archive support changes beyond what header validation requires
- Password-protected ZIP handling (already rejected in `ZipArchive::new`)

## 2. User Stories

### US-001: Reject cloaked archives on extraction

AS A developer embedding exarch in an ingestion pipeline
I WANT extraction to fail when a ZIP's local and central headers disagree
SO THAT a file whose name or metadata differs depending on the extractor is never written to disk

**Acceptance criteria:**
```
GIVEN a ZIP with one entry whose LFH name is "cron_worker.sh" and CDFH name is "doc_report.pdf"
  AND the policy is Enforce
WHEN extract_archive runs
THEN it returns a typed header-inconsistency error identifying the mismatch kind and entry
  AND no file is written to the destination
```

### US-002: Honest verification result

AS A security engineer using `exarch verify` as an admission gate
I WANT `verify` to flag header inconsistencies, duplicate names and overlapping entries, and to report the true entry count
SO THAT a PASS means the archive has none of the structural ambiguities listed in section 11, with the residuals named there excepted

**Acceptance criteria:**
```
GIVEN a ZIP containing two entries both named "a.txt"
WHEN verify_archive runs under policy Enforce
THEN the report contains a typed duplicate-entry issue
  AND the reported total entry count is 2, not 1
  AND the overall status is not PASS
```

### US-003: Visible inconsistencies in listings

AS A user inspecting an untrusted archive with `exarch list`
I WANT inconsistencies to be surfaced rather than a single clean-looking name
SO THAT I am not shown a benign file name that another tool would resolve differently

**Acceptance criteria:**
```
GIVEN the cloaked archive from US-001
WHEN list_archive runs under policy Enforce
THEN it returns the typed header-inconsistency error rather than a manifest
```

### US-004: Explicit, typed opt-out

AS A user who must process archives from a producer known to write benign LFH/CDFH differences
I WANT a typed configuration switch available identically from Rust, CLI, Python and Node
SO THAT I can relax the check deliberately without a stringly-typed or bool flag

**Acceptance criteria:**
```
GIVEN a SecurityConfig built with the Ignore policy
WHEN extract_archive, list_archive or verify_archive runs on the cloaked archive
THEN behavior matches today's (central-directory interpretation) with no new rejection
  AND the true entry count is still reported by verify
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a ZIP is opened for extract, list or verify under the Enforce policy THE SYSTEM SHALL compare each entry's LFH against its CDFH and reject the archive on any mismatch of file name, UnicodePath extra field, compression method, encryption flag, or data-descriptor flag | must |
| FR-002 | WHEN a ZIP is opened under the Enforce policy THE SYSTEM SHALL reject archives containing two or more entries with the same name | must |
| FR-003 | WHEN a ZIP is opened under the Enforce policy THE SYSTEM SHALL reject archives containing overlapping entries (entry data ranges that intersect) | must |
| FR-004 | WHEN the Enforce policy rejects an archive in `extract_archive` or `list_archive` THE SYSTEM SHALL return a typed `ArchiveError` variant carrying a typed mismatch-kind enum and the offending entry index and central-directory name, and SHALL NOT write any file to the destination | must |
| FR-005 | WHEN `verify_archive` runs on an inconsistent ZIP THE SYSTEM SHALL record each finding as an `inspection::report::IssueCategory` variant (new variant(s) for header inconsistency, duplicate entry, overlapping entries) in `VerificationReport.issues` rather than propagating an error, per the constitution's verify-reporting rule | must |
| FR-006 | WHEN `verify_archive` runs on a ZIP THE SYSTEM SHALL report the true number of entries in the central directory, including entries sharing a name, regardless of the configured policy | must |
| FR-007 | WHEN `list_archive` runs on a ZIP containing duplicate names under the Ignore policy THE SYSTEM SHALL list every entry rather than collapsing duplicates. **Resolved:** the under-count originates in the `zip` crate's name index, which keeps one slot per name (first record's position, last record's data) and drops the other records, so they cannot be listed. Ignore lists the crate's view and keeps "last entry wins" extraction; `verify` still reports the raw record count and, under Enforce, a duplicate-entry finding | should |
| FR-008 | THE SYSTEM SHALL expose the policy as a two-state enum (working name `HeaderConsistencyPolicy { Enforce, Ignore }`, final naming in plan) stored on `SecurityConfig`, settable through a fluent `with_*` builder on the `Unvalidated` state only, immutable once `Validated`, consistent with [[014-config-typestate-validation/spec]] | must |
| FR-009 | THE SYSTEM SHALL NOT represent the policy as a `bool`, string, or untyped map at any layer (core, CLI, Python, Node) | must |
| FR-010 | THE SYSTEM SHALL expose the policy through `exarch-cli` (typed `clap` value enum), `exarch-python` and `exarch-node` with identical semantics; the bindings SHALL only map the type and convert the error/issue variants, with all checking logic remaining in `exarch-core` | must |
| FR-011 | WHEN a new error or issue variant is added THE SYSTEM SHALL keep `ArchiveError` and `IssueCategory` `#[non_exhaustive]` and update the wildcard-arm conversions in CLI, Python and Node so an unmapped variant has a generic fallback (per [[016-sanitized-mode-and-non-exhaustive-enums/spec]]) | must |
| FR-012 | WHEN the central directory entry count exceeds `max_file_count` THE SYSTEM SHALL reject the archive before running the per-entry header comparison, so the consistency check cannot be used for resource exhaustion. **Deviation:** the comparison runs while the archive is opened, before any config is known (the open already read one local header per entry without a count bound, so the comparison adds a constant factor and no new vector). The raw record count is checked against `max_file_count` at the start of every operation, whatever the policy, and no operation does further work past it | must |
| FR-013 | THE SYSTEM SHALL document the policy, its default, and the false-positive trade-off in the public API docs of the new enum and builder method, and in the `exarch-cli` skill under `skills/` | must |
| FR-014 | THE SYSTEM SHOULD keep the check on the shared ZIP open path so `extract`, `list` and `verify` cannot diverge (single enforcement point, DRY) | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Enabling Enforce SHALL NOT regress ZIP extraction throughput by more than 10% on the `exarch-core/benches/extraction.rs` ZIP groups (`many_small_files`, `large_files`, `nested_directories`) versus the previous recorded baseline in `.local/testing/benchmarks.md`; a larger regression requires `rust-performance-engineer` review per the constitution |
| NFR-002 | Performance | The added cost for `list` and `verify` SHALL be measured and recorded (these paths do not otherwise read LFHs, so the check adds roughly one extra seek plus one small read per entry); see the cost question in section 9 |
| NFR-003 | Security | Validation SHALL complete before any destination write; a rejected archive leaves the destination untouched |
| NFR-004 | Security | New `ArchiveError` / `IssueCategory` variants are typed enums; no stringly-typed policy or mismatch-kind discriminators |
| NFR-005 | Safety | No `unsafe` code; `deny(unwrap_used)` and `deny(expect_used)` remain satisfied |
| NFR-006 | API stability | The new config field, enum, error variant(s) and issue category variant(s) are public API changes; document in `CHANGELOG.md` under `[Unreleased]` (pre-1.0.0, no deprecation window); if the default is Enforce this is also a behavior change for existing callers and must be called out as such |
| NFR-007 | Compatibility | A compatibility corpus of legitimate ZIPs produced by common tools must pass under the default policy (see section 7, SC-004) |
| NFR-008 | Documentation | Every new `pub` item has a `///` doc comment with runnable `# Examples` for non-trivial APIs; docs build with `RUSTDOCFLAGS="-D warnings"` |
| NFR-009 | Dependencies | No new dependency for the structural checks; the work uses the already-locked `zip` 9.0.5 API. The constitution's Technology Stack line still lists `zip` 9.0.0-pre2 and should be refreshed when this lands. The same change adds `unicode-normalization` as a macOS-only dependency for the name folding of #654 |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `HeaderConsistencyPolicy` (working name) | Two-state, `Copy` policy enum on `SecurityConfig` (and `SecurityConfigFields`); `Enforce` runs the checks, `Ignore` preserves current behavior | Variants `Enforce`, `Ignore`; default per decision in section 9; plain data, no validation state of its own |
| `HeaderInconsistencyKind` (working name) | Typed enum naming what disagreed or was structurally invalid | `NameMismatch`, `UnicodePathMismatch`, `CompressionMethodMismatch`, `EncryptionFlagMismatch`, `DataDescriptorFlagMismatch`, `ModifiedTimeMismatch`, `DataDescriptorMismatch`, `DuplicateName`, `OverlappingEntries`; `#[non_exhaustive]`; exact set follows what the crate can report distinguishably (plan phase) |
| `ArchiveError::HeaderInconsistency` (working name) | New error variant returned by `extract`/`list` on rejection | `kind: HeaderInconsistencyKind`, entry index, central-directory name (archive-relative, attacker-controlled, so not redacted per the constitution's redaction rule) |
| `IssueCategory` additions | New `inspection::report::IssueCategory` variant(s) for verify findings (for example `HeaderInconsistency`, `DuplicateEntry`, `OverlappingEntries`; final split in plan) | Display text follows the existing `=> "Title Case"` convention in the `closed_enum` macro |
| `SecurityConfigFields` addition | New public field holding the policy | Default set in `SecurityConfig::default()` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| LFH name differs from CDFH name (reproduction 1) | Enforce: `extract`/`list` return the typed error with `NameMismatch`; `verify` records an issue and continues. Ignore: unchanged behavior |
| Duplicate names (reproduction 2) | Enforce: error / issue with `DuplicateName`. All policies: `verify` reports total entries = 2 |
| Overlapping entry data ranges | Enforce: error / issue with `OverlappingEntries` |
| Legitimate archive whose LFH mtime differs from CDFH mtime (some producers write a different timestamp in each header) | Risk of false positive under Enforce; see section 9 default decision and compatibility-corpus gate |
| Legitimate archive using data descriptors where LFH sizes/CRC are zero and the real values appear only in the descriptor and CDFH | Must not be flagged; the descriptor comparison must handle the data-descriptor flag correctly (corpus test) |
| Truncated archive where an LFH cannot be read | Existing `InvalidArchive` path; not reclassified as an inconsistency |
| Central directory with more entries than `max_file_count` | Rejected by the quota check before the per-entry comparison (FR-012) |
| Encrypted entry | Already rejected at open (`SecurityViolation`); the encryption-flag mismatch check applies only to archives that get past that |
| Empty archive / directory-only archive | Passes under both policies |
| Binding receives a future error/issue variant it does not know | Generic fallback arm, per FR-011 |
| `verify` under Ignore on an inconsistent archive | No inconsistency issues are raised (policy is explicit), but the true entry count is still reported (FR-006) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Reproduction 1 (name mismatch) under Enforce | `extract` and `list` error with `NameMismatch`; `verify` reports the issue and a non-PASS status; no file written. Covered by a regression test that builds the fixture in test code |
| SC-002 | Reproduction 2 (duplicate names) under Enforce | `verify` reports total entries = 2 plus a `DuplicateName` issue; `extract` rejects; regression test builds the fixture in test code |
| SC-003 | Same two reproductions under Ignore | No new rejection; `verify` still reports 2 entries for the duplicate archive |
| SC-004 | Compatibility corpus | Zero false positives under the default policy on a corpus of legitimate ZIPs from common producers (Info-ZIP `zip`, Python `zipfile`, Java `jar`/`java.util.zip`, `zip` crate with and without data descriptors, Windows Explorer, macOS Archive Utility); the corpus lives in the repo as test data or is generated in test code. Any producer that fails drives the default decision |
| SC-005 | Live test via CLI | Scenario recorded in the live-test plan: build both crafted archives, run `exarch list`, `verify`, `extract` (text and `--json`) under default, Enforce and Ignore; verify exit codes, messages, and that nothing is written on rejection. Also covers a clean-archive round trip (create then extract then verify) |
| SC-006 | Fuzz coverage | `fuzz/fuzz_targets/zip.rs` (and `extract_archive.rs`) exercise both policies; no new crash or timeout in a bounded campaign; header-corruption seeds added to the corpus |
| SC-007 | Extraction performance | Regression of at most 10% on the ZIP extraction benchmark groups with Enforce enabled, compared against the last recorded baseline |
| SC-008 | `list`/`verify` overhead | Measured and recorded in `.local/testing/benchmarks.md` for a 10,000-entry archive; if above 10% it is escalated for review and the finding is documented, not silently accepted |
| SC-009 | Binding parity | The policy and the new error/issue variants are exercised in CLI tests, `pytest` and `npm test`, with matching behavior for the same crafted archives |

## 8. Agent Boundaries

### Always (without asking)
- Keep all consistency logic in `exarch-core`; bindings only map types and convert errors
- Build crafted ZIP fixtures in test code (no checked-in malicious binaries unless generated by a script in the repo)
- Run `rust-security-maintenance` after any change, and live-test the critical paths (ZIP compression-ratio detection, archive-creation round trip) per the continuous-improvement rules
- Update `CHANGELOG.md` under `[Unreleased]` and the `exarch-cli` skill in the same change; verify the skill's claims against the running binary
- Use typed enums for the policy, mismatch kind and issue category; add wildcard arms in bindings for `#[non_exhaustive]` enums

### Ask First
- Choosing the final default policy if the compatibility corpus contradicts the recommendation in section 9
- Relaxing individual checks (for example tolerating mtime differences) to fix a false positive, since that reopens part of the cloaking surface
- Any new dependency, or any change to the locked `zip` version
- Changing the semantics of duplicate-name extraction under Ignore (today: last entry wins)

### Never
- Represent the policy as a `bool`, string or untyped option anywhere
- Put validation logic in `exarch-python`, `exarch-node` or `exarch-cli`
- Write any file to the destination before header validation has completed
- File a public issue or PR text describing a working exploit beyond what is needed to reproduce; this is P2 hardening, but keep fixtures minimal
- Bundle a workspace version bump into this change (releases are a separate commit)

## 9. Open Questions

> [!question] Default policy
> **Resolved: Enforce by default, including `SecurityConfig::permissive()`.** The compatibility corpus (SC-004) showed no false positives from the producers that could be tested (Info-ZIP, ditto, 7-Zip, bsdtar, Go, Python, the `zip` crate); Java (`jar`, `java.util.zip`) and Windows (`Compress-Archive`, .NET `ZipFile`) archives are generated and checked at test time in CI, while Windows Explorer and WinRAR archives are not covered. Original question: should the default be strict (Enforce) or opt-in (Ignore)?
>
> **Recommendation: Enforce by default, with a documented typed opt-out (Ignore).**
>
> | Option | For | Against |
> |--------|-----|---------|
> | Enforce by default | Matches the constitution's deny-by-default stance (section V); matches CPython's behavior, which already rejects name mismatches; makes `verify` and `list` trustworthy as gates without every caller knowing to opt in; the issue is exactly the silent-acceptance case | Behavior change for existing callers; possible false positives on archives from producers that write different mtimes in LFH and CDFH or mishandle data descriptors |
> | Ignore by default (opt-in) | No behavior change; zero false-positive risk | Insecure by default; the inconsistency stays invisible to everyone who does not read the docs; contradicts deny-by-default |
>
> Justification: the checks that matter for cloaking (name, UnicodePath, compression method, encryption flag, duplicates, overlap) have essentially no legitimate reason to differ, so the false-positive risk concentrates in the modification-time and data-descriptor comparisons. The recommendation is Enforce by default, gated on the compatibility corpus (SC-004). If the corpus shows legitimate producers failing only on mtime or data-descriptor fields, the fallback is to keep Enforce as the default and treat those specific mismatch kinds as non-fatal for the default path (an explicit, documented relaxation, listed under Ask First), not to flip the default to Ignore.

> [!question] Per-check granularity
> **Resolved:** the crate reports one opaque `InvalidArchive` error per failed check; exarch classifies it by the fixed message prefix into `ZipHeaderField`, and a message it does not recognise becomes `Unrecognized` (rejection never depends on the classification). One test per field pins the locked crate's wording. Original question: can the `zip` 9.0.5 API distinguish which check failed (needed for the typed `HeaderInconsistencyKind` and for relaxing mtime only), or does it return a single opaque error? If opaque, decide between a coarser kind enum and a small exarch-side comparison. Resolve in the plan phase before committing to the variant list in section 5.]

> [!question] Validation strategy and cost
> **Resolved:** per-entry enforcement while the archive is opened, so `extract`, `list` and `verify` share one pass (FR-014); costs are recorded in `.local/testing/benchmarks.md`. Original question: whole-archive `validate_header_consistency()` at open versus per-entry `enforce_header_consistency` while iterating. Extraction already reads each LFH to locate entry data, so per-entry enforcement adds mostly comparison cost; `list` and `verify` do not touch LFHs today, so they gain roughly one seek and a small read per entry (about 10,000 extra seeks for a 10,000-entry archive, which may be noticeable on network or cold storage). Decide in the plan phase using the benchmark numbers from SC-007 and SC-008, and whether `list` should validate at all or only report from the central directory plus a cheaper structural check.]

> [!question] Duplicate semantics under Ignore
> **Resolved:** see FR-007. Original question: see FR-007. Establish where the 1-entry undercount originates, and decide whether Ignore keeps "last entry wins" extraction or listing shows all entries while extraction behavior is unchanged.]

> [!question] Exact policy and enum naming
> **Resolved:** `ZipConsistencyPolicy { Enforce, Ignore }`, `SecurityConfig::with_zip_consistency`, CLI `--zip-consistency <enforce|ignore>`, Python `with_zip_consistency("enforce" | "ignore")`, Node `setZipConsistency`, error `ArchiveError::ZipInconsistency(ZipInconsistency)`. Original question: final names for the policy enum, the `SecurityConfig` builder method, the CLI flag and the Python/Node surface; align with the naming conventions already used for typed enums in the bindings.]

## 10. See Also

- [[constitution]] — project principles (deny-by-default, verify reports issues rather than propagating errors, immutable typestate config, performance gate)
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — the validation pipeline this check complements
- [[002-format-handlers/spec]] — ZIP handler
- [[014-config-typestate-validation/spec]] — typestate pattern the new config field follows
- [[016-sanitized-mode-and-non-exhaustive-enums/spec]] — `#[non_exhaustive]` and wildcard-arm convention for new error and issue variants
- [[005-cli/spec]], [[006-python-bindings/spec]], [[007-node-bindings/spec]] — mapping layers
- Related issues: #623 (verify has no real integrity check), #599, #624 (honest verify status, shipped); related, not duplicated by this spec
- Code: `crates/exarch-core/src/formats/zip.rs` (`ZipArchive::new`), `crates/exarch-core/src/inspection/list.rs` (`list_zip_reader`), `crates/exarch-core/src/inspection/verify.rs`, `crates/exarch-core/src/inspection/report.rs` (`IssueCategory`), `crates/exarch-core/src/config.rs`, `fuzz/fuzz_targets/zip.rs`, `crates/exarch-core/benches/extraction.rs`
- zip2 advisory GHSA-m665-v7pm-7grj ("Zip Cloaking", published 2026-10-17; fixed by opt-in header-consistency validation in `zip` 9.0.5)
- CPython `Lib/zipfile/__init__.py`: `_RealGetContents` and `ZipFile.open` (central/local file-name mismatch check raising `BadZipFile`)
- CWE-436: Interpretation Conflict

## 11. Implementation Notes

- **Census.** Opening runs the crate's header check on every entry, walks the raw central directory from its start (duplicate records, records beyond the end record's count), looks for local headers in the stub before the archive and the gaps around entry data, looks for end records the crate rejected, and compares the raw directory with the crate's map, which must describe the same directory (the archive is parsed once). Any disagreement fails closed as `InvalidArchive`.
- **Findings.** `ZipInconsistency::{HeaderMismatch, DuplicateName, OverlappingEntries, HiddenLocalHeader, StrayCentralRecord, StrayEndRecord, DescriptorOverrun, XlTypeDivergence, UncountedCentralRecords, IgnoredEndRecord}`; verify categories `Header Mismatch`, `Duplicate Entry`, `Overlapping Entries`, `Hidden Entry`. Findings are kept up to a limit per kind (24 header mismatches, 16 duplicate names, 16 hidden headers, 16 stray central records, 16 stray end records, 16 descriptor overruns, 16 xl type divergences, one overlap, one uncounted-records finding, one ignored end record: 123 in all); the rest are counted and reported as a note, and the search for hidden headers stops at the first one past its limit.
- **Policy.** `Enforce` rejects in `extract` and `list` and reports in `verify`; `Ignore` raises no structural finding. An entry whose local header cannot be parsed fails closed under `Enforce` (`ZipHeaderField::Unparseable`); under `Ignore` it is still admitted through the normal size and method checks.
- **Entry count.** `verify` reports the raw central directory count. A raw count over `max_file_count` is a `QuotaExceeded` error from `extract`, `list` and `verify`, whatever the policy.
- **Behaviour changes.** Pre-ZIP64 archives with more than 65535 entries (wrapped end-record count) and archives with orphaned local headers, or with a central directory signature in a gap before an entry (left by in-place updaters), are rejected under `Enforce` (#680). With duplicate names the local headers are not compared with the central directory.
- **Hidden headers.** The bytes before the first entry, between entries and before the directory are searched for local header signatures (a plausible header needs a name and must fit before the directory), so a header behind padding is found. The bytes before the first entry get the same lenient judge when the file starts with `PK` (a header at offset 0, or a `PK00` marker that streaming readers skip to the next header); a prefix that starts with anything else is a stub and gets the strict judge described under the residuals, except that a header exactly at offset 0 is always judged leniently. Contiguous archives cost no gap read; the type check (#686) reads each central record and each local header once, in directory and file order, through the same window. With duplicate names the gaps are not searched.
- **Residuals, not covered:** (D4) a descriptor, local header and data hidden inside the declared compressed range of a data-descriptor entry, which streaming readers such as `bsdtar` extract and `zip` ignores. For a stored entry it is detected by plain `verify`, `list` and `extract` (#687): the census models where a streaming reader resumes inside the declared range by scanning it for the first descriptor signature and searching the bytes from there to the declared end like any other gap (hidden local headers, reported as `HiddenLocalHeader { region: DescriptorTail }`, and stray central or end record signatures; `formats::zip_tail::scan`, a bounded chunked scan that reads each declared byte once and is not counted in the gap read budget). A ZIP-based file (a JAR or an ODF package, for example) stored whole in an entry that a streaming writer gave a data descriptor is an accepted false positive, since a streaming reader misreads it as well; `--zip-consistency ignore` accepts such archives. For a compressed entry (deflate, bzip2, zstd) it is detected with `--check-integrity` only (`formats::zip_tail` decodes the entry, finds the end of its compressed stream and searches the rest of the declared range for a local header; a zstd tail that is not a skippable frame already fails the entry's own decode), only under the enforcing zip consistency policy; plain `verify`, `list` and `extract` do not see it, since telling where a compressed stream ends takes decoding; a tail that cannot be decided (budget, a raw decode that disagrees with the crate's, such as extra zstd frames) is counted as unverified under its own reason `descriptor_tail`, and listed by path although the entry's own payload may have been verified (#679). A central directory signature (`PK\x01\x02`) before an entry is reported as `StrayCentralRecord { offset }` (#680), because a streaming reader such as `bsdtar` stops listing there and never reaches the entries behind it. The signature alone is the finding, with no check of the record's fields, since the reader reads none: it is searched in every gap before an entry (including the bytes between a data descriptor, as a streaming reader consumes it, and the next header) and, when the file starts with `PK`, in the prefix. The gap behind the last entry hides nothing and is not searched for it, except in a prefixed archive: there the stretch from the end record's directory offset to the directory the `zip` crate uses is searched, and a central or end record signature in it is reported as `StrayCentralRecord` or `StrayEndRecord`, because readers up to `zip` 9.0.5 take the first central record from that offset (a decoy directory). Residual: a decoy inside the declared data range of the last entry is not a gap and is not scanned. An end of central directory record (`PK\x05\x06`) or ZIP64 end record (`PK\x06\x06`) in a gap or in a `PK`-led prefix stops such a reader the same way and is reported as `StrayEndRecord { offset, kind }` (#682); a ZIP64 locator (`PK\x06\x07`) and a descriptor signature (`PK\x07\x08`) do not stop it and are not searched. Residual: the strict stub prefix (a file that does not start with `PK`). The retention limits for stray central and end records (16 each) also end the search for hidden local headers, as the limit for hidden headers ends the search for stray records. A local header with an empty name counts as hidden when its compressed size is not zero, because the reader skips that many bytes after it (the judge used to require a name). The stub before the first entry is scanned with a stricter judge than the gaps (version needed at most 63, no reserved flag bits, known method, name without NUL, header and data inside the stub), so a self-extractor that embeds the signature as code is not flagged, whether its offsets were rewritten (`zip -A`) or not (a stub that embeds a complete ZIP resource is still reported as a hidden entry, in both the old and the new check); a hidden entry that fails that judge inside a stub is not reported. A local header exactly at offset 0 is judged like one in a gap, since a stub never starts with one. An end record the `zip` crate rejected before the one it used is reported (`IgnoredEndRecord`); the used record is identified by its comment and directory offset (through the ZIP64 records when the 32-bit field holds the escape value) within the crate's own search range, and an archive whose used record cannot be identified is reported when it holds more than one candidate. ZIP64 directory entries written by the `zip` crate before 9.1.0 are rejected by the crate's header check; 9.1.0 writes consistent sizes (#667). Only archives from Info-ZIP, `ditto`, 7-Zip, `bsdtar`, Go and Python were tested for false positives locally, and Java and Windows (`Compress-Archive`, .NET `ZipFile`) archives are generated and checked in CI; Windows Explorer and WinRAR archives are not covered.
- **Modeled reader (#683).** The bytes after a data-descriptor entry's data are searched from the end of the data, so the descriptor's own bytes are covered, and the position where a streaming reader resumes is modeled on libarchive 3.7 (`bsdtar`), in both modes: extraction ends a deflated entry where its stream ends and then consumes the descriptor by matching the layouts 24, 20, 16 and 12 bytes (in that order) against the entry's sizes, the CRC being a wildcard; listing resumes at the end of the data for a deflated entry (or after the local compressed size when one is given, resolved through the ZIP64 extra field as the reader does) and, for every other method, scans for `PK\x07\x08` and consumes 16 bytes, or 24 when the local header has a ZIP64 extra field, with no signature meaning an unbounded scan; a local compressed size greater than zero is skipped for every method, after resolving a 32-bit escape through the ZIP64 extra field (uncompressed size first, each only when its field holds the escape), while extraction ends a non-deflated entry only at a signed descriptor, so a stored entry without a descriptor signature is unbounded whatever its local size. Safety against a spanning local size rests on `HeaderMismatch` (without duplicate names) and on the overrun check (with them). The furthest position wins. `DescriptorOverrun { entry, offset }` is reported when it lies past the next header or the directory (`Hidden Entry`, #683). The model reads the central directory sizes, so plain `verify` cannot wildcard them. Java's `ZipInputStream` misreads end in a size or CRC exception, so they are loud and not modeled. Accepted false positive (M1): a descriptor field equal to a stop or local header signature (a compressed size of `PK\x05\x06`, a size of `0x04034B50`) is reported like any signature in a gap, as is a stored entry whose descriptor carries no signature, which `bsdtar` cannot extract. The resume model starts from the end of the declared data; for a stored entry the declared range is also searched from its first descriptor signature on (D4, #687), while the end of a compressed stream inside the declared range is left to `--check-integrity`. The producers checked for false positives now include Go (stored and deflated), Python's unseekable writer (stored, deflated, ZIP64), `bsdtar` and Info-ZIP streaming to a pipe and `7z -so` (`scripts/zip-corpus.sh`).
- **Xl type (#686).** The `zip` crate takes an entry's type only from the external attributes of the central record, while libarchive honours the experimental `xl` (`0x6c78`) extra field, which repeats them (a feature bitmap, then optional version-made-by, internal and external attributes): a streaming reader (`bsdtar` reading a real pipe) reads it from the local header, a seekable one (`bsdtar` on a file, and also `bsdtar -f - < file`, whose input is still seekable) from the central record and then the local header, the later field overriding. The local comparison does not depend on the central record: a central block the model cannot use counts as having no `xl` field. The census parses the field as the reader does (the host system starts as the high byte of the header's version field and a version-made-by in the field replaces it; Unix hosts take the type bits of the external attributes, DOS hosts only the directory bit, and a read-only DOS directory reads as a file because the reader's permission mask clears the type; other hosts no type; an extra field whose length overruns the block makes the reader drop the header, so nothing is taken from it) and compares the resulting type (regular file, directory, symlink or special) with the one the extraction gives from the central attributes and name. A difference is `ZipInconsistency::XlTypeDivergence { entry, offset }` (`Hidden Entry`, #686), so an archive that `bsdtar` extracts or lists as a symlink or directory while the central attributes say regular file (and the reverse) is rejected under `Enforce` and failed by `verify`, with and without `--check-integrity`; verified live with a local `xl` and with a central `xl`, `bsdtar` 3.5.3 on files. The directory decision uses the reader's final name: a Unicode Path extra field whose CRC-32 matches replaces the name, and a DOS host's backslashes become slashes when the name has none. Only entries with an `xl` field carrying external attributes are compared: without one a streaming reader reads every entry as a regular file or directory, so every symlink written by common producers would differ. Accepted limitations, all of which can only add findings: a header the reader rejects for a reason other than an overrunning extra field (malformed ZIP64 or AES field, an unknown 1-3 byte extra block) is still compared; a mode with an unassigned type is compared as a special type although the reader writes a regular file; the name CRC is taken over the raw bytes, which is the reader's name on POSIX but may differ from the converted name of a libarchive that converts names to a locale (Windows). The check needs no data descriptor and also covers entries that have one.
- **Single parse.** The archive is parsed once through a shared reader handle, so admission and every later operation use the same directory.
- **Cost (#662).** The shared handle serves short reads from a 32 KiB window (reads of 4 KiB or more bypass it), because header parsing issued several system calls per entry on an unbuffered file, and an archive that the crate validates in one pass is admitted from raw entries instead of one decoder per entry. On a 10000-entry deflate archive (release build, hyperfine, 40 runs) `list` takes 15 ms against 36 ms before the checks (#637) and `verify` 29 ms against 49 ms; the type check (#686) adds 0.2 ms to `list` (15.2 to 15.4 ms) and 0.8 ms to `verify` (28.8 to 29.6 ms) on a 10000-entry archive of `zipfile`-written deflate entries; extraction of an 80 MB archive is not slower. The type check is unmetered by the gap read budget: per record it reads the fixed part, the extra field and, only when an `xl` field gives a type, the name (about 128 KiB at worst, the same as the crate's own header check per entry); entries that share one local header read it once, and the total is bounded by the distinct headers and central records (tested with 2000 records on one header with a 60 KiB name). The target of staying within 10% of the old baseline is met, so no upstream accessor is needed (follow-up F4 not required). The in-data descriptor scan of stored data-descriptor entries (#687) reads each such entry's declared range once, so its cost is linear in the stored bytes and zero for other archives: on 10000-entry `zipfile`-written archives (release build, hyperfine, 60 runs, the same tree with the scan disabled against enabled) deflate entries are unchanged (`list` 16.2 to 16.3 ms, `verify` 30.3 to 30.2 ms), deflate entries with descriptors are unchanged (`list` 17.3 to 17.3 ms, `verify` 31.2 to 31.2 ms), and 256-byte stored entries with descriptors cost 1.6 ms more in `list` (14.8 to 16.4 ms, 11%) and 1.5 ms more in `verify` (28.9 to 30.4 ms, 5%), the price of one seek and one read of the entry's payload: the cost is linear in the stored payload, and the fixture's 256-byte entries make the scan dominate the otherwise small per-entry work, so the relative figure shrinks as entries grow; the `zip_inspection` benchmark carries the stored-descriptor shape (`stored_descriptor_open_and_list`, `stored_descriptor_open_and_verify`).
- **#654 / #655.** Names fold through NFD plus a per-character case fold on macOS and the case fold alone on Windows; names that differ exactly but fold equal are a `Name Collision` issue. The symlink hop limit is a per-OS constant checked against `canonicalize`. Name limits are per-OS constants (component 255; path 4095 on Linux, 1023 on macOS and other Unix, 32767 UTF-16 units on Windows), and a symlink target is checked against its own limit (the crate-internal `MAX_SYMLINK_TARGET_LEN`: the path limit on Unix, 4091 UTF-16 units on Windows, from the 16 KiB reparse buffer that holds the substitute and print names of a relative target; absolute targets are never created; the byte cap for a target read from an archive is `MAX_SYMLINK_TARGET_BYTES`, three bytes per unit on Windows). Entry paths over them are rejected by `list` and, in the verify pre-flight, dropped from the manifest and recorded as `OversizedEntry { index, bytes }`, one `HIGH` archive issue each, and with `--check-integrity` also counted as unverified with the reason `path_too_long` (#678). Link targets over the host's limits are kept as their length only (`LinkTarget::Oversized`), rejected by `list` and reported by `verify`.
