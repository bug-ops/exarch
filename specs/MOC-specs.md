---
aliases:
  - Specifications Index
  - Specs Overview
tags:
  - moc
  - sdd
created: 2026-05-20
updated: 2026-11-25
status: moc
---

# Specifications

> [!abstract]
> Map of Content for all project specifications. Each entry links to
> a feature spec with its current phase and status.

## Active Specs

| ID | Feature | Phase | Status | Tasks |
|----|---------|-------|--------|-------|
| 001 | [[001-security-pipeline/spec\|Security Pipeline]] | tasks | current (synced through #1186; selection screening, 7z header size and Windows handle-relative links added; typed occupant refusals, #1181, #1183; trailing-separator landing, #1186; synced through #1216: #1204 directory over an escaping symlink, #1215 long landing, #1216 run record in every mode; synced for the #1230 batch: #1230 escaping parent is `SYMLINK_ESCAPE` in every format, #1232 Windows leaf deferral; synced through #1372: #1305 sticky bit cleared, #1307 list reports ZIP and 7z special bits (FR-061), #1308 permission policy on extract (FR-060), #1340 `AdmittedSize` ceiling, #1348 banned components on resolved locations (FR-059)) | [[001-security-pipeline/tasks\|none open]] |
| 002 | [[002-format-handlers/spec\|Format Handlers]] | tasks | current (synced through #1024; #1070 crate-wide index gate, #1071, #1072; sevenz-rust2 0.25, 7z header limit #674, #769, BSD and macOS spool #959; synced through #1372: #1296 7z mode restore (FR-078), #1297 TAR volume label (FR-079), #1287 PAX mtime in list (FR-080), #1298 typed unsupported typeflag, #1349 opt-in GNU sparse expansion (FR-081 to FR-084), #1342 zip-drift floor job (FR-064a)) | [[002-format-handlers/tasks\|none open]] |
| 003 | [[003-config-api/spec\|Configuration API]] | tasks | current (synced through #1184; #1157 Replaceable matrix, #1159, #1161, #1154; #1163, #1168, #1169; #1183 occupant kinds and `by`, #1184 caller destination; synced through #1216: #1198 `OccupiedPaths`, #1197 `DestinationStep` tokens, #1203, #1204, #1206; synced for the #1230 batch: #1201, #1023, #1027 config surface; synced through #1372: #1308 `permissions` governs extraction (FR-061), #1339 umask refusal and staging cleanup (FR-036, FR-076), #1349 `tar_sparse` (FR-077)) | [[003-config-api/tasks\|none]] |
| 004 | [[004-progress-tracking/spec\|Progress Tracking]] | tasks | current (synced through #1024) | [[004-progress-tracking/tasks\|none]] |
| 005 | [[005-cli/spec\|CLI]] | tasks | current (synced through #1184; #1157 and #1154 hints, #1158 mark tokens, #1161; #1183 `conflicts` objects and `by`, #1165 mark warning; synced through #1216: #1196 occupant wording, #1197 `error.step`, #1203, #1204; synced for the #1230 batch: #1201, #1025, #1023, #1027, #1231 flags; synced through #1372: #1349 `--tar-sparse` (FR-152) and its hint, #1308 `--preserve-permissions` meaning (FR-063)) | [[005-cli/tasks\|none open]] |
| 006 | [[006-python-bindings/spec\|Python Bindings]] | tasks | current (synced through #1184; #1154 by, #1159, #1160 properties, #1161; #1183 `OccupiedPath`; synced through #1216: #1207 pickling, #1211 stubtest, #1197 `step`; synced for the #1230 batch: #1201, #1023 options; synced for the #1255 batch: #1256 bytes list and verify password; synced through #1372: #1349 `tar_sparse` (FR-125)) | [[006-python-bindings/tasks\|none]] |
| 007 | [[007-node-bindings/spec\|Node.js Bindings]] | tasks | current (synced through #1184; #1154 by, #1159, #1158, #1161; #1183 `OccupiedPath`; synced through #1216: #1200 committed loader, #1208 package gate, #1197 `step`; synced for the #1230 batch: #1201, #1023, #1233, #1234; synced for the #1255 batch: #1256 bytes list and verify password; synced through #1372: #1349 `tarSparse` (FR-136)) | [[007-node-bindings/tasks\|none]] |
| 011 | [[011-ffi-panic-boundary-simplification/spec\|FFI Panic Boundary Simplification]] | specify | draft (research, P3) | n/a (specify-only) |
| 012 | [[012-windows-reserved-device-names/spec\|Windows Reserved Device Name Validation]] | specify | implemented (0.7.0, #652; extended in 0.8.0, #780, #790; extended: #1364 `ShortNameAlias` for alternate 8.3 spellings of existing entries (FR-007)) | [[012-windows-reserved-device-names/tasks\|not started]] |
| 013 | [[013-quota-permit-capability-token/spec\|Quota Permit Capability Token]] | tasks | current (synced through #1024; synced through #1372: #1340 `AdmittedSize` copy ceiling, `into_bytes` removed (FR-012)) | [[013-quota-permit-capability-token/tasks\|none open]] |
| 015 | [[015-atomic-force-destination-swap-hardening/spec\|Atomic-Force Destination Swap Hardening]] | tasks | current (synced through #1024; #1067 staged children inherit the destination ACL; #1079, #1078 ACL after the rename and private macOS stage; #1117, #1122, #1121 Windows DACL copy; #1119, #1088, #1085, #1083, #1068, #1087; #1145 observed NetBSD and illumos results; #1152 total ACL read on FAT and exFAT; synced through #1372: #1311, #1325, #1341 owner-bit recovery of the stage under an owner-restricting umask (FR-111)) | [[015-atomic-force-destination-swap-hardening/tasks\|none open]] |
| 016 | [[016-sanitized-mode-and-non-exhaustive-enums/spec\|SanitizedMode Newtype and Non-Exhaustive Enum Hardening]] | specify | implemented (v0.6.1, #554) | n/a (specify-only, retrospective) |
| 017 | [[017-zip-header-consistency/spec\|ZIP Header Consistency Validation]] | specify | implemented (0.7.0, #671, #684, #688, #689, #690; extended in 0.9.0, #821, #827, #837, #848; synced through #1372: #1306 `ZipEntryIndex` in the ZIP malformations (FR-019)) | n/a (specify-only) |
| 018 | [[018-7z-stream-map-panic/spec\|7z Stream Map Validation]] | specify | implemented (0.7.0, #752; narrowed in 0.8.0, #751, #770) | n/a (specify-only) |
| 019 | [[019-verify-and-list-model/spec\|Verify and List Reporting Model]] | specify | implemented (0.7.0, retrospective; updated for 0.8.0 and 0.9.0; destination volume probe, #1144; deferred hardlink leaf rule, #1153; `DestinationNotAccessible`, #1161; synced through #1205, typed list-model occupant refusal, Medium for a directory over an archive file; synced for the #1230 batch: #1201 repeat under `Refuse`, #1023 `encrypted` reason; synced through #1372: #1307 special mode bits judged alike in TAR, ZIP and 7z (FR-017), #1349 sparse entries skipped in list and verify (FR-068)) | n/a (specify-only, retrospective) |
| 020 | [[020-reader-sink-and-in-memory-api/spec\|Reader, Sink and In-Memory API]] | specify | implemented (0.8.0, #771, #787, #790, #808; callback and listing for extraction in 0.9.0, #842, #860, #884; request types, admitted sizes and listed config in 0.9.0, #912, #909, #901; sink hardlink refusals, #1154, #1159; synced through #1183, typed sink occupant refusal; synced for the #1255 batch: #1256 `with_password(Option)` on every request) | n/a (specify-only, retrospective) |
| 021 | [[021-create-staging-and-output-policy/spec\|Create Staging and Output Policy]] | specify | implemented (0.9.0, #931, #915, #916; typed source errors and durability, #956, #953, #961; synced for the #1230 batch: #1027 parallel ZIP creation; synced for the #1255 batch: #1255 link policy resolved at walk time; synced through #1372: #1292 one classifier for named and walked sources (FR-056), #1288 size re-check on the opened handle (FR-057)) | n/a (specify-only) |
| 022 | [[022-extract-entry-selection/spec\|Extract Entry Selection and Path Stripping]] | tasks | implemented (#967, #981 batch; grammar replaced by globs in #1024, see 023; synced through #1167; synced for the #1230 batch: #1201 Q10) | [[022-extract-entry-selection/tasks\|22 done]] |
| 023 | [[023-entry-selection-glob-patterns/spec\|Glob Patterns for Entry Selection and Create Excludes]] | specify | implemented (#1024, closes #1000; supersedes 021 FR-019 to FR-021) | n/a (specify-only) |
| 024 | [[024-encrypted-archive-support/spec\|Encrypted Archive Support]] | tasks | implemented (#1001, #1023, unreleased; rpassword, direct zeroize, no `max_kdf_work` CLI flag, `Violation::Encrypted` with machine-readable `reason`; deviations recorded in section 9; synced for the #1255 batch: #1261 selection without password, #1248 verify classification, #1262 encrypted header limits, #1256, #1264; synced through #1372: #1289 one AES key-verdict rule for extract and verify (FR-043), #1351 and #1352 per-operation 7z keys replace the key slot and turn (FR-044 to FR-047), #1363 header prefetch before key derivation) | n/a (batch PR) |
| 025 | [[025-cli-landlock-sandbox/spec\|CLI Landlock Sandbox]] | tasks | implemented (#1025, unreleased; Linux only, opt-in `--sandbox`, `Enforced` from ABI v3, `SandboxNotEnforced`; Linux backend first runs on CI; synced for the #1255 batch: #1259 typed preflight, `rule_path` and optional errno) | [[025-cli-landlock-sandbox/tasks\|6 done]] |
| 026 | [[026-mark-of-the-web-propagation/spec\|Download-Origin Mark Propagation]] | specify | implemented (#1026; opt-in `MarkPropagation`, macOS verified, Windows runs on CI only; `MarkState` tokens, #1158; no-stream volume, #1150; last synced for #1165, `mark_incomplete` JSON warning #1165; synced through #1372: #1308 deferred mode under `Normalize` (FR-007)) | n/a (specify-only) |
| 027 | [[027-zip-parallel-compression/spec\|ZIP Parallel Compression]] | tasks | implemented (#1027, unreleased; byte identity across thread counts, sorted walk and source mtime, `create --threads`; synced for the #1255 batch: #1263 mtime clamp) | [[027-zip-parallel-compression/tasks\|6 done]] |
| 030 | [[030-duplicate-entry-repeated-paths/spec\|Opt-in Refusal of Repeated Archive Paths]] | tasks | implemented (#1201, unreleased; opt-in `RepeatedPaths::Refuse`, default unchanged, fail-closed maker; synced for the #1255 batch: #1258 list agrees with extract and verify) | [[030-duplicate-entry-repeated-paths/tasks\|7 done]] |


## Completed Specs

| ID | Feature | Resolution |
|----|---------|------------|
| 008 | [[008-tar-empty-directory-preservation/spec\|TAR Empty Directory Preservation]] | implemented (#400) — TAR now writes explicit directory entries |
| 009 | [[009-accurate-compression-reporting/spec\|Accurate Compression Reporting]] | implemented (#402) — `bytes_compressed` now measured from real on-disk archive size |

## Obsolete Specs

Kept only until the next release removes them (`status: obsolete`, with `superseded_by` and `obsolete_reason` in the frontmatter).

| ID | Feature | Superseded by |
|----|---------|---------------|
| 014 | [[014-config-typestate-validation/spec\|Config Typestate Validation]] | [[003-config-api/spec]] — the typestate and `validate()` were removed in #898 |

## Archived Specs

- [[001-exarch-system/spec\|exarch System Spec (monolithic)]] — superseded by 001–007 above
- [[001-exarch-system/plan\|exarch Technical Plan (monolithic)]] — reference architecture document

## Project Foundation

- [[constitution]] — non-negotiable project principles
