---
aliases:
  - Specifications Index
  - Specs Overview
tags:
  - moc
  - sdd
created: 2026-05-20
updated: 2026-11-08
status: moc
---

# Specifications

> [!abstract]
> Map of Content for all project specifications. Each entry links to
> a feature spec with its current phase and status.

## Active Specs

| ID | Feature | Phase | Status | Tasks |
|----|---------|-------|--------|-------|
| 001 | [[001-security-pipeline/spec\|Security Pipeline]] | tasks | current (synced through #1024; selection screening, 7z header size and Windows handle-relative links added) | [[001-security-pipeline/tasks\|none open]] |
| 002 | [[002-format-handlers/spec\|Format Handlers]] | tasks | current (synced through #1024; #1070 crate-wide index gate, #1071, #1072; sevenz-rust2 0.25, 7z header limit #674, #769, BSD and macOS spool #959) | [[002-format-handlers/tasks\|none open]] |
| 003 | [[003-config-api/spec\|Configuration API]] | tasks | current (synced through #1024) | [[003-config-api/tasks\|none]] |
| 004 | [[004-progress-tracking/spec\|Progress Tracking]] | tasks | current (synced through #1024) | [[004-progress-tracking/tasks\|none]] |
| 005 | [[005-cli/spec\|CLI]] | tasks | current (synced through #1024) | [[005-cli/tasks\|none open]] |
| 006 | [[006-python-bindings/spec\|Python Bindings]] | tasks | current (synced through #1024) | [[006-python-bindings/tasks\|none]] |
| 007 | [[007-node-bindings/spec\|Node.js Bindings]] | tasks | current (synced through #1024) | [[007-node-bindings/tasks\|none]] |
| 011 | [[011-ffi-panic-boundary-simplification/spec\|FFI Panic Boundary Simplification]] | specify | draft (research, P3) | n/a (specify-only) |
| 012 | [[012-windows-reserved-device-names/spec\|Windows Reserved Device Name Validation]] | specify | implemented (0.7.0, #652; extended in 0.8.0, #780, #790) | [[012-windows-reserved-device-names/tasks\|not started]] |
| 013 | [[013-quota-permit-capability-token/spec\|Quota Permit Capability Token]] | tasks | current (synced through #1024) | [[013-quota-permit-capability-token/tasks\|none open]] |
| 015 | [[015-atomic-force-destination-swap-hardening/spec\|Atomic-Force Destination Swap Hardening]] | tasks | current (synced through #1024; #1067 staged children inherit the destination ACL; #1079, #1078 ACL after the rename and private macOS stage; #1117, #1122, #1121 Windows DACL copy; #1119, #1088, #1085, #1083, #1068, #1087) | [[015-atomic-force-destination-swap-hardening/tasks\|none open]] |
| 016 | [[016-sanitized-mode-and-non-exhaustive-enums/spec\|SanitizedMode Newtype and Non-Exhaustive Enum Hardening]] | specify | implemented (v0.6.1, #554) | n/a (specify-only, retrospective) |
| 017 | [[017-zip-header-consistency/spec\|ZIP Header Consistency Validation]] | specify | implemented (0.7.0, #671, #684, #688, #689, #690; extended in 0.9.0, #821, #827, #837, #848) | n/a (specify-only) |
| 018 | [[018-7z-stream-map-panic/spec\|7z Stream Map Validation]] | specify | implemented (0.7.0, #752; narrowed in 0.8.0, #751, #770) | n/a (specify-only) |
| 019 | [[019-verify-and-list-model/spec\|Verify and List Reporting Model]] | specify | implemented (0.7.0, retrospective; updated for 0.8.0 and 0.9.0) | n/a (specify-only, retrospective) |
| 020 | [[020-reader-sink-and-in-memory-api/spec\|Reader, Sink and In-Memory API]] | specify | implemented (0.8.0, #771, #787, #790, #808; callback and listing for extraction in 0.9.0, #842, #860, #884; request types, admitted sizes and listed config in 0.9.0, #912, #909, #901) | n/a (specify-only, retrospective) |
| 021 | [[021-create-staging-and-output-policy/spec\|Create Staging and Output Policy]] | specify | implemented (0.9.0, #931, #915, #916; typed source errors and durability, #956, #953, #961) | n/a (specify-only) |
| 022 | [[022-extract-entry-selection/spec\|Extract Entry Selection and Path Stripping]] | tasks | implemented (#967, #981 batch; grammar replaced by globs in #1024, see 023) | [[022-extract-entry-selection/tasks\|22 done]] |
| 023 | [[023-entry-selection-glob-patterns/spec\|Glob Patterns for Entry Selection and Create Excludes]] | specify | implemented (#1024, closes #1000; supersedes 021 FR-019 to FR-021) | n/a (specify-only) |
| 024 | [[024-encrypted-archive-support/spec\|Encrypted Archive Support]] | specify | draft (#1001; encrypted archives are still refused with `SECURITY_VIOLATION` / `ENCRYPTED`; implementation-ready only after the Ask First items in section 9 are resolved) | n/a (specify-only) |

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
