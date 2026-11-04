---
aliases:
  - Specifications Index
  - Specs Overview
tags:
  - moc
  - sdd
created: 2026-05-20
updated: 2026-11-04
status: moc
---

# Specifications

> [!abstract]
> Map of Content for all project specifications. Each entry links to
> a feature spec with its current phase and status.

## Active Specs

| ID | Feature | Phase | Status | Tasks |
|----|---------|-------|--------|-------|
| 001 | [[001-security-pipeline/spec\|Security Pipeline]] | tasks | current (synced through #946) | [[001-security-pipeline/tasks\|none open]] |
| 002 | [[002-format-handlers/spec\|Format Handlers]] | tasks | current (synced through #946) | [[002-format-handlers/tasks\|none open]] |
| 003 | [[003-config-api/spec\|Configuration API]] | tasks | current (synced through #946) | [[003-config-api/tasks\|none]] |
| 004 | [[004-progress-tracking/spec\|Progress Tracking]] | tasks | current (synced through #946) | [[004-progress-tracking/tasks\|none]] |
| 005 | [[005-cli/spec\|CLI]] | tasks | current (synced through #946) | [[005-cli/tasks\|none open]] |
| 006 | [[006-python-bindings/spec\|Python Bindings]] | tasks | current (synced through #946) | [[006-python-bindings/tasks\|none]] |
| 007 | [[007-node-bindings/spec\|Node.js Bindings]] | tasks | current (synced through #946) | [[007-node-bindings/tasks\|none]] |
| 011 | [[011-ffi-panic-boundary-simplification/spec\|FFI Panic Boundary Simplification]] | specify | draft (research, P3) | n/a (specify-only) |
| 012 | [[012-windows-reserved-device-names/spec\|Windows Reserved Device Name Validation]] | specify | implemented (0.7.0, #652; extended in 0.8.0, #780, #790) | [[012-windows-reserved-device-names/tasks\|not started]] |
| 013 | [[013-quota-permit-capability-token/spec\|Quota Permit Capability Token]] | tasks | current (synced through #946) | [[013-quota-permit-capability-token/tasks\|none open]] |
| 014 | [[014-config-typestate-validation/spec\|Config Typestate Validation]] | tasks | current (synced through #946) | [[014-config-typestate-validation/tasks\|none open]] |
| 015 | [[015-atomic-force-destination-swap-hardening/spec\|Atomic-Force Destination Swap Hardening]] | tasks | current (synced through #946) | [[015-atomic-force-destination-swap-hardening/tasks\|none open]] |
| 016 | [[016-sanitized-mode-and-non-exhaustive-enums/spec\|SanitizedMode Newtype and Non-Exhaustive Enum Hardening]] | specify | implemented (v0.6.1, #554) | n/a (specify-only, retrospective) |
| 017 | [[017-zip-header-consistency/spec\|ZIP Header Consistency Validation]] | specify | implemented (0.7.0, #671, #684, #688, #689, #690; extended post-0.8.0, #821, #827, #837, #848) | n/a (specify-only) |
| 018 | [[018-7z-stream-map-panic/spec\|7z Stream Map Validation]] | specify | implemented (0.7.0, #752; narrowed in 0.8.0, #751, #770) | n/a (specify-only) |
| 019 | [[019-verify-and-list-model/spec\|Verify and List Reporting Model]] | specify | implemented (0.7.0, retrospective; updated for 0.8.0) | n/a (specify-only, retrospective) |
| 020 | [[020-reader-sink-and-in-memory-api/spec\|Reader, Sink and In-Memory API]] | specify | implemented (0.8.0, #771, #787, #790, #808; callback and listing for extraction post-0.8.0, #842, #860, #884) | n/a (specify-only, retrospective) |

## Completed Specs

| ID | Feature | Resolution |
|----|---------|------------|
| 008 | [[008-tar-empty-directory-preservation/spec\|TAR Empty Directory Preservation]] | implemented (#400) — TAR now writes explicit directory entries |
| 009 | [[009-accurate-compression-reporting/spec\|Accurate Compression Reporting]] | implemented (#402) — `bytes_compressed` now measured from real on-disk archive size |

## Archived Specs

- [[001-exarch-system/spec\|exarch System Spec (monolithic)]] — superseded by 001–007 above
- [[001-exarch-system/plan\|exarch Technical Plan (monolithic)]] — reference architecture document

## Project Foundation

- [[constitution]] — non-negotiable project principles
