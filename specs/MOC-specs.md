---
aliases:
  - Specifications Index
  - Specs Overview
tags:
  - moc
  - sdd
created: 2026-05-20
updated: 2026-08-04
status: moc
---

# Specifications

> [!abstract]
> Map of Content for all project specifications. Each entry links to
> a feature spec with its current phase and status.

## Active Specs

| ID | Feature | Phase | Status | Tasks |
|----|---------|-------|--------|-------|
| 001 | [[001-security-pipeline/spec\|Security Pipeline]] | tasks | current (v0.6.0, unreleased) | [[001-security-pipeline/tasks\|none open]] |
| 002 | [[002-format-handlers/spec\|Format Handlers]] | tasks | current (v0.6.0, unreleased) | [[002-format-handlers/tasks\|none open]] |
| 003 | [[003-config-api/spec\|Configuration API]] | tasks | current (v0.6.0, unreleased) | [[003-config-api/tasks\|none]] |
| 004 | [[004-progress-tracking/spec\|Progress Tracking]] | tasks | current (v0.6.0, unreleased) | [[004-progress-tracking/tasks\|none]] |
| 005 | [[005-cli/spec\|CLI]] | tasks | current (v0.6.0, unreleased) | [[005-cli/tasks\|none open]] |
| 006 | [[006-python-bindings/spec\|Python Bindings]] | tasks | current (v0.6.0, unreleased) | [[006-python-bindings/tasks\|none]] |
| 007 | [[007-node-bindings/spec\|Node.js Bindings]] | tasks | current (v0.6.0, unreleased) | [[007-node-bindings/tasks\|none]] |
| 011 | [[011-ffi-panic-boundary-simplification/spec\|FFI Panic Boundary Simplification]] | specify | draft (research, P3) | n/a (specify-only) |
| 012 | [[012-windows-reserved-device-names/spec\|Windows Reserved Device Name Validation]] | specify | draft (bug, P2) | [[012-windows-reserved-device-names/tasks\|not started]] |
| 013 | [[013-quota-permit-capability-token/spec\|Quota Permit Capability Token]] | tasks | current (v0.6.0, unreleased) | [[013-quota-permit-capability-token/tasks\|none open]] |
| 014 | [[014-config-typestate-validation/spec\|Config Typestate Validation]] | tasks | current (v0.6.0, unreleased) | [[014-config-typestate-validation/tasks\|none open]] |
| 015 | [[015-atomic-force-destination-swap-hardening/spec\|Atomic-Force Destination Swap Hardening]] | tasks | current (v0.6.0, unreleased) | [[015-atomic-force-destination-swap-hardening/tasks\|none open]] |

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
