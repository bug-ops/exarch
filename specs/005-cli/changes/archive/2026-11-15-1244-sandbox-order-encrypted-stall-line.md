---
tags:
  - sdd
  - delta
created: 2026-11-15
status: merged
related:
  - "[[005-cli/spec]]"
---

# Delta: CLI changes of the #1237 to #1246 batch

## MODIFIED

### FR-148

The startup order gains `sandbox::preflight` and `interrupt::prepare`; a missing TAR destination is staged under `--sandbox` (#1244).

### FR-149

`list` marks encrypted entries (`encrypted` in JSON, `(encrypted)` in `list -l`); `unusable_password` joins the reasons; a 7z with AES under a plain header verifies as unverified `encrypted` (#1242, #1243, #1246).

### FR-151

The stall hook writes `exarch-test: stalled at entry <n>` to stderr before it blocks (#1245).
