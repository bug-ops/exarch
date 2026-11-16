---
tags:
  - sdd
  - delta
created: 2026-11-16
status: merged
related:
  - "[[025-cli-landlock-sandbox/spec]]"
---

# Delta: Typed sandbox preflight and optional errno (#1259)

## MODIFIED

### FR-006

`Preflight` is typed by scope: `Preflight<ReadOnly>` for `list` and `verify`, `Preflight<Destination>` for `extract`; confinement order unchanged.

### FR-009

`Unavailable::Kernel { errno: Option<i32> }` and a new `Unavailable::RulePath { errno: Option<i32> }`; the `--json` `sandbox` status gains a `rule_path` reason and a nullable errno; the core-staged reason per platform is unchanged.

## Deviations

- FR-009: a rule-path failure is a distinct reason instead of `kernel`.
