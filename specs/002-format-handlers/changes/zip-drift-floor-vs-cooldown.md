---
tags:
  - sdd
  - spec
  - delta
created: 2026-11-23
status: open
related:
  - "[[spec]]"
---

# Delta: zip-drift workflow also checks manifest floors against the publish-age cooldown (#1342)

> [!info] Scope
> Capability: `002-format-handlers`, FR-064 (the `zip-drift.yml` workflow). The dependency cooldown itself (`.cargo/config.toml` `global-min-publish-age`, #1321) and the Dependabot cooldown (#1338) are repository policy that no spec covers; they are not specified here.

## ADDED

### FR-064a

WHEN `zip-drift.yml` runs (weekly and on manual dispatch), a job `floor-vs-cooldown` SHALL run `cargo update --dry-run` for the workspace and for `fuzz/Cargo.toml` under the repository's own `.cargo/config.toml` (without `CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow`) and fail when a manifest requirement floor, such as the `zip` requirement, is younger than `global-min-publish-age`, because `cargo update` and `cargo semver-checks` fail repository-wide in that state (#1342).

**Priority**: should

## MODIFIED

(none) FR-064's `latest-zip` job is unchanged. Its stale `zip = "~9.4"` wording is outside this delta (the manifest requirement is now `~9.8`).

## REMOVED

(none)

## Deviations

(none) The zip floor self-heals on 2026-11-26, when `zip` 9.8.0 passes the 7-day cooldown; the new job is expected red until then.
