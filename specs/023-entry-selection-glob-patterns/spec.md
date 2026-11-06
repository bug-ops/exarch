---
aliases:
  - Entry Selection Glob Patterns
  - Glob Patterns for Include and Exclude
tags:
  - sdd
  - spec
  - extraction
  - creation
  - security
  - parity
  - rust
created: 2026-11-06
updated: 2026-11-06
status: planned
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[003-config-api/spec]]"
  - "[[005-cli/spec]]"
  - "[[006-python-bindings/spec]]"
  - "[[007-node-bindings/spec]]"
  - "[[019-verify-and-list-model/spec]]"
  - "[[021-create-staging-and-output-policy/spec]]"
  - "[[022-extract-entry-selection/spec]]"
---

# Feature: Glob Patterns for Entry Selection and Create Excludes

> [!info] Metadata
> **Subsystem**: exarch-core / `ExcludePattern` (grammar and matcher shared by creation excludes and extraction `EntrySelection`); surfaces in `exarch-cli`, `exarch-python`, `exarch-node`
> **MSRV**: Rust 1.99.1
> **Origin**: #1000 (research finding, P3, enhancement), found after PR #999. Spec 022 lists a glob engine as out of scope.
> **Status**: planned. This spec merges after the #1000 implementation PR (track S lands after T4), so from the merge on its requirements describe the shipped behavior; until then it describes the target. The design is decided (architect plan rev 3, critic rounds 1 and 2 folded in) and is being implemented under #1000; this spec states WHAT the shipped behavior must be. Section 9 lists what the plan leaves open.

> [!note] Working names
> `ExcludePattern` (alias `EntryPattern`, the type spec 022 reuses), `ExcludeRefusal`, `Shape` and `Matcher` are the identifiers of the plan; the implementation may adjust private ones.

## 1. Overview

### Problem Statement

Spec 022 added `--include`, `--exclude` and `--strip-components` to `extract`, reusing the grammar of `create -x/--exclude` ([[021-create-staging-and-output-policy/spec]] FR-019 to FR-021): an `Exact` component, `Prefix` (`tmp*`), `Suffix` (`*.rs`) and an anchored relative `Path` (`src/lib`, which also selects everything below). That grammar is deliberately not a glob, so a user cannot say "all `.rs` files under `src/c`".

Observed on a release CLI built from 2b53ce5, with an archive holding `src/a/b/one.rs`, `src/c/two.rs` and `src/c/three.txt`:

| Pattern | Result today | `bsdtar -xf t.tar <pattern>` |
|---------|--------------|------------------------------|
| `src/c/*.rs` | refused: "combines `*` with a path separator" | extracts `src/c/two.rs` |
| `src/**/*.rs`, `src/*/two.rs` | same refusal | extracts matching members |
| `src/c/t?o.rs`, `[a-c]*` | refused: "contains `?`, `[`, `]`, `{`, `}` or `!`" | extracts matching members |

The refusal is fail-closed and typed, which is correct. The gap is capability only: users extract everything and prune afterwards, or enumerate files with `list` and pass them one by one.

For a security-first library a glob engine is not a convenience layer. Patterns may come from configuration or API callers, the matcher runs over every entry name of an untrusted archive, and a class or `*` that crosses `/` silently selects more than the caller meant. The extension must not weaken validation, must not add super-linear matching, and must keep `create`, `extract`, `list` and `verify` in agreement.

### Goal

A caller expresses path-aware selection with glob syntax in `create --exclude` and in `extract`/`list`/`verify` `--include`/`--exclude`, in one grammar shared by all of them and by the Rust, Python and Node.js APIs. Every pattern accepted on `main` keeps its meaning. A construct that cannot be matched safely is refused at construction with a typed error naming the pattern.

### Decisions (resolve the open questions of the research draft)

| Question | Decision |
|----------|----------|
| Engine | `globset` 0.4.21 (`default-features = false`; `Unlicense OR MIT`, MSRV 1.88; its regex stack is already in `Cargo.lock`), behind an opaque `ExcludePattern`. No globset type reaches any public API. Chosen over `glob` 0.3.4 because `glob` needs `Path::to_str`, so a non-UTF-8 name would never match while `*.key` matches it today, and its matcher backtracks recursively |
| `*` and `/` | `*` and `?` never match `/` (`literal_separator(true)`); only a whole-component `**` crosses components |
| Case | Case-sensitive bytes on every host (`case_insensitive(false)`) |
| Dotfiles | Leading dots are not special |
| Escape | No backslash escape: `\` is a separator, normalized to `/` before parsing. A literal metacharacter is written in bracket form (`[*]`, `[?]`, `[[]`) |
| `?` | Exactly one byte (`caf?.txt` does not match `café.txt`), consistent with byte matching today |
| Classes | Positive ASCII classes only; ranges only within `0-9`, `a-z` or `A-Z`; negation, POSIX classes and non-ASCII members refused |
| Braces | Refused (no alternation) |
| Pattern count | No cap (see section 6) |
| Case, dotfile, `*`/`/` and engine changes | Were "Ask First" items; decided by the user |

### Out of Scope

- Regular expressions, tar-style `s/old/new/` transforms, filter callbacks (spec 022 open questions, unchanged).
- Positional member arguments in the CLI (spec 022 FR-101).
- Changing the order of operations, collision, link, quota or skip-accounting rules of spec 022; only the pattern grammar and its matcher change.
- Negated classes, non-ASCII class members and brace alternation (refused in v1; see section 9 for a possible follow-up).
- Glob support in `allowed_extensions`.
- A cap on the number of patterns in a list.

## 2. User Stories

### US-001: Select by extension within a directory
AS A developer extracting a source archive
I WANT to write `--include 'src/c/*.rs'`
SO THAT I extract only the Rust files of one directory without listing them

```
GIVEN an archive with src/a/b/one.rs, src/c/two.rs and src/c/three.txt
WHEN I extract with --include 'src/c/*.rs'
THEN only src/c/two.rs is extracted and the other entries are counted as not selected
```

### US-002: Select across directory depth
AS A developer
I WANT a recursive wildcard such as `src/**/*.rs`
SO THAT nesting depth does not matter

```
GIVEN the archive of US-001
WHEN I extract with --include 'src/**/*.rs'
THEN src/a/b/one.rs and src/c/two.rs are extracted and src/c/three.txt is not
```

### US-003: Exclude by glob when creating and extracting
AS A release engineer
I WANT the same glob syntax in `create --exclude` and `extract --exclude`
SO THAT one pattern means the same thing in both commands

```
GIVEN a directory with target/debug/x.o and src/lib.rs
WHEN I create with --exclude 'target/**/*.o'
THEN the archive holds no .o file under target
AND extracting it with the same pattern as --exclude selects the same set
```

### US-004: A bad pattern fails before anything is written
AS A security-minded integrator passing patterns from configuration
I WANT a malformed or unsupported pattern refused up front with a typed error naming it
SO THAT a typo never silently selects everything or nothing

```
GIVEN the pattern 'src/[a-'
WHEN I build the selection or run the CLI
THEN construction fails with InvalidConfiguration naming the setting and the pattern (UnterminatedClass)
AND nothing is written to the destination
```

### US-005: Patterns cannot widen what validation allows
AS A maintainer
I WANT a glob applied only after validation
SO THAT no pattern, however broad, makes an unsafe entry extractable

```
GIVEN an archive entry ../evil.rs
WHEN I extract with --include '**/*.rs'
THEN the entry is refused with the typed traversal error, not selected
```

### US-006: Hostile patterns and names cannot stall the process
AS A service operator
I WANT matching cost bounded by pattern and name length
SO THAT a crafted pattern or entry name cannot cause a denial of service

```
GIVEN the pattern '*a*a*a*a*b' and a 255-byte entry name of 'a'
WHEN the entry is tested
THEN matching finishes and returns a result within the linear bound
```

### US-007: Same behavior in Python and Node.js
AS A Python or Node.js user
I WANT the same glob patterns as the CLI and the Rust API
SO THAT results do not depend on the binding

```
GIVEN include=['src/**/*.rs'] in the Python or Node extract call
WHEN the archive of US-001 is extracted
THEN the extracted set equals the CLI result, and a malformed pattern raises the same typed error
```

## 3. Functional Requirements

### Grammar and construction

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL accept, per path component: `*` (any run of bytes, never `/`), `?` (exactly one byte, never `/`), positive ASCII classes `[abc]`, `[a-c]`, and `**` only as a whole component (zero or more components); `\` SHALL be a separator, rewritten to `/` before any other processing | must |
| FR-002 | Inside a class, a `-` that is neither first nor last SHALL be a range operator whose two ends belong to the same group (`0-9`, `a-z` or `A-Z`, sub-ranges allowed) with `lo <= hi`; a literal `-` is written first or last; `]` first is literal. No accepted range can contain `/` (0x2F), because the lowest permitted end is `0` (0x30) | must |
| FR-003 | A literal metacharacter SHALL be matchable in bracket form (`[*]`, `[?]`, `[[]`); there is no backslash escape | must |
| FR-004 | Patterns SHALL be one opaque value `ExcludePattern` built by one parser (`parse_for`, `TryFrom<&str>`, `FromStr`) and printed by `Display`, shared by creation excludes and extraction include and exclude; there SHALL be no second grammar and no globset type in any public API (no `From`, `Into`, `AsRef`, accessor or re-export); the type SHALL stay `Send + Sync + Unpin + UnwindSafe + RefUnwindSafe`, asserted at compile time | must |
| FR-005 | Case SHALL be sensitive and leading dots SHALL not be special, identically on every host and in `create`, `extract`, `list` and `verify` | must |
| FR-006 | `ExcludePattern` construction SHALL set the globset options explicitly: `literal_separator(true)`, `backslash_escape(false)`, `case_insensitive(false)`, `allow_unclosed_class(false)`, `empty_alternates(false)`; no globset error text SHALL reach the user | must |
| FR-007 | A pattern SHALL be immutable after construction and keep no unparsed string as the source of truth; `Eq` and `Hash` SHALL be on the structured shape (FR-012), so `x` is not equal to `./x`, while `target/`, `./target` and `target/**` are equal | must |

### Refusals (all at construction, before any write)

Every check below runs on the text after `\` is rewritten to `/`, so `[a\b]` is split into components and refused as `UnterminatedClass`.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-010 | THE SYSTEM SHALL keep today's refusals: empty (including a pattern that is only `./`), over 255 bytes (`MAX_CONFIG_ENTRY_LENGTH`), NUL, a `.` or `..` component, an absolute or drive-prefixed pattern, a comma, leading or trailing whitespace or control characters (`Empty`, `TooLong`, `ContainsNul`, `DotEntry`, `Absolute`, `ContainsComma`, `PaddedWithBlank`) | must |
| FR-011 | THE SYSTEM SHALL refuse with new typed reasons: raw text starting with `!` (`LeadingNegation`, "patterns cannot negate; use --exclude"; a `!` anywhere else is a literal character); `{` or `}` (`BraceAlternation`); a component that contains `**` but is not exactly `**`, including `a**b` and `***` (`UnsupportedWildcard`); a class starting with `!` or `^`, a class with a non-ASCII member, a class range whose ends are not in one group, and a POSIX class (`[:` inside a class) (`UnsupportedClass`); a class left open at the end of its component (`UnterminatedClass`); an inverted range such as `[z-a]` (`InvalidClassRange`); and any other globset parse error through a wildcard arm (`UnsupportedSyntax`) | must |
| FR-011a | `ExcludeRefusal` SHALL stay `#[non_exhaustive]` and closed: kept `Empty`, `TooLong`, `ContainsNul`, `DotEntry`, `Absolute`, `UnsupportedWildcard`, `PaddedWithBlank`, `ContainsComma`; added `LeadingNegation`, `BraceAlternation`, `UnsupportedClass`, `UnterminatedClass`, `InvalidClassRange`, `UnsupportedSyntax`; removed `WildcardWithSeparator`, `GlobMetacharacter`. `explanation()`, the doc example in `config_error.rs`, the CLI hints and the binding messages SHALL be updated; globset's `ErrorKind` is foreign and SHALL never be matched exhaustively | must |
| FR-012 | WHEN a pattern is parsed THE SYSTEM SHALL decide anchoring on the raw text after `\` to `/` and before any segment is dropped: any `/` anywhere makes it anchored, no `/` makes it floating (`target/`, `./build`, `build\` and `build/**` stay anchored, as `Path` is today). Then empty and `.` segments are dropped, runs of `**` are collapsed and trailing `**` segments are dropped. A pattern left with only `**` segments (`**`, `./**`, `**/`, `**/**`) SHALL be `MatchAll` whatever its anchoring. The structured form is `Shape { MatchAll, Floating(Box<str>), Anchored(Box<str>) }` | must |
| FR-013 | `Display` SHALL derive from `Shape` and round-trip: `parse(display(p)) == p`. `MatchAll` prints `**`; `Floating` prints the segment; `Anchored` with one segment prints `seg/`, with more `a/b`. So `target/` prints `target/` (it printed `target`, which re-parses as floating, before; CHANGELOG line). The leading-`!` (FR-011) and padding (FR-010) checks SHALL hold for the normalized first and last segments as well, so `./!x` and `a/b /` cannot print a text that re-parses as a refusal (see section 9, Q3) | must |

### Matching semantics

| ID | Requirement | Priority |
|----|------------|----------|
| FR-020 | THE SYSTEM SHALL give every pattern accepted on `main` the same meaning: a floating pattern matches any component and selects that subtree (globs `**/P` and `**/P/**`, exactly today's `Exact`/`Prefix`/`Suffix`); an anchored pattern selects the matched path and its subtree (globs `P` and `P/**`, exactly today's `Path` and bsdtar's directory rule); `MatchAll` is the glob `**`. So `src/c/*.rs` selects `src/c/two.rs`, `build/*` selects the children of `build` and everything below, `*` selects everything | must |
| FR-021 | `matches(&Path)` SHALL be a pure function over a normalized form: when the path is already canonical (no empty or `.` component, no leading `./`, no trailing separator) it SHALL match the raw encoded bytes without allocation; otherwise it SHALL match a `/`-joined buffer of the `Normal` components. A path with no normal component, or with a root, prefix or `..` component, SHALL never match. So `build//out/x` and `build/./out` match `build/out` as they did under `Path::starts_with`, and `a//b` does not meet `a/*/b` (documented) | must |
| FR-022 | Matching SHALL run on bytes (`Candidate::from_bytes(as_encoded_bytes())`: raw bytes on Unix, WTF-8 with `\` rewritten to `/` on Windows), so a non-UTF-8 name is matched and never skipped | must |
| FR-023 | A pattern without `*`, `?` or `[` SHALL be matched by exact component comparison (any component for `Floating`, `Path::starts_with` semantics for `Anchored`) through an internal `Matcher::Literal`; this path SHALL give the same answer as the glob path for every literal name and every path (including `.`, `..`, a root, `//`, a trailing `/` and non-UTF-8 bytes), because the FR-021 normalization and the never-match gate run before `Matcher` dispatch | must |
| FR-024 | The default creation excludes (`.git` and so on, and the suffix default `*.tmp`) SHALL be built without a fallible parse and SHALL never be silently dropped; a test SHALL assert that each default excludes a sample path (the construction mechanism for the suffix default is open, Q4) | must |
| FR-025 | Include/exclude combination rules of spec 022 FR-006 SHALL be unchanged: selected iff it matches an include (or there is none) and matches no exclude; exclude wins | must |
| FR-026 | A refused original path (traversal, absolute, banned component, placement conflict) SHALL stay refused under any pattern, including `**`: selection runs after validation as in spec 022 FR-005 to FR-011 and cannot turn a refused entry into a selected or silently skipped one | must |

### Retained behavior

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | WHEN an include pattern matches no entry in the whole archive THE SYSTEM SHALL fail with the typed unmatched-include error naming every such pattern and carrying the partial outcome (spec 022 FR-043); an exclude that matches nothing is not an error (FR-044) | must |
| FR-031 | `extract`, `list` and `verify` SHALL interpret one pattern identically through one implementation; dispositions, `landing_paths` and findings stay consistent with `extract` (spec 022 FR-050 to FR-054) | must |
| FR-032 | Skip accounting is unchanged (spec 022): `NotSelected`, no quota charge, no directory creation, decode bound of skipped compressed-TAR entries, `max_file_count` charge; `extract --atomic` applies glob selection inside the staging tree and rolls back on an unmatched include | must |

### Surfaces

| ID | Requirement | Priority |
|----|------------|----------|
| FR-100 | THE CLI `create -x/--exclude` and `extract`/`list`/`verify` `--include`/`--exclude` SHALL accept the grammar; a refused pattern SHALL exit `1` with the JSON envelope (`setting` named) and write nothing | must |
| FR-101 | Rust, Python and Node SHALL parse through the single core boundary function (`ExcludePattern::try_from`); bindings keep their `str` inputs and only map types and errors (`ArchiveError::into_ffi_message()`); no binding type changes, only refused-shape tests and docs | must |
| FR-102 | CLI help, Rust docs (with doc-tests), Python and Node docs and the README files SHALL carry the grammar table and one example each for `*`, `**` and the cross-component rule; the `ExcludePattern` docs SHALL state the 10 MiB per-thread lazy cache that globset allows per compiled set | must |
| FR-103 | `skills/exarch-cli/SKILL.md` SHALL be updated in the same change and verified against the running binary | must |
| FR-104 | The create-side semantics of [[021-create-staging-and-output-policy/spec]] FR-019 to FR-021 and the out-of-scope line of [[022-extract-entry-selection/spec]] are amended in this change (done in this PR); the `CHANGELOG.md` SHALL record the breaking changes: `ExcludePattern` opaque, `ExcludeRefusal` variants changed, `Display` of an anchored single segment now ends in `/` | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | The matcher is not a security boundary and adds no path to an unvalidated landing. It is a pure, total function over a normalized `&Path` and never matches a path with a root, prefix or `..` component (FR-021). The research draft asked for proof by types (a `SafePath`-only input); the plan dropped that because `lexical_landing` and `map_link_target` hand normalized `PathBuf`s to selection before validation, so the guarantee is the call order of spec 022 plus the never-match gate |
| NFR-002 | Security | Matching time is linear in the candidate for a fixed pattern (finite automata, no backtracking; globset caps the NFA at 10 MiB); pattern parse and normalization are bounded by 255 bytes; covered by property tests and a fuzz target |
| NFR-003 | Security | Parsing SHALL NOT panic on any input including non-UTF-8 bytes from bindings; no `expect`/`unwrap` (workspace lints) |
| NFR-004 | Correctness | Where meaning is shared with `bsdtar` the selected entries SHOULD agree; every deliberate deviation is listed in the differential table of section 6, and `tests/entry_selection_differential.rs` carries the cases where bsdtar agrees |
| NFR-005 | Performance | Matching a representative selection (10 patterns) against 100000 names SHALL be benchmarked against `main` (bench group in `benches/validation.rs`); the threshold is not fixed (Q5). One `GlobSet` per pattern is the design; compiling each list into one set is deferred (D1: `// TODO(critic): compile include/exclude lists into one GlobSet each if per-pattern matching misses NFR-005` above `EntrySelection::decide`) |
| NFR-006 | Maintainability | One matcher, one grammar, one `Display`; the literal path is a proven-equal shortcut (FR-023), not a second grammar |
| NFR-007 | Dependencies | `globset` is a private dependency of `exarch-core` only (`cargo tree -i globset` lists nothing else), adds no duplicate crate (`multiple-versions = "deny"`), passes `cargo deny --all-features check` and can be bumped without a semver break |
| NFR-008 | Portability | The same pattern selects the same entries on Linux, macOS and Windows; a Windows CI test matches `src\c\two.rs` against `src/c/*.rs` |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `ExcludePattern` (alias `EntryPattern`) | Opaque, immutable, validated pattern | `Shape` for `Eq`/`Hash`/`Display`, `Matcher::{Literal, Glob(GlobSet)}`; `Clone`; `Debug` prints the text only |
| `Shape` | Canonical anchoring and segments | `MatchAll`, `Floating(Box<str>)`, `Anchored(Box<str>)` (segments joined with `/`) |
| `ExcludeRefusal` | Why a pattern was refused | closed `#[non_exhaustive]` enum (FR-011a) |
| `literal_name` | Infallible `pub(crate)` constructor for the default literal excludes | never touches globset |
| Unmatched include report | Typed error payload (spec 022) | pattern text, partial outcome |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `*` against `src/c/two.rs` | Does not cross `/`; matches a single component |
| `**`, `./**`, `**/`, `**/**` | `MatchAll`; still subject to validation (FR-026) |
| `src/**` | Anchored `src`: selects `src` and everything below |
| `target/`, `./build`, `build\`, `build/**` | Anchored, same selection as `Path` on `main` |
| `x` versus `./x` | Different patterns: `x` floats (matches `a/x`), `./x` is anchored |
| Entry `../x.rs` with `**/*.rs` | Refused by validation (FR-026) |
| `src/[a-`, `[a\b]` | `UnterminatedClass` |
| `a**b`, `***` | `UnsupportedWildcard` |
| `{a,b}` | `BraceAlternation` (a comma alone is `ContainsComma`) |
| `!keep.txt` | `LeadingNegation`; `a!b` is a literal |
| `a[!x]b`, `a[^x]b`, `[é]`, `[[:alpha:]]` | `UnsupportedClass` |
| `x[.-9]y`, `x[+-0]y`, `[--0]`, `[*-0]`, `[]-a]` | `UnsupportedClass` (ranges that would span `/` or mix groups) |
| `[z-a]` | `InvalidClassRange` |
| `[a-c]`, `[0-9]`, `[-a]`, `[a-]`, `[]a]`, `[*]` | Accepted |
| `\*` | `\` is a separator, not an escape: the pattern is `/*` after normalization, which is `Absolute` |
| `SRC` versus `src` | Different; case-sensitive everywhere |
| `caf?.txt` against `café.txt` | No match (`?` is one byte) |
| Non-UTF-8 component | Matched by `*` and `?` bytewise |
| Windows `src\c\two.rs` in a TAR | Normalized to `src/c/two.rs` before matching |
| `build//out/x` against `build/out` | Matches (normalization, FR-021) |
| `a//b` against `a/*/b` | No match (documented) |
| `*a*a*a*a*b` against 255 x `a`, deep paths | Finishes within the linear bound |
| 10000 patterns in a list | Accepted; cost is per-pattern matching plus the per-thread cache note (FR-102); measured 0.66 microseconds per check for 1024 complex patterns (critic probe) |
| Include matches nothing | Typed error listing the pattern; under `--atomic`, rolls back |
| Hardlink whose target is excluded | Refused per spec 022 FR-032 |

### Differential table against bsdtar

| Aspect | bsdtar member pattern | exarch | Basis |
|--------|----------------------|--------|-------|
| `*` and `/` | `*` crosses `/` | `*` never crosses `/` | plan |
| Anchoring | member names unanchored | a pattern with a separator is anchored at the root, one without floats | plan |
| Subtree rule | a directory pattern selects its members | same (implicit trailing `**`) | plan |
| `?`, classes | by character | by byte, positive ASCII classes only | plan (`?` byte); refusals above |
| Negated and POSIX classes, braces, backslash escape | not part of this comparison | refused (`\` is a separator) | refusals above |

The differential corpus (`tests/entry_selection_differential.rs`) includes only cases where bsdtar agrees; rows above are the intended disagreements. Rows without a plan statement about bsdtar's behavior are exarch-side facts only.

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | The evidence patterns (`src/c/*.rs`, `src/**/*.rs`, `src/*/two.rs`, `src/c/t?o.rs`, `[a-c]*`) select the entries bsdtar selects where meaning is shared | 100% on the differential corpus, deviations listed |
| SC-002 | Old-vs-new property test over generated `Exact`/`Prefix`/`Suffix`/`Path` patterns and the four texts `target/`, `./build`, `build\`, `build/**` | Same selected set |
| SC-003 | Fuzz target `glob` (arbitrary pattern and name bytes) | No panic; `parse(display(p)) == p`; and for a pattern whose raw text has no `/` and no `**`, restricted to paths with only `Normal` components, `p.matches(path)` equals "some single component `c` of `path` has `p.matches(Path::new(c))`" |
| SC-004 | A refused original path under any pattern including `**` | 100% of the traversal, symlink and placement corpus |
| SC-005 | CLI, Rust, Python and Node results | Same selected set; same typed error on malformed input |
| SC-006 | `create --exclude`, `extract --exclude` and `list` on one fixture | Same entry set |
| SC-007 | Every refusal of FR-010 and FR-011 | One test per variant, pattern named; globset traps (`a**b`, `***`, `{a,b}`, `a[!x]b` against `a/b`, `[é]`, `[[:alpha:]]`, `\*`, `x[.-9]y`, `x[+-0]y`) all refused |
| SC-008 | Literal path versus glob path (FR-023) | Equal over random names and over arbitrary paths |
| SC-009 | Each default exclude (FR-024) | Excludes its sample path |
| SC-010 | Selection benchmark | Recorded against `main` in `.local/testing/benchmarks.md` |

## 8. Agent Boundaries

### Always (without asking)
- Run the full CI-parity gate suite from `.claude/rules/branching.md` and `rust-security-maintenance` after any change to matching or path handling.
- Apply patterns only after validation; keep one parser and one matcher.
- Add regression tests citing the evidence patterns and the refusal list; update `skills/exarch-cli/SKILL.md` and docs in the same change.
- Run the pinned ruff, biome, fuzz fmt and workflow-lint parity gates, and `fy validate` on `ci.yml` when adding the fuzz matrix entry.

### Ask First
- Changing the meaning of a pattern shape that works today.
- Changing case sensitivity, dotfile rules or the `*`/`/` rule.
- Adding negated or non-ASCII classes, brace alternation, a backslash escape, a pattern-count cap, a filter callback or regex support.
- Bumping `globset` or changing its builder options.

### Never
- Match patterns against raw, unvalidated archive strings, or let a pattern reorder or weaken validation, quota or skip rules.
- Expose a globset type, error text or option in a public API.
- Accept a class range that can span `/`.
- Edit `specs/` by hand or work in the main checkout (use the `rust-agents:sdd` agent inside a worktree).

## 9. Open Questions

> [!question] Left open by the plan
> - **Q1 (follow-up)**: negated classes (`[!x]` as `[^x]` that also excludes `/`) and non-ASCII class members are refused in v1; the plan says a follow-up is possible. File one only if demand appears.
> - **Q2**: the variant for a POSIX class (`[:` inside a class). The plan says "refuse" but names no variant; this spec uses `UnsupportedClass`. Confirm, or add a variant.
> - **Q3**: the plan adopted the critic's round-2 finding that the `!` and padding checks must also hold for normalized segments (`./!x`, `a/b /`) only as a round-trip goal; the exact check point is for the implementation plan.
> - **Q4**: how the default `*.tmp` suffix is built infallibly. `literal_name(&'static str)` cannot express it; options are a third infallible constructor or routing it through globset with the FR-024 test proving it never drops. The plan does not choose.
> - **Q5**: the NFR-005 threshold is unverified until the bench runs (the draft's 5% was never measured).
> - **Q6**: whether to compile each include/exclude list into one `GlobSet` (D1, deferred behind the bench).

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[022-extract-entry-selection/spec]] — selection, order of operations, skip accounting; its "no glob engine" exclusion is amended
- [[021-create-staging-and-output-policy/spec]] — `ExcludePattern` (FR-019 to FR-021) and create `--exclude`, amended
- [[019-verify-and-list-model/spec]] — `landing_paths`, `list` and `verify` parity
- [[001-security-pipeline/spec]] — validation order
- [BurntSushi/globset](https://docs.rs/globset) — the engine
- [libarchive bsdtar](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1) — member patterns for the differential table
- Issue #1000; PR #999
