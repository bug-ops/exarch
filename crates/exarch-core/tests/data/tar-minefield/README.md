# tar-minefield corpus (vendored subset)

Source: https://github.com/haampie/tar-minefield, pinned to upstream commit
`e3060bda`. Licence: MIT, copyright Harmen Stoppels (see `LICENSE`).

Vendored cases, copied unchanged from `suite/archives/`:

- `S06` to `S17` (order and state)
- `F01` to `F60` (framing)

Each case is `<id>-<slug>.tar` with its expected result in `<id>-<slug>.json`.
Some archives escape the directory they are extracted to in lenient
implementations, so extract them only in a throwaway directory.

Used by `tests/tar_minefield.rs`, which asserts containment on every case and
pins the outcome kind of each one. The directory is excluded from the
`exarch-core` package.
