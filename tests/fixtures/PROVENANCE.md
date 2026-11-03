# Windows producer fixtures

Archives made by real Windows tools on a GitHub Actions `windows-latest`
runner (CI run 41587926392, 2026-11-03), committed so every host tests the
same bytes. Source tree for the ZIP: `a.txt` ("hello\n"), `empty`,
`sub/café.txt` ("unicode\n"), `sub/rand.bin` (0..=255 cycled, 200000 bytes),
`sub/rep.txt` (5000 x `x`).

| File | Producer | Notes |
|------|----------|-------|
| `zip-family/explorer-windows.zip` | `Shell.Application` `CopyHere` (Explorer "Send to compressed folder") | 5 entries, no directory entries; names are CP437 without the UTF-8 flag (`caf\x82.txt`); `rand.bin` and `rep.txt` exceed the default compression ratio, so extraction needs a raised limit |
| `symlink-7zip-windows-snl.7z` | `7z a -snl` over `a.txt`, `dir/`, and a file symlink and a directory symlink | 4 entries: `dir` (D), `dir-link` (DL), `a.txt` (A), `file-link` (AL); solid; the links are reparse points, not Unix-mode symlinks |

Used by `crates/exarch-core/tests/zip_corpus.rs` and
`crates/exarch-core/tests/sevenz_reparse_point.rs`.
