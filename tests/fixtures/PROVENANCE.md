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

# WinRAR producer fixtures

Archives made by WinRAR, taken unmodified from the Go standard library test
data (`src/archive/zip/testdata`) and from the Apache Commons Compress test
resources. The two Go files cover header shape only: each holds a single empty
stored entry (no compressed payload). `deflate-winrar.zip` carries WinRAR's
deflate output. Common WinRAR traits: version made by `0x001F`, and an NTFS
(`0x000a`) extra field in the central directory only.

| File | Source (pinned) | sha256 | Notes |
|------|-----------------|--------|-------|
| `zip-family/utf8-winrar.zip` | `https://raw.githubusercontent.com/golang/go/4fcc835971ad63cf913ebe074ef6191e35a44ab9/src/archive/zip/testdata/utf8-winrar.zip` | `f41036f0d011ae1c98de383360b1e26eb41f216cea17ab909f8fcf027ba20791` | 146 bytes; one empty entry named `世界` with the UTF-8 flag set |
| `zip-family/time-winrar.zip` | `https://raw.githubusercontent.com/golang/go/6e8894d5ffca9acc635e0d7298167122ed52ce55/src/archive/zip/testdata/time-winrar.zip` | `058b9c059e88fcd17d8e8bee4239f31073969c8affa4993498dbb7e5c1508518` | 150 bytes; one empty entry named `test.txt` |
| `zip-family/deflate-winrar.zip` | `https://raw.githubusercontent.com/apache/commons-compress/0df4d084182c2c2662b777ee2c3b04a1c42bbc66/src/test/resources/COMPRESS-477/split_zip_created_by_winrar/zip_to_compare_created_by_winrar.zip` | `33169cd55b80be1c1b6174d3bf8432b7c239bc5372e2c86e8b7bef95f88e6d81` | 574,820 bytes; 279 entries, version made by `0x001F`, 243 deflated and 36 stored; Apache-2.0, see below |

Used by `crates/exarch-core/tests/zip_corpus.rs`.

## License of the Go test data

`utf8-winrar.zip` and `time-winrar.zip` are distributed under the Go project's BSD-3-Clause
license (text verbatim from the `LICENSE` file at the first pinned commit):

```
Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## License of the Apache Commons Compress test data

`deflate-winrar.zip` is a test resource of Apache Commons Compress
(COMPRESS-477), Copyright The Apache Software Foundation, licensed under the
Apache License, Version 2.0 (`https://www.apache.org/licenses/LICENSE-2.0`).
The file is redistributed unmodified; its sha256 above lets a reader confirm
that.
