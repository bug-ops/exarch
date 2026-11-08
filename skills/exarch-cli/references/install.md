# Install without cargo

Use when `cargo` is unavailable or on Windows. Verify the checksum before extracting.

## Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/bug-ops/exarch/main/scripts/install.sh | sh
```

Checksum-verified; installs to `~/.local/bin` (override with `EXARCH_INSTALL_DIR`).

If the script cannot run (restricted shell), download `exarch-<version>-<target>.tar.gz` and its `.sha256` from GitHub Releases (`https://github.com/bug-ops/exarch/releases`). `<target>` is one of `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`.

```bash
sha256sum -c exarch-<version>-<target>.tar.gz.sha256   # macOS: shasum -a 256 -c
tar -xzf exarch-<version>-<target>.tar.gz
```

## Windows

No install script. Download `exarch-<version>-x86_64-pc-windows-msvc.zip` and its `.sha256` from the same releases page, then in PowerShell:

```powershell
(Get-FileHash exarch-<version>-x86_64-pc-windows-msvc.zip -Algorithm SHA256).Hash
# compare case-insensitively with the .sha256 file, then:
Expand-Archive exarch-<version>-x86_64-pc-windows-msvc.zip -DestinationPath .
```

`CertUtil -hashfile <zip> SHA256` is a cmd-only alternative to `Get-FileHash`.
