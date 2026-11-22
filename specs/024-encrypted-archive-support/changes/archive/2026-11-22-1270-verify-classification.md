---
tags:
  - sdd
  - delta
created: 2026-11-22
status: merged
related:
  - "[[024-encrypted-archive-support/spec]]"
---

# Delta: AES 7z verify reports a password problem only for key-caused failures (#1270)

## MODIFIED

### FR-014

Old: a wrong password for an AES 7z block makes `verify` report each affected entry as `ENCRYPTED` / `wrong_password_or_corrupt`.
New: that report is made only for failures a wrong password or tampered ciphertext can cause (checksum, malformed stream, truncation); a declared-size overrun and a not-decodable coder keep their own report.
