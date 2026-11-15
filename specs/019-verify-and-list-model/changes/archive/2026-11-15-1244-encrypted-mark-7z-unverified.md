---
tags:
  - sdd
  - delta
created: 2026-11-15
status: merged
related:
  - "[[019-verify-and-list-model/spec]]"
---

# Delta: List mark and 7z encrypted content in verify (#1242, #1243, #1239, #1246)

## MODIFIED

### FR-067

`list` marks encrypted entries; a 7z with AES content under a plain header and no password is an unverified `encrypted` WARNING in `verify` like the ZIP, and `extract` refuses it with `password_required`; `unusable_password` and a raw-key modelled header fail in `list`, `verify` and `extract` alike.
