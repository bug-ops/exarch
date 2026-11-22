---
tags:
  - sdd
  - delta
created: 2026-11-22
status: merged
related:
  - "[[002-format-handlers/spec]]"
  - "[[027-zip-parallel-compression/spec]]"
---

# Delta: PAX reference-reader consistency, named-source size skip, ZIP mtime clamp (#1281, #1267, #1268)

## ADDED

### FR-075

PAX records are framed by declared length; a body is accepted only when the reference reader's view agrees: no newline in a key, every record it yields is a whole declared record at the same offset, `path`, `linkpath`, `size`, `uid` and `gid` are visible to it (the last three before its first unreadable line), a hidden `size` is accepted only when canonical decimal and equal to the entry header size, never in a global header and never in a chain with a GNU long name or long link record, other keys may be hidden. Records are matched to the declared ones by key byte offset. The stacked-size rule is evaluated on the declared records, so any `size` record, visible or hidden, in a chain with a GNU long name or long link record is refused in either order. Refusals stay `MalformedRecord`. `SUN.holesdata` is refused as `UnsupportedRecord` by declared key in local and global headers (#1281).

### FR-076

A single file named directly as a `create` source above `max_file_size` is skipped as `OverMaxFileSize` in TAR and ZIP (#1267).

### FR-077

ZIP creation clamps a source mtime at or after the DOS range end (including year 10000 and beyond) to the last DOS second and never panics (#1268).

## MODIFIED

### FR-051

Old: refuses a malformed, empty-key, over-long, duplicate or `GNU.sparse.*`/`SCHILY.realsize` PAX record.
New: the key list also names `SUN.holesdata`, and a PAX record whose reference-reader view differs from its declared framing is refused (FR-075).

## REMOVED

(none)

## Deviations

(none)
