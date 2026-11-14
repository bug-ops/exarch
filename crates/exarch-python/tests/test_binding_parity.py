"""The Python and Node.js bindings expose the same data under the same name (#1011).

Enumerable tokens (error codes, sub-codes, skip kinds, ...) are checked against
`exarch-core`'s `ALL` tables by a Rust test in each binding, so both stubs
follow core and therefore each other. This test covers what those tests cannot:
the field names of the report and error types. Core's structs are
`non_exhaustive`, so the bindings cannot destructure them exhaustively and the
table below stays a hand-kept list; add a row when a type gains a field.

Language conventions are not drift: a Node field is the camelCase of the Python
one. `RENAMED` lists the deliberate differences. The one difference of value
rather than name is the unit of `modified`: float seconds in Python, integer
milliseconds in Node; each stub documents its own, and `ArchiveEntry` below
shares the name only. A Node report is a plain object, so a Python helper
(`is_safe`, `compression_ratio`) is the Node property of the same name.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PYI = re.sub(r'"""(?:.|\n)*?"""', '""', (ROOT / "exarch-python" / "exarch.pyi").read_text())
DTS = (ROOT / "exarch-node" / "index.d.ts").read_text()

RENAMED = {
    # The Node entry path is `entryPath`; Python names it like a skip's `path`.
    "path@VerificationIssue": "entryPath",
    # Python fills `filename` the way `open()` does for an `OSError`; Node says `path`.
    "filename": "path",
}

# (Python class, Node interfaces, shared fields)
SHARED = [
    (
        "VerificationReport",
        ["VerificationReport"],
        [
            "status",
            "issues",
            "total_entries",
            "suspicious_entries",
            "total_size",
            "format",
            "integrity_status",
            "integrity_gaps",
            "security_status",
            "is_safe",
            "has_critical_issues",
        ],
    ),
    (
        "VerificationIssue",
        ["VerificationIssueFields"],
        [
            "severity",
            "category",
            "path@VerificationIssue",
            "message",
            "code",
            "sub_code",
            "relaxable_by",
            "setting",
            "io_kind",
            "mode",
        ],
    ),
    (
        "ArchiveManifest",
        ["ArchiveManifest"],
        ["entries", "total_entries", "total_size", "format", "dispositions"],
    ),
    ("ExtractDisposition", ["ExtractDisposition"], ["action", "path", "landing"]),
    ("SkipDisposition", ["SkipDisposition"], ["action", "path", "kind"]),
    ("RefuseDisposition", ["RefuseDisposition"], ["action", "path"]),
    (
        "BackupCleanupFailedWarning",
        ["BackupCleanupFailedWarning"],
        ["kind", "message", "path", "identity", "io_kind", "reason"],
    ),
    (
        "RootAccessNarrowedWarning",
        ["RootAccessNarrowedWarning"],
        ["kind", "message", "reason"],
    ),
    ("ArchiveError", ["ExarchErrorBase"], ["code", "leftover_path"]),
    ("OutputExistsError", ["ExarchOutputExistsDetail"], ["conflicts", "filename"]),
    ("SourceNotFoundError", ["ExarchSourceNotFoundDetail"], ["filename"]),
    (
        "InvalidConfigurationError",
        ["ExarchInvalidConfigurationDetail"],
        ["setting", "unmatched_patterns", "protected_path", "collision"],
    ),
    ("InvalidArchiveError", ["ExarchInvalidArchiveDetail"], ["sub_code", "non_utf8_entry_path"]),
    (
        "SecurityViolationError",
        ["ExarchSecurityViolationDetail"],
        ["sub_code", "relaxable_by", "by"],
    ),
    ("OccupiedPath", ["OccupiedPath"], ["path", "occupant"]),
    (
        "_IOErrorAttributes",
        ["ExarchIoDetail", "ExarchErrorBase"],
        ["io_kind", "restore", "backup_path", "leftover_path"],
    ),
    (
        "ExtractionReport",
        ["ExtractionReport"],
        [
            "files_extracted",
            "directories_created",
            "symlinks_created",
            "bytes_written",
            "duration_ms",
            "files_skipped",
            "skipped",
            "mark_propagation",
            "marks_written",
            "marks_failed",
            "warnings",
            "total_items",
            "has_warnings",
        ],
    ),
    (
        "CreationReport",
        ["CreationReport"],
        [
            "files_added",
            "directories_added",
            "symlinks_added",
            "bytes_written",
            "bytes_compressed",
            "duration_ms",
            "files_skipped",
            "skipped",
            "warnings",
            "total_items",
            "has_warnings",
            "compression_ratio",
            "compression_percentage",
        ],
    ),
    (
        "ArchiveEntry",
        ["ManifestFileEntry"],
        ["path", "entry_type", "compressed_size", "mode", "modified", "compression_ratio"],
    ),
    ("ListOptions", ["ListOptions"], ["stored_targets"]),
    ("ArchiveFile", ["ManifestFileEntry"], ["size"]),
    ("ArchiveSymlink", ["ManifestSymlinkEntry"], ["target"]),
    ("ArchiveHardlink", ["ManifestHardlinkEntry"], ["target"]),
    ("Skip", ["SkippedEntry"], ["kind", "path", "io_kind"]),
    ("Skipped", ["SkippedSummary"], ["total", "counts", "sample"]),
    ("IntegrityGaps", ["IntegrityGaps"], ["counts", "entries", "omitted", "total"]),
    ("UnverifiedEntry", ["UnverifiedEntry"], ["path", "reason"]),
    ("AntiItemsSkippedWarning", ["AntiItemsSkippedWarning"], ["kind", "message", "count"]),
    (
        "ZipRatioOverDefaultLimitWarning",
        ["ZipRatioOverDefaultLimitWarning"],
        ["kind", "message", "entries", "limit", "needed_ratio"],
    ),
    ("ZipRatioCheckFailedWarning", ["ZipRatioCheckFailedWarning"], ["kind", "message", "reason"]),
    ("DirectoryNotSyncedWarning", ["DirectoryNotSyncedWarning"], ["kind", "message", "io_kind"]),
    ("MemoryFile", ["MemoryFileEntry"], ["path", "kind", "data", "mode"]),
    ("MemoryDirectory", ["MemoryDirectoryEntry"], ["path", "kind"]),
    ("MemorySymlink", ["MemorySymlinkEntry"], ["path", "kind", "target"]),
    ("MemoryHardlink", ["MemoryHardlinkEntry"], ["path", "kind", "target"]),
    ("RecordedLinkTarget", ["RecordedLinkTarget"], ["state", "path"]),
    ("OversizedLinkTarget", ["OversizedLinkTarget"], ["state", "bytes"]),
    ("MissingLinkTarget", ["MissingLinkTarget"], ["state"]),
    ("QuotaExceededError", ["ExarchQuotaDetail"], ["sub_code"]),
    ("ZipBombError", ["ExarchZipBombDetail"], ["sub_code"]),
]


# Declared by the builtin `OSError`, not by the stub.
BUILTIN_ATTRIBUTES = {"filename"}


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part.title() for part in rest)


def _python_members(cls: str) -> set[str]:
    header = re.search(rf"^class {cls}\b(?:\(([^)]*)\))?:", PYI, re.MULTILINE)
    assert header, f"exarch.pyi has no class {cls}"
    body = PYI[header.end() :]
    end = re.search(r"^\S", body, re.MULTILINE)
    body = body[: end.start()] if end else body
    members = set(re.findall(r"^    (\w+)\s*:", body, re.MULTILINE))
    members |= set(re.findall(r"@property\n    def (\w+)\(", body))
    members |= set(re.findall(r"^    def (\w+)\(self", body, re.MULTILINE))
    for parent in (header.group(1) or "").split(","):
        parent = parent.strip().split("[")[0]
        if parent and parent not in {"Exception", "OSError", "ValueError", "Protocol"}:
            if re.search(rf"^class {parent}\b", PYI, re.MULTILINE):
                members |= _python_members(parent)
    return members


def _node_members(interface: str) -> set[str]:
    header = re.search(
        rf"^export (?:interface|declare class) {interface}\b[^{{]*{{", DTS, re.MULTILINE
    )
    assert header, f"index.d.ts has no interface {interface}"
    body = DTS[header.end() :]
    body = body[: body.index("\n}")]
    return set(re.findall(r"^  (\w+)\??:", body, re.MULTILINE)) | set(
        re.findall(r"^  get (\w+)\(", body, re.MULTILINE)
    )


@pytest.mark.parametrize(("python_class", "node_interfaces", "fields"), SHARED)
def test_the_bindings_expose_the_same_fields(python_class, node_interfaces, fields):
    python = _python_members(python_class)
    node = set().union(*(_node_members(name) for name in node_interfaces))
    for field in fields:
        python_name = field.split("@")[0]
        node_name = RENAMED.get(field, RENAMED.get(python_name, _camel(python_name)))
        if python_name not in BUILTIN_ATTRIBUTES:
            assert python_name in python, f"{python_class}.{python_name} is missing from exarch.pyi"
        assert node_name in node, f"{node_interfaces}.{node_name} is missing from index.d.ts"


def test_the_mark_states_match_between_the_bindings():
    python = re.search(r"^_MarkState = Literal\[(.*?)\]", PYI, re.MULTILINE | re.DOTALL)
    node = re.search(r"^  markPropagation: ([^\n]+)$", DTS, re.MULTILINE)
    assert python, "exarch.pyi has no _MarkState"
    assert node, "index.d.ts ExtractionReport has no markPropagation"
    assert set(re.findall(r'"(\w+)"', python.group(1))) == set(
        re.findall(r"'(\w+)'", node.group(1))
    )
