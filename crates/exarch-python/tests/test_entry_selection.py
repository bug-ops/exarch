"""Entry selection (#967): include/exclude patterns, strip and flatten.

The selection lives in `SecurityConfig`, so extract, list, verify and the
in-memory extractions interpret it identically.
"""

import io
import tarfile

import pytest

import exarch


def _tar(temp_dir, entries, name="sel.tar"):
    """`entries`: (name, bytes) for files, (name, None) for directories,
    (name, ("sym" | "hard", target)) for links."""
    archive = temp_dir / name
    with tarfile.open(archive, "w") as tar:
        for entry, payload in entries:
            info = tarfile.TarInfo(entry)
            if payload is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif isinstance(payload, tuple):
                kind, target = payload
                info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                info.linkname = target
                tar.addfile(info)
            else:
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
    return archive


@pytest.fixture
def project(temp_dir):
    return _tar(
        temp_dir,
        [
            ("proj/", None),
            ("proj/src/", None),
            ("proj/src/main.rs", b"fn main() {}"),
            ("proj/src/lib.rs", b"//"),
            ("proj/README.md", b"readme"),
            ("proj/build.tmp", b"tmp"),
        ],
    )


def _files(root):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


def test_defaults_carry_no_selection():
    config = exarch.SecurityConfig()
    assert config.include_patterns == []
    assert config.exclude_patterns == []
    assert config.strip_components is None
    assert config.flatten is False


def test_include_and_exclude_select_on_the_original_path(project, temp_dir):
    out = temp_dir / "out"
    config = (
        exarch.SecurityConfig()
        .add_include_pattern("proj/src")
        .add_include_pattern("proj/README.md")
        .add_exclude_pattern("lib.rs")
    )

    report = exarch.extract_archive(project, out, config)

    assert _files(out) == ["proj/README.md", "proj/src/main.rs"]
    assert report.skipped.count("not_selected") >= 1


def test_glob_patterns_select_entries(project, temp_dir):
    out = temp_dir / "out"
    config = (
        exarch.SecurityConfig()
        .add_include_pattern("proj/**/*.rs")
        .add_exclude_pattern("l?b.rs")
    )

    exarch.extract_archive(project, out, config)

    assert _files(out) == ["proj/src/main.rs"]


def test_a_glob_exclude_drops_a_create_entry(temp_dir):
    src = temp_dir / "src"
    (src / "logs" / "deep").mkdir(parents=True)
    (src / "keep.txt").write_text("k")
    (src / "logs" / "a.log").write_text("a")
    (src / "logs" / "deep" / "b.log").write_text("b")
    archive = temp_dir / "o.tar"

    config = exarch.CreationConfig().with_exclude_patterns(["logs/**/*.log"])
    exarch.create_archive(archive, [src], config)

    paths = {entry.path for entry in exarch.list_archive(archive).entries}
    assert "keep.txt" in paths
    assert not any(path.endswith(".log") for path in paths)


def test_strip_components_drops_leading_components(project, temp_dir):
    out = temp_dir / "out"
    config = exarch.SecurityConfig().with_strip_components(1)

    report = exarch.extract_archive(project, out, config)

    assert _files(out) == ["README.md", "build.tmp", "src/lib.rs", "src/main.rs"]
    assert report.skipped.count("stripped_away") == 1


def test_matching_is_on_the_pre_strip_path(project, temp_dir):
    out = temp_dir / "out"
    config = exarch.SecurityConfig().add_include_pattern("proj/src").with_strip_components(1)

    exarch.extract_archive(project, out, config)

    assert _files(out) == ["src/lib.rs", "src/main.rs"]


def test_flatten_lands_files_by_their_final_component(project, temp_dir):
    out = temp_dir / "out"
    config = exarch.SecurityConfig().with_flatten()

    report = exarch.extract_archive(project, out, config)

    assert _files(out) == ["README.md", "build.tmp", "lib.rs", "main.rs"]
    assert report.skipped.count("stripped_away") >= 1


def test_properties_round_trip_and_rewrite_is_one_choice():
    config = exarch.SecurityConfig()
    config.include_patterns = ["a", "b/c"]
    config.exclude_patterns = ["*.tmp"]
    assert config.include_patterns == ["a", "b/c"]
    assert config.exclude_patterns == ["*.tmp"]

    config.strip_components = 2
    assert (config.strip_components, config.flatten) == (2, False)
    config.flatten = True
    assert (config.strip_components, config.flatten) == (None, True)
    config.strip_components = None
    assert config.flatten is True
    config.strip_components = 1
    assert (config.strip_components, config.flatten) == (1, False)
    config.strip_components = None
    assert config.strip_components is None

    config.include_patterns = []
    assert config.include_patterns == []
    assert config.exclude_patterns == ["*.tmp"]


@pytest.mark.parametrize(
    ("method", "setting"),
    [("add_include_pattern", "entry_include"), ("add_exclude_pattern", "entry_exclude")],
)
@pytest.mark.parametrize("pattern", ["a**b", "{x}", "[x", "!x", "", "a,b"])
def test_a_refused_pattern_names_its_setting(method, setting, pattern):
    config = exarch.SecurityConfig()

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        getattr(config, method)(pattern)

    assert info.value.setting == setting
    assert info.value.code == "INVALID_CONFIGURATION"
    assert config.include_patterns == [] and config.exclude_patterns == []


def test_a_refused_pattern_through_the_property_names_its_setting():
    config = exarch.SecurityConfig()
    config.include_patterns = ["ok"]

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        config.include_patterns = ["fine", "a**b"]

    assert info.value.setting == "entry_include"
    assert config.include_patterns == ["ok"]


@pytest.mark.parametrize("count", [0, -1, 33, 2**70])
def test_an_out_of_range_strip_is_refused(count):
    config = exarch.SecurityConfig()

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        config.with_strip_components(count)

    assert info.value.setting == "strip_components"
    assert config.strip_components is None


@pytest.mark.parametrize("count", [True, 1.5, "1"])
def test_a_strip_of_the_wrong_type_is_a_type_error(count):
    with pytest.raises(TypeError):
        exarch.SecurityConfig().with_strip_components(count)


def test_the_strip_ceiling_follows_max_path_depth():
    config = exarch.SecurityConfig().with_max_path_depth(3)

    assert config.with_strip_components(3).strip_components == 3
    with pytest.raises(exarch.InvalidConfigurationError):
        config.with_strip_components(4)


def test_an_unmatched_include_fails_after_the_scan_and_names_the_patterns(project, temp_dir):
    out = temp_dir / "out"
    config = (
        exarch.SecurityConfig().add_include_pattern("proj/README.md").add_include_pattern("nope")
    )

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.extract_archive(project, out, config)

    assert info.value.setting == "entry_include"
    assert info.value.unmatched_patterns == ["nope"]
    assert info.value.writes == "kept"
    assert (out / "proj" / "README.md").exists()


def test_an_unmatched_include_under_atomic_commits_nothing(project, temp_dir):
    out = temp_dir / "out"
    config = exarch.SecurityConfig().add_include_pattern("nope")
    options = exarch.ExtractionOptions().with_staging("atomic")

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.extract_archive(project, out, config, options)

    assert info.value.unmatched_patterns == ["nope"]
    assert not out.exists()


def test_atomic_replace_refuses_a_selection_in_core(project, temp_dir):
    out = temp_dir / "out"
    out.mkdir()
    (out / "old").write_text("old")
    config = exarch.SecurityConfig().with_strip_components(1)
    options = exarch.ExtractionOptions().with_staging("atomic_replace")

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.extract_archive(project, out, config, options)

    assert info.value.setting == "entry_selection"
    assert (out / "old").read_text() == "old"


def test_a_hardlink_to_an_unselected_target_is_refused(temp_dir):
    archive = _tar(
        temp_dir,
        [("a/target.txt", b"x"), ("b/link.txt", ("hard", "a/target.txt"))],
    )
    config = exarch.SecurityConfig().with_allow_hardlinks().add_include_pattern("b")

    with pytest.raises(exarch.SecurityViolationError) as info:
        exarch.extract_archive(archive, temp_dir / "out", config)

    assert info.value.sub_code == "LINK_TARGET"


def test_a_link_under_flatten_is_refused(temp_dir):
    archive = _tar(temp_dir, [("a/f.txt", b"x"), ("a/l", ("sym", "f.txt"))])
    config = exarch.SecurityConfig().with_allow_symlinks().with_flatten()

    with pytest.raises(exarch.SecurityViolationError) as info:
        exarch.extract_archive(archive, temp_dir / "out", config)

    assert info.value.sub_code == "LINK_POLICY"


def test_strip_never_reopens_traversal(temp_dir):
    archive = _tar(temp_dir, [("top/../x", b"x")])
    config = exarch.SecurityConfig().with_strip_components(1)

    with pytest.raises(exarch.PathTraversalError):
        exarch.extract_archive(archive, temp_dir / "out", config)
    assert not (temp_dir / "x").exists()


def test_list_reports_the_disposition_of_every_entry(project):
    config = exarch.SecurityConfig().add_include_pattern("proj/src").with_strip_components(1)

    manifest = exarch.list_archive(project, config)
    dispositions = {str(d.path): d for d in manifest.dispositions}

    assert manifest.total_entries == 6
    extracted = {
        path: str(d.landing)
        for path, d in dispositions.items()
        if isinstance(d, exarch.ExtractDisposition)
    }
    assert extracted == {
        "proj/src/": "src",
        "proj/src/main.rs": "src/main.rs",
        "proj/src/lib.rs": "src/lib.rs",
    }
    skipped = {
        path: d.kind for path, d in dispositions.items() if isinstance(d, exarch.SkipDisposition)
    }
    assert skipped == {
        "proj/": "not_selected",
        "proj/README.md": "not_selected",
        "proj/build.tmp": "not_selected",
    }
    assert exarch.AnyEntryDisposition is not None


def test_a_manifest_keeps_the_selection_it_was_listed_with(project):
    listed_with = exarch.SecurityConfig().add_include_pattern("proj/README.md")
    manifest = exarch.list_archive(project, listed_with)
    listed_with.include_patterns = ["proj/src"]

    actions = {
        str(d.path): d.action
        for d in manifest.dispositions
        if str(d.path) in {"proj/README.md", "proj/src/main.rs"}
    }

    assert actions == {"proj/README.md": "extract", "proj/src/main.rs": "skip"}
    assert exarch.ExtractDisposition.action == "extract"
    assert exarch.SkipDisposition.action == "skip"


def test_verify_applies_the_same_selection(project):
    config = exarch.SecurityConfig().add_include_pattern("nope")

    report = exarch.verify_archive(project, config)

    assert any("nope" in issue.message for issue in report.issues)


def test_memory_extraction_applies_the_selection(project):
    data = project.read_bytes()
    config = exarch.SecurityConfig().add_include_pattern("proj/src").with_strip_components(1)

    result = exarch.extract_archive_to_memory(data, config)

    assert sorted(e.path for e in result.entries) == ["src", "src/lib.rs", "src/main.rs"]
    assert result.report.skipped.count("not_selected") >= 1


def test_callback_extraction_applies_the_selection(project):
    seen = []
    config = exarch.SecurityConfig().add_include_pattern("proj/README.md").with_flatten()

    exarch.extract_archive_to_callback(
        project.read_bytes(), lambda entry: seen.append(entry.path), config
    )

    assert seen == ["README.md"]


def test_an_unmatched_include_fails_a_memory_extraction(project):
    config = exarch.SecurityConfig().add_include_pattern("nope")

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.extract_archive_to_memory(project.read_bytes(), config)

    assert info.value.unmatched_patterns == ["nope"]
    assert info.value.writes == "discarded"


def test_selection_survives_a_config_copy_through_the_progress_variant(project, temp_dir):
    out = temp_dir / "out"
    config = exarch.SecurityConfig().add_include_pattern("proj/README.md").with_strip_components(1)
    seen = []

    exarch.extract_archive_with_progress(
        project, out, config, lambda path, total, current, written: seen.append(path)
    )

    assert _files(out) == ["README.md"]
    assert seen
