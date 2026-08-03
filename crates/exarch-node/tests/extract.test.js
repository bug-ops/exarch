/**
 * Tests for archive extraction functions
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  extractArchive,
  extractArchiveSync,
  createArchiveSync,
  SecurityConfig,
} = require('../index.js');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-test-'));
}

function createValidArchive(archivePath, tempDir) {
  // Create source files
  const sourceDir = path.join(tempDir, 'source');
  fs.mkdirSync(sourceDir);
  fs.writeFileSync(path.join(sourceDir, 'hello.txt'), 'Hello, World!');

  // Create archive using our library
  createArchiveSync(archivePath, [sourceDir]);
}

describe('extractArchive (async)', () => {
  let tempDir;
  let archivePath;
  let outputDir;

  beforeEach(() => {
    tempDir = createTempDir();
    archivePath = path.join(tempDir, 'test.tar.gz');
    outputDir = path.join(tempDir, 'output');
    fs.mkdirSync(outputDir);
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('should extract a valid archive', async () => {
    createValidArchive(archivePath, tempDir);

    const report = await extractArchive(archivePath, outputDir);

    assert.strictEqual(report.filesExtracted, 1);
    assert.ok(report.bytesWritten >= 13);
    assert.ok(report.durationMs >= 0);

    // Verify extracted file exists and has correct content
    const extractedFile = path.join(outputDir, 'hello.txt');
    assert.ok(fs.existsSync(extractedFile), 'Extracted file should exist');
    const content = fs.readFileSync(extractedFile, 'utf8');
    assert.strictEqual(content, 'Hello, World!');
  });

  it('should accept custom SecurityConfig', async () => {
    createValidArchive(archivePath, tempDir);

    const config = new SecurityConfig();
    config.setMaxFileSize(1024 * 1024);
    const report = await extractArchive(archivePath, outputDir, config);

    assert.ok(report.filesExtracted >= 1);
  });

  // End-to-end regression test for #508: convert_error's PartialExtraction
  // arm must forward filesSkipped/warnings, not just filesExtracted/
  // bytesWritten. Exercises the real extraction path (not just
  // convert_error directly, unlike the Rust-level unit tests) with an
  // archive that both skips an extension-disallowed entry (non-fatal,
  // extraction continues) and then trips a real failure (a file-count
  // quota), so the resulting error carries a non-zero skip count and a
  // real aggregated warning alongside the fatal QUOTA_EXCEEDED error.
  it('carries filesSkipped and warnings on a real PartialExtraction', async () => {
    const sourceDir = path.join(tempDir, 'source');
    fs.mkdirSync(sourceDir);
    // addAllowedExtension matches against the entry's extension without the
    // leading dot, so 'blocked.exe' is rejected while the '.txt' files pass.
    const blockedPath = path.join(sourceDir, 'blocked.exe');
    const firstPath = path.join(sourceDir, 'first.txt');
    const secondPath = path.join(sourceDir, 'second.txt');
    fs.writeFileSync(blockedPath, 'MZ');
    fs.writeFileSync(firstPath, 'ok');
    fs.writeFileSync(secondPath, 'also ok');
    // Pass explicit file paths (not the containing directory) so archive
    // entry order matches this array's order deterministically: creation
    // iterates `sources` in order (crates/exarch-core/src/creation/walker.rs),
    // but a directory source is walked via `WalkDir` with no `.sort_by`, so
    // its entry order is unspecified OS `read_dir` order — that would make
    // `blocked.exe` sometimes lose the race against the quota trip, flaking
    // this test across platforms (see #508 review S4).
    createArchiveSync(archivePath, [blockedPath, firstPath, secondPath]);

    const config = new SecurityConfig();
    config.addAllowedExtension('txt');
    config.setMaxFileCount(1);

    await assert.rejects(
      () => extractArchive(archivePath, outputDir, config),
      (err) => {
        assert.match(err.message, /^QUOTA_EXCEEDED/);
        assert.match(err.message, /filesSkipped=1/);
        assert.match(err.message, /disallowed extension/);
        return true;
      }
    );
  });

  // End-to-end regression test for #508 (true skip-only scenario, now
  // reachable via #509's ArchiveError::partial_or fix). The test above
  // always has at least one file extracted before the fatal error, so it
  // was already reachable as PartialExtraction even under the old, pre-#509
  // partial_or (which only wrapped when something had actually been
  // written). #508's repro steps describe the case where *nothing* is
  // extracted before the failure — a skip-only report where
  // filesExtracted/bytesWritten alone carry zero actionable information and
  // filesSkipped/warnings are the only signal. This archive has an
  // extension-disallowed entry (non-fatal skip) immediately followed by a
  // symlink escape (fatal, and the very first entry that would have written
  // anything), so the resulting error carries filesExtracted=0/bytesWritten=0.
  it('carries filesSkipped and warnings on a skip-only PartialExtraction', async (t) => {
    if (process.platform === 'win32') {
      return t.skip('symlink creation requires elevated privileges on Windows');
    }

    // Two single-entry directories, not one shared directory or two bare
    // file paths:
    // - A bare (non-directory) symlink source hits a real quirk in
    //   `collect_entries`'s single-file branch (walker.rs): it calls
    //   `std::fs::metadata` (follows symlinks) instead of
    //   `symlink_metadata`, so `metadata.is_symlink()` is always false and
    //   the symlink gets archived as a plain File — extension-checked and
    //   content-copied like any other file, defeating this test. Routing it
    //   through a directory walk (`FilteredWalker`, which correctly uses
    //   `follow_links(false)`/lstat semantics) preserves its symlink type.
    // - Each directory holds exactly one entry, so within-directory walk
    //   order can't matter, while the top-level `sources` array order
    //   (`collect_entries` iterates it with a plain `for` loop) still
    //   deterministically puts `blocked.exe` before the escape attempt —
    //   same entry-order concern as the test above (#508 review S4).
    const blockedDir = path.join(tempDir, 'blocked-dir');
    fs.mkdirSync(blockedDir);
    fs.writeFileSync(path.join(blockedDir, 'blocked.exe'), 'MZ');

    const linkDir = path.join(tempDir, 'link-dir');
    fs.mkdirSync(linkDir);
    // The symlink target must exist on disk at archive-creation time —
    // `collect_entries` checks `Path::exists()`, which follows symlinks and
    // errors with SOURCE_NOT_FOUND for a dangling one. Point it at a real
    // file one level above `linkDir` (`../outside.txt`); once extracted, the
    // link lands directly under `outputDir`, so the same relative target
    // resolves outside the extraction destination — a genuine escape.
    fs.writeFileSync(path.join(tempDir, 'outside.txt'), 'should not be reachable');
    fs.symlinkSync('../outside.txt', path.join(linkDir, 'evil_link'));

    createArchiveSync(archivePath, [blockedDir, linkDir]);

    const config = new SecurityConfig();
    config.addAllowedExtension('txt');
    config.setAllowSymlinks(true);

    await assert.rejects(
      () => extractArchive(archivePath, outputDir, config),
      (err) => {
        assert.match(err.message, /^SYMLINK_ESCAPE/);
        assert.match(err.message, /filesExtracted=0/);
        assert.match(err.message, /bytesWritten=0/);
        assert.match(err.message, /filesSkipped=1/);
        assert.match(err.message, /disallowed extension/);
        return true;
      }
    );
  });
});

describe('extractArchiveSync', () => {
  let tempDir;
  let archivePath;
  let outputDir;

  beforeEach(() => {
    tempDir = createTempDir();
    archivePath = path.join(tempDir, 'test.tar.gz');
    outputDir = path.join(tempDir, 'output');
    fs.mkdirSync(outputDir);
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('should extract a valid archive synchronously', () => {
    createValidArchive(archivePath, tempDir);

    const report = extractArchiveSync(archivePath, outputDir);

    assert.strictEqual(report.filesExtracted, 1);
    assert.ok(report.bytesWritten >= 13);

    // Verify extracted file exists and has correct content
    const extractedFile = path.join(outputDir, 'hello.txt');
    assert.ok(fs.existsSync(extractedFile), 'Extracted file should exist');
    const content = fs.readFileSync(extractedFile, 'utf8');
    assert.strictEqual(content, 'Hello, World!');
  });

  it('should accept custom SecurityConfig', () => {
    createValidArchive(archivePath, tempDir);

    const config = new SecurityConfig();
    config.setMaxFileCount(100);
    const report = extractArchiveSync(archivePath, outputDir, config);

    assert.ok(report.filesExtracted >= 1);
  });
});
