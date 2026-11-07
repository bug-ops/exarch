/**
 * Entry selection and path rewriting (#967): include and exclude patterns,
 * stripComponents and flatten on SecurityConfig, shared by extract, list,
 * verify and the in-memory and callback functions.
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  SecurityConfig,
  ExtractionOptions,
  extractArchiveSync,
  extractArchiveToMemory,
  extractArchiveToCallbackSync,
  listArchiveSync,
  listArchiveBytes,
  verifyArchiveSync,
  verifyArchiveBytesSync,
} = require('../index.js');

function tarEntry(name, { type = '0', text = '', link = '' } = {}) {
  const data = Buffer.from(text);
  const header = Buffer.alloc(512);
  header.write(name, 0);
  header.write('0000644\0', 100);
  header.write('0000000\0', 108);
  header.write('0000000\0', 116);
  header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  header.write('00000000000\0', 136);
  header.write(type, 156);
  header.write(link, 157);
  header.write('ustar\0', 257);
  header.write('00', 263);
  header.fill(0x20, 148, 156);
  const sum = header.reduce((acc, byte) => acc + byte, 0);
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(padded);
  return Buffer.concat([header, padded]);
}

const dir = (name) => tarEntry(name, { type: '5' });
const file = (name, text = name) => tarEntry(name, { text });
const tarOf = (...entries) => Buffer.concat([...entries, Buffer.alloc(1024)]);

const TREE = tarOf(
  dir('top/'),
  file('top/a.txt'),
  dir('top/sub/'),
  file('top/sub/b.rs'),
  file('top/sub/c.tmp'),
  file('top/sub/deep/d.rs')
);

describe('entry selection', () => {
  let tempDir;
  let archive;
  let out;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-selection-'));
    archive = path.join(tempDir, 'tree.tar');
    out = path.join(tempDir, 'out');
    fs.writeFileSync(archive, TREE);
    fs.mkdirSync(out);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  const extractedFiles = () =>
    fs
      .readdirSync(out, { recursive: true, withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => path.relative(out, path.join(entry.parentPath, entry.name)))
      .sort();

  describe('configuration', () => {
    it('selects every entry and keeps every path by default', () => {
      const config = new SecurityConfig();
      assert.deepStrictEqual(config.includePatterns, []);
      assert.deepStrictEqual(config.excludePatterns, []);
      assert.strictEqual(config.stripComponents, null);
      assert.strictEqual(config.flatten, false);
    });

    it('appends, replaces and clears the pattern lists', () => {
      const config = new SecurityConfig().addIncludePattern('a').addIncludePattern('b/c');
      assert.deepStrictEqual(config.includePatterns, ['a', 'b/c']);
      assert.strictEqual(config.withIncludePatterns(['x']), config);
      assert.deepStrictEqual(config.includePatterns, ['x']);
      config.addExcludePattern('*.tmp').addExcludePattern('gen');
      assert.deepStrictEqual(config.excludePatterns, ['*.tmp', 'gen']);
      config.withExcludePatterns([]).withIncludePatterns([]);
      assert.deepStrictEqual(config.includePatterns, []);
      assert.deepStrictEqual(config.excludePatterns, []);
    });

    it('refuses a bad pattern as INVALID_CONFIGURATION naming its list and keeps the old one', () => {
      const config = new SecurityConfig()
        .withIncludePatterns(['keep'])
        .withExcludePatterns(['gone']);
      assert.throws(() => config.addIncludePattern('a**b'), {
        code: 'INVALID_CONFIGURATION',
        setting: 'entry_include',
      });
      assert.throws(() => config.withIncludePatterns(['ok', 'a,b']), {
        code: 'INVALID_CONFIGURATION',
        setting: 'entry_include',
      });
      assert.throws(() => config.withExcludePatterns(['ok', '{x}']), {
        code: 'INVALID_CONFIGURATION',
        setting: 'entry_exclude',
      });
      assert.throws(() => config.addExcludePattern(''), {
        code: 'INVALID_CONFIGURATION',
        setting: 'entry_exclude',
      });
      assert.deepStrictEqual(config.includePatterns, ['keep']);
      assert.deepStrictEqual(config.excludePatterns, ['gone']);
    });

    it('sets a strip count, which flatten replaces and the reverse', () => {
      const config = new SecurityConfig();
      assert.strictEqual(config.withStripComponents(2), config);
      assert.strictEqual(config.stripComponents, 2);
      config.withFlatten(true);
      assert.strictEqual(config.flatten, true);
      assert.strictEqual(config.stripComponents, null);
      config.withStripComponents(1);
      assert.strictEqual(config.flatten, false);
      config.withStripComponents(null);
      assert.strictEqual(config.stripComponents, null);
      assert.strictEqual(config.flatten, false);
    });

    it('keeps flatten when the strip count is cleared', () => {
      const config = new SecurityConfig().withFlatten(true);
      config.withStripComponents(null);
      assert.strictEqual(config.flatten, true);
      config.withFlatten(false);
      assert.strictEqual(config.flatten, false);
      assert.strictEqual(config.stripComponents, null);
    });

    it('refuses an unusable strip count as INVALID_CONFIGURATION and keeps the old one', () => {
      const config = new SecurityConfig().withStripComponents(1);
      for (const bad of [0, -1, 1.5, NaN, Infinity, 2 ** 60, 10_000]) {
        assert.throws(
          () => config.withStripComponents(bad),
          { code: 'INVALID_CONFIGURATION', setting: 'strip_components' },
          String(bad)
        );
        assert.strictEqual(config.stripComponents, 1);
      }
      assert.throws(() => config.withStripComponents(undefined));
      assert.strictEqual(config.stripComponents, 1);
    });

    it('bounds the strip count by maxPathDepth', () => {
      const config = new SecurityConfig().withMaxPathDepth(2);
      config.withStripComponents(2);
      assert.throws(() => config.withStripComponents(3), { setting: 'strip_components' });
    });
  });

  describe('extractArchiveSync', () => {
    it('extracts only the entries an include pattern selects and counts the rest', () => {
      const config = new SecurityConfig().addIncludePattern('top/sub');
      const report = extractArchiveSync(archive, out, config);
      assert.deepStrictEqual(extractedFiles(), [
        'top/sub/b.rs',
        'top/sub/c.tmp',
        'top/sub/deep/d.rs',
      ]);
      const kinds = Object.fromEntries(report.skipped.counts.map((c) => [c.kind, c.count]));
      assert.ok(kinds.not_selected >= 1, JSON.stringify(report.skipped));
      assert.strictEqual(report.filesSkipped >= 1, true);
    });

    it('selects entries with glob patterns', () => {
      const config = new SecurityConfig()
        .addIncludePattern('top/**/?.rs')
        .addExcludePattern('d.*');
      extractArchiveSync(archive, out, config);
      assert.deepStrictEqual(extractedFiles(), ['top/sub/b.rs']);
    });

    it('lets an exclude pattern win over an include pattern', () => {
      const config = new SecurityConfig().addIncludePattern('top/sub').addExcludePattern('*.tmp');
      extractArchiveSync(archive, out, config);
      assert.deepStrictEqual(extractedFiles(), ['top/sub/b.rs', 'top/sub/deep/d.rs']);
    });

    it('does not fail on an exclude pattern that matches nothing', () => {
      const config = new SecurityConfig().addExcludePattern('absent');
      const report = extractArchiveSync(archive, out, config);
      assert.strictEqual(report.filesExtracted, 4);
    });

    it('strips leading components and counts what is left with no name', () => {
      const config = new SecurityConfig().withStripComponents(1);
      const report = extractArchiveSync(archive, out, config);
      assert.deepStrictEqual(extractedFiles(), ['a.txt', 'sub/b.rs', 'sub/c.tmp', 'sub/deep/d.rs']);
      const kinds = Object.fromEntries(report.skipped.counts.map((c) => [c.kind, c.count]));
      assert.strictEqual(kinds.stripped_away, 1, 'the top/ directory entry');
    });

    it('matches patterns against the path before stripping', () => {
      const config = new SecurityConfig().addIncludePattern('top/sub').withStripComponents(2);
      extractArchiveSync(archive, out, config);
      assert.deepStrictEqual(extractedFiles(), ['b.rs', 'c.tmp', 'deep/d.rs']);
    });

    it('flattens regular files to their final component and skips directories', () => {
      const config = new SecurityConfig().withFlatten(true);
      const report = extractArchiveSync(archive, out, config);
      assert.deepStrictEqual(extractedFiles(), ['a.txt', 'b.rs', 'c.tmp', 'd.rs']);
      const kinds = Object.fromEntries(report.skipped.counts.map((c) => [c.kind, c.count]));
      assert.strictEqual(kinds.stripped_away, 2, 'the top/ and top/sub/ directory entries');
    });

    it('counts a flatten collision as a duplicate under the default policy', () => {
      const clash = tarOf(file('x/a.txt', 'first'), file('y/a.txt', 'second'));
      const clashPath = path.join(tempDir, 'clash.tar');
      fs.writeFileSync(clashPath, clash);
      const config = new SecurityConfig().withFlatten(true);
      const report = extractArchiveSync(clashPath, out, config);
      assert.strictEqual(report.filesExtracted, 1);
      const kinds = Object.fromEntries(report.skipped.counts.map((c) => [c.kind, c.count]));
      assert.strictEqual(kinds.duplicate, 1);
      assert.strictEqual(fs.readFileSync(path.join(out, 'a.txt'), 'utf8'), 'first');
    });

    it('fails after the scan on an include pattern that matched nothing, naming every one', () => {
      const config = new SecurityConfig()
        .addIncludePattern('top/a.txt')
        .addIncludePattern('missing')
        .addIncludePattern('also/missing');
      assert.throws(
        () => extractArchiveSync(archive, out, config),
        (err) => {
          assert.strictEqual(err.code, 'INVALID_CONFIGURATION');
          assert.strictEqual(err.setting, 'entry_include');
          assert.deepStrictEqual(err.unmatchedPatterns, ['missing', 'also/missing']);
          assert.strictEqual(err.writes, 'kept');
          assert.strictEqual(err.filesExtracted, 1);
          return true;
        }
      );
    });

    it("rolls an unmatched include back under 'atomic' and commits nothing", () => {
      const destination = path.join(tempDir, 'atomic-out');
      const config = new SecurityConfig()
        .addIncludePattern('top/a.txt')
        .addIncludePattern('missing');
      const options = new ExtractionOptions().withStaging('atomic');
      assert.throws(
        () => extractArchiveSync(archive, destination, config, options),
        (err) => {
          assert.deepStrictEqual(err.unmatchedPatterns, ['missing']);
          assert.strictEqual(err.writes, 'rolled_back');
          return true;
        }
      );
      assert.ok(!fs.existsSync(destination));
    });

    it("refuses 'atomic_replace' with a non-default selection in core", () => {
      const options = new ExtractionOptions().withStaging('atomic_replace');
      for (const config of [
        new SecurityConfig().addIncludePattern('top'),
        new SecurityConfig().withStripComponents(1),
        new SecurityConfig().withFlatten(true),
      ]) {
        assert.throws(() => extractArchiveSync(archive, out, config, options), {
          code: 'INVALID_CONFIGURATION',
          setting: 'entry_selection',
        });
      }
    });

    it('refuses a selected symlink under flatten instead of skipping it', () => {
      const links = tarOf(file('d/f.txt'), tarEntry('d/ln', { type: '2', link: 'f.txt' }));
      const linksPath = path.join(tempDir, 'links.tar');
      fs.writeFileSync(linksPath, links);
      const config = new SecurityConfig().withAllowSymlinks(true).withFlatten(true);
      assert.throws(() => extractArchiveSync(linksPath, out, config), {
        code: 'SECURITY_VIOLATION',
        subCode: 'LINK_POLICY',
      });
    });

    it('refuses a hardlink whose target the selection leaves out', () => {
      const links = tarOf(file('t.txt'), tarEntry('h', { type: '1', link: 't.txt' }));
      const linksPath = path.join(tempDir, 'hard.tar');
      fs.writeFileSync(linksPath, links);
      const config = new SecurityConfig().withAllowHardlinks(true).addIncludePattern('h');
      assert.throws(() => extractArchiveSync(linksPath, out, config), {
        code: 'SECURITY_VIOLATION',
        subCode: 'LINK_TARGET',
      });
    });

    it('refuses a hardlink whose target several entries land on after stripping', () => {
      const links = tarOf(
        file('x/a.txt', 'one'),
        file('y/a.txt', 'two'),
        tarEntry('x/h', { type: '1', link: 'x/a.txt' })
      );
      const linksPath = path.join(tempDir, 'ambiguous.tar');
      fs.writeFileSync(linksPath, links);
      const config = new SecurityConfig().withAllowHardlinks(true).withStripComponents(1);
      assert.throws(() => extractArchiveSync(linksPath, out, config), {
        code: 'SECURITY_VIOLATION',
        subCode: 'LINK_TARGET',
      });
    });

    it('still refuses an unsafe name that is not selected', () => {
      const unsafe = tarOf(file('ok.txt'), file('../escape.txt'));
      const unsafePath = path.join(tempDir, 'unsafe.tar');
      fs.writeFileSync(unsafePath, unsafe);
      const config = new SecurityConfig().addIncludePattern('ok.txt');
      assert.throws(() => extractArchiveSync(unsafePath, out, config), {
        code: 'PATH_TRAVERSAL',
      });
      assert.ok(!fs.existsSync(path.join(tempDir, 'escape.txt')));
    });
  });

  describe('list and verify', () => {
    it('lists every entry whatever the selection is', () => {
      const plain = listArchiveSync(archive);
      const selected = listArchiveSync(archive, new SecurityConfig().addIncludePattern('missing'));
      assert.strictEqual(selected.totalEntries, plain.totalEntries);
    });

    it('reports what extraction does with every entry as typed dispositions', () => {
      const config = new SecurityConfig().addIncludePattern('top/sub').withStripComponents(1);
      const manifest = listArchiveSync(archive, config);
      const byPath = Object.fromEntries(manifest.dispositions.map((d) => [d.path, d]));
      assert.deepStrictEqual(byPath['top/sub/b.rs'], {
        action: 'extract',
        path: 'top/sub/b.rs',
        landing: 'sub/b.rs',
      });
      assert.deepStrictEqual(byPath['top/a.txt'], {
        action: 'skip',
        path: 'top/a.txt',
        kind: 'not_selected',
      });
      assert.strictEqual(byPath['top/'].action, 'skip');
    });

    it('reports every entry as extracted at its own path without a selection', () => {
      const manifest = listArchiveSync(archive);
      assert.strictEqual(manifest.dispositions.length, manifest.totalEntries);
      for (const disposition of manifest.dispositions) {
        assert.strictEqual(disposition.action, 'extract');
        assert.strictEqual(disposition.landing, disposition.path.replace(/\/$/, ''));
      }
    });

    it('agrees with what extraction writes', () => {
      const config = new SecurityConfig().addExcludePattern('*.tmp').withFlatten(true);
      const manifest = listArchiveSync(archive, config);
      const landings = manifest.dispositions
        .filter((d) => d.action === 'extract')
        .map((d) => d.landing)
        .sort();
      extractArchiveSync(archive, out, config);
      assert.deepStrictEqual(landings, extractedFiles());
    });

    it('also lists dispositions for in-memory archives', async () => {
      const config = new SecurityConfig().withFlatten(true);
      const manifest = await listArchiveBytes(TREE, config);
      const skipped = manifest.dispositions.filter((d) => d.action === 'skip');
      assert.ok(skipped.every((d) => d.kind === 'stripped_away'));
      assert.strictEqual(manifest.dispositions.length - skipped.length, 4);
    });

    it('verifies a selection that extract would accept', () => {
      const config = new SecurityConfig().addIncludePattern('top/sub').withStripComponents(1);
      const report = verifyArchiveSync(archive, config);
      assert.strictEqual(report.status, 'PASS', JSON.stringify(report.issues));
    });

    it('reports an unmatched include as an issue, as extract refuses it', () => {
      const config = new SecurityConfig().addIncludePattern('missing');
      const report = verifyArchiveSync(archive, config);
      assert.strictEqual(report.status, 'FAIL');
      assert.ok(
        report.issues.some((issue) => issue.code === 'INVALID_CONFIGURATION'),
        JSON.stringify(report.issues)
      );
    });

    it('reports a hardlink to an unselected target as an issue, as extract refuses it', () => {
      const links = tarOf(file('t.txt'), tarEntry('h', { type: '1', link: 't.txt' }));
      const config = new SecurityConfig().withAllowHardlinks(true).addIncludePattern('h');
      const report = verifyArchiveBytesSync(links, config);
      assert.strictEqual(report.status, 'FAIL');
      assert.ok(
        report.issues.some((issue) => issue.subCode === 'LINK_TARGET'),
        JSON.stringify(report.issues)
      );
    });
  });

  describe('in-memory and callback extraction', () => {
    it('applies the selection to extractArchiveToMemory', async () => {
      const config = new SecurityConfig().addIncludePattern('top/sub').withStripComponents(2);
      const result = await extractArchiveToMemory(TREE, config);
      const paths = result.entries.map((entry) => entry.path).sort();
      assert.deepStrictEqual(paths, ['b.rs', 'c.tmp', 'deep/d.rs']);
    });

    it('applies flatten to extractArchiveToCallbackSync', () => {
      const seen = [];
      const config = new SecurityConfig().withFlatten(true);
      extractArchiveToCallbackSync(TREE, (entry) => seen.push(entry.path), config);
      assert.deepStrictEqual(seen.sort(), ['a.txt', 'b.rs', 'c.tmp', 'd.rs']);
    });

    it('fails an unmatched include after delivering what matched', async () => {
      const config = new SecurityConfig()
        .addIncludePattern('top/a.txt')
        .addIncludePattern('missing');
      await assert.rejects(extractArchiveToMemory(TREE, config), (err) => {
        assert.strictEqual(err.code, 'INVALID_CONFIGURATION');
        assert.deepStrictEqual(err.unmatchedPatterns, ['missing']);
        assert.strictEqual(err.writes, 'discarded');
        return true;
      });
    });
  });
});
