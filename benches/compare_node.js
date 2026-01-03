#!/usr/bin/env node
/**
 * Benchmark comparison: exarch-rs vs native Node.js tar/zip libraries.
 *
 * This script compares extraction performance between:
 * - exarch-rs: Rust-based secure archive extraction (via napi-rs bindings)
 * - tar-fs: Popular Node.js TAR extraction library
 * - adm-zip: Popular Node.js ZIP library
 *
 * Usage:
 *   node compare_node.js [fixtures_dir]
 *
 * Requirements:
 *   - exarch-rs package built (npm run build)
 *   - Optional: tar-fs, adm-zip for comparison (npm install tar-fs adm-zip)
 *   - Benchmark fixtures generated (./generate_fixtures.sh)
 *
 * Output:
 *   Markdown table with performance comparison and speedup ratios.
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const zlib = require('node:zlib');
const { pipeline } = require('node:stream/promises');

// Try to load comparison libraries
let tarFs;
let admZip;
let tar;

try {
  tarFs = require('tar-fs');
} catch {
  console.log('Note: tar-fs not installed. Install with: npm install tar-fs');
}

try {
  admZip = require('adm-zip');
} catch {
  console.log('Note: adm-zip not installed. Install with: npm install adm-zip');
}

try {
  tar = require('tar');
} catch {
  console.log('Note: tar not installed. Install with: npm install tar');
}

// Load exarch-rs
let exarch;
try {
  // Try loading from the built module
  exarch = require('../crates/exarch-node');
} catch {
  try {
    // Try loading from npm install
    exarch = require('exarch-rs');
  } catch {
    console.error('Error: exarch-rs not found.');
    console.error('Run: cd crates/exarch-node && npm run build');
    process.exit(1);
  }
}

/**
 * Time a function over multiple iterations and return median time in ms.
 */
async function timeFunction(fn, iterations = 3) {
  const times = [];
  for (let i = 0; i < iterations; i++) {
    const start = process.hrtime.bigint();
    await fn();
    const end = process.hrtime.bigint();
    times.push(Number(end - start) / 1_000_000); // Convert to ms
  }
  times.sort((a, b) => a - b);
  return times[Math.floor(times.length / 2)]; // Return median
}

/**
 * Create a temporary directory.
 */
function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-bench-'));
}

/**
 * Remove a directory recursively.
 */
function removeDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

/**
 * Get archive stats (file count, total size).
 */
function getArchiveStats(archivePath) {
  // Return pre-calculated stats based on fixture name
  const basename = path.basename(archivePath);

  const stats = {
    'small_files.tar': { files: 1000, bytes: 1024 * 1000 },
    'small_files.tar.gz': { files: 1000, bytes: 1024 * 1000 },
    'small_files.zip': { files: 1000, bytes: 1024 * 1000 },
    'medium_files.tar': { files: 100, bytes: 100 * 100 * 1024 },
    'medium_files.tar.gz': { files: 100, bytes: 100 * 100 * 1024 },
    'medium_files.zip': { files: 100, bytes: 100 * 100 * 1024 },
    'large_file.tar': { files: 1, bytes: 100 * 1024 * 1024 },
    'large_file.tar.gz': { files: 1, bytes: 100 * 1024 * 1024 },
    'large_file.zip': { files: 1, bytes: 100 * 1024 * 1024 },
    'nested_dirs.tar.gz': { files: 60, bytes: 60 * 1024 },
    'nested_dirs.zip': { files: 60, bytes: 60 * 1024 },
    'many_files.tar.gz': { files: 10000, bytes: 10000 * 20 },
    'many_files.zip': { files: 10000, bytes: 10000 * 20 },
    'mixed.tar.gz': { files: 555, bytes: 500 * 1024 + 50 * 100 * 1024 + 5 * 1024 * 1024 },
    'mixed.zip': { files: 555, bytes: 500 * 1024 + 50 * 100 * 1024 + 5 * 1024 * 1024 },
  };

  return stats[basename] || { files: 0, bytes: 0 };
}

/**
 * Benchmark TAR extraction with exarch vs tar-fs/tar.
 */
async function benchmarkTarExtraction(archivePath, iterations = 3) {
  const results = { exarch: 0, native: 0 };

  // Exarch extraction (sync)
  results.exarch = await timeFunction(() => {
    const tmpdir = createTempDir();
    try {
      const config = new exarch.SecurityConfig();
      exarch.extractArchiveSync(archivePath, tmpdir, config);
    } finally {
      removeDir(tmpdir);
    }
  }, iterations);

  // Native extraction with tar (if available)
  if (tar) {
    results.native = await timeFunction(async () => {
      const tmpdir = createTempDir();
      try {
        await tar.extract({
          file: archivePath,
          cwd: tmpdir,
        });
      } finally {
        removeDir(tmpdir);
      }
    }, iterations);
  } else if (tarFs) {
    // Fallback to tar-fs
    results.native = await timeFunction(async () => {
      const tmpdir = createTempDir();
      try {
        const isGzipped = archivePath.endsWith('.gz');
        const readStream = fs.createReadStream(archivePath);
        const extractStream = tarFs.extract(tmpdir);

        if (isGzipped) {
          await pipeline(readStream, zlib.createGunzip(), extractStream);
        } else {
          await pipeline(readStream, extractStream);
        }
      } finally {
        removeDir(tmpdir);
      }
    }, iterations);
  }

  return results;
}

/**
 * Benchmark ZIP extraction with exarch vs adm-zip.
 */
async function benchmarkZipExtraction(archivePath, iterations = 3) {
  const results = { exarch: 0, native: 0 };

  // Exarch extraction (sync)
  results.exarch = await timeFunction(() => {
    const tmpdir = createTempDir();
    try {
      const config = new exarch.SecurityConfig();
      exarch.extractArchiveSync(archivePath, tmpdir, config);
    } finally {
      removeDir(tmpdir);
    }
  }, iterations);

  // Native extraction with adm-zip
  if (admZip) {
    results.native = await timeFunction(() => {
      const tmpdir = createTempDir();
      try {
        const zip = new admZip(archivePath);
        zip.extractAllTo(tmpdir, true);
      } finally {
        removeDir(tmpdir);
      }
    }, iterations);
  }

  return results;
}

/**
 * Format a number with thousands separators.
 */
function formatNumber(num) {
  return num.toLocaleString();
}

/**
 * Format results as markdown.
 */
function formatResultsMarkdown(results) {
  const lines = [
    '# Node.js Benchmark Results: exarch-rs vs tar-fs/adm-zip',
    '',
    '## Extraction Performance',
    '',
    '| Archive | Files | Size | exarch (ms) | Native (ms) | Speedup | exarch MB/s |',
    '|---------|-------|------|-------------|-------------|---------|-------------|',
  ];

  for (const r of results) {
    const sizeMb = r.totalBytes / 1024 / 1024;
    const speedup = r.nativeTime > 0 ? r.nativeTime / r.exarchTime : 0;
    const speedupStr = speedup > 0 ? `${speedup.toFixed(2)}x` : 'N/A';
    const throughput = r.exarchTime > 0 ? sizeMb / (r.exarchTime / 1000) : 0;

    lines.push(
      `| ${r.name} | ${formatNumber(r.fileCount)} | ${sizeMb.toFixed(1)} MB | ` +
      `${r.exarchTime.toFixed(1)} | ${r.nativeTime > 0 ? r.nativeTime.toFixed(1) : 'N/A'} | ` +
      `**${speedupStr}** | ${throughput.toFixed(1)} |`
    );
  }

  // Summary
  const validResults = results.filter(r => r.nativeTime > 0);
  if (validResults.length > 0) {
    const avgSpeedup = validResults.reduce((sum, r) => sum + r.nativeTime / r.exarchTime, 0) / validResults.length;
    const maxSpeedup = Math.max(...validResults.map(r => r.nativeTime / r.exarchTime));

    lines.push(
      '',
      '## Summary',
      '',
      `- **Average speedup**: ${avgSpeedup.toFixed(2)}x faster than native Node.js`,
      `- **Maximum speedup**: ${maxSpeedup.toFixed(2)}x`,
      '',
      '### Performance Targets (from CLAUDE.md)',
      '',
      '| Format | Target | Achieved |',
      '|--------|--------|----------|',
    );

    // Calculate throughput for targets
    const tarResults = results.filter(r => r.name.includes('TAR') && r.totalBytes > 10_000_000);
    const zipResults = results.filter(r => r.name.includes('ZIP') && r.totalBytes > 10_000_000);

    if (tarResults.length > 0) {
      const avgTarThroughput = tarResults.reduce((sum, r) => {
        const sizeMb = r.totalBytes / 1024 / 1024;
        return sum + sizeMb / (r.exarchTime / 1000);
      }, 0) / tarResults.length;
      const tarStatus = avgTarThroughput >= 500 ? 'Yes' : 'No';
      lines.push(`| TAR extraction | 500 MB/s | ${avgTarThroughput.toFixed(0)} MB/s (${tarStatus}) |`);
    }

    if (zipResults.length > 0) {
      const avgZipThroughput = zipResults.reduce((sum, r) => {
        const sizeMb = r.totalBytes / 1024 / 1024;
        return sum + sizeMb / (r.exarchTime / 1000);
      }, 0) / zipResults.length;
      const zipStatus = avgZipThroughput >= 300 ? 'Yes' : 'No';
      lines.push(`| ZIP extraction | 300 MB/s | ${avgZipThroughput.toFixed(0)} MB/s (${zipStatus}) |`);
    }
  }

  lines.push(
    '',
    '## Notes',
    '',
    '- Native TAR uses `tar` package (or `tar-fs` fallback)',
    '- Native ZIP uses `adm-zip` package',
    '- exarch uses `SecurityConfig.default()` with all security checks enabled',
    '- Times are median of 5 iterations',
    '- Speedup > 1x means exarch-rs is faster',
    '- N/A indicates native library not installed',
    '',
  );

  return lines.join('\n');
}

/**
 * Main benchmark function.
 */
async function main() {
  const args = process.argv.slice(2);
  const fixturesDir = args[0] || './fixtures';
  const iterations = parseInt(args[1], 10) || 5;

  console.log('='.repeat(60));
  console.log('Node.js Benchmark: exarch-rs vs tar-fs/adm-zip');
  console.log('='.repeat(60));
  console.log();

  if (!fs.existsSync(fixturesDir)) {
    console.error(`Error: Fixtures directory not found: ${fixturesDir}`);
    console.error('Run ./generate_fixtures.sh first to create benchmark fixtures.');
    process.exit(1);
  }

  console.log(`Fixtures directory: ${fixturesDir}`);
  console.log(`Iterations per benchmark: ${iterations}`);
  console.log(`Native TAR library: ${tar ? 'tar' : tarFs ? 'tar-fs' : 'not installed'}`);
  console.log(`Native ZIP library: ${admZip ? 'adm-zip' : 'not installed'}`);
  console.log();

  const results = [];

  // TAR benchmarks
  const tarFixtures = [
    ['small_files.tar', 'TAR small (1MB, 1000 files)'],
    ['small_files.tar.gz', 'TAR+GZIP small'],
    ['medium_files.tar', 'TAR medium (10MB, 100 files)'],
    ['medium_files.tar.gz', 'TAR+GZIP medium'],
    ['large_file.tar', 'TAR large (100MB, 1 file)'],
    ['large_file.tar.gz', 'TAR+GZIP large'],
    ['nested_dirs.tar.gz', 'TAR nested dirs'],
    ['many_files.tar.gz', 'TAR many files (10k)'],
    ['mixed.tar.gz', 'TAR mixed sizes'],
  ];

  for (const [filename, name] of tarFixtures) {
    const archivePath = path.join(fixturesDir, filename);
    if (!fs.existsSync(archivePath)) {
      console.log(`  Skipping ${name}: ${filename} not found`);
      continue;
    }

    console.log(`  Benchmarking ${name}...`);
    const stats = getArchiveStats(archivePath);
    const times = await benchmarkTarExtraction(archivePath, iterations);

    results.push({
      name,
      exarchTime: times.exarch,
      nativeTime: times.native,
      fileCount: stats.files,
      totalBytes: stats.bytes,
    });
  }

  // ZIP benchmarks
  const zipFixtures = [
    ['small_files.zip', 'ZIP small (1MB, 1000 files)'],
    ['medium_files.zip', 'ZIP medium (10MB, 100 files)'],
    ['large_file.zip', 'ZIP large (100MB, 1 file)'],
    ['nested_dirs.zip', 'ZIP nested dirs'],
    ['many_files.zip', 'ZIP many files (10k)'],
    ['mixed.zip', 'ZIP mixed sizes'],
  ];

  for (const [filename, name] of zipFixtures) {
    const archivePath = path.join(fixturesDir, filename);
    if (!fs.existsSync(archivePath)) {
      console.log(`  Skipping ${name}: ${filename} not found`);
      continue;
    }

    console.log(`  Benchmarking ${name}...`);
    const stats = getArchiveStats(archivePath);
    const times = await benchmarkZipExtraction(archivePath, iterations);

    results.push({
      name,
      exarchTime: times.exarch,
      nativeTime: times.native,
      fileCount: stats.files,
      totalBytes: stats.bytes,
    });
  }

  console.log();
  const markdown = formatResultsMarkdown(results);
  console.log(markdown);

  // Write results to file if -o flag provided
  const outputIndex = args.indexOf('-o');
  if (outputIndex !== -1 && args[outputIndex + 1]) {
    fs.writeFileSync(args[outputIndex + 1], markdown);
    console.log(`Results written to: ${args[outputIndex + 1]}`);
  }
}

main().catch(err => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
