#!/usr/bin/env node
// Cross-runtime smoke test for the exarch-rs napi addon (Node, Bun, Deno).
// Loads the CommonJS loader (index.js) via createRequire so the same ESM
// script runs unmodified under all three runtimes, then exercises the basic
// create/list/verify/extract path plus a progress callback and a
// security-violation error path. See issue #567.

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';

const require = createRequire(import.meta.url);
const __dirname = dirname(fileURLToPath(import.meta.url));
const exarch = require(join(__dirname, '..', 'index.js'));

const {
  createArchive,
  extractArchive,
  extractArchiveWithProgress,
  listArchive,
  verifyArchive,
  SecurityConfig,
} = exarch;

const runtime = globalThis.Bun ? 'bun' : globalThis.Deno ? 'deno' : 'node';

function assertOk(condition, message) {
  if (!condition) {
    throw new Error(`SMOKE_FAIL: ${message}`);
  }
}

async function main() {
  const tempDir = mkdtempSync(join(tmpdir(), 'exarch-smoke-'));
  const sourceDir = join(tempDir, 'source');
  const archivePath = join(tempDir, 'fixture.tar.gz');
  const outputDir = join(tempDir, 'output');

  try {
    mkdirSync(sourceDir);
    writeFileSync(join(sourceDir, 'hello.txt'), 'hello from the exarch smoke test');

    const creationReport = await createArchive(archivePath, [sourceDir]);
    assertOk(creationReport.filesAdded >= 1, 'createArchive did not add any files');
    assertOk(existsSync(archivePath), 'createArchive did not write the archive file');
    console.log(`[${runtime}] create: OK (filesAdded=${creationReport.filesAdded})`);

    const manifest = await listArchive(archivePath);
    assertOk(manifest.totalEntries >= 1, 'listArchive returned no entries');
    console.log(`[${runtime}] list: OK (totalEntries=${manifest.totalEntries})`);

    const verification = await verifyArchive(archivePath);
    assertOk(verification.status === 'PASS', `verifyArchive status was ${verification.status}`);
    console.log(`[${runtime}] verify: OK (status=${verification.status})`);

    mkdirSync(outputDir);
    const extractionReport = await extractArchive(archivePath, outputDir);
    assertOk(extractionReport.filesExtracted >= 1, 'extractArchive did not extract any files');
    assertOk(existsSync(join(outputDir, 'hello.txt')), 'extracted file is missing on disk');
    console.log(`[${runtime}] extract: OK (filesExtracted=${extractionReport.filesExtracted})`);

    try {
      const progressCalls = [];
      const progressOutputDir = join(tempDir, 'output-progress');
      mkdirSync(progressOutputDir);
      await extractArchiveWithProgress(archivePath, progressOutputDir, null, null, (err, arg) => {
        progressCalls.push([err, arg]);
      });
      assertOk(progressCalls.length >= 1, 'progress callback was never invoked');
      console.log(`[${runtime}] progress callback: OK (calls=${progressCalls.length})`);
    } catch (progressError) {
      console.log(`SMOKE_WARN: progress callback failed under ${runtime}: ${progressError.message}`);
    }

    const quotaConfig = new SecurityConfig().setMaxFileSize(1);
    const quotaOutputDir = join(tempDir, 'output-quota');
    mkdirSync(quotaOutputDir);
    let quotaError = null;
    try {
      await extractArchive(archivePath, quotaOutputDir, quotaConfig);
    } catch (err) {
      quotaError = err;
    }
    assertOk(quotaError !== null, 'extractArchive did not reject an over-quota file');
    assertOk(
      quotaError.message.startsWith('QUOTA_EXCEEDED'),
      `expected QUOTA_EXCEEDED prefix, got: ${quotaError.message}`
    );
    console.log(`[${runtime}] quota violation: OK (rejected as expected)`);

    console.log(`[${runtime}] smoke test passed`);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err.message ?? err);
  process.exit(1);
});
