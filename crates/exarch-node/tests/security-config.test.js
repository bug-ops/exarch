/**
 * Tests for SecurityConfig class
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const { SecurityConfig } = require('../index.js');

describe('SecurityConfig', () => {
  describe('constructor', () => {
    it('should create config with secure defaults', () => {
      const config = new SecurityConfig();

      assert.strictEqual(config.allowSymlinks, false);
      assert.strictEqual(config.allowHardlinks, false);
      assert.strictEqual(config.allowAbsolutePaths, false);
      assert.strictEqual(config.allowWorldWritable, false);
      assert.strictEqual(config.preservePermissions, false);
    });

    it('should have default size limits', () => {
      const config = new SecurityConfig();

      assert.strictEqual(config.maxFileSize, 50 * 1024 * 1024); // 50 MB
      assert.strictEqual(config.maxTotalSize, 500 * 1024 * 1024); // 500 MB
      assert.strictEqual(config.maxFileCount, 10000);
      assert.strictEqual(config.maxPathDepth, 32);
      assert.strictEqual(config.maxCompressionRatio, 100.0);
    });
  });

  describe('static default()', () => {
    it('should return config equivalent to constructor', () => {
      const config = SecurityConfig.default();

      assert.strictEqual(config.allowSymlinks, false);
      assert.strictEqual(config.maxFileCount, 10000);
    });
  });

  describe('static permissive()', () => {
    it('should return permissive configuration', () => {
      const config = SecurityConfig.permissive();

      assert.strictEqual(config.allowSymlinks, true);
      assert.strictEqual(config.allowHardlinks, true);
      assert.strictEqual(config.allowAbsolutePaths, true);
      assert.strictEqual(config.allowWorldWritable, true);
    });
  });

  describe('builder methods', () => {
    it('should set max file size', () => {
      const config = new SecurityConfig();
      config.withMaxFileSize(100 * 1024 * 1024);

      assert.strictEqual(config.maxFileSize, 100 * 1024 * 1024);
    });

    it('should set max total size', () => {
      const config = new SecurityConfig();
      config.withMaxTotalSize(1024 * 1024 * 1024);

      assert.strictEqual(config.maxTotalSize, 1024 * 1024 * 1024);
    });

    it('should set max file count', () => {
      const config = new SecurityConfig();
      config.withMaxFileCount(50000);

      assert.strictEqual(config.maxFileCount, 50000);
    });

    it('should set max path depth', () => {
      const config = new SecurityConfig();
      config.withMaxPathDepth(64);

      assert.strictEqual(config.maxPathDepth, 64);
    });

    it('should set max compression ratio', () => {
      const config = new SecurityConfig();
      config.withMaxCompressionRatio(50.0);

      assert.strictEqual(config.maxCompressionRatio, 50.0);
    });

    it('should set allow symlinks', () => {
      const config = new SecurityConfig();
      config.withAllowSymlinks(true);

      assert.strictEqual(config.allowSymlinks, true);
    });

    it('should set allow symlinks back to false', () => {
      const config = new SecurityConfig();
      config.withAllowSymlinks(true);
      config.withAllowSymlinks(false);

      assert.strictEqual(config.allowSymlinks, false);
    });

    it('should throw when withAllowSymlinks is called with no argument, undefined, or null', () => {
      const config = new SecurityConfig();
      config.withAllowSymlinks(true);

      assert.throws(() => config.withAllowSymlinks());
      assert.throws(() => config.withAllowSymlinks(undefined));
      assert.throws(() => config.withAllowSymlinks(null));
      assert.strictEqual(
        config.allowSymlinks,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set allow hardlinks', () => {
      const config = new SecurityConfig();
      config.withAllowHardlinks(true);

      assert.strictEqual(config.allowHardlinks, true);
    });

    it('should set allow hardlinks back to false', () => {
      const config = new SecurityConfig();
      config.withAllowHardlinks(true);
      config.withAllowHardlinks(false);

      assert.strictEqual(config.allowHardlinks, false);
    });

    it('should throw when withAllowHardlinks is called with no argument, undefined, or null', () => {
      const config = new SecurityConfig();
      config.withAllowHardlinks(true);

      assert.throws(() => config.withAllowHardlinks());
      assert.throws(() => config.withAllowHardlinks(undefined));
      assert.throws(() => config.withAllowHardlinks(null));
      assert.strictEqual(
        config.allowHardlinks,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set allow absolute paths', () => {
      const config = new SecurityConfig();
      config.withAllowAbsolutePaths(true);

      assert.strictEqual(config.allowAbsolutePaths, true);
    });

    it('should set allow absolute paths back to false', () => {
      const config = new SecurityConfig();
      config.withAllowAbsolutePaths(true);
      config.withAllowAbsolutePaths(false);

      assert.strictEqual(config.allowAbsolutePaths, false);
    });

    it('should throw when withAllowAbsolutePaths is called with no argument, undefined, or null', () => {
      const config = new SecurityConfig();
      config.withAllowAbsolutePaths(true);

      assert.throws(() => config.withAllowAbsolutePaths());
      assert.throws(() => config.withAllowAbsolutePaths(undefined));
      assert.throws(() => config.withAllowAbsolutePaths(null));
      assert.strictEqual(
        config.allowAbsolutePaths,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set allow world writable', () => {
      const config = new SecurityConfig();
      config.withAllowWorldWritable(true);

      assert.strictEqual(config.allowWorldWritable, true);
    });

    it('should set allow world writable back to false', () => {
      const config = new SecurityConfig();
      config.withAllowWorldWritable(true);
      config.withAllowWorldWritable(false);

      assert.strictEqual(config.allowWorldWritable, false);
    });

    it('should throw when withAllowWorldWritable is called with no argument, undefined, or null', () => {
      const config = new SecurityConfig();
      config.withAllowWorldWritable(true);

      assert.throws(() => config.withAllowWorldWritable());
      assert.throws(() => config.withAllowWorldWritable(undefined));
      assert.throws(() => config.withAllowWorldWritable(null));
      assert.strictEqual(
        config.allowWorldWritable,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should default allowSolidArchives to false', () => {
      const config = new SecurityConfig();

      assert.strictEqual(config.allowSolidArchives, false);
    });

    it('should set allow solid archives', () => {
      const config = new SecurityConfig();
      config.withAllowSolidArchives(true);

      assert.strictEqual(config.allowSolidArchives, true);
    });

    it('should set allow solid archives back to false', () => {
      const config = new SecurityConfig();
      config.withAllowSolidArchives(true);
      config.withAllowSolidArchives(false);

      assert.strictEqual(config.allowSolidArchives, false);
    });

    it('should throw when withAllowSolidArchives is called with no argument, undefined, or null', () => {
      const config = new SecurityConfig();
      config.withAllowSolidArchives(true);

      assert.throws(() => config.withAllowSolidArchives());
      assert.throws(() => config.withAllowSolidArchives(undefined));
      assert.throws(() => config.withAllowSolidArchives(null));
      assert.strictEqual(
        config.allowSolidArchives,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set preserve permissions', () => {
      const config = new SecurityConfig();
      config.withPreservePermissions(true);

      assert.strictEqual(config.preservePermissions, true);
    });

    it('should set preserve permissions back to false', () => {
      const config = new SecurityConfig();
      config.withPreservePermissions(true);
      config.withPreservePermissions(false);

      assert.strictEqual(config.preservePermissions, false);
    });

    it('should throw when withPreservePermissions is called with no argument, undefined, or null', () => {
      const config = new SecurityConfig();
      config.withPreservePermissions(true);

      assert.throws(() => config.withPreservePermissions());
      assert.throws(() => config.withPreservePermissions(undefined));
      assert.throws(() => config.withPreservePermissions(null));
      assert.strictEqual(
        config.preservePermissions,
        true,
        'a rejected call must not silently flip the flag'
      );
    });
  });

  describe('extension filtering', () => {
    it('should add allowed extensions', () => {
      const config = new SecurityConfig();
      config.addAllowedExtension('txt');
      config.addAllowedExtension('md');

      assert.ok(config.allowedExtensions.includes('txt'));
      assert.ok(config.allowedExtensions.includes('md'));
    });

    it('should normalize a dotted extension and refuse unusable ones', () => {
      const config = new SecurityConfig();
      config.addAllowedExtension('.TXT');

      assert.deepStrictEqual(config.allowedExtensions, ['txt']);
      for (const raw of [' gz', 'tar.gz', 'a/b']) {
        assert.throws(() => config.addAllowedExtension(raw), undefined, raw);
      }
    });

    it('should check extension allowed', () => {
      const config = new SecurityConfig();
      config.addAllowedExtension('txt');

      assert.strictEqual(config.isExtensionAllowed('txt'), true);
      assert.strictEqual(config.isExtensionAllowed('exe'), false);
    });

    it('should allow all extensions when none specified', () => {
      const config = new SecurityConfig();

      assert.strictEqual(config.isExtensionAllowed('txt'), true);
      assert.strictEqual(config.isExtensionAllowed('exe'), true);
    });

    it('should read the allowlist back as null while every extension is allowed', () => {
      assert.strictEqual(new SecurityConfig().allowedExtensions, null);
      assert.strictEqual(new SecurityConfig().getAllowedExtensionsCount(), 0);
    });

    it('should replace the allowlist with withAllowedExtensions', () => {
      const config = new SecurityConfig().addAllowedExtension('txt');
      assert.strictEqual(config.withAllowedExtensions(['.MD', 'rs']), config);
      assert.deepStrictEqual(config.allowedExtensions, ['md', 'rs']);
      assert.strictEqual(config.isExtensionAllowed('txt'), false);
      assert.strictEqual(config.isExtensionAllowed('md'), true);
    });

    it('should lift the allowlist with withAllowedExtensions(null)', () => {
      const config = new SecurityConfig().addAllowedExtension('txt');
      config.withAllowedExtensions(null);
      assert.strictEqual(config.allowedExtensions, null);
      assert.strictEqual(config.isExtensionAllowed('exe'), true);
    });

    it('should refuse an empty list instead of allowing everything', () => {
      const config = new SecurityConfig().addAllowedExtension('txt');
      assert.throws(() => config.withAllowedExtensions([]), {
        code: 'INVALID_CONFIGURATION',
        setting: 'allowed_extension',
      });
      assert.deepStrictEqual(config.allowedExtensions, ['txt']);
      assert.throws(() => new SecurityConfig().withAllowedExtensions([]), {
        code: 'INVALID_CONFIGURATION',
      });
    });

    it('should not treat undefined or a bad member as a clear and keep the old list', () => {
      const config = new SecurityConfig().addAllowedExtension('txt');
      assert.throws(() => config.withAllowedExtensions(undefined));
      assert.throws(() => config.withAllowedExtensions());
      assert.throws(() => config.withAllowedExtensions(['md', 'a/b']), {
        code: 'INVALID_CONFIGURATION',
        setting: 'allowed_extension',
      });
      assert.deepStrictEqual(config.allowedExtensions, ['txt']);
    });
  });

  describe('path component banning', () => {
    it('should add banned components', () => {
      const config = new SecurityConfig();
      config.addBannedComponent('.secret');

      assert.ok(config.bannedPathComponents.includes('.secret'));
    });

    it('should replace the banned components and clear them with an empty list', () => {
      const config = new SecurityConfig();
      assert.ok(config.bannedPathComponents.includes('.git'));
      assert.strictEqual(config.withBannedComponents(['.secret']), config);
      assert.deepStrictEqual(config.bannedPathComponents, ['.secret']);
      config.withBannedComponents([]);
      assert.deepStrictEqual(config.bannedPathComponents, []);
      assert.strictEqual(config.hasBannedPathComponent('.git'), false);
    });

    it('should refuse a bad member as INVALID_CONFIGURATION and keep the old list', () => {
      const config = new SecurityConfig().withBannedComponents(['.secret']);
      assert.throws(() => config.withBannedComponents(['ok', '..']), {
        code: 'INVALID_CONFIGURATION',
        setting: 'banned_path_component',
      });
      assert.deepStrictEqual(config.bannedPathComponents, ['.secret']);
    });

    it('should refuse components with separators or dots', () => {
      const config = new SecurityConfig();
      for (const raw of ['a/b', '..', '.']) {
        assert.throws(() => config.addBannedComponent(raw), undefined, raw);
      }
    });

    it('should check path component allowed', () => {
      const config = new SecurityConfig();
      config.addBannedComponent('.secret');

      assert.strictEqual(config.isPathComponentAllowed('src'), true);
      assert.strictEqual(config.isPathComponentAllowed('.secret'), false);
    });
  });

  describe('validation', () => {
    it('should throw on invalid compression ratio', () => {
      const config = new SecurityConfig();

      assert.throws(() => {
        config.withMaxCompressionRatio(-1);
      }, /negative/i);

      assert.throws(() => {
        config.withMaxCompressionRatio(Infinity);
      }, /finite/i);
    });

    it('should throw on negative file size', () => {
      const config = new SecurityConfig();

      assert.throws(() => {
        config.withMaxFileSize(-1);
      }, /negative/i);
    });
  });

  describe('parallel decode memory', () => {
    const MIB = 1024 * 1024;

    it('should default to 128 MiB, 1 GiB when permissive', () => {
      assert.strictEqual(new SecurityConfig().parallelDecodeMemory, 128 * MIB);
      assert.strictEqual(SecurityConfig.permissive().parallelDecodeMemory, 1024 * MIB);
    });

    it('should round-trip a size and null', () => {
      const config = new SecurityConfig();
      config.withParallelDecodeMemory(256 * MIB);
      assert.strictEqual(config.parallelDecodeMemory, 256 * MIB);
      config.withParallelDecodeMemory(null);
      assert.strictEqual(config.parallelDecodeMemory, null);
    });

    for (const bad of [0, -1, 1.5, NaN, Infinity]) {
      it(`should reject ${bad} and keep the previous value`, () => {
        const config = new SecurityConfig();
        assert.throws(() => config.withParallelDecodeMemory(bad), {
          code: 'INVALID_CONFIGURATION',
          setting: 'parallel_decode_memory',
        });
        assert.strictEqual(config.parallelDecodeMemory, 128 * MIB);
      });
    }
  });

  describe('count and size setters refuse out-of-range numbers', () => {
    const setters = [
      ['withMaxFileCount', 'maxFileCount', 'max_file_count'],
      ['withMaxPathDepth', 'maxPathDepth', 'max_path_depth'],
      ['withMaxFileSize', 'maxFileSize', 'max_file_size'],
      ['withMaxTotalSize', 'maxTotalSize', 'max_total_size'],
    ];
    const bad = [-1, 0, 1.5, NaN, Infinity, -Infinity, 2 ** 53];

    for (const [setter, getter, setting] of setters) {
      for (const value of bad) {
        it(`${setter}(${value}) throws INVALID_CONFIGURATION and keeps the limit`, () => {
          const config = new SecurityConfig();
          const before = config[getter];
          assert.throws(() => config[setter](value), {
            code: 'INVALID_CONFIGURATION',
            setting,
          });
          assert.strictEqual(config[getter], before);
        });
      }
    }

    it('keeps a count above 2^32 instead of wrapping it', () => {
      const config = new SecurityConfig();
      config.withMaxFileCount(4294967306);
      assert.strictEqual(config.maxFileCount, 4294967306);
    });

    it('accepts the largest exactly representable number', () => {
      const config = new SecurityConfig();
      config.withMaxFileSize(2 ** 53 - 1);
      assert.strictEqual(config.maxFileSize, 2 ** 53 - 1);
    });
  });
});
