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
      config.setMaxFileSize(100 * 1024 * 1024);

      assert.strictEqual(config.maxFileSize, 100 * 1024 * 1024);
    });

    it('should set max total size', () => {
      const config = new SecurityConfig();
      config.setMaxTotalSize(1024 * 1024 * 1024);

      assert.strictEqual(config.maxTotalSize, 1024 * 1024 * 1024);
    });

    it('should set max file count', () => {
      const config = new SecurityConfig();
      config.setMaxFileCount(50000);

      assert.strictEqual(config.maxFileCount, 50000);
    });

    it('should set max path depth', () => {
      const config = new SecurityConfig();
      config.setMaxPathDepth(64);

      assert.strictEqual(config.maxPathDepth, 64);
    });

    it('should set max compression ratio', () => {
      const config = new SecurityConfig();
      config.setMaxCompressionRatio(50.0);

      assert.strictEqual(config.maxCompressionRatio, 50.0);
    });

    it('should set allow symlinks', () => {
      const config = new SecurityConfig();
      config.setAllowSymlinks(true);

      assert.strictEqual(config.allowSymlinks, true);
    });

    it('should set allow symlinks back to false', () => {
      const config = new SecurityConfig();
      config.setAllowSymlinks(true);
      config.setAllowSymlinks(false);

      assert.strictEqual(config.allowSymlinks, false);
    });

    it('should throw when setAllowSymlinks is called with no argument, undefined, or null', () => {
      const config = new SecurityConfig();
      config.setAllowSymlinks(true);

      assert.throws(() => config.setAllowSymlinks());
      assert.throws(() => config.setAllowSymlinks(undefined));
      assert.throws(() => config.setAllowSymlinks(null));
      assert.strictEqual(
        config.allowSymlinks,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set allow hardlinks', () => {
      const config = new SecurityConfig();
      config.setAllowHardlinks(true);

      assert.strictEqual(config.allowHardlinks, true);
    });

    it('should set allow hardlinks back to false', () => {
      const config = new SecurityConfig();
      config.setAllowHardlinks(true);
      config.setAllowHardlinks(false);

      assert.strictEqual(config.allowHardlinks, false);
    });

    it('should throw when setAllowHardlinks is called with no argument, undefined, or null', () => {
      const config = new SecurityConfig();
      config.setAllowHardlinks(true);

      assert.throws(() => config.setAllowHardlinks());
      assert.throws(() => config.setAllowHardlinks(undefined));
      assert.throws(() => config.setAllowHardlinks(null));
      assert.strictEqual(
        config.allowHardlinks,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set allow absolute paths', () => {
      const config = new SecurityConfig();
      config.setAllowAbsolutePaths(true);

      assert.strictEqual(config.allowAbsolutePaths, true);
    });

    it('should set allow absolute paths back to false', () => {
      const config = new SecurityConfig();
      config.setAllowAbsolutePaths(true);
      config.setAllowAbsolutePaths(false);

      assert.strictEqual(config.allowAbsolutePaths, false);
    });

    it('should throw when setAllowAbsolutePaths is called with no argument, undefined, or null', () => {
      const config = new SecurityConfig();
      config.setAllowAbsolutePaths(true);

      assert.throws(() => config.setAllowAbsolutePaths());
      assert.throws(() => config.setAllowAbsolutePaths(undefined));
      assert.throws(() => config.setAllowAbsolutePaths(null));
      assert.strictEqual(
        config.allowAbsolutePaths,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set allow world writable', () => {
      const config = new SecurityConfig();
      config.setAllowWorldWritable(true);

      assert.strictEqual(config.allowWorldWritable, true);
    });

    it('should set allow world writable back to false', () => {
      const config = new SecurityConfig();
      config.setAllowWorldWritable(true);
      config.setAllowWorldWritable(false);

      assert.strictEqual(config.allowWorldWritable, false);
    });

    it('should throw when setAllowWorldWritable is called with no argument, undefined, or null', () => {
      const config = new SecurityConfig();
      config.setAllowWorldWritable(true);

      assert.throws(() => config.setAllowWorldWritable());
      assert.throws(() => config.setAllowWorldWritable(undefined));
      assert.throws(() => config.setAllowWorldWritable(null));
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
      config.setAllowSolidArchives(true);

      assert.strictEqual(config.allowSolidArchives, true);
    });

    it('should set allow solid archives back to false', () => {
      const config = new SecurityConfig();
      config.setAllowSolidArchives(true);
      config.setAllowSolidArchives(false);

      assert.strictEqual(config.allowSolidArchives, false);
    });

    it('should throw when setAllowSolidArchives is called with no argument, undefined, or null', () => {
      const config = new SecurityConfig();
      config.setAllowSolidArchives(true);

      assert.throws(() => config.setAllowSolidArchives());
      assert.throws(() => config.setAllowSolidArchives(undefined));
      assert.throws(() => config.setAllowSolidArchives(null));
      assert.strictEqual(
        config.allowSolidArchives,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set preserve permissions', () => {
      const config = new SecurityConfig();
      config.setPreservePermissions(true);

      assert.strictEqual(config.preservePermissions, true);
    });

    it('should set preserve permissions back to false', () => {
      const config = new SecurityConfig();
      config.setPreservePermissions(true);
      config.setPreservePermissions(false);

      assert.strictEqual(config.preservePermissions, false);
    });

    it('should throw when setPreservePermissions is called with no argument, undefined, or null', () => {
      const config = new SecurityConfig();
      config.setPreservePermissions(true);

      assert.throws(() => config.setPreservePermissions());
      assert.throws(() => config.setPreservePermissions(undefined));
      assert.throws(() => config.setPreservePermissions(null));
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

    it('should replace the allowlist with setAllowedExtensions', () => {
      const config = new SecurityConfig().addAllowedExtension('txt');
      assert.strictEqual(config.setAllowedExtensions(['.MD', 'rs']), config);
      assert.deepStrictEqual(config.allowedExtensions, ['md', 'rs']);
      assert.strictEqual(config.isExtensionAllowed('txt'), false);
      assert.strictEqual(config.isExtensionAllowed('md'), true);
    });

    it('should lift the allowlist with setAllowedExtensions(null)', () => {
      const config = new SecurityConfig().addAllowedExtension('txt');
      config.setAllowedExtensions(null);
      assert.strictEqual(config.allowedExtensions, null);
      assert.strictEqual(config.isExtensionAllowed('exe'), true);
    });

    it('should refuse an empty list instead of allowing everything', () => {
      const config = new SecurityConfig().addAllowedExtension('txt');
      assert.throws(() => config.setAllowedExtensions([]), {
        code: 'INVALID_CONFIGURATION',
        setting: 'allowed_extension',
      });
      assert.deepStrictEqual(config.allowedExtensions, ['txt']);
      assert.throws(() => new SecurityConfig().setAllowedExtensions([]), {
        code: 'INVALID_CONFIGURATION',
      });
    });

    it('should not treat undefined or a bad member as a clear and keep the old list', () => {
      const config = new SecurityConfig().addAllowedExtension('txt');
      assert.throws(() => config.setAllowedExtensions(undefined));
      assert.throws(() => config.setAllowedExtensions());
      assert.throws(() => config.setAllowedExtensions(['md', 'a/b']), {
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
      assert.strictEqual(config.setBannedComponents(['.secret']), config);
      assert.deepStrictEqual(config.bannedPathComponents, ['.secret']);
      config.setBannedComponents([]);
      assert.deepStrictEqual(config.bannedPathComponents, []);
      assert.strictEqual(config.hasBannedPathComponent('.git'), false);
    });

    it('should refuse a bad member as INVALID_CONFIGURATION and keep the old list', () => {
      const config = new SecurityConfig().setBannedComponents(['.secret']);
      assert.throws(() => config.setBannedComponents(['ok', '..']), {
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
        config.setMaxCompressionRatio(-1);
      }, /negative/i);

      assert.throws(() => {
        config.setMaxCompressionRatio(Infinity);
      }, /finite/i);
    });

    it('should throw on negative file size', () => {
      const config = new SecurityConfig();

      assert.throws(() => {
        config.setMaxFileSize(-1);
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
      config.setParallelDecodeMemory(256 * MIB);
      assert.strictEqual(config.parallelDecodeMemory, 256 * MIB);
      config.setParallelDecodeMemory(null);
      assert.strictEqual(config.parallelDecodeMemory, null);
    });

    for (const bad of [0, -1, 1.5, NaN, Infinity]) {
      it(`should reject ${bad} and keep the previous value`, () => {
        const config = new SecurityConfig();
        assert.throws(() => config.setParallelDecodeMemory(bad), {
          code: 'INVALID_CONFIGURATION',
          setting: 'parallel_decode_memory',
        });
        assert.strictEqual(config.parallelDecodeMemory, 128 * MIB);
      });
    }
  });

  describe('count and size setters refuse out-of-range numbers', () => {
    const setters = [
      ['setMaxFileCount', 'maxFileCount', 'max_file_count'],
      ['setMaxPathDepth', 'maxPathDepth', 'max_path_depth'],
      ['setMaxFileSize', 'maxFileSize', 'max_file_size'],
      ['setMaxTotalSize', 'maxTotalSize', 'max_total_size'],
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
      config.setMaxFileCount(4294967306);
      assert.strictEqual(config.maxFileCount, 4294967306);
    });

    it('accepts the largest exactly representable number', () => {
      const config = new SecurityConfig();
      config.setMaxFileSize(2 ** 53 - 1);
      assert.strictEqual(config.maxFileSize, 2 ** 53 - 1);
    });
  });
});
