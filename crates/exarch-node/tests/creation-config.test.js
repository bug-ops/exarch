/**
 * Tests for CreationConfig class
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const { CreationConfig } = require('../index.js');

describe('CreationConfig', () => {
  describe('constructor', () => {
    it('should create config with defaults', () => {
      const config = new CreationConfig();

      assert.strictEqual(config.preservePermissions, true);
      assert.strictEqual(config.followSymlinks, false);
      assert.strictEqual(config.includeHidden, false);
    });
  });

  describe('static default()', () => {
    it('should return config equivalent to constructor', () => {
      const config = CreationConfig.default();

      assert.strictEqual(config.preservePermissions, true);
      assert.strictEqual(config.followSymlinks, false);
    });
  });

  describe('builder methods', () => {
    it('should set compression level', () => {
      const config = new CreationConfig();
      config.withCompressionLevel(9);

      assert.strictEqual(config.compressionLevel, 9);
    });

    it('should set preserve permissions', () => {
      const config = new CreationConfig();
      config.withPreservePermissions(false);

      assert.strictEqual(config.preservePermissions, false);
    });

    it('should set preserve permissions back to true', () => {
      const config = new CreationConfig();
      config.withPreservePermissions(false);
      config.withPreservePermissions(true);

      assert.strictEqual(config.preservePermissions, true);
    });

    it('should throw when withPreservePermissions is called with no argument, undefined, or null', () => {
      const config = new CreationConfig();
      config.withPreservePermissions(false);

      assert.throws(() => config.withPreservePermissions());
      assert.throws(() => config.withPreservePermissions(undefined));
      assert.throws(() => config.withPreservePermissions(null));
      assert.strictEqual(
        config.preservePermissions,
        false,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set follow symlinks', () => {
      const config = new CreationConfig();
      config.withFollowSymlinks(true);

      assert.strictEqual(config.followSymlinks, true);
    });

    it('should set follow symlinks back to false', () => {
      const config = new CreationConfig();
      config.withFollowSymlinks(true);
      config.withFollowSymlinks(false);

      assert.strictEqual(config.followSymlinks, false);
    });

    it('should throw when withFollowSymlinks is called with no argument, undefined, or null', () => {
      const config = new CreationConfig();
      config.withFollowSymlinks(true);

      assert.throws(() => config.withFollowSymlinks());
      assert.throws(() => config.withFollowSymlinks(undefined));
      assert.throws(() => config.withFollowSymlinks(null));
      assert.strictEqual(
        config.followSymlinks,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set include hidden', () => {
      const config = new CreationConfig();
      config.withIncludeHidden(true);

      assert.strictEqual(config.includeHidden, true);
    });

    it('should set include hidden back to false', () => {
      const config = new CreationConfig();
      config.withIncludeHidden(true);
      config.withIncludeHidden(false);

      assert.strictEqual(config.includeHidden, false);
    });

    it('should throw when withIncludeHidden is called with no argument, undefined, or null', () => {
      const config = new CreationConfig();
      config.withIncludeHidden(true);

      assert.throws(() => config.withIncludeHidden());
      assert.throws(() => config.withIncludeHidden(undefined));
      assert.throws(() => config.withIncludeHidden(null));
      assert.strictEqual(
        config.includeHidden,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set max file size', () => {
      const config = new CreationConfig();
      config.withMaxFileSize(100 * 1024 * 1024);

      assert.strictEqual(config.maxFileSize, 100 * 1024 * 1024);
    });

    it('should default to no max file size and accept null to remove it', () => {
      const config = new CreationConfig();
      assert.strictEqual(config.maxFileSize, null);

      config.withMaxFileSize(1024);
      config.withMaxFileSize(null);
      assert.strictEqual(config.maxFileSize, null);
    });

    it('should refuse a zero or negative max file size as INVALID_CONFIGURATION', () => {
      const config = new CreationConfig();
      config.withMaxFileSize(1024);

      for (const bad of [0, -1]) {
        assert.throws(
          () => config.withMaxFileSize(bad),
          (err) => {
            assert.strictEqual(err.code, 'INVALID_CONFIGURATION');
            assert.strictEqual(err.setting, 'max_file_size');
            return true;
          }
        );
      }
      assert.strictEqual(config.maxFileSize, 1024);
    });
  });

  describe('exclude patterns', () => {
    it('should add exclude patterns', () => {
      const config = new CreationConfig();
      config.addExcludePattern('*.log');
      config.addExcludePattern('node_modules');

      assert.ok(config.excludePatterns.includes('*.log'));
      assert.ok(config.excludePatterns.includes('node_modules'));
    });

    it('should refuse a pattern with a null byte as INVALID_CONFIGURATION', () => {
      const config = new CreationConfig();
      const before = config.excludePatterns;
      assert.throws(() => config.addExcludePattern('bad\0pattern'), {
        code: 'INVALID_CONFIGURATION',
        setting: 'exclude_pattern',
      });
      assert.deepStrictEqual(config.excludePatterns, before);
    });

    it('should replace the exclude patterns and clear them with an empty list', () => {
      const config = new CreationConfig();
      assert.ok(config.excludePatterns.includes('.git'));
      assert.strictEqual(config.withExcludePatterns(['target', '*.log']), config);
      assert.deepStrictEqual(config.excludePatterns, ['target', '*.log']);
      config.withExcludePatterns([]);
      assert.deepStrictEqual(config.excludePatterns, []);
    });

    it('should refuse a bad member as INVALID_CONFIGURATION and keep the old list', () => {
      const config = new CreationConfig().withExcludePatterns(['target']);
      assert.throws(() => config.withExcludePatterns(['ok', 'bad\0pattern']), {
        code: 'INVALID_CONFIGURATION',
        setting: 'exclude_pattern',
      });
      assert.deepStrictEqual(config.excludePatterns, ['target']);
    });
  });

  describe('compression levels', () => {
    it('should accept valid compression levels 1-9', () => {
      for (let level = 1; level <= 9; level++) {
        const config = new CreationConfig();
        config.withCompressionLevel(level);
        assert.strictEqual(config.compressionLevel, level);
      }
    });

    it('should throw on invalid compression level', () => {
      const config = new CreationConfig();

      assert.throws(() => {
        config.withCompressionLevel(0);
      }, /1.*9|invalid/i);

      assert.throws(() => {
        config.withCompressionLevel(10);
      }, /1.*9|invalid/i);
    });

    it('refuses every unusable number as INVALID_COMPRESSION_LEVEL and keeps the level', () => {
      for (const bad of [0, 10, 4294967295, 1.5, -3, NaN, Infinity, 4294967302, 2 ** 40]) {
        const config = new CreationConfig();
        assert.throws(
          () => config.withCompressionLevel(bad),
          { code: 'INVALID_COMPRESSION_LEVEL' },
          String(bad)
        );
        assert.strictEqual(config.compressionLevel, 6);
      }
    });

    it('names a whole refused level in the message', () => {
      for (const bad of [0, 10, -3]) {
        assert.throws(() => new CreationConfig().withCompressionLevel(bad), {
          message: new RegExp(`got ${bad}\\b`),
        });
      }
    });

    it('names a non-numeric refused level as a phrase in the message', () => {
      assert.throws(() => new CreationConfig().withCompressionLevel(NaN), {
        message: /got a non-finite number/,
      });
    });
  });
});
