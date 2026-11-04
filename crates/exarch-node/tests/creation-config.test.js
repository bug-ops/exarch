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
      config.setCompressionLevel(9);

      assert.strictEqual(config.compressionLevel, 9);
    });

    it('should set preserve permissions', () => {
      const config = new CreationConfig();
      config.setPreservePermissions(false);

      assert.strictEqual(config.preservePermissions, false);
    });

    it('should set preserve permissions back to true', () => {
      const config = new CreationConfig();
      config.setPreservePermissions(false);
      config.setPreservePermissions(true);

      assert.strictEqual(config.preservePermissions, true);
    });

    it('should throw when setPreservePermissions is called with no argument, undefined, or null', () => {
      const config = new CreationConfig();
      config.setPreservePermissions(false);

      assert.throws(() => config.setPreservePermissions());
      assert.throws(() => config.setPreservePermissions(undefined));
      assert.throws(() => config.setPreservePermissions(null));
      assert.strictEqual(
        config.preservePermissions,
        false,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set follow symlinks', () => {
      const config = new CreationConfig();
      config.setFollowSymlinks(true);

      assert.strictEqual(config.followSymlinks, true);
    });

    it('should set follow symlinks back to false', () => {
      const config = new CreationConfig();
      config.setFollowSymlinks(true);
      config.setFollowSymlinks(false);

      assert.strictEqual(config.followSymlinks, false);
    });

    it('should throw when setFollowSymlinks is called with no argument, undefined, or null', () => {
      const config = new CreationConfig();
      config.setFollowSymlinks(true);

      assert.throws(() => config.setFollowSymlinks());
      assert.throws(() => config.setFollowSymlinks(undefined));
      assert.throws(() => config.setFollowSymlinks(null));
      assert.strictEqual(
        config.followSymlinks,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set include hidden', () => {
      const config = new CreationConfig();
      config.setIncludeHidden(true);

      assert.strictEqual(config.includeHidden, true);
    });

    it('should set include hidden back to false', () => {
      const config = new CreationConfig();
      config.setIncludeHidden(true);
      config.setIncludeHidden(false);

      assert.strictEqual(config.includeHidden, false);
    });

    it('should throw when setIncludeHidden is called with no argument, undefined, or null', () => {
      const config = new CreationConfig();
      config.setIncludeHidden(true);

      assert.throws(() => config.setIncludeHidden());
      assert.throws(() => config.setIncludeHidden(undefined));
      assert.throws(() => config.setIncludeHidden(null));
      assert.strictEqual(
        config.includeHidden,
        true,
        'a rejected call must not silently flip the flag'
      );
    });

    it('should set max file size', () => {
      const config = new CreationConfig();
      config.setMaxFileSize(100 * 1024 * 1024);

      assert.strictEqual(config.maxFileSize, 100 * 1024 * 1024);
    });

    it('should default to no max file size and accept null to remove it', () => {
      const config = new CreationConfig();
      assert.strictEqual(config.maxFileSize, null);

      config.setMaxFileSize(1024);
      config.setMaxFileSize(null);
      assert.strictEqual(config.maxFileSize, null);
    });

    it('should refuse a zero or negative max file size as INVALID_CONFIGURATION', () => {
      const config = new CreationConfig();
      config.setMaxFileSize(1024);

      for (const bad of [0, -1]) {
        assert.throws(
          () => config.setMaxFileSize(bad),
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
  });

  describe('compression levels', () => {
    it('should accept valid compression levels 1-9', () => {
      for (let level = 1; level <= 9; level++) {
        const config = new CreationConfig();
        config.setCompressionLevel(level);
        assert.strictEqual(config.compressionLevel, level);
      }
    });

    it('should throw on invalid compression level', () => {
      const config = new CreationConfig();

      assert.throws(() => {
        config.setCompressionLevel(0);
      }, /1.*9|invalid/i);

      assert.throws(() => {
        config.setCompressionLevel(10);
      }, /1.*9|invalid/i);
    });

    it('refuses fractions and out-of-range numbers instead of wrapping them', () => {
      for (const bad of [6.7, 4294967302, -1, NaN, Infinity, 2 ** 40]) {
        const config = new CreationConfig();
        assert.throws(() => config.setCompressionLevel(bad), {
          code: 'INVALID_COMPRESSION_LEVEL',
        });
        assert.strictEqual(config.compressionLevel, 6);
      }
    });
  });
});
