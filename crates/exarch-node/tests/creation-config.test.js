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

    it('should set follow symlinks', () => {
      const config = new CreationConfig();
      config.setFollowSymlinks(true);

      assert.strictEqual(config.followSymlinks, true);
    });

    it('should set include hidden', () => {
      const config = new CreationConfig();
      config.setIncludeHidden(true);

      assert.strictEqual(config.includeHidden, true);
    });

    it('should set max file size', () => {
      const config = new CreationConfig();
      config.setMaxFileSize(100 * 1024 * 1024);

      assert.strictEqual(config.maxFileSize, 100 * 1024 * 1024);
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
  });
});
