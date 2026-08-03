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
  });

  describe('path component banning', () => {
    it('should add banned components', () => {
      const config = new SecurityConfig();
      config.addBannedComponent('.secret');

      assert.ok(config.bannedPathComponents.includes('.secret'));
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
      }, /positive/i);

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
});
