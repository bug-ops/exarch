// Hand-maintained loader: one literal require per addon the package ships
// (napi.targets in package.json). Never resolves a package name, so a platform
// without a bundled addon fails here instead of loading code from the registry.
// scripts/check-package.mjs enforces this on the packed tarball.

const addons = {
  'darwin-x64': () => require('./exarch-rs.darwin-x64.node'),
  'darwin-arm64': () => require('./exarch-rs.darwin-arm64.node'),
  'win32-x64': () => require('./exarch-rs.win32-x64-msvc.node'),
  'linux-x64': () => require('./exarch-rs.linux-x64-gnu.node'),
  'linux-arm64': () => require('./exarch-rs.linux-arm64-gnu.node'),
};

function isGlibc() {
  const report = process.report?.getReport?.();
  return typeof report?.header?.glibcVersionRuntime === 'string';
}

function platformKey() {
  const key = `${process.platform}-${process.arch}`;
  if (process.platform === 'linux' && !isGlibc()) {
    throw new Error(`exarch-rs: unsupported platform ${key}-musl; only glibc Linux is bundled`);
  }
  if (process.platform === 'win32' && process.arch !== 'x64') {
    throw new Error(`exarch-rs: unsupported platform ${key}`);
  }
  return key;
}

function loadAddon() {
  const key = platformKey();
  const load = Object.hasOwn(addons, key) ? addons[key] : undefined;
  if (load === undefined) {
    throw new Error(`exarch-rs: unsupported platform ${key}`);
  }
  try {
    return load();
  } catch (cause) {
    throw new Error(`exarch-rs: failed to load the addon for ${key}`, { cause });
  }
}

module.exports = loadAddon();
