const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');

const npmRoot = path.join(__dirname, '..');
const binDir = path.join(npmRoot, 'bin');
const mod = require(path.join(binDir, 'agentsecrets.js'));

let tmp;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'as-npm-test-'));
  delete process.env.AGENTSECRETS_BINARY;
  delete process.env.AGENTSECRETS_HOME;
});

afterEach(() => {
  // Clean up any platform package we created under npm/node_modules.
  fs.rmSync(path.join(npmRoot, 'node_modules', '@the-17'), { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
});

function makeExecutable(p) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, '#!/bin/sh\necho stub\n');
  fs.chmodSync(p, 0o755);
  return p;
}

// Build a real npm optional platform package on disk under npm/node_modules so
// that require.resolve (walking up from bin/) finds it, exactly as a real
// `npm install` would place it.
function installPlatformPackage() {
  // npm vocabulary: linux-x64, darwin-arm64, win32-x64 (arch is x64, not amd64).
  // This must match how bundledBinaryPath() names the package and how the real
  // platform packages in optionalDependencies are published.
  const pkgName = `@the-17/agentsecrets-${process.platform}-${process.arch}`;
  const pkgDir = path.join(npmRoot, 'node_modules', pkgName);
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: pkgName, version: '4.0.0-dev', os: [process.platform], cpu: [process.arch] }));
  const binaryName = process.platform === 'win32' ? 'agentsecrets.exe' : 'agentsecrets';
  return makeExecutable(path.join(pkgDir, 'bin', binaryName));
}

test('explicit override wins without any network call', async () => {
  const stub = makeExecutable(path.join(tmp, 'custom', 'agentsecrets'));
  process.env.AGENTSECRETS_BINARY = stub;
  const resolved = await mod.getBinaryPath();
  assert.strictEqual(resolved, stub);
});

test('explicit override that is missing fails closed', async () => {
  process.env.AGENTSECRETS_BINARY = path.join(tmp, 'missing', 'agentsecrets');
  await assert.rejects(() => mod.getBinaryPath(), /not an executable file/);
});

test('bundled platform package binary wins without download', async () => {
  const bundled = installPlatformPackage();
  const resolved = await mod.getBinaryPath();
  assert.strictEqual(resolved, bundled);
});

test('cached binary under explicit home avoids download', async () => {
  process.env.AGENTSECRETS_HOME = tmp;
  const cached = makeExecutable(path.join(tmp, 'bin', `agentsecrets_${require(path.join(npmRoot, 'package.json')).version}`));
  const resolved = await mod.getBinaryPath();
  assert.strictEqual(resolved, cached);
});

test('explicit home wins even when default is writable', () => {
  const explicit = path.join(tmp, 'explicit-home');
  process.env.AGENTSECRETS_HOME = explicit;
  assert.strictEqual(mod.ensureWritableHome(), explicit);
  assert.ok(fs.existsSync(explicit));
});

test('home falls back to tmp when default is unwritable', () => {
  const tmpHome = path.join(tmp, 'tmp');
  fs.mkdirSync(tmpHome, { recursive: true });
  // A real file where a directory is expected makes mkdirSync(recursive) fail,
  // mirroring a read-only or uncreatable HOME.
  const blocker = path.join(tmp, 'blockerfile');
  fs.writeFileSync(blocker, '');
  const origHomedir = os.homedir;
  const origTmpdir = os.tmpdir;
  os.homedir = () => path.join(blocker, 'home');
  os.tmpdir = () => tmpHome;
  try {
    const got = mod.ensureWritableHome();
    assert.strictEqual(got, path.join(tmpHome, 'agentsecrets-home'));
    assert.ok(fs.existsSync(got));
  } finally {
    os.homedir = origHomedir;
    os.tmpdir = origTmpdir;
  }
});
