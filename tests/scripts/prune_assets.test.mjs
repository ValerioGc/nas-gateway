import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compareVersions, pruneAssets } from '../../scripts/release/prune_assets.mjs';

const folders = [];

function folder(names) {
  const directory = mkdtempSync(join(tmpdir(), 'prune-assets-'));
  for (const name of names) writeFileSync(join(directory, name), '');
  mkdirSync(join(directory, 'package'));
  folders.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of folders.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe('prune_assets.mjs', () => {
  it('orders versions as semver does', () => {
    assert.ok(compareVersions('0.1.10', '0.1.9') > 0);
    assert.ok(compareVersions('1.0.0-rc.1', '1.0.0') < 0);
    assert.equal(compareVersions('0.1.3', '0.1.3'), 0);
  });

  it('keeps the release just packaged and the one before it, and nothing else versioned', () => {
    const directory = folder([
      'nas-gateway-0.1.8-linux-x64.tar.gz',
      'nas-gateway-0.1.9-linux-x64.tar.gz',
      'nas-gateway-0.1.9-linux-x64.tar.gz.sha256',
      'nas-gateway-0.1.10-linux-x64.tar.gz',
      'nas-gateway-0.1.10-linux-x64.tar.gz.sha256',
      'gateway-0.1.9.pdf',
      'notes.txt',
    ]);
    const removed = pruneAssets(directory, '0.1.10', ['nas-gateway-']);
    assert.deepEqual(readdirSync(directory).sort(), [
      'nas-gateway-0.1.10-linux-x64.tar.gz',
      'nas-gateway-0.1.10-linux-x64.tar.gz.sha256',
      'nas-gateway-0.1.9-linux-x64.tar.gz',
      'nas-gateway-0.1.9-linux-x64.tar.gz.sha256',
      'notes.txt',
      'package',
    ]);
    assert.deepEqual(removed.sort(), ['gateway-0.1.9.pdf', 'nas-gateway-0.1.8-linux-x64.tar.gz']);
  });

  it('keeps prerelease packages, checksums and manuals without treating extensions as versions', () => {
    const directory = folder([
      'nas-gateway-1.0.0-rc.1-linux-x64.tar.gz',
      'nas-gateway-1.0.0-rc.2-linux-x64.tar.gz',
      'nas-gateway-1.0.0-rc.2-linux-x64.tar.gz.sha256',
      'nas-gateway-1.0.0-rc.2.pdf',
      'nas-gateway-1.0.0-rc.3-linux-x64.tar.gz',
      'nas-gateway-1.0.0-rc.3.tgz',
      'nas-gateway-1.0.0-rc.3.sha256',
      'nas-gateway-1.0.0-rc.3.pdf',
    ]);
    const removed = pruneAssets(directory, '1.0.0-rc.3', ['nas-gateway-']);
    assert.deepEqual(removed, ['nas-gateway-1.0.0-rc.1-linux-x64.tar.gz']);
    assert.deepEqual(readdirSync(directory).sort(), [
      'nas-gateway-1.0.0-rc.2-linux-x64.tar.gz',
      'nas-gateway-1.0.0-rc.2-linux-x64.tar.gz.sha256',
      'nas-gateway-1.0.0-rc.2.pdf',
      'nas-gateway-1.0.0-rc.3-linux-x64.tar.gz',
      'nas-gateway-1.0.0-rc.3.pdf',
      'nas-gateway-1.0.0-rc.3.sha256',
      'nas-gateway-1.0.0-rc.3.tgz',
      'package',
    ]);
  });
});
