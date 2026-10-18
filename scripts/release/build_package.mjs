import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pruneAssets } from './prune_assets.mjs';

const root = join(import.meta.dirname, '..', '..');
const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const assets = join(root, 'release-assets');
const staging = join(assets, 'package');
const installer = join(staging, 'packages', 'gateway_installation');
const binary = join(root, 'target', 'release', 'nas-os-gateway');

const tarPath = '/usr/bin/tar';

const archive = `nas-gateway-${version}-linux-x64.tar.gz`;

if (!existsSync(binary)) {
  throw new Error(`${binary} is missing: build it before packaging.`);
}

rmSync(staging, { recursive: true, force: true });
cpSync(join(root, 'system', 'packages'), join(staging, 'packages'), {
  recursive: true,
});
cpSync(binary, join(installer, 'bin', 'nas-os-gateway'));

execFileSync(
  tarPath,
  ['--owner=0', '--group=0', '-czf', join(assets, archive), '-C', staging, '.'],
  { stdio: 'inherit' },
);

rmSync(staging, { recursive: true, force: true });

const digest = createHash('sha256')
  .update(readFileSync(join(assets, archive)))
  .digest('hex');

writeFileSync(join(assets, `${archive}.sha256`), `${digest}  ${archive}\n`);

console.log(`\n✅ Release package written to ${join(assets, archive)}.`);

for (const name of pruneAssets(assets, version, ['nas-gateway-'])) {
  console.log(`Removed ${name}`);
}
