import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

export const INSTALLATION = resolve(import.meta.dirname, '../../system/packages/gateway_installation');

export function run(script, { args = [], env = {}, input = '' } = {}) {
  const options = { encoding: 'utf8', env: { ...process.env, ...env }, input };
  try {
    const stdout = execFileSync('bash', [script, ...args], options);
    return { code: 0, stdout, output: stdout };
  } catch (failure) {
    const stdout = failure.stdout ?? '';
    return { code: failure.status ?? 1, stdout, output: stdout + (failure.stderr ?? '') };
  }
}

export function workspace() {
  const path = mkdtempSync(join(tmpdir(), 'nas-gateway-scripts-'));
  return { path, remove: () => rmSync(path, { recursive: true, force: true }) };
}

export function fakeCommand(directory, name, body) {
  const path = join(directory, name);
  writeFileSync(path, `#!/usr/bin/env bash\n${body}\n`, { mode: 0o755 });
  return path;
}
