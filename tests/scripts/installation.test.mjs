import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fakeCommand, INSTALLATION, run, workspace } from './helpers.mjs';

const scripts = [
  'install.sh',
  'scripts/check.sh',
  'scripts/uninstall.sh',
  'scripts/copy-database.sh',
  'scripts/share-password.sh',
].map((name) =>
  join(INSTALLATION, name),
);

let temp;
let binary;

beforeEach(() => {
  temp = workspace();
  binary = join(temp.path, 'nas-os-gateway');
  writeFileSync(binary, '');
});

afterEach(() => temp.remove());

describe('the installation scripts', () => {
  for (const script of scripts) {
    it(`${script} parses, stops on an unset variable and explains itself`, () => {
      execFileSync('bash', ['-n', script]);
      const source = readFileSync(script, 'utf8');
      const lines = source.split('\n');

      assert.match(source, /^set -[eu]*u[eo]*/m);
      assert.equal(lines[0], '#!/usr/bin/env bash');
      assert.ok(lines.slice(1, 12).filter((line) => line.startsWith('#')).length > 3);
    });
  }

  it('installs only files that are in the package', () => {
    const install = readFileSync(join(INSTALLATION, 'install.sh'), 'utf8');
    // The binary is the one file the release adds, next to the installer.
    const referenced = [...install.matchAll(/\$here\/([\w./@-]+)/g)]
      .map(([, path]) => path)
      .filter((path) => path !== 'bin/nas-os-gateway');

    assert.ok(referenced.length > 0);
    for (const path of referenced) {
      assert.ok(existsSync(join(INSTALLATION, path)), `install.sh copies ${path}`);
    }
  });
});

describe('install.sh', () => {
  const dryRun = (args = []) =>
    run(join(INSTALLATION, 'install.sh'), { args: ['--dry-run', ...args, binary] });

  it('changes nothing in a dry run, and says so', () => {
    const result = dryRun();

    assert.equal(result.code, 0);
    assert.match(result.output, /Dry run: no change will be applied\./);
    for (const line of result.stdout.split('\n').filter((l) => /^\s+\[dry run\]/.test(l))) {
      assert.match(
        line,
        /\[dry run\] (install|systemctl|groupadd --system nas-os-share-password|bash \S+\/copy-database\.sh)\b/,
      );
    }
  });

  it('installs the binary, the unit and the tools that stay on the machine', () => {
    const { stdout } = dryRun();

    assert.match(stdout, /\/usr\/local\/bin\/nas-os-gateway/);
    assert.match(stdout, /\/etc\/systemd\/system\/nas-os-gateway\.service/);
    assert.match(stdout, /\/usr\/local\/lib\/nas-os-gateway\/check\.sh/);
    assert.match(stdout, /\/usr\/local\/lib\/nas-os-gateway\/uninstall\.sh/);
    assert.match(stdout, /\[dry run\] systemctl enable nas-os-gateway/);
    assert.match(stdout, /\[dry run\] systemctl restart nas-os-gateway/);
  });

  it('makes the group of the share password before the unit that names it', () => {
    const { stdout } = dryRun();

    assert.match(stdout, /nas-os-share-password\.socket/);
    assert.match(stdout, /nas-os-share-password@\.service/);
    assert.match(stdout, /\/usr\/local\/lib\/nas-os-gateway\/share-password\.sh/);
    assert.match(stdout, /\[dry run\] systemctl enable --now nas-os-share-password\.socket/);
    const group = stdout.search(/group nas-os-share-password already there|groupadd --system/);
    assert.ok(group >= 0);
    assert.ok(group < stdout.indexOf('/etc/systemd/system/nas-os-gateway.service'));
  });

  it('leaves the start to the wizard, which holds port 80, with --no-start', () => {
    const { code, stdout } = dryRun(['--no-start']);

    assert.equal(code, 0);
    assert.match(stdout, /\[dry run\] systemctl enable nas-os-gateway/);
    assert.doesNotMatch(stdout, /systemctl restart/);
    assert.match(stdout, /not started/);
  });

  it('never touches the account', () => {
    for (const line of dryRun().stdout.split('\n').filter((l) => l.includes('[dry run]'))) {
      assert.doesNotMatch(line, /gateway\.db|account/);
    }
  });

  it('refuses to go on without a binary, and an option it does not know', () => {
    const missing = run(join(INSTALLATION, 'install.sh'), {
      args: ['--dry-run', join(temp.path, 'nothing')],
    });
    assert.notEqual(missing.code, 0);
    assert.match(missing.output, /binary not found/);

    const unknown = run(join(INSTALLATION, 'install.sh'), { args: ['--wipe-everything'] });
    assert.equal(unknown.code, 2);
    assert.match(unknown.output, /unknown option/);
  });
});

describe('copy-database.sh', () => {
  const script = join(INSTALLATION, 'scripts/copy-database.sh');

  /** A state directory with a database and its write-ahead log, copied at `stamp`. */
  function copyAt(state, stamp) {
    fakeCommand(temp.path, 'date', `echo ${stamp}`);
    return run(script, { args: [state], env: { PATH: `${temp.path}:${process.env.PATH}` } });
  }

  function state() {
    const path = join(temp.path, 'state');
    mkdirSync(path, { recursive: true });
    writeFileSync(join(path, 'gateway.db'), 'database');
    writeFileSync(join(path, 'gateway.db-wal'), 'log');
    return path;
  }

  it('copies the database with its write-ahead log', () => {
    const path = state();
    const result = copyAt(path, '20261003T010000Z');

    assert.equal(result.code, 0);
    const copy = join(path, 'before-update', 'gateway-20261003T010000Z.db');
    assert.equal(readFileSync(copy, 'utf8'), 'database');
    assert.equal(readFileSync(`${copy}-wal`, 'utf8'), 'log');
    assert.equal(existsSync(`${copy}-shm`), false);
  });

  it('keeps the last five copies', () => {
    const path = state();
    for (let hour = 1; hour <= 7; hour++) {
      assert.equal(copyAt(path, `20261003T0${hour}0000Z`).code, 0);
    }

    const kept = readdirSync(join(path, 'before-update')).filter((name) => name.endsWith('.db'));
    assert.deepEqual(kept.sort(), [
      'gateway-20261003T030000Z.db',
      'gateway-20261003T040000Z.db',
      'gateway-20261003T050000Z.db',
      'gateway-20261003T060000Z.db',
      'gateway-20261003T070000Z.db',
    ]);
    assert.equal(existsSync(join(path, 'before-update', 'gateway-20261003T010000Z.db-wal')), false);
  });

  it('refuses a state directory with no database', () => {
    const result = run(script, { args: [temp.path] });
    assert.notEqual(result.code, 0);
    assert.match(result.output, /no database/);
  });
});

describe('check.sh', () => {
  it('reports a gateway that does not run, and fails', () => {
    fakeCommand(temp.path, 'systemctl', 'exit 3');
    const { code, output } = run(join(INSTALLATION, 'scripts/check.sh'), {
      env: { PATH: `${temp.path}:${process.env.PATH}` },
    });

    assert.equal(code, 1);
    assert.match(output, /\[KO\] {3}service not running/);
  });
});

describe('uninstall.sh', () => {
  it('stops the gateway even when the unit listing is larger than a pipe buffer', () => {
    const source = readFileSync(join(INSTALLATION, 'scripts/uninstall.sh'), 'utf8');
    const service = source.slice(source.indexOf('if systemctl list-unit-files'), source.indexOf('say "Password of the shared folders"'));
    const script = join(temp.path, 'service.sh');
    writeFileSync(script, `set -euo pipefail\nNAME=nas-os-gateway\n${service}`);
    fakeCommand(temp.path, 'systemctl', `
if [[ $1 == list-unit-files ]]; then
  set -e
  printf 'nas-os-gateway.service enabled\\n'
  for ((n=0;n<10000;n++)); do printf 'other-%s.service disabled\\n' "$n"; done
else printf '%s\\n' "$*" >> "${join(temp.path, 'calls')}"; fi`);
    fakeCommand(temp.path, 'rm', ':');
    const result = run(script, { env: { PATH: `${temp.path}:${process.env.PATH}` } });
    assert.equal(result.code, 0);
    assert.match(result.output, /stopped, disabled and unit removed/);
    assert.match(readFileSync(join(temp.path, 'calls'), 'utf8'), /disable --now nas-os-gateway/);
  });

  it('refuses an option it does not know', () => {
    const { code, output } = run(join(INSTALLATION, 'scripts/uninstall.sh'), {
      args: ['--everything'],
    });

    assert.equal(code, 2);
    assert.match(output, /unknown option/);
  });
});

describe('share-password.sh', () => {
  const script = join(INSTALLATION, 'scripts/share-password.sh');

  /** The helper with a fake Samba that writes down what it was asked, and the user of the NAS. */
  function helper({ samba = true, known = true, refuse = false } = {}) {
    const conf = join(temp.path, 'dropin');
    mkdirSync(conf, { recursive: true });
    writeFileSync(join(conf, 'user.conf'), '[Service]\nUser=valerio\nGroup=valerio\n');
    const calls = join(temp.path, 'calls');
    fakeCommand(temp.path, 'getent', 'exit 0');
    if (samba) {
      fakeCommand(
        temp.path,
        'smbpasswd',
        `printf 'smbpasswd %s\\n' "$*" >> ${calls}; cat >> ${calls}; ${refuse ? 'exit 1' : 'exit 0'}`,
      );
      fakeCommand(temp.path, 'pdbedit', known ? 'exit 0' : 'exit 1');
    }
    const path = samba ? `${temp.path}:${process.env.PATH}` : `${temp.path}:/usr/bin:/bin`;
    return (input) => {
      const result = run(script, {
        input,
        env: { PATH: path, NAS_TERMINAL_DROPIN: conf },
      });
      return { ...result, calls: existsSync(calls) ? readFileSync(calls, 'utf8') : '' };
    };
  }

  it('makes the Samba account of the user of the shares, the password on its input only', () => {
    const result = helper()('set\nlong enough\n');

    assert.equal(result.stdout, 'ok\n');
    assert.match(result.calls, /smbpasswd -s -a valerio\nlong enough\nlong enough\n/);
    assert.match(result.calls, /smbpasswd -e valerio/);
    assert.doesNotMatch(result.calls, /smbpasswd [^\n]*long enough/);
  });

  it('follows a new password only where Samba has the account', () => {
    assert.equal(helper({ known: false })('update\nanother one\n').calls, '');
    assert.match(helper()('update\nanother one\n').calls, /-s -a valerio\nanother one/);
  });

  it('says what is missing, and refuses a request it does not know', () => {
    assert.equal(helper({ samba: false })('set\nlong enough\n').stdout, 'error: samba is not installed\n');
    assert.equal(helper({ samba: false })('update\nlong enough\n').stdout, 'ok\n');
    assert.equal(helper({ refuse: true })('set\nlong enough\n').stdout, 'error: samba refused the password\n');
    assert.equal(helper()('delete\nlong enough\n').stdout, 'error: unknown request\n');
    assert.equal(helper()('set\n').stdout, 'error: no password\n');
    writeFileSync(join(temp.path, 'dropin', 'user.conf'), '[Service]\nUser=../root\n');
    const unknown = run(script, {
      input: 'set\nlong enough\n',
      env: { PATH: `${temp.path}:${process.env.PATH}`, NAS_TERMINAL_DROPIN: join(temp.path, 'dropin') },
    });
    assert.equal(unknown.stdout, 'error: no user for the shares\n');
  });
});

describe('the unit', () => {
  const unit = readFileSync(join(INSTALLATION, 'files/nas-os-gateway.service'), 'utf8')
    .split('\n')
    .filter((line) => !line.startsWith('#'))
    .join('\n');

  it('runs the gateway as a user of its own, with port 80 as its only privilege', () => {
    for (const line of [
      'ExecStart=/usr/local/bin/nas-os-gateway',
      'DynamicUser=yes',
      'StateDirectory=nas-os-gateway',
      'StateDirectoryMode=0700',
      'AmbientCapabilities=CAP_NET_BIND_SERVICE',
      'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n',
      'Environment=GATEWAY_PORT=80',
      'Environment=GATEWAY_TLS_PORT=443',
      'Environment=GATEWAY_SCREEN_PORT=8081',
      'Environment=GATEWAY_LAUNCHER=127.0.0.1:3000',
      'Environment=GATEWAY_UI_DIR=/usr/local/share/nas-os/ui',
      'Environment=TOKIO_WORKER_THREADS=4 MALLOC_ARENA_MAX=2',
      'SupplementaryGroups=nas-os-share-password',
      'Environment=GATEWAY_SHARE_PASSWORD_SOCKET=/run/nas-os-share-password.sock',
      'ProtectSystem=strict',
      'WantedBy=multi-user.target',
    ]) {
      assert.ok(unit.includes(line), line);
    }
  });
});
