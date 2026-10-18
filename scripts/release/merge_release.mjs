// Automates the release process for the NAS gateway. It handles version bumping, committing, merging into the main branch, and tagging the release.
//
// Usage:
// pnpm run release:merge -- [--type=patch|minor|major] [--branch=main] [--dry-run]

import { execFileSync, execSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { prepareRelease } from './prepare_release.mjs';

const versionFiles = [
  ['Cargo.toml', /^version = ".*"$/m, (version) => `version = "${version}"`],
  [
    'sonar-project.properties',
    /^sonar\.projectVersion=.*$/m,
    (version) => `sonar.projectVersion=${version}`,
  ],
];

const option = (name) =>
  process.argv.find((argument) => argument.startsWith(`--${name}=`))?.split('=')[1];
const type = option('type') ?? 'patch';
const main = option('branch') ?? 'main';
const dryRun = process.argv.includes('--dry-run');

const gitPath = '/usr/bin/git';
const cargoPath = join(process.env.CARGO_HOME ?? join(homedir(), '.cargo'), 'bin', 'cargo');

const git = (...args) => execFileSync(gitPath, args, { encoding: 'utf8' }).trim();
const parse = (version) => version.replace(/^v/, '').split('-')[0].split('.').map(Number);

/**
 * The last release tag, or `null` before the first release. `git describe` fails when there is no
 * tag at all, which is not an error here: it is where every repository starts.
 */
function latestTag() {
  try {
    return execFileSync(gitPath, ['describe', '--tags', '--abbrev=0', '--match', 'v*'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return null;
  }
}

/**
 * The package version when it is already ahead of the last tag, otherwise the next `bump`. The
 * first release is the package version as it stands.
 */
export function nextVersion(current, latest, bump) {
  if (!['major', 'minor', 'patch'].includes(bump)) {
    throw new Error(`Unknown release type "${bump}": use patch, minor or major.`);
  }
  if (!latest) {
    return current;
  }
  const [major, minor, patch] = parse(latest);
  const bumps = {
    major: [major + 1, 0, 0],
    minor: [major, minor + 1, 0],
    patch: [major, minor, patch + 1],
  };

  const [ahead, behind] = [parse(current), parse(latest)];
  const first = ahead.findIndex((part, index) => part !== behind[index]);

  return first !== -1 && ahead[first] > behind[first] ? current : bumps[bump].join('.');
}

function writeVersion(version) {
  execSync(`npm version ${version} --no-git-tag-version --allow-same-version`, {
    stdio: 'ignore',
  });
  for (const [file, pattern, line] of versionFiles) {
    writeFileSync(file, readFileSync(file, 'utf8').replace(pattern, line(version)));
  }

  execFileSync(cargoPath, ['update', '--workspace', '--manifest-path', 'Cargo.toml'], {
    stdio: 'inherit',
  });
}

function mergeRelease() {
  if (git('status', '--porcelain')) {
    throw new Error('The working tree is not clean: commit or stash the changes first.');
  }

  const branch = git('rev-parse', '--abbrev-ref', 'HEAD');
  const latest = latestTag();
  const { version: current } = JSON.parse(readFileSync('package.json', 'utf8'));
  const version = nextVersion(current, latest, type);

  const since = latest ? `last tag ${latest}` : 'first release';
  console.log(`\n🚀 Releasing v${version} from ${branch} into ${main} (${since}).`);
  if (dryRun) {
    return;
  }

  try {
    writeVersion(version);
    prepareRelease();
  } catch (error) {
    git('checkout', '--', '.');
    throw error;
  }

  git('add', '--all');
  if (git('status', '--porcelain')) {
    git('commit', '-m', `chore: release v${version}`);
  }
  if (branch !== main) {
    git('checkout', main);
    git('pull', '--ff-only', 'origin', main);
    git('merge', '--no-ff', '-m', `chore: merge release v${version}`, branch);
  }
  git('tag', `v${version}`);
  git('push', 'origin', main, `v${version}`);

  console.log(`\n✅ v${version} pushed: the build pipeline takes it from here.`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    mergeRelease();
  } catch (error) {
    console.error(`\n❌ ${error instanceof Error ? error.message : error}`);
    process.exit(1);
  }
}
