// Extracts the changelog section for a given version or falls back to the commit messages if no section is found.

const { execFileSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const version = process.argv[2];

if (!version) {
  console.error('Usage: node scripts/release/extract_changelog.cjs <version>');
  process.exit(1);
}

const gitPath = '/usr/bin/git';

const git = (...args) =>
  execFileSync(gitPath, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();

function changelogSection() {
  const changelog = readFileSync(join(__dirname, '..', '..', 'CHANGELOG.txt'), 'utf8');
  const heading = `## [${version}]`;
  const headingIndex = changelog.indexOf(heading);
  if (headingIndex === -1) {
    return null;
  }

  const afterHeading = changelog.slice(headingIndex);
  const nextHeadingIndex = afterHeading.slice(heading.length).search(/^## \[/m);
  return nextHeadingIndex === -1
    ? afterHeading
    : afterHeading.slice(0, heading.length + nextHeadingIndex);
}

function commitSection() {
  const tag = `v${version}`;
  let range = tag;
  try {
    const previous = git('describe', '--tags', '--abbrev=0', '--match', 'v*', `${tag}^`);
    range = `${previous}..${tag}`;
  } catch {
    console.warn(`\n❌ No previous tag found, using all commits up to ${tag}.`);
  }
  const subjects = git('log', '--no-merges', '--format=- %s', range)
    .split('\n')
    .filter((line) => line && !line.startsWith('- chore: release v'));
  return [`## [${version}]`, '', ...subjects].join('\n');
}

try {
  process.stdout.write((changelogSection() ?? commitSection()).trim() + '\n');
} catch {
  console.error(`\n❌ No changelog entry and no tag v${version} to read the commits from.`);
  process.exit(1);
}
