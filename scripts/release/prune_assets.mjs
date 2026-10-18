import { readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';

const VERSION = /(?<![\d.])(\d+)\.(\d+)\.(\d+)/;
const PRE_RELEASE = /^-(?!linux\b)([0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)/;
const EXTENSION = /\.(?:tgz|tar|pdf|sha256)\b/;

function parse(text) {
  const match = VERSION.exec(text);
  if (!match) {
    return null;
  }
  const suffix = text.slice(match.index + match[0].length).split(EXTENSION, 1)[0];
  const pre = PRE_RELEASE.exec(suffix)?.[1] ?? null;
  return {
    text: match[0] + (pre === null ? '' : `-${pre}`),
    parts: match.slice(1, 4).map(Number),
    pre,
  };
}

export function compareVersions(left, right) {
  const a = parse(left);
  const b = parse(right);
  for (let index = 0; index < 3; index += 1) {
    if (a.parts[index] !== b.parts[index]) {
      return a.parts[index] - b.parts[index];
    }
  }
  if (a.pre === b.pre) {
    return 0;
  }
  if (a.pre === null) {
    return 1;
  }
  if (b.pre === null) {
    return -1;
  }
  return a.pre < b.pre ? -1 : 1;
}

/**
 * Removes from `directory` the files of releases other than `version` and the one before it, the
 * newest older version among the files named with one of `prefixes`. Answers the removed names.
 */
export function pruneAssets(directory, version, prefixes) {
  const files = readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name);
  
  const own = (name) => prefixes.some((prefix) => name.startsWith(prefix));
  const versionOf = (name) => parse(name)?.text ?? null;
  const previous = files
    .filter(own)
    .map(versionOf)
    .filter((found) => found !== null && compareVersions(found, version) < 0)
    .sort(compareVersions)
    .at(-1);
  
  const kept = new Set([version, previous].filter(Boolean));
  const removed = files.filter((name) => {
    const found = versionOf(name);
    return found !== null && !(own(name) && kept.has(found));
  });
  
  for (const name of removed) {
    rmSync(join(directory, name), { force: true });
  }

  return removed;
}
