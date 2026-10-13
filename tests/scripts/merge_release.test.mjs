import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { nextVersion } from '../../scripts/release/merge_release.mjs';

describe('merge_release.mjs', () => {
  it('releases the package version as it stands when there is no tag yet', () => {
    assert.equal(nextVersion('0.1.0', null, 'patch'), '0.1.0');
  });

  it('bumps the last tag by the release type', () => {
    assert.equal(nextVersion('0.1.3', 'v0.1.3', 'patch'), '0.1.4');
    assert.equal(nextVersion('0.1.3', 'v0.1.3', 'minor'), '0.2.0');
    assert.equal(nextVersion('0.1.3', 'v0.1.3', 'major'), '1.0.0');
  });

  it('keeps a package version already ahead of the last tag', () => {
    assert.equal(nextVersion('0.3.0', 'v0.2.7', 'patch'), '0.3.0');
  });

  it('refuses a release type it does not know, tag or no tag', () => {
    assert.throws(() => nextVersion('0.1.0', null, 'huge'), /Unknown release type/);
    assert.throws(() => nextVersion('0.1.0', 'v0.1.0', 'huge'), /Unknown release type/);
  });
});
