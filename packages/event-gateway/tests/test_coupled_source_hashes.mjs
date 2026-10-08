import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {test} from 'node:test';
import {sourceHashes} from '../docs/native-bridge/coupled-workerd-source-hashes.mjs';

test('hashes only resolved sources inside qualified roots, before reading contents', t => {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Owned disposable test tree only; no user paths.
  const temporary = fs.mkdtempSync(join(tmpdir(), 'native-source-hashes-'));
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Owned disposable test tree only; no user paths.
  t.after(() => fs.rmSync(temporary, {recursive: true, force: true}));
  const root = join(temporary, 'qualified');
  const fixture = join(temporary, 'fixture');
  const outside = join(temporary, 'qualified-other');
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Owned disposable test tree only; no user paths.
  for (const directory of [root, fixture, outside]) fs.mkdirSync(directory);
  const source = join(root, 'module.ts');
  const fixtureSource = join(fixture, 'worker.ts');
  const escaped = join(outside, 'outside.ts');
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Owned disposable test tree only; no user paths.
  for (const path of [source, fixtureSource, escaped]) fs.writeFileSync(path, 'synthetic source');
  const symlink = join(root, 'escape.ts');
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Owned disposable test tree only; no user paths.
  fs.symlinkSync(escaped, symlink);
  const sha = createHash('sha256').update('synthetic source').digest('hex');
  assert.deepEqual(sourceHashes([source, fixtureSource], [root, fixture]), {
    [source]: sha, [fixtureSource]: sha,
  });
  const read = t.mock.method(fs, 'readFileSync');
  for (const path of [escaped, join(root, '..', 'qualified-other', 'outside.ts'), symlink]) {
    assert.throws(() => sourceHashes([source, path], [root, fixture]), /outside qualified source roots/);
    assert.equal(read.mock.callCount(), 0, 'validate all paths before any content read');
  }
});
