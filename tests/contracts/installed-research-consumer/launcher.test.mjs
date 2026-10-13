import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const launcher = fileURLToPath(new URL('../../../tools/contracts/installed-research-consumer.mjs', import.meta.url));

test('wrong archive fails before any install/import command and preserves its failing receipt', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'ei-installed-research-negative-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const archive = path.join(directory, 'wrong.tgz');
  const output = path.join(directory, 'failed-attempt');
  await writeFile(archive, 'not the owner-authorized archive');
  await assert.rejects(exec(process.execPath, [launcher, '--archive', archive, '--output', output]),
    (error) => error.code === 1);
  const original = await readFile(path.join(output, 'receipt.json'), 'utf8');
  const receipt = JSON.parse(original);
  assert.equal(receipt.producer.version, '0.9.7');
  assert.equal(receipt.candidate_selection.explicit, false);
  assert.equal(receipt.candidate_selection.pin_path, 'tests/contracts/installed-research-consumer/pin.json');
  assert.equal(receipt.diagnostic_status, 'failed');
  assert.equal(receipt.consumer_acceptance, 'INCOMPATIBLE_HOLD');
  assert.deepEqual(receipt.commands, []);
  assert.match(receipt.failures[0].message, /ARCHIVE_DIGEST_MISMATCH/);
  await assert.rejects(exec(process.execPath, [launcher, '--archive', archive, '--output', output]),
    (error) => error.code === 1 && error.stderr.includes('OUTPUT_EXISTS'));
  assert.equal(await readFile(path.join(output, 'receipt.json'), 'utf8'), original);
});

test('explicit 0.10.2 selection checks its own pinned bytes before any install and preserves failure', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'ei-installed-proposal-negative-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const archive = path.join(directory, 'wrong.tgz');
  const output = path.join(directory, 'failed-proposal');
  await writeFile(archive, 'not the separately pinned 0.10.2 proposal');
  const args = [launcher, '--archive', archive, '--output', output, '--candidate', '0.10.2'];
  await assert.rejects(exec(process.execPath, args), (error) => error.code === 1);
  const original = await readFile(path.join(output, 'receipt.json'), 'utf8');
  const receipt = JSON.parse(original);
  assert.equal(receipt.producer.version, '0.10.2');
  assert.equal(receipt.producer.source_sha, '463357726e9825f7e55fbbed54cdcde8129559bf');
  assert.equal(receipt.producer.archive_sha256, 'f317a95bc54a9827cb8d93bf2b6a9bf439752a4d3a18ffef2aa73806c03c8840');
  assert.equal(receipt.candidate_selection.explicit, true);
  assert.equal(receipt.candidate_selection.pin_path, 'tests/contracts/installed-research-consumer/pin-0.10.2.json');
  assert.match(receipt.candidate_selection.pin_sha256, /^[a-f0-9]{64}$/);
  assert.equal(receipt.diagnostic_status, 'failed');
  assert.equal(receipt.consumer_acceptance, 'INCOMPATIBLE_HOLD');
  assert.deepEqual(receipt.commands, []);
  assert.match(receipt.failures[0].message, /ARCHIVE_DIGEST_MISMATCH/);
  assert.deepEqual(receipt.required_checks, { archive_identity: 'failed', installed_content: 'not_run',
    actual_caller: 'not_run', installed_types: 'not_run' });
  assert.equal(receipt.skips.length, 3);
  await assert.rejects(exec(process.execPath, args),
    (error) => error.code === 1 && error.stderr.includes('OUTPUT_EXISTS'));
  assert.equal(await readFile(path.join(output, 'receipt.json'), 'utf8'), original);
});

test('unlisted versions and file paths cannot supply a diagnostic pin', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'ei-installed-proposal-selection-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  for (const [index, candidate] of ['0.10.1', '../../pin.json', '__proto__'].entries()) {
    const output = path.join(directory, `refused-${index}`);
    await assert.rejects(exec(process.execPath, [launcher, '--archive', path.join(directory, 'unused.tgz'),
      '--output', output, '--candidate', candidate]),
    (error) => error.code === 1 && error.stderr.includes('UNSUPPORTED_CANDIDATE'));
    await assert.rejects(lstat(output), (error) => error.code === 'ENOENT');
  }
});
