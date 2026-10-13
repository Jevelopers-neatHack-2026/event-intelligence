import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
const execute = promisify(execFile);
const required = 35;

// These are verifier-only synthetic inventories, not product passes. The real
// product route includes reader.test.mjs only, so this never recurses into itself.
for (const mode of ['complete', 'missing', 'reduced', 'skipped']) {
  test(`dedicated verifier ${mode} inventory`, async (t) => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ei-outcome-verifier-'));
    t.after(() => rm(root, { recursive: true, force: true }));
    await mkdir(path.join(root, 'tools'), { recursive: true });
    await mkdir(path.join(root, 'tests/security/retrieval-outcomes'), { recursive: true });
    await writeFile(path.join(root, 'tools/verify-retrieval-outcomes.mjs'),
      await readFile(new URL('../../../tools/verify-retrieval-outcomes.mjs', import.meta.url)));
    if (mode !== 'missing') {
      const count = mode === 'reduced' ? 1 : required;
      const lines = ["import test from 'node:test';"];
      for (let i = 0; i < count; i++) lines.push(`test${mode === 'skipped' && i === 0 ? '.skip' : ''}('synthetic inventory ${i}', () => {});`);
      await writeFile(path.join(root, 'tests/security/retrieval-outcomes/reader.test.mjs'), lines.join('\n'));
    }
    let result;
    const env = { ...process.env };
    // This is a separate top-level verifier process. Inheriting node:test's
    // private child marker makes run() deliberately refuse recursive execution.
    delete env.NODE_TEST_CONTEXT;
    try {
      result = { ...await execute(process.execPath, ['tools/verify-retrieval-outcomes.mjs'], {
        cwd: root, timeout: 10_000, maxBuffer: 1024 * 1024, env,
      }), code: 0 };
    } catch (error) { result = error; }
    t.diagnostic(result.stdout ?? 'no stdout');
    t.diagnostic(result.stderr ?? 'no stderr');
    assert.equal(result.signal ?? null, null);
    assert.equal(result.killed ?? false, false);
    assert.equal(result.code, mode === 'complete' ? 0 : 1);
    const line = result.stdout.split('\n').find((v) => v.startsWith('RETRIEVAL_OUTCOMES_VERIFY_JSON='));
    assert.ok(line); const summary = JSON.parse(line.slice('RETRIEVAL_OUTCOMES_VERIFY_JSON='.length));
    assert.equal(summary.expected_cases, required);
    assert.equal(summary.status, mode === 'complete' ? 'passed' : 'failed');
    if (mode === 'complete') assert.equal(summary.passed_cases, required);
    if (mode === 'reduced') assert.equal(summary.observed_cases, 1);
    if (mode === 'skipped') assert.equal(summary.skipped_cases, 1);
    if (mode === 'missing') assert.ok(summary.failed_cases > 0);
  });
}
