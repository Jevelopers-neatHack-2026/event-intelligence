import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test, { after, before } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createDiscoveryFrontierStore } from '../../../src/discovery/planner/frontier.mjs';

const REPO = fileURLToPath(new URL('../../../', import.meta.url));
const WORKER = fileURLToPath(new URL('./legacy-writer-fence-worker.mjs', import.meta.url));
const PINS = {
  1: ['d91e08d666abc243ae456a7f9f1bc9c745ca4f8d', '4e6cfbb88e7913984739634a69323c410dbff5ab48128b0ef70eee782de5105e',
    'a61b941ae24b6d6802bb61bb8c88c9a88df6796bab0b1ca8dfcb4dc463c9de88'],
  2: ['d1731173b5ccb6f5212d6e83c71ebd1a8d4ff66f', 'eec8f1f675258517d5aff384d7fbb5d1ad755899b6513b003d1c24b2c8d97fed',
    'a61b941ae24b6d6802bb61bb8c88c9a88df6796bab0b1ca8dfcb4dc463c9de88'],
  3: ['ef69133bb38320793e02f8530accdd67e59f90e3', '1abca6355bf01393dfc81f831638fa77d00945885f7bd339bba1894e85da853f',
    'b5b63ca95f700d5469517513141836142fbb6b109d596bc6afcec2a6fe4f6fa4'],
  4: ['02a9804fda71594d535fb1e249442b1841c7da4b', 'f6f3e4b9d892d22fe3cd04e4edf41d7278c2d0acae9d35ef5a6cc370a39ff300',
    'b5b63ca95f700d5469517513141836142fbb6b109d596bc6afcec2a6fe4f6fa4'],
};
let historicalDirectory;
const versions = {};
before(async () => {
  historicalDirectory = await mkdtemp(path.join(os.tmpdir(), 'ei-fence-historical-source-'));
  for (const [version, [commit, frontierHash, urlPolicyHash]] of Object.entries(PINS)) {
    versions[version] = path.join(historicalDirectory, version);
    for (const [relative, expectedHash] of [
      ['src/discovery/planner/frontier.mjs', frontierHash],
      ['src/security/url-policy.mjs', urlPolicyHash],
      ['src/security/errors.mjs', 'b64dba291da264e75eaf42fd3eeea9ef90785c86aa866bbf6c94ed88769c76d6'],
    ]) {
      const extracted = spawnSync('git', ['show', `${commit}:${relative}`], { cwd: REPO, maxBuffer: 1024 * 1024 });
      assert.equal(extracted.status, 0, 'the exact historical module and its complete local imports must be present');
      assert.equal(createHash('sha256').update(extracted.stdout).digest('hex'), expectedHash);
      const destination = path.join(versions[version], relative);
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, extracted.stdout, { flag: 'wx', mode: 0o600 });
    }
  }
});
after(async () => { if (historicalDirectory) await rm(historicalDirectory, { recursive: true, force: true }); });

async function directoryFor(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ei-legacy-writer-fence-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

for (const writerVersion of [1, 2, 3, 4]) {
  for (const stage of ['schema', 'operation']) {
    test(`actual v${writerVersion} writer is fenced across the ${stage} transaction boundary`, { timeout: 15_000 }, async (t) => {
      const child = spawnSync(process.execPath, [WORKER, JSON.stringify({ role: 'overlap',
        directory: await directoryFor(t), versions, writerVersion, seedVersion: writerVersion, stage })],
      { encoding: 'utf8', timeout: 12_000, maxBuffer: 1024 * 1024, env: process.env });
      if (child.stderr) t.diagnostic(child.stderr);
      assert.equal(child.error, undefined);
      assert.equal(child.status, 0);
      assert.equal(child.signal, null);
      const outcome = JSON.parse(child.stdout);
      assert.equal(outcome.progress.inFlightLeases, 1);
      assert.equal(outcome.progress.limits.maxInFlightLeases, 1);
      assert.equal(outcome.transportExecuted, false);
    });
  }
}

for (const [writerVersion, seedVersion] of [[1, 0], [2, 0], [3, 0], [3, 1], [3, 2]]) {
  test(`actual v${writerVersion} captured schema${seedVersion} cannot escape the durable fence by lowering the header`,
    { timeout: 15_000 }, async (t) => {
      const child = spawnSync(process.execPath, [WORKER, JSON.stringify({ role: 'overlap',
        directory: await directoryFor(t), versions, writerVersion, seedVersion, stage: 'schema' })],
      { encoding: 'utf8', timeout: 12_000, maxBuffer: 1024 * 1024, env: process.env });
      if (child.stderr) t.diagnostic(child.stderr);
      assert.equal(child.error, undefined);
      assert.equal(child.status, 0);
      assert.equal(child.signal, null);
      const outcome = JSON.parse(child.stdout);
      assert.equal(outcome.headerAfterOld, writerVersion, 'the real old PRAGMA must actually lower the header');
      assert.equal(outcome.finalVersion, 5);
      assert.equal(outcome.progress.inFlightLeases, 1);
    });
}

async function fixture(t, now = () => 1000) {
  const directory = await directoryFor(t);
  const tenantId = 'synthetic-legacy-fence';
  const store = createDiscoveryFrontierStore({ directory, resolveTenant: () => tenantId, now,
    tenantLimits: { maxInFlightLeases: 1 } });
  t.after(() => store.close());
  const scope = await store.scopeForAuthenticatedRequest({});
  await store.createRun(scope, { runId: 'old-work', seeds: [{ url: 'https://events.example.com/old-work' }] });
  const hash = createHash('sha256').update(`event-intelligence:tenant:v1:${tenantId}`).digest('hex');
  const database = new DatabaseSync(path.join(directory, hash, 'frontier.sqlite'));
  t.after(() => database.close());
  return { directory, store, scope, database };
}

test('the guard is committed closed and raw legacy DML is denied without changing rows', async (t) => {
  const h = await fixture(t);
  const claim = await h.store.claimNext(h.scope, 'old-work', { workerId: 'current', claimKey: 'current' });
  assert.equal(claim.state, 'claimed');
  assert.equal(h.database.prepare('SELECT is_open FROM frontier_write_fence').get().is_open, 0);
  const before = h.database.prepare('SELECT * FROM frontier_runs').all();
  assert.throws(() => h.database.exec('UPDATE frontier_runs SET attempts_admitted = attempts_admitted + 1'),
    /frontier write fence closed/);
  assert.deepEqual(h.database.prepare('SELECT * FROM frontier_runs').all(), before);
  assert.equal(h.database.prepare('PRAGMA trusted_schema').get().trusted_schema, 1,
    'even a separately opened raw connection cannot write through the guard');
  assert.equal((await h.store.getTenantProgress(h.scope)).inFlightLeases, 1);
});

test('a stale header never authorizes policy replacement and matching recovery retains its lease', async (t) => {
  const h = await fixture(t);
  await h.store.claimNext(h.scope, 'old-work', { workerId: 'retained', claimKey: 'retained' });
  const policy = h.database.prepare('SELECT * FROM frontier_tenant_policy').all();
  const claims = h.database.prepare('SELECT * FROM frontier_claims').all();
  h.database.exec('PRAGMA user_version = 1'); // The historical v1 effect is tested above with its actual writer.
  const mismatched = createDiscoveryFrontierStore({ directory: h.directory,
    resolveTenant: () => 'synthetic-legacy-fence', now: () => 1000, tenantLimits: { maxInFlightLeases: 2 } });
  t.after(() => mismatched.close());
  await assert.rejects(mismatched.getTenantProgress(await mismatched.scopeForAuthenticatedRequest({})),
    (error) => error.code === 'FRONTIER_CONFLICT');
  assert.equal(h.database.prepare('PRAGMA user_version').get().user_version, 1,
    'a mismatched caller cannot commit even a header repair');
  assert.deepEqual(h.database.prepare('SELECT * FROM frontier_tenant_policy').all(), policy);
  assert.deepEqual(h.database.prepare('SELECT * FROM frontier_claims').all(), claims);
  assert.equal((await h.store.getTenantProgress(h.scope)).inFlightLeases, 1);
  assert.equal(h.database.prepare('PRAGMA user_version').get().user_version, 5);
});

test('the later operation transaction rechecks metadata and repairs only an intact stale header', async (t) => {
  const h = await fixture(t);
  const originalExec = DatabaseSync.prototype.exec;
  let begins = 0;
  try {
    DatabaseSync.prototype.exec = function (sql) {
      if (sql === 'BEGIN IMMEDIATE' && ++begins === 2) {
        h.database.exec('PRAGMA user_version = 1');
      }
      return Reflect.apply(originalExec, this, [sql]);
    };
    assert.equal((await h.store.claimNext(h.scope, 'old-work', { workerId: 'late-header', claimKey: 'late-header' })).state, 'claimed');
    assert.equal(begins, 2, 'the header is changed after schema validation and before the separate operation');
  } finally { DatabaseSync.prototype.exec = originalExec; }
  assert.equal(h.database.prepare('PRAGMA user_version').get().user_version, 5);
  assert.equal(h.database.prepare('SELECT is_open FROM frontier_write_fence').get().is_open, 0);

  begins = 0;
  try {
    DatabaseSync.prototype.exec = function (sql) {
      if (sql === 'BEGIN IMMEDIATE' && ++begins === 2) {
        h.database.exec('UPDATE frontier_write_fence SET is_open = 1');
      }
      return Reflect.apply(originalExec, this, [sql]);
    };
    await assert.rejects(h.store.getTenantProgress(h.scope), (error) => error.code === 'FRONTIER_VERSION');
    assert.equal(begins, 2, 'the committed open marker appears only after schema validation');
  } finally { DatabaseSync.prototype.exec = originalExec; }
  assert.equal(h.database.prepare('SELECT is_open FROM frontier_write_fence').get().is_open, 1,
    'failed validation must not silently clear a corrupt committed marker');
  assert.equal(h.database.prepare('SELECT COUNT(*) AS count FROM frontier_claims').get().count, 1);
});

for (const mode of ['throw', 'abort']) {
  test(`a current ${mode} inside the operation rolls back its open fence and admission`, async (t) => {
    let armed = false;
    const controller = new AbortController();
    const h = await fixture(t, () => {
      if (armed) {
        if (mode === 'throw') throw new Error('synthetic clock failure inside current transaction');
        controller.abort();
      }
      return 1000;
    });
    const before = await h.store.getTenantProgress(h.scope);
    armed = true;
    await assert.rejects(h.store.claimNext(h.scope, 'old-work', { workerId: mode, claimKey: mode }, controller.signal),
      (error) => error.code === (mode === 'throw' ? 'FRONTIER_STORAGE' : 'FRONTIER_STOPPED'));
    armed = false;
    assert.equal(h.database.prepare('SELECT is_open FROM frontier_write_fence').get().is_open, 0);
    assert.deepEqual(await h.store.getTenantProgress(h.scope), before);
    assert.equal((await h.store.claimNext(h.scope, 'old-work', { workerId: 'recovery', claimKey: 'recovery' })).state, 'claimed');
  });
}

test('SIGKILL inside the current operation rolls back the open fence before recovery', async (t) => {
  const h = await fixture(t);
  const child = spawnSync(process.execPath, [WORKER, JSON.stringify({ role: 'crash-open', directory: h.directory })],
    { encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024, env: process.env });
  if (child.stderr) t.diagnostic(child.stderr);
  assert.equal(child.error, undefined);
  assert.equal(child.status, null);
  assert.equal(child.signal, 'SIGKILL');
  assert.equal(child.stdout, 'current-operation-callback-entered\n');
  assert.equal(h.database.prepare('SELECT is_open FROM frontier_write_fence').get().is_open, 0);
  assert.equal(h.database.prepare('SELECT COUNT(*) AS count FROM frontier_claims').get().count, 0);
  assert.equal((await h.store.claimNext(h.scope, 'old-work', { workerId: 'recovery', claimKey: 'recovery' })).state, 'claimed');
});

for (const corruption of ['missing-row', 'open-row', 'wrong-protocol', 'missing-trigger', 'changed-trigger', 'missing-table']) {
  test(`schema5 ${corruption} fails closed without policy rebinding or history loss`, async (t) => {
    const h = await fixture(t);
    await h.store.claimNext(h.scope, 'old-work', { workerId: 'retained', claimKey: 'retained' });
    const policy = h.database.prepare('SELECT * FROM frontier_tenant_policy').all();
    const claims = h.database.prepare('SELECT * FROM frontier_claims').all();
    if (corruption === 'missing-row') h.database.exec('DELETE FROM frontier_write_fence');
    if (corruption === 'open-row') h.database.exec('UPDATE frontier_write_fence SET is_open = 1');
    if (corruption === 'wrong-protocol') h.database.exec('PRAGMA ignore_check_constraints = ON; UPDATE frontier_write_fence SET protocol_version = 2');
    if (corruption === 'missing-trigger' || corruption === 'changed-trigger') {
      h.database.exec('DROP TRIGGER frontier_write_fence_frontier_runs_update');
      if (corruption === 'changed-trigger') h.database.exec(`CREATE TRIGGER frontier_write_fence_frontier_runs_update
        BEFORE UPDATE ON frontier_runs BEGIN SELECT 1; END`);
    }
    if (corruption === 'missing-table') h.database.exec('DROP TABLE frontier_write_fence');
    const marker = h.database.prepare("SELECT type, name, sql FROM sqlite_master WHERE name GLOB 'frontier_write_fence*' ORDER BY name").all();
    await assert.rejects(h.store.getTenantProgress(h.scope), (error) => error.code === 'FRONTIER_VERSION');
    assert.deepEqual(h.database.prepare('SELECT * FROM frontier_tenant_policy').all(), policy);
    assert.deepEqual(h.database.prepare('SELECT * FROM frontier_claims').all(), claims);
    assert.deepEqual(h.database.prepare("SELECT type, name, sql FROM sqlite_master WHERE name GLOB 'frontier_write_fence*' ORDER BY name").all(), marker);
    assert.equal(h.database.prepare('PRAGMA user_version').get().user_version, 5);
  });
}
