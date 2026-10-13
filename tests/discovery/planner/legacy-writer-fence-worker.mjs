import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { writeSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { createDiscoveryFrontierStore } from '../../../src/discovery/planner/frontier.mjs';

// Synthetic scheduling of unchanged historical modules and a real current
// process. No transport, provider, private-auth minting, or fixture write bypass.
const job = JSON.parse(process.argv[2]);
const tenantId = 'synthetic-legacy-fence';
const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${tenantId}`).digest('hex');
const databasePath = path.join(job.directory, tenantHash, 'frontier.sqlite');
const options = { directory: job.directory, resolveTenant: () => tenantId, now: () => 1000,
  lockTimeoutMs: 10_000, tenantLimits: { maxInFlightLeases: 1 } };
const historicalOptions = (version) => version === 4 ? options
  : { directory: job.directory, resolveTenant: () => tenantId, now: () => 1000 };
const legacy = async (version) => import(pathToFileURL(path.join(job.versions[version],
  'src/discovery/planner/frontier.mjs')).href);
const seed = (store, scope, runId) => store.createRun(scope,
  { runId, seeds: [{ url: `https://events.example.com/${runId}` }] });
const raw = () => {
  const database = new DatabaseSync(databasePath, { readOnly: true });
  try {
    // Match the child's JSON transport representation while retaining every
    // stored field; DatabaseSync rows themselves have null prototypes.
    return JSON.parse(JSON.stringify({
      version: database.prepare('PRAGMA user_version').get().user_version,
      policy: database.prepare('SELECT * FROM frontier_tenant_policy').get(),
      leased: database.prepare("SELECT COUNT(*) AS count FROM frontier_claims WHERE state = 'leased'").get().count,
      oldRows: {
        runs: database.prepare("SELECT * FROM frontier_runs WHERE run_id = 'old-work'").all(),
        candidates: database.prepare("SELECT * FROM frontier_candidates WHERE run_id = 'old-work'").all(),
      },
    }));
  } finally { database.close(); }
};

if (job.role === 'current-fill') {
  const store = createDiscoveryFrontierStore(options);
  try {
    const scope = await store.scopeForAuthenticatedRequest({});
    await seed(store, scope, 'current-work');
    const claim = await store.claimNext(scope, 'current-work', { workerId: 'current', claimKey: 'current' });
    const progress = await store.getTenantProgress(scope);
    assert.equal(claim.state, 'claimed');
    assert.equal(progress.inFlightLeases, 1);
    assert.equal(progress.limits.maxInFlightLeases, 1);
    process.stdout.write(JSON.stringify({ claim, progress, raw: raw() }));
  } finally { store.close(); }
} else if (job.role === 'crash-open') {
  const store = createDiscoveryFrontierStore({ ...options, now() {
    writeSync(1, 'current-operation-callback-entered\n');
    process.kill(process.pid, 'SIGKILL'); // No JS or SQLite close/rollback handler can run.
  } });
  const scope = await store.scopeForAuthenticatedRequest({});
  await store.claimNext(scope, 'old-work', { workerId: 'crash', claimKey: 'crash' });
  throw new Error('the intended crash callback was not reached');
} else {
  assert.equal(job.role, 'overlap');
  if (job.seedVersion !== 0) {
    const previous = (await legacy(job.seedVersion)).createDiscoveryFrontierStore(historicalOptions(job.seedVersion));
    try { await seed(previous, await previous.scopeForAuthenticatedRequest({}), 'old-work'); }
    finally { previous.close(); }
  }
  const old = (await legacy(job.writerVersion)).createDiscoveryFrontierStore(historicalOptions(job.writerVersion));
  const current = createDiscoveryFrontierStore(options);
  const originalExec = DatabaseSync.prototype.exec;
  let begins = 0;
  let childResult;
  let oldResult;
  let oldError;
  try {
    const scope = await old.scopeForAuthenticatedRequest({});
    DatabaseSync.prototype.exec = function (sql) {
      if (sql === 'BEGIN IMMEDIATE') begins += 1;
      const atSchema = job.writerVersion === 1
        ? typeof sql === 'string' && sql.includes('CREATE TABLE IF NOT EXISTS frontier_runs')
        : sql === 'BEGIN IMMEDIATE' && begins === 1;
      const atOperation = sql === 'BEGIN IMMEDIATE' && begins === (job.writerVersion === 1 ? 1 : 2);
      if (!childResult && (job.stage === 'schema' ? atSchema : atOperation)) {
        const child = spawnSync(process.execPath, [process.argv[1], JSON.stringify({ ...job, role: 'current-fill' })],
          { encoding: 'utf8', timeout: 10_000, maxBuffer: 1024 * 1024, env: process.env });
        if (child.stderr) process.stderr.write(child.stderr);
        if (child.error) throw child.error;
        assert.equal(child.status, 0, 'the actual peer must bind and fill before the old writer resumes');
        assert.equal(child.signal, null);
        childResult = JSON.parse(child.stdout);
      }
      return Reflect.apply(originalExec, this, [sql]);
    };
    try {
      oldResult = job.seedVersion === 0 ? await seed(old, scope, 'old-work')
        : await old.claimNext(scope, 'old-work', { workerId: 'old', claimKey: 'old' });
    } catch (error) { oldError = error.code ?? error.name; }
    finally { DatabaseSync.prototype.exec = originalExec; }
    assert.ok(childResult, 'the intended real-peer interleaving must occur');
    const afterOld = raw();
    assert.equal(oldResult, undefined, 'the old writer must not commit new work');
    assert.ok(['FRONTIER_VERSION', 'FRONTIER_STORAGE'].includes(oldError), oldError);
    assert.equal(afterOld.leased, 1, 'the persisted tenant cap must hold before current readback');
    assert.deepEqual(afterOld.oldRows, childResult.raw.oldRows, 'fenced legacy DML must leave old run rows unchanged');
    assert.deepEqual(afterOld.policy, childResult.raw.policy, 'a stale version header never rebinds the policy');
    const currentScope = await current.scopeForAuthenticatedRequest({});
    const progress = await current.getTenantProgress(currentScope);
    assert.deepEqual(progress, childResult.progress);
    assert.equal(raw().version, 5, 'validated metadata restores a stale legacy header');
    const replay = await current.claimNext(currentScope, 'current-work', { workerId: 'current', claimKey: 'current' });
    assert.equal(replay.state, 'claimed');
    assert.equal(replay.replayed, true);
    assert.equal(replay.leaseToken, childResult.claim.leaseToken);
    await assert.rejects(old.getSnapshot(scope, 'old-work'), (error) => error.code === 'FRONTIER_VERSION');
    process.stdout.write(JSON.stringify({ stage: job.stage, writerVersion: job.writerVersion,
      seedVersion: job.seedVersion, oldError, headerAfterOld: afterOld.version,
      finalVersion: raw().version, progress, transportExecuted: false }));
  } finally {
    DatabaseSync.prototype.exec = originalExec;
    old.close(); current.close();
  }
}
