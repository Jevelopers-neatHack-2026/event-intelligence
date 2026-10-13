import { access, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { createDiscoveryFrontierStore, DiscoveryFrontierError } from '../../../src/discovery/planner/frontier.mjs';

const job = JSON.parse(process.argv[2]);
const originalExec = DatabaseSync.prototype.exec;
let peer;
if (job.peerTenantLimits) {
  // Deterministically let a real peer migrate after the opening connection's
  // pre-lock work, immediately before it acquires its first write transaction.
  DatabaseSync.prototype.exec = function (sql) {
    if (sql === 'BEGIN IMMEDIATE' && peer === undefined) {
      const completed = spawnSync(process.execPath, [process.argv[1], JSON.stringify({
        ...job, id: `${job.id}-peer`, tenantLimits: job.peerTenantLimits, peerTenantLimits: undefined,
      })], { encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024 });
      if (completed.stderr) process.stderr.write(completed.stderr);
      if (completed.error || completed.status !== 0 || completed.signal) throw new Error('synthetic policy peer failed');
      peer = JSON.parse(completed.stdout);
      if (!peer.result) throw new Error('synthetic policy peer did not bind its policy');
    }
    return Reflect.apply(originalExec, this, [sql]);
  };
}
const store = createDiscoveryFrontierStore({
  directory: job.directory,
  resolveTenant: (request) => request.principal.tenantId,
  now: () => 1000,
  lockTimeoutMs: 10_000,
  ...(job.tenantLimits ? { tenantLimits: job.tenantLimits } : {}),
});
try {
  await writeFile(`${job.barrier}/${job.id}.ready`, 'ready', { flag: 'wx' });
  const deadline = performance.now() + 5000;
  let released = false;
  while (performance.now() < deadline) {
    try { await access(`${job.barrier}/release`); released = true; break; } catch {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }
  if (!released) throw new Error('synthetic tenant worker barrier timed out');
  const scope = await store.scopeForAuthenticatedRequest({ principal: { tenantId: job.tenantId } });
  let result;
  if (job.operation === 'claim') {
    result = await store.claimNext(scope, job.runId, { workerId: job.id, claimKey: job.id });
  } else if (job.operation === 'transport') {
    result = await store.admitTransportHop(scope, job.runId, job.input);
  } else if (job.operation === 'policy') {
    result = await store.getTenantProgress(scope);
  } else {
    throw new Error('unsupported synthetic tenant worker operation');
  }
  process.stdout.write(JSON.stringify({ result, peer }));
} catch (error) {
  if (!(error instanceof DiscoveryFrontierError)) throw error;
  process.stdout.write(JSON.stringify({ error: error.code, peer }));
} finally {
  store.close();
  DatabaseSync.prototype.exec = originalExec;
}
