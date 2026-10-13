import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createDiscoveryFrontierStore, DiscoveryFrontierError } from '../../../src/discovery/planner/frontier.mjs';
import { withPrivilegedFrontierFixtureMutation } from './frontier-fixture-mutation.mjs';

const MIB = 1024 * 1024;
const REPO = fileURLToPath(new URL('../../../', import.meta.url));
const WORKER = fileURLToPath(new URL('./tenant-admission-worker.mjs', import.meta.url));
const V1_COMMIT = 'd91e08d666abc243ae456a7f9f1bc9c745ca4f8d';
const V1_HASH = '4e6cfbb88e7913984739634a69323c410dbff5ab48128b0ef70eee782de5105e';
const V3_COMMIT = 'ef69133bb38320793e02f8530accdd67e59f90e3';
const V3_HASH = '1abca6355bf01393dfc81f831638fa77d00945885f7bd339bba1894e85da853f';
const DEFAULTS = { maxInFlightLeases: 4, maxReservedDecodedBytes: 100 * MIB };
const codeIs = (code) => (error) => error instanceof DiscoveryFrontierError && error.code === code;

async function fixture(t, tenantLimits) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ei-tenant-admission-'));
  const stores = new Set();
  const open = async (tenantId = 'tenant-a', limits = tenantLimits) => {
    const store = createDiscoveryFrontierStore({ directory,
      resolveTenant: (request) => request?.principal?.tenantId,
      now: () => 1000,
      ...(limits ? { tenantLimits: limits } : {}),
    });
    stores.add(store);
    return { store, scope: await store.scopeForAuthenticatedRequest({ principal: { tenantId } }) };
  };
  t.after(async () => { for (const store of stores) store.close(); await rm(directory, { recursive: true, force: true }); });
  return { directory, open, ...await open() };
}

async function seed(store, scope, runId) {
  return store.createRun(scope, { runId, seeds: [{ url: `https://events.example.com/${runId}` }] });
}

async function claimRun(store, scope, runId) {
  await seed(store, scope, runId);
  return store.claimNext(scope, runId, { workerId: 'worker', claimKey: 'claim' });
}

function attempt(claim, attemptKey = 'attempt', previousAttemptKey) {
  return { leaseToken: claim.leaseToken, attemptKey, kind: previousAttemptKey ? 'retry' : 'initial',
    ...(previousAttemptKey ? { previousAttemptKey } : {}), url: claim.candidate.canonicalUrl };
}

function token(claim, attemptKey = 'attempt') { return { leaseToken: claim.leaseToken, attemptKey }; }

function databasePath(directory, tenantId = 'tenant-a') {
  const hash = createHash('sha256').update(`event-intelligence:tenant:v1:${tenantId}`).digest('hex');
  return path.join(directory, hash, 'frontier.sqlite');
}

async function racedWorkers(t, h, jobs) {
  const barrier = path.join(h.directory, `barrier-${randomUUID()}`);
  await mkdir(barrier);
  const pending = jobs.map((job, index) => {
    const input = { id: `child-${index}`, directory: h.directory, tenantId: 'tenant-a', ...job, barrier };
    const child = spawn(process.execPath, [WORKER, JSON.stringify(input)], { cwd: REPO, env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'] });
    t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
    const result = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (status, signal) => {
        if (stderr) t.diagnostic(stderr);
        if (status !== 0 || signal) return reject(new Error(`synthetic tenant worker failed (${status}, ${signal})`));
        try { resolve(JSON.parse(stdout)); } catch { reject(new Error('invalid synthetic tenant worker result')); }
      });
    });
    // Observe an early failure while the parent waits for every ready file.
    result.catch(() => {});
    return { id: input.id, result };
  });
  const deadline = performance.now() + 5000;
  let ready = false;
  while (performance.now() < deadline) {
    try { await Promise.all(pending.map(({ id }) => access(path.join(barrier, `${id}.ready`)))); ready = true; break; } catch {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }
  assert.equal(ready, true, 'all independent processes must reach the release barrier');
  await writeFile(path.join(barrier, 'release'), 'release');
  return Promise.all(pending.map(({ result }) => result));
}

test('default tenant policy bounds distinct runs and store instances without changing run limits', async (t) => {
  const h = await fixture(t);
  const claims = [];
  for (let index = 0; index < 4; index += 1) {
    const claim = await claimRun(h.store, h.scope, `run-${index}`);
    assert.equal(claim.state, 'claimed'); claims.push(claim);
  }
  const next = await h.open();
  assert.deepEqual(await claimRun(next.store, next.scope, 'fifth'), { state: 'waiting', reason: 'tenant_in_flight_limit' });
  const progress = await next.store.getTenantProgress(next.scope);
  assert.deepEqual(progress.limits, DEFAULTS);
  assert.equal(progress.inFlightLeases, 4);
  assert.equal(progress.reservedBytes, 0);
  const replay = await next.store.claimNext(next.scope, 'run-0', { workerId: 'worker', claimKey: 'claim' });
  assert.equal(replay.replayed, true);
  assert.equal(replay.leaseToken, claims[0].leaseToken);
  assert.equal((await next.store.getSnapshot(next.scope, 'fifth')).limits.maxInFlightLeases, 4);
});

test('separate processes atomically share the final tenant lease across distinct runs', { timeout: 15_000 }, async (t) => {
  const h = await fixture(t);
  for (let index = 0; index < 6; index += 1) await seed(h.store, h.scope, `process-${index}`);
  const results = await racedWorkers(t, h, Array.from({ length: 6 }, (_, index) => ({ operation: 'claim', runId: `process-${index}` })));
  assert.equal(results.filter(({ result }) => result?.state === 'claimed').length, 4);
  assert.equal(results.filter(({ result }) => result?.state === 'waiting' && result.reason === 'tenant_in_flight_limit').length, 2);
  assert.equal((await h.store.getTenantProgress(h.scope)).inFlightLeases, 4);
});

test('separate processes cannot spend the last tenant reservation from distinct runs', { timeout: 15_000 }, async (t) => {
  const h = await fixture(t);
  const fill = await claimRun(h.store, h.scope, 'fill');
  for (let index = 0; index < 4; index += 1) {
    assert.equal((await h.store.admitTransportHop(h.scope, 'fill', attempt(fill, `fill-${index}`, index ? `fill-${index - 1}` : undefined))).state, 'admitted');
  }
  const left = await claimRun(h.store, h.scope, 'left');
  const right = await claimRun(h.store, h.scope, 'right');
  const results = await racedWorkers(t, h, [
    { operation: 'transport', runId: 'left', input: attempt(left) },
    { operation: 'transport', runId: 'right', input: attempt(right) },
  ]);
  assert.deepEqual(results.map(({ result }) => result?.state).sort(), ['admitted', 'denied']);
  assert.equal(results.find(({ result }) => result?.state === 'denied').result.reason, 'tenant_decoded_budget');
  assert.equal((await h.store.getTenantProgress(h.scope)).reservedBytes, 100 * MIB);
  const snapshots = await Promise.all(['left', 'right'].map((id) => h.store.getSnapshot(h.scope, id)));
  assert.deepEqual(snapshots.map(({ counters }) => counters.transportAttemptAdmissions).sort(), [0, 1]);
});

test('unknown raw admissions retain tenant capacity after unresolved and restart', async (t) => {
  const h = await fixture(t);
  for (let index = 0; index < 4; index += 1) {
    const runId = `raw-${index}`;
    const claim = await claimRun(h.store, h.scope, runId);
    assert.equal((await h.store.admitAttempt(h.scope, runId, attempt(claim))).state, 'admitted');
    await h.store.markUnresolved(h.scope, runId, { leaseToken: claim.leaseToken, reason: 'dispatch_state_unknown' });
  }
  h.store.close();
  const restarted = await h.open();
  assert.deepEqual(await claimRun(restarted.store, restarted.scope, 'raw-fifth'), { state: 'waiting', reason: 'tenant_in_flight_limit' });
  const progress = await restarted.store.getTenantProgress(restarted.scope);
  assert.equal(progress.inFlightLeases, 4);
  assert.equal(progress.untrackedAttempts, 4);
  assert.equal(progress.reservedBytes, 80 * MIB);
});

test('raw admission replay is historical and cannot bypass or double-charge a full tenant policy', async (t) => {
  const h = await fixture(t, { maxInFlightLeases: 1, maxReservedDecodedBytes: 20 * MIB });
  const claim = await claimRun(h.store, h.scope, 'raw-replay');
  const input = attempt(claim);
  assert.equal((await h.store.admitAttempt(h.scope, 'raw-replay', input)).state, 'admitted');
  await h.store.stopRun(h.scope, 'raw-replay', 'cancelled');
  assert.equal((await h.store.admitAttempt(h.scope, 'raw-replay', input)).state, 'already_admitted');
  assert.equal((await h.store.admitTransportHop(h.scope, 'raw-replay', input)).state, 'already_admitted_without_transport_state');
  await assert.rejects(h.store.admitAttempt(h.scope, 'raw-replay', { ...input, url: 'https://events.example.com/different' }), codeIs('FRONTIER_CONFLICT'));
  await h.store.completeCandidate(h.scope, 'raw-replay', { leaseToken: claim.leaseToken,
    completionKey: 'completed', outcome: 'failed', suggestions: [] });
  const progress = await h.store.getTenantProgress(h.scope);
  assert.equal(progress.inFlightLeases, 1);
  assert.equal(progress.reservedBytes, 20 * MIB);
  assert.equal(progress.untrackedAttempts, 1);
  assert.equal(progress.unsettledTransportHops, 0);
  // The old per-run transport projection does not infer a tracked transport or
  // zero usage from a metadata-only admission; it remains a separate ledger.
  assert.equal((await h.store.getTransportProgress(h.scope, 'raw-replay')).reservedBytes, 0);
  assert.equal((await h.store.getSnapshot(h.scope, 'raw-replay')).usageStatus, 'unknown');
  assert.deepEqual(await claimRun(h.store, h.scope, 'after-raw'), { state: 'waiting', reason: 'tenant_in_flight_limit' });
});

test('raw admission has the same pre-insert tenant byte guard as tracked transport', async (t) => {
  const h = await fixture(t, { maxReservedDecodedBytes: 20 * MIB });
  const first = await claimRun(h.store, h.scope, 'raw-first');
  const second = await claimRun(h.store, h.scope, 'raw-second');
  assert.equal((await h.store.admitAttempt(h.scope, 'raw-first', attempt(first))).state, 'admitted');
  assert.deepEqual(await h.store.admitAttempt(h.scope, 'raw-second', attempt(second)), { state: 'denied', reason: 'tenant_decoded_budget' });
  assert.equal((await h.store.getSnapshot(h.scope, 'raw-second')).counters.transportAttemptAdmissions, 0);
});

for (const state of ['reserved', 'dispatch_intent', 'response_received', 'unknown']) {
  test(`${state} transport remains held after cancellation, lease resolution and restart`, async (t) => {
    const h = await fixture(t, { maxInFlightLeases: 1, maxReservedDecodedBytes: 20 * MIB });
    const claim = await claimRun(h.store, h.scope, 'uncertain');
    const input = attempt(claim);
    await h.store.admitTransportHop(h.scope, 'uncertain', input);
    if (state !== 'reserved') await h.store.markTransportDispatchIntent(h.scope, 'uncertain', token(claim));
    if (state === 'response_received') await h.store.markTransportResponseReceived(h.scope, 'uncertain', token(claim));
    if (state === 'unknown') await h.store.markTransportHopUnknown(h.scope, 'uncertain', token(claim));
    await h.store.stopRun(h.scope, 'uncertain', 'cancelled');
    if (state === 'reserved' || state === 'response_received') {
      await h.store.completeCandidate(h.scope, 'uncertain', { leaseToken: claim.leaseToken,
        completionKey: 'uncertain-completion', outcome: 'failed', suggestions: [] });
    } else {
      await h.store.markUnresolved(h.scope, 'uncertain', { leaseToken: claim.leaseToken, reason: 'dispatch_state_unknown' });
    }
    assert.equal((await h.store.getSnapshot(h.scope, 'uncertain')).counters.inFlightLeases, 0);
    h.store.close();
    const reopened = await h.open();
    const progress = await reopened.store.getTenantProgress(reopened.scope);
    assert.equal(progress.inFlightLeases, 1);
    assert.equal(progress.reservedBytes, 20 * MIB);
    assert.equal(progress.unsettledTransportHops, 1);
    assert.equal(progress.untrackedAttempts, 0);
    assert.deepEqual(await claimRun(reopened.store, reopened.scope, 'after-uncertain'), { state: 'waiting', reason: 'tenant_in_flight_limit' });
    const replay = await reopened.store.admitTransportHop(reopened.scope, 'uncertain', input);
    assert.equal(replay.state, 'already_admitted');
    assert.equal(replay.transportState, state);
    await assert.rejects(reopened.store.settleTransportHopKnownZero(reopened.scope, 'uncertain', token(claim)), codeIs('FRONTIER_STALE_LEASE'));
    assert.deepEqual(await reopened.store.getTenantProgress(reopened.scope), progress);
  });
}

for (const settlement of ['known-zero', 'body-complete']) {
  test(`${settlement} releases tenant outstanding capacity while preserving per-run spend`, async (t) => {
    const h = await fixture(t, { maxInFlightLeases: 1, maxReservedDecodedBytes: 20 * MIB });
    const claim = await claimRun(h.store, h.scope, 'settled');
    await h.store.admitTransportHop(h.scope, 'settled', attempt(claim));
    if (settlement === 'known-zero') {
      await h.store.settleTransportHopKnownZero(h.scope, 'settled', token(claim));
    } else {
      await h.store.markTransportDispatchIntent(h.scope, 'settled', token(claim));
      await h.store.markTransportResponseReceived(h.scope, 'settled', token(claim));
      await h.store.settleTransportHopBodyComplete(h.scope, 'settled', token(claim), 4096);
    }
    assert.equal((await h.store.getTenantProgress(h.scope)).inFlightLeases, 1, 'unfinished planner work still owns its lease');
    await h.store.completeCandidate(h.scope, 'settled', { leaseToken: claim.leaseToken,
      completionKey: 'settled-completion', outcome: 'no_links', suggestions: [] });
    const progress = await h.store.getTenantProgress(h.scope);
    assert.equal(progress.inFlightLeases, 0);
    assert.equal(progress.reservedBytes, 0);
    assert.equal((await h.store.getTransportProgress(h.scope, 'settled')).spentBytes, settlement === 'body-complete' ? 4096 : 0);
    const next = await claimRun(h.store, h.scope, 'after-settlement');
    assert.equal(next.state, 'claimed');
    assert.equal((await h.store.admitTransportHop(h.scope, 'after-settlement', attempt(next))).state, 'admitted');
  });
}

test('confirmed cancellation before any admission releases only the unused tenant lease', async (t) => {
  const h = await fixture(t, { maxInFlightLeases: 1 });
  const claim = await claimRun(h.store, h.scope, 'unused');
  await h.store.stopRun(h.scope, 'unused', 'cancelled');
  assert.equal((await h.store.getTenantProgress(h.scope)).inFlightLeases, 1);
  await h.store.markUnresolved(h.scope, 'unused', { leaseToken: claim.leaseToken, reason: 'cancelled_before_dispatch' });
  assert.equal((await h.store.getTenantProgress(h.scope)).inFlightLeases, 0);
  const next = await claimRun(h.store, h.scope, 'used');
  await h.store.admitAttempt(h.scope, 'used', attempt(next));
  await assert.rejects(h.store.markUnresolved(h.scope, 'used', { leaseToken: next.leaseToken, reason: 'cancelled_before_dispatch' }), codeIs('FRONTIER_CONFLICT'));
  assert.equal((await h.store.getTenantProgress(h.scope)).reservedBytes, 20 * MIB);
});

test('redirects count one lease identity and reserve every hop independently', async (t) => {
  const h = await fixture(t, { maxInFlightLeases: 2 });
  const claim = await claimRun(h.store, h.scope, 'redirects');
  for (let index = 0; index < 3; index += 1) {
    const input = index === 0 ? attempt(claim, 'hop-0') : {
      leaseToken: claim.leaseToken, attemptKey: `hop-${index}`, kind: 'redirect',
      previousAttemptKey: `hop-${index - 1}`, url: `https://events.example.com/redirect-${index}`,
    };
    assert.equal((await h.store.admitTransportHop(h.scope, 'redirects', input)).state, 'admitted');
  }
  assert.equal((await h.store.getTenantProgress(h.scope)).inFlightLeases, 1);
  assert.equal((await h.store.getTenantProgress(h.scope)).reservedBytes, 60 * MIB);
  assert.equal((await claimRun(h.store, h.scope, 'other')).state, 'claimed');
  assert.deepEqual(await claimRun(h.store, h.scope, 'third'), { state: 'waiting', reason: 'tenant_in_flight_limit' });
});

test('independent tenants have independent limits and issuer scopes cannot be copied', async (t) => {
  const h = await fixture(t, { maxInFlightLeases: 1, maxReservedDecodedBytes: 20 * MIB });
  const first = await claimRun(h.store, h.scope, 'same-run-id');
  await h.store.admitTransportHop(h.scope, 'same-run-id', attempt(first));
  const other = await h.open('tenant-b');
  const second = await claimRun(other.store, other.scope, 'same-run-id');
  assert.equal(second.state, 'claimed');
  assert.equal((await other.store.admitTransportHop(other.scope, 'same-run-id', attempt(second))).state, 'admitted');
  assert.equal((await other.store.getTenantProgress(other.scope)).reservedBytes, 20 * MIB);
  await assert.rejects(other.store.getTenantProgress(h.scope), codeIs('FRONTIER_DENIED'));
  await assert.rejects(h.store.getTenantProgress({ ...h.scope }), codeIs('FRONTIER_DENIED'));
});

test('normalized tenant policy is immutable across mutation, omission, mismatch and restart', async (t) => {
  const configured = { maxInFlightLeases: 2 };
  const h = await fixture(t, configured);
  configured.maxInFlightLeases = 3;
  assert.equal((await h.store.getTenantProgress(h.scope)).limits.maxInFlightLeases, 2);
  for (const tenantLimits of [undefined, { maxInFlightLeases: 1 }, { maxInFlightLeases: 3 },
    { maxInFlightLeases: 2, maxReservedDecodedBytes: 120 * MIB }]) {
    const conflicting = createDiscoveryFrontierStore({ directory: h.directory,
      resolveTenant: () => 'tenant-a', ...(tenantLimits ? { tenantLimits } : {}) });
    try {
      const scope = await conflicting.scopeForAuthenticatedRequest({});
      await assert.rejects(conflicting.getTenantProgress(scope), codeIs('FRONTIER_CONFLICT'));
      await assert.rejects(seed(conflicting, scope, 'must-not-be-created'), codeIs('FRONTIER_CONFLICT'));
    } finally { conflicting.close(); }
  }
  h.store.close();
  const matching = await h.open('tenant-a', { maxReservedDecodedBytes: 100 * MIB, maxInFlightLeases: 2 });
  assert.equal((await matching.store.getTenantProgress(matching.scope)).limits.maxInFlightLeases, 2);
  await assert.rejects(matching.store.getSnapshot(matching.scope, 'must-not-be-created'), codeIs('FRONTIER_NOT_FOUND'));
});

test('different policies racing to bind one tenant cannot both succeed', { timeout: 15_000 }, async (t) => {
  const h = await fixture(t);
  const results = await racedWorkers(t, h, [
    { operation: 'policy', tenantLimits: { maxInFlightLeases: 2 } },
    { operation: 'policy', tenantLimits: { maxInFlightLeases: 3 } },
  ]);
  assert.equal(results.filter(({ error }) => error === 'FRONTIER_CONFLICT').length, 1);
  const winner = results.find(({ result }) => result);
  assert.ok([2, 3].includes(winner.result.limits.maxInFlightLeases));
  const matching = await h.open('tenant-a', winner.result.limits);
  assert.deepEqual(await matching.store.getTenantProgress(matching.scope), winner.result);
});

test('tenant limit validation rejects coercions, accessors and unsafe arithmetic', () => {
  let hooks = 0;
  const coercion = { valueOf() { hooks += 1; return 4; }, toString() { hooks += 1; return '4'; } };
  const accessor = {};
  Object.defineProperty(accessor, 'maxInFlightLeases', { enumerable: true, get() { hooks += 1; return 4; } });
  const values = [null, [], { unknown: 1 }, accessor,
    ...[0, -1, 1.5, NaN, Infinity, 513, Number.MAX_SAFE_INTEGER + 1, '4', 4n, coercion]
      .map((maxInFlightLeases) => ({ maxInFlightLeases })),
    ...[0, 20 * MIB - 1, 128 * 100 * MIB + 1, NaN, Infinity, Number.MAX_SAFE_INTEGER, '20971520', coercion]
      .map((maxReservedDecodedBytes) => ({ maxReservedDecodedBytes })),
  ];
  for (const tenantLimits of values) {
    assert.throws(() => createDiscoveryFrontierStore({ directory: '/tmp/unused-tenant-limit-validation',
      resolveTenant: () => 'synthetic', tenantLimits }), codeIs('FRONTIER_INVALID_INPUT'));
  }
  assert.equal(hooks, 0);
  const maximum = createDiscoveryFrontierStore({ directory: '/tmp/unused-tenant-limit-validation', resolveTenant: () => 'synthetic',
    tenantLimits: { maxInFlightLeases: 128 * 4, maxReservedDecodedBytes: 128 * 100 * MIB } });
  maximum.close();
});

test('aborted admission cannot commit a lease while another SQLite connection holds the lock', { timeout: 10_000 }, async (t) => {
  const h = await fixture(t);
  await seed(h.store, h.scope, 'aborted');
  const before = await h.store.getTenantProgress(h.scope);
  const lock = new DatabaseSync(databasePath(h.directory));
  const controller = new AbortController();
  lock.exec('BEGIN IMMEDIATE');
  const timer = setTimeout(() => controller.abort(), 20);
  try {
    await assert.rejects(h.store.claimNext(h.scope, 'aborted', { workerId: 'aborted', claimKey: 'aborted' }, controller.signal), codeIs('FRONTIER_STOPPED'));
  } finally { clearTimeout(timer); lock.exec('ROLLBACK'); lock.close(); }
  assert.deepEqual(await h.store.getTenantProgress(h.scope), before);
  assert.equal((await h.store.getSnapshot(h.scope, 'aborted')).counters.inFlightLeases, 0);
});

async function pinnedV3(t) {
  const extracted = spawnSync('git', ['show', `${V3_COMMIT}:src/discovery/planner/frontier.mjs`], { cwd: REPO, maxBuffer: 4 * MIB });
  assert.equal(extracted.status, 0, 'the actual pinned v3 source must be available');
  assert.equal(createHash('sha256').update(extracted.stdout).digest('hex'), V3_HASH);
  const location = path.join(REPO, 'src/discovery/planner', `.legacy-tenant-v3-${process.pid}-${randomUUID()}.mjs`);
  await writeFile(location, extracted.stdout, { flag: 'wx', mode: 0o600 });
  t.after(() => rm(location, { force: true }));
  return import(pathToFileURL(location).href);
}

async function pinnedV1(t) {
  const extracted = spawnSync('git', ['show', `${V1_COMMIT}:src/discovery/planner/frontier.mjs`], { cwd: REPO, maxBuffer: 4 * MIB });
  assert.equal(extracted.status, 0, 'the actual pinned v1 source must be available');
  assert.equal(createHash('sha256').update(extracted.stdout).digest('hex'), V1_HASH);
  const location = path.join(REPO, 'src/discovery/planner', `.legacy-tenant-v1-${process.pid}-${randomUUID()}.mjs`);
  await writeFile(location, extracted.stdout, { flag: 'wx', mode: 0o600 });
  t.after(() => rm(location, { force: true }));
  return import(pathToFileURL(location).href);
}

test('a v1 full-run hold denies new raw admissions under a larger tenant policy while preserving replay', async (t) => {
  const h = await fixture(t, { maxReservedDecodedBytes: 120 * MIB });
  const legacyModule = await pinnedV1(t);
  const legacy = legacyModule.createDiscoveryFrontierStore({ directory: h.directory, resolveTenant: () => 'tenant-a', now: () => 1000 });
  t.after(() => legacy.close());
  const scope = await legacy.scopeForAuthenticatedRequest({});
  const claim = await claimRun(legacy, scope, 'v1-unknown');
  const original = attempt(claim, 'historical');
  assert.equal((await legacy.admitAttempt(scope, 'v1-unknown', original)).state, 'admitted');
  const history = await legacy.getSnapshot(scope, 'v1-unknown');
  legacy.close();

  const held = await h.store.getTenantProgress(h.scope);
  assert.equal(held.legacyUnknownRuns, 1);
  assert.equal(held.reservedBytes, 100 * MIB);
  assert.equal(held.availableReservedBytes, 20 * MIB);
  assert.equal((await h.store.admitAttempt(h.scope, 'v1-unknown', original)).state, 'already_admitted');
  assert.equal((await h.store.admitTransportHop(h.scope, 'v1-unknown', attempt(claim, 'tracked', 'historical'))).reason, 'decoded_budget');
  for (let index = 0; index < 7; index += 1) {
    assert.deepEqual(await h.store.admitAttempt(h.scope, 'v1-unknown', attempt(claim, `new-${index}`, 'historical')),
      { state: 'denied', reason: 'decoded_budget' });
  }
  assert.deepEqual(await h.store.getSnapshot(h.scope, 'v1-unknown'), history);
  assert.deepEqual(await h.store.getTenantProgress(h.scope), held);
  await h.store.stopRun(h.scope, 'v1-unknown', 'cancelled');
  h.store.close();
  const restarted = await h.open();
  assert.equal((await restarted.store.admitAttempt(restarted.scope, 'v1-unknown', original)).state, 'already_admitted');
  assert.deepEqual(await restarted.store.getTenantProgress(restarted.scope), held);
  const fresh = await claimRun(restarted.store, restarted.scope, 'fresh-after-v1');
  assert.equal((await restarted.store.admitAttempt(restarted.scope, 'fresh-after-v1', attempt(fresh))).state, 'admitted');
  const full = await restarted.store.getTenantProgress(restarted.scope);
  assert.equal(full.reservedBytes, 120 * MIB);
  assert.equal(full.untrackedAttempts, 1);
  assert.deepEqual(await restarted.store.admitAttempt(restarted.scope, 'fresh-after-v1', attempt(fresh, 'overflow', 'attempt')),
    { state: 'denied', reason: 'tenant_decoded_budget' });
});

for (const matches of [true, false]) {
  test(`concurrent schema migration rechecks a ${matches ? 'matching' : 'mismatched'} policy after lock acquisition`, { timeout: 15_000 }, async (t) => {
    const h = await fixture(t);
    const legacyModule = await pinnedV3(t);
    const legacy = legacyModule.createDiscoveryFrontierStore({ directory: h.directory, resolveTenant: () => 'tenant-a', now: () => 1000 });
    const scope = await legacy.scopeForAuthenticatedRequest({});
    try { await seed(legacy, scope, 'before-migration'); } finally { legacy.close(); }
    const tenantLimits = { maxInFlightLeases: 2 };
    const peerTenantLimits = { maxInFlightLeases: matches ? 2 : 3 };
    const [outcome] = await racedWorkers(t, h, [{ operation: 'policy', tenantLimits, peerTenantLimits }]);
    assert.equal(outcome.peer.result.limits.maxInFlightLeases, peerTenantLimits.maxInFlightLeases);
    if (matches) {
      assert.equal(outcome.error, undefined);
      assert.deepEqual(outcome.result, outcome.peer.result);
    } else {
      assert.equal(outcome.error, 'FRONTIER_CONFLICT');
      assert.equal(outcome.result, undefined);
    }
    const reopened = await h.open('tenant-a', peerTenantLimits);
    assert.deepEqual(await reopened.store.getTenantProgress(reopened.scope), outcome.peer.result);
    assert.equal((await reopened.store.getSnapshot(reopened.scope, 'before-migration')).runId, 'before-migration');
  });
}

function storedRows(database) {
  const tables = database.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'
    AND name NOT IN ('frontier_tenant_policy', 'frontier_write_fence') ORDER BY name`).all();
  return Object.fromEntries(tables.map(({ name }) => {
    assert.match(name, /^frontier_[a-z_]+$/);
    const rows = database.prepare(`SELECT * FROM ${name}`).all().map((row) => JSON.stringify(row)).sort();
    return [name, rows];
  }));
}

test('actual v3 migration retains over-limit history and old writers cannot bypass schema5', async (t) => {
  const h = await fixture(t);
  const legacyModule = await pinnedV3(t);
  const legacy = legacyModule.createDiscoveryFrontierStore({ directory: h.directory, resolveTenant: () => 'tenant-a', now: () => 1000 });
  t.after(() => legacy.close());
  const scope = await legacy.scopeForAuthenticatedRequest({});
  let firstClaim;
  for (let index = 0; index < 6; index += 1) {
    const runId = `legacy-${index}`;
    const claim = await claimRun(legacy, scope, runId);
    if (index === 0) firstClaim = claim;
    await legacy.admitAttempt(scope, runId, attempt(claim));
    if (index % 3 === 1) await legacy.completeCandidate(scope, runId, { leaseToken: claim.leaseToken,
      completionKey: 'legacy-completion', outcome: 'failed', suggestions: [] });
    if (index % 3 === 2) await legacy.markUnresolved(scope, runId, { leaseToken: claim.leaseToken, reason: 'dispatch_state_unknown' });
  }
  let database = new DatabaseSync(databasePath(h.directory));
  const before = storedRows(database);
  assert.equal(database.prepare('PRAGMA user_version').get().user_version, 3);
  database.close();
  const progress = await h.store.getTenantProgress(h.scope);
  assert.equal(progress.inFlightLeases, 6);
  assert.equal(progress.reservedBytes, 120 * MIB);
  assert.equal(progress.untrackedAttempts, 6);
  assert.equal(progress.availableInFlightLeases, 0);
  assert.equal(progress.availableReservedBytes, 0);
  database = new DatabaseSync(databasePath(h.directory));
  assert.equal(database.prepare('PRAGMA user_version').get().user_version, 5);
  assert.deepEqual(storedRows(database), before, 'migration must retain every old row byte-for-byte in its existing columns');
  database.close();
  await assert.rejects(legacy.getSnapshot(scope, 'legacy-0'), (error) => error.code === 'FRONTIER_VERSION');
  assert.equal((await h.store.admitAttempt(h.scope, 'legacy-0', attempt(firstClaim))).state, 'already_admitted');
  assert.deepEqual(await h.store.admitAttempt(h.scope, 'legacy-0', attempt(firstClaim, 'new', 'attempt')),
    { state: 'denied', reason: 'tenant_in_flight_limit' });
  assert.deepEqual(await claimRun(h.store, h.scope, 'post-migration'), { state: 'waiting', reason: 'tenant_in_flight_limit' });
  assert.deepEqual(await h.store.getTenantProgress(h.scope), progress);
});

for (const corruption of ['missing-policy-row', 'missing-policy-table', 'invalid-policy-hash']) {
  test(`schema5 ${corruption} fails closed without rebinding or refunding`, async (t) => {
    const h = await fixture(t);
    const claim = await claimRun(h.store, h.scope, 'corrupt-policy');
    await h.store.admitTransportHop(h.scope, 'corrupt-policy', attempt(claim));
    const database = new DatabaseSync(databasePath(h.directory));
    const before = storedRows(database);
    withPrivilegedFrontierFixtureMutation(database, () => {
      if (corruption === 'missing-policy-row') database.exec('DELETE FROM frontier_tenant_policy');
      if (corruption === 'missing-policy-table') database.exec('DROP TABLE frontier_tenant_policy');
      if (corruption === 'invalid-policy-hash') database.exec("UPDATE frontier_tenant_policy SET policy_hash = 'invalid'");
    });
    database.close();
    await assert.rejects(h.store.getTenantProgress(h.scope), codeIs('FRONTIER_VERSION'));
    const after = new DatabaseSync(databasePath(h.directory));
    assert.deepEqual(storedRows(after), before);
    assert.equal(after.prepare('PRAGMA user_version').get().user_version, 5);
    after.close();
  });
}
