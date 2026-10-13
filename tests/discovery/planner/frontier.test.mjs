import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { withPrivilegedFrontierFixtureMutation } from './frontier-fixture-mutation.mjs';
import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createDiscoveryFrontierStore, DiscoveryFrontierError } from '../../../src/discovery/planner/frontier.mjs';

const WORKER = new URL('./frontier-worker.mjs', import.meta.url);
const TRANSPORT_WORKER = new URL('./frontier-transport-worker.mjs', import.meta.url);
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const PINNED_V1_FRONTIER_COMMIT = 'd91e08d666abc243ae456a7f9f1bc9c745ca4f8d';
const PINNED_V1_FRONTIER_SHA256 = '4e6cfbb88e7913984739634a69323c410dbff5ab48128b0ef70eee782de5105e';
const PINNED_V2_FRONTIER_COMMIT = 'd1731173b5ccb6f5212d6e83c71ebd1a8d4ff66f';
const PINNED_V2_FRONTIER_SHA256 = 'eec8f1f675258517d5aff384d7fbb5d1ad755899b6513b003d1c24b2c8d97fed';

function sourceRef(url, evidenceId, contentHash = HASH_A) {
  return {
    evidenceId,
    contentHash,
    locator: { kind: 'json-pointer', pointer: '/links/0/href' },
    field: 'outbound_link',
    value: url,
  };
}

async function harness(t, { clock = { value: Date.UTC(2026, 9, 10) }, tenantId = 'tenant-a', tenantLimits } = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ei-frontier-'));
  const stores = new Set();
  const openStore = () => {
    const store = createDiscoveryFrontierStore({
      directory,
      resolveTenant: (request) => request?.principal?.tenantId,
      now: () => clock.value,
      lockTimeoutMs: 10_000,
      ...(tenantLimits ? { tenantLimits } : {}),
    });
    stores.add(store);
    return store;
  };
  t.after(async () => {
    for (const store of stores) store.close();
    await rm(directory, { recursive: true, force: true });
  });
  const store = openStore();
  const scope = await store.scopeForAuthenticatedRequest({ principal: { tenantId } });
  return { directory, clock, openStore, store, scope, tenantId, tenantLimits };
}

async function seedRun(store, scope, runId, seeds = ['https://events.example.com/root'], limits) {
  return store.createRun(scope, {
    runId,
    seeds: seeds.map((url) => ({ url })),
    ...(limits ? { limits } : {}),
  });
}

async function claimAndAdmit(store, scope, runId, { workerId = 'worker-1', claimKey = 'claim-1', attemptKey = 'attempt-1' } = {}) {
  const claim = await store.claimNext(scope, runId, { workerId, claimKey });
  assert.equal(claim.state, 'claimed');
  const admission = await store.admitAttempt(scope, runId, {
    leaseToken: claim.leaseToken,
    attemptKey,
    kind: 'initial',
    url: claim.candidate.canonicalUrl,
  });
  assert.equal(admission.state, 'admitted');
  return { claim, admission };
}

function codeIs(code) {
  return (error) => error instanceof DiscoveryFrontierError && error.code === code;
}

async function loadPinnedV1Frontier(t) {
  return loadPinnedFrontier(t, PINNED_V1_FRONTIER_COMMIT, PINNED_V1_FRONTIER_SHA256, 'd91');
}

async function loadPinnedV2Frontier(t) {
  return loadPinnedFrontier(t, PINNED_V2_FRONTIER_COMMIT, PINNED_V2_FRONTIER_SHA256, 'd173');
}

async function loadPinnedFrontier(t, commit, sourceHash, name) {
  const sourcePath = 'src/discovery/planner/frontier.mjs';
  const extracted = spawnSync('git', ['show', `${commit}:${sourcePath}`], {
    cwd: REPO_ROOT,
    maxBuffer: 8 * 1024 * 1024,
  });
  assert.equal(extracted.status, 0, `pinned ${name} frontier source must exist at ${commit}`);
  assert.equal(createHash('sha256').update(extracted.stdout).digest('hex'), sourceHash,
    `legacy frontier bytes must match the audited pinned ${name} implementation`);
  const modulePath = path.join(REPO_ROOT, 'src/discovery/planner', `.legacy-${name}-frontier-${process.pid}-${randomUUID()}.mjs`);
  await writeFile(modulePath, extracted.stdout, { flag: 'wx', mode: 0o600 });
  t.after(() => rm(modulePath, { force: true }));
  return import(pathToFileURL(modulePath).href);
}

function runWorker(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [WORKER.pathname, ...args], {
      cwd: path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..'),
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (exitCode) => {
      if (exitCode !== 0) reject(new Error(`worker failed with ${exitCode}: ${stderr.slice(0, 500)}`));
      else {
        try { resolve(JSON.parse(stdout)); } catch { reject(new Error('worker returned invalid result')); }
      }
    });
  });
}

function runTransportWorker(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [TRANSPORT_WORKER.pathname, ...args], {
      cwd: path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..'),
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (exitCode) => {
      if (exitCode !== 0) reject(new Error(`transport worker failed with ${exitCode}: ${stderr.slice(0, 500)}`));
      else {
        try { resolve(JSON.parse(stdout)); } catch { reject(new Error('transport worker returned invalid result')); }
      }
    });
  });
}

test('actual pinned v1 frontier migrates unknown admissions without restoring transport capacity', async (t) => {
  const h = await harness(t);
  h.store.close();
  const legacyModule = await loadPinnedV1Frontier(t);
  const legacy = legacyModule.createDiscoveryFrontierStore({
    directory: h.directory,
    resolveTenant: (request) => request?.principal?.tenantId,
    now: () => h.clock.value,
    lockTimeoutMs: 10_000,
  });
  const legacyScope = await legacy.scopeForAuthenticatedRequest({ principal: { tenantId: h.tenantId } });
  const attemptedInput = { runId: 'legacy-admitted', seeds: [{ url: 'https://events.example.com/legacy-admitted' }] };
  const completedInput = { runId: 'legacy-completed', seeds: [{ url: 'https://events.example.com/legacy-completed' }] };
  const untouchedInput = { runId: 'legacy-untouched', seeds: [{ url: 'https://events.example.com/legacy-untouched' }] };
  await legacy.createRun(legacyScope, attemptedInput);
  await legacy.createRun(legacyScope, completedInput);
  await legacy.createRun(legacyScope, untouchedInput);
  const claim = await legacy.claimNext(legacyScope, attemptedInput.runId, {
    workerId: 'legacy-worker', claimKey: 'legacy-claim',
  });
  assert.equal(claim.state, 'claimed');
  const admission = await legacy.admitAttempt(legacyScope, attemptedInput.runId, {
    leaseToken: claim.leaseToken,
    attemptKey: 'legacy-attempt',
    kind: 'initial',
    url: claim.candidate.canonicalUrl,
  });
  assert.equal(admission.state, 'admitted');
  const beforeAttemptSnapshot = await legacy.getSnapshot(legacyScope, attemptedInput.runId);
  const completedClaim = await legacy.claimNext(legacyScope, completedInput.runId, {
    workerId: 'legacy-worker', claimKey: 'legacy-completed-claim',
  });
  const completedAdmission = await legacy.admitAttempt(legacyScope, completedInput.runId, {
    leaseToken: completedClaim.leaseToken,
    attemptKey: 'legacy-completed-attempt',
    kind: 'initial',
    url: completedClaim.candidate.canonicalUrl,
  });
  assert.equal(completedAdmission.state, 'admitted');
  await legacy.completeCandidate(legacyScope, completedInput.runId, {
    leaseToken: completedClaim.leaseToken,
    completionKey: 'legacy-completed-result',
    outcome: 'no_links',
    suggestions: [],
  });
  const beforeCompletedSnapshot = await legacy.getSnapshot(legacyScope, completedInput.runId);
  const beforeUntouchedSnapshot = await legacy.getSnapshot(legacyScope, untouchedInput.runId);
  legacy.close();

  const current = h.openStore();
  const scope = await current.scopeForAuthenticatedRequest({ principal: { tenantId: h.tenantId } });
  assert.deepEqual(await current.createRun(scope, attemptedInput), beforeAttemptSnapshot);
  assert.deepEqual(await current.createRun(scope, completedInput), beforeCompletedSnapshot);
  assert.deepEqual(await current.createRun(scope, untouchedInput), beforeUntouchedSnapshot);
  assert.deepEqual(await current.getSnapshot(scope, attemptedInput.runId), beforeAttemptSnapshot);
  assert.deepEqual(await current.getSnapshot(scope, completedInput.runId), beforeCompletedSnapshot);
  assert.deepEqual(await current.getSnapshot(scope, untouchedInput.runId), beforeUntouchedSnapshot);
  const legacyClaimBinding = await current.getCandidateReceiptBinding(
    scope, attemptedInput.runId, beforeAttemptSnapshot.candidates[0].candidateId,
  );
  assert.equal(legacyClaimBinding.bindingVersion, 0, 'migrated v1 claims do not receive an inferred observation cutoff');
  assert.equal(legacyClaimBinding.candidate, null);
  assert.deepEqual(legacyClaimBinding.claim, {
    claimKey: 'legacy-claim', workerId: 'legacy-worker', leaseToken: claim.leaseToken,
    candidateId: beforeAttemptSnapshot.candidates[0].candidateId, state: 'leased',
  });
  const legacyCompletedBinding = await current.getCandidateReceiptBinding(
    scope, completedInput.runId, beforeCompletedSnapshot.candidates[0].candidateId,
  );
  assert.equal(legacyCompletedBinding.bindingVersion, 0);
  assert.equal(legacyCompletedBinding.candidate, null);
  assert.deepEqual(legacyCompletedBinding.completion, {
    completionKey: 'legacy-completed-result', outcome: 'no_links',
    payloadHash: createHash('sha256').update(JSON.stringify({
      outcome: 'no_links', suggestions: [], truncatedCount: 0,
    })).digest('hex'),
  });

  const legacyCapacity = await current.getTransportProgress(scope, attemptedInput.runId);
  assert.deepEqual({
    reservedBytes: legacyCapacity.reservedBytes,
    spentBytes: legacyCapacity.spentBytes,
    availableBytes: legacyCapacity.availableBytes,
    legacyUnknownRuns: legacyCapacity.legacyUnknownRuns,
  }, {
    reservedBytes: 100 * 1024 * 1024,
    spentBytes: 0,
    availableBytes: 0,
    legacyUnknownRuns: 1,
  });
  const replay = await current.admitTransportHop(scope, attemptedInput.runId, {
    leaseToken: claim.leaseToken,
    attemptKey: 'legacy-attempt',
    kind: 'initial',
    url: claim.candidate.canonicalUrl,
  });
  assert.equal(replay.state, 'already_admitted_without_transport_state');
  assert.equal(replay.capacity.reservedBytes, 100 * 1024 * 1024);
  assert.deepEqual(await current.sealPrivateDraft(scope, attemptedInput.runId), {
    state: 'denied', reason: 'run_incomplete',
  });
  const completedCapacity = await current.getTransportProgress(scope, completedInput.runId);
  assert.equal(completedCapacity.reservedBytes, 100 * 1024 * 1024);
  assert.equal(completedCapacity.legacyUnknownRuns, 1);
  assert.deepEqual(await current.sealPrivateDraft(scope, completedInput.runId), {
    state: 'denied', reason: 'transport_uncertain',
  });

  const untouchedCapacity = await current.getTransportProgress(scope, untouchedInput.runId);
  assert.equal(untouchedCapacity.legacyUnknownRuns, 0);
  assert.equal(untouchedCapacity.availableBytes, 100 * 1024 * 1024);
  const tenantCapacity = await current.getTenantProgress(scope);
  assert.equal(tenantCapacity.legacyUnknownRuns, 2);
  assert.equal(tenantCapacity.untrackedAttempts, 0, 'v1 admissions are covered by their full-run holds');
  assert.equal(tenantCapacity.reservedBytes, 200 * 1024 * 1024);
  assert.equal(tenantCapacity.availableReservedBytes, 0, 'migration preserves over-limit exposure without refunding it');
  current.close();
  const reopened = h.openStore();
  const reopenedScope = await reopened.scopeForAuthenticatedRequest({ principal: { tenantId: h.tenantId } });
  assert.equal((await reopened.getTransportProgress(reopenedScope, attemptedInput.runId)).reservedBytes, 100 * 1024 * 1024);
  assert.equal((await reopened.getTransportProgress(reopenedScope, completedInput.runId)).reservedBytes, 100 * 1024 * 1024);
  assert.equal((await reopened.getTransportProgress(reopenedScope, untouchedInput.runId)).availableBytes, 100 * 1024 * 1024);
});

test('actual pinned v2 frontier migrates legacy claims without inventing a claim-time prefix', async (t) => {
  const h = await harness(t);
  h.store.close();
  const legacyModule = await loadPinnedV2Frontier(t);
  const legacy = legacyModule.createDiscoveryFrontierStore({
    directory: h.directory,
    resolveTenant: (request) => request?.principal?.tenantId,
    now: () => h.clock.value,
    lockTimeoutMs: 10_000,
  });
  const legacyScope = await legacy.scopeForAuthenticatedRequest({ principal: { tenantId: h.tenantId } });
  const completedInput = { runId: 'legacy-v2-completed', seeds: [{ url: 'https://events.example.com/v2-completed' }] };
  const queuedInput = { runId: 'legacy-v2-queued', seeds: [{ url: 'https://events.example.com/v2-queued' }] };
  await legacy.createRun(legacyScope, completedInput);
  await legacy.createRun(legacyScope, queuedInput);
  const claim = await claimAndAdmit(legacy, legacyScope, completedInput.runId, {
    workerId: 'v2-worker', claimKey: 'v2-complete-claim', attemptKey: 'v2-complete-attempt',
  });
  await legacy.completeCandidate(legacyScope, completedInput.runId, {
    leaseToken: claim.claim.leaseToken, completionKey: 'v2-complete-result', outcome: 'no_links', suggestions: [],
  });
  const beforeCompleted = await legacy.getSnapshot(legacyScope, completedInput.runId);
  const beforeQueued = await legacy.getSnapshot(legacyScope, queuedInput.runId);
  legacy.close();

  const current = h.openStore();
  const scope = await current.scopeForAuthenticatedRequest({ principal: { tenantId: h.tenantId } });
  assert.deepEqual(await current.createRun(scope, completedInput), beforeCompleted);
  assert.deepEqual(await current.createRun(scope, queuedInput), beforeQueued);
  const migrated = await current.getCandidateReceiptBinding(
    scope, completedInput.runId, beforeCompleted.candidates[0].candidateId,
  );
  assert.equal(migrated.bindingVersion, 0);
  assert.equal(migrated.candidate, null);
  assert.deepEqual(migrated.claim, {
    claimKey: 'v2-complete-claim', workerId: 'v2-worker', leaseToken: claim.claim.leaseToken,
    candidateId: beforeCompleted.candidates[0].candidateId, state: 'completed',
  });
  assert.deepEqual(migrated.completion, {
    completionKey: 'v2-complete-result', outcome: 'no_links',
    payloadHash: createHash('sha256').update(JSON.stringify({
      outcome: 'no_links', suggestions: [], truncatedCount: 0,
    })).digest('hex'),
  });
  const fresh = await current.claimNext(scope, queuedInput.runId, {
    workerId: 'v3-worker', claimKey: 'v3-new-claim',
  });
  assert.equal(fresh.state, 'claimed');
  const freshBinding = await current.getCandidateReceiptBinding(scope, queuedInput.runId, fresh.candidate.candidateId);
  assert.equal(freshBinding.bindingVersion, 1);
  assert.equal(freshBinding.candidate.depth, 0);
  assert.deepEqual(freshBinding.candidate.sourceRefs, []);
  assert.equal(freshBinding.candidate.suppliedUrl, queuedInput.seeds[0].url);
});

test('claim receipt binding reconstructs only the immutable observation prefix after later duplicate depth and provenance changes', async (t) => {
  const h = await harness(t);
  const { store, scope } = h;
  const runId = 'claim-binding-prefix-depth';
  const seeds = ['https://events.example.com/root-a', 'https://events.example.com/root-b'];
  await seedRun(store, scope, runId, seeds, { maxDepth: 2, maxTransportAttemptAdmissions: 4, maxInFlightLeases: 4 });
  const target = 'https://events.example.com/target';
  const intermediate = 'https://events.example.com/intermediate';
  const completeWithLink = async (workerId, claimKey, attemptKey, parentUrl, targetUrl, evidenceId) => {
    const claim = await claimAndAdmit(store, scope, runId, { workerId, claimKey, attemptKey });
    return store.completeCandidate(scope, runId, {
      leaseToken: claim.claim.leaseToken,
      completionKey: `${claimKey}-complete`,
      outcome: 'links_observed',
      suggestions: [{ url: targetUrl, sourceRefs: [sourceRef(targetUrl, evidenceId)] }],
    });
  };
  await completeWithLink('root-a-worker', 'root-a-claim', 'root-a-attempt', seeds[0], intermediate, 'evidence-root-a');
  const rootB = await claimAndAdmit(store, scope, runId, {
    workerId: 'root-b-worker', claimKey: 'root-b-claim', attemptKey: 'root-b-attempt',
  });
  const intermediateClaim = await claimAndAdmit(store, scope, runId, {
    workerId: 'intermediate-worker', claimKey: 'intermediate-claim', attemptKey: 'intermediate-attempt',
  });
  await store.completeCandidate(scope, runId, {
    leaseToken: intermediateClaim.claim.leaseToken,
    completionKey: 'intermediate-complete', outcome: 'links_observed',
    suggestions: [{ url: target, sourceRefs: [sourceRef(target, 'evidence-intermediate')] }],
  });
  const targetClaim = await claimAndAdmit(store, scope, runId, {
    workerId: 'target-worker', claimKey: 'target-claim', attemptKey: 'target-attempt',
  });
  assert.equal(targetClaim.claim.candidate.canonicalUrl, target);
  const beforeLaterObservation = await store.getCandidateReceiptBinding(scope, runId, targetClaim.claim.candidate.candidateId);
  assert.equal(beforeLaterObservation.bindingVersion, 1);
  assert.equal(beforeLaterObservation.candidate.depth, 2);
  assert.equal(beforeLaterObservation.candidate.suppliedUrl, target);
  assert.deepEqual(beforeLaterObservation.candidate.sourceRefs.map((item) => item.evidenceId), ['evidence-intermediate']);

  const laterSuppliedUrl = 'https://events.example.com:443/target';
  await store.completeCandidate(scope, runId, {
    leaseToken: rootB.claim.leaseToken,
    completionKey: 'root-b-complete', outcome: 'links_observed',
    suggestions: [{ url: laterSuppliedUrl, sourceRefs: [sourceRef(laterSuppliedUrl, 'evidence-root-b')] }],
  });
  const repeatedClaim = await store.claimNext(scope, runId, {
    workerId: 'target-worker', claimKey: 'target-claim',
  });
  assert.equal(repeatedClaim.state, 'claimed');
  assert.equal(repeatedClaim.replayed, true);
  assert.equal(repeatedClaim.leaseToken, targetClaim.claim.leaseToken);
  assert.equal(repeatedClaim.candidate.depth, 1, 'the current frontier snapshot still reports the later shallower observation');
  assert.deepEqual(await store.getCandidateReceiptBinding(scope, runId, targetClaim.claim.candidate.candidateId),
    beforeLaterObservation, 'an idempotent claim retry does not move its persisted prefix cutoff');
  await store.completeCandidate(scope, runId, {
    leaseToken: targetClaim.claim.leaseToken,
    completionKey: 'target-complete', outcome: 'no_links', suggestions: [],
  });
  const snapshot = await store.getSnapshot(scope, runId);
  const currentTarget = snapshot.candidates.find((item) => item.candidateId === targetClaim.claim.candidate.candidateId);
  assert.equal(currentTarget.depth, 1);
  assert.deepEqual(currentTarget.sourceRefs.map((item) => item.evidenceId), ['evidence-intermediate', 'evidence-root-b']);
  assert.ok(currentTarget.sourceRefs.some((item) => item.value === laterSuppliedUrl));
  const afterLaterObservation = await store.getCandidateReceiptBinding(scope, runId, targetClaim.claim.candidate.candidateId);
  assert.equal(afterLaterObservation.candidate.depth, 2);
  assert.equal(afterLaterObservation.candidate.suppliedUrl, target);
  assert.deepEqual(afterLaterObservation.candidate.sourceRefs.map((item) => item.evidenceId), ['evidence-intermediate']);
  assert.deepEqual(afterLaterObservation.completion, {
    completionKey: 'target-complete', outcome: 'no_links',
    payloadHash: createHash('sha256').update(JSON.stringify({
      outcome: 'no_links', suggestions: [], truncatedCount: 0,
    })).digest('hex'),
  });
  assert.equal(afterLaterObservation.claim.state, 'completed');
  const reopened = h.openStore();
  const reopenedScope = await reopened.scopeForAuthenticatedRequest({ principal: { tenantId: h.tenantId } });
  assert.deepEqual(await reopened.getCandidateReceiptBinding(reopenedScope, runId, targetClaim.claim.candidate.candidateId),
    afterLaterObservation, 'the exact claim-time candidate prefix survives a database reopen');
});

for (const tamper of ['missing-pointer', 'mixed-legacy-marker', 'unknown-version', 'missing-prefix', 'malformed-prefix']) {
  test(`claim receipt binding fails closed on ${tamper}`, async (t) => {
    const h = await harness(t);
    const runId = `claim-binding-${tamper}`;
    await seedRun(h.store, h.scope, runId, ['https://events.example.com/claim-prefix'], {
      maxDepth: 0, maxTransportAttemptAdmissions: 1,
    });
    const claim = await h.store.claimNext(h.scope, runId, { workerId: 'claim-prefix-worker', claimKey: 'claim-prefix' });
    assert.equal(claim.state, 'claimed');
    const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${h.tenantId}`).digest('hex');
    const database = new DatabaseSync(path.join(h.directory, tenantHash, 'frontier.sqlite'));
    try {
      withPrivilegedFrontierFixtureMutation(database, () => {
        if (tamper === 'missing-pointer') {
          database.prepare(`UPDATE frontier_claims SET claim_observation_sequence = NULL
            WHERE tenant_hash = ? AND run_id = ? AND claim_key = ?`).run(tenantHash, runId, 'claim-prefix');
        } else if (tamper === 'mixed-legacy-marker') {
          database.prepare(`UPDATE frontier_claims SET claim_binding_version = 0
            WHERE tenant_hash = ? AND run_id = ? AND claim_key = ?`).run(tenantHash, runId, 'claim-prefix');
        } else if (tamper === 'unknown-version') {
          database.exec('PRAGMA ignore_check_constraints = ON');
          database.prepare(`UPDATE frontier_claims SET claim_binding_version = 9
            WHERE tenant_hash = ? AND run_id = ? AND claim_key = ?`).run(tenantHash, runId, 'claim-prefix');
        } else if (tamper === 'missing-prefix') {
          database.prepare(`DELETE FROM frontier_observations WHERE tenant_hash = ? AND run_id = ? AND sequence = 1`)
            .run(tenantHash, runId);
        } else {
          database.prepare(`UPDATE frontier_observations SET source_refs_json = '{malformed'
            WHERE tenant_hash = ? AND run_id = ? AND sequence = 1`).run(tenantHash, runId);
        }
      });
    } finally {
      database.close();
    }
    await assert.rejects(h.store.getCandidateReceiptBinding(h.scope, runId, claim.candidate.candidateId),
      codeIs('FRONTIER_STORAGE'));
  });
}

test('canonical seed permutations, cycle suppression, duplicate provenance, depth bounds, and stable URL ties', async (t) => {
  const { store, scope } = await harness(t);
  const first = await seedRun(store, scope, 'permutation-a', [
    'https://events.example.com/seed-b', 'https://events.example.com/seed-A',
  ]);
  const second = await seedRun(store, scope, 'permutation-b', [
    'https://events.example.com/seed-A', 'https://events.example.com/seed-b',
  ]);
  const expectedOrder = [
    'https://events.example.com/seed-A',
    'https://events.example.com/seed-b',
  ];
  assert.deepEqual(first.candidates.map(({ canonicalUrl }) => canonicalUrl), expectedOrder);
  assert.deepEqual(second.candidates.map(({ canonicalUrl }) => canonicalUrl), expectedOrder);

  const runId = 'cycle-depth';
  await seedRun(store, scope, runId);
  const root = await claimAndAdmit(store, scope, runId);
  const duplicateTarget = 'https://events.example.com/A';
  let snapshot = await store.completeCandidate(scope, runId, {
    leaseToken: root.claim.leaseToken,
    completionKey: 'root-completion',
    outcome: 'links_observed',
    suggestions: [
      { url: duplicateTarget, label: 'official event', sourceRefs: [sourceRef(duplicateTarget, 'evidence-a')] },
      { url: duplicateTarget, label: 'plausible brand', sourceRefs: [sourceRef(duplicateTarget, 'evidence-b')] },
      { url: 'https://events.example.com/root', sourceRefs: [sourceRef('https://events.example.com/root', 'root-ref', 'c'.repeat(64))] },
      { url: 'https://events.example.com/a', sourceRefs: [sourceRef('https://events.example.com/a', 'evidence-c', HASH_B)] },
    ],
  });
  assert.ok(snapshot.observations.some((item) => item.disposition === 'cycle'));
  assert.equal(snapshot.duplicateContentGroups.length, 1);
  assert.deepEqual(snapshot.duplicateContentGroups[0].evidenceIds, ['evidence-a', 'evidence-b']);
  assert.equal(snapshot.duplicateContentGroups[0].independence, 'unknown');
  assert.equal(snapshot.observations.find((item) => item.untrustedLabel === 'official event').sourceAuthority, 'not_evaluated');
  const uppercaseCandidate = snapshot.candidates.find(({ canonicalUrl }) => canonicalUrl === duplicateTarget);
  assert.equal(uppercaseCandidate.sourceRefs.length, 2);

  let task = await claimAndAdmit(store, scope, runId, { claimKey: 'claim-uppercase', attemptKey: 'attempt-uppercase' });
  assert.equal(task.claim.candidate.canonicalUrl, 'https://events.example.com/A');
  snapshot = await store.completeCandidate(scope, runId, {
    leaseToken: task.claim.leaseToken,
    completionKey: 'uppercase-completion',
    outcome: 'links_observed',
    suggestions: [{ url: 'https://events.example.com/grandchild', sourceRefs: [sourceRef('https://events.example.com/grandchild', 'grandchild-ref')] }],
  });
  task = await claimAndAdmit(store, scope, runId, { claimKey: 'claim-lowercase', attemptKey: 'attempt-lowercase' });
  assert.equal(task.claim.candidate.canonicalUrl, 'https://events.example.com/a');
  await store.completeCandidate(scope, runId, {
    leaseToken: task.claim.leaseToken,
    completionKey: 'lowercase-completion',
    outcome: 'no_links',
    suggestions: [],
  });
  task = await claimAndAdmit(store, scope, runId, { claimKey: 'claim-grandchild', attemptKey: 'attempt-grandchild' });
  assert.equal(task.claim.candidate.canonicalUrl, 'https://events.example.com/grandchild');
  snapshot = await store.completeCandidate(scope, runId, {
    leaseToken: task.claim.leaseToken,
    completionKey: 'grandchild-completion',
    outcome: 'links_observed',
    suggestions: [{ url: 'https://events.example.com/depth-three', sourceRefs: [sourceRef('https://events.example.com/depth-three', 'depth-three-ref')] }],
  });
  const depthLimited = snapshot.candidates.find(({ canonicalUrl }) => canonicalUrl.endsWith('/depth-three'));
  assert.equal(depthLimited.state, 'depth_limited');
  assert.ok(snapshot.observations.some((item) => item.canonicalUrl.endsWith('/depth-three') && item.disposition === 'depth_limit'));
  assert.equal(snapshot.readiness, 'blocked_no_transport_adapter');
});

test('attempt admission counts initial, retries, and redirects exactly once and stops at the durable cap', async (t) => {
  const { store, scope } = await harness(t);
  const runId = 'attempt-caps';
  await seedRun(store, scope, runId, undefined, { maxTransportAttemptAdmissions: 3 });
  const claim = await store.claimNext(scope, runId, { workerId: 'worker-a', claimKey: 'claim-a' });
  const initial = await store.admitAttempt(scope, runId, {
    leaseToken: claim.leaseToken, attemptKey: 'admit-1', kind: 'initial', url: claim.candidate.canonicalUrl,
  });
  assert.equal(initial.sequence, 1);
  assert.equal((await store.admitAttempt(scope, runId, {
    leaseToken: claim.leaseToken, attemptKey: 'admit-1', kind: 'initial', url: claim.candidate.canonicalUrl,
  })).state, 'already_admitted');
  const retry = await store.admitAttempt(scope, runId, {
    leaseToken: claim.leaseToken, attemptKey: 'admit-2', kind: 'retry', previousAttemptKey: 'admit-1',
    url: claim.candidate.canonicalUrl,
  });
  assert.equal(retry.sequence, 2);
  const redirectUrl = 'https://events.example.com/redirected';
  const redirect = await store.admitAttempt(scope, runId, {
    leaseToken: claim.leaseToken, attemptKey: 'admit-3', kind: 'redirect', previousAttemptKey: 'admit-2', url: redirectUrl,
  });
  assert.equal(redirect.sequence, 3);
  assert.equal(redirect.stopAfterThisAdmission, true);
  assert.equal((await store.admitAttempt(scope, runId, {
    leaseToken: claim.leaseToken, attemptKey: 'admit-4', kind: 'redirect', previousAttemptKey: 'admit-3',
    url: 'https://events.example.com/fourth',
  })).state, 'denied');
  const snapshot = await store.getSnapshot(scope, runId);
  assert.equal(snapshot.counters.transportAttemptAdmissions, 3);
  assert.deepEqual(snapshot.attempts.map(({ kind }) => kind), ['initial', 'retry', 'redirect']);
  assert.equal(snapshot.stopReason, 'attempt_limit');
  assert.equal((await store.claimNext(scope, runId, { workerId: 'worker-b', claimKey: 'claim-b' })).state, 'stopped');
  assert.equal(snapshot.usageStatus, 'unknown');
  assert.equal(snapshot.budgetAuthority, 'not_evaluated');
});

test('deadline, absolute counters, and claim keys survive close/reopen without lease redelivery', async (t) => {
  const harnessState = await harness(t, { clock: { value: 20_000 } });
  let { store, scope, clock, openStore } = harnessState;
  const runId = 'resume-same-config';
  const input = { runId, seeds: [{ url: 'https://events.example.com/resume' }], limits: { durationMs: 1_000 } };
  const created = await store.createRun(scope, input);
  const claim = await store.claimNext(scope, runId, { workerId: 'worker-resume', claimKey: 'stable-claim-key' });
  await store.admitAttempt(scope, runId, {
    leaseToken: claim.leaseToken, attemptKey: 'resume-attempt', kind: 'initial', url: claim.candidate.canonicalUrl,
  });
  store.close();
  clock.value = 19_000;
  store = openStore();
  scope = await store.scopeForAuthenticatedRequest({ principal: { tenantId: 'tenant-a' } });
  const reopened = await store.createRun(scope, input);
  assert.equal(reopened.deadlineAtMs, created.deadlineAtMs);
  assert.equal(reopened.counters.transportAttemptAdmissions, 1);
  assert.equal(reopened.counters.inFlightLeases, 1);
  assert.equal(reopened.lastObservedClockMs, 20_000);
  const replay = await store.claimNext(scope, runId, { workerId: 'worker-resume', claimKey: 'stable-claim-key' });
  assert.equal(replay.replayed, true);
  assert.equal(replay.leaseToken, claim.leaseToken);
  assert.equal(replay.candidate.admittedAttemptCount, 1);
  clock.value = created.deadlineAtMs;
  const expired = await store.getSnapshot(scope, runId);
  assert.equal(expired.state, 'halted');
  assert.equal(expired.stopReason, 'deadline');
  assert.equal(expired.counters.transportAttemptAdmissions, 1);
  assert.equal(expired.counters.inFlightLeases, 1);
});

test('the persisted deadline is recorded after the final admission halts on attempt_limit', async (t) => {
  const clock = { value: Date.UTC(2026, 9, 10) };
  const { store, scope } = await harness(t, { clock });
  const runId = 'deadline-after-final-admission';
  await seedRun(store, scope, runId, undefined, {
    maxTransportAttemptAdmissions: 1,
    durationMs: 50,
  });
  const claim = await store.claimNext(scope, runId, { workerId: 'worker-deadline', claimKey: 'claim-deadline' });
  const admission = await store.admitAttempt(scope, runId, {
    leaseToken: claim.leaseToken,
    attemptKey: 'deadline-final-hop',
    kind: 'initial',
    url: claim.candidate.canonicalUrl,
  });
  assert.equal(admission.state, 'admitted');
  assert.equal(admission.stopAfterThisAdmission, true);
  const before = await store.getSnapshot(scope, runId);
  assert.equal(before.stopReason, 'attempt_limit');
  assert.deepEqual(before.stopReasons.map(({ reason }) => reason), ['attempt_limit']);

  clock.value += 50;
  const after = await store.getSnapshot(scope, runId);
  assert.equal(after.stopReason, 'attempt_limit', 'the historical primary stop reason stays stable');
  assert.ok(after.stopReasons.some(({ reason }) => reason === 'deadline'), 'deadline is retained as an independent durable stop event');
  assert.equal((await store.sealPrivateDraft(scope, runId)).state, 'denied');
});

test('unresolved work is durable review state and stale tokens cannot complete or requeue it', async (t) => {
  const { store, scope, openStore } = await harness(t);
  const runId = 'worker-lost';
  await seedRun(store, scope, runId);
  const claim = await claimAndAdmit(store, scope, runId, { claimKey: 'lost-claim', attemptKey: 'lost-attempt' });
  store.close();
  const reopened = openStore();
  const reopenedScope = await reopened.scopeForAuthenticatedRequest({ principal: { tenantId: 'tenant-a' } });
  const unresolved = await reopened.markUnresolved(reopenedScope, runId, {
    leaseToken: claim.claim.leaseToken, reason: 'dispatch_state_unknown',
  });
  assert.equal(unresolved.candidates[0].state, 'unresolved');
  assert.equal(unresolved.state, 'halted');
  assert.equal(unresolved.stopReason, 'unresolved_work');
  assert.equal((await reopened.claimNext(reopenedScope, runId, { workerId: 'worker-new', claimKey: 'new-claim' })).state, 'stopped');
  await assert.rejects(reopened.completeCandidate(reopenedScope, runId, {
    leaseToken: claim.claim.leaseToken, completionKey: 'late-completion', outcome: 'no_links', suggestions: [],
  }), codeIs('FRONTIER_STALE_LEASE'));
  const replayedClaim = await reopened.claimNext(reopenedScope, runId, { workerId: 'worker-1', claimKey: 'lost-claim' });
  assert.equal(replayedClaim.state, 'unresolved');
  assert.equal(replayedClaim.leaseToken, claim.claim.leaseToken);
  assert.equal((await reopened.markUnresolved(reopenedScope, runId, {
    leaseToken: claim.claim.leaseToken, reason: 'dispatch_state_unknown',
  })).candidates[0].state, 'unresolved');
});

test('separate SQLite connections serialize concurrent claims at the configured four-lease cap', async (t) => {
  const { directory, store, scope, clock } = await harness(t);
  const runId = 'process-contention';
  const seeds = Array.from({ length: 10 }, (_, index) => `https://events.example.com/seed-${index}`);
  const snapshot = await seedRun(store, scope, runId, seeds);
  assert.equal(snapshot.candidates.length, 10);
  const results = await Promise.all(Array.from({ length: 8 }, (_, index) => runWorker([
    directory, runId, `process-${index}`, `claim-${index}`, String(clock.value),
  ])));
  const claimed = results.filter(({ state }) => state === 'claimed');
  const waiting = results.filter(({ state, reason }) => state === 'waiting' && reason === 'in_flight_limit');
  assert.equal(claimed.length, 4);
  assert.equal(waiting.length, 4);
  assert.equal(new Set(claimed.map(({ candidate }) => candidate.candidateId)).size, 4);
  assert.equal((await store.getSnapshot(scope, runId)).counters.inFlightLeases, 4);
});

test('cancel and budget denial halt admissions while preserving queued candidates and private refs', async (t) => {
  const { store, scope } = await harness(t);
  const runId = 'budget-cancel';
  await seedRun(store, scope, runId, [
    'https://events.example.com/a', 'https://events.example.com/b',
  ]);
  const claim = await store.claimNext(scope, runId, { workerId: 'worker-a', claimKey: 'cancel-claim' });
  const stopped = await store.stopRun(scope, runId, 'budget_denied');
  assert.equal(stopped.state, 'halted');
  assert.equal(stopped.stopReason, 'budget_denied');
  assert.equal(stopped.candidates.filter(({ state }) => state === 'queued').length, 1);
  assert.equal((await store.admitAttempt(scope, runId, {
    leaseToken: claim.leaseToken, attemptKey: 'after-denial', kind: 'initial', url: claim.candidate.canonicalUrl,
  })).state, 'denied');
  assert.equal((await store.getSnapshot(scope, runId)).counters.transportAttemptAdmissions, 0);

  const cancelRunId = 'cancelled-run';
  await seedRun(store, scope, cancelRunId, [
    'https://events.example.com/cancel-a', 'https://events.example.com/cancel-b',
  ]);
  const cancelClaim = await store.claimNext(scope, cancelRunId, { workerId: 'worker-c', claimKey: 'cancel-claim' });
  const cancelled = await store.stopRun(scope, cancelRunId, 'cancelled');
  assert.equal(cancelled.state, 'halted');
  assert.equal(cancelled.stopReason, 'cancelled');
  assert.equal(cancelled.counters.inFlightLeases, 1);
  assert.equal((await store.admitAttempt(scope, cancelRunId, {
    leaseToken: cancelClaim.leaseToken,
    attemptKey: 'cancelled-attempt',
    kind: 'initial',
    url: cancelClaim.candidate.canonicalUrl,
  })).state, 'denied');
});

test('reported fanout truncation leaves an explicit stop reason and keeps the bounded candidate pool', async (t) => {
  const { store, scope } = await harness(t);
  const runId = 'fanout-truncated';
  await seedRun(store, scope, runId, undefined, { maxSuggestionsPerCompletion: 2 });
  const claim = await claimAndAdmit(store, scope, runId);
  const urlA = 'https://events.example.com/kept-a';
  const urlB = 'https://events.example.com/kept-b';
  const snapshot = await store.completeCandidate(scope, runId, {
    leaseToken: claim.claim.leaseToken,
    completionKey: 'truncated-completion',
    outcome: 'links_observed',
    suggestions: [
      { url: urlA, sourceRefs: [sourceRef(urlA, 'kept-a')] },
      { url: urlB, sourceRefs: [sourceRef(urlB, 'kept-b')] },
    ],
    truncatedCount: 98,
  });
  assert.equal(snapshot.state, 'active');
  assert.equal(snapshot.candidates.length, 3);
  assert.ok(snapshot.stopReasons.some(({ reason }) => reason === 'fanout_limit'));
  assert.equal(snapshot.counters.uniqueCandidates, 3);
});

test('completion hash binds supplied URL spelling, normalized target, label, and sorted multi-source provenance', async (t) => {
  const { store, scope, openStore } = await harness(t);
  const runId = 'completion-hash-normalized-provenance';
  await seedRun(store, scope, runId, undefined, { maxSuggestionsPerCompletion: 1 });
  const { claim } = await claimAndAdmit(store, scope, runId);
  const suppliedUrl = 'https://links.example.org:443/events/../event';
  const canonicalUrl = 'https://links.example.org/event';
  const firstRef = sourceRef(suppliedUrl, 'source-a', HASH_A);
  const secondRef = sourceRef(suppliedUrl, 'source-b', HASH_B);
  const completionKey = 'normalized-provenance-completion';
  await store.completeCandidate(scope, runId, {
    leaseToken: claim.leaseToken,
    completionKey,
    outcome: 'links_observed',
    suggestions: [{
      url: suppliedUrl,
      label: 'Synthetic source label',
      sourceRefs: [secondRef, firstRef],
    }],
  });
  const binding = await store.getCandidateReceiptBinding(scope, runId, claim.candidate.candidateId);
  assert.deepEqual(binding.completion, {
    completionKey,
    outcome: 'links_observed',
    payloadHash: createHash('sha256').update(JSON.stringify({
      outcome: 'links_observed',
      suggestions: [{
        suppliedUrl,
        canonicalUrl,
        label: 'Synthetic source label',
        sourceRefs: [firstRef, secondRef],
      }],
      truncatedCount: 0,
    })).digest('hex'),
  });
  assert.equal(binding.candidate.canonicalUrl, 'https://events.example.com/root');
  const reopened = openStore();
  const reopenedScope = await reopened.scopeForAuthenticatedRequest({ principal: { tenantId: 'tenant-a' } });
  assert.deepEqual(await reopened.getCandidateReceiptBinding(reopenedScope, runId, claim.candidate.candidateId), binding);
});

test('authenticated tenant scopes isolate runs and snapshots are immutable; malformed input never calls getters', async (t) => {
  const { store, scope, tenantId } = await harness(t);
  const snapshot = await seedRun(store, scope, 'private-snapshot');
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.candidates), true);
  assert.equal(Object.isFrozen(snapshot.candidates[0].sourceRefs), true);
  assert.throws(() => { snapshot.candidates[0].canonicalUrl = 'https://attacker.example.com'; }, TypeError);

  let getterCalls = 0;
  const getterSeed = {};
  Object.defineProperty(getterSeed, 'url', { enumerable: true, get() { getterCalls += 1; return 'https://events.example.com/unsafe'; } });
  await assert.rejects(store.createRun(scope, { runId: 'getter-input', seeds: [getterSeed] }), codeIs('FRONTIER_INVALID_INPUT'));
  assert.equal(getterCalls, 0);
  const hostile = new Proxy({}, { ownKeys() { throw new Error('private input trap'); } });
  await assert.rejects(store.createRun(scope, hostile), codeIs('FRONTIER_INVALID_INPUT'));

  const otherScope = await store.scopeForAuthenticatedRequest({ principal: { tenantId: `${tenantId}-other` } });
  await assert.rejects(store.getSnapshot(otherScope, 'private-snapshot'), codeIs('FRONTIER_NOT_FOUND'));
  const secondStore = createDiscoveryFrontierStore({
    directory: path.join(os.tmpdir(), 'separate-unused-frontier-root'),
    resolveTenant: () => 'different-tenant',
  });
  t.after(() => secondStore.close());
  await assert.rejects(secondStore.getSnapshot(scope, 'private-snapshot'), codeIs('FRONTIER_DENIED'));
  await assert.rejects(store.createRun(scope, {
    runId: 'private-address', seeds: [{ url: 'https://127.0.0.1/private' }],
  }), codeIs('FRONTIER_INVALID_INPUT'));
  await assert.rejects(store.createRun(scope, {
    runId: 'userinfo', seeds: [{ url: 'https://user:pass@events.example.com/private' }],
  }), codeIs('FRONTIER_INVALID_INPUT'));
});

test('seed and completion content hashes reject coercion without invoking hooks or changing state', async (t) => {
  const { store, scope } = await harness(t);
  const url = 'https://events.example.com/hash-source';
  const sourceBase = sourceRef(url, 'hash-source');
  let hookCalls = 0;
  const forgedHash = {
    toString() { hookCalls += 1; return HASH_A; },
    toJSON() { hookCalls += 1; return 'forged-non-hash'; },
  };
  const hostilePrimitive = {};
  Object.defineProperty(hostilePrimitive, Symbol.toPrimitive, {
    get() {
      hookCalls += 1;
      throw new Error('PRIVATE_REFERENCE_SENTINEL');
    },
  });
  const hostileSerialization = {
    toString() { hookCalls += 1; return HASH_A; },
  };
  Object.defineProperty(hostileSerialization, 'toJSON', {
    get() {
      hookCalls += 1;
      throw new Error('PRIVATE_REFERENCE_SENTINEL');
    },
  });
  const hostileStringifier = {};
  Object.defineProperty(hostileStringifier, 'toString', {
    get() {
      hookCalls += 1;
      throw new Error('PRIVATE_REFERENCE_SENTINEL');
    },
  });
  const invalidHashes = [
    [HASH_A],
    new String(HASH_A),
    forgedHash,
    Symbol('private'),
    17n,
    hostilePrimitive,
    hostileSerialization,
    hostileStringifier,
  ];
  const sanitizedInputError = (error) => error instanceof DiscoveryFrontierError
    && error.code === 'FRONTIER_INVALID_INPUT'
    && error.message === 'invalid frontier input'
    && error.cause === undefined
    && !String(error).includes('PRIVATE_REFERENCE_SENTINEL');

  for (const [index, contentHash] of invalidHashes.entries()) {
    const runId = `invalid-content-hash-seed-${index}`;
    await assert.rejects(store.createRun(scope, {
      runId,
      seeds: [{ url, sourceRefs: [{ ...sourceBase, contentHash }] }],
    }), sanitizedInputError);
    await assert.rejects(store.getSnapshot(scope, runId), codeIs('FRONTIER_NOT_FOUND'));
  }

  const runId = 'invalid-content-hash-completion';
  await seedRun(store, scope, runId);
  const claim = await store.claimNext(scope, runId, { workerId: 'hash-worker', claimKey: 'hash-claim' });
  await store.admitAttempt(scope, runId, {
    leaseToken: claim.leaseToken,
    attemptKey: 'hash-attempt',
    kind: 'initial',
    url: claim.candidate.canonicalUrl,
  });
  const before = await store.getSnapshot(scope, runId);
  for (const [index, contentHash] of invalidHashes.entries()) {
    const suggestionUrl = `https://events.example.com/hash-link-${index}`;
    await assert.rejects(store.completeCandidate(scope, runId, {
      leaseToken: claim.leaseToken,
      completionKey: `invalid-hash-completion-${index}`,
      outcome: 'links_observed',
      suggestions: [{
        url: suggestionUrl,
        sourceRefs: [{ ...sourceRef(suggestionUrl, `invalid-hash-ref-${index}`), contentHash }],
      }],
    }), sanitizedInputError);
    assert.deepEqual(await store.getSnapshot(scope, runId), before);
  }
  assert.equal(hookCalls, 0);

  const validCompletionUrl = 'https://events.example.com/valid-hash-link';
  const completed = await store.completeCandidate(scope, runId, {
    leaseToken: claim.leaseToken,
    completionKey: 'valid-hash-completion',
    outcome: 'links_observed',
    suggestions: [{
      url: validCompletionUrl,
      sourceRefs: [sourceRef(validCompletionUrl, 'valid-hash-completion-ref', HASH_B)],
    }],
  });
  assert.equal(completed.observations.find(({ suppliedUrl }) => suppliedUrl === validCompletionUrl)
    .sourceRefs[0].contentHash, HASH_B);

  const accepted = await store.createRun(scope, {
    runId: 'valid-content-hash',
    seeds: [{ url, sourceRefs: [sourceBase] }],
  });
  assert.equal(accepted.observations[0].sourceRefs[0].contentHash, HASH_A);
});

test('input, fanout, and URL bounds fail without storing partial observations or leaking values in errors', async (t) => {
  const { store, scope } = await harness(t);
  await assert.rejects(store.createRun(scope, {
    runId: 'too-many-seeds', seeds: Array.from({ length: 11 }, (_, index) => ({ url: `https://events.example.com/${index}` })),
  }), codeIs('FRONTIER_INVALID_INPUT'));
  await assert.rejects(store.createRun(scope, {
    runId: 'oversize-url', seeds: [{ url: `https://events.example.com/${'x'.repeat(8_200)}` }],
  }), (error) => error instanceof DiscoveryFrontierError && !error.message.includes('events.example.com'));

  const runId = 'bounded-fanout';
  await seedRun(store, scope, runId);
  const claim = await claimAndAdmit(store, scope, runId);
  const suggestions = Array.from({ length: 17 }, (_, index) => {
    const url = `https://events.example.com/link-${index}`;
    return { url, sourceRefs: [sourceRef(url, `link-${index}`)] };
  });
  await assert.rejects(store.completeCandidate(scope, runId, {
    leaseToken: claim.claim.leaseToken, completionKey: 'too-many-links', outcome: 'links_observed', suggestions,
  }), codeIs('FRONTIER_INVALID_INPUT'));
  const unchanged = await store.getSnapshot(scope, runId);
  assert.equal(unchanged.candidates.length, 1);
  assert.equal(unchanged.candidates[0].state, 'leased');
});

test('unknown error codes use fixed diagnostics without coercing caller values', () => {
  let hookCalls = 0;
  const hostileCode = {};
  Object.defineProperty(hostileCode, Symbol.toPrimitive, {
    get() {
      hookCalls += 1;
      throw new Error('PRIVATE_REFERENCE_SENTINEL');
    },
  });
  const error = new DiscoveryFrontierError(hostileCode);
  assert.equal(error.code, 'FRONTIER_STORAGE');
  assert.equal(error.message, 'frontier storage operation failed');
  assert.equal(String(error).includes('PRIVATE_REFERENCE_SENTINEL'), false);
  assert.equal(hookCalls, 0);
});

test('no transport or provider is called by the frontier core and source authority stays unknown', async (t) => {
  const { store, scope } = await harness(t);
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = () => { fetchCalls += 1; throw new Error('network must stay outside this core'); };
  try {
    const runId = 'no-dispatch';
    await seedRun(store, scope, runId);
    const claim = await claimAndAdmit(store, scope, runId);
    const url = 'https://organizer.example.com/official';
    const snapshot = await store.completeCandidate(scope, runId, {
      leaseToken: claim.claim.leaseToken,
      completionKey: 'untrusted-link',
      outcome: 'links_observed',
      suggestions: [{ url, label: 'official', sourceRefs: [sourceRef(url, 'unknown-source', HASH_B)] }],
    });
    assert.equal(fetchCalls, 0);
    assert.equal(snapshot.sourceAuthority, 'not_evaluated');
    assert.equal(snapshot.candidates.find((candidate) => candidate.canonicalUrl === url).sourceAuthority, 'not_evaluated');
    assert.equal(snapshot.transportDispatch, 'not_implemented');
    assert.equal(snapshot.readiness, 'blocked_no_transport_adapter');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('credential, session, token, and sensitive fragment URLs are rejected before frontier metadata persistence', async (t) => {
  const { store, scope } = await harness(t);
  const secrets = [
    'https://events.example.com/private?access_token=canary-query-secret',
    'https://events.example.com/private?%61ccess_%74oken=canary-encoded-query-secret',
    'https://events.example.com/private?session_id=canary-session-secret',
    'https://user:canary-password-secret@events.example.com/private',
    'https://events.example.com/private#token=canary-fragment-secret',
    'https://events.example.com/private#access_%74oken=canary-encoded-fragment-secret',
    'https://events.example.com/private#%74oken=canary-encoded-fragment-secret',
    'https://events.example.com/private#%2574oken=canary-double-encoded-fragment-secret',
  ];
  let deeplyEncodedToken = '%74oken';
  for (let index = 0; index < 8; index += 1) deeplyEncodedToken = encodeURIComponent(deeplyEncodedToken);
  assert.notEqual(deeplyEncodedToken, 'token', 'the over-encoded fixture contains real nested percent escapes');
  assert.ok(deeplyEncodedToken.includes('%25'));
  let afterFourDecodes = deeplyEncodedToken;
  for (let index = 0; index < 4; index += 1) afterFourDecodes = decodeURIComponent(afterFourDecodes);
  assert.notEqual(afterFourDecodes, 'token', 'the sensitive name remains encoded beyond the production decoding bound');
  for (let index = 0; index < 8; index += 1) afterFourDecodes = decodeURIComponent(afterFourDecodes);
  assert.equal(afterFourDecodes, 'token', 'the fixture eventually decodes to the sensitive token name');
  secrets.push(`https://events.example.com/private#${deeplyEncodedToken}=canary-overencoded-fragment-secret`);
  for (const [index, url] of secrets.entries()) {
    await assert.rejects(store.createRun(scope, {
      runId: `sensitive-seed-${index}`,
      seeds: [{ url }],
    }), (error) => error instanceof DiscoveryFrontierError && error.code === 'FRONTIER_INVALID_INPUT'
      && !error.message.includes('canary'));
  }
  await assert.rejects(store.getSnapshot(scope, 'sensitive-seed-0'), codeIs('FRONTIER_NOT_FOUND'));
  await assert.rejects(store.createRun(scope, {
    runId: 'sensitive-source-ref-encoded',
    seeds: [{
      url: 'https://events.example.com/private#%74oken=canary-source-ref-secret',
      sourceRefs: [sourceRef('https://events.example.com/private#%74oken=canary-source-ref-secret', 'source-ref', HASH_A)],
    }],
  }), (error) => error instanceof DiscoveryFrontierError && error.code === 'FRONTIER_INVALID_INPUT'
    && !error.message.includes('canary'));
  const accepted = await seedRun(store, scope, 'ordinary-query', ['https://events.example.com/public?day=2026-10-10']);
  assert.equal(accepted.candidates.length, 1);
});

test('transport hop admission reserves before dispatch and crash replay never refunds or redispatches', async (t) => {
  const { store, scope, openStore } = await harness(t);
  await seedRun(store, scope, 'transport-crash');
  const claim = await store.claimNext(scope, 'transport-crash', { workerId: 'worker-crash', claimKey: 'claim-crash' });
  const input = {
    leaseToken: claim.leaseToken,
    attemptKey: 'attempt-crash',
    kind: 'initial',
    url: claim.candidate.canonicalUrl,
  };
  const admission = await store.admitTransportHop(scope, 'transport-crash', input);
  assert.equal(admission.state, 'admitted');
  assert.equal(admission.capacity.reservedBytes, 20 * 1024 * 1024);
  assert.equal(admission.capacity.spentBytes, 0);
  await store.markTransportDispatchIntent(scope, 'transport-crash', { leaseToken: claim.leaseToken, attemptKey: input.attemptKey });
  await store.markTransportResponseReceived(scope, 'transport-crash', { leaseToken: claim.leaseToken, attemptKey: input.attemptKey });
  // Model output produced/consumed just before a crash, before durable EOF settlement.
  store.close();

  const reopened = openStore();
  const reopenedScope = await reopened.scopeForAuthenticatedRequest({ principal: { tenantId: 'tenant-a' } });
  const replay = await reopened.admitTransportHop(reopenedScope, 'transport-crash', input);
  assert.equal(replay.state, 'already_admitted');
  assert.equal(replay.transportState, 'response_received');
  assert.equal(replay.capacity.reservedBytes, 20 * 1024 * 1024);
  assert.equal(replay.capacity.spentBytes, 0);
  const duplicateIntent = await reopened.markTransportDispatchIntent(reopenedScope, 'transport-crash', {
    leaseToken: claim.leaseToken, attemptKey: input.attemptKey,
  });
  assert.equal(duplicateIntent.state, 'unchanged');
  assert.equal(duplicateIntent.transportState, 'response_received');
  const after = await reopened.getTransportProgress(reopenedScope, 'transport-crash');
  assert.equal(after.reservedBytes, 20 * 1024 * 1024);
  assert.equal(after.spentBytes, 0);
});

test('known-zero releases only a no-decode reservation and EOF converts reservation to exact decoded spend', async (t) => {
  const { store, scope } = await harness(t);
  await seedRun(store, scope, 'transport-settlement', [
    'https://events.example.com/a', 'https://events.example.com/b',
  ]);
  let claim = await store.claimNext(scope, 'transport-settlement', { workerId: 'worker-settle', claimKey: 'claim-zero' });
  const zero = await store.admitTransportHop(scope, 'transport-settlement', {
    leaseToken: claim.leaseToken, attemptKey: 'attempt-zero', kind: 'initial', url: claim.candidate.canonicalUrl,
  });
  assert.equal(zero.state, 'admitted');
  await store.settleTransportHopKnownZero(scope, 'transport-settlement', {
    leaseToken: claim.leaseToken, attemptKey: 'attempt-zero',
  });
  let capacity = await store.getTransportProgress(scope, 'transport-settlement');
  assert.equal(capacity.reservedBytes, 0);
  assert.equal(capacity.spentBytes, 0);

  await store.completeCandidate(scope, 'transport-settlement', {
    leaseToken: claim.leaseToken, completionKey: 'complete-zero', outcome: 'failed', suggestions: [],
  });
  claim = await store.claimNext(scope, 'transport-settlement', { workerId: 'worker-settle', claimKey: 'claim-eof' });
  const body = await store.admitTransportHop(scope, 'transport-settlement', {
    leaseToken: claim.leaseToken, attemptKey: 'attempt-eof', kind: 'initial', url: claim.candidate.canonicalUrl,
  });
  assert.equal(body.state, 'admitted');
  await store.markTransportDispatchIntent(scope, 'transport-settlement', {
    leaseToken: claim.leaseToken, attemptKey: 'attempt-eof',
  });
  await store.markTransportResponseReceived(scope, 'transport-settlement', {
    leaseToken: claim.leaseToken, attemptKey: 'attempt-eof',
  });
  await store.settleTransportHopBodyComplete(scope, 'transport-settlement', {
    leaseToken: claim.leaseToken, attemptKey: 'attempt-eof',
  }, 4_096);
  capacity = await store.getTransportProgress(scope, 'transport-settlement');
  assert.equal(capacity.reservedBytes, 0);
  assert.equal(capacity.spentBytes, 4_096);
  assert.equal(capacity.availableBytes, 100 * 1024 * 1024 - 4_096);
});

test('a sealed partial draft preserves queued candidates but permanently denies new claims and transport admissions', async (t) => {
  const { store, scope, openStore } = await harness(t);
  const runId = 'sealed-partial-queued';
  await seedRun(store, scope, runId, [
    'https://events.example.com/a', 'https://events.example.com/b',
  ]);
  const first = await store.claimNext(scope, runId, { workerId: 'worker-seal', claimKey: 'seal-first' });
  assert.equal(first.state, 'claimed');
  const admitted = await store.admitTransportHop(scope, runId, {
    leaseToken: first.leaseToken, attemptKey: 'seal-first-hop', kind: 'initial', url: first.candidate.canonicalUrl,
  });
  assert.equal(admitted.state, 'admitted');
  await store.settleTransportHopKnownZero(scope, runId, {
    leaseToken: first.leaseToken, attemptKey: 'seal-first-hop',
  });
  await store.completeCandidate(scope, runId, {
    leaseToken: first.leaseToken, completionKey: 'seal-first-complete', outcome: 'failed', suggestions: [],
  });

  const beforeSeal = await store.getSnapshot(scope, runId);
  const queued = beforeSeal.candidates.find((candidate) => candidate.state === 'queued');
  assert.ok(queued);
  assert.equal((await store.getTransportProgress(scope, runId)).reservedBytes, 0);
  assert.equal((await store.sealPrivateDraft(scope, runId)).state, 'sealed');

  const postSealClaim = await store.claimNext(scope, runId, {
    workerId: 'worker-seal', claimKey: 'seal-after-release',
  });
  assert.deepEqual(postSealClaim, { state: 'stopped', reason: 'private_draft_sealed' });
  const postSealAdmission = await store.admitTransportHop(scope, runId, {
    leaseToken: 'synthetic-after-seal', attemptKey: 'hop-after-seal', kind: 'initial', url: queued.canonicalUrl,
  });
  assert.equal(postSealAdmission.state, 'denied');
  assert.equal(postSealAdmission.reason, 'private_draft_sealed');
  assert.equal(postSealAdmission.capacity.reservedBytes, 0);

  const afterSeal = await store.getSnapshot(scope, runId);
  assert.equal(afterSeal.candidates.find((candidate) => candidate.candidateId === queued.candidateId).state, 'queued');
  const afterSealCancel = await store.stopRun(scope, runId, 'cancelled');
  assert.equal(afterSealCancel.candidates.find((candidate) => candidate.candidateId === queued.candidateId).state, 'queued');
  assert.equal(afterSealCancel.stopReasons.some((entry) => entry.reason === 'cancelled'), false);

  store.close();
  const reopened = openStore();
  const reopenedScope = await reopened.scopeForAuthenticatedRequest({ principal: { tenantId: 'tenant-a' } });
  assert.deepEqual(await reopened.claimNext(reopenedScope, runId, {
    workerId: 'worker-after-restart', claimKey: 'claim-after-sealed-restart',
  }), { state: 'stopped', reason: 'private_draft_sealed' });
  const reopenedAdmission = await reopened.admitTransportHop(reopenedScope, runId, {
    leaseToken: 'synthetic-after-seal', attemptKey: 'hop-after-seal-restart',
    kind: 'initial', url: queued.canonicalUrl,
  });
  assert.equal(reopenedAdmission.state, 'denied');
  assert.equal(reopenedAdmission.reason, 'private_draft_sealed');
  assert.equal(reopenedAdmission.capacity.reservedBytes, 0);
  const reopenedSnapshot = await reopened.getSnapshot(reopenedScope, runId);
  assert.equal(reopenedSnapshot.candidates.find((candidate) => candidate.candidateId === queued.candidateId).state, 'queued');
});

test('independent SQLite connections cannot overspend the last decoded capacity reservation', async (t) => {
  // Four unresolved transport leases and two racing workers are intentional.
  // This case isolates the original per-run byte limit from the tenant limit.
  const { store, scope, openStore } = await harness(t, { tenantLimits: { maxInFlightLeases: 6 } });
  await seedRun(store, scope, 'transport-capacity-race', [
    'https://events.example.com/a', 'https://events.example.com/b',
    'https://events.example.com/c', 'https://events.example.com/d',
    'https://events.example.com/e', 'https://events.example.com/f',
  ]);
  let sequence = 0;
  const reserveAndComplete = async (claimKey) => {
    const claim = await store.claimNext(scope, 'transport-capacity-race', {
      workerId: 'worker-capacity', claimKey,
    });
    assert.equal(claim.state, 'claimed');
    const attemptKey = `capacity-attempt-${sequence}`;
    sequence += 1;
    const admission = await store.admitTransportHop(scope, 'transport-capacity-race', {
      leaseToken: claim.leaseToken, attemptKey, kind: 'initial', url: claim.candidate.canonicalUrl,
    });
    assert.equal(admission.state, 'admitted');
    await store.completeCandidate(scope, 'transport-capacity-race', {
      leaseToken: claim.leaseToken, completionKey: `capacity-complete-${sequence}`,
      outcome: 'failed', suggestions: [],
    });
  };
  await reserveAndComplete('capacity-claim-0');
  await reserveAndComplete('capacity-claim-1');
  await reserveAndComplete('capacity-claim-2');
  await reserveAndComplete('capacity-claim-3');
  const secondStore = openStore();
  const secondScope = await secondStore.scopeForAuthenticatedRequest({ principal: { tenantId: 'tenant-a' } });
  const [left, right] = await Promise.all([
    store.claimNext(scope, 'transport-capacity-race', { workerId: 'worker-left', claimKey: 'capacity-left' }),
    secondStore.claimNext(secondScope, 'transport-capacity-race', { workerId: 'worker-right', claimKey: 'capacity-right' }),
  ]);
  assert.equal(left.state, 'claimed');
  assert.equal(right.state, 'claimed');
  const [leftResult, rightResult] = await Promise.all([
    store.admitTransportHop(scope, 'transport-capacity-race', {
      leaseToken: left.leaseToken, attemptKey: 'last-left', kind: 'initial', url: left.candidate.canonicalUrl,
    }),
    secondStore.admitTransportHop(secondScope, 'transport-capacity-race', {
      leaseToken: right.leaseToken, attemptKey: 'last-right', kind: 'initial', url: right.candidate.canonicalUrl,
    }),
  ]);
  assert.deepEqual([leftResult.state, rightResult.state].sort(), ['admitted', 'denied']);
  const capacity = await store.getTransportProgress(scope, 'transport-capacity-race');
  assert.equal(capacity.reservedBytes, 100 * 1024 * 1024);
  assert.equal(capacity.spentBytes, 0);
  assert.equal(capacity.availableBytes, 0);
});

test('separate OS processes cannot overspend the last decoded capacity reservation', async (t) => {
  // Match the six-lease synthetic policy in every process from first binding.
  // The original 20 MiB reservations and 100 MiB run bound stay unchanged.
  const { directory, clock, store, scope, tenantLimits } = await harness(t, { tenantLimits: { maxInFlightLeases: 6 } });
  const runId = 'transport-multiprocess-race';
  await seedRun(store, scope, runId, [
    'https://events.example.com/a', 'https://events.example.com/b',
    'https://events.example.com/c', 'https://events.example.com/d',
    'https://events.example.com/e', 'https://events.example.com/f',
  ]);
  for (let index = 0; index < 4; index += 1) {
    const claim = await store.claimNext(scope, runId, { workerId: 'prefill-worker', claimKey: `prefill-${index}` });
    assert.equal(claim.state, 'claimed');
    const attemptKey = `prefill-attempt-${index}`;
    const admission = await store.admitTransportHop(scope, runId, {
      leaseToken: claim.leaseToken, attemptKey, kind: 'initial', url: claim.candidate.canonicalUrl,
    });
    assert.equal(admission.state, 'admitted');
    await store.completeCandidate(scope, runId, {
      leaseToken: claim.leaseToken, completionKey: `prefill-completion-${index}`,
      outcome: 'failed', suggestions: [],
    });
  }
  const left = await store.claimNext(scope, runId, { workerId: 'process-left', claimKey: 'process-left' });
  const right = await store.claimNext(scope, runId, { workerId: 'process-right', claimKey: 'process-right' });
  assert.equal(left.state, 'claimed');
  assert.equal(right.state, 'claimed');
  const barrierDirectory = path.join(directory, 'transport-race-barrier');
  await mkdir(barrierDirectory);
  const leftKey = 'process-last-left';
  const rightKey = 'process-last-right';
  const args = (claim, attemptKey) => [directory, runId, claim.leaseToken, attemptKey,
    claim.candidate.canonicalUrl, String(clock.value), barrierDirectory, JSON.stringify(tenantLimits)];
  const leftPending = runTransportWorker(args(left, leftKey));
  const rightPending = runTransportWorker(args(right, rightKey));
  const waitForReadyWorkers = async () => {
    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline) {
      try {
        await Promise.all([
          access(path.join(barrierDirectory, `${leftKey}.ready`)),
          access(path.join(barrierDirectory, `${rightKey}.ready`)),
        ]);
        return;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    }
    throw new Error('transport worker barrier did not become ready');
  };
  await waitForReadyWorkers();
  await writeFile(path.join(barrierDirectory, 'release'), 'release');
  const [leftResult, rightResult] = await Promise.all([leftPending, rightPending]);
  assert.deepEqual([leftResult.state, rightResult.state].sort(), ['admitted', 'denied']);
  const capacity = await store.getTransportProgress(scope, runId);
  assert.equal(capacity.reservedBytes, 100 * 1024 * 1024);
  assert.equal(capacity.spentBytes, 0);
  assert.equal(capacity.availableBytes, 0);
});
