import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import os from 'node:os';
import path from 'node:path';
import { createEvidenceStore, EvidenceStoreError } from '../../src/evidence/store.mjs';

const LOCK_TIMEOUT_MS = 200;
const OVERRUN_MS = 150;
const sleeper = new Int32Array(new SharedArrayBuffer(4));
const tenantId = 'synthetic-lock-deadline';
const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${tenantId}`).digest('hex');
const request = Object.freeze({ principal: Object.freeze({ tenantId }) });

function blockUntil(deadline) {
  while (performance.now() < deadline) {
    Atomics.wait(sleeper, 0, 0, Math.max(1, deadline - performance.now()));
  }
}

async function harness(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ei-lock-deadline-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const databasePath = path.join(directory, tenantHash, 'evidence.sqlite');
  const state = { guard: null, now: null, calls: 0 };
  const options = {
    directory,
    resolveTenant: (authenticated) => authenticated?.principal?.tenantId,
    resolveKey({ tenantId: expected, purpose }) {
      return { keyId: `${purpose}-synthetic-v1`,
        key: createHash('sha256').update(`${expected}:${purpose}:synthetic-lock-deadline`).digest() };
    },
    resolveRetention: ({ nowMs }) => ({ expiresAtMs: nowMs + 60_000,
      policyId: 'synthetic-lock-deadline', policyVersion: '1', accessPolicy: 'tenant_private' }),
    authorizePrivateAccess: ({ tenantId: expected, request: authenticated }) => expected === authenticated?.principal?.tenantId,
    authorizePrivateAccessCurrent(input) {
      if (input.tenantId !== input.request?.principal?.tenantId) return false;
      if (state.guard && ['write_private_run_receipt', 'validate_fact_support'].includes(input.action)) {
        state.calls += 1;
        // The second current hook is the real beforeBegin callback. Earlier
        // encryption/key work and the first hook are outside this lock window.
        if (state.calls === 2) state.guard();
      }
      return true;
    },
    now() {
      state.now?.();
      return Date.now();
    },
    maxRetentionMs: 60_000,
    lockTimeoutMs: LOCK_TIMEOUT_MS,
  };
  const bootstrap = createEvidenceStore({ ...options, lockTimeoutMs: 5_000 });
  const bootstrapScope = await bootstrap.scopeForAuthenticatedRequest(request);
  await bootstrap.integritySnapshot(bootstrapScope);
  const store = createEvidenceStore(options);
  const scope = await store.scopeForAuthenticatedRequest(request);
  const binding = {
    runId: 'lock-deadline-run', configHash: '1'.repeat(64),
    candidate: { candidateId: '2'.repeat(64), canonicalUrl: 'https://synthetic.example.test/lock-deadline',
      depth: 0, seed: true, sourceRefs: [] },
    claim: { claimKey: 'lock-deadline-claim', workerId: 'synthetic-lock-deadline', leaseToken: randomUUID() },
  };
  const completion = { completionKey: 'lock-deadline-completion', outcome: 'failed',
    suggestions: [], limitations: [],
    identity: { entityCandidates: [], occurrenceCandidates: [], transitionLinks: [], unresolvedTransitions: [] } };
  function snapshot() {
    const database = new DatabaseSync(databasePath, { readOnly: true, timeout: 0 });
    try {
      return {
        receipts: database.prepare(`SELECT state, payload_hash, expires_at_ms, updated_at_ms
          FROM private_retrieval_receipts ORDER BY receipt_key`).all().map((row) => ({ ...row })),
        facts: Number(database.prepare("SELECT COUNT(*) AS count FROM sealed_bundles WHERE kind = 'fact'").get().count),
      };
    } finally { database.close(); }
  }
  return { state, store, scope, binding, completion, snapshot,
    begin: (signal) => store.beginPrivateRunReceipt(scope, binding, request, signal),
    finalize: (signal) => store.finalizePrivateRunReceipt(scope,
      { ...binding, completion, selection: { evidence: [], facts: [] } }, request, signal),
    append: (signal) => store.appendFact(scope,
      { field: 'event_timezone', status: 'missing', reason: 'not_observed' }, request, signal),
  };
}

test('on-time receipt begin, completion and replay retain durable behavior', { timeout: 5_000 }, async (t) => {
  const h = await harness(t);
  assert.deepEqual(await h.begin(), { state: 'pending', created: true });
  assert.deepEqual(await h.finalize(), { state: 'complete' });
  assert.deepEqual(await h.begin(), { state: 'complete', created: false });
  const { runId, configHash, candidate } = h.binding;
  const read = await h.store.readPrivateRunReceipt(h.scope, { runId, configHash, candidate }, request);
  assert.equal(read.state, 'complete');
  assert.equal(read.claim.leaseToken, h.binding.claim.leaseToken);
  assert.equal(h.snapshot().receipts.length, 1);
});

for (const action of ['begin', 'finalize', 'append']) {
  test(`${action} refuses a new transaction after its final guard exhausts the original lock window`,
    { timeout: 5_000 }, async (t) => {
      const h = await harness(t);
      if (action === 'finalize') await h.begin();
      const before = h.snapshot();
      let latestDeadline;
      let returnedAt;
      h.state.guard = () => {
        latestDeadline = performance.now() + LOCK_TIMEOUT_MS;
        blockUntil(latestDeadline + OVERRUN_MS);
        returnedAt = performance.now();
      };
      await assert.rejects(h[action](),
        (error) => error instanceof EvidenceStoreError && error.code === 'EVIDENCE_BUSY');
      assert.equal(h.state.calls, 2, 'the final synchronous guard really ran');
      assert.ok(returnedAt >= latestDeadline + OVERRUN_MS,
        'native clocks prove the original window expired, without relying on timer delivery');
      assert.deepEqual(h.snapshot(), before, 'no new receipt, finalization or fact is committed');
      h.state.guard = null;
      if (action === 'append') {
        await h.append();
        assert.equal(h.snapshot().facts, 1, 'the timed-out transaction releases its lock for recovery');
      } else {
        await h[action]();
        assert.equal(h.snapshot().receipts[0].state, action === 'begin' ? 'pending' : 'complete');
      }
    });
}

test('external cancellation observed in a late guard keeps its typed cancellation and no receipt',
  { timeout: 5_000 }, async (t) => {
    const h = await harness(t);
    const controller = new AbortController();
    h.state.guard = () => {
      blockUntil(performance.now() + LOCK_TIMEOUT_MS + OVERRUN_MS);
      controller.abort();
    };
    await assert.rejects(h.begin(controller.signal),
      (error) => error instanceof EvidenceStoreError && error.code === 'EVIDENCE_CANCELLED');
    assert.equal(h.state.calls, 2);
    assert.deepEqual(h.snapshot().receipts, []);
  });

test('a native store-clock callback delay inside BEGIN rolls the receipt back before COMMIT',
  { timeout: 5_000 }, async (t) => {
    const h = await harness(t);
    let latestDeadline;
    let delayed = false;
    h.state.guard = () => {
      latestDeadline = performance.now() + LOCK_TIMEOUT_MS;
      // Leave beforeBegin on time, then delay only the next trusted clock read
      // inside the transaction. The returned wall time remains native Date.now.
      h.state.now = () => {
        h.state.now = null;
        blockUntil(latestDeadline + OVERRUN_MS);
        delayed = true;
      };
    };
    await assert.rejects(h.begin(),
      (error) => error instanceof EvidenceStoreError && error.code === 'EVIDENCE_BUSY');
    assert.equal(h.state.calls, 2);
    assert.equal(delayed, true);
    assert.deepEqual(h.snapshot().receipts, [], 'a transaction that overruns cannot commit its staged row');
    h.state.guard = null;
    assert.deepEqual(await h.begin(), { state: 'pending', created: true });
  });

test('a delayed post-commit microtask does not retroactively fail a committed receipt',
  { timeout: 5_000 }, async (t) => {
    const h = await harness(t);
    let beforeDelay;
    let latestDeadline;
    let resumedAt;
    h.state.guard = () => {
      latestDeadline = performance.now() + LOCK_TIMEOUT_MS;
      queueMicrotask(() => {
        beforeDelay = h.snapshot();
        blockUntil(latestDeadline + OVERRUN_MS);
        resumedAt = performance.now();
      });
    };
    assert.deepEqual(await h.begin(), { state: 'pending', created: true });
    assert.equal(h.state.calls, 2);
    assert.equal(beforeDelay.receipts.length, 1, 'a separate native connection sees the commit before the delay');
    assert.ok(resumedAt >= latestDeadline + OVERRUN_MS);
    assert.deepEqual(h.snapshot(), beforeDelay);
  });

for (const mode of ['normal', 'delayed-schema']) {
  test(`ordinary ${mode} lock preflight observes pending rejection and permits recovery`,
    { timeout: 15_000 }, async (t) => {
      const directory = await mkdtemp(path.join(os.tmpdir(), 'ei-lock-preflight-'));
      t.after(() => rm(directory, { recursive: true, force: true }));
      // A separate strict child makes a missed rejection fatal even when the
      // public API's typed rejection is caught. The one declared SQLite shim
      // delays a real schema get; native clocks, timers and rows are unchanged.
      const script = `
        import assert from 'node:assert/strict';
        import { createHash } from 'node:crypto';
        import { performance } from 'node:perf_hooks';
        import { DatabaseSync } from 'node:sqlite';
        import { createEvidenceStore, EvidenceStoreError } from ${JSON.stringify(new URL('../../src/evidence/store.mjs', import.meta.url).href)};
        const mode = process.argv[1];
        const config = {
          directory: process.argv[2],
          resolveTenant: (request) => request.tenant,
          resolveKey: ({ tenantId, purpose }) => ({ keyId: purpose + '-synthetic',
            key: createHash('sha256').update(tenantId + ':' + purpose).digest() }),
          resolveRetention: ({ nowMs }) => ({ expiresAtMs: nowMs + 60_000,
            policyId: 'synthetic-preflight', policyVersion: '1', accessPolicy: 'tenant_private' }),
        };
        const request = { tenant: 'synthetic-lock-preflight' };
        const bootstrap = createEvidenceStore({ ...config, lockTimeoutMs: 5_000 });
        const baseline = await bootstrap.integritySnapshot(await bootstrap.scopeForAuthenticatedRequest(request));
        const store = createEvidenceStore({ ...config, lockTimeoutMs: ${LOCK_TIMEOUT_MS} });
        const scope = await store.scopeForAuthenticatedRequest(request);
        const originalPrepare = DatabaseSync.prototype.prepare;
        const sleeper = new Int32Array(new SharedArrayBuffer(4));
        const observation = { mode, delayedQueries: 0, delayMs: 0, errorCode: null, completed: false, recovered: false };
        let armed = mode === 'delayed-schema';
        DatabaseSync.prototype.prepare = function (sql, ...rest) {
          const statement = Reflect.apply(originalPrepare, this, [sql, ...rest]);
          if (!armed || !sql.includes('SELECT version FROM evidence_extension_schema')) return statement;
          const get = statement.get;
          return { get(...args) {
            const value = Reflect.apply(get, statement, args);
            armed = false;
            observation.delayedQueries += 1;
            const startedAt = performance.now();
            const until = startedAt + ${LOCK_TIMEOUT_MS + OVERRUN_MS};
            while (performance.now() < until) Atomics.wait(sleeper, 0, 0, Math.max(1, until - performance.now()));
            observation.delayMs = performance.now() - startedAt;
            return value;
          } };
        };
        try {
          const result = await store.integritySnapshot(scope);
          assert.deepEqual(result, baseline);
          observation.completed = true;
        } catch (error) {
          assert.ok(error instanceof EvidenceStoreError);
          observation.errorCode = error.code;
        } finally {
          DatabaseSync.prototype.prepare = originalPrepare;
        }
        await new Promise((resolve) => setImmediate(resolve));
        assert.deepEqual(await store.integritySnapshot(scope), baseline);
        observation.recovered = true;
        console.log(JSON.stringify(observation));
      `;
      const childEnv = { ...process.env };
      delete childEnv.NODE_TEST_CONTEXT;
      const child = spawnSync(process.execPath,
        ['--unhandled-rejections=strict', '--input-type=module', '--eval', script, mode, directory],
        { encoding: 'utf8', env: childEnv, timeout: 10_000 });
      assert.equal(child.error, undefined);
      assert.equal(child.signal, null);
      assert.equal(child.status, 0, child.stderr);
      t.diagnostic(child.stderr.trim());
      const observation = JSON.parse(child.stdout);
      t.diagnostic(JSON.stringify(observation));
      assert.equal(observation.mode, mode);
      assert.equal(observation.recovered, true);
      assert.equal(observation.completed, mode === 'normal');
      assert.equal(observation.errorCode, mode === 'normal' ? null : 'EVIDENCE_BUSY');
      assert.equal(observation.delayedQueries, mode === 'normal' ? 0 : 1);
      if (mode === 'delayed-schema') assert.ok(observation.delayMs >= LOCK_TIMEOUT_MS + OVERRUN_MS);
    });
}
