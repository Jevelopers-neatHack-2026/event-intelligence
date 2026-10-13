import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { CacheRevalidationError } from '../../../src/cache/reuse/revalidation.mjs';
import { getPrivateRevalidationPort } from '../../../src/cache/reuse/store.mjs';
import { createRevalidationContext } from '../../../src/cache/reuse/revalidation-context.mjs';
import { withConditionalFetch } from '../../../src/security/internal/conditional-fetch.mjs';
import { BODY, IDENTITY, PINS, gate, hash, request, revalidationFixture } from './revalidation-support.mjs';

const runFile = promisify(execFile);
const reopenChild = fileURLToPath(new URL('./revalidation-reopen-child.mjs', import.meta.url));
const preflightChild = fileURLToPath(new URL('./revalidation-preflight-child.mjs', import.meta.url));

for (const mode of ['normal', 'abort-deny', 'abort-throw', 'deadline-deny', 'deadline-throw']) {
  test(`strict native child observes the actual authorization Promise on ${mode} preflight`, async () => {
    const { stdout } = await runFile(process.execPath, ['--unhandled-rejections=strict', preflightChild, mode], {
      timeout: 15_000, maxBuffer: 1024 * 1024,
    });
    const result = JSON.parse(stdout);
    assert.equal(result.mode, mode);
    assert.equal(result.nativeTurnsCompleted, true);
    assert.ok(result.callbackEntries >= 1);
    assert.equal(result.financeCalls, 0);
    if (mode === 'normal') {
      assert.equal(result.status, 'completed');
      assert.equal(result.httpStatus, 304);
    } else {
      assert.equal(result.errorCode, mode.startsWith('abort-') ? 'REVALIDATION_CANCELLED' : 'REVALIDATION_DEADLINE');
      assert.equal(result.beforeDispatchUnchanged, true);
      assert.equal(result.reopenedStateUnchanged, true);
      assert.equal(result.recoveryStatus, 'completed');
      assert.equal(result.recoveryHttpStatus, 304);
    }
  });
}

test('stopped preflight observes native Promises without reading a caller then property or adopting arbitrary thenables', async () => {
  const { stdout } = await runFile(process.execPath, ['--unhandled-rejections=strict', preflightChild, 'native-only'], {
    timeout: 15_000, maxBuffer: 1024 * 1024,
  });
  assert.deepEqual(JSON.parse(stdout), { mode: 'native-only', nativeTurnsCompleted: true, thenReads: 0 });
});

test('genuine conditional304 joins retained original evidence to one durable cache observation without Finance completion', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const before = env.snapshot();
  const admission = await env.admit();
  const result = await env.refresh(admission.admissionRef);
  assert.equal(result.status, 'completed');
  assert.equal(result.receipt.httpStatus, 304);
  assert.equal(result.receipt.observationStatus, 'not_modified');
  assert.equal(result.receipt.responseKind, 'not_modified');
  assert.equal(result.usage, 'unknown');
  assert.equal(result.holdDisposition, 'finance_reconciliation_required');
  assert.equal(env.state.financeCalls, 0);
  assert.deepEqual(env.state.phases, ['bind', 'prepare', 'dispatch', 'commit']);
  assert.equal(env.state.requests.length, 2);
  assert.equal(env.state.requests[1].headers['if-none-match'], env.state.etag);
  assert.equal(env.state.requests[1].headers['if-modified-since'], undefined);
  const after = env.snapshot();
  assert.equal(after.observations.length, before.observations.length + 1);
  assert.equal(after.observations.at(-1).id, result.receipt.observationRef);
  assert.equal(after.observations.at(-1).contentHash, hash(BODY));
  assert.equal(after.observations.at(-1).retrievedAtMs, before.observations[0].retrievedAtMs);
  assert.equal(after.observations.at(-1).revalidation.responseRetrievedAt, null);
  assert.deepEqual(after.profile.lineage, before.profile.lineage);
  assert.deepEqual(after.profile.sourceRefs, before.profile.sourceRefs);
  assert.equal(after.flights[0].state, 'active');
  assert.equal(after.flights[0].usage, 'unknown');
  assert.equal(after.flights[0].attemptLineage.status, 'unknown');
  assert.equal(after.outbox, 0);
  const hit = await env.store.getPrivateProfile(env.scope, env.authRequest, env.lookup);
  assert.equal(hit.status, 'hit');
  assert.equal(hit.originalLineageStatus, 'complete');
});

test('a genuine same-body200 records its new retrieval time separately from the original evidence', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  env.state.response = 'same';
  const admission = await env.admit();
  const result = await env.refresh(admission.admissionRef);
  const after = env.snapshot();
  assert.equal(result.status, 'completed');
  assert.equal(result.receipt.responseKind, 'body_unchanged');
  assert.equal(result.receipt.httpStatus, 200);
  assert.equal(after.eligible, 1);
  const original = after.observations[0];
  const current = after.observations.at(-1);
  assert.equal(current.retrievedAtMs, original.retrievedAtMs);
  assert.ok(current.bodyObservedAtMs > original.retrievedAtMs);
  assert.equal(Date.parse(current.revalidation.responseRetrievedAt), current.bodyObservedAtMs);
  assert.equal(current.revalidation.responseBodyHash, hash(BODY));
  assert.equal(current.revalidation.bodyHashDomain, 'safe-fetch-decoded-entity-bytes/v1');
  assert.equal(after.flights[0].attemptLineage.status, 'unknown');
  assert.equal(env.state.financeCalls, 0);
});

test('changed200 atomically invalidates the old profile and leaves an unacknowledged outbox with a replayable local receipt', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  env.state.response = 'changed';
  const admission = await env.admit();
  const result = await env.refresh(admission.admissionRef);
  assert.equal(result.receipt.observationStatus, 'body_changed');
  assert.equal(result.receipt.invalidated, true);
  const after = env.snapshot();
  assert.equal(after.eligible, 0);
  assert.equal(after.sourceBindings, 0, 'invalidation scrubs source URL and validator binding');
  assert.equal(after.outbox, 1);
  assert.equal(after.profile.contentHash, hash(BODY), 'old facts and profile hash are not rewritten');
  assert.equal(after.observations.at(-1).contentHash, hash(`${BODY}Changed source body\n`));
  assert.equal(after.flights[0].state, 'active');
  assert.equal((await env.store.outboxSnapshot(env.scope, env.authRequest)).unresolved, 1);
  await env.reopen();
  const repeated = await env.refresh(admission.admissionRef);
  assert.equal(repeated.status, 'completed');
  assert.equal(repeated.replayed, true);
  assert.equal(repeated.localRefreshId, result.localRefreshId);
  assert.equal(repeated.receipt.observationRef, result.receipt.observationRef);
  assert.equal(env.state.requests.length, 2);
  assert.equal(env.snapshot().observations.length, 2);
  assert.equal(env.state.financeCalls, 0);
});

for (const code of [404, 410, 500, 503]) {
  test(`actual HTTP${code} has a documented local removal/outage result without fabricated retrieval time`, async (t) => {
    const env = await revalidationFixture(t);
    await env.bind();
    env.state.response = String(code);
    const admission = await env.admit();
    const result = await env.refresh(admission.admissionRef);
    const after = env.snapshot();
    const removed = code === 404 || code === 410;
    assert.equal(result.receipt.httpStatus, code);
    assert.equal(result.receipt.observationStatus, removed ? 'removed' : 'outage');
    assert.equal(after.observations.at(-1).retrievedAtMs, after.observations[0].retrievedAtMs);
    assert.equal(after.observations.at(-1).revalidation.responseRetrievedAt, null);
    assert.equal(after.observations.at(-1).bodyObservedAtMs, null);
    assert.equal(after.eligible, removed ? 0 : 1);
    assert.equal(after.outbox, removed ? 1 : 0);
    assert.equal(after.flights[0].state, 'active');
    assert.equal(after.flights[0].usage, 'unknown');
    assert.equal((await env.store.getPrivateProfile(env.scope, env.authRequest, env.lookup)).status, 'unavailable');
    assert.equal(env.state.financeCalls, 0);
  });
}

test('outage recovery requires a new explicit fresh admission and retains the prior failed observation and original source expense', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  env.state.response = '503';
  const first = await env.admit('fresh');
  assert.equal((await env.refresh(first.admissionRef)).receipt.observationStatus, 'outage');
  env.state.response = '304';
  assert.equal((await env.refresh(first.admissionRef)).receipt.observationStatus, 'outage');
  assert.equal(env.state.requests.length, 2, 'same-admission retry does not dispatch');
  const second = await env.admit('fresh');
  assert.equal((await env.refresh(second.admissionRef)).receipt.observationStatus, 'not_modified');
  const after = env.snapshot();
  assert.deepEqual(after.observations.map((observation) => observation.status), ['body_changed', 'outage', 'not_modified']);
  assert.equal(new Set(after.observations.map((observation) => observation.retrievedAtMs)).size, 1);
  assert.equal((await env.store.getPrivateProfile(env.scope, env.authRequest, env.lookup)).status, 'hit');
  assert.equal(after.profile.lineage.billableAttemptId, 'SYNTHETIC_ORIGINAL_EXPENSE');
  assert.equal(after.flights.length, 2);
  assert.equal(after.flights.every((flight) => flight.usage === 'unknown'), true);
  assert.equal(env.state.financeCalls, 0);
});

test('a stale private profile can be revalidated without extending its hard expiry or original retrieval time', async (t) => {
  const env = await revalidationFixture(t, { storeOptions: { defaultFreshnessTtlMs: 1_000 } });
  await env.bind();
  const admission = await env.admit();
  const before = env.snapshot();
  await delay(1_050);
  const stale = await env.store.getPrivateProfile(env.scope, env.authRequest, env.lookup);
  assert.equal(stale.status, 'stale');
  assert.equal(stale.reason, 'ttl_expired');
  await env.refresh(admission.admissionRef);
  const hit = await env.store.getPrivateProfile(env.scope, env.authRequest, env.lookup);
  assert.equal(hit.status, 'hit');
  assert.equal(hit.retrievedAt, env.document.fetchedAt);
  assert.equal(Date.parse(hit.expiresAt), before.profile.retentionPolicy.expiresAtMs);
});

test('a real Last-Modified validator is sent alone and matched against the native304 response', async (t) => {
  const env = await revalidationFixture(t, { initialHeaders: { 'last-modified': 'Sun, 11 Oct 2026 12:00:00 GMT' } });
  env.state.response = '304-date';
  await env.bind();
  const admission = await env.admit();
  const result = await env.refresh(admission.admissionRef);
  assert.equal(result.receipt.httpStatus, 304);
  assert.equal(env.state.requests[1].headers['if-none-match'], undefined);
  assert.equal(env.state.requests[1].headers['if-modified-since'], 'Sun, 11 Oct 2026 12:00:00 GMT');
});

for (const headers of [{}, { etag: '*' }, { etag: ['"one"', '"two"'] }, { etag: `"${'x'.repeat(257)}"` }, { 'last-modified': 'yesterday' }]) {
  test(`initial native validators are unsupported when missing, ambiguous or unbounded: ${JSON.stringify(headers).slice(0, 80)}`, async (t) => {
    const env = await revalidationFixture(t, { initialHeaders: headers });
    await assert.rejects(env.bind(), { code: 'REVALIDATION_PROVENANCE' });
    assert.equal(env.snapshot().sourceBindings, 0);
    assert.equal(env.state.requests.length, 1);
  });
}

for (const response of ['304-missing', '304-duplicate', '304-other', 'redirect', 'abort', '401', '403', 'charset', 'same-other-type']) {
  test(`${response} cannot be converted into positive freshness, removal, or a second dispatch`, async (t) => {
    const env = await revalidationFixture(t);
    await env.bind();
    const admission = await env.admit();
    env.state.response = response;
    await assert.rejects(env.refresh(admission.admissionRef), (error) => typeof error.code === 'string');
    const after = env.snapshot();
    assert.equal(after.observations.length, 1);
    assert.equal(after.eligible, 1);
    assert.equal(after.outbox, 0);
    assert.equal(after.flights[0].state, 'active');
    assert.equal(after.flights[0].localRefresh.state, 'dispatch_intent');
    await env.reopen();
    const repeated = await env.refresh(admission.admissionRef);
    assert.equal(repeated.status, 'unknown');
    assert.equal(repeated.receipt, undefined);
    assert.equal(env.state.requests.length, 2, 'redirect and restart never forward the validator or issue another request');
    assert.equal(env.state.financeCalls, 0);
  });
}

test('copied or byte-mutated original documents cannot mint a source binding', async (t) => {
  const env = await revalidationFixture(t);
  await assert.rejects(env.bind({ document: { ...env.document } }), { code: 'REVALIDATION_PROVENANCE' });
  env.document.bytes[0] ^= 1;
  await assert.rejects(env.bind(), { code: 'REVALIDATION_PROVENANCE' });
  assert.equal(env.state.requests.length, 1);
  assert.equal(env.snapshot().sourceBindings, 0);
});

test('an exact second bind is idempotent, but a different evidence version or extra caller observation is refused', async (t) => {
  const env = await revalidationFixture(t);
  assert.equal((await env.bind()).replayed, false);
  assert.equal((await env.bind()).replayed, true);
  await assert.rejects(env.bind({ evidenceVersion: env.evidence.metadata.version + 1 }), { code: 'REVALIDATION_PROVENANCE' });
  const admission = await env.admit();
  await assert.rejects(env.coordinator.refresh(env.scope, env.authRequest, {
    profileRef: env.profile.profileRef, scopeKind: 'tenant_private', admissionRef: admission.admissionRef,
    observation: { status: 'not_modified', contentHash: hash(BODY) },
  }), { code: 'REVALIDATION_INVALID' });
  assert.equal(env.state.requests.length, 1);
  assert.equal(env.snapshot().sourceBindings, 1);
});

test('a copied native response and an arbitrary response fail the exact intent/provenance join', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admission = await env.admit();
  const context = createRevalidationContext({ timeoutMs: 10_000, request: env.authRequest, readRetainedSource: env.readRetainedSource });
  const port = getPrivateRevalidationPort(env.store, context);
  const prepared = await port.prepare(env.scope, env.authRequest, { profileRef: env.profile.profileRef, scopeKind: 'tenant_private', admissionRef: admission.admissionRef }, context);
  try {
    await port.beforeDispatch(env.scope, env.authRequest, prepared.token, context);
    const native = await withConditionalFetch(env.safeFetcher, prepared.sourceUrl, prepared.validator,
      () => env.safeFetcher.fetch(prepared.sourceUrl), prepared.token);
    const otherIntent = await withConditionalFetch(env.safeFetcher, prepared.sourceUrl, prepared.validator,
      () => env.safeFetcher.fetch(prepared.sourceUrl), Object.freeze({}));
    for (const untrusted of [{ ...native }, { kind: 'not_modified', statusCode: 304 }, {}, otherIntent]) {
      await assert.rejects(port.complete(env.scope, env.authRequest, prepared.token, untrusted, context), { code: 'REVALIDATION_PROVENANCE' });
    }
    assert.equal(env.snapshot().observations.length, 1);
    const actual = await port.complete(env.scope, env.authRequest, prepared.token, native, context);
    assert.equal(actual.status, 'completed');
    await assert.rejects(port.complete(env.scope, env.authRequest, prepared.token, native, context), { code: 'REVALIDATION_PROVENANCE' });
    assert.equal(env.snapshot().observations.length, 2);
  } finally { port.dispose(prepared.token); context.close(); }
});

test('multi-source profiles are refused without inventing an aggregate-to-body hash mapping', async (t) => {
  const env = await revalidationFixture(t, { storeOptions: {
    resolvePrivateProfileReferences: ({ contentHash }) => ({ sourceRefs: ['source-one', 'source-two'], correctionRefs: [],
      permissions: [{ reference: 'SYNTHETIC_PERMISSION', contentHash, version: 1, use: 'cache_read' }] }),
  } });
  await assert.rejects(env.bind(), { code: 'REVALIDATION_UNSUPPORTED' });
  assert.equal(env.state.requests.length, 1);
  assert.equal(env.snapshot().sourceBindings, 0);
});

test('same-hash other profile and mismatched admission identity/pins cannot reuse the source receipt', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admission = await env.admit();
  const other = await env.store.putPrivateProfile(env.scope, env.authRequest, {
    ...env.lookup, identity: { ...IDENTITY, occurrenceId: 'different-occurrence' },
    facts: { event_name: { status: 'sourced', value: 'Other', supportRefs: [env.sourceRef] } }, observation: env.document,
  });
  await assert.rejects(env.coordinator.refresh(env.scope, env.authRequest, {
    profileRef: other.profileRef, scopeKind: 'tenant_private', admissionRef: admission.admissionRef,
  }), { code: 'REVALIDATION_DENIED' });
  await assert.rejects(env.bind({ profileRef: other.profileRef }), { code: 'REVALIDATION_PROVENANCE' });
  const wrongPins = await env.store.admitOperation(env.scope, env.authRequest, { identity: IDENTITY,
    pins: { ...PINS, extractorVersion: 'different-extractor' }, mode: 'fresh' });
  await assert.rejects(env.refresh(wrongPins.admissionRef), { code: 'REVALIDATION_DENIED' });
  assert.equal(env.state.requests.length, 1);
});

test('cross-actor and cross-tenant admission/receipt access is denied before any source dispatch', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admission = await env.admit();
  for (const otherRequest of [request('synthetic-tenant', 'other-actor'), request('other-tenant', 'synthetic-actor')]) {
    const otherScope = await env.store.scopeForAuthenticatedRequest(otherRequest);
    await assert.rejects(env.coordinator.refresh(otherScope, otherRequest, {
      profileRef: env.profile.profileRef, scopeKind: 'tenant_private', admissionRef: admission.admissionRef,
    }), (error) => ['REVALIDATION_DENIED', 'REUSE_NOT_FOUND'].includes(error.code));
  }
  assert.equal(env.state.requests.length, 1);
});

test('two simultaneous reuse callers share one admission, request, observation and unresolved expense', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admissions = await Promise.all([env.admit(), env.admit()]);
  assert.equal(admissions[0].admissionRef, admissions[1].admissionRef);
  const results = await Promise.all(admissions.map((admission) => env.refresh(admission.admissionRef)));
  assert.ok(results.some((result) => result.status === 'completed'));
  assert.equal(new Set(results.map((result) => result.localRefreshId)).size, 1);
  assert.equal(env.state.requests.length, 2);
  assert.equal(env.snapshot().observations.length, 2);
  assert.equal(env.snapshot().flights.length, 1);
  assert.equal(env.snapshot().flights[0].usage, 'unknown');
});

test('separate fresh attempts retain separate unresolved expenses and cannot overwrite a newer observation', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const first = await env.admit('fresh');
  const second = await env.admit('fresh');
  assert.notEqual(first.admissionRef, second.admissionRef);
  const blocked = gate();
  let held = false;
  env.state.phaseHook = async (phase) => {
    if (phase === 'commit' && !held) { held = true; await blocked.wait(); }
  };
  const firstPending = assert.rejects(env.refresh(first.admissionRef), { code: 'REUSE_BUSY' });
  await blocked.reached;
  const secondResult = await env.refresh(second.admissionRef);
  assert.equal(secondResult.status, 'completed');
  blocked.release();
  await firstPending;
  const after = env.snapshot();
  assert.equal(after.observations.length, 2);
  assert.equal(after.flights.length, 2);
  assert.equal(after.flights.every((flight) => flight.state === 'active' && flight.usage === 'unknown'), true);
  assert.deepEqual(after.flights.map((flight) => flight.localRefresh.state).sort(), ['completed', 'dispatch_intent']);
  assert.equal(env.state.requests.length, 3);
  assert.equal(env.state.financeCalls, 0);
});

for (const gateKind of ['retained-source', 'authorization']) {
  test(`cancellation during late ${gateKind} callback cannot commit freshness after the operation returns`, async (t) => {
    const env = await revalidationFixture(t);
    await env.bind();
    const admission = await env.admit();
    const blocked = gate();
    const controller = new AbortController();
    if (gateKind === 'retained-source') env.state.phaseHook = async (phase) => { if (phase === 'commit') await blocked.wait(); };
    else env.state.authHook = async () => { if (env.state.phases.at(-1) === 'commit') await blocked.wait(); };
    const pending = env.refresh(admission.admissionRef, { signal: controller.signal });
    const rejected = assert.rejects(pending, (error) => error instanceof CacheRevalidationError && error.code === 'REVALIDATION_CANCELLED');
    await blocked.reached;
    controller.abort();
    await rejected;
    blocked.release();
    await delay(30);
    assert.equal(env.snapshot().observations.length, 1);
    assert.equal(env.snapshot().flights[0].state, 'active');
    assert.equal(env.snapshot().flights[0].localRefresh.state, 'dispatch_intent');
    env.state.phaseHook = null;
    env.state.authHook = null;
    await env.reopen();
    assert.equal((await env.refresh(admission.admissionRef)).status, 'unknown');
    assert.equal(env.state.requests.length, 2);
  });
}

test('an absolute deadline bounds a stalled retained-evidence callback and blocks its late write', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admission = await env.admit();
  const blocked = gate();
  env.state.phaseHook = async (phase) => { if (phase === 'commit') await blocked.wait(); };
  const coordinator = env.makeCoordinator({ timeoutMs: 500 });
  const rejected = assert.rejects(coordinator.refresh(env.scope, env.authRequest, {
    profileRef: env.profile.profileRef, scopeKind: 'tenant_private', admissionRef: admission.admissionRef,
  }), { code: 'REVALIDATION_DEADLINE' });
  await blocked.reached;
  await rejected;
  blocked.release();
  await delay(30);
  assert.equal(env.snapshot().observations.length, 1);
  assert.equal(env.snapshot().flights[0].usage, 'unknown');
});

test('cancellation at the synchronous final boundary rolls back the observation and local completion together', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admission = await env.admit();
  const controller = new AbortController();
  env.state.boundaryHook = () => { if (env.state.phases.at(-1) === 'commit') controller.abort(); };
  await assert.rejects(env.refresh(admission.admissionRef, { signal: controller.signal }), { code: 'REVALIDATION_CANCELLED' });
  assert.equal(env.snapshot().observations.length, 1);
  assert.equal(env.snapshot().flights[0].localRefresh.state, 'dispatch_intent');
  assert.equal(env.snapshot().outbox, 0);
});

for (const revoked of ['evidence', 'permission', 'principal']) {
  test(`${revoked} loss before the commit boundary prevents the actual HTTP response from freshening cache`, async (t) => {
    const env = await revalidationFixture(t);
    await env.bind();
    const admission = await env.admit();
    env.state.phaseHook = (phase) => {
      if (phase !== 'commit') return;
      if (revoked === 'evidence') env.state.evidenceAvailable = false;
      if (revoked === 'permission') env.state.permission = false;
      if (revoked === 'principal') env.authRequest.principal.actorId = 'new-actor';
    };
    await assert.rejects(env.refresh(admission.admissionRef), (error) => typeof error.code === 'string');
    assert.equal(env.snapshot().observations.length, 1);
    assert.equal(env.snapshot().flights[0].state, 'active');
    assert.equal(env.state.requests.length, 2);
    if (revoked === 'permission') {
      assert.equal(env.snapshot().eligible, 0);
      assert.equal(env.snapshot().sourceBindings, 0);
      assert.equal(env.snapshot().outbox, 1, 'trusted revocation uses the existing durable invalidation queue');
    }
  });
}

test('expiry and rights invalidation scrub the private source binding while unknown admissions retain only minimal replay references', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admission = await env.admit();
  await env.refresh(admission.admissionRef);
  const flight = env.snapshot().flights[0];
  const local = JSON.stringify(flight.localRefresh);
  for (const privateValue of [env.sourceUrl, env.state.etag, env.evidence.metadata.evidenceId, hash(BODY)]) {
    assert.equal(local.includes(privateValue), false);
  }
  await env.store.invalidate(env.scope, env.authRequest, { profileRef: env.profile.profileRef, scopeKind: 'tenant_private', reason: 'rights_revocation' });
  assert.equal(env.snapshot().sourceBindings, 0);
  env.state.offset = 70_000;
  await env.store.purgeExpired(env.scope, env.authRequest);
  const after = env.snapshot();
  assert.equal(after.profile, null);
  assert.equal(after.observations.length, 0);
  assert.equal(after.flights[0].state, 'active');
  assert.equal(after.flights[0].usage, 'unknown');
  const bytes = await env.encryptedBytes();
  for (const privateValue of [env.sourceUrl, env.state.etag, env.evidence.metadata.evidenceId, 'PRIVATE_PERMISSION_CANARY']) {
    assert.equal(bytes.includes(Buffer.from(privateValue)), false);
  }
});

test('source bindings consume the existing global encrypted-byte budget before any new dispatch', async (t) => {
  const env = await revalidationFixture(t);
  const used = env.database((db) => db.prepare(`SELECT
    (SELECT COALESCE(SUM(payload_bytes),0) FROM reuse_entries) +
    (SELECT COALESCE(SUM(length(payload)),0) FROM reuse_observations) +
    (SELECT COALESCE(SUM(length(payload)),0) FROM reuse_consumer_refs) AS bytes`).get().bytes);
  await env.reopen({ maxStoreBytes: used + 2048 + 1 });
  await assert.rejects(env.bind(), { code: 'REUSE_CAPACITY' });
  assert.equal(env.snapshot().sourceBindings, 0);
  assert.equal(env.state.requests.length, 1);
});

test('a reopened store resolves prior payload keys and can revalidate after payload-key rotation', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admission = await env.admit();
  const originalResolver = env.options.resolveKey;
  await env.reopen({ resolveKey: (input) => originalResolver({ ...input,
    ...(input.purpose === 'index' ? { keyId: 'tenant_private:index:1' } : {}) }) });
  env.state.keyVersion = '2';
  const result = await env.refresh(admission.admissionRef);
  assert.equal(result.status, 'completed');
  assert.equal(env.snapshot().flights[0].usage, 'unknown');
  assert.equal(env.state.requests.length, 2);
});

for (const interruption of ['before-socket', 'after-response-loss']) {
  test(`a separate process recovers ${interruption} from the durable admission without redispatch or Finance completion`, async (t) => {
    const env = await revalidationFixture(t);
    await env.bind();
    const admission = await env.admit();
    if (interruption === 'before-socket') {
      const context = createRevalidationContext({ timeoutMs: 10_000, request: env.authRequest, readRetainedSource: env.readRetainedSource });
      const port = getPrivateRevalidationPort(env.store, context);
      const prepared = await port.prepare(env.scope, env.authRequest, { profileRef: env.profile.profileRef,
        scopeKind: 'tenant_private', admissionRef: admission.admissionRef }, context);
      assert.equal(prepared.status, 'dispatch');
      port.dispose(prepared.token);
      context.close(); // Simulated writer loss at the durable pre-socket seam.
    } else {
      env.state.response = 'abort';
      await assert.rejects(env.refresh(admission.admissionRef));
    }
    const result = await runFile(process.execPath, [reopenChild, env.options.directory, env.profile.profileRef, admission.admissionRef], { timeout: 5_000, maxBuffer: 128 * 1024 });
    const recovered = JSON.parse(result.stdout);
    assert.equal(recovered.attemptedNetwork, 0);
    assert.equal(recovered.retainedSourceCalls, 0);
    assert.equal(recovered.result.status, 'unknown');
    assert.equal(recovered.result.usage, 'unknown');
    assert.equal(recovered.result.holdDisposition, 'finance_reconciliation_required');
    assert.equal(env.state.requests.length, interruption === 'before-socket' ? 1 : 2);
    assert.equal(env.snapshot().observations.length, 1);
    assert.equal(env.snapshot().flights[0].state, 'active');
  });
}

test('an already cancelled refresh records no dispatch intent and does not acquire retained source data', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admission = await env.admit();
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(env.refresh(admission.admissionRef, { signal: controller.signal }), { code: 'REVALIDATION_CANCELLED' });
  assert.equal(env.state.requests.length, 1);
  assert.deepEqual(env.state.phases, ['bind']);
  assert.equal(env.snapshot().flights[0].localRefresh, undefined);
});

test('missing final host authority and public-profile requests remain unsupported, with no weaker fallback', async (t) => {
  const env = await revalidationFixture(t);
  await env.reopen({ authorizeBoundary: undefined });
  await assert.rejects(env.bind(), { code: 'REVALIDATION_UNSUPPORTED' });
  await assert.rejects(env.coordinator.bindSource(env.scope, env.authRequest, { ...env.bindInput, scopeKind: 'public_profile' }), { code: 'REVALIDATION_UNSUPPORTED' });
  assert.equal(env.snapshot().sourceBindings, 0);
  assert.equal(env.state.requests.length, 1);
});

test('partial retained bytes, copied binding acknowledgements and source-version mismatches cannot authorize revalidation', async (t) => {
  const env = await revalidationFixture(t);
  for (const change of ['partial-bytes', 'copied-binding', 'version-mismatch']) {
    const coordinator = env.makeCoordinator({ readRetainedSource: async (input) => {
      const retained = await env.readRetainedSource(input);
      if (change === 'partial-bytes') return { ...retained, bytes: retained.bytes.subarray(1) };
      if (change === 'copied-binding') return { ...retained, binding: { ...retained.binding } };
      return { ...retained, binding: { ...retained.binding, evidenceVersion: retained.binding.evidenceVersion + 1 } };
    } });
    await assert.rejects(coordinator.bindSource(env.scope, env.authRequest, env.bindInput), { code: 'REVALIDATION_PROVENANCE' });
  }
  assert.equal(env.state.requests.length, 1);
  assert.equal(env.snapshot().sourceBindings, 0);
});

test('profile-version and encrypted-source-row substitution are refused before dispatch', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admission = await env.admit();
  env.database((db) => db.prepare('UPDATE reuse_entries SET version = version + 1 WHERE entry_id = ?').run(env.profile.profileRef));
  await assert.rejects(env.refresh(admission.admissionRef), { code: 'REVALIDATION_DENIED' });
  env.database((db) => {
    db.prepare('UPDATE reuse_entries SET version = version - 1 WHERE entry_id = ?').run(env.profile.profileRef);
    const row = db.prepare('SELECT payload FROM reuse_refresh_sources WHERE entry_id = ?').get(env.profile.profileRef);
    const damaged = Buffer.from(row.payload);
    damaged[damaged.length - 10] ^= 1;
    db.prepare('UPDATE reuse_refresh_sources SET payload = ? WHERE entry_id = ?').run(damaged, env.profile.profileRef);
  });
  await assert.rejects(env.refresh(admission.admissionRef), { code: 'REUSE_INTEGRITY' });
  assert.equal(env.state.requests.length, 1);
  assert.equal(env.snapshot().observations.length, 1);
});

test('retention expiry at the final synchronous boundary prevents an otherwise valid304 commit', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admission = await env.admit();
  env.state.boundaryHook = () => { if (env.state.phases.at(-1) === 'commit') env.state.offset = 70_000; };
  await assert.rejects(env.refresh(admission.admissionRef), { code: 'REUSE_DENIED' });
  assert.equal(env.snapshot().observations.length, 1);
  assert.equal(env.snapshot().flights[0].localRefresh.state, 'dispatch_intent');
  assert.equal(env.state.requests.length, 2);
});

test('successful transport does not satisfy the existing Finance admission verifier', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admission = await env.admit();
  await env.refresh(admission.admissionRef);
  await assert.rejects(env.store.reconcileAdmission(env.scope, env.authRequest, { admissionRef: admission.admissionRef, outcome: 'completed' }), { code: 'REUSE_POLICY_UNAVAILABLE' });
  assert.equal(env.state.financeCalls, 1);
  assert.equal(env.snapshot().flights[0].state, 'active');
  assert.equal(env.snapshot().flights[0].usage, 'unknown');
});

test('equal-millisecond responses from distinct fresh attempts cannot borrow the prior transport observation', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  // Synthetic clock control forces the real native HTTP responses to share one
  // timestamp; response provenance and both durable admissions remain genuine.
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 2_000 });
  const first = await env.admit('fresh');
  const completed = await env.refresh(first.admissionRef);
  const second = await env.admit('fresh');
  await assert.rejects(env.refresh(second.admissionRef), { code: 'REUSE_BUSY' });
  const after = env.snapshot();
  assert.equal(after.observations.length, 2);
  assert.equal(after.observations.at(-1).revalidation.localRefreshId, completed.localRefreshId);
  assert.equal(after.flights.filter((flight) => flight.localRefresh.state === 'completed').length, 1);
  assert.equal(after.flights.filter((flight) => flight.localRefresh.state === 'dispatch_intent').length, 1);
  const replay = await env.refresh(second.admissionRef);
  assert.equal(replay.status, 'unknown');
  assert.equal(replay.receipt, undefined);
  assert.equal(env.state.requests.length, 3, 'unknown retry never sends a third conditional request');
  assert.equal(after.flights.every((flight) => flight.usage === 'unknown'), true);
  assert.equal(env.state.financeCalls, 0);
});
