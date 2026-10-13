import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { access, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { spawn, spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createScopedReuseStore } from '../../../src/cache/reuse/store.mjs';
import { createCorrectionCacheBinding } from '../../../src/review/history/cache-binding.mjs';
import { createCorrectionHistoryStore, ReviewHistoryError } from '../../../src/review/history/store.mjs';

const EPOCH = Date.parse('2026-10-10T15:00:00.000Z');
const EVENT_ID = 'event-binding-001';
const CONTENT_HASH = 'a'.repeat(64);
const IDENTITY = Object.freeze({ occurrenceId: 'occurrence-binding-1', entityId: 'entity-binding-1', editionId: 'edition-binding-1' });
const PINS = Object.freeze({
  schemaVersion: 'profile-schema-1',
  extractorVersion: 'extractor-1',
  questionSetVersion: 'questions-1',
  policyHash: 'b'.repeat(64),
  modelVersion: 'model-1',
});
const TRUSTED_TOKEN = 'binding-test-server-context';

function request(tenantId = 'tenant-binding', actorId = 'actor-binding') {
  return Object.freeze({ principal: Object.freeze({ tenantId, actorId }), serverContextToken: TRUSTED_TOKEN });
}

function sourceEvidence(id, value) {
  return Object.freeze({ evidenceId: id, contentHash: createHash('sha256').update(value).digest('hex') });
}

function initialFacts() {
  return Object.freeze({
    event_name: Object.freeze({ status: 'sourced', value: 'Lantern Night', sourceEvidence: [sourceEvidence('event-name-source', 'Lantern Night')] }),
    event_date: Object.freeze({ status: 'missing' }),
    venue: Object.freeze({ status: 'conflicting', candidates: [
      Object.freeze({ originStatus: 'sourced', value: 'Civic Hall', sourceEvidence: [sourceEvidence('venue-a', 'Civic Hall')] }),
      Object.freeze({ originStatus: 'inferred', value: 'River Room', sourceEvidence: [sourceEvidence('venue-b', 'River Room')] }),
    ] }),
    event_status: Object.freeze({ status: 'sourced', value: 'scheduled', sourceEvidence: [sourceEvidence('event-status-source', 'scheduled')] }),
  });
}

async function fixture(t, options = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ei-correction-cache-binding-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const clock = { value: EPOCH };
  const permits = new WeakSet();
  const createPermit = () => {
    const permit = Object.freeze(Object.create(null));
    permits.add(permit);
    return permit;
  };
  const historyOptions = {
    directory: path.join(root, 'history'),
    resolveTenant: (value) => value?.principal?.tenantId,
    resolveActor: (value) => options.history?.resolveActor
      ? options.history.resolveActor(value) : value?.principal?.actorId,
    authorize({ tenantId, actorId, action, field, request: value }) {
      if (options.history?.authorize) return options.history.authorize({ tenantId, actorId, action, field, request: value });
      return value?.serverContextToken === TRUSTED_TOKEN && value?.principal?.tenantId === tenantId
        && value?.principal?.actorId === actorId && actorId !== 'outsider';
    },
    authorizeBoundary(input) {
      if (options.history?.authorizeBoundary) return options.history.authorizeBoundary(input);
      const allowed = input.request?.serverContextToken === TRUSTED_TOKEN
        && input.request?.principal?.tenantId === input.tenantId
        && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
      return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
        eventId: input.eventId, action: input.action, field: input.field, nowMs: clock.value }) : false;
    },
    resolveKey({ tenantId, purpose, keyId }) {
      const resolvedId = `${purpose}-v1`;
      if (keyId && keyId !== resolvedId) throw new Error('synthetic history key unavailable');
      return { keyId: resolvedId, key: createHash('sha256').update(`${tenantId}:${purpose}:history-test-key`).digest() };
    },
    resolveRetention({ tenantId, nowMs, sourceExpiresAtMs, retentionHandle }) {
      if (options.history?.resolveRetention) return options.history.resolveRetention({ tenantId, nowMs, sourceExpiresAtMs, retentionHandle });
      if (!['tenant-binding', 'tenant-other'].includes(tenantId) || !permits.has(retentionHandle)) throw new Error('synthetic history retention denied');
      return { expiresAtMs: Math.min(nowMs + 60_000, sourceExpiresAtMs ?? Number.MAX_SAFE_INTEGER),
        policyId: 'synthetic-history-retention', policyVersion: '1', accessPolicy: 'tenant_private' };
    },
    lockedFields: ['event_status'],
    now: options.history?.now ?? (() => clock.value),
  };
  const cacheOptions = {
    directory: path.join(root, 'cache'),
    now: () => clock.value,
    resolveTenant: (value) => value?.principal?.tenantId,
    resolveActor: (value) => value?.principal?.actorId,
    authorizeAction({ tenantId, actorId, request: value }) {
      return value?.serverContextToken === TRUSTED_TOKEN && value?.principal?.tenantId === tenantId
        && value?.principal?.actorId === actorId && actorId !== 'outsider';
    },
    authorizeCurrentRequest({ expectedTenantId, expectedActorId, request: value }) {
      return value?.serverContextToken === TRUSTED_TOKEN && value?.principal?.tenantId === expectedTenantId
        && value?.principal?.actorId === expectedActorId && expectedActorId !== 'outsider';
    },
    authorizeBoundary(input) {
      if (options.cache?.authorizeBoundary) return options.cache.authorizeBoundary(input);
      const allowed = input.request?.serverContextToken === TRUSTED_TOKEN
        && input.request?.principal?.tenantId === input.tenantId
        && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
      return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
        eventId: input.eventId, action: input.action, field: input.field, nowMs: clock.value }) : false;
    },
    resolveKey({ tenantId, scope, purpose, keyId }) {
      const resolvedId = `${scope}:${purpose}:${tenantId ?? 'global'}:v1`;
      if (keyId && keyId !== resolvedId) throw new Error('synthetic cache key unavailable');
      return { keyId: resolvedId, key: createHash('sha256').update(`${tenantId}:${scope}:${purpose}:cache-test-key`).digest() };
    },
    resolveRetention({ nowMs, requestedExpiryMs }) {
      return { expiresAtMs: Math.min(nowMs + 60_000, requestedExpiryMs ?? Number.MAX_SAFE_INTEGER),
        policyId: 'synthetic-cache-retention', policyVersion: '1' };
    },
    verifySourceObservation({ expectedContentHash, purpose, observation }) {
      return { status: 'body_changed', contentHash: expectedContentHash,
        retrievedAt: new Date(clock.value - 1_000).toISOString(), validatedAt: new Date(clock.value).toISOString(),
        attemptLineage: { status: 'unknown' } };
    },
    resolvePrivateProfileReferences({ contentHash }) {
      return { permissions: [{ reference: 'synthetic-private-permission', contentHash, version: 1, use: 'cache_read' }],
        sourceRefs: ['private-source-reference'], correctionRefs: ['private-correction-reference'] };
    },
    verifyPermission({ reference, contentHash, version, use }) {
      return { status: 'valid', reference, contentHash, version, use, validUntilMs: EPOCH + 60_000 };
    },
    resolveLineage: () => ({ status: 'unknown' }),
    resolveInvalidationConsumers: () => ['private-consumer-binding-test'],
    deliverInvalidation: async (event) => event,
    verifyInvalidationAcknowledgement: () => false,
    ...options.cache,
  };
  const authorizeBoundary = options.authorizeBoundary ?? ((input) => input.tenantId === 'tenant-binding'
    && input.request?.serverContextToken === TRUSTED_TOKEN && input.actorId !== 'outsider'
    ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
      eventId: input.eventId, action: input.action, field: input.field, nowMs: clock.value }) : false);
  const makeStore = (timeoutMs = options.operationTimeoutMs) => createCorrectionCacheBinding({ history: historyOptions, cache: cacheOptions,
    authorizeBoundary, operationTimeoutMs: timeoutMs });
  const store = makeStore();
  const authRequest = request();
  const scope = await store.scopeForAuthenticatedRequest(authRequest);
  return { root, clock, createPermit, makeStore, store, authRequest, scope, historyOptions, cacheOptions };
}

async function createSeed(f) {
  return f.store.createHistory(f.scope, { eventId: EVENT_ID, sourceFacts: initialFacts(),
    idempotencyKey: 'initialize-binding-event', retentionHandle: f.createPermit() }, f.authRequest);
}

function cacheProfile(options = {}) {
  return Object.freeze({
    identity: options.identity ?? IDENTITY,
    contentHash: options.contentHash ?? CONTENT_HASH,
    pins: PINS,
    facts: Object.freeze({ event_name: Object.freeze({ status: 'sourced', value: 'ignored input' }) }),
    observation: Object.freeze({ source: 'synthetic local observation' }),
    freshnessTtlMs: options.freshnessTtlMs ?? 30_000,
    expiresAtMs: options.expiresAtMs ?? EPOCH + 45_000,
  });
}

function lookup(options = {}) {
  return Object.freeze({ identity: options.identity ?? IDENTITY, contentHash: options.contentHash ?? CONTENT_HASH, pins: options.pins ?? PINS });
}

async function historyStoreFor(f, requestValue = f.authRequest) {
  const history = createCorrectionHistoryStore(f.historyOptions);
  const scope = await history.scopeForAuthenticatedRequest(requestValue);
  return { history, scope };
}

function runWorker(args) {
  const workerPath = path.resolve('tests/integration/review-cache-binding/worker.mjs');
  const child = spawn(process.execPath, [workerPath, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
  child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
  const exit = new Promise((resolve) => child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr })));
  return { child, exit };
}

function runWorkerSync(args) {
  const workerPath = path.resolve('tests/integration/review-cache-binding/worker.mjs');
  return spawnSync(process.execPath, [workerPath, ...args], {
    encoding: 'utf8',
    timeout: 5_000,
  });
}

async function waitForFile(filePath, timeoutMs = 5_000) {
  const endAt = Date.now() + timeoutMs;
  while (Date.now() < endAt) {
    try { await access(filePath); return; } catch (error) { if (error?.code !== 'ENOENT') throw error; }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('worker did not reach its synchronization point');
}

function historyDatabasePath(root) {
  const tenantHash = createHash('sha256').update('event-intelligence:review-tenant:v1:tenant-binding').digest('hex');
  return path.join(root, 'history', tenantHash, 'history.sqlite');
}

function cacheDatabasePath(root) {
  return path.join(root, 'cache', 'scoped-reuse.sqlite');
}

function boundCacheRows(root) {
  const database = new DatabaseSync(cacheDatabasePath(root));
  try {
    const read = (table, order = 'rowid') => database.prepare(`SELECT * FROM ${table} ORDER BY ${order}`).all();
    return Object.freeze({
      entries: read('reuse_entries'),
      writes: read('reuse_bound_writes'),
      reservations: read('reuse_correction_reservations'),
      consumers: read('reuse_consumer_refs', 'entry_id, consumer_hash'),
      observations: read('reuse_observations', 'entry_id, sequence'),
      outbox: read('reuse_outbox'),
    });
  } finally { database.close(); }
}

function assertNoPendingBinding(root) {
  const database = new DatabaseSync(historyDatabasePath(root));
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM correction_cache_state WHERE phase != 'complete'").get().count, 0);
    assert.equal(database.prepare('SELECT COUNT(*) AS count FROM correction_cache_operations').get().count, 0);
  } finally { database.close(); }
}

async function waitForSignal(signal, label, timeoutMs = 3_000) {
  let timer;
  try {
    await Promise.race([
      signal,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`timed out waiting for ${label}`)), timeoutMs);
      }),
    ]);
  } finally { clearTimeout(timer); }
}

async function awaitWithTimeout(value, label, timeoutMs = 4_000) {
  let timer;
  try {
    return await Promise.race([
      value,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`timed out waiting for ${label}`)), timeoutMs); }),
    ]);
  } finally { clearTimeout(timer); }
}

async function withPhase(label, operation) {
  try { return await operation; }
  catch (error) { throw new Error(`${label}: ${error?.code ?? error?.message ?? error}`, { cause: error }); }
}

function interceptFinalBoundRead(onEntry) {
  const descriptor = Object.getOwnPropertyDescriptor(DatabaseSync.prototype, 'prepare');
  let reached = false;
  let restored = false;
  Object.defineProperty(DatabaseSync.prototype, 'prepare', {
    ...descriptor,
    value(sql, ...args) {
      if (!reached && String(sql).includes('SELECT * FROM reuse_entries WHERE entry_id')
        && new Error().stack.includes('finalBoundRead')) {
        reached = true;
        onEntry();
      }
      return Reflect.apply(descriptor.value, this, [sql, ...args]);
    },
  });
  return Object.freeze({
    reached: () => reached,
    restore() {
      if (restored) return;
      restored = true;
      Object.defineProperty(DatabaseSync.prototype, 'prepare', descriptor);
    },
  });
}

function interceptHistoryDisclosureGuard(onEntry, shouldIntercept = () => true) {
  const descriptor = Object.getOwnPropertyDescriptor(DatabaseSync.prototype, 'prepare');
  let reached = false;
  let restored = false;
  Object.defineProperty(DatabaseSync.prototype, 'prepare', {
    ...descriptor,
    value(sql, ...args) {
      if (!reached && shouldIntercept() && String(sql).includes('SELECT phase, operation_id, fence FROM correction_cache_state WHERE event_key = ?')
        && new Error().stack.includes('guardHistoryDisclosure')) {
        reached = true;
        onEntry();
      }
      return Reflect.apply(descriptor.value, this, [sql, ...args]);
    },
  });
  return Object.freeze({
    reached: () => reached,
    restore() {
      if (restored) return;
      restored = true;
      Object.defineProperty(DatabaseSync.prototype, 'prepare', descriptor);
    },
  });
}

test('composed correction binds exact history provenance, invalidates cache locally, and keeps ACK status separate', async (t) => {
  const f = await fixture(t);
  const seeded = await createSeed(f);
  const bound = await f.store.bindPrivateProfile(f.scope, EVENT_ID, {
    idempotencyKey: 'bind-profile-1', profile: cacheProfile(),
  }, f.authRequest);
  assert.equal(bound.status, 'bound');
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup())).status, 'hit');

  const revised = await f.store.applyCorrection(f.scope, {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-20' },
    idempotencyKey: 'correct-date-1',
    retentionHandle: f.createPermit(),
  }, f.authRequest);
  assert.equal(revised.snapshot.revision, seeded.snapshot.revision + 1);
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup())).status, 'miss');
  const pending = await f.store.outboxSnapshot(f.scope, f.authRequest);
  assert.equal(pending.readiness, 'blocked_pending_external_ack');
  assert.equal(pending.pending > 0, true);
  const dispatched = await f.store.dispatchPendingInvalidations(f.scope, f.authRequest);
  assert.equal(dispatched.delivered, 0);
  assert.equal(dispatched.pending, true);
  const afterUnverifiedAck = await f.store.outboxSnapshot(f.scope, f.authRequest);
  assert.equal(afterUnverifiedAck.pending, pending.pending);
  assert.equal(afterUnverifiedAck.readiness, 'blocked_pending_external_ack');

  await assert.rejects(f.store.getPrivateProfile(f.scope, EVENT_ID, request('tenant-other', 'actor-binding'), lookup()),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_DENIED');
  await assert.rejects(f.store.getPrivateProfile(f.scope, EVENT_ID, request('tenant-binding', 'outsider'), lookup()),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_DENIED');
});

test('bind preflight honors the exact history expiry without extending earlier cache retention', async (t) => {
  const cases = [
    {
      name: 'profile expiry omitted',
      profile() {
        const { expiresAtMs, ...withoutExpiry } = cacheProfile();
        void expiresAtMs;
        return withoutExpiry;
      },
      requestedExpiryMs: EPOCH + 60_000,
      expectedExpiryMs: EPOCH + 60_000,
    },
    {
      name: 'profile expiry later than history',
      profile: () => cacheProfile({ expiresAtMs: EPOCH + 120_000 }),
      requestedExpiryMs: EPOCH + 60_000,
      expectedExpiryMs: EPOCH + 60_000,
    },
    {
      name: 'profile expiry earlier than history',
      profile: () => cacheProfile({ expiresAtMs: EPOCH + 45_000 }),
      requestedExpiryMs: EPOCH + 45_000,
      expectedExpiryMs: EPOCH + 45_000,
    },
  ];
  for (const scenario of cases) {
    await t.test(scenario.name, async (subtest) => {
      const requestedExpiries = [];
      const f = await fixture(subtest, { cache: {
        resolveRetention({ nowMs, requestedExpiryMs }) {
          requestedExpiries.push(requestedExpiryMs);
          return { expiresAtMs: Math.min(nowMs + 180_000, requestedExpiryMs ?? Number.MAX_SAFE_INTEGER),
            policyId: 'synthetic-long-cache-retention', policyVersion: '1' };
        },
      } });
      const seeded = await createSeed(f);
      const bound = await f.store.bindPrivateProfile(f.scope, EVENT_ID,
        { idempotencyKey: `bind-expiry-${scenario.name.replaceAll(' ', '-')}`, profile: scenario.profile() }, f.authRequest);
      assert.equal(bound.status, 'bound');
      assert.equal(bound.historyVersionId, seeded.snapshot.versionId);
      assert.equal(Date.parse(bound.expiresAt), scenario.expectedExpiryMs);
      assert.deepEqual(requestedExpiries, [scenario.requestedExpiryMs]);
      assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).versionId, seeded.snapshot.versionId);

      const cache = new DatabaseSync(cacheDatabasePath(f.root));
      const history = new DatabaseSync(historyDatabasePath(f.root));
      try {
        const entry = cache.prepare(`SELECT expires_at_ms, eligible FROM reuse_entries
          WHERE scope_kind = 'tenant_private'`).get();
        assert.equal(entry.expires_at_ms, scenario.expectedExpiryMs);
        assert.equal(entry.eligible, 1);
        const mapping = history.prepare('SELECT expires_at_ms, bound_version_id FROM correction_cache_bindings').get();
        assert.equal(mapping.expires_at_ms, scenario.expectedExpiryMs);
        assert.equal(mapping.bound_version_id, seeded.snapshot.versionId);
        const state = history.prepare('SELECT kind, phase FROM correction_cache_state').get();
        assert.deepEqual({ ...state }, { kind: 'bind', phase: 'complete' });
      } finally { cache.close(); history.close(); }
    });
  }
});

test('bind preflight rejects a TTL longer than effective history retention before creating a barrier', async (t) => {
  const f = await fixture(t, { cache: { resolveRetention({ nowMs, requestedExpiryMs }) {
    return { expiresAtMs: Math.min(nowMs + 180_000, requestedExpiryMs ?? Number.MAX_SAFE_INTEGER),
      policyId: 'synthetic-long-cache-retention', policyVersion: '1' };
  } } });
  const seeded = await createSeed(f);
  const invalidInput = { idempotencyKey: 'bind-ttl-over-history-expiry',
    profile: cacheProfile({ expiresAtMs: EPOCH + 120_000, freshnessTtlMs: 60_001 }) };
  await assert.rejects(f.store.bindPrivateProfile(f.scope, EVENT_ID, invalidInput, f.authRequest),
    (error) => error?.code === 'REUSE_INVALID');
  assertNoPendingBinding(f.root);
  assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).versionId, seeded.snapshot.versionId);
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup())).status, 'miss');

  const valid = await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-ttl-after-history-expiry-rejection', profile: cacheProfile({ expiresAtMs: EPOCH + 120_000 }) },
    f.authRequest);
  assert.equal(valid.status, 'bound');
  assert.equal(Date.parse(valid.expiresAt), EPOCH + 60_000);
});

test('bind preflight rejects a stale history base without writing a binding barrier', async (t) => {
  let gateNextRetention = false;
  let resolveRetentionStarted;
  let releaseRetention;
  const retentionStarted = new Promise((resolve) => { resolveRetentionStarted = resolve; });
  const retentionGate = new Promise((resolve) => { releaseRetention = resolve; });
  const f = await fixture(t, { cache: { async resolveRetention({ nowMs, requestedExpiryMs }) {
    if (gateNextRetention) {
      gateNextRetention = false;
      resolveRetentionStarted();
      await retentionGate;
    }
    return { expiresAtMs: Math.min(nowMs + 180_000, requestedExpiryMs ?? Number.MAX_SAFE_INTEGER),
      policyId: 'synthetic-long-cache-retention', policyVersion: '1' };
  } } });
  t.after(() => releaseRetention());
  const seeded = await createSeed(f);
  const input = { idempotencyKey: 'bind-stale-preflight-base',
    profile: cacheProfile({ expiresAtMs: EPOCH + 120_000 }) };
  gateNextRetention = true;
  const bindAttempt = f.store.bindPrivateProfile(f.scope, EVENT_ID, input, f.authRequest);
  await waitForSignal(retentionStarted, 'bind retention preflight after history snapshot');

  const corrected = await f.store.applyCorrection(f.scope, {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-26' },
    idempotencyKey: 'advance-history-during-bind-preflight',
    retentionHandle: f.createPermit(),
  }, f.authRequest);
  assert.equal(corrected.snapshot.revision, 2);
  releaseRetention();
  await assert.rejects(awaitWithTimeout(bindAttempt, 'stale bind base rejection'),
    (error) => error?.code === 'REVIEW_VERSION_CONFLICT');

  assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).versionId, corrected.snapshot.versionId);
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup())).status, 'miss');
  const history = new DatabaseSync(historyDatabasePath(f.root));
  try {
    const state = history.prepare('SELECT kind, phase FROM correction_cache_state').get();
    assert.deepEqual({ ...state }, { kind: 'correction', phase: 'complete' });
    assert.equal(history.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 0);
    assert.equal(history.prepare("SELECT COUNT(*) AS count FROM correction_cache_operations WHERE kind = 'bind'").get().count, 0);
  } finally { history.close(); }
  let cacheEntries = 0;
  try {
    await access(cacheDatabasePath(f.root));
    const cache = new DatabaseSync(cacheDatabasePath(f.root));
    try { cacheEntries = cache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count; }
    finally { cache.close(); }
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  assert.equal(cacheEntries, 0);

  const retried = await f.store.bindPrivateProfile(f.scope, EVENT_ID, input, f.authRequest);
  assert.equal(retried.status, 'bound');
  assert.equal(retried.historyVersionId, corrected.snapshot.versionId);
});

test('invalid composed revision input is rejected before a durable barrier is created', async (t) => {
  const cases = [
    {
      name: 'locked field',
      kind: 'correction',
      input: (seeded, f) => ({ eventId: EVENT_ID, baseVersionId: seeded.versionId, baseContentHash: seeded.contentHash,
        field: 'event_status', value: 'cancelled', idempotencyKey: 'invalid-locked-status', retentionHandle: f.createPermit() }),
      code: 'REVIEW_FIELD_LOCKED',
    },
    {
      name: 'malformed date',
      kind: 'correction',
      input: (seeded, f) => ({ eventId: EVENT_ID, baseVersionId: seeded.versionId, baseContentHash: seeded.contentHash,
        field: 'event_date', value: { precision: 'date', value: '2027-02-30' },
        idempotencyKey: 'invalid-malformed-date', retentionHandle: f.createPermit() }),
      code: 'REVIEW_INVALID',
    },
    {
      name: 'malformed source facts',
      kind: 'refresh',
      input: (seeded, f) => ({ eventId: EVENT_ID, baseVersionId: seeded.versionId, baseContentHash: seeded.contentHash,
        sourceFacts: { event_name: { status: 'sourced', value: 'Bad fact', sourceEvidence: [] } },
        idempotencyKey: 'invalid-malformed-refresh', retentionHandle: f.createPermit() }),
      code: 'REVIEW_INVALID',
    },
  ];
  for (const scenario of cases) {
    await t.test(scenario.name, async (subtest) => {
      const f = await fixture(subtest);
      const seeded = (await createSeed(f)).snapshot;
      const operation = scenario.kind === 'correction' ? f.store.applyCorrection : f.store.refreshSources;
      await assert.rejects(operation(f.scope, scenario.input(seeded, f), f.authRequest),
        (error) => error instanceof ReviewHistoryError && error.code === scenario.code);
      assertNoPendingBinding(f.root);
      assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).versionId, seeded.versionId);

      const reopened = f.makeStore();
      const reopenedScope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
      assert.equal((await reopened.getHistory(reopenedScope, EVENT_ID, f.authRequest)).versionId, seeded.versionId);
      const corrected = await reopened.applyCorrection(reopenedScope, {
        eventId: EVENT_ID,
        baseVersionId: seeded.versionId,
        baseContentHash: seeded.contentHash,
        field: 'event_date',
        value: { precision: 'date', value: '2027-06-20' },
        idempotencyKey: `valid-after-${scenario.kind}-${scenario.name.replaceAll(' ', '-')}`,
        retentionHandle: f.createPermit(),
      }, f.authRequest);
      assert.equal(corrected.snapshot.revision, seeded.revision + 1);
    });
  }
});

test('invalid private bind identity or pins and rejected trusted observation leave history usable', async (t) => {
  const cases = [
    { name: 'missing identity coordinates', profile: () => ({ ...cacheProfile(), identity: { occurrenceId: 'only-one' } }), code: 'REUSE_INVALID' },
    { name: 'malformed policy pin', profile: () => ({ ...cacheProfile(), pins: { ...PINS, policyHash: 'bad' } }), code: 'REUSE_INVALID' },
    { name: 'malformed ignored caller facts', profile: () => ({ ...cacheProfile(), facts: { unexpected: 'fact' } }), code: 'REUSE_INVALID' },
    { name: 'trusted observation verifier rejects', profile: () => cacheProfile(), code: 'REUSE_POLICY_UNAVAILABLE', verifier: () => { throw new Error('synthetic verifier denial'); } },
    { name: 'trusted observation verifier returns malformed result', profile: () => cacheProfile(), code: 'REUSE_POLICY_UNAVAILABLE', verifier: () => ({ status: 'body_changed', contentHash: 'bad' }) },
  ];
  for (const scenario of cases) {
    await t.test(scenario.name, async (subtest) => {
      const f = await fixture(subtest, scenario.verifier ? { cache: { verifySourceObservation: scenario.verifier } } : {});
      const seeded = (await createSeed(f)).snapshot;
      await assert.rejects(f.store.bindPrivateProfile(f.scope, EVENT_ID,
        { idempotencyKey: `invalid-${scenario.name.replaceAll(' ', '-')}`, profile: scenario.profile() }, f.authRequest),
      (error) => error?.code === scenario.code);
      assertNoPendingBinding(f.root);
      assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).versionId, seeded.versionId);

      const reopened = f.makeStore();
      const reopenedScope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
      assert.equal((await reopened.getHistory(reopenedScope, EVENT_ID, f.authRequest)).versionId, seeded.versionId);
      const corrected = await reopened.applyCorrection(reopenedScope, {
        eventId: EVENT_ID,
        baseVersionId: seeded.versionId,
        baseContentHash: seeded.contentHash,
        field: 'event_date',
        value: { precision: 'date', value: '2027-06-21' },
        idempotencyKey: `valid-after-bind-${scenario.name.replaceAll(' ', '-')}`,
        retentionHandle: f.createPermit(),
      }, f.authRequest);
      assert.equal(corrected.snapshot.revision, seeded.revision + 1);
    });
  }
});

test('composed revisions reauthorize after a real SQLite writer conflict before any cache mutation', async (t) => {
  for (const scenario of [
    { kind: 'correction', action: 'apply_correction' },
    { kind: 'source refresh', action: 'refresh_source_facts' },
  ]) {
    await t.test(scenario.kind, async (subtest) => {
      let root;
      let requestValue;
      let boundaryAttempts = 0;
      let writer;
      let writerAcquired = false;
      let writerAcquireError;
      let watchBegin = false;
      let busyBeginCount = 0;
      let retryObservedSignalled = false;
      let resolveRetryObserved;
      const retryObserved = new Promise((resolve) => { resolveRetryObserved = resolve; });
      const execDescriptor = Object.getOwnPropertyDescriptor(DatabaseSync.prototype, 'exec');
      Object.defineProperty(DatabaseSync.prototype, 'exec', {
        ...execDescriptor,
        value(sql, ...args) {
          if (watchBegin && sql === 'BEGIN IMMEDIATE') {
            try { return Reflect.apply(execDescriptor.value, this, [sql, ...args]); }
            catch (error) {
              if (error?.code === 'ERR_SQLITE_BUSY' || /busy|locked/i.test(error?.message ?? '')) busyBeginCount += 1;
              throw error;
            }
          }
          return Reflect.apply(execDescriptor.value, this, [sql, ...args]);
        },
      });
      const closeWriter = () => {
        if (!writer) return;
        try { writer.exec('ROLLBACK'); } catch { /* It may already have rolled back. */ }
        try { writer.close(); } catch { /* It may already be closed. */ }
        writer = null;
      };
      const history = {
        resolveActor(value) {
          if (value === requestValue && value.principal.actorId === 'actor-revoked' && !retryObservedSignalled) {
            retryObservedSignalled = true;
            resolveRetryObserved();
          }
          return value?.principal?.actorId;
        },
        authorize({ tenantId, actorId, action, request: value }) {
          return value?.serverContextToken === TRUSTED_TOKEN
            && value?.principal?.tenantId === tenantId
            && value?.principal?.actorId === actorId
            && actorId !== 'outsider' && actorId !== 'actor-revoked';
        },
        authorizeBoundary(input) {
          const boundaryAction = scenario.action === 'apply_correction'
            ? 'review.history.apply_correction' : 'review.history.refresh_source_facts';
          if (input.request === requestValue && input.action === boundaryAction
            && typeof input.details?.targetVersionId === 'string') {
            boundaryAttempts += 1;
            if (boundaryAttempts === 1) {
              try {
                writer = new DatabaseSync(historyDatabasePath(root));
                writer.exec('PRAGMA busy_timeout = 0; BEGIN IMMEDIATE');
                writerAcquired = true;
                watchBegin = true;
              } catch (error) {
                writerAcquireError = error;
              }
            } else if (boundaryAttempts === 2 && writerAcquired) {
              requestValue.principal.actorId = 'actor-revoked';
              if (!retryObservedSignalled) {
                retryObservedSignalled = true;
                resolveRetryObserved();
              }
              return false;
            }
          }
          const allowed = input.request?.serverContextToken === TRUSTED_TOKEN
            && input.request?.principal?.tenantId === input.tenantId
            && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider'
            && input.actorId !== 'actor-revoked';
          return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
            eventId: input.eventId, action: input.action, field: input.field, nowMs: EPOCH }) : false;
        },
      };
      const f = await fixture(subtest, { history });
      subtest.after(() => {
        closeWriter();
        if (requestValue) requestValue.principal.actorId = 'actor-binding';
        Object.defineProperty(DatabaseSync.prototype, 'exec', execDescriptor);
      });
      root = f.root;
      requestValue = { principal: { tenantId: 'tenant-binding', actorId: 'actor-binding' }, serverContextToken: TRUSTED_TOKEN };
      const scope = await f.store.scopeForAuthenticatedRequest(requestValue);
      const first = (await f.store.createHistory(scope, { eventId: EVENT_ID, sourceFacts: initialFacts(),
        idempotencyKey: `writer-revoke-${scenario.kind.replaceAll(' ', '-')}-seed`, retentionHandle: f.createPermit() }, requestValue)).snapshot;
      await f.store.bindPrivateProfile(scope, EVENT_ID,
        { idempotencyKey: `writer-revoke-${scenario.kind.replaceAll(' ', '-')}-bind`, profile: cacheProfile() }, requestValue);

      const input = scenario.kind === 'correction'
        ? { eventId: EVENT_ID, baseVersionId: first.versionId, baseContentHash: first.contentHash,
          field: 'event_date', value: { precision: 'date', value: '2027-06-23' },
          idempotencyKey: 'writer-revoke-composed-correction', retentionHandle: f.createPermit() }
        : { eventId: EVENT_ID, baseVersionId: first.versionId, baseContentHash: first.contentHash,
          sourceFacts: { event_date: { status: 'sourced', value: { precision: 'date', value: '2027-06-24' },
            sourceEvidence: [sourceEvidence('writer-revoke-composed-refresh', '2027-06-24')] } },
          idempotencyKey: 'writer-revoke-composed-source-refresh', retentionHandle: f.createPermit() };
      const run = (store = f.store, operationScope = scope) => scenario.kind === 'correction'
        ? store.applyCorrection(operationScope, input, requestValue)
        : store.refreshSources(operationScope, input, requestValue);

      const historyBefore = new DatabaseSync(historyDatabasePath(f.root));
      let initialHistoryState;
      try {
        initialHistoryState = {
          head: historyBefore.prepare('SELECT version_id, revision FROM heads WHERE event_key IS NOT NULL').get(),
          versions: historyBefore.prepare('SELECT COUNT(*) AS count FROM versions').get().count,
          idempotency: historyBefore.prepare('SELECT COUNT(*) AS count FROM idempotency').get().count,
          invalidations: historyBefore.prepare('SELECT COUNT(*) AS count FROM invalidations').get().count,
        };
      } finally { historyBefore.close(); }
      const cacheBefore = new DatabaseSync(cacheDatabasePath(f.root));
      let initialCacheState;
      try {
        initialCacheState = {
          entry: cacheBefore.prepare(`SELECT version, eligible, payload_purged FROM reuse_entries WHERE binding_hash IS NOT NULL`).get(),
          reservations: cacheBefore.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count,
          outbox: cacheBefore.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count,
          receipts: cacheBefore.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count,
        };
      } finally { cacheBefore.close(); }

      const rejected = await awaitWithTimeout(run(), `revoked composed ${scenario.kind} retry`)
        .then(() => null, (error) => error);
      assert.equal(rejected?.code, 'REVIEW_DENIED', JSON.stringify({
        code: rejected?.code,
        actorId: requestValue.principal.actorId,
        boundaryAttempts,
        busyBeginCount,
        writerAcquired,
        writerAcquireError: writerAcquireError?.message,
        writerHeld: Boolean(writer),
        retryObservedSignalled,
      }));
      await waitForSignal(retryObserved, 'revoked composed revision retry authorization');
      assert.equal(boundaryAttempts, 2, 'the second commit-boundary guard follows the first busy BEGIN retry');
      assert.equal(busyBeginCount, 1, 'the first COMMIT-path BEGIN IMMEDIATE actually encountered the held writer');
      assert.equal(writerAcquired, true, writerAcquireError?.message);
      assert.equal(Boolean(writer), true);
      closeWriter();
      assert.equal(requestValue.principal.actorId, 'actor-revoked');

      const historyAfter = new DatabaseSync(historyDatabasePath(f.root));
      try {
        assert.deepEqual({
          head: historyAfter.prepare('SELECT version_id, revision FROM heads WHERE event_key IS NOT NULL').get(),
          versions: historyAfter.prepare('SELECT COUNT(*) AS count FROM versions').get().count,
          idempotency: historyAfter.prepare('SELECT COUNT(*) AS count FROM idempotency').get().count,
          invalidations: historyAfter.prepare('SELECT COUNT(*) AS count FROM invalidations').get().count,
        }, initialHistoryState);
        assert.equal(historyAfter.prepare("SELECT phase FROM correction_cache_state WHERE kind = ?").get(scenario.kind === 'correction' ? 'correction' : 'source_refresh').phase,
          'pending_correction');
      } finally { historyAfter.close(); }
      const cacheAfter = new DatabaseSync(cacheDatabasePath(f.root));
      try {
        assert.deepEqual({
          entry: cacheAfter.prepare(`SELECT version, eligible, payload_purged FROM reuse_entries WHERE binding_hash IS NOT NULL`).get(),
          reservations: cacheAfter.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count,
          outbox: cacheAfter.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count,
          receipts: cacheAfter.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count,
        }, initialCacheState);
      } finally { cacheAfter.close(); }

      requestValue.principal.actorId = 'actor-binding';
      const reopened = f.makeStore();
      const reopenedScope = await reopened.scopeForAuthenticatedRequest(requestValue);
      const retried = await run(reopened, reopenedScope);
      assert.equal(retried.snapshot.revision, 2);
      const completeHistory = new DatabaseSync(historyDatabasePath(f.root));
      try {
        assert.equal(completeHistory.prepare("SELECT phase FROM correction_cache_state WHERE kind = ?")
          .get(scenario.kind === 'correction' ? 'correction' : 'source_refresh').phase, 'complete');
        assert.equal(completeHistory.prepare('SELECT COUNT(*) AS count FROM idempotency').get().count, initialHistoryState.idempotency + 1);
      } finally { completeHistory.close(); }
      const completeCache = new DatabaseSync(cacheDatabasePath(f.root));
      try {
        assert.equal(completeCache.prepare('SELECT eligible FROM reuse_entries WHERE binding_hash IS NOT NULL').get().eligible, 0);
        assert.equal(completeCache.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count, 1);
        assert.equal(completeCache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox WHERE status = \'pending\'').get().count, 1);
      } finally { completeCache.close(); }
    });
  }
});

test('revision and operation candidate preflights retry zero-timeout writer conflicts and reauthorize before effects', async (t) => {
  for (const phase of ['revision_preflight', 'operation_preflight']) {
    await t.test(phase, async (subtest) => {
      let f;
      let allowAuthorization = true;
      let writer;
      let writerAcquired = false;
      let writerAcquireError;
      let guardAttempts = 0;
      let matchingAsyncAuthorizations = 0;
      let watchBegin = false;
      let busyBeginCount = 0;
      const execDescriptor = Object.getOwnPropertyDescriptor(DatabaseSync.prototype, 'exec');
      Object.defineProperty(DatabaseSync.prototype, 'exec', {
        ...execDescriptor,
        value(sql, ...args) {
          if (watchBegin && sql === 'BEGIN IMMEDIATE') {
            try { return Reflect.apply(execDescriptor.value, this, [sql, ...args]); }
            catch (error) {
              if (error?.code === 'ERR_SQLITE_BUSY' || /busy|locked/i.test(error?.message ?? '')) {
                busyBeginCount += 1;
                allowAuthorization = false;
                watchBegin = false;
              }
              throw error;
            }
          }
          return Reflect.apply(execDescriptor.value, this, [sql, ...args]);
        },
      });
      const closeWriter = () => {
        if (!writer) return;
        try { writer.exec('ROLLBACK'); } catch { /* It may already have rolled back. */ }
        try { writer.close(); } catch { /* It may already be closed. */ }
        writer = null;
      };
      const acquireWriter = () => {
        try {
          writer = new DatabaseSync(historyDatabasePath(f.root));
          writer.exec('PRAGMA busy_timeout = 0; BEGIN IMMEDIATE');
          writerAcquired = true;
        } catch (error) { writerAcquireError = error; }
      };
      const history = {
        authorize({ tenantId, actorId, action, request: value }) {
          if (value === f?.authRequest && action === 'apply_correction') matchingAsyncAuthorizations += 1;
          return allowAuthorization && value?.serverContextToken === TRUSTED_TOKEN
            && value?.principal?.tenantId === tenantId && value?.principal?.actorId === actorId
            && actorId !== 'outsider';
        },
        authorizeBoundary(input) {
          const allowed = allowAuthorization && input.request?.serverContextToken === TRUSTED_TOKEN
            && input.request?.principal?.tenantId === input.tenantId
            && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
          if (input.request === f?.authRequest && input.details?.kind === 'correction'
            && input.details?.stage === phase) {
            guardAttempts += 1;
            if (guardAttempts === 1 && phase === 'operation_preflight') acquireWriter();
            if (guardAttempts === 1) watchBegin = true;
          }
          return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
            eventId: input.eventId, action: input.action, field: input.field, nowMs: EPOCH }) : false;
        },
      };
      f = await fixture(subtest, { history });
      subtest.after(() => {
        closeWriter();
        Object.defineProperty(DatabaseSync.prototype, 'exec', execDescriptor);
      });
      const seeded = await createSeed(f);
      await f.store.bindPrivateProfile(f.scope, EVENT_ID,
        { idempotencyKey: `candidate-preflight-${phase}-bind`, profile: cacheProfile() }, f.authRequest);
      if (phase === 'revision_preflight') acquireWriter();
      if (phase === 'revision_preflight') assert.equal(writerAcquired, true, writerAcquireError?.message);

      const beforeHistory = new DatabaseSync(historyDatabasePath(f.root));
      let historyState;
      try {
        historyState = {
          head: beforeHistory.prepare('SELECT version_id, revision FROM heads WHERE event_key IS NOT NULL').get(),
          versions: beforeHistory.prepare('SELECT COUNT(*) AS count FROM versions').get().count,
          idempotency: beforeHistory.prepare('SELECT COUNT(*) AS count FROM idempotency').get().count,
          operations: beforeHistory.prepare('SELECT COUNT(*) AS count FROM correction_cache_operations').get().count,
          invalidations: beforeHistory.prepare('SELECT COUNT(*) AS count FROM invalidations').get().count,
          pending: beforeHistory.prepare("SELECT COUNT(*) AS count FROM correction_cache_state WHERE phase != 'complete'").get().count,
        };
      } finally { beforeHistory.close(); }
      const beforeCache = new DatabaseSync(cacheDatabasePath(f.root));
      let cacheState;
      try {
        cacheState = {
          entries: beforeCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count,
          reservations: beforeCache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count,
          outbox: beforeCache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count,
        };
      } finally { beforeCache.close(); }

      const input = {
        eventId: EVENT_ID,
        baseVersionId: seeded.snapshot.versionId,
        baseContentHash: seeded.snapshot.contentHash,
        field: 'event_date',
        value: { precision: 'date', value: '2027-06-25' },
        idempotencyKey: `candidate-preflight-${phase}-correction`,
        retentionHandle: f.createPermit(),
      };
      const startedAt = process.hrtime.bigint();
      const rejection = await awaitWithTimeout(f.store.applyCorrection(f.scope, input, f.authRequest),
        `${phase} writer retry authorization`, 2_000).then(() => null, (error) => error);
      const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      assert.equal(rejection?.code, 'REVIEW_DENIED', JSON.stringify({ phase, code: rejection?.code,
        guardAttempts, matchingAsyncAuthorizations, busyBeginCount, elapsedMs, writerAcquired,
        writerAcquireError: writerAcquireError?.message }));
      assert.equal(writerAcquired, true, writerAcquireError?.message);
      assert.equal(busyBeginCount, 1, 'the candidate transaction BEGIN IMMEDIATE encountered the actual held SQLite writer');
      assert.equal(guardAttempts, 1, 'the authorization retry fails before a second synchronous boundary token');
      assert.ok(matchingAsyncAuthorizations >= 3, 'async authorization ran again after the busy BEGIN retry');
      assert.ok(elapsedMs < 1_500, `zero-timeout retry stayed bounded (${elapsedMs.toFixed(1)}ms)`);
      closeWriter();
      allowAuthorization = true;

      const afterHistory = new DatabaseSync(historyDatabasePath(f.root));
      const afterCache = new DatabaseSync(cacheDatabasePath(f.root));
      try {
        assert.deepEqual({
          head: afterHistory.prepare('SELECT version_id, revision FROM heads WHERE event_key IS NOT NULL').get(),
          versions: afterHistory.prepare('SELECT COUNT(*) AS count FROM versions').get().count,
          idempotency: afterHistory.prepare('SELECT COUNT(*) AS count FROM idempotency').get().count,
          operations: afterHistory.prepare('SELECT COUNT(*) AS count FROM correction_cache_operations').get().count,
          invalidations: afterHistory.prepare('SELECT COUNT(*) AS count FROM invalidations').get().count,
          pending: afterHistory.prepare("SELECT COUNT(*) AS count FROM correction_cache_state WHERE phase != 'complete'").get().count,
        }, historyState);
        assert.deepEqual({
          entries: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count,
          reservations: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count,
          outbox: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count,
        }, cacheState);
      } finally { afterHistory.close(); afterCache.close(); }
      assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).versionId, seeded.snapshot.versionId);
    });
  }
});

test('revision projection preflight retries a real SQLite writer and reauthorizes before creating a barrier', async (t) => {
  let f;
  let retentionPermit;
  let holder;
  let allowAuthorization = true;
  let projectionBoundaryAttempts = 0;
  let matchingAuthorizationsAfterBusy = 0;
  let watchBegin = false;
  let busyBeginCount = 0;
  let writerReady = false;
  const markerPath = path.join(os.tmpdir(), `ei-projection-preflight-${process.pid}-${Date.now()}.ready`);
  const execDescriptor = Object.getOwnPropertyDescriptor(DatabaseSync.prototype, 'exec');
  Object.defineProperty(DatabaseSync.prototype, 'exec', {
    ...execDescriptor,
    value(sql, ...args) {
      if (watchBegin && sql === 'BEGIN IMMEDIATE') {
        try { return Reflect.apply(execDescriptor.value, this, [sql, ...args]); }
        catch (error) {
          if (error?.code === 'ERR_SQLITE_BUSY' || /busy|locked/i.test(error?.message ?? '')) {
            busyBeginCount += 1;
            allowAuthorization = false;
            watchBegin = false;
          }
          throw error;
        }
      }
      return Reflect.apply(execDescriptor.value, this, [sql, ...args]);
    },
  });
  const history = {
    async resolveRetention({ nowMs, sourceExpiresAtMs, retentionHandle }) {
      if (retentionHandle === retentionPermit && !holder) {
        holder = runWorker(['hold-history-writer', f.root, EVENT_ID, '', '', markerPath, '3000']);
        await waitForFile(markerPath);
        writerReady = true;
      }
      return { expiresAtMs: Math.min(nowMs + 60_000, sourceExpiresAtMs ?? Number.MAX_SAFE_INTEGER),
        policyId: 'projection-preflight-policy', policyVersion: '1', accessPolicy: 'tenant_private' };
    },
    authorize({ tenantId, actorId, action, request: value }) {
      if (value === f?.authRequest && action === 'apply_correction' && busyBeginCount > 0) {
        matchingAuthorizationsAfterBusy += 1;
      }
      return allowAuthorization && value?.serverContextToken === TRUSTED_TOKEN
        && value?.principal?.tenantId === tenantId && value?.principal?.actorId === actorId
        && actorId !== 'outsider';
    },
    authorizeBoundary(input) {
      if (input.request === f?.authRequest && input.details?.stage === 'revision_projection_preflight') {
        projectionBoundaryAttempts += 1;
        watchBegin = true;
      }
      const allowed = allowAuthorization && input.request?.serverContextToken === TRUSTED_TOKEN
        && input.request?.principal?.tenantId === input.tenantId
        && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
      return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
        eventId: input.eventId, action: input.action, field: input.field, nowMs: EPOCH }) : false;
    },
  };
  f = await fixture(t, { history });
  retentionPermit = f.createPermit();
  t.after(async () => {
    if (holder?.child.exitCode === null && holder.child.signalCode === null) holder.child.kill('SIGKILL');
    if (holder) await holder.exit;
    Object.defineProperty(DatabaseSync.prototype, 'exec', execDescriptor);
    try { await rm(markerPath, { force: true }); } catch { /* The marker is test-local. */ }
  });

  const seeded = await createSeed(f);
  const input = {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-26' },
    idempotencyKey: 'projection-preflight-writer-retry',
    retentionHandle: retentionPermit,
  };
  const before = new DatabaseSync(historyDatabasePath(f.root));
  let beforeState;
  try {
    beforeState = {
      head: before.prepare('SELECT version_id, revision FROM heads WHERE event_key IS NOT NULL').get(),
      versions: before.prepare('SELECT COUNT(*) AS count FROM versions').get().count,
      idempotency: before.prepare('SELECT COUNT(*) AS count FROM idempotency').get().count,
      operations: before.prepare('SELECT COUNT(*) AS count FROM correction_cache_operations').get().count,
      invalidations: before.prepare('SELECT COUNT(*) AS count FROM invalidations').get().count,
      pending: before.prepare("SELECT COUNT(*) AS count FROM correction_cache_state WHERE phase != 'complete'").get().count,
    };
  } finally { before.close(); }

  const startedAt = process.hrtime.bigint();
  const rejection = await awaitWithTimeout(f.store.applyCorrection(f.scope, input, f.authRequest),
    'revision projection preflight writer retry authorization', 2_000).then(() => null, (error) => error);
  const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
  assert.equal(rejection?.code, 'REVIEW_DENIED', JSON.stringify({
    code: rejection?.code, writerReady, projectionBoundaryAttempts, busyBeginCount,
    matchingAuthorizationsAfterBusy, elapsedMs,
  }));
  assert.equal(writerReady, true, 'the separate process acquired the SQLite writer before projection preflight');
  assert.equal(projectionBoundaryAttempts, 1, 'the intended projection-preflight boundary was reached once');
  assert.equal(busyBeginCount, 1, 'the projection-preflight BEGIN IMMEDIATE encountered the actual held writer');
  assert.ok(matchingAuthorizationsAfterBusy >= 1, 'retry reauthorization ran after the busy BEGIN');
  assert.ok(elapsedMs < 1_500, `projection preflight stayed bounded (${elapsedMs.toFixed(1)}ms)`);

  holder.child.kill('SIGKILL');
  const holderExit = await holder.exit;
  assert.equal(holderExit.signal, 'SIGKILL');
  holder = null;
  allowAuthorization = true;
  const after = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.deepEqual({
      head: after.prepare('SELECT version_id, revision FROM heads WHERE event_key IS NOT NULL').get(),
      versions: after.prepare('SELECT COUNT(*) AS count FROM versions').get().count,
      idempotency: after.prepare('SELECT COUNT(*) AS count FROM idempotency').get().count,
      operations: after.prepare('SELECT COUNT(*) AS count FROM correction_cache_operations').get().count,
      invalidations: after.prepare('SELECT COUNT(*) AS count FROM invalidations').get().count,
      pending: after.prepare("SELECT COUNT(*) AS count FROM correction_cache_state WHERE phase != 'complete'").get().count,
    }, beforeState);
  } finally { after.close(); }
  assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).versionId, seeded.snapshot.versionId);
  const retried = await f.store.applyCorrection(f.scope, input, f.authRequest);
  assert.equal(retried.snapshot.revision, seeded.snapshot.revision + 1);
});

test('bind preflight uses its exact history action and cannot borrow refresh authority', async (t) => {
  const seen = [];
  const allowedActions = new Set([
    'review.history.initialize',
    'private_profile.read',
    'review.history.cache_bind_begin',
    'review.history.cache_bind_reference',
    'review.history.cache_operation_state',
    'review.history.retention_purge',
  ]);
  const f = await fixture(t, { history: {
    authorizeBoundary(input) {
      seen.push(input.action);
      const allowed = allowedActions.has(input.action)
        && input.request?.serverContextToken === TRUSTED_TOKEN
        && input.request?.principal?.tenantId === input.tenantId
        && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
      return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
        eventId: input.eventId, action: input.action, field: input.field, nowMs: EPOCH }) : false;
    },
  } });
  await createSeed(f);
  const bound = await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-exact-history-action', profile: cacheProfile() }, f.authRequest);
  assert.equal(bound.status, 'bound');
  assert.ok(seen.includes('review.history.cache_bind_begin'));
  assert.equal(seen.includes('review.history.refresh_source_facts'), false);
});

test('revision expiry is rechecked after materialization and before the first write', async (t) => {
  let f;
  let finalBoundaryReached = false;
  let materializationDelayReached = false;
  let watchedBeginAttempts = 0;
  let watchBegin = false;
  const prepareDescriptor = Object.getOwnPropertyDescriptor(DatabaseSync.prototype, 'prepare');
  const execDescriptor = Object.getOwnPropertyDescriptor(DatabaseSync.prototype, 'exec');
  Object.defineProperty(DatabaseSync.prototype, 'prepare', {
    ...prepareDescriptor,
    value(sql, ...args) {
      if (!materializationDelayReached && finalBoundaryReached && String(sql).includes('SELECT * FROM heads')
        && new Error().stack.includes('materializeBindingRevision')) {
        materializationDelayReached = true;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1_100);
      }
      return Reflect.apply(prepareDescriptor.value, this, [sql, ...args]);
    },
  });
  Object.defineProperty(DatabaseSync.prototype, 'exec', {
    ...execDescriptor,
    value(sql, ...args) {
      if (watchBegin && sql === 'BEGIN IMMEDIATE') watchedBeginAttempts += 1;
      return Reflect.apply(execDescriptor.value, this, [sql, ...args]);
    },
  });
  const fHistory = {
    authorizeBoundary(input) {
      if (input.action === 'review.history.revision_begin' && input.details?.operationId) {
        finalBoundaryReached = true;
        watchBegin = true;
      } else if (input.action === 'review.history.retention_purge') {
        watchBegin = false;
      }
      const allowed = input.request?.serverContextToken === TRUSTED_TOKEN
        && input.request?.principal?.tenantId === input.tenantId
        && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
      return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
        eventId: input.eventId, action: input.action, field: input.field, nowMs: f?.clock.value ?? EPOCH }) : false;
    },
  };
  f = await fixture(t, { history: fHistory });
  t.after(() => {
    Object.defineProperty(DatabaseSync.prototype, 'prepare', prepareDescriptor);
    Object.defineProperty(DatabaseSync.prototype, 'exec', execDescriptor);
  });
  const seeded = await createSeed(f);
  const before = new DatabaseSync(historyDatabasePath(f.root));
  try { assert.equal(before.prepare('SELECT COUNT(*) AS count FROM versions').get().count, 1); }
  finally { before.close(); }
  const cacheState = async () => {
    const databasePath = cacheDatabasePath(f.root);
    try { await access(databasePath); }
    catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
    const database = new DatabaseSync(databasePath);
    try {
      return {
        entries: database.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count,
        reservations: database.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count,
        outbox: database.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count,
        receipts: database.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count,
      };
    } finally { database.close(); }
  };
  const cacheBefore = await cacheState();
  f.clock.value = EPOCH + 59_000;
  const input = {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-27' },
    idempotencyKey: 'revision-expiry-before-first-write',
    retentionHandle: f.createPermit(),
  };
  await assert.rejects(f.store.applyCorrection(f.scope, input, f.authRequest),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_EXPIRED');
  assert.equal(finalBoundaryReached, true, 'the final revision guard ran before materialization');
  assert.equal(materializationDelayReached, true, 'the test delayed actual revision materialization after that guard');
  assert.equal(watchedBeginAttempts, 0, 'expiry rejected the transaction before BEGIN IMMEDIATE');
  assert.deepEqual(await cacheState(), cacheBefore, 'pre-BEGIN expiry has no cache or outbox effects');
  const after = new DatabaseSync(historyDatabasePath(f.root));
  try {
    const head = after.prepare('SELECT version_id, revision, expires_at_ms, state FROM heads WHERE event_key IS NOT NULL').get();
    assert.equal(head.version_id, seeded.snapshot.versionId);
    assert.equal(head.revision, seeded.snapshot.revision);
    assert.equal(head.expires_at_ms, Date.parse(seeded.snapshot.expiresAt));
    assert.equal(head.state, 'available', 'the pre-barrier rejection leaves the prior row intact for normal retention cleanup');
    assert.equal(after.prepare('SELECT COUNT(*) AS count FROM versions WHERE revision = 2').get().count, 0);
    assert.equal(after.prepare('SELECT COUNT(*) AS count FROM correction_cache_operations').get().count, 0);
    assert.equal(after.prepare('SELECT COUNT(*) AS count FROM correction_cache_state').get().count, 0);
  } finally { after.close(); }
});

test('composed correction never invokes the configured history clock while holding its SQLite writer lock', async (t) => {
  let armed = false;
  let historyDatabasePath;
  const attempts = [];
  const f = await fixture(t, { history: { now() {
    if (armed) {
      const attempt = { result: 'writer acquired' };
      let database;
      try {
        database = new DatabaseSync(historyDatabasePath, { timeout: 0 });
        database.exec('PRAGMA busy_timeout = 0; BEGIN IMMEDIATE');
        database.exec('ROLLBACK');
      } catch (error) {
        attempt.result = 'writer rejected';
        attempt.errorCode = error?.code ?? null;
        attempt.errorMessage = String(error?.message ?? error);
      } finally {
        database?.close();
        attempts.push(attempt);
      }
    }
    return EPOCH;
  } } });
  const seeded = await createSeed(f);
  const tenantHash = createHash('sha256').update('event-intelligence:review-tenant:v1:tenant-binding').digest('hex');
  historyDatabasePath = path.join(f.historyOptions.directory, tenantHash, 'history.sqlite');
  armed = true;
  let revised;
  try {
    revised = await f.store.applyCorrection(f.scope, {
      eventId: EVENT_ID,
      baseVersionId: seeded.snapshot.versionId,
      baseContentHash: seeded.snapshot.contentHash,
      field: 'event_date',
      value: { precision: 'date', value: '2027-06-20' },
      idempotencyKey: 'clock-writer-guard-correction',
      retentionHandle: f.createPermit(),
    }, f.authRequest);
  } finally {
    armed = false;
  }

  assert.equal(revised.snapshot.revision, seeded.snapshot.revision + 1);
  assert.ok(attempts.length > 0, 'the injected clock was exercised during the composed correction');
  assert.deepEqual(attempts.filter((attempt) => attempt.result !== 'writer acquired'), []);
});

test('failed history binding context setup zeroes its acquired index key', async (t) => {
  const f = await fixture(t);
  await createSeed(f);
  const historyDirectory = f.historyOptions.directory;
  await rename(historyDirectory, `${historyDirectory}.preserved`);
  await writeFile(historyDirectory, 'regular file prevents tenant-directory setup');

  const originalFill = Buffer.prototype.fill;
  let contextKeyWasZeroed = false;
  Buffer.prototype.fill = function(value, ...args) {
    const contextBinding = value === 0 && this.byteLength === 32 && /bindingContext/.test(new Error().stack ?? '');
    const result = Reflect.apply(originalFill, this, [value, ...args]);
    if (contextBinding) contextKeyWasZeroed = this.every((byte) => byte === 0);
    return result;
  };
  try {
    await assert.rejects(f.store.getHistory(f.scope, EVENT_ID, f.authRequest),
      (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_STORAGE');
  } finally {
    Buffer.prototype.fill = originalFill;
  }
  assert.equal(contextKeyWasZeroed, true);
});

test('composed reads resolve only an exact issued binding and reject malformed mapping state', async (t) => {
  const f = await fixture(t);
  await createSeed(f);
  const unrelated = createScopedReuseStore(f.cacheOptions);
  const unrelatedScope = await unrelated.scopeForAuthenticatedRequest(f.authRequest);
  await unrelated.putPrivateProfile(unrelatedScope, f.authRequest, {
    ...cacheProfile(),
    facts: { event_name: { status: 'sourced', value: 'unbound arbitrary profile' } },
  });
  assert.deepEqual(await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()), { status: 'miss' });

  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-exact-issued-reference', profile: cacheProfile() }, f.authRequest);
  const exact = await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup());
  assert.equal(exact.status, 'hit');
  if (exact.status === 'hit') {
    assert.equal(exact.facts.event_name.value, 'Lantern Night');
    assert.notEqual(exact.facts.event_name.value, 'unbound arbitrary profile');
  }
  assert.deepEqual(await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest,
    { ...lookup(), contentHash: 'c'.repeat(64) }), { status: 'miss' });
  assert.deepEqual(await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest,
    { ...lookup(), pins: { ...PINS, extractorVersion: 'unrelated-pin' } }), { status: 'miss' });
  await assert.rejects(f.store.getPrivateProfile(f.scope, 'unrelated-event', f.authRequest, lookup()),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_NOT_FOUND');

  const history = new DatabaseSync(historyDatabasePath(f.root));
  try {
    const row = history.prepare('SELECT event_key, binding_hash, sealed FROM correction_cache_bindings LIMIT 1').get();
    history.prepare('UPDATE correction_cache_bindings SET sealed = ? WHERE event_key = ? AND binding_hash = ?')
      .run(Buffer.alloc(2), row.event_key, row.binding_hash);
  } finally { history.close(); }
  await assert.rejects(f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_INTEGRITY');
});

test('wrong cache version or history binding coordinates fail closed without revealing a cache hit', async (t) => {
  const f = await fixture(t);
  await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-corrupt-coordinates', profile: cacheProfile() }, f.authRequest);
  const cache = new DatabaseSync(cacheDatabasePath(f.root));
  const history = new DatabaseSync(historyDatabasePath(f.root));
  try {
    const entry = cache.prepare('SELECT entry_id, version FROM reuse_entries LIMIT 1').get();
    cache.prepare('UPDATE reuse_entries SET version = ? WHERE entry_id = ?').run(entry.version + 1, entry.entry_id);
    await assert.rejects(f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()),
      (error) => error?.code === 'REUSE_DENIED' && error.message === 'reuse access denied');
    cache.prepare('UPDATE reuse_entries SET version = ? WHERE entry_id = ?').run(entry.version, entry.entry_id);

    const binding = history.prepare('SELECT event_key, binding_hash, bound_version_id, bound_content_hash FROM correction_cache_bindings LIMIT 1').get();
    history.prepare('UPDATE correction_cache_bindings SET bound_version_id = ? WHERE event_key = ? AND binding_hash = ?')
      .run('unrelated-history-version', binding.event_key, binding.binding_hash);
    assert.deepEqual(await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()), { status: 'miss' });
    history.prepare('UPDATE correction_cache_bindings SET bound_version_id = ? WHERE event_key = ? AND binding_hash = ?')
      .run(binding.bound_version_id, binding.event_key, binding.binding_hash);

    history.prepare('UPDATE correction_cache_bindings SET bound_content_hash = ? WHERE event_key = ? AND binding_hash = ?')
      .run('d'.repeat(64), binding.event_key, binding.binding_hash);
    assert.deepEqual(await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()), { status: 'miss' });
  } finally { cache.close(); history.close(); }
});

test('history commit crash window keeps stale reads blocked and exact retry reconciles after reopen', async (t) => {
  let failKeyOnce = false;
  let indexCallsAfterFailure = 0;
  const f = await fixture(t, { cache: {
    resolveKey({ tenantId, scope, purpose, keyId }) {
      if (failKeyOnce && purpose === 'index') {
        indexCallsAfterFailure += 1;
        if (indexCallsAfterFailure === 2) {
          failKeyOnce = false;
          throw new Error('synthetic key outage after history commit');
        }
      }
      const resolvedId = `${scope}:${purpose}:${tenantId ?? 'global'}:v1`;
      if (keyId && keyId !== resolvedId) throw new Error('synthetic cache key unavailable');
      return { keyId: resolvedId, key: createHash('sha256').update(`${tenantId}:${scope}:${purpose}:cache-test-key`).digest() };
    },
  } });
  const seeded = await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-profile-recovery', profile: cacheProfile() }, f.authRequest);
  const input = {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-21' },
    idempotencyKey: 'correct-date-recover',
    retentionHandle: f.createPermit(),
  };
  failKeyOnce = true;
  await assert.rejects(f.store.applyCorrection(f.scope, input, f.authRequest),
    (error) => error?.code === 'REUSE_KEY_UNAVAILABLE');
  await assert.rejects(f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_BUSY');

  const reopened = f.makeStore();
  const scope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
  const recovered = await reopened.applyCorrection(scope, input, f.authRequest);
  assert.equal(recovered.replayed, true);
  assert.equal((await reopened.getPrivateProfile(scope, EVENT_ID, f.authRequest, lookup())).status, 'miss');
  assert.equal((await reopened.outboxSnapshot(scope, f.authRequest)).readiness, 'blocked_pending_external_ack');
});

test('cache invalidation receipt prevents duplicate outbox rows after post-commit retry', async (t) => {
  let rejectAfterReceipt = true;
  const f = await fixture(t, { cache: {
    authorizeAction({ tenantId, actorId, action, request: value, details }) {
      if (rejectAfterReceipt && action === 'cache.invalidate' && typeof details?.profileRef === 'string') {
        try {
          const database = new DatabaseSync(cacheDatabasePath(f.root));
          try {
            const receipt = database.prepare('SELECT 1 AS found FROM reuse_history_invalidation_ops WHERE entry_id = ? LIMIT 1')
              .get(details.profileRef);
            if (receipt) rejectAfterReceipt = false;
            if (receipt) return false;
          } finally { database.close(); }
        } catch (error) { if (error?.code !== 'ERR_SQLITE_CANTOPEN') throw error; }
      }
      return value?.serverContextToken === TRUSTED_TOKEN && value?.principal?.tenantId === tenantId
        && value?.principal?.actorId === actorId && actorId !== 'outsider';
    },
  } });
  const seeded = await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-receipt-idempotence', profile: cacheProfile() }, f.authRequest);
  const input = {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-23' },
    idempotencyKey: 'correction-receipt-idempotence',
    retentionHandle: f.createPermit(),
  };
  await assert.rejects(f.store.applyCorrection(f.scope, input, f.authRequest), (error) => error?.code === 'REUSE_DENIED');
  assert.equal(rejectAfterReceipt, false);
  assert.equal((await f.store.outboxSnapshot(f.scope, f.authRequest)).pending, 1);
  const recovered = await f.store.applyCorrection(f.scope, input, f.authRequest);
  assert.equal(recovered.replayed, true);
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup())).status, 'miss');
  assert.equal((await f.store.outboxSnapshot(f.scope, f.authRequest)).pending, 1);
  const database = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(database.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count, 1);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM reuse_outbox WHERE status != 'delivered'").get().count, 1);
  } finally { database.close(); }
});

test('real process death after history commit leaves a durable read barrier until exact retry', async (t) => {
  const f = await fixture(t);
  const seeded = await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-process-death', profile: cacheProfile() }, f.authRequest);
  const idempotencyKey = 'correction-process-death';
  const marker = path.join(f.root, 'cache-invalidation-entered');
  const worker = runWorker(['kill-after-history', f.root, EVENT_ID, seeded.snapshot.versionId,
    seeded.snapshot.contentHash, marker, idempotencyKey]);
  t.after(() => { if (worker.child.exitCode === null && worker.child.signalCode === null) worker.child.kill('SIGKILL'); });
  await waitForFile(marker);
  const processResult = await worker.exit;
  assert.equal(processResult.signal, 'SIGKILL');
  assert.equal(await readFile(marker, 'utf8'), 'post-history cache invalidation callback');

  const database = new DatabaseSync(historyDatabasePath(f.root));
  try {
    const durable = database.prepare('SELECT phase, target_version_id FROM correction_cache_state WHERE event_key = (SELECT event_key FROM heads LIMIT 1)').get();
    const head = database.prepare('SELECT revision, version_id FROM heads LIMIT 1').get();
    assert.equal(durable.phase, 'history_committed');
    assert.equal(durable.target_version_id, head.version_id);
    assert.equal(head.revision, 2);
  } finally { database.close(); }
  await assert.rejects(f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_BUSY');

  const recovered = await f.store.applyCorrection(f.scope, {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-22' },
    idempotencyKey,
    retentionHandle: f.createPermit(),
  }, f.authRequest);
  assert.equal(recovered.replayed, true);
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup())).status, 'miss');
  assert.equal((await f.store.outboxSnapshot(f.scope, f.authRequest)).readiness, 'blocked_pending_external_ack');
});

test('real process death after cache invalidation commit replays its receipt without duplicate outbox work', async (t) => {
  const f = await fixture(t);
  const seeded = await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-cache-commit-crash', profile: cacheProfile() }, f.authRequest);
  const idempotencyKey = 'correction-cache-commit-crash';
  const marker = path.join(f.root, 'cache-commit-marker');
  const worker = runWorker(['kill-after-cache-commit', f.root, EVENT_ID, seeded.snapshot.versionId,
    seeded.snapshot.contentHash, marker, idempotencyKey]);
  t.after(() => { if (worker.child.exitCode === null && worker.child.signalCode === null) worker.child.kill('SIGKILL'); });
  await waitForFile(marker);
  const processResult = await worker.exit;
  assert.equal(processResult.signal, 'SIGKILL');
  assert.equal(await readFile(marker, 'utf8'), 'post-cache-commit before history receipt');

  const history = new DatabaseSync(historyDatabasePath(f.root));
  const cache = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    const state = history.prepare('SELECT phase FROM correction_cache_state WHERE event_key = (SELECT event_key FROM heads LIMIT 1)').get();
    const binding = history.prepare('SELECT last_invalidation_operation_id FROM correction_cache_bindings LIMIT 1').get();
    const entry = cache.prepare('SELECT eligible FROM reuse_entries LIMIT 1').get();
    assert.equal(state.phase, 'history_committed');
    assert.equal(binding.last_invalidation_operation_id, null);
    assert.equal(entry.eligible, 0);
    assert.equal(cache.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count, 1);
    assert.equal(cache.prepare("SELECT COUNT(*) AS count FROM reuse_outbox WHERE status != 'delivered'").get().count, 1);
  } finally { history.close(); cache.close(); }
  await assert.rejects(f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_BUSY');

  const reopened = f.makeStore();
  const scope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
  const recovered = await reopened.applyCorrection(scope, {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-22' },
    idempotencyKey,
    retentionHandle: f.createPermit(),
  }, f.authRequest);
  assert.equal(recovered.replayed, true);
  assert.equal((await reopened.getPrivateProfile(scope, EVENT_ID, f.authRequest, lookup())).status, 'miss');
  assert.equal((await reopened.outboxSnapshot(scope, f.authRequest)).pending, 1);
  const finalHistory = new DatabaseSync(historyDatabasePath(f.root));
  const finalCache = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    const state = finalHistory.prepare('SELECT phase FROM correction_cache_state WHERE event_key = (SELECT event_key FROM heads LIMIT 1)').get();
    const binding = finalHistory.prepare('SELECT last_invalidation_operation_id FROM correction_cache_bindings LIMIT 1').get();
    assert.equal(state.phase, 'complete');
    assert.equal(typeof binding.last_invalidation_operation_id, 'string');
    assert.equal(finalCache.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count, 1);
    assert.equal(finalCache.prepare("SELECT COUNT(*) AS count FROM reuse_outbox WHERE status != 'delivered'").get().count, 1);
  } finally { finalHistory.close(); finalCache.close(); }
});

test('real process death after bind reservation reopens with the same durable history admission', async (t) => {
  const f = await fixture(t);
  await createSeed(f);
  const marker = path.join(f.root, 'bind-reservation-marker');
  const idempotencyKey = 'bind-process-death-after-reservation';
  const worker = runWorker(['kill-after-bind-reservation', f.root, EVENT_ID, '', '', marker, idempotencyKey]);
  t.after(() => { if (worker.child.exitCode === null && worker.child.signalCode === null) worker.child.kill('SIGKILL'); });
  await waitForFile(marker);
  const processResult = await worker.exit;
  assert.equal(processResult.signal, 'SIGKILL');
  assert.match(await readFile(marker, 'utf8'), /^bind reservation persisted:[1-9]\d*$/);
  const reservationBytes = Number((await readFile(marker, 'utf8')).split(':').at(-1));

  const history = new DatabaseSync(historyDatabasePath(f.root));
  const cachePathExists = await access(cacheDatabasePath(f.root)).then(() => true, () => false);
  let baseStoredBytes;
  try {
    const operation = history.prepare("SELECT operation_id, phase, reserved_history_bytes FROM correction_cache_operations WHERE kind = 'bind'").get();
    assert.equal(operation.phase, 'pending_bind');
    assert.ok(operation.reserved_history_bytes > 0);
    assert.equal(operation.reserved_history_bytes, reservationBytes);
    baseStoredBytes = history.prepare(`SELECT
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM versions WHERE state = 'available') +
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM downstream_references) +
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM correction_cache_bindings) AS bytes`).get().bytes;
    assert.equal(history.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 0);
  } finally { history.close(); }
  if (cachePathExists) {
    const cache = new DatabaseSync(cacheDatabasePath(f.root));
    try {
      assert.equal(cache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count, 0);
      assert.equal(cache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count, 0);
      assert.equal(cache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 0);
    } finally { cache.close(); }
  }
  await assert.rejects(f.store.getHistory(f.scope, EVENT_ID, f.authRequest),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_BUSY');

  f.historyOptions.maxStoredBytes = baseStoredBytes + reservationBytes;
  const reopened = f.makeStore();
  const scope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
  const bound = await reopened.bindPrivateProfile(scope, EVENT_ID,
    { idempotencyKey, profile: cacheProfile() }, f.authRequest);
  assert.equal(bound.status, 'bound');
  assert.equal((await reopened.getHistory(scope, EVENT_ID, f.authRequest)).revision, 1);
  const complete = new DatabaseSync(historyDatabasePath(f.root));
  try {
    const operation = complete.prepare("SELECT phase, reserved_history_bytes FROM correction_cache_operations WHERE kind = 'bind'").get();
    assert.equal(operation.phase, 'complete');
    assert.equal(operation.reserved_history_bytes, 0);
    assert.equal(complete.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 1);
    assert.equal(complete.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 1);
    const actualPairBytes = complete.prepare(`SELECT
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM downstream_references) +
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM correction_cache_bindings) AS bytes`).get().bytes;
    assert.ok(actualPairBytes <= reservationBytes, `actual binding/reference ${actualPairBytes} exceeded reservation ${reservationBytes}`);
    const actualTotalBytes = complete.prepare(`SELECT
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM versions WHERE state = 'available') +
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM downstream_references) +
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM correction_cache_bindings) AS bytes`).get().bytes;
    assert.ok(actualTotalBytes <= baseStoredBytes + reservationBytes);
  } finally { complete.close(); }

  const below = await fixture(t);
  await createSeed(below);
  const belowHistory = new DatabaseSync(historyDatabasePath(below.root));
  let belowBaseBytes;
  try {
    belowBaseBytes = belowHistory.prepare(`SELECT
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM versions WHERE state = 'available') +
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM downstream_references) +
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM correction_cache_bindings) AS bytes`).get().bytes;
  } finally { belowHistory.close(); }
  below.historyOptions.maxStoredBytes = belowBaseBytes + reservationBytes - 1;
  const belowStore = below.makeStore();
  const belowScope = await belowStore.scopeForAuthenticatedRequest(below.authRequest);
  await assert.rejects(belowStore.bindPrivateProfile(belowScope, EVENT_ID,
    { idempotencyKey, profile: cacheProfile() }, below.authRequest),
  (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_STORAGE_LIMIT');
  assert.equal((await belowStore.getHistory(belowScope, EVENT_ID, below.authRequest)).revision, 1);
  const belowAfter = new DatabaseSync(historyDatabasePath(below.root));
  try {
    assert.equal(belowAfter.prepare("SELECT COUNT(*) AS count FROM correction_cache_operations WHERE kind = 'bind'").get().count, 0);
    assert.equal(belowAfter.prepare("SELECT COUNT(*) AS count FROM correction_cache_state WHERE phase = 'pending_bind'").get().count, 0);
    assert.equal(belowAfter.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 0);
    assert.equal(belowAfter.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 0);
  } finally { belowAfter.close(); }
});

test('another process cannot spend tenant history bytes reserved by a pending bind', async (t) => {
  let f;
  let childAttempt;
  let reservedLimit;
  let liveBefore;
  const peerEventId = 'event-binding-reservation-peer';
  f = await fixture(t, { cache: {
    authorizeAction({ tenantId, actorId, request: value }) {
      if (!childAttempt && value === f?.authRequest && actorId === 'actor-binding') {
        const history = new DatabaseSync(historyDatabasePath(f.root));
        try {
          const pending = history.prepare(`SELECT reserved_history_bytes FROM correction_cache_operations
            WHERE kind = 'bind' AND phase = 'pending_bind'`).get();
          if (pending) {
            liveBefore = history.prepare(`SELECT
              (SELECT COALESCE(SUM(length(sealed)), 0) FROM versions WHERE state = 'available') +
              (SELECT COALESCE(SUM(length(sealed)), 0) FROM downstream_references) +
              (SELECT COALESCE(SUM(length(sealed)), 0) FROM correction_cache_bindings) AS bytes`).get().bytes;
            reservedLimit = liveBefore + pending.reserved_history_bytes;
            childAttempt = runWorkerSync(['register-reference', f.root, peerEventId,
              peerSnapshot.versionId, peerSnapshot.contentHash, String(reservedLimit), 'peer-reference-must-not-fit']);
          }
        } finally { history.close(); }
      }
      return value?.serverContextToken === TRUSTED_TOKEN && value?.principal?.tenantId === tenantId
        && value?.principal?.actorId === actorId && actorId !== 'outsider';
    },
  } });
  await createSeed(f);
  const peerSnapshot = (await f.store.createHistory(f.scope, { eventId: peerEventId, sourceFacts: initialFacts(),
    idempotencyKey: 'initialize-reservation-peer', retentionHandle: f.createPermit() }, f.authRequest)).snapshot;
  const bound = await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-reserves-tenant-wide-bytes', profile: cacheProfile() }, f.authRequest);
  assert.equal(bound.status, 'bound');
  assert.ok(childAttempt, 'the separate writer ran after pending_bind reservation persisted');
  assert.equal(childAttempt.error, undefined);
  assert.equal(childAttempt.status, 0, childAttempt.stderr);
  assert.deepEqual(JSON.parse(childAttempt.stdout), { outcome: 'error', code: 'REVIEW_STORAGE_LIMIT' });
  assert.ok(Number.isSafeInteger(reservedLimit) && reservedLimit > liveBefore);

  const history = new DatabaseSync(historyDatabasePath(f.root));
  try {
    const total = history.prepare(`SELECT
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM versions WHERE state = 'available') +
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM downstream_references) +
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM correction_cache_bindings) AS bytes`).get().bytes;
    assert.ok(total <= reservedLimit, `stored bytes ${total} exceeded preflight limit ${reservedLimit}`);
    assert.equal(history.prepare("SELECT COUNT(*) AS count FROM downstream_references WHERE bound_version_id = ?").get(peerSnapshot.versionId).count, 0);
    const completed = history.prepare("SELECT phase, reserved_history_bytes FROM correction_cache_operations WHERE kind = 'bind'").get();
    assert.deepEqual({ ...completed }, { phase: 'complete', reserved_history_bytes: 0 });
  } finally { history.close(); }
  assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).revision, 1);
  assert.equal((await f.store.getHistory(f.scope, peerEventId, f.authRequest)).revision, 1);
});

test('real process death after bound cache commit replays at exhausted capacity without duplicate rows', async (t) => {
  const f = await fixture(t, { cache: { maxEntries: 1, maxOutboxEntries: 2 } });
  await createSeed(f);
  const idempotencyKey = 'bind-process-death-after-cache-commit';
  const marker = path.join(f.root, 'bind-cache-commit-marker');
  const worker = runWorker(['kill-after-bind-cache-commit', f.root, EVENT_ID, '', '', marker, idempotencyKey]);
  t.after(() => { if (worker.child.exitCode === null && worker.child.signalCode === null) worker.child.kill('SIGKILL'); });
  await waitForFile(marker);
  const processResult = await worker.exit;
  assert.equal(processResult.signal, 'SIGKILL');
  assert.equal(await readFile(marker, 'utf8'), 'bind cache receipt committed before history reference');

  const history = new DatabaseSync(historyDatabasePath(f.root));
  const cache = new DatabaseSync(cacheDatabasePath(f.root));
  let beforeCounts;
  let reservedHistoryBytes;
  try {
    const operation = history.prepare("SELECT phase, reserved_history_bytes FROM correction_cache_operations WHERE kind = 'bind'").get();
    assert.equal(operation.phase, 'pending_bind');
    assert.ok(operation.reserved_history_bytes > 0);
    reservedHistoryBytes = operation.reserved_history_bytes;
    assert.equal(history.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 0);
    beforeCounts = {
      entries: cache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count,
      writes: cache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count,
      reservations: cache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count,
      consumers: cache.prepare('SELECT COUNT(*) AS count FROM reuse_consumer_refs').get().count,
      observations: cache.prepare('SELECT COUNT(*) AS count FROM reuse_observations').get().count,
      outbox: cache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count,
    };
    assert.deepEqual(beforeCounts, { entries: 1, writes: 1, reservations: 1, consumers: 1, observations: 1, outbox: 0 });
  } finally { history.close(); cache.close(); }

  const reopened = f.makeStore();
  const scope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
  const bound = await reopened.bindPrivateProfile(scope, EVENT_ID,
    { idempotencyKey, profile: cacheProfile() }, f.authRequest);
  assert.equal(bound.status, 'bound');
  assert.equal(bound.replayed, true);
  const afterHistory = new DatabaseSync(historyDatabasePath(f.root));
  const afterCache = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    const operation = afterHistory.prepare("SELECT phase, reserved_history_bytes FROM correction_cache_operations WHERE kind = 'bind'").get();
    assert.deepEqual({ ...operation }, { phase: 'complete', reserved_history_bytes: 0 });
    assert.equal(afterHistory.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 1);
    const actualPairBytes = afterHistory.prepare(`SELECT
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM downstream_references) +
      (SELECT COALESCE(SUM(length(sealed)), 0) FROM correction_cache_bindings) AS bytes`).get().bytes;
    assert.ok(actualPairBytes <= reservedHistoryBytes,
      `recovered binding/reference ${actualPairBytes} exceeded persisted reservation ${reservedHistoryBytes}`);
    assert.deepEqual({
      entries: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count,
      writes: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count,
      reservations: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count,
      consumers: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_consumer_refs').get().count,
      observations: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_observations').get().count,
      outbox: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count,
    }, beforeCounts);
  } finally { afterHistory.close(); afterCache.close(); }
});

test('pending bind without a cache receipt keeps its reservation through capacity failure and exact retry', async (t) => {
  let f;
  let competingCache;
  let competingScope;
  let capacityConsumed = false;
  let originalHistoryReservationBytes;
  f = await fixture(t, { cache: {
    maxEntries: 1,
    async authorizeAction({ tenantId, actorId, action, request: value }) {
      if (!capacityConsumed && value === f?.authRequest && action === 'private_profile.write') {
        const history = new DatabaseSync(historyDatabasePath(f.root));
        let pending;
        try {
          pending = history.prepare(`SELECT reserved_history_bytes FROM correction_cache_operations
            WHERE kind = 'bind' AND phase = 'pending_bind'`).get();
          if (pending) originalHistoryReservationBytes = pending.reserved_history_bytes;
        } finally { history.close(); }
        if (pending) {
          capacityConsumed = true;
          const competitorIdentity = Object.freeze({ occurrenceId: 'temporary-capacity-entry',
            entityId: 'temporary-capacity-entry', editionId: 'temporary-capacity-entry' });
          await competingCache.putPrivateProfile(competingScope, value, cacheProfile({
            identity: competitorIdentity,
            contentHash: 'c'.repeat(64),
            freshnessTtlMs: 1,
            expiresAtMs: EPOCH + 1,
          }));
        }
      }
      return value?.serverContextToken === TRUSTED_TOKEN && value?.principal?.tenantId === tenantId
        && value?.principal?.actorId === actorId && actorId !== 'outsider';
    },
  } });
  await createSeed(f);
  competingCache = createScopedReuseStore({ ...f.cacheOptions, maxEntries: 1 });
  competingScope = await competingCache.scopeForAuthenticatedRequest(f.authRequest);
  const input = { idempotencyKey: 'bind-capacity-race-after-intent', profile: cacheProfile() };
  await assert.rejects(f.store.bindPrivateProfile(f.scope, EVENT_ID, input, f.authRequest),
    (error) => error?.code === 'REUSE_CAPACITY');
  assert.equal(capacityConsumed, true, 'the independent cache write ran after the history barrier');
  await assert.rejects(f.store.getHistory(f.scope, EVENT_ID, f.authRequest),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_BUSY');
  const pendingHistory = new DatabaseSync(historyDatabasePath(f.root));
  const blockedCache = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    const operation = pendingHistory.prepare("SELECT phase, reserved_history_bytes FROM correction_cache_operations WHERE kind = 'bind'").get();
    assert.equal(operation.phase, 'pending_bind');
    assert.ok(operation.reserved_history_bytes > 0);
    assert.equal(operation.reserved_history_bytes, originalHistoryReservationBytes,
      'the durable reservation is unchanged through deterministic cache-capacity failure');
    assert.equal(blockedCache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count, 0,
      'the bind did not create a cache write receipt while capacity was unavailable');
    assert.equal(blockedCache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 0,
      'the bind did not create a cache reservation while capacity was unavailable');
    assert.equal(blockedCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count, 1,
      'only the competing temporary cache entry exists');
  } finally { pendingHistory.close(); blockedCache.close(); }

  f.clock.value = EPOCH + 2;
  const purged = await competingCache.purgeExpired(competingScope, f.authRequest);
  assert.equal(purged.purged, 1);
  const expiredSnapshot = await competingCache.integritySnapshot(competingScope, f.authRequest);
  assert.equal(expiredSnapshot.entryCount, 1, 'retention keeps the expired entry tombstone for safe delivery');
  assert.equal(expiredSnapshot.eligibleEntryCount, 0);
  const expiredCache = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(expiredCache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 0,
      'expired binding reservation payload is pruned at cache retention');
  } finally { expiredCache.close(); }
  // The tombstone still consumes the configured row slot. Restore capacity explicitly while
  // preserving the same cache database and durable history operation for exact retry.
  f.cacheOptions.maxEntries = 2;
  const reopened = f.makeStore();
  const scope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
  const retried = await reopened.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest);
  assert.equal(retried.status, 'bound');
  assert.equal(retried.replayed, false, 'there was no prior cache receipt, so the exact retry creates the first cache effect');
  const completeHistory = new DatabaseSync(historyDatabasePath(f.root));
  const completeCache = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    const operation = completeHistory.prepare("SELECT phase, reserved_history_bytes FROM correction_cache_operations WHERE kind = 'bind'").get();
    assert.deepEqual({ ...operation }, { phase: 'complete', reserved_history_bytes: 0 });
    assert.equal(completeHistory.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 1);
    assert.equal(completeCache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count, 1);
    assert.equal(completeCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count, 2,
      'the expired tombstone remains and the restored slot holds one bound profile');
    assert.equal(completeCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries WHERE payload_purged = 1').get().count, 1);
    assert.equal(completeCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries WHERE binding_hash IS NOT NULL AND eligible = 1').get().count, 1);
  } finally { completeHistory.close(); completeCache.close(); }
});

test('completed exact bind replay at exhausted cache capacity awaits history validation before key disposal', async (t) => {
  const f = await fixture(t, { cache: { maxEntries: 1, maxOutboxEntries: 2 } });
  await createSeed(f);
  const input = { idempotencyKey: 'completed-bind-replay-at-capacity', profile: cacheProfile() };
  const original = await f.store.bindPrivateProfile(f.scope, EVENT_ID, input, f.authRequest);
  assert.equal(original.status, 'bound');

  const cache = new DatabaseSync(cacheDatabasePath(f.root));
  const history = new DatabaseSync(historyDatabasePath(f.root));
  let beforeCounts;
  try {
    beforeCounts = {
      entries: cache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count,
      writes: cache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count,
      reservations: cache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count,
      consumers: cache.prepare('SELECT COUNT(*) AS count FROM reuse_consumer_refs').get().count,
      observations: cache.prepare('SELECT COUNT(*) AS count FROM reuse_observations').get().count,
      outbox: cache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count,
      operations: history.prepare("SELECT COUNT(*) AS count FROM correction_cache_operations WHERE kind = 'bind'").get().count,
      references: history.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count,
      bindings: history.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count,
    };
    assert.deepEqual(beforeCounts, { entries: 1, writes: 1, reservations: 1, consumers: 1,
      observations: 1, outbox: 0, operations: 1, references: 1, bindings: 1 });
  } finally { cache.close(); history.close(); }

  const events = [];
  const prepareDescriptor = Object.getOwnPropertyDescriptor(DatabaseSync.prototype, 'prepare');
  const fillDescriptor = Object.getOwnPropertyDescriptor(Buffer.prototype, 'fill');
  let restored = false;
  const restore = () => {
    if (restored) return;
    restored = true;
    Object.defineProperty(DatabaseSync.prototype, 'prepare', prepareDescriptor);
    Object.defineProperty(Buffer.prototype, 'fill', fillDescriptor);
  };
  t.after(restore);
  Object.defineProperty(DatabaseSync.prototype, 'prepare', {
    ...prepareDescriptor,
    value(sql, ...args) {
      const stack = new Error().stack ?? '';
      if (String(sql).includes('SELECT * FROM correction_cache_bindings WHERE event_key')
        && stack.includes('bindingRows')) events.push('binding-row-query');
      return Reflect.apply(prepareDescriptor.value, this, [sql, ...args]);
    },
  });
  Object.defineProperty(Buffer.prototype, 'fill', {
    ...fillDescriptor,
    value(...args) {
      if ((new Error().stack ?? '').includes('disposeBindingContext')) events.push('context-index-key-zeroized');
      return Reflect.apply(fillDescriptor.value, this, args);
    },
  });

  const reopened = f.makeStore();
  const scope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
  const replay = await reopened.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest);
  assert.equal(replay.status, 'bound');
  assert.equal(replay.replayed, true);
  assert.ok(events.includes('binding-row-query'), `binding row query was observed: ${events}`);
  assert.ok(events.includes('context-index-key-zeroized'), `context key disposal was observed: ${events}`);
  assert.ok(events.indexOf('binding-row-query') < events.indexOf('context-index-key-zeroized'),
    `HMAC-backed row validation must finish before key zeroization: ${events}`);

  await assert.rejects(reopened.bindPrivateProfile(scope, EVENT_ID, {
    idempotencyKey: 'new-bind-must-fail-at-exhausted-capacity',
    profile: cacheProfile({ identity: Object.freeze({ ...IDENTITY, occurrenceId: 'new-bind-capacity-entry' }) }),
  }, f.authRequest), (error) => error?.code === 'REUSE_CAPACITY');

  const finalCache = new DatabaseSync(cacheDatabasePath(f.root));
  const finalHistory = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.deepEqual({
      entries: finalCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count,
      writes: finalCache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count,
      reservations: finalCache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count,
      consumers: finalCache.prepare('SELECT COUNT(*) AS count FROM reuse_consumer_refs').get().count,
      observations: finalCache.prepare('SELECT COUNT(*) AS count FROM reuse_observations').get().count,
      outbox: finalCache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count,
      operations: finalHistory.prepare("SELECT COUNT(*) AS count FROM correction_cache_operations WHERE kind = 'bind'").get().count,
      references: finalHistory.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count,
      bindings: finalHistory.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count,
    }, beforeCounts);
  } finally { finalCache.close(); finalHistory.close(); }
});

test('exact bind replay preserves original freshness and hard expiry after elapsed time', async (t) => {
  for (const phase of ['complete', 'pending']) {
    await t.test(`${phase} receipt`, async (subtest) => {
      let f;
      let denyReference = false;
      let observationCalls = 0;
      f = await fixture(subtest, {
        cache: {
          verifySourceObservation({ expectedContentHash }) {
            observationCalls += 1;
            return { status: 'body_changed', contentHash: expectedContentHash,
              retrievedAt: new Date(EPOCH - 1_000).toISOString(),
              validatedAt: new Date(EPOCH).toISOString(), attemptLineage: { status: 'unknown' } };
          },
        },
        history: {
          authorizeBoundary(input) {
            if (denyReference && input.action === 'review.history.cache_bind_reference') {
              denyReference = false;
              return false;
            }
            const allowed = input.request?.serverContextToken === TRUSTED_TOKEN
              && input.request?.principal?.tenantId === input.tenantId
              && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
            return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
              eventId: input.eventId, action: input.action, field: input.field, nowMs: f.clock.value }) : false;
          },
        },
      });
      const seeded = await createSeed(f);
      const input = { idempotencyKey: `elapsed-bind-replay-${phase}`, profile: cacheProfile() };
      if (phase === 'pending') {
        denyReference = true;
        await assert.rejects(f.store.bindPrivateProfile(f.scope, EVENT_ID, input, f.authRequest),
          (error) => error?.code === 'REVIEW_DENIED');
      } else {
        const bound = await f.store.bindPrivateProfile(f.scope, EVENT_ID, input, f.authRequest);
        assert.equal(bound.status, 'bound');
      }
      assert.equal(observationCalls, 1);
      const cacheBeforeReplay = boundCacheRows(f.root);

      f.clock.value = EPOCH + 16_000;
      const reopened = f.makeStore();
      const scope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
      const replay = await reopened.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest);
      assert.equal(replay.status, 'bound');
      assert.equal(replay.replayed, true);
      assert.equal(replay.historyVersionId, seeded.snapshot.versionId);
      assert.equal(replay.expiresAt, new Date(EPOCH + 45_000).toISOString());
      assert.equal(observationCalls, 1, 'an exact receipt replay does not replace the original source observation');
      assert.deepEqual(boundCacheRows(f.root), cacheBeforeReplay,
        'completed replay and pending recovery do not allocate cache rows or change the captured freshness deadline');

      f.clock.value = EPOCH + 31_000;
      const staleReplay = await reopened.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest);
      assert.equal(staleReplay.status, 'bound');
      assert.equal(staleReplay.replayed, true);
      assert.equal(staleReplay.expiresAt, new Date(EPOCH + 45_000).toISOString(),
        'metadata replay keeps the original absolute expiry after freshness has elapsed');
      assert.equal(Object.hasOwn(staleReplay, 'facts'), false);
      const staleProfile = await reopened.getPrivateProfile(scope, EVENT_ID, f.authRequest, lookup());
      assert.equal(staleProfile.status, 'stale');
      assert.equal(staleProfile.reason, 'ttl_expired');
      assert.equal(Object.hasOwn(staleProfile, 'facts'), false,
        'ordinary lookup does not disclose stale facts or renew freshness');
      assert.equal(observationCalls, 1);

      const cacheBeforeHardExpiry = boundCacheRows(f.root);
      f.clock.value = EPOCH + 45_000;
      await assert.rejects(reopened.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest),
        (error) => error?.code === 'REUSE_POLICY_UNAVAILABLE');
      assert.deepEqual(boundCacheRows(f.root), cacheBeforeHardExpiry,
        'hard-expired replay fails closed without recreating or rewriting the original cache effect');
    });
  }
});

test('exact bound replay uses retained envelope keys after payload-key rotation', async (t) => {
  for (const phase of ['complete', 'pending']) {
    await t.test(`${phase} receipt`, async (subtest) => {
      const originalKeyId = 'r11-bind-key';
      const rotatedKeyId = '\u0000'.repeat(128);
      const originalKey = createHash('sha256').update('r11 retained bound payload key').digest();
      const rotatedKey = createHash('sha256').update('r11 unrelated current payload key').digest();
      let f;
      let denyReference = false;
      let activeKeyId = originalKeyId;
      let originalAvailable = true;
      let consumerResolutionCalls = 0;
      let observationCalls = 0;
      f = await fixture(subtest, {
        cache: {
          resolveInvalidationConsumers() {
            consumerResolutionCalls += 1;
            return ['é'.repeat(300)];
          },
          resolveKey({ tenantId, scope, purpose, keyId }) {
            if (purpose === 'payload') {
              const resolvedId = keyId ?? activeKeyId;
              if (resolvedId === originalKeyId && originalAvailable) return { keyId: originalKeyId, key: Buffer.from(originalKey) };
              if (resolvedId === rotatedKeyId) return { keyId: rotatedKeyId, key: Buffer.from(rotatedKey) };
              throw new Error('synthetic retained payload key unavailable');
            }
            const resolvedId = `${scope}:${purpose}:${tenantId ?? 'global'}:v1`;
            if (keyId && keyId !== resolvedId) throw new Error('synthetic non-payload key unavailable');
            return { keyId: resolvedId,
              key: createHash('sha256').update(`${tenantId}:${scope}:${purpose}:r11-cache-key`).digest() };
          },
          verifySourceObservation({ expectedContentHash }) {
            observationCalls += 1;
            return { status: 'body_changed', contentHash: expectedContentHash,
              retrievedAt: new Date(EPOCH - 1_000).toISOString(),
              validatedAt: new Date(EPOCH).toISOString(), attemptLineage: { status: 'unknown' } };
          },
        },
        history: {
          authorizeBoundary(input) {
            if (denyReference && input.action === 'review.history.cache_bind_reference') {
              denyReference = false;
              return false;
            }
            const allowed = input.request?.serverContextToken === TRUSTED_TOKEN
              && input.request?.principal?.tenantId === input.tenantId
              && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
            return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
              eventId: input.eventId, action: input.action, field: input.field, nowMs: f.clock.value }) : false;
          },
        },
      });
      await createSeed(f);
      const input = { idempotencyKey: `rotated-bound-replay-${phase}`, profile: cacheProfile() };
      if (phase === 'pending') {
        denyReference = true;
        await assert.rejects(f.store.bindPrivateProfile(f.scope, EVENT_ID, input, f.authRequest),
          (error) => error?.code === 'REVIEW_DENIED');
      } else {
        assert.equal((await f.store.bindPrivateProfile(f.scope, EVENT_ID, input, f.authRequest)).status, 'bound');
      }
      assert.equal(consumerResolutionCalls, 1);
      assert.equal(observationCalls, 1);
      const rowsBeforeReplay = boundCacheRows(f.root);

      activeKeyId = rotatedKeyId;
      const reopened = f.makeStore();
      const scope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
      const replay = await reopened.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest);
      assert.equal(replay.status, 'bound');
      assert.equal(replay.replayed, true);
      assert.equal(consumerResolutionCalls, 1, 'replay does not resolve or size a new consumer envelope');
      assert.equal(observationCalls, 1, 'replay does not replace the stored observation');
      assert.deepEqual(boundCacheRows(f.root), rowsBeforeReplay,
        'the retained receipt is read under its recorded key without a new cache envelope or allocation');

      originalAvailable = false;
      const rowsBeforeMissingKey = boundCacheRows(f.root);
      await assert.rejects(reopened.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest),
        (error) => error?.code === 'REUSE_KEY_UNAVAILABLE');
      assert.deepEqual(boundCacheRows(f.root), rowsBeforeMissingKey,
        'loss of the retained key fails closed without falling back to the new current key');
      originalAvailable = true;
      assert.equal((await reopened.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest)).replayed, true);
    });
  }
});

test('exact replay preserves an omitted TTL default and rejects changed replay inputs', async (t) => {
  let observationCalls = 0;
  const f = await fixture(t, {
    cache: {
      defaultFreshnessTtlMs: 30_000,
      verifySourceObservation({ expectedContentHash }) {
        observationCalls += 1;
        return { status: 'body_changed', contentHash: expectedContentHash,
          retrievedAt: new Date(EPOCH - 1_000).toISOString(),
          validatedAt: new Date(EPOCH).toISOString(), attemptLineage: { status: 'unknown' } };
      },
    },
  });
  await createSeed(f);
  const profile = { ...cacheProfile() };
  delete profile.freshnessTtlMs;
  const input = { idempotencyKey: 'omitted-ttl-default-replay', profile };
  const original = await f.store.bindPrivateProfile(f.scope, EVENT_ID, input, f.authRequest);
  assert.equal(original.status, 'bound');
  assert.equal(observationCalls, 1);
  const rowsBeforeReplay = boundCacheRows(f.root);

  f.cacheOptions.defaultFreshnessTtlMs = 40_000;
  f.clock.value = EPOCH + 16_000;
  const reopened = f.makeStore();
  const scope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
  const replay = await reopened.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest);
  assert.equal(replay.replayed, true);
  assert.equal(replay.expiresAt, new Date(EPOCH + 45_000).toISOString());
  assert.equal(observationCalls, 1, 'receipt replay does not consult a changed default or re-run validation');
  assert.deepEqual(boundCacheRows(f.root), rowsBeforeReplay);

  const changedTtl = { ...cacheProfile(), freshnessTtlMs: 29_000 };
  await assert.rejects(reopened.bindPrivateProfile(scope, EVENT_ID,
    { idempotencyKey: input.idempotencyKey, profile: changedTtl }, f.authRequest),
  (error) => error?.code === 'REVIEW_IDEMPOTENCY_CONFLICT');
  const changedObservation = { ...profile, observation: { source: 'different caller observation' } };
  await assert.rejects(reopened.bindPrivateProfile(scope, EVENT_ID,
    { idempotencyKey: input.idempotencyKey, profile: changedObservation }, f.authRequest),
  (error) => error?.code === 'REVIEW_IDEMPOTENCY_CONFLICT');
  assert.equal(observationCalls, 1);
  assert.deepEqual(boundCacheRows(f.root), rowsBeforeReplay,
    'changed TTL or observation inputs cannot overwrite the original receipt or freshness window');

  f.clock.value = EPOCH + 31_000;
  const stale = await reopened.getPrivateProfile(scope, EVENT_ID, f.authRequest, lookup());
  assert.equal(stale.status, 'stale');
  assert.equal(stale.reason, 'ttl_expired');
  assert.equal(Object.hasOwn(stale, 'facts'), false);
});

test('completed exact bind replay rechecks authority, head, abort, and cache proof after awaited key resolution', async (t) => {
  for (const scenario of ['history authority', 'history head', 'cache proof', 'abort']) {
    await t.test(scenario, async (subtest) => {
      let f;
      let historyAllowed = true;
      let armed = false;
      let resolverReached = 0;
      let mutation;
      let rowsAfterMutation;
      let tamperCacheAtFinalGuard = false;
      const controller = new AbortController();
      const baseHistory = ({ tenantId, actorId, action, request: value }) => value?.serverContextToken === TRUSTED_TOKEN
        && value?.principal?.tenantId === tenantId && value?.principal?.actorId === actorId && actorId !== 'outsider';
      const historyOptions = {
        authorizeBoundary(input) {
          if (tamperCacheAtFinalGuard && input.action === 'private_profile.read') {
            tamperCacheAtFinalGuard = false;
            const historyDatabase = new DatabaseSync(historyDatabasePath(f.root));
            const cacheDatabase = new DatabaseSync(cacheDatabasePath(f.root));
            try {
              historyDatabase.exec('BEGIN IMMEDIATE');
              historyDatabase.exec('ROLLBACK');
              cacheDatabase.prepare('UPDATE reuse_entries SET eligible = 0 WHERE binding_hash IS NOT NULL').run();
            } finally { historyDatabase.close(); cacheDatabase.close(); }
            rowsAfterMutation = boundCacheRows(f.root);
          }
          if (!historyAllowed) return false;
          const allowed = baseHistory({ tenantId: input.tenantId, actorId: input.actorId, request: input.request });
          return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
            eventId: input.eventId, action: input.action, field: input.field, nowMs: f.clock.value }) : false;
        },
      };
      f = await fixture(subtest, { history: historyOptions });
      const originalHistoryResolver = f.historyOptions.resolveKey;
      f.historyOptions.resolveKey = async (input) => {
        const value = originalHistoryResolver(input);
        if (armed && input.purpose === 'correction_payload' && input.keyId) {
          resolverReached += 1;
          if (resolverReached === 2) {
            armed = false;
            if (scenario === 'cache proof') tamperCacheAtFinalGuard = true;
            await mutation();
          }
        }
        return value;
      };
      const store = f.makeStore();
      const scope = await store.scopeForAuthenticatedRequest(f.authRequest);
      const seeded = await store.createHistory(scope, { eventId: EVENT_ID, sourceFacts: initialFacts(),
        idempotencyKey: 'initialize-late-bound-replay', retentionHandle: f.createPermit() }, f.authRequest);
      const input = { idempotencyKey: `late-bound-replay-${scenario.replaceAll(' ', '-')}`, profile: cacheProfile() };
      await store.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest);
      const rowsBeforeReplay = boundCacheRows(f.root);
      mutation = async () => {
        if (scenario === 'history authority') historyAllowed = false;
        else if (scenario === 'abort') controller.abort();
        else await store.applyCorrection(scope, {
          eventId: EVENT_ID,
          baseVersionId: seeded.snapshot.versionId,
          baseContentHash: seeded.snapshot.contentHash,
          field: 'event_date',
          value: { precision: 'date', value: '2027-06-30' },
          idempotencyKey: 'late-bound-replay-head-advance',
          retentionHandle: f.createPermit(),
        }, f.authRequest);
        if (scenario === 'history head') rowsAfterMutation = boundCacheRows(f.root);
      };
      if (scenario === 'cache proof') mutation = async () => {};
      armed = true;
      const callOptions = scenario === 'abort' ? { signal: controller.signal } : undefined;
      await assert.rejects(store.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest, callOptions),
        (error) => scenario === 'abort'
          ? error?.code === 'REVIEW_ABORTED'
          : scenario === 'history authority'
            ? error?.code === 'REVIEW_DENIED'
            : scenario === 'history head'
              ? ['REUSE_INTEGRITY', 'REVIEW_VERSION_CONFLICT', 'REVIEW_BUSY'].includes(error?.code)
              : scenario === 'cache proof'
                ? ['REUSE_BUSY', 'REUSE_INTEGRITY', 'REUSE_POLICY_UNAVAILABLE', 'REVIEW_VERSION_CONFLICT'].includes(error?.code)
                : false);
      assert.equal(resolverReached, 2, 'the controlled change occurs during the second recorded binding-key resolution');
      assert.deepEqual(boundCacheRows(f.root), rowsAfterMutation ?? rowsBeforeReplay,
        'late denial or abort does not allocate a second cache effect');
      if (scenario === 'history head') {
        assert.equal((await store.getHistory(scope, EVENT_ID, f.authRequest)).revision, 2);
        assert.deepEqual(await store.getPrivateProfile(scope, EVENT_ID, f.authRequest, lookup()), { status: 'miss' });
      } else if (scenario !== 'cache proof') {
        if (scenario === 'history authority') historyAllowed = true;
        const replay = await store.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest);
        assert.equal(replay.status, 'bound');
        assert.equal(replay.replayed, true);
        assert.deepEqual(boundCacheRows(f.root), rowsBeforeReplay);
      }
    });
  }
});

test('composed correction waits out a real cross-process SQLite writer lock', async (t) => {
  const f = await fixture(t);
  const seeded = await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-cross-process-writer', profile: cacheProfile() }, f.authRequest);
  const marker = path.join(f.root, 'cross-process-ready');
  const database = new DatabaseSync(historyDatabasePath(f.root));
  database.exec('PRAGMA busy_timeout = 0');
  database.exec('BEGIN IMMEDIATE');
  let locked = true;
  const release = () => {
    if (!locked) return;
    locked = false;
    database.exec('ROLLBACK');
    database.close();
  };
  t.after(release);
  const worker = runWorker(['compete', f.root, EVENT_ID, seeded.snapshot.versionId,
    seeded.snapshot.contentHash, marker, 'correction-cross-process-writer']);
  t.after(() => { if (worker.child.exitCode === null && worker.child.signalCode === null) worker.child.kill('SIGKILL'); });
  await waitForFile(marker);
  await new Promise((resolve) => setTimeout(resolve, 30));
  release();
  const processResult = await worker.exit;
  assert.equal(processResult.signal, null, processResult.stderr);
  assert.equal(processResult.code, 0, processResult.stderr);
  assert.deepEqual(JSON.parse(processResult.stdout), { outcome: 'committed', revision: 2 });
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup())).status, 'miss');
});

test('refreshSources invalidates the exact cache binding even when source alternatives are retained', async (t) => {
  const f = await fixture(t);
  const seeded = await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-source-refresh', profile: cacheProfile() }, f.authRequest);
  const refreshed = await f.store.refreshSources(f.scope, {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    sourceFacts: { event_name: { status: 'sourced', value: 'Lantern Evening', sourceEvidence: [sourceEvidence('name-refresh', 'Lantern Evening')] } },
    idempotencyKey: 'refresh-source-binding',
    retentionHandle: f.createPermit(),
  }, f.authRequest);
  assert.equal(refreshed.snapshot.revision, seeded.snapshot.revision + 1);
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup())).status, 'miss');
  const pending = await f.store.outboxSnapshot(f.scope, f.authRequest);
  assert.equal(pending.readiness, 'blocked_pending_external_ack');
  assert.equal(pending.pending > 0, true);
});

test('deterministic outbox capacity preflight leaves no operation barrier and retry succeeds after capacity is restored', async (t) => {
  const f = await fixture(t, { cache: { maxOutboxEntries: 1 } });
  const seeded = await createSeed(f);
  const input = { idempotencyKey: 'bind-capacity-retry', profile: cacheProfile() };
  await assert.rejects(f.store.bindPrivateProfile(f.scope, EVENT_ID, input, f.authRequest),
    (error) => error?.code === 'REUSE_CAPACITY');
  assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).versionId, seeded.snapshot.versionId);
  const history = new DatabaseSync(historyDatabasePath(f.root));
  const cache = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(history.prepare("SELECT COUNT(*) AS count FROM correction_cache_operations WHERE kind = 'bind'").get().count, 0);
    assert.equal(history.prepare("SELECT COUNT(*) AS count FROM correction_cache_state WHERE phase != 'complete'").get().count, 0);
    assert.equal(cache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count, 0);
    assert.equal(cache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 0);
    assert.equal(cache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 0);
  } finally { history.close(); cache.close(); }
  f.cacheOptions.maxOutboxEntries = 8;
  const reopened = f.makeStore();
  const scope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
  const bound = await reopened.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest);
  assert.equal(bound.status, 'bound');
  assert.equal((await reopened.getPrivateProfile(scope, EVENT_ID, f.authRequest, lookup())).status, 'hit');
});

test('pending bind fence checks history expiry after the paired cache commit and exact retry reconciles', async (t) => {
  let f;
  let armed = false;
  let cacheBoundaryReached = false;
  let cacheCommitCompleted = false;
  let historyCommitAttempted = false;
  f = await fixture(t, { cache: {
    authorizeBoundary(input) {
      if (armed && input.action === 'cache.private_profile.bind') cacheBoundaryReached = true;
      const allowed = input.request?.serverContextToken === TRUSTED_TOKEN
        && input.request?.principal?.tenantId === input.tenantId
        && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
      return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
        eventId: input.eventId, action: input.action, field: input.field, nowMs: f.clock.value }) : false;
    },
  } });
  await createSeed(f);
  f.clock.value = EPOCH + 59_000;
  const bindingInput = { idempotencyKey: 'pending-bind-fence-expiry',
    profile: cacheProfile({ expiresAtMs: EPOCH + 120_000, freshnessTtlMs: 500 }) };

  const databaseKinds = new WeakMap();
  const prepareDescriptor = Object.getOwnPropertyDescriptor(DatabaseSync.prototype, 'prepare');
  const execDescriptor = Object.getOwnPropertyDescriptor(DatabaseSync.prototype, 'exec');
  let restored = false;
  Object.defineProperty(DatabaseSync.prototype, 'prepare', {
    ...prepareDescriptor,
    value(sql, ...args) {
      const statement = Reflect.apply(prepareDescriptor.value, this, [sql, ...args]);
      const query = String(sql);
      if (/correction_cache_(?:state|meta|bindings)|\bFROM heads\b/.test(query)) databaseKinds.set(this, 'history');
      else if (/\breuse_(?:meta|entries|bound_writes|correction_reservations)\b/.test(query)) databaseKinds.set(this, 'cache');
      return statement;
    },
  });
  Object.defineProperty(DatabaseSync.prototype, 'exec', {
    ...execDescriptor,
    value(sql, ...args) {
      if (armed && sql === 'COMMIT' && databaseKinds.get(this) === 'cache'
        && cacheBoundaryReached && !cacheCommitCompleted) {
        const result = Reflect.apply(execDescriptor.value, this, [sql, ...args]);
        cacheCommitCompleted = true;
        const deadline = process.hrtime.bigint() + 1_100_000_000n;
        while (process.hrtime.bigint() < deadline) { /* Cache committed; let the pending history head expire before its paired COMMIT. */ }
        return result;
      }
      if (armed && sql === 'COMMIT' && databaseKinds.get(this) === 'history' && cacheCommitCompleted) {
        historyCommitAttempted = true;
      }
      return Reflect.apply(execDescriptor.value, this, [sql, ...args]);
    },
  });
  const restore = () => {
    if (restored) return;
    restored = true;
    Object.defineProperty(DatabaseSync.prototype, 'prepare', prepareDescriptor);
    Object.defineProperty(DatabaseSync.prototype, 'exec', execDescriptor);
  };
  t.after(restore);
  armed = true;
  let firstAttemptError;
  try {
    try { await f.store.bindPrivateProfile(f.scope, EVENT_ID, bindingInput, f.authRequest); }
    catch (error) { firstAttemptError = error; }
  } finally { restore(); }

  assert.equal(cacheBoundaryReached, true,
    `the exact cache participant guard ran; first error ${firstAttemptError?.code ?? 'success'}`);
  assert.equal(cacheCommitCompleted, true, 'the paired cache transaction committed before history fence validation');
  assert.equal(historyCommitAttempted, false, 'pending-bind expiry prevented the paired history COMMIT');
  const history = new DatabaseSync(historyDatabasePath(f.root));
  const cache = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(history.prepare("SELECT phase FROM correction_cache_state WHERE kind = 'bind'").get().phase, 'pending_bind');
    assert.equal(history.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 0);
    assert.equal(cache.prepare("SELECT COUNT(*) AS count FROM reuse_entries WHERE scope_kind = 'tenant_private'").get().count, 1);
    assert.equal(cache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count, 1);
  } finally { history.close(); cache.close(); }
  await assert.rejects(f.store.getHistory(f.scope, EVENT_ID, f.authRequest),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_BUSY');

  const retried = await f.store.bindPrivateProfile(f.scope, EVENT_ID, bindingInput, f.authRequest);
  assert.equal(retried.status, 'bound');
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup())).status, 'hit');
  const finalHistory = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.equal(finalHistory.prepare('SELECT phase FROM correction_cache_state WHERE kind = \'bind\'').get().phase, 'complete');
    assert.equal(finalHistory.prepare('SELECT COUNT(*) AS count FROM correction_cache_operations').get().count, 1);
    assert.equal(finalHistory.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 1);
  } finally { finalHistory.close(); }
  const finalCache = new DatabaseSync(cacheDatabasePath(f.root));
  try { assert.equal(finalCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count, 1); }
  finally { finalCache.close(); }
});

test('timed-out binding callback cannot commit after an exact retry advances the fence', async (t) => {
  let observationCalls = 0;
  let initialRequest;
  let resolveObservationStarted;
  let releaseFirstObservation;
  let resolveOldContinuation;
  let oldObservationReleased = false;
  const observationStarted = new Promise((resolve) => { resolveObservationStarted = resolve; });
  const firstObservation = new Promise((resolve) => { releaseFirstObservation = resolve; });
  const oldContinuation = new Promise((resolve) => { resolveOldContinuation = resolve; });
  t.after(() => releaseFirstObservation());
  const f = await fixture(t, { operationTimeoutMs: 500, cache: {
    async verifySourceObservation({ expectedContentHash, request: value }) {
      observationCalls += 1;
      if (observationCalls === 1) {
        resolveObservationStarted();
        await firstObservation;
        oldObservationReleased = true;
      }
      return { status: 'body_changed', contentHash: expectedContentHash,
        retrievedAt: new Date(EPOCH - 1_000).toISOString(), validatedAt: new Date(EPOCH).toISOString(),
        attemptLineage: { status: 'unknown' } };
    },
    authorizeAction({ request: value }) {
      if (value === initialRequest && oldObservationReleased) resolveOldContinuation();
      return value?.serverContextToken === TRUSTED_TOKEN && value?.principal?.tenantId === 'tenant-binding'
        && value?.principal?.actorId === 'actor-binding';
    },
  } });
  await createSeed(f);
  initialRequest = f.authRequest;
  const idempotencyKey = 'bind-late-observation';
  const input = { idempotencyKey, profile: cacheProfile() };
  const initialAttempt = f.store.bindPrivateProfile(f.scope, EVENT_ID, input, f.authRequest);
  const initialRejection = assert.rejects(initialAttempt,
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_ABORTED');
  await waitForSignal(observationStarted, 'first private source observation callback');
  await withPhase('first timed-out bind rejection', initialRejection);

  // The 500ms deadline is the intentional first-attempt fault. Exact recovery gets a
  // separate bounded budget so host scheduling does not turn recovery into a second timeout.
  const recoveryStore = f.makeStore(2_000);
  const recoveryScope = await recoveryStore.scopeForAuthenticatedRequest(request());
  const retried = await withPhase('exact retry bind', recoveryStore.bindPrivateProfile(recoveryScope, EVENT_ID, input, request()));
  assert.equal(retried.status, 'bound');
  releaseFirstObservation();
  await withPhase('late callback continuation guard', waitForSignal(oldContinuation, 'late callback continuation guard'));
  const finalRead = await withPhase('read after late callback', recoveryStore.getPrivateProfile(recoveryScope, EVENT_ID, request(), lookup()));
  assert.equal(finalRead.status, 'hit');
  const database = new DatabaseSync(path.join(f.root, 'cache', 'scoped-reuse.sqlite'));
  try {
    assert.equal(database.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count, 1);
    assert.equal(database.prepare('SELECT COUNT(*) AS count FROM reuse_entries WHERE eligible = 1').get().count, 1);
  } finally { database.close(); }
});

test('cancelled correction callback cannot commit after an exact retry takes over the history fence', async (t) => {
  let f;
  let setupObservationCalls = 0;
  let resolveSetupObservationEntered;
  let releaseSetupObservation;
  const setupObservationEntered = new Promise((resolve) => { resolveSetupObservationEntered = resolve; });
  const setupObservationGate = new Promise((resolve) => { releaseSetupObservation = resolve; });
  t.after(() => releaseSetupObservation());
  let blockFirstPostBarrierAuthorization = false;
  let blockedAuthorization = false;
  let blockedFenceAtEntry;
  let pendingPhaseAtEntry;
  let releaseBlockedAuthorization;
  let resolveBlockedEntry;
  let resolveBlockedCompletion;
  const blockedEntry = new Promise((resolve) => { resolveBlockedEntry = resolve; });
  const blockedCompletion = new Promise((resolve) => { resolveBlockedCompletion = resolve; });
  const pendingCorrection = () => {
    if (!f) return null;
    const database = new DatabaseSync(historyDatabasePath(f.root));
    try {
      return database.prepare("SELECT phase, fence FROM correction_cache_state WHERE kind = 'correction'").get() ?? null;
    } finally { database.close(); }
  };
  // Setup and final reads have their own bounded budget. Only the deliberately
  // blocked correction below uses the 500ms fault deadline.
  f = await fixture(t, { operationTimeoutMs: 2_000, history: {
    authorize({ tenantId, actorId, action, request: value }) {
      const allowed = value?.serverContextToken === TRUSTED_TOKEN
        && value?.principal?.tenantId === tenantId && value?.principal?.actorId === actorId
        && actorId !== 'outsider';
      const state = action === 'apply_correction' ? pendingCorrection() : null;
      if (allowed && blockFirstPostBarrierAuthorization && !blockedAuthorization
        && state?.phase === 'pending_correction') {
        blockedAuthorization = true;
        pendingPhaseAtEntry = state.phase;
        blockedFenceAtEntry = state.fence;
        resolveBlockedEntry();
        return new Promise((resolve) => {
          releaseBlockedAuthorization = () => {
            resolve(allowed);
            resolveBlockedCompletion();
          };
        });
      }
      return allowed;
    },
  }, cache: {
    async verifySourceObservation({ expectedContentHash }) {
      setupObservationCalls += 1;
      if (setupObservationCalls === 1) {
        resolveSetupObservationEntered();
        await setupObservationGate;
      }
      return { status: 'body_changed', contentHash: expectedContentHash,
        retrievedAt: new Date(EPOCH - 1_000).toISOString(), validatedAt: new Date(EPOCH).toISOString(),
        attemptLineage: { status: 'unknown' } };
    },
  } });
  const seeded = await withPhase('setup create history', createSeed(f));
  const setupBind = withPhase('setup bind private profile', f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-cancelled-correction', profile: cacheProfile() }, f.authRequest));
  // Attach a rejection handler while the deterministic setup gate is held; the
  // actual result is still awaited below and cannot become an unhandled rejection.
  setupBind.catch(() => {});
  await withPhase('setup observation entry', waitForSignal(setupObservationEntered, 'setup source observation'));
  // A legitimate setup callback takes longer than the intentional correction fault.
  // This must not borrow that operation's 500ms deadline.
  await new Promise((resolve) => setTimeout(resolve, 600));
  releaseSetupObservation();
  assert.equal((await setupBind).status, 'bound');
  blockFirstPostBarrierAuthorization = true;
  const input = {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-24' },
    idempotencyKey: 'correction-cancelled-before-inner-commit',
    retentionHandle: f.createPermit(),
  };
  t.after(() => releaseBlockedAuthorization?.());
  const faultStore = f.makeStore(500);
  const faultScope = await withPhase('authenticate faulted correction scope', faultStore.scopeForAuthenticatedRequest(f.authRequest));
  const firstAttempt = faultStore.applyCorrection(faultScope, input, f.authRequest);
  const rejected = assert.rejects(firstAttempt,
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_ABORTED');
  await withPhase('post-barrier correction authorization entry', waitForSignal(blockedEntry, 'post-barrier correction authorization'));
  assert.equal(blockedAuthorization, true);
  assert.equal(pendingPhaseAtEntry, 'pending_correction');
  await withPhase('intentional correction deadline rejection', rejected);
  const readWorker = runWorker(['read-history', f.root, EVENT_ID]);
  const readResult = await withPhase('read history barrier in restarted worker', readWorker.exit);
  assert.equal(readResult.signal, null, readResult.stderr);
  assert.equal(readResult.code, 0, readResult.stderr);
  assert.deepEqual(JSON.parse(readResult.stdout), { outcome: 'error', code: 'REVIEW_BUSY' });

  blockFirstPostBarrierAuthorization = false;
  const recoveryWorker = runWorker(['retry-correction', f.root, EVENT_ID,
    seeded.snapshot.versionId, seeded.snapshot.contentHash, '', input.idempotencyKey]);
  const recoveryResult = await withPhase('exact correction retry in restarted worker', recoveryWorker.exit);
  assert.equal(recoveryResult.signal, null, recoveryResult.stderr);
  assert.equal(recoveryResult.code, 0, recoveryResult.stderr);
  assert.deepEqual(JSON.parse(recoveryResult.stdout), { outcome: 'committed', revision: seeded.snapshot.revision + 1 });
  const recoveredState = pendingCorrection();
  assert.equal(recoveredState?.phase, 'complete');
  assert.ok(recoveredState.fence > blockedFenceAtEntry);
  releaseBlockedAuthorization();
  await withPhase('late post-barrier authorization completion', waitForSignal(blockedCompletion, 'late post-barrier authorization callback completion'));
  await new Promise((resolve) => setTimeout(resolve, 30));

  const history = new DatabaseSync(historyDatabasePath(f.root));
  const cache = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    const head = history.prepare('SELECT revision, version_id FROM heads LIMIT 1').get();
    assert.equal(head.revision, seeded.snapshot.revision + 1);
    assert.equal(history.prepare('SELECT COUNT(*) AS count FROM versions').get().count, seeded.snapshot.revision + 1);
    assert.equal(history.prepare('SELECT COUNT(*) AS count FROM correction_cache_operations WHERE target_version_id IS NOT NULL').get().count, 2);
    assert.equal(cache.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count, 1);
    assert.equal(cache.prepare("SELECT COUNT(*) AS count FROM reuse_outbox WHERE status != 'delivered'").get().count, 1);
  } finally { history.close(); cache.close(); }
  const finalRead = await withPhase('read after late correction callback', f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()));
  assert.equal(finalRead.status, 'miss');
});

for (const mode of ['abort during participant key preparation', 'abort from final bind guard']) {
  test(`late bind cancellation preserves the cache receipt and resumes by exact retry (${mode})`, async (t) => {
    const controller = new AbortController();
    let reached;
    let releaseKey;
    let resolveKeyEntered;
    let resolveLateContinuation;
    const keyEntered = new Promise((resolve) => { resolveKeyEntered = resolve; });
    const keyGate = new Promise((resolve) => { releaseKey = resolve; });
    const lateContinuation = new Promise((resolve) => { resolveLateContinuation = resolve; });
    const f = await fixture(t);
    await createSeed(f);
    const originalResolveKey = f.historyOptions.resolveKey;
    const originalBoundary = f.historyOptions.authorizeBoundary;
    const originalAuthorize = f.historyOptions.authorize;
    let participantAuthorizationCalls = 0;
    let authorizationCallsAtKey = null;
    let lateParticipantAuthorizationReached = false;
    let lateBindBoundaryReached = false;
    f.historyOptions.authorize = async (input) => {
      if (input.action === 'record_downstream_reference') participantAuthorizationCalls += 1;
      return originalAuthorize(input);
    };
    if (mode === 'abort during participant key preparation') {
      f.historyOptions.resolveKey = async (input) => {
        const resolved = originalResolveKey(input);
        if (input.purpose === 'correction_payload' && !input.keyId && !reached) {
          reached = true;
          authorizationCallsAtKey = participantAuthorizationCalls;
          resolveKeyEntered();
          await keyGate;
          resolveLateContinuation();
        }
        return resolved;
      };
      f.historyOptions.authorizeBoundary = (input) => {
        if (input.action === 'review.history.cache_bind_reference') lateBindBoundaryReached = true;
        return originalBoundary(input);
      };
    } else {
      f.historyOptions.authorizeBoundary = (input) => {
        const permit = originalBoundary(input);
        if (input.action === 'review.history.cache_bind_reference') {
          reached = true;
          controller.abort();
        }
        return permit;
      };
    }
    t.after(() => releaseKey?.());
    const store = f.makeStore(5_000);
    const scope = await store.scopeForAuthenticatedRequest(f.authRequest);
    const input = { idempotencyKey: `late-bind-recovery-${mode.replaceAll(' ', '-')}`, profile: cacheProfile() };
    const attempt = store.bindPrivateProfile(scope, EVENT_ID, input, f.authRequest, { signal: controller.signal });
    if (mode === 'abort during participant key preparation') {
      await waitForSignal(keyEntered, 'post-cache history payload-key resolution');
      const beforeAbortHistory = new DatabaseSync(historyDatabasePath(f.root));
      const beforeAbortCache = new DatabaseSync(cacheDatabasePath(f.root));
      try {
        assert.equal(beforeAbortHistory.prepare("SELECT phase FROM correction_cache_state WHERE kind = 'bind'").get().phase,
          'pending_bind');
        assert.equal(beforeAbortCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count, 1);
        assert.equal(beforeAbortCache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count, 1);
      } finally { beforeAbortHistory.close(); beforeAbortCache.close(); }
      controller.abort();
      await assert.rejects(attempt, (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_ABORTED');
      releaseKey();
      await waitForSignal(lateContinuation, 'late history-key continuation after abort');
      await new Promise((resolve) => setImmediate(resolve));
      lateParticipantAuthorizationReached = participantAuthorizationCalls > authorizationCallsAtKey;
      assert.equal(lateParticipantAuthorizationReached, false,
        'the settled key continuation did not enter another participant authorization');
      assert.equal(lateBindBoundaryReached, false,
        'the settled key continuation did not enter the bind-reference transaction boundary');
    } else {
      await assert.rejects(attempt, (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_ABORTED');
      assert.equal(reached, true, 'the abort occurred inside the final synchronous history guard');
    }

    const pendingHistory = new DatabaseSync(historyDatabasePath(f.root));
    const pendingCache = new DatabaseSync(cacheDatabasePath(f.root));
    try {
      assert.equal(pendingHistory.prepare("SELECT phase FROM correction_cache_state WHERE kind = 'bind'").get().phase,
        'pending_bind');
      assert.equal(pendingHistory.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 0);
      assert.equal(pendingHistory.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 0);
      assert.equal(pendingCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count, 1,
        'the cache profile committed before cancellation is retained');
      assert.equal(pendingCache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count, 1,
        'the original cache receipt remains available for exact recovery');
    } finally { pendingHistory.close(); pendingCache.close(); }
    await assert.rejects(store.getHistory(scope, EVENT_ID, f.authRequest),
      (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_BUSY');

    f.historyOptions.resolveKey = originalResolveKey;
    f.historyOptions.authorizeBoundary = originalBoundary;
    f.historyOptions.authorize = originalAuthorize;
    const reopened = f.makeStore(5_000);
    const reopenedScope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
    const recovered = await reopened.bindPrivateProfile(reopenedScope, EVENT_ID, input, f.authRequest);
    assert.equal(recovered.status, 'bound');
    assert.equal(recovered.replayed, true, 'recovery consumes the existing cache receipt');
    const completeHistory = new DatabaseSync(historyDatabasePath(f.root));
    const completeCache = new DatabaseSync(cacheDatabasePath(f.root));
    try {
      assert.equal(completeHistory.prepare("SELECT phase FROM correction_cache_state WHERE kind = 'bind'").get().phase,
        'complete');
      assert.equal(completeHistory.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 1);
      assert.equal(completeHistory.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 1);
      assert.equal(completeCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count, 1);
      assert.equal(completeCache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count, 1);
    } finally { completeHistory.close(); completeCache.close(); }
  });
}

for (const kind of ['correction', 'source_refresh']) {
  for (const markerPhase of ['cache_invalidating', 'complete']) {
    test(`late ${kind} cancellation leaves an exact retry barrier at ${markerPhase}`, async (t) => {
      const controller = new AbortController();
      let markerGuardReached = false;
      let abortAtMarker = true;
      const f = await fixture(t);
      const seeded = await createSeed(f);
      await f.store.bindPrivateProfile(f.scope, EVENT_ID,
        { idempotencyKey: `bind-before-${kind}-${markerPhase}`, profile: cacheProfile() }, f.authRequest);
      const originalBoundary = f.historyOptions.authorizeBoundary;
      f.historyOptions.authorizeBoundary = (input) => {
        const permit = originalBoundary(input);
        if (abortAtMarker && input.action === 'review.history.cache_operation_state'
          && input.details?.phase === markerPhase) {
          markerGuardReached = true;
          controller.abort();
        }
        return permit;
      };
      const store = f.makeStore(5_000);
      const scope = await store.scopeForAuthenticatedRequest(f.authRequest);
      const idempotencyKey = `cancel-${kind}-${markerPhase}`;
      const input = kind === 'correction'
        ? { eventId: EVENT_ID, baseVersionId: seeded.snapshot.versionId,
          baseContentHash: seeded.snapshot.contentHash, field: 'event_date',
          value: { precision: 'date', value: '2027-06-24' }, idempotencyKey,
          retentionHandle: f.createPermit() }
        : { eventId: EVENT_ID, baseVersionId: seeded.snapshot.versionId,
          baseContentHash: seeded.snapshot.contentHash,
          sourceFacts: Object.freeze({ ...initialFacts(), event_name: Object.freeze({ status: 'sourced',
            value: 'Updated Lantern Night', sourceEvidence: [sourceEvidence('updated-event-name', 'Updated Lantern Night')] }) }),
          idempotencyKey,
          retentionHandle: f.createPermit() };
      const attempt = kind === 'correction'
        ? store.applyCorrection(scope, input, f.authRequest, { signal: controller.signal })
        : store.refreshSources(scope, input, f.authRequest, { signal: controller.signal });
      await assert.rejects(attempt, (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_ABORTED');
      assert.equal(markerGuardReached, true, `the ${markerPhase} final guard aborted the real transaction`);

      const pendingHistory = new DatabaseSync(historyDatabasePath(f.root));
      const pendingCache = new DatabaseSync(cacheDatabasePath(f.root));
      let committedRevision;
      try {
        const state = pendingHistory.prepare('SELECT phase, target_version_id FROM correction_cache_state').get();
        assert.ok(['history_committed', 'cache_invalidating'].includes(state.phase));
        assert.ok(state.target_version_id, 'the immutable history revision committed before participant cancellation');
        committedRevision = pendingHistory.prepare('SELECT revision FROM heads').get().revision;
        assert.equal(pendingHistory.prepare('SELECT COUNT(*) AS count FROM versions').get().count, 2,
          'the earlier history commit is preserved, not rolled back');
        const binding = pendingHistory.prepare('SELECT last_invalidation_operation_id FROM correction_cache_bindings').get();
        if (markerPhase === 'cache_invalidating') assert.equal(binding.last_invalidation_operation_id, null,
          'the post-abort history invalidation marker was not written');
        else assert.ok(binding.last_invalidation_operation_id,
          'the invalidation marker committed before cancellation reached finishOperation');
        assert.equal(pendingCache.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count, 1,
          'the cache invalidation receipt committed before cancellation');
        assert.equal(pendingCache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 1,
          'the existing external-delivery work remains exactly once');
      } finally { pendingHistory.close(); pendingCache.close(); }
      await assert.rejects(store.getHistory(scope, EVENT_ID, f.authRequest),
        (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_BUSY');

      abortAtMarker = false;
      const reopened = f.makeStore(5_000);
      const reopenedScope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
      const recovered = kind === 'correction'
        ? await reopened.applyCorrection(reopenedScope, input, f.authRequest)
        : await reopened.refreshSources(reopenedScope, input, f.authRequest);
      assert.equal(recovered.snapshot.revision, committedRevision,
        'exact retry recovers the same immutable revision');
      const completeHistory = new DatabaseSync(historyDatabasePath(f.root));
      const completeCache = new DatabaseSync(cacheDatabasePath(f.root));
      try {
        assert.equal(completeHistory.prepare('SELECT phase FROM correction_cache_state').get().phase, 'complete');
        assert.equal(completeHistory.prepare('SELECT revision FROM heads').get().revision, committedRevision);
        assert.equal(completeHistory.prepare('SELECT COUNT(*) AS count FROM versions').get().count, 2);
        assert.equal(completeCache.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count, 1);
        assert.equal(completeCache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 1,
          'recovery does not duplicate the already committed invalidation event');
      } finally { completeHistory.close(); completeCache.close(); }
    });
  }
}

test('final synchronous boundary permit is current and permission expiry is resampled afterward', async (t) => {
  let authorized = true;
  const f = await fixture(t, {
    authorizeBoundary(input) {
      assert.equal(input.details.permissionValidUntilMs, EPOCH + 500);
      if (!authorized) return false;
      f.clock.value = EPOCH + 500;
      return Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
        eventId: input.eventId, action: input.action, field: input.field, nowMs: f.clock.value });
    },
    cache: {
      verifyPermission({ reference, contentHash, version, use }) {
        return { status: 'valid', reference, contentHash, version, use, validUntilMs: EPOCH + 500 };
      },
    },
  });
  const seeded = await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-final-guard', profile: cacheProfile() }, f.authRequest);
  const expired = await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup());
  assert.deepEqual(expired, { status: 'unavailable', reason: 'expired' });
  assert.equal(Object.hasOwn(expired, 'profileRef'), false);
  f.clock.value = EPOCH;
  authorized = false;
  await assert.rejects(f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_DENIED');
  void seeded;
});

test('final composed cache read denies disclosure when permission expires during synchronous SQLite work', async (t) => {
  let readGuardReached = false;
  const f = await fixture(t, {
    authorizeBoundary(input) {
      if (input.action === 'private_profile.read') readGuardReached = true;
      return input.tenantId === 'tenant-binding'
        && input.request?.serverContextToken === TRUSTED_TOKEN
        && input.request?.principal?.tenantId === input.tenantId
        && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider'
        ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
          eventId: input.eventId, action: input.action, field: input.field, nowMs: EPOCH }) : false;
    },
    cache: { verifyPermission({ reference, contentHash, version, use }) {
      return { status: 'valid', reference, contentHash, version, use, validUntilMs: EPOCH + 60 };
    } },
  });
  await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-final-read-expiry', profile: cacheProfile() }, f.authRequest);

  const interception = interceptFinalBoundRead(() => {
    const deadline = process.hrtime.bigint() + 160_000_000n;
    while (process.hrtime.bigint() < deadline) { /* Exercise the real synchronous SQLite read boundary. */ }
  });
  t.after(interception.restore);
  let result;
  let error;
  try {
    result = await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup());
  } catch (caught) { error = caught; }
  finally { interception.restore(); }
  assert.equal(readGuardReached, true, 'the required final synchronous boundary guard ran');
  assert.equal(interception.reached(), true, 'the delay occurred inside finalBoundRead after the guard');
  assert.notEqual(result?.status, 'hit', `expired permission must not disclose a profile (error ${error?.code ?? 'none'})`);
});

test('final composed cache read honors a genuine abort during synchronous SQLite work', async (t) => {
  const f = await fixture(t);
  await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-final-read-abort', profile: cacheProfile() }, f.authRequest);
  const controller = new AbortController();
  const interception = interceptFinalBoundRead(() => controller.abort());
  t.after(interception.restore);
  let error;
  try {
    await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup(), 'cache_read', { signal: controller.signal });
  } catch (caught) { error = caught; }
  finally { interception.restore(); }
  assert.equal(interception.reached(), true, 'abort occurred during the final cache read, not during setup');
  assert.equal(error?.code, 'REVIEW_ABORTED');
});

test('revoked current permission fails closed before a bound profile can be disclosed', async (t) => {
  let revoked = false;
  const f = await fixture(t, { cache: {
    verifyPermission({ reference, contentHash, version, use }) {
      if (revoked) return 'revoked';
      return { status: 'valid', reference, contentHash, version, use, validUntilMs: EPOCH + 60_000 };
    },
  } });
  await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-revoked-permission', profile: cacheProfile() }, f.authRequest);
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup())).status, 'hit');
  revoked = true;
  await assert.rejects(f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()),
    (error) => error?.code === 'REUSE_DENIED' && error.message === 'reuse access denied');
});

test('composed cancellation reads genuine AbortSignal state through captured intrinsics', async (t) => {
  const f = await fixture(t);
  await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID, { idempotencyKey: 'bind-abort-signal', profile: cacheProfile() }, f.authRequest);

  const activeController = new AbortController();
  Object.defineProperty(activeController.signal, 'aborted', { configurable: true, value: true });
  Object.defineProperty(activeController.signal, 'addEventListener', { configurable: true, value() { throw new Error('own override'); } });
  Object.defineProperty(activeController.signal, 'removeEventListener', { configurable: true, value() { throw new Error('own override'); } });
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup(), undefined,
    { signal: activeController.signal })).status, 'hit');

  const abortedController = new AbortController();
  abortedController.abort();
  Object.defineProperty(abortedController.signal, 'aborted', { configurable: true, value: false });
  Object.defineProperty(abortedController.signal, 'addEventListener', { configurable: true, value() {} });
  await assert.rejects(f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup(), undefined,
    { signal: abortedController.signal }),
  (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_ABORTED');
});

test('asynchronous and hostile final boundary permits fail closed without thenable property access', async (t) => {
  const asyncFixture = await fixture(t, { authorizeBoundary: async () => true });
  await createSeed(asyncFixture);
  await asyncFixture.store.bindPrivateProfile(asyncFixture.scope, EVENT_ID,
    { idempotencyKey: 'bind-async-final-guard', profile: cacheProfile() }, asyncFixture.authRequest);
  await assert.rejects(asyncFixture.store.getPrivateProfile(asyncFixture.scope, EVENT_ID,
    asyncFixture.authRequest, lookup()),
  (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_DENIED');

  let thenReads = 0;
  const hostileFixture = await fixture(t, { authorizeBoundary: () => Object.defineProperty({}, 'then', {
    get() { thenReads += 1; throw new Error('hostile then getter'); },
  }) });
  await createSeed(hostileFixture);
  await hostileFixture.store.bindPrivateProfile(hostileFixture.scope, EVENT_ID,
    { idempotencyKey: 'bind-hostile-final-guard', profile: cacheProfile() }, hostileFixture.authRequest);
  await assert.rejects(hostileFixture.store.getPrivateProfile(hostileFixture.scope, EVENT_ID,
    hostileFixture.authRequest, lookup()),
  (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_DENIED');
  assert.equal(thenReads, 0);

  const rejectedFixture = await fixture(t, { authorizeBoundary: () => Promise.reject(new Error('rejected async guard')) });
  await createSeed(rejectedFixture);
  await rejectedFixture.store.bindPrivateProfile(rejectedFixture.scope, EVENT_ID,
    { idempotencyKey: 'bind-rejected-final-guard', profile: cacheProfile() }, rejectedFixture.authRequest);
  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    await assert.rejects(rejectedFixture.store.getPrivateProfile(rejectedFixture.scope, EVENT_ID,
      rejectedFixture.authRequest, lookup()),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_DENIED');
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(unhandled, []);
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});

test('malformed final boundary permit shapes fail closed without changing the bound row', async (t) => {
  let mode = 'valid';
  let accessorReads = 0;
  let proxyTraps = 0;
  const f = await fixture(t, { authorizeBoundary(input) {
    const permit = Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
      eventId: input.eventId, action: input.action, field: input.field, nowMs: EPOCH });
    if (mode === 'valid') return permit;
    if (mode === 'denied') return false;
    if (mode === 'throw') throw new Error('trusted guard failure');
    if (mode === 'tenant') return { ...permit, tenantId: 'tenant-other' };
    if (mode === 'actor') return { ...permit, actorId: 'actor-other' };
    if (mode === 'event') return { ...permit, eventId: 'event-other' };
    if (mode === 'action') return { ...permit, action: 'review.history.read' };
    if (mode === 'field') return { ...permit, field: 'event_name' };
    if (mode === 'clock') return { ...permit, nowMs: Number.NaN };
    if (mode === 'extra') return { ...permit, extra: true };
    if (mode === 'accessor') {
      const result = { ...permit };
      Object.defineProperty(result, 'nowMs', { enumerable: true, get() { accessorReads += 1; throw new Error('permit getter'); } });
      return result;
    }
    if (mode === 'proxy') return new Proxy(permit, { ownKeys() { proxyTraps += 1; throw new Error('permit proxy trap'); } });
    if (mode === 'prototype') return Object.assign(Object.create({ trusted: true }), permit);
    return permit;
  } });
  await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-malformed-final-permit', profile: cacheProfile() }, f.authRequest);

  for (const invalidMode of ['denied', 'throw', 'tenant', 'actor', 'event', 'action', 'field', 'clock', 'extra', 'accessor', 'proxy', 'prototype']) {
    mode = invalidMode;
    await assert.rejects(f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()),
      (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_DENIED', invalidMode);
  }
  assert.equal(accessorReads, 0, 'permit getters are inspected as descriptors, never invoked');
  assert.equal(proxyTraps, 0, 'proxy detection runs before proxy traps');

  const history = new DatabaseSync(historyDatabasePath(f.root));
  const cache = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(history.prepare('SELECT revision FROM heads').get().revision, 1);
    assert.equal(cache.prepare('SELECT eligible FROM reuse_entries WHERE binding_hash IS NOT NULL').get().eligible, 1);
  } finally { history.close(); cache.close(); }
  mode = 'valid';
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup())).status, 'hit');
});

test('a composed cache participant requires its sync guard while standalone cache remains compatible', async (t) => {
  const f = await fixture(t);
  const { authorizeBoundary: _standaloneOptionalGuard, ...standaloneOptions } = f.cacheOptions;
  const standalone = createScopedReuseStore(standaloneOptions);
  assert.ok(await standalone.scopeForAuthenticatedRequest(f.authRequest));

  assert.throws(() => createCorrectionCacheBinding({
    history: f.historyOptions,
    cache: standaloneOptions,
    authorizeBoundary: () => false,
  }), (error) => error?.code === 'REUSE_DENIED');
  await assert.rejects(access(historyDatabasePath(f.root)), { code: 'ENOENT' });
  await assert.rejects(access(cacheDatabasePath(f.root)), { code: 'ENOENT' });
});

test('cache expiry atomically removes its reservation and history cleanup retires only the expired mapping', async (t) => {
  const f = await fixture(t);
  await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-retention-cleanup', profile: cacheProfile() }, f.authRequest);
  const cache = createScopedReuseStore(f.cacheOptions);
  const cacheScope = await cache.scopeForAuthenticatedRequest(f.authRequest);
  const cacheDb = new DatabaseSync(cacheDatabasePath(f.root));
  let legacyReservation;
  try {
    const entry = cacheDb.prepare('SELECT * FROM reuse_entries WHERE binding_hash IS NOT NULL').get();
    const reservation = cacheDb.prepare('SELECT * FROM reuse_correction_reservations WHERE entry_id = ?').get(entry.entry_id);
    assert.ok(reservation);
    legacyReservation = { ...reservation, payload: Buffer.from(reservation.payload) };
  } finally { cacheDb.close(); }

  f.clock.value = EPOCH + 45_000;
  assert.equal((await cache.purgeExpired(cacheScope, f.authRequest)).purged, 1);

  const afterCacheExpiry = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    const entry = afterCacheExpiry.prepare(`SELECT eligible, payload_bytes, payload_purged, length(payload) AS payload_length
      FROM reuse_entries WHERE binding_hash IS NOT NULL`).get();
    assert.deepEqual({ ...entry }, { eligible: 0, payload_bytes: 0, payload_purged: 1, payload_length: 0 });
    assert.equal(afterCacheExpiry.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 0);
    assert.deepEqual(afterCacheExpiry.prepare('SELECT status, COUNT(*) AS count FROM reuse_outbox GROUP BY status').all().map((row) => ({ ...row })),
      [{ status: 'pending', count: 1 }]);
    const history = new DatabaseSync(historyDatabasePath(f.root));
    try {
      assert.equal(history.prepare("SELECT state FROM heads WHERE state = 'available'").get().state, 'available');
      assert.equal(history.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 1);
      assert.ok(history.prepare('SELECT length(sealed) AS bytes FROM correction_cache_bindings').get().bytes > 0);
      assert.equal(history.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 1);
    } finally { history.close(); }
  } finally { afterCacheExpiry.close(); }

  // Recreate the former stale private row so the bounded compatibility sweep is exercised.
  const legacyDb = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    legacyDb.prepare(`INSERT INTO reuse_correction_reservations
      (entry_id, scope_kind, partition_hash, binding_hash, outbox_slots, payload_key_id, payload, payload_bytes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(legacyReservation.entry_id, legacyReservation.scope_kind,
      legacyReservation.partition_hash, legacyReservation.binding_hash, legacyReservation.outbox_slots,
      legacyReservation.payload_key_id, legacyReservation.payload, legacyReservation.payload_bytes);
  } finally { legacyDb.close(); }
  assert.equal((await cache.purgeExpired(cacheScope, f.authRequest)).purged, 0);
  const afterResidualSweep = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(afterResidualSweep.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 0);
    assert.equal(afterResidualSweep.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 1);
  } finally { afterResidualSweep.close(); }

  const historyStore = await historyStoreFor(f);
  assert.equal(await historyStore.history.purgeExpired(historyStore.scope, f.authRequest), 0);
  const afterHistorySweep = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.equal(afterHistorySweep.prepare("SELECT state FROM heads WHERE state = 'available'").get().state, 'available');
    assert.equal(afterHistorySweep.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 0);
    assert.equal(afterHistorySweep.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 1);
  } finally { afterHistorySweep.close(); }

  f.clock.value = EPOCH + 60_000;
  assert.equal((await cache.purgeExpired(cacheScope, f.authRequest)).purged, 0);
  assert.equal(await historyStore.history.purgeExpired(historyStore.scope, f.authRequest), 1);
  const finalHistory = new DatabaseSync(historyDatabasePath(f.root));
  const finalCache = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(finalHistory.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 0);
    assert.equal(finalCache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 0);
    assert.equal(finalCache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 1);
  } finally { finalHistory.close(); finalCache.close(); }
  assert.equal((await f.store.outboxSnapshot(f.scope, f.authRequest)).readiness, 'blocked_pending_external_ack');
});

test('composed binding enumeration prunes an expired mapping and preserves a later live binding and history references', async (t) => {
  const f = await fixture(t);
  await createSeed(f);
  const laterIdentity = Object.freeze({ ...IDENTITY, occurrenceId: 'occurrence-binding-later' });
  await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-expiry-first', profile: cacheProfile() }, f.authRequest);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-expiry-later', profile: cacheProfile({ identity: laterIdentity, expiresAtMs: EPOCH + 50_000,
      freshnessTtlMs: 50_000 }) },
    f.authRequest);
  f.clock.value = EPOCH + 45_000;

  assert.deepEqual(await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()), { status: 'miss' });
  const history = new DatabaseSync(historyDatabasePath(f.root));
  try {
    const live = history.prepare('SELECT expires_at_ms, length(sealed) AS bytes FROM correction_cache_bindings').get();
    assert.equal(live.expires_at_ms, EPOCH + 50_000);
    assert.ok(live.bytes > 0);
    assert.equal(history.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 2);
    assert.equal(history.prepare("SELECT state FROM heads WHERE state = 'available'").get().state, 'available');
  } finally { history.close(); }
  assert.equal((await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup({ identity: laterIdentity }))).status, 'hit');
});

test('correction after cache effective expiry keeps the history reference invalidation without a second cache event', async (t) => {
  const f = await fixture(t);
  const seeded = await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-correction-after-expiry', profile: cacheProfile() }, f.authRequest);
  const cache = createScopedReuseStore(f.cacheOptions);
  const cacheScope = await cache.scopeForAuthenticatedRequest(f.authRequest);
  f.clock.value = EPOCH + 45_000;
  assert.equal((await cache.purgeExpired(cacheScope, f.authRequest)).purged, 1);

  const revised = await f.store.applyCorrection(f.scope, {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-20' },
    idempotencyKey: 'correction-after-cache-effective-expiry',
    retentionHandle: f.createPermit(),
  }, f.authRequest);
  assert.equal(revised.snapshot.revision, seeded.snapshot.revision + 1);

  const history = new DatabaseSync(historyDatabasePath(f.root));
  const cacheDb = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(history.prepare('SELECT COUNT(*) AS count FROM invalidations').get().count, 1);
    assert.equal(history.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 0);
    assert.equal(cacheDb.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 1);
    assert.equal(cacheDb.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count, 0);
    assert.equal(cacheDb.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 0);
  } finally { history.close(); cacheDb.close(); }
  assert.equal((await f.store.outboxSnapshot(f.scope, f.authRequest)).readiness, 'blocked_pending_external_ack');
});

test('an expiry race leaves the durable history barrier until exact retry retires the expired mapping', async (t) => {
  let releaseIndexKey;
  let signalIndexKey;
  let indexResolveCount = 0;
  let blockIndexResolution = false;
  const indexResolutionStarted = new Promise((resolve) => { signalIndexKey = resolve; });
  const f = await fixture(t, { cache: { resolveKey({ tenantId, scope, purpose, keyId }) {
    if (blockIndexResolution && tenantId === 'tenant-binding' && purpose === 'index' && ++indexResolveCount === 2) {
      blockIndexResolution = false;
      signalIndexKey();
      return new Promise((resolve) => {
        releaseIndexKey = () => resolve({ keyId: `${scope}:${purpose}:${tenantId}:v1`,
          key: createHash('sha256').update(`${tenantId}:${scope}:${purpose}:cache-test-key`).digest() });
      });
    }
    const resolvedId = `${scope}:${purpose}:${tenantId ?? 'global'}:v1`;
    if (keyId && keyId !== resolvedId) throw new Error('synthetic cache key unavailable');
    return { keyId: resolvedId,
      key: createHash('sha256').update(`${tenantId}:${scope}:${purpose}:cache-test-key`).digest() };
  } } });
  t.after(() => releaseIndexKey?.());
  const seeded = await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-expiry-race', profile: cacheProfile() }, f.authRequest);
  const input = {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-22' },
    idempotencyKey: 'correction-expiry-race-exact-retry',
    retentionHandle: f.createPermit(),
  };
  blockIndexResolution = true;
  indexResolveCount = 0;
  const firstAttempt = f.store.applyCorrection(f.scope, input, f.authRequest);
  const rejected = assert.rejects(firstAttempt, (error) => ['REUSE_DENIED', 'REVIEW_DENIED'].includes(error?.code));
  await waitForSignal(indexResolutionStarted, 'cache invalidation index-key resolution after history binding enumeration');
  const cache = createScopedReuseStore(f.cacheOptions);
  const cacheScope = await cache.scopeForAuthenticatedRequest(f.authRequest);
  f.clock.value = EPOCH + 45_000;
  assert.equal((await cache.purgeExpired(cacheScope, f.authRequest)).purged, 1);
  releaseIndexKey();
  await rejected;
  await assert.rejects(f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup()),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_BUSY');

  const recovered = await f.store.applyCorrection(f.scope, input, f.authRequest);
  assert.equal(recovered.snapshot.revision, seeded.snapshot.revision + 1);
  const history = new DatabaseSync(historyDatabasePath(f.root));
  const cacheDb = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(history.prepare("SELECT phase FROM correction_cache_state WHERE kind = 'correction'").get().phase, 'complete');
    assert.equal(history.prepare('SELECT COUNT(*) AS count FROM invalidations').get().count, 1);
    assert.equal(history.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 0);
    assert.equal(cacheDb.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 1);
    assert.equal(cacheDb.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count, 0);
  } finally { history.close(); cacheDb.close(); }
});

test('correction invalidation that commits before expiry keeps its receipt and does not duplicate the outbox event', async (t) => {
  const f = await fixture(t);
  const seeded = await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-correction-before-expiry', profile: cacheProfile() }, f.authRequest);
  const input = {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-23' },
    idempotencyKey: 'correction-before-cache-expiry',
    retentionHandle: f.createPermit(),
  };
  await f.store.applyCorrection(f.scope, input, f.authRequest);
  const cache = createScopedReuseStore(f.cacheOptions);
  const cacheScope = await cache.scopeForAuthenticatedRequest(f.authRequest);
  f.clock.value = EPOCH + 45_000;
  assert.equal((await cache.purgeExpired(cacheScope, f.authRequest)).purged, 1);
  assert.equal((await f.store.applyCorrection(f.scope, input, f.authRequest)).replayed, true);
  const cacheDb = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(cacheDb.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 1);
    assert.equal(cacheDb.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count, 1);
    assert.equal(cacheDb.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 0);
  } finally { cacheDb.close(); }
});

test('tenant-scoped residual reservation cleanup progresses past 500 rows and preserves another tenant', async (t) => {
  const f = await fixture(t);
  await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-residual-default', profile: cacheProfile() }, f.authRequest);
  const otherRequest = request('tenant-other', 'actor-binding');
  const otherScope = await f.store.scopeForAuthenticatedRequest(otherRequest);
  await f.store.createHistory(otherScope, { eventId: EVENT_ID, sourceFacts: initialFacts(),
    idempotencyKey: 'initialize-other-tenant-event', retentionHandle: f.createPermit() }, otherRequest);
  const otherIdentity = Object.freeze({ ...IDENTITY, occurrenceId: 'occurrence-other-tenant' });
  await f.store.bindPrivateProfile(otherScope, EVENT_ID,
    { idempotencyKey: 'bind-residual-other-tenant', profile: cacheProfile({ identity: otherIdentity, expiresAtMs: EPOCH + 55_000 }) },
    otherRequest);

  const cache = createScopedReuseStore(f.cacheOptions);
  const cacheScope = await cache.scopeForAuthenticatedRequest(f.authRequest);
  const database = new DatabaseSync(cacheDatabasePath(f.root));
  let expiredEntry;
  let oldReservation;
  try {
    expiredEntry = database.prepare('SELECT * FROM reuse_entries WHERE expires_at_ms = ?').get(EPOCH + 45_000);
    oldReservation = database.prepare('SELECT * FROM reuse_correction_reservations WHERE entry_id = ?').get(expiredEntry.entry_id);
    oldReservation = { ...oldReservation, payload: Buffer.from(oldReservation.payload) };
  } finally { database.close(); }

  f.clock.value = EPOCH + 45_000;
  assert.equal((await cache.purgeExpired(cacheScope, f.authRequest)).purged, 1);
  const seedLegacy = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    const insertEntry = seedLegacy.prepare(`INSERT INTO reuse_entries
      (entry_id, scope_kind, partition_hash, identity_hash, cache_key_hash, content_hash_mac, pins_hash, version,
       created_at_ms, expires_at_ms, eligible, payload_key_id, payload, payload_bytes, payload_purged, binding_hash)
      VALUES (?, 'tenant_private', ?, ?, ?, ?, ?, 1, ?, ?, 0, ?, ?, 0, 1, ?)`);
    const insertReservation = seedLegacy.prepare(`INSERT INTO reuse_correction_reservations
      (entry_id, scope_kind, partition_hash, binding_hash, outbox_slots, payload_key_id, payload, payload_bytes)
      VALUES (?, 'tenant_private', ?, ?, 1, ?, ?, ?)`);
    for (let index = 0; index < 501; index += 1) {
      const entryId = `legacy-expired-reservation-${String(index).padStart(4, '0')}`;
      const uniqueHash = index.toString(16).padStart(64, '0');
      insertEntry.run(entryId, expiredEntry.partition_hash, 'a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64), 'd'.repeat(64),
        EPOCH, EPOCH + 45_000, oldReservation.payload_key_id, Buffer.alloc(0), uniqueHash);
      insertReservation.run(entryId, expiredEntry.partition_hash, uniqueHash, oldReservation.payload_key_id,
        oldReservation.payload, oldReservation.payload_bytes);
    }
  } finally { seedLegacy.close(); }

  assert.equal((await cache.purgeExpired(cacheScope, f.authRequest)).purged, 0);
  const afterFirstSweep = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(afterFirstSweep.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 2);
    assert.equal(afterFirstSweep.prepare(`SELECT COUNT(*) AS count FROM reuse_correction_reservations
      WHERE partition_hash = ?`).get(expiredEntry.partition_hash).count, 1);
    assert.equal(afterFirstSweep.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 1);
  } finally { afterFirstSweep.close(); }

  assert.equal((await cache.purgeExpired(cacheScope, f.authRequest)).purged, 0);
  const afterSecondSweep = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(afterSecondSweep.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 1);
    assert.equal(afterSecondSweep.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 1);
  } finally { afterSecondSweep.close(); }

  const otherTenantHash = createHash('sha256').update('event-intelligence:review-tenant:v1:tenant-other').digest('hex');
  const otherHistory = new DatabaseSync(path.join(f.historyOptions.directory, otherTenantHash, 'history.sqlite'));
  try {
    assert.equal(otherHistory.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 1);
    assert.equal(otherHistory.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 1);
  } finally { otherHistory.close(); }
});

test('cache expiry consumes the reserved retention event at the exact outbox capacity boundary', async (t) => {
  const f = await fixture(t, { cache: { maxOutboxEntries: 2 } });
  await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-capacity-expiry', profile: cacheProfile() }, f.authRequest);
  const cache = createScopedReuseStore(f.cacheOptions);
  const cacheScope = await cache.scopeForAuthenticatedRequest(f.authRequest);
  const before = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(before.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 0);
    assert.equal(before.prepare('SELECT SUM(outbox_slots) AS count FROM reuse_correction_reservations').get().count, 1);
  } finally { before.close(); }
  f.clock.value = EPOCH + 45_000;
  assert.equal((await cache.purgeExpired(cacheScope, f.authRequest)).purged, 1);
  const after = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(after.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 1);
    assert.equal(after.prepare("SELECT COUNT(*) AS count FROM reuse_outbox WHERE status = 'pending'").get().count, 1);
    assert.equal(after.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 0);
  } finally { after.close(); }
});

test('history mapping purge rechecks current authorization after a real SQLite writer conflict before retry', async (t) => {
  let revoked = false;
  let watchBoundary = false;
  let boundaryAttempts = 0;
  let purgeAuthorizationCalls = 0;
  const authorizationCountsAtBoundary = [];
  let writer;
  let writerAcquired = false;
  let writerAcquireError;
  let signalRetry;
  const retryObserved = new Promise((resolve) => { signalRetry = resolve; });
  const f = await fixture(t, { history: {
    authorize({ tenantId, actorId, action, request: value }) {
      if (action === 'purge_correction_history') purgeAuthorizationCalls += 1;
      return !revoked && value?.serverContextToken === TRUSTED_TOKEN && value?.principal?.tenantId === tenantId
        && value?.principal?.actorId === actorId && actorId !== 'outsider';
    },
    authorizeBoundary(input) {
      if (watchBoundary && input.eventId === null && input.action === 'review.history.retention_purge') {
        boundaryAttempts += 1;
        authorizationCountsAtBoundary.push(purgeAuthorizationCalls);
        if (boundaryAttempts === 1) {
          try {
            writer = new DatabaseSync(historyDatabasePath(f.root), { timeout: 0 });
            writer.exec('PRAGMA busy_timeout = 0; BEGIN IMMEDIATE');
            writerAcquired = true;
          } catch (error) {
            writerAcquireError = error;
          }
          if (!writerAcquired) return false;
          return Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
            eventId: input.eventId, action: input.action, field: input.field, nowMs: f.clock.value });
        }
        if (boundaryAttempts === 2) {
          revoked = true;
          signalRetry();
          return false;
        }
      }
      const allowed = input.request?.serverContextToken === TRUSTED_TOKEN
        && input.request?.principal?.tenantId === input.tenantId
        && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider'
        && !revoked;
      return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
        eventId: input.eventId, action: input.action, field: input.field, nowMs: f.clock.value }) : false;
    },
  } });
  t.after(() => {
    try { writer?.exec('ROLLBACK'); } catch { /* It may already be closed. */ }
    try { writer?.close(); } catch { /* Cleanup is best-effort after a test failure. */ }
  });
  await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-purge-auth-race', profile: cacheProfile() }, f.authRequest);
  f.clock.value = EPOCH + 45_000;
  const history = await historyStoreFor(f);
  watchBoundary = true;
  const purgeAttempt = history.history.purgeExpired(history.scope, f.authRequest);
  const rejection = await awaitWithTimeout(purgeAttempt, 'history purge authorization retry')
    .then(() => null, (error) => error);
  assert.equal(rejection instanceof ReviewHistoryError, true);
  assert.equal(rejection?.code, 'REVIEW_DENIED');
  await waitForSignal(retryObserved, 'history purge synchronous boundary rejection');
  assert.equal(writerAcquired, true, writerAcquireError?.message);
  assert.equal(boundaryAttempts, 2, 'the second guard follows an actual busy BEGIN retry');
  assert.equal(authorizationCountsAtBoundary[1] - authorizationCountsAtBoundary[0], 2,
    'the retry performs both async authorization checks before its final synchronous guard');
  writer.exec('ROLLBACK');
  writer.close();
  writer = undefined;
  const deniedSweep = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.equal(deniedSweep.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 1);
    assert.equal(deniedSweep.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 1);
  } finally { deniedSweep.close(); }

  revoked = false;
  assert.equal(await history.history.purgeExpired(history.scope, f.authRequest), 0);
  const allowedSweep = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.equal(allowedSweep.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count, 0);
    assert.equal(allowedSweep.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count, 1);
    assert.equal(allowedSweep.prepare("SELECT state FROM heads WHERE state = 'available'").get().state, 'available');
  } finally { allowedSweep.close(); }
});

test('binding preflight accepts the cache projection maxima of 32 candidates and 64 support references', async (t) => {
  const candidate = (value, prefix, referenceCount = 1) => Object.freeze({
    originStatus: 'sourced',
    value,
    sourceEvidence: Object.freeze(Array.from({ length: referenceCount }, (_, index) =>
      sourceEvidence(`${prefix}-${index}`, `${value}:${prefix}:${index}`))),
  });

  await t.test('exactly 32 projected candidates remain bindable', async (subtest) => {
    const f = await fixture(subtest);
    const facts = { ...initialFacts(), venue: Object.freeze({ status: 'conflicting',
      candidates: Object.freeze(Array.from({ length: 32 }, (_, index) =>
        candidate(`Venue ${index}`, `candidate-${index}`))) }) };
    await f.store.createHistory(f.scope, { eventId: EVENT_ID, sourceFacts: facts,
      idempotencyKey: 'initialize-exactly-32-candidates', retentionHandle: f.createPermit() }, f.authRequest);
    const bound = await f.store.bindPrivateProfile(f.scope, EVENT_ID,
      { idempotencyKey: 'bind-exactly-32-candidates', profile: cacheProfile() }, f.authRequest);
    assert.equal(bound.status, 'bound');
    const profile = await f.store.getPrivateProfile(f.scope, EVENT_ID, f.authRequest, lookup());
    assert.equal(profile.status, 'hit');
    assert.equal(profile.facts.venue.candidates.length, 32);
  });

  await t.test('exactly 64 support references on one projected candidate remain bindable', async (subtest) => {
    const f = await fixture(subtest);
    const facts = { ...initialFacts(), venue: Object.freeze({ status: 'conflicting', candidates: Object.freeze([
      candidate('Civic Hall', 'civic-initial', 32),
      candidate('River Room', 'river-initial'),
    ]) }) };
    const first = await f.store.createHistory(f.scope, { eventId: EVENT_ID, sourceFacts: facts,
      idempotencyKey: 'initialize-exactly-64-support-references', retentionHandle: f.createPermit() }, f.authRequest);
    const refreshed = await f.store.refreshSources(f.scope, {
      eventId: EVENT_ID,
      baseVersionId: first.snapshot.versionId,
      baseContentHash: first.snapshot.contentHash,
      sourceFacts: { venue: { status: 'sourced', value: 'Civic Hall',
        sourceEvidence: Array.from({ length: 32 }, (_, index) =>
          sourceEvidence(`civic-refresh-${index}`, `Civic Hall:refresh:${index}`)) } },
      idempotencyKey: 'refresh-exactly-64-support-references',
      retentionHandle: f.createPermit(),
    }, f.authRequest);
    const civicCandidate = refreshed.snapshot.fields.venue.candidates.find((entry) => entry.value === 'Civic Hall');
    assert.equal(civicCandidate.sourceEvidence.length, 64, JSON.stringify({
      claims: refreshed.snapshot.fields.venue.sourceClaims.map((claim) => claim.sourceEvidence.length),
      candidates: refreshed.snapshot.fields.venue.candidates.map((item) => ({ value: item.value, refs: item.sourceEvidence.length })),
    }));
    const bound = await f.store.bindPrivateProfile(f.scope, EVENT_ID,
      { idempotencyKey: 'bind-exactly-64-support-references', profile: cacheProfile() }, f.authRequest);
    assert.equal(bound.status, 'bound');
  });
});

test('facade binds exactly 128 distinct history references and rejects bind 129 before effects', async (t) => {
  const f = await fixture(t);
  await createSeed(f);
  for (let index = 0; index < 128; index += 1) {
    const identity = Object.freeze({ ...IDENTITY, occurrenceId: `occurrence-binding-slot-${index}` });
    const result = await f.store.bindPrivateProfile(f.scope, EVENT_ID, {
      idempotencyKey: `bind-reference-slot-${index}`,
      profile: cacheProfile({ identity }),
    }, f.authRequest);
    assert.equal(result.status, 'bound');
  }

  const beforeHistory = new DatabaseSync(historyDatabasePath(f.root));
  const beforeCache = new DatabaseSync(cacheDatabasePath(f.root));
  let beforeCounts;
  try {
    beforeCounts = {
      references: beforeHistory.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count,
      bindings: beforeHistory.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count,
      operations: beforeHistory.prepare('SELECT COUNT(*) AS count FROM correction_cache_operations WHERE kind = \'bind\'').get().count,
      entries: beforeCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count,
      writes: beforeCache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count,
      reservations: beforeCache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count,
      observations: beforeCache.prepare('SELECT COUNT(*) AS count FROM reuse_observations').get().count,
      outbox: beforeCache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count,
    };
    assert.equal(beforeCounts.references, 128);
    assert.equal(beforeCounts.bindings, 128);
    assert.equal(beforeCounts.operations, 128);
  } finally { beforeHistory.close(); beforeCache.close(); }

  await assert.rejects(f.store.bindPrivateProfile(f.scope, EVENT_ID, {
    idempotencyKey: 'bind-reference-slot-128', profile: cacheProfile(),
  }, f.authRequest), (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_STORAGE_LIMIT');
  assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).revision, 1);

  const afterHistory = new DatabaseSync(historyDatabasePath(f.root));
  const afterCache = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(afterHistory.prepare("SELECT COUNT(*) AS count FROM correction_cache_state WHERE phase != 'complete'").get().count, 0);
    assert.deepEqual({
      references: afterHistory.prepare('SELECT COUNT(*) AS count FROM downstream_references').get().count,
      bindings: afterHistory.prepare('SELECT COUNT(*) AS count FROM correction_cache_bindings').get().count,
      operations: afterHistory.prepare("SELECT COUNT(*) AS count FROM correction_cache_operations WHERE kind = 'bind'").get().count,
      entries: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count,
      writes: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_bound_writes').get().count,
      reservations: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count,
      observations: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_observations').get().count,
      outbox: afterCache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count,
    }, beforeCounts);
  } finally { afterHistory.close(); afterCache.close(); }

  const reopened = f.makeStore();
  const scope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
  assert.equal((await reopened.getHistory(scope, EVENT_ID, f.authRequest)).revision, 1);
});

test('unsupported accumulated projections fail before a durable bind barrier', async (t) => {
  const f = await fixture(t);
  let current = await createSeed(f);
  for (const [batch, count] of [32, 32, 32, 30].entries()) {
    const candidates = Array.from({ length: count }, (_, index) => {
      const value = `Accumulated venue ${batch}-${index}`;
      return { originStatus: 'sourced', value,
        sourceEvidence: [sourceEvidence(`accumulated-${batch}-${index}`, value)] };
    });
    current = await f.store.refreshSources(f.scope, {
      eventId: EVENT_ID,
      baseVersionId: current.snapshot.versionId,
      baseContentHash: current.snapshot.contentHash,
      sourceFacts: { venue: { status: 'conflicting', candidates } },
      idempotencyKey: `accumulated-candidates-${batch}`,
      retentionHandle: f.createPermit(),
    }, f.authRequest);
  }
  assert.equal(current.snapshot.fields.venue.sourceClaims.length, 128);
  assert.equal(current.snapshot.fields.venue.candidates.length, 128);

  const bindError = await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-128-accumulated-candidates', profile: cacheProfile() }, f.authRequest)
    .then(() => null, (error) => error);
  assert.equal(bindError?.code, 'REUSE_INVALID');
  const reopenedHistory = await f.store.getHistory(f.scope, EVENT_ID, f.authRequest);
  assert.equal(reopenedHistory.contentHash, current.snapshot.contentHash);
  assert.equal(reopenedHistory.fields.venue.sourceClaims.length, 128);
  assert.equal(reopenedHistory.fields.venue.candidates.length, 128,
    'preflight must preserve every immutable alternative rather than truncate to the cache bound');

  const history = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.equal(history.prepare("SELECT COUNT(*) AS count FROM correction_cache_operations WHERE kind = 'bind'").get().count, 0);
    assert.equal(history.prepare("SELECT COUNT(*) AS count FROM correction_cache_state WHERE phase = 'pending_bind'").get().count, 0);
  } finally { history.close(); }

  const standaloneHistory = await historyStoreFor(f);
  await assert.rejects(standaloneHistory.history.refreshSources(standaloneHistory.scope, {
    eventId: EVENT_ID,
    baseVersionId: current.snapshot.versionId,
    baseContentHash: current.snapshot.contentHash,
    sourceFacts: { venue: { status: 'sourced', value: 'Overflow venue',
      sourceEvidence: [sourceEvidence('overflow-venue-129', 'Overflow venue')] } },
    idempotencyKey: 'history-129th-source-claim',
    retentionHandle: f.createPermit(),
  }, f.authRequest), (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_STORAGE_LIMIT');
  assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).contentHash, current.snapshot.contentHash,
    'the 129th source claim remains rejected without changing the 128-claim history');
});

test('65 accumulated support references fail before a bind barrier without changing history', async (t) => {
  const f = await fixture(t);
  let current = await createSeed(f);
  for (let batch = 0; batch < 2; batch += 1) {
    current = await f.store.refreshSources(f.scope, {
      eventId: EVENT_ID,
      baseVersionId: current.snapshot.versionId,
      baseContentHash: current.snapshot.contentHash,
      sourceFacts: { venue: { status: 'sourced', value: 'Civic Hall', sourceEvidence: Array.from({ length: 32 }, (_, index) =>
        sourceEvidence(`support-overflow-${batch}-${index}`, `Civic Hall:support-overflow:${batch}:${index}`)) } },
      idempotencyKey: `support-overflow-refresh-${batch}`,
      retentionHandle: f.createPermit(),
    }, f.authRequest);
  }
  const civic = current.snapshot.fields.venue.candidates.find((candidate) => candidate.value === 'Civic Hall');
  assert.equal(civic.sourceEvidence.length, 65);
  const before = await f.store.getHistory(f.scope, EVENT_ID, f.authRequest);

  await assert.rejects(f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-65-accumulated-support-references', profile: cacheProfile() }, f.authRequest),
  (error) => error?.code === 'REUSE_INVALID');
  const after = await f.store.getHistory(f.scope, EVENT_ID, f.authRequest);
  assert.equal(after.versionId, before.versionId);
  assert.equal(after.contentHash, before.contentHash);
  assert.equal(after.fields.venue.candidates.find((candidate) => candidate.value === 'Civic Hall').sourceEvidence.length, 65);

  const database = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM correction_cache_operations WHERE kind = 'bind'").get().count, 0);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM correction_cache_state WHERE phase = 'pending_bind'").get().count, 0);
  } finally { database.close(); }

  const corrected = await f.store.applyCorrection(f.scope, {
    eventId: EVENT_ID,
    baseVersionId: after.versionId,
    baseContentHash: after.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-26' },
    idempotencyKey: 'correct-after-65-support-references',
    retentionHandle: f.createPermit(),
  }, f.authRequest);
  assert.equal(corrected.snapshot.revision, after.revision + 1);
  assert.equal(corrected.snapshot.fields.venue.candidates.find((candidate) => candidate.value === 'Civic Hall').sourceEvidence.length, 65);
});

test('composed refresh rejects the 129th accumulated source claim before its durable barrier', async (t) => {
  const f = await fixture(t);
  let current = await createSeed(f);
  for (const [batch, count] of [32, 32, 32, 30].entries()) {
    const candidates = Array.from({ length: count }, (_, index) => {
      const value = `Source claim ${batch}-${index}`;
      return { originStatus: 'sourced', value,
        sourceEvidence: [sourceEvidence(`source-claim-${batch}-${index}`, value)] };
    });
    current = await f.store.refreshSources(f.scope, {
      eventId: EVENT_ID,
      baseVersionId: current.snapshot.versionId,
      baseContentHash: current.snapshot.contentHash,
      sourceFacts: { venue: { status: 'conflicting', candidates } },
      idempotencyKey: `source-claim-batch-${batch}`,
      retentionHandle: f.createPermit(),
    }, f.authRequest);
  }
  assert.equal(current.snapshot.fields.venue.sourceClaims.length, 128);
  const before = new DatabaseSync(historyDatabasePath(f.root));
  let operationCount;
  try { operationCount = before.prepare('SELECT COUNT(*) AS count FROM correction_cache_operations').get().count; }
  finally { before.close(); }

  await assert.rejects(f.store.refreshSources(f.scope, {
    eventId: EVENT_ID,
    baseVersionId: current.snapshot.versionId,
    baseContentHash: current.snapshot.contentHash,
    sourceFacts: { venue: { status: 'sourced', value: 'Overflow claim',
      sourceEvidence: [sourceEvidence('source-claim-overflow', 'Overflow claim')] } },
    idempotencyKey: 'composed-source-claim-129',
    retentionHandle: f.createPermit(),
  }, f.authRequest), (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_STORAGE_LIMIT');

  const afterFailure = await f.store.getHistory(f.scope, EVENT_ID, f.authRequest);
  assert.equal(afterFailure.versionId, current.snapshot.versionId);
  assert.equal(afterFailure.contentHash, current.snapshot.contentHash);
  assert.equal(afterFailure.fields.venue.sourceClaims.length, 128);
  const unchanged = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.equal(unchanged.prepare('SELECT COUNT(*) AS count FROM correction_cache_operations').get().count, operationCount);
    assert.equal(unchanged.prepare("SELECT phase FROM correction_cache_state WHERE event_key = (SELECT event_key FROM heads LIMIT 1)").get().phase, 'complete');
  } finally { unchanged.close(); }

  const corrected = await f.store.applyCorrection(f.scope, {
    eventId: EVENT_ID,
    baseVersionId: current.snapshot.versionId,
    baseContentHash: current.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-22' },
    idempotencyKey: 'valid-correction-after-source-capacity-rejection',
    retentionHandle: f.createPermit(),
  }, f.authRequest);
  assert.equal(corrected.snapshot.revision, current.snapshot.revision + 1);
  assert.equal(corrected.snapshot.fields.venue.sourceClaims.length, 128);
});

test('exact correction and source-refresh receipts replay after later binds and reopen without duplicate effects', async (t) => {
  const f = await fixture(t);
  const seeded = await createSeed(f);
  const correctionInput = {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-23' },
    idempotencyKey: 'receipt-replay-correction',
    retentionHandle: f.createPermit(),
  };
  const corrected = await f.store.applyCorrection(f.scope, correctionInput, f.authRequest);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'receipt-replay-bind-after-correction', profile: cacheProfile() }, f.authRequest);

  const reopened = f.makeStore();
  const reopenedScope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
  const correctionCounts = () => {
    const history = new DatabaseSync(historyDatabasePath(f.root));
    const cache = new DatabaseSync(cacheDatabasePath(f.root));
    try {
      return {
        operations: history.prepare('SELECT COUNT(*) AS count FROM correction_cache_operations').get().count,
        invalidations: history.prepare('SELECT COUNT(*) AS count FROM invalidations').get().count,
        cacheReceipts: cache.prepare('SELECT COUNT(*) AS count FROM reuse_history_invalidation_ops').get().count,
        outbox: cache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count,
      };
    } finally { history.close(); cache.close(); }
  };
  const beforeCorrectionReplay = correctionCounts();
  const correctionReplay = await reopened.applyCorrection(reopenedScope, {
    ...correctionInput, retentionHandle: f.createPermit(),
  }, f.authRequest);
  assert.equal(correctionReplay.replayed, true);
  assert.equal(correctionReplay.snapshot.versionId, corrected.snapshot.versionId);
  assert.equal(correctionReplay.snapshot.contentHash, corrected.snapshot.contentHash);
  assert.deepEqual(correctionCounts(), beforeCorrectionReplay);

  const refreshInput = {
    eventId: EVENT_ID,
    baseVersionId: corrected.snapshot.versionId,
    baseContentHash: corrected.snapshot.contentHash,
    sourceFacts: { event_name: { status: 'sourced', value: 'Lantern Night revised',
      sourceEvidence: [sourceEvidence('receipt-replay-refresh', 'Lantern Night revised')] } },
    idempotencyKey: 'receipt-replay-refresh',
    retentionHandle: f.createPermit(),
  };
  const refreshed = await reopened.refreshSources(reopenedScope, refreshInput, f.authRequest);
  await reopened.bindPrivateProfile(reopenedScope, EVENT_ID,
    { idempotencyKey: 'receipt-replay-bind-after-refresh', profile: cacheProfile() }, f.authRequest);

  const counts = correctionCounts();
  const refreshReplay = await reopened.refreshSources(reopenedScope, {
    ...refreshInput, retentionHandle: f.createPermit(),
  }, f.authRequest);
  assert.equal(refreshReplay.replayed, true);
  assert.equal(refreshReplay.snapshot.versionId, refreshed.snapshot.versionId);
  assert.equal(refreshReplay.snapshot.contentHash, refreshed.snapshot.contentHash);

  const after = new DatabaseSync(historyDatabasePath(f.root));
  const cacheAfter = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.deepEqual(correctionCounts(), counts);
    for (const [base, target] of [[seeded.snapshot, corrected.snapshot], [corrected.snapshot, refreshed.snapshot]]) {
      const operation = after.prepare(`SELECT phase, base_version_id, base_content_hash, target_version_id,
        target_content_hash, fence FROM correction_cache_operations WHERE target_version_id = ?`).get(target.versionId);
      assert.equal(operation.phase, 'complete');
      assert.equal(operation.base_version_id, base.versionId);
      assert.equal(operation.base_content_hash, base.contentHash);
      assert.equal(operation.target_content_hash, target.contentHash);
      assert.equal(Number.isSafeInteger(operation.fence) && operation.fence > 0, true);
    }
  } finally { after.close(); cacheAfter.close(); }
});

test('receipt migration backfills only the exact current operation and keeps older completion rows fail closed', async (t) => {
  const f = await fixture(t);
  const seeded = await createSeed(f);
  const firstInput = {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-24' },
    idempotencyKey: 'legacy-receipt-first',
    retentionHandle: f.createPermit(),
  };
  const first = await f.store.applyCorrection(f.scope, firstInput, f.authRequest);
  const secondInput = {
    eventId: EVENT_ID,
    baseVersionId: first.snapshot.versionId,
    baseContentHash: first.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-25' },
    idempotencyKey: 'legacy-receipt-second',
    retentionHandle: f.createPermit(),
  };
  const second = await f.store.applyCorrection(f.scope, secondInput, f.authRequest);

  const legacy = new DatabaseSync(historyDatabasePath(f.root));
  try {
    for (const column of ['base_version_id', 'base_content_hash', 'fence', 'phase', 'reserved_history_bytes']) {
      legacy.exec(`ALTER TABLE correction_cache_operations DROP COLUMN ${column}`);
    }
    legacy.prepare("UPDATE correction_cache_meta SET value = '2' WHERE key = 'binding_operation_receipt_schema'").run();
  } finally { legacy.close(); }

  const reopened = f.makeStore();
  const reopenedScope = await reopened.scopeForAuthenticatedRequest(f.authRequest);
  const current = await reopened.getHistory(reopenedScope, EVENT_ID, f.authRequest);
  assert.equal(current.versionId, second.snapshot.versionId);
  const migrated = new DatabaseSync(historyDatabasePath(f.root));
  try {
    const schema = new Set(migrated.prepare('PRAGMA table_info(correction_cache_operations)').all().map((column) => column.name));
    for (const column of ['base_version_id', 'base_content_hash', 'fence', 'phase', 'reserved_history_bytes']) assert.equal(schema.has(column), true);
    assert.equal(migrated.prepare("SELECT value FROM correction_cache_meta WHERE key = 'binding_operation_receipt_schema'").get().value, '3');
    const oldReceipt = migrated.prepare('SELECT base_version_id, base_content_hash, fence, phase FROM correction_cache_operations WHERE target_version_id = ?')
      .get(first.snapshot.versionId);
    assert.deepEqual({ ...oldReceipt }, { base_version_id: null, base_content_hash: null, fence: null, phase: null },
      'a historical row not represented by the current singleton does not receive a fabricated fence');
    const currentReceipt = migrated.prepare('SELECT base_version_id, base_content_hash, fence, phase FROM correction_cache_operations WHERE target_version_id = ?')
      .get(second.snapshot.versionId);
    assert.equal(currentReceipt.base_version_id, first.snapshot.versionId);
    assert.equal(currentReceipt.base_content_hash, first.snapshot.contentHash);
    assert.equal(Number.isSafeInteger(currentReceipt.fence) && currentReceipt.fence > 0, true);
    assert.equal(currentReceipt.phase, 'complete');
  } finally { migrated.close(); }

  await assert.rejects(reopened.applyCorrection(reopenedScope, {
    ...firstInput, retentionHandle: f.createPermit(),
  }, f.authRequest), (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_BUSY');
  const replay = await reopened.applyCorrection(reopenedScope, {
    ...secondInput, retentionHandle: f.createPermit(),
  }, f.authRequest);
  assert.equal(replay.replayed, true);
  assert.equal(replay.snapshot.versionId, second.snapshot.versionId);
  const repeated = f.makeStore();
  const repeatedScope = await repeated.scopeForAuthenticatedRequest(f.authRequest);
  assert.equal((await repeated.getHistory(repeatedScope, EVENT_ID, f.authRequest)).versionId, second.snapshot.versionId);
});

test('bound invalidation preflight uses the production envelope sealer at the exact UTF-8 cap', async (t) => {
  const keyId = 'k'.repeat(127);
  const longEventId = 'x'.repeat(180);
  for (const [length, shouldFit] of [[275, true], [276, true], [277, false]]) {
    await t.test(`${length} multibyte consumer code units ${shouldFit ? 'fit' : 'fail closed'}`, async (subtest) => {
      const f = await fixture(subtest, { cache: {
        resolveKey({ tenantId, scope, purpose, keyId: requestedKeyId }) {
          if (requestedKeyId && requestedKeyId !== keyId) throw new Error('unexpected test key id');
          return { keyId, key: createHash('sha256').update(`${tenantId}:${scope}:${purpose}:exact-envelope-key`).digest() };
        },
        resolveInvalidationConsumers: () => ['é'.repeat(length)],
      } });
      await f.store.createHistory(f.scope, { eventId: longEventId, sourceFacts: initialFacts(),
        idempotencyKey: `initialize-envelope-${length}`, retentionHandle: f.createPermit() }, f.authRequest);
      const bind = f.store.bindPrivateProfile(f.scope, longEventId,
        { idempotencyKey: `bind-envelope-${length}`, profile: cacheProfile() }, f.authRequest);
      if (shouldFit) {
        assert.equal((await bind).status, 'bound');
        const operation = new DatabaseSync(historyDatabasePath(f.root));
        try { assert.equal(operation.prepare("SELECT phase FROM correction_cache_state WHERE kind = 'bind'").get().phase, 'complete'); }
        finally { operation.close(); }
      } else {
        await assert.rejects(bind, (error) => error?.code === 'REUSE_CAPACITY');
        const history = await f.store.getHistory(f.scope, longEventId, f.authRequest);
        assert.equal(history.eventId, longEventId);
        assertNoPendingBinding(f.root);
        assert.equal(await access(cacheDatabasePath(f.root)).then(() => true, () => false), false,
          'oversized future payload is rejected before opening or mutating the cache database');
      }
    });
  }
});

test('bound invalidation preflight accounts for escaped consumers and maximum key identifiers', async (t) => {
  const cases = [
    { name: 'escaped quote and backslash consumer at the exact cap', keyId: 'k'.repeat(127), consumer: '"\\'.repeat(137) + '"', fits: true },
    { name: '128-character ASCII key id', keyId: 'k'.repeat(128), consumer: 'é'.repeat(275), fits: false },
    { name: 'escaped quote key id', keyId: '"'.repeat(128), consumer: 'é'.repeat(275), fits: false },
    { name: 'multibyte key id at 128 UTF-16 units', keyId: '😀'.repeat(64), consumer: 'é'.repeat(275), fits: false },
    { name: 'escaped control consumer', keyId: 'k'.repeat(127), consumer: '\u0000'.repeat(275), fits: false },
  ];
  for (const [index, item] of cases.entries()) {
    await t.test(item.name, async (subtest) => {
      const f = await fixture(subtest, { cache: {
        resolveKey({ tenantId, scope, purpose, keyId: requestedKeyId }) {
          if (requestedKeyId && requestedKeyId !== item.keyId) throw new Error('unexpected test key id');
          return { keyId: item.keyId, key: createHash('sha256').update(`${tenantId}:${scope}:${purpose}:escaped-envelope-${index}`).digest() };
        },
        resolveInvalidationConsumers: () => [item.consumer],
      } });
      const eventId = 'x'.repeat(180);
      await f.store.createHistory(f.scope, { eventId, sourceFacts: initialFacts(),
        idempotencyKey: `initialize-escaped-envelope-${index}`, retentionHandle: f.createPermit() }, f.authRequest);
      const bind = f.store.bindPrivateProfile(f.scope, eventId,
        { idempotencyKey: `bind-escaped-envelope-${index}`, profile: cacheProfile() }, f.authRequest);
      if (item.fits) {
        assert.equal((await bind).status, 'bound');
      } else {
        await assert.rejects(bind, (error) => error?.code === 'REUSE_CAPACITY');
        assert.equal((await f.store.getHistory(f.scope, eventId, f.authRequest)).revision, 1);
        assertNoPendingBinding(f.root);
      }
    });
  }
});

test('history invalidation and every delivery reseal retain the bind-time proof key after rotation', async (t) => {
  const originalKeyId = 'k';
  const rotatedKeyId = '\u0000'.repeat(128);
  const originalKey = createHash('sha256').update('retained-payload-key-k').digest();
  const rotatedKey = createHash('sha256').update('rotated-payload-key-with-128-nuls').digest();
  let rotated = false;
  const f = await fixture(t, { cache: {
    maxOutboxAttempts: 3,
    resolveKey({ tenantId, scope, purpose, keyId }) {
      if (purpose === 'payload') {
        const requestedId = keyId ?? (rotated ? rotatedKeyId : originalKeyId);
        if (requestedId === originalKeyId) return { keyId: originalKeyId, key: Buffer.from(originalKey) };
        if (requestedId === rotatedKeyId) return { keyId: rotatedKeyId, key: Buffer.from(rotatedKey) };
        throw new Error('synthetic payload key unavailable');
      }
      const resolvedId = `${scope}:${purpose}:${tenantId ?? 'global'}:v1`;
      if (keyId && keyId !== resolvedId) throw new Error('synthetic non-payload key unavailable');
      return { keyId: resolvedId, key: createHash('sha256').update(`${tenantId}:${scope}:${purpose}:cache-test-key`).digest() };
    },
    resolveInvalidationConsumers: () => ['é'.repeat(300)],
    deliverInvalidation: async () => null,
    verifyInvalidationAcknowledgement: () => false,
  } });
  const seeded = await createSeed(f);
  const bound = await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-retained-envelope-key', profile: cacheProfile() }, f.authRequest);
  assert.equal(bound.status, 'bound');
  const beforeRotation = new DatabaseSync(cacheDatabasePath(f.root));
  try {
    assert.equal(beforeRotation.prepare('SELECT payload_key_id FROM reuse_correction_reservations').get().payload_key_id,
      originalKeyId);
  } finally { beforeRotation.close(); }

  rotated = true;
  const corrected = await f.store.applyCorrection(f.scope, {
    eventId: EVENT_ID,
    baseVersionId: seeded.snapshot.versionId,
    baseContentHash: seeded.snapshot.contentHash,
    field: 'event_date',
    value: { precision: 'date', value: '2027-06-28' },
    idempotencyKey: 'correct-after-payload-key-rotation',
    retentionHandle: f.createPermit(),
  }, f.authRequest);
  assert.equal(corrected.snapshot.revision, 2);

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    f.clock.value = EPOCH + (attempt - 1) * 60_000;
    const result = await f.store.dispatchPendingInvalidations(f.scope, f.authRequest);
    assert.equal(result.attempted, 1);
    assert.equal(result.delivered, 0);
    const cache = new DatabaseSync(cacheDatabasePath(f.root));
    try {
      const row = cache.prepare('SELECT status, attempt_count, payload_key_id, payload_bytes FROM reuse_outbox').get();
      assert.equal(row.attempt_count, attempt);
      assert.equal(row.payload_key_id, originalKeyId, 'delivery attempt reseals with the retained reservation key id');
      assert.ok(row.payload_bytes <= 2_048);
      assert.equal(row.status, attempt === 3 ? 'failed' : 'pending');
    } finally { cache.close(); }
  }
  f.clock.value = EPOCH + 180_000;
  const final = await f.store.outboxSnapshot(f.scope, f.authRequest);
  assert.equal(final.failed, 1);
  assert.equal(final.delivered, 0);
  assert.equal(final.readiness, 'blocked_pending_external_ack');
});

test('bound consumer projection rejects oversized attempt envelopes before the history barrier', async (t) => {
  for (const [length, shouldFit] of [[250, true], [300, true], [350, false], [400, false]]) {
    await t.test(`${length} UTF-8 multibyte consumer ${shouldFit ? 'is admitted' : 'is rejected'}`, async (subtest) => {
      const f = await fixture(subtest, { cache: { resolveInvalidationConsumers: () => ['é'.repeat(length)] } });
      await createSeed(f);
      const bind = f.store.bindPrivateProfile(f.scope, EVENT_ID,
        { idempotencyKey: `bound-consumer-size-${length}`, profile: cacheProfile() }, f.authRequest);
      if (shouldFit) {
        await bind;
        const correction = await f.store.applyCorrection(f.scope, {
          eventId: EVENT_ID,
          baseVersionId: (await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).versionId,
          baseContentHash: (await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).contentHash,
          field: 'event_date', value: { precision: 'date', value: '2027-06-26' },
          idempotencyKey: `correct-bound-consumer-${length}`, retentionHandle: f.createPermit(),
        }, f.authRequest);
        assert.equal(correction.snapshot.revision, 2);
        const cache = new DatabaseSync(cacheDatabasePath(f.root));
        try {
          const row = cache.prepare('SELECT payload_bytes, has_consumer, status FROM reuse_outbox').get();
          assert.equal(row.has_consumer, 1);
          assert.equal(row.status, 'pending');
          assert.equal(row.payload_bytes <= 2_048, true);
        } finally { cache.close(); }
        const readiness = await f.store.outboxSnapshot(f.scope, f.authRequest);
        assert.equal(readiness.readiness, 'blocked_pending_external_ack');
      } else {
        await assert.rejects(bind, (error) => error?.code === 'REUSE_CAPACITY');
        assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).revision, 1);
        assertNoPendingBinding(f.root);
        assert.equal(await access(cacheDatabasePath(f.root)).then(() => true, () => false), false,
          'consumer rejection occurs before the cache participant opens its database');
      }
    });
  }
});

test('bound preflight preserves zero and 64 consumer reservations and rejects 65 without trimming', async (t) => {
  await t.test('no consumers reserve one correction event without claiming external delivery', async (subtest) => {
    const f = await fixture(subtest, { cache: { resolveInvalidationConsumers: () => [] } });
    const seeded = await createSeed(f);
    await f.store.bindPrivateProfile(f.scope, EVENT_ID,
      { idempotencyKey: 'bind-zero-consumers', profile: cacheProfile() }, f.authRequest);
    const beforeInvalidation = new DatabaseSync(cacheDatabasePath(f.root));
    try {
      assert.equal(beforeInvalidation.prepare('SELECT outbox_slots FROM reuse_correction_reservations').get().outbox_slots, 1);
    } finally { beforeInvalidation.close(); }
    const correction = await f.store.applyCorrection(f.scope, {
      eventId: EVENT_ID, baseVersionId: seeded.snapshot.versionId, baseContentHash: seeded.snapshot.contentHash,
      field: 'event_date', value: { precision: 'date', value: '2027-06-27' },
      idempotencyKey: 'correct-zero-consumers', retentionHandle: f.createPermit(),
    }, f.authRequest);
    assert.equal(correction.snapshot.revision, 2);
    const cache = new DatabaseSync(cacheDatabasePath(f.root));
    try {
      const event = cache.prepare('SELECT has_consumer, status FROM reuse_outbox').get();
      assert.deepEqual({ ...event }, { has_consumer: 0, status: 'pending' });
    } finally { cache.close(); }
  });

  await t.test('64 consumers reserve all 128 slot classes and preserve each reference', async (subtest) => {
    const refs = Array.from({ length: 64 }, (_, index) => `consumer-${index}`);
    const f = await fixture(subtest, { cache: { resolveInvalidationConsumers: () => refs } });
    await createSeed(f);
    await f.store.bindPrivateProfile(f.scope, EVENT_ID,
      { idempotencyKey: 'bind-sixty-four-consumers', profile: cacheProfile() }, f.authRequest);
    const cache = new DatabaseSync(cacheDatabasePath(f.root));
    try {
      assert.equal(cache.prepare('SELECT outbox_slots FROM reuse_correction_reservations').get().outbox_slots, 64);
      assert.equal(cache.prepare('SELECT COUNT(*) AS count FROM reuse_consumer_refs').get().count, 64);
    } finally { cache.close(); }
  });

  await t.test('65 consumers fail before barrier and are not truncated', async (subtest) => {
    const refs = Array.from({ length: 65 }, (_, index) => `consumer-${index}`);
    const f = await fixture(subtest, { cache: { resolveInvalidationConsumers: () => refs } });
    await createSeed(f);
    await assert.rejects(f.store.bindPrivateProfile(f.scope, EVENT_ID,
      { idempotencyKey: 'bind-sixty-five-consumers', profile: cacheProfile() }, f.authRequest),
    (error) => error?.code === 'REUSE_POLICY_UNAVAILABLE');
    assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).revision, 1);
    assertNoPendingBinding(f.root);
    assert.equal(await access(cacheDatabasePath(f.root)).then(() => true, () => false), false,
      'the unsupported list is rejected before opening the cache database');
  });
});

test('bound cache byte and slot budgets admit exact capacity and reject one below before the history barrier', async (t) => {
  const baseline = await fixture(t);
  await createSeed(baseline);
  await baseline.store.bindPrivateProfile(baseline.scope, EVENT_ID,
    { idempotencyKey: 'bind-capacity-baseline', profile: cacheProfile() }, baseline.authRequest);
  const baselineCache = new DatabaseSync(cacheDatabasePath(baseline.root));
  let requiredBytes;
  try {
    const used = baselineCache.prepare(`SELECT
      (SELECT COALESCE(SUM(payload_bytes), 0) FROM reuse_entries) +
      (SELECT COALESCE(SUM(length(payload)), 0) FROM reuse_observations) +
      (SELECT COALESCE(SUM(length(payload)), 0) FROM reuse_consumer_refs) +
      (SELECT COALESCE(SUM(length(payload)), 0) FROM reuse_correction_reservations) +
      (SELECT COALESCE(SUM(payload_bytes), 0) FROM reuse_outbox) AS bytes`).get().bytes;
    const entrySlots = baselineCache.prepare(`SELECT
      (SELECT COALESCE(SUM(MAX(1, ref_count)), 0) FROM (
        SELECT e.entry_id, COUNT(c.consumer_hash) AS ref_count FROM reuse_entries AS e
        LEFT JOIN reuse_consumer_refs AS c ON c.entry_id = e.entry_id WHERE e.eligible = 1 GROUP BY e.entry_id
      )) + (SELECT COALESCE(SUM(outbox_slots), 0) FROM reuse_correction_reservations) AS slots`).get().slots;
    const version = baselineCache.prepare('SELECT version FROM reuse_entries LIMIT 1').get().version;
    const versionPlainDelta = String(Number.MAX_SAFE_INTEGER).length - String(version).length;
    const conservativeVersionBytes = 2 * 4 * Math.ceil(versionPlainDelta / 3);
    requiredBytes = used + entrySlots * 2_048 + conservativeVersionBytes;
  } finally { baselineCache.close(); }

  const exact = await fixture(t, { cache: { maxStoreBytes: requiredBytes, maxOutboxEntries: 2 } });
  await createSeed(exact);
  const bound = await exact.store.bindPrivateProfile(exact.scope, EVENT_ID,
    { idempotencyKey: 'bind-exact-cache-capacity', profile: cacheProfile() }, exact.authRequest);
  assert.equal(bound.status, 'bound');

  for (const [label, cacheLimits] of [
    ['one byte below', { maxStoreBytes: requiredBytes - 1, maxOutboxEntries: 2 }],
    ['one outbox slot below', { maxStoreBytes: requiredBytes, maxOutboxEntries: 1 }],
  ]) {
    await t.test(label, async (subtest) => {
      const f = await fixture(subtest, { cache: cacheLimits });
      await createSeed(f);
      await assert.rejects(f.store.bindPrivateProfile(f.scope, EVENT_ID,
        { idempotencyKey: `bind-${label.replaceAll(' ', '-')}`, profile: cacheProfile() }, f.authRequest),
      (error) => error?.code === 'REUSE_CAPACITY');
      assert.equal((await f.store.getHistory(f.scope, EVENT_ID, f.authRequest)).revision, 1);
      assertNoPendingBinding(f.root);
      const database = new DatabaseSync(cacheDatabasePath(f.root));
      try {
        assert.equal(database.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count, 0);
        assert.equal(database.prepare('SELECT COUNT(*) AS count FROM reuse_correction_reservations').get().count, 0);
        assert.equal(database.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 0);
      } finally { database.close(); }
    });
  }
});

test('bound preflight resolves private participants and write keys before the barrier without late callbacks', async (t) => {
  let rootPath;
  const calls = { references: 0, lineage: 0, consumers: 0, keyPurposes: [], afterBarrier: [] };
  const recordCallback = (name) => {
    if (rootPath) {
      const database = new DatabaseSync(historyDatabasePath(rootPath));
      try {
        const pending = database.prepare("SELECT COUNT(*) AS count FROM correction_cache_state WHERE phase = 'pending_bind'").get().count;
        if (pending !== 0) calls.afterBarrier.push(name);
      } finally { database.close(); }
    }
    if (name !== 'keyPurposes') calls[name] += 1;
  };
  const f = await fixture(t, { cache: {
    resolvePrivateProfileReferences(input) {
      recordCallback('references');
      return { permissions: [{ reference: 'preflight-permission', contentHash: input.contentHash,
        version: 1, use: 'cache_read' }], sourceRefs: ['preflight-source'], correctionRefs: ['preflight-correction'] };
    },
    resolveLineage() { recordCallback('lineage'); return { status: 'unknown' }; },
    resolveInvalidationConsumers() { recordCallback('consumers'); return ['preflight-consumer']; },
    resolveKey({ tenantId, scope, purpose, keyId }) {
      recordCallback('keyPurposes');
      calls.keyPurposes.push(purpose);
      const resolvedId = `${scope}:${purpose}:${tenantId ?? 'global'}:v1`;
      if (keyId && keyId !== resolvedId) throw new Error('unexpected preflight key identifier');
      return { keyId: resolvedId,
        key: createHash('sha256').update(`${tenantId}:${scope}:${purpose}:one-shot-preflight-test-key`).digest() };
    },
  } });
  rootPath = f.root;
  await createSeed(f);

  const result = await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-one-shot-preflight', profile: cacheProfile() }, f.authRequest);
  assert.equal(result.status, 'bound');
  assert.equal(calls.references, 1);
  assert.equal(calls.lineage, 1);
  assert.equal(calls.consumers, 1);
  assert.deepEqual(calls.keyPurposes.sort(), ['index', 'index', 'payload'],
    'one index key establishes the paired scope and one index/payload pair forms the reusable write preflight');
  assert.deepEqual(calls.afterBarrier, [], 'no participant or key callback is repeated after the durable barrier');
});

test('unsupported accumulated support references fail before a durable bind barrier', async (t) => {
  const f = await fixture(t);
  let current = await createSeed(f);
  for (let batch = 0; batch < 2; batch += 1) {
    current = await f.store.refreshSources(f.scope, {
      eventId: EVENT_ID,
      baseVersionId: current.snapshot.versionId,
      baseContentHash: current.snapshot.contentHash,
      sourceFacts: { venue: { status: 'sourced', value: 'Civic Hall',
        sourceEvidence: Array.from({ length: 32 }, (_, index) =>
          sourceEvidence(`support-ref-${batch}-${index}`, `support-ref:${batch}:${index}`)) } },
      idempotencyKey: `support-reference-refresh-${batch}`,
      retentionHandle: f.createPermit(),
    }, f.authRequest);
  }
  assert.equal(current.snapshot.fields.venue.candidates
    .find((entry) => entry.value === 'Civic Hall').sourceEvidence.length, 65);

  const bindError = await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-65-accumulated-support-references', profile: cacheProfile() }, f.authRequest)
    .then(() => null, (error) => error);
  assert.equal(bindError?.code, 'REUSE_INVALID');
  const reopenedHistory = await f.store.getHistory(f.scope, EVENT_ID, f.authRequest);
  assert.equal(reopenedHistory.contentHash, current.snapshot.contentHash);
  assert.equal(reopenedHistory.fields.venue.candidates
    .find((entry) => entry.value === 'Civic Hall').sourceEvidence.length, 65,
  'preflight must preserve immutable support evidence instead of truncating it');
  const history = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.equal(history.prepare("SELECT COUNT(*) AS count FROM correction_cache_operations WHERE kind = 'bind'").get().count, 0);
    assert.equal(history.prepare("SELECT COUNT(*) AS count FROM correction_cache_state WHERE phase = 'pending_bind'").get().count, 0);
  } finally { history.close(); }
});

for (const kind of ['correction', 'source_refresh']) {
  test(`composed ${kind} rechecks private history permission after cache host work and exact retry does not duplicate effects`, async (t) => {
    let revokeHistoryRead = false;
    let revokeOnInvalidate = false;
    let cacheInvalidationReached = false;
    const historyReadDecisions = [];
    const f = await fixture(t, {
      history: {
        authorizeBoundary(input) {
          const denied = revokeHistoryRead && input.action === 'private_profile.read';
          const allowed = !denied && input.request?.serverContextToken === TRUSTED_TOKEN
            && input.request?.principal?.tenantId === input.tenantId
            && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
          if (input.action === 'private_profile.read') historyReadDecisions.push(allowed);
          return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
            eventId: input.eventId, action: input.action, field: input.field, nowMs: f.clock.value }) : false;
        },
      },
      cache: {
        authorizeBoundary(input) {
          if (revokeOnInvalidate && input.action === 'cache.private_profile.invalidate') {
            cacheInvalidationReached = true;
            revokeHistoryRead = true;
          }
          const allowed = input.request?.serverContextToken === TRUSTED_TOKEN
            && input.request?.principal?.tenantId === input.tenantId
            && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
          return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
            eventId: input.eventId, action: input.action, field: input.field, nowMs: f.clock.value }) : false;
        },
      },
    });
    const seeded = await createSeed(f);
    await f.store.bindPrivateProfile(f.scope, EVENT_ID,
      { idempotencyKey: `bind-final-${kind}`, profile: cacheProfile() }, f.authRequest);
    const input = kind === 'correction' ? {
      eventId: EVENT_ID,
      baseVersionId: seeded.snapshot.versionId,
      baseContentHash: seeded.snapshot.contentHash,
      field: 'event_date',
      value: { precision: 'date', value: '2027-06-27' },
      idempotencyKey: `final-disclosure-${kind}`,
      retentionHandle: f.createPermit(),
    } : {
      eventId: EVENT_ID,
      baseVersionId: seeded.snapshot.versionId,
      baseContentHash: seeded.snapshot.contentHash,
      sourceFacts: { event_date: { status: 'sourced', value: { precision: 'date', value: '2027-06-28' },
        sourceEvidence: [sourceEvidence(`final-disclosure-${kind}`, '2027-06-28')] } },
      idempotencyKey: `final-disclosure-${kind}`,
      retentionHandle: f.createPermit(),
    };
    const invoke = () => kind === 'correction'
      ? f.store.applyCorrection(f.scope, input, f.authRequest)
      : f.store.refreshSources(f.scope, input, f.authRequest);

    revokeOnInvalidate = true;
    const denied = await invoke().then(() => null, (error) => error);
    assert.equal(denied?.code, 'REVIEW_DENIED');
    assert.equal(cacheInvalidationReached, true, 'cache host invalidation ran before final history disclosure');
    assert.equal(historyReadDecisions.at(-1), false, 'the final history disclosure guard observed revoked permission');

    const historyDb = new DatabaseSync(historyDatabasePath(f.root));
    const cacheDb = new DatabaseSync(cacheDatabasePath(f.root));
    try {
      assert.equal(historyDb.prepare('SELECT COUNT(*) AS count FROM versions').get().count, 2,
        'the committed history effect remains durable although its result was denied');
      assert.equal(historyDb.prepare('SELECT COUNT(*) AS count FROM idempotency').get().count, 2);
      assert.equal(historyDb.prepare("SELECT phase FROM correction_cache_state WHERE kind = ?").get(kind).phase, 'complete');
      assert.equal(cacheDb.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 1);
    } finally { historyDb.close(); cacheDb.close(); }

    revokeHistoryRead = false;
    revokeOnInvalidate = false;
    const retried = await invoke();
    assert.equal(retried.replayed, true);
    assert.equal(retried.snapshot.revision, seeded.snapshot.revision + 1);
    const afterRetryHistory = new DatabaseSync(historyDatabasePath(f.root));
    const afterRetryCache = new DatabaseSync(cacheDatabasePath(f.root));
    try {
      assert.equal(afterRetryHistory.prepare('SELECT COUNT(*) AS count FROM versions').get().count, 2,
        'exact retry returns the committed version without adding a duplicate');
      assert.equal(afterRetryHistory.prepare('SELECT COUNT(*) AS count FROM idempotency').get().count, 2);
      assert.equal(afterRetryCache.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count, 1,
        'the invalidation receipt prevents duplicate cache outbox work');
    } finally { afterRetryHistory.close(); afterRetryCache.close(); }
  });
}

test('abort during final history disclosure rejects createHistory but exact retry replays its committed version', async (t) => {
  const controller = new AbortController();
  let abortAtRead = false;
  let finalReadReached = false;
  const f = await fixture(t, { history: {
    authorizeBoundary(input) {
      if (input.action === 'private_profile.read' && abortAtRead) {
        finalReadReached = true;
        controller.abort();
      }
      const allowed = input.request?.serverContextToken === TRUSTED_TOKEN
        && input.request?.principal?.tenantId === input.tenantId
        && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
      return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
        eventId: input.eventId, action: input.action, field: input.field, nowMs: f.clock.value }) : false;
    },
  } });
  const history = await historyStoreFor(f);
  const input = { eventId: EVENT_ID, sourceFacts: initialFacts(), idempotencyKey: 'abort-final-history-disclosure',
    retentionHandle: f.createPermit() };

  abortAtRead = true;
  await assert.rejects(history.history.createHistory(history.scope, input, f.authRequest, { signal: controller.signal }),
    (error) => error instanceof ReviewHistoryError && error.code === 'REVIEW_ABORTED');
  assert.equal(finalReadReached, true, 'the genuine signal aborted from the final private read guard');
  const afterAbort = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.equal(afterAbort.prepare('SELECT COUNT(*) AS count FROM versions').get().count, 1,
      'the already-committed history version remains available after disclosure cancellation');
    assert.equal(afterAbort.prepare('SELECT COUNT(*) AS count FROM idempotency').get().count, 1);
  } finally { afterAbort.close(); }

  abortAtRead = false;
  const replay = await history.history.createHistory(history.scope, input, f.authRequest);
  assert.equal(replay.replayed, true);
  const afterRetry = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.equal(afterRetry.prepare('SELECT COUNT(*) AS count FROM versions').get().count, 1,
      'the authorized exact retry discloses the existing version without duplicating it');
    assert.equal(afterRetry.prepare('SELECT COUNT(*) AS count FROM idempotency').get().count, 1);
  } finally { afterRetry.close(); }
});

test('composed correction refuses final disclosure when history expires during final SQLite guard work', async (t) => {
  let afterCacheInvalidation = false;
  let finalHistoryGuard = false;
  const f = await fixture(t, {
    history: {
      authorizeBoundary(input) {
        if (input.action === 'private_profile.read' && afterCacheInvalidation) {
          finalHistoryGuard = true;
          f.clock.value = EPOCH + 59_950;
        }
        const allowed = input.request?.serverContextToken === TRUSTED_TOKEN
          && input.request?.principal?.tenantId === input.tenantId
          && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
        return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
          eventId: input.eventId, action: input.action, field: input.field, nowMs: f.clock.value }) : false;
      },
    },
    cache: {
      authorizeBoundary(input) {
        if (input.action === 'cache.private_profile.invalidate') afterCacheInvalidation = true;
        const allowed = input.request?.serverContextToken === TRUSTED_TOKEN
          && input.request?.principal?.tenantId === input.tenantId
          && input.request?.principal?.actorId === input.actorId && input.actorId !== 'outsider';
        return allowed ? Object.freeze({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
          eventId: input.eventId, action: input.action, field: input.field, nowMs: f.clock.value }) : false;
      },
    },
  });
  const seeded = await createSeed(f);
  await f.store.bindPrivateProfile(f.scope, EVENT_ID,
    { idempotencyKey: 'bind-final-correction-expiry', profile: cacheProfile() }, f.authRequest);
  const interception = interceptHistoryDisclosureGuard(() => {
    const deadline = process.hrtime.bigint() + 100_000_000n;
    while (process.hrtime.bigint() < deadline) { /* Expire the history retention after the final permit is captured. */ }
  }, () => afterCacheInvalidation);
  t.after(interception.restore);
  let result;
  let error;
  try {
    result = await f.store.applyCorrection(f.scope, {
      eventId: EVENT_ID,
      baseVersionId: seeded.snapshot.versionId,
      baseContentHash: seeded.snapshot.contentHash,
      field: 'event_date',
      value: { precision: 'date', value: '2027-06-29' },
      idempotencyKey: 'final-correction-expiry',
      retentionHandle: f.createPermit(),
    }, f.authRequest);
  } catch (caught) { error = caught; }
  finally { interception.restore(); }

  assert.equal(afterCacheInvalidation, true);
  assert.equal(finalHistoryGuard, true, 'the final history permit was captured after all cache host work');
  assert.equal(interception.reached(), true, 'synchronous SQLite work crossed the history expiry boundary');
  assert.equal(error?.code, 'REVIEW_EXPIRED');
  assert.equal(result, undefined, 'the expired history result was not disclosed');
  const historyDb = new DatabaseSync(historyDatabasePath(f.root));
  try {
    assert.equal(historyDb.prepare('SELECT COUNT(*) AS count FROM versions').get().count, 2,
      'expiry denies disclosure without undoing the committed correction');
    assert.equal(historyDb.prepare("SELECT phase FROM correction_cache_state WHERE kind = 'correction'").get().phase,
      'complete');
  } finally { historyDb.close(); }
});
