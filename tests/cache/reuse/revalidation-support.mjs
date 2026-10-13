import assert from 'node:assert/strict';
import { createDecipheriv, createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import os from 'node:os';
import path from 'node:path';
import { SafeFetcher } from '../../../src/security/controlled-fetch.mjs';
import { createEvidenceStore } from '../../../src/evidence/store.mjs';
import { safeFetchProvenance } from '../../../src/security/internal/fetch-lifecycle.mjs';
import { createScopedReuseStore } from '../../../src/cache/reuse/store.mjs';
import { createPrivateCacheRevalidation } from '../../../src/cache/reuse/revalidation.mjs';
import { startFixture, localTestSeam, fixtureUrl, respond } from '../../security/support.mjs';

// All principals, permissions, keys and expense IDs below are synthetic local
// host authority. The HTTP server, SafeFetcher, encrypted evidence/cache stores,
// conditional headers and durable joins are actual implementation paths.
export const BODY = 'Event: Conditional Cache Test\nVenue: Test Hall\n';
export const IDENTITY = Object.freeze({ occurrenceId: 'synthetic-occurrence', entityId: 'synthetic-entity', editionId: 'synthetic-edition' });
export const PINS = Object.freeze({ schemaVersion: 'local-profile-1', extractorVersion: 'local-extractor-1', questionSetVersion: 'local-questions-1', policyHash: 'a'.repeat(64), modelVersion: 'none' });
export const hash = (value) => createHash('sha256').update(value).digest('hex');
export const request = (tenantId = 'synthetic-tenant', actorId = 'synthetic-actor') => ({ principal: { tenantId, actorId } });

export function gate() {
  let entered;
  let release;
  const reached = new Promise((resolve) => { entered = resolve; });
  const released = new Promise((resolve) => { release = resolve; });
  return { reached, release, async wait() { entered(); await released; } };
}

export async function revalidationFixture(t, overrides = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ei-conditional-revalidation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const state = {
    requests: [], phases: [], response: '304', etag: '"PRIVATE_VALIDATOR_CANARY"',
    offset: 0, authorized: true, permission: true, evidenceAvailable: true,
    phaseHook: null, boundaryHook: null, authHook: null, beforeResponse: null, keyVersion: '1',
    financeCalls: 0, sourceRefs: null,
  };
  const now = () => Date.now() + state.offset;
  const initialHeaders = overrides.initialHeaders ?? { etag: state.etag };
  const server = await startFixture(async (incoming, response) => {
    state.requests.push({ url: incoming.url, headers: { ...incoming.headers } });
    if (state.requests.length === 1) return respond(response, 200, { 'content-type': 'text/plain; charset=utf-8', ...initialHeaders }, BODY);
    if (state.beforeResponse) await state.beforeResponse();
    if (state.response === 'abort') return incoming.socket.destroy();
    if (state.response === 'redirect') return respond(response, 302, { location: '/validator-must-not-follow' });
    if (state.response === '304') return respond(response, 304, { etag: state.etag });
    if (state.response === '304-missing') return respond(response, 304);
    if (state.response === '304-duplicate') return respond(response, 304, { etag: [state.etag, state.etag] });
    if (state.response === '304-other') return respond(response, 304, { etag: '"DIFFERENT"' });
    if (state.response === '304-date') return respond(response, 304, { 'last-modified': initialHeaders['last-modified'] });
    if (state.response === 'same') return respond(response, 200, { 'content-type': 'text/plain', etag: state.etag }, BODY);
    if (state.response === 'same-other-type') return respond(response, 200, { 'content-type': 'text/html', etag: state.etag }, BODY);
    if (state.response === 'changed') return respond(response, 200, { 'content-type': 'text/plain', etag: '"new-body"' }, `${BODY}Changed source body\n`);
    if (state.response === 'charset') return respond(response, 200, { 'content-type': 'text/plain; charset=iso-8859-1', etag: state.etag }, BODY);
    return respond(response, Number(state.response), { etag: state.etag });
  });
  t.after(() => server.close());
  const sourceUrl = fixtureUrl(server.port, '/PRIVATE_SOURCE_URL_CANARY');
  const safeFetcher = new SafeFetcher(localTestSeam({ port: server.port }));
  const document = await safeFetcher.fetch(sourceUrl);
  const authRequest = request();
  const evidenceOptions = {
    directory: path.join(directory, 'evidence'), now,
    resolveTenant: (r) => r?.principal?.tenantId,
    resolveKey: ({ tenantId, purpose, keyId }) => ({ keyId: keyId ?? `${purpose}-1`, key: createHash('sha256').update(`${tenantId}:${purpose}:synthetic-evidence-key`).digest() }),
    resolveRetention: ({ nowMs }) => ({ expiresAtMs: nowMs + 60_000, policyId: 'synthetic-full-original', policyVersion: '1', accessPolicy: 'tenant_private' }),
    authorizePrivateAccess: ({ tenantId, request: r }) => state.evidenceAvailable && r?.principal?.tenantId === tenantId,
    authorizePrivateAccessCurrent: ({ tenantId, request: r }) => state.evidenceAvailable && r?.principal?.tenantId === tenantId,
    consumePrivatePayload: ({ source, positions }) => ({
      sourceUrl: source.sourceUrl, sourceHash: source.contentHash, retrievedAt: source.retrievedAt,
      positions: positions.map((position) => ({ locator: position.locator, bytes: Buffer.from(position.content).toString('base64') })),
    }),
    maxRetentionMs: 120_000,
  };
  const evidenceStore = createEvidenceStore(evidenceOptions);
  const evidenceScope = await evidenceStore.scopeForAuthenticatedRequest(authRequest);
  const evidence = await evidenceStore.ingestEvidence(evidenceScope, {
    sourceUrl, content: document.bytes, contentType: document.contentType, retrievedAt: document.fetchedAt,
    sourceKind: 'external', retentionHandle: Object.freeze({}),
    positions: [{ locator: { kind: 'text-range', startByte: 0, endByte: document.bytes.byteLength }, content: document.bytes }],
  });
  const sourceRef = `retained-original:${evidence.metadata.evidenceId}`;
  const currentKey = ({ tenantId, scope, purpose, keyId }) => {
    const selected = keyId ?? `${scope}:${purpose}:${state.keyVersion}`;
    return { keyId: selected, key: createHash('sha256').update(`${tenantId}:${selected}:synthetic-cache-key`).digest() };
  };
  const options = {
    directory: path.join(directory, 'cache'), now, defaultFreshnessTtlMs: 5_000,
    resolveTenant: (r) => r?.principal?.tenantId,
    resolveActor: (r) => r?.principal?.actorId,
    authorizeAction: async () => { if (state.authHook) await state.authHook(); return state.authorized; },
    authorizeCurrentRequest: ({ expectedTenantId, expectedActorId, request: r }) => state.authorized
      && r?.principal?.tenantId === expectedTenantId && r?.principal?.actorId === expectedActorId,
    authorizeBoundary: (input) => {
      state.boundaryHook?.(input);
      if (!state.authorized || input.request?.principal?.tenantId !== input.tenantId || input.request?.principal?.actorId !== input.actorId) return false;
      return { authorized: true, tenantId: input.tenantId, actorId: input.actorId, eventId: input.eventId,
        action: input.action, field: input.field, nowMs: now() };
    },
    resolveKey: currentKey,
    resolveRetention: ({ nowMs }) => ({ expiresAtMs: nowMs + 60_000, policyId: 'synthetic-private', policyVersion: '1' }),
    verifySourceObservation: ({ purpose, observation }) => {
      assert.equal(purpose, 'initial', 'conditional observations must use genuine private transport proof, not this initial seam');
      assert.equal(safeFetchProvenance(observation)?.bodyHash, hash(BODY));
      return { status: 'body_changed', contentHash: hash(BODY), retrievedAt: observation.fetchedAt,
        validatedAt: observation.fetchedAt, sourceVersion: 'synthetic-source-1', attemptLineage: { status: 'unknown' } };
    },
    resolvePrivateProfileReferences: ({ contentHash }) => ({ sourceRefs: state.sourceRefs ?? [sourceRef], correctionRefs: [],
      permissions: [{ reference: 'PRIVATE_PERMISSION_CANARY', contentHash, version: 1, use: 'cache_read' }] }),
    verifyPermission: ({ reference, contentHash, version, use, nowMs }) => state.permission
      ? { status: 'valid', reference, contentHash, version, use, validUntilMs: nowMs + 60_000 } : 'revoked',
    resolveLineage: () => ({ status: 'complete', logicalOperationId: 'SYNTHETIC_ORIGINAL_OPERATION', billableAttemptId: 'SYNTHETIC_ORIGINAL_EXPENSE',
      transportAttemptId: 'SYNTHETIC_ORIGINAL_TRANSPORT', observationIds: ['SYNTHETIC_ORIGINAL_OBSERVATION'], usageEventIds: ['SYNTHETIC_ORIGINAL_USAGE'] }),
    resolveInvalidationConsumers: () => ['SYNTHETIC_UNACKED_CONSUMER'],
    verifyAdmissionOutcome: () => { state.financeCalls += 1; throw new Error('No Finance completion authority in this fixture'); },
    ...overrides.storeOptions,
  };
  let store = createScopedReuseStore(options);
  let scope = await store.scopeForAuthenticatedRequest(authRequest);
  const lookup = { identity: IDENTITY, pins: PINS, contentHash: hash(BODY) };
  const profile = await store.putPrivateProfile(scope, authRequest, { ...lookup, facts: { event_name: { status: 'sourced', value: 'Conditional Cache Test', supportRefs: [sourceRef] } }, observation: document });
  const readRetainedSource = async ({ request: r, binding, phase }) => {
    state.phases.push(phase);
    if (state.phaseHook) await state.phaseHook(phase, binding);
    assert.equal(binding.scopeKind, 'tenant_private');
    assert.equal(binding.tenantId, authRequest.principal.tenantId);
    assert.equal(binding.actorId, authRequest.principal.actorId);
    assert.equal(binding.profileRef, profile.profileRef);
    assert.equal(binding.profileVersion, profile.version);
    assert.deepEqual(binding.identity, IDENTITY);
    assert.deepEqual(binding.pins, PINS);
    assert.equal(binding.sourceRef, sourceRef);
    assert.equal(binding.evidenceId, evidence.metadata.evidenceId);
    assert.equal(binding.evidenceVersion, evidence.metadata.version);
    assert.equal(binding.sourceUrl, sourceUrl);
    assert.equal(binding.originalBodyHash, evidence.metadata.contentHash);
    assert.equal(binding.profileContentHash, hash(BODY));
    assert.equal(binding.profileHashDomain, 'safe-fetch-decoded-entity-bytes/v1');
    // Reopen the actual encrypted store each time, with the current request.
    const reopened = createEvidenceStore(evidenceOptions);
    const currentScope = await reopened.scopeForAuthenticatedRequest(r);
    const handle = await reopened.lookupEvidence(currentScope, binding.evidenceId);
    const metadata = await reopened.getEvidenceMetadata(currentScope, handle);
    assert.equal(metadata.state, 'available');
    assert.equal(metadata.version, binding.evidenceVersion);
    const retained = await reopened.withPrivatePayload(currentScope, handle, r);
    assert.equal(retained.sourceUrl, binding.sourceUrl);
    assert.equal(retained.sourceHash, binding.originalBodyHash);
    assert.equal(retained.retrievedAt, binding.originalRetrievedAt);
    assert.equal(retained.positions.length, 1);
    assert.deepEqual({ ...retained.positions[0].locator }, { kind: 'text-range', startByte: 0, endByte: Buffer.byteLength(BODY) });
    return { binding, representation: 'full_original_response', bytes: Buffer.from(retained.positions[0].bytes, 'base64'),
      validUntilMs: Math.min(binding.expiresAtMs, Date.parse(metadata.expiresAt)) };
  };
  const makeCoordinator = (extra = {}) => createPrivateCacheRevalidation({ store, safeFetcher, readRetainedSource, ...extra });
  let coordinator = makeCoordinator();
  const bindInput = { profileRef: profile.profileRef, scopeKind: 'tenant_private', sourceRef,
    evidenceId: evidence.metadata.evidenceId, evidenceVersion: evidence.metadata.version, document };
  function database(operation) {
    const db = new DatabaseSync(path.join(options.directory, 'scoped-reuse.sqlite'));
    try { return operation(db); } finally { db.close(); }
  }
  function decode(row, kind, id) {
    const envelope = JSON.parse(Buffer.from(row.payload).toString());
    const key = currentKey({ tenantId: authRequest.principal.tenantId, scope: 'tenant_private', purpose: 'payload', keyId: row.payload_key_id }).key;
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(Buffer.from(`event-intelligence:scoped-reuse:v1:${kind}:${row.partition_hash}:${id}:${row.payload_key_id}`));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]).toString());
  }
  const env = {
    directory, state, document, sourceUrl, safeFetcher, evidence, evidenceOptions, sourceRef, options, profile, lookup, authRequest, bindInput,
    get store() { return store; }, get scope() { return scope; }, get coordinator() { return coordinator; },
    makeCoordinator, readRetainedSource,
    async bind(extra = {}) { return coordinator.bindSource(scope, authRequest, { ...bindInput, ...extra }); },
    async admit(mode = 'reuse', extra = {}) { return store.admitOperation(scope, authRequest, { identity: IDENTITY, pins: PINS, mode, ...extra }); },
    async refresh(admissionRef, optionsValue) { return coordinator.refresh(scope, authRequest, { profileRef: profile.profileRef, scopeKind: 'tenant_private', admissionRef }, optionsValue); },
    async reopen(extra = {}) {
      store = createScopedReuseStore({ ...options, ...extra });
      scope = await store.scopeForAuthenticatedRequest(authRequest);
      coordinator = makeCoordinator();
    },
    database,
    snapshot() {
      return database((db) => {
        const entry = db.prepare('SELECT * FROM reuse_entries WHERE entry_id = ?').get(profile.profileRef);
        const observations = db.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence').all(profile.profileRef)
          .map((row) => ({ id: row.observation_id, ...decode({ ...row, partition_hash: entry.partition_hash }, 'observation', row.observation_id) }));
        const flights = db.prepare('SELECT * FROM reuse_flights').all().map((row) => ({ state: row.state, ...decode(row, 'flight', row.admission_id) }));
        return { eligible: entry.eligible, profile: entry.payload_purged ? null : decode(entry, 'entry', entry.entry_id), observations, flights,
          sourceBindings: db.prepare('SELECT COUNT(*) AS count FROM reuse_refresh_sources').get().count,
          outbox: db.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count };
      });
    },
    async encryptedBytes() { return readFile(path.join(options.directory, 'scoped-reuse.sqlite')); },
  };
  return env;
}
