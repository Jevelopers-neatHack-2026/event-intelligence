import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createEvidenceStore } from '../../../src/evidence/store.mjs';
import { composeSourceIdentity } from '../../../src/discovery/identity/from-extraction.mjs';
import { buildSourceCorroboration, corroborationDigest, validateSourceCorroboration } from '../../../src/discovery/identity/corroboration.mjs';
import { prepareIdentityQuestionFromComposition } from '../../../src/decisions/questions/index.mjs';

const REQUEST = Object.freeze({ tenantId: 'attribution-test-tenant', allowed: true });

async function harness(t, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ei-attribution-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const permits = new WeakMap();
  const clock = { value: Date.now() };
  const createPermit = () => {
    const permit = Object.freeze({});
    permits.set(permit, clock.value + 120_000);
    return permit;
  };
  const settings = {
    directory,
    now: () => clock.value,
    resolveTenant: (request) => request?.tenantId,
    resolveKey: ({ tenantId, purpose, keyId }) => {
      const id = `${purpose}-attribution-test-v1`;
      if (keyId && keyId !== id) throw new Error('unexpected fixture key');
      return { keyId: id, key: createHash('sha256').update(`${tenantId}:${purpose}`).digest() };
    },
    resolveRetention: ({ kind, retentionHandle, sourceExpiresAtMs, nowMs }) => {
      const expiresAtMs = kind === 'evidence' ? permits.get(retentionHandle) : sourceExpiresAtMs ?? nowMs + 60_000;
      if (!expiresAtMs) throw new Error('missing fixture retention permit');
      return { expiresAtMs, policyId: 'attribution-fixture', policyVersion: '1', accessPolicy: 'tenant_private' };
    },
    authorizePrivateAccess: ({ tenantId, request }) => request?.tenantId === tenantId && request.allowed === true,
    authorizePrivateAccessCurrent: ({ tenantId, request }) => request?.tenantId === tenantId && request.allowed === true,
    maxSourceBytes: 2 * 1024 * 1024,
    maxPositionBytes: 64 * 1024,
    maxPositionCount: 128,
    maxStoredPayloadBytes: 512 * 1024,
    maxRetentionMs: 180_000,
    ...options,
  };
  const store = createEvidenceStore(settings);
  return { store, reopen: () => createEvidenceStore(settings), createPermit, clock };
}

function page(url, entities, extra = '') {
  const body = Array.isArray(entities) ? { '@graph': entities } : entities;
  return {
    url, contentType: 'text/html; charset=utf-8', fetchedAt: '2026-10-12T12:00:00.000Z', redirects: 0,
    bytes: Buffer.from(`<!doctype html><script type="application/ld+json">${JSON.stringify(body)}</script>${extra}`),
  };
}

function event(name, extra = {}) {
  return { '@type': 'Event', name, startDate: '2027-08-01', ...extra };
}

function compose(h, documents, store = h.store, request = REQUEST) {
  return composeSourceIdentity({
    sources: documents.map((document) => ({ document, retentionHandle: h.createPermit() })),
    request, evidenceStore: store,
  });
}

function candidate(result, name) {
  const value = result.occurrenceCandidates.find((item) => item.facts.title?.some((claim) => claim.value === name));
  assert.ok(value, `actual composer produced ${name}`);
  return value.candidateId;
}

function cluster(result, candidateId) {
  assert.equal(result.corroboration.schema, 'ei-source-corroboration-internal/v1');
  const value = result.corroboration.clusters.find((item) => item.members.includes(candidateId));
  assert.ok(value, 'every eligible entity has one explicit cluster');
  return value;
}

function preparePair(result, left, right) {
  const pair = [left, right];
  const used = new Set(result.occurrenceCandidates.filter((item) => pair.includes(item.candidateId))
    .flatMap((item) => Object.values(item.facts).flatMap((claims) => claims.flatMap((claim) => claim.supports.map((support) => support.evidenceId)))));
  return prepareIdentityQuestionFromComposition(result, {
    candidateIds: pair, languageByEvidenceId: Object.fromEntries([...used].map((id) => [id, 'en'])),
  });
}

test('explicit retained derivation groups altered sources while preserving unknown independent origin', async (t) => {
  const h = await harness(t);
  const documents = [
    page('https://origin.example.test/event', event('Original')),
    page('https://copy.example.test/event', event('Altered copy', { isBasedOn: 'https://origin.example.test/event', startDate: '2027-08-02' })),
    page('https://independent.example.test/event', event('Independent', { brand: 'Original' })),
  ];
  const result = await compose(h, documents);
  assert.equal(result.schema, 'ei-source-identity-composition-internal/v2');
  const original = candidate(result, 'Original');
  const copy = candidate(result, 'Altered copy');
  const independent = candidate(result, 'Independent');
  assert.equal(cluster(result, original).clusterId, cluster(result, copy).clusterId);
  assert.notEqual(cluster(result, original).clusterId, cluster(result, independent).clusterId);
  assert.notEqual(result.sources[0].evidence.contentHash, result.sources[1].evidence.contentHash);
  assert.notEqual(result.sources[0].evidence.duplicateGroupId, result.sources[1].evidence.duplicateGroupId);
  assert.equal(result.corroboration.edges.filter((edge) => edge.basis === 'source_declared_derivation').length, 1);
  assert.equal(result.sourceAuthority, 'not_evaluated');
  assert.ok(result.facts.every((fact) => fact.supports.every((support) => support.independence === 'unknown')));
  const declaration = result.facts.find((fact) => fact.field === 'isBasedOn');
  assert.equal(declaration?.status, 'sourced');
  assert.equal(declaration?.rawValue, '"https://origin.example.test/event"');
  assert.equal(declaration?.normalizedValue, 'https://origin.example.test/event');
  assert.ok(result.occurrenceDecisions.some((decision) => decision.conflictFields.includes('start')));
  const reopened = h.reopen();
  const scope = await reopened.scopeForAuthenticatedRequest(REQUEST);
  const handle = await reopened.lookupFact(scope, declaration.factId);
  const persisted = await reopened.readFact(scope, handle, REQUEST);
  assert.equal(persisted.rawValue, declaration.rawValue);
  assert.equal(persisted.normalizedValue, declaration.normalizedValue);
  const replay = await compose(h, [...documents].reverse(), reopened);
  assert.equal(replay.corroboration.digest, result.corroboration.digest, 'input ordering and reopen do not change retained attribution decisions');
});

test('a source declaration belongs only to its entity on a multi-event page', async (t) => {
  const h = await harness(t);
  const result = await compose(h, [
    page('https://origin.example.test/event', event('Original')),
    page('https://copy.example.test/events', [
      event('Declared copy', { isBasedOn: 'https://origin.example.test/event' }),
      event('Separate sibling'),
    ]),
  ]);
  assert.equal(cluster(result, candidate(result, 'Original')).clusterId, cluster(result, candidate(result, 'Declared copy')).clusterId);
  assert.notEqual(cluster(result, candidate(result, 'Original')).clusterId, cluster(result, candidate(result, 'Separate sibling')).clusterId);
  assert.equal(result.corroboration.clusters.length, 2);
});

test('actual question consumer carries shared dependency context without collapsing candidate observations', async (t) => {
  const h = await harness(t);
  const result = await compose(h, [
    page('https://origin.example.test/event', event('Original')),
    page('https://copy.example.test/event', event('Declared copy', { isBasedOn: 'https://origin.example.test/event' })),
  ]);
  const pair = [candidate(result, 'Original'), candidate(result, 'Declared copy')];
  const prepared = preparePair(result, ...pair);
  const binding = prepared.sourceIdentityBinding;
  assert.equal(binding.schema, 'ei-source-identity-question-binding-internal/v2');
  assert.equal(binding.observationGroups.length, 2);
  const groups = binding.observationGroups.map((group) => JSON.parse(group.text));
  assert.equal(groups[0].corroboration.clusterId, groups[1].corroboration.clusterId);
  assert.ok(groups.every((group) => group.corroboration.independence === 'unknown'));
  assert.equal(binding.corroboration.sourceGraphDigest, result.corroboration.digest);
  assert.equal(prepared.plan.executionStatus, 'not_dispatched');
  assert.equal(prepared.plan.promotionStatus, 'unpromoted');
  assert.equal(prepared.plan.authorityScope.sourceOfficialnessGranted, false);
  assert.equal(new Set(binding.observationGroups.map((group) => group.observationRef)).size, 2);
});

test('identical multi-event bytes cluster corresponding entities without merging their siblings', async (t) => {
  const h = await harness(t);
  const document = page('https://one.example.test/events', [event('First event'), event('Second event')]);
  const result = await compose(h, [document, { ...document, url: 'https://two.example.test/events' }]);
  assert.equal(result.corroboration.nodes.length, 4);
  assert.equal(result.corroboration.clusters.length, 2);
  assert.ok(result.corroboration.clusters.every((item) => item.members.length === 2 && item.independence === 'unknown'));
  assert.deepEqual(result.corroboration.edges.map((edge) => edge.basis), ['exact_content', 'exact_content']);
  assert.notEqual(cluster(result, candidate(result, 'First event')).clusterId, cluster(result, candidate(result, 'Second event')).clusterId);
});

for (const cycle of [false, true]) {
  test(`retained declarations resolve transitively with bounded ${cycle ? 'cyclic' : 'acyclic'} chains`, async (t) => {
    const h = await harness(t);
    const result = await compose(h, [
      page('https://a.example.test/event', event('A', { isBasedOn: 'https://b.example.test/event' })),
      page('https://b.example.test/event', event('B', { isBasedOn: 'https://c.example.test/event' })),
      page('https://c.example.test/event', event('C', cycle ? { isBasedOn: 'https://a.example.test/event' } : {})),
    ]);
    assert.equal(result.corroboration.clusters.length, 1);
    assert.equal(result.corroboration.clusters[0].members.length, 3);
    assert.equal(result.corroboration.clusters[0].origin, 'not_established');
    assert.equal(result.corroboration.edges.length, cycle ? 3 : 2);
    const prepared = preparePair(result, candidate(result, 'A'), candidate(result, 'C'));
    assert.equal(prepared.sourceIdentityBinding.observationGroups.length, 2);
    assert.equal(prepared.sourceIdentityBinding.corroboration.clusters[0].members.length, 3);
    assert.equal(prepared.sourceIdentityBinding.corroboration.edges.length, cycle ? 3 : 2);
    assert.equal(prepared.plan.authorityScope.verifiedFactStatusGranted, false);
  });
}

for (const other of [event('Other eligible event'), { '@type': 'Event', description: 'No supported identity claim' }]) {
  test(`a target page with another ${other.name ? 'eligible' : 'ineligible'} event is ambiguous`, async (t) => {
    const h = await harness(t);
    const result = await compose(h, [
      page('https://origin.example.test/events', [event('Original'), other]),
      page('https://copy.example.test/event', event('Copy', { isBasedOn: 'https://origin.example.test/events' })),
    ]);
    assert.equal(result.corroboration.edges.length, 0);
    assert.equal(result.corroboration.unresolved[0].reason, 'target_ambiguous');
    assert.notEqual(cluster(result, candidate(result, 'Original')).clusterId, cluster(result, candidate(result, 'Copy')).clusterId);
  });
}

test('several retained documents with the same final URL do not elect a target', async (t) => {
  const h = await harness(t);
  const redirected = (name) => ({ ...page('https://shared.example.test/event', event(name)),
    requestedUrl: `https://${name.toLowerCase()}.example.test/event`, redirects: 1, redirectChain: ['https://shared.example.test/event'] });
  const result = await compose(h, [redirected('A'), redirected('B'),
    page('https://copy.example.test/event', event('Copy', { isBasedOn: 'https://shared.example.test/event' }))]);
  assert.equal(result.corroboration.edges.length, 0);
  assert.equal(result.corroboration.unresolved[0].reason, 'target_ambiguous');
});

test('branding, metadata, sameAs and misleading property paths do not create derivation or authority', async (t) => {
  const h = await harness(t);
  const origin = 'https://origin.example.test/event';
  const result = await compose(h, [page(origin, event('Original')),
    page('https://copy.example.test/event', event('Copy', {
      brand: 'Original', sameAs: origin, url: origin, '@id': origin, mainEntityOfPage: origin,
      'isBasedOn.fake': origin, 'isBasedOn/': origin, 'isBasedOn~': origin, nested: { isBasedOn: origin },
    }), `<link rel="canonical" href="${origin}"><meta property="og:url" content="${origin}">`)]);
  assert.ok(result.linkCandidates.length > 0, 'navigation metadata remains separately available');
  assert.equal(result.corroboration.claims.length, 0);
  assert.equal(result.corroboration.clusters.length, 2);
  assert.equal(result.sourceAuthority, 'not_evaluated');
  const prepared = preparePair(result, candidate(result, 'Original'), candidate(result, 'Copy'));
  assert.ok(prepared.sourceIdentityBinding.observationGroups.every((group) => group.corroboration.independence === 'unknown'));
  assert.equal(prepared.plan.authorityScope.sourceOfficialnessGranted, false);
});

for (const [label, value, expectedClaims] of [
  ['array', ['https://origin.example.test/event'], 1], ['object', { '@id': 'https://origin.example.test/event' }, 1],
  ['number', 42, 1], ['boolean', true, 1], ['null', null, 1], ['empty array', [], 0], ['empty object', {}, 0],
  ['relative URL', '/event', 1], ['query', 'https://origin.example.test/event?view=1', 1],
  ['fragment', 'https://origin.example.test/event#event', 1], ['whitespace', ' https://origin.example.test/event ', 1],
  ['non-HTTP', 'data:text/plain,fixture', 1], ['userinfo', 'https://fixture-user:fixture-password@origin.example.test/event', 1],
]) {
  test(`unsupported ${label} declaration remains unknown without an inferred dependence edge`, async (t) => {
    const h = await harness(t);
    const result = await compose(h, [page('https://origin.example.test/event', event('Original')),
      page('https://copy.example.test/event', event('Copy', { isBasedOn: value }))]);
    assert.equal(result.corroboration.claims.length, expectedClaims);
    assert.equal(result.corroboration.edges.length, 0);
    assert.equal(result.corroboration.clusters.length, 2);
    assert.ok(result.corroboration.claims.every((claim) => claim.status === 'unsupported' && claim.targetUrl === null));
    assert.ok(result.facts.every((fact) => fact.field !== 'isBasedOn'));
    const prepared = preparePair(result, candidate(result, 'Original'), candidate(result, 'Copy'));
    assert.ok(prepared.sourceIdentityBinding.observationGroups.every((group) => group.corroboration.independence === 'unknown'));
  });
}

test('an unavailable target remains a retained attributable statement with unresolved origin', async (t) => {
  const h = await harness(t);
  const result = await compose(h, [page('https://copy.example.test/event', event('Copy', { isBasedOn: 'https://missing.example.test/event' }))]);
  assert.equal(result.corroboration.claims[0].status, 'retained');
  assert.equal(result.corroboration.unresolved[0].reason, 'target_not_retained');
  assert.equal(result.facts.find((fact) => fact.field === 'isBasedOn').normalizedValue, 'https://missing.example.test/event');
  assert.equal(result.corroboration.clusters[0].origin, 'not_established');
});

test('organization declarations form their own clusters and do not join an event to an organization', async (t) => {
  const h = await harness(t);
  const result = await compose(h, [
    page('https://origin.example.test/organization', { '@type': 'Organization', name: 'Origin organization' }),
    page('https://copy.example.test/organization', { '@type': 'Organization', name: 'Copy organization', isBasedOn: 'https://origin.example.test/organization' }),
    page('https://a.example.test/event', event('A', { isBasedOn: 'https://origin.example.test/organization' })),
    page('https://b.example.test/event', event('B')),
  ]);
  assert.equal(result.corroboration.clusters.length, 3);
  assert.equal(result.corroboration.edges.length, 1);
  assert.equal(result.corroboration.unresolved[0].reason, 'target_not_retained');
  const prepared = preparePair(result, candidate(result, 'A'), candidate(result, 'B'));
  assert.equal(prepared.sourceIdentityBinding.corroboration.clusters.length, 2);
  assert.equal(prepared.sourceIdentityBinding.corroboration.edges.length, 0);
});

test('XHTML serialized source slices retain the exact declared URL provenance', async (t) => {
  const h = await harness(t);
  const document = page('https://copy.example.test/event', event('Copy'));
  const json = JSON.stringify(event('Copy', { isBasedOn: 'https://origin.example.test/event' }));
  document.contentType = 'application/xhtml+xml';
  document.bytes = Buffer.from(`<html xmlns="http://www.w3.org/1999/xhtml"><head><script type="application/ld+json">${json.replaceAll('&', '&amp;').replaceAll('"', '&quot;')}</script></head><body/></html>`);
  const result = await compose(h, [page('https://origin.example.test/event', event('Original')), document]);
  const fact = result.facts.find((item) => item.field === 'isBasedOn');
  assert.equal(fact.rawValue, '&quot;https://origin.example.test/event&quot;');
  const ref = result.corroboration.claims[0].sourceRef;
  const originalSlice = document.bytes.subarray(ref.locator.startByte, ref.locator.endByte);
  assert.equal(originalSlice.toString('utf8'), fact.rawValue);
  assert.equal(createHash('sha256').update(originalSlice).digest('hex'), ref.positionHash);
  assert.equal(result.corroboration.clusters.length, 1);
  assert.equal(preparePair(result, candidate(result, 'Original'), candidate(result, 'Copy')).sourceIdentityBinding.corroboration.edges.length, 1);
});

test('question preparation rejects missing, tampered and rehashed inconsistent graphs without invoking accessors', async (t) => {
  const h = await harness(t);
  const result = await compose(h, [page('https://origin.example.test/event', event('Original')),
    page('https://copy.example.test/event', event('Copy', { isBasedOn: 'https://origin.example.test/event' }))]);
  const pair = [candidate(result, 'Original'), candidate(result, 'Copy')];
  const reject = (graph) => assert.throws(() => preparePair({ ...result, corroboration: graph }, ...pair));
  reject(undefined);
  reject({ ...result.corroboration, digest: '0'.repeat(64) });
  const changed = structuredClone(result.corroboration);
  changed.edges = [];
  const { digest: ignored, ...core } = changed;
  changed.digest = corroborationDigest('source-corroboration', core);
  reject(changed);
  const nodes = structuredClone(result.corroboration.nodes);
  nodes.find((node) => node.candidateId === pair[0]).sourceUrls = ['https://forged.example.test/event'];
  const claims = result.corroboration.claims.map(({ claimId, ...claim }) => claim);
  reject(buildSourceCorroboration(nodes, claims));
  reject(buildSourceCorroboration(result.corroboration.nodes, []));
  assert.throws(() => preparePair({ ...result, facts: result.facts.filter((fact) => fact.field !== 'isBasedOn') }, ...pair), { code: 'SOURCE_BINDING_FAILED' });
  let calls = 0;
  const accessor = { ...result.corroboration };
  Object.defineProperty(accessor, 'claims', { enumerable: true, get() { calls += 1; throw new Error('must not run'); } });
  reject(accessor);
  reject(new Proxy(result.corroboration, { ownKeys() { calls += 1; throw new Error('must not run'); } }));
  assert.equal(calls, 0);
  assert.deepEqual(validateSourceCorroboration(result.corroboration), result.corroboration);
});

test('durable declaration reads honor current permission and expiry after reopen', async (t) => {
  const h = await harness(t);
  const result = await compose(h, [page('https://copy.example.test/event', event('Copy', { isBasedOn: 'https://origin.example.test/event' }))]);
  const original = result.facts.find((fact) => fact.field === 'isBasedOn');
  const store = h.reopen();
  const scope = await store.scopeForAuthenticatedRequest(REQUEST);
  const handle = await store.lookupFact(scope, original.factId);
  await assert.rejects(store.readFact(scope, handle, { ...REQUEST, allowed: false }), { code: 'EVIDENCE_DENIED' });
  assert.equal((await store.readFact(scope, handle, REQUEST)).rawValue, original.rawValue);
  h.clock.value += 120_001;
  await assert.rejects(store.readFact(scope, handle, REQUEST), { code: 'EVIDENCE_EXPIRED' });
});

async function loadPinnedPredecessor(t) {
  const root = fileURLToPath(new URL('../../../', import.meta.url));
  const pin = 'dc97a96d07abd5d7b66c0c18f46021e85fd60cea';
  const source = spawnSync('git', ['show', `${pin}:src/discovery/identity/from-extraction.mjs`], { cwd: root, maxBuffer: 8 * 1024 * 1024 });
  assert.equal(source.status, 0, 'the actual pinned predecessor must be available');
  assert.equal(createHash('sha256').update(source.stdout).digest('hex'), 'f6636d8f2a2388f1df3320ebad66c25a3d8c79f8bbc82abd51e705770a700f92');
  const modulePath = path.join(root, 'src/discovery/identity', `.legacy-attribution-${process.pid}-${randomUUID()}.mjs`);
  await writeFile(modulePath, source.stdout, { flag: 'wx', mode: 0o600 });
  t.after(() => rm(modulePath, { force: true }));
  return (await import(pathToFileURL(modulePath).href)).composeSourceIdentity;
}

test('pinned v1 replay preserves immutable missing declaration positions and remains explicitly unknown', async (t) => {
  const h = await harness(t);
  const legacyComposer = await loadPinnedPredecessor(t);
  const documents = [page('https://origin.example.test/event', event('Original')),
    page('https://copy.example.test/event', event('Copy', { isBasedOn: 'https://origin.example.test/event' }))];
  const legacy = await legacyComposer({ sources: documents.map((document) => ({ document, retentionHandle: h.createPermit() })), request: REQUEST, evidenceStore: h.store });
  assert.equal(legacy.schema, 'ei-source-identity-composition-internal/v1');
  assert.equal(Object.hasOwn(legacy, 'corroboration'), false);
  const legacyPlan = preparePair(legacy, candidate(legacy, 'Original'), candidate(legacy, 'Copy'));
  assert.equal(legacyPlan.sourceIdentityBinding.schema, 'ei-source-identity-question-binding-internal/v1');
  assert.equal(Object.hasOwn(legacyPlan.sourceIdentityBinding, 'corroboration'), false);
  assert.equal(legacyPlan.plan.promotionStatus, 'unpromoted');
  const replay = await compose(h, documents, h.reopen());
  assert.deepEqual(replay.sources.map((item) => item.evidence), legacy.sources.map((item) => item.evidence));
  assert.equal(replay.corroboration.claims[0].status, 'legacy_position_unavailable');
  assert.equal(replay.corroboration.unresolved[0].reason, 'legacy_position_unavailable');
  assert.equal(replay.corroboration.edges.length, 0);
  assert.ok(replay.facts.every((fact) => fact.field !== 'isBasedOn'));
  const current = preparePair(replay, candidate(replay, 'Original'), candidate(replay, 'Copy'));
  assert.equal(current.sourceIdentityBinding.schema, 'ei-source-identity-question-binding-internal/v2');
  assert.ok(current.sourceIdentityBinding.observationGroups.every((group) => group.corroboration.independence === 'unknown'));
  assert.throws(() => preparePair({ ...replay, schema: legacy.schema }, candidate(replay, 'Original'), candidate(replay, 'Copy')),
    { code: 'INVALID_INPUT' }, 'a malformed version cannot silently fall back to the historical profile');
});

test('graph caps and canceled entry refuse before producing a partial result, then a fresh call recovers', async (t) => {
  const h = await harness(t);
  const document = page('https://copy.example.test/event', event('Copy', { isBasedOn: 'https://origin.example.test/event' }));
  const signal = AbortSignal.abort();
  await assert.rejects(composeSourceIdentity({ sources: [{ document, retentionHandle: h.createPermit() }],
    request: REQUEST, evidenceStore: h.store, signal }), { code: 'CANCELED' });
  const result = await compose(h, [document]);
  assert.equal(result.corroboration.claims[0].status, 'retained');
  const nodes = result.corroboration.nodes;
  const claims = result.corroboration.claims.map(({ claimId, ...claim }) => claim);
  assert.throws(() => buildSourceCorroboration(Array(24).fill(nodes[0]), []), { code: 'LIMIT' });
  assert.throws(() => buildSourceCorroboration(nodes, Array(129).fill(claims[0])), { code: 'LIMIT' });
  assert.throws(() => validateSourceCorroboration({ ...result.corroboration, schema: 'x'.repeat(4097) }), { code: 'LIMIT' });
});

test('separate fact binding accepts mixed legacy and newly retained same-byte sources', async (t) => {
  const h = await harness(t);
  const legacyComposer = await loadPinnedPredecessor(t);
  const original = page('https://old.example.test/event', event('Copy', { isBasedOn: 'https://origin.example.test/event' }));
  await legacyComposer({ sources: [{ document: original, retentionHandle: h.createPermit() }], request: REQUEST, evidenceStore: h.store });
  const result = await compose(h, [original, { ...original, url: 'https://new.example.test/event' }], h.reopen());
  assert.deepEqual(result.corroboration.claims.map((claim) => claim.status).sort(), ['legacy_position_unavailable', 'retained']);
  assert.equal(result.facts.filter((fact) => fact.field === 'isBasedOn').length, 1);
  const prepared = preparePair(result, ...result.occurrenceCandidates.map((item) => item.candidateId));
  assert.equal(prepared.sourceIdentityBinding.schema, 'ei-source-identity-question-binding-internal/v2');
  assert.equal(prepared.sourceIdentityBinding.observationGroups.length, 2);
});

test('separate fact binding rejects one retained fact being reused for two entity declarations', async (t) => {
  const h = await harness(t);
  const result = await compose(h, [page('https://copy.example.test/events', [
    event('First', { isBasedOn: 'https://origin.example.test/event' }),
    event('Second', { isBasedOn: 'https://origin.example.test/event' }),
  ])]);
  const declarations = result.facts.filter((fact) => fact.field === 'isBasedOn');
  assert.equal(declarations.length, 2);
  assert.notEqual(declarations[0].factId, declarations[1].factId);
  const pair = result.occurrenceCandidates.map((item) => item.candidateId);
  assert.equal(preparePair(result, ...pair).sourceIdentityBinding.observationGroups.length, 2);
  const missing = { ...result, facts: result.facts.filter((fact) => fact.factId !== declarations[0].factId) };
  assert.throws(() => preparePair(missing, ...pair), { code: 'SOURCE_BINDING_FAILED' });
});

test('each retained declaration has one distinct binding and all attribution facts are bound', async (t) => {
  const h = await harness(t);
  const result = await compose(h, [page('https://copy.example.test/events', [
    event('First', { isBasedOn: 'https://origin.example.test/event' }),
    event('Second', { isBasedOn: 'https://origin.example.test/event' }),
  ])]);
  const pair = result.occurrenceCandidates.map((item) => item.candidateId);
  const [first, second] = result.corroborationFactBindings;
  const reject = (bindings) => assert.throws(() => preparePair({ ...result, corroborationFactBindings: bindings }, ...pair),
    { code: 'SOURCE_BINDING_FAILED' });
  assert.equal(result.corroborationFactBindings.length, 2);
  reject([first]);
  reject([first, first]);
  reject([first, { ...second, factId: first.factId }]);
  reject([first, { ...second, claimId: '0'.repeat(64) }]);
  const extraFact = { ...result.facts.find((fact) => fact.factId === first.factId), factId: 'unbound-attribution-fixture' };
  assert.throws(() => preparePair({ ...result, facts: [...result.facts, extraFact] }, ...pair), { code: 'SOURCE_BINDING_FAILED' });
  const prepared = preparePair(result, ...pair);
  assert.deepEqual(prepared.sourceIdentityBinding.corroboration.factBindings, result.corroborationFactBindings);
});

test('escaped parent pointers preserve the exact entity and malformed JSON Pointer escapes are refused', async (t) => {
  const h = await harness(t);
  const result = await compose(h, [page('https://origin.example.test/event', event('Original')),
    page('https://copy.example.test/event', { 'outer~/key': event('Copy', { isBasedOn: 'https://origin.example.test/event' }) })]);
  const pair = [candidate(result, 'Original'), candidate(result, 'Copy')];
  const claim = result.corroboration.claims[0];
  assert.equal(claim.sourceRef.jsonPointer, '/outer~0~1key/isBasedOn');
  assert.equal(preparePair(result, ...pair).sourceIdentityBinding.corroboration.edges.length, 1);
  const claims = result.corroboration.claims.map(({ claimId, ...value }) => value);
  const nodes = structuredClone(result.corroboration.nodes);
  nodes.find((node) => node.candidateId === pair[1]).entityPointer = '/outer~2key';
  assert.throws(() => buildSourceCorroboration(nodes, claims), { code: 'INVALID' });
});

test('actual v2 retained declarations obey exact observation and aggregate UTF-8 limits', async (t) => {
  const h = await harness(t);
  const large = (lengths) => event('N'.repeat(lengths[0]), {
    series: 'S'.repeat(lengths[1]), seriesName: 's'.repeat(lengths[2]), edition: 'E'.repeat(lengths[3]),
    eventEdition: 'e'.repeat(lengths[4]), location: { name: 'V'.repeat(lengths[5]), address: { addressLocality: 'C'.repeat(lengths[6]) } },
  });
  const build = async (lengths, rightLength) => {
    const result = await compose(h, [page('https://bounds.example.test/left', large(lengths)),
      page('https://bounds.example.test/right', event('R'.repeat(rightLength), { isBasedOn: 'https://bounds.example.test/left' }))]);
    return { result, pair: result.occurrenceCandidates.map((item) => item.candidateId) };
  };
  const prepare = ({ result, pair }) => preparePair(result, ...pair);
  const sourceGroupBytes = (prepared, result, sourceIndex) => Buffer.byteLength(prepared.sourceIdentityBinding.observationGroups
    .find((group) => group.evidenceId === result.sources[sourceIndex].evidence.evidenceId).text, 'utf8');
  const lengths = Array(7).fill(1);
  const baselineInput = await build(lengths, 1);
  const baseline = prepare(baselineInput);
  let remaining = 4_096 - sourceGroupBytes(baseline, baselineInput.result, 0);
  assert.ok(remaining > 0 && remaining < 7 * 511, 'actual composer output has room for a controlled first-over input');
  for (let index = 0; index < lengths.length; index += 1) {
    const increase = Math.min(511, remaining);
    lengths[index] += increase;
    remaining -= increase;
  }
  assert.equal(remaining, 0);
  const exactInput = await build(lengths, 1);
  const exact = prepare(exactInput);
  assert.equal(sourceGroupBytes(exact, exactInput.result, 0), 4_096);
  assert.ok(exact.sourceIdentityBinding.limits.observationTextBytes <= 10_000);
  assert.equal(exact.sourceIdentityBinding.corroboration.edges.length, 1);
  const overLengths = [...lengths];
  overLengths[overLengths.findIndex((length) => length < 512)] += 1;
  const fieldOver = await build(overLengths, 1);
  assert.ok(2 * (4_097 + sourceGroupBytes(exact, exactInput.result, 1)) <= 10_000,
    'the aggregate limit does not mask the first observation byte over');
  assert.throws(() => prepare(fieldOver), { code: 'RESOURCE_LIMIT_EXCEEDED' });
  const rightLength = 1 + 904 - sourceGroupBytes(exact, exactInput.result, 1);
  assert.ok(rightLength >= 1 && rightLength < 512, 'the actual second source can reach the remaining aggregate allowance');
  const aggregateInput = await build(lengths, rightLength);
  const aggregate = prepare(aggregateInput);
  assert.equal(sourceGroupBytes(aggregate, aggregateInput.result, 1), 904);
  assert.equal(aggregate.sourceIdentityBinding.limits.observationTextBytes, 10_000);
  const aggregateOver = await build(lengths, rightLength + 1);
  assert.throws(() => prepare(aggregateOver), { code: 'RESOURCE_LIMIT_EXCEEDED' });
});
