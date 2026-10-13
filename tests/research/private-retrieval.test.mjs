import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { withPrivilegedFrontierFixtureMutation } from '../discovery/planner/frontier-fixture-mutation.mjs';
import { spawn } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import { createEvidenceStore } from '../../src/evidence/store.mjs';
import { createDiscoveryFrontierStore } from '../../src/discovery/planner/frontier.mjs';
import { createPrivateAssetReleaseAuthority, runPrivateRetrieval } from '../../src/research/private-retrieval.mjs';
import { SafeFetcher } from '../../src/security/controlled-fetch.mjs';
import { fixtureUrl, localTestSeam, respond, startFixture } from '../security/support.mjs';

const STOP_WORKER = new URL('./frontier-stop-worker.mjs', import.meta.url);
const TENANT = 'tenant-a';
const LOCAL_FIXTURE_HOST = 'fixture.example.org';

function sourceUrl(pathname = '/') {
  return fixtureUrl(80, pathname, LOCAL_FIXTURE_HOST);
}

function frontierWithSealHook(frontier, hook) {
  const wrapped = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'createRun', 'claimNext', 'getCandidateReceiptBinding', 'admitTransportHop',
    'markTransportDispatchIntent', 'markTransportResponseReceived', 'settleTransportHopKnownZero',
    'settleTransportHopBodyComplete', 'markTransportHopUnknown', 'getTransportProgress',
    'completeCandidate', 'markUnresolved', 'stopRun', 'getSnapshot',
  ]) wrapped[name] = frontier[name].bind(frontier);
  wrapped.sealPrivateDraft = (...args) => hook(frontier.sealPrivateDraft.bind(frontier), ...args);
  return wrapped;
}

function frontierWithDelayedCreateRun(frontier, gate, onAttempt) {
  const wrapped = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'claimNext', 'getCandidateReceiptBinding', 'admitTransportHop',
    'markTransportDispatchIntent', 'markTransportResponseReceived', 'settleTransportHopKnownZero',
    'settleTransportHopBodyComplete', 'markTransportHopUnknown', 'getTransportProgress',
    'completeCandidate', 'markUnresolved', 'stopRun', 'sealPrivateDraft', 'getSnapshot',
  ]) wrapped[name] = frontier[name].bind(frontier);
  wrapped.createRun = async (...args) => {
    await gate;
    try { return await frontier.createRun(...args); }
    finally { onAttempt(); }
  };
  return wrapped;
}

function frontierWithMethodOverrides(frontier, overrides) {
  const wrapped = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'createRun', 'claimNext', 'getCandidateReceiptBinding', 'admitTransportHop',
    'markTransportDispatchIntent', 'markTransportResponseReceived', 'settleTransportHopKnownZero',
    'settleTransportHopBodyComplete', 'markTransportHopUnknown', 'getTransportProgress',
    'completeCandidate', 'markUnresolved', 'stopRun', 'sealPrivateDraft', 'getSnapshot',
  ]) wrapped[name] = Object.hasOwn(overrides, name) ? overrides[name] : frontier[name].bind(frontier);
  return wrapped;
}

function legacyEvidenceAdapter(evidenceStore) {
  const adapter = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'ingestEvidence', 'appendFact', 'ingestDerivedPdfEvidence',
    'ingestAssetSourceEvidence', 'lookupEvidence', 'lookupFact', 'materializeSelected',
    'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) adapter[name] = evidenceStore[name].bind(evidenceStore);
  return adapter;
}

function controlledEvidenceAdapter(evidenceStore) {
  const adapter = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'ingestEvidence', 'appendFact', 'ingestDerivedPdfEvidence',
    'ingestAssetSourceEvidence', 'lookupEvidence', 'lookupFact', 'materializeSelected',
    'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
    'ingestControlledAssetEvidence', 'readControlledAssetBytes', 'readAssetSourceCandidateBinding',
    'revalidateControlledAssetRelease', 'finalizeControlledAssetRelease', 'discardControlledAssetRelease',
  ]) adapter[name] = evidenceStore[name].bind(evidenceStore);
  return adapter;
}

async function waitUntilPerfAtOrAfter(targetPerfMs) {
  while (performance.now() < targetPerfMs) {
    const remainingMs = targetPerfMs - performance.now();
    await new Promise((resolve) => setTimeout(resolve, Math.max(1, Math.ceil(remainingMs))));
  }
  return performance.now();
}

function request(allowPrivate = true) {
  return { principal: { tenantId: TENANT }, allowPrivate };
}

function eventHtml({ name = 'Moonlight Market', date = '2027-06-20', city = 'Boston', asset = false } = {}) {
  const event = {
    '@type': 'Event', name, startDate: date,
    location: { name: 'Civic Hall', address: { addressLocality: city } },
  };
  return Buffer.from(`<!doctype html>${asset ? '<meta property="og:image" content="/poster.jpg">' : ''}`
    + `<script type="application/ld+json">${JSON.stringify(event)}</script>`);
}

function eventHtmlWithCanonicalLinks(urls) {
  const event = {
    '@type': 'Event', name: 'Bounded Link Event', startDate: '2027-06-20',
    location: { name: 'Civic Hall', address: { addressLocality: 'Boston' } },
  };
  const links = urls.map((url) => `<link rel="canonical" href="${url}">`).join('');
  return Buffer.from(`<!doctype html>${links}<script type="application/ld+json">${JSON.stringify(event)}</script>`);
}

async function runStopWorker(directory, runId) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [STOP_WORKER.pathname, directory, runId], {
      cwd: path.resolve(path.dirname(new URL(import.meta.url).pathname), '../..'),
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (exitCode) => {
      if (exitCode !== 0) reject(new Error(`stop worker failed (${exitCode}): ${stderr.slice(0, 500)}`));
      else {
        try { resolve(JSON.parse(stdout)); } catch { reject(new Error('stop worker returned invalid result')); }
      }
    });
  });
}

async function harness(t, { evidenceOptions = {}, hostnames = [LOCAL_FIXTURE_HOST], addresses } = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ei-private-retrieval-'));
  const frontierDirectory = path.join(root, 'frontier');
  const evidenceDirectory = path.join(root, 'evidence');
  const requests = new Set();
  const releaseControllers = [];
  const permitted = new WeakMap();
  let currentAcl = true;
  const createRetention = (expiresAtMs = Date.now() + 120_000) => {
    const handle = Object.freeze(Object.create(null));
    permitted.set(handle, { tenantId: TENANT, expiresAtMs });
    return handle;
  };
  const evidenceConfig = {
    directory: evidenceDirectory,
    resolveTenant: (authenticated) => authenticated?.principal?.tenantId,
    resolveKey({ tenantId, purpose, keyId }) {
      const selectedKeyId = `${purpose}-test-v1`;
      if (keyId && keyId !== selectedKeyId) throw new Error('private key selection denied');
      return { keyId: selectedKeyId, key: createHash('sha256').update(`${tenantId}:${purpose}:private-retrieval-test`).digest() };
    },
    resolveRetention({ tenantId, kind, nowMs, sourceExpiresAtMs, retentionHandle }) {
      if (kind === 'evidence') {
        const stored = permitted.get(retentionHandle);
        if (!stored || stored.tenantId !== tenantId) throw new Error('retention denied');
        return { expiresAtMs: stored.expiresAtMs, policyId: 'offline-private-test', policyVersion: '1', accessPolicy: 'tenant_private' };
      }
      return {
        expiresAtMs: sourceExpiresAtMs ?? nowMs + 60_000,
        policyId: 'offline-private-fact-test', policyVersion: '1', accessPolicy: 'tenant_private',
      };
    },
    authorizePrivateAccess({ tenantId, request: authenticated }) {
      return currentAcl && authenticated?.principal?.tenantId === tenantId && authenticated.allowPrivate === true;
    },
    authorizePrivateAccessCurrent({ tenantId, request: authenticated }) {
      return currentAcl && authenticated?.principal?.tenantId === tenantId && authenticated.allowPrivate === true;
    },
    now: () => Date.now(),
    maxSourceBytes: 2 * 1024 * 1024,
    maxPositionBytes: 64 * 1024,
    maxPositionCount: 128,
    maxStoredPayloadBytes: 512 * 1024,
    maxRetentionMs: 180_000,
    ...evidenceOptions,
  };
  const evidenceStore = createEvidenceStore(evidenceConfig);
  const frontierStores = new Set();
  const openFrontier = () => {
    const store = createDiscoveryFrontierStore({
      directory: frontierDirectory,
      resolveTenant: (authenticated) => authenticated?.principal?.tenantId,
      lockTimeoutMs: 10_000,
    });
    frontierStores.add(store);
    return store;
  };
  const frontier = openFrontier();
  const scope = await frontier.scopeForAuthenticatedRequest(request());
  const evidenceScope = await evidenceStore.scopeForAuthenticatedRequest(request());
  t.after(async () => {
    for (const store of frontierStores) store.close();
    await rm(root, { recursive: true, force: true });
  });
  const makeFetcher = (server) => new SafeFetcher(localTestSeam({
    port: 80, dialPort: server.port, hostnames, addresses,
    onDial: () => requests.add('dial'),
  }));
  const makeInput = ({ runId, server, seeds, limits, authorizeCurrent, retentionHandleFor, safeFetcher, signal,
    assetAcquisitionPolicyFor, assetAcquisitionReleaseAuthorityFor,
    frontier: frontierStore = frontier, store = evidenceStore }) => {
    const authenticated = request();
    const releaseAuthorityFor = assetAcquisitionReleaseAuthorityFor === null
      ? undefined
      : assetAcquisitionReleaseAuthorityFor ?? (assetAcquisitionPolicyFor ? (_request, context) => {
        const issued = createPrivateAssetReleaseAuthority({
          tenantId: authenticated.principal.tenantId,
          runId: context.runId,
          policy: context.policy,
          expiresAtMonotonic: context.deadlineAtMonotonic,
        });
        releaseControllers.push(issued);
        return issued;
      } : undefined);
    return {
      frontier: frontierStore,
      evidenceStore: store,
      safeFetcher: safeFetcher ?? makeFetcher(server),
      request: authenticated,
      runId,
      seeds,
      ...(limits ? { limits } : {}),
      ...(signal ? { signal } : {}),
      ...(assetAcquisitionPolicyFor ? { assetAcquisitionPolicyFor } : {}),
      ...(releaseAuthorityFor ? { assetAcquisitionReleaseAuthorityFor: releaseAuthorityFor } : {}),
      retentionHandleFor: retentionHandleFor ?? (() => createRetention()),
      authorizeCurrent: authorizeCurrent ?? (() => true),
    };
  };
  return {
    root, frontierDirectory, frontier, scope, openFrontier, evidenceStore, evidenceScope,
    evidenceConfig,
    createRetention, makeFetcher, makeInput, requests, releaseControllers,
    currentlyAuthorized() { return currentAcl; },
    setAcl(value) { currentAcl = value; },
  };
}

for (const [name, expectedLimitation, content] of [
  ['javascript-shell', 'dynamic_rendering_required', '<html><body><noscript>JavaScript is required to continue</noscript></body></html>'],
  ['access-gate', 'source_access_restricted', '<html><body><h1>Access denied</h1></body></html>'],
  ['legacy-encoding', 'malformed_or_unsupported_encoding', '<html><head><meta charset="iso-8859-1"></head><body>Legacy encoding</body></html>'],
  // SafeFetcher rejects malformed UTF-8 before the source composer runs.
  ['malformed-encoding', 'unsupported_media', Buffer.concat([
    Buffer.from('<!doctype html><html><body><p>'), Buffer.from([0xff]), Buffer.from('</p></body></html>'),
  ])],
]) {
  test(`retains ${name} refusal after receipt restart without another request`, async (t) => {
    const h = await harness(t);
    const paths = [];
    const server = await startFixture((incoming, response) => {
      paths.push(incoming.url);
      respond(response, 200, { 'content-type': 'text/html' }, content);
    });
    t.after(() => server.close());
    const runId = `private-source-refusal-${name}`;
    const seeds = [{ url: sourceUrl('/refused') }];
    const limits = { maxDepth: 0, maxTransportAttemptAdmissions: 1, durationMs: 10_000 };
    const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
    assert.equal(first.status, 'incomplete', JSON.stringify(first));
    assert.equal(first.draft, null);
    assert.ok(first.limitations.includes(expectedLimitation), JSON.stringify(first));
    assert.equal(first.limitations.includes('source_incomplete_or_access_restricted'), false);
    const transport = await h.frontier.getTransportProgress(h.scope, runId);

    const reopenedFrontier = h.openFrontier();
    const reopenedStore = createEvidenceStore(h.evidenceConfig);
    const replay = await runPrivateRetrieval(h.makeInput({
      runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
    }));
    assert.equal(replay.status, 'incomplete', JSON.stringify(replay));
    assert.equal(replay.draft, null);
    assert.deepEqual(replay.limitations, first.limitations);
    assert.deepEqual(paths, ['/refused'], 'no retry, browser or parser subresource request is made');
    const reopenedScope = await reopenedFrontier.scopeForAuthenticatedRequest(request());
    assert.deepEqual(await reopenedFrontier.getTransportProgress(reopenedScope, runId), transport,
      'the completed transport admission and decoded-byte accounting survive restart');
    const evidenceScope = await reopenedStore.scopeForAuthenticatedRequest(request());
    const stored = await reopenedStore.integritySnapshot(evidenceScope);
    assert.equal(stored.availableEvidence, 0);
    assert.equal(stored.availableFacts, 0);
  });
}

async function legacyOvercapWorkspace(t, requestCounter, fixtureName = 'private-run-receipt-v1-overcap') {
  const fixtureDirectory = new URL(`../evidence/fixtures/${fixtureName}/`, import.meta.url);
  const fixtureBytes = await readFile(new URL('fixture.json', fixtureDirectory));
  const fixtureDescriptorHashes = {
    'private-run-receipt-v1-overcap': '2981e94690d5c041b364ac91f8ebc24d5d0bc0742d48c46c9574e951aaa35cae',
    'private-run-receipt-v1-policy-omission': 'f57113de37a9d8d65eb4c86191364d14ac052d41b279666dc9933b55fafe2b3f',
  };
  assert.equal(createHash('sha256').update(fixtureBytes).digest('hex'), fixtureDescriptorHashes[fixtureName],
    'the reviewed fixture descriptor is the captured baseline artifact');
  const fixture = JSON.parse(fixtureBytes.toString('utf8'));
  const evidenceBytes = await readFile(new URL('evidence.sqlite', fixtureDirectory));
  const frontierBytes = await readFile(new URL('frontier.sqlite', fixtureDirectory));
  assert.equal(createHash('sha256').update(evidenceBytes).digest('hex'), fixture.evidenceDatabaseSha256);
  assert.equal(createHash('sha256').update(frontierBytes).digest('hex'), fixture.frontierDatabaseSha256);
  const root = await mkdtemp(path.join(os.tmpdir(), `ei-private-${fixtureName}-`));
  t.after(() => rm(root, { recursive: true, force: true }));
  const frontierStores = new Set();
  t.after(() => {
    for (const store of frontierStores) store.close();
  });
  const evidenceDirectory = path.join(root, 'evidence');
  const frontierDirectory = path.join(root, 'frontier');
  await mkdir(path.join(evidenceDirectory, fixture.tenantHash), { recursive: true });
  await mkdir(path.join(frontierDirectory, fixture.tenantHash), { recursive: true });
  await copyFile(new URL('evidence.sqlite', fixtureDirectory),
    path.join(evidenceDirectory, fixture.tenantHash, 'evidence.sqlite'));
  await copyFile(new URL('frontier.sqlite', fixtureDirectory),
    path.join(frontierDirectory, fixture.tenantHash, 'frontier.sqlite'));
  const frontierDatabase = new DatabaseSync(path.join(frontierDirectory, fixture.tenantHash, 'frontier.sqlite'));
  try {
    withPrivilegedFrontierFixtureMutation(frontierDatabase, () => {
      const refreshed = frontierDatabase.prepare(`UPDATE frontier_runs SET deadline_at_ms = ?
        WHERE tenant_hash = ? AND run_id = ?`)
        .run(Date.now() + fixture.limits.durationMs, fixture.tenantHash, fixture.runId);
      assert.equal(refreshed.changes, 1, 'the test copy receives a fresh bounded restart window');
    });
  } finally {
    frontierDatabase.close();
  }
  const authenticatedRequest = { principal: { tenantId: fixture.tenantId }, allowPrivate: true };
  const evidenceConfig = {
    directory: evidenceDirectory,
    resolveTenant: (value) => value?.principal?.tenantId,
    resolveKey({ tenantId, purpose, keyId }) {
      assert.equal(tenantId, fixture.tenantId);
      const selectedId = `${purpose}-legacy-fixture-v1`;
      if (keyId) assert.equal(keyId, selectedId);
      return {
        keyId: selectedId,
        key: createHash('sha256').update(`${tenantId}:${purpose}:legacy-receipt-v1`).digest(),
      };
    },
    resolveRetention({ tenantId, kind, nowMs, sourceExpiresAtMs, retentionHandle }) {
      assert.equal(tenantId, fixture.tenantId);
      return {
        expiresAtMs: kind === 'evidence'
          ? retentionHandle?.expiresAtMs ?? nowMs + fixture.retentionWindowMs
          : sourceExpiresAtMs ?? nowMs + fixture.retentionWindowMs,
        policyId: 'legacy-fixture-recovery', policyVersion: '1', accessPolicy: 'tenant_private',
      };
    },
    authorizePrivateAccess: ({ tenantId, request: value }) => tenantId === fixture.tenantId
      && value?.principal?.tenantId === tenantId && value.allowPrivate === true,
    authorizePrivateAccessCurrent: ({ tenantId, request: value }) => tenantId === fixture.tenantId
      && value?.principal?.tenantId === tenantId && value.allowPrivate === true,
    consumePrivatePayload({ source, positions }) {
      return { sourceUrl: source.sourceUrl, sourceHash: source.contentHash,
        snapshots: positions.map((position) => position.content.toString('utf8')) };
    },
    now: () => Date.now(),
    maxSourceBytes: 2 * 1024 * 1024,
    maxPositionBytes: 64 * 1024,
    maxPositionCount: 128,
    maxStoredPayloadBytes: 512 * 1024,
    maxRetentionMs: fixture.retentionWindowMs,
  };
  const openEvidenceStore = () => createEvidenceStore(evidenceConfig);
  const openFrontier = () => {
    const store = createDiscoveryFrontierStore({
      directory: frontierDirectory,
      resolveTenant: (value) => value?.principal?.tenantId,
      lockTimeoutMs: 10_000,
    });
    frontierStores.add(store);
    return store;
  };
  const server = await startFixture((_request, response) => {
    requestCounter.count += 1;
    const body = fixture.legacyLimitation
      ? eventHtmlWithCanonicalLinks(['https://links.example.org/?access_token=synthetic-canary'])
      : eventHtml();
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, body);
  });
  t.after(() => server.close());
  const safeFetcher = new SafeFetcher(localTestSeam({
    port: 80, dialPort: server.port, hostnames: ['fixture.example.org'],
  }));
  return {
    fixture,
    request: authenticatedRequest,
    safeFetcher,
    seeds: fixture.seeds,
    limits: fixture.limits,
    runId: fixture.runId,
    evidenceDirectory,
    frontierDirectory,
    openEvidenceStore,
    openFrontier,
    readLegacyReceiptRow() {
      return this.readLegacyReceiptRows()[0];
    },
    readLegacyReceiptRows() {
      const database = new DatabaseSync(path.join(evidenceDirectory, fixture.tenantHash, 'evidence.sqlite'), { readOnly: true });
      try {
        return database.prepare(`SELECT state, key_id, payload_hash, payload_bytes, sealed
          FROM private_retrieval_receipts WHERE tenant_hash = ? ORDER BY receipt_key`)
          .all(fixture.tenantHash).map((row) => ({
            state: row.state,
            keyId: row.key_id,
            payloadHash: row.payload_hash,
            payloadBytes: row.payload_bytes,
            sealed: Buffer.from(row.sealed),
          }));
      } finally {
        database.close();
      }
    },
    async run(frontier, evidenceStore) {
      return runPrivateRetrieval({
        frontier,
        evidenceStore,
        safeFetcher,
        request: authenticatedRequest,
        runId: fixture.runId,
        seeds: fixture.seeds,
        limits: fixture.limits,
        retentionHandleFor: () => Object.freeze(Object.create(null)),
        authorizeCurrent: () => true,
      });
    },
  };
}

function insertContradictoryLinkObservation({ databasePath, tenantHash, runId, parentCandidateId, outcome }) {
  const database = new DatabaseSync(databasePath);
  try {
    withPrivilegedFrontierFixtureMutation(database, () => {
      const row = database.prepare(`SELECT tenant_hash, run_id, kind, parent_candidate_id, target_candidate_id,
        supplied_url, canonical_url, depth, label, source_refs_json, disposition
        FROM frontier_observations
        WHERE tenant_hash = ? AND run_id = ? AND parent_candidate_id = ? AND kind = 'link'
        ORDER BY sequence LIMIT 1`).get(tenantHash, runId, parentCandidateId);
      assert.ok(row, 'the completed parent has an original link observation');
      const sequence = database.prepare(`SELECT MAX(sequence) AS sequence FROM frontier_observations
        WHERE tenant_hash = ? AND run_id = ?`).get(tenantHash, runId).sequence;
      const sourceRefs = JSON.parse(row.source_refs_json);
      assert.ok(sourceRefs.length > 0);
      sourceRefs[0].field = 'conflicting.extra.source';
      database.prepare(`INSERT INTO frontier_observations
        (tenant_hash, run_id, sequence, kind, parent_candidate_id, target_candidate_id,
          supplied_url, canonical_url, depth, label, source_refs_json, disposition, outcome)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(row.tenant_hash, row.run_id, sequence + 1, row.kind, row.parent_candidate_id,
          row.target_candidate_id, row.supplied_url, row.canonical_url, row.depth, row.label,
          JSON.stringify(sourceRefs), row.disposition, outcome);
      const updated = database.prepare(`UPDATE frontier_runs SET next_observation_sequence = ?
        WHERE tenant_hash = ? AND run_id = ? AND next_observation_sequence = ?`)
        .run(sequence + 2, tenantHash, runId, sequence + 1);
      assert.equal(updated.changes, 1, 'the synthetic observation advances the persisted append sequence');
    });
  } finally {
    database.close();
  }
}

function insertUnverifiedQueuedParentLinkObservation({ databasePath, tenantHash, runId, queuedCandidateId, field }) {
  const database = new DatabaseSync(databasePath);
  try {
    withPrivilegedFrontierFixtureMutation(database, () => {
      const row = database.prepare(`SELECT tenant_hash, run_id, kind, target_candidate_id,
        supplied_url, canonical_url, depth, label, source_refs_json, disposition, outcome
        FROM frontier_observations
        WHERE tenant_hash = ? AND run_id = ? AND target_candidate_id = ? AND kind = 'link'
        ORDER BY sequence LIMIT 1`).get(tenantHash, runId, queuedCandidateId);
      assert.ok(row, 'the queued child already has a legitimate link observation');
      const sequence = database.prepare(`SELECT MAX(sequence) AS sequence FROM frontier_observations
        WHERE tenant_hash = ? AND run_id = ?`).get(tenantHash, runId).sequence;
      const sourceRefs = JSON.parse(row.source_refs_json);
      assert.ok(sourceRefs.length > 0);
      sourceRefs[0].field = field;
      database.prepare(`INSERT INTO frontier_observations
        (tenant_hash, run_id, sequence, kind, parent_candidate_id, target_candidate_id,
          supplied_url, canonical_url, depth, label, source_refs_json, disposition, outcome)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        row.tenant_hash, row.run_id, sequence + 1, row.kind, queuedCandidateId, row.target_candidate_id,
        row.supplied_url, row.canonical_url, row.depth, row.label, JSON.stringify(sourceRefs), row.disposition, row.outcome,
      );
      const updated = database.prepare(`UPDATE frontier_runs SET next_observation_sequence = ?
        WHERE tenant_hash = ? AND run_id = ? AND next_observation_sequence = ?`)
        .run(sequence + 2, tenantHash, runId, sequence + 1);
      assert.equal(updated.changes, 1, 'the synthetic observation advances the persisted append sequence');
    });
  } finally {
    database.close();
  }
}

function reassignLinkObservationTarget({ databasePath, tenantHash, runId, canonicalUrl, targetCandidateId }) {
  const database = new DatabaseSync(databasePath);
  try {
    database.exec('PRAGMA foreign_keys=ON');
    return withPrivilegedFrontierFixtureMutation(database, () => {
      const observation = database.prepare(`SELECT sequence, target_candidate_id, canonical_url
        FROM frontier_observations WHERE tenant_hash = ? AND run_id = ? AND kind = 'link' AND canonical_url = ?
        ORDER BY sequence LIMIT 1`).get(tenantHash, runId, canonicalUrl);
      assert.ok(observation, 'the selected parent link observation exists');
      assert.notEqual(targetCandidateId, observation.target_candidate_id,
        'the replacement target differs from the observation target');
      assert.ok(database.prepare(`SELECT 1 AS found FROM frontier_candidates
        WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`).get(tenantHash, runId, targetCandidateId),
      'the replacement target is a real candidate in this run');
      const updated = database.prepare(`UPDATE frontier_observations SET target_candidate_id = ?
        WHERE tenant_hash = ? AND run_id = ? AND sequence = ?`).run(
        targetCandidateId, tenantHash, runId, observation.sequence,
      );
      assert.equal(updated.changes, 1);
      assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [],
        'the reassigned target remains a valid same-run foreign key');
      return observation;
    });
  } finally {
    database.close();
  }
}

function reassignCandidateDepth({ databasePath, tenantHash, runId, candidateId, depth }) {
  const database = new DatabaseSync(databasePath);
  try {
    return withPrivilegedFrontierFixtureMutation(database, () => {
      const candidate = database.prepare(`SELECT best_depth FROM frontier_candidates
        WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`).get(tenantHash, runId, candidateId);
      assert.ok(candidate, 'the selected candidate exists in this run');
      const updated = database.prepare(`UPDATE frontier_candidates SET best_depth = ?
        WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`).run(depth, tenantHash, runId, candidateId);
      assert.equal(updated.changes, 1);
      return candidate.best_depth;
    });
  } finally {
    database.close();
  }
}

function reassignCandidateAndIncomingLinkDepth({
  databasePath, tenantHash, runId, candidateId, depth, disposition, candidateState,
}) {
  const database = new DatabaseSync(databasePath);
  try {
    return withPrivilegedFrontierFixtureMutation(database, () => {
      const candidate = database.prepare(`SELECT best_depth FROM frontier_candidates
        WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`).get(tenantHash, runId, candidateId);
      assert.ok(candidate, 'the selected candidate exists in this run');
      const changedCandidate = candidateState === undefined
        ? database.prepare(`UPDATE frontier_candidates SET best_depth = ?
          WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
          .run(depth, tenantHash, runId, candidateId)
        : database.prepare(`UPDATE frontier_candidates SET best_depth = ?, state = ?
          WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
          .run(depth, candidateState, tenantHash, runId, candidateId);
      assert.equal(changedCandidate.changes, 1);
      const changedObservations = disposition === undefined
        ? database.prepare(`UPDATE frontier_observations SET depth = ?
          WHERE tenant_hash = ? AND run_id = ? AND kind = 'link' AND target_candidate_id = ?`)
          .run(depth, tenantHash, runId, candidateId)
        : database.prepare(`UPDATE frontier_observations SET depth = ?, disposition = ?
          WHERE tenant_hash = ? AND run_id = ? AND kind = 'link' AND target_candidate_id = ?`)
          .run(depth, disposition, tenantHash, runId, candidateId);
      assert.ok(changedObservations.changes > 0, 'the selected candidate has an incoming link observation');
      assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [],
        'the coordinated depth mutation preserves same-run foreign keys');
      return candidate.best_depth;
    });
  } finally {
    database.close();
  }
}

function insertUnobservedCandidate({ databasePath, tenantHash, runId, canonicalUrl, depth = 1 }) {
  const candidateId = createHash('sha256')
    .update(`event-intelligence:frontier-candidate:v1\0${tenantHash}\0${runId}\0${canonicalUrl}`)
    .digest('hex');
  const database = new DatabaseSync(databasePath);
  try {
    database.exec('PRAGMA foreign_keys=ON');
    return withPrivilegedFrontierFixtureMutation(database, () => {
      const run = database.prepare(`SELECT max_depth FROM frontier_runs WHERE tenant_hash = ? AND run_id = ?`)
        .get(tenantHash, runId);
      assert.ok(run, 'the candidate belongs to a persisted frontier run');
      assert.ok(depth <= run.max_depth, 'the orphan control is otherwise eligible for the projection');
      database.prepare(`INSERT INTO frontier_candidates
        (tenant_hash, run_id, candidate_id, canonical_url, best_depth, state, is_seed)
        VALUES (?, ?, ?, ?, ?, 'queued', 0)`)
        .run(tenantHash, runId, candidateId, canonicalUrl, depth);
      assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [],
        'the unsupported candidate still has valid foreign keys');
      return candidateId;
    });
  } finally {
    database.close();
  }
}

function readPrivateReceiptRows(databasePath, tenantHash) {
  const database = new DatabaseSync(databasePath, { readOnly: true });
  try {
    return database.prepare(`SELECT state, payload_hash, payload_bytes, sealed
      FROM private_retrieval_receipts WHERE tenant_hash = ? ORDER BY receipt_key`)
      .all(tenantHash).map((row) => ({
        state: row.state,
        payloadHash: row.payload_hash,
        payloadBytes: row.payload_bytes,
        sealed: Buffer.from(row.sealed),
      }));
  } finally {
    database.close();
  }
}

test('sensitive seed query and fragment material is rejected before frontier persistence', async (t) => {
  const server = await startFixture((_request, response) => {
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-sensitive-seed';
  const sensitiveUrl = 'http://fixture.example.org/?%61ccess_%74oken=canary#%2574oken=canary';
  await assert.rejects(runPrivateRetrieval(h.makeInput({
    runId, server, seeds: [{ url: sensitiveUrl }],
  })), (error) => error?.code === 'INVALID_INPUT' && !error.message.includes('canary'));
  await assert.rejects(h.frontier.getSnapshot(h.scope, runId), (error) => error?.code === 'FRONTIER_NOT_FOUND');
});

test('one-hop limit admits and completes its last real request, then releases AES-backed facts with exact source provenance', async (t) => {
  let requestCount = 0;
  const server = await startFixture((requestValue, response) => {
    requestCount += 1;
    assert.equal(requestValue.headers.authorization, undefined);
    assert.equal(requestValue.headers.cookie, undefined);
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml({ asset: true }));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const suppliedUrl = sourceUrl('/event/../event?source=offline');
  const canonicalUrl = new URL(suppliedUrl).href;
  const fetchedBuffers = [];
  const observedStore = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'appendFact', 'ingestDerivedPdfEvidence', 'lookupEvidence', 'lookupFact', 'materializeSelected',
    'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) observedStore[name] = h.evidenceStore[name].bind(h.evidenceStore);
  observedStore.ingestEvidence = async (...args) => {
    fetchedBuffers.push(args[1].content);
    return h.evidenceStore.ingestEvidence(...args);
  };
  observedStore.ingestAssetSourceEvidence = async (...args) => {
    fetchedBuffers.push(args[1].document.bytes);
    return h.evidenceStore.ingestAssetSourceEvidence(...args);
  };
  const result = await runPrivateRetrieval(h.makeInput({
    runId: 'private-max-one', server, seeds: [{ url: suppliedUrl }],
    store: observedStore,
    limits: { maxTransportAttemptAdmissions: 1, maxDepth: 0 },
    retentionHandleFor: async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      return h.createRetention();
    },
  }));

  assert.equal(result.schema, 'ei-private-retrieval-draft/v1');
  assert.equal(result.status, 'draft', JSON.stringify(result));
  assert.equal(result.completeness, 'incomplete');
  assert.ok(result.facts.some((fact) => fact.field === 'startDate'));
  assert.equal(result.sources.filter((source) => source.representation === 'raw').length, 1);
  assert.equal(result.sources.filter((source) => source.representation === 'asset-source-excerpt').length, 1, JSON.stringify(result));
  assert.equal(result.sources.find((source) => source.representation === 'raw').sourceUrl, suppliedUrl);
  assert.equal(result.sources.find((source) => source.representation === 'raw').canonicalUrl, canonicalUrl);
  assert.ok(result.sources.find((source) => source.representation === 'asset-source-excerpt').assetCandidates.length > 0);
  assert.equal(result.sources.find((source) => source.representation === 'asset-source-excerpt').assetCandidates[0].permission, 'unknown');
  assert.equal(result.sources.find((source) => source.representation === 'asset-source-excerpt').assetCandidates[0].inspection, 'pending');
  assert.deepEqual(result.conflicts, []);
  assert.equal(result.sourceAuthority, 'not_evaluated');
  assert.equal(result.rights, 'not_evaluated');
  assert.equal(result.usage, 'unknown');
  assert.equal(requestCount, 1, 'discovered image candidates are stored without fetching the asset');
  assert.equal(result.progress.transportAttemptAdmissions, 1);
  assert.equal(fetchedBuffers.length, 2);
  assert.ok(fetchedBuffers.every((buffer) => Buffer.isBuffer(buffer) && buffer.every((byte) => byte === 0)),
    'private SafeFetcher body references passed to evidence stores are wiped after use');

  const reopened = createEvidenceStore(h.evidenceConfig);
  const reopenedScope = await reopened.scopeForAuthenticatedRequest(request());
  const selectedHandles = await Promise.all(result.sources.map((source) => reopened.lookupEvidence(reopenedScope, source.evidenceId)));
  const readback = await reopened.materializeSelected(reopenedScope, {
    evidence: selectedHandles, facts: [],
  }, request());
  assert.deepEqual(readback.evidence.map((item) => item.metadata.evidenceId).sort(),
    result.sources.map((source) => source.evidenceId).sort());
  const reopenedRaw = readback.evidence.find((item) => item.metadata.representation === undefined);
  assert.equal(reopenedRaw.source.sourceUrl, suppliedUrl);
  assert.equal(reopenedRaw.source.canonicalUrl, canonicalUrl);
  assert.ok(reopenedRaw.positions.length > 0);
});

test('opted-in SVG acquisition shares the same run, keeps lexical excerpt bindings, and reopens role-separated encrypted bytes', async (t) => {
  const paths = [];
  const canonicalSvg = '<svg height="10" width="10" xmlns="http://www.w3.org/2000/svg"><rect fill="red" height="3" width="2"/></svg>';
  const event = {
    '@context': 'https://schema.org',
    '@type': 'Event',
    name: 'Bound SVG Event',
    startDate: '2027-06-20',
    location: { name: 'Civic Hall', address: { addressLocality: 'Boston' } },
    logo: '/secondary.svg',
  };
  const jsonLd = JSON.stringify(event).replace('/secondary.svg', `${String.fromCharCode(92)}/secondary.svg`);
  const html = Buffer.from(`<!doctype html><html><head><meta property="og:image" content="/logo&#46;svg#mark"></head><body>`
    + `<script type="application/ld+json">${jsonLd}</script></body></html>`);
  const server = await startFixture((requestValue, response) => {
    paths.push(new URL(requestValue.url, 'http://fixture.example.org').pathname);
    assert.equal(requestValue.headers.authorization, undefined);
    assert.equal(requestValue.headers.cookie, undefined);
    if (['/logo.svg', '/secondary.svg'].includes(new URL(requestValue.url, 'http://fixture.example.org').pathname)) {
      respond(response, 200, { 'content-type': 'image/svg+xml' }, canonicalSvg);
      return;
    }
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, html);
  });
  t.after(() => server.close());
  let evidenceNow = Date.now();
  // The host's lower position ceiling is preserved for controlled byte records;
  // successful reopen below proves the asset is stored in capped chunks.
  const h = await harness(t, { evidenceOptions: { now: () => evidenceNow, maxPositionBytes: 32 } });
  const runId = 'private-controlled-svg-same-run';
  const seedUrl = sourceUrl('/event');
  const sourceRetentionExpiresAt = evidenceNow + 120_000;
  const retentionHandleFor = () => h.createRetention(sourceRetentionExpiresAt);
  const receiptFailures = [];
  const controlledAssetDuplicates = [];
  const observedStore = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'ingestEvidence', 'appendFact', 'ingestDerivedPdfEvidence', 'ingestAssetSourceEvidence',
    'lookupEvidence', 'lookupFact', 'materializeSelected', 'beginPrivateRunReceipt', 'readPrivateRunReceipt',
    'ingestControlledAssetEvidence', 'readControlledAssetBytes', 'readAssetSourceCandidateBinding',
    'revalidateControlledAssetRelease', 'finalizeControlledAssetRelease', 'discardControlledAssetRelease',
  ]) observedStore[name] = h.evidenceStore[name].bind(h.evidenceStore);
  observedStore.finalizePrivateRunReceipt = async (...args) => {
    try { return await h.evidenceStore.finalizePrivateRunReceipt(...args); }
    catch (error) { receiptFailures.push(error?.code ?? error?.name ?? 'unknown'); throw error; }
  };
  observedStore.ingestControlledAssetEvidence = async (...args) => {
    const first = await h.evidenceStore.ingestControlledAssetEvidence(...args);
    const duplicate = await h.evidenceStore.ingestControlledAssetEvidence(...args);
    controlledAssetDuplicates.push({
      role: args[1].provenance.role,
      firstId: first.metadata.evidenceId,
      duplicateId: duplicate.metadata.evidenceId,
      firstCreated: first.created,
      duplicateCreated: duplicate.created,
    });
    return first;
  };
  const assetAcquisitionPolicy = Object.freeze({
    schemaVersion: 1,
    policyVersion: 'ei-private-svg-acquisition/1',
    policyId: 'offline-controlled-svg-test-v1',
    allowedOrigins: Object.freeze(['http://fixture.example.org']),
  });
  const assetAcquisitionPolicyFor = () => assetAcquisitionPolicy;
  const result = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds: [{ url: seedUrl }], assetAcquisitionPolicyFor, retentionHandleFor, store: observedStore,
  }));

  assert.equal(result.status, 'draft', JSON.stringify({ result, receiptFailures }));
  assert.equal(h.releaseControllers.at(-1)?.revoke('positive_after_release'), 'after_release',
    'the host observes a revoke after the synchronous SQLite-backed projection as after_release');
  assert.equal(result.progress.transportAttemptAdmissions, 3, JSON.stringify({ paths, sources: result.sources, limitations: result.limitations }));
  assert.deepEqual(paths, ['/event', '/logo.svg', '/secondary.svg']);
  assert.equal(result.assetAcquisitions.length, 2);
  assert.equal(controlledAssetDuplicates.length, 4);
  assert.ok(controlledAssetDuplicates.every((entry) => entry.firstCreated
    && !entry.duplicateCreated && entry.firstId === entry.duplicateId),
  'an exact same-context and same-role duplicate is idempotent and keeps its immutable evidence identity');
  for (const acquisition of result.assetAcquisitions) {
    assert.equal(acquisition.status, 'blocked_local_inspection_only');
    assert.equal(acquisition.acceptedExternalAssetVersion, null);
    assert.equal(acquisition.questionPlan.status, 'blocked');
    assert.equal(acquisition.questionPlan.execution, 'not_dispatched');
    assert.equal(acquisition.questionPlan.observerMetadata, null);
    assert.equal(acquisition.questionPlan.rights, 'unknown');
    assert.equal(acquisition.questionPlan.permission, 'unknown');
    assert.equal(acquisition.questionPlan.roleClassification, null);
    assert.equal(acquisition.acquiredEvidence.storedBytesReopenedAndVerified, true);
    assert.equal(acquisition.acquiredEvidence.sourceBytesHash, acquisition.acquiredEvidence.transformedBytesHash,
      'canonical input is idempotently transformed while both provenance stages remain represented');
    assert.notEqual(acquisition.acquiredEvidence.fetchedSource.evidenceId,
      acquisition.acquiredEvidence.transformed.evidenceId);
  }
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshot.candidates.length, 3);
  assert.ok(snapshot.candidates.every((candidate) => candidate.state === 'completed'));
  assert.equal(snapshot.attempts.length, 3);

  const reopenedStore = createEvidenceStore(h.evidenceConfig);
  const reopenedScope = await reopenedStore.scopeForAuthenticatedRequest(request());
  const expectedLexicalValues = new Set([
    '/logo&#46;svg#mark',
    `"${String.fromCharCode(92)}/secondary.svg"`,
  ]);
  for (const acquisition of result.assetAcquisitions) {
    const sourceHandle = await reopenedStore.lookupEvidence(reopenedScope, acquisition.candidate.sourceEvidenceId);
    const sourceBinding = await reopenedStore.readAssetSourceCandidateBinding(
      reopenedScope, sourceHandle, acquisition.candidate.assetSourceCandidateId, request(),
    );
    assert.equal(sourceBinding.candidate.value, [...expectedLexicalValues].find((value) => value === sourceBinding.candidate.value));
    assert.equal(sourceBinding.candidate.fetchSuggestion, acquisition.candidate.assetUrl);
    for (const [role, artifact] of [
      ['fetched-source', acquisition.acquiredEvidence.fetchedSource],
      ['transformed', acquisition.acquiredEvidence.transformed],
    ]) {
      const handle = await reopenedStore.lookupEvidence(reopenedScope, artifact.evidenceId);
      const opened = await reopenedStore.readControlledAssetBytes(reopenedScope, handle, request());
      assert.equal(opened.metadata.version, artifact.version);
      assert.equal(opened.metadata.contentHash, artifact.contentHash);
      assert.equal(opened.source.controlledAsset.role, role);
      assert.equal(createHash('sha256').update(opened.bytes).digest('hex'), artifact.contentHash);
      assert.equal(opened.bytes.toString('utf8'), canonicalSvg);
      assert.ok(opened.bytes.byteLength > 32, 'reopened source spans multiple positions under the host 32-byte cap');
      if (role === 'fetched-source') {
        const copiedBytes = Buffer.from(opened.bytes);
        try {
          await assert.rejects(reopenedStore.ingestControlledAssetEvidence(reopenedScope, {
            document: {
              url: opened.source.sourceUrl,
              contentType: opened.source.contentType,
              bytes: copiedBytes,
              fetchedAt: opened.source.retrievedAt,
              redirects: 0,
            },
            retentionHandle: h.createRetention(),
            retentionCeiling: {
              evidence: sourceHandle,
              version: sourceBinding.metadata.version,
              contentHash: sourceBinding.metadata.contentHash,
            },
            provenance: opened.source.controlledAsset,
            witness: Object.freeze(Object.create(null)),
          }, request()), (error) => error?.code === 'EVIDENCE_INVALID');
        } finally {
          copiedBytes.fill(0);
        }
      }
      opened.bytes.fill(0);
    }
  }

  const restartedFrontier = h.openFrontier();
  const recovered = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds: [{ url: seedUrl }], assetAcquisitionPolicyFor, retentionHandleFor,
    frontier: restartedFrontier, store: reopenedStore,
  }));
  assert.equal(recovered.status, 'draft', JSON.stringify(recovered));
  assert.equal(recovered.assetAcquisitions.length, 2);
  assert.equal(paths.length, 3, 'same-config receipt replay reopens evidence without another request');

  const changedPolicyResult = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds: [{ url: seedUrl }],
    assetAcquisitionPolicyFor: () => ({ ...assetAcquisitionPolicy, policyId: 'changed-policy-v1' }),
    retentionHandleFor, frontier: restartedFrontier, store: reopenedStore,
  }));
  assert.equal(changedPolicyResult.status, 'incomplete', 'a changed allowlist policy cannot reopen an immutable run');
  assert.equal(paths.length, 3, 'changed run policy is rejected before transport');

  const revokedAssetAuthorization = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds: [{ url: seedUrl }], assetAcquisitionPolicyFor, retentionHandleFor,
    authorizeCurrent: (_request, context) => context.stage !== 'asset-acquisition',
    frontier: restartedFrontier, store: reopenedStore,
  }));
  assert.equal(revokedAssetAuthorization.status, 'incomplete', JSON.stringify(revokedAssetAuthorization));
  assert.equal(revokedAssetAuthorization.draft, null, 'revoked asset authorization suppresses the local plan');
  assert.equal(paths.length, 3, 'revoked asset authorization does not redispatch completed evidence');

  const roleSwapStore = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'ingestEvidence', 'appendFact', 'ingestDerivedPdfEvidence', 'ingestAssetSourceEvidence',
    'lookupEvidence', 'lookupFact', 'materializeSelected', 'beginPrivateRunReceipt', 'readPrivateRunReceipt',
    'readControlledAssetBytes', 'readAssetSourceCandidateBinding', 'finalizePrivateRunReceipt',
    'revalidateControlledAssetRelease', 'finalizeControlledAssetRelease', 'discardControlledAssetRelease',
  ]) roleSwapStore[name] = h.evidenceStore[name].bind(h.evidenceStore);
  const ingestControlledAssetEvidence = h.evidenceStore.ingestControlledAssetEvidence.bind(h.evidenceStore);
  let fetchedRoleWitness;
  roleSwapStore.ingestControlledAssetEvidence = (scope, input, authenticatedRequest, signal) => {
    if (input.provenance.role === 'fetched-source') fetchedRoleWitness = input.witness;
    return ingestControlledAssetEvidence(scope, {
      ...input,
      ...(input.provenance.role === 'transformed' ? { witness: fetchedRoleWitness } : {}),
    }, authenticatedRequest, signal);
  };
  const roleSwapResult = await runPrivateRetrieval(h.makeInput({
    runId: 'private-controlled-svg-role-swap', server, seeds: [{ url: seedUrl }], assetAcquisitionPolicyFor,
    retentionHandleFor, store: roleSwapStore,
  }));
  assert.equal(roleSwapResult.status, 'draft', JSON.stringify(roleSwapResult));
  assert.deepEqual(roleSwapResult.assetAcquisitions, [], 'a source-role witness cannot authorize a transformed-role record');
  assert.equal(paths.length, 6, 'role mismatch is detected after only the same-run page and two SVG requests');
  const roleSwapSnapshot = await h.frontier.getSnapshot(h.scope, 'private-controlled-svg-role-swap');
  assert.deepEqual(roleSwapSnapshot.candidates.filter((candidate) => candidate.depth > 0)
    .map((candidate) => candidate.completionOutcome), ['failed', 'failed']);

  evidenceNow = sourceRetentionExpiresAt + 1;
  const expiredSourceReplay = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds: [{ url: seedUrl }], assetAcquisitionPolicyFor, retentionHandleFor,
    frontier: restartedFrontier, store: reopenedStore,
  }));
  assert.equal(expiredSourceReplay.status, 'incomplete', JSON.stringify(expiredSourceReplay));
  assert.equal(paths.length, 6, 'expired source evidence cannot trigger a fresh asset fetch');
});

test('controlled release joint tail catches cross-domain revocation after the final async store authorization', async (t) => {
  const svg = '<svg height="10" width="10" xmlns="http://www.w3.org/2000/svg"><rect fill="red" height="3" width="2"/></svg>';
  const policy = Object.freeze({
    schemaVersion: 1,
    policyVersion: 'ei-private-svg-acquisition/1',
    policyId: 'offline-controlled-svg-joint-tail-v1',
    allowedOrigins: Object.freeze(['http://fixture.example.org']),
  });

  for (const mode of [
    'async-store-asset-revocation',
    'async-store-release-revocation',
    'async-store-deadline',
    'host-finalizer-store-acl-revocation',
    'host-finalizer-store-expiry',
    'store-current-auth-host-revocation',
  ]) {
    const paths = [];
    const page = Buffer.from('<!doctype html><html><head><meta property="og:image" content="/logo.svg"></head><body>'
      + '<script type="application/ld+json">{"@type":"Event","name":"Joint Tail Event","startDate":"2027-06-20"}</script></body></html>');
    const server = await startFixture((requestValue, response) => {
      const pathname = new URL(requestValue.url, 'http://fixture.example.org').pathname;
      paths.push(pathname);
      if (pathname === '/logo.svg') respond(response, 200, { 'content-type': 'image/svg+xml' }, svg);
      else respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, page);
    });
    t.after(() => server.close());

    let storeAcl = true;
    let hostReleaseAuthorized = true;
    let hostAssetAuthorized = true;
    const evidenceNowStart = Date.now();
    let evidenceNow = evidenceNowStart;
    const sourceRetentionExpiresAt = evidenceNowStart + 120_000;
    let finalRevalidationEntered = false;
    let firstStoreAuthorizationTriggered = false;
    let firstCurrentAuthorizationTriggered = false;
    let firstHostFinalizationTriggered = false;
    let hostRevocationDisposition = null;
    let finalProjectionEntered = false;
    const performanceObject = globalThis.performance;
    const priorOwnPerformanceNow = Object.getOwnPropertyDescriptor(performanceObject, 'now');
    const realPerformanceNow = performanceObject.now.bind(performanceObject);
    const performanceStart = realPerformanceNow();

    const h = await harness(t, {
      evidenceOptions: {
        now: () => evidenceNow,
        async authorizePrivateAccess({ tenantId, request: authenticated }) {
          if (finalRevalidationEntered && !firstStoreAuthorizationTriggered && mode.startsWith('async-store-')) {
            firstStoreAuthorizationTriggered = true;
            if (mode === 'async-store-asset-revocation') hostAssetAuthorized = false;
            if (mode === 'async-store-release-revocation') hostReleaseAuthorized = false;
            if (mode === 'async-store-asset-revocation' || mode === 'async-store-release-revocation') {
              queueMicrotask(() => {
                hostRevocationDisposition = h.releaseControllers.at(-1)?.revoke(`queued_${mode}`);
              });
            }
            if (mode === 'async-store-deadline') {
              // Advance the actual monotonic clock source used by the runner
              // after final store authorization, without sleeping 30 seconds.
              Object.defineProperty(performanceObject, 'now', {
                configurable: true,
                value: () => performanceStart + 60_000,
              });
            }
          }
          return storeAcl && authenticated?.principal?.tenantId === tenantId && authenticated.allowPrivate === true;
        },
        authorizePrivateAccessCurrent({ tenantId, request: authenticated }) {
          const authorized = storeAcl && authenticated?.principal?.tenantId === tenantId && authenticated.allowPrivate === true;
          if (finalRevalidationEntered && !firstCurrentAuthorizationTriggered
            && mode === 'store-current-auth-host-revocation') {
            firstCurrentAuthorizationTriggered = true;
            hostReleaseAuthorized = false;
            hostRevocationDisposition = h.releaseControllers.at(-1)?.revoke('store_current_auth_reentry');
          }
          return authorized;
        },
      },
    });

    const store = Object.create(null);
    for (const name of [
      'scopeForAuthenticatedRequest', 'ingestEvidence', 'appendFact', 'ingestDerivedPdfEvidence', 'ingestAssetSourceEvidence',
      'lookupEvidence', 'lookupFact', 'materializeSelected', 'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
      'ingestControlledAssetEvidence', 'readControlledAssetBytes', 'readAssetSourceCandidateBinding',
      'revalidateControlledAssetRelease', 'finalizeControlledAssetRelease', 'discardControlledAssetRelease',
    ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
    const finalize = h.evidenceStore.finalizeControlledAssetRelease.bind(h.evidenceStore);
    store.finalizeControlledAssetRelease = (scope, check, authenticated, signal, input) => finalize(
      scope, check, authenticated, signal, {
        ...input,
        project(current) {
          finalProjectionEntered = true;
          return input.project(current);
        },
      },
    );
    const revalidate = h.evidenceStore.revalidateControlledAssetRelease.bind(h.evidenceStore);
    store.revalidateControlledAssetRelease = (scope, input, authenticated, signal) => {
      finalRevalidationEntered = true;
      return revalidate(scope, {
        ...input,
        finalizeHostAuthority(context) {
          const decision = input.finalizeHostAuthority(context);
          if (!firstHostFinalizationTriggered && mode === 'host-finalizer-store-acl-revocation') {
            firstHostFinalizationTriggered = true;
            storeAcl = false;
          }
          if (!firstHostFinalizationTriggered && mode === 'host-finalizer-store-expiry') {
            firstHostFinalizationTriggered = true;
            evidenceNow = sourceRetentionExpiresAt + 1;
          }
          return decision;
        },
      }, authenticated, signal);
    };

    const runId = `private-controlled-svg-joint-tail-${mode}`;
    let result;
    try {
      result = await runPrivateRetrieval(h.makeInput({
        runId,
        server,
        seeds: [{ url: sourceUrl('/event') }],
        store,
        retentionHandleFor: () => h.createRetention(sourceRetentionExpiresAt),
        assetAcquisitionPolicyFor: () => policy,
        authorizeCurrent: (_request, context) => {
          if (context.stage === 'release') return hostReleaseAuthorized;
          if (context.stage === 'asset-acquisition') return hostAssetAuthorized;
          return true;
        },
      }));
    } finally {
      if (priorOwnPerformanceNow) Object.defineProperty(performanceObject, 'now', priorOwnPerformanceNow);
      else delete performanceObject.now;
    }

    assert.deepEqual(paths, ['/event', '/logo.svg'], `${mode} never dispatches a second or replay request`);
    assert.equal(result.status, 'incomplete', `${mode} suppresses stale release output: ${JSON.stringify(result)}`);
    assert.equal(result.draft, null);
    assert.deepEqual(result.assetAcquisitions ?? [], []);
    if (mode === 'async-store-release-revocation') assert.equal(firstStoreAuthorizationTriggered, true);
    if (mode === 'async-store-asset-revocation' || mode === 'async-store-release-revocation'
      || mode === 'store-current-auth-host-revocation') {
      assert.equal(hostRevocationDisposition, 'before_release', `${mode} revokes before the projection linearization point`);
    }
    if (mode === 'async-store-deadline') assert.equal(firstStoreAuthorizationTriggered, true);
    if (mode === 'host-finalizer-store-acl-revocation' || mode === 'host-finalizer-store-expiry') {
      assert.equal(firstHostFinalizationTriggered, true);
    }
    if (mode === 'store-current-auth-host-revocation') assert.equal(firstCurrentAuthorizationTriggered, true);
    if (mode === 'store-current-auth-host-revocation') {
      assert.equal(finalProjectionEntered, false, 'synchronous reentrant revocation is observed before projection');
    }
  }
});

test('opt-in release issuance rejects missing, copied, and wrong-run controllers before transport', async (t) => {
  const paths = [];
  const server = await startFixture((requestValue, response) => {
    paths.push(new URL(requestValue.url, 'http://fixture.example.org').pathname);
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml({ asset: true }));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const policy = Object.freeze({
    schemaVersion: 1,
    policyVersion: 'ei-private-svg-acquisition/1',
    policyId: 'offline-release-capability-v1',
    allowedOrigins: Object.freeze(['http://fixture.example.org']),
  });
  const cases = [
    ['missing', null],
    ['copied-controller', (_request, context) => {
      const controller = createPrivateAssetReleaseAuthority({
        tenantId: TENANT, runId: context.runId, policy: context.policy,
        expiresAtMonotonic: context.deadlineAtMonotonic,
      });
      return Object.freeze({ revoke: controller.revoke });
    }],
    ['wrong-run', (_request, context) => createPrivateAssetReleaseAuthority({
      tenantId: TENANT, runId: `${context.runId}-other`, policy: context.policy,
      expiresAtMonotonic: context.deadlineAtMonotonic,
    })],
  ];
  for (const [name, authorityFor] of cases) {
    const result = await runPrivateRetrieval(h.makeInput({
      runId: `private-release-controller-${name}`, server, seeds: [{ url: sourceUrl('/event') }],
      assetAcquisitionPolicyFor: () => policy,
      assetAcquisitionReleaseAuthorityFor: authorityFor,
    }));
    assert.equal(result.status, 'incomplete', `${name}: ${JSON.stringify(result)}`);
    assert.equal(result.draft, null);
  }
  assert.deepEqual(paths, [], 'invalid opt-in authority cannot dispatch the page or an asset request');
});

test('a queued revocation after SQLite-backed synchronous projection is classified after_release', async (t) => {
  const paths = [];
  const svg = '<svg height="10" width="10" xmlns="http://www.w3.org/2000/svg"><rect height="3" width="2"/></svg>';
  const page = Buffer.from('<!doctype html><html><head><meta property="og:image" content="/logo.svg"></head><body>'
    + '<script type="application/ld+json">{"@type":"Event","name":"Release Event","startDate":"2027-06-20"}</script></body></html>');
  const server = await startFixture((requestValue, response) => {
    const pathname = new URL(requestValue.url, 'http://fixture.example.org').pathname;
    paths.push(pathname);
    if (pathname === '/logo.svg') respond(response, 200, { 'content-type': 'image/svg+xml' }, svg);
    else respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, page);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const policy = Object.freeze({
    schemaVersion: 1,
    policyVersion: 'ei-private-svg-acquisition/1',
    policyId: 'offline-post-release-v1',
    allowedOrigins: Object.freeze(['http://fixture.example.org']),
  });
  let controller;
  let disposition;
  const store = controlledEvidenceAdapter(h.evidenceStore);
  const finalize = store.finalizeControlledAssetRelease.bind(h.evidenceStore);
  store.finalizeControlledAssetRelease = (scope, check, authenticated, signal, input) => finalize(
    scope, check, authenticated, signal, {
      ...input,
      project(current) {
        const projected = input.project(current);
        queueMicrotask(() => { disposition = controller.revoke('queued_after_projection'); });
        return projected;
      },
    },
  );
  const result = await runPrivateRetrieval(h.makeInput({
    runId: 'private-release-after-projection', server, seeds: [{ url: sourceUrl('/event') }],
    store,
    assetAcquisitionPolicyFor: () => policy,
    assetAcquisitionReleaseAuthorityFor: (_request, context) => {
      controller = createPrivateAssetReleaseAuthority({
        tenantId: TENANT, runId: context.runId, policy: context.policy,
        expiresAtMonotonic: context.deadlineAtMonotonic,
      });
      return controller;
    },
  }));
  assert.equal(result.status, 'draft', JSON.stringify(result));
  assert.equal(result.assetAcquisitions.length, 1);
  assert.deepEqual(paths, ['/event', '/logo.svg']);
  await Promise.resolve();
  assert.equal(disposition, 'after_release');
});

test('cancellation queued after revalidation discards its retained one-shot check before projection', async (t) => {
  const paths = [];
  const svg = '<svg height="10" width="10" xmlns="http://www.w3.org/2000/svg"><rect height="3" width="2"/></svg>';
  const page = Buffer.from('<!doctype html><html><head><meta property="og:image" content="/logo.svg"></head><body>'
    + '<script type="application/ld+json">{"@type":"Event","name":"Cancel Release Event","startDate":"2027-06-20"}</script></body></html>');
  const server = await startFixture((requestValue, response) => {
    const pathname = new URL(requestValue.url, 'http://fixture.example.org').pathname;
    paths.push(pathname);
    if (pathname === '/logo.svg') respond(response, 200, { 'content-type': 'image/svg+xml' }, svg);
    else respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, page);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const store = controlledEvidenceAdapter(h.evidenceStore);
  const revalidate = store.revalidateControlledAssetRelease.bind(h.evidenceStore);
  const abortController = new AbortController();
  store.revalidateControlledAssetRelease = async (...args) => {
    const result = await revalidate(...args);
    queueMicrotask(() => abortController.abort());
    return result;
  };
  const policy = Object.freeze({
    schemaVersion: 1,
    policyVersion: 'ei-private-svg-acquisition/1',
    policyId: 'offline-cancel-release-v1',
    allowedOrigins: Object.freeze(['http://fixture.example.org']),
  });
  const result = await runPrivateRetrieval(h.makeInput({
    runId: 'private-release-cancel-check', server, seeds: [{ url: sourceUrl('/event') }], store,
    signal: abortController.signal,
    assetAcquisitionPolicyFor: () => policy,
  }));
  assert.equal(result.status, 'cancelled', JSON.stringify(result));
  assert.equal(result.draft, null);
  assert.deepEqual(paths, ['/event', '/logo.svg']);
  assert.equal(h.releaseControllers.at(-1)?.revoke('cancel_after_preflight'), 'before_release',
    'discard consumes and revokes the authority without releasing the retained snapshot');
});

test('opted-in runs with zero surviving asset plans still recheck current selected retention before projection', async (t) => {
  const paths = [];
  let evidenceNow = Date.now();
  let retentionExpiresAt = evidenceNow + 30_000;
  let finalRevalidationEntered = false;
  const server = await startFixture((requestValue, response) => {
    paths.push(new URL(requestValue.url, 'http://fixture.example.org').pathname);
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t, {
    evidenceOptions: {
      now: () => evidenceNow,
      authorizePrivateAccess({ tenantId, request: authenticated }) {
        if (finalRevalidationEntered) evidenceNow = retentionExpiresAt + 1;
        return tenantId === TENANT && authenticated.allowPrivate === true;
      },
    },
  });
  const store = controlledEvidenceAdapter(h.evidenceStore);
  const revalidate = store.revalidateControlledAssetRelease.bind(h.evidenceStore);
  store.revalidateControlledAssetRelease = (...args) => {
    finalRevalidationEntered = true;
    return revalidate(...args);
  };
  const policy = Object.freeze({
    schemaVersion: 1,
    policyVersion: 'ei-private-svg-acquisition/1',
    policyId: 'offline-empty-assets-v1',
    allowedOrigins: Object.freeze(['http://fixture.example.org']),
  });
  const result = await runPrivateRetrieval(h.makeInput({
    runId: 'private-release-empty-assets', server, seeds: [{ url: sourceUrl('/event') }], store,
    assetAcquisitionPolicyFor: () => policy,
    retentionHandleFor: () => h.createRetention(retentionExpiresAt),
  }));
  assert.equal(finalRevalidationEntered, true, 'the final same-run release barrier runs with no asset role groups');
  assert.equal(result.status, 'incomplete', JSON.stringify(result));
  assert.equal(result.draft, null, 'expired selected source and supported facts cannot escape the final barrier');
  assert.deepEqual(result.assetAcquisitions ?? [], []);
  assert.deepEqual(paths, ['/event'], 'the empty asset path performs no additional transport');
});

test('a store adapter cannot turn the synchronous projection into an async thenable release', async (t) => {
  const paths = [];
  const svg = '<svg height="10" width="10" xmlns="http://www.w3.org/2000/svg"><rect height="3" width="2"/></svg>';
  const page = Buffer.from('<!doctype html><html><head><meta property="og:image" content="/logo.svg"></head><body>'
    + '<script type="application/ld+json">{"@type":"Event","name":"Thenable Event","startDate":"2027-06-20"}</script></body></html>');
  const server = await startFixture((requestValue, response) => {
    const pathname = new URL(requestValue.url, 'http://fixture.example.org').pathname;
    paths.push(pathname);
    if (pathname === '/logo.svg') respond(response, 200, { 'content-type': 'image/svg+xml' }, svg);
    else respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, page);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const store = controlledEvidenceAdapter(h.evidenceStore);
  const finalize = store.finalizeControlledAssetRelease.bind(h.evidenceStore);
  store.finalizeControlledAssetRelease = (scope, check, authenticated, signal, input) => finalize(
    scope, check, authenticated, signal, {
      ...input,
      project(current) { return Promise.resolve(input.project(current)); },
    },
  );
  const policy = Object.freeze({
    schemaVersion: 1,
    policyVersion: 'ei-private-svg-acquisition/1',
    policyId: 'offline-thenable-release-v1',
    allowedOrigins: Object.freeze(['http://fixture.example.org']),
  });
  const result = await runPrivateRetrieval(h.makeInput({
    runId: 'private-release-thenable', server, seeds: [{ url: sourceUrl('/event') }], store,
    assetAcquisitionPolicyFor: () => policy,
  }));
  assert.equal(result.status, 'incomplete', JSON.stringify(result));
  assert.equal(result.draft, null);
  assert.deepEqual(paths, ['/event', '/logo.svg']);
  assert.equal(h.releaseControllers.at(-1)?.revoke('thenable_projection_failed'), 'before_release');
});

test('default-off and zero-depth runs never issue separate asset requests; an ordinary SVG seed stays failed', async (t) => {
  const paths = [];
  const page = Buffer.from('<!doctype html><html><head><meta property="og:image" content="/logo.svg"></head><body>'
    + '<script type="application/ld+json">{"@type":"Event","name":"Bounded Event","startDate":"2027-06-20"}</script></body></html>');
  const server = await startFixture((requestValue, response) => {
    const pathname = new URL(requestValue.url, 'http://fixture.example.org').pathname;
    paths.push(pathname);
    if (pathname.endsWith('.svg')) respond(response, 200, { 'content-type': 'image/svg+xml' }, '<svg/>');
    else respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, page);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const policy = () => ({
    schemaVersion: 1,
    policyVersion: 'ei-private-svg-acquisition/1',
    policyId: 'offline-controlled-svg-test-v1',
    allowedOrigins: ['http://fixture.example.org'],
  });
  const legacyStore = legacyEvidenceAdapter(h.evidenceStore);

  const defaultOff = await runPrivateRetrieval(h.makeInput({
    runId: 'private-controlled-svg-default-off', server, seeds: [{ url: sourceUrl('/event-off') }],
    store: legacyStore,
  }));
  assert.equal(defaultOff.status, 'draft', JSON.stringify(defaultOff));
  assert.deepEqual(paths, ['/event-off']);
  assert.deepEqual(defaultOff.assetAcquisitions, []);

  const explicitNullPolicy = await runPrivateRetrieval(h.makeInput({
    runId: 'private-controlled-svg-policy-null', server, seeds: [{ url: sourceUrl('/event-null') }],
    store: legacyStore, assetAcquisitionPolicyFor: () => null,
  }));
  assert.equal(explicitNullPolicy.status, 'draft', JSON.stringify(explicitNullPolicy));
  assert.deepEqual(paths, ['/event-off', '/event-null'], 'a null policy preserves the default-off legacy path');

  const missingOptInMethods = await runPrivateRetrieval(h.makeInput({
    runId: 'private-controlled-svg-missing-opt-in-methods', server,
    seeds: [{ url: sourceUrl('/event-missing-methods') }],
    store: legacyStore, assetAcquisitionPolicyFor: policy,
  }));
  assert.equal(missingOptInMethods.status, 'incomplete', JSON.stringify(missingOptInMethods));
  assert.ok(missingOptInMethods.limitations.includes('asset_acquisition_store_unavailable'));
  assert.deepEqual(paths, ['/event-off', '/event-null'], 'an opt-in run with a legacy store fails closed before transport');

  const missingReleaseAuthority = await runPrivateRetrieval(h.makeInput({
    runId: 'private-controlled-svg-missing-release-authority', server,
    seeds: [{ url: sourceUrl('/event-missing-authority') }],
    assetAcquisitionPolicyFor: policy,
    assetAcquisitionReleaseAuthorityFor: null,
  }));
  assert.equal(missingReleaseAuthority.status, 'incomplete', JSON.stringify(missingReleaseAuthority));
  assert.ok(missingReleaseAuthority.limitations.includes('asset_acquisition_release_authority_unavailable'));
  assert.deepEqual(paths, ['/event-off', '/event-null'], 'an explicit policy without a release capability does not fetch');

  const widenedDefaultOff = await runPrivateRetrieval(h.makeInput({
    runId: 'private-controlled-svg-default-off', server, seeds: [{ url: sourceUrl('/event-off') }],
    assetAcquisitionPolicyFor: policy,
  }));
  assert.equal(widenedDefaultOff.status, 'incomplete', 'a default-off run cannot be widened on resume');
  assert.equal(paths.length, 2, 'policy widening is rejected before another transport request');

  const zeroDepth = await runPrivateRetrieval(h.makeInput({
    runId: 'private-controlled-svg-zero-depth', server, seeds: [{ url: sourceUrl('/event-zero') }],
    limits: { maxDepth: 0 }, assetAcquisitionPolicyFor: policy,
  }));
  assert.equal(zeroDepth.status, 'draft', JSON.stringify(zeroDepth));
  assert.deepEqual(paths, ['/event-off', '/event-null', '/event-zero']);
  assert.equal(zeroDepth.progress.transportAttemptAdmissions, 1);
  assert.equal(zeroDepth.assetAcquisitions.length, 0);

  const ordinarySeed = await runPrivateRetrieval(h.makeInput({
    runId: 'private-controlled-svg-ordinary-seed', server, seeds: [{ url: sourceUrl('/ordinary.svg') }],
    assetAcquisitionPolicyFor: policy,
  }));
  assert.equal(ordinarySeed.status, 'incomplete', JSON.stringify(ordinarySeed));
  assert.equal(paths.at(-1), '/ordinary.svg');
  assert.equal(ordinarySeed.assetAcquisitions, undefined);
  const ordinarySnapshot = await h.frontier.getSnapshot(h.scope, 'private-controlled-svg-ordinary-seed');
  assert.equal(ordinarySnapshot.candidates[0].completionOutcome, 'failed');
});

test('an asset and ordinary-link URL collision keeps the candidate on ordinary-link retrieval', async (t) => {
  const paths = [];
  const page = Buffer.from('<!doctype html><html><head><meta property="og:image" content="/logo.svg"></head><body>'
    + '<a href="/logo.svg">ordinary link</a>'
    + '<script type="application/ld+json">{"@type":"Event","name":"Collision Event","startDate":"2027-06-20"}</script></body></html>');
  const server = await startFixture((requestValue, response) => {
    const pathname = new URL(requestValue.url, 'http://fixture.example.org').pathname;
    paths.push(pathname);
    if (pathname === '/logo.svg') respond(response, 200, { 'content-type': 'image/svg+xml' }, '<svg/>');
    else respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, page);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const result = await runPrivateRetrieval(h.makeInput({
    runId: 'private-controlled-svg-link-collision', server, seeds: [{ url: sourceUrl('/collision') }],
    assetAcquisitionPolicyFor: () => ({
      schemaVersion: 1,
      policyVersion: 'ei-private-svg-acquisition/1',
      policyId: 'offline-controlled-svg-test-v1',
      allowedOrigins: ['http://fixture.example.org'],
    }),
  }));

  assert.equal(result.status, 'draft', JSON.stringify(result));
  assert.deepEqual(result.assetAcquisitions, [], 'mixed-role URL references cannot upgrade a generic child to asset purpose');
  assert.deepEqual(paths, ['/collision', '/logo.svg']);
  assert.equal(result.progress.transportAttemptAdmissions, 2);
  const snapshot = await h.frontier.getSnapshot(h.scope, 'private-controlled-svg-link-collision');
  const child = snapshot.candidates.find((candidate) => candidate.depth === 1);
  assert.ok(child);
  assert.equal(child.state, 'completed');
  assert.equal(child.completionOutcome, 'failed', 'the ordinary generic retriever rejects the SVG media type');
  assert.equal(snapshot.attempts.length, 2, 'the collision is admitted only once as a normal frontier child');
});

test('transport-accepted SVG prolog syntax is rejected by inspection before evidence promotion', async (t) => {
  const paths = [];
  const page = Buffer.from('<!doctype html><html><head><meta property="og:image" content="/prolog.svg"></head><body>'
    + '<script type="application/ld+json">{"@type":"Event","name":"SVG Prolog Event","startDate":"2027-06-20"}</script></body></html>');
  const declaration = '<?xml version="1.0" encoding="UTF-8"?>';
  const commentPrefix = `${declaration}<!--`;
  const filler = 'a'.repeat(1023 - Buffer.byteLength(commentPrefix));
  const prologSvg = Buffer.from(`${commentPrefix}${filler}é--><svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1"/></svg>`);
  const server = await startFixture((requestValue, response) => {
    const pathname = new URL(requestValue.url, 'http://fixture.example.org').pathname;
    paths.push(pathname);
    if (pathname === '/prolog.svg') respond(response, 200, { 'content-type': 'image/svg+xml' }, prologSvg);
    else respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, page);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const result = await runPrivateRetrieval(h.makeInput({
    runId: 'private-controlled-svg-prolog-reject', server, seeds: [{ url: sourceUrl('/prolog-event') }],
    assetAcquisitionPolicyFor: () => ({
      schemaVersion: 1,
      policyVersion: 'ei-private-svg-acquisition/1',
      policyId: 'offline-controlled-svg-test-v1',
      allowedOrigins: ['http://fixture.example.org'],
    }),
  }));

  assert.equal(result.status, 'draft', JSON.stringify(result));
  assert.deepEqual(paths, ['/prolog-event', '/prolog.svg']);
  assert.equal(result.progress.transportAttemptAdmissions, 2);
  assert.deepEqual(result.assetAcquisitions, [], 'transport signature acceptance does not bypass the safe asset inspector');
  const snapshot = await h.frontier.getSnapshot(h.scope, 'private-controlled-svg-prolog-reject');
  const assetCandidate = snapshot.candidates.find((candidate) => candidate.depth === 1);
  assert.ok(assetCandidate);
  assert.equal(assetCandidate.state, 'completed');
  assert.equal(assetCandidate.completionOutcome, 'failed');
  const transport = await h.frontier.getTransportProgress(h.scope, 'private-controlled-svg-prolog-reject');
  assert.equal(transport.states.body_complete, 2, 'the complete bounded bytes reached inspection without a second request');
  assert.equal(transport.states.unknown ?? 0, 0);
});

test('active, malformed, over-limit, and signature-deceptive SVG responses are never promoted', async (t) => {
  const paths = [];
  const assetPaths = ['/active.svg', '/malformed.svg', '/oversized.svg', '/deceptive.svg'];
  const page = Buffer.from('<!doctype html><html><head>'
    + assetPaths.map((assetPath) => `<meta property="og:image" content="${assetPath}">`).join('')
    + '</head><body><script type="application/ld+json">{"@type":"Event","name":"Bad SVG Event","startDate":"2027-06-20"}</script></body></html>');
  const bodies = new Map([
    ['/active.svg', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><script>alert(1)</script></svg>')],
    ['/malformed.svg', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1">')],
    ['/oversized.svg', Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">${' '.repeat(128 * 1024)}</svg>`) ],
    ['/deceptive.svg', Buffer.from('<!doctype html><html><body>not SVG</body></html>')],
  ]);
  const server = await startFixture((requestValue, response) => {
    const pathname = new URL(requestValue.url, 'http://fixture.example.org').pathname;
    paths.push(pathname);
    if (bodies.has(pathname)) respond(response, 200, { 'content-type': 'image/svg+xml' }, bodies.get(pathname));
    else respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, page);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const result = await runPrivateRetrieval(h.makeInput({
    runId: 'private-controlled-svg-negative-bytes', server, seeds: [{ url: sourceUrl('/bad-assets') }],
    assetAcquisitionPolicyFor: () => ({
      schemaVersion: 1,
      policyVersion: 'ei-private-svg-acquisition/1',
      policyId: 'offline-controlled-svg-test-v1',
      allowedOrigins: ['http://fixture.example.org'],
    }),
  }));

  assert.equal(result.status, 'incomplete', JSON.stringify(result));
  assert.equal(result.draft, null);
  assert.equal(result.progress.transportAttemptAdmissions, 5);
  assert.equal(paths.length, 5, 'each in-budget candidate gets one same-run request');
  assert.deepEqual(new Set(paths), new Set(['/bad-assets', ...assetPaths]));
  assert.equal(result.assetAcquisitions, undefined, 'invalid source bytes never yield stored evidence or a blocked plan');
  const snapshot = await h.frontier.getSnapshot(h.scope, 'private-controlled-svg-negative-bytes');
  assert.equal(snapshot.candidates.length, 5);
  const assetCandidates = snapshot.candidates.filter((candidate) => candidate.depth === 1);
  assert.ok(assetCandidates.every((candidate) => candidate.state === 'completed' && candidate.completionOutcome === 'failed'));
  const transport = await h.frontier.getTransportProgress(h.scope, 'private-controlled-svg-negative-bytes');
  assert.ok(transport.states.unknown > 0, 'an over-limit dispatched response remains unknown rather than releasing its reservation');
});

test('selected-evidence cap seals a useful incomplete draft while preserving queued candidates without another dispatch', async (t) => {
  let requestCount = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-selection-cap-queued';
  const seeds = Array.from({ length: 9 }, (_, index) => ({ url: sourceUrl(`/cap-${index}`) }));
  const result = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds,
    limits: { maxTransportAttemptAdmissions: 8, maxDepth: 0 },
  }));

  assert.equal(result.status, 'draft', JSON.stringify(result));
  assert.equal(result.completeness, 'incomplete');
  assert.ok(result.sources.length > 0);
  assert.ok(result.limitations.includes('selected_evidence_limit'));
  assert.equal(requestCount, 8, 'the selected-evidence cap stops before a ninth request');
  assert.equal(result.progress.transportAttemptAdmissions, 8);
  assert.equal(result.progress.remainingCandidates, 1);
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshot.candidates.filter((candidate) => candidate.state === 'queued').length, 1);
  assert.equal(snapshot.candidates.filter((candidate) => candidate.state === 'completed').length, 8);
  const queued = snapshot.candidates.find((candidate) => candidate.state === 'queued');
  assert.ok(queued);
  assert.deepEqual(await h.frontier.claimNext(h.scope, runId, {
    workerId: 'after-seal', claimKey: 'claim-after-partial-release',
  }), { state: 'stopped', reason: 'private_draft_sealed' });
  const afterSeal = await h.frontier.admitTransportHop(h.scope, runId, {
    leaseToken: 'synthetic-after-partial-release', attemptKey: 'transport-after-partial-release',
    kind: 'initial', url: queued.canonicalUrl,
  });
  assert.equal(afterSeal.state, 'denied');
  assert.equal(afterSeal.reason, 'private_draft_sealed');
  assert.equal(requestCount, 8);
  assert.equal((await h.frontier.getTransportProgress(h.scope, runId)).reservedBytes, 0);
  const reopened = h.openFrontier();
  const reopenedScope = await reopened.scopeForAuthenticatedRequest(request());
  const persisted = await reopened.getSnapshot(reopenedScope, runId);
  assert.equal(persisted.candidates.filter((candidate) => candidate.state === 'queued').length, 1);
  assert.equal(persisted.candidates.filter((candidate) => candidate.state === 'completed').length, 8);
  assert.deepEqual(await reopened.claimNext(reopenedScope, runId, {
    workerId: 'after-reopen', claimKey: 'claim-after-sealed-reopen',
  }), { state: 'stopped', reason: 'private_draft_sealed' });
});

test('each real redirect is admitted before fetch and retained with its exact transport chain', async (t) => {
  let requestCount = 0;
  const finalUrl = new URL(sourceUrl('/final')).href;
  const server = await startFixture((requestValue, response) => {
    requestCount += 1;
    if (requestValue.url === '/start') {
      response.writeHead(302, { location: '/final' });
      response.end();
      return;
    }
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-redirect-chain';
  const result = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds: [{ url: sourceUrl('/start') }],
    limits: { maxTransportAttemptAdmissions: 2, maxDepth: 0 },
  }));
  assert.equal(result.status, 'draft', JSON.stringify(result));
  assert.equal(requestCount, 2);
  assert.equal(result.progress.transportAttemptAdmissions, 2);
  assert.deepEqual(result.sources.find((source) => source.representation === 'raw').redirectChain, [finalUrl]);
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transport.reservedBytes, 0);
  assert.ok(transport.spentBytes > 0);
  assert.equal(transport.states.known_zero, 1);
  assert.equal(transport.states.body_complete, 1);
});

test('private and credential-bearing redirect targets stop before a second admission or dispatch', async (t) => {
  const targets = [
    'http://127.0.0.1/private',
    '/next?access_token=canary-redirect-token',
  ];
  for (const [index, target] of targets.entries()) {
    let requestCount = 0;
    const server = await startFixture((_request, response) => {
      requestCount += 1;
      response.writeHead(302, { location: target });
      response.end();
    });
    t.after(() => server.close());
    const h = await harness(t);
    const runId = `private-redirect-denied-${index}`;
    const result = await runPrivateRetrieval(h.makeInput({
      runId, server, seeds: [{ url: sourceUrl('/start') }],
      limits: { maxTransportAttemptAdmissions: 2, maxDepth: 0 },
    }));
    assert.equal(result.draft, null);
    assert.equal(result.status, 'cancelled');
    assert.ok(result.limitations.includes('safe_fetch_policy_or_dns_denied'));
    assert.equal(requestCount, 1);
    const transport = await h.frontier.getTransportProgress(h.scope, runId);
    assert.equal(transport.reservedBytes, 0);
    assert.equal(transport.spentBytes, 0);
    assert.equal(transport.states.known_zero, 1);
    const snapshot = await h.frontier.getSnapshot(h.scope, runId);
    assert.equal(snapshot.counters.transportAttemptAdmissions, 1);
    assert.equal(JSON.stringify(snapshot).includes('canary-redirect-token'), false);
  }
});

test('real source-bound results aggregate cross-source matching and contradictory event claims', async (t) => {
  const same = eventHtml({ name: 'Moonlight Market', date: '2027-06-20', city: 'Boston' });
  const conflict = eventHtml({ name: 'Moonlight Market', date: '2027-06-21', city: 'Boston' });
  const server = await startFixture((requestValue, response) => {
    const body = requestValue.url === '/same-a' || requestValue.url === '/same-b' ? same : conflict;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, body);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const result = await runPrivateRetrieval(h.makeInput({
    runId: 'private-cross-source', server,
    seeds: ['/same-a', '/same-b', '/conflict'].map((pathname) => ({ url: sourceUrl(pathname) })),
    limits: { maxTransportAttemptAdmissions: 3, maxDepth: 0 },
  }));

  assert.equal(result.status, 'draft', JSON.stringify(result));
  assert.equal(result.occurrenceCandidates.length, 3);
  assert.equal(result.occurrenceDecisions.length, 3);
  assert.ok(result.occurrenceDecisions.some((decision) => decision.duplicateContentHashes.length === 1));
  assert.ok(result.occurrenceDecisions.some((decision) => decision.conflictFields.includes('start')));
  assert.ok(result.conflicts.some((conflictValue) => conflictValue.fields?.includes('start')));
  assert.ok(result.facts.filter((fact) => fact.field === 'startDate').length >= 3);
});

test('an OS-process cancellation closes a slow active request and leaves its full reservation unresolved', { timeout: 8_000 }, async (t) => {
  let reached;
  let closed;
  let release;
  const requestStarted = new Promise((resolve) => { reached = resolve; });
  const requestClosed = new Promise((resolve) => { closed = resolve; });
  const hold = new Promise((resolve) => { release = resolve; });
  const server = await startFixture(async (_request, response) => {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.write('<!doctype html><html><body>slow');
    response.once('close', closed);
    reached();
    await hold;
    if (!response.destroyed) response.end(eventHtml());
  });
  t.after(async () => { release(); await server.close(); });
  const h = await harness(t);
  const runId = 'private-remote-cancel';
  const running = runPrivateRetrieval(h.makeInput({
    runId, server, seeds: [{ url: sourceUrl('/slow') }],
    limits: { maxTransportAttemptAdmissions: 1, maxDepth: 0 },
  }));
  await requestStarted;
  assert.equal((await h.frontier.getSnapshot(h.scope, runId)).stopReason, 'attempt_limit',
    'automatic exhaustion after the last allowed admission is not itself cancellation');
  const cancelStarted = Date.now();
  await runStopWorker(h.frontierDirectory, runId);
  assert.ok((await h.frontier.getSnapshot(h.scope, runId)).stopReasons.some((entry) => entry.reason === 'cancelled'),
    'the durable cancellation event is present even when the primary stop reason was already exhausted');
  await requestClosed;
  const result = await running;
  assert.ok(Date.now() - cancelStarted < 5_000, 'remote cancellation closes the active request promptly');
  assert.equal(result.status, 'cancelled');
  assert.equal(result.draft, null);
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transport.reservedBytes, 20 * 1024 * 1024);
  assert.equal(transport.spentBytes, 0);
});

test('abort races an initially-live hop settlement without a late commit', { timeout: 8_000 }, async (t) => {
  for (const scenario of ['known-zero', 'unknown']) {
    let settlementReached;
    let settlementFinished;
    let releaseSettlement;
    const reached = new Promise((resolve) => { settlementReached = resolve; });
    const finished = new Promise((resolve) => { settlementFinished = resolve; });
    const held = new Promise((resolve) => { releaseSettlement = resolve; });
    const controller = new AbortController();
    const server = await startFixture((_request, response) => {
      if (scenario === 'unknown') {
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        response.write('<!doctype html><html><body>partial');
        setTimeout(() => response.destroy(), 25);
      } else {
        respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
      }
    });
    t.after(() => server.close());
    const h = await harness(t);
    const settlementMethod = scenario === 'known-zero'
      ? 'settleTransportHopKnownZero'
      : 'markTransportHopUnknown';
    let settlementCalls = 0;
    const overrides = {
      [settlementMethod]: async (...args) => {
        settlementCalls += 1;
        if (scenario === 'known-zero' && settlementCalls === 1) {
          throw new Error('fail the SafeFetcher known-zero hook so finally owns the next settlement');
        }
        assert.equal(args.at(-1)?.aborted, false, 'the finalizer settlement starts while the run is still live');
        settlementReached();
        await held;
        try { return await h.frontier[settlementMethod](...args); }
        finally { settlementFinished(); }
      },
    };
    if (scenario === 'known-zero') {
      overrides.markTransportDispatchIntent = async () => {
        throw new Error('controlled dispatch hook failure before socket creation');
      };
    }
    const frontier = frontierWithMethodOverrides(h.frontier, overrides);
    const runId = `private-late-${scenario}-settlement`;
    const running = runPrivateRetrieval(h.makeInput({
      runId, server, frontier, signal: controller.signal,
      seeds: [{ url: sourceUrl(`/${scenario}`) }],
      limits: { maxTransportAttemptAdmissions: 1, maxDepth: 0 },
    }));
    const gateOutcome = await Promise.race([
      reached.then(() => ({ reached: true })),
      running.then((value) => ({ result: value }), (error) => ({ error: String(error) })),
      new Promise((resolve) => setTimeout(() => resolve({ timeout: true }), 2_000)),
    ]);
    assert.equal(gateOutcome.reached, true, JSON.stringify(gateOutcome));
    assert.equal(settlementCalls, scenario === 'known-zero' ? 2 : 1,
      'the delayed operation is the intended initially-live finally settlement');
    const abortStarted = Date.now();
    controller.abort();
    const result = await running;
    assert.ok(Date.now() - abortStarted < 1_000, `${scenario} settlement wait is bounded to shutdown scale`);
    assert.equal(result.draft, null);
    assert.equal(result.status, 'cancelled');
    releaseSettlement();
    await Promise.race([
      finished,
      new Promise((_, reject) => setTimeout(() => reject(new Error('late settlement did not acknowledge its attempt')), 1_000)),
    ]);
    const reopened = h.openFrontier();
    const reopenedScope = await reopened.scopeForAuthenticatedRequest(request());
    const transport = await reopened.getTransportProgress(reopenedScope, runId);
    assert.equal(transport.reservedBytes, 20 * 1024 * 1024,
      'a settlement whose outcome was uncertain at cancellation retains its full durable reservation');
    assert.equal(transport.spentBytes, 0);
    assert.equal(transport.states[scenario === 'known-zero' ? 'reserved' : 'response_received'], 1);
    assert.equal(transport.states.known_zero ?? 0, 0);
  }
});

test('a restarted runner reports an admitted stale lease incomplete without redispatching it', async (t) => {
  let requestCount = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-restart-unknown';
  const seeds = [{ url: sourceUrl('/already-dispatched') }];
  const limits = {
    maxDepth: 0,
    maxTransportAttemptAdmissions: 1,
    maxInFlightLeases: 4,
    durationMs: 30_000,
    maxSuggestionsPerCompletion: 16,
  };
  await h.frontier.createRun(h.scope, { runId, seeds, limits });
  const priorClaim = await h.frontier.claimNext(h.scope, runId, { workerId: 'crashed-worker', claimKey: 'crashed-claim' });
  const attemptKey = 'crashed-in-flight-attempt';
  const admission = await h.frontier.admitTransportHop(h.scope, runId, {
    leaseToken: priorClaim.leaseToken, attemptKey, kind: 'initial', url: priorClaim.candidate.canonicalUrl,
  });
  assert.equal(admission.state, 'admitted');
  await h.frontier.markTransportDispatchIntent(h.scope, runId, { leaseToken: priorClaim.leaseToken, attemptKey });
  await h.frontier.markTransportResponseReceived(h.scope, runId, { leaseToken: priorClaim.leaseToken, attemptKey });
  h.frontier.close();

  const restartedFrontier = h.openFrontier();
  const restartedScope = await restartedFrontier.scopeForAuthenticatedRequest(request());
  const result = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, frontier: restartedFrontier, limits,
  }));
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('dispatch_state_unknown'), JSON.stringify(result));
  assert.equal(requestCount, 0, 'a prior lease and admission do not authorize a second transport dispatch');
  const snapshot = await restartedFrontier.getSnapshot(restartedScope, runId);
  assert.equal(snapshot.counters.transportAttemptAdmissions, 1);
  assert.equal(snapshot.candidates[0].state, 'unresolved');
  assert.ok(snapshot.stopReasons.some((entry) => entry.reason === 'unresolved_work'));
  const transport = await restartedFrontier.getTransportProgress(restartedScope, runId);
  assert.equal(transport.reservedBytes, 20 * 1024 * 1024);
  assert.equal(transport.spentBytes, 0);
  assert.equal(transport.states.response_received, 1);
});

test('encrypted receipts recover sealed cross-source identity after same-config restart with current authorization', async (t) => {
  let requestCount = 0;
  const same = eventHtml({ name: 'Moonlight Market', date: '2027-06-20', city: 'Boston' });
  const conflict = eventHtml({ name: 'Moonlight Market', date: '2027-06-21', city: 'Boston' });
  const server = await startFixture((requestValue, response) => {
    requestCount += 1;
    const body = requestValue.url === '/same-a' || requestValue.url === '/same-b' ? same : conflict;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, body);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-receipt-sealed-restart';
  const seeds = ['/same-a', '/same-b', '/conflict'].map((pathname) => ({ url: sourceUrl(pathname) }));
  const limits = {
    maxDepth: 0,
    maxTransportAttemptAdmissions: 3,
    maxInFlightLeases: 4,
    durationMs: 30_000,
    maxSuggestionsPerCompletion: 16,
  };
  const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
  assert.equal(first.status, 'draft', JSON.stringify(first));
  assert.ok(first.conflicts.some((item) => item.fields?.includes('start')));
  assert.equal(requestCount, 3);

  const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
  const database = new DatabaseSync(path.join(h.evidenceConfig.directory, tenantHash, 'evidence.sqlite'));
  try {
    const manifest = JSON.parse(database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?')
      .get(tenantHash).document);
    const extension = database.prepare(`SELECT version FROM evidence_extension_schema
      WHERE extension = 'private-retrieval-receipts'`).get();
    assert.equal(manifest.schemaVersion, 1, 'receipt storage does not migrate the evidence manifest profile');
    assert.equal(extension.version, 1, 'receipt storage keeps its own additive schema version');
    const receipts = database.prepare(`SELECT state, schema_version, key_id, payload_hash, payload_bytes, sealed
      FROM private_retrieval_receipts WHERE tenant_hash = ? ORDER BY receipt_key`).all(tenantHash);
    assert.equal(receipts.length, 3);
    assert.ok(receipts.every((row) => row.state === 'complete' && row.schema_version === 1));
    for (const row of receipts) {
      assert.equal(row.key_id, 'payload-test-v1');
      assert.match(row.payload_hash, /^[a-f0-9]{64}$/);
      assert.ok(row.payload_bytes > 0 && row.payload_bytes <= 512 * 1024);
      const envelope = Buffer.from(row.sealed).toString('utf8');
      for (const privateValue of ['Moonlight Market', 'Civic Hall', '2027-06-20', '2027-06-21', 'Boston']) {
        assert.equal(envelope.includes(privateValue), false, `receipt envelope must not expose ${privateValue}`);
      }
    }
  } finally {
    database.close();
  }

  const reopenedFrontier = h.openFrontier();
  const reopenedStore = createEvidenceStore(h.evidenceConfig);
  const recovered = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
  }));
  assert.equal(requestCount, 3, 'sealed receipt replay performs no second transport');
  assert.equal(recovered.status, 'draft', JSON.stringify(recovered));
  assert.deepEqual(recovered.facts, first.facts);
  assert.deepEqual(recovered.sources, first.sources);
  assert.deepEqual(JSON.parse(JSON.stringify(recovered.occurrenceCandidates)),
    JSON.parse(JSON.stringify(first.occurrenceCandidates)));
  assert.deepEqual(JSON.parse(JSON.stringify(recovered.occurrenceDecisions)),
    JSON.parse(JSON.stringify(first.occurrenceDecisions)));
  assert.deepEqual(recovered.conflicts, first.conflicts);

  h.setAcl(false);
  const deniedFrontier = h.openFrontier();
  const deniedStore = createEvidenceStore(h.evidenceConfig);
  const denied = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: deniedFrontier, store: deniedStore,
  }));
  assert.equal(denied.draft, null);
  assert.notEqual(denied.status, 'draft');
  assert.ok(denied.limitations.includes('private_receipt_unavailable'));
  assert.equal(requestCount, 3, 'revoked authorization cannot turn receipt replay into a new fetch');
});

for (const mode of ['self-canonical', 'backlink', 'cycle']) {
  test(`same-config receipt replay retains claim-time binding after ${mode} observations`, async (t) => {
    let requestCount = 0;
    const targetFor = (pathname) => mode === 'self-canonical'
      ? (pathname === '/self' ? sourceUrl('/self') : null)
      : mode === 'backlink'
        ? (pathname === '/b' ? sourceUrl('/a') : null)
        : (pathname === '/a' ? sourceUrl('/b') : pathname === '/b' ? sourceUrl('/a') : null);
    const server = await startFixture((requestValue, response) => {
      requestCount += 1;
      const canonicalTarget = targetFor(requestValue.url);
      const canonical = canonicalTarget ? `<link rel="canonical" href="${canonicalTarget}">` : '';
      respond(response, 200, { 'content-type': 'text/html; charset=utf-8' },
        Buffer.concat([eventHtml({ name: `Canonical replay ${requestValue.url}` }), Buffer.from(canonical)]));
    });
    t.after(() => server.close());
    const h = await harness(t);
    const runId = `private-claim-prefix-${mode}`;
    const seeds = (mode === 'self-canonical' ? ['/self'] : mode === 'backlink' ? ['/a', '/b'] : ['/a'])
      .map((pathname) => ({ url: sourceUrl(pathname) }));
    const limits = { maxDepth: 1, maxTransportAttemptAdmissions: mode === 'cycle' ? 2 : seeds.length };
    const canonicalUrl = (pathname) => new URL(sourceUrl(pathname)).href;
    const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
    assert.equal(first.status, 'draft', JSON.stringify(first));
    const firstSnapshot = await h.frontier.getSnapshot(h.scope, runId);
    if (mode === 'self-canonical') {
      assert.ok(firstSnapshot.observations.some((item) => ['cycle', 'duplicate'].includes(item.disposition)
        && item.canonicalUrl === canonicalUrl('/self')));
    } else if (mode === 'backlink') {
      const linkedSeed = firstSnapshot.candidates.find((item) => item.canonicalUrl === canonicalUrl('/a'));
      assert.ok(linkedSeed.sourceRefs.length > 0, 'the later backlink remains in current frontier provenance');
    } else {
      assert.ok(firstSnapshot.observations.some((item) => item.disposition === 'cycle'),
        'the later cyclic observation remains represented');
    }

    const reopenedFrontier = h.openFrontier();
    const reopenedStore = createEvidenceStore(h.evidenceConfig);
    const replay = await runPrivateRetrieval(h.makeInput({
      runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
    }));
    assert.equal(requestCount, seeds.length + (mode === 'cycle' ? 1 : 0), 'replay never redispatches a completed candidate');
    assert.equal(replay.status, 'draft', JSON.stringify(replay));
    assert.deepEqual(replay.facts, first.facts);
    const reopenedScope = await reopenedFrontier.scopeForAuthenticatedRequest(request());
    const replaySnapshot = await reopenedFrontier.getSnapshot(reopenedScope, runId);
    assert.deepEqual(replaySnapshot.observations, firstSnapshot.observations,
      'later duplicate/cycle provenance remains available after receipt replay');
  });
}

for (const tamper of ['provenance', 'candidate', 'supplied-url', 'claim-key', 'claim-worker', 'claim-lease', 'completion-key', 'completion-outcome']) {
  test(`receipt replay withholds disclosure when durable ${tamper} no longer matches the sealed claim`, async (t) => {
    let requestCount = 0;
    const server = await startFixture((requestValue, response) => {
      requestCount += 1;
      const canonical = requestValue.url === '/root'
        ? `<link rel="canonical" href="${sourceUrl('/target')}">` : '';
      respond(response, 200, { 'content-type': 'text/html; charset=utf-8' },
        Buffer.concat([eventHtml({ name: `Tamper check ${requestValue.url}` }), Buffer.from(canonical)]));
    });
    t.after(() => server.close());
    const h = await harness(t);
    const runId = `private-claim-tamper-${tamper}`;
    const seeds = [{ url: sourceUrl('/root') }];
    const limits = { maxDepth: 1, maxTransportAttemptAdmissions: 2 };
    const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
    assert.equal(first.status, 'draft', JSON.stringify(first));
    const before = await h.frontier.getSnapshot(h.scope, runId);
    const candidate = before.candidates.find((item) => item.canonicalUrl === new URL(sourceUrl('/target')).href);
    assert.ok(candidate);
    if (tamper === 'provenance') assert.equal(candidate.sourceRefs.length, 1);

    const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
    const database = new DatabaseSync(path.join(h.frontierDirectory, tenantHash, 'frontier.sqlite'));
    try {
      withPrivilegedFrontierFixtureMutation(database, () => {
        if (tamper === 'provenance') {
          database.prepare(`UPDATE frontier_observations SET source_refs_json = '[]'
            WHERE tenant_hash = ? AND run_id = ? AND target_candidate_id = ? AND kind = 'link'`)
            .run(tenantHash, runId, candidate.candidateId);
        } else if (tamper === 'supplied-url') {
          const suppliedUrl = 'http://fixture.example.org:80/target';
          const observations = database.prepare(`SELECT sequence, source_refs_json FROM frontier_observations
            WHERE tenant_hash = ? AND run_id = ? AND target_candidate_id = ? AND kind = 'link'`)
            .all(tenantHash, runId, candidate.candidateId);
          assert.equal(observations.length, 1);
          for (const observation of observations) {
            const sourceRefs = JSON.parse(observation.source_refs_json);
            for (const reference of sourceRefs) reference.value = suppliedUrl;
            database.prepare(`UPDATE frontier_observations SET supplied_url = ?, source_refs_json = ?
              WHERE tenant_hash = ? AND run_id = ? AND sequence = ?`)
              .run(suppliedUrl, JSON.stringify(sourceRefs), tenantHash, runId, observation.sequence);
          }
        } else if (tamper === 'candidate') {
          database.prepare(`UPDATE frontier_candidates SET canonical_url = 'https://fixture.example.org/tampered-candidate'
            WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
            .run(tenantHash, runId, candidate.candidateId);
        } else if (tamper === 'claim-key') {
          database.exec('PRAGMA defer_foreign_keys = ON');
          database.prepare(`UPDATE frontier_attempts SET claim_key = 'tampered-claim-key'
            WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
            .run(tenantHash, runId, candidate.candidateId);
          database.prepare(`UPDATE frontier_claims SET claim_key = 'tampered-claim-key'
            WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
            .run(tenantHash, runId, candidate.candidateId);
        } else if (tamper === 'claim-worker') {
          database.prepare(`UPDATE frontier_claims SET worker_id = 'tampered-worker'
            WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
            .run(tenantHash, runId, candidate.candidateId);
        } else if (tamper === 'claim-lease') {
          database.prepare(`UPDATE frontier_claims SET lease_token = '123e4567-e89b-42d3-a456-426614174001'
            WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
            .run(tenantHash, runId, candidate.candidateId);
        } else if (tamper === 'completion-key') {
          database.prepare(`UPDATE frontier_completions SET completion_key = 'tampered-completion'
            WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
            .run(tenantHash, runId, candidate.candidateId);
        } else {
          database.prepare(`UPDATE frontier_completions SET outcome = 'failed'
            WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
            .run(tenantHash, runId, candidate.candidateId);
        }
      });
    } finally {
      database.close();
    }

    const reopenedFrontier = h.openFrontier();
    const reopenedStore = createEvidenceStore(h.evidenceConfig);
    const replay = await runPrivateRetrieval(h.makeInput({
      runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
    }));
    assert.equal(replay.status, 'incomplete', JSON.stringify(replay));
    assert.equal(replay.draft, null);
    const expectedLimitation = ['provenance', 'supplied-url'].includes(tamper) ? 'private_receipt_mismatch'
      : ['claim-key', 'claim-worker'].includes(tamper) ? 'private_receipt_claim_mismatch'
        : ['completion-key', 'completion-outcome'].includes(tamper) ? 'private_receipt_completion_mismatch'
          : 'private_receipt_unavailable';
    assert.ok(replay.limitations.includes(expectedLimitation), JSON.stringify(replay));
    assert.equal(requestCount, 2, 'mismatched durable bindings do not authorize a second request');
  });
}

test('a complete receipt recovers evidence committed before a failed frontier completion without redispatch', async (t) => {
  let requestCount = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-receipt-before-frontier-completion';
  const seeds = [{ url: sourceUrl('/receipt-before-frontier') }];
  const limits = { maxDepth: 0, maxTransportAttemptAdmissions: 1 };
  let failCompletion = true;
  const interruptedFrontier = frontierWithMethodOverrides(h.frontier, {
    completeCandidate: async (...args) => {
      if (failCompletion) {
        failCompletion = false;
        throw new Error('simulated interruption after receipt commit');
      }
      return h.frontier.completeCandidate(...args);
    },
  });
  const interrupted = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: interruptedFrontier,
  }));
  assert.equal(interrupted.status, 'incomplete');
  assert.equal(interrupted.draft, null);
  assert.equal(requestCount, 1);
  const beforeRestart = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(beforeRestart.candidates[0].state, 'leased');
  assert.equal((await h.frontier.getTransportProgress(h.scope, runId)).reservedBytes, 0);

  const reopenedFrontier = h.openFrontier();
  const reopenedStore = createEvidenceStore(h.evidenceConfig);
  const recovered = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
  }));
  assert.equal(recovered.status, 'draft', JSON.stringify(recovered));
  assert.ok(recovered.facts.some((fact) => fact.field === 'startDate'));
  assert.equal(requestCount, 1, 'frontier completion is repaired from the receipt without a second request');
  const reopenedScope = await reopenedFrontier.scopeForAuthenticatedRequest(request());
  const afterRestart = await reopenedFrontier.getSnapshot(reopenedScope, runId);
  assert.equal(afterRestart.candidates[0].state, 'completed');
});

test('per-completion cap retains omitted provenance and deterministically replays after receipt interruption', async (t) => {
  let requestCount = 0;
  const acceptedUrl = 'https://links.example.org/a-first';
  const omittedUrl = 'https://links.example.org/z-last';
  const server = await startFixture((requestValue, response) => {
    requestCount += 1;
    const reverse = requestValue.url.endsWith('/reverse');
    const links = reverse ? [omittedUrl, acceptedUrl] : [acceptedUrl, omittedUrl];
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtmlWithCanonicalLinks(links));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const limits = {
    maxDepth: 1,
    maxTransportAttemptAdmissions: 1,
    maxInFlightLeases: 4,
    durationMs: 30_000,
    maxSuggestionsPerCompletion: 1,
  };
  const assertBoundedResult = (result) => {
    assert.equal(result.status, 'draft', JSON.stringify(result));
    assert.equal(result.linkCandidates.length, 1);
    assert.equal(result.linkCandidates[0].url, acceptedUrl);
    assert.equal(result.omittedLinkCandidates.length, 1);
    assert.equal(result.omittedLinkCandidates[0].url, omittedUrl);
    assert.equal(result.omittedLinkCandidates[0].reason, 'completion_suggestion_limit');
    assert.equal(result.omittedLinkCandidates[0].depth, undefined,
      'omitted links are not projected as queued frontier candidates');
    assert.equal(result.omittedLinkCandidates[0].sourceAuthority, undefined);
    assert.equal(result.progress.truncatedSuggestionCount, 1);
    assert.equal(result.progress.sourceLinkCandidateOmittedCount, 0);
    assert.equal(result.progress.sourceLinkCandidateOmittedCountLowerBound, 0);
    assert.equal(result.progress.sourceLinkCandidateOmittedCountComplete, true);
    assert.ok(result.progress.stopReasons.includes('fanout_limit'));
    const acceptedRef = result.linkCandidates[0].sourceRefs[0];
    const omittedRef = result.omittedLinkCandidates[0].sourceRefs[0];
    assert.equal(acceptedRef.value, acceptedUrl);
    assert.equal(omittedRef.value, omittedUrl);
    const source = result.sources.find((candidate) => candidate.evidenceId === omittedRef.evidenceId);
    assert.ok(source, 'omitted provenance remains tied to selected evidence');
    assert.equal(omittedRef.contentHash, source.contentHash);
    assert.equal(acceptedRef.contentHash, source.contentHash);
  };

  const orderedRunId = 'private-cap-order-a';
  const orderedSeeds = [{ url: sourceUrl('/fanout/ordered') }];
  const ordered = await runPrivateRetrieval(h.makeInput({ runId: orderedRunId, server, seeds: orderedSeeds, limits }));
  assertBoundedResult(ordered);
  const orderedSnapshot = await h.frontier.getSnapshot(h.scope, orderedRunId);
  assert.equal(orderedSnapshot.candidates.filter((candidate) => candidate.state === 'queued').length, 1);
  assert.ok(!orderedSnapshot.candidates.some((candidate) => candidate.canonicalUrl === omittedUrl));

  const interruptedRunId = 'private-cap-order-b-restart';
  const interruptedSeeds = [{ url: sourceUrl('/fanout/reverse') }];
  let failCompletion = true;
  const interruptedFrontier = frontierWithMethodOverrides(h.frontier, {
    completeCandidate: async (...args) => {
      if (failCompletion) {
        failCompletion = false;
        throw new Error('simulated crash after bounded receipt finalization');
      }
      return h.frontier.completeCandidate(...args);
    },
  });
  const interrupted = await runPrivateRetrieval(h.makeInput({
    runId: interruptedRunId, server, seeds: interruptedSeeds, limits, frontier: interruptedFrontier,
  }));
  assert.equal(interrupted.status, 'incomplete');
  assert.equal(interrupted.draft, null);
  assert.equal(requestCount, 2, 'each seed is fetched once despite the receipt/frontier crash boundary');
  const interruptedSnapshot = await h.frontier.getSnapshot(h.scope, interruptedRunId);
  assert.equal(interruptedSnapshot.candidates[0].state, 'leased');
  assert.equal((await h.frontier.getTransportProgress(h.scope, interruptedRunId)).reservedBytes, 0);
  const bindingBeforeRestart = await h.frontier.getCandidateReceiptBinding(
    h.scope, interruptedRunId, interruptedSnapshot.candidates[0].candidateId,
  );
  const configHash = createHash('sha256').update(JSON.stringify({
    runId: interruptedRunId,
    seeds: interruptedSeeds,
    limits,
  })).digest('hex');
  const receiptBeforeRestart = await h.evidenceStore.readPrivateRunReceipt(h.evidenceScope, {
    runId: interruptedRunId,
    configHash,
    candidate: bindingBeforeRestart.candidate,
  }, request());
  assert.equal(receiptBeforeRestart.state, 'complete');
  assert.equal(receiptBeforeRestart.truncatedCount, 1);
  assert.deepEqual(receiptBeforeRestart.suggestions.map((suggestion) => suggestion.url), [acceptedUrl]);
  assert.deepEqual(receiptBeforeRestart.omittedSuggestions.map((suggestion) => suggestion.url), [omittedUrl]);

  const reopenedFrontier = h.openFrontier();
  const reopenedStore = createEvidenceStore(h.evidenceConfig);
  const recovered = await runPrivateRetrieval(h.makeInput({
    runId: interruptedRunId, server, seeds: interruptedSeeds, limits,
    frontier: reopenedFrontier, store: reopenedStore,
  }));
  assertBoundedResult(recovered);
  assert.equal(requestCount, 2, 'receipt recovery does not dispatch the old lease again');
  const reopenedScope = await reopenedFrontier.scopeForAuthenticatedRequest(request());
  const afterRestart = await reopenedFrontier.getSnapshot(reopenedScope, interruptedRunId);
  assert.equal(afterRestart.candidates[0].state, 'completed');
  const reopenedEvidenceScope = await reopenedStore.scopeForAuthenticatedRequest(request());
  const receiptAfterRestart = await reopenedStore.readPrivateRunReceipt(reopenedEvidenceScope, {
    runId: interruptedRunId,
    configHash,
    candidate: bindingBeforeRestart.candidate,
  }, request());
  assert.deepEqual(receiptAfterRestart.suggestions, receiptBeforeRestart.suggestions);
  assert.deepEqual(receiptAfterRestart.omittedSuggestions, receiptBeforeRestart.omittedSuggestions);
  assert.equal(receiptAfterRestart.truncatedCount, receiptBeforeRestart.truncatedCount);
  assert.equal(recovered.linkCandidates[0].url, ordered.linkCandidates[0].url,
    'sorting by URL makes the accepted subset independent of extraction order');
  assert.equal(recovered.omittedLinkCandidates[0].url, ordered.omittedLinkCandidates[0].url);
});

test('no-links receipt records parser or URL-policy omission counts without retaining unsafe URLs', async (t) => {
  let requestCount = 0;
  const unsafeUrl = 'https://links.example.org/?access_token=synthetic-canary';
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' },
      eventHtmlWithCanonicalLinks([unsafeUrl]));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-no-links-policy-omission';
  const seeds = [{ url: sourceUrl('/unsafe-canonical') }];
  const limits = {
    maxDepth: 1, maxTransportAttemptAdmissions: 1, maxInFlightLeases: 4,
    durationMs: 30_000, maxSuggestionsPerCompletion: 1,
  };
  const result = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
  assert.equal(result.status, 'draft', JSON.stringify(result));
  assert.equal(result.linkCandidates.length, 0);
  assert.equal(result.omittedLinkCandidates.length, 0,
    'unsafe source URLs are counted without exposing or retaining their values');
  assert.equal(result.progress.truncatedSuggestionCount, 0,
    'the completion fanout cap did not omit any eligible suggestion');
  assert.equal(result.progress.sourceLinkCandidateOmittedCount, 1);
  assert.equal(result.progress.sourceLinkCandidateOmittedCountLowerBound, 1);
  assert.equal(result.progress.sourceLinkCandidateOmittedCountComplete, true);
  assert.ok(!result.progress.stopReasons.includes('fanout_limit'));
  assert.ok(result.limitations.includes('some_link_candidates_omitted_by_policy_or_parser_limit'));
  assert.equal(JSON.stringify(result).includes('synthetic-canary'), false);
  assert.equal(requestCount, 1, 'the unsafe canonical link is never fetched');

  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  const candidate = snapshot.candidates.find((item) => item.seed);
  const binding = await h.frontier.getCandidateReceiptBinding(h.scope, runId, candidate.candidateId);
  const configHash = createHash('sha256').update(JSON.stringify({ runId, seeds, limits })).digest('hex');
  const receipt = await h.evidenceStore.readPrivateRunReceipt(h.evidenceScope, {
    runId, configHash, candidate: binding.candidate,
  }, request());
  assert.equal(receipt.state, 'complete');
  assert.equal(receipt.outcome, 'no_links');
  assert.equal(receipt.truncatedCount, 0);
  assert.deepEqual(receipt.omittedSuggestions, []);
  assert.equal(receipt.sourceLinkCandidatesOmittedCount, 1);
  assert.ok(receipt.limitations.includes('some_link_candidates_omitted_by_policy_or_parser_limit'));
});

test('baseline positive run-level omission marker stays unknown when aggregated with a new exact contribution', async (t) => {
  const requests = { count: 0 };
  const h = await legacyOvercapWorkspace(t, requests, 'private-run-receipt-v1-policy-omission');
  let frontier = h.openFrontier();
  let evidenceStore = h.openEvidenceStore();
  const scope = await frontier.scopeForAuthenticatedRequest(h.request);
  const before = await frontier.getSnapshot(scope, h.runId);
  const completedSeed = before.candidates.find((candidate) => candidate.seed && candidate.state === 'completed');
  const queuedSeeds = before.candidates.filter((candidate) => candidate.seed && candidate.state === 'queued');
  assert.ok(completedSeed);
  assert.equal(queuedSeeds.length, 1);
  assert.equal(before.counters.transportAttemptAdmissions, 1);
  const binding = await frontier.getCandidateReceiptBinding(scope, h.runId, completedSeed.candidateId);
  const evidenceScope = await evidenceStore.scopeForAuthenticatedRequest(h.request);
  const legacyReceipt = await evidenceStore.readPrivateRunReceipt(evidenceScope, {
    runId: h.runId, configHash: h.fixture.configHash, candidate: binding.candidate,
  }, h.request);
  assert.equal(legacyReceipt.state, 'complete');
  assert.equal(legacyReceipt.omissionMetadataVersion, 0);
  assert.equal(legacyReceipt.sourceLinkCandidatesOmittedCount, 0,
    'the compatibility reader still exposes its historical zero default');
  assert.ok(legacyReceipt.limitations.includes(h.fixture.legacyLimitation));
  const legacyReceiptRow = h.readLegacyReceiptRows()[0];
  assert.ok(legacyReceiptRow.sealed.byteLength > 0);

  const replay = await h.run(frontier, evidenceStore);
  assert.equal(replay.status, 'draft', JSON.stringify(replay));
  assert.equal(replay.linkCandidates.length, 0);
  assert.equal(replay.progress.sourceLinkCandidateOmittedCount, null,
    'the old reader default cannot turn an unquantified positive marker into exact zero');
  assert.equal(replay.progress.sourceLinkCandidateOmittedCountLowerBound, 2,
    'the old positive marker proves at least one and the new receipt contributes one exact omission');
  assert.equal(replay.progress.sourceLinkCandidateOmittedCountComplete, false);
  assert.ok(replay.limitations.includes(h.fixture.legacyLimitation));
  assert.equal(JSON.stringify(replay).includes('synthetic-canary'), false,
    'the rejected canonical URL remains absent from the projection');
  assert.equal(requests.count, 1, 'only the queued new receipt dispatches after replay');
  const after = await frontier.getSnapshot(scope, h.runId);
  assert.equal(after.candidates.filter((candidate) => candidate.seed && candidate.state === 'completed').length, 2);
  assert.equal(after.counters.transportAttemptAdmissions, 2);
  const rowsAfterReplay = h.readLegacyReceiptRows();
  assert.equal(rowsAfterReplay.length, 2, 'replay adds one modern receipt for the queued seed');
  assert.deepEqual(rowsAfterReplay.find((row) => row.payloadHash === legacyReceiptRow.payloadHash), legacyReceiptRow,
    'mixed-version replay retains the old authenticated ciphertext row byte-for-byte');
  frontier.close();
  frontier = h.openFrontier();
  evidenceStore = h.openEvidenceStore();
  const secondReplay = await h.run(frontier, evidenceStore);
  assert.equal(secondReplay.status, 'draft', JSON.stringify(secondReplay));
  assert.equal(secondReplay.progress.sourceLinkCandidateOmittedCount, null);
  assert.equal(secondReplay.progress.sourceLinkCandidateOmittedCountLowerBound, 2);
  assert.equal(secondReplay.progress.sourceLinkCandidateOmittedCountComplete, false);
  assert.equal(requests.count, 1, 'another restart keeps the mixed-version aggregate without redispatch');
  assert.deepEqual(h.readLegacyReceiptRows().find((row) => row.payloadHash === legacyReceiptRow.payloadHash), legacyReceiptRow);
});

test('completed legacy recovery hashes noncanonical URL spellings, labels, and multiple source references exactly', async (t) => {
  let requestCount = 0;
  const suppliedUrl = 'https://LINKS.example.org:443/a/../a-first';
  const canonicalUrl = new URL(suppliedUrl).href;
  const label = 'duplicate canonical and OpenGraph source';
  const body = Buffer.from(eventHtml().toString('utf8').replace('<!doctype html>',
    `<!doctype html><link rel="canonical" href="${suppliedUrl}">`
      + `<meta property="og:url" content="${suppliedUrl}">`));
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, body);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-legacy-payload-hash-canonicalization';
  const seeds = [{ url: sourceUrl('/legacy-payload-hash') }];
  const limits = {
    maxDepth: 0, maxTransportAttemptAdmissions: 1, maxInFlightLeases: 4,
    durationMs: 30_000, maxSuggestionsPerCompletion: 1,
  };
  let mergedLegacySuggestion;
  let wrappedSuggestionCount;
  const observedStore = Object.create(null);
  for (const method of [
    'scopeForAuthenticatedRequest', 'appendFact', 'ingestDerivedPdfEvidence', 'lookupEvidence', 'lookupFact',
    'materializeSelected', 'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
    'ingestEvidence', 'ingestAssetSourceEvidence',
  ]) observedStore[method] = h.evidenceStore[method].bind(h.evidenceStore);
  observedStore.finalizePrivateRunReceipt = async (scope, input, authenticatedRequest, signal) => {
    wrappedSuggestionCount = input.completion.suggestions.length;
    assert.equal(input.completion.suggestions.length, 1,
      'the source composer deduplicates canonical and OpenGraph links by normalized URL');
    assert.equal(input.completion.suggestions[0].url, canonicalUrl);
    const materialized = await h.evidenceStore.materializeSelected(scope, {
      evidence: input.selection.evidence,
      facts: [],
    }, authenticatedRequest);
    const sourceEvidence = materialized.evidence.find((item) =>
      item.metadata.evidenceId === input.completion.suggestions[0].sourceRefs[0].evidenceId);
    assert.ok(sourceEvidence, 'the selected suggestion is bound to retained source evidence');
    const urlBytes = Buffer.from(suppliedUrl, 'utf8');
    const urlOffsets = [];
    for (let offset = body.indexOf(urlBytes); offset >= 0; offset = body.indexOf(urlBytes, offset + 1)) {
      urlOffsets.push(offset);
    }
    assert.equal(urlOffsets.length, 2, 'the fixture has canonical and OpenGraph URL occurrences');
    const positionsByOffset = new Map(sourceEvidence.positions
      .filter((position) => position.locator.kind === 'text-range'
        && urlOffsets.includes(position.locator.startByte)
        && position.locator.endByte - position.locator.startByte === urlBytes.length)
      .map((position) => [position.locator.startByte, position]));
    assert.equal(positionsByOffset.size, 2, 'both source occurrences were retained as validated positions');
    const sourceRefs = urlOffsets.map((offset, index) => {
      const position = positionsByOffset.get(offset);
      assert.ok(position);
      assert.equal(position.contentHash, createHash('sha256').update(urlBytes).digest('hex'));
      assert.deepEqual(body.subarray(position.locator.startByte, position.locator.endByte), urlBytes);
      return {
        evidenceId: sourceEvidence.metadata.evidenceId,
        contentHash: sourceEvidence.metadata.contentHash,
        locator: position.locator,
        field: index === 0 ? 'canonical.url' : 'openGraph.url',
        value: suppliedUrl,
      };
    }).sort((left, right) => JSON.stringify(left) < JSON.stringify(right) ? -1
      : JSON.stringify(left) > JSON.stringify(right) ? 1 : 0);
    mergedLegacySuggestion = { url: suppliedUrl, label, sourceRefs };
    const legacyCompletion = { ...input.completion, suggestions: [mergedLegacySuggestion] };
    delete legacyCompletion.truncatedCount;
    delete legacyCompletion.omittedSuggestions;
    delete legacyCompletion.sourceLinkCandidatesOmittedCount;
    return h.evidenceStore.finalizePrivateRunReceipt(scope, {
      ...input,
      completion: legacyCompletion,
    }, authenticatedRequest, signal);
  };
  let interruptAfterReceipt = true;
  const interruptedFrontier = frontierWithMethodOverrides(h.frontier, {
    completeCandidate: async (scope, requestedRunId, completion, signal) => {
      if (interruptAfterReceipt) {
        interruptAfterReceipt = false;
        throw new Error('simulated interruption after legacy-format receipt finalization');
      }
      return h.frontier.completeCandidate(scope, requestedRunId, completion, signal);
    },
  });
  const interrupted = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: interruptedFrontier, store: observedStore,
  }));
  assert.equal(interrupted.status, 'incomplete');
  assert.equal(requestCount, 1);
  assert.equal(wrappedSuggestionCount, 1, JSON.stringify(interrupted));
  assert.ok(mergedLegacySuggestion);

  let frontier = h.openFrontier();
  let evidenceStore = createEvidenceStore(h.evidenceConfig);
  let scope = await frontier.scopeForAuthenticatedRequest(request());
  let snapshot = await frontier.getSnapshot(scope, runId);
  const parent = snapshot.candidates.find((candidate) => candidate.seed);
  const binding = await frontier.getCandidateReceiptBinding(scope, runId, parent.candidateId);
  const configHash = createHash('sha256').update(JSON.stringify({ runId, seeds, limits })).digest('hex');
  let evidenceScope = await evidenceStore.scopeForAuthenticatedRequest(request());
  const legacyReceipt = await evidenceStore.readPrivateRunReceipt(evidenceScope, {
    runId, configHash, candidate: binding.candidate,
  }, request());
  assert.equal(legacyReceipt.omissionMetadataVersion, 0);
  assert.equal(legacyReceipt.suggestions[0].url, suppliedUrl);
  assert.equal(legacyReceipt.suggestions[0].label, label);
  assert.equal(JSON.stringify(legacyReceipt.suggestions[0].sourceRefs), JSON.stringify(mergedLegacySuggestion.sourceRefs));

  const recovered = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier, store: evidenceStore,
  }));
  assert.equal(recovered.status, 'draft', JSON.stringify(recovered));
  assert.equal(requestCount, 1, 'the persisted receipt recovers without a second dispatch');
  assert.equal(recovered.linkCandidates[0].url, canonicalUrl);
  assert.equal(recovered.linkCandidates[0].sourceRefs.length, 2);
  const linkedBinding = await frontier.getCandidateReceiptBinding(scope, runId, parent.candidateId);
  assert.equal(linkedBinding.completion.payloadHash, createHash('sha256').update(JSON.stringify({
    outcome: 'links_observed',
    suggestions: [{
      suppliedUrl,
      canonicalUrl,
      label,
      sourceRefs: mergedLegacySuggestion.sourceRefs,
    }],
    truncatedCount: 0,
  })).digest('hex'), 'the test computes the same exact canonical payload committed by the frontier');

  frontier.close();
  frontier = h.openFrontier();
  evidenceStore = createEvidenceStore(h.evidenceConfig);
  scope = await frontier.scopeForAuthenticatedRequest(request());
  snapshot = await frontier.getSnapshot(scope, runId);
  const reopenedParent = snapshot.candidates.find((candidate) => candidate.seed);
  const replayed = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier, store: evidenceStore,
  }));
  assert.equal(replayed.status, 'draft', JSON.stringify(replayed));
  assert.equal(replayed.linkCandidates[0].url, canonicalUrl);
  assert.equal(replayed.linkCandidates[0].sourceRefs.length, 2);
  assert.equal(requestCount, 1, 'completed legacy payload verification remains dispatch-free after another restart');
  assert.equal(reopenedParent.state, 'completed');
});

for (const observationOutcome of ['failed', null]) {
  test(`completed metadata-v1 receipt rejects an extra link observation with outcome ${observationOutcome ?? 'null'}`, async (t) => {
    let requestCount = 0;
    const seedPath = `/metadata-v1-extra-${observationOutcome ?? 'null'}`;
    const targetUrl = sourceUrl(`${seedPath}/linked`);
    const server = await startFixture((requestValue, response) => {
      requestCount += 1;
      const body = requestValue.url === seedPath
        ? eventHtmlWithCanonicalLinks([targetUrl]) : eventHtml();
      respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, body);
    });
    t.after(() => server.close());
    const h = await harness(t);
    const runId = `private-v1-extra-${observationOutcome ?? 'null'}`;
    const seeds = [{ url: sourceUrl(seedPath) }];
    const limits = { maxDepth: 1, maxTransportAttemptAdmissions: 2 };
    const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
    assert.equal(first.status, 'draft', JSON.stringify(first));
    const snapshot = await h.frontier.getSnapshot(h.scope, runId);
    const parent = snapshot.candidates.find((candidate) => candidate.seed);
    const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
    insertContradictoryLinkObservation({
      databasePath: path.join(h.frontierDirectory, tenantHash, 'frontier.sqlite'),
      tenantHash,
      runId,
      parentCandidateId: parent.candidateId,
      outcome: observationOutcome,
    });

    const reopenedFrontier = h.openFrontier();
    const reopenedStore = createEvidenceStore(h.evidenceConfig);
    const replay = await runPrivateRetrieval(h.makeInput({
      runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
    }));
    assert.equal(replay.status, 'incomplete', JSON.stringify(replay));
    assert.equal(replay.draft, null);
    assert.ok(replay.limitations.includes('private_receipt_mismatch'));
    assert.equal(requestCount, 2, 'the corrupted completion is withheld without another transport request');
  });
}

for (const observationOutcome of ['failed', null]) {
test(`concurrent completion rejects an extra parent observation with outcome ${observationOutcome ?? 'null'}`, async (t) => {
  let requestCount = 0;
  const acceptedUrl = 'https://links.example.org/a-first';
  const omittedUrl = 'https://links.example.org/z-last';
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' },
      eventHtmlWithCanonicalLinks([acceptedUrl, omittedUrl]));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-concurrent-completion-extra-observation';
  const seeds = [{ url: sourceUrl('/concurrent-extra-observation') }];
  const limits = {
    maxDepth: 1, maxTransportAttemptAdmissions: 1, maxInFlightLeases: 4,
    durationMs: 30_000, maxSuggestionsPerCompletion: 1,
  };
  let interruptAfterReceipt = true;
  const interruptedFrontier = frontierWithMethodOverrides(h.frontier, {
    completeCandidate: async (...args) => {
      if (interruptAfterReceipt) {
        interruptAfterReceipt = false;
        throw new Error('simulated receipt/frontier interruption');
      }
      return h.frontier.completeCandidate(...args);
    },
  });
  const interrupted = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: interruptedFrontier,
  }));
  assert.equal(interrupted.status, 'incomplete');
  assert.equal(requestCount, 1);

  const reopenedFrontier = h.openFrontier();
  const reopenedStore = createEvidenceStore(h.evidenceConfig);
  let simulatedConcurrentCompletion = false;
  const interleavedFrontier = frontierWithMethodOverrides(reopenedFrontier, {
    claimNext: async (scope, requestedRunId, claimInput, signal) => {
      if (!simulatedConcurrentCompletion) {
        simulatedConcurrentCompletion = true;
        const snapshot = await reopenedFrontier.getSnapshot(scope, requestedRunId, signal);
        const parent = snapshot.candidates.find((candidate) => candidate.seed);
        const binding = await reopenedFrontier.getCandidateReceiptBinding(scope, requestedRunId,
          parent.candidateId, signal);
        const evidenceScope = await reopenedStore.scopeForAuthenticatedRequest(request());
        const configHash = createHash('sha256').update(JSON.stringify({ runId, seeds, limits })).digest('hex');
        const receipt = await reopenedStore.readPrivateRunReceipt(evidenceScope, {
          runId, configHash, candidate: binding.candidate,
        }, request(), signal);
        assert.equal(receipt.state, 'complete');
        await reopenedFrontier.completeCandidate(scope, requestedRunId, {
          leaseToken: binding.claim.leaseToken,
          completionKey: receipt.completionKey,
          outcome: receipt.outcome,
          suggestions: receipt.suggestions,
          truncatedCount: receipt.truncatedCount,
        }, signal);
        const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
        insertContradictoryLinkObservation({
          databasePath: path.join(h.frontierDirectory, tenantHash, 'frontier.sqlite'),
          tenantHash,
          runId,
          parentCandidateId: parent.candidateId,
          outcome: observationOutcome,
        });
      }
      return reopenedFrontier.claimNext(scope, requestedRunId, claimInput, signal);
    },
  });
  const replay = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: interleavedFrontier, store: reopenedStore,
  }));
  assert.equal(simulatedConcurrentCompletion, true);
  assert.equal(replay.status, 'incomplete', JSON.stringify(replay));
  assert.equal(replay.draft, null);
  assert.ok(replay.limitations.includes('private_receipt_completion_mismatch'), JSON.stringify(replay));
  assert.equal(requestCount, 1, 'the concurrent receipt repair remains dispatch-free');
});
}

test('a queued link child keeps provenance from its verified completed parent across restart', async (t) => {
  let requestCount = 0;
  const targetUrl = 'https://links.example.org/verified-child';
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtmlWithCanonicalLinks([targetUrl]));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-verified-parent-queued-child';
  const seeds = [{ url: sourceUrl('/verified-parent') }];
  const limits = { maxDepth: 1, maxTransportAttemptAdmissions: 1, maxSuggestionsPerCompletion: 1 };
  const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
  assert.equal(first.status, 'draft', JSON.stringify(first));
  assert.equal(requestCount, 1);
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  const linkObservation = snapshot.observations.find((item) => item.kind === 'link');
  assert.ok(linkObservation);
  const parent = snapshot.candidates.find((item) => item.candidateId === linkObservation.parentCandidateId);
  const child = snapshot.candidates.find((item) => item.candidateId === linkObservation.targetCandidateId);
  assert.equal(parent.state, 'completed');
  assert.equal(child.state, 'queued');
  assert.deepEqual(child.sourceRefs, linkObservation.sourceRefs);
  assert.equal(first.linkCandidates.find((item) => item.candidateId === child.candidateId).sourceRefs[0].value, targetUrl);

  const reopenedFrontier = h.openFrontier();
  const reopenedStore = createEvidenceStore(h.evidenceConfig);
  const replay = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
  }));
  assert.equal(replay.status, 'draft', JSON.stringify(replay));
  assert.equal(requestCount, 1, 'verified queued-child provenance is replayed without another request');
  assert.deepEqual(replay.linkCandidates.find((item) => item.candidateId === child.candidateId).sourceRefs, child.sourceRefs);
});

test('repeated out-of-depth links retain both verified parent references across restart', async (t) => {
  let requestCount = 0;
  const targetUrl = 'https://links.example.org/repeated-depth-limit-child';
  const requestedPaths = [];
  const server = await startFixture((requestValue, response) => {
    requestCount += 1;
    requestedPaths.push(requestValue.url);
    const body = Buffer.concat([
      eventHtmlWithCanonicalLinks([targetUrl]),
      Buffer.from(`<!-- ${requestValue.url} -->`),
    ]);
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, body);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-repeated-depth-limit-parents';
  const seeds = [
    { url: sourceUrl('/depth-limit-seed-a') },
    { url: sourceUrl('/depth-limit-seed-b') },
  ];
  const limits = {
    maxDepth: 0,
    maxTransportAttemptAdmissions: 2,
    maxInFlightLeases: 1,
    maxSuggestionsPerCompletion: 1,
  };
  const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
  assert.equal(first.status, 'draft', JSON.stringify(first));
  assert.equal(requestCount, 2, 'only the two configured seeds are fetched');
  assert.deepEqual(requestedPaths.sort(), ['/depth-limit-seed-a', '/depth-limit-seed-b']);
  assert.equal(first.progress.transportAttemptAdmissions, 2);
  const firstCandidate = first.linkCandidates.find((candidate) => candidate.url === targetUrl);
  assert.ok(firstCandidate, `the out-of-depth target remains visible as bounded frontier evidence: ${JSON.stringify(first)}`);
  assert.equal(firstCandidate.depth, 1);
  assert.deepEqual(firstCandidate.sourceRefs.map((reference) => reference.value), [targetUrl, targetUrl]);
  assert.equal(new Set(firstCandidate.sourceRefs.map((reference) => reference.evidenceId)).size, 2,
    'each completed seed contributes its independently retained source position');

  const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
  const evidencePath = path.join(h.evidenceConfig.directory, tenantHash, 'evidence.sqlite');
  const immutableReceiptRows = readPrivateReceiptRows(evidencePath, tenantHash);
  const transportBefore = await h.frontier.getTransportProgress(h.scope, runId);
  const firstSnapshot = await h.frontier.getSnapshot(h.scope, runId);
  const firstLinkObservations = firstSnapshot.observations.filter((observation) =>
    observation.kind === 'link' && observation.canonicalUrl === targetUrl);
  assert.equal(firstLinkObservations.length, 2);
  assert.deepEqual(firstLinkObservations.map((observation) => observation.disposition), ['depth_limit', 'depth_limit']);
  assert.equal(new Set(firstLinkObservations.map((observation) => observation.targetCandidateId)).size, 1);
  assert.deepEqual(firstLinkObservations.map((observation) => observation.sourceRefs.length), [1, 1]);

  h.frontier.close();
  const reopenedFrontier = h.openFrontier();
  const reopenedStore = createEvidenceStore(h.evidenceConfig);
  const replay = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
  }));
  assert.equal(replay.status, 'draft', JSON.stringify(replay));
  assert.equal(replay.completeness, 'incomplete');
  assert.equal(requestCount, 2, 'restart reuses both completed seed receipts and never fetches the child');
  assert.deepEqual(replay.linkCandidates.find((candidate) => candidate.url === targetUrl).sourceRefs,
    firstCandidate.sourceRefs, 'both parent references survive identical bounded replay');
  assert.deepEqual(readPrivateReceiptRows(evidencePath, tenantHash), immutableReceiptRows,
    'restart does not rewrite either authenticated receipt');
  const reopenedScope = await reopenedFrontier.scopeForAuthenticatedRequest(request());
  assert.deepEqual(await reopenedFrontier.getTransportProgress(reopenedScope, runId), transportBefore,
    'restart preserves transport counters and settled bytes');
});

test('receipt recovery accepts a claim-depth parent link at its later shallower best depth', async (t) => {
  let requestCount = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-claim-depth-shallower-rediscovery';
  const firstSeedUrl = sourceUrl('/a-r8-root');
  const laterSeedUrl = sourceUrl('/z-r8-late-parent');
  const intermediateUrl = new URL(sourceUrl('/r8-intermediate')).href;
  const targetUrl = new URL(sourceUrl('/r8-shallower-target')).href;
  const childUrl = new URL(sourceUrl('/r8-shallower-edge-child')).href;
  const seeds = [{ url: firstSeedUrl }, { url: laterSeedUrl }];
  const limits = {
    maxDepth: 2,
    maxTransportAttemptAdmissions: 4,
    maxInFlightLeases: 2,
    durationMs: 30_000,
    maxSuggestionsPerCompletion: 1,
  };
  const configHash = createHash('sha256').update(JSON.stringify({ runId, seeds, limits })).digest('hex');
  const scope = await h.frontier.scopeForAuthenticatedRequest(request());
  const evidenceScope = await h.evidenceStore.scopeForAuthenticatedRequest(request());
  await h.frontier.createRun(scope, { runId, seeds, limits });

  const evidenceText = `${intermediateUrl}\n${targetUrl}\n${childUrl}\n`;
  const intermediateStart = 0;
  const targetStart = Buffer.byteLength(`${intermediateUrl}\n`, 'utf8');
  const childStart = targetStart + Buffer.byteLength(`${targetUrl}\n`, 'utf8');
  const evidence = await h.evidenceStore.ingestEvidence(evidenceScope, {
    sourceUrl: new URL(sourceUrl('/r8-synthetic-link-evidence')).href,
    canonicalUrl: new URL(sourceUrl('/r8-synthetic-link-evidence')).href,
    redirectChain: [],
    content: Buffer.from(evidenceText, 'utf8'),
    contentType: 'text/plain; charset=utf-8',
    retrievedAt: '2026-10-11T12:00:00.000Z',
    sourceKind: 'external',
    positions: [
      { locator: { kind: 'text-range', startByte: intermediateStart, endByte: Buffer.byteLength(intermediateUrl, 'utf8') },
        content: intermediateUrl },
      { locator: { kind: 'text-range', startByte: targetStart, endByte: targetStart + Buffer.byteLength(targetUrl, 'utf8') },
        content: targetUrl },
      { locator: { kind: 'text-range', startByte: childStart, endByte: childStart + Buffer.byteLength(childUrl, 'utf8') },
        content: childUrl },
    ],
    retentionHandle: h.createRetention(),
  });
  const evidenceHandle = await h.evidenceStore.lookupEvidence(evidenceScope, evidence.metadata.evidenceId);
  const referenceFor = (url, startByte) => ({
    evidenceId: evidence.metadata.evidenceId,
    contentHash: evidence.metadata.contentHash,
    locator: { kind: 'text-range', startByte, endByte: startByte + Buffer.byteLength(url, 'utf8') },
    field: 'link.href',
    value: url,
  });
  const intermediateRef = referenceFor(intermediateUrl, intermediateStart);
  const targetRef = referenceFor(targetUrl, targetStart);
  const childRef = referenceFor(childUrl, childStart);

  let completionSerial = 0;
  const writeReceipt = async (claim, outcome, suggestions) => {
    const binding = await h.frontier.getCandidateReceiptBinding(scope, runId, claim.candidate.candidateId);
    assert.equal(binding.claim.state, 'leased');
    const attemptKey = `r8-attempt-${++completionSerial}`;
    const admission = await h.frontier.admitTransportHop(scope, runId, {
      leaseToken: binding.claim.leaseToken,
      attemptKey,
      kind: 'initial',
      url: binding.candidate.suppliedUrl,
    });
    assert.equal(admission.state, 'admitted');
    await h.frontier.settleTransportHopKnownZero(scope, runId, {
      leaseToken: binding.claim.leaseToken, attemptKey,
    });
    const completionKey = `r8-completion-${completionSerial}`;
    const claimBinding = {
      claimKey: binding.claim.claimKey,
      workerId: binding.claim.workerId,
      leaseToken: binding.claim.leaseToken,
    };
    const receiptBinding = { runId, configHash, candidate: binding.candidate, claim: claimBinding };
    assert.deepEqual(await h.evidenceStore.beginPrivateRunReceipt(evidenceScope, receiptBinding, request()),
      { state: 'pending', created: true });
    const completion = {
      completionKey,
      outcome,
      suggestions,
      truncatedCount: 0,
      omittedSuggestions: [],
      sourceLinkCandidatesOmittedCount: 0,
      limitations: [],
      identity: { entityCandidates: [], occurrenceCandidates: [], transitionLinks: [], unresolvedTransitions: [] },
    };
    await h.evidenceStore.finalizePrivateRunReceipt(evidenceScope, {
      ...receiptBinding,
      completion,
      selection: { evidence: suggestions.length > 0 ? [evidenceHandle] : [], facts: [] },
    }, request());
    return { binding, completionKey, outcome, suggestions };
  };
  const complete = async (claim, outcome, suggestions) => {
    const written = await writeReceipt(claim, outcome, suggestions);
    await h.frontier.completeCandidate(scope, runId, {
      leaseToken: written.binding.claim.leaseToken,
      completionKey: written.completionKey,
      outcome: written.outcome,
      suggestions: written.suggestions,
      truncatedCount: 0,
    });
    return written;
  };
  const claim = async (workerId) => {
    const result = await h.frontier.claimNext(scope, runId, { workerId, claimKey: `${workerId}-claim` });
    assert.equal(result.state, 'claimed', JSON.stringify(result));
    return result;
  };

  const firstSeed = await claim('r8-first-seed');
  assert.equal(firstSeed.candidate.canonicalUrl, new URL(firstSeedUrl).href);
  await complete(firstSeed, 'links_observed', [{ url: intermediateUrl, sourceRefs: [intermediateRef] }]);

  // Hold the second seed claim while the first branch creates and claims the target at depth 2.
  const laterSeed = await claim('r8-later-seed');
  assert.equal(laterSeed.candidate.canonicalUrl, new URL(laterSeedUrl).href);
  const intermediate = await claim('r8-intermediate');
  assert.equal(intermediate.candidate.canonicalUrl, new URL(intermediateUrl).href);
  await complete(intermediate, 'links_observed', [{ url: targetUrl, sourceRefs: [targetRef] }]);
  const target = await claim('r8-target');
  assert.equal(target.candidate.canonicalUrl, new URL(targetUrl).href);
  assert.equal(target.candidate.depth, 2);
  const targetBindingBeforeRediscovery = await h.frontier.getCandidateReceiptBinding(scope, runId,
    target.candidate.candidateId);
  assert.equal(targetBindingBeforeRediscovery.candidate.depth, 2);

  // This completed seed receipt is finalized after the target's claim prefix and lowers its current best depth.
  await complete(laterSeed, 'links_observed', [{ url: targetUrl, sourceRefs: [targetRef] }]);
  const afterRediscovery = await h.frontier.getSnapshot(scope, runId);
  assert.equal(afterRediscovery.candidates.find((candidate) => candidate.candidateId === target.candidate.candidateId).depth, 1);
  const targetBindingAfterRediscovery = await h.frontier.getCandidateReceiptBinding(scope, runId,
    target.candidate.candidateId);
  assert.equal(targetBindingAfterRediscovery.candidate.depth, 2,
    'the persisted claim prefix remains at depth 2 after the current best depth becomes 1');
  await complete(target, 'links_observed', [{ url: childUrl, sourceRefs: [childRef] }]);
  const beforeReplay = await h.frontier.getSnapshot(scope, runId);
  assert.equal(beforeReplay.candidates.find((candidate) => candidate.canonicalUrl === new URL(childUrl).href).depth, 2);
  const transportBeforeReplay = await h.frontier.getTransportProgress(scope, runId);

  const replayFrontier = h.openFrontier();
  const replayStore = createEvidenceStore(h.evidenceConfig);
  const replay = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: replayFrontier, store: replayStore,
  }));
  assert.equal(replay.schema, 'ei-private-retrieval-draft/v1', JSON.stringify(replay));
  assert.ok(!replay.limitations.includes('private_receipt_completion_mismatch'), JSON.stringify(replay));
  assert.equal(replay.linkCandidates.find((candidate) => candidate.url === targetUrl).depth, 1);
  const retainedChild = replay.linkCandidates.find((candidate) => candidate.url === childUrl);
  assert.equal(retainedChild.depth, 2,
    'a claim-depth-2 receipt may emit the lawful outgoing edge at current best depth 1 plus one');
  assert.deepEqual(retainedChild.sourceRefs, [childRef]);
  assert.equal(requestCount, 0, 'completed authenticated receipts replay without private transport');
  assert.deepEqual(await replayFrontier.getTransportProgress(await replayFrontier.scopeForAuthenticatedRequest(request()), runId),
    transportBeforeReplay, 'valid shallower rediscovery does not change settled transport counters');
});

test('modern and baseline receipts reject link provenance reassigned to another candidate', async (t) => {
  let requestCount = 0;
  const firstUrl = 'https://links.example.org/a-first';
  const secondUrl = 'https://links.example.org/z-last';
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' },
      eventHtmlWithCanonicalLinks([firstUrl, secondUrl]));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-modern-target-reassignment';
  const seeds = [{ url: sourceUrl('/target-reassignment-parent') }];
  const limits = { maxDepth: 1, maxTransportAttemptAdmissions: 1, maxSuggestionsPerCompletion: 2 };
  const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
  assert.equal(first.status, 'draft', JSON.stringify(first));
  assert.equal(first.linkCandidates.length, 2);
  assert.equal(requestCount, 1);
  const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
  const databasePath = path.join(h.frontierDirectory, tenantHash, 'frontier.sqlite');
  const evidencePath = path.join(h.evidenceConfig.directory, tenantHash, 'evidence.sqlite');
  const immutableReceiptRows = readPrivateReceiptRows(evidencePath, tenantHash);
  const scope = await h.frontier.scopeForAuthenticatedRequest(request());
  const before = await h.frontier.getSnapshot(scope, runId);
  const firstObservation = before.observations.find((item) => item.kind === 'link' && item.canonicalUrl === firstUrl);
  const secondObservation = before.observations.find((item) => item.kind === 'link' && item.canonicalUrl === secondUrl);
  assert.ok(firstObservation && secondObservation);
  const firstCandidateId = firstObservation.targetCandidateId;
  const secondCandidateId = secondObservation.targetCandidateId;
  assert.notEqual(firstCandidateId, secondCandidateId);
  const transportBefore = await h.frontier.getTransportProgress(scope, runId);

  reassignLinkObservationTarget({ databasePath, tenantHash, runId, canonicalUrl: firstUrl,
    targetCandidateId: secondCandidateId });
  const reassigned = await h.frontier.getSnapshot(scope, runId);
  assert.deepEqual(reassigned.candidates.find((candidate) => candidate.candidateId === firstCandidateId).sourceRefs, [],
    'the original target loses the moved position in the tampered projection');
  assert.equal(reassigned.candidates.find((candidate) => candidate.candidateId === secondCandidateId).sourceRefs.length,
    firstObservation.sourceRefs.length + secondObservation.sourceRefs.length,
    'the other target now receives both source positions');

  h.frontier.close();
  const replayFrontier = h.openFrontier();
  const replayStore = createEvidenceStore(h.evidenceConfig);
  const replay = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: replayFrontier, store: replayStore,
  }));
  assert.equal(replay.status, 'incomplete', JSON.stringify(replay));
  assert.equal(replay.draft, null);
  assert.ok(replay.limitations.includes('private_receipt_completion_mismatch'));
  assert.equal(requestCount, 1, 'rejected modern target association does not redispatch the parent or child');
  assert.deepEqual(readPrivateReceiptRows(evidencePath, tenantHash), immutableReceiptRows,
    'the target association failure leaves authenticated receipt bytes unchanged');
  const replayScope = await replayFrontier.scopeForAuthenticatedRequest(request());
  assert.deepEqual(await replayFrontier.getTransportProgress(replayScope, runId), transportBefore,
    'the target association failure leaves transport accounting unchanged');

  const legacyRequests = { count: 0 };
  const legacy = await legacyOvercapWorkspace(t, legacyRequests);
  let legacyFrontier = legacy.openFrontier();
  let legacyStore = legacy.openEvidenceStore();
  const legacyFirst = await legacy.run(legacyFrontier, legacyStore);
  assert.equal(legacyFirst.status, 'draft', JSON.stringify(legacyFirst));
  assert.equal(legacyRequests.count, 0);
  const legacyRows = legacy.readLegacyReceiptRows();
  const legacyScope = await legacyFrontier.scopeForAuthenticatedRequest(legacy.request);
  const legacySnapshot = await legacyFrontier.getSnapshot(legacyScope, legacy.runId);
  const legacyLink = legacySnapshot.observations.find((item) => item.kind === 'link');
  const legacySeed = legacySnapshot.candidates.find((candidate) => candidate.seed);
  assert.ok(legacyLink && legacySeed);
  const legacyTransport = await legacyFrontier.getTransportProgress(legacyScope, legacy.runId);
  const legacyDatabasePath = path.join(legacy.frontierDirectory, legacy.fixture.tenantHash, 'frontier.sqlite');
  reassignLinkObservationTarget({ databasePath: legacyDatabasePath, tenantHash: legacy.fixture.tenantHash,
    runId: legacy.runId, canonicalUrl: legacyLink.canonicalUrl, targetCandidateId: legacySeed.candidateId });
  const legacyTampered = await legacyFrontier.getSnapshot(legacyScope, legacy.runId);
  assert.ok(legacyTampered.candidates.find((candidate) => candidate.seed).sourceRefs.length > 0,
    'the invalid link position is now incorrectly aggregated into the existing seed row');

  legacyFrontier.close();
  legacyFrontier = legacy.openFrontier();
  legacyStore = legacy.openEvidenceStore();
  const legacyReplay = await legacy.run(legacyFrontier, legacyStore);
  assert.equal(legacyReplay.status, 'incomplete', JSON.stringify(legacyReplay));
  assert.equal(legacyReplay.draft, null);
  assert.ok(legacyReplay.limitations.includes('legacy_receipt_fanout_recovery_unverified'));
  assert.ok(legacyReplay.limitations.includes('private_receipt_completion_mismatch'));
  assert.equal(legacyRequests.count, 0, 'rejected legacy target association does not redispatch');
  assert.deepEqual(legacy.readLegacyReceiptRows(), legacyRows,
    'the legacy target association failure does not rewrite the old encrypted receipt');
  const legacyReplayScope = await legacyFrontier.scopeForAuthenticatedRequest(legacy.request);
  assert.deepEqual(await legacyFrontier.getTransportProgress(legacyReplayScope, legacy.runId), legacyTransport);
});

test('duplicate seed observations bind to the configured seed multiset and references', async (t) => {
  let requestCount = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-duplicate-seed-observation-proof';
  const seedUrl = sourceUrl('/duplicate-seed-proof');
  const seed = {
    url: seedUrl,
    sourceRefs: [{
      evidenceId: '123e4567-e89b-42d3-a456-426614174000',
      contentHash: createHash('sha256').update('seed-input-evidence').digest('hex'),
      locator: { kind: 'text-range', startByte: 0, endByte: 1 },
      field: 'seed_url',
      value: seedUrl,
    }],
  };
  const seeds = [seed, seed];
  const limits = { maxDepth: 0, maxTransportAttemptAdmissions: 1 };
  const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
  const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
  const debugEvidencePath = path.join(h.evidenceConfig.directory, tenantHash, 'evidence.sqlite');
  assert.equal(first.status, 'draft', JSON.stringify({ first, snapshot: await h.frontier.getSnapshot(h.scope, runId),
    requests: h.requests.size, receipts: readPrivateReceiptRows(debugEvidencePath, tenantHash) }));
  assert.equal(requestCount, 1, 'duplicate seed inputs retain one canonical candidate and one request');
  const evidencePath = path.join(h.evidenceConfig.directory, tenantHash, 'evidence.sqlite');
  const immutableReceiptRows = readPrivateReceiptRows(evidencePath, tenantHash);
  const scope = await h.frontier.scopeForAuthenticatedRequest(request());
  const before = await h.frontier.getSnapshot(scope, runId);
  const seedObservations = before.observations.filter((item) => item.kind === 'seed');
  assert.equal(seedObservations.length, 2, 'both configured duplicate seed observations are retained');
  assert.deepEqual(seedObservations[0].sourceRefs, seedObservations[1].sourceRefs);
  assert.equal(before.candidates[0].sourceRefs.length, 1);
  const transportBefore = await h.frontier.getTransportProgress(scope, runId);
  const frontierPath = path.join(h.frontierDirectory, tenantHash, 'frontier.sqlite');
  const database = new DatabaseSync(frontierPath);
  try {
    withPrivilegedFrontierFixtureMutation(database, () => {
      const row = database.prepare(`SELECT sequence FROM frontier_observations
        WHERE tenant_hash = ? AND run_id = ? AND kind = 'seed' ORDER BY sequence LIMIT 1`).get(tenantHash, runId);
      assert.ok(row);
      database.prepare(`UPDATE frontier_observations SET source_refs_json = '[]'
        WHERE tenant_hash = ? AND run_id = ? AND sequence = ?`).run(tenantHash, runId, row.sequence);
    });
  } finally {
    database.close();
  }
  const tampered = await h.frontier.getSnapshot(scope, runId);
  assert.equal(tampered.candidates[0].sourceRefs.length, 1,
    'deduplicated candidate provenance alone still looks unchanged after one duplicate is altered');
  assert.equal(tampered.observations.filter((item) => item.kind === 'seed')[0].sourceRefs.length, 0);

  h.frontier.close();
  const replayFrontier = h.openFrontier();
  const replay = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: replayFrontier, store: createEvidenceStore(h.evidenceConfig),
  }));
  assert.equal(replay.status, 'incomplete', JSON.stringify(replay));
  assert.equal(replay.draft, null);
  assert.ok(replay.limitations.includes('private_receipt_completion_mismatch'));
  assert.equal(requestCount, 1, 'seed-observation mismatch does not repeat retrieval');
  assert.deepEqual(readPrivateReceiptRows(evidencePath, tenantHash), immutableReceiptRows);
  const replayScope = await replayFrontier.scopeForAuthenticatedRequest(request());
  assert.deepEqual(await replayFrontier.getTransportProgress(replayScope, runId), transportBefore);
});

test('a candidate without any authenticated incoming observation is withheld from projection', async (t) => {
  let requestCount = 0;
  const targetUrl = 'https://links.example.org/orphan-projection-control';
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtmlWithCanonicalLinks([targetUrl]));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-orphan-candidate-projection';
  const seeds = [{ url: sourceUrl('/orphan-control-parent') }];
  const limits = { maxDepth: 1, maxTransportAttemptAdmissions: 1, maxSuggestionsPerCompletion: 1 };
  const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
  assert.equal(first.status, 'draft', JSON.stringify(first));
  assert.equal(first.linkCandidates.length, 1, 'the valid target provides the positive projection control');
  const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
  const evidencePath = path.join(h.evidenceConfig.directory, tenantHash, 'evidence.sqlite');
  const immutableReceiptRows = readPrivateReceiptRows(evidencePath, tenantHash);
  const scope = await h.frontier.scopeForAuthenticatedRequest(request());
  const transportBefore = await h.frontier.getTransportProgress(scope, runId);
  const orphanUrl = 'https://links.example.org/unobserved-candidate-row';
  const candidateId = insertUnobservedCandidate({
    databasePath: path.join(h.frontierDirectory, tenantHash, 'frontier.sqlite'),
    tenantHash, runId, canonicalUrl: orphanUrl,
  });
  const tampered = await h.frontier.getSnapshot(scope, runId);
  assert.deepEqual(tampered.candidates.find((candidate) => candidate.candidateId === candidateId).sourceRefs, []);
  assert.ok(!tampered.observations.some((observation) => observation.targetCandidateId === candidateId));

  h.frontier.close();
  const replayFrontier = h.openFrontier();
  const replay = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: replayFrontier, store: createEvidenceStore(h.evidenceConfig),
  }));
  assert.equal(replay.status, 'incomplete', JSON.stringify(replay));
  assert.equal(replay.draft, null);
  assert.ok(replay.limitations.includes('private_receipt_completion_mismatch'));
  assert.equal(requestCount, 1, 'unsupported candidate rows do not dispatch again');
  assert.deepEqual(readPrivateReceiptRows(evidencePath, tenantHash), immutableReceiptRows);
  const replayScope = await replayFrontier.scopeForAuthenticatedRequest(request());
  assert.deepEqual(await replayFrontier.getTransportProgress(replayScope, runId), transportBefore);
});

test('a candidate depth must equal its earliest authenticated frontier observation', async (t) => {
  let requestCount = 0;
  const targetUrl = 'https://links.example.org/depth-bound-child';
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtmlWithCanonicalLinks([targetUrl]));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-target-depth-bound-to-observations';
  const seeds = [{ url: sourceUrl('/depth-bound-parent') }];
  const limits = { maxDepth: 1, maxTransportAttemptAdmissions: 1, maxSuggestionsPerCompletion: 1 };
  const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
  assert.equal(first.status, 'draft', JSON.stringify(first));
  assert.equal(requestCount, 1);

  const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
  const databasePath = path.join(h.frontierDirectory, tenantHash, 'frontier.sqlite');
  const evidencePath = path.join(h.evidenceConfig.directory, tenantHash, 'evidence.sqlite');
  const immutableReceiptRows = readPrivateReceiptRows(evidencePath, tenantHash);
  const scope = await h.frontier.scopeForAuthenticatedRequest(request());
  const before = await h.frontier.getSnapshot(scope, runId);
  const linkObservation = before.observations.find((item) => item.kind === 'link' && item.canonicalUrl === targetUrl);
  assert.ok(linkObservation);
  const target = before.candidates.find((candidate) => candidate.candidateId === linkObservation.targetCandidateId);
  assert.ok(target);
  assert.equal(target.depth, 1);
  const transportBefore = await h.frontier.getTransportProgress(scope, runId);

  reassignCandidateDepth({ databasePath, tenantHash, runId, candidateId: target.candidateId, depth: 0 });
  const tampered = await h.frontier.getSnapshot(scope, runId);
  assert.equal(tampered.candidates.find((candidate) => candidate.candidateId === target.candidateId).depth, 0);

  h.frontier.close();
  const replayFrontier = h.openFrontier();
  const replayStore = createEvidenceStore(h.evidenceConfig);
  const replay = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: replayFrontier, store: replayStore,
  }));
  assert.equal(replay.status, 'incomplete', JSON.stringify(replay));
  assert.equal(replay.draft, null);
  assert.ok(replay.limitations.includes('private_receipt_completion_mismatch'));
  assert.equal(requestCount, 1, 'rejecting a forged candidate depth never retries private transport');
  assert.deepEqual(readPrivateReceiptRows(evidencePath, tenantHash), immutableReceiptRows,
    'the depth mismatch leaves authenticated receipt bytes unchanged');
  const replayScope = await replayFrontier.scopeForAuthenticatedRequest(request());
  assert.deepEqual(await replayFrontier.getTransportProgress(replayScope, runId), transportBefore);
});

test('restart rejects coordinated child and observation depth inflation beyond the authenticated parent claim', async (t) => {
  let requestCount = 0;
  const targetUrl = 'https://links.example.org/coordinated-depth-child';
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtmlWithCanonicalLinks([targetUrl]));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-coordinated-depth-inflation';
  const seeds = [{ url: sourceUrl('/coordinated-depth-parent') }];
  const limits = { maxDepth: 2, maxTransportAttemptAdmissions: 1, maxSuggestionsPerCompletion: 1 };
  const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
  assert.equal(first.status, 'draft', JSON.stringify(first));
  assert.equal(requestCount, 1);

  const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
  const databasePath = path.join(h.frontierDirectory, tenantHash, 'frontier.sqlite');
  const evidencePath = path.join(h.evidenceConfig.directory, tenantHash, 'evidence.sqlite');
  const immutableReceiptRows = readPrivateReceiptRows(evidencePath, tenantHash);
  const scope = await h.frontier.scopeForAuthenticatedRequest(request());
  const before = await h.frontier.getSnapshot(scope, runId);
  const observation = before.observations.find((item) => item.kind === 'link' && item.canonicalUrl === targetUrl);
  assert.ok(observation);
  const child = before.candidates.find((candidate) => candidate.candidateId === observation.targetCandidateId);
  assert.equal(child.depth, 1);
  assert.equal(child.state, 'queued');
  const transportBefore = await h.frontier.getTransportProgress(scope, runId);

  reassignCandidateAndIncomingLinkDepth({ databasePath, tenantHash, runId, candidateId: child.candidateId, depth: 2 });
  const tampered = await h.frontier.getSnapshot(scope, runId);
  assert.equal(tampered.candidates.find((candidate) => candidate.candidateId === child.candidateId).depth, 2);
  assert.equal(tampered.observations.find((item) => item.sequence === observation.sequence).depth, 2);

  h.frontier.close();
  const reopenedFrontier = h.openFrontier();
  const reopenedStore = createEvidenceStore(h.evidenceConfig);
  const replay = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
  }));
  assert.equal(replay.status, 'incomplete', JSON.stringify(replay));
  assert.equal(replay.draft, null);
  assert.ok(replay.limitations.includes('private_receipt_completion_mismatch'));
  assert.equal(requestCount, 1, 'coordinated depth inflation never dispatches the queued child');
  assert.deepEqual(readPrivateReceiptRows(evidencePath, tenantHash), immutableReceiptRows,
    'recovery leaves the authenticated receipt bytes unchanged');
  const reopenedScope = await reopenedFrontier.scopeForAuthenticatedRequest(request());
  assert.deepEqual(await reopenedFrontier.getTransportProgress(reopenedScope, runId), transportBefore,
    'recovery preserves the settled transport counters and bytes');
});

test('the completion boundary rejects a reassigned target before receipt proof', async (t) => {
  let requestCount = 0;
  const firstUrl = 'https://links.example.org/concurrent-a-first';
  const secondUrl = 'https://links.example.org/concurrent-z-last';
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' },
      eventHtmlWithCanonicalLinks([firstUrl, secondUrl]));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-concurrent-target-reassignment';
  const seeds = [{ url: sourceUrl('/concurrent-target-parent') }];
  const limits = { maxDepth: 1, maxTransportAttemptAdmissions: 1, maxSuggestionsPerCompletion: 2 };
  const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
  const frontierPath = path.join(h.frontierDirectory, tenantHash, 'frontier.sqlite');
  const evidencePath = path.join(h.evidenceConfig.directory, tenantHash, 'evidence.sqlite');
  let targetChanged = false;
  let receiptRowsAtMutation;
  let transportAtMutation;
  const instrumentedFrontier = frontierWithMethodOverrides(h.frontier, {
    completeCandidate: async (...args) => {
      const completed = await h.frontier.completeCandidate(...args);
      if (!targetChanged) {
        const snapshot = await h.frontier.getSnapshot(h.scope, runId);
        const otherTarget = snapshot.candidates.find((candidate) => candidate.canonicalUrl === secondUrl);
        assert.ok(otherTarget);
        reassignLinkObservationTarget({ databasePath: frontierPath, tenantHash, runId,
          canonicalUrl: firstUrl, targetCandidateId: otherTarget.candidateId });
        targetChanged = true;
        receiptRowsAtMutation = readPrivateReceiptRows(evidencePath, tenantHash);
        transportAtMutation = await h.frontier.getTransportProgress(h.scope, runId);
      }
      return completed;
    },
  });
  const result = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: instrumentedFrontier,
  }));
  assert.equal(targetChanged, true, 'the target changes after atomic frontier completion and before receipt proof');
  assert.equal(result.status, 'incomplete', JSON.stringify(result));
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('private_receipt_completion_mismatch'));
  assert.equal(requestCount, 1, 'the concurrent proof rejection never retries transport');
  assert.deepEqual(readPrivateReceiptRows(evidencePath, tenantHash), receiptRowsAtMutation,
    'completion-proof rejection leaves the finalized authenticated receipt unchanged');
  assert.deepEqual(await h.frontier.getTransportProgress(h.scope, runId), transportAtMutation);
});

test('legacy overcap replay rejects a link observation attributed to an unverified queued parent', async (t) => {
  const requests = { count: 0 };
  const h = await legacyOvercapWorkspace(t, requests);
  let frontier = h.openFrontier();
  let evidenceStore = h.openEvidenceStore();
  const first = await h.run(frontier, evidenceStore);
  assert.equal(first.status, 'draft', JSON.stringify(first));
  assert.equal(requests.count, 0);
  const immutableReceiptRows = h.readLegacyReceiptRows();
  assert.equal(immutableReceiptRows.length, 1);
  const scope = await frontier.scopeForAuthenticatedRequest(h.request);
  const snapshot = await frontier.getSnapshot(scope, h.runId);
  const queuedChild = snapshot.candidates.find((candidate) => candidate.depth > 0 && candidate.state === 'queued');
  assert.ok(queuedChild);
  const transportBefore = await frontier.getTransportProgress(scope, h.runId);
  insertUnverifiedQueuedParentLinkObservation({
    databasePath: path.join(h.frontierDirectory, h.fixture.tenantHash, 'frontier.sqlite'),
    tenantHash: h.fixture.tenantHash,
    runId: h.runId,
    queuedCandidateId: queuedChild.candidateId,
    field: 'independent.unproved.legacy.extra',
  });
  const tamperedSnapshot = await frontier.getSnapshot(scope, h.runId);
  assert.ok(tamperedSnapshot.candidates.find((candidate) => candidate.candidateId === queuedChild.candidateId)
    .sourceRefs.some((reference) => reference.field === 'independent.unproved.legacy.extra'));

  frontier.close();
  frontier = h.openFrontier();
  evidenceStore = h.openEvidenceStore();
  const recovered = await h.run(frontier, evidenceStore);
  assert.equal(recovered.status, 'incomplete', JSON.stringify(recovered));
  assert.equal(recovered.draft, null);
  assert.ok(recovered.limitations.includes('private_receipt_completion_mismatch'));
  assert.ok(recovered.limitations.includes('legacy_receipt_fanout_recovery_unverified'));
  assert.equal(requests.count, 0, 'legacy stream rejection does not redispatch the sealed receipt');
  assert.deepEqual(h.readLegacyReceiptRows(), immutableReceiptRows,
    'legacy stream rejection leaves authenticated ciphertext rows unchanged');
  const after = await frontier.getSnapshot(await frontier.scopeForAuthenticatedRequest(h.request), h.runId);
  assert.deepEqual(await frontier.getTransportProgress(await frontier.scopeForAuthenticatedRequest(h.request), h.runId),
    transportBefore, 'legacy stream rejection preserves transport counters and settled bytes');
  assert.equal(after.counters.transportAttemptAdmissions, snapshot.counters.transportAttemptAdmissions);
});

test('the final projection rechecks all verified parents when an outgoing observation disappears after receipt proof', async (t) => {
  let requestCount = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtmlWithCanonicalLinks([
      'https://links.example.org/final-snapshot-child',
    ]));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-final-projection-observation-deletion';
  const seeds = [{ url: sourceUrl('/final-snapshot-parent') }];
  const limits = { maxDepth: 1, maxTransportAttemptAdmissions: 1, maxSuggestionsPerCompletion: 1 };
  let completionFinished = false;
  let receiptReadAfterCompletion = false;
  let proofSnapshotPending = false;
  let proofSnapshotSeen = false;
  let laterSnapshotOmittedLink = false;
  const observedStore = Object.create(null);
  for (const method of [
    'scopeForAuthenticatedRequest', 'appendFact', 'ingestDerivedPdfEvidence', 'lookupEvidence', 'lookupFact',
    'materializeSelected', 'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
    'ingestEvidence', 'ingestAssetSourceEvidence',
  ]) observedStore[method] = h.evidenceStore[method].bind(h.evidenceStore);
  observedStore.readPrivateRunReceipt = async (...args) => {
    const receipt = await h.evidenceStore.readPrivateRunReceipt(...args);
    if (completionFinished && receipt.state === 'complete') receiptReadAfterCompletion = true;
    return receipt;
  };
  const instrumentedFrontier = frontierWithMethodOverrides(h.frontier, {
    completeCandidate: async (...args) => {
      const result = await h.frontier.completeCandidate(...args);
      completionFinished = true;
      return result;
    },
    getCandidateReceiptBinding: async (...args) => {
      if (receiptReadAfterCompletion) {
        receiptReadAfterCompletion = false;
        proofSnapshotPending = true;
      }
      return h.frontier.getCandidateReceiptBinding(...args);
    },
    getSnapshot: async (...args) => {
      const snapshot = await h.frontier.getSnapshot(...args);
      if (proofSnapshotPending) {
        proofSnapshotPending = false;
        proofSnapshotSeen = true;
        return snapshot;
      }
      if (proofSnapshotSeen) {
        laterSnapshotOmittedLink = true;
        return { ...snapshot, observations: snapshot.observations.filter((observation) => observation.kind !== 'link') };
      }
      return snapshot;
    },
  });
  const result = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: instrumentedFrontier, store: observedStore,
  }));
  assert.equal(proofSnapshotSeen, true, 'the authenticated receipt and initial frontier payload were proved first');
  assert.equal(laterSnapshotOmittedLink, true, 'a later snapshot returned to the final gate omits the link observation');
  assert.equal(result.status, 'incomplete', JSON.stringify(result));
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('private_receipt_completion_mismatch'));
  assert.equal(requestCount, 1, 'final proof rejection never retries the completed receipt or fetches its child');
  const actualSnapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(actualSnapshot.observations.filter((observation) => observation.kind === 'link').length, 1,
    'the test withholds the observation only from the final projection snapshot');
});

test('the final projection rejects a changed link target after receipt proof', async (t) => {
  let requestCount = 0;
  const firstUrl = 'https://links.example.org/final-target-a-first';
  const secondUrl = 'https://links.example.org/final-target-z-last';
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' },
      eventHtmlWithCanonicalLinks([firstUrl, secondUrl]));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-final-projection-target-change';
  const seeds = [{ url: sourceUrl('/final-target-parent') }];
  const limits = { maxDepth: 1, maxTransportAttemptAdmissions: 1, maxSuggestionsPerCompletion: 2 };
  let completionFinished = false;
  let receiptReadAfterCompletion = false;
  let proofSnapshotPending = false;
  let proofSnapshotSeen = false;
  let laterSnapshotTargetChanged = false;
  const observedStore = Object.create(null);
  for (const method of [
    'scopeForAuthenticatedRequest', 'appendFact', 'ingestDerivedPdfEvidence', 'lookupEvidence', 'lookupFact',
    'materializeSelected', 'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
    'ingestEvidence', 'ingestAssetSourceEvidence',
  ]) observedStore[method] = h.evidenceStore[method].bind(h.evidenceStore);
  observedStore.readPrivateRunReceipt = async (...args) => {
    const receipt = await h.evidenceStore.readPrivateRunReceipt(...args);
    if (completionFinished && receipt.state === 'complete') receiptReadAfterCompletion = true;
    return receipt;
  };
  const instrumentedFrontier = frontierWithMethodOverrides(h.frontier, {
    completeCandidate: async (...args) => {
      const result = await h.frontier.completeCandidate(...args);
      completionFinished = true;
      return result;
    },
    getCandidateReceiptBinding: async (...args) => {
      if (receiptReadAfterCompletion) {
        receiptReadAfterCompletion = false;
        proofSnapshotPending = true;
      }
      return h.frontier.getCandidateReceiptBinding(...args);
    },
    getSnapshot: async (...args) => {
      const snapshot = await h.frontier.getSnapshot(...args);
      if (proofSnapshotPending) {
        proofSnapshotPending = false;
        proofSnapshotSeen = true;
        return snapshot;
      }
      if (!proofSnapshotSeen) return snapshot;
      const firstObservation = snapshot.observations.find((item) => item.kind === 'link' && item.canonicalUrl === firstUrl);
      const secondObservation = snapshot.observations.find((item) => item.kind === 'link' && item.canonicalUrl === secondUrl);
      assert.ok(firstObservation && secondObservation);
      laterSnapshotTargetChanged = true;
      return {
        ...snapshot,
        observations: snapshot.observations.map((observation) => observation === firstObservation
          ? { ...observation, targetCandidateId: secondObservation.targetCandidateId }
          : observation),
      };
    },
  });
  const result = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: instrumentedFrontier, store: observedStore,
  }));
  assert.equal(proofSnapshotSeen, true, 'the exact receipt and original target association are proved first');
  assert.equal(laterSnapshotTargetChanged, true, 'a later snapshot supplies a different existing target id');
  assert.equal(result.status, 'incomplete', JSON.stringify(result));
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('private_receipt_completion_mismatch'));
  assert.equal(requestCount, 1, 'late projection rejection causes no additional private request');
});

test('the final projection rejects coordinated child and observation depth inflation after receipt proof', async (t) => {
  let requestCount = 0;
  const targetUrl = 'https://links.example.org/final-coordinated-depth-child';
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtmlWithCanonicalLinks([targetUrl]));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-final-coordinated-depth-inflation';
  const seeds = [{ url: sourceUrl('/final-coordinated-depth-parent') }];
  const limits = { maxDepth: 2, maxTransportAttemptAdmissions: 1, maxSuggestionsPerCompletion: 1 };
  let completionFinished = false;
  let receiptReadAfterCompletion = false;
  let proofSnapshotPending = false;
  let proofSnapshotSeen = false;
  let attemptLimitObserved = false;
  let finalDepthTamperingApplied = false;
  const observedStore = Object.create(null);
  for (const method of [
    'scopeForAuthenticatedRequest', 'appendFact', 'ingestDerivedPdfEvidence', 'lookupEvidence', 'lookupFact',
    'materializeSelected', 'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
    'ingestEvidence', 'ingestAssetSourceEvidence',
  ]) observedStore[method] = h.evidenceStore[method].bind(h.evidenceStore);
  observedStore.readPrivateRunReceipt = async (...args) => {
    const receipt = await h.evidenceStore.readPrivateRunReceipt(...args);
    if (completionFinished && receipt.state === 'complete') receiptReadAfterCompletion = true;
    return receipt;
  };
  const instrumentedFrontier = frontierWithMethodOverrides(h.frontier, {
    completeCandidate: async (...args) => {
      const result = await h.frontier.completeCandidate(...args);
      completionFinished = true;
      return result;
    },
    getCandidateReceiptBinding: async (...args) => {
      if (receiptReadAfterCompletion) {
        receiptReadAfterCompletion = false;
        proofSnapshotPending = true;
      }
      return h.frontier.getCandidateReceiptBinding(...args);
    },
    claimNext: async (...args) => {
      const result = await h.frontier.claimNext(...args);
      if (result.state === 'stopped' && result.reason === 'attempt_limit') attemptLimitObserved = true;
      return result;
    },
    getSnapshot: async (...args) => {
      const snapshot = await h.frontier.getSnapshot(...args);
      if (proofSnapshotPending) {
        proofSnapshotPending = false;
        proofSnapshotSeen = true;
        return snapshot;
      }
      if (!attemptLimitObserved || !proofSnapshotSeen) return snapshot;
      const link = snapshot.observations.find((item) => item.kind === 'link' && item.canonicalUrl === targetUrl);
      assert.ok(link);
      finalDepthTamperingApplied = true;
      return {
        ...snapshot,
        candidates: snapshot.candidates.map((candidate) => candidate.candidateId === link.targetCandidateId
          ? { ...candidate, depth: 2 } : candidate),
        observations: snapshot.observations.map((observation) => observation.sequence === link.sequence
          ? { ...observation, depth: 2 } : observation),
      };
    },
  });
  const result = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: instrumentedFrontier, store: observedStore,
  }));
  assert.equal(proofSnapshotSeen, true, 'the unmodified authenticated receipt payload is proved first');
  assert.equal(attemptLimitObserved, true, 'the projection reaches its final gate without admitting the child');
  assert.equal(finalDepthTamperingApplied, true, 'the final snapshot carries the coordinated depth mutation');
  assert.equal(result.status, 'incomplete', JSON.stringify(result));
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('private_receipt_completion_mismatch'));
  assert.equal(requestCount, 1, 'the final proof rejection does not dispatch the child');
});

test('metadata-v1 replay rejects a link observation attributed to an unverified queued parent', async (t) => {
  let requestCount = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtmlWithCanonicalLinks([
      'https://links.example.org/a-first', 'https://links.example.org/z-last',
    ]));
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-metadata-unverified-queued-parent';
  const seeds = [{ url: sourceUrl('/metadata-parent') }];
  const limits = { maxDepth: 1, maxTransportAttemptAdmissions: 1, maxSuggestionsPerCompletion: 1 };
  const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
  assert.equal(first.status, 'draft', JSON.stringify(first));
  assert.equal(requestCount, 1);
  const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
  const evidencePath = path.join(h.evidenceConfig.directory, tenantHash, 'evidence.sqlite');
  const readReceiptRows = () => {
    const database = new DatabaseSync(evidencePath, { readOnly: true });
    try {
      return database.prepare(`SELECT state, payload_hash, payload_bytes, sealed
        FROM private_retrieval_receipts ORDER BY receipt_key`).all().map((row) => ({
        state: row.state,
        payloadHash: row.payload_hash,
        payloadBytes: row.payload_bytes,
        sealed: Buffer.from(row.sealed),
      }));
    } finally {
      database.close();
    }
  };
  const immutableReceiptRows = readReceiptRows();
  assert.equal(immutableReceiptRows.length, 1);
  const scope = await h.frontier.scopeForAuthenticatedRequest(request());
  const snapshot = await h.frontier.getSnapshot(scope, runId);
  const queuedChild = snapshot.candidates.find((candidate) => candidate.depth > 0 && candidate.state === 'queued');
  assert.ok(queuedChild);
  const transportBefore = await h.frontier.getTransportProgress(scope, runId);
  insertUnverifiedQueuedParentLinkObservation({
    databasePath: path.join(h.frontierDirectory, tenantHash, 'frontier.sqlite'),
    tenantHash,
    runId,
    queuedCandidateId: queuedChild.candidateId,
    field: 'independent.unproved.metadata.extra',
  });
  const tamperedSnapshot = await h.frontier.getSnapshot(scope, runId);
  assert.ok(tamperedSnapshot.candidates.find((candidate) => candidate.candidateId === queuedChild.candidateId)
    .sourceRefs.some((reference) => reference.field === 'independent.unproved.metadata.extra'));

  h.frontier.close();
  const reopenedFrontier = h.openFrontier();
  const reopenedStore = createEvidenceStore(h.evidenceConfig);
  const recovered = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
  }));
  assert.equal(recovered.status, 'incomplete', JSON.stringify(recovered));
  assert.equal(recovered.draft, null);
  assert.ok(recovered.limitations.includes('private_receipt_completion_mismatch'));
  assert.equal(requestCount, 1, 'metadata-v1 stream rejection does not dispatch the queued child');
  assert.deepEqual(readReceiptRows(), immutableReceiptRows,
    'metadata-v1 stream rejection leaves authenticated ciphertext rows unchanged');
  const reopenedScope = await reopenedFrontier.scopeForAuthenticatedRequest(request());
  const after = await reopenedFrontier.getSnapshot(reopenedScope, runId);
  assert.deepEqual(await reopenedFrontier.getTransportProgress(reopenedScope, runId), transportBefore,
    'metadata-v1 stream rejection preserves transport counters and settled bytes');
  assert.equal(after.counters.transportAttemptAdmissions, snapshot.counters.transportAttemptAdmissions);
});

test('baseline v1 overcap receipt recovers once and reconstructs identical omission evidence after another restart', async (t) => {
  const requests = { count: 0 };
  const h = await legacyOvercapWorkspace(t, requests);
  let frontier = h.openFrontier();
  let evidenceStore = h.openEvidenceStore();
  const scope = await frontier.scopeForAuthenticatedRequest(h.request);
  const before = await frontier.getSnapshot(scope, h.runId);
  assert.equal(before.candidates[0].state, 'leased');
  assert.equal(before.counters.transportAttemptAdmissions, 1);
  const transportBefore = await frontier.getTransportProgress(scope, h.runId);
  assert.equal(transportBefore.reservedBytes, 0);
  assert.ok(transportBefore.spentBytes > 0);
  const immutableReceiptRow = h.readLegacyReceiptRow();
  assert.equal(immutableReceiptRow.state, 'complete');
  assert.match(immutableReceiptRow.payloadHash, /^[a-f0-9]{64}$/);
  assert.ok(immutableReceiptRow.payloadBytes > 0 && immutableReceiptRow.sealed.byteLength > 0);
  const candidate = before.candidates[0];
  const initialBinding = await frontier.getCandidateReceiptBinding(scope, h.runId, candidate.candidateId);
  const evidenceScope = await evidenceStore.scopeForAuthenticatedRequest(h.request);
  const oldReceipt = await evidenceStore.readPrivateRunReceipt(evidenceScope, {
    runId: h.runId, configHash: h.fixture.configHash, candidate: initialBinding.candidate,
  }, h.request);
  assert.equal(oldReceipt.state, 'complete');
  assert.equal(oldReceipt.omissionMetadataVersion, 0);
  assert.equal(oldReceipt.suggestions.length, 2);
  assert.equal(oldReceipt.truncatedCount, 0,
    'the modern reader does not invent a persisted omission count for an old receipt');
  assert.ok(!oldReceipt.limitations.includes('some_link_candidates_omitted_by_policy_or_parser_limit'));

  const recovered = await h.run(frontier, evidenceStore);
  assert.equal(recovered.status, 'draft', JSON.stringify(recovered));
  assert.equal(recovered.linkCandidates.length, 1);
  assert.equal(recovered.linkCandidates[0].url, 'https://links.example.org/a-first');
  assert.equal(recovered.omittedLinkCandidates.length, 1);
  assert.equal(recovered.omittedLinkCandidates[0].url, 'https://links.example.org/z-last');
  assert.equal(recovered.progress.truncatedSuggestionCount, 1);
  assert.equal(recovered.progress.sourceLinkCandidateOmittedCount, 0,
    'the fully recovered baseline run has no preserved run-level omission marker');
  assert.equal(recovered.progress.sourceLinkCandidateOmittedCountLowerBound, 0);
  assert.equal(recovered.progress.sourceLinkCandidateOmittedCountComplete, true);
  assert.ok(recovered.progress.stopReasons.includes('fanout_limit'));
  assert.equal(requests.count, 0, 'legacy receipt recovery does not repeat its original transport dispatch');
  const afterFirstRecovery = await frontier.getSnapshot(scope, h.runId);
  assert.equal(afterFirstRecovery.candidates.find((item) => item.seed).state, 'completed');
  assert.equal(afterFirstRecovery.counters.transportAttemptAdmissions, before.counters.transportAttemptAdmissions);
  assert.deepEqual(await frontier.getTransportProgress(scope, h.runId), transportBefore,
    'recovery preserves the original settled transport spend and admission counters');
  assert.deepEqual(h.readLegacyReceiptRow(), immutableReceiptRow,
    'frontier recovery leaves the historical encrypted receipt row unchanged');
  const omissionSourceRef = recovered.omittedLinkCandidates[0].sourceRefs[0];
  assert.equal(omissionSourceRef.value, 'https://links.example.org/z-last');
  assert.ok(recovered.sources.some((item) => item.evidenceId === omissionSourceRef.evidenceId
    && item.contentHash === omissionSourceRef.contentHash),
  'the recovery-time omitted URL remains attributable to the encrypted source evidence');

  frontier.close();
  frontier = h.openFrontier();
  evidenceStore = h.openEvidenceStore();
  const replayed = await h.run(frontier, evidenceStore);
  assert.equal(replayed.status, 'draft', JSON.stringify(replayed));
  assert.equal(replayed.progress.truncatedSuggestionCount, 1);
  assert.equal(replayed.omittedLinkCandidates[0].url, recovered.omittedLinkCandidates[0].url);
  assert.deepEqual(replayed.omittedLinkCandidates[0].sourceRefs, recovered.omittedLinkCandidates[0].sourceRefs,
    'the repeated completed-receipt reconstruction retains the same omitted provenance');
  assert.equal(requests.count, 0, 'the second restart remains receipt-only');
  const replayScope = await frontier.scopeForAuthenticatedRequest(h.request);
  const afterSecondRecovery = await frontier.getSnapshot(replayScope, h.runId);
  assert.equal(afterSecondRecovery.counters.transportAttemptAdmissions, before.counters.transportAttemptAdmissions);
  assert.deepEqual(await frontier.getTransportProgress(replayScope, h.runId), transportBefore);
  assert.deepEqual(h.readLegacyReceiptRow(), immutableReceiptRow);
});

test('baseline overcap recovery rejects coordinated depth inflation without rewriting the legacy receipt', async (t) => {
  const requests = { count: 0 };
  const h = await legacyOvercapWorkspace(t, requests);
  let frontier = h.openFrontier();
  let evidenceStore = h.openEvidenceStore();
  const recovered = await h.run(frontier, evidenceStore);
  assert.equal(recovered.status, 'draft', JSON.stringify(recovered));
  assert.equal(requests.count, 0);

  const immutableReceiptRow = h.readLegacyReceiptRow();
  const scope = await frontier.scopeForAuthenticatedRequest(h.request);
  const before = await frontier.getSnapshot(scope, h.runId);
  const child = before.candidates.find((candidate) => candidate.canonicalUrl === 'https://links.example.org/a-first');
  assert.ok(child);
  assert.equal(child.depth, 1);
  assert.equal(child.state, 'queued');
  const transportBefore = await frontier.getTransportProgress(scope, h.runId);
  reassignCandidateAndIncomingLinkDepth({
    databasePath: path.join(h.frontierDirectory, h.fixture.tenantHash, 'frontier.sqlite'),
    tenantHash: h.fixture.tenantHash,
    runId: h.runId,
    candidateId: child.candidateId,
    depth: 2,
    disposition: 'depth_limit',
    candidateState: 'depth_limited',
  });
  const tampered = await frontier.getSnapshot(scope, h.runId);
  assert.equal(tampered.candidates.find((candidate) => candidate.candidateId === child.candidateId).depth, 2);
  assert.equal(tampered.observations.find((item) => item.targetCandidateId === child.candidateId).depth, 2);
  assert.equal(tampered.observations.find((item) => item.targetCandidateId === child.candidateId).disposition, 'depth_limit');

  frontier.close();
  frontier = h.openFrontier();
  evidenceStore = h.openEvidenceStore();
  const replay = await h.run(frontier, evidenceStore);
  assert.equal(replay.status, 'incomplete', JSON.stringify(replay));
  assert.equal(replay.draft, null);
  assert.ok(replay.limitations.includes('private_receipt_completion_mismatch'));
  assert.ok(replay.limitations.includes('legacy_receipt_fanout_recovery_unverified'));
  assert.equal(requests.count, 0, 'legacy depth validation never dispatches the retained child');
  assert.deepEqual(h.readLegacyReceiptRow(), immutableReceiptRow,
    'legacy recovery leaves its original encrypted receipt row byte-for-byte unchanged');
  const replayScope = await frontier.scopeForAuthenticatedRequest(h.request);
  assert.deepEqual(await frontier.getTransportProgress(replayScope, h.runId), transportBefore,
    'legacy depth rejection preserves the original transport settlement');
});

test('legacy overcap recovery refuses missing or conflicting observations and a changed frontier payload hash', async (t) => {
  const requests = { count: 0 };
  const missingObservation = await legacyOvercapWorkspace(t, requests);
  let frontier = missingObservation.openFrontier();
  let evidenceStore = missingObservation.openEvidenceStore();
  const recovered = await missingObservation.run(frontier, evidenceStore);
  assert.equal(recovered.status, 'draft', JSON.stringify(recovered));
  const scope = await frontier.scopeForAuthenticatedRequest(missingObservation.request);
  const snapshot = await frontier.getSnapshot(scope, missingObservation.runId);
  const parent = snapshot.candidates.find((item) => item.seed);
  const databasePath = path.join(missingObservation.frontierDirectory,
    missingObservation.fixture.tenantHash, 'frontier.sqlite');
  const database = new DatabaseSync(databasePath);
  try {
    withPrivilegedFrontierFixtureMutation(database, () => {
      const observationCount = database.prepare(`SELECT COUNT(*) AS count FROM frontier_observations
        WHERE tenant_hash = ? AND run_id = ? AND parent_candidate_id = ? AND kind = 'link'`)
        .get(missingObservation.fixture.tenantHash, missingObservation.runId, parent.candidateId).count;
      assert.equal(observationCount, 1);
      database.prepare(`DELETE FROM frontier_observations
        WHERE tenant_hash = ? AND run_id = ? AND parent_candidate_id = ? AND kind = 'link'`)
        .run(missingObservation.fixture.tenantHash, missingObservation.runId, parent.candidateId);
    });
  } finally {
    database.close();
  }
  frontier.close();
  frontier = missingObservation.openFrontier();
  evidenceStore = missingObservation.openEvidenceStore();
  const missingReplay = await missingObservation.run(frontier, evidenceStore);
  assert.equal(missingReplay.status, 'incomplete', JSON.stringify(missingReplay));
  assert.equal(missingReplay.draft, null);
  assert.ok(missingReplay.limitations.includes('legacy_receipt_fanout_recovery_unverified'));
  assert.equal(requests.count, 0);

  const conflictingObservation = await legacyOvercapWorkspace(t, requests);
  frontier = conflictingObservation.openFrontier();
  evidenceStore = conflictingObservation.openEvidenceStore();
  const conflictRecovered = await conflictingObservation.run(frontier, evidenceStore);
  assert.equal(conflictRecovered.status, 'draft', JSON.stringify(conflictRecovered));
  const conflictScope = await frontier.scopeForAuthenticatedRequest(conflictingObservation.request);
  const conflictSnapshot = await frontier.getSnapshot(conflictScope, conflictingObservation.runId);
  const conflictParent = conflictSnapshot.candidates.find((item) => item.seed);
  const conflictDatabasePath = path.join(conflictingObservation.frontierDirectory,
    conflictingObservation.fixture.tenantHash, 'frontier.sqlite');
  const conflictDatabase = new DatabaseSync(conflictDatabasePath);
  try {
    withPrivilegedFrontierFixtureMutation(conflictDatabase, () => {
      const observation = conflictDatabase.prepare(`SELECT sequence, source_refs_json FROM frontier_observations
        WHERE tenant_hash = ? AND run_id = ? AND parent_candidate_id = ? AND kind = 'link' ORDER BY sequence LIMIT 1`)
        .get(conflictingObservation.fixture.tenantHash, conflictingObservation.runId, conflictParent.candidateId);
      assert.ok(observation);
      const sourceRefs = JSON.parse(observation.source_refs_json);
      assert.equal(sourceRefs.length, 1);
      sourceRefs[0].value = 'https://links.example.org/conflicting-observation';
      conflictDatabase.prepare(`UPDATE frontier_observations SET source_refs_json = ?
        WHERE tenant_hash = ? AND run_id = ? AND sequence = ?`)
        .run(JSON.stringify(sourceRefs), conflictingObservation.fixture.tenantHash,
          conflictingObservation.runId, observation.sequence);
    });
  } finally {
    conflictDatabase.close();
  }
  frontier.close();
  frontier = conflictingObservation.openFrontier();
  evidenceStore = conflictingObservation.openEvidenceStore();
  const conflictingReplay = await conflictingObservation.run(frontier, evidenceStore);
  assert.equal(conflictingReplay.status, 'incomplete', JSON.stringify(conflictingReplay));
  assert.equal(conflictingReplay.draft, null);
  assert.ok(conflictingReplay.limitations.includes('legacy_receipt_fanout_recovery_unverified'));
  assert.equal(requests.count, 0);

  for (const outcome of ['failed', null]) {
    const contradictory = await legacyOvercapWorkspace(t, requests);
    frontier = contradictory.openFrontier();
    evidenceStore = contradictory.openEvidenceStore();
    const completed = await contradictory.run(frontier, evidenceStore);
    assert.equal(completed.status, 'draft', JSON.stringify(completed));
    const originalReceiptRow = contradictory.readLegacyReceiptRow();
    const contradictoryScope = await frontier.scopeForAuthenticatedRequest(contradictory.request);
    const completedSnapshot = await frontier.getSnapshot(contradictoryScope, contradictory.runId);
    const parentCandidate = completedSnapshot.candidates.find((item) => item.seed);
    insertContradictoryLinkObservation({
      databasePath: path.join(contradictory.frontierDirectory, contradictory.fixture.tenantHash, 'frontier.sqlite'),
      tenantHash: contradictory.fixture.tenantHash,
      runId: contradictory.runId,
      parentCandidateId: parentCandidate.candidateId,
      outcome,
    });
    frontier.close();
    frontier = contradictory.openFrontier();
    evidenceStore = contradictory.openEvidenceStore();
    const rejected = await contradictory.run(frontier, evidenceStore);
    assert.equal(rejected.status, 'incomplete', JSON.stringify(rejected));
    assert.equal(rejected.draft, null);
    assert.ok(rejected.limitations.includes('legacy_receipt_fanout_recovery_unverified'));
    assert.equal(requests.count, 0, 'rejected observation evidence never causes a transport retry');
    assert.deepEqual(contradictory.readLegacyReceiptRow(), originalReceiptRow,
      'rejected legacy observations never rewrite the authenticated receipt');
  }

  const changedHash = await legacyOvercapWorkspace(t, requests);
  frontier = changedHash.openFrontier();
  evidenceStore = changedHash.openEvidenceStore();
  const hashRecovered = await changedHash.run(frontier, evidenceStore);
  assert.equal(hashRecovered.status, 'draft', JSON.stringify(hashRecovered));
  const hashDatabasePath = path.join(changedHash.frontierDirectory, changedHash.fixture.tenantHash, 'frontier.sqlite');
  const hashDatabase = new DatabaseSync(hashDatabasePath);
  try {
    withPrivilegedFrontierFixtureMutation(hashDatabase, () => {
      hashDatabase.prepare(`UPDATE frontier_completions SET payload_hash = ?
        WHERE tenant_hash = ? AND run_id = ?`).run('0'.repeat(64), changedHash.fixture.tenantHash, changedHash.runId);
    });
  } finally {
    hashDatabase.close();
  }
  frontier.close();
  frontier = changedHash.openFrontier();
  evidenceStore = changedHash.openEvidenceStore();
  const hashReplay = await changedHash.run(frontier, evidenceStore);
  assert.equal(hashReplay.status, 'incomplete', JSON.stringify(hashReplay));
  assert.equal(hashReplay.draft, null);
  assert.ok(hashReplay.limitations.includes('legacy_receipt_fanout_recovery_unverified'));
  assert.ok(hashReplay.limitations.includes('private_receipt_completion_mismatch'));
  assert.equal(requests.count, 0);
});

test('an expired encrypted receipt withholds replayed facts and does not authorize another request', async (t) => {
  let requestCount = 0;
  let evidenceNow = Date.now();
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t, { evidenceOptions: { now: () => evidenceNow } });
  const runId = 'private-receipt-expired-restart';
  const seeds = [{ url: sourceUrl('/receipt-expiry') }];
  const limits = {
    maxDepth: 0,
    maxTransportAttemptAdmissions: 1,
    maxInFlightLeases: 4,
    durationMs: 30_000,
    maxSuggestionsPerCompletion: 16,
  };
  const first = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits }));
  assert.equal(first.status, 'draft', JSON.stringify(first));
  assert.equal(requestCount, 1);

  evidenceNow += 181_000;
  const reopenedFrontier = h.openFrontier();
  const reopenedStore = createEvidenceStore(h.evidenceConfig);
  const reopenedScope = await reopenedStore.scopeForAuthenticatedRequest(request());
  const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
  const databasePath = path.join(h.evidenceConfig.directory, tenantHash, 'evidence.sqlite');
  const beforePurge = new DatabaseSync(databasePath);
  try {
    const row = beforePurge.prepare(`SELECT state, key_id, payload_hash, payload_bytes, sealed
      FROM private_retrieval_receipts WHERE tenant_hash = ? LIMIT 1`).get(tenantHash);
    assert.equal(row.state, 'complete', 'the completed runner persisted its replay receipt');
    assert.equal(row.key_id, 'payload-test-v1');
    assert.match(row.payload_hash, /^[a-f0-9]{64}$/);
    assert.ok(row.payload_bytes > 0 && row.sealed.byteLength > 0);
  } finally {
    beforePurge.close();
  }
  assert.equal(await reopenedStore.purgeExpired(reopenedScope), first.facts.length + 1,
    'tenant-wide purge expires the source and all extracted facts before exact receipt lookup');
  const afterPurge = new DatabaseSync(databasePath);
  try {
    const row = afterPurge.prepare(`SELECT state, key_id, payload_hash, payload_bytes, sealed
      FROM private_retrieval_receipts WHERE tenant_hash = ? LIMIT 1`).get(tenantHash);
    assert.equal(row.state, 'expired', 'purge clears the complete receipt before exact receipt lookup');
    assert.equal(row.key_id, null);
    assert.equal(row.payload_hash, null);
    assert.equal(row.payload_bytes, null);
    assert.equal(row.sealed, null);
  } finally {
    afterPurge.close();
  }
  assert.deepEqual(await reopenedStore.integritySnapshot(reopenedScope), {
    availableEvidence: 0,
    expiredEvidence: 1,
    availableFacts: 0,
    expiredFacts: first.facts.length,
    encryptedPayloadRecords: 0,
    encryptedPrivateReceiptRecords: 0,
  }, 'ordinary expiry purge removes the expired receipt envelope as well as evidence payloads');
  const expired = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
  }));
  assert.equal(expired.status, 'incomplete');
  assert.equal(expired.draft, null);
  assert.ok(expired.limitations.includes('private_receipt_expired'), JSON.stringify(expired));
  assert.ok(expired.limitations.includes('private_receipt_unavailable'));
  assert.equal(requestCount, 1, 'expired records and receipts never trigger a replacement fetch');
});

test('a durable pending receipt after the pre-dispatch crash boundary remains incomplete and is never redispatched', async (t) => {
  let requestCount = 0;
  let receiptBinding;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-pending-receipt-crash';
  const seeds = [{ url: sourceUrl('/pending-receipt') }];
  const limits = { maxDepth: 0, maxTransportAttemptAdmissions: 1 };
  const store = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'appendFact', 'ingestEvidence', 'ingestDerivedPdfEvidence',
    'ingestAssetSourceEvidence', 'lookupEvidence', 'lookupFact', 'materializeSelected',
    'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.beginPrivateRunReceipt = async (scope, binding, authenticated, signal) => {
    receiptBinding = binding;
    const result = await h.evidenceStore.beginPrivateRunReceipt(scope, binding, authenticated, signal);
    assert.deepEqual(result, { state: 'pending', created: true });
    throw new Error('simulated process loss after durable pending receipt and before first admission');
  };
  const interrupted = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits, store }));
  assert.equal(interrupted.draft, null);
  assert.equal(requestCount, 0);
  assert.equal((await h.frontier.getSnapshot(h.scope, runId)).counters.transportAttemptAdmissions, 0);
  assert.ok(receiptBinding);
  const pending = await h.evidenceStore.readPrivateRunReceipt(h.evidenceScope, {
    runId, configHash: receiptBinding.configHash, candidate: receiptBinding.candidate,
  }, request());
  assert.equal(pending.state, 'pending');

  const reopenedFrontier = h.openFrontier();
  const reopenedStore = createEvidenceStore(h.evidenceConfig);
  const recovered = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
  }));
  assert.equal(recovered.draft, null);
  assert.equal(recovered.status, 'incomplete');
  assert.ok(recovered.limitations.includes('private_receipt_pending'));
  assert.ok(recovered.limitations.includes('cancelled_before_dispatch'));
  assert.equal(requestCount, 0, 'a pending receipt is never a replay or dispatch grant');
  const reopenedScope = await reopenedFrontier.scopeForAuthenticatedRequest(request());
  const persisted = await reopenedFrontier.getSnapshot(reopenedScope, runId);
  assert.equal(persisted.candidates[0].state, 'unresolved');
  assert.equal(persisted.candidates[0].unresolvedReason, 'cancelled_before_dispatch');
  assert.ok(persisted.stopReasons.some((entry) => entry.reason === 'unresolved_work'));
  assert.deepEqual(await reopenedStore.beginPrivateRunReceipt(
    await reopenedStore.scopeForAuthenticatedRequest(request()), receiptBinding, request(),
  ), { state: 'pending', created: false }, 'an existing pending marker cannot become a fresh dispatch grant');
});

test('a pending receipt that appears before begin returns its existing marker and resolves the lease without redispatch', async (t) => {
  let requestCount = 0;
  let receiptBinding;
  let beginCalls = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-pending-receipt-existing-marker';
  const seeds = [{ url: sourceUrl('/pending-existing-marker') }];
  const limits = { maxDepth: 0, maxTransportAttemptAdmissions: 1 };
  const store = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'appendFact', 'ingestEvidence', 'ingestDerivedPdfEvidence',
    'ingestAssetSourceEvidence', 'lookupEvidence', 'lookupFact', 'materializeSelected',
    'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.beginPrivateRunReceipt = async (scope, binding, authenticated, signal) => {
    beginCalls += 1;
    receiptBinding = binding;
    const concurrentlyCreated = await h.evidenceStore.beginPrivateRunReceipt(scope, binding, authenticated, signal);
    assert.deepEqual(concurrentlyCreated, { state: 'pending', created: true });
    // Model a concurrent creator winning immediately before this begin observes
    // its key: the real store returns its durable existing-marker result.
    return h.evidenceStore.beginPrivateRunReceipt(scope, binding, authenticated, signal);
  };

  const result = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits, store }));
  assert.equal(beginCalls, 1);
  assert.equal(result.status, 'incomplete', JSON.stringify(result));
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('private_receipt_pending'), JSON.stringify(result));
  assert.ok(result.limitations.includes('cancelled_before_dispatch'), JSON.stringify(result));
  const pendingMarkerLimitations = result.limitations.filter((limitation) => [
    'private_receipt_pending', 'private_receipt_already_exists', 'cancelled_before_dispatch',
    'dispatch_state_unknown', 'source_unavailable',
  ].includes(limitation)).sort();
  assert.deepEqual(pendingMarkerLimitations, ['cancelled_before_dispatch', 'private_receipt_pending'],
    'the existing marker is handled directly without a generic source failure or changed uncertainty');
  assert.ok(!result.limitations.includes('source_unavailable'), JSON.stringify(result));
  assert.equal(requestCount, 0, 'an existing pending marker never authorizes another fetch');
  assert.ok(receiptBinding);
  const receipt = await h.evidenceStore.readPrivateRunReceipt(h.evidenceScope, {
    runId, configHash: receiptBinding.configHash, candidate: receiptBinding.candidate,
  }, request());
  assert.equal(receipt.state, 'pending');
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshot.counters.transportAttemptAdmissions, 0);
  assert.equal(snapshot.candidates[0].state, 'unresolved');
  assert.equal(snapshot.candidates[0].unresolvedReason, 'cancelled_before_dispatch');
});

test('evidence committed before receipt completion remains explicit uncertainty after restart', async (t) => {
  let requestCount = 0;
  let receiptBinding;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-evidence-before-receipt-crash';
  const seeds = [{ url: sourceUrl('/evidence-before-receipt') }];
  const limits = { maxDepth: 0, maxTransportAttemptAdmissions: 1 };
  const store = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'appendFact', 'ingestEvidence', 'ingestDerivedPdfEvidence',
    'ingestAssetSourceEvidence', 'lookupEvidence', 'lookupFact', 'materializeSelected',
    'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.beginPrivateRunReceipt = async (scope, binding, authenticated, signal) => {
    receiptBinding = binding;
    return h.evidenceStore.beginPrivateRunReceipt(scope, binding, authenticated, signal);
  };
  store.finalizePrivateRunReceipt = async () => {
    throw new Error('simulated crash after evidence and fact commits, before the complete receipt');
  };
  const interrupted = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits, store }));
  assert.equal(interrupted.status, 'incomplete');
  assert.equal(interrupted.draft, null);
  assert.equal(requestCount, 1);
  const persistedEvidence = await h.evidenceStore.integritySnapshot(h.evidenceScope);
  assert.ok(persistedEvidence.availableEvidence >= 1);
  assert.ok(persistedEvidence.availableFacts >= 1);
  assert.ok(receiptBinding);
  assert.equal((await h.evidenceStore.readPrivateRunReceipt(h.evidenceScope, {
    runId, configHash: receiptBinding.configHash, candidate: receiptBinding.candidate,
  }, request())).state, 'pending');
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transport.reservedBytes, 0);
  assert.ok(transport.spentBytes > 0);

  const reopenedFrontier = h.openFrontier();
  const reopenedScope = await reopenedFrontier.scopeForAuthenticatedRequest(request());
  const reopenedStore = createEvidenceStore(h.evidenceConfig);
  const recovered = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds, limits, frontier: reopenedFrontier, store: reopenedStore,
  }));
  assert.equal(recovered.status, 'incomplete');
  assert.equal(recovered.draft, null, 'unreceipted stored facts are not assumed to belong to a completed selection');
  assert.ok(recovered.limitations.includes('private_receipt_pending'), JSON.stringify(recovered));
  assert.ok(recovered.limitations.includes('dispatch_state_unknown'));
  assert.equal(requestCount, 1, 'an evidence/receipt crash gap never redispatches its old lease');
  const snapshot = await reopenedFrontier.getSnapshot(reopenedScope, runId);
  assert.equal(snapshot.candidates[0].state, 'unresolved');
  assert.equal(snapshot.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.equal((await reopenedFrontier.getTransportProgress(reopenedScope, runId)).spentBytes, transport.spentBytes);
});

test('remote cancellation bounds a never-resolving retention callback and ignores its late result', { timeout: 8_000 }, async (t) => {
  let retentionStarted;
  let resolveRetention;
  const retentionCallbackStarted = new Promise((resolve) => { retentionStarted = resolve; });
  const pendingRetention = new Promise((resolve) => { resolveRetention = resolve; });
  const server = await startFixture((_request, response) => {
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  let ingestCalls = 0;
  const store = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'appendFact', 'ingestDerivedPdfEvidence', 'ingestAssetSourceEvidence',
    'lookupEvidence', 'lookupFact', 'materializeSelected',
    'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.ingestEvidence = async (...args) => {
    ingestCalls += 1;
    return h.evidenceStore.ingestEvidence(...args);
  };
  const runId = 'private-cancel-retention';
  const running = runPrivateRetrieval(h.makeInput({
    runId, server, seeds: [{ url: sourceUrl('/event') }], store,
    retentionHandleFor() { retentionStarted(); return pendingRetention; },
  }));
  await retentionCallbackStarted;
  const cancelStarted = Date.now();
  await runStopWorker(h.frontierDirectory, runId);
  assert.ok((await h.frontier.getSnapshot(h.scope, runId)).stopReasons.some((entry) => entry.reason === 'cancelled'),
    'the durable cancellation event is present even if another stop reason remains primary');
  const result = await running;
  assert.ok(Date.now() - cancelStarted < 5_000, 'an unresolved host callback cannot delay cancellation');
  assert.equal(result.status, 'cancelled');
  assert.equal(result.draft, null);
  assert.equal(ingestCalls, 0);
  resolveRetention(h.createRetention());
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(ingestCalls, 0, 'the late handle is not used to write private evidence after cancellation');
});

test('external cancellation bounds stalled stop persistence and keeps an admitted lease unknown across restart', { timeout: 8_000 }, async (t) => {
  let retentionStarted;
  const retentionCallbackStarted = new Promise((resolve) => { retentionStarted = resolve; });
  const pendingRetention = new Promise(() => {});
  let requestCount = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-external-cancel-stalled-stop';
  const frontier = frontierWithMethodOverrides(h.frontier, {
    stopRun: async () => new Promise(() => {}),
  });
  const cancellation = new AbortController();
  const running = runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier,
    signal: cancellation.signal,
    seeds: [{ url: sourceUrl('/external-cancel-stalled-stop') }],
    limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1, durationMs: 5_000 },
    retentionHandleFor() {
      retentionStarted();
      return pendingRetention;
    },
  }));
  await retentionCallbackStarted;
  const cancelledAt = performance.now();
  cancellation.abort();
  const result = await running;
  const cleanupElapsedMs = performance.now() - cancelledAt;
  t.diagnostic(JSON.stringify({ cleanupElapsedMs, resultStatus: result.status, requestCount, stopPersistence: 'never-settles' }));
  assert.ok(cleanupElapsedMs <= 850,
    `external cancellation returns within the 750ms cleanup budget plus 100ms scheduling tolerance (${cleanupElapsedMs.toFixed(1)}ms)`);
  assert.equal(result.status, 'cancelled');
  assert.equal(result.draft, null);
  assert.equal(requestCount, 1, 'the initial admitted response was the only HTTP request');

  const interrupted = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(interrupted.candidates[0].state, 'unresolved');
  assert.equal(interrupted.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.equal(interrupted.candidates[0].admittedAttemptCount, 1);
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transport.reservedBytes, 0, 'the completed body keeps its settled accounting');
  assert.ok(transport.spentBytes > 0);

  const reopened = h.openFrontier();
  const reopenedScope = await reopened.scopeForAuthenticatedRequest(request());
  const restarted = await runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier: reopened,
    seeds: [{ url: sourceUrl('/external-cancel-stalled-stop') }],
    limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1, durationMs: 5_000 },
  }));
  assert.equal(restarted.draft, null);
  assert.equal(requestCount, 1, 'restart cannot redispatch the unresolved admission while stop persistence is stalled');
  const afterRestart = await reopened.getSnapshot(reopenedScope, runId);
  assert.equal(afterRestart.candidates[0].state, 'unresolved');
  assert.equal(afterRestart.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.equal((await reopened.getTransportProgress(reopenedScope, runId)).spentBytes, transport.spentBytes);
});

for (const { siblingAbortDelayMs, cleanupServiceStallMs = 0 } of [
  { siblingAbortDelayMs: 0 }, { siblingAbortDelayMs: 600 }, { siblingAbortDelayMs: 900 },
  { siblingAbortDelayMs: 600, cleanupServiceStallMs: 400 },
]) {
  const serviceLabel = cleanupServiceStallMs ? ' with the original cleanup boundary blocked by a native callback' : '';
  test(`deferred stop callback enforces its original deadline after a ${siblingAbortDelayMs}ms sibling abort listener${serviceLabel}`, { timeout: 8_000 }, async (t) => {
    const h = await harness(t);
    const body = eventHtml();
    let requestCount = 0;
    const server = await startFixture((_request, response) => {
      requestCount += 1;
      respond(response, 200, { 'content-type': 'text/html' }, body);
    });
    t.after(() => server.close());
    let signalAtEntry;
    let stopEnteredAt;
    let stopAbortedAt;
    let stopCalls = 0;
    let serviceStallEnteredAt;
    let serviceStallReturnedAt;
    const unresolvedCalls = [];
    const frontier = frontierWithMethodOverrides(h.frontier, {
      stopRun: async (_scope, _runId, _reason, signal) => {
        stopCalls += 1;
        stopEnteredAt = performance.now();
        signalAtEntry = signal.aborted;
        const observeAbort = () => { stopAbortedAt = performance.now(); };
        if (signal.aborted) observeAbort();
        else signal.addEventListener('abort', observeAbort, { once: true });
        if (cleanupServiceStallMs) {
          // Enter the native control in this actual deferred callback. A
          // separate timer could run only after another synchronous cleanup
          // callback had already consumed the intended original boundary.
          serviceStallEnteredAt = performance.now();
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, cleanupServiceStallMs);
          serviceStallReturnedAt = performance.now();
        }
        return new Promise(() => {});
      },
      markUnresolved: async (...args) => {
        const signal = args[3];
        const observation = { enteredAt: performance.now(), signalAtEntry: signal?.aborted };
        unresolvedCalls.push(observation);
        const observeAbort = () => { observation.abortedAt = performance.now(); };
        signal?.addEventListener('abort', observeAbort, { once: true });
        try { return await h.frontier.markUnresolved(...args); }
        finally {
          observation.returnedAt = performance.now();
          observation.signalAtReturn = signal?.aborted;
          signal?.removeEventListener('abort', observeAbort);
        }
      },
    });
    let retentionEntered;
    const entered = new Promise((resolve) => { retentionEntered = resolve; });
    const cancellation = new AbortController();
    const runId = `private-deferred-stop-${siblingAbortDelayMs}-${cleanupServiceStallMs}`;
    const seeds = [{ url: sourceUrl('/deferred-stop') }];
    const limits = { maxDepth: 0, maxTransportAttemptAdmissions: 1, durationMs: 5_000 };
    const running = runPrivateRetrieval(h.makeInput({
      runId, server, frontier, seeds, limits, signal: cancellation.signal,
      retentionHandleFor() { retentionEntered(); return new Promise(() => {}); },
    }));
    assert.equal(await Promise.race([
      entered.then(() => 'retention'), running.then(() => 'completed-before-retention'),
    ]), 'retention', 'the actual response body completes before cancellation');

    // The runner's listener schedules stop persistence first. This ordinary
    // sibling listener blocks before that microtask and any overdue timer run.
    let siblingReturnedAt;
    cancellation.signal.addEventListener('abort', () => {
      if (siblingAbortDelayMs) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, siblingAbortDelayMs);
      siblingReturnedAt = performance.now();
    }, { once: true });
    // This independent native timer is registered before cancellation. Its
    // actual callback time distinguishes service of the original boundary from
    // a renewed cleanup allowance. It never changes a runner clock or timer.
    let heartbeatServicedAt;
    const heartbeatScheduledAt = performance.now();
    let heartbeatTimer;
    const heartbeat = new Promise((resolve) => {
      heartbeatTimer = setTimeout(() => { heartbeatServicedAt = performance.now(); resolve(); }, 750);
    });
    t.after(() => clearTimeout(heartbeatTimer));
    const cancelledAt = performance.now();
    cancellation.abort();
    const result = await running;
    const returnedAt = performance.now();
    await heartbeat;
    const originalCleanupBoundaryAt = cancelledAt + 750;
    const cleanupServiceBoundaryAt = Math.max(originalCleanupBoundaryAt, siblingReturnedAt, heartbeatServicedAt);
    t.diagnostic(JSON.stringify({ siblingAbortDelayMs, cleanupServiceStallMs,
      cancelledAt, siblingReturnedAt, returnedAt, originalCleanupBoundaryAt,
      heartbeatScheduledAt, heartbeatRequestedDelayMs: 750, heartbeatServicedAt,
      serviceStallPhase: cleanupServiceStallMs ? 'deferred-stopRun-entry' : null,
      serviceStallEnteredAt, serviceStallReturnedAt,
      cancellationToReturnMs: returnedAt - cancelledAt,
      withinOriginal850Ms: returnedAt - cancelledAt <= 850,
      cleanupAfterBoundaryServiceMs: returnedAt - cleanupServiceBoundaryAt,
      unresolvedCalls, stopEntryMs: stopEnteredAt - cancelledAt,
      signalAtEntry, stopAbortMs: stopAbortedAt - cancelledAt,
      cleanupAfterListenerMs: returnedAt - siblingReturnedAt, requestCount, stopCalls }));
    assert.equal(stopCalls, 1);
    assert.ok(stopEnteredAt >= siblingReturnedAt, 'the stop callback enters after the sibling listener');
    assert.equal(result.status, 'cancelled');
    assert.equal(result.draft, null);
    assert.equal(requestCount, 1);
    assert.ok(returnedAt <= cleanupServiceBoundaryAt + 100,
      'cleanup returns within 100ms after the event loop can service the original boundary; deferred entry does not renew its allowance');
    if (cleanupServiceStallMs) {
      assert.ok(serviceStallEnteredAt >= stopEnteredAt,
        'the native control enters inside the actual stop callback');
      assert.ok(serviceStallEnteredAt >= siblingReturnedAt && serviceStallEnteredAt < originalCleanupBoundaryAt,
        'the native control starts after deferred entry and before the original cleanup boundary');
      assert.ok(serviceStallReturnedAt >= originalCleanupBoundaryAt,
        'the native control actually prevents service at the original cleanup boundary');
      assert.ok(heartbeatServicedAt >= serviceStallReturnedAt, 'the independent heartbeat observes actual late service');
      assert.ok(returnedAt - cancelledAt > 850,
        'the deliberately blocked-service control retains its observed violation of the old absolute 850ms assertion');
    }
    const snapshot = await h.frontier.getSnapshot(h.scope, runId);
    assert.notEqual(snapshot.candidates[0].state, 'completed');
    assert.equal(snapshot.candidates[0].admittedAttemptCount, 1);
    const transport = await h.frontier.getTransportProgress(h.scope, runId);
    assert.equal(transport.reservedBytes, 0, 'the completed body retains its settled reservation');
    assert.equal(transport.spentBytes, body.length, 'actual decoded bytes remain accounted for');
    const reopened = h.openFrontier();
    const restarted = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits, frontier: reopened }));
    assert.equal(restarted.draft, null);
    assert.equal(requestCount, 1, 'restart does not redispatch the interrupted admission');
    const reopenedScope = await reopened.scopeForAuthenticatedRequest(request());
    const recoveredTransport = await reopened.getTransportProgress(reopenedScope, runId);
    assert.equal(recoveredTransport.reservedBytes, transport.reservedBytes);
    assert.equal(recoveredTransport.spentBytes, transport.spentBytes);

    if (siblingAbortDelayMs === 0) {
      assert.equal(signalAtEntry, false, 'the control retains its valid initial stop allowance');
      assert.ok(stopAbortedAt - cancelledAt < 650, 'the original 500ms signal cap remains in force');
    } else {
      assert.ok(stopEnteredAt - cancelledAt >= 500, 'the stop callback starts after its own 500ms deadline');
      if (siblingAbortDelayMs < 750) {
        assert.ok(stopEnteredAt - cancelledAt < 750,
          'this case expires the stop allowance while the shared envelope still has time');
      }
      assert.equal(signalAtEntry, true, 'an expired stop allowance is checked at actual callback entry');
    }
  });
}

test('an entered stop callback cannot retain an expired signal after the run returns', { timeout: 8_000 }, async (t) => {
  const h = await harness(t);
  const body = eventHtml();
  let requestCount = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html' }, body);
  });
  t.after(() => server.close());
  let stopSignal;
  let signalAtEntry;
  let callbackReturnedAt;
  let stopCalls = 0;
  const frontier = frontierWithMethodOverrides(h.frontier, {
    stopRun: async (_scope, _runId, _reason, signal) => {
      stopCalls += 1;
      stopSignal = signal;
      signalAtEntry = signal.aborted;
      // Entry has a valid allowance. Synchronous host work consumes it, then
      // returns control before the overdue abort timer can run.
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 900);
      callbackReturnedAt = performance.now();
      return new Promise(() => {});
    },
  });
  let retentionEntered;
  const entered = new Promise((resolve) => { retentionEntered = resolve; });
  const cancellation = new AbortController();
  const runId = 'private-entered-stop-expiry';
  const seeds = [{ url: sourceUrl('/entered-stop') }];
  const limits = { maxDepth: 0, maxTransportAttemptAdmissions: 1, durationMs: 5_000 };
  const running = runPrivateRetrieval(h.makeInput({
    runId, server, frontier, seeds, limits, signal: cancellation.signal,
    retentionHandleFor() { retentionEntered(); return new Promise(() => {}); },
  }));
  assert.equal(await Promise.race([
    entered.then(() => 'retention'), running.then(() => 'completed-before-retention'),
  ]), 'retention');
  const cancelledAt = performance.now();
  cancellation.abort();
  const result = await running;
  const returnedAt = performance.now();
  const signalAbortedAtReturn = stopSignal?.aborted;
  t.diagnostic(JSON.stringify({ signalAtEntry, signalAbortedAtReturn, stopCalls, requestCount,
    callbackReturnMs: callbackReturnedAt - cancelledAt, cleanupAfterCallbackMs: returnedAt - callbackReturnedAt }));
  assert.equal(stopCalls, 1);
  assert.equal(signalAtEntry, false, 'the stop callback starts with a valid allowance');
  assert.ok(callbackReturnedAt - cancelledAt >= 750, 'synchronous work consumes the entire shared envelope');
  assert.ok(returnedAt - callbackReturnedAt < 100, 'return grants no new scheduled cleanup wait');
  assert.equal(result.status, 'cancelled');
  assert.equal(result.draft, null);
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transport.reservedBytes, 0);
  assert.equal(transport.spentBytes, body.length);
  const reopened = h.openFrontier();
  const restarted = await runPrivateRetrieval(h.makeInput({ runId, server, seeds, limits, frontier: reopened }));
  assert.equal(restarted.draft, null);
  assert.equal(requestCount, 1, 'restart cannot repeat the admitted request');
  const reopenedScope = await reopened.scopeForAuthenticatedRequest(request());
  const recoveredTransport = await reopened.getTransportProgress(reopenedScope, runId);
  assert.equal(recoveredTransport.reservedBytes, transport.reservedBytes);
  assert.equal(recoveredTransport.spentBytes, transport.spentBytes);
  assert.equal(signalAbortedAtReturn, true, 'the expired pending signal is revoked before the run returns');
});

test('external cancellation still resolves an admitted lease when stop persistence rejects', { timeout: 8_000 }, async (t) => {
  let retentionStarted;
  const retentionCallbackStarted = new Promise((resolve) => { retentionStarted = resolve; });
  const pendingRetention = new Promise(() => {});
  let requestCount = 0;
  let stopCalls = 0;
  let unresolvedCalls = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const frontier = frontierWithMethodOverrides(h.frontier, {
    stopRun: async () => {
      stopCalls += 1;
      throw new Error('simulated stop persistence failure');
    },
    markUnresolved: async (...args) => {
      unresolvedCalls += 1;
      return h.frontier.markUnresolved(...args);
    },
  });
  const runId = 'private-external-cancel-stop-error';
  const cancellation = new AbortController();
  const running = runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier,
    signal: cancellation.signal,
    seeds: [{ url: sourceUrl('/external-cancel-stop-error') }],
    limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1, durationMs: 5_000 },
    retentionHandleFor() {
      retentionStarted();
      return pendingRetention;
    },
  }));
  await retentionCallbackStarted;
  const cancelledAt = performance.now();
  cancellation.abort();
  const result = await running;
  const cleanupElapsedMs = performance.now() - cancelledAt;
  t.diagnostic(JSON.stringify({ cleanupElapsedMs, resultStatus: result.status, requestCount, stopCalls, unresolvedCalls }));
  assert.ok(cleanupElapsedMs <= 850,
    `a rejected stop write cannot exceed the 750ms cleanup budget plus 100ms scheduling tolerance (${cleanupElapsedMs.toFixed(1)}ms)`);
  assert.equal(result.status, 'cancelled');
  assert.equal(result.draft, null);
  assert.equal(requestCount, 1);
  assert.equal(stopCalls, 1);
  assert.ok(unresolvedCalls >= 1 && unresolvedCalls <= 2,
    'the run makes at most one uncertainty retry after its first bounded mark');
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshot.candidates[0].state, 'unresolved');
  assert.equal(snapshot.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.equal(snapshot.candidates[0].admittedAttemptCount, 1);
});

test('deadline returns with an unresolved admission when stop persistence never settles', { timeout: 8_000 }, async (t) => {
  let retentionStarted;
  let runAuthorizedAt;
  const retentionCallbackStarted = new Promise((resolve) => { retentionStarted = resolve; });
  const pendingRetention = new Promise(() => {});
  let requestCount = 0;
  let stopCalls = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const frontier = frontierWithMethodOverrides(h.frontier, {
    stopRun: async () => {
      stopCalls += 1;
      return new Promise(() => {});
    },
  });
  const runId = 'private-deadline-never-stop';
  const durationMs = 1_500;
  const running = runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier,
    seeds: [{ url: sourceUrl('/deadline-never-stop') }],
    limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1, durationMs },
    authorizeCurrent() {
      if (runAuthorizedAt === undefined) runAuthorizedAt = performance.now();
      return true;
    },
    retentionHandleFor() {
      retentionStarted();
      return pendingRetention;
    },
  }));
  await retentionCallbackStarted;
  const result = await running;
  const elapsedMs = performance.now() - runAuthorizedAt;
  t.diagnostic(JSON.stringify({ elapsedMs, durationMs, resultStatus: result.status, requestCount, stopCalls }));
  assert.ok(elapsedMs <= durationMs + 850,
    `deadline cleanup returns within the original duration plus the 750ms budget and 100ms scheduling tolerance (${elapsedMs.toFixed(1)}ms)`);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('deadline_exceeded'));
  assert.equal(requestCount, 1);
  assert.equal(stopCalls, 1);
  const interrupted = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(interrupted.candidates[0].state, 'unresolved');
  assert.equal(interrupted.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.equal(interrupted.candidates[0].admittedAttemptCount, 1);
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transport.reservedBytes, 0);
  assert.ok(transport.spentBytes > 0);

  const reopened = h.openFrontier();
  const reopenedScope = await reopened.scopeForAuthenticatedRequest(request());
  const restarted = await runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier: reopened,
    seeds: [{ url: sourceUrl('/deadline-never-stop') }],
    limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1, durationMs },
  }));
  assert.equal(restarted.draft, null);
  assert.equal(requestCount, 1, 'an expired restarted run cannot redispatch its unresolved admission');
  const afterRestart = await reopened.getSnapshot(reopenedScope, runId);
  assert.equal(afterRestart.candidates[0].state, 'unresolved');
  assert.equal(afterRestart.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.equal((await reopened.getTransportProgress(reopenedScope, runId)).spentBytes, transport.spentBytes);
});

test('late deadline delivery cannot renew cleanup for a stalled stop write', { timeout: 8_000 }, async (t) => {
  let retentionStarted;
  let runAuthorizedAt;
  let persistedDeadlineAtMs;
  let stopEnteredAt;
  const retentionCallbackStarted = new Promise((resolve) => { retentionStarted = resolve; });
  const pendingRetention = new Promise(() => {});
  let requestCount = 0;
  let stopCalls = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const frontier = frontierWithMethodOverrides(h.frontier, {
    createRun: async (...args) => {
      const created = await h.frontier.createRun(...args);
      persistedDeadlineAtMs = created.deadlineAtMs;
      return created;
    },
    stopRun: async () => {
      stopCalls += 1;
      stopEnteredAt = performance.now();
      return new Promise(() => {});
    },
  });
  const runId = 'private-delayed-deadline-never-stop';
  const durationMs = 1_500;
  const cancellation = new AbortController();
  t.after(() => cancellation.abort());
  const input = h.makeInput({
    runId, server, frontier, signal: cancellation.signal,
    seeds: [{ url: sourceUrl('/delayed-deadline-never-stop') }],
    limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1, durationMs },
    authorizeCurrent() {
      if (runAuthorizedAt === undefined) runAuthorizedAt = performance.now();
      return true;
    },
    retentionHandleFor() {
      retentionStarted();
      return pendingRetention;
    },
  });
  const runEnteredAt = performance.now();
  const running = runPrivateRetrieval(input);
  const phase = await Promise.race([
    retentionCallbackStarted.then(() => 'retention-entered'),
    running.then(() => 'returned-before-retention'),
  ]);
  assert.equal(phase, 'retention-entered', 'the admitted body completes before the deadline-delivery fault');
  const deadlineLowerAt = runEnteredAt + durationMs;
  const deadlineUpperAt = runAuthorizedAt + durationMs;
  // Start from the proven retention phase so a scheduled wake cannot race expiry.
  const blockStartedAt = performance.now();
  assert.ok(blockStartedAt < deadlineLowerAt, 'the controlled delay starts before the original deadline');
  assert.equal(stopCalls, 0, 'deadline cleanup has not started before the fault is injected');
  // Deliberately prevent timer delivery across the original deadline. The
  // blocking interval ends inside its existing 750ms cleanup envelope; it does
  // not demand an impossible return while JavaScript is still blocked.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0,
    Math.max(0, deadlineUpperAt + 300 - performance.now()));
  const blockEndedAt = performance.now();
  assert.ok(blockEndedAt >= deadlineUpperAt + 250, 'deadline delivery is delayed by at least 250ms');
  assert.ok(blockEndedAt < deadlineLowerAt + 650, 'at least 100ms of the original cleanup envelope remains');
  const result = await running;
  const elapsedMs = performance.now() - runAuthorizedAt;
  t.diagnostic(JSON.stringify({
    mode: 'synthetic-deadline-delivery-delay', durationMs, elapsedMs,
    runEnteredAt, runAuthorizedAt, deadlineLowerAt, deadlineUpperAt,
    blockStartedAt, blockEndedAt, stopEnteredAt, persistedDeadlineAtMs,
    resultStatus: result.status, requestCount, stopCalls,
  }));
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('deadline_exceeded'));
  assert.equal(requestCount, 1);
  assert.equal(stopCalls, 1);
  assert.ok(stopEnteredAt >= blockEndedAt, 'the stop write starts only after delayed deadline delivery');
  const interrupted = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(interrupted.deadlineAtMs, persistedDeadlineAtMs, 'fault injection cannot reset the stored deadline');
  assert.equal(interrupted.candidates[0].state, 'unresolved');
  assert.equal(interrupted.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.equal(interrupted.candidates[0].admittedAttemptCount, 1);
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transport.reservedBytes, 0);
  assert.ok(transport.spentBytes > 0);
  const reopened = h.openFrontier();
  const reopenedScope = await reopened.scopeForAuthenticatedRequest(request());
  const restarted = await runPrivateRetrieval(h.makeInput({
    runId, server, frontier: reopened,
    seeds: [{ url: sourceUrl('/delayed-deadline-never-stop') }],
    limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1, durationMs },
  }));
  assert.equal(restarted.draft, null);
  assert.equal(requestCount, 1, 'restart cannot redispatch the expired unresolved admission');
  const afterRestart = await reopened.getSnapshot(reopenedScope, runId);
  assert.equal(afterRestart.deadlineAtMs, persistedDeadlineAtMs);
  assert.equal(afterRestart.candidates[0].state, 'unresolved');
  assert.equal(afterRestart.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.deepEqual(await reopened.getTransportProgress(reopenedScope, runId), transport,
    'restart cannot release spent bytes or create another transport attempt');
  assert.ok(elapsedMs <= durationMs + 850,
    `late timer delivery cannot renew the original 750ms cleanup budget plus 100ms scheduling tolerance (${elapsedMs.toFixed(1)}ms)`);
});

for (const deadlineLagMs of [350, 900]) {
  test(`stop persistence shares the remaining cleanup signal after ${deadlineLagMs}ms of event-loop delay`, { timeout: 8_000 }, async (t) => {
    const durationMs = 1_500;
    let authorizedAt;
    let callbackReleasedAt;
    let stopSignalAbortedAt;
    let stopCalls = 0;
    let requestCount = 0;
    const server = await startFixture((_request, response) => {
      requestCount += 1;
      respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
    });
    t.after(() => server.close());
    const h = await harness(t);
    const frontier = frontierWithMethodOverrides(h.frontier, {
      stopRun: async (_scope, _runId, _reason, signal) => {
        stopCalls += 1;
        const observeAbort = () => { stopSignalAbortedAt = performance.now(); };
        if (signal.aborted) observeAbort();
        else signal.addEventListener('abort', observeAbort, { once: true });
        return new Promise(() => {});
      },
    });
    const runId = `private-delayed-deadline-${deadlineLagMs}`;
    const running = runPrivateRetrieval(h.makeInput({
      runId,
      server,
      frontier,
      seeds: [{ url: sourceUrl('/delayed-deadline') }],
      limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1, durationMs },
      authorizeCurrent() {
        if (authorizedAt === undefined) authorizedAt = performance.now();
        return true;
      },
      async retentionHandleFor() {
        const deadline = authorizedAt + durationMs;
        // Block on callback entry so a scheduled wake cannot race expiry.
        assert.ok(performance.now() < deadline, 'the fixture enters its blocking callback before expiry');
        // Deliberately prevent the deadline timer from running. This is a local
        // fixture, not a claim that JavaScript can interrupt synchronous work.
        const blocker = new Int32Array(new SharedArrayBuffer(4));
        Atomics.wait(blocker, 0, 0, Math.max(1, deadline + deadlineLagMs - performance.now()));
        callbackReleasedAt = performance.now();
        return new Promise(() => {});
      },
    }));
    const result = await running;
    const returnedAt = performance.now();
    const elapsedMs = returnedAt - authorizedAt;
    t.diagnostic(JSON.stringify({ deadlineLagMs, durationMs, elapsedMs,
      callbackLagMs: callbackReleasedAt - authorizedAt - durationMs,
      cleanupAfterCallbackMs: returnedAt - callbackReleasedAt,
      stopSignalLagMs: stopSignalAbortedAt - authorizedAt - durationMs }));
    assert.ok(callbackReleasedAt >= authorizedAt + durationMs + deadlineLagMs - 5,
      'the fixture actually delays deadline observation by the declared interval');
    if (deadlineLagMs < 750) {
      assert.ok(elapsedMs <= durationMs + 850,
        `delayed deadline handling shares the original 750ms cleanup envelope plus 100ms scheduling tolerance (${elapsedMs.toFixed(1)}ms)`);
    } else {
      assert.ok(returnedAt - callbackReleasedAt < 100,
        'an exhausted cleanup envelope does not start another scheduled wait');
    }
    assert.ok(Number.isFinite(stopSignalAbortedAt), 'stop persistence is signalled within the remaining cleanup envelope');
    assert.ok(stopSignalAbortedAt <= Math.max(authorizedAt + durationMs + 750, callbackReleasedAt) + 100,
      'the stop-persistence signal cannot restart its 500ms allowance after delayed handling');
    assert.equal(result.status, 'incomplete');
    assert.equal(result.draft, null);
    assert.ok(result.limitations.includes('deadline_exceeded'));
    assert.equal(stopCalls, 1);
    assert.equal(requestCount, 1);
    const snapshot = await h.frontier.getSnapshot(h.scope, runId);
    assert.notEqual(snapshot.candidates[0].state, 'completed');
    assert.equal(snapshot.candidates[0].admittedAttemptCount, 1);
    const transport = await h.frontier.getTransportProgress(h.scope, runId);
    assert.equal(transport.reservedBytes, 0, 'the completed response retains its actual byte settlement');
    assert.ok(transport.spentBytes > 0);
    const reopened = h.openFrontier();
    const restarted = await runPrivateRetrieval(h.makeInput({
      runId, server, frontier: reopened,
      seeds: [{ url: sourceUrl('/delayed-deadline') }],
      limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1, durationMs },
    }));
    assert.equal(restarted.draft, null);
    assert.equal(requestCount, 1, 'restart cannot redispatch the expired admitted candidate');
    const reopenedScope = await reopened.scopeForAuthenticatedRequest(request());
    assert.equal((await reopened.getTransportProgress(reopenedScope, runId)).spentBytes, transport.spentBytes);
  });
}

test('a stop before the first admission keeps the lease cancellation reason', { timeout: 8_000 }, async (t) => {
  let bindingStarted;
  const candidateBindingStarted = new Promise((resolve) => { bindingStarted = resolve; });
  let requestCount = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const frontier = frontierWithMethodOverrides(h.frontier, {
    getCandidateReceiptBinding: async () => {
      bindingStarted();
      return new Promise(() => {});
    },
  });
  const runId = 'private-cancel-before-admission';
  const running = runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier,
    seeds: [{ url: sourceUrl('/cancel-before-admission') }],
    limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1 },
  }));
  await candidateBindingStarted;
  await runStopWorker(h.frontierDirectory, runId);
  const result = await running;
  assert.equal(result.status, 'cancelled');
  assert.equal(result.draft, null);
  assert.equal(requestCount, 0);
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshot.candidates[0].state, 'unresolved');
  assert.equal(snapshot.candidates[0].unresolvedReason, 'cancelled_before_dispatch');
  assert.equal(snapshot.candidates[0].admittedAttemptCount, 0);
  assert.equal(snapshot.counters.transportAttemptAdmissions, 0);
  assert.ok(snapshot.stopReasons.some((entry) => entry.reason === 'cancelled'));
});

test('a denied first admission keeps the lease cancellation reason without recording admission', async (t) => {
  let deniedAdmissionCalls = 0;
  let requestCount = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const frontier = frontierWithMethodOverrides(h.frontier, {
    admitTransportHop: async () => {
      deniedAdmissionCalls += 1;
      return { state: 'denied', reason: 'decoded_budget' };
    },
  });
  const runId = 'private-budget-denied-before-admission';
  const result = await runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier,
    seeds: [{ url: sourceUrl('/budget-denied-before-admission') }],
    limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1 },
  }));
  assert.equal(result.draft, null);
  assert.equal(requestCount, 0);
  assert.equal(deniedAdmissionCalls, 1);
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshot.candidates[0].state, 'unresolved');
  assert.equal(snapshot.candidates[0].unresolvedReason, 'cancelled_before_dispatch');
  assert.equal(snapshot.candidates[0].admittedAttemptCount, 0);
  assert.equal(snapshot.counters.transportAttemptAdmissions, 0);
  assert.ok(snapshot.stopReasons.some((entry) => entry.reason === 'budget_denied'));
});

test('a stop after admission commit but before its result is observed preserves unknown transport state', { timeout: 8_000 }, async (t) => {
  let admissionCommitted;
  const admissionWasCommitted = new Promise((resolve) => { admissionCommitted = resolve; });
  let requestCount = 0;
  let ingestCalls = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const store = Object.create(null);
  let beginReceiptCalls = 0;
  let finalizeReceiptCalls = 0;
  for (const name of [
    'scopeForAuthenticatedRequest', 'appendFact', 'ingestDerivedPdfEvidence', 'ingestAssetSourceEvidence',
    'lookupEvidence', 'lookupFact', 'materializeSelected',
    'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.beginPrivateRunReceipt = async (...args) => {
    beginReceiptCalls += 1;
    return h.evidenceStore.beginPrivateRunReceipt(...args);
  };
  store.finalizePrivateRunReceipt = async (...args) => {
    finalizeReceiptCalls += 1;
    return h.evidenceStore.finalizePrivateRunReceipt(...args);
  };
  store.ingestEvidence = async (...args) => {
    ingestCalls += 1;
    return h.evidenceStore.ingestEvidence(...args);
  };
  const frontier = frontierWithMethodOverrides(h.frontier, {
    admitTransportHop: async (...args) => {
      const admission = await h.frontier.admitTransportHop(...args);
      assert.equal(admission.state, 'admitted');
      admissionCommitted();
      const signal = args[3];
      await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
      return admission;
    },
  });
  const runId = 'private-cancel-after-admission-commit';
  const running = runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier,
    store,
    seeds: [{ url: sourceUrl('/cancel-after-admission-commit') }],
    limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1 },
  }));
  await admissionWasCommitted;
  await runStopWorker(h.frontierDirectory, runId);
  const result = await running;
  assert.equal(result.status, 'cancelled');
  assert.equal(result.draft, null);
  assert.equal(requestCount, 0, 'an admission without an observed result does not reach the network');
  assert.equal(ingestCalls, 0);
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshot.candidates[0].state, 'unresolved');
  assert.equal(snapshot.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.equal(snapshot.candidates[0].admittedAttemptCount, 1);
  assert.equal(snapshot.counters.transportAttemptAdmissions, 1);
  assert.equal(beginReceiptCalls, 1);
  assert.equal(finalizeReceiptCalls, 0);
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.ok(transport.reservedBytes > 0,
    'the interrupted admission keeps its conservative reservation rather than inventing a refund');
  assert.ok(snapshot.stopReasons.some((entry) => entry.reason === 'cancelled'));
  const restarted = h.openFrontier();
  const restartedScope = await restarted.scopeForAuthenticatedRequest(request());
  const reopened = await restarted.getSnapshot(restartedScope, runId);
  assert.equal(reopened.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.equal(reopened.candidates[0].admittedAttemptCount, 1);
  const repeated = await runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier: restarted,
    store,
    seeds: [{ url: sourceUrl('/cancel-after-admission-commit') }],
    limits: { maxDepth: 0, maxTransportAttemptAdmissions: 1 },
  }));
  assert.equal(repeated.draft, null);
  assert.equal(requestCount, 0, 'reopening and retrying cannot redispatch an uncertain admitted request');
  assert.equal(ingestCalls, 0);
  assert.equal(beginReceiptCalls, 1, 'the restart does not begin another receipt for the unresolved candidate');
  assert.equal(finalizeReceiptCalls, 0, 'the interrupted receipt is not finalized by the restart');
  const afterRestart = await restarted.getSnapshot(restartedScope, runId);
  assert.equal(afterRestart.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.equal(afterRestart.candidates[0].admittedAttemptCount, 1);
  const transportAfterRestart = await restarted.getTransportProgress(restartedScope, runId);
  assert.equal(transportAfterRestart.reservedBytes, transport.reservedBytes);
});

test('the whole-run deadline bounds a never-resolving final retention callback after the last admission', { timeout: 10_000 }, async (t) => {
  const runDurationMs = 5_000;
  const settlementReturnLeadMs = 1_250;
  const maximumMappingWidthMs = 25;
  let retentionStarted;
  let resolveRetention;
  const retentionCallbackStarted = new Promise((resolve) => { retentionStarted = resolve; });
  const pendingRetention = new Promise((resolve) => { resolveRetention = resolve; });
  let requestCount = 0;
  let tcpConnectionCount = 0;
  let persistedDeadlineAtMs;
  let persistedDeadlineMapPerfBeforeMs;
  let persistedDeadlineWallSampleAtMs;
  let persistedDeadlineMapPerfAfterMs;
  let persistedDeadlineLowerPerfMs;
  let persistedDeadlineUpperPerfMs;
  let runEntryPerfBeforeMs;
  let runEntryPerfAfterMs;
  let runEntryDeadlineLowerPerfMs;
  let runEntryDeadlineUpperPerfMs;
  let effectiveDeadlineLowerPerfMs;
  let effectiveDeadlineUpperPerfMs;
  let requestReceivedAtPerfMs;
  let settlementReturnTargetPerfMs;
  let responseStartedAtPerfMs;
  let responseFinishedAtPerfMs;
  let bodySettledAtPerfMs;
  let settlementWrapperReturnAtPerfMs;
  let retentionCallbackStartedAtPerfMs;
  let runReturnedAtPerfMs;
  let retentionCalls = 0;
  const server = await startFixture(async (_request, response) => {
    requestCount += 1;
    requestReceivedAtPerfMs = performance.now();
    if (!Number.isFinite(effectiveDeadlineLowerPerfMs)) {
      response.destroy();
      return;
    }
    responseStartedAtPerfMs = performance.now();
    response.once('finish', () => { responseFinishedAtPerfMs = performance.now(); });
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  server.server.on('connection', () => { tcpConnectionCount += 1; });
  t.after(() => server.close());
  const h = await harness(t);
  let ingestCalls = 0;
  const store = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'appendFact', 'ingestDerivedPdfEvidence', 'ingestAssetSourceEvidence',
    'lookupEvidence', 'lookupFact', 'materializeSelected',
    'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.ingestEvidence = async (...args) => {
    ingestCalls += 1;
    return h.evidenceStore.ingestEvidence(...args);
  };
  const runId = 'private-deadline-retention';
  // Keep cold tenant schema creation outside the run budget; this case targets
  // the stalled retention callback after a real response body has settled.
  await h.evidenceStore.integritySnapshot(h.evidenceScope);
  await assert.rejects(h.frontier.getSnapshot(h.scope, runId), (error) => error?.code === 'FRONTIER_NOT_FOUND');
  const frontier = frontierWithMethodOverrides(h.frontier, {
    createRun: async (...args) => {
      const created = await h.frontier.createRun(...args);
      persistedDeadlineAtMs = created.deadlineAtMs;
      persistedDeadlineMapPerfBeforeMs = performance.now();
      persistedDeadlineWallSampleAtMs = Date.now();
      persistedDeadlineMapPerfAfterMs = performance.now();
      // Date.now() is millisecond-granular. Include its full quantization
      // interval rather than treating either sampled endpoint as exact.
      persistedDeadlineLowerPerfMs = persistedDeadlineMapPerfBeforeMs
        + (persistedDeadlineAtMs - persistedDeadlineWallSampleAtMs - 1);
      persistedDeadlineUpperPerfMs = persistedDeadlineMapPerfAfterMs
        + (persistedDeadlineAtMs - persistedDeadlineWallSampleAtMs + 1);
      effectiveDeadlineLowerPerfMs = Math.min(runEntryDeadlineLowerPerfMs, persistedDeadlineLowerPerfMs);
      effectiveDeadlineUpperPerfMs = Math.min(runEntryDeadlineUpperPerfMs, persistedDeadlineUpperPerfMs);
      return created;
    },
    settleTransportHopBodyComplete: async (...args) => {
      const settled = await h.frontier.settleTransportHopBodyComplete(...args);
      bodySettledAtPerfMs = performance.now();
      settlementReturnTargetPerfMs = effectiveDeadlineLowerPerfMs - settlementReturnLeadMs;
      settlementWrapperReturnAtPerfMs = await waitUntilPerfAtOrAfter(settlementReturnTargetPerfMs);
      return settled;
    },
  });
  runEntryPerfBeforeMs = performance.now();
  const running = runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier,
    seeds: [{ url: sourceUrl('/event') }],
    limits: { maxTransportAttemptAdmissions: 1, maxDepth: 0, durationMs: runDurationMs },
    store,
    retentionHandleFor() {
      retentionCalls += 1;
      retentionCallbackStartedAtPerfMs = performance.now();
      retentionStarted();
      return pendingRetention;
    },
  }));
  runEntryPerfAfterMs = performance.now();
  runEntryDeadlineLowerPerfMs = runEntryPerfBeforeMs + runDurationMs;
  runEntryDeadlineUpperPerfMs = runEntryPerfAfterMs + runDurationMs;
  const runOutcome = running.then(
    (result) => ({ kind: 'returned', result }),
    (error) => ({ kind: 'rejected', error }),
  );
  const phase = await Promise.race([
    retentionCallbackStarted.then(() => ({ kind: 'retention-callback-started' })),
    runOutcome,
  ]);
  if (phase.kind !== 'retention-callback-started') {
    const outcome = phase.kind === 'returned'
      ? JSON.stringify({ status: phase.result.status, limitations: phase.result.limitations })
      : String(phase.error);
    assert.fail(`run ended before final retention callback; diagnostics=${JSON.stringify({
      outcome,
      ingestCalls,
      tcpConnectionCount,
      requestCount,
      runEntryPerfBeforeMs,
      runEntryPerfAfterMs,
      persistedDeadlineAtMs: persistedDeadlineAtMs ?? null,
      effectiveDeadlineLowerPerfMs: effectiveDeadlineLowerPerfMs ?? null,
      effectiveDeadlineUpperPerfMs: effectiveDeadlineUpperPerfMs ?? null,
      requestReceivedAtPerfMs: requestReceivedAtPerfMs ?? null,
      settlementReturnTargetPerfMs: settlementReturnTargetPerfMs ?? null,
      responseStartedAtPerfMs: responseStartedAtPerfMs ?? null,
      bodySettledAtPerfMs: bodySettledAtPerfMs ?? null,
      settlementWrapperReturnAtPerfMs: settlementWrapperReturnAtPerfMs ?? null,
    })}`);
  }
  const remainingAtRetentionCallbackMs = effectiveDeadlineLowerPerfMs - retentionCallbackStartedAtPerfMs;
  const remainingAtRequestMs = effectiveDeadlineLowerPerfMs - requestReceivedAtPerfMs;
  const diagnostics = () => ({
    runDurationMs,
    settlementReturnLeadMs,
    tcpConnectionCount,
    requestCount,
    runEntryPerfBeforeMs,
    runEntryPerfAfterMs,
    runEntryBracketWidthMs: runEntryPerfAfterMs - runEntryPerfBeforeMs,
    runEntryDeadlineLowerPerfMs,
    runEntryDeadlineUpperPerfMs,
    persistedDeadlineAtMs,
    persistedDeadlineMapPerfBeforeMs,
    persistedDeadlineWallSampleAtMs,
    persistedDeadlineMapPerfAfterMs,
    persistedDeadlineMapSampleWidthMs: persistedDeadlineMapPerfAfterMs - persistedDeadlineMapPerfBeforeMs,
    persistedDeadlineLowerPerfMs,
    persistedDeadlineUpperPerfMs,
    persistedDeadlineMappedWidthMs: persistedDeadlineUpperPerfMs - persistedDeadlineLowerPerfMs,
    effectiveDeadlineLowerPerfMs,
    effectiveDeadlineUpperPerfMs,
    effectiveDeadlineIntervalWidthMs: effectiveDeadlineUpperPerfMs - effectiveDeadlineLowerPerfMs,
    requestReceivedAtPerfMs: requestReceivedAtPerfMs ?? null,
    remainingAtRequestMs,
    settlementReturnTargetPerfMs: settlementReturnTargetPerfMs ?? null,
    responseStartedAtPerfMs: responseStartedAtPerfMs ?? null,
    responseFinishedAtPerfMs: responseFinishedAtPerfMs ?? null,
    bodySettledAtPerfMs: bodySettledAtPerfMs ?? null,
    settlementWrapperReturnAtPerfMs: settlementWrapperReturnAtPerfMs ?? null,
    retentionCallbackStartedAtPerfMs,
    remainingAtRetentionCallbackMs,
    retentionCalls,
    runReturnedAtPerfMs: runReturnedAtPerfMs ?? null,
  });
  t.diagnostic(JSON.stringify(diagnostics()));
  assert.equal(tcpConnectionCount, 1, 'a real local TCP connection reached the fixture');
  assert.equal(requestCount, 1, 'a real local HTTP request reached the fixture');
  assert.ok(Number.isSafeInteger(persistedDeadlineAtMs), 'the frontier persisted its absolute deadline');
  assert.ok(runEntryPerfAfterMs - runEntryPerfBeforeMs <= maximumMappingWidthMs,
    'the monotonic run-entry sample interval is narrow and bounded');
  assert.ok(persistedDeadlineMapPerfAfterMs - persistedDeadlineMapPerfBeforeMs <= maximumMappingWidthMs,
    'the persisted wall-to-monotonic sample interval is narrow and bounded');
  assert.ok(persistedDeadlineUpperPerfMs - persistedDeadlineLowerPerfMs <= maximumMappingWidthMs,
    'the quantization-aware persisted deadline interval is narrow and bounded');
  assert.ok(effectiveDeadlineLowerPerfMs <= effectiveDeadlineUpperPerfMs);
  assert.ok(effectiveDeadlineUpperPerfMs - effectiveDeadlineLowerPerfMs <= maximumMappingWidthMs,
    'the effective deadline interval is narrow and bounded');
  assert.ok(remainingAtRequestMs > 500,
    'the admitted real HTTP request reached the fixture with more than 500ms remaining');
  assert.ok(responseStartedAtPerfMs >= requestReceivedAtPerfMs,
    'the real HTTP response started after the admitted request reached the fixture');
  assert.ok(responseFinishedAtPerfMs < settlementReturnTargetPerfMs,
    'the real HTTP response finished before the test phase gate');
  assert.ok(bodySettledAtPerfMs < settlementReturnTargetPerfMs,
    'the real HTTP body settled durably before the test phase gate');
  assert.ok(settlementWrapperReturnAtPerfMs >= settlementReturnTargetPerfMs,
    'the test wrapper returned from real body settlement at the original absolute phase target');
  assert.ok(settlementWrapperReturnAtPerfMs < retentionCallbackStartedAtPerfMs,
    'the final retention callback begins only after the settlement wrapper returns');
  assert.ok(bodySettledAtPerfMs < retentionCallbackStartedAtPerfMs,
    'the admitted response body settled in the frontier before final retention began');
  assert.ok(remainingAtRetentionCallbackMs >= 250 && remainingAtRetentionCallbackMs <= 1_500,
    'final retention begins with a bounded, measured amount of the original deadline remaining');
  assert.equal(retentionCalls, 1, 'the phase was reached by one final retention callback');

  const result = await running;
  runReturnedAtPerfMs = performance.now();
  t.diagnostic(JSON.stringify(diagnostics()));
  assert.ok(runReturnedAtPerfMs - retentionCallbackStartedAtPerfMs < 2_000,
    'the whole-run deadline releases the stalled final retention callback promptly');
  assert.ok(runReturnedAtPerfMs >= effectiveDeadlineLowerPerfMs - 100,
    'the admitted run did not return before the conservative absolute deadline bound');
  assert.ok(runReturnedAtPerfMs <= effectiveDeadlineUpperPerfMs + 2_000,
    'cleanup returns within a bounded interval after the conservative absolute deadline bound');
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('deadline_exceeded'));
  assert.equal(ingestCalls, 0);
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshot.deadlineAtMs, persistedDeadlineAtMs, 'the persisted absolute deadline remains unchanged');
  assert.ok(snapshot.stopReasons.some((entry) => entry.reason === 'attempt_limit'));
  assert.ok(snapshot.stopReasons.some((entry) => entry.reason === 'deadline'));
  assert.equal(snapshot.candidates[0].state, 'unresolved');
  assert.equal(snapshot.candidates[0].admittedAttemptCount, 1);
  assert.equal(snapshot.counters.transportAttemptAdmissions, 1);
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transport.reservedBytes, 0, 'the complete response was settled before retention paused');
  assert.ok(transport.spentBytes > 0);
  resolveRetention(h.createRetention());
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(ingestCalls, 0, 'a late retention result cannot write evidence after the deadline');
  const restarted = h.openFrontier();
  const restartedScope = await restarted.scopeForAuthenticatedRequest(request());
  const reopened = await restarted.getSnapshot(restartedScope, runId);
  assert.equal(reopened.deadlineAtMs, persistedDeadlineAtMs, 'reopening preserves the original absolute deadline');
  assert.equal(reopened.candidates[0].state, 'unresolved');
  assert.ok(reopened.stopReasons.some((entry) => entry.reason === 'deadline'));
});

test('the whole-run deadline bounds a never-resolving final retention callback under SQLite contention after the last admission', { timeout: 10_000 }, async (t) => {
  const runDurationMs = 5_000;
  const settlementReturnLeadMs = 1_250;
  const maximumMappingWidthMs = 25;
  let retentionStarted;
  let resolveRetention;
  const retentionCallbackStarted = new Promise((resolve) => { retentionStarted = resolve; });
  const pendingRetention = new Promise((resolve) => { resolveRetention = resolve; });
  let requestCount = 0;
  let tcpConnectionCount = 0;
  let persistedDeadlineAtMs;
  let persistedDeadlineMapPerfBeforeMs;
  let persistedDeadlineWallSampleAtMs;
  let persistedDeadlineMapPerfAfterMs;
  let persistedDeadlineLowerPerfMs;
  let persistedDeadlineUpperPerfMs;
  let runEntryPerfBeforeMs;
  let runEntryPerfAfterMs;
  let runEntryDeadlineLowerPerfMs;
  let runEntryDeadlineUpperPerfMs;
  let effectiveDeadlineLowerPerfMs;
  let effectiveDeadlineUpperPerfMs;
  let requestReceivedAtPerfMs;
  let settlementReturnTargetPerfMs;
  let responseStartedAtPerfMs;
  let responseFinishedAtPerfMs;
  let bodySettledAtPerfMs;
  let settlementWrapperReturnAtPerfMs;
  let retentionCallbackStartedAtPerfMs;
  let runReturnedAtPerfMs;
  let retentionCalls = 0;
  let frontierLock;
  let lockReleaseTimer;
  let lockStartedAtPerfMs;
  let lockReleasedAtPerfMs;
  let resolveLockReleased;
  const lockReleased = new Promise((resolve) => { resolveLockReleased = resolve; });
  const cleanupTrace = [];
  const server = await startFixture(async (_request, response) => {
    requestCount += 1;
    requestReceivedAtPerfMs = performance.now();
    if (!Number.isFinite(effectiveDeadlineLowerPerfMs)) {
      response.destroy();
      return;
    }
    responseStartedAtPerfMs = performance.now();
    response.once('finish', () => { responseFinishedAtPerfMs = performance.now(); });
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  server.server.on('connection', () => { tcpConnectionCount += 1; });
  t.after(() => server.close());
  const h = await harness(t);
  t.after(() => {
    if (lockReleaseTimer) clearTimeout(lockReleaseTimer);
    try { frontierLock?.exec('ROLLBACK'); } catch { /* The release timer may already have rolled it back. */ }
    try { frontierLock?.close(); } catch { /* Keep cleanup idempotent. */ }
  });
  let ingestCalls = 0;
  let beginReceiptCalls = 0;
  let finalizeReceiptCalls = 0;
  const store = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'appendFact', 'ingestDerivedPdfEvidence', 'ingestAssetSourceEvidence',
    'lookupEvidence', 'lookupFact', 'materializeSelected',
    'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.beginPrivateRunReceipt = async (...args) => {
    beginReceiptCalls += 1;
    return h.evidenceStore.beginPrivateRunReceipt(...args);
  };
  store.finalizePrivateRunReceipt = async (...args) => {
    finalizeReceiptCalls += 1;
    return h.evidenceStore.finalizePrivateRunReceipt(...args);
  };
  store.ingestEvidence = async (...args) => {
    ingestCalls += 1;
    return h.evidenceStore.ingestEvidence(...args);
  };
  const runId = 'private-deadline-retention';
  // Keep cold tenant schema creation outside the run budget; this case targets
  // the stalled retention callback after a real response body has settled.
  await h.evidenceStore.integritySnapshot(h.evidenceScope);
  await assert.rejects(h.frontier.getSnapshot(h.scope, runId), (error) => error?.code === 'FRONTIER_NOT_FOUND');
  const frontier = frontierWithMethodOverrides(h.frontier, {
    createRun: async (...args) => {
      const created = await h.frontier.createRun(...args);
      persistedDeadlineAtMs = created.deadlineAtMs;
      persistedDeadlineMapPerfBeforeMs = performance.now();
      persistedDeadlineWallSampleAtMs = Date.now();
      persistedDeadlineMapPerfAfterMs = performance.now();
      // Date.now() is millisecond-granular. Include its full quantization
      // interval rather than treating either sampled endpoint as exact.
      persistedDeadlineLowerPerfMs = persistedDeadlineMapPerfBeforeMs
        + (persistedDeadlineAtMs - persistedDeadlineWallSampleAtMs - 1);
      persistedDeadlineUpperPerfMs = persistedDeadlineMapPerfAfterMs
        + (persistedDeadlineAtMs - persistedDeadlineWallSampleAtMs + 1);
      effectiveDeadlineLowerPerfMs = Math.min(runEntryDeadlineLowerPerfMs, persistedDeadlineLowerPerfMs);
      effectiveDeadlineUpperPerfMs = Math.min(runEntryDeadlineUpperPerfMs, persistedDeadlineUpperPerfMs);
      return created;
    },
    settleTransportHopBodyComplete: async (...args) => {
      const settled = await h.frontier.settleTransportHopBodyComplete(...args);
      bodySettledAtPerfMs = performance.now();
      settlementReturnTargetPerfMs = effectiveDeadlineLowerPerfMs - settlementReturnLeadMs;
      settlementWrapperReturnAtPerfMs = await waitUntilPerfAtOrAfter(settlementReturnTargetPerfMs);
      return settled;
    },
    markUnresolved: async (...args) => {
      const reason = args[2]?.reason;
      cleanupTrace.push({ method: 'markUnresolved', phase: 'start', reason,
        sequence: cleanupTrace.length + 1, atPerfMs: performance.now() });
      try {
        const result = await h.frontier.markUnresolved(...args);
        cleanupTrace.push({ method: 'markUnresolved', phase: 'success', reason,
          sequence: cleanupTrace.length + 1, atPerfMs: performance.now() });
        return result;
      } catch (error) {
        cleanupTrace.push({ method: 'markUnresolved', phase: 'error', reason,
          code: error?.code ?? null, sequence: cleanupTrace.length + 1, atPerfMs: performance.now() });
        throw error;
      }
    },
    stopRun: async (...args) => {
      const reason = args[2];
      cleanupTrace.push({ method: 'stopRun', phase: 'start', reason,
        sequence: cleanupTrace.length + 1, atPerfMs: performance.now() });
      try {
        const result = await h.frontier.stopRun(...args);
        cleanupTrace.push({ method: 'stopRun', phase: 'success', reason,
          sequence: cleanupTrace.length + 1, atPerfMs: performance.now() });
        return result;
      } catch (error) {
        cleanupTrace.push({ method: 'stopRun', phase: 'error', reason,
          code: error?.code ?? null, sequence: cleanupTrace.length + 1, atPerfMs: performance.now() });
        throw error;
      }
    },
  });
  runEntryPerfBeforeMs = performance.now();
  const running = runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier,
    seeds: [{ url: sourceUrl('/event') }],
    limits: { maxTransportAttemptAdmissions: 1, maxDepth: 0, durationMs: runDurationMs },
    store,
    retentionHandleFor() {
      retentionCalls += 1;
      retentionCallbackStartedAtPerfMs = performance.now();
      if (!frontierLock) {
        const tenantHash = createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex');
        frontierLock = new DatabaseSync(path.join(h.frontierDirectory, tenantHash, 'frontier.sqlite'), { timeout: 0 });
        frontierLock.exec('BEGIN IMMEDIATE');
        lockStartedAtPerfMs = performance.now();
        const releaseDelayMs = Math.max(0, effectiveDeadlineLowerPerfMs - performance.now() + 350);
        lockReleaseTimer = setTimeout(() => {
          try { frontierLock.exec('ROLLBACK'); } catch { /* Test teardown also releases on failure. */ }
          try { frontierLock.close(); } catch { /* The test teardown remains idempotent. */ }
          lockReleasedAtPerfMs = performance.now();
          resolveLockReleased();
        }, releaseDelayMs);
      }
      retentionStarted();
      return pendingRetention;
    },
  }));
  runEntryPerfAfterMs = performance.now();
  runEntryDeadlineLowerPerfMs = runEntryPerfBeforeMs + runDurationMs;
  runEntryDeadlineUpperPerfMs = runEntryPerfAfterMs + runDurationMs;
  const runOutcome = running.then(
    (result) => ({ kind: 'returned', result }),
    (error) => ({ kind: 'rejected', error }),
  );
  const phase = await Promise.race([
    retentionCallbackStarted.then(() => ({ kind: 'retention-callback-started' })),
    runOutcome,
  ]);
  if (phase.kind !== 'retention-callback-started') {
    const outcome = phase.kind === 'returned'
      ? JSON.stringify({ status: phase.result.status, limitations: phase.result.limitations })
      : String(phase.error);
    assert.fail(`run ended before final retention callback; diagnostics=${JSON.stringify({
      outcome,
      ingestCalls,
      tcpConnectionCount,
      requestCount,
      runEntryPerfBeforeMs,
      runEntryPerfAfterMs,
      persistedDeadlineAtMs: persistedDeadlineAtMs ?? null,
      effectiveDeadlineLowerPerfMs: effectiveDeadlineLowerPerfMs ?? null,
      effectiveDeadlineUpperPerfMs: effectiveDeadlineUpperPerfMs ?? null,
      requestReceivedAtPerfMs: requestReceivedAtPerfMs ?? null,
      settlementReturnTargetPerfMs: settlementReturnTargetPerfMs ?? null,
      responseStartedAtPerfMs: responseStartedAtPerfMs ?? null,
      bodySettledAtPerfMs: bodySettledAtPerfMs ?? null,
      settlementWrapperReturnAtPerfMs: settlementWrapperReturnAtPerfMs ?? null,
    })}`);
  }
  const remainingAtRetentionCallbackMs = effectiveDeadlineLowerPerfMs - retentionCallbackStartedAtPerfMs;
  const remainingAtRequestMs = effectiveDeadlineLowerPerfMs - requestReceivedAtPerfMs;
  const diagnostics = () => ({
    runDurationMs,
    settlementReturnLeadMs,
    tcpConnectionCount,
    requestCount,
    runEntryPerfBeforeMs,
    runEntryPerfAfterMs,
    runEntryBracketWidthMs: runEntryPerfAfterMs - runEntryPerfBeforeMs,
    runEntryDeadlineLowerPerfMs,
    runEntryDeadlineUpperPerfMs,
    persistedDeadlineAtMs,
    persistedDeadlineMapPerfBeforeMs,
    persistedDeadlineWallSampleAtMs,
    persistedDeadlineMapPerfAfterMs,
    persistedDeadlineMapSampleWidthMs: persistedDeadlineMapPerfAfterMs - persistedDeadlineMapPerfBeforeMs,
    persistedDeadlineLowerPerfMs,
    persistedDeadlineUpperPerfMs,
    persistedDeadlineMappedWidthMs: persistedDeadlineUpperPerfMs - persistedDeadlineLowerPerfMs,
    effectiveDeadlineLowerPerfMs,
    effectiveDeadlineUpperPerfMs,
    effectiveDeadlineIntervalWidthMs: effectiveDeadlineUpperPerfMs - effectiveDeadlineLowerPerfMs,
    requestReceivedAtPerfMs: requestReceivedAtPerfMs ?? null,
    remainingAtRequestMs,
    settlementReturnTargetPerfMs: settlementReturnTargetPerfMs ?? null,
    responseStartedAtPerfMs: responseStartedAtPerfMs ?? null,
    responseFinishedAtPerfMs: responseFinishedAtPerfMs ?? null,
    bodySettledAtPerfMs: bodySettledAtPerfMs ?? null,
    settlementWrapperReturnAtPerfMs: settlementWrapperReturnAtPerfMs ?? null,
    retentionCallbackStartedAtPerfMs,
    remainingAtRetentionCallbackMs,
    retentionCalls,
    lockStartedAtPerfMs: lockStartedAtPerfMs ?? null,
    lockReleasedAtPerfMs: lockReleasedAtPerfMs ?? null,
    cleanupTrace,
    runReturnedAtPerfMs: runReturnedAtPerfMs ?? null,
  });
  t.diagnostic(JSON.stringify(diagnostics()));
  assert.equal(tcpConnectionCount, 1, 'a real local TCP connection reached the fixture');
  assert.equal(requestCount, 1, 'a real local HTTP request reached the fixture');
  assert.ok(Number.isSafeInteger(persistedDeadlineAtMs), 'the frontier persisted its absolute deadline');
  assert.ok(runEntryPerfAfterMs - runEntryPerfBeforeMs <= maximumMappingWidthMs,
    'the monotonic run-entry sample interval is narrow and bounded');
  assert.ok(persistedDeadlineMapPerfAfterMs - persistedDeadlineMapPerfBeforeMs <= maximumMappingWidthMs,
    'the persisted wall-to-monotonic sample interval is narrow and bounded');
  assert.ok(persistedDeadlineUpperPerfMs - persistedDeadlineLowerPerfMs <= maximumMappingWidthMs,
    'the quantization-aware persisted deadline interval is narrow and bounded');
  assert.ok(effectiveDeadlineLowerPerfMs <= effectiveDeadlineUpperPerfMs);
  assert.ok(effectiveDeadlineUpperPerfMs - effectiveDeadlineLowerPerfMs <= maximumMappingWidthMs,
    'the effective deadline interval is narrow and bounded');
  assert.ok(remainingAtRequestMs > 500,
    'the admitted real HTTP request reached the fixture with more than 500ms remaining');
  assert.ok(responseStartedAtPerfMs >= requestReceivedAtPerfMs,
    'the real HTTP response started after the admitted request reached the fixture');
  assert.ok(responseFinishedAtPerfMs < settlementReturnTargetPerfMs,
    'the real HTTP response finished before the test phase gate');
  assert.ok(bodySettledAtPerfMs < settlementReturnTargetPerfMs,
    'the real HTTP body settled durably before the test phase gate');
  assert.ok(settlementWrapperReturnAtPerfMs >= settlementReturnTargetPerfMs,
    'the test wrapper returned from real body settlement at the original absolute phase target');
  assert.ok(settlementWrapperReturnAtPerfMs < retentionCallbackStartedAtPerfMs,
    'the final retention callback begins only after the settlement wrapper returns');
  assert.ok(bodySettledAtPerfMs < retentionCallbackStartedAtPerfMs,
    'the admitted response body settled in the frontier before final retention began');
  assert.ok(remainingAtRetentionCallbackMs >= 250 && remainingAtRetentionCallbackMs <= 1_500,
    'final retention begins with a bounded, measured amount of the original deadline remaining');
  assert.equal(retentionCalls, 1, 'the phase was reached by one final retention callback');

  const result = await running;
  runReturnedAtPerfMs = performance.now();
  await lockReleased;
  t.diagnostic(JSON.stringify(diagnostics()));
  assert.ok(runReturnedAtPerfMs - retentionCallbackStartedAtPerfMs < 2_000,
    'the whole-run deadline releases the stalled final retention callback promptly');
  assert.ok(runReturnedAtPerfMs >= effectiveDeadlineLowerPerfMs - 100,
    'the admitted run did not return before the conservative absolute deadline bound');
  const cleanupAfterDeadlineMs = runReturnedAtPerfMs - effectiveDeadlineUpperPerfMs;
  assert.ok(cleanupAfterDeadlineMs <= 850,
    `cleanup returns within the shared 750ms envelope plus 100ms SQLite/timer tolerance (${cleanupAfterDeadlineMs.toFixed(1)}ms)`);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('deadline_exceeded'));
  assert.equal(ingestCalls, 0);
  assert.ok(lockStartedAtPerfMs >= retentionCallbackStartedAtPerfMs,
    'the lock begins only after final retention starts');
  assert.ok(lockReleasedAtPerfMs >= effectiveDeadlineLowerPerfMs + 300,
    'the writer lock outlasts the first bounded cleanup attempt');
  assert.ok(cleanupTrace.some((entry) => entry.method === 'markUnresolved'
    && entry.phase === 'error' && entry.code === 'FRONTIER_STOPPED'),
  'the first unresolved cleanup attempt reaches its existing abort bound under SQLite contention');
  const unresolvedAttempts = cleanupTrace.filter((entry) => entry.method === 'markUnresolved');
  assert.ok(unresolvedAttempts.length >= 2, 'a second cleanup attempt follows the bounded first attempt');
  assert.ok(unresolvedAttempts.every((entry) => entry.reason === 'dispatch_state_unknown'),
    'every cleanup attempt preserves the possible admission state');
  assert.ok(unresolvedAttempts.some((entry) => entry.phase === 'success'),
    'the repeated uncertainty resolution succeeds after the writer lock releases');
  const firstResolutionFailure = cleanupTrace.findIndex((entry) => entry.method === 'markUnresolved'
    && entry.phase === 'error');
  const deadlineStopSuccess = cleanupTrace.findIndex((entry) => entry.method === 'stopRun'
    && entry.phase === 'success');
  const postStopResolution = cleanupTrace.findIndex((entry, index) => index > firstResolutionFailure
    && entry.method === 'markUnresolved' && entry.phase === 'success');
  assert.ok(firstResolutionFailure >= 0 && deadlineStopSuccess > firstResolutionFailure
    && postStopResolution > deadlineStopSuccess,
  'the recovery write waits until the bounded deadline stop releases its competing writer transaction');
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshot.deadlineAtMs, persistedDeadlineAtMs, 'the persisted absolute deadline remains unchanged');
  assert.ok(snapshot.stopReasons.some((entry) => entry.reason === 'attempt_limit'));
  assert.ok(snapshot.stopReasons.some((entry) => entry.reason === 'deadline'));
  assert.equal(snapshot.candidates[0].state, 'unresolved');
  assert.equal(snapshot.candidates[0].admittedAttemptCount, 1);
  assert.equal(snapshot.counters.transportAttemptAdmissions, 1);
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transport.reservedBytes, 0, 'the complete response was settled before retention paused');
  assert.ok(transport.spentBytes > 0);
  resolveRetention(h.createRetention());
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(ingestCalls, 0, 'a late retention result cannot write evidence after the deadline');
  const restarted = h.openFrontier();
  const restartedScope = await restarted.scopeForAuthenticatedRequest(request());
  const reopened = await restarted.getSnapshot(restartedScope, runId);
  assert.equal(reopened.deadlineAtMs, persistedDeadlineAtMs, 'reopening preserves the original absolute deadline');
  assert.equal(reopened.candidates[0].state, 'unresolved');
  assert.equal(reopened.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.equal(reopened.candidates[0].admittedAttemptCount, 1);
  const reopenedTransport = await restarted.getTransportProgress(restartedScope, runId);
  assert.equal(reopenedTransport.reservedBytes, 0);
  assert.ok(reopened.stopReasons.some((entry) => entry.reason === 'deadline'));
  assert.equal(beginReceiptCalls, 1);
  assert.equal(finalizeReceiptCalls, 0);
  const repeated = await runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier: restarted,
    store,
    seeds: [{ url: sourceUrl('/event') }],
    limits: { maxTransportAttemptAdmissions: 1, maxDepth: 0, durationMs: runDurationMs },
  }));
  assert.equal(repeated.draft, null);
  assert.equal(requestCount, 1, 'the restarted run cannot dispatch another HTTP request');
  assert.equal(tcpConnectionCount, 1);
  assert.equal(ingestCalls, 0);
  assert.equal(beginReceiptCalls, 1, 'the restart does not begin another receipt for the unresolved candidate');
  assert.equal(finalizeReceiptCalls, 0, 'the interrupted receipt is not finalized after restart');
  const afterRestart = await restarted.getSnapshot(restartedScope, runId);
  assert.equal(afterRestart.deadlineAtMs, persistedDeadlineAtMs);
  assert.equal(afterRestart.candidates[0].unresolvedReason, 'dispatch_state_unknown');
  assert.equal(afterRestart.candidates[0].admittedAttemptCount, 1);
  assert.equal((await restarted.getTransportProgress(restartedScope, runId)).reservedBytes, 0);
});

test('a delayed createRun cannot create a durable run after timeout or dispatch late', { timeout: 8_000 }, async (t) => {
  let releaseCreate;
  let markAttempted;
  const createGate = new Promise((resolve) => { releaseCreate = resolve; });
  const lateCreateAttempted = new Promise((resolve) => { markAttempted = resolve; });
  let requestCount = 0;
  const server = await startFixture((_request, response) => {
    requestCount += 1;
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const frontier = frontierWithDelayedCreateRun(h.frontier, createGate, markAttempted);
  const runId = 'private-timeout-during-create';
  const running = runPrivateRetrieval(h.makeInput({
    runId,
    server,
    frontier,
    seeds: [{ url: sourceUrl('/event') }],
    limits: { durationMs: 100 },
  }));
  const timeoutObservedAt = Date.now();
  const result = await running;
  assert.ok(Date.now() - timeoutObservedAt < 2_000);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('deadline_exceeded'));
  assert.equal(requestCount, 0);

  releaseCreate();
  await lateCreateAttempted;
  await assert.rejects(h.frontier.getSnapshot(h.scope, runId), (error) => error?.code === 'FRONTIER_NOT_FOUND');
});

test('the whole-run deadline interrupts an already-admitted last request and keeps uncertain capacity reserved', { timeout: 10_000 }, async (t) => {
  const runDurationMs = 5_000;
  const preCreateDelayMs = 200;
  const closeEventObservationTimeoutMs = 1_000;
  let requestCount = 0;
  let tcpConnectionCount = 0;
  let responseClosed = false;
  let socketClosed = false;
  let lateBodyAttempted = false;
  let lateBodyDelivered = false;
  let lateBodySawClosedResponse = false;
  let persistedDeadlineAtMs;
  let createRunEnteredAtPerfMs;
  let createRunInvokedAtPerfMs;
  let preCreateDelayElapsedMs;
  let persistedDeadlineMapPerfBeforeMs;
  let persistedDeadlineWallSampleAtMs;
  let persistedDeadlineMapPerfAfterMs;
  let persistedDeadlineLowerPerfMs;
  let persistedDeadlineUpperPerfMs;
  let runEntryPerfBeforeMs;
  let runEntryPerfAfterMs;
  let runEntryDeadlineLowerPerfMs;
  let runEntryDeadlineUpperPerfMs;
  let effectiveDeadlineLowerPerfMs;
  let effectiveDeadlineUpperPerfMs;
  let requestReceivedAtPerfMs;
  let responseClosedAtPerfMs;
  let socketClosedAtPerfMs;
  let lateBodyAttemptedAtPerfMs;
  let serverResponse;
  let resolveRequestReceived;
  let resolveResponseClosed;
  let resolveSocketClosed;
  let resolveLateBodyAttempt;
  const requestReceived = new Promise((resolve) => { resolveRequestReceived = resolve; });
  const responseClosedEvent = new Promise((resolve) => { resolveResponseClosed = resolve; });
  const socketClosedEvent = new Promise((resolve) => { resolveSocketClosed = resolve; });
  const lateBodyAttempt = new Promise((resolve) => { resolveLateBodyAttempt = resolve; });
  const server = await startFixture((_request, response) => {
    serverResponse = response;
    requestCount += 1;
    requestReceivedAtPerfMs = performance.now();
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.write('<!doctype html>');
    response.once('close', () => {
      responseClosed = true;
      responseClosedAtPerfMs = performance.now();
      resolveResponseClosed();
    });
    resolveRequestReceived();
  });
  server.server.on('connection', (socket) => {
    tcpConnectionCount += 1;
    socket.once('close', () => {
      socketClosed = true;
      socketClosedAtPerfMs = performance.now();
      resolveSocketClosed();
    });
  });
  t.after(async () => {
    await server.close();
  });
  const h = await harness(t);
  const runId = 'private-deadline-last-hop';
  const frontier = frontierWithMethodOverrides(h.frontier, {
    createRun: async (...args) => {
      createRunEnteredAtPerfMs = performance.now();
      const preCreateTargetPerfMs = createRunEnteredAtPerfMs + preCreateDelayMs;
      while (performance.now() < preCreateTargetPerfMs) {
        const remainingDelayMs = preCreateTargetPerfMs - performance.now();
        await new Promise((resolve) => setTimeout(resolve, Math.max(1, Math.ceil(remainingDelayMs))));
      }
      createRunInvokedAtPerfMs = performance.now();
      preCreateDelayElapsedMs = createRunInvokedAtPerfMs - createRunEnteredAtPerfMs;
      const created = await h.frontier.createRun(...args);
      persistedDeadlineAtMs = created.deadlineAtMs;
      persistedDeadlineMapPerfBeforeMs = performance.now();
      persistedDeadlineWallSampleAtMs = Date.now();
      persistedDeadlineMapPerfAfterMs = performance.now();
      // Date.now() is millisecond-granular. These sample intervals conservatively
      // map the persisted wall deadline into the monotonic clock without selecting
      // one sample endpoint as an exact deadline.
      persistedDeadlineLowerPerfMs = persistedDeadlineMapPerfBeforeMs
        + (persistedDeadlineAtMs - persistedDeadlineWallSampleAtMs - 1);
      persistedDeadlineUpperPerfMs = persistedDeadlineMapPerfAfterMs
        + (persistedDeadlineAtMs - persistedDeadlineWallSampleAtMs + 1);
      effectiveDeadlineLowerPerfMs = Math.min(runEntryDeadlineLowerPerfMs, persistedDeadlineLowerPerfMs);
      effectiveDeadlineUpperPerfMs = Math.min(runEntryDeadlineUpperPerfMs, persistedDeadlineUpperPerfMs);
      return created;
    },
  });
  const input = h.makeInput({
    runId,
    server,
    frontier,
    seeds: [{ url: sourceUrl('/slow-body') }],
    limits: { maxTransportAttemptAdmissions: 1, maxDepth: 0, durationMs: runDurationMs },
  });
  runEntryPerfBeforeMs = performance.now();
  const running = runPrivateRetrieval(input);
  runEntryPerfAfterMs = performance.now();
  runEntryDeadlineLowerPerfMs = runEntryPerfBeforeMs + runDurationMs;
  runEntryDeadlineUpperPerfMs = runEntryPerfAfterMs + runDurationMs;
  const runOutcome = running.then(
    (result) => ({ kind: 'returned', result }),
    (error) => ({ kind: 'rejected', error }),
  );
  const phase = await Promise.race([
    requestReceived.then(() => ({ kind: 'request-received' })),
    runOutcome,
  ]);
  if (phase.kind !== 'request-received') {
    const outcome = phase.kind === 'returned'
      ? JSON.stringify({ status: phase.result.status, limitations: phase.result.limitations })
      : String(phase.error);
    assert.fail(`run ended before a real local HTTP request arrived; requestCount=${requestCount}; elapsedMs=${performance.now() - runEntryPerfBeforeMs}; outcome=${outcome}`);
  }
  const remainingAtRequestMs = effectiveDeadlineLowerPerfMs - requestReceivedAtPerfMs;
  assert.equal(tcpConnectionCount, 1, 'the local fixture observed a real TCP connection');
  assert.equal(requestCount, 1, 'the local HTTP handler observed the admitted request');
  assert.ok(Number.isSafeInteger(persistedDeadlineAtMs), 'the real frontier persisted the original run deadline');
  assert.ok(preCreateDelayElapsedMs >= preCreateDelayMs, 'createRun was phase-shifted by the full bounded real-time delay');
  assert.ok(persistedDeadlineLowerPerfMs > runEntryDeadlineUpperPerfMs,
    'the newly persisted deadline maps later than the entire run-entry deadline interval');
  assert.ok(effectiveDeadlineLowerPerfMs <= effectiveDeadlineUpperPerfMs, 'the effective deadline bounds are ordered');
  assert.ok(remainingAtRequestMs > 500, 'the request reached the fixture with a bounded window left on the original deadline');
  assert.ok(requestReceivedAtPerfMs < effectiveDeadlineLowerPerfMs,
    'the request arrived before the conservative lower bound of the effective whole-run deadline');

  const result = await running;
  const runReturnedAtPerfMs = performance.now();
  const deadlineReturnLagFromUpperMs = runReturnedAtPerfMs - effectiveDeadlineUpperPerfMs;
  const closeWaitStartedAtPerfMs = performance.now();
  let closeEventsObserved;
  let closeWaitTimer;
  try {
    closeEventsObserved = await Promise.race([
      Promise.all([responseClosedEvent, socketClosedEvent]).then(() => true),
      new Promise((resolve) => {
        closeWaitTimer = setTimeout(() => resolve(false), closeEventObservationTimeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(closeWaitTimer);
  }
  const closeWaitFinishedAtPerfMs = performance.now();
  t.diagnostic(JSON.stringify({
    preCreateDelayTargetMs: preCreateDelayMs,
    preCreateDelayElapsedMs,
    createRunEnteredAtPerfMs,
    createRunInvokedAtPerfMs,
    runEntryPerfBeforeMs,
    runEntryPerfAfterMs,
    runEntryBracketWidthMs: runEntryPerfAfterMs - runEntryPerfBeforeMs,
    runEntryDeadlineLowerPerfMs,
    runEntryDeadlineUpperPerfMs,
    persistedDeadlineAtMs,
    persistedDeadlineMapPerfBeforeMs,
    persistedDeadlineWallSampleAtMs,
    persistedDeadlineMapPerfAfterMs,
    persistedDeadlineMapSampleWidthMs: persistedDeadlineMapPerfAfterMs - persistedDeadlineMapPerfBeforeMs,
    persistedDeadlineLowerPerfMs,
    persistedDeadlineUpperPerfMs,
    persistedDeadlineMappedWidthMs: persistedDeadlineUpperPerfMs - persistedDeadlineLowerPerfMs,
    effectiveDeadlineLowerPerfMs,
    effectiveDeadlineUpperPerfMs,
    effectiveDeadlineIntervalWidthMs: effectiveDeadlineUpperPerfMs - effectiveDeadlineLowerPerfMs,
    requestReceivedAtPerfMs: requestReceivedAtPerfMs ?? null,
    remainingAtRequestMs: Number.isFinite(requestReceivedAtPerfMs)
      ? effectiveDeadlineLowerPerfMs - requestReceivedAtPerfMs : null,
    tcpConnectionCount,
    requestCount,
    runReturnedAtPerfMs,
    deadlineReturnLagFromUpperMs,
    deadlineReturnLagFromLowerMs: runReturnedAtPerfMs - effectiveDeadlineLowerPerfMs,
    closeWaitStartedAtPerfMs,
    closeWaitFinishedAtPerfMs,
    closeWaitLagMs: closeWaitFinishedAtPerfMs - closeWaitStartedAtPerfMs,
    closeEventObservationTimeoutMs,
    closeEventsObserved,
    responseClosed,
    responseClosedAtPerfMs: responseClosedAtPerfMs ?? null,
    socketClosed,
    socketClosedAtPerfMs: socketClosedAtPerfMs ?? null,
    lateBodyAttempted,
    lateBodyAttemptedAtPerfMs: lateBodyAttemptedAtPerfMs ?? null,
    lateBodySawClosedResponse,
    lateBodyDelivered,
  }));
  assert.ok(runReturnedAtPerfMs <= effectiveDeadlineUpperPerfMs + 2_000,
    'the final authorized hop returns promptly after the upper bound of the effective run deadline');
  assert.equal(closeEventsObserved, true, 'both local response and TCP socket close events are observed within the bounded wait');
  assert.ok(closeWaitFinishedAtPerfMs - closeWaitStartedAtPerfMs <= closeEventObservationTimeoutMs,
    'both close events are observed within one second after the run returns');
  assert.ok(responseClosedAtPerfMs >= effectiveDeadlineLowerPerfMs - 100,
    'the active local response remains open until the original run deadline');
  assert.ok(socketClosedAtPerfMs >= effectiveDeadlineLowerPerfMs - 100,
    'the local TCP socket remains open until the original run deadline');
  assert.ok(responseClosed && socketClosed, 'both observed close events came from real local fixture objects');

  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('deadline_exceeded'));
  const snapshotBeforeLateBody = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshotBeforeLateBody.deadlineAtMs, persistedDeadlineAtMs, 'phase synchronization did not reset the persisted deadline');
  assert.ok(snapshotBeforeLateBody.stopReasons.some((entry) => entry.reason === 'attempt_limit'));
  assert.ok(snapshotBeforeLateBody.stopReasons.some((entry) => entry.reason === 'deadline'));
  assert.equal(snapshotBeforeLateBody.counters.transportAttemptAdmissions, 1);
  assert.equal(snapshotBeforeLateBody.candidates[0].state, 'unresolved');
  assert.equal(snapshotBeforeLateBody.candidates[0].admittedAttemptCount, 1);
  const transportBeforeLateBody = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transportBeforeLateBody.reservedBytes, 20 * 1024 * 1024);
  assert.equal(transportBeforeLateBody.spentBytes, 0);
  assert.equal(transportBeforeLateBody.states.unknown, 1);
  assert.equal(responseClosed, true, 'deadline abort closes the local response socket');
  assert.equal(socketClosed, true, 'the TCP socket is closed before the late body attempt');

  const lateBodyTargetPerfMs = effectiveDeadlineUpperPerfMs + 250;
  await waitUntilPerfAtOrAfter(lateBodyTargetPerfMs);
  lateBodyAttempted = true;
  lateBodyAttemptedAtPerfMs = performance.now();
  lateBodySawClosedResponse = serverResponse.destroyed;
  if (!serverResponse.destroyed) {
    lateBodyDelivered = true;
    serverResponse.end(eventHtml());
  }
  resolveLateBodyAttempt();

  await lateBodyAttempt;
  assert.equal(lateBodyAttempted, true, 'the scheduled late body phase actually ran');
  assert.ok(lateBodyAttemptedAtPerfMs >= lateBodyTargetPerfMs,
    'the late body phase begins no earlier than 250ms after the upper bound of the effective original deadline');
  assert.equal(lateBodySawClosedResponse, true, 'the response was already closed at the late body phase');
  assert.equal(lateBodyDelivered, false, 'a late body cannot reach the closed client');
  assert.ok(responseClosedAtPerfMs < lateBodyAttemptedAtPerfMs);
  assert.ok(socketClosedAtPerfMs < lateBodyAttemptedAtPerfMs);
  const snapshotAfterLateBody = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshotAfterLateBody.deadlineAtMs, persistedDeadlineAtMs);
  assert.deepEqual(
    snapshotAfterLateBody.candidates.map(({ candidateId, state, admittedAttemptCount }) => ({ candidateId, state, admittedAttemptCount })),
    snapshotBeforeLateBody.candidates.map(({ candidateId, state, admittedAttemptCount }) => ({ candidateId, state, admittedAttemptCount })),
    'the late server callback cannot complete or otherwise change the unresolved candidate',
  );
  assert.deepEqual(
    snapshotAfterLateBody.stopReasons.map((entry) => entry.reason).sort(),
    snapshotBeforeLateBody.stopReasons.map((entry) => entry.reason).sort(),
  );
  const transportAfterLateBody = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transportAfterLateBody.reservedBytes, transportBeforeLateBody.reservedBytes);
  assert.equal(transportAfterLateBody.spentBytes, transportBeforeLateBody.spentBytes);
  assert.deepEqual(transportAfterLateBody.states, transportBeforeLateBody.states);
  t.diagnostic(JSON.stringify({
    runEntryPerfBeforeMs,
    runEntryPerfAfterMs,
    runEntryBracketWidthMs: runEntryPerfAfterMs - runEntryPerfBeforeMs,
    persistedDeadlineLowerPerfMs,
    persistedDeadlineUpperPerfMs,
    persistedDeadlineMappedWidthMs: persistedDeadlineUpperPerfMs - persistedDeadlineLowerPerfMs,
    effectiveDeadlineLowerPerfMs,
    effectiveDeadlineUpperPerfMs,
    effectiveDeadlineIntervalWidthMs: effectiveDeadlineUpperPerfMs - effectiveDeadlineLowerPerfMs,
    persistedDeadlineAtMs,
    requestReceivedAtPerfMs,
    remainingAtRequestMs,
    tcpConnectionCount,
    requestCount,
    responseClosedAtPerfMs,
    socketClosedAtPerfMs,
    lateBodyAttemptedAtPerfMs,
    lateBodyDelivered,
    deadlineReturnLagFromUpperMs,
    reservedBytesAfterLateBody: transportAfterLateBody.reservedBytes,
    spentBytesAfterLateBody: transportAfterLateBody.spentBytes,
    statesAfterLateBody: transportAfterLateBody.states,
  }));
});

test('a remote stop during final evidence lookup returns promptly without materializing a draft', { timeout: 8_000 }, async (t) => {
  let lookupStarted;
  const finalLookupStarted = new Promise((resolve) => { lookupStarted = resolve; });
  const server = await startFixture((_request, response) => {
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-cancel-final-lookup';
  let materializeCalls = 0;
  const store = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'ingestEvidence', 'appendFact', 'ingestDerivedPdfEvidence', 'ingestAssetSourceEvidence',
    'lookupFact', 'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.materializeSelected = async (...args) => {
    materializeCalls += 1;
    return h.evidenceStore.materializeSelected(...args);
  };
  store.lookupEvidence = async (scope, evidenceId) => {
    const snapshot = await h.frontier.getSnapshot(h.scope, runId);
    if (snapshot.candidates.length > 0 && snapshot.candidates.every((candidate) => candidate.state === 'completed')) {
      lookupStarted();
      return new Promise(() => {});
    }
    return h.evidenceStore.lookupEvidence(scope, evidenceId);
  };
  const running = runPrivateRetrieval(h.makeInput({
    runId, server, store, seeds: [{ url: sourceUrl('/event') }],
  }));
  await finalLookupStarted;
  const stopStarted = Date.now();
  await runStopWorker(h.frontierDirectory, runId);
  const result = await running;
  assert.ok(Date.now() - stopStarted < 2_000, 'the active watcher interrupts a stalled pre-seal lookup');
  assert.equal(result.status, 'cancelled');
  assert.equal(result.draft, null);
  assert.equal(materializeCalls, 2, 'only the source composer materializations ran');
});

test('the whole-run deadline withholds a final materialization that never returns after sealing', { timeout: 8_000 }, async (t) => {
  let materializationStarted;
  const finalMaterializationStarted = new Promise((resolve) => { materializationStarted = resolve; });
  const server = await startFixture((_request, response) => {
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-deadline-final-materialize';
  let materializeCalls = 0;
  let persistedDeadlineAtMs;
  let releaseSealCompletedAtMs;
  let releaseSealState;
  let sealWrapperReturnedAtMs;
  let sealReturnGateWaitMs;
  let finalMaterializationEnteredAtMs;
  let finalEntryRemainingAtMs;
  const store = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'ingestEvidence', 'appendFact', 'ingestDerivedPdfEvidence', 'ingestAssetSourceEvidence',
    'lookupEvidence', 'lookupFact', 'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.materializeSelected = async (...args) => {
    materializeCalls += 1;
    if (materializeCalls < 3) return h.evidenceStore.materializeSelected(...args);
    assert.ok(releaseSealCompletedAtMs <= Date.now() && ['sealed', 'already_sealed'].includes(releaseSealState),
      'the final selected materialization follows a successful durable release seal');
    assert.ok(Number.isSafeInteger(persistedDeadlineAtMs), 'the real frontier run persisted its original deadline');
    finalMaterializationEnteredAtMs = Date.now();
    finalEntryRemainingAtMs = persistedDeadlineAtMs - finalMaterializationEnteredAtMs;
    assert.ok(finalEntryRemainingAtMs > 0, 'the sealed final materialization is entered before the original deadline');
    materializationStarted();
    return new Promise(() => {});
  };
  const startedAt = Date.now();
  const frontier = frontierWithMethodOverrides(h.frontier, {
    createRun: async (...args) => {
      const created = await h.frontier.createRun(...args);
      persistedDeadlineAtMs = created.deadlineAtMs;
      return created;
    },
    sealPrivateDraft: async (...args) => {
      const sealed = await h.frontier.sealPrivateDraft(...args);
      releaseSealState = sealed.state;
      releaseSealCompletedAtMs = Date.now();
      const gateUntilMs = persistedDeadlineAtMs - 1_400;
      const waitMs = Math.max(0, gateUntilMs - Date.now());
      if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
      sealReturnGateWaitMs = Date.now() - releaseSealCompletedAtMs;
      sealWrapperReturnedAtMs = Date.now();
      return sealed;
    },
  });
  const running = runPrivateRetrieval(h.makeInput({
    runId,
    server,
    store,
    frontier,
    seeds: [{ url: sourceUrl('/event') }],
    limits: { maxTransportAttemptAdmissions: 1, maxDepth: 0, durationMs: 5_000 },
  }));
  const runOutcome = running.then(
    (result) => ({ kind: 'returned', result }),
    (error) => ({ kind: 'rejected', error }),
  );
  const phase = await Promise.race([
    finalMaterializationStarted.then(() => ({ kind: 'final-materialization-started' })),
    runOutcome,
  ]);
  if (phase.kind !== 'final-materialization-started') {
    const outcome = phase.kind === 'returned'
      ? JSON.stringify({ status: phase.result.status, limitations: phase.result.limitations })
      : String(phase.error);
    const phases = JSON.stringify({
      persistedDeadlineAtMs,
      releaseSealState,
      releaseSealCompletedAtMs,
      sealWrapperReturnedAtMs,
      sealReturnGateWaitMs,
      finalMaterializationEnteredAtMs,
      finalEntryRemainingAtMs,
    });
    assert.fail(`run ended before stalled final materialization; calls=${materializeCalls}; elapsedMs=${Date.now() - startedAt}; phases=${phases}; outcome=${outcome}`);
  }
  assert.ok(Number.isSafeInteger(persistedDeadlineAtMs));
  assert.ok(releaseSealCompletedAtMs <= sealWrapperReturnedAtMs && sealWrapperReturnedAtMs <= finalMaterializationEnteredAtMs,
    'both real materializations and the durable release seal finish before the final call enters');
  assert.ok(['sealed', 'already_sealed'].includes(releaseSealState));
  assert.ok(finalEntryRemainingAtMs > 0 && finalEntryRemainingAtMs <= 1_500,
    'the actual final materialization is entered with a measured, bounded portion of the original persisted deadline remaining');
  const sealReturnRemainingAtMs = persistedDeadlineAtMs - sealWrapperReturnedAtMs;
  assert.ok(sealReturnRemainingAtMs > 0 && sealReturnRemainingAtMs <= 1_500,
    'the real seal wrapper returns only after the original deadline gate opens');
  assert.ok(sealReturnGateWaitMs >= 0);
  const result = await running;
  const finalEntryWaitMs = Date.now() - finalMaterializationEnteredAtMs;
  assert.ok(finalEntryWaitMs < 2_000, 'the final-release phase remains covered after watcher drain');
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('deadline_exceeded'));
  assert.equal(materializeCalls, 3);
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshot.deadlineAtMs, persistedDeadlineAtMs, 'the stored deadline was not reset by phase synchronization');
  assert.ok(snapshot.stopReasons.some((entry) => entry.reason === 'deadline'));
  t.diagnostic(JSON.stringify({
    persistedDeadlineAtMs,
    releaseSealState,
    sealReturnGateWaitMs,
    sealReturnRemainingAtMs,
    finalEntryRemainingAtMs,
    finalEntryWaitMs,
    wholeRunElapsedMs: Date.now() - startedAt,
  }));
});

test('final selected readback rechecks current retention expiry after the composer materializations', async (t) => {
  let evidenceNow = Date.now();
  const retentionExpiresAt = evidenceNow + 60_000;
  const h = await harness(t, { evidenceOptions: { now: () => evidenceNow } });
  const server = await startFixture((_request, response) => {
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const runId = 'private-final-retention-expiry';
  const store = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'ingestEvidence', 'appendFact', 'ingestDerivedPdfEvidence', 'ingestAssetSourceEvidence',
    'lookupFact', 'materializeSelected', 'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.lookupEvidence = async (scope, evidenceId) => {
    const snapshot = await h.frontier.getSnapshot(h.scope, runId);
    if (snapshot.candidates.length > 0 && snapshot.candidates.every((candidate) => candidate.state === 'completed')) {
      evidenceNow = retentionExpiresAt + 1;
    }
    return h.evidenceStore.lookupEvidence(scope, evidenceId);
  };
  const result = await runPrivateRetrieval(h.makeInput({
    runId,
    server,
    store,
    seeds: [{ url: sourceUrl('/event') }],
    retentionHandleFor: () => h.createRetention(retentionExpiresAt),
  }));
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('selected_evidence_expired_or_revoked'));
});

test('final selected readback fails closed if the current decryption key is revoked', async (t) => {
  let keyAvailable = true;
  const h = await harness(t, {
    evidenceOptions: {
      resolveKey({ tenantId, purpose, keyId }) {
        if (!keyAvailable) throw new Error('current key unavailable');
        const selectedKeyId = `${purpose}-test-v1`;
        if (keyId && keyId !== selectedKeyId) throw new Error('private key selection denied');
        return { keyId: selectedKeyId, key: createHash('sha256').update(`${tenantId}:${purpose}:private-retrieval-test`).digest() };
      },
    },
  });
  const server = await startFixture((_request, response) => {
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  let materializeCalls = 0;
  const store = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'ingestEvidence', 'appendFact', 'ingestDerivedPdfEvidence', 'ingestAssetSourceEvidence',
    'lookupEvidence', 'lookupFact', 'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.materializeSelected = async (...args) => {
    materializeCalls += 1;
    if (materializeCalls === 3) keyAvailable = false;
    return h.evidenceStore.materializeSelected(...args);
  };
  const result = await runPrivateRetrieval(h.makeInput({
    runId: 'private-final-key-revoked', server, store, seeds: [{ url: sourceUrl('/event') }],
  }));
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('selected_evidence_key_unavailable'));
  assert.equal(materializeCalls, 3);
});

test('identity responses stay inside the smaller hard wire ceiling and retain unknown capacity on interruption', async (t) => {
  const tooLarge = Buffer.alloc(10 * 1024 * 1024 + 128 * 1024, 0x61);
  const server = await startFixture((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    response.end(tooLarge);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-identity-wire-cap';
  const result = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds: [{ url: sourceUrl('/identity-over-wire-limit') }],
  }));

  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('resource_limit'));
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshot.observations.filter((observation) => observation.kind === 'source').length, 0);
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transport.reservedBytes, 20 * 1024 * 1024);
  assert.equal(transport.spentBytes, 0);
  assert.equal(transport.states.unknown, 1);
});

test('gzip expansion beyond the accepted-byte cap remains a full unknown reservation', async (t) => {
  const expanded = Buffer.concat([
    Buffer.from('<!doctype html><html><body>'),
    Buffer.alloc(20 * 1024 * 1024, 0x61),
    Buffer.from('</body></html>'),
  ]);
  const compressed = gzipSync(expanded);
  const server = await startFixture((_request, response) => {
    respond(response, 200, {
      'content-type': 'text/html; charset=utf-8',
      'content-encoding': 'gzip',
      'content-length': String(compressed.length),
    }, compressed);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-gzip-overlimit';
  const result = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds: [{ url: sourceUrl('/gzip-overlimit') }],
  }));
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('resource_limit'));
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transport.reservedBytes, 20 * 1024 * 1024);
  assert.equal(transport.spentBytes, 0);
  assert.equal(transport.states.unknown, 1);
});

test('truncated gzip after decoded output retains the full reservation and produces no evidence', async (t) => {
  const compressed = gzipSync(eventHtml());
  const partial = compressed.subarray(0, compressed.length - 8);
  const server = await startFixture((_request, response) => {
    respond(response, 200, {
      'content-type': 'text/html; charset=utf-8',
      'content-encoding': 'gzip',
      'content-length': String(partial.length),
    }, partial);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const runId = 'private-gzip-truncated';
  const result = await runPrivateRetrieval(h.makeInput({
    runId, server, seeds: [{ url: sourceUrl('/gzip-truncated') }],
  }));
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  const transport = await h.frontier.getTransportProgress(h.scope, runId);
  assert.equal(transport.reservedBytes, 20 * 1024 * 1024);
  assert.equal(transport.spentBytes, 0);
  assert.equal(transport.states.unknown, 1);
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.equal(snapshot.observations.filter((observation) => observation.kind === 'source').length, 0);
});

test('revocation while final selected materialization is returning withholds the draft', async (t) => {
  const server = await startFixture((_request, response) => {
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  let finalReached;
  let releaseFinal;
  const finalMaterializationReached = new Promise((resolve) => { finalReached = resolve; });
  const finalMaterializationRelease = new Promise((resolve) => { releaseFinal = resolve; });
  let selectedCalls = 0;
  const store = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'ingestEvidence', 'appendFact', 'ingestDerivedPdfEvidence',
    'ingestAssetSourceEvidence', 'lookupEvidence', 'lookupFact',
    'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.materializeSelected = async (...args) => {
    selectedCalls += 1;
    const selected = await h.evidenceStore.materializeSelected(...args);
    if (selectedCalls === 3) {
      finalReached();
      await finalMaterializationRelease;
    }
    return selected;
  };
  const running = runPrivateRetrieval(h.makeInput({
    runId: 'private-revoked-final', server, seeds: [{ url: sourceUrl('/event') }], store,
    authorizeCurrent: () => h.currentlyAuthorized(),
  }));
  await finalMaterializationReached;
  h.setAcl(false);
  releaseFinal();
  const result = await running;
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('authorization_revoked'));
});

test('default-off legacy evidence adapters still recheck host release authorization after materialization', async (t) => {
  const server = await startFixture((_request, response) => {
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  let materializationCalls = 0;
  let finalMaterializationCompleted = false;
  let releaseAuthorized = true;
  let releaseCheckedAfterMaterialization = false;
  const store = legacyEvidenceAdapter(h.evidenceStore);
  const materialize = store.materializeSelected;
  store.materializeSelected = async (...args) => {
    const result = await materialize(...args);
    materializationCalls += 1;
    if (materializationCalls === 3) {
      finalMaterializationCompleted = true;
      releaseAuthorized = false;
    }
    return result;
  };
  const result = await runPrivateRetrieval(h.makeInput({
    runId: 'private-default-off-final-release-revoked',
    server,
    seeds: [{ url: sourceUrl('/event') }],
    store,
    authorizeCurrent: (_request, context) => {
      if (context.stage === 'release' && finalMaterializationCompleted) {
        releaseCheckedAfterMaterialization = true;
      }
      return context.stage !== 'release' || releaseAuthorized;
    },
  }));
  assert.equal(finalMaterializationCompleted, true, 'the fixture revoked release only after final selection materialized');
  assert.equal(releaseCheckedAfterMaterialization, true);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.draft, null);
  assert.ok(result.limitations.includes('authorization_revoked'));
});

test('a remote stop committed before the durable release seal prevents final materialization', { timeout: 8_000 }, async (t) => {
  const server = await startFixture((_request, response) => {
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  let reached;
  let release;
  const sealReached = new Promise((resolve) => { reached = resolve; });
  const holdSeal = new Promise((resolve) => { release = resolve; });
  const frontier = frontierWithSealHook(h.frontier, async (seal, ...args) => {
    reached();
    await holdSeal;
    return seal(...args);
  });
  let materializeCalls = 0;
  const store = Object.create(null);
  for (const name of [
    'scopeForAuthenticatedRequest', 'ingestEvidence', 'appendFact', 'ingestDerivedPdfEvidence',
    'ingestAssetSourceEvidence', 'lookupEvidence', 'lookupFact',
    'beginPrivateRunReceipt', 'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]) store[name] = h.evidenceStore[name].bind(h.evidenceStore);
  store.materializeSelected = async (...args) => {
    materializeCalls += 1;
    return h.evidenceStore.materializeSelected(...args);
  };
  const runId = 'private-cancel-before-seal';
  const running = runPrivateRetrieval(h.makeInput({
    runId, server, frontier, store, seeds: [{ url: sourceUrl('/event') }],
  }));
  await sealReached;
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.ok(snapshot.candidates.every((candidate) => candidate.state === 'completed'));
  assert.equal((await h.frontier.getTransportProgress(h.scope, runId)).reservedBytes, 0);
  const cancelStarted = Date.now();
  await runStopWorker(h.frontierDirectory, runId);
  assert.ok((await h.frontier.getSnapshot(h.scope, runId)).stopReasons.some((entry) => entry.reason === 'cancelled'),
    'the durable cancellation event is present even when frontier exhaustion stays primary');
  release();
  const result = await running;
  assert.ok(Date.now() - cancelStarted < 5_000);
  assert.equal(result.draft, null);
  assert.equal(materializeCalls, 2, 'only the composer internal materializations occurred');
});

test('the durable release seal linearizes a later cross-process stop after completed candidates', { timeout: 8_000 }, async (t) => {
  const server = await startFixture((_request, response) => {
    respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(() => server.close());
  const h = await harness(t);
  let reached;
  let release;
  const sealReached = new Promise((resolve) => { reached = resolve; });
  const holdAfterSeal = new Promise((resolve) => { release = resolve; });
  const frontier = frontierWithSealHook(h.frontier, async (seal, ...args) => {
    const result = await seal(...args);
    assert.equal(result.state, 'sealed');
    reached();
    await holdAfterSeal;
    return result;
  });
  const runId = 'private-cancel-after-seal';
  const running = runPrivateRetrieval(h.makeInput({
    runId, server, frontier, seeds: [{ url: sourceUrl('/event') }],
  }));
  await sealReached;
  const snapshot = await h.frontier.getSnapshot(h.scope, runId);
  assert.ok(snapshot.candidates.every((candidate) => candidate.state === 'completed'));
  const stopped = await runStopWorker(h.frontierDirectory, runId);
  assert.equal(stopped.stopReason, snapshot.stopReason,
    'a stop after the committed seal cannot retroactively invalidate the release order');
  assert.deepEqual((await h.frontier.getSnapshot(h.scope, runId)).stopReasons, snapshot.stopReasons);
  release();
  const result = await running;
  assert.equal(result.status, 'draft');
  assert.ok(result.sources.length > 0);
});

test('Linux private PDF retrieval selects stored derived provenance instead of claiming identity facts', { skip: process.platform !== 'linux' }, async (t) => {
  const { readFile } = await import('node:fs/promises');
  const pdfBytes = await readFile(new URL('../extraction/pdf/fixtures/text-multipage.pdf', import.meta.url));
  const server = await startFixture((_request, response) => {
    respond(response, 200, { 'content-type': 'application/pdf' }, pdfBytes);
  });
  t.after(() => server.close());
  const h = await harness(t);
  const result = await runPrivateRetrieval(h.makeInput({
    runId: 'private-pdf', server, seeds: [{ url: sourceUrl('/program.pdf') }],
    limits: { maxTransportAttemptAdmissions: 1, maxDepth: 0 },
  }));
  assert.equal(result.status, 'incomplete');
  assert.ok(Array.isArray(result.facts), `PDF run returned no fact projection: ${JSON.stringify(result)}`);
  assert.equal(result.facts.length, 0);
  assert.ok(Array.isArray(result.sources), `PDF run returned no source projection: ${JSON.stringify(result)}`);
  const pdf = result.sources.find((source) => source.representation === 'pdf-derived-text');
  assert.ok(pdf);
  assert.ok(pdf.pdf.pageCount > 0);
  assert.ok(pdf.pdf.textBoxCount > 0);
  assert.equal(pdf.pdf.requiresInspection, true);
  assert.equal(result.limitations.includes('pdf_identity_extraction_not_supported'), true);
});
