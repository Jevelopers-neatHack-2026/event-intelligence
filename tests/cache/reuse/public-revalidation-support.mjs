import assert from 'node:assert/strict';
import { createDecipheriv } from 'node:crypto';
import { createEvidenceStore } from '../../../src/evidence/store.mjs';
import { createPrivacyBoundary } from '../../../src/privacy/boundary.mjs';
import { createReviewedPublicCacheRevalidation } from '../../../src/cache/reuse/public-revalidation.mjs';
import { safeFetchProvenance } from '../../../src/security/internal/fetch-lifecycle.mjs';
import { BODY, IDENTITY, PINS, hash, request, revalidationFixture } from './revalidation-support.mjs';

export const PUBLIC_FACTS = Object.freeze({ event_name: 'Conditional Cache Test', event_date: '2027-06-20', venue: 'Test Hall' });
export const PUBLIC_HASH = hash(`SYNTHETIC_REVIEWED_PROFILE_KEY:${JSON.stringify(PUBLIC_FACTS)}`);
export const PROFILE_DOMAIN = 'scoped-reuse-reviewed-publication-content-key/v1';
export const BODY_DOMAIN = 'safe-fetch-decoded-entity-bytes/v1';

// This fixture uses actual PrivacyBoundary publication, actual encrypted public
// profile/private-link storage and an actual retained full-original EvidenceStore.
// All reviews, identities, mapping records, permissions and expense IDs are
// synthetic local host authority. Nothing here is a real consumer/owner ACK.
export async function publicRevalidationFixture(t, overrides = {}) {
  const records = new Map();
  let env;
  const authority = { publicRights: true, sourceRights: true, sourceAccess: true, mappingAvailable: true,
    publicMutation: true, publicBoundary: true, permissionsUntil: null, retainedUntil: null,
    phaseHook: null, mappingOverride: null, mappingCalls: [], publicPermissions: overrides.publicPermissions ?? true };
  env = await revalidationFixture(t, { ...overrides, storeOptions: {
    verifySourceObservation: ({ purpose, expectedContentHash: expectedHash, observation }) => {
      assert.equal(purpose, 'initial', 'conditional public results never use a caller observation fixture');
      assert.ok([hash(BODY), PUBLIC_HASH].includes(expectedHash));
      assert.equal(safeFetchProvenance(observation)?.bodyHash, hash(BODY));
      return { status: 'body_changed', contentHash: expectedHash, retrievedAt: observation.fetchedAt,
        validatedAt: observation.fetchedAt, sourceVersion: 'synthetic-source-1', attemptLineage: { status: 'unknown' } };
    },
    authorizePublicPublication: ({ tenantId, actorId, sourceRecordId, facts, contentHash, identity }) => {
      assert.deepEqual({ ...facts }, PUBLIC_FACTS);
      assert.equal(contentHash, PUBLIC_HASH);
      records.set(sourceRecordId, { tenantId, actorId, sourceRecordId, contentHash, identity });
      return { status: 'approved', contentHash, identity, publicPermissions: authority.publicPermissions
        ? [{ reference: 'SYNTHETIC_PUBLIC_FACT_RIGHTS', contentHash, version: 1, use: 'fact_read' }] : [] };
    },
    verifyPermission: ({ reference, contentHash, version, use, nowMs }) => {
      const publicRight = reference === 'SYNTHETIC_PUBLIC_FACT_RIGHTS';
      assert.equal(use, publicRight ? 'fact_read' : 'cache_read');
      assert.ok([hash(BODY), PUBLIC_HASH].includes(contentHash));
      if (!(publicRight ? authority.publicRights : authority.sourceRights)) return 'revoked';
      return { status: 'valid', reference, contentHash, version, use,
        validUntilMs: authority.permissionsUntil ?? nowMs + 60_000 };
    },
    ...overrides.storeOptions,
  } });
  const oldAction = env.options.authorizeAction;
  const oldBoundary = env.options.authorizeBoundary;
  const options = {
    authorizeAction: async (input) => {
      if (input.action === 'freshness.observe' && input.details?.scopeKind === 'public_profile' && !authority.publicMutation) return false;
      return oldAction(input);
    },
    authorizeBoundary: (input) => {
      if (input.action === 'freshness.observe' && input.details?.scopeKind === 'public_profile' && !authority.publicBoundary) return false;
      return oldBoundary(input);
    },
  };
  await env.reopen(options);
  const decode = (row, kind, id, publicRow = false) => {
    const envelope = JSON.parse(Buffer.from(row.payload).toString());
    const key = env.options.resolveKey({ tenantId: publicRow ? null : env.authRequest.principal.tenantId,
      scope: publicRow ? 'public_profile' : 'tenant_private', purpose: 'payload', keyId: row.payload_key_id }).key;
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
      decipher.setAAD(Buffer.from(`event-intelligence:scoped-reuse:v1:${kind}:${row.partition_hash ?? row.tenant_partition_hash}:${id}:${row.payload_key_id}`));
      decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
      return JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]).toString());
    } finally { key.fill(0); }
  };
  const publish = async (authRequest = env.authRequest, extra = {}) => {
    const boundary = createPrivacyBoundary({ resolveTenant: (r) => r?.principal?.tenantId,
      reviewPublicFacts: ({ tenantId, sourceDigest, candidate }) => ({ status: 'approved', tenantId, sourceDigest, facts: candidate }) });
    const boundaryScope = boundary.scopeForAuthenticatedRequest(authRequest);
    const started = boundary.begin(boundaryScope, { modality: 'plain_text', content: BODY });
    await boundary.prepare(boundaryScope, started.session, PUBLIC_FACTS);
    const derivative = boundary.publish(boundaryScope, started.session);
    const exported = boundary.exportDerivative(boundaryScope, derivative);
    const scope = await env.store.scopeForAuthenticatedRequest(authRequest);
    const profile = await env.store.publishReviewedPublicProfile(scope, authRequest, {
      boundary, boundaryScope, derivative, identity: IDENTITY, pins: PINS, contentHash: PUBLIC_HASH,
      observation: env.document, ...extra,
    });
    const mapping = records.get(exported.recordId);
    assert.ok(mapping);
    // The approved record, returned immutable profile identity, and actual stored
    // private link are joined explicitly. The native body hash is a separate key.
    const links = env.database((db) => db.prepare('SELECT * FROM reuse_private_links WHERE public_entry_id = ?').all(profile.profileRef));
    if (authRequest === env.authRequest) {
      const link = links.find((row) => {
        try { return decode(row, 'private_link', row.link_id).sourceRecordId === exported.recordId; } catch { return false; }
      });
      if (link) records.set(exported.recordId, Object.freeze({ ...mapping, publicationLinkId: link.link_id,
        profileRef: profile.profileRef, profileVersion: profile.version, sourceRef: env.sourceRef,
        evidenceId: env.evidence.metadata.evidenceId, evidenceVersion: env.evidence.metadata.version,
        originalBodyHash: env.evidence.metadata.contentHash }));
    }
    return { profile, scope, authRequest, exported, boundary, boundaryScope, derivative };
  };
  const published = await publish(env.authRequest, overrides.publicInput);
  const lookup = { identity: IDENTITY, pins: PINS, contentHash: PUBLIC_HASH };
  const readRetainedPublicSource = async ({ request: currentRequest, binding, phase, signal }) => {
    authority.mappingCalls.push({ phase, binding });
    if (authority.phaseHook) await authority.phaseHook(phase, binding, signal);
    assert.ok(authority.mappingAvailable, 'explicit host publication-to-original mapping required');
    const actual = records.get(binding.sourceRecordId);
    assert.ok(actual);
    assert.equal(actual.tenantId, currentRequest.principal.tenantId);
    assert.equal(actual.actorId, currentRequest.principal.actorId);
    assert.equal(binding.tenantId, actual.tenantId);
    assert.equal(binding.actorId, actual.actorId);
    assert.equal(binding.scopeKind, 'public_profile');
    assert.equal(binding.publicationLinkId, actual.publicationLinkId);
    assert.equal(binding.profileRef, actual.profileRef);
    assert.equal(binding.profileVersion, actual.profileVersion);
    assert.equal(binding.profileContentHash, actual.contentHash);
    assert.equal(binding.profileHashDomain, PROFILE_DOMAIN);
    assert.equal(binding.bodyHashDomain, BODY_DOMAIN);
    assert.notEqual(binding.profileContentHash, binding.originalBodyHash);
    assert.deepEqual(binding.identity, actual.identity);
    assert.deepEqual(binding.pins, PINS);
    const mapping = { schema: 'ei-reviewed-public-source-mapping/v1', publicationLinkId: actual.publicationLinkId,
      sourceRecordId: actual.sourceRecordId, profileRef: actual.profileRef, profileVersion: actual.profileVersion,
      profileContentHash: actual.contentHash, profileHashDomain: PROFILE_DOMAIN, sourceRef: actual.sourceRef,
      evidenceId: actual.evidenceId, evidenceVersion: actual.evidenceVersion,
      originalBodyHash: actual.originalBodyHash, bodyHashDomain: BODY_DOMAIN, ...authority.mappingOverride };
    if (!authority.sourceAccess) return { status: 'source_access_revoked', binding, mapping };
    const reopened = createEvidenceStore(env.evidenceOptions);
    const currentScope = await reopened.scopeForAuthenticatedRequest(currentRequest);
    const handle = await reopened.lookupEvidence(currentScope, actual.evidenceId);
    const metadata = await reopened.getEvidenceMetadata(currentScope, handle);
    assert.equal(metadata.state, 'available');
    assert.equal(metadata.version, binding.evidenceVersion);
    assert.equal(metadata.contentHash, binding.originalBodyHash);
    const retained = await reopened.withPrivatePayload(currentScope, handle, currentRequest);
    assert.equal(retained.sourceUrl, binding.sourceUrl);
    assert.equal(retained.sourceHash, binding.originalBodyHash);
    assert.equal(retained.retrievedAt, binding.originalRetrievedAt);
    assert.equal(retained.positions.length, 1);
    assert.deepEqual({ ...retained.positions[0].locator }, { kind: 'text-range', startByte: 0, endByte: Buffer.byteLength(BODY) });
    return { binding, mapping, representation: 'full_original_response', bytes: Buffer.from(retained.positions[0].bytes, 'base64'),
      validUntilMs: Math.min(binding.expiresAtMs, Date.parse(metadata.expiresAt), authority.retainedUntil ?? Infinity) };
  };
  const makeCoordinator = (extra = {}) => createReviewedPublicCacheRevalidation({ store: env.store, safeFetcher: env.safeFetcher, readRetainedPublicSource, ...extra });
  let coordinator = makeCoordinator();
  const bindInput = { scopeKind: 'public_profile', profileRef: published.profile.profileRef, sourceRef: env.sourceRef,
    evidenceId: env.evidence.metadata.evidenceId, evidenceVersion: env.evidence.metadata.version, document: env.document };
  return {
    env, authority, records, published, lookup, bindInput, readRetainedPublicSource, makeCoordinator, publish,
    get coordinator() { return coordinator; },
    async bind(extra = {}, optionsValue) { return coordinator.bindSource(env.scope, env.authRequest, { ...bindInput, ...extra }, optionsValue); },
    async refresh(admissionRef, optionsValue) { return coordinator.refresh(env.scope, env.authRequest,
      { scopeKind: 'public_profile', profileRef: published.profile.profileRef, admissionRef }, optionsValue); },
    async reopen(extra = {}) { await env.reopen({ ...options, ...extra }); coordinator = makeCoordinator(); },
    async publicRead() {
      const other = request('synthetic-other-tenant', 'synthetic-other-reader');
      const scope = await env.store.scopeForAuthenticatedRequest(other);
      return env.store.getPublicProfile(scope, other, lookup);
    },
    snapshot() {
      return env.database((db) => {
        const entry = db.prepare('SELECT * FROM reuse_entries WHERE entry_id = ?').get(published.profile.profileRef);
        const observations = db.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence').all(entry.entry_id)
          .map((row) => ({ id: row.observation_id, ...decode({ ...row, partition_hash: entry.partition_hash }, 'observation', row.observation_id, true) }));
        const privatePartition = db.prepare('SELECT partition_hash FROM reuse_entries WHERE entry_id = ?').get(env.profile.profileRef).partition_hash;
        const sources = db.prepare('SELECT * FROM reuse_public_refresh_sources WHERE entry_id = ? AND tenant_partition_hash = ?').all(entry.entry_id, privatePartition)
          .map((row) => ({ purged: row.payload_purged, expiresAtMs: row.expires_at_ms, payloadBytes: row.payload.byteLength,
            ...(row.payload_purged ? {} : { binding: decode(row, 'public_refresh_source', row.entry_id) }) }));
        const responses = db.prepare('SELECT * FROM reuse_public_refresh_responses WHERE entry_id = ? AND tenant_partition_hash = ?').all(entry.entry_id, privatePartition)
          .map((row) => ({ id: row.response_id, expiresAtMs: row.expires_at_ms, ...decode(row, 'public_refresh_response', row.response_id) }));
        const flights = db.prepare('SELECT * FROM reuse_flights WHERE partition_hash = ?').all(privatePartition)
          .map((row) => ({ id: row.admission_id, state: row.state, ...decode(row, 'flight', row.admission_id) }));
        const outbox = db.prepare('SELECT * FROM reuse_outbox WHERE entry_id = ?').all(entry.entry_id)
          .map((row) => ({ id: row.event_id, status: row.status, ...decode(row, 'outbox', row.event_id, true) }));
        return { eligible: entry.eligible, profile: entry.payload_purged ? null : decode(entry, 'entry', entry.entry_id, true),
          observations, sources, responses, flights, outbox };
      });
    },
  };
}
