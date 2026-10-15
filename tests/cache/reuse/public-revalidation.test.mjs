import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { createReviewedPublicCacheRevalidation } from '../../../src/cache/reuse/public-revalidation.mjs';
import { getReviewedPublicRevalidationPort } from '../../../src/cache/reuse/store.mjs';
import { createRevalidationContext } from '../../../src/cache/reuse/revalidation-context.mjs';
import { withConditionalFetch } from '../../../src/security/internal/conditional-fetch.mjs';
import { BODY, IDENTITY, PINS, gate, hash, request } from './revalidation-support.mjs';
import { PUBLIC_FACTS, PUBLIC_HASH, publicRevalidationFixture } from './public-revalidation-support.mjs';

const runFile = promisify(execFile);
const reopenChild = fileURLToPath(new URL('./public-revalidation-reopen-child.mjs', import.meta.url));
const rejects = (operation, codes = ['REVALIDATION_DENIED', 'REVALIDATION_PROVENANCE', 'REVALIDATION_UNSUPPORTED', 'REUSE_DENIED', 'REUSE_BUSY']) =>
  assert.rejects(operation, (error) => codes.includes(error.code));

test('reviewed public publication joins one private source and actual304 without exposing tenant source or settling Finance', async (t) => {
  const f = await publicRevalidationFixture(t);
  assert.equal((await f.publicRead()).status, 'hit');
  await f.bind();
  const before = f.snapshot();
  const admission = await f.env.admit();
  const result = await f.refresh(admission.admissionRef);
  assert.equal(result.status, 'completed');
  assert.equal(result.scopeKind, 'public_profile');
  assert.equal(result.receipt.effectKind, 'observation');
  assert.equal(result.receipt.observationStatus, 'not_modified');
  assert.equal(result.receipt.httpStatus, 304);
  assert.equal(result.receipt.responseRetainedAtCompletion, true);
  assert.equal(result.usage, 'unknown');
  assert.equal(result.holdDisposition, 'finance_reconciliation_required');
  assert.equal(f.env.state.financeCalls, 0);
  assert.equal(f.env.state.requests.length, 2);
  assert.equal(f.env.state.requests[1].headers['if-none-match'], f.env.state.etag);
  const after = f.snapshot();
  assert.equal(after.observations.length, 2);
  assert.equal(after.observations.at(-1).id, result.receipt.observationRef);
  assert.equal(after.observations.at(-1).contentHash, PUBLIC_HASH);
  assert.equal(after.observations.at(-1).retrievedAtMs, before.observations[0].retrievedAtMs);
  assert.ok(after.observations.at(-1).validatedAtMs > before.observations[0].validatedAtMs);
  assert.equal(after.responses[0].id, result.receipt.responseRef);
  assert.equal(after.responses[0].responseRetrievedAt, null);
  assert.equal(after.flights[0].state, 'active');
  assert.equal(after.flights[0].usage, 'unknown');
  assert.equal(after.flights[0].attemptLineage.status, 'unknown');
  const hit = await f.publicRead();
  assert.equal(hit.status, 'hit');
  assert.deepEqual({ ...hit.facts }, PUBLIC_FACTS);
  const publicText = JSON.stringify({ profile: after.profile, observations: after.observations, outbox: after.outbox, hit });
  for (const secret of [f.env.sourceUrl, f.env.state.etag, f.env.sourceRef, f.env.evidence.metadata.evidenceId,
    f.env.evidence.metadata.contentHash, 'SYNTHETIC_ORIGINAL_EXPENSE', result.localRefreshId, result.bindingDigest]) {
    assert.equal(publicText.includes(secret), false, 'private source/expense/intent material stays outside public encryption and projection');
  }
});

test('same-body200 is a new actual retrieval while the approved profile key and original evidence stay distinct', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  f.env.state.response = 'same';
  const result = await f.refresh((await f.env.admit()).admissionRef);
  const after = f.snapshot();
  assert.equal(result.receipt.effectKind, 'observation');
  assert.equal(result.receipt.responseKind, 'body_unchanged');
  assert.equal(result.receipt.httpStatus, 200);
  const original = after.observations[0];
  const current = after.observations.at(-1);
  assert.ok(current.retrievedAtMs > original.retrievedAtMs);
  assert.equal(current.retrievedAtMs, Date.parse(after.responses[0].responseRetrievedAt));
  assert.equal(after.sources[0].binding.originalRetrievedAt, f.env.document.fetchedAt);
  assert.equal(after.sources[0].binding.originalBodyHash, hash(BODY));
  assert.equal(after.profile.contentHash, PUBLIC_HASH);
  assert.notEqual(PUBLIC_HASH, hash(BODY));
  assert.equal((await f.publicRead()).retrievedAt, new Date(current.retrievedAtMs).toISOString());
  assert.equal(f.env.state.financeCalls, 0);
});

test('changed200 invalidates the actual old public version without publishing the unreviewed hash or borrowing an observation', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  const before = f.snapshot();
  f.env.state.response = 'changed';
  const admission = await f.env.admit();
  const result = await f.refresh(admission.admissionRef);
  const after = f.snapshot();
  assert.equal(result.receipt.effectKind, 'invalidation');
  assert.equal(result.receipt.reason, 'source_body_changed');
  assert.equal('observationRef' in result.receipt, false);
  assert.equal(result.receipt.responseKind, 'body');
  assert.equal(result.receipt.responseRetainedAtCompletion, false);
  assert.equal(after.eligible, 0);
  assert.equal(after.sources.length, 0);
  assert.equal(after.responses.length, 0);
  assert.deepEqual(after.observations, before.observations);
  assert.equal(after.profile.contentHash, PUBLIC_HASH);
  assert.deepEqual(result.receipt.invalidationEventRefs, after.outbox.map((event) => event.id));
  assert.equal(after.outbox.length, 1);
  assert.equal(after.outbox[0].status, 'pending');
  assert.equal(JSON.stringify(after).includes(hash(`${BODY}Changed source body\n`)), false);
  assert.notEqual((await f.publicRead()).status, 'hit');
  await f.reopen();
  assert.deepEqual((await f.refresh(admission.admissionRef)).receipt, result.receipt);
  assert.equal(f.env.state.requests.length, 2);
  assert.equal(f.env.state.financeCalls, 0);
});

for (const status of [404, 410, 500, 503]) {
  test(`actual public HTTP${status} records only its defined removal/outage effect and preserves source/Finance limits`, async (t) => {
    const f = await publicRevalidationFixture(t);
    await f.bind();
    f.env.state.response = String(status);
    const result = await f.refresh((await f.env.admit()).admissionRef);
    const after = f.snapshot();
    const removed = status === 404 || status === 410;
    assert.equal(result.receipt.httpStatus, status);
    assert.equal(result.receipt.effectKind, removed ? 'invalidation' : 'observation');
    assert.equal(result.receipt.observationStatus, removed ? 'removed' : 'outage');
    assert.equal(result.receipt.observationRef, after.observations.at(-1).id);
    assert.equal(after.observations.at(-1).contentHash, PUBLIC_HASH);
    assert.equal(after.observations.at(-1).retrievedAtMs, after.observations[0].retrievedAtMs);
    assert.equal(after.eligible, removed ? 0 : 1);
    assert.equal(after.sources.length, removed ? 0 : 1);
    assert.equal(after.responses.length, removed ? 0 : 1);
    if (removed) assert.deepEqual(result.receipt.invalidationEventRefs, after.outbox.map((event) => event.id));
    assert.notEqual((await f.publicRead()).status, 'hit');
    assert.equal(after.flights[0].usage, 'unknown');
    assert.equal(after.flights[0].state, 'active');
  });
}

test('outage recovers through a separately admitted genuine304 without resetting original retrieval or expenses', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  f.env.state.response = '503';
  const first = await f.refresh((await f.env.admit()).admissionRef);
  assert.equal(first.receipt.observationStatus, 'outage');
  f.env.state.response = '304';
  const second = await f.refresh((await f.env.admit('fresh')).admissionRef);
  assert.equal(second.receipt.observationStatus, 'not_modified');
  assert.notEqual(second.localRefreshId, first.localRefreshId);
  assert.equal((await f.publicRead()).status, 'hit');
  assert.equal(f.snapshot().observations.at(-1).retrievedAtMs, f.snapshot().observations[0].retrievedAtMs);
  assert.equal(f.snapshot().flights.length, 2);
  assert.equal(f.env.state.financeCalls, 0);
});

test('a stale public TTL can be revalidated before hard retention without treating stale facts as fresh evidence', async (t) => {
  const f = await publicRevalidationFixture(t, { publicInput: { freshnessTtlMs: 400 } });
  await f.bind();
  await delay(410);
  assert.equal((await f.publicRead()).status, 'stale');
  const result = await f.refresh((await f.env.admit()).admissionRef);
  assert.equal(result.receipt.observationStatus, 'not_modified');
  assert.equal((await f.publicRead()).status, 'hit');
});

for (const response of ['redirect', '304-missing', '304-duplicate', '304-other', 'same-other-type', 'charset', 'abort', '401', '403']) {
  test(`public conditional ${response} refusal never asserts source removal or freshness`, async (t) => {
    const f = await publicRevalidationFixture(t);
    await f.bind();
    const before = f.snapshot();
    f.env.state.response = response;
    const admission = await f.env.admit();
    await assert.rejects(f.refresh(admission.admissionRef));
    const after = f.snapshot();
    assert.equal(after.eligible, 1);
    assert.deepEqual(after.observations, before.observations);
    assert.equal(after.outbox.length, 0);
    assert.equal(after.responses.length, 0);
    assert.equal(after.flights[0].localRefresh.state, 'dispatch_intent');
    assert.equal(after.flights[0].usage, 'unknown');
    await f.reopen();
    assert.equal((await f.refresh(admission.admissionRef)).status, 'unknown');
    assert.equal(f.env.state.requests.length, 2, 'exact retry never redispatches or forwards the validator');
  });
}

test('public Last-Modified uses only the exact retained date validator', async (t) => {
  const date = 'Wed, 21 Oct 2015 07:28:00 GMT';
  const f = await publicRevalidationFixture(t, { initialHeaders: { 'last-modified': date } });
  await f.bind();
  f.env.state.response = '304-date';
  assert.equal((await f.refresh((await f.env.admit()).admissionRef)).receipt.httpStatus, 304);
  assert.equal(f.env.state.requests[1].headers['if-modified-since'], date);
  assert.equal(f.env.state.requests[1].headers['if-none-match'], undefined);
});

test('a genuine public source without a usable original validator cannot be bound', async (t) => {
  const f = await publicRevalidationFixture(t, { initialHeaders: {} });
  await rejects(f.bind(), ['REVALIDATION_PROVENANCE']);
  assert.equal(f.snapshot().sources.length, 0);
  assert.equal(f.env.state.requests.length, 1);
});

test('copied original documents and wrong evidence versions cannot replace actual source provenance', async (t) => {
  const f = await publicRevalidationFixture(t);
  await rejects(f.bind({ document: { ...f.env.document } }), ['REVALIDATION_PROVENANCE']);
  await rejects(f.bind({ evidenceVersion: f.env.evidence.metadata.version + 1 }), ['REVALIDATION_PROVENANCE']);
  assert.equal(f.snapshot().sources.length, 0);
  assert.equal(f.env.state.requests.length, 1);
});

for (const [field, value] of [['publicationLinkId', 'other-link'], ['sourceRecordId', 'other-record'],
  ['profileRef', 'other-profile'], ['profileVersion', 999], ['profileContentHash', hash(BODY)],
  ['profileHashDomain', 'safe-fetch-decoded-entity-bytes/v1'], ['sourceRef', 'other-source'],
  ['evidenceId', 'other-evidence'], ['originalBodyHash', PUBLIC_HASH]]) {
  test(`explicit publication/evidence mapping rejects ${field} substitution`, async (t) => {
    const f = await publicRevalidationFixture(t);
    f.authority.mappingOverride = { [field]: value };
    await rejects(f.bind(), ['REVALIDATION_PROVENANCE']);
    assert.equal(f.snapshot().sources.length, 0);
    assert.equal(f.env.state.requests.length, 1);
  });
}

test('missing complete host mapping or denied current EvidenceStore access never becomes a binding', async (t) => {
  const f = await publicRevalidationFixture(t);
  f.authority.mappingAvailable = false;
  await rejects(f.bind(), ['REVALIDATION_PROVENANCE']);
  f.authority.mappingAvailable = true;
  f.env.state.evidenceAvailable = false;
  await rejects(f.bind(), ['REVALIDATION_PROVENANCE']);
  assert.equal(f.snapshot().sources.length, 0);
  assert.equal((await f.publicRead()).status, 'hit');
});

test('a public read/publication grant cannot substitute for current public freshness mutation authority', async (t) => {
  const f = await publicRevalidationFixture(t, { publicPermissions: false });
  assert.equal((await f.publicRead()).status, 'hit');
  f.authority.publicMutation = false;
  await rejects(f.bind(), ['REUSE_DENIED']);
  f.authority.publicMutation = true;
  f.authority.publicBoundary = false;
  await rejects(f.bind(), ['REUSE_DENIED']);
  assert.equal(f.snapshot().sources.length, 0);
  assert.equal(f.env.state.requests.length, 1);
});

for (const cause of ['private-link permission', 'retained source access']) {
  test(`${cause} revocation scrubs only private refresh data and leaves reviewed public facts available`, async (t) => {
    const f = await publicRevalidationFixture(t);
    await f.bind();
    await f.refresh((await f.env.admit()).admissionRef);
    const before = f.snapshot();
    if (cause === 'private-link permission') f.authority.sourceRights = false;
    else f.authority.sourceAccess = false;
    await rejects(f.refresh((await f.env.admit('fresh')).admissionRef), ['REVALIDATION_DENIED']);
    const after = f.snapshot();
    assert.equal(after.eligible, 1);
    assert.deepEqual(after.observations, before.observations);
    assert.deepEqual(after.sources, [{ purged: 1, expiresAtMs: before.sources[0].expiresAtMs, payloadBytes: 0 }]);
    assert.equal(after.responses.length, 0);
    assert.equal(after.outbox.length, 0);
    assert.equal((await f.publicRead()).status, 'hit');
    f.authority.sourceRights = true;
    f.authority.sourceAccess = true;
    await rejects(f.bind(), ['REVALIDATION_DENIED']);
    assert.equal(f.env.state.requests.length, 2);
    assert.equal(f.env.state.financeCalls, 0);
  });
}

test('actual public fact-rights revocation invalidates the exact public profile under public freshness authority', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  f.authority.publicRights = false;
  await rejects(f.refresh((await f.env.admit()).admissionRef), ['REVALIDATION_DENIED']);
  const after = f.snapshot();
  assert.equal(after.eligible, 0);
  assert.equal(after.sources.length, 0);
  assert.equal(after.outbox.length, 1);
  assert.equal(f.env.state.requests.length, 1);
});

for (const phase of ['dispatch', 'commit']) {
  test(`a second originating publication arriving during ${phase} cannot inherit the first tenant's source proof`, async (t) => {
    const f = await publicRevalidationFixture(t);
    await f.bind();
    const blocked = gate();
    f.authority.phaseHook = async (actual) => { if (actual === phase) await blocked.wait(); };
    const admission = await f.env.admit();
    const running = f.refresh(admission.admissionRef);
    const rejected = rejects(running);
    await blocked.reached;
    await f.publish(request('synthetic-second-publisher', 'synthetic-second-actor'));
    blocked.release();
    await rejected;
    assert.equal(f.snapshot().observations.length, 1);
    assert.equal(f.snapshot().responses.length, 0);
    assert.equal(f.snapshot().flights[0].localRefresh.state, 'dispatch_intent');
    assert.equal(f.env.state.requests.length, phase === 'dispatch' ? 1 : 2);
  });
}

test('an already shared public profile and multiple source/correction references stay explicitly unsupported', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.publish(request('synthetic-second-publisher', 'synthetic-second-actor'));
  await rejects(f.bind(), ['REVALIDATION_UNSUPPORTED']);
  assert.equal(f.env.state.requests.length, 1);
  const multiple = await publicRevalidationFixture(t, { storeOptions: {
    resolvePrivateProfileReferences: ({ contentHash }) => ({ sourceRefs: ['one', 'two'], correctionRefs: ['correction'],
      permissions: [{ reference: 'PRIVATE_PERMISSION_CANARY', contentHash, version: 1, use: 'cache_read' }] }),
  } });
  await rejects(multiple.bind(), ['REVALIDATION_UNSUPPORTED']);
});

test('cross-tenant and cross-actor public refresh cannot use the originating private binding/admission', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  const admission = await f.env.admit();
  for (const other of [request('other-tenant', 'other-actor'), request('synthetic-tenant', 'other-actor')]) {
    const scope = await f.env.store.scopeForAuthenticatedRequest(other);
    await rejects(f.coordinator.refresh(scope, other, { scopeKind: 'public_profile', profileRef: f.published.profile.profileRef,
      admissionRef: admission.admissionRef }), ['REVALIDATION_DENIED', 'REUSE_NOT_FOUND']);
  }
  assert.equal(f.env.state.requests.length, 1);
  assert.equal(f.snapshot().flights[0].localRefresh, undefined);
});

test('same body/profile hashes on another occurrence cannot reuse a completed profile-specific receipt', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  const admission = await f.env.admit();
  await f.refresh(admission.admissionRef);
  const other = await f.publish(f.env.authRequest, { identity: { ...IDENTITY, occurrenceId: 'other-occurrence' } });
  await rejects(f.coordinator.refresh(f.env.scope, f.env.authRequest, { scopeKind: 'public_profile',
    profileRef: other.profile.profileRef, admissionRef: admission.admissionRef }), ['REVALIDATION_DENIED']);
  assert.equal(f.env.state.requests.length, 2);
});

test('private and public historical intents cannot cross-replay even with the same supplied profile reference', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  await f.env.bind();
  const privateAdmission = await f.env.admit();
  await f.env.refresh(privateAdmission.admissionRef);
  await rejects(f.coordinator.refresh(f.env.scope, f.env.authRequest, { scopeKind: 'public_profile',
    profileRef: f.env.profile.profileRef, admissionRef: privateAdmission.admissionRef }), ['REVALIDATION_DENIED']);
  const publicAdmission = await f.env.admit('fresh');
  await f.refresh(publicAdmission.admissionRef);
  await rejects(f.env.coordinator.refresh(f.env.scope, f.env.authRequest, { scopeKind: 'tenant_private',
    profileRef: f.published.profile.profileRef, admissionRef: publicAdmission.admissionRef }), ['REVALIDATION_DENIED']);
  assert.equal(f.env.state.requests.length, 3);
});

test('concurrent same-admission public calls and separate-process replay dispatch exactly once', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  const blocked = gate();
  f.authority.phaseHook = async (phase) => { if (phase === 'dispatch') await blocked.wait(); };
  const admission = await f.env.admit();
  const running = f.refresh(admission.admissionRef);
  await blocked.reached;
  const raced = await f.refresh(admission.admissionRef);
  assert.equal(raced.status, 'unknown');
  assert.equal(raced.replayed, true);
  blocked.release();
  const completed = await running;
  const child = await runFile(process.execPath, [reopenChild, f.env.options.directory, f.published.profile.profileRef, admission.admissionRef]);
  const replay = JSON.parse(child.stdout);
  assert.deepEqual(replay.result.receipt, completed.receipt);
  assert.equal(replay.result.bindingDigest, completed.bindingDigest);
  assert.equal(replay.attemptedNetwork, 0);
  assert.equal(replay.retainedSourceCalls, 0);
  assert.equal(f.env.state.requests.length, 2);
});

for (const phase of ['dispatch', 'commit']) {
  test(`cancelled ${phase} evidence callback cannot write later; reopen keeps unknown without redispatch`, async (t) => {
    const f = await publicRevalidationFixture(t);
    await f.bind();
    const blocked = gate();
    f.authority.phaseHook = async (actual) => { if (actual === phase) await blocked.wait(); };
    const controller = new AbortController();
    const admission = await f.env.admit();
    const running = f.refresh(admission.admissionRef, { signal: controller.signal });
    const rejected = rejects(running, ['REVALIDATION_CANCELLED']);
    await blocked.reached;
    controller.abort();
    await rejected;
    blocked.release();
    await delay(25);
    assert.equal(f.snapshot().observations.length, 1);
    assert.equal(f.snapshot().responses.length, 0);
    const child = await runFile(process.execPath, [reopenChild, f.env.options.directory, f.published.profile.profileRef, admission.admissionRef]);
    const replay = JSON.parse(child.stdout);
    assert.equal(replay.result.status, 'unknown');
    assert.equal(replay.attemptedNetwork, 0);
    assert.equal(replay.retainedSourceCalls, 0);
    assert.equal(f.env.state.requests.length, phase === 'dispatch' ? 1 : 2);
  });
}

test('source retention is fixed at bind, private purge scrubs bytes, and renewal cannot revive the old claim', async (t) => {
  const f = await publicRevalidationFixture(t);
  f.authority.retainedUntil = Date.now() + 2_000;
  await f.bind();
  await f.refresh((await f.env.admit()).admissionRef);
  const before = f.snapshot();
  const fixed = before.sources[0].expiresAtMs;
  assert.ok(fixed < before.profile.retentionPolicy.expiresAtMs);
  f.authority.retainedUntil = Date.now() + 30_000;
  await f.bind();
  assert.equal(f.snapshot().sources[0].expiresAtMs, fixed);
  f.env.state.offset = 2_100;
  await f.env.store.purgeExpired(f.env.scope, f.env.authRequest);
  const after = f.snapshot();
  assert.equal(after.sources[0].purged, 1);
  assert.equal(after.sources[0].payloadBytes, 0);
  assert.equal(after.responses.length, 0);
  assert.equal(after.eligible, 1);
  assert.equal(after.outbox.length, 0);
  await rejects(f.bind(), ['REVALIDATION_DENIED']);
  assert.equal(f.env.state.requests.length, 2);
});

for (const mode of ['stable-earliest', 'retained-source', 'private-source-permission', 'public-fact-permission']) {
  test(`final public binding grant cannot outlive accepted authority: ${mode}`, async (t) => {
    // The store/evidence clock and grants are synthetic. Publication, private
    // link, full-original evidence, native HTTP and reopen use real components.
    const permissionUntil = { private: null, public: null };
    const f = await publicRevalidationFixture(t, { storeOptions: {
      verifyPermission: ({ reference, contentHash, version, use, nowMs }) => {
        const domain = reference === 'SYNTHETIC_PUBLIC_FACT_RIGHTS' ? 'public' : 'private';
        assert.equal(use, domain === 'public' ? 'fact_read' : 'cache_read');
        assert.ok([hash(BODY), PUBLIC_HASH].includes(contentHash));
        return { status: 'valid', reference, contentHash, version, use,
          validUntilMs: permissionUntil[domain] ?? nowMs + 60_000 };
      },
    } });
    const origin = Date.now();
    const earlier = origin + 10_000;
    const later = origin + 30_000;
    if (mode === 'private-source-permission') permissionUntil.private = later;
    else if (mode === 'public-fact-permission') permissionUntil.public = later;
    else f.authority.retainedUntil = mode === 'stable-earliest' ? earlier : later;
    let bindReads = 0;
    f.authority.phaseHook = async (phase) => {
      if (phase !== 'bind') return;
      bindReads += 1;
      if (bindReads !== 2) return;
      if (mode === 'private-source-permission') permissionUntil.private = earlier;
      else if (mode === 'public-fact-permission') permissionUntil.public = earlier;
      else f.authority.retainedUntil = earlier;
    };
    const before = f.snapshot();
    if (mode === 'stable-earliest') {
      assert.equal((await f.bind()).status, 'bound');
      assert.equal(f.snapshot().sources[0].expiresAtMs, earlier);
      assert.equal(f.snapshot().sources[0].binding.expiresAtMs, earlier);
    } else {
      await rejects(f.bind(), ['REVALIDATION_DENIED']);
      assert.deepEqual(f.snapshot().sources, []);
    }
    assert.equal(bindReads, 2, 'final grant is checked with a bounded pair of source reads');
    assert.ok(Date.now() < earlier, 'both grants are still valid during binding');
    assert.deepEqual(f.snapshot().observations, before.observations);
    assert.deepEqual(f.snapshot().responses, []);
    assert.equal(f.env.state.requests.length, 1);

    // A later grant after reopen must not revive the expired original claim,
    // nor create a binding that was refused before its first durable insert.
    await f.reopen();
    f.authority.phaseHook = null;
    f.authority.retainedUntil = origin + 50_000;
    permissionUntil.private = origin + 50_000;
    permissionUntil.public = origin + 50_000;
    f.env.state.offset = 15_000;
    assert.ok(earlier < Date.now() + f.env.state.offset && Date.now() + f.env.state.offset < later);
    const admission = await f.env.admit();
    await rejects(f.refresh(admission.admissionRef), mode === 'stable-earliest'
      ? ['REVALIDATION_DENIED'] : ['REVALIDATION_PROVENANCE']);
    const after = f.snapshot();
    assert.equal(f.env.state.requests.length, 1, 'refusal precedes a second native HTTP request');
    assert.deepEqual(after.observations, before.observations);
    assert.deepEqual(after.responses, []);
    assert.equal(after.eligible, 1, 'private refresh authority cannot retract approved public facts');
    if (mode === 'stable-earliest') {
      assert.deepEqual(after.sources, [{ purged: 1, expiresAtMs: earlier, payloadBytes: 0 }]);
    } else assert.deepEqual(after.sources, []);
    assert.equal(after.flights[0].state, 'active');
    assert.equal(after.flights[0].usage, 'unknown');
    assert.equal(after.flights[0].localRefresh, undefined);
    assert.equal(f.env.state.financeCalls, 0);
  });
}

test('public invalidation and hard-retention purge scrub new private rows while historical receipts stay minimal', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  const admission = await f.env.admit();
  await f.refresh(admission.admissionRef);
  await f.env.store.invalidate(f.env.scope, f.env.authRequest, { scopeKind: 'public_profile',
    profileRef: f.published.profile.profileRef, reason: 'material_fact_change' });
  assert.equal(f.snapshot().sources.length, 0);
  assert.equal(f.snapshot().responses.length, 0);
  f.env.state.offset = 70_000;
  await f.env.store.purgeExpired(f.env.scope, f.env.authRequest, 'public_profile');
  const after = f.snapshot();
  assert.equal(after.profile, null);
  assert.equal(after.observations.length, 0);
  assert.equal(after.outbox[0].status, 'pending');
  const receipt = await f.refresh(admission.admissionRef);
  assert.equal(receipt.status, 'completed');
  assert.equal(receipt.replayed, true);
  for (const privateValue of [f.env.sourceUrl, f.env.state.etag, f.env.sourceRef, f.env.evidence.metadata.evidenceId, hash(BODY)]) {
    assert.equal(JSON.stringify(after.flights).includes(privateValue), false);
  }
  assert.equal(f.env.state.requests.length, 2);
});

test('retained key IDs survive payload-key rotation and reopen without replacing or extending the source binding', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  const before = f.snapshot().sources[0];
  const originalResolver = f.env.options.resolveKey;
  f.env.state.keyVersion = '2';
  await f.reopen({ resolveKey: (input) => originalResolver({ ...input,
    ...(input.purpose === 'index' ? { keyId: `${input.scope}:index:1` } : {}) }) });
  assert.equal((await f.bind()).replayed, true);
  await f.refresh((await f.env.admit()).admissionRef);
  assert.deepEqual(f.snapshot().sources[0], before);
  assert.equal((await f.publicRead()).status, 'hit');
});

test('rotating the private index namespace never silently migrates another source binding into it', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  f.env.state.keyVersion = '2';
  await f.reopen();
  await rejects(f.bind(), ['REVALIDATION_UNSUPPORTED']);
  assert.equal(f.env.state.requests.length, 1);
});

for (const defect of ['copied binding', 'partial bytes']) {
  test(`a retained ${defect} cannot replace the exact full-original host/evidence join`, async (t) => {
    const f = await publicRevalidationFixture(t);
    const coordinator = f.makeCoordinator({ readRetainedPublicSource: async (input) => {
      const retained = await f.readRetainedPublicSource(input);
      return defect === 'copied binding' ? { ...retained, binding: { ...input.binding } }
        : { ...retained, bytes: retained.bytes.subarray(1) };
    } });
    await rejects(coordinator.bindSource(f.env.scope, f.env.authRequest, f.bindInput), ['REVALIDATION_PROVENANCE']);
    assert.equal(f.snapshot().sources.length, 0);
  });
}

test('the public absolute deadline bounds a stalled commit callback and rejects its late write', { timeout: 15_000 }, async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  const admission = await f.env.admit();
  const blocked = gate();
  f.authority.phaseHook = async (phase) => { if (phase === 'commit') await blocked.wait(); };
  // Native encrypted evidence reads can consume the old 500ms allowance before
  // commit on slower hosts. Keep one real entry deadline, but first prove that
  // the intended callback was entered instead of waiting forever on its gate.
  const coordinator = f.makeCoordinator({ timeoutMs: 5_000 });
  const running = coordinator.refresh(f.env.scope, f.env.authRequest, { scopeKind: 'public_profile',
    profileRef: f.published.profile.profileRef, admissionRef: admission.admissionRef });
  const outcome = running.then(
    () => ({ phase: 'completed_before_gate' }),
    (error) => ({ phase: 'rejected_before_gate', error }),
  );
  try {
    const entered = await Promise.race([
      blocked.reached.then(() => ({ phase: 'commit_entered' })), outcome,
    ]);
    assert.equal(entered.phase, 'commit_entered',
      `deadline probe never reached commit: ${entered.error?.code ?? entered.phase}`);
    await rejects(running, ['REVALIDATION_DEADLINE']);
  } finally {
    blocked.release();
  }
  await delay(25);
  assert.equal(f.snapshot().observations.length, 1);
  assert.equal(f.snapshot().responses.length, 0);
  assert.equal(f.snapshot().flights[0].localRefresh.state, 'dispatch_intent');
  assert.equal(f.snapshot().flights[0].usage, 'unknown');
});

for (const refusal of ['cancel', 'public-authority']) {
  test(`final synchronous public ${refusal} refusal rolls back response/observation/receipt atomically`, async (t) => {
    const f = await publicRevalidationFixture(t);
    await f.bind();
    const admission = await f.env.admit();
    const controller = new AbortController();
    f.env.state.boundaryHook = (input) => {
      if (input.details?.scopeKind === 'public_profile' && f.authority.mappingCalls.at(-1)?.phase === 'commit') {
        if (refusal === 'cancel') controller.abort();
        else f.env.state.authorized = false;
      }
    };
    await rejects(f.refresh(admission.admissionRef, { signal: controller.signal }),
      refusal === 'cancel' ? ['REVALIDATION_CANCELLED'] : ['REUSE_DENIED']);
    const after = f.snapshot();
    assert.equal(after.observations.length, 1);
    assert.equal(after.responses.length, 0);
    assert.equal(after.flights[0].localRefresh.state, 'dispatch_intent');
    assert.equal(after.eligible, 1);
  });
}

test('public source input proxy traps and an authority-free factory are rejected without execution', async (t) => {
  const f = await publicRevalidationFixture(t);
  let traps = 0;
  const proxy = new Proxy({}, { getPrototypeOf() { traps += 1; return Object.prototype; }, ownKeys() { traps += 1; return []; } });
  await rejects(f.coordinator.bindSource(f.env.scope, f.env.authRequest, proxy), ['REVALIDATION_INVALID']);
  assert.equal(traps, 0);
  assert.throws(() => createReviewedPublicCacheRevalidation({ store: f.env.store, safeFetcher: f.env.safeFetcher }),
    (error) => error.code === 'REVALIDATION_INVALID');
});

test('every public freshness authorization can require the exact public profile scope and reference', async (t) => {
  const f = await publicRevalidationFixture(t);
  const seen = [];
  const authorize = ({ action, details }) => {
    if (action !== 'freshness.observe') return true;
    seen.push(details);
    return details?.scopeKind === 'public_profile' && details.profileRef === f.published.profile.profileRef;
  };
  await f.reopen({ authorizeAction: authorize, authorizeCurrentRequest: (input) =>
    input.request?.principal?.tenantId === input.expectedTenantId && input.request?.principal?.actorId === input.expectedActorId && authorize(input) });
  await f.bind();
  assert.equal((await f.refresh((await f.env.admit()).admissionRef)).status, 'completed');
  assert.ok(seen.length > 0);
  assert.equal(seen.every((item) => item.scopeKind === 'public_profile' && item.profileRef === f.published.profile.profileRef), true);
});

for (const retained of ['source binding', 'source response']) {
  test(`global encrypted-byte admission includes the private public-profile ${retained}`, async (t) => {
    const f = await publicRevalidationFixture(t);
    await f.bind();
    const admission = await f.env.admit('fresh');
    const nextAdmissionBytes = f.env.database((db) => db.prepare('SELECT length(payload) AS bytes FROM reuse_flights WHERE admission_id = ?')
      .get(admission.admissionRef).bytes);
    if (retained === 'source response') await f.refresh(admission.admissionRef);
    const actualCiphertextBytes = f.env.database((db) => {
      let bytes = 0;
      for (const { name } of db.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name LIKE 'reuse_%'").all()) {
        assert.match(name, /^reuse_[a-z_]+$/);
        if (db.prepare(`PRAGMA table_info(${name})`).all().some((column) => column.name === 'payload')) {
          bytes += db.prepare(`SELECT COALESCE(SUM(length(payload)), 0) AS bytes FROM ${name}`).get().bytes;
        }
      }
      assert.equal(db.prepare('SELECT COUNT(*) AS count FROM reuse_entries WHERE eligible = 1').get().count, 2);
      assert.equal(db.prepare('SELECT COUNT(*) AS count FROM reuse_consumer_refs').get().count, 2);
      return bytes;
    });
    // Two eligible fixture profiles each retain their existing 2KiB outbox
    // reservation. The next identical fresh admission would exceed by one byte.
    const maxStoreBytes = actualCiphertextBytes + 2 * 2_048 + nextAdmissionBytes - 1;
    await f.reopen({ maxStoreBytes });
    await rejects(f.env.admit('fresh'), ['REUSE_CAPACITY']);
    assert.equal(f.snapshot().flights.length, 1);
  });
}

test('observation capacity refusal rolls back the private response and completion after a real HTTP response', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  const admission = await f.env.admit();
  await f.reopen({ maxObservationsPerEntry: 1 });
  await rejects(f.refresh(admission.admissionRef), ['REUSE_CAPACITY']);
  const after = f.snapshot();
  assert.equal(f.env.state.requests.length, 2);
  assert.equal(after.observations.length, 1);
  assert.equal(after.responses.length, 0);
  assert.equal(after.flights[0].localRefresh.state, 'dispatch_intent');
  assert.equal(after.flights[0].usage, 'unknown');
  assert.equal(after.sources.length, 1);
});

test('arbitrary, copied and different-intent native responses cannot complete an actual public refresh intent', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  const admission = await f.env.admit();
  const context = createRevalidationContext({ timeoutMs: 10_000, request: f.env.authRequest,
    readRetainedSource: async (input) => {
      // This private-port negative probe uses the same actual host/evidence read;
      // the public factory separately enforces the explicit mapping fields.
      const retained = await f.readRetainedPublicSource(input);
      return { binding: retained.binding, representation: retained.representation, bytes: retained.bytes,
        validUntilMs: retained.validUntilMs };
    },
  });
  const port = getReviewedPublicRevalidationPort(f.env.store, context);
  let prepared;
  try {
    prepared = await port.prepare(f.env.scope, f.env.authRequest, { scopeKind: 'public_profile',
      profileRef: f.published.profile.profileRef, admissionRef: admission.admissionRef }, context);
    const otherToken = Object.freeze({});
    const otherResponse = await withConditionalFetch(f.env.safeFetcher, prepared.sourceUrl, prepared.validator,
      () => f.env.safeFetcher.fetch(prepared.sourceUrl), otherToken);
    for (const response of [{ kind: 'not_modified', statusCode: 304 }, { ...otherResponse }, otherResponse]) {
      await rejects(port.complete(f.env.scope, f.env.authRequest, prepared.token, response, context), ['REVALIDATION_PROVENANCE']);
    }
    assert.equal(f.snapshot().observations.length, 1);
    assert.equal(f.snapshot().responses.length, 0);
    assert.equal(f.snapshot().flights[0].localRefresh.state, 'dispatch_intent');
    assert.equal(f.env.state.financeCalls, 0);
  } finally {
    if (prepared?.token) port.dispose(prepared.token);
    context.close();
  }
});

test('distinct real public HTTP attempts at one synthetic wall-clock millisecond cannot share a completion observation', async (t) => {
  const f = await publicRevalidationFixture(t);
  await f.bind();
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 1_000 });
  const first = await f.refresh((await f.env.admit()).admissionRef);
  const secondAdmission = await f.env.admit('fresh');
  await rejects(f.refresh(secondAdmission.admissionRef), ['REVALIDATION_PROVENANCE']);
  const after = f.snapshot();
  assert.equal(after.observations.length, 2);
  assert.equal(after.observations.at(-1).id, first.receipt.observationRef);
  assert.equal(after.responses.length, 1);
  assert.deepEqual(after.flights.map((flight) => flight.localRefresh.state).sort(), ['completed', 'dispatch_intent']);
  assert.equal(f.env.state.requests.length, 3);
});

for (const defect of ['correction-derived', 'missing private source permission']) {
  test(`${defect} publication does not gain full-original revalidation authority from public review`, async (t) => {
    const f = await publicRevalidationFixture(t, { storeOptions: {
      resolvePrivateProfileReferences: ({ contentHash }) => ({ sourceRefs: ['one-original'],
        correctionRefs: defect === 'correction-derived' ? ['correction-reference'] : [],
        permissions: defect === 'missing private source permission' ? []
          : [{ reference: 'PRIVATE_PERMISSION_CANARY', contentHash, version: 1, use: 'cache_read' }] }),
    } });
    await rejects(f.bind(), ['REVALIDATION_UNSUPPORTED']);
    assert.equal(f.env.state.requests.length, 1);
    assert.equal(f.snapshot().sources.length, 0);
  });
}
