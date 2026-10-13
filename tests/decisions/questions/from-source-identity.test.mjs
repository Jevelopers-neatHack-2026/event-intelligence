import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createEvidenceStore } from '../../../src/evidence/store.mjs';
import { compareOccurrenceIdentity } from '../../../src/discovery/occurrences/identity.mjs';
import { composeSourceIdentity } from '../../../src/discovery/identity/from-extraction.mjs';
import { prepareIndependentQuestions } from '../../../src/decisions/questions/prepare.mjs';
import {
  QuestionPreparationError,
  SourceIdentityQuestionPreparationError,
  prepareIdentityQuestionFromComposition
} from '../../../src/decisions/questions/index.mjs';

const QUESTION_ID = 'Q-EI-IDENTITY:v1';

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function eventPage({ city, startDate, status = 'https://schema.org/EventScheduled', name = 'Garden Light Festival', rawNameJson, visibleMarkup = '' }) {
  const event = {
    '@type': 'Event',
    name,
    series: 'Garden Light Tour',
    edition: '2027',
    startDate,
    endDate: '2027-08-02',
    eventStatus: status,
    location: { name: `Hall ${city}`, address: { addressLocality: city } }
  };
  let json = JSON.stringify(event);
  if (rawNameJson !== undefined) {
    const nameToken = JSON.stringify(name);
    const nameOffset = json.indexOf(nameToken);
    assert.notEqual(nameOffset, -1);
    json = `${json.slice(0, nameOffset)}${rawNameJson}${json.slice(nameOffset + nameToken.length)}`;
  }
  return Buffer.from(`<!doctype html><script type="application/ld+json">${json}</script>${visibleMarkup}`);
}

function document(bytes, url) {
  return {
    url,
    contentType: 'text/html; charset=utf-8',
    fetchedAt: '2026-10-11T16:00:00.000Z',
    redirects: 0,
    bytes
  };
}

async function createHarness(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ei-question-preparation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const permits = new WeakMap();
  const createPermit = (tenantId = 'tenant-a', durationMs = 120_000) => {
    const permit = Object.freeze(Object.create(null));
    permits.set(permit, { tenantId, expiresAtMs: Date.now() + durationMs });
    return permit;
  };
  const store = createEvidenceStore({
    directory,
    resolveTenant: (request) => request?.principal?.tenantId,
    resolveKey({ tenantId, purpose, keyId }) {
      const expectedKeyId = `${purpose}-test-v1`;
      if (keyId && keyId !== expectedKeyId) throw new Error('Unexpected test key identifier');
      return { keyId: expectedKeyId, key: createHash('sha256').update(`${tenantId}:${purpose}:test-key`).digest() };
    },
    resolveRetention({ tenantId, kind, nowMs, sourceExpiresAtMs, retentionHandle }) {
      if (kind === 'evidence') {
        const permit = permits.get(retentionHandle);
        if (!permit || permit.tenantId !== tenantId) throw new Error('Invalid test retention permit');
        return { expiresAtMs: permit.expiresAtMs, policyId: 'test-private', policyVersion: '1', accessPolicy: 'tenant_private' };
      }
      return {
        expiresAtMs: sourceExpiresAtMs ?? nowMs + 60_000,
        policyId: 'test-private-fact',
        policyVersion: '1',
        accessPolicy: 'tenant_private'
      };
    },
    authorizePrivateAccess: ({ tenantId, request }) => request?.principal?.tenantId === tenantId && request.allowPrivate === true,
    authorizePrivateAccessCurrent: ({ tenantId, request }) => request?.principal?.tenantId === tenantId && request.allowPrivate === true,
    maxSourceBytes: 2 * 1024 * 1024,
    maxPositionBytes: 64 * 1024,
    maxPositionCount: 128,
    maxStoredPayloadBytes: 512 * 1024,
    maxRetentionMs: 180_000
  });
  return { store, createPermit };
}

async function compose(t, events) {
  const harness = await createHarness(t);
  const request = { principal: { tenantId: 'tenant-a' }, allowPrivate: true };
  const result = await composeSourceIdentity({
    sources: events.map(({ bytes, url }) => ({
      document: document(Buffer.from(bytes), url),
      retentionHandle: harness.createPermit()
    })),
    request,
    evidenceStore: harness.store
  });
  return result;
}

function candidateForCity(composition, city) {
  const candidate = composition.occurrenceCandidates.find((item) => item.facts.city?.some((claim) => claim.value === city));
  assert.ok(candidate, `composer output contains a candidate for ${city}`);
  return candidate;
}

function languageMap(composition, value = 'en') {
  return Object.fromEntries(composition.sources.filter((source) => source.evidence)
    .map((source) => [source.evidence.evidenceId, value]));
}

function prepare(composition, candidateIds, languageByEvidenceId = languageMap(composition)) {
  return prepareIdentityQuestionFromComposition(composition, { candidateIds, languageByEvidenceId });
}

function cloneComposition(composition, patch) {
  return { ...composition, ...patch };
}

// Synthetic multi-support and byte-boundary fixtures describe the historical v1
// profile. They deliberately have no current v2 retained-source graph. Keep them
// explicit so current-composer coverage cannot silently downgrade malformed v2.
function legacySyntheticComposition(composition, patch = {}) {
  const { corroboration: ignored, corroborationFactBindings: ignoredBindings, ...legacy } = composition;
  return { ...legacy, ...patch, schema: 'ei-source-identity-composition-internal/v1' };
}

function changedCandidate(composition, candidateId, transform) {
  const original = composition.occurrenceCandidates.find((item) => item.candidateId === candidateId);
  assert.ok(original);
  const replacement = transform(original);
  return cloneComposition(composition, {
    occurrenceCandidates: composition.occurrenceCandidates.map((candidate) => candidate.candidateId === candidateId ? replacement : candidate)
  });
}

function selectedQuestion(plan) {
  return plan.questions.find((question) => question.questionId === QUESTION_ID);
}

function assertBlockedPlan(plan, pair) {
  assert.equal(plan.candidateOnly, true);
  assert.equal(plan.readinessStatus, 'blocked');
  assert.equal(plan.executionStatus, 'not_dispatched');
  assert.equal(plan.promotionStatus, 'unpromoted');
  assert.equal(plan.decisionPortContractStatus, 'unavailable');
  assert.equal(plan.authorityScope.sourceOfficialnessGranted, false);
  assert.equal(plan.authorityScope.verifiedFactStatusGranted, false);
  assert.equal(plan.authorityScope.budgetGranted, false);
  assert.equal(plan.authorityScope.promotionGranted, false);
  assert.deepEqual(selectedQuestion(plan).targetBinding.candidateRefs, [...pair].sort());
}

function claimGroupProjection(binding, group) {
  const candidate = binding.selectedCandidates.find((item) => item.candidateId === group.candidateId);
  const unique = new Map();
  for (const claim of candidate.facts) {
    if (!claim.supports.some((support) => support.evidenceId === group.evidenceId && support.contentHash === group.contentHash)) continue;
    const projection = {
      field: claim.field,
      value: claim.value,
      origin: claim.origin,
      ...(claim.precision ? { precision: claim.precision } : {}),
      retentionTags: claim.retentionTags
    };
    unique.set(stableJsonTest(projection), projection);
  }
  return [...unique.values()].sort((left, right) => stableJsonTest(left).localeCompare(stableJsonTest(right), 'en'));
}

function stableJsonTest(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJsonTest).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJsonTest(value[key])}`).join(',')}}`;
}

function groupCoreFor(group) {
  return {
    candidateId: group.candidateId,
    evidenceId: group.evidenceId,
    contentHash: group.contentHash,
    languageLabel: group.languageLabel,
    claims: group.claims,
    ...(group.corroboration ? { corroboration: group.corroboration } : {})
  };
}

for (const notice of [
  'Cancelled: Garden Light Festival will not take place.',
  'Rescheduled: Garden Light Festival has moved to 14 October.',
  'The event is not cancelled.'
]) {
  test(`visible status requires review without changing stale structured claims: ${notice}`, async (t) => {
    const bytes = eventPage({ city: 'Seattle', startDate: '2027-08-01', visibleMarkup: `<p>${notice}</p>` });
    const composition = await compose(t, [
      { bytes, url: 'https://events.example.test/seattle' },
      { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
    ]);
    const mentions = composition.sources[0].extraction.statusMentions;
    assert.equal(mentions.length, 1);
    assert.equal(mentions[0].normalizedValue, notice);
    const { startByte, endByte } = mentions[0].source.locator;
    assert.equal(bytes.subarray(startByte, endByte).toString('utf8'), mentions[0].rawValue);
    assert.deepEqual(composition.occurrenceCandidates.map((candidate) => candidate.facts.status.map((claim) => claim.value)), [['scheduled'], ['scheduled']]);
    const original = JSON.stringify(composition);
    const pair = composition.occurrenceCandidates.map((candidate) => candidate.candidateId);
    assert.throws(() => prepare(composition, pair), (error) => {
      assert.ok(error instanceof SourceIdentityQuestionPreparationError);
      assert.equal(error.code, 'VISIBLE_STATUS_REVIEW_REQUIRED');
      assert.equal(error.message, 'Source-level status evidence requires review before identity question preparation.');
      return true;
    });
    assert.equal(JSON.stringify(composition), original, 'the notice, byte provenance, and structured claims remain available for review');
  });
}

test('an ambiguous visible notice on a two-edition page refuses preparation without assigning an occurrence', async (t) => {
  const events = ['2026', '2027'].map((edition) => ({
    '@type': 'Event', name: 'Garden Light Festival', series: 'Garden Light Tour', edition,
    startDate: `${edition}-08-01`, endDate: `${edition}-08-02`, eventStatus: 'https://schema.org/EventScheduled',
    location: { name: 'Hall Seattle', address: { addressLocality: 'Seattle' } }
  }));
  const notice = 'The event is cancelled.';
  const bytes = Buffer.from(`<!doctype html><script type="application/ld+json">${JSON.stringify({ '@graph': events })}</script><p>${notice}</p>`);
  const composition = await compose(t, [{ bytes, url: 'https://events.example.test/editions' }]);
  assert.equal(composition.occurrenceCandidates.length, 2);
  assert.deepEqual(composition.occurrenceCandidates.flatMap((candidate) => candidate.facts.edition.map((claim) => claim.value)).sort(), ['2026', '2027']);
  assert.deepEqual(composition.occurrenceCandidates.map((candidate) => candidate.facts.status.map((claim) => claim.value)), [['scheduled'], ['scheduled']]);
  const mentions = composition.sources[0].extraction.statusMentions;
  assert.equal(mentions.length, 1);
  assert.equal(mentions[0].normalizedValue, notice);
  const { startByte, endByte } = mentions[0].source.locator;
  assert.equal(bytes.subarray(startByte, endByte).toString('utf8'), mentions[0].rawValue);
  const original = JSON.stringify(composition);
  assert.throws(() => prepare(composition, composition.occurrenceCandidates.map((candidate) => candidate.candidateId)), {
    name: 'SourceIdentityQuestionPreparationError', code: 'VISIBLE_STATUS_REVIEW_REQUIRED'
  });
  assert.equal(JSON.stringify(composition), original);
});

test('a visible notice in an unrelated source does not block the selected pair', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' },
    { bytes: eventPage({ city: 'Portland', startDate: '2027-08-03', visibleMarkup: '<p>The event is cancelled.</p>' }), url: 'https://events.example.test/portland' }
  ]);
  assert.equal(composition.sources[2].extraction.statusMentions.length, 1);
  const pair = [candidateForCity(composition, 'Seattle').candidateId, candidateForCity(composition, 'Vancouver').candidateId];
  const selectedLanguages = Object.fromEntries(composition.sources.slice(0, 2).map((source) => [source.evidence.evidenceId, 'en']));
  const result = prepare(composition, pair, selectedLanguages);
  assert.equal(selectedQuestion(result.plan).eligible, true);
  assertBlockedPlan(result.plan, pair);
  assert.equal(result.sourceIdentityBinding.sourceEvidence.length, 2);
});

test('selected status metadata is hash-bound, descriptor-safe, and bounded before entry access', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const pair = composition.occurrenceCandidates.map((candidate) => candidate.candidateId);
  const original = composition.sources[0].extraction;
  assert.equal(original.sourceHash, `sha256:${composition.sources[0].evidence.contentHash}`);
  assert.deepEqual(original.statusMentions, []);
  const reject = (extraction, code = 'INVALID_INPUT') => assert.throws(() => prepare(cloneComposition(composition, {
    sources: [{ ...composition.sources[0], extraction }, ...composition.sources.slice(1)]
  }), pair), { name: 'SourceIdentityQuestionPreparationError', code });
  reject(undefined);
  reject(null);
  reject({ sourceHash: original.sourceHash });
  reject({ ...original, statusMentions: null });
  reject({ ...original, statusMentions: {} });
  reject({ ...original, sourceHash: `sha256:${'0'.repeat(64)}` }, 'SOURCE_BINDING_FAILED');

  let trapCount = 0;
  const trap = () => { trapCount += 1; throw new Error('caller code must not run'); };
  const traps = { get: trap, getPrototypeOf: trap, ownKeys: trap, getOwnPropertyDescriptor: trap };
  reject(new Proxy(original, traps));
  reject({ ...original, statusMentions: new Proxy([], traps) });
  reject(Object.defineProperty({ sourceHash: original.sourceHash }, 'statusMentions', { enumerable: true, get: trap }));
  reject(Object.defineProperty({ statusMentions: [] }, 'sourceHash', { enumerable: true, get: trap }));
  const accessorEntries = Object.defineProperty([], '0', { enumerable: true, get: trap });
  reject({ ...original, statusMentions: accessorEntries });
  reject({ ...original, statusMentions: new Array(2) });
  const oversized = Object.defineProperty(new Array(33), '0', { enumerable: true, get: trap });
  reject({ ...original, statusMentions: oversized }, 'RESOURCE_LIMIT_EXCEEDED');
  reject({ ...original, statusMentions: new Array(0xffffffff) }, 'RESOURCE_LIMIT_EXCEEDED');
  const opaqueMention = new Proxy({}, traps);
  reject({ ...original, statusMentions: Array(32).fill(opaqueMention) }, 'VISIBLE_STATUS_REVIEW_REQUIRED');
  assert.equal(trapCount, 0, 'neither input accessors nor status text/proxy contents are executed');
});

test('prepares the explicitly selected composer pair while retaining date, city, status, and source provenance', async (t) => {
  const leftBytes = eventPage({ city: 'Seattle', startDate: '2027-08-01', status: 'https://schema.org/EventCancelled' });
  const rightBytes = eventPage({ city: 'Vancouver', startDate: '2027-08-01T20:00:00-07:00', status: 'https://schema.org/EventRescheduled' });
  const composition = await compose(t, [
    { bytes: leftBytes, url: 'https://events.example.test/seattle' },
    { bytes: rightBytes, url: 'https://events.example.test/vancouver' }
  ]);
  const left = candidateForCity(composition, 'Seattle');
  const right = candidateForCity(composition, 'Vancouver');
  const pair = [left.candidateId, right.candidateId].sort();
  const result = prepare(composition, [right.candidateId, left.candidateId]);
  const question = selectedQuestion(result.plan);

  assertBlockedPlan(result.plan, pair);
  assert.equal(question.eligible, true);
  assert.ok(question.reasonCodes.length === 0);
  assert.equal(result.plan.preparationStatus, 'prepared');
  assert.equal(result.plan.state.observations.length, 2);
  assert.deepEqual(result.sourceIdentityBinding.candidateIds, pair);
  assert.equal(result.sourceIdentityBinding.questionId, QUESTION_ID);
  assert.equal(result.sourceIdentityBinding.localReviewOnly, true);
  assert.equal(result.sourceIdentityBinding.sourceAuthority, 'not_evaluated');
  assert.equal(result.sourceIdentityBinding.transitionLinks.length, 0);
  assert.deepEqual(result.sourceIdentityBinding.unresolvedTransitions.map(({ transition }) => transition).sort(), ['canceled', 'rescheduled']);
  assert.deepEqual(result.sourceIdentityBinding.comparison.conflictFields, ['city', 'start', 'status', 'venue']);
  assert.equal(result.sourceIdentityBinding.comparison.relation, 'different_occurrence_candidate');
  assert.equal(result.sourceIdentityBinding.observationGroups.length, 2);
  for (const group of result.sourceIdentityBinding.observationGroups) {
    assert.deepEqual(group.claims, claimGroupProjection(result.sourceIdentityBinding, group));
    assert.deepEqual(JSON.parse(group.text), { claims: group.claims, corroboration: group.corroboration });
    assert.equal(group.corroboration.independence, 'unknown');
    const expectedReference = `source-identity-${createHash('sha256')
      .update('event-intelligence:source-identity-question-group:v2\0', 'utf8')
      .update(stableJsonTest(groupCoreFor(group)), 'utf8').digest('hex')}`;
    assert.equal(group.observationRef, expectedReference);
    const observation = result.plan.state.observations.find((item) => item.observationRef === group.observationRef);
    assert.ok(observation);
    assert.equal(observation.sourceRef, group.evidenceId);
    assert.equal(observation.candidateRef, group.candidateId);
    assert.equal(observation.text, group.text);
    assert.equal(observation.claimText, group.text);
  }
  assert.ok(result.sourceIdentityBinding.observationGroups.every((group) => group.claims.some((claim) => claim.field === 'city')));

  const cityGroup = result.sourceIdentityBinding.observationGroups.find((group) => group.claims.some((claim) => claim.field === 'city'));
  const droppedCity = { ...cityGroup, claims: cityGroup.claims.filter((claim) => claim.field !== 'city') };
  assert.notDeepEqual(droppedCity.claims, claimGroupProjection(result.sourceIdentityBinding, droppedCity),
    'cross-checking the group against the immutable per-field support map detects a dropped critical claim');
  const droppedCityReference = `source-identity-${createHash('sha256')
    .update('event-intelligence:source-identity-question-group:v2\0', 'utf8')
    .update(stableJsonTest(groupCoreFor(droppedCity)), 'utf8').digest('hex')}`;
  assert.notEqual(droppedCityReference, droppedCity.observationRef);
  const droppedSupportMap = {
    ...result.sourceIdentityBinding,
    selectedCandidates: result.sourceIdentityBinding.selectedCandidates.map((candidate) => candidate.candidateId === cityGroup.candidateId
      ? { ...candidate, facts: candidate.facts.map((claim) => claim.field === 'city' ? { ...claim, supports: [] } : claim) }
      : candidate)
  };
  assert.notDeepEqual(cityGroup.claims, claimGroupProjection(droppedSupportMap, cityGroup),
    'cross-checking group text against the immutable support map detects a dropped critical source reference');

  const dateClaims = result.sourceIdentityBinding.selectedCandidates.flatMap((candidate) => candidate.facts.filter((claim) => claim.field === 'start'));
  assert.deepEqual(dateClaims.map((claim) => claim.precision).sort(), ['date', 'instant']);
  const cityClaims = result.sourceIdentityBinding.selectedCandidates.flatMap((candidate) => candidate.facts.filter((claim) => claim.field === 'city'));
  assert.deepEqual(cityClaims.map((claim) => claim.value).sort(), ['Seattle', 'Vancouver']);
  assert.ok(result.plan.preservedCriticalEvidence.some((item) => item.tags.includes('date')));
  assert.ok(result.plan.preservedCriticalEvidence.some((item) => item.tags.includes('tour_city')));
  assert.ok(result.plan.preservedCriticalEvidence.some((item) => item.tags.includes('cancellation')));
  assert.ok(result.plan.preservedCriticalEvidence.some((item) => item.tags.includes('reschedule')));
  assert.equal(result.sourceIdentityBinding.bindingHashes.sourceEvidenceHash, result.plan.sourceEvidenceHash);
  assert.equal(result.sourceIdentityBinding.bindingHashes.targetBindingHash, question.targetBindingHash);
  assert.equal(result.sourceIdentityBinding.bindingHashes.targetStateHash, question.targetStateHash);
  assert.equal(result.sourceIdentityBinding.bindingHashes.questionInstanceHash, question.questionInstanceHash);
  assert.equal(result.sourceIdentityBinding.bindingHashes.planHash, result.plan.planHash);
  assert.match(result.sourceIdentityBinding.digest, /^[a-f0-9]{64}$/);
  const actualPlanInputTextBytes = result.plan.state.observations.reduce((sum, observation) => (
    sum + Buffer.byteLength(observation.text, 'utf8') + Buffer.byteLength(observation.claimText, 'utf8')
  ), 0);
  assert.equal(result.sourceIdentityBinding.limits.observationTextBytes, actualPlanInputTextBytes);
  assert.ok(result.sourceIdentityBinding.utf8Bytes <= result.sourceIdentityBinding.limits.maxUtf8Bytes);
  assert.ok(Object.isFrozen(result.sourceIdentityBinding));
  assert.ok(Object.isFrozen(result.sourceIdentityBinding.selectedCandidates[0].facts));
});

test('pair order, support order, and caller-language map order do not change the prepared hashes', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const left = candidateForCity(composition, 'Seattle');
  const right = candidateForCity(composition, 'Vancouver');
  const pair = [left.candidateId, right.candidateId].sort();
  const language = languageMap(composition);
  const reversedLanguage = Object.fromEntries(Object.entries(language).reverse());
  const baseline = prepare(composition, pair, language);
  const reversedPair = prepare(composition, [...pair].reverse(), reversedLanguage);
  assert.equal(reversedPair.plan.planHash, baseline.plan.planHash);
  assert.equal(reversedPair.sourceIdentityBinding.digest, baseline.sourceIdentityBinding.digest);

  const titleClaim = left.facts.title[0];
  const otherTitleSupport = right.facts.title[0].supports[0];
  assert.equal(titleClaim.value, otherTitleSupport.value);
  const augmented = { ...titleClaim, supports: [titleClaim.supports[0], otherTitleSupport] };
  const leftWithTwoSupports = {
    ...left,
    facts: { ...left.facts, title: [augmented, ...left.facts.title.slice(1)] }
  };
  const rightUnchanged = right;
  const pairDecision = compareOccurrenceIdentity(
    pair[0] === left.candidateId ? leftWithTwoSupports : rightUnchanged,
    pair[1] === right.candidateId ? rightUnchanged : leftWithTwoSupports
  );
  const supportOrderA = cloneComposition(composition, {
    occurrenceCandidates: composition.occurrenceCandidates.map((candidate) => candidate.candidateId === left.candidateId ? leftWithTwoSupports : candidate),
    occurrenceDecisions: [pairDecision]
  });
  const reversedSupports = { ...augmented, supports: [...augmented.supports].reverse() };
  const leftReverse = {
    ...left,
    facts: { ...left.facts, title: [reversedSupports, ...left.facts.title.slice(1)] }
  };
  const reverseDecision = compareOccurrenceIdentity(
    pair[0] === left.candidateId ? leftReverse : rightUnchanged,
    pair[1] === right.candidateId ? rightUnchanged : leftReverse
  );
  const supportOrderB = cloneComposition(composition, {
    occurrenceCandidates: composition.occurrenceCandidates.map((candidate) => candidate.candidateId === left.candidateId ? leftReverse : candidate),
    occurrenceDecisions: [reverseDecision]
  });
  assert.throws(() => prepare(supportOrderA, pair, language), { code: 'SOURCE_BINDING_FAILED' });
  const first = prepare(legacySyntheticComposition(supportOrderA), pair, language);
  const second = prepare(legacySyntheticComposition(supportOrderB), pair, language);
  assert.equal(first.sourceIdentityBinding.schema, 'ei-source-identity-question-binding-internal/v1');
  assert.equal(first.plan.planHash, second.plan.planHash);
  assert.equal(first.sourceIdentityBinding.digest, second.sourceIdentityBinding.digest);
  assert.equal(first.sourceIdentityBinding.selectedCandidates.find((candidate) => candidate.candidateId === left.candidateId)
    .facts.find((claim) => claim.field === 'title').supports.length, 2);
});

test('equal-byte evidence remains distinct and is marked duplicate rather than independent corroboration', async (t) => {
  const bytes = eventPage({ city: 'Portland', startDate: '2027-08-01' });
  const composition = await compose(t, [
    { bytes, url: 'https://one.example.test/event' },
    { bytes, url: 'https://two.example.test/event' }
  ]);
  const pair = composition.occurrenceCandidates.map((candidate) => candidate.candidateId).sort();
  const result = prepare(composition, pair);
  const supports = result.sourceIdentityBinding.selectedCandidates.flatMap((candidate) => candidate.facts.flatMap((claim) => claim.supports));
  const fullHash = digest(bytes);

  assert.equal(new Set(supports.map((support) => support.evidenceId)).size, 2);
  assert.ok(supports.every((support) => support.contentHash === fullHash));
  assert.equal(new Set(supports.map((support) => support.duplicateGroupId)).size, 1);
  assert.deepEqual(result.sourceIdentityBinding.comparison.duplicateContentHashes, [fullHash]);
  assert.equal(result.plan.authorityScope.independentVerificationGranted, false);
  assert.ok(!('independence' in supports[0]));
  assertBlockedPlan(result.plan, pair);
});

test('missing language is unknown and known non-English language keeps review behavior', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const pair = [candidateForCity(composition, 'Seattle').candidateId, candidateForCity(composition, 'Vancouver').candidateId];
  const missing = prepare(composition, pair, {});
  assert.equal(selectedQuestion(missing.plan).eligible, false);
  assert.ok(selectedQuestion(missing.plan).reasonCodes.includes('language_unknown'));
  assertBlockedPlan(missing.plan, pair);

  const nonEnglish = prepare(composition, pair, languageMap(composition, 'fr'));
  assert.equal(selectedQuestion(nonEnglish.plan).eligible, true);
  assert.equal(selectedQuestion(nonEnglish.plan).reviewRequired, true);
  assert.ok(selectedQuestion(nonEnglish.plan).reviewReasons.includes('non_english_or_multilingual_input_requires_review'));
  assert.ok(nonEnglish.sourceIdentityBinding.selectedCandidates.flatMap((candidate) => candidate.facts)
    .flatMap((claim) => claim.supports).every((support) => support.languageLabel === 'fr'));
});

test('missing, altered, cross-composition, malformed, customer-supplied, and unknown references fail closed', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const left = candidateForCity(composition, 'Seattle');
  const right = candidateForCity(composition, 'Vancouver');
  const pair = [left.candidateId, right.candidateId];
  const firstClaim = left.facts.title[0];
  const reject = (value, ids = pair) => assert.throws(() => prepare(value, ids, {}), SourceIdentityQuestionPreparationError);

  reject(composition, [left.candidateId, left.candidateId]);
  reject(composition, [left.candidateId, 'event-unknown']);
  reject(changedCandidate(composition, left.candidateId, (candidate) => ({ ...candidate, facts: { ...candidate.facts, title: [{ ...firstClaim, supports: [{ ...firstClaim.supports[0], evidenceId: '00000000-0000-4000-8000-000000000000' }] }] } })));
  reject(changedCandidate(composition, left.candidateId, (candidate) => ({ ...candidate, facts: { ...candidate.facts, title: [{ ...firstClaim, supports: [{ ...firstClaim.supports[0], contentHash: '0'.repeat(64) }] }] } })));
  reject(changedCandidate(composition, left.candidateId, (candidate) => ({ ...candidate, facts: { ...candidate.facts, title: [{ ...firstClaim, supports: [{ ...firstClaim.supports[0], field: 'startDate' }] }] } })));
  reject(changedCandidate(composition, left.candidateId, (candidate) => ({ ...candidate, facts: { ...candidate.facts, title: [{ ...firstClaim, value: 'Changed title' }] } })));
  reject(changedCandidate(composition, left.candidateId, (candidate) => ({ ...candidate, facts: { ...candidate.facts, title: [{ ...firstClaim, origin: 'customer_supplied' }] } })));
  reject(changedCandidate(composition, left.candidateId, (candidate) => ({
    ...candidate,
    facts: { ...candidate.facts, title: [{ ...firstClaim, supports: [{ ...firstClaim.supports[0], locator: { kind: 'text-range', startByte: 0, endByte: 512 * 1024 + 1 } }] }] }
  })));

  const missingSummary = cloneComposition(composition, {
    sources: composition.sources.map((source) => source.evidence?.evidenceId === firstClaim.supports[0].evidenceId
      ? { ...source, evidence: null }
      : source)
  });
  reject(missingSummary);
  const noAuthority = { ...composition, tenantId: 'tenant-a', sourceAuthority: 'official' };
  reject(noAuthority);
  reject(cloneComposition(composition, { transitionLinks: [{}] }));
  assert.throws(() => prepare(composition, pair, { [firstClaim.supports[0].evidenceId]: 'en\ud800' }), SourceIdentityQuestionPreparationError);
  assert.throws(() => prepare(composition, pair, Object.defineProperty({}, 'candidateIds', { enumerable: true, get() { throw new Error('getter must not run'); } })), SourceIdentityQuestionPreparationError);

  let proxyTrapCount = 0;
  const throwingTraps = {
    get() { proxyTrapCount += 1; throw new Error('get trap must not run'); },
    getPrototypeOf() { proxyTrapCount += 1; throw new Error('prototype trap must not run'); },
    ownKeys() { proxyTrapCount += 1; throw new Error('ownKeys trap must not run'); },
    getOwnPropertyDescriptor() { proxyTrapCount += 1; throw new Error('descriptor trap must not run'); }
  };
  const trapped = new Proxy(composition, throwingTraps);
  reject(trapped);
  const nestedRecordProxy = new Proxy(composition.sources[0], throwingTraps);
  reject(cloneComposition(composition, {
    sources: composition.sources.map((source, index) => index === 0 ? nestedRecordProxy : source)
  }));
  const nestedArrayProxy = new Proxy(composition.occurrenceCandidates, throwingTraps);
  reject(cloneComposition(composition, { occurrenceCandidates: nestedArrayProxy }));
  const revoked = Proxy.revocable(composition.occurrenceCandidates[0], {});
  revoked.revoke();
  reject(cloneComposition(composition, {
    occurrenceCandidates: [revoked.proxy, ...composition.occurrenceCandidates.slice(1)]
  }));
  assert.equal(proxyTrapCount, 0);
});

test('language metadata is bounded at eight source IDs before descriptor copying', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const pair = [candidateForCity(composition, 'Seattle').candidateId, candidateForCity(composition, 'Vancouver').candidateId];
  const languageByEvidenceId = Object.fromEntries(Array.from({ length: 9 }, (_, index) => [`evidence-extra-${index}`, 'en']));
  assert.throws(() => prepare(composition, pair, languageByEvidenceId), (error) => {
    assert.ok(error instanceof SourceIdentityQuestionPreparationError);
    assert.equal(error.code, 'RESOURCE_LIMIT_EXCEEDED');
    return true;
  });
});

test('expired-looking retrieval metadata remains provenance and does not claim current authorization', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const pair = [candidateForCity(composition, 'Seattle').candidateId, candidateForCity(composition, 'Vancouver').candidateId];
  const evidenceId = composition.occurrenceCandidates.find((candidate) => candidate.candidateId === pair[0]).facts.title[0].supports[0].evidenceId;
  const stale = cloneComposition(composition, {
    sources: composition.sources.map((source) => source.evidence?.evidenceId === evidenceId
      ? { ...source, evidence: { ...source.evidence, expiresAt: '2000-01-01T00:00:00.000Z' } }
      : source)
  });
  const result = prepare(stale, pair);
  const summary = result.sourceIdentityBinding.sourceEvidence.find((item) => item.evidenceId === evidenceId);
  assert.equal(summary.expiresAt, '2000-01-01T00:00:00.000Z');
  assert.equal(result.plan.readinessStatus, 'blocked');
  assert.equal(result.sourceIdentityBinding.sourceAuthority, 'not_evaluated');
});

function syntheticSupport(evidence, pointer, value) {
  return {
    evidenceId: evidence.evidenceId,
    contentHash: evidence.contentHash,
    locator: { kind: 'json-pointer', pointer },
    field: 'name',
    value
  };
}

function legacySyntheticPairComposition(composition, pair, { perCandidate = 16, pointerBytes = 8, valueBytes = 0, extraSeries = false } = {}) {
  const byId = new Map(composition.occurrenceCandidates.map((candidate) => [candidate.candidateId, candidate]));
  const summaries = composition.sources.map((source) => source.evidence).filter(Boolean);
  const candidates = pair.map((candidateId, candidateIndex) => {
    const summary = summaries.find((item) => item.evidenceId === byId.get(candidateId).facts.title[0].supports[0].evidenceId);
    const titleCount = perCandidate;
    const title = Array.from({ length: titleCount }, (_, index) => {
      const label = `Title ${candidateIndex}-${index}`;
      const value = valueBytes ? label.padEnd(valueBytes, 'x') : label;
      return {
      value,
      origin: 'sourced',
      supports: [syntheticSupport(summary, `/${'p'.repeat(pointerBytes - 1)}${index}`, value)]
    };
    });
    const facts = { title };
    if (extraSeries && candidateIndex === 0) {
      facts.series = [{
        value: 'Garden Light Tour',
        origin: 'sourced',
        supports: [
          {
            evidenceId: summary.evidenceId,
            contentHash: summary.contentHash,
            locator: { kind: 'json-pointer', pointer: '/series' },
            field: 'series',
            value: 'Garden Light Tour'
          }
        ]
      }];
    }
    return { schema: 'ei-occurrence-observation-internal/v1', candidateId, facts };
  });
  const decision = compareOccurrenceIdentity(candidates[0], candidates[1]);
  return legacySyntheticComposition(composition, {
    occurrenceCandidates: composition.occurrenceCandidates.map((candidate) => candidates.find((item) => item.candidateId === candidate.candidateId) ?? candidate),
    occurrenceDecisions: [decision]
  });
}

function titleClaimsTextBytes(lengths) {
  const claims = lengths.map((length, index) => ({
    field: 'title',
    value: `${index.toString(36)}${'x'.repeat(length - 1)}`,
    origin: 'sourced',
    retentionTags: ['event_identity', 'occurrence']
  }));
  return Buffer.byteLength(stableJsonTest(claims), 'utf8');
}

function lengthsForTitleTextBytes(targetBytes, prefix = []) {
  for (let length = 1; length <= 512; length += 1) {
    const lengths = [...prefix, length];
    if (titleClaimsTextBytes(lengths) === targetBytes) return lengths;
  }
  throw new Error(`Could not construct exact ${targetBytes}-byte title group`);
}

function legacyMinimalPairComposition(composition, pair, leftLengths, rightLengths, pointerBytes = 8) {
  const lengthsById = new Map([[pair[0], leftLengths], [pair[1], rightLengths]]);
  const originalById = new Map(composition.occurrenceCandidates.map((candidate) => [candidate.candidateId, candidate]));
  const replacementById = new Map();
  for (const candidateId of pair) {
    const original = originalById.get(candidateId);
    assert.ok(original?.facts.title?.[0]?.supports?.[0]);
    const evidenceId = original.facts.title[0].supports[0].evidenceId;
    const evidence = composition.sources.find((source) => source.evidence?.evidenceId === evidenceId)?.evidence;
    assert.ok(evidence);
    const title = lengthsById.get(candidateId).map((length, index) => {
      const value = `${index.toString(36)}${'x'.repeat(length - 1)}`;
      return {
        value,
        origin: 'sourced',
        supports: [syntheticSupport(evidence, `/${'p'.repeat(pointerBytes - 1)}`, value)]
      };
    });
    replacementById.set(candidateId, {
      schema: 'ei-occurrence-observation-internal/v1',
      candidateId,
      facts: { title }
    });
  }
  const ordered = pair.map((candidateId) => replacementById.get(candidateId));
  return legacySyntheticComposition(composition, {
    occurrenceCandidates: composition.occurrenceCandidates.map((candidate) => replacementById.get(candidate.candidateId) ?? candidate),
    occurrenceDecisions: [compareOccurrenceIdentity(ordered[0], ordered[1])]
  });
}

function withDuplicateGroupIdLength(composition, length) {
  return cloneComposition(composition, {
    sources: composition.sources.map((source) => source.evidence
      ? { ...source, evidence: { ...source.evidence, duplicateGroupId: 'd'.repeat(length) } }
      : source)
  });
}

function withSelectedPositionCount(composition, pair, positionCount) {
  const evidenceIds = new Set(pair.map((candidateId) => {
    const candidate = composition.occurrenceCandidates.find((item) => item.candidateId === candidateId);
    return candidate.facts.title[0].supports[0].evidenceId;
  }));
  let changed = false;
  const sources = composition.sources.map((source) => {
    if (!source.evidence || !evidenceIds.has(source.evidence.evidenceId) || changed) return source;
    changed = true;
    return { ...source, evidence: { ...source.evidence, positionCount } };
  });
  assert.ok(changed);
  return cloneComposition(composition, { sources });
}

function withFirstSelectedLocatorPadding(composition, pair, extraBytes) {
  if (extraBytes === 0) return composition;
  const candidateId = pair[0];
  const replacements = new Map();
  for (const candidate of composition.occurrenceCandidates) {
    if (candidate.candidateId !== candidateId) continue;
    const firstClaim = candidate.facts.title[0];
    const firstSupport = firstClaim.supports[0];
    const support = {
      ...firstSupport,
      locator: { ...firstSupport.locator, pointer: `${firstSupport.locator.pointer}${'p'.repeat(extraBytes)}` }
    };
    const title = [{ ...firstClaim, supports: [support] }, ...candidate.facts.title.slice(1)];
    replacements.set(candidate.candidateId, { ...candidate, facts: { ...candidate.facts, title } });
  }
  const updated = composition.occurrenceCandidates.map((candidate) => replacements.get(candidate.candidateId) ?? candidate);
  const pairCandidates = pair.map((candidateId) => updated.find((candidate) => candidate.candidateId === candidateId));
  return cloneComposition(composition, {
    occurrenceCandidates: updated,
    occurrenceDecisions: [compareOccurrenceIdentity(pairCandidates[0], pairCandidates[1])]
  });
}

test('legacy v1 groups 32 supported claims by their exact candidate and evidence identity without treating them as independent sources', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const pair = [candidateForCity(composition, 'Seattle').candidateId, candidateForCity(composition, 'Vancouver').candidateId].sort();
  const atCap = legacySyntheticPairComposition(composition, pair);
  const result = prepare(atCap, pair);
  assert.equal(result.plan.state.observations.length, 2);
  assert.equal(result.sourceIdentityBinding.selectedCandidates.reduce((sum, candidate) => sum + candidate.facts.length, 0), 32);
  assert.equal(result.sourceIdentityBinding.observationGroups.length, 2);
  assert.equal(result.sourceIdentityBinding.limits.maxObservations, 32);
  assert.equal(result.sourceIdentityBinding.limits.observationTextBytes,
    result.plan.state.observations.reduce((sum, observation) => sum
      + Buffer.byteLength(observation.text, 'utf8') + Buffer.byteLength(observation.claimText, 'utf8'), 0));
  assertBlockedPlan(result.plan, pair);

  const over = legacySyntheticPairComposition(composition, pair, { perCandidate: 9, valueBytes: 512 });
  assert.throws(() => prepare(over, pair), (error) => {
    assert.ok(error instanceof SourceIdentityQuestionPreparationError);
    assert.equal(error.code, 'RESOURCE_LIMIT_EXCEEDED');
    return true;
  });
});

test('legacy v1 retains more than 32 comparator provenance references in two grouped observations', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const pair = [candidateForCity(composition, 'Seattle').candidateId, candidateForCity(composition, 'Vancouver').candidateId].sort();
  const input = legacySyntheticPairComposition(composition, pair, { perCandidate: 16, extraSeries: true });
  assert.equal(input.occurrenceDecisions[0].provenanceReferences.length, 33);

  const result = prepare(input, pair);
  assert.equal(result.sourceIdentityBinding.comparison.provenanceReferences.length, 33);
  assert.equal(result.sourceIdentityBinding.observationGroups.length, 2);
  assert.equal(result.plan.state.observations.length, 2);
  assert.equal(result.sourceIdentityBinding.selectedCandidates.reduce((sum, candidate) => sum + candidate.facts.length, 0), 33);
  assertBlockedPlan(result.plan, pair);
});

test('legacy v1 enforces exact UTF-8 observation and aggregate limits at the first byte over', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const pair = composition.occurrenceCandidates.map((candidate) => candidate.candidateId).sort();
  const leftAtFieldCap = lengthsForTitleTextBytes(4_096, Array(6).fill(512));
  const exactField = prepare(legacyMinimalPairComposition(composition, pair, leftAtFieldCap, [8]), pair);
  const exactFieldGroups = exactField.sourceIdentityBinding.observationGroups;
  assert.equal(Buffer.byteLength(exactFieldGroups.find((group) => group.candidateId === pair[0]).text, 'utf8'), 4_096);
  assert.equal(Buffer.byteLength(exactFieldGroups.find((group) => group.candidateId === pair[1]).text, 'utf8'), titleClaimsTextBytes([8]));
  assert.ok(exactFieldGroups.every((group) => Buffer.byteLength(group.text, 'utf8') <= 4_096));

  const fieldOver = legacyMinimalPairComposition(composition, pair, [...leftAtFieldCap.slice(0, -1), leftAtFieldCap.at(-1) + 1], [8]);
  const smallGroupBytes = titleClaimsTextBytes([8]);
  assert.ok(2 * (4_097 + smallGroupBytes) <= 10_000, 'aggregate cap does not mask the first per-group byte over');
  assert.throws(() => prepare(fieldOver, pair), (error) => {
    assert.ok(error instanceof SourceIdentityQuestionPreparationError);
    assert.equal(error.code, 'RESOURCE_LIMIT_EXCEEDED');
    return true;
  });

  const rightAtAggregateCap = lengthsForTitleTextBytes(904, [512]);
  const exactAggregate = prepare(legacyMinimalPairComposition(composition, pair, leftAtFieldCap, rightAtAggregateCap), pair);
  assert.deepEqual(exactAggregate.sourceIdentityBinding.observationGroups.map((group) => Buffer.byteLength(group.text, 'utf8')).sort((a, b) => a - b), [904, 4_096]);
  assert.equal(exactAggregate.sourceIdentityBinding.limits.observationTextBytes, 10_000,
    'the maintained preparer counts both equal text and claimText fields');

  const aggregateOver = legacyMinimalPairComposition(composition, pair, leftAtFieldCap,
    [...rightAtAggregateCap.slice(0, -1), rightAtAggregateCap.at(-1) + 1]);
  assert.equal(2 * (4_096 + 905), 10_002);
  assert.throws(() => prepare(aggregateOver, pair), (error) => {
    assert.ok(error instanceof SourceIdentityQuestionPreparationError);
    assert.equal(error.code, 'RESOURCE_LIMIT_EXCEEDED');
    return true;
  });
});

test('legacy v1 fails before scanning overlength strings and detects the exact first sidecar byte over', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const pair = [candidateForCity(composition, 'Seattle').candidateId, candidateForCity(composition, 'Vancouver').candidateId].sort();
  const original = composition.occurrenceCandidates.find((candidate) => candidate.candidateId === pair[0]);
  const oversizedTitle = { ...original.facts.title[0], value: 'x'.repeat(1_000_000) };
  const oversizedText = changedCandidate(composition, pair[0], (candidate) => ({
    ...candidate,
    facts: { ...candidate.facts, title: [oversizedTitle, ...candidate.facts.title.slice(1)] }
  }));
  assert.throws(() => prepare(oversizedText, pair), (error) => {
    assert.ok(error instanceof SourceIdentityQuestionPreparationError);
    assert.equal(error.code, 'RESOURCE_LIMIT_EXCEEDED');
    return true;
  });

  const titleCount = 16;
  const base = withSelectedPositionCount(withDuplicateGroupIdLength(
    legacySyntheticPairComposition(composition, pair, { perCandidate: titleCount, pointerBytes: 1 }), 1
  ), pair, 9);
  const baseResult = prepare(base, pair);
  const pointerStep = prepare(withSelectedPositionCount(withDuplicateGroupIdLength(
    legacySyntheticPairComposition(composition, pair, { perCandidate: titleCount, pointerBytes: 2 }), 1
  ), pair, 9), pair).sourceIdentityBinding.utf8Bytes - baseResult.sourceIdentityBinding.utf8Bytes;
  const duplicateGroupStep = prepare(withSelectedPositionCount(withDuplicateGroupIdLength(
    legacySyntheticPairComposition(composition, pair, { perCandidate: titleCount, pointerBytes: 1 }), 2
  ), pair, 9), pair).sourceIdentityBinding.utf8Bytes - baseResult.sourceIdentityBinding.utf8Bytes;
  const locatorStep = prepare(withFirstSelectedLocatorPadding(base, pair, 1), pair)
    .sourceIdentityBinding.utf8Bytes - baseResult.sourceIdentityBinding.utf8Bytes;
  assert.ok(pointerStep > 0 && duplicateGroupStep > 0 && locatorStep > 0);

  let exactInput;
  let closest = { absoluteRemainder: Number.POSITIVE_INFINITY };
  for (let pointerBytes = 1; pointerBytes <= 510 && !exactInput; pointerBytes += 1) {
    for (let duplicateGroupLength = 1; duplicateGroupLength <= 128 && !exactInput; duplicateGroupLength += 1) {
      const baseBytes = baseResult.sourceIdentityBinding.utf8Bytes
        + pointerStep * (pointerBytes - 1) + duplicateGroupStep * (duplicateGroupLength - 1);
      const locatorBytes = pointerBytes + 1;
      const maxExtraLocatorBytes = 512 - locatorBytes;
      const remainder = 65_536 - baseBytes;
      for (let extra = 0; extra <= maxExtraLocatorBytes; extra += 1) {
        const residual = remainder - extra * locatorStep;
        if (Math.abs(residual) < closest.absoluteRemainder) {
          closest = { absoluteRemainder: Math.abs(residual), residual, pointerBytes, duplicateGroupLength, extra };
        }
        if (residual === 0) {
          exactInput = withSelectedPositionCount(withFirstSelectedLocatorPadding(withDuplicateGroupIdLength(
            legacySyntheticPairComposition(composition, pair, { perCandidate: titleCount, pointerBytes }), duplicateGroupLength
          ), pair, extra), pair, 9);
          break;
        }
      }
    }
  }
  assert.ok(exactInput, `the 65,536-byte sidecar boundary is reachable within source locator and sidecar caps; base=${baseResult.sourceIdentityBinding.utf8Bytes}, pointerStep=${pointerStep}, duplicateGroupStep=${duplicateGroupStep}, locatorStep=${locatorStep}, closest=${JSON.stringify(closest)}`);
  const atSidecarCap = prepare(exactInput, pair);
  assert.equal(atSidecarCap.sourceIdentityBinding.utf8Bytes, 65_536);
  const firstOverInput = withSelectedPositionCount(exactInput, pair, 10);
  assert.throws(() => prepare(firstOverInput, pair), (error) => {
    assert.ok(error instanceof SourceIdentityQuestionPreparationError);
    assert.equal(error.code, 'RESOURCE_LIMIT_EXCEEDED');
    return true;
  });
});

test('legacy v1 rejects a materially oversized sidecar projection without truncating it', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const pair = composition.occurrenceCandidates.map((candidate) => candidate.candidateId).sort();
  const oversized = legacySyntheticPairComposition(composition, pair, { perCandidate: 16, pointerBytes: 510 });
  assert.throws(() => prepare(oversized, pair), (error) => {
    assert.ok(error instanceof SourceIdentityQuestionPreparationError);
    assert.equal(error.code, 'RESOURCE_LIMIT_EXCEEDED');
    return true;
  });
});

test('rejects an unquoted sensitive source value before question serialization', async (t) => {
  const composition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01', name: 'password=abcdefghijklmnop' }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const pair = composition.occurrenceCandidates.map((candidate) => candidate.candidateId).sort();
  assert.throws(() => prepare(composition, pair), (error) => {
    assert.ok(error instanceof SourceIdentityQuestionPreparationError);
    assert.equal(error.code, 'SENSITIVE_CONTENT');
    return true;
  });
});

test('rejects quoted credential assignments after actual composer decoding and preserves safe quoted names', async (t) => {
  const sensitiveName = 'password="abcdefghijklmnop"';
  const encodedCases = [
    { label: 'JSON escaped double quotes', rawNameJson: undefined },
    { label: 'JSON Unicode-escaped credential label', rawNameJson: '"pass\\u0077ord=\\"abcdefghijklmnop\\""' },
    { label: 'JSON Unicode-escaped assignment quotes', rawNameJson: '"password=\\u0022abcdefghijklmnop\\u0022"' }
  ];

  for (const { label, rawNameJson } of encodedCases) {
    await t.test(label, async (subtest) => {
      const composition = await compose(subtest, [
        { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01', name: sensitiveName, rawNameJson }), url: 'https://events.example.test/seattle' },
        { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
      ]);
      const left = candidateForCity(composition, 'Seattle');
      const right = candidateForCity(composition, 'Vancouver');
      const pair = [left.candidateId, right.candidateId].sort();
      assert.equal(left.facts.title[0].value, sensitiveName, 'the maintained composer decoded the intended selected claim');

      const rawObservation = {
        observationRef: 'sensitive-probe',
        kind: 'claim_evidence_text',
        sourceRef: 'source-probe',
        candidateRef: left.candidateId,
        fieldRef: 'title-probe',
        language: 'en',
        text: sensitiveName,
        claimText: sensitiveName
      };
      assert.throws(() => prepareIndependentQuestions([rawObservation]), (error) => {
        assert.ok(error instanceof QuestionPreparationError);
        assert.equal(error.code, 'SENSITIVE_CONTENT');
        return true;
      });
      assert.throws(() => prepare(composition, pair), (error) => {
        assert.ok(error instanceof SourceIdentityQuestionPreparationError);
        assert.equal(error.code, 'SENSITIVE_CONTENT');
        return true;
      });
    });
  }

  const safeName = 'Garden "Evening" Festival';
  const safeComposition = await compose(t, [
    { bytes: eventPage({ city: 'Seattle', startDate: '2027-08-01', name: safeName }), url: 'https://events.example.test/seattle' },
    { bytes: eventPage({ city: 'Vancouver', startDate: '2027-08-02' }), url: 'https://events.example.test/vancouver' }
  ]);
  const pair = [candidateForCity(safeComposition, 'Seattle').candidateId, candidateForCity(safeComposition, 'Vancouver').candidateId].sort();
  const result = prepare(safeComposition, pair);
  assert.ok(result.sourceIdentityBinding.selectedCandidates.some((candidate) => candidate.facts.some((claim) => claim.value === safeName)));
  assert.equal(result.plan.readinessStatus, 'blocked');
  assert.equal(result.plan.executionStatus, 'not_dispatched');
});
