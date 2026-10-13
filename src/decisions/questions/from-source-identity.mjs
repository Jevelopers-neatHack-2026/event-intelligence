import { createHash } from 'node:crypto';
import { types } from 'node:util';

import { compareOccurrenceIdentity } from '../../discovery/occurrences/identity.mjs';
import { validateSourceCorroboration, corroborationDigest, normalizedAttributionUrl, CorroborationError } from '../../discovery/identity/corroboration.mjs';
import { QuestionPreparationError, deriveQuestionTargetRef, prepareIndependentQuestions } from './prepare.mjs';
import { hasCredentialLikeText } from './sensitive-content.mjs';

const COMPOSITION_SCHEMA = 'ei-source-identity-composition-internal/v1';
const COMPOSITION_SCHEMA_V2 = 'ei-source-identity-composition-internal/v2';
const OCCURRENCE_SCHEMA = 'ei-occurrence-observation-internal/v1';
const DECISION_SCHEMA = 'ei-occurrence-identity-decision-internal/v1';
const TRANSITION_SCHEMA = 'ei-occurrence-transition-internal/v1';
const QUESTION_ID = 'Q-EI-IDENTITY:v1';
const BINDING_SCHEMA = 'ei-source-identity-question-binding-internal/v1';
const BINDING_SCHEMA_V2 = 'ei-source-identity-question-binding-internal/v2';
const BINDING_HASH_DOMAIN = 'event-intelligence:source-identity-question-binding:v1\0';
const OBSERVATION_HASH_DOMAIN = 'event-intelligence:source-identity-question-group:v1\0';
const FIELD_REF_HASH_DOMAIN = 'event-intelligence:source-identity-question-field:v1\0';

const MAX_SOURCES = 8;
const MAX_STATUS_MENTIONS_PER_SOURCE = 32;
const MAX_CANDIDATES = 23;
const MAX_COMPARISONS = 256;
const MAX_TRANSITIONS = 64;
const MAX_UNRESOLVED_TRANSITIONS = 128;
const MAX_FACTS = 128;
const MAX_OBSERVATIONS = 32;
const MAX_TEXT_BYTES_PER_FIELD = 4_096;
const MAX_TOTAL_TEXT_BYTES = 10_000;
const MAX_SUPPORTS_PER_CLAIM = 8;
const MAX_PROVENANCE_REFERENCES = MAX_FACTS * MAX_SUPPORTS_PER_CLAIM;
const MAX_SIDE_CAR_UTF8_BYTES = 65_536;
const MAX_SOURCE_BYTES = 512 * 1024;
const MAX_LOCATOR_BYTES = 512;
const MAX_FIELD_BYTES = 120;
const MAX_VALUE_BYTES = 512;
const MAX_TEMPORAL_BYTES = 100;
const SHA256 = /^[a-f0-9]{64}$/;
const OPAQUE_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const SOURCE_FIELDS = Object.freeze({
  title: new Set(['name']),
  series: new Set(['series', 'seriesName']),
  edition: new Set(['edition', 'eventEdition']),
  city: new Set(['location.address.addressLocality']),
  venue: new Set(['location.name']),
  start: new Set(['startDate']),
  end: new Set(['endDate']),
  status: new Set(['eventStatus'])
});
const FACT_FIELDS = Object.freeze(['title', 'series', 'edition', 'city', 'venue', 'start', 'end', 'status']);
const ROOT_KEYS = new Set([
  'schema', 'sources', 'facts', 'entityCandidates', 'occurrenceCandidates', 'entityDecisions',
  'occurrenceDecisions', 'transitionLinks', 'unresolvedTransitions', 'linkCandidates',
  'linkCandidatesOmitted', 'sourceAuthority', 'limits'
]);
const ROOT_ARRAY_KEYS = new Set(['sources', 'facts', 'entityCandidates', 'occurrenceCandidates', 'entityDecisions', 'occurrenceDecisions', 'transitionLinks', 'unresolvedTransitions', 'linkCandidates']);

export class SourceIdentityQuestionPreparationError extends Error {
  constructor(code = 'INVALID_INPUT') {
    super(code === 'VISIBLE_STATUS_REVIEW_REQUIRED'
      ? 'Source-level status evidence requires review before identity question preparation.'
      : 'Source identity question preparation input is invalid or outside its local bounds.');
    this.name = 'SourceIdentityQuestionPreparationError';
    this.code = code;
  }
}

function fail(code = 'INVALID_INPUT') {
  throw new SourceIdentityQuestionPreparationError(code);
}

function byteLength(value) {
  return Buffer.byteLength(value, 'utf8');
}

function wellFormed(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

function safeText(value, maximum, { empty = false } = {}) {
  if (typeof value !== 'string') fail();
  if (value.length > maximum) fail('RESOURCE_LIMIT_EXCEEDED');
  if (!wellFormed(value) || (!empty && value.length === 0)
    || (!empty && value.trim().length === 0) || value.includes('\0') || byteLength(value) > maximum) fail();
  return value;
}

function safeReference(value) {
  if (typeof value !== 'string' || !OPAQUE_REFERENCE.test(value) || /^(?:https?|data|file):/i.test(value)
    || value.includes('://') || /(?:token|secret|password|key)=/i.test(value)) fail();
  return value;
}

function safeDataRecord(value, allowedKeys, { exact = true } = {}) {
  try {
    if (types.isProxy(value)) fail();
    if (value === null || typeof value !== 'object' || Array.isArray(value)) fail();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail();
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string' || !allowedKeys.has(key))) fail();
    if (exact && (keys.length !== allowedKeys.size || [...allowedKeys].some((key) => !keys.includes(key)))) fail();
    const descriptors = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) fail();
      descriptors[key] = descriptor;
    }
    return descriptors;
  } catch (error) {
    if (error instanceof SourceIdentityQuestionPreparationError) throw error;
    fail();
  }
}

function safeDescriptorMap(value) {
  try {
    if (types.isProxy(value)) fail();
    if (value === null || typeof value !== 'object' || Array.isArray(value)) fail();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail();
    const keys = Reflect.ownKeys(value);
    if (keys.length > MAX_SOURCES) fail('RESOURCE_LIMIT_EXCEEDED');
    if (keys.some((key) => typeof key !== 'string')) fail();
    const descriptors = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) fail();
      descriptors[key] = descriptor;
    }
    return descriptors;
  } catch (error) {
    if (error instanceof SourceIdentityQuestionPreparationError) throw error;
    fail();
  }
}

function dataValue(value, key, allowedKeys) {
  if (types.isProxy(value) || value === null || typeof value !== 'object' || Array.isArray(value)) fail();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail();
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) fail();
  if (allowedKeys && !allowedKeys.has(key)) fail();
  return descriptor.value;
}

function safeArray(value, maximum, { exactLength } = {}) {
  try {
    if (types.isProxy(value)) fail();
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fail();
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    if (!lengthDescriptor || !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value > maximum) fail('RESOURCE_LIMIT_EXCEEDED');
    const length = lengthDescriptor.value;
    if (exactLength !== undefined && length !== exactLength) fail();
    const keys = Reflect.ownKeys(value);
    if (keys.length !== length + 1 || !keys.includes('length')) fail();
    const values = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) fail();
      values.push(descriptor.value);
    }
    return values;
  } catch (error) {
    if (error instanceof SourceIdentityQuestionPreparationError) throw error;
    fail();
  }
}

function stableJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
}

function hash(domain, value) {
  return createHash('sha256').update(domain, 'utf8').update(stableJson(value), 'utf8').digest('hex');
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function parseOptions(rawOptions) {
  const options = safeDataRecord(rawOptions, new Set(['candidateIds', 'languageByEvidenceId']));
  const candidateIds = safeArray(options.candidateIds.value, 2, { exactLength: 2 });
  const left = safeReference(candidateIds[0]);
  const right = safeReference(candidateIds[1]);
  if (left === right) fail('INVALID_TARGET_BINDING');
  const pair = [left, right].sort();
  const languageDescriptors = safeDescriptorMap(options.languageByEvidenceId.value);
  return { pair, languageDescriptors };
}

function assertCompositionShape(composition) {
  const schema = dataValue(composition, 'schema');
  const descriptors = safeDataRecord(composition, schema === COMPOSITION_SCHEMA_V2
    ? new Set([...ROOT_KEYS, 'corroboration', 'corroborationFactBindings']) : ROOT_KEYS);
  for (const key of ROOT_ARRAY_KEYS) {
    if (!Object.hasOwn(descriptors, key) || !Object.hasOwn(descriptors[key], 'value')) fail();
  }
  if (![COMPOSITION_SCHEMA, COMPOSITION_SCHEMA_V2].includes(schema) || descriptors.sourceAuthority.value !== 'not_evaluated') fail('SOURCE_BINDING_FAILED');
  return descriptors;
}

function projectCorroboration(root, sourceById) {
  if (root.schema.value === COMPOSITION_SCHEMA) return null;
  const graph = validateSourceCorroboration(root.corroboration.value);
  const nodeById = new Map(graph.nodes.map((node) => [node.candidateId, node]));
  const observed = new Set();
  let identityCount = 0;
  const bindIdentity = (id, kind, supports) => {
    const node = nodeById.get(id);
    if (!node || node.kind !== kind || observed.has(id)) fail('SOURCE_BINDING_FAILED');
    const keys = supports.map((support) => {
      if (support.evidenceId !== node.evidenceId || support.contentHash !== node.contentHash) fail('SOURCE_BINDING_FAILED');
      return corroborationDigest('source-identity-support', support);
    }).sort();
    identityCount += keys.length;
    if (identityCount > MAX_FACTS) fail('RESOURCE_LIMIT_EXCEEDED');
    if (stableJson(keys) !== stableJson(node.identityKeys)) fail('SOURCE_BINDING_FAILED');
    observed.add(id);
  };
  for (const raw of safeArray(root.occurrenceCandidates.value, MAX_CANDIDATES)) {
    const candidate = projectCandidate(raw, sourceById);
    bindIdentity(candidate.candidateId, 'event', Object.values(candidate.facts).flatMap((claims) => claims.flatMap((claim) => claim.supports)));
  }
  for (const raw of safeArray(root.entityCandidates.value, MAX_CANDIDATES)) {
    const candidate = safeDataRecord(raw, new Set(['schema', 'candidateId', 'kind', 'names']));
    if (candidate.schema.value !== 'ei-entity-observation-internal/v1' || candidate.kind.value !== 'organization') fail('SOURCE_BINDING_FAILED');
    const names = safeArray(candidate.names.value, 24).map((claim) => projectClaim(claim, 'title', sourceById));
    bindIdentity(safeReference(candidate.candidateId.value), 'organization', names.flatMap((claim) => claim.supports));
  }
  if (observed.size !== nodeById.size) fail('SOURCE_BINDING_FAILED');

  const facts = safeArray(root.facts.value, MAX_FACTS);
  const factById = new Map();
  for (const fact of facts) {
    const id = safeReference(dataValue(fact, 'factId'));
    if (factById.has(id)) fail('SOURCE_BINDING_FAILED');
    factById.set(id, fact);
  }
  const bindingByClaim = new Map();
  const usedFacts = new Set();
  const factBindings = safeArray(root.corroborationFactBindings.value, MAX_FACTS).map((value) => {
    const entry = safeDataRecord(value, new Set(['claimId', 'factId']));
    const claimId = entry.claimId.value;
    const factId = safeReference(entry.factId.value);
    if (typeof claimId !== 'string' || !SHA256.test(claimId) || bindingByClaim.has(claimId)
      || usedFacts.has(factId) || !factById.has(factId)
      || !graph.claims.some((claim) => claim.claimId === claimId && claim.status === 'retained')) fail('SOURCE_BINDING_FAILED');
    const binding = Object.freeze({ claimId, factId });
    bindingByClaim.set(claimId, binding); usedFacts.add(factId);
    return binding;
  }).sort((a, b) => a.claimId < b.claimId ? -1 : 1);
  if (graph.claims.filter((claim) => claim.status === 'retained').length !== factBindings.length
    || facts.some((fact) => dataValue(fact, 'field') === 'isBasedOn' && !usedFacts.has(dataValue(fact, 'factId')))) fail('SOURCE_BINDING_FAILED');
  const observedClaims = new Set();
  const sourceBoundNodes = new Set();
  for (const rawSource of safeArray(root.sources.value, MAX_SOURCES)) {
    const evidence = dataValue(rawSource, 'evidence');
    if (evidence === null) continue;
    const evidenceId = safeReference(dataValue(evidence, 'evidenceId'));
    const source = sourceById.get(evidenceId);
    const stored = dataValue(rawSource, 'storedSource');
    const extraction = dataValue(rawSource, 'extraction');
    if (!source || dataValue(extraction, 'sourceHash') !== `sha256:${source.contentHash}`
      || dataValue(stored, 'contentHash') !== source.contentHash) fail('SOURCE_BINDING_FAILED');
    const urls = [...new Set(['sourceUrl', 'canonicalUrl'].map((key) =>
      normalizedAttributionUrl(safeText(dataValue(stored, key), 4096))).filter(Boolean))].sort();
    for (const [kind, field] of [['event', 'events'], ['organization', 'organizations']]) {
      const entities = safeArray(dataValue(extraction, field), 24);
      for (const entity of entities) {
        const block = dataValue(entity, 'blockIndex');
        const ordinal = dataValue(entity, 'ordinal');
        if (!Number.isSafeInteger(block) || block < 0 || block >= 8 || !Number.isSafeInteger(ordinal) || ordinal < 0 || ordinal >= 24) fail('SOURCE_BINDING_FAILED');
        const id = `${kind === 'event' ? 'event' : 'org'}-${evidenceId.replaceAll('-', '')}-${block}-${ordinal}`;
        const node = nodeById.get(id);
        if (!node) continue;
        const pointer = safeText(dataValue(entity, 'jsonPointer'), MAX_LOCATOR_BYTES, { empty: true });
        if (node.entityPointer !== pointer || node.entityKey !== `${kind}:script-${block}:${ordinal}`
          || node.sourceEntityCount !== entities.length || stableJson(node.sourceUrls) !== stableJson(urls)
          || dataValue(entity, 'kind') !== kind || dataValue(entity, 'entityId') !== `${kind}:script-${block}:${pointer}`) fail('SOURCE_BINDING_FAILED');
        if (sourceBoundNodes.has(id)) fail('SOURCE_BINDING_FAILED');
        sourceBoundNodes.add(id);
        const rootPointer = `${pointer}/isBasedOn`;
        for (const candidate of safeArray(dataValue(entity, 'candidates'), 64)) {
          const origin = dataValue(candidate, 'source');
          const jsonPointer = safeText(dataValue(origin, 'jsonPointer'), MAX_LOCATOR_BYTES, { empty: true });
          if (jsonPointer !== rootPointer && !jsonPointer.startsWith(`${rootPointer}/`)) continue;
          const locator = projectLocator(dataValue(origin, 'locator'));
          const rawValue = safeText(dataValue(candidate, 'rawValue'), 4096);
          if (dataValue(origin, 'kind') !== 'jsonld' || locator.kind !== 'text-range'
            || byteLength(rawValue) !== locator.endByte - locator.startByte) fail('SOURCE_BINDING_FAILED');
          const sourceRef = { evidenceId, contentHash: source.contentHash, locator,
            positionHash: createHash('sha256').update(rawValue, 'utf8').digest('hex'), jsonPointer };
          const matches = graph.claims.filter((claim) => claim.candidateId === id && stableJson(claim.sourceRef) === stableJson(sourceRef));
          if (matches.length !== 1 || observedClaims.has(matches[0].claimId)) fail('SOURCE_BINDING_FAILED');
          const claim = matches[0];
          observedClaims.add(claim.claimId);
          const value = dataValue(candidate, 'normalizedValue');
          if (claim.form === 'direct_string' && (typeof value !== 'string' || normalizedAttributionUrl(value) !== claim.targetUrl)) fail('SOURCE_BINDING_FAILED');
          if (claim.form === 'unsupported_shape' && jsonPointer === rootPointer) fail('SOURCE_BINDING_FAILED');
          if (claim.form === 'unsupported_value' && jsonPointer !== rootPointer) fail('SOURCE_BINDING_FAILED');
          if (claim.form !== 'direct_string') continue;
          const binding = bindingByClaim.get(claim.claimId);
          if (claim.status === 'retained') {
            const fact = factById.get(binding?.factId);
            if (!fact || dataValue(fact, 'field') !== 'isBasedOn' || dataValue(fact, 'status') !== 'sourced'
              || dataValue(fact, 'rawValue') !== rawValue || dataValue(fact, 'normalizedValue') !== value) fail('SOURCE_BINDING_FAILED');
            const supports = safeArray(dataValue(fact, 'supports'), 1);
            if (supports.length !== 1 || dataValue(supports[0], 'contentHash') !== source.contentHash
              || dataValue(supports[0], 'duplicateGroupId') !== source.duplicateGroupId || dataValue(supports[0], 'independence') !== 'unknown') fail('SOURCE_BINDING_FAILED');
          } else if (binding) fail('SOURCE_BINDING_FAILED');
        }
      }
    }
  }
  if (observedClaims.size !== graph.claims.length || sourceBoundNodes.size !== nodeById.size) fail('SOURCE_BINDING_FAILED');
  return { graph, factBindings };
}

function corroborationContext(graph, candidateId) {
  const cluster = graph.clusters.find((item) => item.members.includes(candidateId));
  if (!cluster) fail('SOURCE_BINDING_FAILED');
  const bases = [...new Set(graph.edges.filter((edge) => cluster.members.includes(edge.from)
    && cluster.members.includes(edge.to)).map((edge) => edge.basis))].sort();
  return Object.freeze({
    schema: graph.schema, policy: graph.policy, clusterId: cluster.clusterId,
    relation: cluster.members.length > 1 ? 'shared_dependence_cluster' : 'no_retained_dependence_link',
    independence: 'unknown', origin: 'not_established', sourceAuthority: 'not_evaluated',
    bases: Object.freeze(bases),
    unresolvedClaimCount: graph.unresolved.filter((item) => graph.claims.some((claim) =>
      claim.claimId === item.claimId && claim.candidateId === candidateId)).length,
  });
}

function projectEvidenceSummaries(rawSources) {
  const sourceRecords = safeArray(rawSources, MAX_SOURCES);
  const byId = new Map();
  for (const source of sourceRecords) {
    const sourceRecord = safeDataRecord(source, new Set(['evidence', 'storedSource', 'observedRetrievedAt', 'extraction']));
    const evidence = sourceRecord.evidence.value;
    if (evidence === null) continue;
    const record = safeDataRecord(evidence, new Set(['evidenceId', 'contentHash', 'duplicateGroupId', 'retrievedAt', 'expiresAt', 'positionCount']));
    const evidenceId = safeReference(record.evidenceId.value);
    const contentHash = record.contentHash.value;
    if (typeof contentHash !== 'string' || !SHA256.test(contentHash)) fail('SOURCE_BINDING_FAILED');
    const duplicateGroupId = safeReference(record.duplicateGroupId.value);
    const retrievedAt = safeText(record.retrievedAt.value, 64);
    const expiresAt = safeText(record.expiresAt.value, 64);
    if (!Number.isFinite(Date.parse(retrievedAt)) || !Number.isFinite(Date.parse(expiresAt))) fail('SOURCE_BINDING_FAILED');
    const positionCount = record.positionCount.value;
    if (!Number.isSafeInteger(positionCount) || positionCount < 0 || positionCount > 128 || byId.has(evidenceId)) fail('SOURCE_BINDING_FAILED');
    byId.set(evidenceId, Object.freeze({ evidenceId, contentHash, duplicateGroupId, retrievedAt, expiresAt, positionCount }));
  }
  return byId;
}

function assertSelectedStatusEvidenceSupported(rawSources, usedEvidenceIds, sourceById) {
  for (const source of safeArray(rawSources, MAX_SOURCES)) {
    const evidence = dataValue(source, 'evidence');
    if (evidence === null) continue;
    const evidenceId = dataValue(evidence, 'evidenceId');
    if (!usedEvidenceIds.has(evidenceId)) continue;
    const extraction = dataValue(source, 'extraction');
    if (dataValue(extraction, 'sourceHash') !== `sha256:${sourceById.get(evidenceId).contentHash}`) {
      fail('SOURCE_BINDING_FAILED');
    }
    const mentions = safeArray(dataValue(extraction, 'statusMentions'), MAX_STATUS_MENTIONS_PER_SOURCE);
    // A source-level notice cannot be assigned to either occurrence by this
    // adapter. Refuse before producing a projection that would omit it.
    if (mentions.length > 0) fail('VISIBLE_STATUS_REVIEW_REQUIRED');
  }
}

function findCandidates(rawCandidates, pair) {
  const candidates = safeArray(rawCandidates, MAX_CANDIDATES);
  const byId = new Map();
  const requested = new Set(pair);
  for (const candidate of candidates) {
    const descriptors = safeDataRecord(candidate, new Set(['schema', 'candidateId', 'facts']));
    const candidateId = safeReference(descriptors.candidateId.value);
    if (descriptors.schema.value !== OCCURRENCE_SCHEMA || byId.has(candidateId)) fail('SOURCE_BINDING_FAILED');
    if (requested.has(candidateId)) byId.set(candidateId, candidate);
  }
  if (byId.size !== 2) fail('UNKNOWN_TARGET_REFERENCE');
  return pair.map((candidateId) => byId.get(candidateId));
}

function projectLocator(rawLocator) {
  const kind = dataValue(rawLocator, 'kind');
  if (kind === 'text-range') {
    const record = safeDataRecord(rawLocator, new Set(['kind', 'startByte', 'endByte']));
    const startByte = record.startByte.value;
    const endByte = record.endByte.value;
    if (!Number.isSafeInteger(startByte) || !Number.isSafeInteger(endByte) || startByte < 0
      || endByte <= startByte || endByte > MAX_SOURCE_BYTES) fail('SOURCE_BINDING_FAILED');
    return Object.freeze({ kind, startByte, endByte });
  }
  if (kind === 'json-pointer') {
    const record = safeDataRecord(rawLocator, new Set(['kind', 'pointer']));
    const pointer = safeText(record.pointer.value, MAX_LOCATOR_BYTES, { empty: true });
    if (pointer !== '' && (!pointer.trim() || !/^(?:\/(?:[^~/]|~[01])*)*$/.test(pointer))) fail('SOURCE_BINDING_FAILED');
    return Object.freeze({ kind, pointer });
  }
  fail('SOURCE_BINDING_FAILED');
}

function projectSourceReference(rawReference, claimValue, field, sourceById) {
  const record = safeDataRecord(rawReference, new Set(['evidenceId', 'contentHash', 'locator', 'field', 'value']));
  const evidenceId = safeReference(record.evidenceId.value);
  const contentHash = record.contentHash.value;
  if (typeof contentHash !== 'string' || !SHA256.test(contentHash)) fail('SOURCE_BINDING_FAILED');
  const sourceField = safeText(record.field.value, MAX_FIELD_BYTES);
  if (!SOURCE_FIELDS[field].has(sourceField)) fail('SOURCE_BINDING_FAILED');
  const value = safeText(record.value.value, field === 'start' || field === 'end' ? MAX_TEMPORAL_BYTES : MAX_VALUE_BYTES);
  if (value !== claimValue) fail('SOURCE_BINDING_FAILED');
  const locator = projectLocator(record.locator.value);
  const summary = sourceById.get(evidenceId);
  if (!summary || summary.contentHash !== contentHash) fail('SOURCE_BINDING_FAILED');
  return Object.freeze({ evidenceId, contentHash, locator, field: sourceField, value });
}

function projectClaim(rawClaim, field, sourceById) {
  const temporal = field === 'start' || field === 'end';
  const keys = temporal ? new Set(['value', 'precision', 'origin', 'supports']) : new Set(['value', 'origin', 'supports']);
  const record = safeDataRecord(rawClaim, keys);
  const value = safeText(record.value.value, temporal ? MAX_TEMPORAL_BYTES : MAX_VALUE_BYTES);
  if (hasCredentialLikeText(value)) fail('SENSITIVE_CONTENT');
  const origin = record.origin.value;
  if (origin !== 'sourced') fail('UNSUPPORTED_ORIGIN');
  let precision;
  if (temporal) {
    precision = record.precision.value;
    if (!['date', 'local_datetime', 'instant', 'unknown'].includes(precision)) fail('SOURCE_BINDING_FAILED');
  }
  const rawSupports = safeArray(record.supports.value, MAX_SUPPORTS_PER_CLAIM);
  if (rawSupports.length === 0) fail('SOURCE_BINDING_FAILED');
  const supports = rawSupports.map((support) => projectSourceReference(support, value, field, sourceById));
  const supportKeys = supports.map((support) => stableJson({
    evidenceId: support.evidenceId,
    contentHash: support.contentHash,
    locator: support.locator,
    field: support.field,
    value: support.value
  }));
  if (new Set(supportKeys).size !== supportKeys.length) fail('SOURCE_BINDING_FAILED');
  supports.sort((left, right) => stableJson(left).localeCompare(stableJson(right), 'en'));
  return Object.freeze({ value, origin, ...(temporal ? { precision } : {}), supports: Object.freeze(supports) });
}

function projectCandidate(rawCandidate, sourceById, maxFacts = MAX_FACTS) {
  const candidate = safeDataRecord(rawCandidate, new Set(['schema', 'candidateId', 'facts']));
  const candidateId = safeReference(candidate.candidateId.value);
  if (candidate.schema.value !== OCCURRENCE_SCHEMA) fail('SOURCE_BINDING_FAILED');
  const factsRecord = safeDataRecord(candidate.facts.value, new Set(FACT_FIELDS), { exact: false });
  const facts = Object.create(null);
  let factCount = 0;
  for (const field of FACT_FIELDS) {
    if (!Object.hasOwn(factsRecord, field)) {
      facts[field] = Object.freeze([]);
      continue;
    }
    const claims = safeArray(factsRecord[field].value, maxFacts);
    factCount += claims.length;
    if (factCount > maxFacts) fail('RESOURCE_LIMIT_EXCEEDED');
    facts[field] = Object.freeze(claims.map((claim) => projectClaim(claim, field, sourceById)));
  }
  return { schema: OCCURRENCE_SCHEMA, candidateId, facts: Object.freeze(facts), factCount };
}

function retentionTags(field, claim) {
  const tags = ['occurrence'];
  if (field === 'title' || field === 'series') tags.push('event_identity');
  if (field === 'edition') tags.push('annual_edition');
  if (field === 'city') tags.push('tour_city');
  if (field === 'venue') tags.push('venue');
  if (field === 'start' || field === 'end') {
    tags.push('date');
    if (claim.precision === 'instant' && /(?:Z|[+-]\d{2}:\d{2})$/.test(claim.value)) tags.push('time_zone');
  }
  if (field === 'status' && claim.value === 'canceled') tags.push('cancellation');
  if (field === 'status' && claim.value === 'rescheduled') tags.push('reschedule');
  return Object.freeze(tags.sort());
}

function languageFor(evidenceId, descriptors) {
  if (!Object.hasOwn(descriptors, evidenceId)) return 'und';
  const descriptor = descriptors[evidenceId];
  if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) fail();
  const language = safeText(descriptor.value, 35);
  if (language.toLowerCase() === 'und' || language.toLowerCase() === 'mul') return language.toLowerCase();
  if (!/^(?:[A-Za-z]{2,8})(?:-[A-Za-z0-9]{1,8})*$/.test(language)) fail();
  return language;
}

function observationsFor(pair, candidates, languageDescriptors, sourceById, corroboration) {
  const selectedProjection = [];
  const groupsByKey = new Map();
  for (const candidate of candidates) {
    const candidateClaims = [];
    for (const field of FACT_FIELDS) {
      const claims = candidate.facts[field];
      for (const claim of claims) {
        const tags = retentionTags(field, claim);
        const supportRecords = [];
        for (const support of claim.supports) {
          const language = languageFor(support.evidenceId, languageDescriptors);
          const source = sourceById.get(support.evidenceId);
          if (!source || source.contentHash !== support.contentHash) fail('SOURCE_BINDING_FAILED');
          supportRecords.push(Object.freeze({
            ...support,
            duplicateGroupId: source.duplicateGroupId,
            languageLabel: language,
            languageLabelTrust: 'unverified_caller_metadata'
          }));
          const groupIdentity = Object.freeze({
            candidateId: candidate.candidateId,
            evidenceId: support.evidenceId,
            contentHash: support.contentHash,
            languageLabel: language
          });
          const groupKey = stableJson(groupIdentity);
          let group = groupsByKey.get(groupKey);
          if (!group) {
            if (groupsByKey.size >= MAX_OBSERVATIONS) fail('RESOURCE_LIMIT_EXCEEDED');
            group = { ...groupIdentity, claimsByKey: new Map() };
            groupsByKey.set(groupKey, group);
          }
          const claimProjection = Object.freeze({
            field,
            value: claim.value,
            origin: claim.origin,
            ...(claim.precision ? { precision: claim.precision } : {}),
            retentionTags: tags
          });
          group.claimsByKey.set(stableJson(claimProjection), claimProjection);
        }
        candidateClaims.push(Object.freeze({
          field,
          value: claim.value,
          origin: claim.origin,
          ...(claim.precision ? { precision: claim.precision } : {}),
          retentionTags: tags,
          supports: Object.freeze(supportRecords)
        }));
      }
    }
    candidateClaims.sort((left, right) => stableJson(left).localeCompare(stableJson(right), 'en'));
    selectedProjection.push(Object.freeze({ candidateId: candidate.candidateId, facts: Object.freeze(candidateClaims) }));
  }
  const groups = [...groupsByKey.values()].sort((left, right) => stableJson({
    candidateId: left.candidateId, evidenceId: left.evidenceId, contentHash: left.contentHash, languageLabel: left.languageLabel
  }).localeCompare(stableJson({
    candidateId: right.candidateId, evidenceId: right.evidenceId, contentHash: right.contentHash, languageLabel: right.languageLabel
  }), 'en'));
  if (groups.length < 2) fail('INVALID_TARGET_BINDING');
  if (groups.length > MAX_OBSERVATIONS) fail('RESOURCE_LIMIT_EXCEEDED');
  let totalTextBytes = 0;
  const observations = [];
  const observationGroups = [];
  for (const group of groups) {
    const claims = [...group.claimsByKey.values()].sort((left, right) => stableJson(left).localeCompare(stableJson(right), 'en'));
    const context = corroboration ? corroborationContext(corroboration, group.candidateId) : null;
    const payload = context ? { claims, corroboration: context } : claims;
    const textBytes = serializedJsonByteLength(payload);
    if (textBytes > MAX_TEXT_BYTES_PER_FIELD) fail('RESOURCE_LIMIT_EXCEEDED');
    // The maintained parser counts both `text` and `claimText`; this adapter
    // supplies the same bounded group payload in both fields.
    totalTextBytes += textBytes * 2;
    if (totalTextBytes > MAX_TOTAL_TEXT_BYTES) fail('RESOURCE_LIMIT_EXCEEDED');
    const text = stableJson(payload);
    const observationCore = Object.freeze({
      candidateId: group.candidateId,
      evidenceId: group.evidenceId,
      contentHash: group.contentHash,
      languageLabel: group.languageLabel,
      claims: Object.freeze(claims),
      ...(context ? { corroboration: context } : {})
    });
    const observationRef = `source-identity-${hash(context ? OBSERVATION_HASH_DOMAIN.replace(':v1\0', ':v2\0') : OBSERVATION_HASH_DOMAIN, observationCore)}`;
    const fieldRef = `occurrence-group-${hash(FIELD_REF_HASH_DOMAIN, {
      candidateId: group.candidateId,
      evidenceId: group.evidenceId,
      contentHash: group.contentHash
    }).slice(0, 40)}`;
    const retentionTags = Object.freeze([...new Set(claims.flatMap((claim) => claim.retentionTags))].sort());
    observations.push({
      observationRef,
      kind: 'claim_evidence_text',
      sourceRef: group.evidenceId,
      candidateRef: group.candidateId,
      fieldRef,
      claimText: text,
      language: group.languageLabel,
      text,
      retentionTags
    });
    const source = sourceById.get(group.evidenceId);
    if (!source || source.contentHash !== group.contentHash) fail('SOURCE_BINDING_FAILED');
    observationGroups.push(Object.freeze({
      ...observationCore,
      duplicateGroupId: source.duplicateGroupId,
      languageLabelTrust: 'unverified_caller_metadata',
      fieldRef,
      observationRef,
      text
    }));
  }
  return { observations, selectedProjection, observationGroups: Object.freeze(observationGroups), totalTextBytes };
}

function sourceSummaryProjection(candidates, sourceById) {
  const used = new Set();
  for (const candidate of candidates) {
    for (const field of FACT_FIELDS) {
      for (const claim of candidate.facts[field]) for (const support of claim.supports) used.add(support.evidenceId);
    }
  }
  return [...used].sort().map((evidenceId) => {
    const summary = sourceById.get(evidenceId);
    if (!summary) fail('SOURCE_BINDING_FAILED');
    return summary;
  });
}

function relevantTransition(rawTransition, pair, sourceById) {
  const keys = new Set(['schema', 'id', 'predecessorId', 'successorId', 'transition', 'supports']);
  const descriptors = safeDataRecord(rawTransition, keys);
  const predecessorId = safeReference(descriptors.predecessorId.value);
  const successorId = descriptors.successorId.value === null ? null : safeReference(descriptors.successorId.value);
  const kind = descriptors.transition.value;
  if (kind !== 'canceled' && kind !== 'rescheduled') fail('SOURCE_BINDING_FAILED');
  if (kind === 'canceled' && pair.includes(predecessorId)) {
    return Object.freeze({
      schema: descriptors.schema.value,
      id: safeText(descriptors.id.value, 74),
      predecessorId,
      successorId,
      transition: kind,
      supports: projectTransitionSupports(descriptors.supports.value, kind, sourceById)
    });
  }
  if (kind === 'rescheduled' && pair.includes(predecessorId) && pair.includes(successorId)) {
    return Object.freeze({
      schema: descriptors.schema.value,
      id: safeText(descriptors.id.value, 74),
      predecessorId,
      successorId,
      transition: kind,
      supports: projectTransitionSupports(descriptors.supports.value, kind, sourceById)
    });
  }
  return null;
}

function projectTransitionSupports(value, transition, sourceById) {
  const supports = safeArray(value, 16);
  if (supports.length === 0) fail('SOURCE_BINDING_FAILED');
  return Object.freeze(supports.map((support) => {
    const record = safeDataRecord(support, new Set(['evidenceId', 'contentHash', 'locator', 'field', 'value']));
    const evidenceId = safeReference(record.evidenceId.value);
    const contentHash = safeText(record.contentHash.value, 64);
    const field = safeText(record.field.value, MAX_FIELD_BYTES);
    const valueText = safeText(record.value.value, MAX_VALUE_BYTES);
    const summary = sourceById.get(evidenceId);
    const expectedValue = transition === 'canceled' ? 'canceled' : 'rescheduled';
    if (!summary || summary.contentHash !== contentHash || field !== 'status' || valueText !== expectedValue) fail('SOURCE_BINDING_FAILED');
    return Object.freeze({
      evidenceId,
      contentHash,
      locator: projectLocator(record.locator.value),
      field,
      value: valueText
    });
  }));
}

function selectedTransitions(rawTransitions) {
  const values = safeArray(rawTransitions, MAX_TRANSITIONS);
  if (values.length !== 0) fail('SOURCE_BINDING_FAILED');
  return [];
}

function unresolvedForPair(rawValues, pair) {
  const values = safeArray(rawValues, MAX_UNRESOLVED_TRANSITIONS);
  const unresolved = [];
  for (const value of values) {
    const descriptors = safeDataRecord(value, new Set(['candidateId', 'transition', 'reason']));
    const candidateId = safeReference(descriptors.candidateId.value);
    if (!pair.includes(candidateId)) continue;
    const transition = descriptors.transition.value;
    if (transition !== 'canceled' && transition !== 'rescheduled') fail('SOURCE_BINDING_FAILED');
    unresolved.push(Object.freeze({
      candidateId,
      transition,
      reason: safeText(descriptors.reason.value, 256)
    }));
  }
  return unresolved.sort((left, right) => stableJson(left).localeCompare(stableJson(right), 'en'));
}

function parseDecision(rawDecisions, pair, sourceById) {
  const decisions = safeArray(rawDecisions, MAX_COMPARISONS);
  const selected = [];
  for (const value of decisions) {
    const candidateIds = safeArray(dataValue(value, 'candidateIds'), 2, { exactLength: 2 });
    const ids = candidateIds.map(safeReference);
    if (ids.length === 2 && ids.every((id, index) => id === pair[index])) selected.push(value);
  }
  if (selected.length !== 1) fail('SOURCE_BINDING_FAILED');
  const descriptors = safeDataRecord(selected[0], new Set([
    'schema', 'candidateIds', 'relation', 'reasonCodes', 'conflictFields', 'sourceAuthority',
    'duplicateContentHashes', 'provenanceReferences', 'candidates', 'transitionLinks'
  ]));
  const candidateIds = safeArray(descriptors.candidateIds.value, 2, { exactLength: 2 }).map(safeReference);
  if (descriptors.schema.value !== DECISION_SCHEMA || descriptors.sourceAuthority.value !== 'not_evaluated'
    || candidateIds[0] !== pair[0] || candidateIds[1] !== pair[1]) fail('SOURCE_BINDING_FAILED');
  const relation = descriptors.relation.value;
  if (!['same_occurrence_candidate', 'different_occurrence_candidate', 'review', 'unknown'].includes(relation)) fail('SOURCE_BINDING_FAILED');
  const reasonCodes = safeArray(descriptors.reasonCodes.value, 32).map((value) => safeReference(value));
  const conflictFields = safeArray(descriptors.conflictFields.value, FACT_FIELDS.length).map((value) => {
    if (!FACT_FIELDS.includes(value)) fail('SOURCE_BINDING_FAILED');
    return value;
  });
  const duplicateContentHashes = safeArray(descriptors.duplicateContentHashes.value, 32).map((value) => {
    if (typeof value !== 'string' || !SHA256.test(value)) fail('SOURCE_BINDING_FAILED');
    return value;
  });
  const provenanceReferences = safeArray(descriptors.provenanceReferences.value, MAX_PROVENANCE_REFERENCES).map((reference) => {
    const record = safeDataRecord(reference, new Set(['evidenceId', 'contentHash', 'locator', 'field', 'value']));
    return Object.freeze({
      evidenceId: safeReference(record.evidenceId.value),
      contentHash: safeText(record.contentHash.value, 64),
      locator: projectLocator(record.locator.value),
      field: safeText(record.field.value, MAX_FIELD_BYTES),
      value: safeText(record.value.value, MAX_VALUE_BYTES)
    });
  });
  const candidates = safeArray(descriptors.candidates.value, 2, { exactLength: 2 })
    .map((candidate) => projectCandidate(candidate, sourceById));
  const transitions = safeArray(descriptors.transitionLinks.value, MAX_TRANSITIONS)
    .map((transition) => relevantTransition(transition, pair, sourceById));
  if (transitions.some((transition) => transition === null)) fail('SOURCE_BINDING_FAILED');
  const projection = Object.freeze({
    schema: DECISION_SCHEMA,
    candidateIds: Object.freeze(candidateIds),
    relation,
    reasonCodes: Object.freeze(reasonCodes),
    conflictFields: Object.freeze(conflictFields),
    sourceAuthority: 'not_evaluated',
    duplicateContentHashes: Object.freeze(duplicateContentHashes),
    provenanceReferences: Object.freeze(provenanceReferences),
    candidates: Object.freeze(candidates.map(({ factCount: _factCount, ...candidate }) => candidate)),
    transitionLinks: Object.freeze(transitions)
  });
  return projection;
}

function checkSelectedDecision(candidates, transitions, rawDecisions, pair, sourceById) {
  const provided = parseDecision(rawDecisions, pair, sourceById);
  const projectedDecisionCandidates = provided.candidates;
  const canonicalCandidates = candidates.map(({ factCount: _factCount, ...candidate }) => candidate);
  if (stableJson(projectedDecisionCandidates) !== stableJson(canonicalCandidates)) fail('SOURCE_BINDING_FAILED');
  const recomputed = compareOccurrenceIdentity(canonicalCandidates[0], canonicalCandidates[1], { transitions });
  const expectedCore = {
    schema: recomputed.schema,
    candidateIds: recomputed.candidateIds,
    relation: recomputed.relation,
    reasonCodes: recomputed.reasonCodes,
    conflictFields: recomputed.conflictFields,
    sourceAuthority: recomputed.sourceAuthority,
    duplicateContentHashes: recomputed.duplicateContentHashes,
    provenanceReferences: recomputed.provenanceReferences,
    candidates: recomputed.candidates,
    transitionLinks: recomputed.transitionLinks
  };
  const actualCore = provided;
  if (stableJson(actualCore) !== stableJson(expectedCore)) fail('SOURCE_BINDING_FAILED');
  if (stableJson(provided.transitionLinks) !== stableJson(transitions)) fail('SOURCE_BINDING_FAILED');
  return Object.freeze({
    schema: DECISION_SCHEMA,
    candidateIds: Object.freeze([...recomputed.candidateIds]),
    relation: recomputed.relation,
    reasonCodes: Object.freeze([...recomputed.reasonCodes]),
    conflictFields: Object.freeze([...recomputed.conflictFields]),
    sourceAuthority: recomputed.sourceAuthority,
    duplicateContentHashes: Object.freeze([...recomputed.duplicateContentHashes]),
    provenanceReferences: Object.freeze(recomputed.provenanceReferences.map((reference) => Object.freeze({
      evidenceId: reference.evidenceId,
      contentHash: reference.contentHash,
      locator: projectLocator(reference.locator),
      field: reference.field,
      value: reference.value
    }))),
    transitionLinks: Object.freeze(transitions)
  });
}

function sidecar(core) {
  const preflight = { ...core, digest: '0'.repeat(64), utf8Bytes: MAX_SIDE_CAR_UTF8_BYTES };
  if (serializedJsonByteLength(preflight) > MAX_SIDE_CAR_UTF8_BYTES) fail('RESOURCE_LIMIT_EXCEEDED');
  const digest = hash(core.schema === BINDING_SCHEMA_V2 ? BINDING_HASH_DOMAIN.replace(':v1\0', ':v2\0') : BINDING_HASH_DOMAIN, core);
  let utf8Bytes = 0;
  let output;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    output = { ...core, digest, utf8Bytes };
    const next = byteLength(stableJson(output));
    if (next === utf8Bytes) break;
    utf8Bytes = next;
  }
  output = { ...core, digest, utf8Bytes };
  const serializedBytes = byteLength(stableJson(output));
  if (serializedBytes !== utf8Bytes || serializedBytes > MAX_SIDE_CAR_UTF8_BYTES) fail('RESOURCE_LIMIT_EXCEEDED');
  return deepFreeze(output);
}

function serializedJsonByteLength(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') {
    return byteLength(JSON.stringify(value));
  }
  if (typeof value === 'string') return byteLength(JSON.stringify(value));
  if (Array.isArray(value)) {
    let bytes = 2;
    for (let index = 0; index < value.length; index += 1) {
      if (index > 0) bytes += 1;
      bytes += serializedJsonByteLength(value[index]);
    }
    return bytes;
  }
  let bytes = 2;
  const keys = Object.keys(value).sort();
  for (let index = 0; index < keys.length; index += 1) {
    if (index > 0) bytes += 1;
    const key = keys[index];
    bytes += byteLength(JSON.stringify(key)) + 1 + serializedJsonByteLength(value[key]);
  }
  return bytes;
}

/**
 * Build a local-only identity question plan from an explicitly selected pair in a
 * maintained source-identity composition. The result does not attest the caller's
 * object, authorize a tenant, revalidate retention, or dispatch a question.
 * Visible status notices in selected sources require review before preparation.
 */
export function prepareIdentityQuestionFromComposition(composition, rawOptions) {
  try {
    const { pair, languageDescriptors } = parseOptions(rawOptions);
    const root = assertCompositionShape(composition);
    const sourceById = projectEvidenceSummaries(root.sources.value);
    const rawCandidates = findCandidates(root.occurrenceCandidates.value, pair);
    const candidates = rawCandidates.map((candidate) => projectCandidate(candidate, sourceById));
    const selectedClaims = candidates.reduce((total, candidate) => total + candidate.factCount, 0);
    if (selectedClaims > MAX_FACTS) fail('RESOURCE_LIMIT_EXCEEDED');
    const usedEvidenceIds = new Set(candidates.flatMap((candidate) => FACT_FIELDS
      .flatMap((field) => candidate.facts[field].flatMap((claim) => claim.supports.map((support) => support.evidenceId)))));
    assertSelectedStatusEvidenceSupported(root.sources.value, usedEvidenceIds, sourceById);
    const provenance = projectCorroboration(root, sourceById);
    const corroboration = provenance?.graph ?? null;

    const selectedLinks = selectedTransitions(root.transitionLinks.value);
    const decision = checkSelectedDecision(candidates, selectedLinks, root.occurrenceDecisions.value, pair, sourceById);
    const unresolvedTransitions = unresolvedForPair(root.unresolvedTransitions.value, pair);
    const { observations, selectedProjection, observationGroups, totalTextBytes } = observationsFor(pair, candidates, languageDescriptors, sourceById, corroboration);
    if (Object.keys(languageDescriptors).some((evidenceId) => !usedEvidenceIds.has(evidenceId))) fail('INVALID_INPUT');
    const observationRefs = observations.map((observation) => observation.observationRef);
    const targetRef = deriveQuestionTargetRef(QUESTION_ID, observationRefs, { candidateRefs: pair });
    const targetBinding = Object.freeze({ questionId: QUESTION_ID, targetRef, observationRefs, candidateRefs: pair });
    const plan = prepareIndependentQuestions(observations, [targetBinding]);
    const question = plan.questions.find((item) => item.questionId === QUESTION_ID);
    if (!question || plan.candidateOnly !== true || plan.readinessStatus !== 'blocked'
      || plan.executionStatus !== 'not_dispatched' || plan.promotionStatus !== 'unpromoted'
      || plan.decisionPortContractStatus !== 'unavailable' || plan.authorityScope.promotionGranted !== false) {
      fail('SOURCE_BINDING_FAILED');
    }
    const bindingHashes = Object.freeze({
      registryVersion: plan.registryVersion,
      registryHash: plan.registryHash,
      questionDefinitionHash: question.definitionHash,
      sourceEvidenceHash: plan.sourceEvidenceHash,
      targetRef: question.targetBinding?.targetRef ?? null,
      targetBindingHash: question.targetBindingHash,
      targetStateHash: question.targetStateHash,
      questionInstanceHash: question.questionInstanceHash,
      planHash: plan.planHash
    });
    const summaries = sourceSummaryProjection(candidates, sourceById);
    const core = Object.freeze({
      schema: corroboration ? BINDING_SCHEMA_V2 : BINDING_SCHEMA,
      questionId: QUESTION_ID,
      candidateIds: Object.freeze(pair),
      sourceCompositionSchema: root.schema.value,
      ...(corroboration ? { corroboration: {
        schema: corroboration.schema, policy: corroboration.policy,
        sourceGraphDigest: corroboration.digest, sourceAuthority: 'not_evaluated', independence: 'unknown',
        factBindings: provenance.factBindings,
        selectedCandidates: pair.map((candidateId) => ({ candidateId, ...corroborationContext(corroboration, candidateId) })),
        clusters: corroboration.clusters.filter((cluster) => cluster.members.some((id) => pair.includes(id))),
        edges: corroboration.edges.filter((edge) => corroboration.clusters.some((cluster) =>
          cluster.members.some((id) => pair.includes(id)) && cluster.members.includes(edge.from) && cluster.members.includes(edge.to))),
      } } : {}),
      sourceAuthority: 'not_evaluated',
      sourceEvidence: Object.freeze(summaries),
      selectedCandidates: Object.freeze(selectedProjection),
      observationGroups,
      comparison: decision,
      transitionLinks: Object.freeze(selectedLinks),
      unresolvedTransitions: Object.freeze(unresolvedTransitions),
      languageMetadataTrust: 'unverified_caller_metadata',
      localReviewOnly: true,
      bindingHashes,
      limits: Object.freeze({
        maxUtf8Bytes: MAX_SIDE_CAR_UTF8_BYTES,
        maxObservations: MAX_OBSERVATIONS,
        maxTextBytesPerField: MAX_TEXT_BYTES_PER_FIELD,
        maxTotalTextBytes: MAX_TOTAL_TEXT_BYTES,
        observationTextBytes: totalTextBytes
      })
    });
    const sourceIdentityBinding = sidecar(core);
    return Object.freeze({ plan, sourceIdentityBinding });
  } catch (error) {
    if (error instanceof SourceIdentityQuestionPreparationError || error instanceof QuestionPreparationError) throw error;
    if (error instanceof CorroborationError && error.code === 'LIMIT') fail('RESOURCE_LIMIT_EXCEEDED');
    fail('SOURCE_BINDING_FAILED');
  }
}
