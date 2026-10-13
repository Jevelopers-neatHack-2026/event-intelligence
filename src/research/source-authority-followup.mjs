import { createHash } from 'node:crypto';
import { types } from 'node:util';

const SCHEMA = 'ei-private-source-authority-review/v1';
const HASH_DOMAIN = 'event-intelligence:private-source-authority-question:v1\0';
const MAX_QUESTIONS = 8;
const MAX_SOURCES = 8;
const MAX_CANDIDATES_PER_KIND = 23;
const MAX_CLAIMS = 128;
const MAX_SUPPORTS = 8;
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const FACT_FIELDS = new Set(['title', 'series', 'edition', 'city', 'venue', 'start', 'end', 'status']);
const ENTITY_KINDS = new Set(['organization', 'performer', 'venue', 'person', 'event_series']);
const PROMPTS = Object.freeze({
  occurrence: 'Can you provide an attributable official event or organizer page for this occurrence, including its date and venue?',
  entity: 'Can you provide an attributable official page that identifies this entity and its relationship to the event?',
  source_input: 'Can you provide an accessible official event or organizer source containing the event details?',
});
const SOURCE_REFUSALS = new Set([
  'no_supported_identity_or_link_candidates', 'dynamic_rendering_required', 'unsupported_media',
  'malformed_or_unsupported_encoding', 'source_access_restricted',
]);
// Unknown limitations are deliberately not upgraded into a manual input request.
// Normal settled frontier caps are not a financial-authority grant or denial.
const ELIGIBLE_LIMITATIONS = new Set([
  'source_authority_not_evaluated', 'rights_not_evaluated', 'billable_usage_unknown',
  'provider_and_external_egress_not_measured', ...SOURCE_REFUSALS,
  'transport_attempt_limit', 'frontier_depth_limit', 'candidate_fanout_limit',
  'frontier_stopped',
  'selected_evidence_limit', 'selected_fact_limit', 'completion_suggestion_limit',
  'candidate_not_dispatched_before_attempt_limit', 'candidate_receipt_selection_limit',
  'some_link_candidates_omitted_by_policy_or_parser_limit', 'extraction_incomplete',
  'pdf_identity_extraction_not_supported', 'asset_bytes_not_inspected_or_promoted',
  'asset_source_selection_limit',
]);
const ELIGIBLE_STOPS = new Set(['frontier_exhausted', 'attempt_limit', 'depth_limit', 'fanout_limit']);

function invalid() {
  const error = new Error('Private source-authority follow-up input is invalid.');
  error.code = 'FOLLOWUP_INVALID_INPUT';
  throw error;
}

function record(value) {
  if (!value || typeof value !== 'object' || types.isProxy(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const keys = Reflect.ownKeys(value);
  if (keys.length > 32) invalid();
  const copy = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== 'string' || !descriptor || !Object.hasOwn(descriptor, 'value')) invalid();
    copy[key] = descriptor.value;
  }
  return copy;
}

function array(value, maximum) {
  if (!Array.isArray(value) || types.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype) invalid();
  const length = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum
    || Reflect.ownKeys(value).length !== length + 1) invalid();
  const copy = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) invalid();
    copy.push(descriptor.value);
  }
  return copy;
}

function eligible(limitations, stopReasons) {
  const codes = array(limitations, 128);
  const stops = array(stopReasons, 32);
  return codes.every((code) => typeof code === 'string' && ELIGIBLE_LIMITATIONS.has(code))
    && stops.every((code) => typeof code === 'string' && ELIGIBLE_STOPS.has(code))
    // Sealed attempt-cap replay retains this baseline generic marker. It is
    // eligible only with an explicit ordinary stop, never on the marker alone.
    && (!codes.includes('frontier_stopped') || stops.length > 0);
}

function compare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function referenceKey(reference) {
  return JSON.stringify([reference.evidenceId, reference.version, reference.contentHash]);
}

function sourceMap(sources) {
  const result = new Map();
  for (const value of array(sources, MAX_SOURCES)) {
    const source = record(value);
    if (typeof source.evidenceId !== 'string' || !OPAQUE_ID.test(source.evidenceId)
      || typeof source.contentHash !== 'string' || !DIGEST.test(source.contentHash)
      || !Number.isSafeInteger(source.version) || source.version < 1
      || source.sourceAuthority !== 'not_evaluated' || result.has(source.evidenceId)) invalid();
    result.set(source.evidenceId, Object.freeze({
      evidenceId: source.evidenceId, version: source.version, contentHash: source.contentHash,
    }));
  }
  return result;
}

function candidateReferences(candidate, kind, sources) {
  const references = new Map();
  let groups;
  if (kind === 'occurrence') {
    if (candidate.schema !== 'ei-occurrence-observation-internal/v1') invalid();
    const facts = record(candidate.facts);
    if (Object.keys(facts).some((field) => !FACT_FIELDS.has(field))) invalid();
    groups = Object.values(facts);
  } else {
    if (candidate.schema !== 'ei-entity-observation-internal/v1' || !ENTITY_KINDS.has(candidate.kind)) invalid();
    groups = [candidate.names ?? [], candidate.identifiers ?? []];
  }
  let claimCount = 0;
  for (const group of groups) {
    for (const claimValue of array(group, MAX_CLAIMS)) {
      if (++claimCount > MAX_CLAIMS) invalid();
      const claim = record(claimValue);
      if (claim.origin !== 'sourced') invalid();
      const supports = array(claim.supports, MAX_SUPPORTS);
      if (supports.length === 0) invalid();
      for (const supportValue of supports) {
        const support = record(supportValue);
        const current = sources.get(support.evidenceId);
        if (!current || support.contentHash !== current.contentHash) invalid();
        references.set(referenceKey(current), current);
      }
    }
  }
  if (references.size === 0) invalid();
  return Object.freeze([...references].sort(([left], [right]) => compare(left, right)).map(([, ref]) => ref));
}

function question(kind, candidateId, evidenceRefs) {
  const candidateRef = candidateId === null ? null : Object.freeze({ kind, candidateId });
  const binding = JSON.stringify([SCHEMA, kind, candidateId, evidenceRefs]);
  return Object.freeze({
    questionId: `authority-${createHash('sha256').update(HASH_DOMAIN).update(binding).digest('hex')}`,
    kind,
    prompt: PROMPTS[kind],
    candidateRef,
    evidenceRefs,
  });
}

function review(questions, omittedQuestionCount, reasonCodes) {
  return Object.freeze({
    schema: SCHEMA,
    status: 'review_required',
    authority: 'unknown',
    execution: 'not_dispatched',
    questions: Object.freeze(questions),
    omittedQuestionCount,
    reasonCodes: Object.freeze(reasonCodes),
  });
}

/** Internal projection only: the caller has already revalidated this private selection. */
export function composeSourceAuthorityReview(value) {
  const input = record(value);
  if (!eligible(input.limitations, input.stopReasons)) return undefined;
  const sources = sourceMap(input.sources);
  if (sources.size === 0) invalid();
  const questions = new Map();
  // Explicit priority: occurrences, then entities; opaque IDs break ties by code point.
  for (const [kind, values] of [['occurrence', input.occurrenceCandidates], ['entity', input.entityCandidates]]) {
    for (const candidateValue of array(values, MAX_CANDIDATES_PER_KIND)) {
      const candidate = record(candidateValue);
      if (typeof candidate.candidateId !== 'string' || !OPAQUE_ID.test(candidate.candidateId)) invalid();
      const refs = candidateReferences(candidate, kind, sources);
      const key = `${kind === 'occurrence' ? '0' : '1'}:${candidate.candidateId}`;
      const next = question(kind, candidate.candidateId, refs);
      const previous = questions.get(key);
      if (previous && previous.questionId !== next.questionId) invalid();
      questions.set(key, next);
    }
  }
  const ordered = [...questions].sort(([left], [right]) => compare(left, right)).map(([, item]) => item);
  if (ordered.length === 0) {
    const refs = Object.freeze([...sources.values()].sort((left, right) => compare(referenceKey(left), referenceKey(right))));
    ordered.push(question('source_input', null, refs));
  }
  return review(ordered.slice(0, MAX_QUESTIONS), Math.max(0, ordered.length - MAX_QUESTIONS),
    ['source_authority_not_evaluated']);
}

/** Called only at the settled no-evidence return, after current release authorization. */
export function composeNoSourceAuthorityReview(limitations, stopReasons) {
  if (!eligible(limitations, stopReasons)) return undefined;
  const reasons = array(limitations, 128).filter((code) => SOURCE_REFUSALS.has(code));
  if (reasons.length === 0) return undefined;
  return review([question('source_input', null, Object.freeze([]))], 0, [...new Set(reasons)].sort(compare));
}
