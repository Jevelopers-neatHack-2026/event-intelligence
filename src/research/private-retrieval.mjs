import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { types as utilTypes } from 'node:util';
import { SafeFetcher, RetrievalError } from '../security/controlled-fetch.mjs';
import {
  createControlledSvgIngestWitness,
  runWithSafeFetchLifecycle,
  safeFetchProvenance,
} from '../security/internal/fetch-lifecycle.mjs';
import { composeSourceIdentity, SourceIdentityCompositionError } from '../discovery/identity/from-extraction.mjs';
import { compareEntityIdentity } from '../discovery/entities/identity.mjs';
import { compareOccurrenceIdentity } from '../discovery/occurrences/identity.mjs';
import { parseAndValidateUrl } from '../security/url-policy.mjs';
import { inspectSafeAssetBytes, SAFE_ASSET_POLICY_VERSION, SAFE_ASSET_LIMITS } from '../security/assets/inspect.mjs';
import { composeSourceAuthorityReview, composeNoSourceAuthorityReview } from './source-authority-followup.mjs';
import {
  createPrivateAssetReleaseAuthority as createReleaseAuthorityState,
  hasThenableBehavior,
  isPrivateAssetReleaseController,
  privateAssetReleaseAuthorityForController,
  privateAssetReleaseControllerMatches,
  revokePrivateAssetReleaseController,
  subscribeToSupportedNativePromise,
} from './private-asset-release.mjs';

const PRIVATE_DRAFT_SCHEMA = 'ei-private-retrieval-draft/v1';
const MAX_ADMISSIONS = 8;
const STOP_PERSIST_CLEANUP_MS = 500;
const PRE_STOP_UNRESOLVED_CLEANUP_MS = 100;
const ABORTABLE_CLEANUP_MS = 250;
const STOP_RECOVERY_ENVELOPE_MS = STOP_PERSIST_CLEANUP_MS + ABORTABLE_CLEANUP_MS;
const ASSET_ACQUISITION_POLICY_VERSION = 'ei-private-svg-acquisition/1';
const SVG_SOURCE_MAX_BYTES = 128 * 1024;
const MAX_SELECTED_EVIDENCE = 8;
const MAX_SELECTED_FACTS = 128;
const MAX_AGGREGATE_IDENTITY_CANDIDATES = 23;
const MAX_AGGREGATE_COMPARISONS = 256;
const DECODED_BUFFER_MARGIN_BYTES = 64 * 1024;
const GZIP_CHUNK_BYTES = 4 * 1024;
// Source-pinned conservative accounting: native output (1x), Gunzip readable
// queue (2x), output writable queue (2x), output readable queue (2x), async
// iterator aggregate (2x), and the accumulator copy (2x), all in 4 KiB units.
const DECODED_INFLIGHT_BOUND_BYTES = 11 * GZIP_CHUNK_BYTES;
if (DECODED_INFLIGHT_BOUND_BYTES >= DECODED_BUFFER_MARGIN_BYTES) {
  throw new Error('private decoded stream bound exceeds its accepted-byte margin');
}
const TEXT_ACCEPTED_BYTES = 20 * 1024 * 1024 - DECODED_BUFFER_MARGIN_BYTES;
const MEDIA_ACCEPTED_BYTES = 10 * 1024 * 1024 - DECODED_BUFFER_MARGIN_BYTES;
const CANCELLATION_REASONS = new Set([
  'cancelled', 'budget_denied', 'deadline', 'access_restricted', 'adequate_facts', 'review_required',
]);
const STOP_LIMITATIONS = new Map([
  ['attempt_limit', 'transport_attempt_limit'],
  ['depth_limit', 'frontier_depth_limit'],
  ['fanout_limit', 'candidate_fanout_limit'],
]);
const ABORTED_GETTER = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const ADD_EVENT_LISTENER = EventTarget.prototype.addEventListener;
const REMOVE_EVENT_LISTENER = EventTarget.prototype.removeEventListener;

export class PrivateRetrievalError extends Error {
  constructor(code) {
    super(code === 'INVALID_INPUT' ? 'Private retrieval input is invalid.' : 'Private retrieval could not be authorized.');
    this.name = 'PrivateRetrievalError';
    this.code = code;
  }
}

function fail(code = 'INVALID_INPUT') {
  throw new PrivateRetrievalError(code);
}

function plainDataRecord(value, allowed) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string' || !allowed.has(key))) return null;
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) return null;
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    return null;
  }
}

function exactMethods(value, names) {
  try {
    if (!value || typeof value !== 'object') return null;
    const result = Object.create(null);
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') return null;
      result[name] = descriptor.value.bind(value);
    }
    return result;
  } catch {
    return null;
  }
}

function ownArray(value, maximum) {
  try {
    if (!Array.isArray(value) || value.length > maximum) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes('length')) return null;
    const copy = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) return null;
      copy.push(descriptor.value);
    }
    return copy;
  } catch {
    return null;
  }
}

function repeatedDecode(value) {
  let current = value;
  for (let depth = 0; depth < 4; depth += 1) {
    let decoded;
    try { decoded = decodeURIComponent(current.replaceAll('+', '%20')); }
    catch { return null; }
    if (decoded === current) return current;
    current = decoded;
  }
  try {
    return decodeURIComponent(current.replaceAll('+', '%20')) === current ? current : null;
  } catch {
    return null;
  }
}

function sensitiveKey(value) {
  return /(?:token|key|auth|code|signature|sig|secret|session|password|credential|invite|ticket|admission)/i.test(value);
}

function urlHasSensitiveMaterial(value) {
  try {
    if (typeof value !== 'string' || value.length > 8_192) return true;
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return true;
    for (const key of parsed.searchParams.keys()) {
      const decoded = repeatedDecode(key);
      if (decoded === null || sensitiveKey(decoded)) return true;
    }
    const fragment = parsed.hash.slice(1);
    if (fragment === '') return false;
    const decodedFragment = repeatedDecode(fragment);
    if (decodedFragment === null || sensitiveKey(decodedFragment)) return true;
    for (const component of decodedFragment.split(/[&;]/)) {
      const key = repeatedDecode(component.split('=', 1)[0]);
      if (key === null || sensitiveKey(key)) return true;
    }
    return false;
  } catch {
    return true;
  }
}

function snapshotRunInput(value) {
  const input = plainDataRecord(value, new Set([
    'frontier', 'evidenceStore', 'safeFetcher', 'request', 'runId', 'seeds', 'limits',
    'retentionHandleFor', 'authorizeCurrent', 'assetAcquisitionPolicyFor',
    'assetAcquisitionReleaseAuthorityFor', 'signal',
  ]));
  if (!input || typeof input.runId !== 'string' || input.runId.length < 1 || input.runId.length > 96
    || input.request === null || (typeof input.request !== 'object' && typeof input.request !== 'function')
    || typeof input.retentionHandleFor !== 'function' || typeof input.authorizeCurrent !== 'function') fail();
  try { ABORTED_GETTER.call(input.signal); } catch {
    if (input.signal !== undefined) fail();
  }
  const seedValues = ownArray(input.seeds, 10);
  if (!seedValues || seedValues.length < 1) fail();
  const seeds = seedValues.map((value) => {
    const seed = plainDataRecord(value, new Set(['url', 'sourceRefs']));
    if (!seed || typeof seed.url !== 'string' || urlHasSensitiveMaterial(seed.url)) fail();
    const sourceRefs = seed.sourceRefs === undefined ? undefined : ownArray(seed.sourceRefs, 4);
    if (seed.sourceRefs !== undefined && !sourceRefs) fail();
    const copiedRefs = sourceRefs?.map((reference) => {
      const ref = plainDataRecord(reference, new Set(['evidenceId', 'contentHash', 'locator', 'field', 'value']));
      if (!ref || ref.value !== seed.url || typeof ref.evidenceId !== 'string'
        || typeof ref.contentHash !== 'string' || typeof ref.field !== 'string') fail();
      return { ...ref };
    });
    return { url: seed.url, ...(copiedRefs ? { sourceRefs: copiedRefs } : {}) };
  });
  const rawLimits = input.limits === undefined ? Object.create(null)
    : plainDataRecord(input.limits, new Set([
      'maxDepth', 'maxTransportAttemptAdmissions', 'maxInFlightLeases', 'durationMs', 'maxSuggestionsPerCompletion',
    ]));
  if (!rawLimits) fail();
  const limits = {
    maxDepth: rawLimits.maxDepth ?? 2,
    maxTransportAttemptAdmissions: rawLimits.maxTransportAttemptAdmissions ?? MAX_ADMISSIONS,
    maxInFlightLeases: rawLimits.maxInFlightLeases ?? 4,
    durationMs: rawLimits.durationMs ?? 30_000,
    maxSuggestionsPerCompletion: rawLimits.maxSuggestionsPerCompletion ?? 16,
  };
  if (!Number.isSafeInteger(limits.maxDepth) || limits.maxDepth < 0 || limits.maxDepth > 2
    || !Number.isSafeInteger(limits.maxTransportAttemptAdmissions) || limits.maxTransportAttemptAdmissions < 1
      || limits.maxTransportAttemptAdmissions > MAX_ADMISSIONS
    || !Number.isSafeInteger(limits.maxInFlightLeases) || limits.maxInFlightLeases < 1 || limits.maxInFlightLeases > 4
    || !Number.isSafeInteger(limits.durationMs) || limits.durationMs < 1 || limits.durationMs > 30_000
    || !Number.isSafeInteger(limits.maxSuggestionsPerCompletion) || limits.maxSuggestionsPerCompletion < 1
      || limits.maxSuggestionsPerCompletion > 16) fail();
  const frontier = exactMethods(input.frontier, [
    'scopeForAuthenticatedRequest', 'createRun', 'claimNext', 'getCandidateReceiptBinding', 'admitTransportHop',
    'markTransportDispatchIntent', 'markTransportResponseReceived', 'settleTransportHopKnownZero',
    'settleTransportHopBodyComplete', 'markTransportHopUnknown', 'getTransportProgress',
    'completeCandidate', 'markUnresolved', 'stopRun', 'sealPrivateDraft', 'getSnapshot',
  ]);
  const evidenceStore = exactMethods(input.evidenceStore, [
    'scopeForAuthenticatedRequest', 'ingestEvidence', 'appendFact', 'ingestDerivedPdfEvidence', 'ingestAssetSourceEvidence',
    'lookupEvidence', 'lookupFact', 'materializeSelected', 'beginPrivateRunReceipt',
    'finalizePrivateRunReceipt', 'readPrivateRunReceipt',
  ]);
  const controlledAssetEvidenceStore = exactMethods(input.evidenceStore, [
    'ingestControlledAssetEvidence', 'readControlledAssetBytes', 'revalidateControlledAssetRelease',
  ]);
  const assetSourceBindingStore = exactMethods(input.evidenceStore, ['readAssetSourceCandidateBinding']);
  if (!frontier || !evidenceStore || !(input.safeFetcher instanceof SafeFetcher)) fail();
  if (input.assetAcquisitionPolicyFor !== undefined && typeof input.assetAcquisitionPolicyFor !== 'function') fail();
  if (input.assetAcquisitionReleaseAuthorityFor !== undefined
    && typeof input.assetAcquisitionReleaseAuthorityFor !== 'function') fail();
  if (input.assetAcquisitionReleaseAuthorityFor !== undefined && input.assetAcquisitionPolicyFor === undefined) fail();
  return {
    ...input, seeds, limits, frontier, evidenceStore,
    controlledAssetEvidenceStore,
    assetSourceBindingStore,
    assetReleaseFinalizationStore: exactMethods(input.evidenceStore, [
      'finalizeControlledAssetRelease', 'discardControlledAssetRelease',
    ]),
    workerId: `private-retrieval-${randomUUID()}`,
  };
}

function normalizeAssetAcquisitionPolicy(value) {
  if (value === null || value === undefined) return null;
  const policy = plainDataRecord(value, new Set(['schemaVersion', 'policyVersion', 'policyId', 'allowedOrigins']));
  if (!policy || policy.schemaVersion !== 1 || policy.policyVersion !== ASSET_ACQUISITION_POLICY_VERSION
    || typeof policy.policyId !== 'string' || !/^[A-Za-z0-9._:-]{1,96}$/.test(policy.policyId)) fail();
  const origins = ownArray(policy.allowedOrigins, 32);
  if (!origins || origins.length === 0) fail();
  const normalizedOrigins = origins.map((origin) => {
    if (typeof origin !== 'string' || origin.length > 512 || urlHasSensitiveMaterial(origin)) fail();
    let parsed;
    try { parsed = new URL(origin); } catch { fail(); }
    if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password
      || parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.origin !== origin) fail();
    return parsed.origin;
  }).sort();
  if (new Set(normalizedOrigins).size !== normalizedOrigins.length) fail();
  return Object.freeze({
    schemaVersion: 1,
    policyVersion: ASSET_ACQUISITION_POLICY_VERSION,
    policyId: policy.policyId,
    allowedOrigins: Object.freeze(normalizedOrigins),
  });
}

/**
 * Creates a host-owned, one-shot release authority for one tenant, logical run,
 * immutable asset policy, and run deadline. Keep the returned controller in the
 * host authorization layer and call revoke() synchronously when any bound
 * authority changes. A revoke before the store's synchronous projection denies
 * release; a revoke after it reports after_release. This is opt-in only.
 */
export function createPrivateAssetReleaseAuthority({ tenantId, runId, policy, expiresAtMonotonic }) {
  const normalizedPolicy = normalizeAssetAcquisitionPolicy(policy);
  if (!normalizedPolicy) fail();
  const maximumExpiry = performance.now() + 30_000;
  const selectedExpiry = expiresAtMonotonic;
  if (!Number.isFinite(selectedExpiry) || selectedExpiry <= performance.now() || selectedExpiry > maximumExpiry) fail();
  return createReleaseAuthorityState({
    tenantId,
    runId,
    policyDigest: digestJson(normalizedPolicy),
    expiresAtMonotonic: selectedExpiry,
  });
}

function assetPolicyAllowsUrl(policy, value) {
  if (!policy || urlHasSensitiveMaterial(value)) return false;
  try {
    const parsed = parseAndValidateUrl(value).url;
    return parsed.href === value && policy.allowedOrigins.includes(parsed.origin);
  } catch {
    return false;
  }
}

function assetBindingFromStoredCandidate(policy, stored, candidateId) {
  const metadata = stored?.metadata;
  const source = stored?.source;
  const candidate = stored?.candidate;
  const matches = source?.assetSource?.candidates?.filter((entry) => entry.candidateId === candidateId) ?? [];
  if (!policy || !metadata || !source || metadata.state !== 'available'
    || metadata.representation !== 'asset-source-excerpt' || !/^[a-f0-9]{64}$/.test(metadata.contentHash ?? '')
    || !/^[a-f0-9]{64}$/.test(metadata.derivationDigest ?? '') || source.contentHash !== metadata.contentHash
    || source.redirectChain?.length !== 0 || source.assetSource?.sourceUrl !== source.sourceUrl
    || source.assetSource.derivationDigest !== metadata.derivationDigest || matches.length !== 1 || !candidate
    || candidate.candidateId !== candidateId || candidate.positionIndex !== matches[0].positionIndex
    || candidate.sourceForm !== matches[0].sourceForm || candidate.field !== matches[0].field
    || candidate.fetchSuggestion !== matches[0].fetchSuggestion || candidate.quarantineReason !== null
    || candidate.excerptHash !== matches[0].excerptHash
    || JSON.stringify(candidate.locator) !== JSON.stringify(matches[0].locator)
    || typeof candidate.value !== 'string' || candidate.value.length < 1 || candidate.value.length > 8_192
    || hashBytes(Buffer.from(candidate.value, 'utf8')) !== candidate.excerptHash
    || !assetPolicyAllowsUrl(policy, candidate.fetchSuggestion)
    || typeof candidate.field !== 'string' || candidate.field.length < 1 || candidate.field.length > 160) return null;
  const excerpt = candidate.value;
  if (excerpt.length < 1 || excerpt.length > 8_192) return null;
  let sourceUrl;
  try { parseAndValidateUrl(source.sourceUrl); sourceUrl = source.sourceUrl; } catch { return null; }
  return Object.freeze({
    schemaVersion: 1,
    policyVersion: ASSET_ACQUISITION_POLICY_VERSION,
    policyId: policy.policyId,
    sourceEvidenceId: stored.evidenceId,
    sourceEvidenceVersion: metadata.version,
    sourceContentHash: metadata.contentHash,
    sourceDerivationDigest: metadata.derivationDigest,
    sourceUrl,
    candidateId: candidate.candidateId,
    positionIndex: candidate.positionIndex,
    sourceForm: candidate.sourceForm,
    sourceLocator: Object.freeze({ ...candidate.locator }),
    excerptHash: candidate.excerptHash,
    field: candidate.field,
    value: excerpt,
    assetUrl: candidate.fetchSuggestion,
  });
}

function assetSuggestionSourceRef(binding) {
  return Object.freeze({
    evidenceId: binding.sourceEvidenceId,
    contentHash: binding.sourceContentHash,
    locator: Object.freeze({ ...binding.sourceLocator }),
    field: binding.field,
    value: binding.assetUrl,
  });
}

function sameSourceReference(left, right) {
  return left?.evidenceId === right?.evidenceId && left?.contentHash === right?.contentHash
    && left?.field === right?.field && left?.value === right?.value
    && JSON.stringify(left?.locator) === JSON.stringify(right?.locator);
}

function findAssetBindingForCandidate(candidate, snapshot, verifiedCompletionProofs, policy) {
  if (!policy || candidate.seed || candidate.depth < 1 || candidate.sourceRefs.length !== 1) return null;
  const observations = snapshot.observations.filter((observation) => observation.kind === 'link'
    && observation.targetCandidateId === candidate.candidateId);
  if (observations.length !== 1) return null;
  const observation = observations[0];
  const proof = verifiedCompletionProofs.get(observation.parentCandidateId);
  if (!proof || proof.receipt.candidate.candidateId !== observation.parentCandidateId) return null;
  const observationRefs = observation.sourceRefs ?? [];
  if (observationRefs.length !== 1 || candidate.canonicalUrl !== observation.canonicalUrl
    || candidate.suppliedUrl !== observation.suppliedUrl
    || !sameSourceReference(candidate.sourceRefs[0], observationRefs[0])) return null;
  const bindings = (proof.receipt.assetSuggestions ?? []).filter((binding) => binding.assetUrl === candidate.suppliedUrl
    && sameSourceReference(assetSuggestionSourceRef(binding), observationRefs[0])
    && proof.receipt.evidenceIds.includes(binding.sourceEvidenceId));
  return bindings.length === 1 ? bindings[0] : null;
}

function signalAborted(signal) {
  if (signal === undefined) return false;
  try { return ABORTED_GETTER.call(signal); } catch { return true; }
}

function addAbortListener(signal, callback) {
  Reflect.apply(ADD_EVENT_LISTENER, signal, ['abort', callback, { once: true }]);
}

function removeAbortListener(signal, callback) {
  try { Reflect.apply(REMOVE_EVENT_LISTENER, signal, ['abort', callback]); } catch { /* Native signal validated at entry. */ }
}

async function awaitAbortableOperation(operation, signal, abortError) {
  if (signalAborted(signal)) throw abortError();
  let onAbort;
  const aborted = new Promise((_, reject) => {
    onAbort = () => reject(abortError());
    addAbortListener(signal, onAbort);
  });
  try {
    if (signalAborted(signal)) throw abortError();
    const pending = Promise.resolve().then(() => {
      if (signalAborted(signal)) throw abortError();
      return operation();
    });
    return await Promise.race([pending, aborted]);
  } finally {
    removeAbortListener(signal, onAbort);
  }
}

async function awaitAbortableHostCallback(callback, args, signal, abortError) {
  return awaitAbortableOperation(() => callback(...args), signal, abortError);
}

async function awaitControlledAssetPreparation(operation, signal, abortError, onLateSuccess) {
  if (signalAborted(signal)) throw abortError();
  let abandoned = false;
  let onAbort;
  const preparation = new Promise((resolve) => {
    let pending;
    try { pending = operation(); }
    catch (error) { resolve({ kind: 'rejected', error }); return; }
    const fulfilled = (value) => {
      try {
        if (abandoned || signalAborted(signal)) {
          abandoned = true;
          try { onLateSuccess(value); } catch { /* Revocation remains fail-closed. */ }
          resolve({ kind: 'late_success' });
          return;
        }
        resolve({ kind: 'resolved', value });
      } catch (error) {
        resolve({ kind: 'rejected', error });
      }
    };
    const rejected = (error) => {
      try {
        resolve({ kind: abandoned || signalAborted(signal) ? 'late_rejection' : 'rejected', error });
      } catch (signalError) {
        resolve({ kind: 'rejected', error: signalError });
      }
    };
    if (!subscribeToSupportedNativePromise(pending, fulfilled, rejected)) resolve({ kind: 'invalid' });
  });
  const aborted = new Promise((resolve) => {
    onAbort = () => {
      abandoned = true;
      resolve({ kind: 'aborted' });
    };
    addAbortListener(signal, onAbort);
    if (signalAborted(signal)) onAbort();
  });
  try {
    const outcome = await Promise.race([preparation, aborted]);
    if (outcome.kind === 'aborted') throw abortError();
    if (outcome.kind === 'rejected') throw outcome.error;
    if (outcome.kind !== 'resolved') throw new RetrievalError('EVIDENCE_INVALID');
    if (signalAborted(signal)) {
      abandoned = true;
      try { onLateSuccess(outcome.value); } catch { /* Revocation remains fail-closed. */ }
      throw abortError();
    }
    // Keep the opaque result nested so promise resolution never adopts a value
    // returned by the host adapter.
    return Object.freeze({ value: outcome.value });
  } finally {
    removeAbortListener(signal, onAbort);
  }
}

async function awaitBoundedCleanup(operation, timeoutMs = 250) {
  let timer;
  const pending = Promise.resolve().then(operation).then(() => true, () => true);
  const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve(false), timeoutMs); });
  try { return await Promise.race([pending, timeout]); }
  finally { clearTimeout(timer); }
}

async function awaitAbortableCleanup(operation, timeoutMs = 250, waitMs = timeoutMs + 25) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    await awaitBoundedCleanup(() => operation(controller.signal), waitMs);
  } finally {
    clearTimeout(timer);
    if (!controller.signal.aborted) controller.abort();
  }
}

function authorized(input, stage) {
  try {
    const value = input.authorizeCurrent(input.request, Object.freeze({ runId: input.runId, stage }));
    if (value === true) return true;
    // Authorization is synchronous. Invalid native Promise outcomes must stay
    // observed without forwarding a fulfilled value into another Promise.
    subscribeToSupportedNativePromise(value, () => {}, () => {});
    return false;
  } catch {
    return false;
  }
}

function snapshotHasBlockingStop(snapshot) {
  return snapshot.stopReasons.some((entry) => CANCELLATION_REASONS.has(entry.reason));
}

function stopLimitation(snapshot, limitations) {
  for (const entry of snapshot.stopReasons) {
    const mapped = STOP_LIMITATIONS.get(entry.reason);
    if (mapped) limitations.add(mapped);
  }
}

function safeFailureCode(error) {
  if (error instanceof RetrievalError) return error.code;
  if (error instanceof SourceIdentityCompositionError) return error.code;
  if (typeof error?.code === 'string' && /^[A-Z_]{3,40}$/.test(error.code)) return error.code;
  return 'UNAVAILABLE';
}

function limitationFor(code) {
  if (code === 'UNSUPPORTED_MEDIA') return 'unsupported_media';
  if (code === 'RESOURCE_LIMIT') return 'resource_limit';
  if (code === 'MALFORMED_ENCODING' || code === 'UNSUPPORTED_ENCODING') return 'malformed_or_unsupported_encoding';
  if (code === 'NO_IDENTITY_CANDIDATES') return 'no_supported_identity_or_link_candidates';
  if (code === 'JS_REQUIRED') return 'dynamic_rendering_required';
  if (code === 'ACCESS_RESTRICTED') return 'source_access_restricted';
  if (code === 'EXTRACTION_UNUSABLE') return 'source_incomplete_or_access_restricted';
  if (code === 'EVIDENCE_EXPIRED') return 'selected_evidence_expired_or_revoked';
  if (code === 'EVIDENCE_KEY_UNAVAILABLE') return 'selected_evidence_key_unavailable';
  if (code === 'DEADLINE_EXCEEDED') return 'deadline_exceeded';
  if (code === 'CANCELED') return 'cancelled';
  if (code === 'POLICY_DENIED' || code === 'DNS_FAILURE') return 'safe_fetch_policy_or_dns_denied';
  return 'source_unavailable';
}

function hashBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function validateProvenance(document, provenance, initialUrl, hops, mode = 'document') {
  if (!provenance || provenance.requestedUrl !== initialUrl || provenance.finalUrl !== document.url
    || provenance.mode !== mode || provenance.lifecycleBound !== true
    || provenance.bodyHash !== hashBytes(document.bytes)
    || !Array.isArray(provenance.redirectChain) || provenance.redirectChain.length !== document.redirects
    || !Array.isArray(provenance.hops) || provenance.hops.length !== document.redirects + 1
    || provenance.hops.length !== hops.length || provenance.hops.some((hop, index) => {
      const admitted = hops[index];
      return !admitted || hop.url !== admitted.url || hop.dispatchIntent !== true || hop.responseReceived !== true
        || (index < hops.length - 1
          ? hop.bodyComplete !== false || hop.decodedBytes !== null
          : hop.bodyComplete !== true || hop.decodedBytes !== document.bytes.byteLength);
    })) return false;
  for (let index = 0; index < provenance.redirectChain.length; index += 1) {
    if (provenance.redirectChain[index] !== hops[index + 1]?.url) return false;
  }
  return true;
}

function factFingerprint(fact) {
  return JSON.stringify({
    factId: fact.factId,
    field: fact.field,
    status: fact.status,
    rawValue: fact.rawValue,
    normalizedValue: fact.normalizedValue,
    precision: fact.precision,
    supports: (fact.supports ?? []).map((support) => ({
      contentHash: support.contentHash,
      duplicateGroupId: support.duplicateGroupId,
      independence: support.independence,
    })),
  });
}

function digestJson(value) {
  return createHash('sha256').update(JSON.stringify(value), 'utf8').digest('hex');
}

function stableTextCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function suggestionSortKey(suggestion) {
  const references = Array.isArray(suggestion?.sourceRefs) ? suggestion.sourceRefs.map((reference) => {
    const locator = reference?.locator;
    return JSON.stringify([
      reference?.evidenceId ?? '', reference?.contentHash ?? '', locator?.kind ?? '',
      locator?.startByte ?? null, locator?.endByte ?? null, locator?.pointer ?? null,
      reference?.field ?? '', reference?.value ?? '',
    ]);
  }).sort(stableTextCompare) : [];
  return JSON.stringify([suggestion?.url ?? '', references, suggestion?.label ?? null]);
}

function boundCompletionSuggestions(suggestions, maximum) {
  const ordered = [...suggestions].sort((left, right) =>
    stableTextCompare(suggestionSortKey(left), suggestionSortKey(right)));
  return { suggestions: ordered.slice(0, maximum), omittedSuggestions: ordered.slice(maximum) };
}

function completionObservations(snapshot, candidateId) {
  return snapshot.observations.filter((observation) => observation.kind === 'link'
    && observation.parentCandidateId === candidateId);
}

function observationsMatchSuggestions(observations, suggestions, outcome) {
  if (observations.length !== suggestions.length
    || observations.some((observation) => observation.outcome !== outcome)) return false;
  const counts = new Map();
  for (const suggestion of suggestions) {
    const key = suggestionSortKey(suggestion);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  for (const observation of observations) {
    const key = suggestionSortKey({
      url: observation.suppliedUrl,
      sourceRefs: observation.sourceRefs,
      label: observation.untrustedLabel ?? null,
    });
    const count = counts.get(key) ?? 0;
    if (count < 1) return false;
    if (count === 1) counts.delete(key);
    else counts.set(key, count - 1);
  }
  return counts.size === 0;
}

function completionPayloadHashFromObservations(observations, outcome, truncatedCount) {
  const suggestions = observations.map((observation) => ({
    suppliedUrl: observation.suppliedUrl,
    canonicalUrl: observation.canonicalUrl,
    label: observation.untrustedLabel ?? null,
    sourceRefs: observation.sourceRefs,
  })).sort((left, right) => stableTextCompare(JSON.stringify(left), JSON.stringify(right)));
  return digestJson({ outcome, suggestions, truncatedCount });
}

function projectionReferenceKey(reference) {
  if (!reference || typeof reference !== 'object' || Array.isArray(reference)) return null;
  const referenceKeys = Reflect.ownKeys(reference);
  if (referenceKeys.length !== 5 || referenceKeys.some((key) => typeof key !== 'string')
    || ['evidenceId', 'contentHash', 'locator', 'field', 'value'].some((key) => !Object.hasOwn(reference, key))
    || typeof reference.evidenceId !== 'string' || reference.evidenceId.length < 1
    || typeof reference.contentHash !== 'string' || !/^[a-f0-9]{64}$/.test(reference.contentHash)
    || typeof reference.field !== 'string' || reference.field.length < 1
    || typeof reference.value !== 'string' || reference.value.length < 1) return null;
  const locator = reference.locator;
  if (!locator || typeof locator !== 'object' || Array.isArray(locator)) return null;
  const locatorKeys = Reflect.ownKeys(locator);
  let normalizedLocator;
  if (locator.kind === 'text-range' && locatorKeys.length === 3
    && locatorKeys.every((key) => typeof key === 'string')
    && Number.isSafeInteger(locator.startByte) && locator.startByte >= 0
    && Number.isSafeInteger(locator.endByte) && locator.endByte > locator.startByte) {
    normalizedLocator = { kind: 'text-range', startByte: locator.startByte, endByte: locator.endByte };
  } else if (locator.kind === 'json-pointer' && locatorKeys.length === 2
    && locatorKeys.every((key) => typeof key === 'string')
    && typeof locator.pointer === 'string') {
    normalizedLocator = { kind: 'json-pointer', pointer: locator.pointer };
  } else {
    return null;
  }
  return JSON.stringify([
    reference.evidenceId, reference.contentHash, normalizedLocator, reference.field, reference.value,
  ]);
}

function projectionReferenceKeys(references) {
  if (!Array.isArray(references)) return null;
  const keys = references.map(projectionReferenceKey);
  if (keys.some((key) => key === null)) return null;
  return keys.sort(stableTextCompare);
}

function projectionObservationPathExists(observations, startCandidateId, targetCandidateId, excludedIndex) {
  if (startCandidateId === targetCandidateId) return true;
  const edges = new Map();
  observations.forEach((observation, index) => {
    if (index === excludedIndex || observation.kind !== 'link') return;
    const children = edges.get(observation.parentCandidateId) ?? [];
    children.push(observation.targetCandidateId);
    edges.set(observation.parentCandidateId, children);
  });
  const pending = [startCandidateId];
  const visited = new Set();
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === targetCandidateId) return true;
    if (visited.has(current)) continue;
    visited.add(current);
    for (const child of edges.get(current) ?? []) pending.push(child);
  }
  return false;
}

function projectionSnapshotReferencesMatch(snapshot, seeds) {
  if (!Array.isArray(snapshot?.candidates) || !Array.isArray(snapshot.observations)
    || !Array.isArray(seeds) || !Number.isSafeInteger(snapshot.limits?.maxDepth)
    || !Array.isArray(snapshot.stopReasons)) return false;
  const candidatesById = new Map(snapshot.candidates.map((candidate) => [candidate.candidateId, candidate]));
  if (candidatesById.size !== snapshot.candidates.length) return false;
  const canonicalCandidateIds = new Map();
  for (const candidate of snapshot.candidates) {
    if (!candidate || typeof candidate.candidateId !== 'string' || typeof candidate.canonicalUrl !== 'string'
      || !Number.isSafeInteger(candidate.depth) || candidate.depth < 0 || typeof candidate.seed !== 'boolean') return false;
    const prior = canonicalCandidateIds.get(candidate.canonicalUrl);
    if (prior !== undefined && prior !== candidate.candidateId) return false;
    canonicalCandidateIds.set(candidate.canonicalUrl, candidate.candidateId);
  }

  const seedInputs = new Map();
  for (const seed of seeds) {
    let canonicalUrl;
    try { canonicalUrl = parseAndValidateUrl(seed.url).url.href; } catch { return false; }
    const sourceRefKeys = projectionReferenceKeys(seed.sourceRefs ?? []);
    if (!sourceRefKeys) return false;
    const key = JSON.stringify([seed.url, canonicalUrl, sourceRefKeys]);
    seedInputs.set(key, (seedInputs.get(key) ?? 0) + 1);
  }

  const targetReferences = new Map();
  const targetObservationCounts = new Map();
  const targetOriginCounts = new Map();
  const targetDepthLimitCounts = new Map();
  const targetMinimumDepth = new Map();
  const seedTargets = new Set();
  const linkDispositions = new Set(['duplicate', 'cycle', 'depth_limit', 'queued', 'retained_after_stop']);
  const maximumDepth = snapshot.limits.maxDepth;
  for (const [observationIndex, observation] of snapshot.observations.entries()) {
    if (!observation || !['seed', 'link'].includes(observation.kind)
      || typeof observation.targetCandidateId !== 'string' || typeof observation.canonicalUrl !== 'string') return false;
    const target = candidatesById.get(observation.targetCandidateId);
    if (!target || target.canonicalUrl !== observation.canonicalUrl) return false;
    const referenceKeys = projectionReferenceKeys(observation.sourceRefs);
    if (!referenceKeys) return false;
    targetObservationCounts.set(observation.targetCandidateId,
      (targetObservationCounts.get(observation.targetCandidateId) ?? 0) + 1);
    if (!Number.isSafeInteger(observation.depth) || observation.depth < 0) return false;
    targetMinimumDepth.set(observation.targetCandidateId,
      Math.min(targetMinimumDepth.get(observation.targetCandidateId) ?? Number.POSITIVE_INFINITY, observation.depth));
    const accumulated = targetReferences.get(observation.targetCandidateId) ?? [];
    accumulated.push(...referenceKeys);
    targetReferences.set(observation.targetCandidateId, accumulated);

    if (observation.kind === 'seed') {
      if (observation.parentCandidateId !== null || observation.depth !== 0
        || !['seed', 'duplicate'].includes(observation.disposition)
        || (observation.outcome !== undefined && observation.outcome !== null)
        || typeof observation.suppliedUrl !== 'string') return false;
      const key = JSON.stringify([observation.suppliedUrl, observation.canonicalUrl, referenceKeys]);
      const remaining = seedInputs.get(key) ?? 0;
      if (remaining < 1) return false;
      if (remaining === 1) seedInputs.delete(key);
      else seedInputs.set(key, remaining - 1);
      seedTargets.add(observation.targetCandidateId);
      if (observation.disposition === 'seed') {
        targetOriginCounts.set(observation.targetCandidateId,
          (targetOriginCounts.get(observation.targetCandidateId) ?? 0) + 1);
      }
    } else {
      const parent = candidatesById.get(observation.parentCandidateId);
      if (!parent || !Number.isSafeInteger(parent.depth) || parent.depth < 0
        || typeof observation.suppliedUrl !== 'string' || observation.outcome !== 'links_observed'
        || !linkDispositions.has(observation.disposition)
        || !Number.isSafeInteger(observation.depth) || observation.depth < parent.depth + 1
        || (observation.depth > maximumDepth + 1 && observation.disposition !== 'cycle')) return false;
      if (observation.disposition === 'depth_limit') {
        if (observation.depth <= maximumDepth) return false;
      } else if (observation.disposition !== 'cycle' && observation.depth > maximumDepth) {
        return false;
      }
      if (observation.disposition === 'retained_after_stop'
        && (!snapshot.stopReasons.some((stop) => stop.reason === 'attempt_limit') || snapshot.state === 'active')) {
        return false;
      }
      if (['queued', 'retained_after_stop'].includes(observation.disposition)) {
        targetOriginCounts.set(observation.targetCandidateId,
          (targetOriginCounts.get(observation.targetCandidateId) ?? 0) + 1);
      }
      if (observation.disposition === 'depth_limit') {
        targetDepthLimitCounts.set(observation.targetCandidateId,
          (targetDepthLimitCounts.get(observation.targetCandidateId) ?? 0) + 1);
      }
      if (observation.disposition === 'cycle'
        && !projectionObservationPathExists(snapshot.observations, observation.targetCandidateId,
          observation.parentCandidateId, observationIndex)) return false;
    }
  }
  if (seedInputs.size !== 0) return false;
  for (const candidate of snapshot.candidates) {
    if (candidate.seed !== seedTargets.has(candidate.candidateId)
      || candidate.depth !== targetMinimumDepth.get(candidate.candidateId)
      || (targetObservationCounts.get(candidate.candidateId) ?? 0) < 1) return false;
    const originCount = targetOriginCounts.get(candidate.candidateId) ?? 0;
    const depthLimitCount = targetDepthLimitCounts.get(candidate.candidateId) ?? 0;
    if (candidate.seed ? originCount !== 1 : originCount > 1 || originCount + depthLimitCount === 0) return false;
    const expected = [...new Set(targetReferences.get(candidate.candidateId) ?? [])].sort(stableTextCompare);
    const actual = projectionReferenceKeys(candidate.sourceRefs);
    if (!actual || JSON.stringify(actual) !== JSON.stringify(expected)) return false;
  }
  return true;
}

function projectionObservationTargetsMatch(snapshot, parentCandidateId, observations, authenticatedClaimDepth) {
  if (!Array.isArray(snapshot?.candidates) || !Array.isArray(snapshot.observations)
    || !Number.isSafeInteger(snapshot.limits?.maxDepth)
    || !Number.isSafeInteger(authenticatedClaimDepth) || authenticatedClaimDepth < 0) return false;
  const candidatesById = new Map(snapshot.candidates.map((candidate) => [candidate.candidateId, candidate]));
  const parent = candidatesById.get(parentCandidateId);
  if (!parent || !Number.isSafeInteger(parent.depth) || parent.depth < 0
    || parent.depth > authenticatedClaimDepth) return false;
  const maximumDepth = snapshot.limits.maxDepth;
  for (const observation of observations) {
    if (observation.parentCandidateId !== parentCandidateId
      || typeof observation.targetCandidateId !== 'string'
      || typeof observation.canonicalUrl !== 'string'
      || !Number.isSafeInteger(observation.depth) || observation.depth < parent.depth + 1
      || observation.depth > authenticatedClaimDepth + 1
      || observation.depth > maximumDepth + 1 && observation.disposition !== 'cycle') return false;
    const target = candidatesById.get(observation.targetCandidateId);
    if (!target || target.canonicalUrl !== observation.canonicalUrl
      || !Number.isSafeInteger(target.depth) || target.depth < 0 || target.depth > observation.depth) return false;
    if (observation.disposition === 'depth_limit') {
      if (observation.depth <= maximumDepth) return false;
    } else if (observation.disposition !== 'cycle' && observation.depth > maximumDepth) {
      return false;
    }
  }
  return true;
}

function completionPayloadMatches(receipt, snapshot, candidateId, completion, truncatedCount) {
  if (!completion || typeof completion.payloadHash !== 'string'
    || receipt?.candidate?.candidateId !== candidateId
    || !Number.isSafeInteger(receipt.candidate.depth) || receipt.candidate.depth < 0) return false;
  const observations = completionObservations(snapshot, candidateId);
  return observationsMatchSuggestions(observations, receipt.suggestions, receipt.outcome)
    && projectionObservationTargetsMatch(snapshot, candidateId, observations, receipt.candidate.depth)
    && completionPayloadHashFromObservations(observations, receipt.outcome, truncatedCount) === completion.payloadHash;
}

function reconstructCompletedLegacyReceipt(receipt, snapshot, candidateId, completion, maximum) {
  const full = boundCompletionSuggestions(receipt.suggestions, receipt.suggestions.length);
  if (completionPayloadMatches({ ...receipt, suggestions: full.suggestions }, snapshot, candidateId, completion, 0)) {
    return { ...receipt, suggestions: full.suggestions, truncatedCount: 0, omittedSuggestions: [] };
  }
  const bounded = boundCompletionSuggestions(receipt.suggestions, maximum);
  if (bounded.omittedSuggestions.length > 0
    && completionPayloadMatches({ ...receipt, suggestions: bounded.suggestions }, snapshot, candidateId,
      completion, bounded.omittedSuggestions.length)) {
    return {
      ...receipt,
      suggestions: bounded.suggestions,
      truncatedCount: bounded.omittedSuggestions.length,
      omittedSuggestions: bounded.omittedSuggestions,
    };
  }
  return null;
}

function receiptCandidate(candidate, bindSuppliedUrl = false, assetAcquisition) {
  if (bindSuppliedUrl && (typeof candidate.suppliedUrl !== 'string' || candidate.suppliedUrl.length < 1
    || candidate.suppliedUrl.length > 8_192 || urlHasSensitiveMaterial(candidate.suppliedUrl))) {
    throw new PrivateRetrievalError('INVALID_INPUT');
  }
  return Object.freeze({
    candidateId: candidate.candidateId,
    canonicalUrl: candidate.canonicalUrl,
    ...(bindSuppliedUrl ? { suppliedUrl: candidate.suppliedUrl } : {}),
    depth: candidate.depth,
    seed: candidate.seed,
    sourceRefs: Object.freeze(candidate.sourceRefs.map((reference) => Object.freeze({ ...reference }))),
    ...(assetAcquisition ? { assetAcquisition } : {}),
  });
}

function emptyIdentityResult() {
  return Object.freeze({
    entityCandidates: Object.freeze([]),
    occurrenceCandidates: Object.freeze([]),
    transitionLinks: Object.freeze([]),
    unresolvedTransitions: Object.freeze([]),
  });
}

function compareAllPairs(values, compare) {
  const comparisonCount = values.length * (values.length - 1) / 2;
  if (!Number.isSafeInteger(comparisonCount) || comparisonCount > MAX_AGGREGATE_COMPARISONS) {
    throw new PrivateRetrievalError('RESOURCE_LIMIT');
  }
  const decisions = [];
  for (let left = 0; left < values.length; left += 1) {
    for (let right = left + 1; right < values.length; right += 1) decisions.push(compare(values[left], values[right]));
  }
  return Object.freeze(decisions);
}

function aggregateIdentity(candidateResults) {
  const entityCandidates = candidateResults.flatMap((item) => item.entityCandidates);
  const occurrenceCandidates = candidateResults.flatMap((item) => item.occurrenceCandidates);
  if (entityCandidates.length > MAX_AGGREGATE_IDENTITY_CANDIDATES
    || occurrenceCandidates.length > MAX_AGGREGATE_IDENTITY_CANDIDATES) {
    throw new PrivateRetrievalError('RESOURCE_LIMIT');
  }
  return Object.freeze({
    entityCandidates: Object.freeze(entityCandidates),
    occurrenceCandidates: Object.freeze(occurrenceCandidates),
    entityDecisions: compareAllPairs(entityCandidates, compareEntityIdentity),
    occurrenceDecisions: compareAllPairs(occurrenceCandidates, compareOccurrenceIdentity),
    transitionLinks: Object.freeze(candidateResults.flatMap((item) => item.transitionLinks)),
    unresolvedTransitions: Object.freeze(candidateResults.flatMap((item) => item.unresolvedTransitions)),
  });
}

function projection(identity, selectedEvidence, selectedFacts, progress, limitations, omittedLinkCandidates,
  truncatedSuggestionCount, sourceLinkCandidateOmittedCount, sourceLinkCandidateOmittedCountLowerBound,
  sourceLinkCandidateOmittedCountComplete, assetCandidateIds = new Set(), assetAcquisitions = undefined,
  deadlineAtMonotonic, signal) {
  // A trusted final authority callback can consume time synchronously. Recheck
  // the original deadline before reading the selection into a new projection.
  if (performance.now() >= deadlineAtMonotonic) throw new RetrievalError('DEADLINE_EXCEEDED');
  if (signalAborted(signal)) throw new RetrievalError('CANCELED');
  const facts = selectedFacts;
  const evidenceById = new Map(selectedEvidence.map((item) => [item.metadata.evidenceId, item]));
  const sources = [...evidenceById.values()].map((item) => Object.freeze({
    evidenceId: item.metadata.evidenceId,
    version: item.metadata.version,
    representation: item.metadata.representation ?? 'raw',
    sourceUrl: item.source.sourceUrl,
    canonicalUrl: item.source.canonicalUrl,
    redirectChain: Object.freeze([...item.source.redirectChain]),
    contentType: item.source.contentType,
    retrievedAt: item.source.retrievedAt,
    contentHash: item.source.contentHash,
    sourceAuthority: 'not_evaluated',
    ...(item.source.derivedPdf ? {
      pdf: Object.freeze({
        pageCount: item.source.derivedPdf.pages.length,
        textPageCount: item.source.derivedPdf.pages.filter((page) => page.textPresence === 'text-present').length,
        textBoxCount: item.source.derivedPdf.textBoxCount,
        completeness: 'incomplete',
        requiresInspection: true,
      }),
    } : {}),
    ...(item.source.assetSource ? {
      assetCandidates: Object.freeze(item.source.assetSource.candidates.map((candidate) => Object.freeze({
        candidateId: candidate.candidateId,
        sourceForm: candidate.sourceForm,
        field: candidate.field,
        association: candidate.association,
        locator: candidate.locator,
        excerptHash: candidate.excerptHash,
        normalizedSuggestion: candidate.normalizedSuggestion,
        fetchSuggestion: candidate.fetchSuggestion,
        quarantineReason: candidate.quarantineReason,
        role: 'unknown',
        permission: 'unknown',
        inspection: 'pending',
        sourceRef: Object.freeze({
          evidenceId: item.metadata.evidenceId,
          contentHash: item.source.contentHash,
          locator: candidate.locator,
          field: candidate.field,
        }),
      }))),
      assetCompleteness: item.source.assetSource.completeness,
      assetLimitations: Object.freeze([...item.source.assetSource.limitations]),
    } : {}),
  }));
  const occurrenceCandidates = identity.occurrenceCandidates;
  const entityCandidates = identity.entityCandidates;
  const occurrenceDecisions = identity.occurrenceDecisions;
  const entityDecisions = identity.entityDecisions;
  const conflicts = Object.freeze([
    ...occurrenceDecisions.filter((decision) => decision.conflictFields.length > 0).map((decision) => Object.freeze({
      kind: 'occurrence_identity', candidateIds: decision.candidateIds, reasonCodes: decision.reasonCodes,
      fields: decision.conflictFields, decision,
    })),
    ...entityDecisions.filter((decision) => decision.relation === 'review'
      && decision.reasonCodes.some((reason) => reason.endsWith('_conflict'))).map((decision) => Object.freeze({
      kind: 'entity_identity', candidateIds: decision.candidateIds, reasonCodes: decision.reasonCodes, decision,
    })),
  ]);
  const linkCandidates = progress.candidates.filter((candidate) => candidate.depth > 0
    && !assetCandidateIds.has(candidate.candidateId)).map((candidate) => Object.freeze({
    candidateId: candidate.candidateId,
    url: candidate.canonicalUrl,
    depth: candidate.depth,
    sourceRefs: candidate.sourceRefs,
    sourceAuthority: 'not_evaluated',
  }));
  const sourceAuthorityReview = composeSourceAuthorityReview({
    occurrenceCandidates, entityCandidates, sources,
    limitations: [...limitations], stopReasons: progress.stopReasons.map((entry) => entry.reason),
  });
  const draft = Object.freeze({
    schema: PRIVATE_DRAFT_SCHEMA,
    status: facts.length > 0 ? 'draft' : 'incomplete',
    completeness: 'incomplete',
    facts: Object.freeze(facts),
    occurrenceCandidates: Object.freeze(occurrenceCandidates),
    entityCandidates: Object.freeze(entityCandidates),
    occurrenceDecisions: Object.freeze(occurrenceDecisions),
    entityDecisions: Object.freeze(entityDecisions),
    transitionLinks: identity.transitionLinks,
    unresolvedTransitions: identity.unresolvedTransitions,
    sources: Object.freeze(sources),
    linkCandidates: Object.freeze(linkCandidates),
    ...(assetAcquisitions !== undefined ? { assetAcquisitions: Object.freeze([...assetAcquisitions]) } : {}),
    omittedLinkCandidates: Object.freeze(omittedLinkCandidates.map((suggestion) => Object.freeze({
      url: suggestion.url,
      sourceRefs: suggestion.sourceRefs,
      reason: 'completion_suggestion_limit',
    }))),
    conflicts,
    sourceAuthority: 'not_evaluated',
    ...(sourceAuthorityReview ? { sourceAuthorityReview } : {}),
    rights: 'not_evaluated',
    usage: 'unknown',
    limitations: Object.freeze([...limitations].sort()),
    progress: Object.freeze({
      state: progress.state,
      stopReason: progress.stopReason,
      stopReasons: Object.freeze(progress.stopReasons.map((entry) => entry.reason)),
      completedCandidates: progress.candidates.filter((candidate) => candidate.state === 'completed').length,
      remainingCandidates: progress.candidates.filter((candidate) => candidate.state === 'queued' || candidate.state === 'leased').length,
      transportAttemptAdmissions: progress.counters.transportAttemptAdmissions,
      truncatedSuggestionCount,
      sourceLinkCandidateOmittedCount,
      sourceLinkCandidateOmittedCountLowerBound,
      sourceLinkCandidateOmittedCountComplete,
    }),
  });
  if (performance.now() >= deadlineAtMonotonic) throw new RetrievalError('DEADLINE_EXCEEDED');
  if (signalAborted(signal)) throw new RetrievalError('CANCELED');
  return draft;
}

/**
 * Private offline retrieval composition. It accepts only source URLs and app-issued
 * host callbacks; fetched documents and caller-provided extraction/provenance are not inputs.
 */
export async function runPrivateRetrieval(value) {
  const input = snapshotRunInput(value);
  let runConfigHash = digestJson({ runId: input.runId, seeds: input.seeds, limits: input.limits });
  let assetPolicy = null;
  let assetReleaseController = null;
  let assetReleaseAuthority = null;
  const limitations = new Set([
    'source_authority_not_evaluated', 'rights_not_evaluated', 'billable_usage_unknown', 'provider_and_external_egress_not_measured',
  ]);
  const candidateResults = [];
  const outputFacts = new Map();
  const evidenceIds = new Set();
  const verifiedCompletionProofs = new Map();
  const omittedLinkCandidates = [];
  const assetAcquisitionResults = [];
  const assetAcquisitionReceipts = new Map();
  const assetReleaseRoleReferences = new Map();
  const assetCandidateIds = new Set();
  let truncatedSuggestionCount = 0;
  let sourceLinkCandidateOmittedCountLowerBound = 0;
  let sourceLinkCandidateOmittedCountComplete = true;
  const activeHops = new Map();
  const controller = new AbortController();
  const runStartedAt = performance.now();
  let deadlineAtMonotonic = runStartedAt + input.limits.durationMs;
  let deadlineTimer;
  let scope;
  let evidenceScope;
  let runCreated = false;
  let watcherOpen = false;
  let watcherPromise = Promise.resolve();
  let watcherDrained = false;
  let localStopPromise = Promise.resolve();
  const stopCleanupCallbacks = new Map();
  let externalAbort = false;
  let stopCause = null;
  let deadlineStopStarted = false;
  let stopPersistenceStarted = false;
  let cleanupEnvelopeDeadline = Number.NaN;
  let runFailure = null;
  let assetReleaseAuthorityRevoked = false;
  const discardedAssetReleaseChecks = new WeakSet();
  const abortError = () => new RetrievalError(stopCause === 'deadline' ? 'DEADLINE_EXCEEDED' : 'CANCELED');
  const beginCleanupEnvelope = () => {
    if (!Number.isFinite(cleanupEnvelopeDeadline)) {
      // A delayed deadline callback must spend the time left in the original
      // recovery envelope, rather than granting a new full cleanup budget.
      // Cancellation observed before that deadline still gets its own envelope.
      cleanupEnvelopeDeadline = Math.min(performance.now(), deadlineAtMonotonic)
        + STOP_RECOVERY_ENVELOPE_MS;
    }
  };
  const remainingCleanupMs = () => Number.isFinite(cleanupEnvelopeDeadline)
    ? Math.max(0, cleanupEnvelopeDeadline - performance.now()) : 0;
  const awaitRunCleanup = (operation, maximumWaitMs = ABORTABLE_CLEANUP_MS) => {
    const remaining = remainingCleanupMs();
    if (remaining <= 0) return Promise.resolve(false);
    const timeoutMs = Math.min(maximumWaitMs, remaining);
    const waitMs = Math.min(timeoutMs + 25, remaining);
    return awaitAbortableCleanup(operation, timeoutMs, waitMs);
  };
  const persistStop = (reason) => {
    stopPersistenceStarted = true;
    if (!runCreated) return;
    const cleanup = new AbortController();
    const stopDeadlineAt = Math.min(performance.now() + STOP_PERSIST_CLEANUP_MS, cleanupEnvelopeDeadline);
    const remaining = Math.max(0, stopDeadlineAt - performance.now());
    let timer;
    const abortStop = () => {
      clearTimeout(timer);
      if (!cleanup.signal.aborted) cleanup.abort();
    };
    stopCleanupCallbacks.set(abortStop, stopDeadlineAt);
    if (remaining <= 0) abortStop();
    else timer = setTimeout(abortStop, remaining);
    const pending = Promise.resolve().then(() => {
      // A sibling abort listener may block after this microtask is scheduled.
      // Microtasks run before overdue timers, so enforce the original bound
      // again at callback entry without granting another stop allowance.
      if (performance.now() >= stopDeadlineAt) abortStop();
      return input.frontier.stopRun(scope, input.runId, reason, cleanup.signal);
    })
      .catch(() => {}).finally(() => {
        stopCleanupCallbacks.delete(abortStop);
        abortStop();
      });
    localStopPromise = Promise.all([localStopPromise, pending]).then(() => undefined);
  };
  const awaitStopPersistence = async () => {
    const remaining = remainingCleanupMs();
    const settled = remaining > 0 && await awaitBoundedCleanup(() => localStopPromise, remaining);
    // The bounded waiter can run before a stop timer due at the same boundary.
    // Once this wait is exhausted, no pending stop signal retains an allowance.
    if (!settled) for (const abortStop of stopCleanupCallbacks.keys()) abortStop();
    return settled;
  };
  const revokeAssetReleaseAuthority = (reason) => {
    if (!assetReleaseController || assetReleaseAuthorityRevoked) return;
    assetReleaseAuthorityRevoked = true;
    revokePrivateAssetReleaseController(assetReleaseController, reason);
  };
  const releaseCheckFromPreparation = (value) => {
    try {
      if (!value || typeof value !== 'object' || utilTypes.isProxy(value)) return null;
      const record = plainDataRecord(value, new Set(['releaseCheck', 'candidateIds']));
      if (!record || !Object.hasOwn(record, 'releaseCheck')) return null;
      const check = record.releaseCheck;
      return check && typeof check === 'object' ? check : null;
    } catch { return null; }
  };
  const discardAssetReleaseCheck = (releaseCheck) => {
    if (!releaseCheck || discardedAssetReleaseChecks.has(releaseCheck)) return false;
    discardedAssetReleaseChecks.add(releaseCheck);
    try {
      return input.assetReleaseFinalizationStore.discardControlledAssetRelease(evidenceScope, releaseCheck) === true;
    } catch { return false; }
  };
  const discardAssetReleasePreparation = (value) =>
    discardAssetReleaseCheck(releaseCheckFromPreparation(value));
  const abortForStop = (reason) => {
    if (stopCause === null) stopCause = reason;
    beginCleanupEnvelope();
    if (!controller.signal.aborted) controller.abort();
    revokeAssetReleaseAuthority(`run_stopped:${reason}`);
  };
  const triggerDeadline = () => {
    if (stopCause === null) stopCause = 'deadline';
    beginCleanupEnvelope();
    if (!controller.signal.aborted) controller.abort();
    revokeAssetReleaseAuthority('run_deadline');
    if (!deadlineStopStarted) {
      deadlineStopStarted = true;
      persistStop('deadline');
    }
  };
  const armDeadline = () => {
    if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
    const remainingMs = deadlineAtMonotonic - performance.now();
    if (remainingMs <= 0) {
      triggerDeadline();
      return;
    }
    deadlineTimer = setTimeout(triggerDeadline, Math.ceil(remainingMs));
  };
  const checkDeadline = () => {
    if (performance.now() >= deadlineAtMonotonic) triggerDeadline();
    if (controller.signal.aborted) throw abortError();
  };
  const awaitOperation = async (operation) => {
    checkDeadline();
    return await awaitAbortableOperation(operation, controller.signal, abortError);
  };
  const currentAssetPolicyMatches = async () => {
    if (!assetPolicy || !assetReleaseController || !assetReleaseAuthority
      || !input.assetAcquisitionPolicyFor || !authorized(input, 'asset-acquisition')
      || !privateAssetReleaseControllerMatches(assetReleaseController, {
        runId: input.runId,
        policyDigest: digestJson(assetPolicy),
        deadlineAtMonotonic,
      })) return false;
    try {
      const valueNow = await awaitAbortableHostCallback(input.assetAcquisitionPolicyFor, [input.request,
        Object.freeze({ runId: input.runId })], controller.signal, abortError);
      const current = normalizeAssetAcquisitionPolicy(valueNow);
      return current !== null && digestJson(current) === digestJson(assetPolicy);
    } catch {
      return false;
    }
  };
  const forgetAcquiredAssetPlan = (candidateId) => {
    assetAcquisitionReceipts.delete(candidateId);
    assetReleaseRoleReferences.delete(candidateId);
    const index = assetAcquisitionResults.findIndex((entry) => entry.candidate.frontierCandidateId === candidateId);
    if (index >= 0) assetAcquisitionResults.splice(index, 1);
  };
  const openCurrentAssetSource = async (binding) => {
    if (!assetPolicy || !await currentAssetPolicyMatches()) return null;
    try {
      const handle = await awaitOperation(() => input.evidenceStore.lookupEvidence(
        evidenceScope, binding.sourceEvidenceId, controller.signal,
      ));
      if (!input.assetSourceBindingStore) return null;
      const stored = await awaitOperation(() => input.assetSourceBindingStore.readAssetSourceCandidateBinding(
        evidenceScope, handle, binding.candidateId, input.request, controller.signal,
      ));
      const actualBinding = assetBindingFromStoredCandidate(assetPolicy, stored, binding.candidateId);
      if (!actualBinding || JSON.stringify(actualBinding) !== JSON.stringify(binding)) return null;
      return { handle, stored };
    } catch {
      if (controller.signal.aborted) throw abortError();
      return null;
    }
  };
  const rememberAcquiredAssetPlan = async (receipt) => {
    const binding = receipt?.candidate?.assetAcquisition;
    const acquisition = receipt?.assetAcquisition;
    if (!binding || !acquisition) return true;
    assetCandidateIds.add(receipt.candidate.candidateId);
    if (!input.controlledAssetEvidenceStore || !await currentAssetPolicyMatches()) {
      limitations.add('asset_acquisition_reopen_unavailable');
      return false;
    }
    const source = await openCurrentAssetSource(binding);
    if (!source) {
      limitations.add('asset_source_candidate_reopen_failed');
      return false;
    }
    let original;
    let transformed;
    let inspection;
    let checkedTransformed;
    try {
      const originalHandle = await awaitOperation(() => input.evidenceStore.lookupEvidence(
        evidenceScope, acquisition.originalEvidence.evidenceId, controller.signal,
      ));
      const transformedHandle = await awaitOperation(() => input.evidenceStore.lookupEvidence(
        evidenceScope, acquisition.transformedEvidence.evidenceId, controller.signal,
      ));
      original = await awaitOperation(() => input.controlledAssetEvidenceStore.readControlledAssetBytes(
        evidenceScope, originalHandle, input.request, controller.signal,
      ));
      transformed = await awaitOperation(() => input.controlledAssetEvidenceStore.readControlledAssetBytes(
        evidenceScope, transformedHandle, input.request, controller.signal,
      ));
      if (original.metadata.version !== acquisition.originalEvidence.version
        || original.metadata.contentHash !== acquisition.originalEvidence.contentHash
        || original.bytes.byteLength !== acquisition.originalEvidence.byteLength
        || transformed.metadata.version !== acquisition.transformedEvidence.version
        || transformed.metadata.contentHash !== acquisition.transformedEvidence.contentHash
        || transformed.bytes.byteLength !== acquisition.transformedEvidence.byteLength
        || hashBytes(original.bytes) !== acquisition.sourceBytesHash
        || hashBytes(transformed.bytes) !== acquisition.transformedBytesHash) {
        limitations.add('asset_acquisition_reopen_hash_mismatch');
        return false;
      }
      inspection = inspectSafeAssetBytes(original.bytes, { contentType: 'image/svg+xml', signal: controller.signal });
      if (inspection.action !== 'transformed' || inspection.policyVersion !== SAFE_ASSET_POLICY_VERSION
        || inspection.sourceHash !== acquisition.sourceBytesHash
        || inspection.transformedHash !== acquisition.transformedBytesHash) {
        limitations.add('asset_acquisition_reinspection_failed');
        return false;
      }
      checkedTransformed = inspection.copyTransformedBytes();
      if (!inspection.matchesTransformedBytes(checkedTransformed)
        || !Buffer.from(checkedTransformed).equals(Buffer.from(transformed.bytes))) {
        limitations.add('asset_acquisition_reinspection_failed');
        return false;
      }
      if (!await currentAssetPolicyMatches()) {
        limitations.add('asset_acquisition_policy_changed');
        return false;
      }
      // The policy callback may be asynchronous. Recheck the synchronous
      // stage capability after it resolves so a revocation during that await
      // cannot mint or refresh a released local plan.
      if (!authorized(input, 'asset-acquisition')) {
        limitations.add('authorization_revoked');
        return false;
      }
      const bindingHash = digestJson({
        runId: input.runId,
        configHash: runConfigHash,
        frontierCandidateId: receipt.candidate.candidateId,
        binding,
        sourceEvidence: {
          evidenceId: source.stored.metadata.evidenceId,
          version: source.stored.metadata.version,
          contentHash: source.stored.metadata.contentHash,
          derivationDigest: source.stored.metadata.derivationDigest,
        },
        originalEvidence: acquisition.originalEvidence,
        transformedEvidence: acquisition.transformedEvidence,
      });
      const questionPlan = Object.freeze({
        questionId: 'Q-EI-BRAND-ROLE:v1',
        status: 'blocked',
        candidateBindingHash: bindingHash,
        execution: 'not_dispatched',
        observerMetadata: null,
        observerMetadataProvenance: 'absent',
        rights: 'unknown',
        permission: 'unknown',
        roleClassification: null,
        reasonCodes: Object.freeze([
          'observer_metadata_unavailable', 'decision_port_contract_unavailable', 'rights_not_evaluated',
        ]),
      });
      const result = Object.freeze({
        schemaVersion: 1,
        status: 'blocked_local_inspection_only',
        candidateBindingHash: bindingHash,
        candidate: Object.freeze({
          frontierCandidateId: receipt.candidate.candidateId,
          assetSourceCandidateId: binding.candidateId,
          sourceEvidenceId: binding.sourceEvidenceId,
          assetUrl: binding.assetUrl,
          field: binding.field,
          excerptHash: binding.excerptHash,
        }),
        sourceEvidence: Object.freeze({
          evidenceId: source.stored.metadata.evidenceId,
          version: source.stored.metadata.version,
          contentHash: source.stored.metadata.contentHash,
          derivationDigest: source.stored.metadata.derivationDigest,
        }),
        acquiredEvidence: Object.freeze({
          fetchedSource: Object.freeze({ ...acquisition.originalEvidence }),
          transformed: Object.freeze({ ...acquisition.transformedEvidence }),
          sourceBytesHash: acquisition.sourceBytesHash,
          transformedBytesHash: acquisition.transformedBytesHash,
          inspectionPolicyVersion: acquisition.inspectionPolicyVersion,
          storedBytesReopenedAndVerified: true,
        }),
        acceptedExternalAssetVersion: null,
        questionPlan,
      });
      assetCandidateIds.add(receipt.candidate.candidateId);
      const existing = assetAcquisitionResults.findIndex((entry) => entry.candidate.frontierCandidateId
        === receipt.candidate.candidateId);
      if (existing < 0) assetAcquisitionResults.push(result);
      else assetAcquisitionResults[existing] = result;
      assetReleaseRoleReferences.set(receipt.candidate.candidateId, Object.freeze({
        candidateId: receipt.candidate.candidateId,
        evidence: Object.freeze([
          Object.freeze({ handle: originalHandle, metadata: original.metadata }),
          Object.freeze({ handle: transformedHandle, metadata: transformed.metadata }),
        ]),
      }));
      assetAcquisitionReceipts.set(receipt.candidate.candidateId, receipt);
      return true;
    } catch {
      limitations.add('asset_acquisition_reopen_unavailable');
      return false;
    } finally {
      original?.bytes?.fill(0);
      transformed?.bytes?.fill(0);
      checkedTransformed?.fill(0);
      inspection?.dispose?.();
    }
  };
  armDeadline();
  const onExternalAbort = () => {
    externalAbort = true;
    if (stopCause === null) stopCause = 'cancelled';
    beginCleanupEnvelope();
    if (!controller.signal.aborted) controller.abort();
    revokeAssetReleaseAuthority('run_cancelled');
    persistStop('cancelled');
  };
  if (input.signal !== undefined) {
    addAbortListener(input.signal, onExternalAbort);
    if (signalAborted(input.signal)) onExternalAbort();
  }
  try {
    checkDeadline();
    if (controller.signal.aborted) return incompleteResult(input.runId, stopCause === 'deadline' ? 'incomplete' : 'cancelled',
      [stopCause === 'deadline' ? 'deadline_exceeded' : 'cancelled']);
    if (!authorized(input, 'start')) return incompleteResult(input.runId, 'denied', ['authorization_denied']);
    if (input.assetAcquisitionPolicyFor) {
      const policyValue = await awaitAbortableHostCallback(input.assetAcquisitionPolicyFor, [input.request,
        Object.freeze({ runId: input.runId })], controller.signal, abortError);
      assetPolicy = normalizeAssetAcquisitionPolicy(policyValue);
      if (assetPolicy) {
        runConfigHash = digestJson({
          schema: 'ei-private-retrieval-config/asset-acquisition-v2',
          runId: input.runId,
          seeds: input.seeds,
          limits: input.limits,
          assetAcquisitionPolicy: assetPolicy,
          releaseProtocol: 'one-shot-synchronous-projection/v1',
        });
        if (!input.controlledAssetEvidenceStore || !input.assetSourceBindingStore || !input.assetReleaseFinalizationStore) {
          limitations.add('asset_acquisition_store_unavailable');
          return incompleteResult(input.runId, 'incomplete', [...limitations]);
        }
        if (!input.assetAcquisitionReleaseAuthorityFor) {
          limitations.add('asset_acquisition_release_authority_unavailable');
          return incompleteResult(input.runId, 'incomplete', [...limitations]);
        }
        const policyDigest = digestJson(assetPolicy);
        let issued;
        try {
          issued = await awaitAbortableHostCallback(input.assetAcquisitionReleaseAuthorityFor, [input.request,
            Object.freeze({
              runId: input.runId,
              policy: assetPolicy,
              policyDigest,
              deadlineAtMonotonic,
            })], controller.signal, abortError);
        } catch {
          limitations.add('asset_acquisition_release_authority_unavailable');
          return incompleteResult(input.runId, 'incomplete', [...limitations]);
        }
        if (!isPrivateAssetReleaseController(issued)
          || !privateAssetReleaseControllerMatches(issued, {
            runId: input.runId,
            policyDigest,
            deadlineAtMonotonic,
          })) {
          limitations.add('asset_acquisition_release_authority_unavailable');
          return incompleteResult(input.runId, 'incomplete', [...limitations]);
        }
        assetReleaseController = issued;
        assetReleaseAuthority = privateAssetReleaseAuthorityForController(issued);
        if (!assetReleaseAuthority) {
          revokePrivateAssetReleaseController(issued, 'invalid_host_capability');
          limitations.add('asset_acquisition_release_authority_unavailable');
          return incompleteResult(input.runId, 'incomplete', [...limitations]);
        }
      }
    }
    scope = await awaitOperation(() => input.frontier.scopeForAuthenticatedRequest(input.request));
    evidenceScope = await awaitOperation(() => input.evidenceStore.scopeForAuthenticatedRequest(input.request));
    const initial = await awaitOperation(() => {
      const creating = input.frontier.createRun(scope, {
        runId: input.runId,
        seeds: input.seeds,
        limits: input.limits,
        ...(assetPolicy ? { privateRunConfigHash: runConfigHash } : {}),
      }, controller.signal);
      void Promise.resolve(creating).then(() => {
        runCreated = true;
        if (controller.signal.aborted) persistStop(stopCause === 'deadline' ? 'deadline' : 'cancelled');
      }, () => {});
      return creating;
    });
    const maxSuggestionsPerCompletion = initial.limits?.maxSuggestionsPerCompletion;
    if (!Number.isSafeInteger(maxSuggestionsPerCompletion)
      || maxSuggestionsPerCompletion < 1 || maxSuggestionsPerCompletion > 16) {
      throw new RetrievalError('FRONTIER_UNAVAILABLE');
    }
    if (!Number.isSafeInteger(initial.deadlineAtMs)) throw new RetrievalError('FRONTIER_UNAVAILABLE');
    deadlineAtMonotonic = Math.min(deadlineAtMonotonic,
      performance.now() + Math.max(0, initial.deadlineAtMs - Date.now()));
    armDeadline();
    runCreated = true;
    if (controller.signal.aborted) persistStop(stopCause === 'deadline' ? 'deadline' : 'cancelled');

    watcherOpen = true;
    watcherPromise = (async () => {
      while (watcherOpen) {
        await new Promise((resolve) => setTimeout(resolve, 25));
        if (!watcherOpen) break;
        try {
          const snapshot = await awaitOperation(() => input.frontier.getSnapshot(scope, input.runId, controller.signal));
          if (snapshotHasBlockingStop(snapshot)) {
            const blocking = snapshot.stopReasons.find((entry) => CANCELLATION_REASONS.has(entry.reason));
            if (blocking) abortForStop(blocking.reason);
            break;
          }
        } catch {
          if (controller.signal.aborted) break;
          runFailure = 'frontier_unavailable';
          beginCleanupEnvelope();
          if (!controller.signal.aborted) controller.abort();
          break;
        }
      }
    })();

    const readActiveSnapshot = async () => {
      checkDeadline();
      const snapshot = await awaitOperation(() => input.frontier.getSnapshot(scope, input.runId, controller.signal));
      if (snapshotHasBlockingStop(snapshot)) {
        const blocking = snapshot.stopReasons.find((entry) => CANCELLATION_REASONS.has(entry.reason));
        if (blocking) abortForStop(blocking.reason);
        throw abortError();
      }
      return snapshot;
    };

    const rememberVerifiedCompletion = async (candidateId, receipt) => {
      let binding;
      let snapshot;
      try {
        binding = await awaitOperation(() => input.frontier.getCandidateReceiptBinding(
          scope, input.runId, candidateId, controller.signal,
        ));
        snapshot = await readActiveSnapshot();
      } catch (error) {
        return { valid: false, unavailable: true, error };
      }
      const truncatedCount = receipt.truncatedCount ?? 0;
      if (!binding || binding.claim.candidateId !== candidateId || binding.claim.state !== 'completed'
        || binding.claim.claimKey !== receipt.claim.claimKey
        || binding.claim.workerId !== receipt.claim.workerId
        || binding.claim.leaseToken !== receipt.claim.leaseToken
        || !projectionSnapshotReferencesMatch(snapshot, input.seeds)
        || binding.completion?.completionKey !== receipt.completionKey
        || binding.completion?.outcome !== receipt.outcome
        || !completionPayloadMatches(receipt, snapshot, candidateId, binding.completion, truncatedCount)) {
        return { valid: false, unavailable: false };
      }
      verifiedCompletionProofs.set(candidateId, {
        completionKey: receipt.completionKey,
        claim: {
          claimKey: receipt.claim.claimKey,
          workerId: receipt.claim.workerId,
          leaseToken: receipt.claim.leaseToken,
        },
        legacyReceipt: receipt.omissionMetadataVersion !== 1,
        receipt: {
          candidate: receipt.candidate,
          outcome: receipt.outcome,
          suggestions: receipt.suggestions,
          assetSuggestions: receipt.assetSuggestions ?? [],
          evidenceIds: receipt.evidenceIds ?? [],
          truncatedCount,
        },
      });
      return { valid: true, snapshot };
    };

    const verifyProjectionObservationStream = async (snapshot) => {
      const candidatesById = new Map(snapshot.candidates.map((candidate) => [candidate.candidateId, candidate]));
      const parents = new Set(verifiedCompletionProofs.keys());
      const hasLegacyReceipt = [...verifiedCompletionProofs.values()].some((proof) => proof.legacyReceipt);
      if (!projectionSnapshotReferencesMatch(snapshot, input.seeds)) {
        return { valid: false, unavailable: false, legacy: hasLegacyReceipt };
      }
      for (const observation of snapshot.observations) {
        if (observation.kind !== 'link') continue;
        const parentCandidateId = observation.parentCandidateId;
        const parent = candidatesById.get(parentCandidateId);
        const proof = verifiedCompletionProofs.get(parentCandidateId);
        if (!parent || parent.state !== 'completed' || !proof) {
          return { valid: false, unavailable: false, legacy: hasLegacyReceipt };
        }
        parents.add(parentCandidateId);
      }
      for (const parentCandidateId of parents) {
        const proof = verifiedCompletionProofs.get(parentCandidateId);
        const parent = candidatesById.get(parentCandidateId);
        if (!parent || parent.state !== 'completed' || parent.completionOutcome !== proof.receipt.outcome) {
          return { valid: false, unavailable: false, legacy: hasLegacyReceipt };
        }
        let binding;
        try {
          binding = await awaitOperation(() => input.frontier.getCandidateReceiptBinding(
            scope, input.runId, parentCandidateId, controller.signal,
          ));
        } catch (error) {
          return { valid: false, unavailable: true, legacy: hasLegacyReceipt, error };
        }
        if (!binding || binding.claim.candidateId !== parentCandidateId || binding.claim.state !== 'completed'
          || binding.claim.claimKey !== proof.claim.claimKey
          || binding.claim.workerId !== proof.claim.workerId
          || binding.claim.leaseToken !== proof.claim.leaseToken
          || binding.completion?.completionKey !== proof.completionKey
          || binding.completion?.outcome !== proof.receipt.outcome
          || !completionPayloadMatches(proof.receipt, snapshot, parentCandidateId,
            binding.completion, proof.receipt.truncatedCount)) {
          return { valid: false, unavailable: false, legacy: hasLegacyReceipt };
        }
      }
      return { valid: true };
    };

    const retainReceipt = (receipt) => {
      for (const evidenceId of receipt.evidenceIds) evidenceIds.add(evidenceId);
      for (const fact of receipt.facts) outputFacts.set(fact.factId, fact);
      omittedLinkCandidates.push(...(receipt.omittedSuggestions ?? []));
      truncatedSuggestionCount += receipt.truncatedCount ?? receipt.omittedSuggestions?.length ?? 0;
      if (receipt.omissionMetadataVersion === 1) {
        sourceLinkCandidateOmittedCountLowerBound += receipt.sourceLinkCandidatesOmittedCount;
      } else if (receipt.limitations.includes('some_link_candidates_omitted_by_policy_or_parser_limit')) {
        // Historical v1 bodies retained that at least one link was omitted, but not the count.
        sourceLinkCandidateOmittedCountLowerBound += 1;
        sourceLinkCandidateOmittedCountComplete = false;
      }
      for (const limitation of receipt.limitations) limitations.add(limitation);
      const identity = receipt.identity;
      if (identity.entityCandidates.length > 0 || identity.occurrenceCandidates.length > 0
        || identity.transitionLinks.length > 0 || identity.unresolvedTransitions.length > 0) {
        candidateResults.push(identity);
      }
    };

    const recoverDurableReceipts = async () => {
      const snapshot = await readActiveSnapshot();
      const durableCandidates = snapshot.candidates.filter((candidate) =>
        candidate.state === 'completed' || candidate.state === 'leased');
      for (const candidate of durableCandidates) {
        if (!authorized(input, 'candidate')) {
          limitations.add('authorization_revoked');
          runFailure = 'authorization_revoked';
          return;
        }
        let frontierBinding;
        try {
          frontierBinding = await awaitOperation(() => input.frontier.getCandidateReceiptBinding(
            scope, input.runId, candidate.candidateId, controller.signal,
          ));
        } catch (error) {
          limitations.add(limitationFor(stopCause === 'deadline' ? 'DEADLINE_EXCEEDED' : safeFailureCode(error)));
          limitations.add('private_receipt_unavailable');
          runFailure = 'private_receipt_unavailable';
          return;
        }
        const expectedClaimState = candidate.state === 'completed' ? 'completed' : 'leased';
        if (!frontierBinding || frontierBinding.claim.candidateId !== candidate.candidateId
          || frontierBinding.claim.state !== expectedClaimState
          || (frontierBinding.bindingVersion === 1 && !frontierBinding.candidate)) {
          limitations.add('private_receipt_claim_mismatch');
          runFailure = 'private_receipt_unavailable';
          return;
        }
        const expectedCandidate = frontierBinding.candidate ?? candidate;
        const expectedAssetBinding = findAssetBindingForCandidate(expectedCandidate, snapshot,
          verifiedCompletionProofs, assetPolicy);
        if (expectedAssetBinding) {
          assetCandidateIds.add(candidate.candidateId);
          if (!await openCurrentAssetSource(expectedAssetBinding)) {
            limitations.add('asset_source_candidate_reopen_failed');
            if (candidate.state === 'leased' && frontierBinding.claim.state === 'leased') {
              try {
                await awaitOperation(() => input.frontier.markUnresolved(scope, input.runId, {
                  leaseToken: frontierBinding.claim.leaseToken,
                  reason: candidate.admittedAttemptCount > 0
                    ? 'dispatch_state_unknown' : 'cancelled_before_dispatch',
                }, controller.signal));
              } catch { /* The active lease remains conservative when resolution is unavailable. */ }
            } else {
              runFailure = 'private_receipt_unavailable';
            }
            return;
          }
        }
        let receipt;
        try {
          receipt = await awaitOperation(() => input.evidenceStore.readPrivateRunReceipt(evidenceScope, {
            runId: input.runId,
            configHash: runConfigHash,
            candidate: receiptCandidate(expectedCandidate, frontierBinding.bindingVersion === 1, expectedAssetBinding),
          }, input.request, controller.signal));
        } catch (error) {
          const code = stopCause === 'deadline' ? 'DEADLINE_EXCEEDED' : safeFailureCode(error);
          limitations.add(limitationFor(code));
          limitations.add('private_receipt_unavailable');
          runFailure = 'private_receipt_unavailable';
          return;
        }
        if (receipt.state !== 'complete') {
          limitations.add(`private_receipt_${receipt.state}`);
          if (candidate.state === 'leased' && receipt.state !== 'mismatch'
            && frontierBinding.claim.state === 'leased') {
            const reason = candidate.admittedAttemptCount > 0
              ? 'dispatch_state_unknown' : 'cancelled_before_dispatch';
            limitations.add(reason);
            try {
              const priorClaim = await awaitOperation(() => input.frontier.claimNext(scope, input.runId, {
                workerId: frontierBinding.claim.workerId,
                claimKey: frontierBinding.claim.claimKey,
              }, controller.signal));
              if (priorClaim.state === 'claimed'
                && priorClaim.leaseToken === frontierBinding.claim.leaseToken
                && priorClaim.candidate.candidateId === candidate.candidateId) {
                await awaitOperation(() => input.frontier.markUnresolved(scope, input.runId, {
                  leaseToken: frontierBinding.claim.leaseToken,
                  reason,
                }, controller.signal));
              }
            } catch {
              // Keep the explicit uncertainty even if the durable lease cannot be resolved now.
            }
          }
          runFailure = 'private_receipt_unavailable';
          return;
        }
        if (receipt.claim.claimKey !== frontierBinding.claim.claimKey
          || receipt.claim.workerId !== frontierBinding.claim.workerId
          || receipt.claim.leaseToken !== frontierBinding.claim.leaseToken) {
          limitations.add('private_receipt_claim_mismatch');
          runFailure = 'private_receipt_unavailable';
          return;
        }
        let replayReceipt = receipt;
        if (candidate.state === 'completed') {
          if (receipt.omissionMetadataVersion === 1) {
            const completionObservationsForReceipt = completionObservations(snapshot, candidate.candidateId);
            if (!observationsMatchSuggestions(completionObservationsForReceipt, receipt.suggestions, receipt.outcome)) {
              limitations.add('private_receipt_mismatch');
              runFailure = 'private_receipt_unavailable';
              return;
            }
            if (!completionPayloadMatches(receipt, snapshot, candidate.candidateId,
              frontierBinding.completion, receipt.truncatedCount)) {
              limitations.add('private_receipt_completion_mismatch');
              runFailure = 'private_receipt_unavailable';
              return;
            }
          } else {
            const reconstructed = reconstructCompletedLegacyReceipt(receipt, snapshot, candidate.candidateId,
              frontierBinding.completion, maxSuggestionsPerCompletion);
            if (!reconstructed) {
              limitations.add('legacy_receipt_fanout_recovery_unverified');
              limitations.add('private_receipt_completion_mismatch');
              runFailure = 'private_receipt_unavailable';
              return;
            }
            replayReceipt = reconstructed;
          }
        } else if (candidate.state === 'leased') {
          if (receipt.omissionMetadataVersion === 1 && receipt.suggestions.length > maxSuggestionsPerCompletion) {
            limitations.add('private_receipt_completion_mismatch');
            runFailure = 'private_receipt_unavailable';
            return;
          }
          const bounded = boundCompletionSuggestions(receipt.suggestions, maxSuggestionsPerCompletion);
          if (receipt.omissionMetadataVersion === 1 && bounded.omittedSuggestions.length > 0) {
            limitations.add('private_receipt_completion_mismatch');
            runFailure = 'private_receipt_unavailable';
            return;
          }
          replayReceipt = {
            ...receipt,
            suggestions: bounded.suggestions,
            truncatedCount: (receipt.truncatedCount ?? 0) + bounded.omittedSuggestions.length,
            omittedSuggestions: [...(receipt.omittedSuggestions ?? []), ...bounded.omittedSuggestions],
            sourceLinkCandidatesOmittedCount: receipt.sourceLinkCandidatesOmittedCount ?? 0,
          };
        }
        if (candidate.state === 'completed'
          && (candidate.completionOutcome !== receipt.outcome
            || !frontierBinding.completion
            || frontierBinding.completion.completionKey !== receipt.completionKey
            || frontierBinding.completion.outcome !== receipt.outcome)) {
          limitations.add('private_receipt_completion_mismatch');
          runFailure = 'private_receipt_unavailable';
          return;
        }
        if (candidate.state === 'leased' && frontierBinding.completion !== null) {
          limitations.add('private_receipt_completion_mismatch');
          runFailure = 'private_receipt_unavailable';
          return;
        }
        if (candidate.state === 'leased') {
          const priorClaim = await awaitOperation(() => input.frontier.claimNext(scope, input.runId, {
            workerId: receipt.claim.workerId,
            claimKey: receipt.claim.claimKey,
          }, controller.signal));
          if (priorClaim.state !== 'claimed' && priorClaim.state !== 'completed') {
            limitations.add('private_receipt_completion_unavailable');
            runFailure = 'private_receipt_unavailable';
            return;
          }
          if (priorClaim.leaseToken !== receipt.claim.leaseToken || priorClaim.candidate.candidateId !== candidate.candidateId) {
            limitations.add('private_receipt_claim_mismatch');
            runFailure = 'private_receipt_unavailable';
            return;
          }
          if (priorClaim.state === 'claimed') {
            await awaitOperation(() => input.frontier.completeCandidate(scope, input.runId, {
              leaseToken: replayReceipt.claim.leaseToken,
              completionKey: replayReceipt.completionKey,
              outcome: replayReceipt.outcome,
              suggestions: replayReceipt.suggestions,
              truncatedCount: replayReceipt.truncatedCount ?? 0,
            }, controller.signal));
          } else {
            const completedBinding = await awaitOperation(() => input.frontier.getCandidateReceiptBinding(
              scope, input.runId, candidate.candidateId, controller.signal,
            ));
            const completedSnapshot = await awaitOperation(() => input.frontier.getSnapshot(
              scope, input.runId, controller.signal,
            ));
            if (!completedBinding || completedBinding.claim.state !== 'completed'
              || completedBinding.claim.claimKey !== receipt.claim.claimKey
              || completedBinding.claim.workerId !== receipt.claim.workerId
              || completedBinding.claim.leaseToken !== receipt.claim.leaseToken
              || completedBinding.completion?.completionKey !== receipt.completionKey
              || completedBinding.completion?.outcome !== replayReceipt.outcome
              || !completionPayloadMatches(replayReceipt, completedSnapshot, candidate.candidateId,
                completedBinding.completion, replayReceipt.truncatedCount ?? 0)) {
              limitations.add('private_receipt_completion_mismatch');
              runFailure = 'private_receipt_unavailable';
              return;
            }
          }
        }
        const proof = await rememberVerifiedCompletion(candidate.candidateId, replayReceipt);
        if (!proof.valid) {
          if (proof.unavailable) limitations.add('private_receipt_unavailable');
          else limitations.add('private_receipt_completion_mismatch');
          if (!proof.unavailable && receipt.omissionMetadataVersion !== 1) {
            limitations.add('legacy_receipt_fanout_recovery_unverified');
          }
          runFailure = 'private_receipt_unavailable';
          return;
        }
        retainReceipt(replayReceipt);
        if (replayReceipt.candidate.assetAcquisition) await rememberAcquiredAssetPlan(replayReceipt);
      }
    };

    await recoverDurableReceipts();
    if (!runFailure) {
      const recoveredSnapshot = await readActiveSnapshot();
      const streamProof = await verifyProjectionObservationStream(recoveredSnapshot);
      if (!streamProof.valid) {
        limitations.add(streamProof.unavailable ? 'private_receipt_unavailable' : 'private_receipt_completion_mismatch');
        if (streamProof.legacy) limitations.add('legacy_receipt_fanout_recovery_unverified');
        runFailure = 'private_receipt_unavailable';
      }
    }

    const processClaim = async (claim, claimProgress) => {
      const candidate = claim.candidate;
      const priorLimitations = new Set(limitations);
      const candidateEvidenceIds = new Set();
      const candidateFacts = [];
      let selectedSourceLinkCandidatesOmittedCount = 0;
      const claimBinding = Object.freeze({
        claimKey: claim.claimKey,
        workerId: claim.workerId,
        leaseToken: claim.leaseToken,
      });
      const completionKey = `complete:${claim.leaseToken}:${randomUUID()}`;
      const frontierBinding = await awaitOperation(() => input.frontier.getCandidateReceiptBinding(
        scope, input.runId, candidate.candidateId, controller.signal,
      ));
      if (!frontierBinding || frontierBinding.bindingVersion !== 1 || !frontierBinding.candidate
        || frontierBinding.claim.state !== 'leased'
        || frontierBinding.claim.claimKey !== claim.claimKey
        || frontierBinding.claim.workerId !== claim.workerId
        || frontierBinding.claim.leaseToken !== claim.leaseToken
        || frontierBinding.claim.candidateId !== candidate.candidateId
        || frontierBinding.candidate.candidateId !== candidate.candidateId
        || frontierBinding.candidate.canonicalUrl !== candidate.canonicalUrl
        || frontierBinding.candidate.depth !== candidate.depth) throw new RetrievalError('TRANSPORT_FAILURE');
      if (typeof frontierBinding.candidate.suppliedUrl !== 'string' || urlHasSensitiveMaterial(frontierBinding.candidate.suppliedUrl)) {
        throw new PrivateRetrievalError('INVALID_INPUT');
      }
      let assetBinding;
      const candidateSnapshot = await readActiveSnapshot();
      assetBinding = findAssetBindingForCandidate(frontierBinding.candidate, candidateSnapshot,
        verifiedCompletionProofs, assetPolicy);
      let assetSourceEvidenceHandle;
      if (assetBinding) {
        assetCandidateIds.add(candidate.candidateId);
        const source = await openCurrentAssetSource(assetBinding);
        if (!source) {
          limitations.add('asset_source_candidate_reopen_failed');
          await awaitOperation(() => input.frontier.markUnresolved(scope, input.runId, {
            leaseToken: claim.leaseToken,
            reason: candidate.admittedAttemptCount > 0 ? 'dispatch_state_unknown' : 'cancelled_before_dispatch',
          }, controller.signal));
          return;
        }
        assetSourceEvidenceHandle = source.handle;
        candidateEvidenceIds.add(assetBinding.sourceEvidenceId);
      }
      const candidateBinding = receiptCandidate(frontierBinding.candidate, true, assetBinding);
      const receiptBinding = Object.freeze({
        runId: input.runId,
        configHash: runConfigHash,
        candidate: candidateBinding,
      });
      const suppliedUrl = frontierBinding.candidate.suppliedUrl;
      if (!authorized(input, 'candidate')) {
        abortForStop('access_restricted');
        persistStop('access_restricted');
        throw new RetrievalError('POLICY_DENIED');
      }
      const pendingReceipt = await awaitOperation(() => input.evidenceStore.beginPrivateRunReceipt(evidenceScope, {
        ...receiptBinding,
        claim: claimBinding,
      }, input.request, controller.signal));
      if (pendingReceipt.state !== 'pending' || pendingReceipt.created !== true) {
        const reason = candidate.admittedAttemptCount > 0
          ? 'dispatch_state_unknown' : 'cancelled_before_dispatch';
        limitations.add(pendingReceipt.state === 'pending'
          ? 'private_receipt_pending' : 'private_receipt_already_exists');
        limitations.add(reason);
        await awaitOperation(() => input.frontier.markUnresolved(scope, input.runId, {
          leaseToken: claim.leaseToken,
          reason,
        }, controller.signal));
        return;
      }
      const hopRecords = [];
      let previousAttemptKey;
      let completeDocument;
      let selectedOutcome = 'failed';
      let selectedSuggestions = [];
      let assetSuggestionBindings = [];
      let selectedResult;
      let pdfRecord;
      let assetRecord;
      let assetCompletion;
      let failure = null;
      const stateForHop = (index) => hopRecords[index];
      const checkNoBlockingStop = async () => {
        checkDeadline();
        const current = await awaitOperation(() => input.frontier.getSnapshot(scope, input.runId, controller.signal));
        if (snapshotHasBlockingStop(current)) {
          const blocking = current.stopReasons.find((entry) => CANCELLATION_REASONS.has(entry.reason));
          if (blocking) abortForStop(blocking.reason);
          throw abortError();
        }
      };
      const hooks = {
        async beforeHop({ url, hopIndex }) {
          if (urlHasSensitiveMaterial(url)) throw new RetrievalError('POLICY_DENIED');
          if (assetBinding && (hopIndex !== 0 || url !== assetBinding.assetUrl
            || !await currentAssetPolicyMatches())) throw new RetrievalError('POLICY_DENIED');
          await checkNoBlockingStop();
          const attemptKey = `hop:${claim.leaseToken}:${hopIndex}:${randomUUID()}`;
          let admissionOperationStarted = false;
          let admission;
          try {
            admission = await awaitOperation(() => {
              admissionOperationStarted = true;
              return input.frontier.admitTransportHop(scope, input.runId, {
                leaseToken: claim.leaseToken,
                attemptKey,
                kind: hopIndex === 0 ? 'initial' : 'redirect',
                ...(hopIndex > 0 ? { previousAttemptKey } : {}),
                url,
              }, controller.signal);
            });
          } catch (error) {
            // The abort can win the await race after SQLite committed the
            // admission. Keep the lease classification conservative when the
            // operation started but its result could not be observed.
            if (admissionOperationStarted && controller.signal.aborted) {
              claimProgress.admissionMayHaveBeenPersisted = true;
            }
            throw error;
          }
          if (admission.state === 'admitted' || admission.state === 'already_admitted'
            || admission.state === 'already_admitted_without_transport_state') {
            claimProgress.admissionMayHaveBeenPersisted = true;
          }
          if (admission.state === 'denied') {
            if (admission.reason === 'decoded_budget') {
              abortForStop('budget_denied');
              persistStop('budget_denied');
              limitations.add('decoded_response_budget_exhausted');
              throw new RetrievalError('RESOURCE_LIMIT');
            }
            if (admission.reason === 'attempt_limit') {
              limitations.add('transport_attempt_limit');
              throw new RetrievalError('REQUEST_LIMIT');
            }
            throw new RetrievalError('CANCELED');
          }
          if (admission.state !== 'admitted') {
            // A historical admission is state inspection, never authorization to fetch again.
            limitations.add('transport_state_unknown');
            throw new RetrievalError('CANCELED');
          }
          const record = { attemptKey, url, state: 'reserved', decodeStarted: false, bodyComplete: false };
          hopRecords[hopIndex] = record;
          activeHops.set(attemptKey, record);
          previousAttemptKey = attemptKey;
          await checkNoBlockingStop();
        },
        async onDispatchIntent({ hopIndex }) {
          const record = stateForHop(hopIndex);
          if (!record) throw new RetrievalError('CANCELED');
          if (assetBinding && !await currentAssetPolicyMatches()) throw new RetrievalError('POLICY_DENIED');
          await checkNoBlockingStop();
          await awaitOperation(() => input.frontier.markTransportDispatchIntent(scope, input.runId, {
            leaseToken: claim.leaseToken, attemptKey: record.attemptKey,
          }, controller.signal));
          record.state = 'dispatch_intent';
          await checkNoBlockingStop();
        },
        async onResponseHeaders({ hopIndex }) {
          const record = stateForHop(hopIndex);
          if (!record) throw new RetrievalError('CANCELED');
          await checkNoBlockingStop();
          await awaitOperation(() => input.frontier.markTransportResponseReceived(scope, input.runId, {
            leaseToken: claim.leaseToken, attemptKey: record.attemptKey,
          }, controller.signal));
          record.state = 'response_received';
        },
        async onKnownZero({ hopIndex }) {
          const record = stateForHop(hopIndex);
          if (!record || record.decodeStarted || record.bodyComplete) return;
          await awaitOperation(() => input.frontier.settleTransportHopKnownZero(scope, input.runId, {
            leaseToken: claim.leaseToken, attemptKey: record.attemptKey,
          }, controller.signal));
          record.state = 'known_zero';
          activeHops.delete(record.attemptKey);
        },
        async onDecodeStart({ hopIndex }) {
          const record = stateForHop(hopIndex);
          if (!record) throw new RetrievalError('CANCELED');
          record.decodeStarted = true;
        },
        async onBodyComplete({ hopIndex, decodedBytes }) {
          const record = stateForHop(hopIndex);
          if (!record || !record.decodeStarted || record.bodyComplete) throw new RetrievalError('TRANSPORT_FAILURE');
          await awaitOperation(() => input.frontier.settleTransportHopBodyComplete(scope, input.runId, {
            leaseToken: claim.leaseToken, attemptKey: record.attemptKey,
          }, decodedBytes, controller.signal));
          record.bodyComplete = true;
          record.state = 'body_complete';
          activeHops.delete(record.attemptKey);
        },
      };
      try {
        checkDeadline();
        const fetchRemainingMs = Math.floor(deadlineAtMonotonic - performance.now());
        if (fetchRemainingMs < 1) {
          triggerDeadline();
          throw abortError();
        }
        completeDocument = await runWithSafeFetchLifecycle(input.safeFetcher, hooks, {
          decodedTextBytesPerResponse: TEXT_ACCEPTED_BYTES,
          decodedMediaBytesPerResponse: MEDIA_ACCEPTED_BYTES,
          gzipChunkSize: GZIP_CHUNK_BYTES,
          gzipReadableHighWaterMark: GZIP_CHUNK_BYTES,
          gzipWritableHighWaterMark: GZIP_CHUNK_BYTES,
          totalMilliseconds: Math.min(30_000, fetchRemainingMs),
        }, () => assetBinding
          ? SafeFetcher.prototype.fetchSvgAsset.call(input.safeFetcher, suppliedUrl, { signal: controller.signal })
          : SafeFetcher.prototype.fetch.call(input.safeFetcher, suppliedUrl, { signal: controller.signal }));
        const provenance = safeFetchProvenance(completeDocument);
        if (!validateProvenance(completeDocument, provenance, assetBinding?.assetUrl ?? candidate.canonicalUrl, hopRecords,
          assetBinding ? 'svg-asset' : 'document')) {
          limitations.add('transport_provenance_unavailable');
          throw new RetrievalError('TRANSPORT_FAILURE');
        }
        if (assetBinding) {
          await checkNoBlockingStop();
          if (!await currentAssetPolicyMatches()) throw new RetrievalError('POLICY_DENIED');
          const inspection = inspectSafeAssetBytes(completeDocument.bytes, {
            contentType: 'image/svg+xml', signal: controller.signal,
          });
          try {
            if (inspection.action !== 'transformed' || inspection.policyVersion !== SAFE_ASSET_POLICY_VERSION
              || inspection.sourceHash !== hashBytes(completeDocument.bytes)) {
              limitations.add(inspection.action === 'review'
                ? 'asset_inspection_review_required' : 'asset_inspection_rejected');
              selectedOutcome = 'failed';
            } else {
              const transformedBytes = inspection.copyTransformedBytes();
              try {
                if (!inspection.matchesTransformedBytes(transformedBytes)
                  || hashBytes(transformedBytes) !== inspection.transformedHash
                  || transformedBytes.byteLength > SAFE_ASSET_LIMITS.maxTransformedBytes) {
                  limitations.add('asset_inspection_rejected');
                  selectedOutcome = 'failed';
                } else {
                  const retentionHandle = await awaitAbortableHostCallback(input.retentionHandleFor, [input.request,
                    Object.freeze({
                      runId: input.runId,
                      sourceUrl: assetBinding.assetUrl,
                      canonicalUrl: assetBinding.assetUrl,
                      representation: 'controlled-asset-bytes',
                      sourceEvidenceId: assetBinding.sourceEvidenceId,
                      sourceEvidenceVersion: assetBinding.sourceEvidenceVersion,
                      sourceContentHash: assetBinding.sourceContentHash,
                    })], controller.signal, abortError);
                  await checkNoBlockingStop();
                  if (!retentionHandle || typeof retentionHandle !== 'object') throw new RetrievalError('POLICY_DENIED');
                  const verifyDurableAttempt = async () => {
                    if (controller.signal.aborted || !await currentAssetPolicyMatches()) return false;
                    const currentSnapshot = await readActiveSnapshot();
                    const currentCandidate = currentSnapshot.candidates.find((entry) => entry.candidateId === candidate.candidateId);
                    const currentAttempts = currentSnapshot.attempts.filter((entry) => entry.candidateId === candidate.candidateId);
                    if (!currentCandidate || currentCandidate.state !== 'leased' || currentCandidate.seed
                      || currentCandidate.admittedAttemptCount !== 1 || currentAttempts.length !== 1
                      || currentAttempts[0].attemptKey !== hopRecords[0]?.attemptKey
                      || currentAttempts[0].kind !== 'initial' || currentAttempts[0].canonicalUrl !== candidate.canonicalUrl
                      || hopRecords.length !== 1 || hopRecords[0].state !== 'body_complete'
                      || hopRecords[0].url !== assetBinding.assetUrl) return false;
                    const currentBinding = await awaitOperation(() => input.frontier.getCandidateReceiptBinding(
                      scope, input.runId, candidate.candidateId, controller.signal,
                    ));
                    if (!currentBinding || currentBinding.claim.state !== 'leased'
                      || currentBinding.claim.leaseToken !== claim.leaseToken
                      || currentBinding.claim.claimKey !== claim.claimKey
                      || currentBinding.candidate?.candidateId !== candidate.candidateId
                      || currentBinding.candidate?.canonicalUrl !== candidate.canonicalUrl
                      || currentBinding.candidate?.seed !== false
                      || currentBinding.candidate?.suppliedUrl !== assetBinding.assetUrl) return false;
                    const pending = await awaitOperation(() => input.evidenceStore.readPrivateRunReceipt(
                      evidenceScope, receiptBinding, input.request, controller.signal,
                    ));
                    return pending.state === 'pending'
                      && JSON.stringify(pending.candidate) === JSON.stringify(candidateBinding)
                      && pending.claim.leaseToken === claim.leaseToken
                      && pending.claim.claimKey === claim.claimKey;
                  };
                  const provenanceForRole = (role) => Object.freeze({
                    schemaVersion: assetBinding.schemaVersion,
                    policyVersion: assetBinding.policyVersion,
                    policyId: assetBinding.policyId,
                    role,
                    inspectionPolicyVersion: SAFE_ASSET_POLICY_VERSION,
                    sourceEvidenceId: assetBinding.sourceEvidenceId,
                    sourceEvidenceVersion: assetBinding.sourceEvidenceVersion,
                    sourceContentHash: assetBinding.sourceContentHash,
                    sourceDerivationDigest: assetBinding.sourceDerivationDigest,
                    sourceUrl: assetBinding.sourceUrl,
                    candidateId: assetBinding.candidateId,
                    positionIndex: assetBinding.positionIndex,
                    sourceForm: assetBinding.sourceForm,
                    sourceLocator: assetBinding.sourceLocator,
                    excerptHash: assetBinding.excerptHash,
                    field: assetBinding.field,
                    value: assetBinding.value,
                    assetUrl: assetBinding.assetUrl,
                    sourceBytesHash: inspection.sourceHash,
                    transformedBytesHash: inspection.transformedHash,
                  });
                  const commonIngest = {
                    document: completeDocument,
                    retentionHandle,
                    retentionCeiling: {
                      evidence: assetSourceEvidenceHandle,
                      version: assetBinding.sourceEvidenceVersion,
                      contentHash: assetBinding.sourceContentHash,
                    },
                  };
                  let originalStored;
                  let transformedStored;
                  try {
                    const originalProvenance = provenanceForRole('fetched-source');
                    const originalWitness = createControlledSvgIngestWitness(
                      completeDocument, originalProvenance, async () => verifyDurableAttempt(),
                    );
                    if (!originalWitness) throw new RetrievalError('TRANSPORT_FAILURE');
                    originalStored = await awaitOperation(() => input.controlledAssetEvidenceStore.ingestControlledAssetEvidence(
                      evidenceScope, { ...commonIngest, provenance: originalProvenance, witness: originalWitness },
                      input.request, controller.signal,
                    ));
                    const transformedProvenance = provenanceForRole('transformed');
                    const transformedWitness = createControlledSvgIngestWitness(
                      completeDocument, transformedProvenance, async () => verifyDurableAttempt(),
                    );
                    if (!transformedWitness) throw new RetrievalError('TRANSPORT_FAILURE');
                    transformedStored = await awaitOperation(() => input.controlledAssetEvidenceStore.ingestControlledAssetEvidence(
                      evidenceScope, { ...commonIngest, provenance: transformedProvenance, witness: transformedWitness },
                      input.request, controller.signal,
                    ));
                    if (originalStored?.outcome !== 'stored' || transformedStored?.outcome !== 'stored') {
                      throw new RetrievalError('TRANSPORT_FAILURE');
                    }
                    if (!await currentAssetPolicyMatches()) throw new RetrievalError('POLICY_DENIED');
                    await checkNoBlockingStop();
                    const originalEvidence = Object.freeze({
                      evidenceId: originalStored.metadata.evidenceId,
                      version: originalStored.metadata.version,
                      contentHash: originalStored.metadata.contentHash,
                      byteLength: completeDocument.bytes.byteLength,
                    });
                    const transformedEvidence = Object.freeze({
                      evidenceId: transformedStored.metadata.evidenceId,
                      version: transformedStored.metadata.version,
                      contentHash: transformedStored.metadata.contentHash,
                      byteLength: transformedBytes.byteLength,
                    });
                    if (originalEvidence.contentHash !== inspection.sourceHash
                      || transformedEvidence.contentHash !== inspection.transformedHash) {
                      throw new RetrievalError('TRANSPORT_FAILURE');
                    }
                    assetCompletion = Object.freeze({
                      schemaVersion: 1,
                      policyVersion: assetBinding.policyVersion,
                      inspectionPolicyVersion: inspection.policyVersion,
                      binding: assetBinding,
                      sourceBytesHash: inspection.sourceHash,
                      transformedBytesHash: inspection.transformedHash,
                      originalEvidence,
                      transformedEvidence,
                    });
                    candidateEvidenceIds.add(originalEvidence.evidenceId);
                    candidateEvidenceIds.add(transformedEvidence.evidenceId);
                    selectedOutcome = 'no_links';
                  } catch (error) {
                    if (controller.signal.aborted) throw error;
                    if (error?.code === 'POLICY_DENIED') throw error;
                    limitations.add('asset_evidence_storage_failed');
                    assetCompletion = undefined;
                    selectedOutcome = 'failed';
                  }
                }
              } finally {
                transformedBytes.fill(0);
              }
            }
          } finally {
            inspection.dispose?.();
          }
        } else if (completeDocument.contentType === 'application/pdf') {
          const retentionHandle = await awaitAbortableHostCallback(input.retentionHandleFor, [input.request, Object.freeze({
            runId: input.runId, sourceUrl: suppliedUrl, canonicalUrl: completeDocument.url,
          })], controller.signal, abortError);
          await checkNoBlockingStop();
          if (!retentionHandle || typeof retentionHandle !== 'object') throw new RetrievalError('POLICY_DENIED');
          const stored = await awaitOperation(() => input.evidenceStore.ingestDerivedPdfEvidence(evidenceScope, {
            sourceUrl: suppliedUrl,
            canonicalUrl: provenance.finalUrl,
            redirectChain: provenance.redirectChain,
            content: completeDocument.bytes,
            contentType: completeDocument.contentType,
            retrievedAt: completeDocument.fetchedAt,
            sourceKind: 'external',
            retentionHandle,
          }, input.request, controller.signal));
          if (stored.outcome === 'stored') {
            pdfRecord = { evidenceId: stored.metadata.evidenceId, role: 'pdf' };
          } else {
            limitations.add(stored.outcome === 'no-text' ? 'pdf_requires_inspection' : 'pdf_derivation_incomplete');
          }
          limitations.add('pdf_identity_extraction_not_supported');
          selectedOutcome = 'no_links';
        } else if (completeDocument.contentType.startsWith('image/')) {
          limitations.add('asset_bytes_not_inspected_or_promoted');
          selectedOutcome = 'failed';
        } else {
          const retentionHandle = await awaitAbortableHostCallback(input.retentionHandleFor, [input.request, Object.freeze({
            runId: input.runId, sourceUrl: suppliedUrl, canonicalUrl: provenance.finalUrl,
          })], controller.signal, abortError);
          await checkNoBlockingStop();
          if (!retentionHandle || typeof retentionHandle !== 'object') throw new RetrievalError('POLICY_DENIED');
          const trustedDocument = Object.freeze({
            url: provenance.finalUrl,
            requestedUrl: suppliedUrl,
            redirectChain: provenance.redirectChain,
            contentType: completeDocument.contentType,
            fetchedAt: completeDocument.fetchedAt,
            redirects: completeDocument.redirects,
            bytes: completeDocument.bytes,
          });
          selectedResult = await awaitOperation(() => composeSourceIdentity({
            sources: [{ document: trustedDocument, retentionHandle }],
            request: input.request,
            evidenceStore: input.evidenceStore,
            signal: controller.signal,
          }));
          const composedSource = selectedResult.sources[0];
          if (composedSource?.evidence?.evidenceId) {
            candidateEvidenceIds.add(composedSource.evidence.evidenceId);
          }
          if (selectedResult.facts.length + outputFacts.size > MAX_SELECTED_FACTS) {
            limitations.add('selected_fact_limit');
            abortForStop('budget_denied');
            persistStop('budget_denied');
            throw new RetrievalError('RESOURCE_LIMIT');
          }
          candidateFacts.push(...selectedResult.facts);
          selectedSuggestions = selectedResult.linkCandidates.map((link) => ({
            url: link.url,
            sourceRefs: [{
              evidenceId: link.sourceRef.evidenceId,
              contentHash: link.sourceRef.contentHash,
              locator: link.sourceRef.locator,
              field: link.sourceRef.field,
              value: link.url,
            }],
          }));
          selectedSourceLinkCandidatesOmittedCount = selectedResult.linkCandidatesOmitted;
          if (selectedSourceLinkCandidatesOmittedCount > 0) {
            limitations.add('some_link_candidates_omitted_by_policy_or_parser_limit');
          }
          const extraction = composedSource?.extraction;
          if (extraction?.jsRequired === true) limitations.add('dynamic_rendering_required');
          if (extraction?.status === 'PARTIAL' && extraction?.termination !== null) limitations.add('extraction_incomplete');
          if (selectedSuggestions.length > 0) selectedOutcome = 'links_observed';
          else selectedOutcome = 'no_links';
          if (composedSource?.evidence?.evidenceId && composedSource?.extraction?.assetSources?.length > 0) {
            if (completeDocument.redirects !== 0) {
              limitations.add('asset_source_evidence_requires_redirect_free_source');
            } else if (evidenceIds.size < MAX_SELECTED_EVIDENCE) {
              const assetHandle = await awaitAbortableHostCallback(input.retentionHandleFor, [input.request, Object.freeze({
                runId: input.runId, sourceUrl: suppliedUrl, canonicalUrl: provenance.finalUrl, representation: 'asset-source-excerpt',
              })], controller.signal, abortError);
              await checkNoBlockingStop();
              if (!assetHandle || typeof assetHandle !== 'object') throw new RetrievalError('POLICY_DENIED');
              const asset = await awaitOperation(() => input.evidenceStore.ingestAssetSourceEvidence(evidenceScope, {
                document: {
                  url: suppliedUrl,
                  contentType: completeDocument.contentType,
                  bytes: completeDocument.bytes,
                  fetchedAt: completeDocument.fetchedAt,
                  redirects: 0,
                },
                retentionHandle: assetHandle,
              }, input.request, controller.signal));
              if (asset.outcome === 'stored') {
                assetRecord = { evidenceId: asset.metadata.evidenceId, role: 'asset-source-excerpt' };
                candidateEvidenceIds.add(asset.metadata.evidenceId);
            if (assetPolicy && input.limits.maxDepth > candidate.depth
              && selectedSuggestions.length < maxSuggestionsPerCompletion
              && await currentAssetPolicyMatches()) {
              const materializedAssetSource = await awaitOperation(() => input.evidenceStore.materializeSelected(
                evidenceScope, { evidence: [asset.evidence], facts: [] }, input.request, controller.signal,
              ));
              const storedAssetSource = materializedAssetSource.evidence.length === 1
                && materializedAssetSource.facts.length === 0 ? materializedAssetSource.evidence[0] : null;
              const assetCandidates = storedAssetSource?.source?.assetSource?.candidates ?? [];
              const currentSnapshot = await readActiveSnapshot();
              const occupiedUrls = new Set([
                ...input.seeds.map((seed) => {
                  try { return parseAndValidateUrl(seed.url).url.href; } catch { return null; }
                }),
                ...currentSnapshot.candidates.map((entry) => entry.canonicalUrl),
                ...selectedSuggestions.map((suggestion) => suggestion.url),
              ].filter((url) => typeof url === 'string'));
              for (const sourceCandidate of assetCandidates) {
                if (selectedSuggestions.length >= maxSuggestionsPerCompletion) break;
                if (sourceCandidate.quarantineReason !== null || typeof sourceCandidate.fetchSuggestion !== 'string'
                  || occupiedUrls.has(sourceCandidate.fetchSuggestion)
                  || assetSuggestionBindings.some((binding) => binding.assetUrl === sourceCandidate.fetchSuggestion)
                  || !assetPolicyAllowsUrl(assetPolicy, sourceCandidate.fetchSuggestion)) continue;
                const stored = await awaitOperation(() => input.assetSourceBindingStore.readAssetSourceCandidateBinding(
                  evidenceScope, asset.evidence, sourceCandidate.candidateId, input.request, controller.signal,
                ));
                const binding = assetBindingFromStoredCandidate(assetPolicy, stored, sourceCandidate.candidateId);
                if (!binding || binding.sourceEvidenceId !== asset.metadata.evidenceId
                  || binding.sourceEvidenceVersion !== asset.metadata.version
                  || binding.sourceContentHash !== asset.metadata.contentHash
                  || binding.sourceDerivationDigest !== asset.metadata.derivationDigest
                  || occupiedUrls.has(binding.assetUrl)) continue;
                selectedSuggestions.push({
                  url: binding.assetUrl,
                  sourceRefs: [assetSuggestionSourceRef(binding)],
                });
                assetSuggestionBindings.push(binding);
                occupiedUrls.add(binding.assetUrl);
              }
              if (assetSuggestionBindings.length > 0) selectedOutcome = 'links_observed';
            }
              } else {
                limitations.add(`asset_source_${asset.code.toLowerCase()}`);
              }
            } else {
              limitations.add('asset_source_selection_limit');
            }
          }
        }
      } catch (error) {
        failure = error;
        const code = stopCause === 'deadline' ? 'DEADLINE_EXCEEDED' : safeFailureCode(error);
        limitations.add(limitationFor(code));
        if (code === 'DEADLINE_EXCEEDED') {
          triggerDeadline();
        }
        if (code === 'POLICY_DENIED' && !controller.signal.aborted) {
          abortForStop('access_restricted');
          persistStop('access_restricted');
        }
      } finally {
        if (completeDocument?.bytes && ArrayBuffer.isView(completeDocument.bytes)) completeDocument.bytes.fill(0);
        for (const record of hopRecords) {
          if (!record || !activeHops.has(record.attemptKey)) continue;
          try {
            if (record.state === 'reserved') {
              // The beforeHop hook did not complete, so no DNS/socket/body path began.
              if (controller.signal.aborted) {
                await awaitRunCleanup((signal) => input.frontier.settleTransportHopKnownZero(scope, input.runId, {
                  leaseToken: claim.leaseToken, attemptKey: record.attemptKey,
                }, signal));
              } else {
                await awaitOperation(() => input.frontier.settleTransportHopKnownZero(scope, input.runId, {
                  leaseToken: claim.leaseToken, attemptKey: record.attemptKey,
                }, controller.signal));
              }
            } else if (record.state === 'dispatch_intent' || record.state === 'response_received') {
              if (controller.signal.aborted) {
                await awaitRunCleanup((signal) => input.frontier.markTransportHopUnknown(scope, input.runId, {
                  leaseToken: claim.leaseToken, attemptKey: record.attemptKey,
                }, signal));
              } else {
                await awaitOperation(() => input.frontier.markTransportHopUnknown(scope, input.runId, {
                  leaseToken: claim.leaseToken, attemptKey: record.attemptKey,
                }, controller.signal));
              }
            }
          } catch { /* Persisted full reservation remains conservative when settlement cannot be proven. */ }
          activeHops.delete(record.attemptKey);
        }
      }

      if (controller.signal.aborted) {
        const hasAdmissions = claimProgress.admissionMayHaveBeenPersisted
          || candidate.admittedAttemptCount > 0 || hopRecords.length > 0;
        await awaitRunCleanup((signal) => input.frontier.markUnresolved(scope, input.runId, {
          leaseToken: claim.leaseToken,
          reason: hasAdmissions ? 'dispatch_state_unknown' : 'cancelled_before_dispatch',
        }, signal), stopPersistenceStarted ? PRE_STOP_UNRESOLVED_CLEANUP_MS : ABORTABLE_CLEANUP_MS);
        throw abortError();
      }

      if (failure && !completeDocument && failure.code === 'REQUEST_LIMIT' && candidate.admittedAttemptCount === 0) {
        // The durable run limit already records this stop. Leave the lease unresolved rather than invent a completion.
        limitations.add('candidate_not_dispatched_before_attempt_limit');
        return;
      }

      const outcome = failure
        ? (failure.code === 'POLICY_DENIED' ? 'access_restricted' : 'failed')
        : selectedOutcome;
      if (pdfRecord) candidateEvidenceIds.add(pdfRecord.evidenceId);
      if (assetRecord) candidateEvidenceIds.add(assetRecord.evidenceId);
      if (candidateEvidenceIds.size > MAX_SELECTED_EVIDENCE || candidateFacts.length > MAX_SELECTED_FACTS) {
        limitations.add('candidate_receipt_selection_limit');
        throw new RetrievalError('RESOURCE_LIMIT');
      }
      const candidateIdentity = selectedResult?.sources[0]?.evidence?.evidenceId
        ? Object.freeze({
          entityCandidates: selectedResult.entityCandidates,
          occurrenceCandidates: selectedResult.occurrenceCandidates,
          transitionLinks: selectedResult.transitionLinks,
          unresolvedTransitions: selectedResult.unresolvedTransitions,
        })
        : emptyIdentityResult();
      const candidateSuggestions = failure ? [] : selectedSuggestions;
      const boundedSuggestions = boundCompletionSuggestions(candidateSuggestions, maxSuggestionsPerCompletion);
      const acceptedSuggestions = boundedSuggestions.suggestions;
      const acceptedAssetSuggestions = failure ? [] : assetSuggestionBindings.filter((binding) =>
        acceptedSuggestions.some((suggestion) => suggestion.url === binding.assetUrl
          && suggestion.sourceRefs.some((reference) => sameSourceReference(reference, assetSuggestionSourceRef(binding)))));
      const omittedSuggestions = boundedSuggestions.omittedSuggestions;
      const truncatedCount = omittedSuggestions.length;
      const candidateSourceLinkCandidatesOmittedCount = failure ? 0 : selectedSourceLinkCandidatesOmittedCount;
      if (truncatedCount > 0) limitations.add('completion_suggestion_limit');
      const evidenceHandles = [];
      for (const evidenceId of candidateEvidenceIds) {
        evidenceHandles.push(await awaitOperation(() => input.evidenceStore.lookupEvidence(evidenceScope, evidenceId, controller.signal)));
      }
      const factHandles = [];
      for (const fact of candidateFacts) {
        factHandles.push(await awaitOperation(() => input.evidenceStore.lookupFact(evidenceScope, fact.factId, controller.signal)));
      }
      const candidateLimitations = [...limitations].filter((value) => !priorLimitations.has(value));
      await awaitOperation(() => input.evidenceStore.finalizePrivateRunReceipt(evidenceScope, {
        ...receiptBinding,
        claim: claimBinding,
        completion: {
          completionKey,
          outcome,
          suggestions: acceptedSuggestions,
          truncatedCount,
          omittedSuggestions,
          sourceLinkCandidatesOmittedCount: candidateSourceLinkCandidatesOmittedCount,
          limitations: candidateLimitations,
          identity: candidateIdentity,
          ...(acceptedAssetSuggestions.length > 0 ? { assetSuggestions: acceptedAssetSuggestions } : {}),
          ...(assetCompletion ? { assetAcquisition: assetCompletion } : {}),
        },
        selection: { evidence: evidenceHandles, facts: factHandles },
      }, input.request, controller.signal));
      for (const evidenceId of candidateEvidenceIds) evidenceIds.add(evidenceId);
      for (const fact of candidateFacts) outputFacts.set(fact.factId, fact);
      omittedLinkCandidates.push(...omittedSuggestions);
      truncatedSuggestionCount += truncatedCount;
      sourceLinkCandidateOmittedCountLowerBound += candidateSourceLinkCandidatesOmittedCount;
      if (selectedResult?.sources[0]?.evidence?.evidenceId) candidateResults.push(candidateIdentity);
      await awaitOperation(() => input.frontier.completeCandidate(scope, input.runId, {
        leaseToken: claim.leaseToken,
        completionKey,
        outcome,
        suggestions: acceptedSuggestions,
        truncatedCount,
      }, controller.signal));
      let persistedReceipt;
      try {
        persistedReceipt = await awaitOperation(() => input.evidenceStore.readPrivateRunReceipt(
          evidenceScope, receiptBinding, input.request, controller.signal,
        ));
      } catch (error) {
        limitations.add(limitationFor(stopCause === 'deadline' ? 'DEADLINE_EXCEEDED' : safeFailureCode(error)));
        limitations.add('private_receipt_unavailable');
        runFailure = 'private_receipt_unavailable';
        return;
      }
      const proof = persistedReceipt.state === 'complete'
        ? await rememberVerifiedCompletion(candidate.candidateId, persistedReceipt)
        : { valid: false, unavailable: false };
      if (!proof.valid) {
        limitations.add(proof.unavailable ? 'private_receipt_unavailable' : 'private_receipt_completion_mismatch');
        if (!proof.unavailable && persistedReceipt.omissionMetadataVersion !== 1) {
          limitations.add('legacy_receipt_fanout_recovery_unverified');
        }
        runFailure = 'private_receipt_unavailable';
      } else if (persistedReceipt.candidate.assetAcquisition) {
        await rememberAcquiredAssetPlan(persistedReceipt);
      }
    };

    while (!controller.signal.aborted && !runFailure) {
      const current = await readActiveSnapshot();
      stopLimitation(current, limitations);
      if (current.state !== 'active' && current.stopReason !== 'attempt_limit') break;
      if (evidenceIds.size >= MAX_SELECTED_EVIDENCE) {
        limitations.add('selected_evidence_limit');
        break;
      }
      if (!authorized(input, 'candidate')) {
        abortForStop('access_restricted');
        persistStop('access_restricted');
        limitations.add('authorization_revoked');
        break;
      }
      const claim = await awaitOperation(() => input.frontier.claimNext(scope, input.runId, {
        workerId: input.workerId,
        claimKey: `claim:${input.workerId}:${randomUUID()}`,
      }, controller.signal));
      if (claim.state === 'claimed') {
        if (claim.replayed) {
          // A restart may observe old durable claims. Their lease never grants redispatch.
          limitations.add('prior_claim_not_replayed');
          await awaitOperation(() => input.frontier.markUnresolved(scope, input.runId, {
            leaseToken: claim.leaseToken,
            reason: claim.candidate.admittedAttemptCount > 0 ? 'dispatch_state_unknown' : 'cancelled_before_dispatch',
          }, controller.signal));
          continue;
        }
        const claimProgress = {
          admissionMayHaveBeenPersisted: claim.candidate.admittedAttemptCount > 0,
        };
        try { await processClaim(claim, claimProgress); }
        catch (error) {
          const code = stopCause === 'deadline' ? 'DEADLINE_EXCEEDED' : safeFailureCode(error);
          limitations.add(limitationFor(code));
          if (code === 'CANCELED' || code === 'DEADLINE_EXCEEDED' || controller.signal.aborted) {
            // The deadline stop and a second unresolved write can contend for
            // the same SQLite writer lock. Let the separately bounded stop
            // attempt finish first, then spend only the remaining shared
            // cleanup budget on one recovery write.
            const stopSettled = await awaitStopPersistence();
            if (stopSettled) {
              await awaitRunCleanup((signal) => input.frontier.markUnresolved(scope, input.runId, {
                leaseToken: claim.leaseToken,
                reason: claimProgress.admissionMayHaveBeenPersisted
                  ? 'dispatch_state_unknown' : 'cancelled_before_dispatch',
              }, signal));
            }
            break;
          }
          if (code === 'INVALID_INPUT') {
            runFailure = 'invalid_frontier_candidate';
            break;
          }
        }
        continue;
      }
      if (claim.state === 'waiting') {
        limitations.add(claim.reason === 'in_flight_limit' ? 'other_worker_in_flight' : 'frontier_waiting');
      } else if (claim.state === 'stopped' && claim.reason === 'attempt_limit') {
        limitations.add('transport_attempt_limit');
      } else if (claim.state === 'stopped' && !['frontier_exhausted', 'depth_limit', 'fanout_limit'].includes(claim.reason)) {
        limitations.add('frontier_stopped');
      }
      break;
    }

    await awaitOperation(() => localStopPromise);
    const finalSnapshot = await awaitOperation(() => input.frontier.getSnapshot(scope, input.runId, controller.signal));
    stopLimitation(finalSnapshot, limitations);
    if (externalAbort || snapshotHasBlockingStop(finalSnapshot) || controller.signal.aborted) {
      if (stopCause === 'deadline') return incompleteWithProgress(input.runId, finalSnapshot, [...limitations, 'deadline_exceeded']);
      return incompleteResult(input.runId, 'cancelled', [...limitations, 'cancelled']);
    }
    const finalStreamProof = await verifyProjectionObservationStream(finalSnapshot);
    if (!finalStreamProof.valid) {
      limitations.add(finalStreamProof.unavailable ? 'private_receipt_unavailable' : 'private_receipt_completion_mismatch');
      if (finalStreamProof.legacy) limitations.add('legacy_receipt_fanout_recovery_unverified');
      runFailure = 'private_receipt_unavailable';
    }
    if (runFailure) return incompleteResult(input.runId, 'incomplete', [...limitations, runFailure]);
    const transport = await awaitOperation(() => input.frontier.getTransportProgress(scope, input.runId, controller.signal));
    const hasLeased = finalSnapshot.candidates.some((candidate) => candidate.state === 'leased');
    if (transport.reservedBytes > 0 || hasLeased || finalSnapshot.candidates.some((candidate) => candidate.state === 'unresolved')) {
      limitations.add('transport_state_unknown_or_unresolved_work');
      return incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
    }
    if (evidenceIds.size === 0) {
      checkDeadline();
      if (controller.signal.aborted) throw abortError();
      if (!authorized(input, 'release')) {
        limitations.add('authorization_revoked');
        return incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
      }
      checkDeadline();
      if (controller.signal.aborted) throw abortError();
      if (assetPolicy && !privateAssetReleaseControllerMatches(assetReleaseController, {
        runId: input.runId, policyDigest: digestJson(assetPolicy), deadlineAtMonotonic,
      })) {
        limitations.add('asset_acquisition_release_authority_unavailable');
        return incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
      }
      const sourceAuthorityReview = composeNoSourceAuthorityReview(
        [...limitations], finalSnapshot.stopReasons.map((entry) => entry.reason),
      );
      checkDeadline();
      if (controller.signal.aborted) throw abortError();
      const incomplete = incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
      return sourceAuthorityReview ? Object.freeze({ ...incomplete, sourceAuthorityReview }) : incomplete;
    }
    if (evidenceIds.size > MAX_SELECTED_EVIDENCE || outputFacts.size > MAX_SELECTED_FACTS) {
      limitations.add('selected_materialization_limit');
      return incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
    }
    let identity;
    try { identity = aggregateIdentity(candidateResults); }
    catch {
      limitations.add('aggregate_identity_limit');
      return incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
    }
    const evidenceHandles = [];
    for (const evidenceId of evidenceIds) {
      evidenceHandles.push(await awaitOperation(() => input.evidenceStore.lookupEvidence(evidenceScope, evidenceId, controller.signal)));
    }
    const factHandles = [];
    for (const factId of outputFacts.keys()) {
      factHandles.push(await awaitOperation(() => input.evidenceStore.lookupFact(evidenceScope, factId, controller.signal)));
    }
    await awaitOperation(() => localStopPromise);
    checkDeadline();
    watcherOpen = false;
    await awaitOperation(() => watcherPromise);
    watcherDrained = true;
    const release = await awaitOperation(() => input.frontier.sealPrivateDraft(scope, input.runId, controller.signal));
    if (release.state !== 'sealed' && release.state !== 'already_sealed') {
      limitations.add(release.reason === 'transport_uncertain' ? 'transport_state_unknown_or_unresolved_work' : 'release_seal_denied');
      return incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
    }
    if (!authorized(input, 'release')) {
      limitations.add('authorization_revoked');
      return incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
    }
    const materialized = await awaitOperation(() => input.evidenceStore.materializeSelected(evidenceScope, {
      evidence: evidenceHandles,
      facts: factHandles,
    }, input.request, controller.signal));
    checkDeadline();
    if (controller.signal.aborted || !authorized(input, 'release')) {
      limitations.add(controller.signal.aborted ? 'cancelled' : 'authorization_revoked');
      return incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
    }
    const actualFacts = new Map(materialized.facts.map((fact) => [fact.factId, fact]));
    if (actualFacts.size !== outputFacts.size || materialized.evidence.length < evidenceIds.size
      || [...outputFacts].some(([factId, fact]) => factFingerprint(actualFacts.get(factId) ?? {}) !== factFingerprint(fact))) {
      limitations.add('final_selected_snapshot_mismatch');
      return incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
    }
    const actualEvidence = new Set(materialized.evidence.map((item) => item.metadata.evidenceId));
    if ([...evidenceIds].some((id) => !actualEvidence.has(id))) {
      limitations.add('final_selected_snapshot_mismatch');
      return incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
    }
    // Plans are cached while processing durable receipts. Reopen each source
    // candidate and both role-separated encrypted asset records after final
    // materialization, then bind the result to the selected source snapshot.
    // This adds no transport work and shares the run's completed frontier.
    for (const [candidateId, receipt] of [...assetAcquisitionReceipts]) {
      let current = false;
      try { current = await rememberAcquiredAssetPlan(receipt); }
      catch { current = false; }
      const plan = assetAcquisitionResults.find((entry) => entry.candidate.frontierCandidateId === candidateId);
      const source = plan && materialized.evidence.find((item) => item.metadata.evidenceId === plan.sourceEvidence.evidenceId);
      const sourceCandidateMatches = source
        && source.metadata.version === plan.sourceEvidence.version
        && source.metadata.contentHash === plan.sourceEvidence.contentHash
        && source.metadata.derivationDigest === plan.sourceEvidence.derivationDigest
        && source.source.assetSource?.candidates?.filter((candidate) =>
          candidate.candidateId === plan.candidate.assetSourceCandidateId
          && candidate.field === plan.candidate.field
          && candidate.excerptHash === plan.candidate.excerptHash
          && candidate.fetchSuggestion === plan.candidate.assetUrl).length === 1;
      if (!current || !plan || !sourceCandidateMatches) {
        forgetAcquiredAssetPlan(candidateId);
        limitations.add('asset_acquisition_final_revalidation_failed');
      }
    }
    const sourceLinkCandidateOmittedCount = sourceLinkCandidateOmittedCountComplete
      ? sourceLinkCandidateOmittedCountLowerBound : null;
    let finalEvidence = materialized.evidence;
    if (assetPolicy) {
      const assetGroups = assetAcquisitionResults.map((result) =>
        assetReleaseRoleReferences.get(result.candidate.frontierCandidateId)).filter(Boolean);
      if (assetGroups.length !== assetAcquisitionResults.length) {
        for (const candidateId of [...assetAcquisitionReceipts.keys()]) forgetAcquiredAssetPlan(candidateId);
        limitations.add('asset_acquisition_reopen_unavailable');
      }
      const revalidationInput = {
        runId: input.runId,
        policyDigest: digestJson(assetPolicy),
        releaseController: assetReleaseController,
        evidence: materialized.evidence.map((item) => ({ handle: item.handle, metadata: item.metadata })),
        facts: factHandles,
        assetGroups,
        beforeFinalization: async () => {
          if (!await currentAssetPolicyMatches()) {
            for (const candidateId of [...assetAcquisitionReceipts.keys()]) forgetAcquiredAssetPlan(candidateId);
            limitations.add('asset_acquisition_policy_changed');
            return [];
          }
          return assetAcquisitionResults.map((entry) => entry.candidate.frontierCandidateId);
        },
        finalizeHostAuthority: () => {
          checkDeadline();
          if (controller.signal.aborted) return { releaseAuthorized: false, candidateIds: [] };
          if (!authorized(input, 'release')) return { releaseAuthorized: false, candidateIds: [] };
          if (assetAcquisitionResults.length > 0 && !authorized(input, 'asset-acquisition')) {
            for (const candidateId of [...assetAcquisitionReceipts.keys()]) forgetAcquiredAssetPlan(candidateId);
            limitations.add('authorization_revoked');
          }
          checkDeadline();
          return {
            releaseAuthorized: true,
            candidateIds: assetAcquisitionResults.map((entry) => entry.candidate.frontierCandidateId),
          };
        },
      };
      let preparation;
      try {
        preparation = await awaitControlledAssetPreparation(
          () => input.controlledAssetEvidenceStore.revalidateControlledAssetRelease(
            evidenceScope, revalidationInput, input.request, controller.signal,
          ),
          controller.signal,
          abortError,
          (lateValue) => {
            revokeAssetReleaseAuthority('late_asset_release_preparation');
            discardAssetReleasePreparation(lateValue);
          },
        );
      } catch (error) {
        revokeAssetReleaseAuthority('asset_release_preparation_failed');
        throw error;
      }
      let revalidated = null;
      try {
        if (!utilTypes.isProxy(preparation.value)) {
          const copied = plainDataRecord(preparation.value, new Set(['releaseCheck', 'candidateIds']));
          const candidateIds = copied && ownArray(copied.candidateIds, 8);
          if (copied && candidateIds && copied.releaseCheck && typeof copied.releaseCheck === 'object') {
            revalidated = Object.freeze({ releaseCheck: copied.releaseCheck, candidateIds: Object.freeze(candidateIds) });
          }
        }
      } catch { /* malformed adapter result fails closed below */ }
      if (!revalidated) {
        revokeAssetReleaseAuthority('invalid_asset_release_preparation');
        discardAssetReleasePreparation(preparation.value);
        throw new RetrievalError('EVIDENCE_INVALID');
      }

      try {
        checkDeadline();
        if (controller.signal.aborted) throw abortError();
      } catch (error) {
        revokeAssetReleaseAuthority('asset_release_preparation_expired');
        discardAssetReleaseCheck(revalidated.releaseCheck);
        throw error;
      }

      const activeCandidateIds = new Set(revalidated.candidateIds);
      for (const candidateId of [...assetAcquisitionReceipts.keys()]) {
        if (!activeCandidateIds.has(candidateId)) forgetAcquiredAssetPlan(candidateId);
      }
      const finalized = input.assetReleaseFinalizationStore.finalizeControlledAssetRelease(
        evidenceScope,
        revalidated.releaseCheck,
        input.request,
        controller.signal,
        {
          releaseController: assetReleaseController,
          runId: input.runId,
          policyDigest: digestJson(assetPolicy),
          deadlineAtMonotonic,
          candidateIds: revalidated.candidateIds,
          project: ({ currentEvidenceMetadata }) => {
            checkDeadline();
            if (controller.signal.aborted) throw abortError();
            const currentMetadata = new Map(currentEvidenceMetadata.map((metadata) => [metadata.evidenceId, metadata]));
            finalEvidence = materialized.evidence.map((item) => {
              const metadata = currentMetadata.get(item.metadata.evidenceId);
              if (!metadata) throw new RetrievalError('final_selected_snapshot_mismatch');
              return Object.freeze({ ...item, metadata });
            });
            return projection(identity, finalEvidence, materialized.facts, finalSnapshot, limitations,
              omittedLinkCandidates, truncatedSuggestionCount, sourceLinkCandidateOmittedCount,
              sourceLinkCandidateOmittedCountLowerBound, sourceLinkCandidateOmittedCountComplete,
              assetCandidateIds, assetAcquisitionResults, deadlineAtMonotonic, controller.signal);
          },
        },
      );
      if (hasThenableBehavior(finalized)) {
        revokeAssetReleaseAuthority('asynchronous_asset_projection_denied');
        discardAssetReleaseCheck(revalidated.releaseCheck);
        throw new RetrievalError('EVIDENCE_INVALID');
      }
      return finalized;
    }
    checkDeadline();
    if (controller.signal.aborted) {
      limitations.add('cancelled');
      return incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
    }
    if (!authorized(input, 'release')) {
      limitations.add('authorization_revoked');
      return incompleteWithProgress(input.runId, finalSnapshot, [...limitations]);
    }
    const draft = projection(identity, finalEvidence, materialized.facts, finalSnapshot, limitations,
      omittedLinkCandidates, truncatedSuggestionCount, sourceLinkCandidateOmittedCount,
      sourceLinkCandidateOmittedCountLowerBound, sourceLinkCandidateOmittedCountComplete,
      assetCandidateIds, assetAcquisitionResults, deadlineAtMonotonic, controller.signal);
    return draft;
  } catch (error) {
    const code = stopCause === 'deadline' ? 'DEADLINE_EXCEEDED' : safeFailureCode(error);
    limitations.add(limitationFor(code));
    if (code === 'DEADLINE_EXCEEDED') {
      triggerDeadline();
      await awaitStopPersistence();
      return incompleteResult(input.runId, 'incomplete', [...limitations, 'deadline_exceeded']);
    }
    if (code === 'CANCELED' || externalAbort) return incompleteResult(input.runId, 'cancelled', [...limitations, 'cancelled']);
    return incompleteResult(input.runId, 'incomplete', [...limitations]);
  } finally {
    for (const [abortStop, stopDeadlineAt] of stopCleanupCallbacks) {
      if (performance.now() >= stopDeadlineAt) abortStop();
    }
    if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
    watcherOpen = false;
    if (!watcherDrained) void watcherPromise.catch(() => {});
    if (input.signal !== undefined) removeAbortListener(input.signal, onExternalAbort);
  }
}

function incompleteResult(runId, status, limitations) {
  return Object.freeze({
    schema: PRIVATE_DRAFT_SCHEMA,
    runId,
    status,
    completeness: 'incomplete',
    draft: null,
    limitations: Object.freeze([...new Set(limitations)].sort()),
  });
}

function incompleteWithProgress(runId, snapshot, limitations) {
  return Object.freeze({
    schema: PRIVATE_DRAFT_SCHEMA,
    runId,
    status: 'incomplete',
    completeness: 'incomplete',
    draft: null,
    limitations: Object.freeze([...new Set(limitations)].sort()),
    progress: Object.freeze({
      state: snapshot.state,
      stopReason: snapshot.stopReason,
      stopReasons: Object.freeze(snapshot.stopReasons.map((entry) => entry.reason)),
      completedCandidates: snapshot.candidates.filter((candidate) => candidate.state === 'completed').length,
      remainingCandidates: snapshot.candidates.filter((candidate) => candidate.state === 'queued' || candidate.state === 'leased').length,
      transportAttemptAdmissions: snapshot.counters.transportAttemptAdmissions,
    }),
  });
}
