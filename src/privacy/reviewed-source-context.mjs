import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { types as utilTypes } from 'node:util';
import { createEvidenceStore, EvidenceStoreError } from '../evidence/store.mjs';
import { extractDeterministically, EXTRACTION_LIMITS } from '../extraction/index.mjs';
import { isPrivacyBoundary, readDerivativeSourceAssociation } from './boundary.mjs';

export const REVIEWED_SOURCE_CONTEXT_SCHEMA = 'ei-private-reviewed-source-context/1';
const MAX_SOURCE_BYTES = 512 * 1024;
const MAX_CONTEXT_BYTES = 16 * 1024;
const MAX_RANGES = 32;
const MAX_NOTICES = 64;
const MAX_DEADLINE_MS = 12_000;
const SIGNAL_ABORTED = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const ADD_LISTENER = EventTarget.prototype.addEventListener;
const REMOVE_LISTENER = EventTarget.prototype.removeEventListener;
const NATIVE_THEN = Promise.prototype.then;
const MONOTONIC_NOW = performance.now.bind(performance);
const CODES = Object.freeze({
  INVALID_INPUT: 'Reviewed source context input is invalid',
  SOURCE_BINDING_DENIED: 'The private derivative source association is unavailable',
  SOURCE_MISMATCH: 'Retained evidence does not match the reviewed source',
  SOURCE_CONTEXT_INCOMPLETE: 'The complete source context is not retained',
  UNSUPPORTED_SOURCE: 'The retained source representation is unsupported',
  EXTRACTION_INCOMPLETE: 'Critical source notices could not be fully checked',
  REVIEW_REQUIRED: 'An explicit trusted source-context review is required',
  REVIEW_REJECTED: 'The trusted source-context review did not approve this context',
  REVIEW_INVALID: 'The source-context review is not bound to this source and purpose',
  CRITICAL_NOTICE_OMITTED: 'The reviewed context omits a detected critical notice',
  AUTHORITY_DENIED: 'Current private source-context authority was denied',
  EVIDENCE_DENIED: 'Retained evidence access was denied',
  EVIDENCE_EXPIRED: 'Retained source context has expired',
  EVIDENCE_UNAVAILABLE: 'Retained source context is unavailable',
  CONTEXT_REVOKED: 'The private source context was revoked',
  CANCELED: 'Source-context preparation was canceled',
  DEADLINE_EXCEEDED: 'Source-context preparation exceeded its original deadline',
  BUSY: 'This source-context adapter already has an active operation',
});

export class ReviewedSourceContextError extends Error {
  constructor(code = 'EVIDENCE_UNAVAILABLE') {
    const safeCode = typeof code === 'string' && Object.hasOwn(CODES, code) ? code : 'EVIDENCE_UNAVAILABLE';
    super(CODES[safeCode]);
    this.name = 'ReviewedSourceContextError';
    this.code = safeCode;
  }
}

function fail(code) { throw new ReviewedSourceContextError(code); }
function opaque() { return Object.freeze(Object.create(null)); }
function hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

function record(value, names) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string' || !names.includes(key))) return null;
    const copy = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
      copy[key] = descriptor.value;
    }
    return copy;
  } catch { return null; }
}

function array(value, maximum) {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
    const length = Object.getOwnPropertyDescriptor(value, 'length')?.value;
    if (!Number.isSafeInteger(length) || length < 0 || length > maximum
      || Reflect.ownKeys(value).length !== length + 1) return null;
    const copy = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
      copy.push(descriptor.value);
    }
    return copy;
  } catch { return null; }
}

function label(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,95}$/.test(value);
}

function observeNativePromise(value) {
  if (!utilTypes.isPromise(value)) return;
  // Discard both outcomes. Forwarding a settled fulfillment can assimilate a
  // then getter installed on that value later, creating a detached rejection.
  try { Reflect.apply(NATIVE_THEN, value, [() => {}, () => {}]); } catch { /* still refuse */ }
}

function safeError(error) {
  try {
    const code = error && Object.getOwnPropertyDescriptor(error, 'code')?.value;
    if (error instanceof ReviewedSourceContextError) return new ReviewedSourceContextError(code);
    if (error instanceof EvidenceStoreError) {
      if (code === 'EVIDENCE_DENIED') return new ReviewedSourceContextError('EVIDENCE_DENIED');
      if (code === 'EVIDENCE_EXPIRED') return new ReviewedSourceContextError('EVIDENCE_EXPIRED');
      if (code === 'EVIDENCE_CANCELLED') return new ReviewedSourceContextError('CANCELED');
    }
  } catch { /* thrown proxies and accessor-bearing errors never become diagnostics */ }
  return new ReviewedSourceContextError('EVIDENCE_UNAVAILABLE');
}

function sameSource(left, right) {
  return left.evidenceId === right.evidenceId && left.version === right.version
    && left.contentHash === right.contentHash && left.sourceUrl === right.sourceUrl
    && left.canonicalUrl === right.canonicalUrl && left.contentType === right.contentType
    && left.sourceKind === right.sourceKind && left.retrievedAt === right.retrievedAt
    && JSON.stringify(left.redirectChain) === JSON.stringify(right.redirectChain);
}

function exactText(bytes, startByte, endByte, code) {
  if (!Number.isSafeInteger(startByte) || !Number.isSafeInteger(endByte)
    || startByte < 0 || endByte <= startByte || endByte > bytes.length) fail(code);
  try {
    const selected = bytes.subarray(startByte, endByte);
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(selected);
    if (!Buffer.from(text, 'utf8').equals(selected)) fail(code);
    return text;
  } catch { fail(code); }
}

function noticesFromExtraction(extraction, bytes, expectedDigest) {
  if (!['PARTIAL', 'NO_ANSWER'].includes(extraction.status) || extraction.termination !== null
    || extraction.sourceHash !== `sha256:${expectedDigest}` || extraction.accessSignals.length > 0
    || extraction.diagnostics.some((item) => !['NO_EVENT_CANDIDATES', 'DUPLICATE_JSONLD_BLOCK'].includes(item.code))) {
    fail('EXTRACTION_INCOMPLETE');
  }
  const candidates = [...extraction.statusMentions];
  for (const entity of extraction.events) {
    candidates.push(...entity.candidates.filter((candidate) => candidate.field === 'eventStatus'));
  }
  if (candidates.length > MAX_NOTICES) fail('EXTRACTION_INCOMPLETE');
  const notices = new Map();
  for (const candidate of candidates) {
    const locator = candidate.source.locator;
    if (locator.kind !== 'text-range') fail('EXTRACTION_INCOMPLETE');
    const text = exactText(bytes, locator.startByte, locator.endByte, 'EXTRACTION_INCOMPLETE');
    if (text !== candidate.rawValue) fail('EXTRACTION_INCOMPLETE');
    notices.set(`${locator.startByte}:${locator.endByte}`, Object.freeze({
      kind: candidate.field === 'eventStatus' ? 'structured-event-status' : 'source-status-notice',
      startByte: locator.startByte,
      endByte: locator.endByte,
      text,
    }));
  }
  return Object.freeze([...notices.values()].sort((left, right) => left.startByte - right.startByte));
}

/**
 * Trusted composition root only. This creates the concrete EvidenceStore itself;
 * a request cannot provide a store-shaped result or a private payload callback.
 */
export function createReviewedSourceContext(options) {
  const config = record(options, ['boundary', 'evidenceStoreOptions', 'purpose', 'reviewContext',
    'authorizeContextCurrent', 'deadlineMs']);
  if (!config || !isPrivacyBoundary(config.boundary) || !label(config.purpose)
    || (config.reviewContext !== undefined && typeof config.reviewContext !== 'function')
    || (config.authorizeContextCurrent !== undefined && typeof config.authorizeContextCurrent !== 'function')) {
    throw new TypeError('trusted reviewed source-context configuration required');
  }
  const storeConfig = record(config.evidenceStoreOptions, ['directory', 'resolveTenant', 'resolveKey',
    'resolveRetention', 'authorizePrivateAccess', 'authorizePrivateAccessCurrent', 'now',
    'maxSourceBytes', 'maxPositionBytes', 'maxPositionCount', 'maxStoredPayloadBytes',
    'maxRetentionMs', 'lockTimeoutMs']);
  if (!storeConfig || typeof storeConfig.resolveTenant !== 'function'
    || typeof storeConfig.authorizePrivateAccess !== 'function'
    || typeof storeConfig.authorizePrivateAccessCurrent !== 'function') {
    throw new TypeError('concrete evidence store configuration and current authority required');
  }
  const deadlineMs = config.deadlineMs ?? MAX_DEADLINE_MS;
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > MAX_DEADLINE_MS) {
    throw new TypeError('bounded source-context deadline required');
  }
  const clock = storeConfig.now ?? Date.now;
  const boundary = config.boundary;
  const contexts = new WeakMap();
  const operations = new WeakMap();
  let active = null;

  function currentTime() {
    const time = clock();
    if (!Number.isSafeInteger(time) || time < 0) fail('EVIDENCE_UNAVAILABLE');
    return time;
  }

  function association(scope, derivative) {
    try { return readDerivativeSourceAssociation(boundary, scope, derivative); }
    catch { fail('SOURCE_BINDING_DENIED'); }
  }

  // This guard invokes no configured clock or association callback. Reuse the
  // original captured deadline after each trusted phase, without renewing it.
  function checkActive(op) {
    if (op.failure) throw op.failure;
    if (op.done || active !== op) fail('CANCELED');
    if (MONOTONIC_NOW() >= op.deadlineAt) fail('DEADLINE_EXCEEDED');
    if (op.entry?.revoked) fail('CONTEXT_REVOKED');
  }

  function check(op) {
    checkActive(op);
    if (op.binding && association(op.scope, op.derivative) !== op.binding) fail('SOURCE_BINDING_DENIED');
    checkActive(op);
    const time = currentTime();
    if (op.source && time >= op.source.expiresAtMs) fail('EVIDENCE_EXPIRED');
    // Both clocks and host callbacks may synchronously revoke/cancel.
    if (op.failure) throw op.failure;
    if (op.entry?.revoked) fail('CONTEXT_REVOKED');
    if (op.binding && SIGNAL_ABORTED.call(op.binding.signal)) fail('SOURCE_BINDING_DENIED');
    checkActive(op);
  }

  function authorizeCurrent(op) {
    check(op);
    if (typeof config.authorizeContextCurrent !== 'function') fail('AUTHORITY_DENIED');
    let result;
    try {
      result = config.authorizeContextCurrent(Object.freeze({
        tenantId: op.binding.tenantId,
        request: op.request,
        action: op.action,
        purpose: config.purpose,
        recordId: op.binding.recordId,
        sourceDigest: op.binding.sourceDigest,
        evidenceId: op.source.evidenceId,
      }));
    } catch { fail('AUTHORITY_DENIED'); }
    if (result !== true) {
      observeNativePromise(result);
      fail('AUTHORITY_DENIED');
    }
    check(op);
  }

  function stop(op, code) {
    if (op.done || op.failure) return;
    op.failure = new ReviewedSourceContextError(code);
    op.controller.abort();
  }

  function follow(op, signal, code) {
    if (signal === undefined) return;
    try { SIGNAL_ABORTED.call(signal); } catch { fail('INVALID_INPUT'); }
    const listener = () => stop(op, code);
    Reflect.apply(ADD_LISTENER, signal, ['abort', listener, { once: true }]);
    op.listeners.push([signal, listener]);
    if (SIGNAL_ABORTED.call(signal)) listener();
  }

  function wait(op, operation) {
    // The pending promise has rejection handlers before a callback can cancel
    // synchronously and return (or throw into) a rejecting promise.
    const pending = Promise.resolve().then(() => { check(op); return operation(); });
    return new Promise((resolve, reject) => {
      let settled = false;
      const cleanup = () => Reflect.apply(REMOVE_LISTENER, op.controller.signal, ['abort', onAbort]);
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (error) reject(error); else resolve(value);
      };
      const onAbort = () => finish(op.failure ?? new ReviewedSourceContextError('CANCELED'));
      pending.then((value) => {
        try { check(op); finish(null, value); } catch (error) { finish(error); }
      }, (error) => finish(error));
      Reflect.apply(ADD_LISTENER, op.controller.signal, ['abort', onAbort, { once: true }]);
      if (SIGNAL_ABORTED.call(op.controller.signal)) onAbort();
    });
  }

  function unwrap(request) { return operations.get(request)?.request ?? request; }

  function privatePayload(input) {
    const op = operations.get(input.request);
    if (!op || active !== op || op.done) fail('EVIDENCE_DENIED');
    let bytes;
    try {
      check(op);
      if (input.tenantId !== op.binding.tenantId || input.evidenceId !== input.metadata.evidenceId
        || input.source.contentHash !== op.binding.sourceDigest
        || input.metadata.contentHash !== op.binding.sourceDigest) fail('SOURCE_MISMATCH');
      if (input.metadata.representation !== undefined || input.source.derivedPdf !== undefined
        || input.source.assetSource !== undefined || input.source.controlledAsset !== undefined
        || !['text/html', 'application/xhtml+xml', 'text/plain', 'application/ld+json'].includes(
          input.source.contentType.split(';', 1)[0].trim().toLowerCase())
        || !['html', 'plain_text', 'ocr_text', 'pdf_text', 'pdf_metadata'].includes(op.binding.modality)) {
        fail('UNSUPPORTED_SOURCE');
      }
      const source = Object.freeze({
        evidenceId: input.evidenceId,
        version: input.metadata.version,
        contentHash: input.source.contentHash,
        sourceUrl: input.source.sourceUrl,
        canonicalUrl: input.source.canonicalUrl,
        redirectChain: Object.freeze([...input.source.redirectChain]),
        contentType: input.source.contentType,
        sourceKind: input.source.sourceKind,
        retrievedAt: input.source.retrievedAt,
        expiresAtMs: Date.parse(input.metadata.expiresAt),
      });
      if (!Number.isSafeInteger(source.expiresAtMs)) fail('EVIDENCE_UNAVAILABLE');
      if (op.source && !sameSource(op.source, source)) fail('SOURCE_MISMATCH');
      op.source = Object.freeze({ ...source,
        expiresAtMs: Math.min(op.source?.expiresAtMs ?? source.expiresAtMs, source.expiresAtMs),
      });
      authorizeCurrent(op);
      const positions = [...input.positions].sort((left, right) => left.locator.startByte - right.locator.startByte);
      if (positions.length === 0 || positions.length > 128) fail('SOURCE_CONTEXT_INCOMPLETE');
      let covered = 0;
      for (const position of positions) {
        const locator = position.locator;
        if (locator.kind !== 'text-range' || locator.startByte !== covered
          || !Number.isSafeInteger(locator.endByte) || locator.endByte <= covered
          || locator.endByte - locator.startByte !== position.content.byteLength
          || locator.endByte > MAX_SOURCE_BYTES || hash(position.content) !== position.contentHash) {
          fail('SOURCE_CONTEXT_INCOMPLETE');
        }
        covered = locator.endByte;
      }
      bytes = Buffer.concat(positions.map((position) => position.content), covered);
      if (hash(bytes) !== op.binding.sourceDigest) fail('SOURCE_CONTEXT_INCOMPLETE');
      authorizeCurrent(op);
      if (op.mode === 'capture') {
        op.bytes = bytes;
        bytes = undefined;
      } else if (op.mode !== 'verify') fail('EVIDENCE_DENIED');
      op.payloadSeen = true;
      return undefined;
    } catch (error) {
      op.failure = safeError(error);
      throw op.failure;
    } finally { bytes?.fill(0); }
  }

  const evidenceStore = createEvidenceStore({
    ...storeConfig,
    resolveTenant: (request) => storeConfig.resolveTenant(unwrap(request)),
    authorizePrivateAccess: (input) => storeConfig.authorizePrivateAccess(Object.freeze({
      ...input, request: unwrap(input.request),
    })),
    authorizePrivateAccessCurrent: (input) => storeConfig.authorizePrivateAccessCurrent(Object.freeze({
      ...input, request: unwrap(input.request),
    })),
    consumePrivatePayload: privatePayload,
  });

  function start(value, action) {
    if (active) fail('BUSY');
    const op = { action, controller: new AbortController(), listeners: [], done: false,
      failure: null, deadlineAt: MONOTONIC_NOW() + deadlineMs };
    active = op;
    try {
      const input = record(value, action === 'review_source_context'
        ? ['scope', 'derivative', 'evidence', 'request', 'signal'] : ['scope', 'context', 'request', 'signal']);
      if (!input || !Object.hasOwn(input, 'request') || !input.request
        || !['object', 'function'].includes(typeof input.request)) fail('INVALID_INPUT');
      op.scope = input.scope;
      op.request = input.request;
      op.entry = action === 'materialize_source_context' ? contexts.get(input.context) : null;
      if (action === 'materialize_source_context' && !op.entry) fail('INVALID_INPUT');
      op.derivative = op.entry?.derivative ?? input.derivative;
      op.evidence = op.entry?.evidence ?? input.evidence;
      op.binding = association(op.scope, op.derivative);
      if (op.entry && op.binding !== op.entry.binding) fail('SOURCE_BINDING_DENIED');
      op.source = op.entry?.source ?? null;
      follow(op, input.signal, 'CANCELED');
      follow(op, op.binding.signal, 'SOURCE_BINDING_DENIED');
      follow(op, op.entry?.controller.signal, 'CONTEXT_REVOKED');
      // Initial source association may consume part of the original budget.
      // Rounding only accounts for the native timer's millisecond resolution.
      op.timer = setTimeout(() => stop(op, 'DEADLINE_EXCEEDED'),
        Math.max(1, Math.ceil(op.deadlineAt - MONOTONIC_NOW())));
      op.key = opaque();
      operations.set(op.key, op);
      check(op);
      return op;
    } catch (error) { close(op); throw safeError(error); }
  }

  function close(op) {
    op.done = true;
    clearTimeout(op.timer);
    for (const [signal, listener] of op.listeners) Reflect.apply(REMOVE_LISTENER, signal, ['abort', listener]);
    if (op.key) operations.delete(op.key);
    op.bytes?.fill(0);
    op.bytes = null;
    if (active === op) active = null;
  }

  async function readRetained(op, mode) {
    op.mode = mode;
    op.payloadSeen = false;
    const scope = await wait(op, () => evidenceStore.scopeForAuthenticatedRequest(op.key));
    await wait(op, () => evidenceStore.withPrivatePayload(scope, op.evidence, op.key));
    if (!op.payloadSeen || (mode === 'capture' && !op.bytes)) fail('EVIDENCE_UNAVAILABLE');
    authorizeCurrent(op);
  }

  function approvedRanges(op, decision, notices) {
    const reviewed = record(decision, ['status', 'schema', 'purpose', 'tenantId', 'recordId',
      'sourceDigest', 'evidenceId', 'sourceUrl', 'reviewVersion', 'completeForPurpose', 'criticalNoticesReviewed', 'ranges']);
    check(op);
    if (!reviewed) fail('REVIEW_INVALID');
    if (reviewed.status === 'rejected') fail('REVIEW_REJECTED');
    if (reviewed.status !== 'approved' || reviewed.schema !== REVIEWED_SOURCE_CONTEXT_SCHEMA
      || reviewed.purpose !== config.purpose || reviewed.tenantId !== op.binding.tenantId
      || reviewed.recordId !== op.binding.recordId || reviewed.sourceDigest !== op.binding.sourceDigest
      || reviewed.evidenceId !== op.source.evidenceId || reviewed.sourceUrl !== op.source.sourceUrl
      || !label(reviewed.reviewVersion) || reviewed.completeForPurpose !== true
      || reviewed.criticalNoticesReviewed !== true) fail('REVIEW_INVALID');
    const ranges = array(reviewed.ranges, MAX_RANGES);
    check(op);
    if (!ranges || ranges.length === 0) fail('REVIEW_INVALID');
    let total = 0;
    let priorEnd = 0;
    const segments = [];
    for (const raw of ranges) {
      const range = record(raw, ['startByte', 'endByte']);
      check(op);
      if (!range || range.startByte < priorEnd) fail('REVIEW_INVALID');
      const text = exactText(op.bytes, range.startByte, range.endByte, 'REVIEW_INVALID');
      total += range.endByte - range.startByte;
      if (total > MAX_CONTEXT_BYTES) fail('REVIEW_INVALID');
      segments.push(Object.freeze({ startByte: range.startByte, endByte: range.endByte, text }));
      priorEnd = range.endByte;
    }
    if (notices.some((notice) => !segments.some((segment) =>
      segment.startByte <= notice.startByte && segment.endByte >= notice.endByte))) fail('CRITICAL_NOTICE_OMITTED');
    authorizeCurrent(op);
    return Object.freeze({ reviewVersion: reviewed.reviewVersion, segments: Object.freeze(segments), notices });
  }

  async function review(value) {
    const op = start(value, 'review_source_context');
    try {
      if (typeof config.reviewContext !== 'function') fail('REVIEW_REQUIRED');
      if (typeof config.authorizeContextCurrent !== 'function') fail('AUTHORITY_DENIED');
      await readRetained(op, 'capture');
      const extraction = await wait(op, () => extractDeterministically({
        url: op.source.canonicalUrl,
        requestedUrl: op.source.sourceUrl,
        redirectChain: op.source.redirectChain,
        redirects: op.source.redirectChain.length,
        contentType: op.source.contentType,
        fetchedAt: op.source.retrievedAt,
        bytes: op.bytes,
      }, { signal: op.controller.signal, limits: { ...EXTRACTION_LIMITS, maxDocumentBytes: MAX_SOURCE_BYTES } }));
      const notices = noticesFromExtraction(extraction, op.bytes, op.binding.sourceDigest);
      authorizeCurrent(op);
      const input = Object.freeze({
        schema: REVIEWED_SOURCE_CONTEXT_SCHEMA,
        purpose: config.purpose,
        tenantId: op.binding.tenantId,
        recordId: op.binding.recordId,
        sourceDigest: op.binding.sourceDigest,
        evidenceId: op.source.evidenceId,
        modality: op.binding.modality,
        source: Object.freeze({ sourceUrl: op.source.sourceUrl, contentType: op.source.contentType }),
        criticalNotices: notices,
        signal: op.controller.signal,
        readSourceText() {
          authorizeCurrent(op);
          return exactText(op.bytes, 0, op.bytes.length, 'UNSUPPORTED_SOURCE');
        },
      });
      const decision = await wait(op, () => config.reviewContext(input));
      const approved = approvedRanges(op, decision, notices);
      // The review may await or reenter. Reopen the actual encrypted source and
      // let EvidenceStore check current keys, authority, state and retention again.
      await readRetained(op, 'verify');
      authorizeCurrent(op);
      const context = opaque();
      contexts.set(context, { binding: op.binding, derivative: op.derivative, evidence: op.evidence,
        source: op.source, approved, revoked: false, controller: new AbortController() });
      return context;
    } catch (error) { throw safeError(op.failure ?? error); }
    finally { close(op); }
  }

  async function materialize(value) {
    const op = start(value, 'materialize_source_context');
    try {
      await readRetained(op, 'verify');
      authorizeCurrent(op);
      return Object.freeze({
        schema: REVIEWED_SOURCE_CONTEXT_SCHEMA,
        visibility: 'tenant_private',
        trust: 'untrusted_external',
        purpose: config.purpose,
        recordId: op.binding.recordId,
        evidenceId: op.source.evidenceId,
        sourceDigest: op.binding.sourceDigest,
        sourceUrl: op.source.sourceUrl,
        expiresAt: new Date(op.source.expiresAtMs).toISOString(),
        reviewVersion: op.entry.approved.reviewVersion,
        segments: op.entry.approved.segments,
        criticalNotices: op.entry.approved.notices,
        canonicalAdoption: false,
        dispatchStatus: 'not_dispatched',
      });
    } catch (error) { throw safeError(op.failure ?? error); }
    finally { close(op); }
  }

  function revoke(scope, context) {
    const entry = contexts.get(context);
    if (!entry) fail('INVALID_INPUT');
    if (association(scope, entry.derivative) !== entry.binding) fail('SOURCE_BINDING_DENIED');
    if (entry.revoked) return false;
    entry.revoked = true;
    entry.controller.abort();
    return true;
  }

  return Object.freeze({ evidenceStore, review, materialize, revoke });
}
