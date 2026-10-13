import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';

const TEXT_MODALITIES = new Set(['html', 'ocr_text', 'pdf_text', 'pdf_metadata', 'plain_text']);
const BINARY_MODALITIES = new Set(['image_binary', 'pdf_binary', 'attendee_csv', 'unknown_binary']);
const ALL_MODALITIES = new Set([...TEXT_MODALITIES, ...BINARY_MODALITIES]);
const STATES = new Set(['accepting', 'preparing', 'ready_for_publish', 'published', 'quarantined', 'cancelled', 'expired']);
const REASONS = new Set(['unverified_public_facts', 'review_unavailable', 'unsupported_modality', 'invalid_text', 'invalid_candidate', 'invalid_review_decision', 'source_expired', 'cancelled']);
const TRUST = 'untrusted_external';
const UNAVAILABLE = 'private evidence unavailable';
const privacyBoundaries = new WeakSet();
const derivativeSourceReaders = new WeakMap();
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_TAG_GETTER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, Symbol.toStringTag).get;
const TYPED_ARRAY_LENGTH_GETTER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'length').get;
const UINT8_ARRAY_SET = Uint8Array.prototype.set;

function deny() {
  return new Error(UNAVAILABLE);
}

export function isPrivacyBoundary(value) {
  return privacyBoundaries.has(value);
}

/** @internal Private association only; this does not authorize a source read. */
export function readDerivativeSourceAssociation(boundary, scope, derivative) {
  const read = derivativeSourceReaders.get(boundary);
  if (!read) throw deny();
  return read(scope, derivative);
}

function opaque() {
  return Object.freeze(Object.create(null));
}

function isWellFormed(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function isRecord(value) {
  if (value === null || typeof value !== 'object') return false;
  try {
    if (Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function ownDataRecord(value, allowedKeys) {
  if (!isRecord(value)) return null;
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string' || !allowedKeys.has(key))) return null;
    const out = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
      out[key] = descriptor.value;
    }
    return out;
  } catch {
    return null;
  }
}

function validateFacts(value) {
  const record = ownDataRecord(value, new Set(['event_name', 'event_date', 'venue']));
  if (!record) return null;
  const facts = Object.create(null);
  for (const key of ['event_name', 'event_date', 'venue']) {
    if (!Object.hasOwn(record, key)) continue;
    const item = record[key];
    if (typeof item !== 'string' || item.length === 0 || item.length > 180 || !isWellFormed(item)) return null;
    if (key === 'event_date') {
      const parsed = new Date(`${item}T00:00:00.000Z`);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(item) || Number.isNaN(parsed.valueOf()) || parsed.toISOString().slice(0, 10) !== item) return null;
    }
    facts[key] = item;
  }
  if (Object.keys(facts).length === 0) return null;
  return Object.freeze(facts);
}

function copyUint8Array(content, maxBytes) {
  try {
    if (TYPED_ARRAY_TAG_GETTER.call(content) !== 'Uint8Array') throw deny();
    const length = TYPED_ARRAY_LENGTH_GETTER.call(content);
    if (!Number.isSafeInteger(length) || length === 0 || length > maxBytes) throw deny();
    const bytes = new Uint8Array(length);
    // TypedArray#set reads the source's internal typed-array slots; it does not call
    // caller-owned valueOf, iterator, constructor, or indexed accessors.
    UINT8_ARRAY_SET.call(bytes, content);
    return bytes;
  } catch {
    throw deny();
  }
}

function sourceSnapshot(modality, content, maxBytes) {
  try {
    if (typeof modality !== 'string' || !ALL_MODALITIES.has(modality)) throw deny();
    let raw;
    let text = null;
    let bytes;
    if (typeof content === 'string') {
      if (!isWellFormed(content)) throw deny();
      text = content;
      bytes = Buffer.from(content, 'utf8');
      raw = TEXT_MODALITIES.has(modality) ? content : Buffer.from(bytes);
    } else {
      bytes = copyUint8Array(content, maxBytes);
      if (TEXT_MODALITIES.has(modality)) {
        try {
          text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        } catch {
          text = null;
        }
        raw = text === null ? Buffer.from(bytes) : text;
      } else {
        raw = Buffer.from(bytes);
      }
    }
    if (bytes.byteLength === 0 || bytes.byteLength > maxBytes) throw deny();
    const digest = createHash('sha256').update(bytes).digest('hex');
    return { modality, raw, text, digest };
  } catch {
    throw deny();
  }
}

function validateCandidate(value) {
  if (value === undefined) return Object.freeze(Object.create(null));
  const record = ownDataRecord(value, new Set(['event_name', 'event_date', 'venue']));
  if (!record) return null;
  const candidate = Object.create(null);
  for (const [key, item] of Object.entries(record)) {
    if (typeof item !== 'string' || item.length === 0 || item.length > 1000 || !isWellFormed(item)) return null;
    candidate[key] = item;
  }
  return Object.freeze(candidate);
}

export function createPrivacyBoundary(options = {}) {
  if (!isRecord(options)) throw new TypeError('boundary options required');
  const {
    resolveTenant,
    reviewPublicFacts,
    authorizePrivateReview,
    consumePrivateOriginal,
    retentionMs = 60 * 60 * 1000,
    maxSourceBytes = 5 * 1024 * 1024,
    now = () => performance.now(),
  } = options;
  if (resolveTenant !== undefined && typeof resolveTenant !== 'function') throw new TypeError('trusted tenant resolver required');
  if (reviewPublicFacts !== undefined && typeof reviewPublicFacts !== 'function') throw new TypeError('trusted public-fact reviewer required');
  if (authorizePrivateReview !== undefined && typeof authorizePrivateReview !== 'function') throw new TypeError('private-review authorizer required');
  if (consumePrivateOriginal !== undefined && typeof consumePrivateOriginal !== 'function') throw new TypeError('private-review consumer required');
  if (typeof now !== 'function' || !Number.isSafeInteger(retentionMs) || retentionMs <= 0 || !Number.isSafeInteger(maxSourceBytes) || maxSourceBytes <= 0) {
    throw new TypeError('valid retention, source-size, and clock settings required');
  }

  const scopeRecords = new WeakMap();
  const partitionByTenant = new Map();
  const sourceRecords = new WeakMap();
  const sessionRecords = new WeakMap();
  const resultRecords = new WeakMap();
  const derivativeRecords = new WeakMap();
  const derivativeSources = new WeakMap();
  const retained = new Map();

  function currentTime() {
    const value = now();
    if (!Number.isFinite(value)) throw deny();
    return value;
  }

  function requireScope(scope) {
    const info = scopeRecords.get(scope);
    if (!info) throw deny();
    return info;
  }

  function createResult(info, sessionInfo) {
    const result = opaque();
    resultRecords.set(result, Object.freeze({
      partition: info.partition,
      tenantId: info.tenantId,
      recordId: sessionInfo.recordId,
      state: sessionInfo.state,
      modality: sessionInfo.modality,
      trust: TRUST,
      reasonCode: sessionInfo.reasonCode,
      redactionCategories: Object.freeze([]),
    }));
    return result;
  }

  function requireSession(scope, session) {
    const info = requireScope(scope);
    const state = sessionRecords.get(session);
    if (!state || state.tenantId !== info.tenantId || state.partition !== info.partition) throw deny();
    return { info, state };
  }

  function activeEntry(info, token) {
    const entry = retained.get(token);
    if (!entry || entry.tenantId !== info.tenantId || entry.partition !== info.partition) throw deny();
    if (entry.expiresAt <= currentTime()) {
      retained.delete(token);
      throw deny();
    }
    return entry;
  }

  function createSession(info, token) {
    const session = opaque();
    const entry = activeEntry(info, token);
    sessionRecords.set(session, {
      token,
      tenantId: info.tenantId,
      partition: info.partition,
      state: 'accepting',
      generation: 0,
      recordId: randomUUID(),
      modality: entry.modality,
      reasonCode: null,
      pendingFacts: null,
      derivative: null,
      abortController: null,
    });
    return session;
  }

  function stateAfterMissingEntry(sessionInfo) {
    const controller = sessionInfo.abortController;
    sessionInfo.generation += 1;
    sessionInfo.pendingFacts = null;
    sessionInfo.abortController = null;
    sessionInfo.state = 'expired';
    sessionInfo.reasonCode = 'source_expired';
    // Commit the terminal state before abort dispatch, which synchronously runs
    // listeners that may reenter this boundary.
    controller?.abort();
  }

  function refreshSessionRetention(info, sessionInfo) {
    if (sessionInfo.state === 'published' || sessionInfo.state === 'cancelled' || sessionInfo.state === 'expired') return;
    try {
      activeEntry(info, sessionInfo.token);
    } catch {
      stateAfterMissingEntry(sessionInfo);
    }
  }

  function isCurrentAttempt(sessionInfo, generation) {
    return sessionInfo.generation === generation && sessionInfo.state === 'preparing';
  }

  function refreshAttempt(info, sessionInfo, generation) {
    if (!isCurrentAttempt(sessionInfo, generation)) return false;
    try {
      activeEntry(info, sessionInfo.token);
    } catch {
      if (isCurrentAttempt(sessionInfo, generation)) stateAfterMissingEntry(sessionInfo);
      return false;
    }
    return isCurrentAttempt(sessionInfo, generation);
  }

  function scopeForAuthenticatedRequest(request) {
    if (typeof resolveTenant !== 'function') throw deny();
    let tenantId;
    try {
      tenantId = resolveTenant(request);
    } catch {
      throw deny();
    }
    if (typeof tenantId !== 'string' || tenantId.length === 0 || tenantId.length > 256 || !isWellFormed(tenantId)) throw deny();
    let partition = partitionByTenant.get(tenantId);
    if (!partition) {
      partition = opaque();
      partitionByTenant.set(tenantId, partition);
    }
    const scope = opaque();
    scopeRecords.set(scope, Object.freeze({ tenantId, partition }));
    return scope;
  }

  function begin(scope, document) {
    const info = requireScope(scope);
    const input = ownDataRecord(document, new Set(['modality', 'content']));
    if (!input || !Object.hasOwn(input, 'modality') || !Object.hasOwn(input, 'content')) throw deny();
    const snapshot = sourceSnapshot(input.modality, input.content, maxSourceBytes);
    const token = randomUUID();
    retained.set(token, {
      tenantId: info.tenantId,
      partition: info.partition,
      modality: snapshot.modality,
      raw: snapshot.raw,
      text: snapshot.text,
      digest: snapshot.digest,
      expiresAt: currentTime() + retentionMs,
    });
    const source = opaque();
    sourceRecords.set(source, Object.freeze({ token, tenantId: info.tenantId, partition: info.partition }));
    const session = createSession(info, token);
    return Object.freeze({ source, session });
  }

  function restart(scope, source) {
    const info = requireScope(scope);
    const reference = sourceRecords.get(source);
    if (!reference || reference.tenantId !== info.tenantId || reference.partition !== info.partition) throw deny();
    activeEntry(info, reference.token);
    return createSession(info, reference.token);
  }

  async function prepare(scope, session, candidateValue) {
    const { info, state } = requireSession(scope, session);
    refreshSessionRetention(info, state);
    if (state.state === 'expired') return createResult(info, state);
    if (state.state !== 'accepting') throw deny();

    // Claim the attempt before invoking any validation operation on caller-owned
    // candidate or decision objects. Reentrant cancellation advances generation.
    const generation = ++state.generation;
    const controller = new AbortController();
    state.abortController = controller;
    state.state = 'preparing';
    const finish = () => createResult(info, state);
    const quarantine = (reasonCode) => {
      if (!isCurrentAttempt(state, generation)) return finish();
      const abortController = state.abortController;
      state.abortController = null;
      state.pendingFacts = null;
      state.state = 'quarantined';
      state.reasonCode = reasonCode;
      // Abort listeners may cancel synchronously. The quarantine transition is
      // committed first so a later successful cancellation remains terminal.
      abortController?.abort();
      return finish();
    };

    let entry;
    try {
      entry = activeEntry(info, state.token);
    } catch {
      if (isCurrentAttempt(state, generation)) stateAfterMissingEntry(state);
      return finish();
    }
    if (!isCurrentAttempt(state, generation)) return finish();
    if (!TEXT_MODALITIES.has(entry.modality)) {
      return quarantine('unsupported_modality');
    }
    if (typeof entry.text !== 'string') {
      return quarantine('invalid_text');
    }

    const candidate = validateCandidate(candidateValue);
    if (!refreshAttempt(info, state, generation)) return finish();
    if (!candidate) {
      return quarantine('invalid_candidate');
    }
    if (typeof reviewPublicFacts !== 'function') {
      return quarantine('unverified_public_facts');
    }
    if (!refreshAttempt(info, state, generation)) return finish();
    const sourceToken = state.token;
    const reviewInput = Object.freeze({
      tenantId: info.tenantId,
      sourceDigest: entry.digest,
      modality: entry.modality,
      candidate,
      signal: controller.signal,
      readSourceText() {
        if (controller.signal.aborted || state.generation !== generation || state.state !== 'preparing') throw deny();
        const currentSource = activeEntry(info, sourceToken);
        if (typeof currentSource.text !== 'string') throw deny();
        return currentSource.text;
      },
    });
    entry = null;
    let decision;
    let reviewFailed = false;
    try {
      decision = await reviewPublicFacts(reviewInput);
    } catch {
      reviewFailed = true;
    }

    if (!refreshAttempt(info, state, generation)) return finish();
    if (reviewFailed) return quarantine('review_unavailable');

    // Normalizing a review decision can execute Proxy traps. Do not commit the
    // result until generation and retention have been rechecked after each phase.
    const reviewed = ownDataRecord(decision, new Set(['status', 'tenantId', 'sourceDigest', 'facts']));
    if (!refreshAttempt(info, state, generation)) return finish();
    const facts = reviewed && validateFacts(reviewed.facts);
    if (!refreshAttempt(info, state, generation)) return finish();

    let current;
    try {
      current = activeEntry(info, state.token);
    } catch {
      if (isCurrentAttempt(state, generation)) stateAfterMissingEntry(state);
      return finish();
    }
    if (!isCurrentAttempt(state, generation)) return finish();
    if (!reviewed || reviewed.status !== 'approved' || reviewed.tenantId !== info.tenantId || reviewed.sourceDigest !== current.digest || !facts) {
      return quarantine('invalid_review_decision');
    }

    // This is the last check before the synchronous result commit.
    if (!refreshAttempt(info, state, generation)) return finish();
    state.abortController = null;
    state.pendingFacts = facts;
    state.state = 'ready_for_publish';
    state.reasonCode = null;
    return finish();
  }

  function publish(scope, session) {
    const { info, state } = requireSession(scope, session);
    if (state.state === 'published' && state.derivative) return state.derivative;
    if (state.state !== 'ready_for_publish' || !state.pendingFacts) throw deny();
    let entry;
    try {
      entry = activeEntry(info, state.token);
    } catch {
      stateAfterMissingEntry(state);
      throw deny();
    }
    const derivative = opaque();
    derivativeRecords.set(derivative, Object.freeze({
      tenantId: info.tenantId,
      partition: info.partition,
      recordId: state.recordId,
      modality: entry.modality,
      trust: TRUST,
      facts: state.pendingFacts,
    }));
    const sourceController = new AbortController();
    derivativeSources.set(derivative, {
      partition: info.partition,
      expiresAt: entry.expiresAt,
      revoked: false,
      controller: sourceController,
      association: Object.freeze({
        tenantId: info.tenantId,
        recordId: state.recordId,
        modality: entry.modality,
        sourceDigest: entry.digest,
        signal: sourceController.signal,
      }),
    });
    state.pendingFacts = null;
    state.derivative = derivative;
    state.state = 'published';
    state.reasonCode = null;
    retained.delete(state.token);
    return derivative;
  }

  function cancel(scope, session) {
    const { info, state } = requireSession(scope, session);
    refreshSessionRetention(info, state);
    if (state.state === 'published' || state.state === 'cancelled' || state.state === 'expired') return false;
    const controller = state.abortController;
    state.generation += 1;
    state.abortController = null;
    state.pendingFacts = null;
    state.derivative = null;
    state.state = 'cancelled';
    state.reasonCode = 'cancelled';
    retained.delete(state.token);
    // Make cancellation observable before synchronously notifying listeners.
    controller?.abort();
    return true;
  }

  function result(scope, session) {
    const { info, state } = requireSession(scope, session);
    refreshSessionRetention(info, state);
    return createResult(info, state);
  }

  function diagnostics(scope, resultHandle) {
    const info = requireScope(scope);
    const data = resultRecords.get(resultHandle);
    if (!data || data.tenantId !== info.tenantId || data.partition !== info.partition) throw deny();
    if (!STATES.has(data.state) || (data.reasonCode !== null && !REASONS.has(data.reasonCode))) throw deny();
    return Object.freeze({
      recordId: data.recordId,
      state: data.state,
      modality: data.modality,
      trust: data.trust,
      reasonCode: data.reasonCode,
      redactionCategories: Object.freeze([...data.redactionCategories]),
    });
  }

  function exportDerivative(scope, derivative) {
    const info = requireScope(scope);
    const data = derivativeRecords.get(derivative);
    if (!data || data.tenantId !== info.tenantId || data.partition !== info.partition) throw deny();
    return Object.freeze({
      recordId: data.recordId,
      modality: data.modality,
      trust: data.trust,
      facts: Object.freeze({ ...data.facts }),
    });
  }

  function readSourceAssociation(scope, derivative) {
    const info = requireScope(scope);
    const source = derivativeSources.get(derivative);
    if (!source || source.partition !== info.partition || source.revoked) throw deny();
    const time = currentTime();
    // A trusted clock may reenter. Never resurrect an association it revoked.
    if (source.revoked || source.expiresAt <= time) throw deny();
    return source.association;
  }

  function revokeSourceAssociation(scope, derivative) {
    const info = requireScope(scope);
    const source = derivativeSources.get(derivative);
    if (!source || source.partition !== info.partition) throw deny();
    if (source.revoked) return false;
    // Commit revocation before abort listeners can reenter the adapter.
    source.revoked = true;
    source.controller.abort();
    return true;
  }

  async function withPrivateOriginal(scope, source, request) {
    const info = requireScope(scope);
    const reference = sourceRecords.get(source);
    if (!reference || reference.tenantId !== info.tenantId || reference.partition !== info.partition) throw deny();
    if (typeof authorizePrivateReview !== 'function' || typeof consumePrivateOriginal !== 'function') throw deny();
    let authorized = false;
    try {
      authorized = (await authorizePrivateReview(Object.freeze({ tenantId: info.tenantId, request }))) === true;
    } catch {
      throw deny();
    }
    if (!authorized) throw deny();
    const entry = activeEntry(info, reference.token);
    const content = typeof entry.raw === 'string' ? entry.raw : Uint8Array.from(entry.raw);
    try {
      return await consumePrivateOriginal(Object.freeze({
        tenantId: info.tenantId,
        modality: entry.modality,
        sourceDigest: entry.digest,
        content,
        request,
      }));
    } catch {
      throw deny();
    }
  }

  function purgeExpired() {
    let removed = 0;
    const time = currentTime();
    for (const [token, entry] of retained) {
      if (entry.expiresAt <= time) {
        retained.delete(token);
        removed += 1;
      }
    }
    return removed;
  }

  function retainedOriginalCount() {
    purgeExpired();
    return retained.size;
  }

  function sessionState(scope, session) {
    const { info, state } = requireSession(scope, session);
    refreshSessionRetention(info, state);
    return state.state;
  }

  function scopePartition(scope) {
    return requireScope(scope).partition;
  }

  const boundary = Object.freeze({
    scopeForAuthenticatedRequest,
    begin,
    restart,
    prepare,
    publish,
    cancel,
    result,
    diagnostics,
    exportDerivative,
    revokeSourceAssociation,
    withPrivateOriginal,
    purgeExpired,
    retainedOriginalCount,
    sessionState,
    scopePartition,
  });
  privacyBoundaries.add(boundary);
  derivativeSourceReaders.set(boundary, readSourceAssociation);
  return boundary;
}
