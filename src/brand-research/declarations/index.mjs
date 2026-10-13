import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { types } from 'node:util';
import { createEvidenceStore, EvidenceStoreError } from '../../evidence/store.mjs';
import { DECLARATION_LIMITS, parseDeclarations } from './parse.mjs';

export { DECLARATION_LIMITS } from './parse.mjs';
export const DECLARATION_PROFILE = 'ei-private-html-brand-declarations/1';
const NOW = performance.now.bind(performance);
const ABORTED = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const ADD = EventTarget.prototype.addEventListener;
const REMOVE = EventTarget.prototype.removeEventListener;
const THEN = Promise.prototype.then;
const CODES = new Set(['INVALID_INPUT', 'BUSY', 'CANCELED', 'DEADLINE_EXCEEDED', 'EVIDENCE_DENIED',
  'EVIDENCE_EXPIRED', 'EVIDENCE_UNAVAILABLE', 'SOURCE_MISMATCH', 'SOURCE_INCOMPLETE',
  'UNSUPPORTED_SOURCE', 'MALFORMED_HTML', 'PARSER_FAILURE', 'RESOURCE_LIMIT']);
const STORE_KEYS = ['directory', 'resolveTenant', 'resolveKey', 'resolveRetention', 'authorizePrivateAccess',
  'authorizePrivateAccessCurrent', 'now', 'maxSourceBytes', 'maxPositionBytes', 'maxPositionCount',
  'maxStoredPayloadBytes', 'maxRetentionMs', 'lockTimeoutMs'];
const hash = (value) => createHash('sha256').update(value).digest('hex');
export class BrandDeclarationError extends Error {
  constructor(code = 'EVIDENCE_UNAVAILABLE') {
    super('Private brand declarations are unavailable.');
    this.name = 'BrandDeclarationError';
    this.code = typeof code === 'string' && CODES.has(code) ? code : 'EVIDENCE_UNAVAILABLE';
  }
}
function fail(code) { throw new BrandDeclarationError(code); }
function record(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value)) return null;
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some((k) => typeof k !== 'string' || !keys.includes(k))) return null;
  const result = Object.create(null);
  for (const [key, d] of Object.entries(descriptors)) {
    if (!Object.hasOwn(d, 'value') || !d.enumerable) return null;
    result[key] = d.value;
  }
  return result;
}
function safeError(error) {
  if (!error || types.isProxy(error)) return new BrandDeclarationError();
  const code = Object.getOwnPropertyDescriptor(error, 'code')?.value;
  if (error instanceof BrandDeclarationError) return new BrandDeclarationError(code);
  if (error instanceof EvidenceStoreError) {
    if (code === 'EVIDENCE_DENIED' || code === 'EVIDENCE_EXPIRED') return new BrandDeclarationError(code);
    if (code === 'EVIDENCE_CANCELLED') return new BrandDeclarationError('CANCELED');
  }
  return new BrandDeclarationError();
}

/** Trusted composition root. The adapter owns the real store's private consumer. */
export function createBrandDeclarationReader(options) {
  const config = record(options, ['evidenceStoreOptions', 'deadlineMs']);
  const storeConfig = config && record(config.evidenceStoreOptions, STORE_KEYS);
  if (!storeConfig || typeof storeConfig.resolveTenant !== 'function'
    || typeof storeConfig.authorizePrivateAccess !== 'function'
    || typeof storeConfig.authorizePrivateAccessCurrent !== 'function') fail('INVALID_INPUT');
  const deadlineMs = config.deadlineMs ?? DECLARATION_LIMITS.deadlineMs;
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > DECLARATION_LIMITS.deadlineMs) fail('INVALID_INPUT');
  const clock = storeConfig.now ?? Date.now;
  const operations = new WeakMap();
  let active = null;
  function check(op) {
    if (op.failure) throw op.failure;
    if (op.done || active !== op) fail('CANCELED');
    if (NOW() >= op.deadlineAt) fail('DEADLINE_EXCEEDED');
    if (op.retentionDeadlineAt !== undefined && NOW() >= op.retentionDeadlineAt) fail('EVIDENCE_EXPIRED');
  }
  function current(op) {
    check(op);
    const now = clock();
    check(op);
    if (!Number.isSafeInteger(now) || now < 0) fail('EVIDENCE_UNAVAILABLE');
    if (op.source && now >= op.source.expiresAtMs) fail('EVIDENCE_EXPIRED');
    if (op.source) op.retentionDeadlineAt = Math.min(op.retentionDeadlineAt ?? Infinity,
      NOW() + op.source.expiresAtMs - now);
  }
  function stop(op, code) {
    if (op.done || op.failure) return;
    op.failure = new BrandDeclarationError(code);
    op.controller.abort();
  }
  function wait(op, action) {
    op.pending += 1;
    const pending = Promise.resolve().then(() => { check(op); return action(); });
    return new Promise((resolve, reject) => {
      let done = false;
      const finish = (error, value) => {
        if (done) return;
        done = true;
        REMOVE.call(op.controller.signal, 'abort', aborted);
        if (error) reject(error); else resolve(value);
      };
      const aborted = () => finish(op.failure ?? new BrandDeclarationError('CANCELED'));
      const released = () => {
        op.pending -= 1;
        if (op.done && op.pending === 0 && active === op) active = null;
      };
      pending.then((value) => {
        try { check(op); finish(null, value); } catch (e) { finish(e); } finally { released(); }
      }, (e) => { try { finish(op.failure ?? e); } finally { released(); } });
      ADD.call(op.controller.signal, 'abort', aborted, { once: true });
      if (ABORTED.call(op.controller.signal)) aborted();
    });
  }
  const unwrap = (request) => operations.get(request)?.request ?? request;
  function consume(input) {
    const op = operations.get(input.request);
    if (!op || op.done || active !== op) fail('EVIDENCE_DENIED');
    let bytes;
    try {
      current(op);
      if (input.metadata.representation !== undefined || input.source.derivedPdf || input.source.assetSource
        || input.source.controlledAsset || input.source.contentType.split(';', 1)[0].trim().toLowerCase() !== 'text/html') fail('UNSUPPORTED_SOURCE');
      const source = Object.freeze({ tenantId: input.tenantId, evidenceId: input.evidenceId,
        version: input.metadata.version, contentHash: input.source.contentHash,
        sourceUrl: input.source.sourceUrl, sourceKind: input.source.sourceKind,
        contentType: input.source.contentType, retrievedAt: input.source.retrievedAt,
        expiresAtMs: Date.parse(input.metadata.expiresAt) });
      if (!Number.isSafeInteger(source.expiresAtMs) || source.evidenceId !== input.metadata.evidenceId
        || source.contentHash !== input.metadata.contentHash) fail('SOURCE_MISMATCH');
      if (op.source && Object.keys(source).some((key) => source[key] !== op.source[key])) fail('SOURCE_MISMATCH');
      op.source = source;
      current(op);
      if (input.positions.length === 0 || input.positions.length > DECLARATION_LIMITS.positions) fail('SOURCE_INCOMPLETE');
      const positions = [...input.positions].sort((a, b) => a.locator.startByte - b.locator.startByte);
      let covered = 0;
      for (const position of positions) {
        const { locator, content, contentHash } = position;
        if (locator.kind !== 'text-range' || locator.startByte !== covered
          || !Number.isSafeInteger(locator.endByte) || locator.endByte <= covered
          || locator.endByte - covered !== content.byteLength || locator.endByte > DECLARATION_LIMITS.sourceBytes
          || hash(content) !== contentHash) fail('SOURCE_INCOMPLETE');
        covered = locator.endByte;
      }
      bytes = Buffer.concat(positions.map((p) => p.content), covered);
      if (hash(bytes) !== source.contentHash) fail('SOURCE_MISMATCH');
      current(op);
      if (op.capture) { op.bytes = bytes; bytes = undefined; }
      op.seen = true;
      return undefined;
    } catch (error) { op.failure = safeError(error); throw op.failure; }
    finally { bytes?.fill(0); }
  }
  const evidenceStore = createEvidenceStore({ ...storeConfig,
    resolveTenant: (request) => storeConfig.resolveTenant(unwrap(request)),
    authorizePrivateAccess: (input) => storeConfig.authorizePrivateAccess(Object.freeze({ ...input, request: unwrap(input.request) })),
    authorizePrivateAccessCurrent: (input) => storeConfig.authorizePrivateAccessCurrent(Object.freeze({ ...input, request: unwrap(input.request) })),
    consumePrivatePayload: consume,
  });
  async function read(value) {
    if (active) fail('BUSY');
    const op = { deadlineAt: NOW() + deadlineMs, done: false, failure: null, pending: 0,
      controller: new AbortController(), capture: true, seen: false, source: null, bytes: null };
    active = op;
    let signal, onAbort;
    try {
      const input = record(value, ['evidence', 'request', 'signal']);
      if (!input || !input.request || typeof input.request !== 'object' || types.isProxy(input.request)) fail('INVALID_INPUT');
      op.request = input.request;
      op.key = Object.freeze(Object.create(null));
      operations.set(op.key, op);
      signal = input.signal;
      if (signal !== undefined) {
        try { ABORTED.call(signal); } catch { fail('INVALID_INPUT'); }
        onAbort = () => stop(op, 'CANCELED');
        ADD.call(signal, 'abort', onAbort, { once: true });
        if (ABORTED.call(signal)) onAbort();
      }
      op.timer = setTimeout(() => stop(op, 'DEADLINE_EXCEEDED'), Math.max(1, Math.ceil(op.deadlineAt - NOW())));
      async function reopen(capture) {
        op.capture = capture; op.seen = false;
        const scope = await wait(op, () => evidenceStore.scopeForAuthenticatedRequest(op.key));
        await wait(op, () => evidenceStore.withPrivatePayload(scope, input.evidence, op.key));
        current(op);
        if (!op.seen) fail('EVIDENCE_UNAVAILABLE');
      }
      await reopen(true);
      const parsed = await wait(op, () => parseDeclarations(op.bytes, op.source.contentType, {
        signal: op.controller.signal, check: () => current(op), fail,
        remainingMs: () => op.deadlineAt - NOW(),
      }));
      await reopen(false);
      const { tenantId: omittedTenant, expiresAtMs, ...source } = op.source;
      const result = Object.freeze({ profile: DECLARATION_PROFILE, visibility: 'tenant_private',
        trust: 'untrusted_source_declarations', completeness: 'incomplete-supported-subset',
        status: parsed.declarations.length ? 'declarations_observed' : 'no_supported_declarations',
        canonicalAdoption: false, dispatchStatus: 'not_dispatched', officialBrand: 'unknown',
        renderedAppearance: 'not_evaluated', fontAvailability: 'unknown', permission: 'unknown',
        source: Object.freeze({ ...source, expiresAt: new Date(expiresAtMs).toISOString() }),
        ...parsed,
      });
      if (Buffer.byteLength(JSON.stringify(result)) > DECLARATION_LIMITS.outputBytes) fail('RESOURCE_LIMIT');
      current(op);
      // Final authority runs after all parsing/serialization and the configured
      // clock. No host callback or await follows it before the native-time guard.
      const allowed = storeConfig.authorizePrivateAccessCurrent(Object.freeze({
        tenantId: op.source.tenantId, request: op.request, action: 'read_private_evidence',
        evidenceIds: Object.freeze([op.source.evidenceId]), factIds: Object.freeze([]),
      }));
      if (allowed !== true) {
        if (types.isPromise(allowed) && !types.isProxy(allowed)
          && Object.getPrototypeOf(allowed) === Promise.prototype
          && !Object.hasOwn(allowed, 'constructor')) {
          try { THEN.call(allowed, () => {}, () => {}); } catch { /* refuse either way */ }
        }
        fail('EVIDENCE_DENIED');
      }
      check(op);
      return result;
    } catch (error) { throw safeError(op.failure ?? error); }
    finally {
      op.done = true;
      clearTimeout(op.timer);
      if (signal !== undefined && onAbort) REMOVE.call(signal, 'abort', onAbort);
      if (op.key) operations.delete(op.key);
      op.bytes?.fill(0);
      op.bytes = null;
      // A trusted store/host callback cannot be preempted. Keep its capacity held
      // after cancellation until the underlying operation actually settles.
      if (active === op && op.pending === 0) active = null;
    }
  }
  return Object.freeze({ evidenceStore, read });
}
