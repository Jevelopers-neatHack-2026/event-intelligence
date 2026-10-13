import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { monotonicNow } from '../../security/internal/monotonic-clock.mjs';

const contexts = new WeakSet();
const errors = new WeakSet();
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const typedArray = Object.getPrototypeOf(Uint8Array.prototype);
const tag = Object.getOwnPropertyDescriptor(typedArray, Symbol.toStringTag).get;
const length = Object.getOwnPropertyDescriptor(typedArray, 'length').get;
const set = Uint8Array.prototype.set;
const nativeThen = Promise.prototype.then;
const MAX_BYTES = 20 * 1024 * 1024;

const MESSAGES = Object.freeze({
  REVALIDATION_INVALID: 'invalid private revalidation input',
  REVALIDATION_UNSUPPORTED: 'private source revalidation is unsupported',
  REVALIDATION_DENIED: 'private source revalidation denied',
  REVALIDATION_CANCELLED: 'private source revalidation cancelled',
  REVALIDATION_DEADLINE: 'private source revalidation deadline exceeded',
  REVALIDATION_PROVENANCE: 'private source revalidation provenance unavailable',
});

export class CacheRevalidationError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES.REVALIDATION_DENIED);
    this.name = 'CacheRevalidationError';
    this.code = Object.hasOwn(MESSAGES, code) ? code : 'REVALIDATION_DENIED';
    errors.add(this);
  }
}

export function revalidationFail(code) { throw new CacheRevalidationError(code); }
export function isCacheRevalidationError(error) { return errors.has(error); }
export function isRevalidationContext(value) { return contexts.has(value); }

export function dataRecord(value, fields) {
  if (!value || typeof value !== 'object' || types.isProxy(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const result = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !fields.includes(key)) return null;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
    result[key] = descriptor.value;
  }
  return result;
}

/** Hash an owned bounded copy; never retain or mutate the host's source bytes. */
export function originalBodyHash(value) {
  let copy;
  try {
    if (types.isProxy(value) || tag.call(value) !== 'Uint8Array') return null;
    const size = length.call(value);
    if (!Number.isSafeInteger(size) || size < 1 || size > MAX_BYTES) return null;
    copy = new Uint8Array(size);
    set.call(copy, value);
    return createHash('sha256').update(copy).digest('hex');
  } catch { return null; }
  finally { copy?.fill(0); }
}

/** One operation's real cancellation/deadline guard, including late async continuations. */
export function createRevalidationContext({ signal, timeoutMs, request, readRetainedSource }) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000
    || typeof readRetainedSource !== 'function' || types.isProxy(readRetainedSource)) {
    revalidationFail('REVALIDATION_INVALID');
  }
  if (signal !== undefined) {
    try { if (types.isProxy(signal)) throw new Error(); aborted.call(signal); }
    catch { revalidationFail('REVALIDATION_INVALID'); }
  }
  const deadlineAtMonotonic = monotonicNow() + timeoutMs;
  const controller = new AbortController();
  let stopped = null;
  let closed = false;
  const stop = (reason) => {
    stopped ??= reason;
    if (!controller.signal.aborted) controller.abort();
  };
  const externalAbort = () => stop('REVALIDATION_CANCELLED');
  signal?.addEventListener('abort', externalAbort, { once: true });
  if (signal !== undefined && aborted.call(signal)) externalAbort();
  const timer = setTimeout(() => stop('REVALIDATION_DEADLINE'), Math.max(1, Math.ceil(deadlineAtMonotonic - monotonicNow())));
  function check() {
    if (signal !== undefined && aborted.call(signal)) stop('REVALIDATION_CANCELLED');
    if (monotonicNow() >= deadlineAtMonotonic) stop('REVALIDATION_DEADLINE');
    if (stopped) revalidationFail(stopped);
    if (closed) revalidationFail('REVALIDATION_DENIED');
  }
  async function wait(value) {
    try { check(); }
    catch (error) {
      // A trusted callback can stop this operation before its already-created
      // native Promise reaches wait(). Observe that Promise without adopting
      // arbitrary thenables or replacing the original cancellation/deadline.
      if (types.isPromise(value)) {
        try { Reflect.apply(nativeThen, value, [() => {}, () => {}]); }
        catch { /* Preserve the original refusal if observation is unavailable. */ }
      }
      throw error;
    }
    let listener;
    const stoppedPromise = new Promise((resolve, reject) => {
      listener = () => reject(new CacheRevalidationError(stopped ?? 'REVALIDATION_CANCELLED'));
      controller.signal.addEventListener('abort', listener, { once: true });
    });
    try {
      const result = await Promise.race([value, stoppedPromise]);
      check();
      return result;
    } finally { controller.signal.removeEventListener('abort', listener); }
  }
  const context = Object.freeze({
    signal: controller.signal,
    deadlineAtMonotonic,
    check,
    wait,
    async retain(binding, phase) {
      check();
      let raw;
      try {
        raw = await wait(Promise.resolve().then(() => {
          check();
          return readRetainedSource(Object.freeze({ request, binding, phase, signal: controller.signal }));
        }));
      } catch (error) {
        if (isCacheRevalidationError(error)) throw error;
        revalidationFail('REVALIDATION_PROVENANCE');
      }
      const result = dataRecord(raw, ['binding', 'representation', 'bytes', 'validUntilMs']);
      if (!result || result.binding !== binding || result.representation !== 'full_original_response'
        || !Number.isSafeInteger(result.validUntilMs) || result.validUntilMs < 1
        || result.validUntilMs > binding.expiresAtMs
        || originalBodyHash(result.bytes) !== binding.originalBodyHash) {
        revalidationFail('REVALIDATION_PROVENANCE');
      }
      check();
      return result.validUntilMs;
    },
    close() {
      closed = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', externalAbort);
    },
  });
  contexts.add(context);
  return context;
}
