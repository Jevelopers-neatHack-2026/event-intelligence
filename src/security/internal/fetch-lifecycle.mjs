import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { copyConditionalValidator } from './conditional-fetch.mjs';

const contexts = new AsyncLocalStorage();
const provenDocuments = new WeakMap();
const controlledSvgIngestWitnesses = new WeakMap();
const LIFECYCLE_HOOKS = new Set([
  'beforeHop', 'onDispatchIntent', 'onResponseHeaders', 'onKnownZero', 'onDecodeStart', 'onBodyComplete',
]);
const LIFECYCLE_OPTIONS = new Set([
  'decodedTextBytesPerResponse', 'decodedMediaBytesPerResponse',
  'gzipChunkSize', 'gzipReadableHighWaterMark', 'gzipWritableHighWaterMark',
  'totalMilliseconds', 'deadlineAtMonotonic',
]);

function exactDataRecord(value, allowed) {
  try {
    if (value === null || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value)) return null;
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

export function runWithSafeFetchLifecycle(fetcher, hooks, options, operation) {
  const hookInput = exactDataRecord(hooks, LIFECYCLE_HOOKS);
  const optionInput = exactDataRecord(options, LIFECYCLE_OPTIONS);
  if (!fetcher || typeof fetcher !== 'object' || !hookInput || !optionInput || typeof operation !== 'function') {
    throw new TypeError('private retrieval lifecycle unavailable');
  }
  for (const [name, callback] of Object.entries(hookInput)) {
    if (typeof callback !== 'function') throw new TypeError('private retrieval lifecycle unavailable');
  }
  for (const [name, value] of Object.entries(optionInput)) {
    // Only private server composition can supply this performance-timeline
    // deadline. An expired finite value is valid and must stop before DNS;
    // native transport also clamps it to its own unchanged relative budget.
    if (name === 'deadlineAtMonotonic') {
      if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
        throw new TypeError('private retrieval lifecycle unavailable');
      }
      continue;
    }
    if (!Number.isSafeInteger(value) || value < 1) throw new TypeError('private retrieval lifecycle unavailable');
    if (name === 'totalMilliseconds' && value > 30_000) throw new TypeError('private retrieval lifecycle unavailable');
    if (name === 'gzipChunkSize' && value > 4_096) throw new TypeError('private retrieval lifecycle unavailable');
    if (name === 'gzipReadableHighWaterMark' && value > 4_096) throw new TypeError('private retrieval lifecycle unavailable');
    if (name === 'gzipWritableHighWaterMark' && value > 4_096) throw new TypeError('private retrieval lifecycle unavailable');
  }
  return contexts.run(Object.freeze({ fetcher, hooks: Object.freeze(hookInput), options: Object.freeze(optionInput) }), operation);
}

export function safeFetchLifecycleFor(fetcher) {
  const context = contexts.getStore();
  return context?.fetcher === fetcher ? context : null;
}

export function recordSafeFetchProvenance(document, provenance) {
  if (!document || typeof document !== 'object' || !provenance || typeof provenance !== 'object') return;
  const copied = Object.freeze({
    requestedUrl: provenance.requestedUrl,
    finalUrl: provenance.finalUrl,
    mode: provenance.mode === 'svg-asset' ? 'svg-asset' : 'document',
    lifecycleBound: provenance.lifecycleBound === true,
    bodyHash: provenance.bodyHash,
    conditionalValidator: copyConditionalValidator(provenance.conditionalValidator),
    redirectChain: Object.freeze([...provenance.redirectChain]),
    hops: Object.freeze(provenance.hops.map((hop) => Object.freeze({
      url: hop.url,
      statusCode: hop.statusCode,
      dispatchIntent: hop.dispatchIntent,
      responseReceived: hop.responseReceived,
      bodyComplete: hop.bodyComplete,
      decodedBytes: hop.decodedBytes,
    }))),
  });
  provenDocuments.set(document, copied);
}

export function safeFetchProvenance(document) {
  if (!document || typeof document !== 'object') return null;
  return provenDocuments.get(document) ?? null;
}

export function isCompletedControlledSvgFetch(document, expectedUrl) {
  const provenance = safeFetchProvenance(document);
  if (!provenance || provenance.mode !== 'svg-asset' || provenance.lifecycleBound !== true
    || provenance.requestedUrl !== expectedUrl || provenance.finalUrl !== expectedUrl
    || provenance.redirectChain.length !== 0 || provenance.hops.length !== 1) return false;
  const hop = provenance.hops[0];
  if (hop.url !== expectedUrl || hop.statusCode !== 200 || hop.dispatchIntent !== true
    || hop.responseReceived !== true || hop.bodyComplete !== true
    || hop.decodedBytes !== document.bytes?.byteLength || document.contentType !== 'image/svg+xml'
    || document.url !== expectedUrl || document.redirects !== 0 || !(document.bytes instanceof Uint8Array)) return false;
  return provenance.bodyHash === createHash('sha256').update(document.bytes).digest('hex');
}

/**
 * Trusted internal composition capability. The production private-retrieval
 * path mints this only after it has admitted and durably completed the exact
 * same-run transport. These helpers are not part of the package export map;
 * direct source imports are trusted server code. The store accepts the
 * original document object plus this non-copyable token, then asks the bound
 * verifier to re-check the frontier and pending receipt.
 */
export function createControlledSvgIngestWitness(document, binding, verify) {
  if (!isCompletedControlledSvgFetch(document, binding?.assetUrl) || typeof verify !== 'function') return null;
  let bindingJson;
  try { bindingJson = JSON.stringify(binding); } catch { return null; }
  if (typeof bindingJson !== 'string' || bindingJson.length > 32_768) return null;
  const witness = Object.freeze(Object.create(null));
  controlledSvgIngestWitnesses.set(witness, { document, bindingJson, verify });
  return witness;
}

export async function verifyControlledSvgIngestWitness(witness, document, binding, stage) {
  const entry = controlledSvgIngestWitnesses.get(witness);
  if (!entry || entry.document !== document || typeof stage !== 'string'
    || entry.bindingJson !== JSON.stringify(binding)
    || !isCompletedControlledSvgFetch(document, binding?.assetUrl)) return false;
  try { return await entry.verify(stage) === true; }
  catch { return false; }
}
