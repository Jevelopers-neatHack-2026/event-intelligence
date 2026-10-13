import { AsyncLocalStorage } from 'node:async_hooks';
import { types } from 'node:util';

const contexts = new AsyncLocalStorage();
const responses = new WeakMap();
const VALIDATOR_NAMES = new Set(['etag', 'last-modified']);

function validValue(name, value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) return false;
  if (name === 'etag') return /^(?:W\/)?"[\x21\x23-\x7e]*"$/.test(value);
  if (name !== 'last-modified' || !/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value)) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toUTCString() === value;
}

export function copyConditionalValidator(value) {
  if (!value || typeof value !== 'object' || types.isProxy(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  if (Reflect.ownKeys(value).length !== 2) return null;
  const name = Object.getOwnPropertyDescriptor(value, 'name');
  const content = Object.getOwnPropertyDescriptor(value, 'value');
  if (!name || !content || !Object.hasOwn(name, 'value') || !Object.hasOwn(content, 'value')
    || !VALIDATOR_NAMES.has(name.value) || !validValue(name.value, content.value)) return null;
  return Object.freeze({ name: name.value, value: content.value });
}

/** Bounded metadata from the native response, never an arbitrary request-header map. */
export function conditionalValidatorFromResponse(response) {
  const values = {};
  for (const name of VALIDATOR_NAMES) {
    const entries = response.headersDistinct[name];
    if (entries === undefined) continue;
    if (!Array.isArray(entries) || entries.length !== 1 || !validValue(name, entries[0])) return null;
    values[name] = entries[0];
  }
  const name = values.etag !== undefined ? 'etag' : values['last-modified'] !== undefined ? 'last-modified' : null;
  return name ? Object.freeze({ name, value: values[name] }) : null;
}

/** Trusted EI-local composition only; absent from the package export map. */
export function withConditionalFetch(fetcher, sourceUrl, validator, operation, intent) {
  const copied = copyConditionalValidator(validator);
  if (!fetcher || typeof fetcher !== 'object' || typeof sourceUrl !== 'string'
    || sourceUrl.length > 8_192 || !copied || typeof operation !== 'function') {
    throw new TypeError('private conditional retrieval unavailable');
  }
  return contexts.run(Object.freeze({ fetcher, sourceUrl, validator: copied, intent }), operation);
}

export function conditionalFetchFor(fetcher) {
  const context = contexts.getStore();
  return context?.fetcher === fetcher ? context : null;
}

export function conditionalRequestHeaders(context) {
  return Object.freeze({
    [context.validator.name === 'etag' ? 'if-none-match' : 'if-modified-since']: context.validator.value,
  });
}

/** Called only by the native controlled-fetch implementation. Copied results have no witness. */
export function recordConditionalResponse(result, input) {
  responses.set(result, Object.freeze({
    intent: input.intent,
    sourceUrl: input.sourceUrl,
    statusCode: input.statusCode,
    kind: input.kind,
    observedAt: input.observedAt,
    retrievedAt: input.retrievedAt ?? null,
    bodyHash: input.bodyHash ?? null,
    bodyHashDomain: 'safe-fetch-decoded-entity-bytes/v1',
    sentValidator: copyConditionalValidator(input.sentValidator),
    receivedValidator: copyConditionalValidator(input.receivedValidator),
    redirects: 0,
  }));
}

export function conditionalResponseProvenance(result) {
  return result && typeof result === 'object' ? responses.get(result) ?? null : null;
}
