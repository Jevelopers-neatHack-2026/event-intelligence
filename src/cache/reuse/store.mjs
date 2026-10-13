import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { chmod, lstat, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { types as utilTypes } from 'node:util';
import { isPrivacyBoundary } from '../../privacy/boundary.mjs';
import { isCorrectionCacheBindingCapability } from '../../review/history/cache-binding-capability.mjs';
import { beginLocalBoundary, localBoundaryEffectiveNow, monotonicTimestampNs } from '../../private/boundary-guard.mjs';
import { safeFetchProvenance } from '../../security/internal/fetch-lifecycle.mjs';
import { conditionalResponseProvenance } from '../../security/internal/conditional-fetch.mjs';
import { isCacheRevalidationError, isRevalidationContext, originalBodyHash, revalidationFail } from './revalidation-context.mjs';

const ERROR_MESSAGES = Object.freeze({
  REUSE_DENIED: 'reuse access denied',
  REUSE_INVALID: 'invalid reuse record',
  REUSE_NOT_FOUND: 'reuse record not found',
  REUSE_BUSY: 'reuse store is busy',
  REUSE_STORAGE: 'reuse storage operation failed',
  REUSE_INTEGRITY: 'reuse integrity check failed',
  REUSE_KEY_UNAVAILABLE: 'reuse encryption key unavailable',
  REUSE_CAPACITY: 'reuse storage capacity reached',
  REUSE_POLICY_UNAVAILABLE: 'trusted reuse policy unavailable',
});
const SCOPES = new WeakMap();
const LOCAL_QUEUES = new Map();
const CACHE_BINDING_PORTS = new WeakMap();
const REVALIDATION_PORTS = new WeakMap();
const PUBLIC_REVALIDATION_PORTS = new WeakMap();
const TRUSTED_ERRORS = new WeakSet();
const FACT_FIELDS = Object.freeze(['event_name', 'event_date', 'venue']);
const PRIVATE_FACT_FIELDS_BY_KIND = Object.freeze([...FACT_FIELDS, 'event_status']);
const PIN_FIELDS = Object.freeze(['schemaVersion', 'extractorVersion', 'questionSetVersion', 'policyHash', 'modelVersion']);
const IDENTITY_FIELDS = Object.freeze(['occurrenceId', 'entityId', 'editionId']);
const LINEAGE_FIELDS = new Set([
  'logicalOperationId', 'billableAttemptId', 'transportAttemptId', 'providerRequestId',
  'observationIds', 'usageEventIds', 'status',
]);
const PERMISSION_FIELDS = new Set(['reference', 'contentHash', 'version', 'use']);
const PRIVATE_FACT_FIELDS = new Set(['status', 'value', 'reason', 'supportRefs', 'candidates']);
const MAX_TIME = 8_640_000_000_000_000;
const MAX_INVALIDATION_RECORD_BYTES = 2_048;
const IS_PROXY = utilTypes.isProxy;
const ABORTED_GETTER = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_TAG_GETTER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, Symbol.toStringTag).get;
const TYPED_ARRAY_LENGTH_GETTER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'length').get;
const UINT8_ARRAY_SET = Uint8Array.prototype.set;

export class ScopedReuseError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES.REUSE_STORAGE);
    this.name = 'ScopedReuseError';
    this.code = Object.hasOwn(ERROR_MESSAGES, code) ? code : 'REUSE_STORAGE';
    TRUSTED_ERRORS.add(this);
  }
}

function fail(code) {
  const error = new ScopedReuseError(code);
  TRUSTED_ERRORS.add(error);
  throw error;
}

function opaque() {
  return Object.freeze(Object.create(null));
}

function record(value, allowed) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string' || !allowed.has(key))) return null;
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    return null;
  }
}

function safeArrayValues(value, maximum) {
  try {
    if (!Array.isArray(value)) fail('REUSE_INVALID');
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    const length = lengthDescriptor?.value;
    if (!lengthDescriptor || !Object.hasOwn(lengthDescriptor, 'value') || !Number.isSafeInteger(length)
      || length < 0 || length > maximum) fail('REUSE_INVALID');
    const keys = Reflect.ownKeys(value);
    if (keys.length !== length + 1 || !keys.includes('length')) fail('REUSE_INVALID');
    const values = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail('REUSE_INVALID');
      values.push(descriptor.value);
    }
    return values;
  } catch (error) {
    if (TRUSTED_ERRORS.has(error)) throw error;
    fail('REUSE_INVALID');
  }
}

function isWellFormed(value) {
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

function string(value, maximum = 512) {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum && isWellFormed(value);
}

function mac(key, value) {
  return createHmac('sha256', key).update(value).digest('hex');
}

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function timestamp(value) {
  if (!string(value, 64) || !Number.isFinite(Date.parse(value))) fail('REUSE_INVALID');
  return Date.parse(value);
}

function effectiveRetrievedAt(payload, observation) {
  if (Number.isSafeInteger(observation?.retrievedAtMs)
    && (observation.status !== 'body_changed' || observation.contentHash === payload.contentHash)) {
    return observation.retrievedAtMs;
  }
  return payload.retrievedAtMs;
}

function iso(value) {
  try { return new Date(value).toISOString(); } catch { fail('REUSE_INTEGRITY'); }
}

function signalAborted(signal) {
  if (signal === undefined) return false;
  try {
    if (IS_PROXY(signal)) fail('REUSE_INVALID');
    return ABORTED_GETTER.call(signal);
  } catch (error) {
    if (TRUSTED_ERRORS.has(error)) throw error;
    fail('REUSE_INVALID');
  }
}

function copyFacts(value, publicOnly = false) {
  const fields = publicOnly ? FACT_FIELDS : PRIVATE_FACT_FIELDS_BY_KIND;
  const allowed = new Set(fields);
  const input = record(value, allowed);
  if (!input || Object.keys(input).length === 0) fail('REUSE_INVALID');
  const output = Object.create(null);
  for (const field of fields) {
    if (!Object.hasOwn(input, field)) continue;
    const item = input[field];
    if (publicOnly) {
      if (!string(item, 180)) fail('REUSE_INVALID');
      if (field === 'event_date') {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(item) || Number.isNaN(Date.parse(`${item}T00:00:00Z`))
          || new Date(`${item}T00:00:00Z`).toISOString().slice(0, 10) !== item) fail('REUSE_INVALID');
      }
      output[field] = item;
      continue;
    }
    const fact = record(item, PRIVATE_FACT_FIELDS);
    if (!fact || !['sourced', 'inferred', 'customer_supplied', 'conflicting', 'missing'].includes(fact.status)) fail('REUSE_INVALID');
    const copy = Object.create(null);
    copy.status = fact.status;
    if (fact.value !== undefined) {
      if (!string(fact.value, 1000)) fail('REUSE_INVALID');
      copy.value = fact.value;
    }
    if (fact.reason !== undefined) {
      if (!string(fact.reason, 1000)) fail('REUSE_INVALID');
      copy.reason = fact.reason;
    }
    if (fact.supportRefs !== undefined) copy.supportRefs = boundedRefList(fact.supportRefs, 64);
    if (fact.status === 'conflicting' || (fact.status === 'customer_supplied' && fact.candidates !== undefined)) {
      if (fact.status === 'conflicting' && copy.value !== undefined) fail('REUSE_INVALID');
      const candidateValues = safeArrayValues(fact.candidates, 32);
      if ((fact.status === 'conflicting' && candidateValues.length < 2)
        || (fact.status === 'customer_supplied' && candidateValues.length < 1)) fail('REUSE_INVALID');
      const candidates = [];
      for (const candidateValue of candidateValues) {
        const candidate = record(candidateValue, new Set(['status', 'value', 'supportRefs']));
        if (!candidate || !['sourced', 'inferred', 'customer_supplied'].includes(candidate.status)
          || !string(candidate.value, 1000)) fail('REUSE_INVALID');
        candidates.push(freeze({ status: candidate.status, value: candidate.value, supportRefs: boundedRefList(candidate.supportRefs ?? [], 64) }));
      }
      copy.candidates = Object.freeze(candidates);
    } else if (fact.candidates !== undefined) fail('REUSE_INVALID');
    if (fact.status === 'missing' && copy.value !== undefined) fail('REUSE_INVALID');
    if (fact.status !== 'missing' && fact.status !== 'conflicting' && copy.value === undefined) fail('REUSE_INVALID');
    output[field] = freeze(copy);
  }
  if (Object.keys(output).length === 0) fail('REUSE_INVALID');
  return freeze(output);
}

function boundedRefList(value, maximum = 128) {
  const values = safeArrayValues(value, maximum);
  if (values.some((item) => !string(item, 512))) fail('REUSE_INVALID');
  return Object.freeze(values);
}

function identity(value) {
  const input = record(value, new Set(IDENTITY_FIELDS));
  if (!input || IDENTITY_FIELDS.some((field) => !string(input[field]))) fail('REUSE_INVALID');
  return freeze({ occurrenceId: input.occurrenceId, entityId: input.entityId, editionId: input.editionId });
}

function pins(value) {
  const input = record(value, new Set(PIN_FIELDS));
  if (!input || PIN_FIELDS.some((field) => !string(input[field]))) fail('REUSE_INVALID');
  if (!/^[a-f0-9]{64}$/.test(input.policyHash)) fail('REUSE_INVALID');
  return freeze({
    schemaVersion: input.schemaVersion,
    extractorVersion: input.extractorVersion,
    questionSetVersion: input.questionSetVersion,
    policyHash: input.policyHash,
    modelVersion: input.modelVersion,
  });
}

function hashValue(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail('REUSE_INVALID');
  return value;
}

function validatePermissions(value) {
  const values = safeArrayValues(value, 128);
  const output = [];
  for (const valueItem of values) {
    const permission = record(valueItem, PERMISSION_FIELDS);
    if (!permission || !string(permission.reference) || typeof permission.contentHash !== 'string' || !/^[a-f0-9]{64}$/.test(permission.contentHash)
      || !Number.isSafeInteger(permission.version) || permission.version < 1 || !string(permission.use, 80)) fail('REUSE_INVALID');
    output.push(freeze({
      reference: permission.reference,
      contentHash: permission.contentHash,
      version: permission.version,
      use: permission.use,
    }));
  }
  return Object.freeze(output);
}

function validateLineage(value) {
  const input = record(value, LINEAGE_FIELDS);
  if (!input) fail('REUSE_INVALID');
  const output = Object.create(null);
  for (const field of ['logicalOperationId', 'billableAttemptId', 'transportAttemptId', 'providerRequestId']) {
    if (input[field] !== undefined && input[field] !== null) {
      if (!string(input[field], 512)) fail('REUSE_INVALID');
      output[field] = input[field];
    }
  }
  for (const field of ['observationIds', 'usageEventIds']) {
    if (input[field] !== undefined) output[field] = boundedRefList(input[field]);
  }
  output.status = input.status === 'complete'
    && typeof output.logicalOperationId === 'string'
    && typeof output.billableAttemptId === 'string'
    && ((output.transportAttemptId && output.transportAttemptId.length > 0) || (output.providerRequestId && output.providerRequestId.length > 0))
    && Array.isArray(output.usageEventIds) && output.usageEventIds.length > 0
    ? 'complete'
    : 'unknown';
  return freeze(output);
}

function copyIndex(input) {
  const parsedIdentity = identity(input.identity);
  const parsedPins = pins(input.pins);
  const contentHash = hashValue(input.contentHash);
  return { identity: parsedIdentity, pins: parsedPins, contentHash };
}

function safeError(error) {
  if (isCacheRevalidationError(error)) return error;
  if (error && (typeof error === 'object' || typeof error === 'function') && TRUSTED_ERRORS.has(error)) return error;
  try {
    const errcode = Object.getOwnPropertyDescriptor(error, 'errcode')?.value;
    const code = Object.getOwnPropertyDescriptor(error, 'code')?.value;
    if (code === 'REVIEW_BUSY') return new ScopedReuseError('REUSE_BUSY');
    if (code === 'REVIEW_ABORTED') return new ScopedReuseError('REUSE_DENIED');
    if (errcode === 5 || errcode === 6 || code === 'ERR_SQLITE_BUSY') return new ScopedReuseError('REUSE_BUSY');
  } catch { /* Return a generic error without consulting caller properties. */ }
  return new ScopedReuseError('REUSE_STORAGE');
}

function publicBoundary(operation) {
  return async (...args) => {
    try {
      return await operation(...args);
    } catch (error) {
      if (error && (typeof error === 'object' || typeof error === 'function') && TRUSTED_ERRORS.has(error)) throw error;
      fail('REUSE_INVALID');
    }
  };
}

async function withLocalQueue(key, operation) {
  const previous = LOCAL_QUEUES.get(key) ?? Promise.resolve();
  let release;
  const current = new Promise((resolve) => { release = resolve; });
  LOCAL_QUEUES.set(key, current);
  await previous.catch(() => {});
  try { return await operation(); } finally {
    release();
    if (LOCAL_QUEUES.get(key) === current) LOCAL_QUEUES.delete(key);
  }
}

export function createScopedReuseStore(options) {
  const config = record(options, new Set([
    'directory', 'resolveTenant', 'resolveActor', 'authorizeAction', 'authorizeCurrentRequest', 'authorizeBoundary', 'resolveKey', 'resolveRetention',
    'verifySourceObservation', 'verifyAdmissionOutcome', 'authorizePublicPublication', 'resolvePrivateProfileReferences', 'verifyPermission', 'resolveLineage', 'consumeOriginalLineage',
    'resolveInvalidationConsumers', 'deliverInvalidation', 'verifyInvalidationAcknowledgement',
    'now', 'maxEntryBytes', 'maxEntries', 'maxFlights', 'maxPrivateLinks', 'maxObservationsPerEntry', 'maxOutboxEntries',
    'maxOutboxAttempts', 'maxRetentionMs', 'lockTimeoutMs', 'defaultFreshnessTtlMs', 'maxStoreBytes',
  ]));
  if (!config || !string(config.directory, 4096) || typeof config.resolveTenant !== 'function'
    || typeof config.resolveActor !== 'function' || typeof config.authorizeAction !== 'function'
    || typeof config.authorizeCurrentRequest !== 'function'
    || typeof config.resolveKey !== 'function' || typeof config.resolveRetention !== 'function') fail('REUSE_INVALID');
  for (const name of ['authorizeBoundary', 'verifySourceObservation', 'verifyAdmissionOutcome', 'authorizePublicPublication', 'resolvePrivateProfileReferences', 'verifyPermission', 'resolveLineage', 'consumeOriginalLineage', 'resolveInvalidationConsumers', 'deliverInvalidation', 'verifyInvalidationAcknowledgement']) {
    if (config[name] !== undefined && typeof config[name] !== 'function') fail('REUSE_INVALID');
  }
  const limits = {
    now: config.now ?? (() => Date.now()),
    maxEntryBytes: config.maxEntryBytes ?? 128 * 1024,
    maxEntries: config.maxEntries ?? 2000,
    maxFlights: config.maxFlights ?? 5000,
    maxPrivateLinks: config.maxPrivateLinks ?? 5000,
    maxObservationsPerEntry: config.maxObservationsPerEntry ?? 128,
    maxOutboxEntries: config.maxOutboxEntries ?? 10_000,
    maxOutboxAttempts: config.maxOutboxAttempts ?? 8,
    maxRetentionMs: config.maxRetentionMs ?? 30 * 24 * 60 * 60 * 1000,
    lockTimeoutMs: config.lockTimeoutMs ?? 5_000,
    defaultFreshnessTtlMs: config.defaultFreshnessTtlMs ?? 24 * 60 * 60 * 1000,
    maxStoreBytes: config.maxStoreBytes ?? 512 * 1024 * 1024,
  };
  if (typeof limits.now !== 'function' || limits.maxEntryBytes < MAX_INVALIDATION_RECORD_BYTES) fail('REUSE_INVALID');
  for (const [key, value] of Object.entries(limits)) {
    if (key !== 'now' && (!Number.isSafeInteger(value) || value <= 0)) fail('REUSE_INVALID');
  }
  const rootDirectory = path.resolve(config.directory);
  const storeAuthority = Object.freeze(Object.create(null));
  const boundProfilePreflights = new WeakMap();
  const boundFinalDisclosures = new WeakMap();

  function currentTime() {
    let value;
    try { value = limits.now(); } catch { fail('REUSE_STORAGE'); }
    if (!Number.isSafeInteger(value) || value < 0 || value > MAX_TIME) fail('REUSE_STORAGE');
    return value;
  }

  function boundaryInput(info, request, eventId, action, details = {}, field = null) {
    return Object.freeze({ request, tenantId: info.tenantId, actorId: info.actorId,
      eventId, action, field, details: Object.freeze({ ...details }) });
  }

  async function authenticatedScope(request) {
    const { tenantId, actorId } = await resolvePrincipal(request);
    const scope = opaque();
    SCOPES.set(scope, Object.freeze({ tenantId, actorId, storeAuthority }));
    return scope;
  }

  async function resolvePrincipal(request) {
    let tenantId;
    let actorId;
    let confirmedTenantId;
    let confirmedActorId;
    try {
      tenantId = await config.resolveTenant(request);
      actorId = await config.resolveActor(request);
      confirmedTenantId = await config.resolveTenant(request);
      confirmedActorId = await config.resolveActor(request);
    } catch { fail('REUSE_DENIED'); }
    if (!string(tenantId, 256) || !string(actorId, 256)
      || tenantId !== confirmedTenantId || actorId !== confirmedActorId) fail('REUSE_DENIED');
    return { tenantId, actorId };
  }

  function scopeInfo(scope) {
    const info = SCOPES.get(scope);
    if (!info || info.storeAuthority !== storeAuthority) fail('REUSE_DENIED');
    return info;
  }

  async function authorize(info, request, action, details = {}) {
    const before = await resolvePrincipal(request);
    if (before.tenantId !== info.tenantId || before.actorId !== info.actorId) fail('REUSE_DENIED');
    let allowed = false;
    try {
      allowed = (await config.authorizeAction(Object.freeze({
        tenantId: before.tenantId,
        actorId: before.actorId,
        action,
        request,
        details: Object.freeze({ ...details }),
      }))) === true;
    } catch { fail('REUSE_DENIED'); }
    if (!allowed) fail('REUSE_DENIED');
    const after = await resolvePrincipal(request);
    if (after.tenantId !== info.tenantId || after.actorId !== info.actorId) fail('REUSE_DENIED');
  }

  async function authorizeCurrentRequest(info, request, action, details = {}) {
    let allowed = false;
    try {
      allowed = (await config.authorizeCurrentRequest(Object.freeze({
        expectedTenantId: info.tenantId,
        expectedActorId: info.actorId,
        action,
        request,
        details: Object.freeze({ ...details }),
      }))) === true;
    } catch { fail('REUSE_DENIED'); }
    if (!allowed) fail('REUSE_DENIED');
  }

  function authorizationGuard(info, request, action, signal) {
    return async () => {
      await authorize(info, request, action);
      if (signalAborted(signal)) fail('REUSE_DENIED');
    };
  }

  async function resolveKey(info, purpose, keyId, guard) {
    try {
      const raw = await config.resolveKey(Object.freeze({
        tenantId: info?.tenantId ?? null,
        scope: info ? 'tenant_private' : 'public_profile',
        purpose,
        ...(keyId ? { keyId } : {}),
      }));
      if (guard) await guard();
      // Read the key holder's own data slots; never invoke caller supplied getters.
      let resolvedKeyId;
      let resolvedKey;
      try {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('REUSE_KEY_UNAVAILABLE');
        const ownKeys = Reflect.ownKeys(raw);
        if (ownKeys.length !== 2 || ownKeys.some((key) => !['keyId', 'key'].includes(key))) fail('REUSE_KEY_UNAVAILABLE');
        const idDescriptor = Object.getOwnPropertyDescriptor(raw, 'keyId');
        const keyDescriptor = Object.getOwnPropertyDescriptor(raw, 'key');
        if (!idDescriptor || !Object.hasOwn(idDescriptor, 'value') || !keyDescriptor || !Object.hasOwn(keyDescriptor, 'value')) fail('REUSE_KEY_UNAVAILABLE');
        resolvedKeyId = idDescriptor.value;
        resolvedKey = keyDescriptor.value;
      } catch { fail('REUSE_KEY_UNAVAILABLE'); }
      let length;
      try {
        if (TYPED_ARRAY_TAG_GETTER.call(resolvedKey) !== 'Uint8Array') fail('REUSE_KEY_UNAVAILABLE');
        length = TYPED_ARRAY_LENGTH_GETTER.call(resolvedKey);
      } catch { fail('REUSE_KEY_UNAVAILABLE'); }
      if (!string(resolvedKeyId, 128) || length !== 32 || (keyId && resolvedKeyId !== keyId)) fail('REUSE_KEY_UNAVAILABLE');
      const keyCopy = new Uint8Array(32);
      try { UINT8_ARRAY_SET.call(keyCopy, resolvedKey); } catch { fail('REUSE_KEY_UNAVAILABLE'); }
      return { keyId: resolvedKeyId, key: Buffer.from(keyCopy) };
    } catch (error) {
      if (error && (typeof error === 'object' || typeof error === 'function') && TRUSTED_ERRORS.has(error)) throw error;
      fail('REUSE_KEY_UNAVAILABLE');
    }
  }

  async function indexInfo(info, scopeKind, guard) {
    const indexInfoValue = scopeKind === 'public_profile' ? null : info;
    const keyInfo = await resolveKey(indexInfoValue, 'index', undefined, guard);
    const tenantPart = indexInfoValue ? mac(keyInfo.key, `tenant:${indexInfoValue.tenantId}`) : 'public-profile-v1';
    return { keyInfo, partitionHash: tenantPart, scopeKind };
  }

  function seal(key, keyId, partitionHash, kind, id, value) {
    try {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(Buffer.from(`event-intelligence:scoped-reuse:v1:${kind}:${partitionHash}:${id}:${keyId}`, 'utf8'));
      const plaintext = Buffer.from(stable(value), 'utf8');
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      return Buffer.from(JSON.stringify({ version: 1, keyId, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') }), 'utf8');
    } catch { fail('REUSE_STORAGE'); }
  }

  function sealBounded(key, keyId, partitionHash, kind, id, value, maximum = limits.maxEntryBytes) {
    const sealed = seal(key, keyId, partitionHash, kind, id, value);
    if (sealed.byteLength > maximum) fail('REUSE_CAPACITY');
    return sealed;
  }

  function unseal(key, partitionHash, kind, id, bytes, expectedKeyId) {
    if (!bytes || !Number.isSafeInteger(bytes.byteLength) || bytes.byteLength > limits.maxEntryBytes) fail('REUSE_INTEGRITY');
    let envelope;
    try { envelope = JSON.parse(Buffer.from(bytes).toString('utf8')); } catch { fail('REUSE_INTEGRITY'); }
    if (!envelope || envelope.version !== 1 || typeof envelope.keyId !== 'string' || (expectedKeyId && envelope.keyId !== expectedKeyId)
      || typeof envelope.iv !== 'string' || typeof envelope.tag !== 'string' || typeof envelope.ciphertext !== 'string') fail('REUSE_INTEGRITY');
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
      decipher.setAAD(Buffer.from(`event-intelligence:scoped-reuse:v1:${kind}:${partitionHash}:${id}:${envelope.keyId}`, 'utf8'));
      decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
      const plain = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
      return JSON.parse(plain.toString('utf8'));
    } catch { fail('REUSE_INTEGRITY'); }
  }

  async function openStoreDatabase(timeoutMs = limits.lockTimeoutMs) {
    let database;
    try {
      await mkdir(rootDirectory, { recursive: true, mode: 0o700 });
      const rootStats = await lstat(rootDirectory);
      if (rootStats.isSymbolicLink() || !rootStats.isDirectory()) fail('REUSE_STORAGE');
      await chmod(rootDirectory, 0o700);
      const databasePath = path.join(rootDirectory, 'scoped-reuse.sqlite');
      let prior = null;
      try {
        prior = await lstat(databasePath);
        if (prior.isSymbolicLink() || !prior.isFile()) fail('REUSE_STORAGE');
      } catch (error) { if (error?.code !== 'ENOENT') throw error; }
      database = new DatabaseSync(databasePath, { timeout: timeoutMs });
      if (timeoutMs === 0) database.exec('PRAGMA busy_timeout = 0');
      const opened = await lstat(databasePath);
      if (opened.isSymbolicLink() || !opened.isFile() || (prior && (opened.dev !== prior.dev || opened.ino !== prior.ino))) fail('REUSE_STORAGE');
      database.exec(`
          PRAGMA journal_mode = DELETE;
          PRAGMA synchronous = FULL;
          PRAGMA secure_delete = ON;
          PRAGMA trusted_schema = OFF;
          CREATE TABLE IF NOT EXISTS reuse_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL) STRICT;
          CREATE TABLE IF NOT EXISTS reuse_entries (
            entry_id TEXT PRIMARY KEY NOT NULL,
            scope_kind TEXT NOT NULL CHECK (scope_kind IN ('tenant_private', 'public_profile')),
            partition_hash TEXT NOT NULL,
            identity_hash TEXT NOT NULL,
            cache_key_hash TEXT NOT NULL,
            content_hash_mac TEXT NOT NULL,
            pins_hash TEXT NOT NULL,
            version INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            eligible INTEGER NOT NULL CHECK (eligible IN (0, 1)),
            payload_key_id TEXT NOT NULL,
            payload BLOB NOT NULL,
            payload_bytes INTEGER NOT NULL,
            payload_purged INTEGER NOT NULL DEFAULT 0 CHECK (payload_purged IN (0, 1)),
            binding_hash TEXT
          ) STRICT;
          CREATE INDEX IF NOT EXISTS reuse_lookup ON reuse_entries (scope_kind, partition_hash, cache_key_hash, eligible, version DESC);
          CREATE INDEX IF NOT EXISTS reuse_identity ON reuse_entries (scope_kind, partition_hash, identity_hash, eligible);
          CREATE TABLE IF NOT EXISTS reuse_observations (
            observation_id TEXT PRIMARY KEY NOT NULL,
            entry_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            observed_at_ms INTEGER NOT NULL,
            status TEXT NOT NULL,
            payload_key_id TEXT NOT NULL,
            payload BLOB NOT NULL,
            UNIQUE(entry_id, sequence)
          ) STRICT;
          CREATE INDEX IF NOT EXISTS reuse_observation_latest ON reuse_observations (entry_id, sequence DESC);
          CREATE TABLE IF NOT EXISTS reuse_refresh_sources (
            entry_id TEXT PRIMARY KEY NOT NULL,
            partition_hash TEXT NOT NULL,
            version INTEGER NOT NULL,
            payload_key_id TEXT NOT NULL,
            payload BLOB NOT NULL
          ) STRICT;
          CREATE TABLE IF NOT EXISTS reuse_private_links (
            link_id TEXT PRIMARY KEY NOT NULL,
            tenant_partition_hash TEXT NOT NULL,
            public_entry_id TEXT NOT NULL,
            payload_key_id TEXT NOT NULL,
            payload BLOB NOT NULL,
            UNIQUE (tenant_partition_hash, public_entry_id)
          ) STRICT;
          CREATE INDEX IF NOT EXISTS reuse_private_link_lookup ON reuse_private_links (tenant_partition_hash, public_entry_id);
          CREATE TABLE IF NOT EXISTS reuse_public_refresh_sources (
            entry_id TEXT NOT NULL,
            tenant_partition_hash TEXT NOT NULL,
            link_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            payload_key_id TEXT NOT NULL,
            payload BLOB NOT NULL,
            payload_purged INTEGER NOT NULL DEFAULT 0 CHECK (payload_purged IN (0, 1)),
            PRIMARY KEY (entry_id, tenant_partition_hash)
          ) STRICT;
          CREATE TABLE IF NOT EXISTS reuse_public_refresh_responses (
            response_id TEXT PRIMARY KEY NOT NULL,
            entry_id TEXT NOT NULL,
            tenant_partition_hash TEXT NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            payload_key_id TEXT NOT NULL,
            payload BLOB NOT NULL
          ) STRICT;
          CREATE INDEX IF NOT EXISTS reuse_public_refresh_response_entry ON reuse_public_refresh_responses (entry_id, tenant_partition_hash);
          -- Cleanup also applies to an already-open older store writer. These
          -- triggers use the original schema's columns, before payload_purged
          -- is migrated. They remove private material, not grant public mutation.
          CREATE TRIGGER IF NOT EXISTS reuse_public_refresh_entry_cleanup
          AFTER UPDATE OF eligible, payload ON reuse_entries
          WHEN NEW.eligible = 0 OR length(NEW.payload) = 0
          BEGIN
            DELETE FROM reuse_public_refresh_sources WHERE entry_id = NEW.entry_id;
            DELETE FROM reuse_public_refresh_responses WHERE entry_id = NEW.entry_id;
          END;
          CREATE TRIGGER IF NOT EXISTS reuse_public_refresh_link_cleanup
          AFTER DELETE ON reuse_private_links
          BEGIN
            DELETE FROM reuse_public_refresh_sources WHERE link_id = OLD.link_id;
            DELETE FROM reuse_public_refresh_responses WHERE entry_id = OLD.public_entry_id AND tenant_partition_hash = OLD.tenant_partition_hash;
          END;
          CREATE TABLE IF NOT EXISTS reuse_consumer_refs (
            entry_id TEXT NOT NULL,
            scope_kind TEXT NOT NULL,
            partition_hash TEXT NOT NULL,
            consumer_hash TEXT NOT NULL,
            payload_key_id TEXT NOT NULL,
            payload BLOB NOT NULL,
            PRIMARY KEY (entry_id, consumer_hash)
          ) STRICT;
          CREATE TABLE IF NOT EXISTS reuse_flights (
            flight_key TEXT PRIMARY KEY NOT NULL,
            scope_kind TEXT NOT NULL,
            partition_hash TEXT NOT NULL,
            admission_id TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('active', 'unknown', 'completed', 'not_dispatched')),
            created_at_ms INTEGER NOT NULL,
            lease_expires_at_ms INTEGER NOT NULL,
            payload_key_id TEXT NOT NULL,
            payload BLOB NOT NULL
          ) STRICT;
          CREATE TABLE IF NOT EXISTS reuse_outbox (
            event_id TEXT PRIMARY KEY NOT NULL,
            entry_id TEXT NOT NULL,
            scope_kind TEXT NOT NULL,
            partition_hash TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('pending', 'delivering', 'failed', 'delivered')),
            attempt_count INTEGER NOT NULL,
            next_attempt_at_ms INTEGER NOT NULL,
            has_consumer INTEGER NOT NULL DEFAULT 1 CHECK (has_consumer IN (0, 1)),
            active_attempt_id TEXT,
            payload_key_id TEXT NOT NULL,
            payload BLOB NOT NULL,
            payload_bytes INTEGER NOT NULL
          ) STRICT;
          CREATE INDEX IF NOT EXISTS reuse_outbox_pending ON reuse_outbox (scope_kind, partition_hash, status, next_attempt_at_ms);
          CREATE TABLE IF NOT EXISTS reuse_correction_reservations (
            entry_id TEXT PRIMARY KEY NOT NULL,
            scope_kind TEXT NOT NULL CHECK (scope_kind = 'tenant_private'),
            partition_hash TEXT NOT NULL,
            binding_hash TEXT NOT NULL,
            outbox_slots INTEGER NOT NULL CHECK (outbox_slots >= 1),
            payload_key_id TEXT NOT NULL,
            payload BLOB NOT NULL,
            payload_bytes INTEGER NOT NULL
          ) STRICT;
          CREATE TABLE IF NOT EXISTS reuse_history_invalidation_ops (
            operation_id TEXT NOT NULL,
            entry_id TEXT NOT NULL,
            partition_hash TEXT NOT NULL,
            binding_hash TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            event_ids TEXT NOT NULL,
            PRIMARY KEY (operation_id, entry_id)
          ) STRICT;
          CREATE TABLE IF NOT EXISTS reuse_bound_writes (
            operation_id TEXT PRIMARY KEY NOT NULL,
            partition_hash TEXT NOT NULL,
            binding_hash TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            entry_id TEXT NOT NULL,
            version INTEGER NOT NULL
          ) STRICT;
      `);
      const outboxColumns = database.prepare('PRAGMA table_info(reuse_outbox)').all();
      if (!outboxColumns.some((column) => column.name === 'active_attempt_id')) {
        database.exec('ALTER TABLE reuse_outbox ADD COLUMN active_attempt_id TEXT');
      }
      if (!outboxColumns.some((column) => column.name === 'has_consumer')) {
        database.exec('ALTER TABLE reuse_outbox ADD COLUMN has_consumer INTEGER NOT NULL DEFAULT 1 CHECK (has_consumer IN (0, 1))');
      }
      const entryColumns = database.prepare('PRAGMA table_info(reuse_entries)').all();
      if (!entryColumns.some((column) => column.name === 'payload_purged')) {
        database.exec('ALTER TABLE reuse_entries ADD COLUMN payload_purged INTEGER NOT NULL DEFAULT 0 CHECK (payload_purged IN (0, 1))');
      }
      if (!entryColumns.some((column) => column.name === 'binding_hash')) {
        database.exec('ALTER TABLE reuse_entries ADD COLUMN binding_hash TEXT');
      }
      database.exec('CREATE INDEX IF NOT EXISTS reuse_binding ON reuse_entries (scope_kind, partition_hash, binding_hash, eligible)');
      await chmod(databasePath, 0o600);
      return database;
    } catch (error) {
      database?.close();
      throw safeError(error);
    }
  }

  async function prepareStoreDatabase() {
    return withLocalQueue(rootDirectory, openStoreDatabase);
  }

  async function withDatabase(operation) {
    return withLocalQueue(rootDirectory, async () => {
      let database;
      let transactionOpen = false;
      try {
        database = await openStoreDatabase();
        // The injected clock is host code; evaluate it before SQLite owns its writer lock.
        const now = currentTime();
        database.exec('BEGIN IMMEDIATE');
        transactionOpen = true;
        const currentMax = database.prepare("SELECT value FROM reuse_meta WHERE key = 'clock_max_ms'").get();
        const previousMax = currentMax ? Number(currentMax.value) : null;
        if (currentMax && (!Number.isSafeInteger(previousMax) || previousMax < 0 || previousMax > MAX_TIME)) fail('REUSE_INTEGRITY');
        const clockRollback = Boolean(currentMax && now < previousMax);
        if (!clockRollback && (!currentMax || now > previousMax)) {
          database.prepare("INSERT INTO reuse_meta (key, value) VALUES ('clock_max_ms', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(String(now));
        }
        const result = operation(database, { now, clockRollback });
        database.exec('COMMIT');
        transactionOpen = false;
        return result;
      } catch (error) {
        if (transactionOpen) {
          try { database.exec('ROLLBACK'); } catch { /* SQLite also rolls back when the connection closes. */ }
        }
        throw safeError(error);
      } finally {
        database?.close();
      }
    });
  }

  async function withBindingDatabase(gate, operation, signal = undefined, boundary = undefined) {
    const delays = [2, 4, 8, 12, 20, 30, 40];
    const startedAt = monotonicTimestampNs();
    for (let attempt = 0; ; attempt += 1) {
      if (signalAborted(signal)) fail('REUSE_DENIED');
      try {
        return await withLocalQueue(rootDirectory, async () => {
          let database;
          let transactionOpen = false;
          try {
            database = await openStoreDatabase(0);
            // The synchronous host decision runs after every async/filesystem preparation
            // and before either paired SQLite writer is acquired.
            const boundaryToken = boundary
              ? beginLocalBoundary(config.authorizeBoundary, boundary.input, () => fail('REUSE_DENIED'))
              : null;
            boundary?.check?.();
            const now = boundaryToken?.nowMs ?? currentTime();
            const effectiveNow = boundaryToken ? localBoundaryEffectiveNow(boundaryToken) : now;
            if (!Number.isSafeInteger(effectiveNow) || effectiveNow < now || effectiveNow > MAX_TIME
              || (boundary?.mustBeBeforeMs !== undefined && effectiveNow >= boundary.mustBeBeforeMs)) fail('REUSE_DENIED');
            if (signalAborted(signal)) fail('REUSE_DENIED');
            try {
              return gate(() => {
                database.exec('BEGIN IMMEDIATE');
                transactionOpen = true;
                const currentMax = database.prepare("SELECT value FROM reuse_meta WHERE key = 'clock_max_ms'").get();
                const previousMax = currentMax ? Number(currentMax.value) : null;
                if (currentMax && (!Number.isSafeInteger(previousMax) || previousMax < 0 || previousMax > MAX_TIME)) fail('REUSE_INTEGRITY');
                const clockRollback = Boolean(currentMax && now < previousMax);
                if (clockRollback) fail('REUSE_DENIED');
                if (!currentMax || now > previousMax) {
                  database.prepare("INSERT INTO reuse_meta (key, value) VALUES ('clock_max_ms', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
                    .run(String(now));
                }
                const result = operation(database, { now, effectiveNow, clockRollback });
                if (result && typeof result.then === 'function') fail('REUSE_STORAGE');
                if (signalAborted(signal)) fail('REUSE_DENIED');
                if (boundaryToken) {
                  const effectiveCommitNow = localBoundaryEffectiveNow(boundaryToken);
                  if (!Number.isSafeInteger(effectiveCommitNow) || effectiveCommitNow < now
                    || effectiveCommitNow > MAX_TIME
                    || (boundary?.mustBeBeforeMs !== undefined && effectiveCommitNow >= boundary.mustBeBeforeMs)) fail('REUSE_DENIED');
                }
                boundary?.check?.();
                database.exec('COMMIT');
                transactionOpen = false;
                return result;
              }, Object.freeze({ now, effectiveNow, boundaryToken }));
            } catch (error) {
              // The private history participant fence may rethrow a cache error after
              // rolling back its paired transaction. Recreate only the fixed cache
              // error vocabulary here so the cache module's private trust set retains
              // the intended denial/capacity semantics.
              try {
                if (error && !IS_PROXY(error)) {
                  const name = Object.getOwnPropertyDescriptor(error, 'name')?.value;
                  const code = Object.getOwnPropertyDescriptor(error, 'code')?.value;
                  if (name === 'ScopedReuseError' && typeof code === 'string'
                    && ['REUSE_DENIED', 'REUSE_INVALID', 'REUSE_NOT_FOUND', 'REUSE_BUSY', 'REUSE_STORAGE',
                      'REUSE_INTEGRITY', 'REUSE_KEY_UNAVAILABLE', 'REUSE_CAPACITY', 'REUSE_POLICY_UNAVAILABLE'].includes(code)) {
                    throw new ScopedReuseError(code);
                  }
                }
              } catch (mapped) {
                if (mapped instanceof ScopedReuseError && TRUSTED_ERRORS.has(mapped)) throw mapped;
                throw error;
              }
              throw error;
            }
          } catch (error) {
            if (transactionOpen) {
              try { database.exec('ROLLBACK'); } catch { /* Closing the connection also rolls back. */ }
            }
            throw safeError(error);
          } finally {
            database?.close();
          }
        });
      } catch (error) {
        const safe = safeError(error);
        if (safe.code !== 'REUSE_BUSY' || attempt >= delays.length || signalAborted(signal)) throw safe;
        const elapsed = monotonicTimestampNs() - startedAt;
        const remaining = limits.lockTimeoutMs - Number((elapsed + 999_999n) / 1_000_000n);
        if (remaining <= 0) throw safe;
        await new Promise((resolve) => setTimeout(resolve, Math.min(delays[attempt], remaining)));
      }
    }
  }

  async function withBindingRead(operation) {
    let database;
    let transactionOpen = false;
    try {
      database = await openStoreDatabase(0);
      // As with writes, the injected clock must run before entering SQLite.
      const now = currentTime();
      database.exec('BEGIN');
      transactionOpen = true;
      const currentMax = database.prepare("SELECT value FROM reuse_meta WHERE key = 'clock_max_ms'").get();
      const previousMax = currentMax ? Number(currentMax.value) : null;
      if (currentMax && (!Number.isSafeInteger(previousMax) || previousMax < 0 || previousMax > MAX_TIME)) fail('REUSE_INTEGRITY');
      const clockRollback = Boolean(currentMax && now < previousMax);
      const result = operation(database, { now, clockRollback });
      if (result && typeof result.then === 'function') fail('REUSE_STORAGE');
      database.exec('COMMIT');
      transactionOpen = false;
      return result;
    } catch (error) {
      if (transactionOpen) {
        try { database.exec('ROLLBACK'); } catch { /* Closing the connection also rolls back. */ }
      }
      throw safeError(error);
    } finally {
      database?.close();
    }
  }

  async function prepareBindingDatabase() {
    return openStoreDatabase(0);
  }

  function usedPayloadBytes(database) {
    return database.prepare(`
      SELECT
        (SELECT COALESCE(SUM(payload_bytes), 0) FROM reuse_entries) +
        (SELECT COALESCE(SUM(length(payload)), 0) FROM reuse_observations) +
        (SELECT COALESCE(SUM(length(payload)), 0) FROM reuse_refresh_sources) +
        (SELECT COALESCE(SUM(length(payload)), 0) FROM reuse_public_refresh_sources) +
        (SELECT COALESCE(SUM(length(payload)), 0) FROM reuse_public_refresh_responses) +
        (SELECT COALESCE(SUM(length(payload)), 0) FROM reuse_private_links) +
        (SELECT COALESCE(SUM(length(payload)), 0) FROM reuse_consumer_refs) +
        (SELECT COALESCE(SUM(length(payload)), 0) FROM reuse_flights) +
        (SELECT COALESCE(SUM(payload_bytes), 0) FROM reuse_correction_reservations) +
        (SELECT COALESCE(SUM(payload_bytes), 0) FROM reuse_outbox) AS total
    `).get().total;
  }

  function reservationState(database) {
    const eligibleEntries = database.prepare('SELECT entry_id FROM reuse_entries WHERE eligible = 1').all();
    let reserved = 0;
    for (const entry of eligibleEntries) {
      const refs = database.prepare('SELECT COUNT(*) AS count FROM reuse_consumer_refs WHERE entry_id = ?').get(entry.entry_id).count;
      reserved += Math.max(1, refs);
    }
    const correctionReservations = database.prepare('SELECT COALESCE(SUM(outbox_slots), 0) AS count FROM reuse_correction_reservations').get().count;
    return reserved + correctionReservations;
  }

  function reservedOutboxGrowthBytes(database) {
    const pendingGrowth = database.prepare(`SELECT COALESCE(SUM(MAX(0, ? - payload_bytes)), 0) AS bytes
      FROM reuse_outbox WHERE has_consumer = 1 AND status IN ('pending', 'delivering') AND attempt_count < ?`)
      .get(MAX_INVALIDATION_RECORD_BYTES, limits.maxOutboxAttempts).bytes;
    return pendingGrowth;
  }

  function ensureStorageCapacity(database, newBytes, replacedBytes = 0, additionalReservations = 0, additionalOutboxGrowth = 0, outboxGrowthCredit = 0) {
    const used = usedPayloadBytes(database);
    const reserved = reservationState(database) + additionalReservations;
    const retryGrowth = Math.max(0, reservedOutboxGrowthBytes(database) + additionalOutboxGrowth - outboxGrowthCredit);
    const outboxCount = database.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count;
    if (outboxCount + reserved > limits.maxOutboxEntries
      || used - replacedBytes + newBytes + reserved * MAX_INVALIDATION_RECORD_BYTES + retryGrowth > limits.maxStoreBytes) fail('REUSE_CAPACITY');
  }

  function assertOutboxHeadroom(database, additionalReservations = 0) {
    const reserved = reservationState(database);
    const outboxCount = database.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count;
    const totalReserved = reserved + additionalReservations;
    if (outboxCount + totalReserved > limits.maxOutboxEntries
      || usedPayloadBytes(database) + totalReserved * MAX_INVALIDATION_RECORD_BYTES + reservedOutboxGrowthBytes(database) > limits.maxStoreBytes) fail('REUSE_CAPACITY');
  }

  async function resolveRetention(info, kind, nowMs, requestedExpiry = null) {
    let result;
    try {
      result = await config.resolveRetention(Object.freeze({
        tenantId: info?.tenantId ?? null,
        kind,
        nowMs,
        requestedExpiryMs: requestedExpiry,
      }));
    } catch { fail('REUSE_POLICY_UNAVAILABLE'); }
    const decision = record(result, new Set(['expiresAtMs', 'policyId', 'policyVersion']));
    if (!decision || !Number.isSafeInteger(decision.expiresAtMs) || decision.expiresAtMs <= nowMs
      || decision.expiresAtMs - nowMs > limits.maxRetentionMs || !string(decision.policyId, 128)
      || !string(decision.policyVersion, 128)) fail('REUSE_POLICY_UNAVAILABLE');
    if (requestedExpiry !== null && decision.expiresAtMs > requestedExpiry) fail('REUSE_POLICY_UNAVAILABLE');
    return Object.freeze({ expiresAtMs: decision.expiresAtMs, policyId: decision.policyId, policyVersion: decision.policyVersion });
  }

  async function verifyObservation(info, request, expectedHash, rawObservation, purpose) {
    if (typeof config.verifySourceObservation !== 'function') fail('REUSE_POLICY_UNAVAILABLE');
    let result;
    try {
      result = await config.verifySourceObservation(Object.freeze({
        tenantId: info?.tenantId ?? null,
        actorId: info?.actorId ?? null,
        request,
        purpose,
        expectedContentHash: expectedHash,
        observation: rawObservation,
      }));
    } catch { fail('REUSE_POLICY_UNAVAILABLE'); }
    const parsed = record(result, new Set(['status', 'contentHash', 'retrievedAt', 'validatedAt', 'sourceVersion', 'attemptLineage']));
    if (!parsed || !['body_changed', 'not_modified', 'removed', 'outage', 'evidence_lost'].includes(parsed.status)
      || (parsed.sourceVersion !== undefined && parsed.sourceVersion !== null && !string(parsed.sourceVersion, 128))) fail('REUSE_POLICY_UNAVAILABLE');
    if (parsed.status === 'body_changed' || parsed.status === 'not_modified') {
      if (typeof parsed.contentHash !== 'string' || !/^[a-f0-9]{64}$/.test(parsed.contentHash)) fail('REUSE_POLICY_UNAVAILABLE');
    }
    if (purpose === 'initial' && parsed.contentHash !== expectedHash) fail('REUSE_POLICY_UNAVAILABLE');
    if (purpose === 'revalidate' && parsed.status === 'body_changed' && parsed.contentHash === expectedHash) fail('REUSE_POLICY_UNAVAILABLE');
    const validatedAtMs = timestamp(parsed.validatedAt);
    const retrievedAtMs = parsed.retrievedAt === undefined ? null : timestamp(parsed.retrievedAt);
    if (parsed.status === 'body_changed' && retrievedAtMs === null) fail('REUSE_POLICY_UNAVAILABLE');
    if (parsed.status === 'not_modified' && retrievedAtMs !== null) fail('REUSE_POLICY_UNAVAILABLE');
    if (parsed.status !== 'body_changed' && parsed.status !== 'not_modified' && retrievedAtMs !== null) fail('REUSE_POLICY_UNAVAILABLE');
    if (parsed.status === 'not_modified' && parsed.contentHash !== expectedHash) fail('REUSE_POLICY_UNAVAILABLE');
    return freeze({
      status: parsed.status,
      contentHash: parsed.contentHash ?? null,
      retrievedAtMs,
      validatedAtMs,
      sourceVersion: parsed.sourceVersion ?? 'unknown',
      attemptLineage: validateLineage(parsed.attemptLineage ?? { status: 'unknown' }),
    });
  }

  function validateInitialObservation(observation, expectedHash, now) {
    if (observation.status !== 'body_changed' || observation.contentHash !== expectedHash
      || observation.retrievedAtMs > observation.validatedAtMs || observation.validatedAtMs > now + 60_000) {
      fail('REUSE_POLICY_UNAVAILABLE');
    }
    return observation;
  }

  async function resolveLineage(info, request, descriptor) {
    if (typeof config.resolveLineage !== 'function') return validateLineage({ status: 'unknown' });
    let result;
    try {
      result = await config.resolveLineage(Object.freeze({ tenantId: info?.tenantId ?? null, actorId: info?.actorId ?? null, request, descriptor }));
    } catch { return validateLineage({ status: 'unknown' }); }
    try { return validateLineage(result); } catch { return validateLineage({ status: 'unknown' }); }
  }

  async function resolveConsumers(info, request, descriptor) {
    if (typeof config.resolveInvalidationConsumers !== 'function') return Object.freeze([]);
    let refs;
    try {
      refs = await config.resolveInvalidationConsumers(Object.freeze({ tenantId: info?.tenantId ?? null, actorId: info?.actorId ?? null, request, descriptor }));
    } catch { fail('REUSE_POLICY_UNAVAILABLE'); }
    try { return boundedRefList(refs, 64); } catch { fail('REUSE_POLICY_UNAVAILABLE'); }
  }

  function nextVersion(database, scopeKind, partitionHash, identityHash) {
    const row = database.prepare('SELECT MAX(version) AS version FROM reuse_entries WHERE scope_kind = ? AND partition_hash = ? AND identity_hash = ?').get(scopeKind, partitionHash, identityHash);
    return (row?.version ?? 0) + 1;
  }

  function decryptEntry(info, entry, kind = 'entry') {
    return unseal(info.payloadKey.key, entry.partition_hash, kind, entry.entry_id, entry.payload, entry.payload_key_id);
  }

  async function indexParts(info, scopeKind, index, guard) {
    const keys = await indexInfo(info, scopeKind, guard);
    const identityHash = mac(keys.keyInfo.key, stable(index.identity));
    const contentMac = mac(keys.keyInfo.key, index.contentHash);
    const pinsHash = mac(keys.keyInfo.key, stable(index.pins));
    const cacheKeyHash = mac(keys.keyInfo.key, stable({ identity: index.identity, contentHash: index.contentHash, pins: index.pins }));
    return { ...keys, identityHash, contentMac, pinsHash, cacheKeyHash };
  }

  async function keyPartsFromIndex(info, indexKeys, guard) {
    const keys = indexKeys;
    const scopeKind = keys.scopeKind;
    const payloadKey = await resolveKey(scopeKind === 'public_profile' ? null : info, 'payload', undefined, guard);
    return { ...keys, payloadKey };
  }

  async function keyParts(info, scopeKind, index, guard) {
    const keys = await indexParts(info, scopeKind, index, guard);
    return keyPartsFromIndex(info, keys, guard);
  }

  function insertObservation(database, entryId, partitionHash, payloadKeyId, payloadKey, observation, sequence = null) {
    const latest = database.prepare('SELECT MAX(sequence) AS sequence, COUNT(*) AS count FROM reuse_observations WHERE entry_id = ?').get(entryId);
    if (latest.count >= limits.maxObservationsPerEntry) fail('REUSE_CAPACITY');
    const seq = sequence ?? ((latest.sequence ?? 0) + 1);
    const observationId = randomUUID();
    const payload = sealBounded(payloadKey, payloadKeyId, partitionHash, 'observation', observationId, observation);
    ensureStorageCapacity(database, payload.byteLength);
    database.prepare('INSERT INTO reuse_observations (observation_id, entry_id, sequence, observed_at_ms, status, payload_key_id, payload) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(observationId, entryId, seq, observation.validatedAtMs, observation.status, payloadKeyId, payload);
  }

  function latestIdentityObservation(database, scopeKind, partitionHash, identityHash) {
    return database.prepare(`SELECT o.observation_id, o.observed_at_ms, o.status, o.payload_key_id, o.payload,
        e.content_hash_mac, e.entry_id, e.version
      FROM reuse_observations o JOIN reuse_entries e ON e.entry_id = o.entry_id
      WHERE e.scope_kind = ? AND e.partition_hash = ? AND e.identity_hash = ?
      ORDER BY o.observed_at_ms DESC, e.version DESC, o.sequence DESC LIMIT 1`)
      .get(scopeKind, partitionHash, identityHash);
  }

  function checkInitialObservationOrder(database, keys, scopeKind, observation) {
    const latest = latestIdentityObservation(database, scopeKind, keys.partitionHash, keys.identityHash);
    if (!latest) return false;
    if (observation.validatedAtMs < latest.observed_at_ms) fail('REUSE_POLICY_UNAVAILABLE');
    if (observation.validatedAtMs > latest.observed_at_ms) return false;
    if (latest.status === 'body_changed' && latest.content_hash_mac === keys.contentMac
      && latest.payload_key_id === keys.payloadKey.keyId) {
      const prior = unseal(keys.payloadKey.key, keys.partitionHash, 'observation', latest.observation_id, latest.payload, latest.payload_key_id);
      const expected = {
        status: observation.status,
        contentHash: observation.contentHash,
        retrievedAtMs: observation.retrievedAtMs,
        bodyObservedAtMs: observation.status === 'body_changed' ? observation.retrievedAtMs : null,
        validatedAtMs: observation.validatedAtMs,
        sourceVersion: observation.sourceVersion,
        attemptLineage: observation.attemptLineage,
      };
      if (sameObservationIdentity(prior, expected)) return true;
    }
    fail('REUSE_POLICY_UNAVAILABLE');
  }

  function sameObservationIdentity(left, right) {
    const observedBodyTime = (observation) => observation.bodyObservedAtMs
      ?? (observation.status === 'body_changed' ? observation.retrievedAtMs : null);
    return left.status === right.status
      && left.contentHash === right.contentHash
      && left.retrievedAtMs === right.retrievedAtMs
      && observedBodyTime(left) === observedBodyTime(right)
      && left.validatedAtMs === right.validatedAtMs
      && left.sourceVersion === right.sourceVersion
      && stable(left.attemptLineage) === stable(right.attemptLineage);
  }

  function eventPayload(entry, payload, reason, consumerRef, now, indexKey) {
    return {
      eventId: randomUUID(),
      reason,
      entryRef: entry.entry_id,
      contentHash: entry.scope_kind === 'public_profile'
        ? mac(indexKey, `public-content:${payload.contentHash}`)
        : payload.contentHash,
      version: entry.version,
      consumerRef,
      createdAtMs: now,
    };
  }

  function assertConsumersRevocable(consumers, keys, partitionHash) {
    const probeId = 'f'.repeat(36);
    for (const consumerRef of consumers) {
      if (consumerRef === null) continue;
      const base = {
        eventId: probeId,
        reason: 'policy_version_change',
        entryRef: 'e'.repeat(36),
        contentHash: 'f'.repeat(64),
        version: Number.MAX_SAFE_INTEGER,
        consumerRef,
        createdAtMs: MAX_TIME,
      };
      sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, partitionHash, 'outbox', probeId, base, MAX_INVALIDATION_RECORD_BYTES);
      sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, partitionHash, 'outbox', probeId, {
        ...base,
        deliveryAttemptId: 'd'.repeat(36),
        deliveryAttemptNumber: Number.MAX_SAFE_INTEGER,
      }, MAX_INVALIDATION_RECORD_BYTES);
    }
  }

  function assertBoundHistoryEventsFit(consumers, keys, binding, contentHash) {
    const targets = consumers.length > 0 ? consumers : [null];
    for (const consumerRef of targets) {
      const event = {
        eventId: 'e'.repeat(36),
        reason: 'history_version_changed',
        entryRef: 'p'.repeat(36),
        contentHash,
        version: Number.MAX_SAFE_INTEGER,
        consumerRef,
        createdAtMs: MAX_TIME,
        bindingId: 'b'.repeat(36),
        historyOperationId: 'o'.repeat(36),
        priorHistoryVersionId: binding.historyVersionId,
        priorHistoryContentHash: binding.historyContentHash,
        targetHistoryVersionId: 'v'.repeat(36),
        targetHistoryContentHash: 'h'.repeat(64),
      };
      sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, keys.partitionHash,
        'outbox', event.eventId, event, MAX_INVALIDATION_RECORD_BYTES);
      sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, keys.partitionHash, 'outbox', event.eventId, {
        ...event,
        deliveryAttemptId: 'd'.repeat(36),
        deliveryAttemptNumber: Number.MAX_SAFE_INTEGER,
      }, MAX_INVALIDATION_RECORD_BYTES);
    }
  }

  function disposeBoundProfilePreflight(preflightToken) {
    if (!preflightToken || (typeof preflightToken !== 'object' && typeof preflightToken !== 'function')) return;
    const preflight = boundProfilePreflights.get(preflightToken);
    if (!preflight) return;
    boundProfilePreflights.delete(preflightToken);
    for (const key of [preflight.keys?.keyInfo?.key, preflight.keys?.payloadKey?.key]) {
      try { key?.fill(0); } catch { /* A cache-owned key copy is best-effort zeroized. */ }
    }
    zeroBoundReceiptRows(preflight.replayProof);
    preflight.replayProof = null;
    preflight.replayPayload = null;
    preflight.entryPayload = null;
    preflight.observation = null;
    preflight.consumers = null;
    preflight.lineage = null;
  }

  function boundProfileSignature(index, input, facts, binding) {
    return stable({
      identity: index.identity,
      contentHash: index.contentHash,
      pins: index.pins,
      facts,
      observation: input.observation,
      freshnessTtlMs: input.freshnessTtlMs ?? null,
      expiresAtMs: input.expiresAtMs ?? null,
      binding,
    });
  }

  function boundWriteFingerprint(keys, index, entryPayload, observation, binding, operationId) {
    return mac(keys.keyInfo.key, stable({
      operationId,
      bindingId: binding.bindingId,
      eventId: binding.eventId,
      historyVersionId: binding.historyVersionId,
      historyContentHash: binding.historyContentHash,
      historyProjectionHash: binding.historyProjectionHash,
      historyExpiresAtMs: binding.historyExpiresAtMs,
      identity: index.identity,
      pins: index.pins,
      cacheSourceContentHash: index.contentHash,
      facts: entryPayload.facts,
      observation,
      freshnessTtlMs: entryPayload.freshnessTtlMs,
      retentionPolicy: entryPayload.retentionPolicy,
    }));
  }

  function copySqliteRow(row) {
    if (!row) return null;
    const copy = { ...row };
    for (const [name, value] of Object.entries(copy)) {
      if (value instanceof Uint8Array) copy[name] = Buffer.from(value);
    }
    return copy;
  }

  function zeroBoundReceiptRows(rows) {
    if (!rows) return;
    const all = [rows.receipt, rows.entry, rows.reservation, rows.observation,
      ...(rows.bindingEntries ?? []), ...(rows.bindingReservations ?? []),
      ...(rows.consumers ?? []), ...(rows.invalidationReceipts ?? [])];
    for (const row of all) {
      if (!row || typeof row !== 'object') continue;
      for (const value of Object.values(row)) {
        try { if (value instanceof Uint8Array) value.fill(0); } catch { /* Copied ciphertext is best-effort cleared. */ }
      }
    }
  }

  function readBoundReplayRows(database, binding, keys) {
    const receipt = copySqliteRow(database.prepare(`SELECT * FROM reuse_bound_writes
      WHERE operation_id = ? AND partition_hash = ?`).get(binding.operationId, keys.partitionHash));
    const bindingEntries = database.prepare(`SELECT * FROM reuse_entries WHERE scope_kind = 'tenant_private'
      AND partition_hash = ? AND binding_hash = ? ORDER BY entry_id`)
      .all(keys.partitionHash, mac(keys.keyInfo.key,
        `event-intelligence:correction-cache-binding:v1:${keys.partitionHash}:${binding.bindingId}`))
      .map(copySqliteRow);
    const bindingReservations = database.prepare(`SELECT * FROM reuse_correction_reservations
      WHERE scope_kind = 'tenant_private' AND partition_hash = ? AND binding_hash = ? ORDER BY entry_id`)
      .all(keys.partitionHash, mac(keys.keyInfo.key,
        `event-intelligence:correction-cache-binding:v1:${keys.partitionHash}:${binding.bindingId}`))
      .map(copySqliteRow);
    const entry = receipt ? copySqliteRow(database.prepare(`SELECT * FROM reuse_entries WHERE entry_id = ?
      AND scope_kind = 'tenant_private' AND partition_hash = ?`).get(receipt.entry_id, keys.partitionHash)) : null;
    const reservation = receipt ? copySqliteRow(database.prepare(`SELECT * FROM reuse_correction_reservations
      WHERE entry_id = ? AND scope_kind = 'tenant_private' AND partition_hash = ?`)
      .get(receipt.entry_id, keys.partitionHash)) : null;
    const consumers = receipt ? database.prepare(`SELECT * FROM reuse_consumer_refs WHERE entry_id = ?
      AND scope_kind = 'tenant_private' AND partition_hash = ? ORDER BY consumer_hash`)
      .all(receipt.entry_id, keys.partitionHash).map(copySqliteRow) : [];
    const observation = receipt ? copySqliteRow(database.prepare(`SELECT * FROM reuse_observations
      WHERE entry_id = ? AND sequence = 1`).get(receipt.entry_id)) : null;
    const observationCount = receipt ? database.prepare('SELECT COUNT(*) AS count FROM reuse_observations WHERE entry_id = ?')
      .get(receipt.entry_id).count : 0;
    const outboxCount = receipt ? database.prepare('SELECT COUNT(*) AS count FROM reuse_outbox WHERE entry_id = ?')
      .get(receipt.entry_id).count : 0;
    const invalidationReceipts = database.prepare(`SELECT * FROM reuse_history_invalidation_ops
      WHERE operation_id = ? AND partition_hash = ? ORDER BY entry_id`)
      .all(binding.operationId, keys.partitionHash).map(copySqliteRow);
    const entryCount = database.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count;
    const historicalCap = database.prepare(`SELECT MIN(expires_at_ms) AS expires_at_ms FROM reuse_entries
      WHERE scope_kind = 'tenant_private' AND partition_hash = ? AND identity_hash = ? AND cache_key_hash = ?`)
      .get(keys.partitionHash, keys.identityHash, keys.cacheKeyHash).expires_at_ms;
    return { receipt, bindingEntries, bindingReservations, entry, reservation, consumers,
      observation, observationCount, outboxCount, invalidationReceipts, entryCount, historicalCap };
  }

  function sameSqliteRow(left, right) {
    if (left === null || right === null) return left === right;
    const leftKeys = Object.keys(left).sort();
    const rightKeys = Object.keys(right).sort();
    if (stable(leftKeys) !== stable(rightKeys)) return false;
    return leftKeys.every((key) => {
      const a = left[key];
      const b = right[key];
      if (a instanceof Uint8Array || b instanceof Uint8Array) {
        return a instanceof Uint8Array && b instanceof Uint8Array && Buffer.from(a).equals(Buffer.from(b));
      }
      return a === b;
    });
  }

  function sameBoundReceiptRows(left, right) {
    if (!sameSqliteRow(left.receipt, right.receipt) || !sameSqliteRow(left.entry, right.entry)
      || !sameSqliteRow(left.reservation, right.reservation) || !sameSqliteRow(left.observation, right.observation)
      || left.observationCount !== right.observationCount || left.outboxCount !== right.outboxCount
      || left.invalidationReceipts.length !== right.invalidationReceipts.length
      || left.bindingEntries.length !== right.bindingEntries.length
      || left.bindingReservations.length !== right.bindingReservations.length
      || left.consumers.length !== right.consumers.length) return false;
    return left.bindingEntries.every((row, index) => sameSqliteRow(row, right.bindingEntries[index]))
      && left.bindingReservations.every((row, index) => sameSqliteRow(row, right.bindingReservations[index]))
      && left.invalidationReceipts.every((row, index) => sameSqliteRow(row, right.invalidationReceipts[index]))
      && left.consumers.every((row, index) => sameSqliteRow(row, right.consumers[index]));
  }

  function expectedCorrectionBinding(binding) {
    return Object.freeze({
      bindingId: binding.bindingId,
      eventId: binding.eventId,
      historyVersionId: binding.historyVersionId,
      historyContentHash: binding.historyContentHash,
      historyProjectionHash: binding.historyProjectionHash,
      operationId: binding.operationId,
      historyExpiresAtMs: binding.historyExpiresAtMs,
    });
  }

  async function verifyBoundReceipt({ info, request, signal, keys, index, facts, binding, rows, now }) {
    const phase = binding.operationPhase;
    if (!rows.receipt) {
      if (phase === 'complete' || rows.bindingEntries.length > 0 || rows.bindingReservations.length > 0
        || rows.invalidationReceipts.length > 0) fail('REUSE_INTEGRITY');
      return null;
    }
    if (!['pending_bind', 'complete'].includes(phase)
      || rows.receipt.operation_id !== binding.operationId
      || rows.receipt.partition_hash !== keys.partitionHash
      || !/^[a-f0-9]{64}$/.test(rows.receipt.binding_hash ?? '')
      || rows.receipt.binding_hash !== binding.cacheBindingHash
      || !/^[a-f0-9]{64}$/.test(rows.receipt.fingerprint ?? '')
      || !/^[0-9a-f-]{36}$/i.test(rows.receipt.entry_id ?? '')
      || !Number.isSafeInteger(rows.receipt.version) || rows.receipt.version < 1
      || rows.bindingEntries.length !== 1 || rows.bindingReservations.length !== 1
      || rows.invalidationReceipts.length !== 0 || !rows.entry
      || rows.entry.entry_id !== rows.receipt.entry_id
      || rows.bindingEntries[0].entry_id !== rows.entry.entry_id
      || rows.bindingReservations[0].entry_id !== rows.entry.entry_id
      || !rows.reservation || !rows.observation || rows.observation.sequence !== 1
      || rows.observationCount !== 1 || rows.outboxCount !== 0) fail('REUSE_INTEGRITY');

    const entry = rows.entry;
    if (entry && Number.isSafeInteger(entry.expires_at_ms) && entry.expires_at_ms <= now) {
      fail('REUSE_POLICY_UNAVAILABLE');
    }
    if (entry && (entry.eligible !== 1 || entry.payload_purged !== 0)) fail('REUSE_POLICY_UNAVAILABLE');
    const expectedHash = mac(keys.keyInfo.key,
      `event-intelligence:correction-cache-binding:v1:${keys.partitionHash}:${binding.bindingId}`);
    if (rows.receipt.binding_hash !== expectedHash || entry.scope_kind !== 'tenant_private'
      || entry.partition_hash !== keys.partitionHash || entry.version !== rows.receipt.version
      || entry.binding_hash !== expectedHash || entry.identity_hash !== keys.identityHash
      || entry.content_hash_mac !== keys.contentMac || entry.pins_hash !== keys.pinsHash
      || entry.eligible !== 1 || entry.payload_purged !== 0
      || !Number.isSafeInteger(entry.created_at_ms) || entry.created_at_ms < 0
      || !Number.isSafeInteger(entry.expires_at_ms) || entry.expires_at_ms <= now
      || entry.expires_at_ms > MAX_TIME || entry.created_at_ms > entry.expires_at_ms
      || !string(entry.payload_key_id, 128) || !Number.isSafeInteger(entry.payload_bytes)
      || !(entry.payload instanceof Uint8Array) || entry.payload_bytes !== entry.payload.byteLength
      || !Number.isSafeInteger(binding.historyExpiresAtMs) || entry.expires_at_ms > binding.historyExpiresAtMs
      || rows.reservation.scope_kind !== 'tenant_private' || rows.reservation.partition_hash !== keys.partitionHash
      || rows.reservation.binding_hash !== expectedHash || rows.reservation.entry_id !== entry.entry_id
      || !string(rows.reservation.payload_key_id, 128)
      || !Number.isSafeInteger(rows.reservation.outbox_slots) || rows.reservation.outbox_slots < 1
      || !(rows.reservation.payload instanceof Uint8Array)
      || rows.reservation.payload_bytes !== rows.reservation.payload.byteLength
      || !(rows.observation.payload instanceof Uint8Array) || !string(rows.observation.payload_key_id, 128)
      || rows.consumers.some((row) => !(row.payload instanceof Uint8Array) || !string(row.payload_key_id, 128))) {
      fail('REUSE_INTEGRITY');
    }

    const action = phase === 'complete' ? 'private_profile.read' : 'private_profile.write';
    const guard = authorizationGuard(info, request, action, signal);
    const ownedKeys = new Map();
    const payloadKeyForStored = async (keyId) => {
      if (keys.payloadKey?.keyId === keyId) return keys.payloadKey;
      if (ownedKeys.has(keyId)) return ownedKeys.get(keyId);
      const key = await resolveKey(info, 'payload', keyId, guard);
      ownedKeys.set(keyId, key);
      return key;
    };
    try {
      const entryKey = await payloadKeyForStored(entry.payload_key_id);
      const payloadValue = unseal(entryKey.key, keys.partitionHash, 'entry', entry.entry_id,
        entry.payload, entry.payload_key_id);
      const payload = record(payloadValue, new Set([
        'kind', 'identity', 'pins', 'contentHash', 'facts', 'sourceVersion', 'retrievedAtMs',
        'initialValidatedAtMs', 'freshnessTtlMs', 'permissions', 'sourceRefs', 'correctionRefs',
        'correctionBinding', 'lineage', 'consumers', 'retentionPolicy', 'rights', 'version',
      ]));
      const retention = record(payload?.retentionPolicy, new Set(['expiresAtMs', 'policyId', 'policyVersion']));
      const storedBinding = record(payload?.correctionBinding, new Set([
        'bindingId', 'eventId', 'historyVersionId', 'historyContentHash', 'historyProjectionHash',
        'operationId', 'historyExpiresAtMs',
      ]));
      if (!payload || payload.kind !== 'private' || stable(identity(payload.identity)) !== stable(index.identity)
        || stable(pins(payload.pins)) !== stable(index.pins) || payload.contentHash !== index.contentHash
        || stable(copyFacts(payload.facts)) !== stable(facts) || !retention
        || retention.expiresAtMs !== entry.expires_at_ms || !string(retention.policyId, 128)
        || !string(retention.policyVersion, 128) || !storedBinding
        || stable(storedBinding) !== stable(expectedCorrectionBinding(binding))
        || payload.version !== entry.version || !Number.isSafeInteger(payload.initialValidatedAtMs)
        || !Number.isSafeInteger(payload.retrievedAtMs) || payload.retrievedAtMs > payload.initialValidatedAtMs
        || !Number.isSafeInteger(payload.freshnessTtlMs) || payload.freshnessTtlMs < 1
        || payload.freshnessTtlMs > limits.maxRetentionMs
        || !Number.isSafeInteger(payload.initialValidatedAtMs + payload.freshnessTtlMs)
        || payload.initialValidatedAtMs + payload.freshnessTtlMs > entry.expires_at_ms
        || !Array.isArray(payload.permissions) || !Array.isArray(payload.sourceRefs)
        || !Array.isArray(payload.correctionRefs) || !Array.isArray(payload.consumers)
        || payload.rights !== 'not_asserted') fail('REUSE_INTEGRITY');
      const storedConsumers = boundedRefList(payload.consumers, 64);
      const storedPermissions = validatePermissions(payload.permissions);
      const storedLineage = validateLineage(payload.lineage);
      const storedSourceRefs = boundedRefList(payload.sourceRefs);
      const storedCorrectionRefs = boundedRefList(payload.correctionRefs);
      if (stable(storedConsumers) !== stable(payload.consumers)
        || stable(storedPermissions) !== stable(payload.permissions)
        || stable(storedLineage) !== stable(payload.lineage)
        || stable(storedSourceRefs) !== stable(payload.sourceRefs)
        || stable(storedCorrectionRefs) !== stable(payload.correctionRefs)
        || rows.consumers.length !== storedConsumers.length
        || rows.reservation.payload_key_id !== entry.payload_key_id
        || rows.reservation.outbox_slots !== Math.max(1, storedConsumers.length)) fail('REUSE_INTEGRITY');

      const reservationKey = await payloadKeyForStored(rows.reservation.payload_key_id);
      const reservation = unseal(reservationKey.key, keys.partitionHash, 'correction_reservation', entry.entry_id,
        rows.reservation.payload, rows.reservation.payload_key_id);
      const expectedReservation = {
        bindingId: binding.bindingId,
        eventId: binding.eventId,
        historyVersionId: binding.historyVersionId,
        historyContentHash: binding.historyContentHash,
        historyProjectionHash: binding.historyProjectionHash,
        operationId: binding.operationId,
        profileRef: entry.entry_id,
        bindingHash: expectedHash,
        identity: index.identity,
        pins: index.pins,
        contentHash: index.contentHash,
        version: entry.version,
        expiresAtMs: entry.expires_at_ms,
        outboxSlots: Math.max(1, storedConsumers.length),
        consumers: storedConsumers,
      };
      if (stable(reservation) !== stable(expectedReservation)) fail('REUSE_INTEGRITY');

      const actualConsumers = [];
      for (const row of rows.consumers) {
        if (row.scope_kind !== 'tenant_private' || row.partition_hash !== keys.partitionHash
          || !/^[a-f0-9]{64}$/.test(row.consumer_hash ?? '') || !string(row.payload_key_id, 128)) fail('REUSE_INTEGRITY');
        const consumerKey = await payloadKeyForStored(row.payload_key_id);
        const consumer = unseal(consumerKey.key, keys.partitionHash, 'consumer_ref',
          `${entry.entry_id}:${row.consumer_hash}`, row.payload, row.payload_key_id);
        const parsed = record(consumer, new Set(['consumerRef']));
        if (!parsed || !string(parsed.consumerRef, 512)
          || mac(keys.keyInfo.key, parsed.consumerRef) !== row.consumer_hash) fail('REUSE_INTEGRITY');
        actualConsumers.push(parsed.consumerRef);
      }
      if (new Set(actualConsumers).size !== actualConsumers.length
        || stable([...actualConsumers].sort()) !== stable([...storedConsumers].sort())) fail('REUSE_INTEGRITY');

      const observationKey = await payloadKeyForStored(rows.observation.payload_key_id);
      const observationValue = unseal(observationKey.key, keys.partitionHash, 'observation',
        rows.observation.observation_id, rows.observation.payload, rows.observation.payload_key_id);
      const observation = record(observationValue, new Set([
        'status', 'retrievedAtMs', 'validatedAtMs', 'contentHash', 'sourceVersion', 'attemptLineage',
      ]));
      if (!observation || observation.status !== 'body_changed'
        || observation.contentHash !== index.contentHash
        || observation.retrievedAtMs !== payload.retrievedAtMs
        || observation.validatedAtMs !== payload.initialValidatedAtMs
        || observation.sourceVersion !== payload.sourceVersion
        || rows.observation.entry_id !== entry.entry_id || rows.observation.status !== 'body_changed'
        || rows.observation.observed_at_ms !== observation.validatedAtMs
        || !Number.isSafeInteger(observation.validatedAtMs) || observation.retrievedAtMs > observation.validatedAtMs) {
        fail('REUSE_INTEGRITY');
      }
      const observationLineage = validateLineage(observation.attemptLineage);
      if (stable(observationLineage) !== stable(observation.attemptLineage)) fail('REUSE_INTEGRITY');
      const fingerprint = boundWriteFingerprint(keys, index, payload, observation, binding, binding.operationId);
      if (rows.receipt.fingerprint !== fingerprint) fail('REUSE_INTEGRITY');
      return Object.freeze({ rows, payload: freeze(payload), observation: freeze(observation),
        expiresAtMs: entry.expires_at_ms, version: entry.version, profileRef: entry.entry_id,
        bindingHash: expectedHash, freshnessDeadlineMs: payload.initialValidatedAtMs + payload.freshnessTtlMs });
    } finally {
      for (const key of ownedKeys.values()) key.key.fill(0);
    }
  }

  async function preflightBoundCacheCapacity({ keys, index, entryPayload, observation, consumers, binding, ttlMs }) {
    const correctionSlots = Math.max(1, consumers.length);
    const generalSlots = Math.max(1, consumers.length);
    const additionalSlots = correctionSlots + generalSlots;
    const read = await withBindingRead((database, time) => {
      if (time.clockRollback) fail('REUSE_DENIED');
      const rows = readBoundReplayRows(database, binding, keys);
      if (rows.receipt || rows.bindingEntries.length > 0 || rows.bindingReservations.length > 0
        || rows.invalidationReceipts.length > 0 || binding.operationPhase === 'complete') fail('REUSE_BUSY');
      return { rows, now: time.now };
    });
    const effectiveExpiry = Math.min(entryPayload.retentionPolicy.expiresAtMs,
      binding.historyExpiresAtMs, read.rows.historicalCap ?? MAX_TIME);
    const freshnessDeadlineMs = observation.validatedAtMs + ttlMs;
    if (!Number.isSafeInteger(freshnessDeadlineMs) || freshnessDeadlineMs <= read.now
      || effectiveExpiry <= read.now || effectiveExpiry > binding.historyExpiresAtMs
      || freshnessDeadlineMs > effectiveExpiry) fail('REUSE_POLICY_UNAVAILABLE');
    const retentionPolicy = Object.freeze({ ...entryPayload.retentionPolicy, expiresAtMs: effectiveExpiry });
    const fixedRetention = Object.freeze({ ...retentionPolicy, expiresAtMs: effectiveExpiry });

    // Capacity estimates apply only to a first effect. Existing receipts are
    // classified and authenticated before this function is reached.
    const versionedPayload = freeze({ ...entryPayload, retentionPolicy, version: Number.MAX_SAFE_INTEGER });
    const entry = sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, keys.partitionHash,
      'entry', 'p'.repeat(36), versionedPayload);
    let additionalPayloadBytes = 0;
    for (const consumerRef of consumers) {
      const consumerHash = mac(keys.keyInfo.key, consumerRef);
      const consumerPayload = sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, keys.partitionHash,
        'consumer_ref', `${'p'.repeat(36)}:${consumerHash}`, { consumerRef });
      additionalPayloadBytes += consumerPayload.byteLength;
    }
    const observationPayload = sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, keys.partitionHash,
      'observation', 'o'.repeat(36), {
        status: 'body_changed',
        retrievedAtMs: observation.retrievedAtMs,
        validatedAtMs: observation.validatedAtMs,
        contentHash: index.contentHash,
        sourceVersion: observation.sourceVersion,
        attemptLineage: observation.attemptLineage,
      });
    additionalPayloadBytes += observationPayload.byteLength;
    const reservation = {
      bindingId: binding.bindingId,
      eventId: binding.eventId,
      historyVersionId: binding.historyVersionId,
      historyContentHash: binding.historyContentHash,
      historyProjectionHash: binding.historyProjectionHash,
      operationId: binding.operationId,
      profileRef: 'p'.repeat(36),
      bindingHash: binding.cacheBindingHash,
      identity: index.identity,
      pins: index.pins,
      contentHash: index.contentHash,
      version: Number.MAX_SAFE_INTEGER,
      expiresAtMs: effectiveExpiry,
      outboxSlots: correctionSlots,
      consumers,
    };
    const reserved = sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, keys.partitionHash,
      'correction_reservation', reservation.profileRef, reservation);
    await withBindingRead((database, time) => {
      if (time.clockRollback || time.now >= effectiveExpiry || time.now >= freshnessDeadlineMs) fail('REUSE_POLICY_UNAVAILABLE');
      const current = readBoundReplayRows(database, binding, keys);
      if (current.receipt || current.bindingEntries.length > 0 || current.bindingReservations.length > 0
        || current.invalidationReceipts.length > 0) fail('REUSE_BUSY');
      if (current.entryCount >= limits.maxEntries) fail('REUSE_CAPACITY');
      assertOutboxHeadroom(database, additionalSlots);
      ensureStorageCapacity(database, entry.byteLength + reserved.byteLength + additionalPayloadBytes, 0, additionalSlots);
    });
    return Object.freeze({ retention: fixedRetention, replayProof: null, replayed: false,
      freshnessDeadlineMs });
  }

  function registeredConsumers(database, entry, payload, keys) {
    const refs = new Set(payload.consumers ?? []);
    const rows = database.prepare('SELECT * FROM reuse_consumer_refs WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?').all(entry.entry_id, entry.scope_kind, entry.partition_hash);
    for (const row of rows) {
      const refKey = row.payload_key_id === keys.payloadKey.keyId ? keys.payloadKey : null;
      const key = refKey;
      if (!key) fail('REUSE_KEY_UNAVAILABLE');
      const content = unseal(key.key, row.partition_hash, 'consumer_ref', `${entry.entry_id}:${row.consumer_hash}`, row.payload, row.payload_key_id);
      if (!content || !string(content.consumerRef)) fail('REUSE_INTEGRITY');
      refs.add(content.consumerRef);
    }
    return Object.freeze([...refs]);
  }

  function registerConsumers(database, entryId, scopeKind, keys, refs) {
    let prior = database.prepare('SELECT COUNT(*) AS count FROM reuse_consumer_refs').get().count;
    const existingForEntry = database.prepare('SELECT consumer_hash FROM reuse_consumer_refs WHERE entry_id = ?').all(entryId);
    const existingHashes = new Set(existingForEntry.map((row) => row.consumer_hash));
    const newHashes = new Set(refs.map((consumerRef) => mac(keys.keyInfo.key, consumerRef)).filter((consumerHash) => !existingHashes.has(consumerHash)));
    const existingReservation = Math.max(1, existingHashes.size);
    const nextReservation = Math.max(1, existingHashes.size + newHashes.size);
    assertOutboxHeadroom(database, nextReservation - existingReservation);
    for (const consumerRef of refs) {
      const consumerHash = mac(keys.keyInfo.key, consumerRef);
      const exists = database.prepare('SELECT 1 AS found FROM reuse_consumer_refs WHERE entry_id = ? AND consumer_hash = ?').get(entryId, consumerHash);
      if (exists) continue;
      if (prior >= limits.maxOutboxEntries) fail('REUSE_CAPACITY');
      const payload = sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, keys.partitionHash, 'consumer_ref', `${entryId}:${consumerHash}`, { consumerRef });
      const currentCount = database.prepare('SELECT COUNT(*) AS count FROM reuse_consumer_refs WHERE entry_id = ?').get(entryId).count;
      const reservationDelta = Math.max(1, currentCount + 1) - Math.max(1, currentCount);
      ensureStorageCapacity(database, payload.byteLength, 0, reservationDelta);
      database.prepare('INSERT INTO reuse_consumer_refs (entry_id, scope_kind, partition_hash, consumer_hash, payload_key_id, payload) VALUES (?, ?, ?, ?, ?, ?)')
        .run(entryId, scopeKind, keys.partitionHash, consumerHash, keys.payloadKey.keyId, payload);
      prior += 1;
    }
  }

  function enqueueInvalidations(database, entry, payload, reason, consumers, now, keys) {
    const count = database.prepare('SELECT COUNT(*) AS count FROM reuse_outbox').get().count;
    const targetRefs = consumers.length > 0 ? consumers : [null];
    const reserved = reservationState(database);
    if (count + targetRefs.length + reserved > limits.maxOutboxEntries) fail('REUSE_CAPACITY');
    const prepared = [];
    for (const consumerRef of targetRefs) {
      const event = eventPayload(entry, payload, reason, consumerRef, now, keys.keyInfo.key);
      const sealed = sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, entry.partition_hash, 'outbox', event.eventId, event, MAX_INVALIDATION_RECORD_BYTES);
      prepared.push({ event, consumerRef, sealed });
    }
    const eventBytes = prepared.reduce((total, item) => total + item.sealed.byteLength, 0);
    const retryGrowth = prepared.reduce((total, item) => total + MAX_INVALIDATION_RECORD_BYTES - item.sealed.byteLength, 0);
    ensureStorageCapacity(database, eventBytes, 0, 0, retryGrowth);
    for (const { event, consumerRef, sealed } of prepared) {
      database.prepare('INSERT INTO reuse_outbox (event_id, entry_id, scope_kind, partition_hash, status, attempt_count, next_attempt_at_ms, has_consumer, payload_key_id, payload, payload_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run(event.eventId, entry.entry_id, entry.scope_kind, entry.partition_hash, 'pending', 0, now, consumerRef === null ? 0 : 1,
          keys.payloadKey.keyId, sealed, sealed.byteLength);
    }
  }

  function invalidateEntry(database, info, entry, payload, reason, consumers, now, keys) {
    if (!entry || entry.eligible !== 1 || !payload) return false;
    const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?')
      .get(entry.entry_id, entry.scope_kind, entry.partition_hash);
    if (!current || current.eligible !== 1 || current.version !== entry.version
      || current.payload_bytes !== entry.payload_bytes || current.payload_purged === 1) return false;
    const changed = database.prepare('UPDATE reuse_entries SET eligible = 0 WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ? AND eligible = 1 AND version = ? AND payload_purged = 0')
      .run(current.entry_id, current.scope_kind, current.partition_hash, current.version);
    if (changed.changes !== 1) return false;
    database.prepare('DELETE FROM reuse_refresh_sources WHERE entry_id = ? AND partition_hash = ?')
      .run(current.entry_id, current.partition_hash);
    const allConsumers = registeredConsumers(database, current, payload, keys);
    enqueueInvalidations(database, current, payload, reason, allConsumers, now, keys);
    return true;
  }

  function expireEntry(database, info, entry, payload, now, keys) {
    if (!entry || entry.expires_at_ms > now) return false;
    let transitioned = false;
    if (entry.eligible === 1) {
      if (!payload) fail('REUSE_INTEGRITY');
      transitioned = invalidateEntry(database, info, entry, payload, 'retention_expired', payload.consumers ?? [], now, keys);
    }
    if (entry.payload_purged !== 1) {
      const purged = database.prepare('UPDATE reuse_entries SET payload = ?, payload_bytes = 0, payload_purged = 1 WHERE entry_id = ? AND payload_purged = 0')
        .run(Buffer.alloc(0), entry.entry_id);
      transitioned ||= purged.changes === 1;
    }
    database.prepare('DELETE FROM reuse_observations WHERE entry_id = ?').run(entry.entry_id);
    database.prepare('DELETE FROM reuse_refresh_sources WHERE entry_id = ? AND partition_hash = ?')
      .run(entry.entry_id, entry.partition_hash);
    database.prepare('DELETE FROM reuse_private_links WHERE public_entry_id = ?').run(entry.entry_id);
    database.prepare('DELETE FROM reuse_consumer_refs WHERE entry_id = ?').run(entry.entry_id);
    if (entry.scope_kind === 'tenant_private' && entry.partition_hash) {
      database.prepare(`DELETE FROM reuse_correction_reservations WHERE entry_id = ?
        AND scope_kind = 'tenant_private' AND partition_hash = ?`).run(entry.entry_id, entry.partition_hash);
    }
    return transitioned;
  }

  async function maybePermissions(info, request, payload, use, now) {
    if (!Array.isArray(payload.permissions) || payload.permissions.length === 0) {
      return payload.kind === 'public' && use === 'fact_read' ? { status: 'not_asserted', valid: true } : { status: 'unverified', valid: false };
    }
    if (typeof config.verifyPermission !== 'function') return { status: 'unverified', valid: false };
    let validUntilMs = MAX_TIME;
    for (const permission of payload.permissions) {
      if (permission.contentHash !== payload.contentHash || permission.use !== use) return { status: 'use_or_hash_mismatch', valid: false };
      let result;
      try {
        result = await config.verifyPermission(Object.freeze({
          tenantId: info?.tenantId ?? null,
          actorId: info?.actorId ?? null,
          request,
          reference: permission.reference,
          contentHash: permission.contentHash,
          version: permission.version,
          use,
          nowMs: now,
        }));
      } catch { return { status: 'unverified', valid: false }; }
      if (info) {
        const action = payload.kind === 'public' ? 'public_profile.read' : 'private_profile.read';
        await authorize(info, request, action);
      }
      const decision = permissionDecision(result, permission, currentTime());
      if (!decision.valid) return decision;
      validUntilMs = Math.min(validUntilMs, decision.validUntilMs);
    }
    if (currentTime() >= validUntilMs) return { status: 'expired', valid: false };
    return { status: 'valid', valid: true, validUntilMs };
  }

  async function verifyStoredPermissions(info, request, payload, authorizationAction, now, authorizationDetails = {}) {
    if (!Array.isArray(payload.permissions) || payload.permissions.length === 0) return { status: 'not_asserted', valid: true };
    if (typeof config.verifyPermission !== 'function') return { status: 'unverified', valid: false };
    let validUntilMs = MAX_TIME;
    for (const permission of payload.permissions) {
      if (permission.contentHash !== payload.contentHash) return { status: 'use_or_hash_mismatch', valid: false };
      let result;
      try {
        result = await config.verifyPermission(Object.freeze({
          tenantId: info?.tenantId ?? null,
          actorId: info?.actorId ?? null,
          request,
          reference: permission.reference,
          contentHash: permission.contentHash,
          version: permission.version,
          use: permission.use,
          nowMs: now,
        }));
      } catch { return { status: 'unverified', valid: false }; }
      if (info) await authorize(info, request, authorizationAction, authorizationDetails);
      const decision = permissionDecision(result, permission, currentTime());
      if (!decision.valid) return decision;
      validUntilMs = Math.min(validUntilMs, decision.validUntilMs);
    }
    if (currentTime() >= validUntilMs) return { status: 'expired', valid: false };
    return { status: 'valid', valid: true, validUntilMs };
  }

  function permissionDecision(result, permission, now) {
    if (typeof result === 'string') {
      if (result === 'revoked' || result === 'expired') return { status: result, valid: false };
      return { status: 'unverified', valid: false };
    }
    const parsed = record(result, new Set(['status', 'reference', 'contentHash', 'version', 'use', 'validUntilMs']));
    if (!parsed || parsed.status !== 'valid' || parsed.reference !== permission.reference
      || parsed.contentHash !== permission.contentHash || parsed.version !== permission.version || parsed.use !== permission.use) {
      return { status: parsed?.status === 'revoked' || parsed?.status === 'expired' ? parsed.status : 'unverified', valid: false };
    }
    if (!Number.isSafeInteger(parsed.validUntilMs) || parsed.validUntilMs > MAX_TIME) return { status: 'unverified', valid: false };
    if (parsed.validUntilMs <= now) return { status: 'expired', valid: false };
    return { status: 'valid', valid: true, validUntilMs: parsed.validUntilMs };
  }

  async function commitBoundProfile({ info, request, input, index, keys, entryPayload, observation, consumers, binding, external }) {
    if (binding.scopeKind !== 'tenant_private' || typeof external.commitGate !== 'function'
      || !external.bindingOperation || typeof external.bindingOperation.operationId !== 'string'
      || !Number.isSafeInteger(external.bindingOperation.fence) || external.bindingOperation.fence < 1) fail('REUSE_DENIED');
    const bindingHash = mac(keys.keyInfo.key, `event-intelligence:correction-cache-binding:v1:${keys.partitionHash}:${binding.bindingId}`);
    const writeFingerprint = boundWriteFingerprint(keys, index, entryPayload, observation,
      binding, external.bindingOperation.operationId);
    const operationId = external.bindingOperation.operationId;
    const profileRef = randomUUID();
    const freshnessDeadlineMs = entryPayload.initialValidatedAtMs + entryPayload.freshnessTtlMs;
    if (!Number.isSafeInteger(freshnessDeadlineMs) || freshnessDeadlineMs <= external.boundProfilePreflight?.nowMs
      || freshnessDeadlineMs > entryPayload.retentionPolicy.expiresAtMs) fail('REUSE_POLICY_UNAVAILABLE');
    await authorize(info, request, 'private_profile.write');
    if (signalAborted(external.signal)) fail('REUSE_DENIED');
    const boundary = Object.freeze({
      input: boundaryInput(info, request, binding.eventId, 'cache.private_profile.bind', {
        operationId,
        fence: external.bindingOperation.fence,
        bindingId: binding.bindingId,
        profileRef,
        scopeKind: binding.scopeKind,
        identity: index.identity,
        pins: index.pins,
        cacheSourceContentHash: index.contentHash,
        historyVersionId: binding.historyVersionId,
        historyContentHash: binding.historyContentHash,
        historyProjectionHash: binding.historyProjectionHash,
        effectiveExpiresAtMs: Math.min(binding.historyExpiresAtMs, entryPayload.retentionPolicy.expiresAtMs),
        freshnessDeadlineMs,
      }),
      mustBeBeforeMs: Math.min(binding.historyExpiresAtMs, entryPayload.retentionPolicy.expiresAtMs, freshnessDeadlineMs),
    });
    const result = await withBindingDatabase((commit, time) => external.commitGate(commit, time), (database, time) => {
      const replay = database.prepare('SELECT * FROM reuse_bound_writes WHERE operation_id = ? AND partition_hash = ?')
        .get(operationId, keys.partitionHash);
      if (replay || external.boundProfilePreflight?.replayed) fail('REUSE_BUSY');
      const currentProof = readBoundReplayRows(database, { ...binding, cacheBindingHash: bindingHash }, keys);
      if (currentProof.bindingEntries.length > 0 || currentProof.bindingReservations.length > 0
        || currentProof.invalidationReceipts.length > 0) fail('REUSE_INTEGRITY');
      if (time.clockRollback || signalAborted(external.signal)) fail('REUSE_DENIED');
      const entryCount = database.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count;
      if (entryCount >= limits.maxEntries) fail('REUSE_CAPACITY');
      const historicalCap = database.prepare(`SELECT MIN(expires_at_ms) AS expires_at_ms FROM reuse_entries
        WHERE scope_kind = ? AND partition_hash = ? AND identity_hash = ? AND cache_key_hash = ?`)
        .get('tenant_private', keys.partitionHash, keys.identityHash, keys.cacheKeyHash).expires_at_ms;
      const fixedExpiry = historicalCap === null ? entryPayload.retentionPolicy.expiresAtMs
        : Math.min(entryPayload.retentionPolicy.expiresAtMs, historicalCap);
      if (fixedExpiry <= time.effectiveNow || fixedExpiry > binding.historyExpiresAtMs
        || freshnessDeadlineMs <= time.effectiveNow || freshnessDeadlineMs > fixedExpiry) fail('REUSE_POLICY_UNAVAILABLE');
      const version = nextVersion(database, 'tenant_private', keys.partitionHash, keys.identityHash);
      if (!Number.isSafeInteger(version) || version < 1 || version > Number.MAX_SAFE_INTEGER) fail('REUSE_CAPACITY');
      const fixedRetention = Object.freeze({ ...entryPayload.retentionPolicy, expiresAtMs: fixedExpiry });
      const versionedPayload = freeze({ ...entryPayload, retentionPolicy: fixedRetention, version });
      const sealed = sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, keys.partitionHash, 'entry', profileRef, versionedPayload);
      const targetRefs = consumers.length > 0 ? consumers : [null];
      const correctionSlots = targetRefs.length;
      const generalSlots = Math.max(1, consumers.length);
      assertOutboxHeadroom(database, correctionSlots + generalSlots);
      const reservationPayload = {
        bindingId: binding.bindingId,
        eventId: binding.eventId,
        historyVersionId: binding.historyVersionId,
        historyContentHash: binding.historyContentHash,
        historyProjectionHash: binding.historyProjectionHash,
        operationId: binding.operationId,
        profileRef,
        bindingHash,
        identity: index.identity,
        pins: index.pins,
        contentHash: index.contentHash,
        version,
        expiresAtMs: fixedExpiry,
        outboxSlots: correctionSlots,
        consumers,
      };
      const reservationSealed = sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, keys.partitionHash,
        'correction_reservation', profileRef, reservationPayload);
      ensureStorageCapacity(database, sealed.byteLength + reservationSealed.byteLength, 0, correctionSlots + generalSlots);
      database.prepare(`INSERT INTO reuse_entries
        (entry_id, scope_kind, partition_hash, identity_hash, cache_key_hash, content_hash_mac, pins_hash, version,
         created_at_ms, expires_at_ms, eligible, payload_key_id, payload, payload_bytes, payload_purged, binding_hash)
        VALUES (?, 'tenant_private', ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, 0, ?)`)
        .run(profileRef, keys.partitionHash, keys.identityHash, keys.cacheKeyHash, keys.contentMac, keys.pinsHash,
          version, time.now, fixedExpiry, keys.payloadKey.keyId, sealed, sealed.byteLength, bindingHash);
      database.prepare(`INSERT INTO reuse_correction_reservations
        (entry_id, scope_kind, partition_hash, binding_hash, outbox_slots, payload_key_id, payload, payload_bytes)
        VALUES (?, 'tenant_private', ?, ?, ?, ?, ?, ?)`)
        .run(profileRef, keys.partitionHash, bindingHash, correctionSlots, keys.payloadKey.keyId,
          reservationSealed, reservationSealed.byteLength);
      registerConsumers(database, profileRef, 'tenant_private', keys, consumers);
      insertObservation(database, profileRef, keys.partitionHash, keys.payloadKey.keyId, keys.payloadKey.key,
        { status: 'body_changed', retrievedAtMs: observation.retrievedAtMs, validatedAtMs: observation.validatedAtMs,
          contentHash: index.contentHash, sourceVersion: observation.sourceVersion, attemptLineage: observation.attemptLineage });
      database.prepare(`INSERT INTO reuse_bound_writes (operation_id, partition_hash, binding_hash, fingerprint, entry_id, version)
        VALUES (?, ?, ?, ?, ?, ?)`)
        .run(operationId, keys.partitionHash, bindingHash, writeFingerprint, profileRef, version);
      return Object.freeze({ status: 'stored', profileRef, version, freshness: 'fresh',
        originalLineageStatus: entryPayload.lineage?.status ?? 'unknown', replayed: false, expiresAtMs: fixedExpiry,
        bindingHash, identity: index.identity, pins: index.pins, cacheSourceContentHash: index.contentHash,
        scopeKind: 'tenant_private' });
    }, external.signal, boundary);
    await authorize(info, request, 'private_profile.write');
    if (signalAborted(external.signal)) fail('REUSE_DENIED');
    return result;
  }

  async function storeProfile(info, request, scopeKind, input, publicFacts, external = {}) {
    const index = copyIndex(input);
    const parsedIdentity = index.identity;
    const parsedPins = index.pins;
    const now = currentTime();
    if (signalAborted(external.signal)) fail('REUSE_DENIED');
    const writeAction = scopeKind === 'public_profile' ? 'public_profile.publish' : 'private_profile.write';
    const preflight = external.boundProfilePreflight;
    const observation = preflight?.observation
      ?? await verifyObservation(info, request, index.contentHash, input.observation, 'initial');
    await authorize(info, request, writeAction);
    if (signalAborted(external.signal)) fail('REUSE_DENIED');
    validateInitialObservation(observation, index.contentHash, preflight?.nowMs ?? now);
    const retention = preflight?.retention ?? await resolveRetention(info, scopeKind, now, input.expiresAtMs ?? null);
    await authorize(info, request, scopeKind === 'public_profile' ? 'public_profile.publish' : 'private_profile.write');
    if (signalAborted(external.signal)) fail('REUSE_DENIED');
    const ttlMs = preflight?.ttlMs ?? input.freshnessTtlMs ?? limits.defaultFreshnessTtlMs;
    const retentionBaseNow = preflight?.nowMs ?? now;
    const freshnessDeadlineMs = preflight?.freshnessDeadlineMs ?? observation.validatedAtMs + ttlMs;
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > limits.maxRetentionMs
      || !Number.isSafeInteger(freshnessDeadlineMs) || freshnessDeadlineMs <= retentionBaseNow
      || freshnessDeadlineMs > retention.expiresAtMs) fail('REUSE_INVALID');
    let privateReferences = preflight?.privateReferences ?? { permissions: [], sourceRefs: [], correctionRefs: [] };
    if (!preflight && typeof config.resolvePrivateProfileReferences === 'function') {
      let references;
      try {
        references = await config.resolvePrivateProfileReferences(Object.freeze({
          tenantId: info.tenantId,
          actorId: info.actorId,
          request,
          kind: scopeKind,
          identity: parsedIdentity,
          contentHash: index.contentHash,
          projection: publicFacts,
        }));
      } catch { fail('REUSE_POLICY_UNAVAILABLE'); }
      const parsed = record(references, new Set(['permissions', 'sourceRefs', 'correctionRefs']));
      if (!parsed) fail('REUSE_POLICY_UNAVAILABLE');
      privateReferences = {
        permissions: validatePermissions(parsed.permissions ?? []),
        sourceRefs: boundedRefList(parsed.sourceRefs ?? []),
        correctionRefs: boundedRefList(parsed.correctionRefs ?? []),
      };
      await authorize(info, request, scopeKind === 'public_profile' ? 'public_profile.publish' : 'private_profile.write');
      if (signalAborted(external.signal)) fail('REUSE_DENIED');
    }
    const permissions = validatePermissions(scopeKind === 'public_profile' ? (external.publicPermissions ?? []) : privateReferences.permissions);
    const lineage = preflight?.lineage ?? await resolveLineage(info, request, Object.freeze({
      kind: scopeKind,
      identity: parsedIdentity,
      contentHash: index.contentHash,
      version: 1,
      observation: observation.status,
    }));
    if (!preflight) {
      await authorize(info, request, scopeKind === 'public_profile' ? 'public_profile.publish' : 'private_profile.write');
      if (signalAborted(external.signal)) fail('REUSE_DENIED');
    }
    const consumers = preflight?.consumers ?? await resolveConsumers(info, request, Object.freeze({
      identity: parsedIdentity,
      contentHash: index.contentHash,
      scopeKind,
      ...(scopeKind === 'public_profile' ? { publicSafeOnly: true } : {}),
    }));
    if (!preflight) {
      await authorize(info, request, scopeKind === 'public_profile' ? 'public_profile.publish' : 'private_profile.write');
      if (signalAborted(external.signal)) fail('REUSE_DENIED');
    }
    const keys = preflight?.keys ?? await keyParts(info, scopeKind, index, async () => {
      await authorize(info, request, writeAction);
      if (signalAborted(external.signal)) fail('REUSE_DENIED');
    });
    assertConsumersRevocable(consumers, keys, keys.partitionHash);
    const scoped = { ...keys, scopeKind, index, info };
    const profileRef = randomUUID();
    const correctionBinding = external.correctionBinding === undefined ? null
      : record(external.correctionBinding, new Set([
        'bindingId', 'eventId', 'historyVersionId', 'historyContentHash', 'historyProjectionHash', 'operationId', 'historyExpiresAtMs',
      ]));
    if (external.correctionBinding !== undefined && (!correctionBinding || scopeKind !== 'tenant_private'
      || !string(correctionBinding.bindingId, 128) || !string(correctionBinding.historyVersionId, 180)
      || !string(correctionBinding.eventId, 180)
      || !/^[a-f0-9]{64}$/.test(correctionBinding.historyContentHash)
      || !/^[a-f0-9]{64}$/.test(correctionBinding.historyProjectionHash)
      || !Number.isSafeInteger(correctionBinding.historyExpiresAtMs)
      || correctionBinding.operationId !== external.bindingOperation?.operationId)) fail('REUSE_INVALID');
    const entryPayload = freeze({
      kind: scopeKind === 'public_profile' ? 'public' : 'private',
      identity: parsedIdentity,
      pins: parsedPins,
      contentHash: index.contentHash,
      facts: publicFacts,
      sourceVersion: observation.sourceVersion,
      retrievedAtMs: observation.retrievedAtMs,
      initialValidatedAtMs: observation.validatedAtMs,
      freshnessTtlMs: ttlMs,
      permissions,
      sourceRefs: scopeKind === 'tenant_private' ? privateReferences.sourceRefs : Object.freeze([]),
      correctionRefs: scopeKind === 'tenant_private' ? privateReferences.correctionRefs : Object.freeze([]),
      ...(correctionBinding ? { correctionBinding } : {}),
      lineage: scopeKind === 'tenant_private' ? lineage : validateLineage({ status: 'unknown' }),
      consumers,
      retentionPolicy: retention,
      rights: 'not_asserted',
    });
    const serializedBytes = Buffer.byteLength(stable(entryPayload), 'utf8');
    if (serializedBytes > limits.maxEntryBytes) fail('REUSE_CAPACITY');
    const ciphertext = sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, keys.partitionHash, 'entry', profileRef, entryPayload);
    let privateLinkKeys = null;
    if (scopeKind === 'public_profile') {
      privateLinkKeys = await indexInfo(info, 'tenant_private');
      await authorize(info, request, 'public_profile.publish');
      if (signalAborted(external.signal)) fail('REUSE_DENIED');
      privateLinkKeys.payloadKey = await resolveKey(info, 'payload');
      await authorize(info, request, 'public_profile.publish');
      if (signalAborted(external.signal)) fail('REUSE_DENIED');
    }
    const privateLinkPayload = scopeKind === 'public_profile' ? {
      sourceRecordId: external.sourceRecordId ?? null,
      contentHash: index.contentHash,
      identity: parsedIdentity,
      sourceRefs: privateReferences.sourceRefs,
      correctionRefs: privateReferences.correctionRefs,
      permissions: privateReferences.permissions,
      lineage,
    } : null;
    if (privateLinkPayload && Buffer.byteLength(stable(privateLinkPayload), 'utf8') > limits.maxEntryBytes) fail('REUSE_CAPACITY');
    if (scopeKind === 'public_profile') {
      await authorize(info, request, 'public_profile.publish');
      if (signalAborted(external.signal)) fail('REUSE_DENIED');
    }
    if (correctionBinding) {
      return commitBoundProfile({ info, request, input, index, keys, entryPayload, observation, consumers,
        binding: Object.freeze({ ...correctionBinding, scopeKind }), external });
    }
    const result = await withDatabase((database, time) => {
      if (time.clockRollback || signalAborted(external.signal)) fail('REUSE_DENIED');
      const existing = database.prepare('SELECT * FROM reuse_entries WHERE scope_kind = ? AND partition_hash = ? AND cache_key_hash = ? AND eligible = 1 AND binding_hash IS NULL ORDER BY version DESC LIMIT 1')
        .get(scopeKind, keys.partitionHash, keys.cacheKeyHash);
      const duplicateInitialObservation = checkInitialObservationOrder(database, keys, scopeKind, observation);
      if (existing) {
        if (existing.expires_at_ms <= time.now) {
          const oldPayload = decryptEntry(scoped, existing);
          expireEntry(database, info, existing, oldPayload, time.now, keys);
          return Object.freeze({ status: 'expired', profileRef: existing.entry_id, version: existing.version, freshness: 'unavailable', originalLineageStatus: 'unknown' });
        }
        const oldPayload = decryptEntry(scoped, existing);
        if (!duplicateInitialObservation) {
          insertObservation(database, existing.entry_id, existing.partition_hash, keys.payloadKey.keyId, keys.payloadKey.key,
            { status: 'body_changed', retrievedAtMs: observation.retrievedAtMs, bodyObservedAtMs: observation.retrievedAtMs, validatedAtMs: observation.validatedAtMs, contentHash: index.contentHash, sourceVersion: observation.sourceVersion, attemptLineage: observation.attemptLineage });
        }
        registerConsumers(database, existing.entry_id, scopeKind, keys, consumers);
        let originalLineageStatus = oldPayload.lineage?.status ?? 'unknown';
        if (privateLinkPayload) {
          const priorLink = database.prepare('SELECT link_id FROM reuse_private_links WHERE tenant_partition_hash = ? AND public_entry_id = ?')
            .get(privateLinkKeys.partitionHash, existing.entry_id);
          if (priorLink) {
            originalLineageStatus = 'unknown';
          } else {
            const tenantLinkId = randomUUID();
            const linkPayload = { ...privateLinkPayload, version: existing.version, expiresAtMs: existing.expires_at_ms };
            const linkCiphertext = sealBounded(privateLinkKeys.payloadKey.key, privateLinkKeys.payloadKey.keyId, privateLinkKeys.partitionHash, 'private_link', tenantLinkId, linkPayload);
            if (database.prepare('SELECT COUNT(*) AS count FROM reuse_private_links').get().count >= limits.maxPrivateLinks) fail('REUSE_CAPACITY');
            ensureStorageCapacity(database, linkCiphertext.byteLength);
            database.prepare('INSERT INTO reuse_private_links (link_id, tenant_partition_hash, public_entry_id, payload_key_id, payload) VALUES (?, ?, ?, ?, ?)')
              .run(tenantLinkId, privateLinkKeys.partitionHash, existing.entry_id, privateLinkKeys.payloadKey.keyId, linkCiphertext);
            originalLineageStatus = lineage.status;
          }
        }
        return Object.freeze({ status: 'existing', profileRef: existing.entry_id, version: existing.version, freshness: 'body_retrieved_unchanged', originalLineageStatus });
      }
      const current = database.prepare('SELECT * FROM reuse_entries WHERE scope_kind = ? AND partition_hash = ? AND identity_hash = ? AND eligible = 1 AND binding_hash IS NULL ORDER BY version DESC')
        .all(scopeKind, keys.partitionHash, keys.identityHash);
      const historicalCap = database.prepare('SELECT MIN(expires_at_ms) AS expires_at_ms FROM reuse_entries WHERE scope_kind = ? AND partition_hash = ? AND identity_hash = ? AND cache_key_hash = ?')
        .get(scopeKind, keys.partitionHash, keys.identityHash, keys.cacheKeyHash).expires_at_ms;
      const fixedExpiry = historicalCap === null ? retention.expiresAtMs : Math.min(retention.expiresAtMs, historicalCap);
      if (fixedExpiry <= time.now) fail('REUSE_POLICY_UNAVAILABLE');
      for (const oldEntry of current) {
        const oldPayload = decryptEntry(scoped, oldEntry);
        const reason = oldEntry.content_hash_mac !== keys.contentMac ? 'material_fact_change'
          : oldEntry.pins_hash !== keys.pinsHash ? 'policy_version_change' : 'superseded_profile';
        invalidateEntry(database, info, oldEntry, oldPayload, reason, oldPayload.consumers ?? [], time.now, keys);
      }
      const entryCount = database.prepare('SELECT COUNT(*) AS count FROM reuse_entries').get().count;
      if (entryCount >= limits.maxEntries) fail('REUSE_CAPACITY');
      const version = nextVersion(database, scopeKind, keys.partitionHash, keys.identityHash);
      const fixedRetention = Object.freeze({ ...retention, expiresAtMs: fixedExpiry });
      const versionedPayload = freeze({ ...entryPayload, retentionPolicy: fixedRetention, version });
      const sealed = sealBounded(keys.payloadKey.key, keys.payloadKey.keyId, keys.partitionHash, 'entry', profileRef, versionedPayload);
      ensureStorageCapacity(database, sealed.byteLength);
      database.prepare('INSERT INTO reuse_entries (entry_id, scope_kind, partition_hash, identity_hash, cache_key_hash, content_hash_mac, pins_hash, version, created_at_ms, expires_at_ms, eligible, payload_key_id, payload, payload_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)')
        .run(profileRef, scopeKind, keys.partitionHash, keys.identityHash, keys.cacheKeyHash, keys.contentMac, keys.pinsHash, version, time.now, fixedExpiry, keys.payloadKey.keyId, sealed, sealed.byteLength);
      registerConsumers(database, profileRef, scopeKind, keys, consumers);
      insertObservation(database, profileRef, keys.partitionHash, keys.payloadKey.keyId, keys.payloadKey.key,
        { status: 'body_changed', retrievedAtMs: observation.retrievedAtMs, validatedAtMs: observation.validatedAtMs, contentHash: index.contentHash, sourceVersion: observation.sourceVersion, attemptLineage: observation.attemptLineage });
      if (privateLinkPayload) {
        const tenantLinkId = randomUUID();
        const linkPayload = { ...privateLinkPayload, version, expiresAtMs: fixedExpiry };
        const linkCiphertext = sealBounded(privateLinkKeys.payloadKey.key, privateLinkKeys.payloadKey.keyId, privateLinkKeys.partitionHash, 'private_link', tenantLinkId, linkPayload);
        if (database.prepare('SELECT COUNT(*) AS count FROM reuse_private_links').get().count >= limits.maxPrivateLinks) fail('REUSE_CAPACITY');
        ensureStorageCapacity(database, linkCiphertext.byteLength);
        database.prepare('INSERT INTO reuse_private_links (link_id, tenant_partition_hash, public_entry_id, payload_key_id, payload) VALUES (?, ?, ?, ?, ?)')
          .run(tenantLinkId, privateLinkKeys.partitionHash, profileRef, privateLinkKeys.payloadKey.keyId, linkCiphertext);
      }
      return Object.freeze({ status: 'stored', profileRef, version, freshness: 'fresh', originalLineageStatus: lineage.status, rights: 'not_asserted' });
    });
    await authorize(info, request, scopeKind === 'public_profile' ? 'public_profile.publish' : 'private_profile.write');
    if (signalAborted(external.signal)) fail('REUSE_DENIED');
    if (result.status === 'stored' || result.status === 'existing') {
      const headState = await withDatabase((database, time) => {
        if (time.clockRollback) return 'clock_rollback';
        const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?')
          .get(result.profileRef, scopeKind, keys.partitionHash);
        const head = database.prepare('SELECT entry_id, expires_at_ms FROM reuse_entries WHERE scope_kind = ? AND partition_hash = ? AND identity_hash = ? AND eligible = 1 AND binding_hash IS NULL ORDER BY version DESC LIMIT 1')
          .get(scopeKind, keys.partitionHash, keys.identityHash);
        if (!current || current.eligible !== 1 || !head || head.entry_id !== current.entry_id) return 'not_current_head';
        if (current.expires_at_ms <= time.now || head.expires_at_ms <= time.now) {
          const currentPayload = decryptEntry(scoped, current);
          expireEntry(database, info, current, currentPayload, time.now, keys);
          return 'expired';
        }
        return 'current';
      });
      await authorize(info, request, scopeKind === 'public_profile' ? 'public_profile.publish' : 'private_profile.write');
      if (signalAborted(external.signal)) fail('REUSE_DENIED');
      if (headState === 'expired') {
        return Object.freeze({ status: 'expired', profileRef: result.profileRef, version: result.version, freshness: 'unavailable', originalLineageStatus: 'unknown' });
      }
      if (headState !== 'current') fail('REUSE_DENIED');
    }
    return result;
  }

  async function putPrivateProfile(scope, request, inputValue) {
    const info = scopeInfo(scope);
    const input = record(inputValue, new Set(['identity', 'contentHash', 'pins', 'facts', 'observation', 'freshnessTtlMs', 'expiresAtMs', 'signal']));
    if (!input) fail('REUSE_INVALID');
    const facts = copyFacts(input.facts);
    copyIndex(input);
    await authorize(info, request, 'private_profile.write');
    return storeProfile(info, request, 'tenant_private', input, facts, { signal: input.signal });
  }

  async function putBoundPrivateProfile(scope, request, inputValue, bindingValue, operation, commitGate, signal, capability, preflightToken) {
    if (!isCorrectionCacheBindingCapability(capability)) fail('REUSE_DENIED');
    const info = scopeInfo(scope);
    const input = record(inputValue, new Set(['identity', 'contentHash', 'pins', 'facts', 'observation', 'freshnessTtlMs', 'expiresAtMs']));
    const binding = record(bindingValue, new Set([
      'bindingId', 'eventId', 'historyVersionId', 'historyContentHash', 'historyProjectionHash', 'historyExpiresAtMs',
    ]));
    if (!input || !binding || typeof commitGate !== 'function' || !operation
      || typeof operation.operationId !== 'string' || !Number.isSafeInteger(operation.fence)
      || operation.fence < 1 || !string(binding.bindingId, 128) || !string(binding.eventId, 180)
      || !string(binding.historyVersionId, 180) || !/^[a-f0-9]{64}$/.test(binding.historyContentHash)
      || !/^[a-f0-9]{64}$/.test(binding.historyProjectionHash)
      || !Number.isSafeInteger(binding.historyExpiresAtMs)) fail('REUSE_INVALID');
    const facts = copyFacts(input.facts);
    const index = copyIndex(input);
    const preflight = preflightToken && boundProfilePreflights.get(preflightToken);
    const bindingCoordinates = Object.freeze({
      eventId: binding.eventId,
      historyVersionId: binding.historyVersionId,
      historyContentHash: binding.historyContentHash,
      historyProjectionHash: binding.historyProjectionHash,
      historyExpiresAtMs: binding.historyExpiresAtMs,
      operationId: operation.operationId,
      bindingId: binding.bindingId,
    });
    const signature = boundProfileSignature(index, input, facts, bindingCoordinates);
    if (!preflight || preflight.used || preflight.info !== info || preflight.request !== request
      || preflight.signature !== signature || stable(preflight.binding) !== stable(bindingCoordinates)) fail('REUSE_INVALID');
    preflight.used = true;
    await authorize(info, request, 'private_profile.write');
    if (signalAborted(signal)) fail('REUSE_DENIED');
    if (preflight.replayed) {
      const exactBinding = Object.freeze({ ...binding, operationId: operation.operationId,
        operationPhase: operation.phase, cacheBindingHash: preflight.replayProof.receipt?.binding_hash });
      const current = await withBindingRead((database, time) => {
        if (time.clockRollback || signalAborted(signal) || time.now >= preflight.replayPayload.retentionPolicy.expiresAtMs) {
          fail('REUSE_POLICY_UNAVAILABLE');
        }
        const rows = readBoundReplayRows(database, exactBinding, preflight.keys);
        if (!sameBoundReceiptRows(preflight.replayProof, rows) || !rows.entry
          || rows.entry.eligible !== 1 || rows.entry.payload_purged !== 0
          || rows.entry.expires_at_ms !== preflight.replayPayload.retentionPolicy.expiresAtMs) fail('REUSE_BUSY');
        return { row: rows.entry, now: time.now };
      });
      await authorize(info, request, 'private_profile.write');
      if (signalAborted(signal)) fail('REUSE_DENIED');
      const freshnessDeadlineMs = preflight.replayPayload.initialValidatedAtMs + preflight.replayPayload.freshnessTtlMs;
      return Object.freeze({ status: 'stored', profileRef: current.row.entry_id, version: current.row.version,
        freshness: current.now >= freshnessDeadlineMs ? 'stale' : 'fresh',
        originalLineageStatus: preflight.replayPayload.lineage?.status ?? 'unknown', replayed: true,
        expiresAtMs: current.row.expires_at_ms, bindingHash: current.row.binding_hash,
        identity: index.identity, pins: index.pins, cacheSourceContentHash: index.contentHash,
        scopeKind: 'tenant_private' });
    }
    return await storeProfile(info, request, 'tenant_private', input, facts, {
      correctionBinding: Object.freeze({ ...binding, operationId: operation.operationId }),
      bindingOperation: operation,
      commitGate,
      signal,
      boundProfilePreflight: preflight,
    });
  }

  async function validateBoundPrivateProfileInput(scope, request, inputValue, signal, capability, callerFacts, bindingValue) {
    if (!isCorrectionCacheBindingCapability(capability)) fail('REUSE_DENIED');
    const info = scopeInfo(scope);
    const input = record(inputValue, new Set([
      'identity', 'contentHash', 'pins', 'facts', 'observation', 'freshnessTtlMs', 'expiresAtMs',
    ]));
    const binding = record(bindingValue, new Set([
      'eventId', 'historyVersionId', 'historyContentHash', 'historyProjectionHash', 'historyExpiresAtMs',
      'operationId', 'bindingId', 'operationPhase',
    ]));
    if (!input || !Object.hasOwn(input, 'facts') || !Object.hasOwn(input, 'observation')
      || !binding || !string(binding.eventId, 180) || !string(binding.historyVersionId, 180)
      || !/^[a-f0-9]{64}$/.test(binding.historyContentHash ?? '')
      || !/^[a-f0-9]{64}$/.test(binding.historyProjectionHash ?? '')
      || !string(binding.operationId, 36) || !/^[0-9a-f-]{36}$/i.test(binding.operationId)
      || !string(binding.bindingId, 36) || !/^[0-9a-f-]{36}$/i.test(binding.bindingId)
      || !['new', 'pending_bind', 'complete'].includes(binding.operationPhase)
      || !Number.isSafeInteger(binding.historyExpiresAtMs) || binding.historyExpiresAtMs < 0
      || binding.historyExpiresAtMs > MAX_TIME) fail('REUSE_INVALID');
    const index = copyIndex(input);
    const facts = copyFacts(input.facts);
    if (callerFacts !== undefined) copyFacts(callerFacts);
    if (input.freshnessTtlMs !== undefined
      && (!Number.isSafeInteger(input.freshnessTtlMs) || input.freshnessTtlMs < 1
        || input.freshnessTtlMs > limits.maxRetentionMs)) fail('REUSE_INVALID');
    if (input.expiresAtMs !== undefined
      && (!Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs < 0 || input.expiresAtMs > MAX_TIME)) {
      fail('REUSE_INVALID');
    }
    let keys;
    let transferred = false;
    try {
      const now = currentTime();
      if (signalAborted(signal)) fail('REUSE_DENIED');
      await authorize(info, request, 'private_profile.write');
      if (signalAborted(signal)) fail('REUSE_DENIED');
      const guard = authorizationGuard(info, request, 'private_profile.write', signal);
      keys = await indexParts(info, 'tenant_private', index, guard);
      const cacheBindingHash = mac(keys.keyInfo.key,
        `event-intelligence:correction-cache-binding:v1:${keys.partitionHash}:${binding.bindingId}`);
      const exactBinding = Object.freeze({ ...binding, cacheBindingHash });
      const signatureBinding = Object.freeze({ eventId: binding.eventId, historyVersionId: binding.historyVersionId,
        historyContentHash: binding.historyContentHash, historyProjectionHash: binding.historyProjectionHash,
        historyExpiresAtMs: binding.historyExpiresAtMs, operationId: binding.operationId, bindingId: binding.bindingId });
      const cacheSignature = boundProfileSignature(index, input, facts, signatureBinding);

      if (binding.operationPhase !== 'new') {
        const candidate = await withBindingRead((database, time) => {
          if (time.clockRollback) fail('REUSE_DENIED');
          return { rows: readBoundReplayRows(database, exactBinding, keys), now: time.now };
        });
        if (candidate.rows.receipt) {
          if (binding.operationPhase === 'new') fail('REUSE_BUSY');
          const receipt = await verifyBoundReceipt({ info, request, signal, keys, index, facts,
            binding: exactBinding, rows: candidate.rows, now: candidate.now });
          const confirmed = await withBindingRead((database, time) => {
            if (time.clockRollback || time.now >= receipt.expiresAtMs) fail('REUSE_POLICY_UNAVAILABLE');
            const current = readBoundReplayRows(database, exactBinding, keys);
            if (!sameBoundReceiptRows(candidate.rows, current)) fail('REUSE_BUSY');
            return current;
          });
          const preflightToken = opaque();
          boundProfilePreflights.set(preflightToken, {
            info,
            request,
            signature: cacheSignature,
            binding: Object.freeze({ ...signatureBinding }),
            observation: receipt.observation,
            entryPayload: receipt.payload,
            retention: receipt.payload.retentionPolicy,
            replayProof: confirmed,
            replayPayload: receipt.payload,
            replayed: true,
            ttlMs: receipt.payload.freshnessTtlMs,
            nowMs: now,
            privateReferences: null,
            lineage: receipt.payload.lineage,
            consumers: receipt.payload.consumers,
            index,
            keys,
            used: false,
          });
          transferred = true;
          return preflightToken;
        }
        if (binding.operationPhase === 'complete' || candidate.rows.bindingEntries.length > 0
          || candidate.rows.bindingReservations.length > 0 || candidate.rows.invalidationReceipts.length > 0) {
          fail('REUSE_INTEGRITY');
        }
      }

      const observation = validateInitialObservation(
        await verifyObservation(info, request, index.contentHash, input.observation, 'initial'), index.contentHash, now);
      await authorize(info, request, 'private_profile.write');
      if (signalAborted(signal)) fail('REUSE_DENIED');
      let retention = await resolveRetention(info, 'tenant_private', now, input.expiresAtMs ?? null);
      await authorize(info, request, 'private_profile.write');
      if (signalAborted(signal)) fail('REUSE_DENIED');
      const ttlMs = input.freshnessTtlMs ?? limits.defaultFreshnessTtlMs;
      const freshnessDeadlineMs = observation.validatedAtMs + ttlMs;
      if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > limits.maxRetentionMs
        || !Number.isSafeInteger(freshnessDeadlineMs) || freshnessDeadlineMs <= now
        || freshnessDeadlineMs > retention.expiresAtMs || freshnessDeadlineMs > binding.historyExpiresAtMs) fail('REUSE_INVALID');

      let privateReferences = { permissions: [], sourceRefs: [], correctionRefs: [] };
      if (typeof config.resolvePrivateProfileReferences === 'function') {
        let references;
        try {
          references = await config.resolvePrivateProfileReferences(Object.freeze({
            tenantId: info.tenantId,
            actorId: info.actorId,
            request,
            kind: 'tenant_private',
            identity: index.identity,
            contentHash: index.contentHash,
            projection: facts,
          }));
        } catch { fail('REUSE_POLICY_UNAVAILABLE'); }
        const parsed = record(references, new Set(['permissions', 'sourceRefs', 'correctionRefs']));
        if (!parsed) fail('REUSE_POLICY_UNAVAILABLE');
        privateReferences = {
          permissions: validatePermissions(parsed.permissions ?? []),
          sourceRefs: boundedRefList(parsed.sourceRefs ?? []),
          correctionRefs: boundedRefList(parsed.correctionRefs ?? []),
        };
        await authorize(info, request, 'private_profile.write');
        if (signalAborted(signal)) fail('REUSE_DENIED');
      }
      const lineage = await resolveLineage(info, request, Object.freeze({
        kind: 'tenant_private', identity: index.identity, contentHash: index.contentHash,
        version: 1, observation: observation.status,
      }));
      await authorize(info, request, 'private_profile.write');
      if (signalAborted(signal)) fail('REUSE_DENIED');
      const consumers = await resolveConsumers(info, request, Object.freeze({
        identity: index.identity, contentHash: index.contentHash, scopeKind: 'tenant_private',
      }));
      await authorize(info, request, 'private_profile.write');
      if (signalAborted(signal)) fail('REUSE_DENIED');
      keys = await keyPartsFromIndex(info, keys, guard);
      assertConsumersRevocable(consumers, keys, keys.partitionHash);
      const permissions = validatePermissions(privateReferences.permissions);
      const correctionBinding = Object.freeze({
        bindingId: binding.bindingId,
        eventId: binding.eventId,
        historyVersionId: binding.historyVersionId,
        historyContentHash: binding.historyContentHash,
        historyProjectionHash: binding.historyProjectionHash,
        operationId: binding.operationId,
        historyExpiresAtMs: binding.historyExpiresAtMs,
      });
      const entryPayload = freeze({
        kind: 'private',
        identity: index.identity,
        pins: index.pins,
        contentHash: index.contentHash,
        facts,
        sourceVersion: observation.sourceVersion,
        retrievedAtMs: observation.retrievedAtMs,
        initialValidatedAtMs: observation.validatedAtMs,
        freshnessTtlMs: ttlMs,
        permissions,
        sourceRefs: privateReferences.sourceRefs,
        correctionRefs: privateReferences.correctionRefs,
        correctionBinding,
        lineage,
        consumers,
        retentionPolicy: retention,
        rights: 'not_asserted',
      });
      if (Buffer.byteLength(stable(entryPayload), 'utf8') > limits.maxEntryBytes) fail('REUSE_CAPACITY');
      if (binding.operationPhase === 'new') {
        assertBoundHistoryEventsFit(consumers, keys, exactBinding, index.contentHash);
      }
      const capacity = await preflightBoundCacheCapacity({ info, request, signal, keys, index, entryPayload,
        observation, consumers, binding: exactBinding, ttlMs });
      retention = capacity.retention;
      if (!capacity.replayed && binding.operationPhase !== 'new') {
        assertBoundHistoryEventsFit(consumers, keys, exactBinding, index.contentHash);
      }
      if (signalAborted(signal)) fail('REUSE_DENIED');
      const preflightToken = opaque();
      boundProfilePreflights.set(preflightToken, {
        info,
        request,
        signature: cacheSignature,
        binding: Object.freeze({ ...signatureBinding }),
        observation,
        entryPayload,
        retention,
        replayProof: capacity.replayProof,
        replayed: capacity.replayed,
        ttlMs,
        freshnessDeadlineMs: capacity.freshnessDeadlineMs,
        nowMs: now,
        privateReferences,
        lineage,
        consumers,
        index,
        keys,
        used: false,
      });
      transferred = true;
      return preflightToken;
    } finally {
      if (!transferred && keys) {
        try { keys.keyInfo.key.fill(0); } catch { /* Cache-owned key copy. */ }
        try { keys.payloadKey?.key.fill(0); } catch { /* Cache-owned key copy. */ }
      }
    }
  }

  async function publishReviewedPublicProfile(scope, request, inputValue) {
    const info = scopeInfo(scope);
    const input = record(inputValue, new Set([
      'boundary', 'boundaryScope', 'derivative', 'identity', 'contentHash', 'pins', 'observation', 'freshnessTtlMs', 'expiresAtMs', 'signal',
    ]));
    if (!input || !isPrivacyBoundary(input.boundary) || !input.boundaryScope || !input.derivative
      || typeof config.authorizePublicPublication !== 'function') fail('REUSE_POLICY_UNAVAILABLE');
    const parsedIdentity = identity(input.identity);
    const contentHash = hashValue(input.contentHash);
    const parsedPins = pins(input.pins);
    let exported;
    try { exported = input.boundary.exportDerivative(input.boundaryScope, input.derivative); } catch { fail('REUSE_DENIED'); }
    const facts = copyFacts(exported.facts, true);
    await authorize(info, request, 'public_profile.publish');
    let attestation;
    try {
      attestation = await config.authorizePublicPublication(Object.freeze({
        tenantId: info.tenantId,
        actorId: info.actorId,
        request,
        boundaryTrust: exported.trust,
        facts,
        identity: parsedIdentity,
        contentHash,
        boundaryScope: input.boundaryScope,
        sourceRecordId: exported.recordId,
      }));
    } catch { fail('REUSE_POLICY_UNAVAILABLE'); }
    await authorize(info, request, 'public_profile.publish');
    if (signalAborted(input.signal)) fail('REUSE_DENIED');
    const approval = record(attestation, new Set(['status', 'contentHash', 'identity', 'publicPermissions']));
    if (!approval || approval.status !== 'approved' || approval.contentHash !== contentHash
      || stable(identity(approval.identity)) !== stable(parsedIdentity)) fail('REUSE_POLICY_UNAVAILABLE');
    const publicPermissions = validatePermissions(approval.publicPermissions ?? []);
    return storeProfile(info, request, 'public_profile', {
      identity: parsedIdentity,
      contentHash,
      pins: parsedPins,
      observation: input.observation,
      freshnessTtlMs: input.freshnessTtlMs,
      expiresAtMs: input.expiresAtMs,
      signal: input.signal,
    }, facts, { publicPermissions, sourceRecordId: exported.recordId, signal: input.signal });
  }

  function eligibility(row, payload, observation, now, clockRollback, pinsMatch) {
    if (clockRollback) return { status: 'unavailable', reason: 'clock_rollback' };
    if (row.eligible !== 1) return { status: 'unavailable', reason: 'invalidated' };
    if (!pinsMatch) return { status: 'stale', reason: 'policy_hash_stale' };
    if (row.expires_at_ms <= now || payload.retentionPolicy?.expiresAtMs <= now) return { status: 'unavailable', reason: 'expired' };
    if (observation.status === 'removed') return { status: 'unavailable', reason: 'source_removed' };
    if (observation.status === 'evidence_lost') return { status: 'unavailable', reason: 'evidence_lost' };
    if (observation.status === 'outage') return { status: 'unavailable', reason: 'source_outage' };
    if (observation.status === 'body_changed' && observation.contentHash !== payload.contentHash) return { status: 'stale', reason: 'body_changed' };
    if (!Number.isSafeInteger(observation.validatedAtMs) || observation.validatedAtMs > now + 60_000) return { status: 'unavailable', reason: 'invalid_validation_time' };
    if (now - observation.validatedAtMs >= payload.freshnessTtlMs) return { status: 'stale', reason: 'ttl_expired' };
    return { status: 'fresh', reason: null };
  }

  async function readCurrentFreshness(info, request, scopeKind, row, entryPayload, keys, readGuard, pinsMatch, linkedPrivateRef = null) {
    const snapshot = () => withDatabase((database, time) => {
      let current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?')
        .get(row.entry_id, scopeKind, row.partition_hash);
      if (!time.clockRollback && current && current.expires_at_ms <= time.now && current.payload_purged !== 1) {
        expireEntry(database, info, current, current.eligible === 1 ? entryPayload : null, time.now, keys);
        current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?')
          .get(row.entry_id, scopeKind, row.partition_hash);
      }
      const head = database.prepare('SELECT entry_id, expires_at_ms FROM reuse_entries WHERE scope_kind = ? AND partition_hash = ? AND identity_hash = ? AND eligible = 1 AND binding_hash IS NULL ORDER BY version DESC LIMIT 1')
        .get(scopeKind, row.partition_hash, row.identity_hash);
      const observation = current?.eligible === 1
        ? database.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(row.entry_id)
        : null;
      const privateLink = linkedPrivateRef === null ? null
        : database.prepare('SELECT link_id, payload_key_id, payload, length(payload) AS payload_bytes FROM reuse_private_links WHERE public_entry_id = ? AND tenant_partition_hash = ?')
          .get(row.entry_id, linkedPrivateRef.partitionHash);
      return { now: time.now, clockRollback: time.clockRollback, current, head, observation, privateLink };
    });

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const first = await snapshot();
      if (first.clockRollback) return { state: { status: 'unavailable', reason: 'clock_rollback' }, now: first.now };
      if (!first.current || first.current.eligible !== 1 || !first.head || first.head.entry_id !== row.entry_id) {
        return { state: { status: 'unavailable', reason: first.current?.expires_at_ms <= first.now ? 'expired' : 'invalidated' }, now: first.now };
      }
      if (first.current.expires_at_ms <= first.now) return { state: { status: 'unavailable', reason: 'expired' }, now: first.now };
      if (!first.observation) return { state: { status: 'unavailable', reason: 'observation_missing' }, now: first.now };
      const observationKey = first.observation.payload_key_id === keys.payloadKey.keyId
        ? keys.payloadKey
        : await resolveKey(scopeKind === 'public_profile' ? null : info, 'payload', first.observation.payload_key_id, readGuard);
      const observation = unseal(observationKey.key, row.partition_hash, 'observation', first.observation.observation_id,
        first.observation.payload, first.observation.payload_key_id);
      const final = await snapshot();
      if (final.clockRollback) return { state: { status: 'unavailable', reason: 'clock_rollback' }, now: final.now };
      if (!final.current || final.current.eligible !== 1 || !final.head || final.head.entry_id !== row.entry_id) {
        return { state: { status: 'unavailable', reason: final.current?.expires_at_ms <= final.now ? 'expired' : 'invalidated' }, now: final.now };
      }
      if (final.current.version !== first.current.version || final.current.payload_bytes !== first.current.payload_bytes
        || !final.observation || final.observation.sequence !== first.observation.sequence
        || final.observation.observation_id !== first.observation.observation_id) continue;
      if (linkedPrivateRef && (!final.privateLink || final.privateLink.link_id !== linkedPrivateRef.linkId
        || final.privateLink.payload_key_id !== linkedPrivateRef.payloadKeyId
        || final.privateLink.payload_bytes !== linkedPrivateRef.payloadBytes)) {
        return { state: { status: 'unavailable', reason: 'invalidated' }, now: final.now };
      }
      const state = eligibility(final.current, entryPayload, observation, final.now, false, pinsMatch);
      return { state, now: final.now, observation, current: final.current, head: final.head, privateLink: final.privateLink };
    }
    return { state: { status: 'unavailable', reason: 'observation_changed' }, now: currentTime() };
  }

  async function finalizeCurrentFreshness(info, request, action, scopeKind, row, entryPayload, keys, readGuard,
    pinsMatch, linkedPrivateRef, permissionCheck, complete) {
    const entryInfo = scopeKind === 'public_profile' ? null : info;
    const snapshot = () => withDatabase((database, time) => {
      let current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?')
        .get(row.entry_id, scopeKind, row.partition_hash);
      if (!time.clockRollback && current && current.expires_at_ms <= time.now && current.payload_purged !== 1) {
        expireEntry(database, entryInfo, current, current.eligible === 1 ? entryPayload : null, time.now, keys);
        current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?')
          .get(row.entry_id, scopeKind, row.partition_hash);
      }
      const head = database.prepare('SELECT entry_id, expires_at_ms FROM reuse_entries WHERE scope_kind = ? AND partition_hash = ? AND identity_hash = ? AND eligible = 1 AND binding_hash IS NULL ORDER BY version DESC LIMIT 1')
        .get(scopeKind, row.partition_hash, row.identity_hash);
      const observation = current?.eligible === 1
        ? database.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(row.entry_id)
        : null;
      const privateLink = linkedPrivateRef === null ? null
        : database.prepare('SELECT link_id, payload_key_id, payload, length(payload) AS payload_bytes FROM reuse_private_links WHERE public_entry_id = ? AND tenant_partition_hash = ?')
          .get(row.entry_id, linkedPrivateRef.partitionHash);
      return { now: time.now, clockRollback: time.clockRollback, current, head, observation, privateLink };
    });
    const finishEarly = (state, now) => complete({ state, now }, undefined);
    const first = await snapshot();
    if (first.clockRollback) return finishEarly({ status: 'unavailable', reason: 'clock_rollback' }, first.now);
    if (!first.current || first.current.eligible !== 1 || !first.head || first.head.entry_id !== row.entry_id) {
      return finishEarly({ status: 'unavailable', reason: first.current?.expires_at_ms <= first.now ? 'expired' : 'invalidated' }, first.now);
    }
    if (first.current.expires_at_ms <= first.now) return finishEarly({ status: 'unavailable', reason: 'expired' }, first.now);
    if (!sameStoredEntry(first.current, row)) return finishEarly({ status: 'unavailable', reason: 'observation_changed' }, first.now);
    if (!first.observation) return finishEarly({ status: 'unavailable', reason: 'observation_missing' }, first.now);
    if (linkedPrivateRef && (!first.privateLink || first.privateLink.link_id !== linkedPrivateRef.linkId
      || first.privateLink.payload_key_id !== linkedPrivateRef.payloadKeyId
      || first.privateLink.payload_bytes !== linkedPrivateRef.payloadBytes
      || !Buffer.from(first.privateLink.payload).equals(Buffer.from(linkedPrivateRef.payload)))) {
      return finishEarly({ status: 'unavailable', reason: 'invalidated' }, first.now);
    }
    const observationKey = first.observation.payload_key_id === keys.payloadKey.keyId
      ? keys.payloadKey
      : await resolveKey(scopeKind === 'public_profile' ? null : info, 'payload', first.observation.payload_key_id, readGuard);
    const observation = unseal(observationKey.key, row.partition_hash, 'observation', first.observation.observation_id,
      first.observation.payload, first.observation.payload_key_id);

    // Finish asynchronous filesystem, key, permission and legacy authorization work before
    // the combined current-principal/exact-action host decision.
    // The connection is open but has no transaction while trusted host callbacks run.
    const database = await prepareStoreDatabase();
    let transactionOpen = false;
    let final;
    let finalPermissionState;
    try {
      if (permissionCheck) finalPermissionState = await permissionCheck();
      await authorize(info, request, action, { profileRef: row.entry_id });
      await authorizeCurrentRequest(info, request, action, { profileRef: row.entry_id });
      database.exec('BEGIN IMMEDIATE');
      transactionOpen = true;
      const currentMax = database.prepare("SELECT value FROM reuse_meta WHERE key = 'clock_max_ms'").get();
      const now = currentTime();
      const previousMax = currentMax ? Number(currentMax.value) : null;
      if (currentMax && (!Number.isSafeInteger(previousMax) || previousMax < 0 || previousMax > MAX_TIME)) fail('REUSE_INTEGRITY');
      const clockRollback = Boolean(currentMax && now < previousMax);
      if (!clockRollback && (!currentMax || now > previousMax)) {
        database.prepare("INSERT INTO reuse_meta (key, value) VALUES ('clock_max_ms', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(String(now));
      }
      let current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?')
        .get(row.entry_id, scopeKind, row.partition_hash);
      if (!clockRollback && current && current.expires_at_ms <= now && current.payload_purged !== 1) {
        expireEntry(database, entryInfo, current, current.eligible === 1 ? entryPayload : null, now, keys);
        current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?')
          .get(row.entry_id, scopeKind, row.partition_hash);
      }
      const head = database.prepare('SELECT entry_id, expires_at_ms FROM reuse_entries WHERE scope_kind = ? AND partition_hash = ? AND identity_hash = ? AND eligible = 1 AND binding_hash IS NULL ORDER BY version DESC LIMIT 1')
        .get(scopeKind, row.partition_hash, row.identity_hash);
      const latestObservation = current?.eligible === 1
        ? database.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(row.entry_id)
        : null;
      const privateLink = linkedPrivateRef === null ? null
        : database.prepare('SELECT link_id, payload_key_id, payload, length(payload) AS payload_bytes FROM reuse_private_links WHERE public_entry_id = ? AND tenant_partition_hash = ?')
          .get(row.entry_id, linkedPrivateRef.partitionHash);
      let state;
      if (clockRollback) {
        state = { status: 'unavailable', reason: 'clock_rollback' };
      } else if (!current || current.eligible !== 1 || !head || head.entry_id !== row.entry_id) {
        state = { status: 'unavailable', reason: current?.expires_at_ms <= now ? 'expired' : 'invalidated' };
      } else if (current.expires_at_ms <= now) {
        state = { status: 'unavailable', reason: 'expired' };
      } else if (!sameStoredEntry(current, first.current) || !sameStoredObservation(latestObservation, first.observation)) {
        state = { status: 'unavailable', reason: 'observation_changed' };
      } else if (linkedPrivateRef && !sameStoredPrivateLink(privateLink, first.privateLink)) {
        state = { status: 'unavailable', reason: 'invalidated' };
      } else if (!latestObservation) {
        state = { status: 'unavailable', reason: 'observation_missing' };
      } else {
        state = eligibility(current, entryPayload, observation, now, false, pinsMatch);
      }
      final = { state, now, observation, current, head, privateLink, permissionState: finalPermissionState };
      database.exec('COMMIT');
      transactionOpen = false;
    } catch (error) {
      if (transactionOpen) {
        try { database.exec('ROLLBACK'); } catch { /* SQLite also rolls back when the connection closes. */ }
      }
      throw safeError(error);
    } finally {
      database.close();
    }
    // Internal completion only builds the result or invokes the authorized Finance callback.
    // It runs synchronously after the persisted snapshot and outside any SQLite transaction.
    return await complete(final, finalPermissionState);
  }

  function sameStoredEntry(left, right) {
    return Boolean(left && right && left.entry_id === right.entry_id && left.scope_kind === right.scope_kind
      && left.partition_hash === right.partition_hash && left.identity_hash === right.identity_hash
      && left.version === right.version && left.expires_at_ms === right.expires_at_ms
      && left.eligible === right.eligible && left.payload_key_id === right.payload_key_id
      && left.payload_bytes === right.payload_bytes && left.payload_purged === right.payload_purged
      && Buffer.from(left.payload).equals(Buffer.from(right.payload)));
  }

  function sameStoredObservation(left, right) {
    return Boolean(left && right && left.observation_id === right.observation_id && left.entry_id === right.entry_id
      && left.sequence === right.sequence && left.observed_at_ms === right.observed_at_ms && left.status === right.status
      && left.payload_key_id === right.payload_key_id && Buffer.from(left.payload).equals(Buffer.from(right.payload)));
  }

  function sameStoredPrivateLink(left, right) {
    return Boolean(left && right && left.link_id === right.link_id && left.payload_key_id === right.payload_key_id
      && left.payload_bytes === right.payload_bytes && Buffer.from(left.payload).equals(Buffer.from(right.payload)));
  }

  async function lookupProfile(scope, request, scopeKind, lookupValue, use = 'fact_read') {
    const info = scope ? scopeInfo(scope) : null;
    const lookup = record(lookupValue, new Set(['identity', 'contentHash', 'pins']));
    if (!lookup) fail('REUSE_INVALID');
    const index = copyIndex(lookup);
    const readAction = `${scopeKind === 'public_profile' ? 'public' : 'private'}_profile.read`;
    if (info) await authorize(info, request, readAction);
    const keys = await keyParts(info, scopeKind, index, async () => {
      if (info) await authorize(info, request, readAction);
    });
    const candidate = await withDatabase((database, time) => {
      if (time.clockRollback) return { clockRollback: true };
      const exact = database.prepare('SELECT * FROM reuse_entries WHERE scope_kind = ? AND partition_hash = ? AND cache_key_hash = ? AND binding_hash IS NULL ORDER BY version DESC LIMIT 1')
        .get(scopeKind, keys.partitionHash, keys.cacheKeyHash);
      const row = exact ?? database.prepare('SELECT * FROM reuse_entries WHERE scope_kind = ? AND partition_hash = ? AND identity_hash = ? AND binding_hash IS NULL ORDER BY version DESC LIMIT 1')
        .get(scopeKind, keys.partitionHash, keys.identityHash);
      if (!row) return null;
      if (row.eligible !== 1) return { row, now: time.now, payloadKey: null, invalidated: true, clockRollback: false };
      const payloadKey = keys.payloadKey.keyId === row.payload_key_id ? keys.payloadKey : null;
      return { row, now: time.now, payloadKey, clockRollback: false };
    });
    if (!candidate) return Object.freeze({ status: 'miss' });
    if (candidate.clockRollback) return Object.freeze({ status: 'unavailable', reason: 'clock_rollback' });
    const row = candidate.row;
    if (candidate.invalidated) {
      if (row.expires_at_ms <= candidate.now && row.payload_purged !== 1) {
        await withDatabase((database, time) => {
          const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?')
            .get(row.entry_id, scopeKind, row.partition_hash);
          expireEntry(database, info, current, null, time.now, keys);
        });
      }
      if (info) await authorize(info, request, `${scopeKind === 'public_profile' ? 'public' : 'private'}_profile.read`);
      return Object.freeze({ status: 'unavailable', reason: 'invalidated', profileRef: row.entry_id });
    }
    const readGuard = authorizationGuard(info, request, readAction);
    const payloadKey = candidate.payloadKey ?? await resolveKey(scopeKind === 'public_profile' ? null : info, 'payload', row.payload_key_id, readGuard);
    const entryPayload = unseal(payloadKey.key, row.partition_hash, 'entry', row.entry_id, row.payload, row.payload_key_id);
    const latest = await withDatabase((database) => {
      const observationRow = database.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(row.entry_id);
      if (!observationRow) fail('REUSE_INTEGRITY');
      return observationRow;
    });
    const observationKey = latest.payload_key_id === payloadKey.keyId ? payloadKey : await resolveKey(scopeKind === 'public_profile' ? null : info, 'payload', latest.payload_key_id, readGuard);
    const observation = unseal(observationKey.key, row.partition_hash, 'observation', latest.observation_id, latest.payload, latest.payload_key_id);
    const identityMatches = stable(entryPayload.identity) === stable(index.identity);
    const contentMatches = entryPayload.contentHash === index.contentHash;
    const pinsMatch = row.pins_hash === keys.pinsHash && stable(entryPayload.pins) === stable(index.pins);
    const state = !identityMatches
      ? { status: 'stale', reason: 'identity_version_mismatch' }
      : !contentMatches
        ? { status: 'stale', reason: 'content_hash_mismatch' }
        : eligibility(row, entryPayload, observation, candidate.now, false, pinsMatch);
    if (state.status !== 'fresh') {
      if (state.reason === 'expired') {
        await withDatabase((database, time) => {
          const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ?').get(row.entry_id);
          expireEntry(database, info, current, entryPayload, time.now, keys);
        });
      } else if (state.reason === 'source_removed' || state.reason === 'evidence_lost') {
        const consumers = entryPayload.consumers ?? [];
        await withDatabase((database, time) => {
          const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ?').get(row.entry_id);
          invalidateEntry(database, info, current, entryPayload, state.reason, consumers, time.now, keys);
        });
      }
      if (info) await authorize(info, request, `${scopeKind === 'public_profile' ? 'public' : 'private'}_profile.read`);
      return Object.freeze({ status: state.status, reason: state.reason, profileRef: row.entry_id });
    }
    const permissionState = await maybePermissions(info, request, entryPayload, use, candidate.now);
    if (info) await authorize(info, request, `${scopeKind === 'public_profile' ? 'public' : 'private'}_profile.read`);
    const invalidatePermission = async (state) => {
      if (state.status !== 'revoked' && state.status !== 'expired') return;
      await withDatabase((database, time) => {
        const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ?').get(row.entry_id);
        invalidateEntry(database, info, current, entryPayload, `permission_${state.status}`, entryPayload.consumers ?? [], time.now, keys);
      });
      if (info) await authorize(info, request, readAction);
    };
    if (!permissionState.valid) {
      await invalidatePermission(permissionState);
      return Object.freeze({ status: 'ineligible', reason: `permission_${permissionState.status}`, profileRef: row.entry_id });
    }
    const finalState = await readCurrentFreshness(info, request, scopeKind, row, entryPayload, keys, readGuard, pinsMatch);
    if (finalState.state.status !== 'fresh') {
      if (info) await authorize(info, request, `${scopeKind === 'public_profile' ? 'public' : 'private'}_profile.read`);
      return Object.freeze({ status: finalState.state.status, reason: finalState.state.reason, profileRef: row.entry_id });
    }
    const preFinalPermissionState = await maybePermissions(info, request, entryPayload, use, currentTime());
    if (!preFinalPermissionState.valid) {
      await invalidatePermission(preFinalPermissionState);
      return Object.freeze({ status: 'ineligible', reason: `permission_${preFinalPermissionState.status}`, profileRef: row.entry_id });
    }
    if (info) await authorize(info, request, readAction);
    const finalized = await finalizeCurrentFreshness(info, request, readAction, scopeKind, row, entryPayload, keys,
      readGuard, pinsMatch, null,
      () => maybePermissions(info, request, entryPayload, use, currentTime()),
      (finalCheck, finalPermissionState) => {
        if (finalPermissionState && !finalPermissionState.valid) {
          return { kind: 'permission', state: finalPermissionState };
        }
        if (finalCheck.state.status !== 'fresh') {
          return { kind: 'result', result: Object.freeze({
            status: finalCheck.state.status, reason: finalCheck.state.reason, profileRef: row.entry_id,
          }) };
        }
        if (!finalPermissionState?.valid) {
          return { kind: 'permission', state: finalPermissionState ?? { status: 'unverified' } };
        }
        if (finalPermissionState.validUntilMs !== undefined && finalPermissionState.validUntilMs <= finalCheck.now) {
          return { kind: 'permission', state: { status: 'expired' } };
        }
        const finalObservation = finalCheck.observation;
        if (scopeKind === 'public_profile') {
          return { kind: 'result', result: Object.freeze({
            status: 'hit',
            profileRef: row.entry_id,
            version: row.version,
            facts: entryPayload.facts,
            trust: 'untrusted_external',
            rights: 'not_asserted',
            permissionStatus: finalPermissionState.status,
            retrievedAt: iso(effectiveRetrievedAt(entryPayload, finalObservation)),
            validatedAt: iso(finalObservation.validatedAtMs),
            expiresAt: iso(row.expires_at_ms),
            originalLineageStatus: entryPayload.lineage?.status ?? 'unknown',
          }) };
        }
        return { kind: 'result', result: Object.freeze({
          status: 'hit',
          profileRef: row.entry_id,
          version: row.version,
          facts: entryPayload.facts,
          trust: 'tenant_private',
          permissionStatus: finalPermissionState.status,
          retrievedAt: iso(effectiveRetrievedAt(entryPayload, finalObservation)),
          validatedAt: iso(finalObservation.validatedAtMs),
          expiresAt: iso(row.expires_at_ms),
          originalLineageStatus: entryPayload.lineage?.status ?? 'unknown',
        }) };
      });
    if (finalized.kind === 'permission') {
      await invalidatePermission(finalized.state);
      return Object.freeze({ status: 'ineligible', reason: `permission_${finalized.state.status}`, profileRef: row.entry_id });
    }
    return finalized.result;
  }

  async function getPrivateProfile(scope, request, lookup) {
    scopeInfo(scope);
    return lookupProfile(scope, request, 'tenant_private', lookup, 'cache_read');
  }

  async function loadBoundCandidate(scope, request, bindingValue, use, signal, capability) {
    if (!isCorrectionCacheBindingCapability(capability)) fail('REUSE_DENIED');
    const info = scopeInfo(scope);
    const binding = record(bindingValue, new Set([
      'bindingId', 'eventId', 'historyVersionId', 'historyContentHash', 'historyProjectionHash',
      'operationId', 'profileRef', 'cacheVersion', 'scopeKind', 'cacheBindingHash', 'identity', 'pins',
      'cacheSourceContentHash', 'cacheExpiresAtMs', 'historyExpiresAtMs', 'expiresAtMs',
    ]));
    if (!binding || !string(binding.bindingId, 128) || !string(binding.eventId, 180)
      || !string(binding.historyVersionId, 180) || !/^[a-f0-9]{64}$/.test(binding.historyContentHash)
      || !/^[a-f0-9]{64}$/.test(binding.historyProjectionHash) || !string(binding.profileRef, 128)
      || !string(binding.operationId, 128)
      || !Number.isSafeInteger(binding.cacheVersion) || binding.cacheVersion < 1
      || binding.scopeKind !== 'tenant_private' || !/^[a-f0-9]{64}$/.test(binding.cacheBindingHash)
      || !/^[a-f0-9]{64}$/.test(binding.cacheSourceContentHash)
      || !Number.isSafeInteger(binding.cacheExpiresAtMs) || !Number.isSafeInteger(binding.historyExpiresAtMs)
      || !Number.isSafeInteger(binding.expiresAtMs)) fail('REUSE_DENIED');
    const action = 'private_profile.read';
    const index = copyIndex({ identity: binding.identity, contentHash: binding.cacheSourceContentHash, pins: binding.pins });
    await authorize(info, request, action, { profileRef: binding.profileRef });
    if (signalAborted(signal)) fail('REUSE_DENIED');
    const guard = async () => {
      await authorize(info, request, action, { profileRef: binding.profileRef });
      if (signalAborted(signal)) fail('REUSE_DENIED');
    };
    const keys = await keyParts(info, 'tenant_private', index, guard);
    const expectedBindingHash = mac(keys.keyInfo.key,
      `event-intelligence:correction-cache-binding:v1:${keys.partitionHash}:${binding.bindingId}`);
    if (expectedBindingHash !== binding.cacheBindingHash) fail('REUSE_DENIED');
    const raw = await withBindingRead((database, time) => {
      const row = database.prepare(`SELECT * FROM reuse_entries WHERE entry_id = ?
        AND scope_kind = 'tenant_private' AND partition_hash = ?`).get(binding.profileRef, keys.partitionHash);
      const observation = row?.eligible === 1
        ? database.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(row.entry_id)
        : null;
      return { row, observation, now: time.now, clockRollback: time.clockRollback };
    });
    if (signalAborted(signal) || raw.clockRollback || !raw.row || !raw.observation
      || raw.row.version !== binding.cacheVersion || raw.row.binding_hash !== binding.cacheBindingHash
      || raw.row.eligible !== 1 || raw.row.payload_purged === 1 || raw.row.expires_at_ms !== binding.cacheExpiresAtMs
      || binding.expiresAtMs !== Math.min(binding.cacheExpiresAtMs, binding.historyExpiresAtMs)
      || raw.now >= binding.expiresAtMs) fail('REUSE_DENIED');
    const payloadKey = raw.row.payload_key_id === keys.payloadKey.keyId
      ? keys.payloadKey : await resolveKey(info, 'payload', raw.row.payload_key_id, guard);
    if (signalAborted(signal)) fail('REUSE_DENIED');
    const payload = freeze(unseal(payloadKey.key, raw.row.partition_hash, 'entry', raw.row.entry_id, raw.row.payload, raw.row.payload_key_id));
    const correctionBinding = record(payload.correctionBinding, new Set([
      'bindingId', 'eventId', 'historyVersionId', 'historyContentHash', 'historyProjectionHash', 'operationId', 'historyExpiresAtMs',
    ]));
    if (!correctionBinding || correctionBinding.bindingId !== binding.bindingId
      || correctionBinding.eventId !== binding.eventId || correctionBinding.historyVersionId !== binding.historyVersionId
      || correctionBinding.historyContentHash !== binding.historyContentHash
      || correctionBinding.historyProjectionHash !== binding.historyProjectionHash
      || correctionBinding.operationId !== binding.operationId
      || correctionBinding.historyExpiresAtMs !== binding.historyExpiresAtMs
      || stable(payload.identity) !== stable(index.identity) || stable(payload.pins) !== stable(index.pins)
      || payload.contentHash !== binding.cacheSourceContentHash
      || raw.row.identity_hash !== keys.identityHash || raw.row.content_hash_mac !== keys.contentMac
      || raw.row.pins_hash !== keys.pinsHash) fail('REUSE_DENIED');
    const observationKey = raw.observation.payload_key_id === payloadKey.keyId
      ? payloadKey : await resolveKey(info, 'payload', raw.observation.payload_key_id, guard);
    if (signalAborted(signal)) fail('REUSE_DENIED');
    const observation = freeze(unseal(observationKey.key, raw.row.partition_hash, 'observation', raw.observation.observation_id,
      raw.observation.payload, raw.observation.payload_key_id));
    const state = eligibility(raw.row, payload, observation, raw.now, false, true);
    if (state.status !== 'fresh' && !(state.status === 'stale' && state.reason === 'ttl_expired')) fail('REUSE_DENIED');
    const permissionState = await maybePermissions(info, request, payload, use, raw.now);
    if (signalAborted(signal) || !permissionState.valid || (permissionState.validUntilMs !== undefined
      && permissionState.validUntilMs <= currentTime())) fail('REUSE_DENIED');
    await guard();
    const preFinalNow = currentTime();
    if (preFinalNow >= binding.expiresAtMs || (permissionState.validUntilMs !== undefined
      && preFinalNow >= permissionState.validUntilMs)) fail('REUSE_DENIED');
    return Object.freeze({
      row: raw.row,
      observationRow: raw.observation,
      observation,
      payload,
      freshnessState: Object.freeze({ ...state }),
      permissionState: Object.freeze({ ...permissionState }),
      binding,
      keys: Object.freeze({ partitionHash: keys.partitionHash, identityHash: keys.identityHash,
        contentMac: keys.contentMac, pinsHash: keys.pinsHash, payloadKey }),
      use,
      signal,
    });
  }

  async function prepareBoundReadDatabase(capability) {
    if (!isCorrectionCacheBindingCapability(capability)) fail('REUSE_DENIED');
    return openStoreDatabase(0);
  }

  async function prepareBoundFinalDisclosure(scope, request, preflightToken, bindingValue, signal, capability) {
    if (!isCorrectionCacheBindingCapability(capability)) fail('REUSE_DENIED');
    const info = scopeInfo(scope);
    const binding = record(bindingValue, new Set([
      'schemaVersion', 'bindingId', 'operationId', 'eventId', 'historyVersionId', 'historyContentHash', 'historyProjectionHash',
      'profileRef', 'cacheVersion', 'scopeKind', 'cacheBindingHash', 'identity', 'pins', 'cacheSourceContentHash',
      'cacheExpiresAtMs', 'historyExpiresAtMs', 'expiresAtMs', 'bindingHash', 'referenceHash',
      'lastInvalidationOperationId', 'lastInvalidationTargetVersionId', 'lastInvalidationTargetHash', 'sealed',
    ]));
    const preflight = preflightToken && boundProfilePreflights.get(preflightToken);
    if (!binding || !preflight || preflight.info !== info || preflight.request !== request
      || binding.schemaVersion !== 1 || binding.scopeKind !== 'tenant_private' || binding.operationId !== preflight.binding.operationId
      || binding.bindingId !== preflight.binding.bindingId || binding.eventId !== preflight.binding.eventId
      || binding.historyVersionId !== preflight.binding.historyVersionId
      || binding.historyContentHash !== preflight.binding.historyContentHash
      || binding.historyProjectionHash !== preflight.binding.historyProjectionHash
      || binding.historyExpiresAtMs !== preflight.binding.historyExpiresAtMs
      || !string(binding.profileRef, 128) || !Number.isSafeInteger(binding.cacheVersion)
      || !/^[a-f0-9]{64}$/.test(binding.cacheBindingHash ?? '')
      || !Number.isSafeInteger(binding.cacheExpiresAtMs) || !Number.isSafeInteger(binding.historyExpiresAtMs)
      || binding.expiresAtMs !== Math.min(binding.cacheExpiresAtMs, binding.historyExpiresAtMs)) fail('REUSE_DENIED');
    if (signalAborted(signal)) fail('REUSE_DENIED');
    await authorize(info, request, 'private_profile.read');
    if (signalAborted(signal)) fail('REUSE_DENIED');
    const exactBinding = Object.freeze({ ...preflight.binding, cacheBindingHash: binding.cacheBindingHash,
      operationPhase: 'complete' });
    const expectedHash = mac(preflight.keys.keyInfo.key,
      `event-intelligence:correction-cache-binding:v1:${preflight.keys.partitionHash}:${binding.bindingId}`);
    if (expectedHash !== binding.cacheBindingHash) fail('REUSE_INTEGRITY');
    const candidate = await withBindingRead((database, time) => {
      if (time.clockRollback) fail('REUSE_DENIED');
      return { rows: readBoundReplayRows(database, exactBinding, preflight.keys), now: time.now };
    });
    const facts = preflight.entryPayload?.facts ?? preflight.replayPayload?.facts;
    const proof = await verifyBoundReceipt({ info, request, signal, keys: preflight.keys,
      index: preflight.index, facts, binding: exactBinding, rows: candidate.rows, now: candidate.now });
    if (!proof || proof.profileRef !== binding.profileRef || proof.version !== binding.cacheVersion
      || proof.expiresAtMs !== binding.cacheExpiresAtMs
      || binding.expiresAtMs !== Math.min(proof.expiresAtMs, binding.historyExpiresAtMs)
      || (preflight.replayProof && !sameBoundReceiptRows(preflight.replayProof, candidate.rows))) fail('REUSE_BUSY');
    if (signalAborted(signal)) fail('REUSE_DENIED');
    const database = await openStoreDatabase(0);
    try {
      await authorize(info, request, 'private_profile.read');
      if (signalAborted(signal)) fail('REUSE_DENIED');
      const token = opaque();
      boundFinalDisclosures.set(token, {
        info, request, signal, keys: preflight.keys, binding: Object.freeze({ ...binding }),
        rows: proof.rows, database, used: false,
      });
      return token;
    } catch (error) {
      database.close();
      throw error;
    }
  }

  function finalBoundDisclosureCheck(token, effectiveNow, capability) {
    if (!isCorrectionCacheBindingCapability(capability)) return false;
    const state = token && boundFinalDisclosures.get(token);
    if (!state || state.used || signalAborted(state.signal) || !Number.isSafeInteger(effectiveNow)
      || effectiveNow < 0 || effectiveNow > MAX_TIME) return false;
    state.used = true;
    let transactionOpen = false;
    try {
      const database = state.database;
      database.exec('BEGIN IMMEDIATE');
      transactionOpen = true;
      const currentMax = database.prepare("SELECT value FROM reuse_meta WHERE key = 'clock_max_ms'").get();
      const previousMax = currentMax ? Number(currentMax.value) : null;
      if (currentMax && (!Number.isSafeInteger(previousMax) || previousMax < 0 || previousMax > MAX_TIME)) throw new Error('cache clock metadata invalid');
      if (previousMax !== null && effectiveNow < previousMax) throw new Error('cache clock moved backward');
      const binding = { ...state.binding, operationPhase: 'complete' };
      const current = readBoundReplayRows(database, binding, state.keys);
      const entry = current.entry;
      if (!sameBoundReceiptRows(state.rows, current) || !entry
        || entry.entry_id !== binding.profileRef || entry.version !== binding.cacheVersion
        || entry.binding_hash !== binding.cacheBindingHash || entry.eligible !== 1 || entry.payload_purged !== 0
        || entry.expires_at_ms !== binding.cacheExpiresAtMs || entry.expires_at_ms <= effectiveNow
        || binding.expiresAtMs !== Math.min(entry.expires_at_ms, binding.historyExpiresAtMs)
        || current.outboxCount !== 0 || current.invalidationReceipts.length !== 0
        || signalAborted(state.signal)) throw new Error('cache binding changed during disclosure');
      database.exec('COMMIT');
      transactionOpen = false;
      return true;
    } catch {
      if (transactionOpen) {
        try { state.database.exec('ROLLBACK'); } catch { /* Closing the handle also rolls back. */ }
      }
      return false;
    }
  }

  function disposeBoundFinalDisclosure(token, capability) {
    if (!isCorrectionCacheBindingCapability(capability)) fail('REUSE_DENIED');
    const state = token && boundFinalDisclosures.get(token);
    if (!state) return;
    boundFinalDisclosures.delete(token);
    zeroBoundReceiptRows(state.rows);
    try { state.database.close(); } catch { /* A closed connection is already harmless. */ }
  }

  function finalBoundRead(database, candidate, now, effectiveNow, capability, boundaryToken) {
    if (!isCorrectionCacheBindingCapability(capability) || !database || signalAborted(candidate?.signal)
      || !Number.isSafeInteger(now) || !Number.isSafeInteger(effectiveNow) || effectiveNow < now
      || !boundaryToken) fail('REUSE_DENIED');
    const boundaryNow = () => {
      const current = localBoundaryEffectiveNow(boundaryToken);
      if (!Number.isSafeInteger(current) || current < effectiveNow || current > MAX_TIME) fail('REUSE_DENIED');
      return current;
    };
    let transactionOpen = false;
    try {
      database.exec('BEGIN IMMEDIATE');
      transactionOpen = true;
      const currentMax = database.prepare("SELECT value FROM reuse_meta WHERE key = 'clock_max_ms'").get();
      const previousMax = currentMax ? Number(currentMax.value) : null;
      if (currentMax && (!Number.isSafeInteger(previousMax) || previousMax < 0 || previousMax > MAX_TIME)) fail('REUSE_INTEGRITY');
      if (previousMax !== null && now < previousMax) fail('REUSE_DENIED');
      const current = database.prepare(`SELECT * FROM reuse_entries WHERE entry_id = ?
        AND scope_kind = 'tenant_private' AND partition_hash = ?`)
        .get(candidate.row.entry_id, candidate.keys.partitionHash);
      const latest = database.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1')
        .get(candidate.row.entry_id);
      const remainsCurrent = (at) => sameStoredEntry(current, candidate.row)
        && sameStoredObservation(latest, candidate.observationRow)
        && current?.eligible === 1 && current?.binding_hash === candidate.binding.cacheBindingHash
        && current?.version === candidate.binding.cacheVersion && current?.payload_purged !== 1
        && current?.expires_at_ms === candidate.binding.cacheExpiresAtMs
        && at < candidate.binding.expiresAtMs
        && (candidate.permissionState.validUntilMs === undefined || at < candidate.permissionState.validUntilMs)
        && (() => {
          const currentState = eligibility(current, candidate.payload, candidate.observation, at, false, true);
          return candidate.freshnessState.status === 'fresh'
            ? currentState.status === 'fresh'
            : currentState.status === 'stale' && currentState.reason === 'ttl_expired';
        })();
      if (!remainsCurrent(boundaryNow()) || signalAborted(candidate.signal)) fail('REUSE_DENIED');
      const result = candidate.freshnessState.status === 'fresh'
        ? Object.freeze({ status: 'hit', profileRef: current.entry_id, version: current.version,
          facts: candidate.payload.facts, trust: 'tenant_private', permissionStatus: candidate.permissionState.status,
          retrievedAt: iso(effectiveRetrievedAt(candidate.payload, candidate.observation)),
          validatedAt: iso(candidate.observation.validatedAtMs), expiresAt: iso(current.expires_at_ms),
          originalLineageStatus: candidate.payload.lineage?.status ?? 'unknown' })
        : Object.freeze({ status: 'stale', reason: 'ttl_expired', profileRef: current.entry_id });
      if (signalAborted(candidate.signal) || !remainsCurrent(boundaryNow())) fail('REUSE_DENIED');
      database.exec('COMMIT');
      transactionOpen = false;
      if (signalAborted(candidate.signal) || !remainsCurrent(boundaryNow())) fail('REUSE_DENIED');
      return result;
    } catch (error) {
      if (transactionOpen) {
        try { database.exec('ROLLBACK'); } catch { /* Closing the handle also rolls back. */ }
      }
      throw safeError(error);
    }
  }

  async function invalidateBoundProfile(scope, request, bindingValue, operation, historyGate, signal, capability) {
    if (!isCorrectionCacheBindingCapability(capability)) fail('REUSE_DENIED');
    const info = scopeInfo(scope);
    const binding = record(bindingValue, new Set([
      'bindingId', 'eventId', 'historyVersionId', 'historyContentHash', 'historyProjectionHash',
      'operationId', 'profileRef', 'cacheVersion', 'scopeKind', 'cacheBindingHash', 'identity', 'pins',
      'cacheSourceContentHash', 'cacheExpiresAtMs', 'historyExpiresAtMs', 'expiresAtMs',
    ]));
    if (!binding || !string(binding.bindingId, 128) || !string(binding.eventId, 180)
      || !string(binding.historyVersionId, 180) || !/^[a-f0-9]{64}$/.test(binding.historyContentHash)
      || !/^[a-f0-9]{64}$/.test(binding.historyProjectionHash) || !string(binding.profileRef, 128)
      || !string(binding.operationId, 128)
      || !Number.isSafeInteger(binding.cacheVersion) || binding.cacheVersion < 1
      || binding.scopeKind !== 'tenant_private' || !/^[a-f0-9]{64}$/.test(binding.cacheBindingHash)
      || !/^[a-f0-9]{64}$/.test(binding.cacheSourceContentHash)
      || !Number.isSafeInteger(binding.cacheExpiresAtMs) || !Number.isSafeInteger(binding.historyExpiresAtMs)
      || !Number.isSafeInteger(binding.expiresAtMs)
      || binding.expiresAtMs !== Math.min(binding.cacheExpiresAtMs, binding.historyExpiresAtMs)
      || !operation || !string(operation.operationId, 128) || !Number.isSafeInteger(operation.fence)
      || operation.fence < 1 || operation.baseVersionId !== binding.historyVersionId
      || operation.baseContentHash !== binding.historyContentHash
      || !string(operation.targetVersionId, 180) || !/^[a-f0-9]{64}$/.test(operation.targetContentHash)
      || typeof historyGate !== 'function') fail('REUSE_DENIED');
    const action = 'cache.invalidate';
    await authorize(info, request, action, { profileRef: binding.profileRef });
    if (signalAborted(signal)) fail('REUSE_DENIED');
    const index = copyIndex({ identity: binding.identity, contentHash: binding.cacheSourceContentHash, pins: binding.pins });
    const guard = async () => {
      await authorize(info, request, action, { profileRef: binding.profileRef });
      if (signalAborted(signal)) fail('REUSE_DENIED');
    };
    const keys = await keyParts(info, 'tenant_private', index, guard);
    let retainedProofKey;
    try {
    const expectedBindingHash = mac(keys.keyInfo.key,
      `event-intelligence:correction-cache-binding:v1:${keys.partitionHash}:${binding.bindingId}`);
    if (expectedBindingHash !== binding.cacheBindingHash) fail('REUSE_DENIED');
    const fingerprint = mac(keys.keyInfo.key, stable({
      operationId: operation.operationId,
      profileRef: binding.profileRef,
      bindingId: binding.bindingId,
      eventId: binding.eventId,
      priorVersionId: binding.historyVersionId,
      priorContentHash: binding.historyContentHash,
      targetVersionId: operation.targetVersionId,
      targetContentHash: operation.targetContentHash,
      cacheVersion: binding.cacheVersion,
      cacheBindingHash: binding.cacheBindingHash,
    }));
    const preflight = await withBindingRead((database) => ({
      row: database.prepare(`SELECT * FROM reuse_entries WHERE entry_id = ?
        AND scope_kind = 'tenant_private' AND partition_hash = ?`).get(binding.profileRef, keys.partitionHash),
      reservation: database.prepare(`SELECT * FROM reuse_correction_reservations WHERE entry_id = ?
        AND scope_kind = 'tenant_private' AND partition_hash = ?`).get(binding.profileRef, keys.partitionHash),
      receipt: database.prepare(`SELECT binding_hash, fingerprint, event_ids FROM reuse_history_invalidation_ops
        WHERE operation_id = ? AND entry_id = ? AND partition_hash = ?`)
        .get(operation.operationId, binding.profileRef, keys.partitionHash),
    }));
    if (signalAborted(signal) || !preflight.row
      || preflight.row.version !== binding.cacheVersion || preflight.row.binding_hash !== binding.cacheBindingHash
      || preflight.row.expires_at_ms !== binding.cacheExpiresAtMs
      || preflight.row.identity_hash !== keys.identityHash || preflight.row.content_hash_mac !== keys.contentMac
      || preflight.row.pins_hash !== keys.pinsHash || preflight.row.scope_kind !== 'tenant_private'
      || binding.expiresAtMs !== Math.min(preflight.row.expires_at_ms, binding.historyExpiresAtMs)) {
      fail('REUSE_DENIED');
    }
    let reservation;
    let reservationConsumers;
    let reservationKey;
    if (preflight.receipt) {
      let eventIds;
      try { eventIds = JSON.parse(preflight.receipt.event_ids); } catch { fail('REUSE_INTEGRITY'); }
      if (preflight.receipt.binding_hash !== binding.cacheBindingHash
        || preflight.receipt.fingerprint !== fingerprint || !Array.isArray(eventIds)
        || eventIds.length < 1 || eventIds.length > 64
        || eventIds.some((eventId) => !string(eventId, 64) || !/^[0-9a-f-]{36}$/i.test(eventId))
        || new Set(eventIds).size !== eventIds.length) fail('REUSE_INTEGRITY');
    } else {
      if (!preflight.reservation) fail('REUSE_DENIED');
      reservationKey = preflight.reservation.payload_key_id === keys.payloadKey.keyId
        ? keys.payloadKey : await resolveKey(info, 'payload', preflight.reservation.payload_key_id, guard);
      if (reservationKey !== keys.payloadKey) retainedProofKey = reservationKey;
      if (signalAborted(signal)) fail('REUSE_DENIED');
      reservation = unseal(reservationKey.key, keys.partitionHash, 'correction_reservation', binding.profileRef,
        preflight.reservation.payload, preflight.reservation.payload_key_id);
      reservationConsumers = safeArrayValues(reservation.consumers, 64);
      if (reservation.bindingId !== binding.bindingId || reservation.operationId !== binding.operationId
        || reservation.eventId !== binding.eventId
        || reservation.historyVersionId !== binding.historyVersionId
        || reservation.historyContentHash !== binding.historyContentHash
        || reservation.historyProjectionHash !== binding.historyProjectionHash
        || reservation.profileRef !== binding.profileRef
        || reservation.bindingHash !== binding.cacheBindingHash || reservation.version !== binding.cacheVersion
        || reservation.contentHash !== binding.cacheSourceContentHash || reservation.expiresAtMs !== binding.cacheExpiresAtMs
        || reservation.expiresAtMs > binding.historyExpiresAtMs
        || binding.expiresAtMs !== Math.min(reservation.expiresAtMs, binding.historyExpiresAtMs)
        || stable(reservation.identity) !== stable(index.identity) || stable(reservation.pins) !== stable(index.pins)
        || (reservation.outboxSlots !== Math.max(1, reservationConsumers.length))) fail('REUSE_INTEGRITY');
    }
    await guard();
    if (signalAborted(signal)) fail('REUSE_DENIED');
    const boundary = Object.freeze({
      input: boundaryInput(info, request, binding.eventId, 'cache.private_profile.invalidate', {
        operationId: operation.operationId,
        fence: operation.fence,
        bindingId: binding.bindingId,
        profileRef: binding.profileRef,
        cacheVersion: binding.cacheVersion,
        cacheBindingHash: binding.cacheBindingHash,
        priorHistoryVersionId: binding.historyVersionId,
        priorHistoryContentHash: binding.historyContentHash,
        targetHistoryVersionId: operation.targetVersionId,
        targetHistoryContentHash: operation.targetContentHash,
      }),
    });
    const result = await withBindingDatabase((commit, time) => historyGate(commit, time), (database, time) => {
      const priorReceipt = database.prepare(`SELECT binding_hash, fingerprint, event_ids FROM reuse_history_invalidation_ops
        WHERE operation_id = ? AND entry_id = ? AND partition_hash = ?`)
        .get(operation.operationId, binding.profileRef, keys.partitionHash);
      if (priorReceipt) {
        if (priorReceipt.binding_hash !== binding.cacheBindingHash || priorReceipt.fingerprint !== fingerprint) fail('REUSE_DENIED');
        let eventIds;
        try { eventIds = JSON.parse(priorReceipt.event_ids); } catch { fail('REUSE_INTEGRITY'); }
        if (!Array.isArray(eventIds) || eventIds.length < 1 || eventIds.length > 64
          || eventIds.some((eventId) => !string(eventId, 64) || !/^[0-9a-f-]{36}$/i.test(eventId))
          || new Set(eventIds).size !== eventIds.length) fail('REUSE_INTEGRITY');
        const current = database.prepare(`SELECT * FROM reuse_entries WHERE entry_id = ?
          AND scope_kind = 'tenant_private' AND partition_hash = ?`).get(binding.profileRef, keys.partitionHash);
        if (!current || !sameStoredEntry(current, preflight.row) || current.version !== binding.cacheVersion
          || current.binding_hash !== binding.cacheBindingHash) fail('REUSE_BUSY');
        for (const eventId of eventIds) {
          const event = database.prepare('SELECT entry_id, scope_kind, partition_hash FROM reuse_outbox WHERE event_id = ?').get(eventId);
          if (!event || event.entry_id !== binding.profileRef || event.scope_kind !== 'tenant_private'
            || event.partition_hash !== keys.partitionHash) fail('REUSE_INTEGRITY');
        }
        return Object.freeze({ profileRef: binding.profileRef, locallyIneligible: true,
          eventIds: Object.freeze(eventIds), replayed: true });
      }
      if (!reservation) fail('REUSE_BUSY');
      if (signalAborted(signal)) fail('REUSE_DENIED');
      const current = database.prepare(`SELECT * FROM reuse_entries WHERE entry_id = ?
        AND scope_kind = 'tenant_private' AND partition_hash = ?`).get(binding.profileRef, keys.partitionHash);
      const currentReservation = database.prepare(`SELECT * FROM reuse_correction_reservations WHERE entry_id = ?
        AND scope_kind = 'tenant_private' AND partition_hash = ?`).get(binding.profileRef, keys.partitionHash);
      if (!current || !sameStoredEntry(current, preflight.row) || current.version !== binding.cacheVersion
        || current.binding_hash !== binding.cacheBindingHash || !currentReservation
        || currentReservation.payload_key_id !== preflight.reservation.payload_key_id
        || currentReservation.payload_bytes !== preflight.reservation.payload_bytes
        || !Buffer.from(currentReservation.payload).equals(Buffer.from(preflight.reservation.payload))) fail('REUSE_BUSY');
      const exactReservation = unseal(reservationKey.key, keys.partitionHash, 'correction_reservation', binding.profileRef,
        currentReservation.payload, currentReservation.payload_key_id);
      if (stable(exactReservation) !== stable(reservation)) fail('REUSE_INTEGRITY');
      database.prepare('DELETE FROM reuse_correction_reservations WHERE entry_id = ?').run(binding.profileRef);
      if (current.eligible === 1) {
        const update = database.prepare(`UPDATE reuse_entries SET eligible = 0 WHERE entry_id = ?
          AND scope_kind = 'tenant_private' AND partition_hash = ? AND binding_hash = ? AND version = ? AND eligible = 1`)
          .run(binding.profileRef, keys.partitionHash, binding.cacheBindingHash, binding.cacheVersion);
        if (update.changes !== 1) fail('REUSE_BUSY');
      } else if (current.eligible !== 0) fail('REUSE_INTEGRITY');
      database.prepare('DELETE FROM reuse_refresh_sources WHERE entry_id = ? AND partition_hash = ?')
        .run(binding.profileRef, keys.partitionHash);
      const consumers = Object.freeze(reservationConsumers);
      const targetRefs = consumers.length > 0 ? consumers : [null];
      if (targetRefs.length !== reservation.outboxSlots) fail('REUSE_INTEGRITY');
      const proofPayloadKey = reservationKey;
      if (!proofPayloadKey) fail('REUSE_KEY_UNAVAILABLE');
      assertOutboxHeadroom(database, targetRefs.length);
      const prepared = [];
      for (const consumerRef of targetRefs) {
        const event = {
          ...eventPayload(current, { contentHash: reservation.contentHash }, 'history_version_changed', consumerRef, time.now, keys.keyInfo.key),
          bindingId: binding.bindingId,
          historyOperationId: operation.operationId,
          priorHistoryVersionId: binding.historyVersionId,
          priorHistoryContentHash: binding.historyContentHash,
          targetHistoryVersionId: operation.targetVersionId,
          targetHistoryContentHash: operation.targetContentHash,
        };
        const sealed = sealBounded(proofPayloadKey.key, proofPayloadKey.keyId, keys.partitionHash,
          'outbox', event.eventId, event, MAX_INVALIDATION_RECORD_BYTES);
        prepared.push({ event, consumerRef, sealed });
      }
      const eventBytes = prepared.reduce((total, item) => total + item.sealed.byteLength, 0);
      const retryGrowth = prepared.reduce((total, item) => total + MAX_INVALIDATION_RECORD_BYTES - item.sealed.byteLength, 0);
      ensureStorageCapacity(database, eventBytes, 0, 0, retryGrowth);
      for (const { event, consumerRef, sealed } of prepared) {
        database.prepare(`INSERT INTO reuse_outbox
          (event_id, entry_id, scope_kind, partition_hash, status, attempt_count, next_attempt_at_ms,
           has_consumer, payload_key_id, payload, payload_bytes)
          VALUES (?, ?, 'tenant_private', ?, 'pending', 0, ?, ?, ?, ?, ?)`)
          .run(event.eventId, binding.profileRef, keys.partitionHash, time.now, consumerRef === null ? 0 : 1,
            proofPayloadKey.keyId, sealed, sealed.byteLength);
      }
      const eventIds = prepared.map(({ event }) => event.eventId);
      database.prepare(`INSERT INTO reuse_history_invalidation_ops
        (operation_id, entry_id, partition_hash, binding_hash, fingerprint, event_ids)
        VALUES (?, ?, ?, ?, ?, ?)`)
        .run(operation.operationId, binding.profileRef, keys.partitionHash, binding.cacheBindingHash,
          fingerprint, JSON.stringify(eventIds));
      return Object.freeze({ profileRef: binding.profileRef, locallyIneligible: true,
        eventIds: Object.freeze(eventIds), replayed: false });
    }, signal, boundary);
    await guard();
    return result;
    } finally {
      retainedProofKey?.key.fill(0);
      keys.payloadKey.key.fill(0);
      keys.keyInfo.key.fill(0);
    }
  }

  async function getPublicProfile(scope, request, lookup) {
    scopeInfo(scope);
    return lookupProfile(scope, request, 'public_profile', lookup, 'fact_read');
  }

  function entryRefFor(scope, ref) {
    if (typeof ref !== 'string' || !/^[0-9a-f-]{36}$/.test(ref)) fail('REUSE_NOT_FOUND');
    void scope;
    return ref;
  }

  async function loadEntry(info, scopeKind, ref, guard) {
    const keys = await indexInfo(info, scopeKind, guard);
    const row = await withDatabase((database) => database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?').get(ref, scopeKind, keys.partitionHash));
    if (!row) fail('REUSE_NOT_FOUND');
    const payloadKey = await resolveKey(scopeKind === 'public_profile' ? null : info, 'payload', row.payload_key_id, guard);
    return { row, keys: { ...keys, payloadKey }, payloadKey, payload: unseal(payloadKey.key, row.partition_hash, 'entry', row.entry_id, row.payload, row.payload_key_id) };
  }

  function commitPreparedObservation(database, time, prepared) {
    const { info, input, ref, row, keys, payloadKey, payload, last, rawCurrent, verified, next } = prepared;
    if (time.clockRollback) return Object.freeze({ status: 'unavailable', reason: 'clock_rollback' });
    const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?')
      .get(ref, input.scopeKind, keys.partitionHash);
    if (!current || current.version !== row.version || current.payload_bytes !== row.payload_bytes) {
      return Object.freeze({ status: 'unavailable', reason: 'observation_changed' });
    }
    if (current.eligible !== 1) return Object.freeze({ status: 'unavailable', reason: 'invalidated' });
    if (current.expires_at_ms <= time.now) {
      expireEntry(database, info, current, payload, time.now, { ...keys, payloadKey });
      return Object.freeze({ status: 'unavailable', reason: 'expired' });
    }
    const currentLast = database.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(ref);
    if (!currentLast || currentLast.sequence !== last.sequence || currentLast.observation_id !== last.observation_id) {
      return Object.freeze({ status: 'unavailable', reason: 'observation_changed' });
    }
    const identityLatest = latestIdentityObservation(database, input.scopeKind, keys.partitionHash, current.identity_hash);
    if (!identityLatest || verified.validatedAtMs < identityLatest.observed_at_ms) {
      return Object.freeze({ status: 'unavailable', reason: 'observation_changed' });
    }
    if (verified.validatedAtMs === identityLatest.observed_at_ms) {
      if (identityLatest.entry_id !== ref || !sameObservationIdentity(rawCurrent, next)) fail('REUSE_POLICY_UNAVAILABLE');
      return Object.freeze({
        status: verified.status,
        profileRef: ref,
        invalidated: false,
        duplicateObservation: true,
        retrievedAt: iso(effectiveRetrievedAt(payload, rawCurrent)),
        validatedAt: iso(rawCurrent.validatedAtMs),
        usageLineage: rawCurrent.attemptLineage.status,
      });
    }
    const count = database.prepare('SELECT COUNT(*) AS count FROM reuse_observations WHERE entry_id = ?').get(ref).count;
    if (count >= limits.maxObservationsPerEntry) fail('REUSE_CAPACITY');
    insertObservation(database, ref, row.partition_hash, payloadKey.keyId, payloadKey.key, next, currentLast.sequence + 1);
    let invalidated = false;
    if (verified.status !== 'not_modified' && verified.status !== 'outage') {
      const reason = verified.status === 'body_changed' ? 'source_body_changed' : verified.status;
      invalidated = invalidateEntry(database, info, current, payload, reason, payload.consumers ?? [], time.now, { ...keys, payloadKey });
    }
    return Object.freeze({ status: verified.status, profileRef: ref, invalidated, retrievedAt: iso(effectiveRetrievedAt(payload, rawCurrent)), validatedAt: iso(verified.validatedAtMs), usageLineage: verified.attemptLineage.status });
  }

  async function observe(scope, request, inputValue) {
    const info = scopeInfo(scope);
    const input = record(inputValue, new Set(['profileRef', 'scopeKind', 'observation']));
    if (!input || !['tenant_private', 'public_profile'].includes(input.scopeKind)) fail('REUSE_INVALID');
    const ref = entryRefFor(scope, input.profileRef);
    await authorize(info, request, 'freshness.observe');
    const { row, keys, payloadKey, payload } = await loadEntry(info, input.scopeKind, ref, authorizationGuard(info, request, 'freshness.observe'));
    await authorize(info, request, 'freshness.observe', { profileRef: ref });
    const preflightNow = currentTime();
    if (row.eligible !== 1) fail('REUSE_DENIED');
    if (row.expires_at_ms <= preflightNow) {
      await withDatabase((database, time) => expireEntry(database, info, row, payload, time.now, keys));
      await authorize(info, request, 'freshness.observe', { profileRef: ref });
      fail('REUSE_DENIED');
    }
    const observationGuard = authorizationGuard(info, request, 'freshness.observe');
    const last = await withDatabase((database) => database.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(ref));
    if (!last) fail('REUSE_INTEGRITY');
    const lastPayloadKey = last.payload_key_id === payloadKey.keyId
      ? payloadKey
      : await resolveKey(input.scopeKind === 'public_profile' ? null : info, 'payload', last.payload_key_id, observationGuard);
    const rawCurrent = unseal(lastPayloadKey.key, row.partition_hash, 'observation', last.observation_id, last.payload, last.payload_key_id);
    const verified = await verifyObservation(info, request, payload.contentHash, input.observation, 'revalidate');
    await authorize(info, request, 'freshness.observe', { profileRef: ref });
    if (verified.status === 'not_modified' && verified.contentHash !== payload.contentHash) fail('REUSE_POLICY_UNAVAILABLE');
    if (verified.status === 'body_changed' && verified.retrievedAtMs > verified.validatedAtMs) fail('REUSE_POLICY_UNAVAILABLE');
    if (verified.validatedAtMs < rawCurrent.validatedAtMs) fail('REUSE_POLICY_UNAVAILABLE');
    const now = currentTime();
    if (verified.validatedAtMs > now + 60_000) fail('REUSE_POLICY_UNAVAILABLE');
    const next = {
      status: verified.status,
      contentHash: verified.contentHash,
      retrievedAtMs: effectiveRetrievedAt(payload, rawCurrent),
      bodyObservedAtMs: verified.status === 'body_changed' ? verified.retrievedAtMs : null,
      validatedAtMs: verified.validatedAtMs,
      sourceVersion: verified.sourceVersion,
      attemptLineage: verified.attemptLineage,
      previousObservationStatus: rawCurrent.status,
    };
    const result = await withDatabase((database, time) => commitPreparedObservation(database, time, {
      info, input, ref, row, keys, payloadKey, payload, last, rawCurrent, verified, next,
    }));
    await authorize(info, request, 'freshness.observe', { profileRef: ref });
    if (result.status === 'unavailable' && result.reason !== 'clock_rollback') fail('REUSE_BUSY');
    return result;
  }

  async function withPrivateLineage(scope, request, profileRef) {
    const info = scopeInfo(scope);
    const ref = entryRefFor(scope, profileRef);
    if (typeof config.consumeOriginalLineage !== 'function') fail('REUSE_POLICY_UNAVAILABLE');
    await authorize(info, request, 'finance.read_original_lineage', { profileRef: ref });
    const keys = await indexInfo(info, 'tenant_private', authorizationGuard(info, request, 'finance.read_original_lineage'));
    await authorize(info, request, 'finance.read_original_lineage', { profileRef: ref });
    const located = await withDatabase((database, time) => {
      const entry = database.prepare("SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = 'tenant_private' AND partition_hash = ?").get(ref, keys.partitionHash);
      if (entry) return { kind: 'private_entry', row: entry, now: time.now, clockRollback: time.clockRollback };
      const link = database.prepare('SELECT * FROM reuse_private_links WHERE public_entry_id = ? AND tenant_partition_hash = ?').get(ref, keys.partitionHash);
      if (!link) return null;
      const parent = database.prepare("SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = 'public_profile'").get(ref);
      return { kind: 'public_link', row: link, parent, now: time.now, clockRollback: time.clockRollback };
    });
    if (!located || located.clockRollback) fail('REUSE_DENIED');
    const lineageGuard = authorizationGuard(info, request, 'finance.read_original_lineage');
    if (located.kind === 'private_entry' && located.row.eligible !== 1) fail('REUSE_DENIED');
    if (located.kind === 'public_link' && (!located.parent || located.parent.eligible !== 1)) {
      await withDatabase((database) => database.prepare('DELETE FROM reuse_private_links WHERE link_id = ?').run(located.row.link_id));
      await authorize(info, request, 'finance.read_original_lineage', { profileRef: ref });
      fail('REUSE_DENIED');
    }
    const key = await resolveKey(info, 'payload', located.row.payload_key_id, lineageGuard);
    await authorize(info, request, 'finance.read_original_lineage', { profileRef: ref });
    const payload = unseal(key.key, keys.partitionHash, located.kind === 'private_entry' ? 'entry' : 'private_link', located.kind === 'private_entry' ? ref : located.row.link_id, located.row.payload, located.row.payload_key_id);
    const deadline = located.kind === 'private_entry' ? located.row.expires_at_ms : payload.expiresAtMs;
    let publicParentPayload = null;
    let publicParentKeys = null;
    if (located.kind === 'public_link' && located.parent.expires_at_ms <= located.now) {
      publicParentKeys = await indexInfo(null, 'public_profile', lineageGuard);
      const publicKey = await resolveKey(null, 'payload', located.parent.payload_key_id, lineageGuard);
      publicParentKeys.payloadKey = publicKey;
      publicParentPayload = unseal(publicKey.key, located.parent.partition_hash, 'entry', located.parent.entry_id, located.parent.payload, located.parent.payload_key_id);
      await withDatabase((database, time) => {
        const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ?').get(ref);
        expireEntry(database, null, current, publicParentPayload, time.now, publicParentKeys);
      });
      await authorize(info, request, 'finance.read_original_lineage', { profileRef: ref });
      fail('REUSE_DENIED');
    }
    if (deadline !== null && deadline <= located.now) {
      if (located.kind === 'private_entry' && located.row.eligible === 1) {
        const keyBundle = { ...keys, payloadKey: key };
        await withDatabase((database, time) => expireEntry(database, info, located.row, payload, time.now, keyBundle));
      } else if (located.kind === 'public_link') {
        await withDatabase((database) => database.prepare('DELETE FROM reuse_private_links WHERE link_id = ?').run(located.row.link_id));
      }
      await authorize(info, request, 'finance.read_original_lineage', { profileRef: ref });
      fail('REUSE_DENIED');
    }
    const permissionNow = currentTime();
    const permissionState = await verifyStoredPermissions(info, request, payload, 'finance.read_original_lineage', permissionNow);
    if (!permissionState.valid) {
      if (permissionState.status === 'revoked' || permissionState.status === 'expired') {
        if (located.kind === 'private_entry') {
          await withDatabase((database, time) => {
            const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ?').get(ref);
            invalidateEntry(database, info, current, payload, `permission_${permissionState.status}`, payload.consumers ?? [], time.now, { ...keys, payloadKey: key });
          });
        } else {
          publicParentKeys ??= await indexInfo(null, 'public_profile', lineageGuard);
          if (!publicParentKeys.payloadKey) publicParentKeys.payloadKey = await resolveKey(null, 'payload', located.parent.payload_key_id, lineageGuard);
          publicParentPayload ??= unseal(publicParentKeys.payloadKey.key, located.parent.partition_hash, 'entry', located.parent.entry_id, located.parent.payload, located.parent.payload_key_id);
          await withDatabase((database, time) => {
            const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ?').get(ref);
            invalidateEntry(database, null, current, publicParentPayload, `permission_${permissionState.status}`, publicParentPayload.consumers ?? [], time.now, publicParentKeys);
          });
        }
      }
      await authorize(info, request, 'finance.read_original_lineage', { profileRef: ref });
      fail('REUSE_DENIED');
    }
    let handoffFreshness;
    if (located.kind === 'private_entry') {
      handoffFreshness = await readCurrentFreshness(info, request, 'tenant_private', located.row, payload,
        { ...keys, payloadKey: key }, lineageGuard, true);
    } else {
      publicParentKeys ??= await indexInfo(null, 'public_profile', lineageGuard);
      if (!publicParentKeys.payloadKey) publicParentKeys.payloadKey = await resolveKey(null, 'payload', located.parent.payload_key_id, lineageGuard);
      publicParentPayload ??= unseal(publicParentKeys.payloadKey.key, located.parent.partition_hash, 'entry', located.parent.entry_id,
        located.parent.payload, located.parent.payload_key_id);
      handoffFreshness = await readCurrentFreshness(null, request, 'public_profile', located.parent, publicParentPayload,
        publicParentKeys, lineageGuard, true);
    }
    if (!handoffFreshness || handoffFreshness.state.status !== 'fresh') fail('REUSE_DENIED');
    await authorize(info, request, 'finance.read_original_lineage', { profileRef: ref });
    const preFinalPermissionState = await verifyStoredPermissions(info, request, payload, 'finance.read_original_lineage', currentTime());
    if (!preFinalPermissionState.valid) fail('REUSE_DENIED');
    await authorize(info, request, 'finance.read_original_lineage', { profileRef: ref });
    if (located.kind === 'public_link') {
      publicParentKeys ??= await indexInfo(null, 'public_profile', lineageGuard);
      if (!publicParentKeys.payloadKey) publicParentKeys.payloadKey = await resolveKey(null, 'payload', located.parent.payload_key_id, lineageGuard);
      publicParentPayload ??= unseal(publicParentKeys.payloadKey.key, located.parent.partition_hash, 'entry', located.parent.entry_id,
        located.parent.payload, located.parent.payload_key_id);
    }
    const finalRow = located.kind === 'private_entry' ? located.row : located.parent;
    const finalScopeKind = located.kind === 'private_entry' ? 'tenant_private' : 'public_profile';
    const finalPayload = located.kind === 'private_entry' ? payload : publicParentPayload;
    const finalKeys = located.kind === 'private_entry' ? { ...keys, payloadKey: key } : publicParentKeys;
    const finalFreshness = await finalizeCurrentFreshness(info, request, 'finance.read_original_lineage', finalScopeKind,
      finalRow, finalPayload, finalKeys, lineageGuard, true,
      located.kind === 'public_link' ? {
        partitionHash: keys.partitionHash,
        linkId: located.row.link_id,
        payloadKeyId: located.row.payload_key_id,
        payload: located.row.payload,
        payloadBytes: located.row.payload.byteLength,
      } : null,
      () => verifyStoredPermissions(info, request, payload, 'finance.read_original_lineage', currentTime()),
      async (finalCheck, finalPermissionState) => {
        if (!finalCheck || finalCheck.state.status !== 'fresh' || !finalPermissionState?.valid) fail('REUSE_DENIED');
        const handoffTime = finalCheck.now;
        if (deadline !== null && handoffTime >= deadline) fail('REUSE_DENIED');
        if (finalPermissionState.validUntilMs !== undefined && handoffTime >= finalPermissionState.validUntilMs) fail('REUSE_DENIED');
        let response;
        try {
          // Invoke the trusted host handoff synchronously after the final snapshot; the DB is closed.
          response = config.consumeOriginalLineage(Object.freeze({
            tenantId: info.tenantId,
            actorId: info.actorId,
            request,
            profileRef: ref,
            scope: 'tenant_private',
            contentHash: payload.contentHash,
            version: located.kind === 'private_entry' ? located.row.version : payload.version,
            lineage: payload.lineage ?? validateLineage({ status: 'unknown' }),
            sourceRefs: payload.sourceRefs ?? Object.freeze([]),
            correctionRefs: payload.correctionRefs ?? Object.freeze([]),
            permissions: payload.permissions ?? Object.freeze([]),
          }));
          response = await response;
        } catch { fail('REUSE_POLICY_UNAVAILABLE'); }
        await authorize(info, request, 'finance.read_original_lineage', { profileRef: ref });
        const safe = record(response, new Set(['status', 'logicalOperationBound', 'billedAttemptCount', 'usageObservationCount']));
        if (!safe || !['linked', 'incomplete', 'unavailable'].includes(safe.status)
          || typeof safe.logicalOperationBound !== 'boolean'
          || !Number.isSafeInteger(safe.billedAttemptCount) || safe.billedAttemptCount < 0
          || !Number.isSafeInteger(safe.usageObservationCount) || safe.usageObservationCount < 0) fail('REUSE_POLICY_UNAVAILABLE');
        return Object.freeze({
          status: safe.status,
          logicalOperationBound: safe.logicalOperationBound,
          billedAttemptCount: safe.billedAttemptCount,
          usageObservationCount: safe.usageObservationCount,
          allocationAuthority: 'finance_external',
        });
      });
    return finalFreshness;
  }

  async function invalidate(scope, request, inputValue) {
    const info = scopeInfo(scope);
    const input = record(inputValue, new Set(['profileRef', 'scopeKind', 'reason']));
    if (!input || !['tenant_private', 'public_profile'].includes(input.scopeKind)
      || !['material_fact_change', 'rights_revocation', 'evidence_lost', 'permission_expiry'].includes(input.reason)) fail('REUSE_INVALID');
    const ref = entryRefFor(scope, input.profileRef);
    await authorize(info, request, 'cache.invalidate');
    const { row, keys, payload, payloadKey } = await loadEntry(info, input.scopeKind, ref, authorizationGuard(info, request, 'cache.invalidate'));
    return withDatabase((database, time) => Object.freeze({
      invalidated: invalidateEntry(database, info, row, payload, input.reason, payload.consumers ?? [], time.now, { ...keys, payloadKey }),
      profileRef: ref,
      version: row.version,
    }));
  }

  async function admitOperation(scope, request, inputValue) {
    const info = scopeInfo(scope);
    const input = record(inputValue, new Set(['identity', 'pins', 'mode', 'leaseMs']));
    if (!input || !['reuse', 'fresh'].includes(input.mode)) fail('REUSE_INVALID');
    const parsedIdentity = identity(input.identity);
    const parsedPins = pins(input.pins);
    const leaseMs = input.leaseMs ?? 60_000;
    if (!Number.isSafeInteger(leaseMs) || leaseMs < 1 || leaseMs > 15 * 60_000) fail('REUSE_INVALID');
    await authorize(info, request, 'operation.admit');
    const operationGuard = authorizationGuard(info, request, 'operation.admit');
    const keys = await indexInfo(info, 'tenant_private', operationGuard);
    const baseKey = mac(keys.keyInfo.key, stable({
      scopeKind: 'tenant_private',
      partitionHash: keys.partitionHash,
      indexKeyId: keys.keyInfo.keyId,
      identity: parsedIdentity,
      pins: parsedPins,
    }));
    const flightKey = input.mode === 'fresh' ? mac(keys.keyInfo.key, `${baseKey}:fresh:${randomUUID()}`) : baseKey;
    const payloadKey = await resolveKey(info, 'payload', undefined, operationGuard);
    const outcome = await withDatabase((database, time) => {
      if (time.clockRollback) return Object.freeze({ status: 'unavailable', reason: 'clock_rollback' });
      if (input.mode === 'reuse') {
        const existing = database.prepare('SELECT * FROM reuse_flights WHERE flight_key = ? AND scope_kind = ? AND partition_hash = ?')
          .get(flightKey, 'tenant_private', keys.partitionHash);
        if (existing) {
          if (existing.state === 'active' && existing.lease_expires_at_ms <= time.now) {
            database.prepare("UPDATE reuse_flights SET state = 'unknown' WHERE flight_key = ? AND scope_kind = ? AND partition_hash = ? AND state = 'active'")
              .run(flightKey, 'tenant_private', keys.partitionHash);
            return Object.freeze({ status: 'needs_reconciliation', admissionRef: existing.admission_id, usage: 'unknown' });
          }
          return Object.freeze({ status: existing.state === 'active' ? 'in_flight' : existing.state === 'unknown' ? 'needs_reconciliation' : 'already_completed', admissionRef: existing.admission_id, usage: existing.state === 'unknown' ? 'unknown' : 'unresolved' });
        }
      }
      if (database.prepare('SELECT COUNT(*) AS count FROM reuse_flights').get().count >= limits.maxFlights) fail('REUSE_CAPACITY');
      const admissionId = randomUUID();
      const payload = { identity: parsedIdentity, pins: parsedPins, mode: input.mode, usage: 'unknown',
        actorBinding: mac(keys.keyInfo.key, `revalidation-actor:${info.actorId}`),
        attemptLineage: validateLineage({ status: 'unknown' }) };
      const sealed = sealBounded(payloadKey.key, payloadKey.keyId, keys.partitionHash, 'flight', admissionId, payload);
      ensureStorageCapacity(database, sealed.byteLength);
      database.prepare('INSERT INTO reuse_flights (flight_key, scope_kind, partition_hash, admission_id, state, created_at_ms, lease_expires_at_ms, payload_key_id, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run(flightKey, 'tenant_private', keys.partitionHash, admissionId, 'active', time.now, time.now + leaseMs, payloadKey.keyId, sealed);
      return Object.freeze({ status: input.mode === 'fresh' ? 'refresh_unresolved' : 'admitted', admissionRef: admissionId, usage: 'unknown', providerTransport: 'not_implemented' });
    });
    await authorize(info, request, 'operation.admit');
    return outcome;
  }

  async function reconcileAdmission(scope, request, inputValue) {
    const info = scopeInfo(scope);
    const input = record(inputValue, new Set(['admissionRef', 'outcome']));
    if (!input || !string(input.admissionRef, 64) || !['completed', 'unknown', 'not_dispatched'].includes(input.outcome)) fail('REUSE_INVALID');
    await authorize(info, request, 'operation.reconcile');
    const reconcileGuard = authorizationGuard(info, request, 'operation.reconcile');
    const keys = await indexInfo(info, 'tenant_private', reconcileGuard);
    const row = await withDatabase((database) => database.prepare('SELECT * FROM reuse_flights WHERE admission_id = ? AND scope_kind = ? AND partition_hash = ?').get(input.admissionRef, 'tenant_private', keys.partitionHash));
    if (!row) fail('REUSE_NOT_FOUND');
    if (row.state !== 'unknown' && row.state !== 'active') return Object.freeze({ status: row.state, usage: 'unknown' });
    if (typeof config.verifyAdmissionOutcome !== 'function') fail('REUSE_POLICY_UNAVAILABLE');
    const payloadKey = await resolveKey(info, 'payload', row.payload_key_id, reconcileGuard);
    await authorize(info, request, 'operation.reconcile', { admissionRef: input.admissionRef });
    let raw;
    try {
      raw = await config.verifyAdmissionOutcome(Object.freeze({
        tenantId: info.tenantId,
        actorId: info.actorId,
        request,
        admissionRef: input.admissionRef,
        existingState: row.state,
        requestedOutcome: input.outcome,
      }));
    } catch { fail('REUSE_POLICY_UNAVAILABLE'); }
    await authorize(info, request, 'operation.reconcile', { admissionRef: input.admissionRef });
    const attestation = record(raw, new Set(['outcome', 'attemptLineage']));
    if (!attestation || attestation.outcome !== input.outcome) fail('REUSE_POLICY_UNAVAILABLE');
    const lineage = validateLineage(attestation.attemptLineage ?? { status: 'unknown' });
    return withDatabase((database) => {
      const current = database.prepare('SELECT * FROM reuse_flights WHERE admission_id = ? AND scope_kind = ? AND partition_hash = ?')
        .get(input.admissionRef, 'tenant_private', keys.partitionHash);
      if (!current) fail('REUSE_NOT_FOUND');
      if (current.state !== 'unknown' && current.state !== 'active') return Object.freeze({ status: current.state, usage: 'unknown', duplicateCompletion: true });
      const existingPayload = unseal(payloadKey.key, current.partition_hash, 'flight', current.admission_id, current.payload, current.payload_key_id);
      const mergedLineage = input.outcome === 'unknown' && lineage.status !== 'complete' && existingPayload.attemptLineage?.billableAttemptId
        ? existingPayload.attemptLineage
        : lineage;
      const updatedPayload = { ...existingPayload, attemptLineage: mergedLineage, usage: 'unknown' };
      const sealed = sealBounded(payloadKey.key, payloadKey.keyId, current.partition_hash, 'flight', current.admission_id, updatedPayload);
      ensureStorageCapacity(database, sealed.byteLength, current.payload.byteLength);
      const state = input.outcome === 'completed' ? 'completed' : input.outcome === 'not_dispatched' ? 'not_dispatched' : 'unknown';
      database.prepare('UPDATE reuse_flights SET state = ?, payload_key_id = ?, payload = ? WHERE admission_id = ? AND scope_kind = ? AND partition_hash = ?')
        .run(state, payloadKey.keyId, sealed, input.admissionRef, 'tenant_private', keys.partitionHash);
      return Object.freeze({ status: state, usage: 'unknown', lineage: mergedLineage.status, holdDisposition: 'finance_reconciliation_required' });
    });
  }

  async function dispatchPendingInvalidations(scope, request, maximum = 20, scopeKind = 'tenant_private', signal = undefined) {
    const info = scopeInfo(scope);
    if (!['tenant_private', 'public_profile'].includes(scopeKind)) fail('REUSE_INVALID');
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 100) fail('REUSE_INVALID');
    if (signalAborted(signal)) fail('REUSE_DENIED');
    await authorize(info, request, scopeKind === 'public_profile' ? 'outbox.dispatch_public' : 'outbox.dispatch');
    if (typeof config.deliverInvalidation !== 'function' || typeof config.verifyInvalidationAcknowledgement !== 'function') {
      return Object.freeze({ attempted: 0, delivered: 0, pending: true, reason: 'consumer_port_unavailable' });
    }
    const dispatchGuard = authorizationGuard(info, request, scopeKind === 'public_profile' ? 'outbox.dispatch_public' : 'outbox.dispatch', signal);
    const baseKeys = await indexInfo(info, scopeKind, dispatchGuard);
    const keys = { ...baseKeys, payloadKey: await resolveKey(scopeKind === 'public_profile' ? null : info, 'payload', undefined, dispatchGuard) };
    let attempted = 0;
    let delivered = 0;
    const skippedEvents = new Set();
    let scanned = 0;
    while (attempted < maximum && scanned < 1_000) {
      const row = await withDatabase((database, time) => {
        const exclusions = [...skippedEvents];
        const excludedSql = exclusions.length ? `AND event_id NOT IN (${exclusions.map(() => '?').join(',')})` : '';
        const candidate = database.prepare(`SELECT * FROM reuse_outbox WHERE scope_kind = ? AND partition_hash = ?
          AND status IN ('pending', 'delivering') AND has_consumer = 1 AND attempt_count < ? AND next_attempt_at_ms <= ?
          ${excludedSql} ORDER BY next_attempt_at_ms, event_id LIMIT 1`)
          .get(scopeKind, keys.partitionHash, limits.maxOutboxAttempts, time.now, ...exclusions);
        if (!candidate) return null;
        const priorKey = candidate.payload_key_id === keys.payloadKey.keyId ? keys.payloadKey : null;
        return { candidate, now: time.now, payloadKeyId: candidate.payload_key_id, payloadKey: priorKey };
      });
      if (!row) break;
      scanned += 1;
      await dispatchGuard();
      const payloadKey = row.payloadKey ?? await resolveKey(scopeKind === 'public_profile' ? null : info, 'payload', row.payloadKeyId, dispatchGuard);
      const event = unseal(payloadKey.key, row.candidate.partition_hash, 'outbox', row.candidate.event_id, row.candidate.payload, row.candidate.payload_key_id);
      if (!event.consumerRef) {
        skippedEvents.add(row.candidate.event_id);
        continue;
      }
      await dispatchGuard();
      const deliveryAttemptId = randomUUID();
      const attempt = await withDatabase((database, time) => {
        if (signalAborted(signal)) fail('REUSE_DENIED');
        const current = database.prepare('SELECT status, attempt_count, next_attempt_at_ms, has_consumer FROM reuse_outbox WHERE event_id = ?').get(row.candidate.event_id);
        if (!current || !['pending', 'delivering'].includes(current.status) || current.has_consumer !== 1
          || current.attempt_count >= limits.maxOutboxAttempts
          || current.attempt_count !== row.candidate.attempt_count || current.next_attempt_at_ms > time.now) return null;
        const nextAttempt = current.attempt_count + 1;
        const stored = { ...event, deliveryAttemptId, deliveryAttemptNumber: nextAttempt };
        const sealed = sealBounded(payloadKey.key, payloadKey.keyId, row.candidate.partition_hash, 'outbox', row.candidate.event_id, stored, MAX_INVALIDATION_RECORD_BYTES);
        ensureStorageCapacity(database, sealed.byteLength, row.candidate.payload_bytes, 0, 0,
          Math.max(0, sealed.byteLength - row.candidate.payload_bytes));
        const claimed = database.prepare("UPDATE reuse_outbox SET status = 'delivering', attempt_count = ?, next_attempt_at_ms = ?, active_attempt_id = ?, payload = ?, payload_key_id = ?, payload_bytes = ? WHERE event_id = ? AND status = ? AND has_consumer = 1 AND attempt_count = ? AND attempt_count < ? AND next_attempt_at_ms <= ?")
          .run(nextAttempt, time.now + Math.min(60_000, 250 * (2 ** (nextAttempt - 1))), deliveryAttemptId, sealed, payloadKey.keyId, sealed.byteLength,
            row.candidate.event_id, current.status, current.attempt_count, limits.maxOutboxAttempts, time.now);
        if (claimed.changes !== 1) return null;
        return nextAttempt;
      });
      if (attempt === null) {
        skippedEvents.add(row.candidate.event_id);
        continue;
      }
      const expected = Object.freeze({
        eventId: row.candidate.event_id,
        consumerRef: event.consumerRef,
        entryRef: event.entryRef,
        contentHash: event.contentHash,
        version: event.version,
        deliveryAttemptId,
        attemptNumber: attempt,
        reason: event.reason,
        ...(event.reason === 'history_version_changed' ? {
          bindingId: event.bindingId,
          historyOperationId: event.historyOperationId,
          priorHistoryVersionId: event.priorHistoryVersionId,
          priorHistoryContentHash: event.priorHistoryContentHash,
          targetHistoryVersionId: event.targetHistoryVersionId,
          targetHistoryContentHash: event.targetHistoryContentHash,
        } : {}),
      });
      try {
        await dispatchGuard();
      } catch (error) {
        await withDatabase((database) => {
          database.prepare(`UPDATE reuse_outbox SET status = ?, attempt_count = ?, next_attempt_at_ms = ?,
            has_consumer = ?, active_attempt_id = ?, payload_key_id = ?, payload = ?, payload_bytes = ?
            WHERE event_id = ? AND status = 'delivering' AND attempt_count = ? AND active_attempt_id = ?`)
            .run(row.candidate.status, row.candidate.attempt_count, row.candidate.next_attempt_at_ms,
              row.candidate.has_consumer, row.candidate.active_attempt_id, row.candidate.payload_key_id,
              row.candidate.payload, row.candidate.payload_bytes, row.candidate.event_id, attempt, deliveryAttemptId);
        });
        throw error;
      }
      attempted += 1;
      let ack;
      try { ack = await config.deliverInvalidation(expected); } catch { ack = null; }
      await dispatchGuard();
      let valid = false;
      try { valid = (await config.verifyInvalidationAcknowledgement(Object.freeze({ expected, acknowledgement: ack, tenantId: info.tenantId, actorId: info.actorId }))) === true; } catch { valid = false; }
      await dispatchGuard();
      await withDatabase((database) => {
        if (valid) {
          const updated = database.prepare("UPDATE reuse_outbox SET status = 'delivered', active_attempt_id = NULL WHERE event_id = ? AND status = 'delivering' AND attempt_count = ? AND active_attempt_id = ?")
            .run(row.candidate.event_id, attempt, deliveryAttemptId);
          if (updated.changes === 1) delivered += 1;
        } else if (attempt >= limits.maxOutboxAttempts) {
          database.prepare("UPDATE reuse_outbox SET status = 'failed', active_attempt_id = NULL WHERE event_id = ? AND status = 'delivering' AND attempt_count = ? AND active_attempt_id = ?").run(row.candidate.event_id, attempt, deliveryAttemptId);
        } else {
          database.prepare("UPDATE reuse_outbox SET status = 'pending', active_attempt_id = NULL WHERE event_id = ? AND status = 'delivering' AND attempt_count = ? AND active_attempt_id = ?").run(row.candidate.event_id, attempt, deliveryAttemptId);
        }
      });
    }
    const remaining = await withDatabase((database) => database.prepare('SELECT COUNT(*) AS count FROM reuse_outbox WHERE scope_kind = ? AND partition_hash = ? AND status != \'delivered\'').get(scopeKind, keys.partitionHash).count);
    return Object.freeze({ attempted, delivered, pending: remaining > 0, unresolvedCount: remaining, deliveryKind: 'injected_host_callback' });
  }

  async function outboxSnapshot(scope, request, scopeKind = 'tenant_private') {
    const info = scopeInfo(scope);
    if (!['tenant_private', 'public_profile'].includes(scopeKind)) fail('REUSE_INVALID');
    await authorize(info, request, scopeKind === 'public_profile' ? 'outbox.read_public' : 'outbox.read');
    const keys = await indexInfo(info, scopeKind, authorizationGuard(info, request, scopeKind === 'public_profile' ? 'outbox.read_public' : 'outbox.read'));
    return withDatabase((database) => {
      const rows = database.prepare('SELECT status, COUNT(*) AS count FROM reuse_outbox WHERE scope_kind = ? AND partition_hash = ? GROUP BY status').all(scopeKind, keys.partitionHash);
      const result = { pending: 0, delivering: 0, failed: 0, delivered: 0, unresolved: 0, readiness: 'blocked_pending_external_ack' };
      for (const row of rows) result[row.status] = row.count;
      result.unresolved = result.pending + result.delivering + result.failed;
      if (result.unresolved === 0) result.readiness = 'external_consumer_unverified';
      return Object.freeze(result);
    });
  }

  async function integritySnapshot(scope, request) {
    const info = scopeInfo(scope);
    await authorize(info, request, 'cache.snapshot');
    const snapshotGuard = authorizationGuard(info, request, 'cache.snapshot');
    const baseKeys = await indexInfo(info, 'tenant_private', snapshotGuard);
    const keys = { ...baseKeys, payloadKey: await resolveKey(info, 'payload', undefined, snapshotGuard) };
    return withDatabase((database, time) => {
      const entries = database.prepare("SELECT COUNT(*) AS count, SUM(CASE WHEN eligible = 1 THEN 1 ELSE 0 END) AS eligible, SUM(payload_bytes) AS bytes FROM reuse_entries WHERE scope_kind = 'tenant_private' AND partition_hash = ?").get(keys.partitionHash);
      const outbox = database.prepare("SELECT status, COUNT(*) AS count FROM reuse_outbox WHERE scope_kind = 'tenant_private' AND partition_hash = ? GROUP BY status").all(keys.partitionHash);
      const flights = database.prepare("SELECT state, COUNT(*) AS count FROM reuse_flights WHERE scope_kind = 'tenant_private' AND partition_hash = ? GROUP BY state").all(keys.partitionHash);
      return Object.freeze({
        entryCount: entries.count,
        eligibleEntryCount: entries.eligible ?? 0,
        encryptedPayloadBytes: entries.bytes ?? 0,
        outbox: Object.freeze(Object.fromEntries(outbox.map((item) => [item.status, item.count]))),
        flights: Object.freeze(Object.fromEntries(flights.map((item) => [item.state, item.count]))),
        clock: time.clockRollback ? 'rollback_detected' : 'trusted',
      });
    });
  }

  async function purgeExpired(scope, request, scopeKind = 'tenant_private') {
    const info = scopeInfo(scope);
    if (!['tenant_private', 'public_profile'].includes(scopeKind)) fail('REUSE_INVALID');
    const action = scopeKind === 'public_profile' ? 'cache.retention.purge_public' : 'cache.retention.purge';
    await authorize(info, request, action);
    const purgeGuard = authorizationGuard(info, request, action);
    const baseKeys = await indexInfo(info, scopeKind, purgeGuard);
    const keys = { ...baseKeys, payloadKey: await resolveKey(scopeKind === 'public_profile' ? null : info, 'payload', undefined, purgeGuard) };
    const rows = await withDatabase((database, time) => database.prepare('SELECT * FROM reuse_entries WHERE scope_kind = ? AND partition_hash = ? AND expires_at_ms <= ? AND payload_purged = 0 ORDER BY expires_at_ms, entry_id LIMIT 500')
      .all(scopeKind, keys.partitionHash, time.now));
    let purged = 0;
    for (const row of rows) {
      const payloadKey = row.eligible === 1
        ? (row.payload_key_id === keys.payloadKey.keyId ? keys.payloadKey : await resolveKey(scopeKind === 'public_profile' ? null : info, 'payload', row.payload_key_id, purgeGuard))
        : null;
      await authorize(info, request, action);
      const payload = row.eligible === 1
        ? unseal(payloadKey.key, row.partition_hash, 'entry', row.entry_id, row.payload, row.payload_key_id)
        : null;
      await withDatabase((database, time) => {
        const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = ? AND partition_hash = ?')
          .get(row.entry_id, scopeKind, keys.partitionHash);
        if (expireEntry(database, scopeKind === 'public_profile' ? null : info, current, payload, time.now, { ...keys, payloadKey: payloadKey ?? keys.payloadKey })) purged += 1;
      });
    }
    if (scopeKind === 'tenant_private') {
      await authorize(info, request, action);
      await withDatabase((database, time) => {
        // Keep only a minimal expired claim so rebinding cannot silently extend
        // the first retained-source/permission deadline. No source bytes, URL,
        // validator, evidence ID or response metadata survives this sweep.
        database.prepare(`UPDATE reuse_public_refresh_sources SET payload = ?, payload_purged = 1
          WHERE tenant_partition_hash = ? AND payload_purged = 0 AND entry_id IN (
            SELECT entry_id FROM reuse_public_refresh_sources
            WHERE tenant_partition_hash = ? AND payload_purged = 0 AND expires_at_ms <= ? ORDER BY expires_at_ms, entry_id LIMIT 500
          )`).run(Buffer.alloc(0), keys.partitionHash, keys.partitionHash, time.now);
        database.prepare(`DELETE FROM reuse_public_refresh_responses WHERE response_id IN (
          SELECT response_id FROM reuse_public_refresh_responses
          WHERE tenant_partition_hash = ? AND expires_at_ms <= ? ORDER BY expires_at_ms, response_id LIMIT 500
        )`).run(keys.partitionHash, time.now);
        database.prepare(`DELETE FROM reuse_correction_reservations
          WHERE scope_kind = 'tenant_private' AND partition_hash = ? AND entry_id IN (
            SELECT entry_id FROM reuse_entries
            WHERE scope_kind = 'tenant_private' AND partition_hash = ? AND expires_at_ms <= ? AND payload_purged = 1
              AND entry_id IN (SELECT entry_id FROM reuse_correction_reservations
                WHERE scope_kind = 'tenant_private' AND partition_hash = ?)
            ORDER BY expires_at_ms, entry_id LIMIT 500
          )`).run(keys.partitionHash, keys.partitionHash, time.now, keys.partitionHash);
      });
    }
    return Object.freeze({ purged, retainedOutboxPending: (await outboxSnapshot(scope, request, scopeKind)).unresolved });
  }

  async function bindingContext(scope, request, action, capability) {
    if (!isCorrectionCacheBindingCapability(capability)) fail('REUSE_DENIED');
    const info = scopeInfo(scope);
    const exactAction = action === 'private_profile.write' || action === 'private_profile.read'
      || action === 'cache.invalidate' ? action : 'private_profile.read';
    await authorize(info, request, exactAction);
    const index = await indexInfo(info, 'tenant_private', authorizationGuard(info, request, exactAction));
    try {
      return Object.freeze({ tenantId: info.tenantId, actorId: info.actorId, partitionHash: index.partitionHash });
    } finally {
      index.keyInfo.key.fill(0);
    }
  }

  // Private conditional transport participates in this store's existing encrypted
  // admission and observation transactions. It cannot reconcile monetary usage.
  const refreshIntents = new WeakMap();
  const bodyHashDomain = 'safe-fetch-decoded-entity-bytes/v1';

  function refreshContext(context) {
    if (!isRevalidationContext(context) || typeof config.authorizeBoundary !== 'function') {
      revalidationFail('REVALIDATION_UNSUPPORTED');
    }
    context.check();
  }

  function refreshGuard(info, request, profileRef, context) {
    return async () => {
      context.check();
      await context.wait(authorize(info, request, 'freshness.observe', { profileRef }));
      await context.wait(authorizeCurrentRequest(info, request, 'freshness.observe', { profileRef }));
      context.check();
    };
  }

  function refreshBoundary(info, request, binding, context, validUntilMs) {
    return {
      input: boundaryInput(info, request, binding.profileRef, 'freshness.observe', { revalidation: binding }),
      mustBeBeforeMs: Math.min(binding.expiresAtMs, validUntilMs),
      check: context.check,
    };
  }

  async function refreshPermission(info, request, loaded, binding, context) {
    const result = await context.wait(maybePermissions(info, request, loaded.payload, 'cache_read', currentTime()));
    if (!result.valid && (result.status === 'revoked' || result.status === 'expired')) {
      // A trusted rights decision uses the same local invalidation primitive as
      // an ordinary permission-checked cache read. Missing policy is not revocation.
      await refreshGuard(info, request, binding.profileRef, context)();
      await context.wait(withBindingDatabase((commit) => commit(), (database, time) => {
        context.check();
        const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND partition_hash = ?')
          .get(binding.profileRef, loaded.row.partition_hash);
        if (!sameStoredEntry(current, loaded.row)) fail('REUSE_BUSY');
        invalidateEntry(database, info, current, loaded.payload, `permission_${result.status}`,
          loaded.payload.consumers ?? [], time.now, loaded.keys);
      }, context.signal, refreshBoundary(info, request, binding, context, binding.expiresAtMs)));
    }
    if (!result.valid || !Number.isSafeInteger(result.validUntilMs)) revalidationFail('REVALIDATION_DENIED');
    return result.validUntilMs;
  }

  function sourceBindingMatches(binding, info, loaded) {
    return binding.schema === 'ei-private-conditional-source/v1'
      && binding.scopeKind === 'tenant_private' && binding.tenantId === info.tenantId && binding.actorId === info.actorId
      && binding.profileRef === loaded.row.entry_id && binding.profileVersion === loaded.row.version
      && binding.profileContentHash === loaded.payload.contentHash && binding.originalBodyHash === loaded.payload.contentHash
      && binding.bodyHashDomain === bodyHashDomain && binding.profileHashDomain === bodyHashDomain
      && binding.expiresAtMs === loaded.row.expires_at_ms
      && binding.originalRetrievedAt === iso(loaded.payload.retrievedAtMs)
      && stable(binding.identity) === stable(loaded.payload.identity) && stable(binding.pins) === stable(loaded.payload.pins)
      && loaded.payload.sourceRefs?.length === 1 && loaded.payload.sourceRefs[0] === binding.sourceRef;
  }

  async function bindRefreshSource(scope, request, inputValue, context) {
    refreshContext(context);
    const input = record(inputValue, new Set(['profileRef', 'scopeKind', 'sourceRef', 'evidenceId', 'evidenceVersion', 'document']));
    if (!input || input.scopeKind !== 'tenant_private' || !string(input.sourceRef) || !string(input.evidenceId)
      || !Number.isSafeInteger(input.evidenceVersion) || input.evidenceVersion < 1) revalidationFail('REVALIDATION_INVALID');
    const info = scopeInfo(scope);
    const ref = entryRefFor(scope, input.profileRef);
    const guard = refreshGuard(info, request, ref, context);
    await guard();
    const loaded = await context.wait(loadEntry(info, 'tenant_private', ref, guard));
    const { row, payload, keys, payloadKey } = loaded;
    try {
      const proof = safeFetchProvenance(input.document);
      const hop = proof?.hops?.[0];
      if (!proof || proof.mode !== 'document' || proof.redirectChain.length !== 0 || proof.hops.length !== 1
        || !proof.conditionalValidator || proof.requestedUrl !== proof.finalUrl || input.document.url !== proof.finalUrl
        || input.document.redirects !== 0 || hop.url !== proof.finalUrl || hop.statusCode !== 200
        || !hop.bodyComplete || !hop.dispatchIntent || !hop.responseReceived
        || hop.decodedBytes !== input.document.bytes?.byteLength || originalBodyHash(input.document.bytes) !== proof.bodyHash) {
        revalidationFail('REVALIDATION_PROVENANCE');
      }
      const binding = freeze({
        schema: 'ei-private-conditional-source/v1', scopeKind: 'tenant_private',
        tenantId: info.tenantId, actorId: info.actorId, profileRef: ref, profileVersion: row.version,
        identity: payload.identity, pins: payload.pins, profileContentHash: payload.contentHash,
        profileHashDomain: bodyHashDomain, sourceRef: input.sourceRef,
        evidenceId: input.evidenceId, evidenceVersion: input.evidenceVersion,
        sourceUrl: proof.finalUrl, contentType: input.document.contentType, originalBodyHash: proof.bodyHash, bodyHashDomain,
        originalRetrievedAt: input.document.fetchedAt, validator: proof.conditionalValidator,
        expiresAtMs: row.expires_at_ms,
      });
      if (row.eligible !== 1 || !sourceBindingMatches(binding, info, loaded)) revalidationFail('REVALIDATION_UNSUPPORTED');
      const retainedUntil = await context.retain(binding, 'bind');
      const permissionUntil = await refreshPermission(info, request, loaded, binding, context);
      await guard();
      const sealed = sealBounded(payloadKey.key, payloadKey.keyId, row.partition_hash, 'refresh_source', ref, binding);
      return await context.wait(withBindingDatabase((commit) => commit(), (database) => {
        context.check();
        const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND partition_hash = ?').get(ref, row.partition_hash);
        if (!sameStoredEntry(current, row)) fail('REUSE_BUSY');
        const prior = database.prepare('SELECT * FROM reuse_refresh_sources WHERE entry_id = ? AND partition_hash = ?').get(ref, row.partition_hash);
        if (prior) {
          if (prior.payload_key_id !== payloadKey.keyId) revalidationFail('REVALIDATION_UNSUPPORTED');
          const old = unseal(payloadKey.key, row.partition_hash, 'refresh_source', ref, prior.payload, prior.payload_key_id);
          if (stable(old) !== stable(binding)) revalidationFail('REVALIDATION_DENIED');
          return Object.freeze({ status: 'bound', profileRef: ref, profileVersion: row.version, replayed: true });
        }
        ensureStorageCapacity(database, sealed.byteLength);
        database.prepare('INSERT INTO reuse_refresh_sources (entry_id, partition_hash, version, payload_key_id, payload) VALUES (?, ?, ?, ?, ?)')
          .run(ref, row.partition_hash, row.version, payloadKey.keyId, sealed);
        return Object.freeze({ status: 'bound', profileRef: ref, profileVersion: row.version, replayed: false });
      }, context.signal, refreshBoundary(info, request, binding, context, Math.min(retainedUntil, permissionUntil))));
    } finally {
      keys.keyInfo.key.fill(0);
      payloadKey.key.fill(0);
    }
  }

  async function loadRefreshFlight(info, request, ref, admissionRef, context, suppliedGuard) {
    const guard = suppliedGuard ?? refreshGuard(info, request, ref, context);
    await guard();
    const keys = await context.wait(indexInfo(info, 'tenant_private', guard));
    let payloadKey;
    try {
      const row = await context.wait(withDatabase((database) => database.prepare("SELECT * FROM reuse_flights WHERE admission_id = ? AND scope_kind = 'tenant_private' AND partition_hash = ?")
        .get(admissionRef, keys.partitionHash)));
      if (!row) fail('REUSE_NOT_FOUND');
      payloadKey = await context.wait(resolveKey(info, 'payload', row.payload_key_id, guard));
      const payload = unseal(payloadKey.key, keys.partitionHash, 'flight', admissionRef, row.payload, row.payload_key_id);
      const actorBinding = mac(keys.keyInfo.key, `revalidation-actor:${info.actorId}`);
      if (!payload.actorBinding || payload.actorBinding !== actorBinding) {
        revalidationFail('REVALIDATION_DENIED');
      }
      return { row, keys, payloadKey, payload, actorBinding, guard };
    } catch (error) { keys.keyInfo.key.fill(0); payloadKey?.key.fill(0); throw error; }
  }

  function localRefreshResult(admissionRef, local, replayed) {
    return freeze({
      status: local.state === 'completed' ? 'completed' : 'unknown',
      admissionRef, profileRef: local.profileRef, profileVersion: local.profileVersion,
      localRefreshId: local.localRefreshId, bindingDigest: local.bindingDigest, replayed,
      ...(local.receipt ? { receipt: local.receipt } : {}),
      usage: 'unknown', holdDisposition: 'finance_reconciliation_required',
    });
  }

  async function prepareRefresh(scope, request, inputValue, context) {
    refreshContext(context);
    const input = record(inputValue, new Set(['profileRef', 'scopeKind', 'admissionRef']));
    if (!input || input.scopeKind !== 'tenant_private' || !string(input.admissionRef, 64)) revalidationFail('REVALIDATION_INVALID');
    const info = scopeInfo(scope);
    const ref = entryRefFor(scope, input.profileRef);
    const flight = await loadRefreshFlight(info, request, ref, input.admissionRef, context);
    let loaded;
    let sourceKey;
    try {
      if (flight.payload.localRefresh) {
        const local = flight.payload.localRefresh;
        if (local.scopeKind === 'public_profile' || local.profileRef !== ref || local.actorBinding !== flight.actorBinding) revalidationFail('REVALIDATION_DENIED');
        await flight.guard();
        // This is an authorized historical receipt, not a new freshness decision.
        beginLocalBoundary(config.authorizeBoundary, boundaryInput(info, request, ref, 'freshness.observe', {
          admissionRef: input.admissionRef, localRefreshId: local.localRefreshId, historicalReceipt: true,
        }), () => fail('REUSE_DENIED'));
        context.check();
        return localRefreshResult(input.admissionRef, local, true);
      }
      if (flight.row.state !== 'active' || flight.row.lease_expires_at_ms <= currentTime()) revalidationFail('REVALIDATION_DENIED');
      loaded = await context.wait(loadEntry(info, 'tenant_private', ref, flight.guard));
      if (loaded.row.eligible !== 1 || stable(flight.payload.identity) !== stable(loaded.payload.identity)
        || stable(flight.payload.pins) !== stable(loaded.payload.pins)) revalidationFail('REVALIDATION_DENIED');
      const sourceRow = await context.wait(withDatabase((database) => database.prepare('SELECT * FROM reuse_refresh_sources WHERE entry_id = ? AND partition_hash = ?').get(ref, flight.keys.partitionHash)));
      if (!sourceRow) revalidationFail('REVALIDATION_PROVENANCE');
      sourceKey = await context.wait(resolveKey(info, 'payload', sourceRow.payload_key_id, flight.guard));
      const binding = freeze(unseal(sourceKey.key, sourceRow.partition_hash, 'refresh_source', ref, sourceRow.payload, sourceRow.payload_key_id));
      if (!sourceBindingMatches(binding, info, loaded)) revalidationFail('REVALIDATION_DENIED');
      const retainedUntil = await context.retain(binding, 'prepare');
      const permissionUntil = await refreshPermission(info, request, loaded, binding, context);
      await flight.guard();
      const local = {
        localRefreshId: randomUUID(), state: 'dispatch_intent', profileRef: ref, profileVersion: loaded.row.version,
        actorBinding: flight.actorBinding, bindingDigest: mac(flight.keys.keyInfo.key, stable(binding)),
      };
      const prepared = await context.wait(withBindingDatabase((commit) => commit(), (database, time) => {
        context.check();
        const currentFlight = database.prepare('SELECT * FROM reuse_flights WHERE admission_id = ? AND partition_hash = ?').get(input.admissionRef, flight.keys.partitionHash);
        if (!currentFlight || currentFlight.payload_key_id !== flight.row.payload_key_id) fail('REUSE_BUSY');
        if (!Buffer.from(currentFlight.payload).equals(Buffer.from(flight.row.payload))) {
          const raced = unseal(flight.payloadKey.key, flight.keys.partitionHash, 'flight', input.admissionRef,
            currentFlight.payload, currentFlight.payload_key_id).localRefresh;
          if (!raced || raced.scopeKind === 'public_profile' || raced.profileRef !== ref || raced.actorBinding !== flight.actorBinding
            || raced.bindingDigest !== local.bindingDigest) fail('REUSE_BUSY');
          return { replay: localRefreshResult(input.admissionRef, raced, true) };
        }
        if (currentFlight.state !== 'active' || currentFlight.lease_expires_at_ms <= time.now) fail('REUSE_DENIED');
        const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND partition_hash = ?').get(ref, flight.keys.partitionHash);
        const currentSource = database.prepare('SELECT * FROM reuse_refresh_sources WHERE entry_id = ? AND partition_hash = ?').get(ref, flight.keys.partitionHash);
        if (!sameStoredEntry(current, loaded.row) || !currentSource
          || !Buffer.from(currentSource.payload).equals(Buffer.from(sourceRow.payload))) fail('REUSE_BUSY');
        const last = database.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(ref);
        if (!last) fail('REUSE_INTEGRITY');
        const payload = sealBounded(flight.payloadKey.key, flight.payloadKey.keyId, flight.keys.partitionHash, 'flight', input.admissionRef,
          { ...flight.payload, localRefresh: local });
        ensureStorageCapacity(database, payload.byteLength, currentFlight.payload.byteLength);
        database.prepare('UPDATE reuse_flights SET payload = ? WHERE admission_id = ? AND partition_hash = ?')
          .run(payload, input.admissionRef, flight.keys.partitionHash);
        return { last };
      }, context.signal, refreshBoundary(info, request, binding, context, Math.min(retainedUntil, permissionUntil, flight.row.lease_expires_at_ms))));
      if (prepared.replay) return prepared.replay;
      const token = opaque();
      refreshIntents.set(token, { context, info, binding, sourceRow, entry: loaded.row, last: prepared.last,
        admissionRef: input.admissionRef, local });
      return Object.freeze({ status: 'dispatch', token, sourceUrl: binding.sourceUrl, validator: binding.validator });
    } finally {
      flight.keys.keyInfo.key.fill(0);
      flight.payloadKey.key.fill(0);
      loaded?.keys.keyInfo.key.fill(0);
      loaded?.payloadKey.key.fill(0);
      sourceKey?.key.fill(0);
    }
  }

  async function withCurrentRefresh(scope, request, token, context, phase, operation) {
    refreshContext(context);
    const pending = refreshIntents.get(token);
    const info = scopeInfo(scope);
    if (!pending || pending.context !== context || pending.info.tenantId !== info.tenantId
      || pending.info.actorId !== info.actorId) revalidationFail('REVALIDATION_DENIED');
    const { binding } = pending;
    const guard = refreshGuard(info, request, binding.profileRef, context);
    await guard();
    const loaded = await context.wait(loadEntry(info, 'tenant_private', binding.profileRef, guard));
    let flight;
    try {
      if (!sourceBindingMatches(binding, info, loaded)) revalidationFail('REVALIDATION_DENIED');
      const retainedUntil = await context.retain(binding, phase);
      const permissionUntil = await refreshPermission(info, request, loaded, binding, context);
      flight = await loadRefreshFlight(info, request, binding.profileRef, pending.admissionRef, context);
      const local = flight.payload.localRefresh;
      if (!local || local.localRefreshId !== pending.local.localRefreshId || local.bindingDigest !== pending.local.bindingDigest
        || local.state !== 'dispatch_intent' || !['active', 'unknown'].includes(flight.row.state)) revalidationFail('REVALIDATION_DENIED');
      const lastKey = pending.last.payload_key_id === loaded.payloadKey.keyId ? loaded.payloadKey
        : await context.wait(resolveKey(info, 'payload', pending.last.payload_key_id, guard));
      try {
        const rawCurrent = unseal(lastKey.key, loaded.row.partition_hash, 'observation', pending.last.observation_id, pending.last.payload, pending.last.payload_key_id);
        await guard();
        return await context.wait(withBindingDatabase((commit) => commit(), (database, time) => {
          context.check();
          const current = database.prepare('SELECT * FROM reuse_entries WHERE entry_id = ? AND partition_hash = ?').get(binding.profileRef, loaded.row.partition_hash);
          const source = database.prepare('SELECT * FROM reuse_refresh_sources WHERE entry_id = ? AND partition_hash = ?').get(binding.profileRef, loaded.row.partition_hash);
          const last = database.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(binding.profileRef);
          const currentFlight = database.prepare('SELECT * FROM reuse_flights WHERE admission_id = ? AND partition_hash = ?').get(pending.admissionRef, loaded.row.partition_hash);
          if (!sameStoredEntry(current, pending.entry) || !sameStoredEntry(current, loaded.row)
            || !sameStoredObservation(last, pending.last) || !source
            || source.payload_key_id !== pending.sourceRow.payload_key_id
            || !Buffer.from(source.payload).equals(Buffer.from(pending.sourceRow.payload))
            || !currentFlight || currentFlight.state !== flight.row.state || currentFlight.payload_key_id !== flight.row.payload_key_id
            || !Buffer.from(currentFlight.payload).equals(Buffer.from(flight.row.payload))) fail('REUSE_BUSY');
          if (phase === 'dispatch' && (currentFlight.state !== 'active' || currentFlight.lease_expires_at_ms <= time.now)) {
            revalidationFail('REVALIDATION_DENIED');
          }
          const result = operation({ database, time, info, pending, loaded, flight, rawCurrent });
          context.check();
          return result;
        }, context.signal, refreshBoundary(info, request, binding, context, Math.min(retainedUntil, permissionUntil))));
      } finally { if (lastKey !== loaded.payloadKey) lastKey.key.fill(0); }
    } finally {
      loaded.keys.keyInfo.key.fill(0);
      loaded.payloadKey.key.fill(0);
      flight?.keys.keyInfo.key.fill(0);
      flight?.payloadKey.key.fill(0);
    }
  }

  async function completeRefresh(scope, request, token, response, context) {
    const proof = conditionalResponseProvenance(response);
    const pending = refreshIntents.get(token);
    if (!proof || !pending || proof.intent !== token || proof.sourceUrl !== pending.binding.sourceUrl
      || proof.redirects !== 0 || proof.bodyHashDomain !== bodyHashDomain
      || stable(proof.sentValidator) !== stable(pending.binding.validator)
      || (proof.kind === 'not_modified' && stable(proof.receivedValidator) !== stable(pending.binding.validator))
      || (proof.kind === 'body' && (originalBodyHash(response.bytes) !== proof.bodyHash
        || (proof.bodyHash === pending.binding.originalBodyHash && response.contentType !== pending.binding.contentType)))) {
      revalidationFail('REVALIDATION_PROVENANCE');
    }
    const result = await withCurrentRefresh(scope, request, token, context, 'commit', ({ database, time, info, pending: exact, loaded, flight, rawCurrent }) => {
      const verified = {
        status: proof.kind === 'body' ? proof.bodyHash === exact.binding.originalBodyHash ? 'not_modified' : 'body_changed' : proof.kind,
        contentHash: proof.kind === 'body' ? proof.bodyHash : exact.binding.originalBodyHash,
        retrievedAtMs: proof.kind === 'body' ? timestamp(proof.retrievedAt) : null,
        validatedAtMs: timestamp(proof.observedAt), sourceVersion: 'unknown', attemptLineage: validateLineage({ status: 'unknown' }),
      };
      if (!['not_modified', 'body_changed', 'removed', 'outage'].includes(verified.status)
        || verified.validatedAtMs < rawCurrent.validatedAtMs || verified.validatedAtMs > time.now + 60_000) {
        revalidationFail('REVALIDATION_PROVENANCE');
      }
      const transport = {
        localRefreshId: exact.local.localRefreshId, bindingDigest: exact.local.bindingDigest,
        responseKind: proof.kind === 'body' && verified.status === 'not_modified' ? 'body_unchanged' : proof.kind,
        httpStatus: proof.statusCode, responseObservedAt: proof.observedAt, responseRetrievedAt: proof.retrievedAt,
        responseBodyHash: proof.bodyHash, bodyHashDomain,
      };
      const next = {
        status: verified.status, contentHash: verified.contentHash, retrievedAtMs: effectiveRetrievedAt(loaded.payload, rawCurrent),
        bodyObservedAtMs: proof.kind === 'body' ? verified.retrievedAtMs : null,
        validatedAtMs: verified.validatedAtMs, sourceVersion: verified.sourceVersion, attemptLineage: verified.attemptLineage,
        previousObservationStatus: rawCurrent.status, revalidation: transport,
      };
      const observed = commitPreparedObservation(database, time, {
        info, input: { scopeKind: 'tenant_private' }, ref: exact.binding.profileRef,
        row: loaded.row, keys: loaded.keys, payloadKey: loaded.payloadKey, payload: loaded.payload,
        last: exact.last, rawCurrent, verified, next,
      });
      if (observed.status === 'unavailable') fail('REUSE_BUSY');
      // Legacy observation identity can coalesce equal-millisecond results.
      // A new refresh attempt cannot borrow a different transport's durable join.
      if (observed.duplicateObservation && (rawCurrent.revalidation?.localRefreshId !== exact.local.localRefreshId
        || rawCurrent.revalidation?.bindingDigest !== exact.local.bindingDigest)) fail('REUSE_BUSY');
      const observation = database.prepare('SELECT observation_id FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(exact.binding.profileRef);
      const receipt = {
        observationRef: observation.observation_id, observationStatus: observed.status,
        responseKind: transport.responseKind, httpStatus: proof.statusCode,
        invalidated: observed.invalidated, duplicateObservation: observed.duplicateObservation === true,
      };
      const completed = { ...flight.payload.localRefresh, state: 'completed', receipt };
      const payload = sealBounded(flight.payloadKey.key, flight.payloadKey.keyId, flight.keys.partitionHash, 'flight', exact.admissionRef,
        { ...flight.payload, localRefresh: completed });
      ensureStorageCapacity(database, payload.byteLength, flight.row.payload.byteLength);
      // Only the local receipt changes: state, unknown usage and original expense lineage are retained.
      database.prepare('UPDATE reuse_flights SET payload = ? WHERE admission_id = ? AND partition_hash = ?')
        .run(payload, exact.admissionRef, flight.keys.partitionHash);
      return localRefreshResult(exact.admissionRef, completed, false);
    });
    refreshIntents.delete(token);
    return result;
  }

  // Reviewed public facts and the originating tenant's full source occupy
  // different authority, encryption and hash domains. This composition never
  // calls the legacy Finance lineage handoff to obtain mutation permission.
  const publicRefreshIntents = new WeakMap();
  const publicProfileHashDomain = 'scoped-reuse-reviewed-publication-content-key/v1';

  function publicRefreshGuard(info, request, profileRef, context) {
    return async () => {
      context.check();
      const details = { profileRef, scopeKind: 'public_profile' };
      await context.wait(authorize(info, request, 'freshness.observe', details));
      await context.wait(authorizeCurrentRequest(info, request, 'freshness.observe', details));
      context.check();
    };
  }

  function publicRefreshBoundary(info, request, binding, context, validUntilMs, cleanup = false) {
    return {
      input: boundaryInput(info, request, binding.profileRef, 'freshness.observe', {
        scopeKind: 'public_profile', revalidation: binding, ...(cleanup ? { privateSourceCleanup: true } : {}),
      }),
      mustBeBeforeMs: cleanup ? MAX_TIME : Math.min(binding.expiresAtMs, validUntilMs),
      check: context.check,
    };
  }

  function disposePublicTarget(target) {
    target?.keys.keyInfo.key.fill(0);
    target?.payloadKey.key.fill(0);
    target?.privateKeys?.keyInfo.key.fill(0);
    target?.linkKey?.key.fill(0);
    target?.sourceKey?.key.fill(0);
  }

  async function loadPublicRefreshTarget(info, request, ref, context) {
    const guard = publicRefreshGuard(info, request, ref, context);
    await guard();
    const target = await context.wait(loadEntry(info, 'public_profile', ref, guard));
    try {
      target.privateKeys = await context.wait(indexInfo(info, 'tenant_private', guard));
      const links = await context.wait(withDatabase((database) => database.prepare('SELECT * FROM reuse_private_links WHERE public_entry_id = ? LIMIT 2').all(ref)));
      if (links.length !== 1 || links[0].tenant_partition_hash !== target.privateKeys.partitionHash) {
        revalidationFail('REVALIDATION_UNSUPPORTED');
      }
      target.link = links[0];
      target.linkKey = await context.wait(resolveKey(info, 'payload', target.link.payload_key_id, guard));
      target.linkPayload = unseal(target.linkKey.key, target.privateKeys.partitionHash, 'private_link',
        target.link.link_id, target.link.payload, target.link.payload_key_id);
      const link = target.linkPayload;
      if (target.payload.kind !== 'public' || target.row.eligible !== 1 || target.row.payload_purged !== 0
        || !string(link.sourceRecordId) || link.version !== target.row.version
        || link.contentHash !== target.payload.contentHash || stable(link.identity) !== stable(target.payload.identity)
        || !Array.isArray(link.sourceRefs) || link.sourceRefs.length !== 1
        || !Array.isArray(link.correctionRefs) || link.correctionRefs.length !== 0
        || !Array.isArray(link.permissions) || link.permissions.length === 0
        || !Number.isSafeInteger(link.expiresAtMs)) revalidationFail('REVALIDATION_UNSUPPORTED');
      target.sourceRow = await context.wait(withDatabase((database) => database.prepare(
        'SELECT * FROM reuse_public_refresh_sources WHERE entry_id = ? AND tenant_partition_hash = ?',
      ).get(ref, target.privateKeys.partitionHash)));
      if (target.sourceRow && target.sourceRow.payload_purged === 0) {
        target.sourceKey = await context.wait(resolveKey(info, 'payload', target.sourceRow.payload_key_id, guard));
        target.binding = freeze(unseal(target.sourceKey.key, target.privateKeys.partitionHash, 'public_refresh_source',
          ref, target.sourceRow.payload, target.sourceRow.payload_key_id));
      }
      return target;
    } catch (error) { disposePublicTarget(target); throw error; }
  }

  function samePublicTarget(database, target) {
    const current = database.prepare("SELECT * FROM reuse_entries WHERE entry_id = ? AND scope_kind = 'public_profile' AND partition_hash = ?")
      .get(target.row.entry_id, target.row.partition_hash);
    const links = database.prepare('SELECT * FROM reuse_private_links WHERE public_entry_id = ? LIMIT 2').all(target.row.entry_id);
    if (!sameStoredEntry(current, target.row) || current.eligible !== 1 || links.length !== 1
      || links[0].link_id !== target.link.link_id || links[0].tenant_partition_hash !== target.privateKeys.partitionHash
      || links[0].payload_key_id !== target.link.payload_key_id
      || !Buffer.from(links[0].payload).equals(Buffer.from(target.link.payload))) fail('REUSE_BUSY');
    return current;
  }

  function samePublicSource(left, right) {
    return Boolean(left && right && left.entry_id === right.entry_id && left.tenant_partition_hash === right.tenant_partition_hash
      && left.link_id === right.link_id && left.version === right.version && left.expires_at_ms === right.expires_at_ms
      && left.payload_purged === right.payload_purged && left.payload_key_id === right.payload_key_id
      && Buffer.from(left.payload).equals(Buffer.from(right.payload)));
  }

  function publicSourceMatches(binding, info, target) {
    return binding?.schema === 'ei-reviewed-public-conditional-source/v1' && binding.scopeKind === 'public_profile'
      && binding.tenantId === info.tenantId && binding.actorId === info.actorId
      && binding.profileRef === target.row.entry_id && binding.profileVersion === target.row.version
      && binding.publicationLinkId === target.link.link_id && binding.sourceRecordId === target.linkPayload.sourceRecordId
      && binding.profileContentHash === target.payload.contentHash && binding.profileHashDomain === publicProfileHashDomain
      && binding.bodyHashDomain === bodyHashDomain && binding.sourceRef === target.linkPayload.sourceRefs[0]
      && stable(binding.identity) === stable(target.payload.identity) && stable(binding.pins) === stable(target.payload.pins)
      && Number.isSafeInteger(binding.expiresAtMs) && binding.expiresAtMs <= target.row.expires_at_ms
      && binding.expiresAtMs <= target.linkPayload.expiresAtMs;
  }

  async function scrubPublicSource(info, request, target, binding, context) {
    await publicRefreshGuard(info, request, binding.profileRef, context)();
    await context.wait(withBindingDatabase((commit) => commit(), (database) => {
      samePublicTarget(database, target);
      const source = database.prepare('SELECT * FROM reuse_public_refresh_sources WHERE entry_id = ? AND tenant_partition_hash = ?')
        .get(binding.profileRef, target.privateKeys.partitionHash);
      if (target.sourceRow && !samePublicSource(source, target.sourceRow)) fail('REUSE_BUSY');
      if (source) database.prepare('UPDATE reuse_public_refresh_sources SET payload = ?, payload_purged = 1 WHERE entry_id = ? AND tenant_partition_hash = ?')
        .run(Buffer.alloc(0), binding.profileRef, target.privateKeys.partitionHash);
      database.prepare('DELETE FROM reuse_public_refresh_responses WHERE entry_id = ? AND tenant_partition_hash = ?')
        .run(binding.profileRef, target.privateKeys.partitionHash);
    }, context.signal, publicRefreshBoundary(info, request, binding, context, MAX_TIME, true)));
  }

  async function revokeRetainedPublicSource(scope, request, binding, context) {
    refreshContext(context);
    const info = scopeInfo(scope);
    const target = await loadPublicRefreshTarget(info, request, binding.profileRef, context);
    try {
      if (!publicSourceMatches(binding, info, target)
        || (target.binding && stable(target.binding) !== stable(binding))) revalidationFail('REVALIDATION_DENIED');
      await scrubPublicSource(info, request, target, binding, context);
    } finally { disposePublicTarget(target); }
  }

  async function publicRefreshPermissions(info, request, target, binding, context) {
    const guard = publicRefreshGuard(info, request, binding.profileRef, context);
    if (currentTime() >= Math.min(binding.expiresAtMs, target.linkPayload.expiresAtMs, target.row.expires_at_ms)) {
      await scrubPublicSource(info, request, target, binding, context);
      revalidationFail('REVALIDATION_DENIED');
    }
    const facts = await context.wait(maybePermissions(info, request, target.payload, 'fact_read', currentTime()));
    if (!facts.valid) {
      if (facts.status === 'revoked' || facts.status === 'expired') {
        await guard();
        await context.wait(withBindingDatabase((commit) => commit(), (database, time) => {
          const current = samePublicTarget(database, target);
          invalidateEntry(database, info, current, target.payload, `permission_${facts.status}`,
            target.payload.consumers ?? [], time.now, target.keys);
        }, context.signal, publicRefreshBoundary(info, request, binding, context, binding.expiresAtMs)));
      }
      revalidationFail('REVALIDATION_DENIED');
    }
    // The stored private permission still refers to the reviewed profile key and
    // its original use. Full-source EvidenceStore access is a separate mandatory
    // authority check, not an inferred permission on the native body hash.
    const source = await context.wait(verifyStoredPermissions(info, request, target.linkPayload, 'freshness.observe', currentTime(),
      { profileRef: binding.profileRef, scopeKind: 'public_profile' }));
    if (!source.valid || !Number.isSafeInteger(source.validUntilMs)) {
      if (source.status === 'revoked' || source.status === 'expired') await scrubPublicSource(info, request, target, binding, context);
      revalidationFail('REVALIDATION_DENIED');
    }
    await guard();
    return Math.min(source.validUntilMs, facts.validUntilMs ?? target.row.expires_at_ms, binding.expiresAtMs);
  }

  async function bindPublicRefreshSource(scope, request, inputValue, context) {
    refreshContext(context);
    const input = !IS_PROXY(inputValue) && record(inputValue, new Set(['profileRef', 'scopeKind', 'sourceRef', 'evidenceId', 'evidenceVersion', 'document']));
    if (!input || input.scopeKind !== 'public_profile' || !string(input.sourceRef) || !string(input.evidenceId)
      || !Number.isSafeInteger(input.evidenceVersion) || input.evidenceVersion < 1) revalidationFail('REVALIDATION_INVALID');
    const info = scopeInfo(scope);
    const ref = entryRefFor(scope, input.profileRef);
    const target = await loadPublicRefreshTarget(info, request, ref, context);
    try {
      if (target.sourceRow?.payload_purged === 1) revalidationFail('REVALIDATION_DENIED');
      const proof = safeFetchProvenance(input.document);
      const hop = proof?.hops?.[0];
      if (!proof || proof.mode !== 'document' || proof.redirectChain.length !== 0 || proof.hops.length !== 1
        || !proof.conditionalValidator || proof.requestedUrl !== proof.finalUrl || input.document.url !== proof.finalUrl
        || input.document.redirects !== 0 || hop.url !== proof.finalUrl || hop.statusCode !== 200
        || !hop.bodyComplete || !hop.dispatchIntent || !hop.responseReceived
        || hop.decodedBytes !== input.document.bytes?.byteLength || originalBodyHash(input.document.bytes) !== proof.bodyHash) {
        revalidationFail('REVALIDATION_PROVENANCE');
      }
      let binding = freeze({
        schema: 'ei-reviewed-public-conditional-source/v1', scopeKind: 'public_profile',
        tenantId: info.tenantId, actorId: info.actorId, publicationLinkId: target.link.link_id,
        sourceRecordId: target.linkPayload.sourceRecordId, profileRef: ref, profileVersion: target.row.version,
        identity: target.payload.identity, pins: target.payload.pins, profileContentHash: target.payload.contentHash,
        profileHashDomain: publicProfileHashDomain, sourceRef: input.sourceRef, evidenceId: input.evidenceId,
        evidenceVersion: input.evidenceVersion, sourceUrl: proof.finalUrl, contentType: input.document.contentType,
        originalBodyHash: proof.bodyHash, bodyHashDomain, originalRetrievedAt: input.document.fetchedAt,
        validator: proof.conditionalValidator,
        expiresAtMs: target.binding?.expiresAtMs ?? Math.min(target.row.expires_at_ms, target.linkPayload.expiresAtMs),
      });
      if (!publicSourceMatches(binding, info, target)) revalidationFail('REVALIDATION_UNSUPPORTED');
      if (target.binding && stable(target.binding) !== stable(binding)) revalidationFail('REVALIDATION_DENIED');
      let permissionUntil = await publicRefreshPermissions(info, request, target, binding, context);
      let retainedUntil = await context.retain(binding, 'bind');
      const fixedExpiry = Math.min(binding.expiresAtMs, retainedUntil, permissionUntil);
      if (!target.binding && fixedExpiry !== binding.expiresAtMs) {
        binding = freeze({ ...binding, expiresAtMs: fixedExpiry });
        // Bind the final earliest deadline explicitly; never silently renew it.
        retainedUntil = await context.retain(binding, 'bind');
        permissionUntil = await publicRefreshPermissions(info, request, target, binding, context);
      }
      // Every accepted grant must cover the exact immutable retention claim.
      // A second narrowing cannot silently preserve the first, longer expiry;
      // refuse before persistence instead of chasing changing grants in a loop.
      if (Math.min(retainedUntil, permissionUntil) < binding.expiresAtMs) revalidationFail('REVALIDATION_DENIED');
      await publicRefreshGuard(info, request, ref, context)();
      const sealed = sealBounded(target.linkKey.key, target.linkKey.keyId, target.privateKeys.partitionHash,
        'public_refresh_source', ref, binding);
      return await context.wait(withBindingDatabase((commit) => commit(), (database) => {
        samePublicTarget(database, target);
        const prior = database.prepare('SELECT * FROM reuse_public_refresh_sources WHERE entry_id = ? AND tenant_partition_hash = ?')
          .get(ref, target.privateKeys.partitionHash);
        if (prior) {
          if (!samePublicSource(prior, target.sourceRow) || !target.binding) fail('REUSE_BUSY');
          return Object.freeze({ status: 'bound', scopeKind: 'public_profile', profileRef: ref, profileVersion: target.row.version, replayed: true });
        }
        if (target.sourceRow) fail('REUSE_BUSY');
        ensureStorageCapacity(database, sealed.byteLength);
        database.prepare(`INSERT INTO reuse_public_refresh_sources
          (entry_id, tenant_partition_hash, link_id, version, expires_at_ms, payload_key_id, payload) VALUES (?, ?, ?, ?, ?, ?, ?)`)
          .run(ref, target.privateKeys.partitionHash, target.link.link_id, target.row.version, binding.expiresAtMs, target.linkKey.keyId, sealed);
        return Object.freeze({ status: 'bound', scopeKind: 'public_profile', profileRef: ref, profileVersion: target.row.version, replayed: false });
      }, context.signal, publicRefreshBoundary(info, request, binding, context, Math.min(retainedUntil, permissionUntil))));
    } finally { disposePublicTarget(target); }
  }

  function publicRefreshResult(admissionRef, local, replayed) {
    return freeze({ ...localRefreshResult(admissionRef, local, replayed), scopeKind: 'public_profile' });
  }

  async function preparePublicRefresh(scope, request, inputValue, context) {
    refreshContext(context);
    const input = !IS_PROXY(inputValue) && record(inputValue, new Set(['profileRef', 'scopeKind', 'admissionRef']));
    if (!input || input.scopeKind !== 'public_profile' || !string(input.admissionRef, 64)) revalidationFail('REVALIDATION_INVALID');
    const info = scopeInfo(scope);
    const ref = entryRefFor(scope, input.profileRef);
    const guard = publicRefreshGuard(info, request, ref, context);
    const flight = await loadRefreshFlight(info, request, ref, input.admissionRef, context, guard);
    let target;
    try {
      if (flight.payload.localRefresh) {
        const local = flight.payload.localRefresh;
        if (local.scopeKind !== 'public_profile' || local.profileRef !== ref || local.actorBinding !== flight.actorBinding) revalidationFail('REVALIDATION_DENIED');
        await guard();
        beginLocalBoundary(config.authorizeBoundary, boundaryInput(info, request, ref, 'freshness.observe', {
          scopeKind: 'public_profile', admissionRef: input.admissionRef, localRefreshId: local.localRefreshId, historicalReceipt: true,
        }), () => fail('REUSE_DENIED'));
        context.check();
        return publicRefreshResult(input.admissionRef, local, true);
      }
      if (flight.row.state !== 'active' || flight.row.lease_expires_at_ms <= currentTime()) revalidationFail('REVALIDATION_DENIED');
      target = await loadPublicRefreshTarget(info, request, ref, context);
      if (!target.binding || !publicSourceMatches(target.binding, info, target)
        || stable(flight.payload.identity) !== stable(target.payload.identity)
        || stable(flight.payload.pins) !== stable(target.payload.pins)) revalidationFail('REVALIDATION_PROVENANCE');
      const binding = target.binding;
      const permissionUntil = await publicRefreshPermissions(info, request, target, binding, context);
      const retainedUntil = await context.retain(binding, 'prepare');
      await guard();
      const local = { scopeKind: 'public_profile', localRefreshId: randomUUID(), state: 'dispatch_intent',
        profileRef: ref, profileVersion: target.row.version, actorBinding: flight.actorBinding,
        bindingDigest: mac(flight.keys.keyInfo.key, stable(binding)) };
      const prepared = await context.wait(withBindingDatabase((commit) => commit(), (database, time) => {
        samePublicTarget(database, target);
        const source = database.prepare('SELECT * FROM reuse_public_refresh_sources WHERE entry_id = ? AND tenant_partition_hash = ?')
          .get(ref, target.privateKeys.partitionHash);
        if (!samePublicSource(source, target.sourceRow)) fail('REUSE_BUSY');
        const currentFlight = database.prepare('SELECT * FROM reuse_flights WHERE admission_id = ? AND partition_hash = ?')
          .get(input.admissionRef, flight.keys.partitionHash);
        if (!currentFlight || currentFlight.payload_key_id !== flight.row.payload_key_id) fail('REUSE_BUSY');
        if (!Buffer.from(currentFlight.payload).equals(Buffer.from(flight.row.payload))) {
          const raced = unseal(flight.payloadKey.key, flight.keys.partitionHash, 'flight', input.admissionRef,
            currentFlight.payload, currentFlight.payload_key_id).localRefresh;
          if (!raced || raced.scopeKind !== 'public_profile' || raced.profileRef !== ref || raced.actorBinding !== flight.actorBinding
            || raced.bindingDigest !== local.bindingDigest) fail('REUSE_BUSY');
          return { replay: publicRefreshResult(input.admissionRef, raced, true) };
        }
        if (currentFlight.state !== 'active' || currentFlight.lease_expires_at_ms <= time.now) revalidationFail('REVALIDATION_DENIED');
        const last = database.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(ref);
        if (!last) fail('REUSE_INTEGRITY');
        const payload = sealBounded(flight.payloadKey.key, flight.payloadKey.keyId, flight.keys.partitionHash, 'flight', input.admissionRef,
          { ...flight.payload, localRefresh: local });
        ensureStorageCapacity(database, payload.byteLength, currentFlight.payload.byteLength);
        database.prepare('UPDATE reuse_flights SET payload = ? WHERE admission_id = ? AND partition_hash = ?')
          .run(payload, input.admissionRef, flight.keys.partitionHash);
        return { last };
      }, context.signal, publicRefreshBoundary(info, request, binding, context, Math.min(retainedUntil, permissionUntil, flight.row.lease_expires_at_ms))));
      if (prepared.replay) return prepared.replay;
      const token = opaque();
      publicRefreshIntents.set(token, { context, info, binding, sourceRow: target.sourceRow, link: target.link,
        entry: target.row, last: prepared.last, admissionRef: input.admissionRef, local });
      return Object.freeze({ status: 'dispatch', token, sourceUrl: binding.sourceUrl, validator: binding.validator });
    } finally {
      disposePublicTarget(target);
      flight.keys.keyInfo.key.fill(0);
      flight.payloadKey.key.fill(0);
    }
  }

  async function withCurrentPublicRefresh(scope, request, token, context, phase, operation) {
    refreshContext(context);
    const pending = publicRefreshIntents.get(token);
    const info = scopeInfo(scope);
    if (!pending || pending.context !== context || pending.info.tenantId !== info.tenantId
      || pending.info.actorId !== info.actorId) revalidationFail('REVALIDATION_DENIED');
    const { binding } = pending;
    const guard = publicRefreshGuard(info, request, binding.profileRef, context);
    const target = await loadPublicRefreshTarget(info, request, binding.profileRef, context);
    let flight;
    let lastKey;
    try {
      if (!publicSourceMatches(binding, info, target) || !samePublicSource(target.sourceRow, pending.sourceRow)
        || target.link.link_id !== pending.link.link_id || target.link.payload_key_id !== pending.link.payload_key_id
        || !Buffer.from(target.link.payload).equals(Buffer.from(pending.link.payload))) revalidationFail('REVALIDATION_DENIED');
      const permissionUntil = await publicRefreshPermissions(info, request, target, binding, context);
      const retainedUntil = await context.retain(binding, phase);
      flight = await loadRefreshFlight(info, request, binding.profileRef, pending.admissionRef, context, guard);
      const local = flight.payload.localRefresh;
      if (!local || local.scopeKind !== 'public_profile' || local.localRefreshId !== pending.local.localRefreshId
        || local.bindingDigest !== pending.local.bindingDigest || local.state !== 'dispatch_intent'
        || !['active', 'unknown'].includes(flight.row.state)) revalidationFail('REVALIDATION_DENIED');
      lastKey = pending.last.payload_key_id === target.payloadKey.keyId ? target.payloadKey
        : await context.wait(resolveKey(null, 'payload', pending.last.payload_key_id, guard));
      const rawCurrent = unseal(lastKey.key, target.row.partition_hash, 'observation', pending.last.observation_id,
        pending.last.payload, pending.last.payload_key_id);
      await guard();
      return await context.wait(withBindingDatabase((commit) => commit(), (database, time) => {
        const current = samePublicTarget(database, target);
        const source = database.prepare('SELECT * FROM reuse_public_refresh_sources WHERE entry_id = ? AND tenant_partition_hash = ?')
          .get(binding.profileRef, target.privateKeys.partitionHash);
        const last = database.prepare('SELECT * FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(binding.profileRef);
        const currentFlight = database.prepare('SELECT * FROM reuse_flights WHERE admission_id = ? AND partition_hash = ?')
          .get(pending.admissionRef, flight.keys.partitionHash);
        if (!sameStoredEntry(current, pending.entry) || !sameStoredObservation(last, pending.last)
          || !samePublicSource(source, pending.sourceRow) || !currentFlight || currentFlight.state !== flight.row.state
          || currentFlight.payload_key_id !== flight.row.payload_key_id
          || !Buffer.from(currentFlight.payload).equals(Buffer.from(flight.row.payload))) fail('REUSE_BUSY');
        if (phase === 'dispatch' && (currentFlight.state !== 'active' || currentFlight.lease_expires_at_ms <= time.now)) {
          revalidationFail('REVALIDATION_DENIED');
        }
        const result = operation({ database, time, info, pending, target, flight, rawCurrent });
        context.check();
        return result;
      }, context.signal, publicRefreshBoundary(info, request, binding, context, Math.min(retainedUntil, permissionUntil))));
    } finally {
      if (lastKey && lastKey !== target.payloadKey) lastKey.key.fill(0);
      disposePublicTarget(target);
      flight?.keys.keyInfo.key.fill(0);
      flight?.payloadKey.key.fill(0);
    }
  }

  async function completePublicRefresh(scope, request, token, response, context) {
    const proof = conditionalResponseProvenance(response);
    const pending = publicRefreshIntents.get(token);
    if (!proof || !pending || proof.intent !== token || proof.sourceUrl !== pending.binding.sourceUrl
      || proof.redirects !== 0 || proof.bodyHashDomain !== bodyHashDomain
      || stable(proof.sentValidator) !== stable(pending.binding.validator)
      || (proof.kind === 'not_modified' && stable(proof.receivedValidator) !== stable(pending.binding.validator))
      || (proof.kind === 'body' && (originalBodyHash(response.bytes) !== proof.bodyHash
        || (proof.bodyHash === pending.binding.originalBodyHash && response.contentType !== pending.binding.contentType)))) {
      revalidationFail('REVALIDATION_PROVENANCE');
    }
    const result = await withCurrentPublicRefresh(scope, request, token, context, 'commit', ({ database, time, info, pending: exact, target, flight, rawCurrent }) => {
      const changed = proof.kind === 'body' && proof.bodyHash !== exact.binding.originalBodyHash;
      const status = proof.kind === 'body' ? changed ? 'body_changed' : 'not_modified' : proof.kind;
      const observedAtMs = timestamp(proof.observedAt);
      if (!['not_modified', 'body_changed', 'removed', 'outage'].includes(status)
        || observedAtMs <= rawCurrent.validatedAtMs || observedAtMs > time.now + 60_000) revalidationFail('REVALIDATION_PROVENANCE');
      const responseRef = randomUUID();
      const responseKind = proof.kind === 'body' && !changed ? 'body_unchanged' : proof.kind;
      const responsePayload = sealBounded(flight.payloadKey.key, flight.payloadKey.keyId, flight.keys.partitionHash,
        'public_refresh_response', responseRef, {
          localRefreshId: exact.local.localRefreshId, bindingDigest: exact.local.bindingDigest,
          responseKind, httpStatus: proof.statusCode, responseObservedAt: proof.observedAt,
          responseRetrievedAt: proof.retrievedAt, responseBodyHash: proof.bodyHash, bodyHashDomain,
        });
      ensureStorageCapacity(database, responsePayload.byteLength);
      database.prepare(`INSERT INTO reuse_public_refresh_responses
        (response_id, entry_id, tenant_partition_hash, expires_at_ms, payload_key_id, payload) VALUES (?, ?, ?, ?, ?, ?)`)
        .run(responseRef, exact.binding.profileRef, flight.keys.partitionHash, exact.binding.expiresAtMs,
          flight.payloadKey.keyId, responsePayload);
      const previousEvents = new Set(database.prepare('SELECT event_id FROM reuse_outbox WHERE entry_id = ?').all(exact.binding.profileRef).map((row) => row.event_id));
      let effect;
      if (changed) {
        // The new unreviewed body/hash never enters the shared fact profile or
        // observation stream. Invalidate exactly the old reviewed version.
        if (!invalidateEntry(database, info, target.row, target.payload, 'source_body_changed',
          target.payload.consumers ?? [], time.now, target.keys)) fail('REUSE_BUSY');
        effect = { effectKind: 'invalidation', reason: 'source_body_changed', invalidated: true };
      } else {
        const verified = { status, contentHash: target.payload.contentHash,
          retrievedAtMs: proof.kind === 'body' ? timestamp(proof.retrievedAt) : null,
          validatedAtMs: observedAtMs, sourceVersion: 'unknown', attemptLineage: validateLineage({ status: 'unknown' }) };
        const next = { status, contentHash: target.payload.contentHash,
          retrievedAtMs: proof.kind === 'body' ? verified.retrievedAtMs : effectiveRetrievedAt(target.payload, rawCurrent),
          bodyObservedAtMs: proof.kind === 'body' ? verified.retrievedAtMs : null,
          validatedAtMs: observedAtMs, sourceVersion: 'unknown', attemptLineage: verified.attemptLineage,
          previousObservationStatus: rawCurrent.status };
        const observed = commitPreparedObservation(database, time, { info, input: { scopeKind: 'public_profile' },
          ref: exact.binding.profileRef, row: target.row, keys: target.keys, payloadKey: target.payloadKey,
          payload: target.payload, last: exact.last, rawCurrent, verified, next });
        if (observed.status === 'unavailable' || observed.duplicateObservation) fail('REUSE_BUSY');
        const observation = database.prepare('SELECT observation_id FROM reuse_observations WHERE entry_id = ? ORDER BY sequence DESC LIMIT 1').get(exact.binding.profileRef);
        effect = { effectKind: observed.invalidated ? 'invalidation' : 'observation',
          ...(observed.invalidated ? { reason: 'removed' } : {}), invalidated: observed.invalidated,
          observationRef: observation.observation_id, observationStatus: status };
      }
      if (effect.invalidated) {
        effect.invalidationEventRefs = database.prepare('SELECT event_id FROM reuse_outbox WHERE entry_id = ?').all(exact.binding.profileRef)
          .map((row) => row.event_id).filter((id) => !previousEvents.has(id));
        if (effect.invalidationEventRefs.length === 0) fail('REUSE_INTEGRITY');
      }
      const receipt = { ...effect, responseRef, responseKind, httpStatus: proof.statusCode,
        responseRetainedAtCompletion: !effect.invalidated, duplicateObservation: false };
      const completed = { ...flight.payload.localRefresh, state: 'completed', receipt };
      const payload = sealBounded(flight.payloadKey.key, flight.payloadKey.keyId, flight.keys.partitionHash, 'flight', exact.admissionRef,
        { ...flight.payload, localRefresh: completed });
      ensureStorageCapacity(database, payload.byteLength, flight.row.payload.byteLength);
      database.prepare('UPDATE reuse_flights SET payload = ? WHERE admission_id = ? AND partition_hash = ?')
        .run(payload, exact.admissionRef, flight.keys.partitionHash);
      return publicRefreshResult(exact.admissionRef, completed, false);
    });
    publicRefreshIntents.delete(token);
    return result;
  }

  const api = Object.freeze({
    scopeForAuthenticatedRequest: publicBoundary(authenticatedScope),
    putPrivateProfile: publicBoundary(putPrivateProfile),
    publishReviewedPublicProfile: publicBoundary(publishReviewedPublicProfile),
    getPrivateProfile: publicBoundary(getPrivateProfile),
    getPublicProfile: publicBoundary(getPublicProfile),
    observe: publicBoundary(observe),
    invalidate: publicBoundary(invalidate),
    admitOperation: publicBoundary(admitOperation),
    reconcileAdmission: publicBoundary(reconcileAdmission),
    withPrivateLineage: publicBoundary(withPrivateLineage),
    dispatchPendingInvalidations: publicBoundary(dispatchPendingInvalidations),
    outboxSnapshot: publicBoundary(outboxSnapshot),
    integritySnapshot: publicBoundary(integritySnapshot),
    purgeExpired: publicBoundary(purgeExpired),
  });
  CACHE_BINDING_PORTS.set(api, Object.freeze({
    hasBoundaryGuard: typeof config.authorizeBoundary === 'function',
    context: bindingContext,
    validateProfileInput: (scope, request, input, signal, capability, callerFacts, binding) =>
      validateBoundPrivateProfileInput(scope, request, input, signal, capability, callerFacts, binding),
    disposePreflight: (token, capability) => {
      if (!isCorrectionCacheBindingCapability(capability)) fail('REUSE_DENIED');
      disposeBoundProfilePreflight(token);
    },
    putProfile: (scope, request, input, binding, operation, gate, signal, capability, preflightToken) =>
      putBoundPrivateProfile(scope, request, input, binding, operation, gate, signal, capability, preflightToken),
    loadCandidate: (scope, request, binding, use, signal, capability) =>
      loadBoundCandidate(scope, request, binding, use, signal, capability),
    prepareReadDatabase: (capability) => prepareBoundReadDatabase(capability),
    finalRead: (database, candidate, now, effectiveNow, capability, boundaryToken) =>
      finalBoundRead(database, candidate, now, effectiveNow, capability, boundaryToken),
    prepareFinalDisclosure: (scope, request, preflight, binding, signal, capability) =>
      prepareBoundFinalDisclosure(scope, request, preflight, binding, signal, capability),
    finalDisclosureCheck: (token, effectiveNow, capability) =>
      finalBoundDisclosureCheck(token, effectiveNow, capability),
    disposeFinalDisclosure: (token, capability) => disposeBoundFinalDisclosure(token, capability),
    invalidate: (scope, request, binding, operation, gate, signal, capability) =>
      invalidateBoundProfile(scope, request, binding, operation, gate, signal, capability),
    now: currentTime,
  }));
  REVALIDATION_PORTS.set(api, Object.freeze({
    bindSource: bindRefreshSource,
    prepare: prepareRefresh,
    beforeDispatch: (scope, request, token, context) => withCurrentRefresh(scope, request, token, context, 'dispatch', () => undefined),
    complete: completeRefresh,
    dispose: (token) => refreshIntents.delete(token),
  }));
  PUBLIC_REVALIDATION_PORTS.set(api, Object.freeze({
    bindSource: bindPublicRefreshSource,
    prepare: preparePublicRefresh,
    beforeDispatch: (scope, request, token, context) => withCurrentPublicRefresh(scope, request, token, context, 'dispatch', () => undefined),
    complete: completePublicRefresh,
    sourceAccessRevoked: revokeRetainedPublicSource,
    dispose: (token) => publicRefreshIntents.delete(token),
  }));
  return api;
}

export function getScopedReuseBindingPort(store, capability) {
  if (!isCorrectionCacheBindingCapability(capability)) fail('REUSE_DENIED');
  const port = CACHE_BINDING_PORTS.get(store);
  if (!port || !port.hasBoundaryGuard) fail('REUSE_DENIED');
  return port;
}

/** Private source import only. The opaque per-operation context is not host authority. */
export function getPrivateRevalidationPort(store, context) {
  if (!isRevalidationContext(context)) revalidationFail('REVALIDATION_DENIED');
  const port = REVALIDATION_PORTS.get(store);
  if (!port) revalidationFail('REVALIDATION_UNSUPPORTED');
  return port;
}

/** Private server composition only; this opaque capability is not host authority. */
export function getReviewedPublicRevalidationPort(store, context) {
  if (!isRevalidationContext(context)) revalidationFail('REVALIDATION_DENIED');
  const port = PUBLIC_REVALIDATION_PORTS.get(store);
  if (!port) revalidationFail('REVALIDATION_UNSUPPORTED');
  return port;
}
