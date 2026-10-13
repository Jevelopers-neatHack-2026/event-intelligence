import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, chmod } from 'node:fs/promises';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { hasSensitiveUrlMaterial, parseAndValidateUrl } from '../../security/url-policy.mjs';

const SCHEMA_VERSION = 5;
const WRITE_FENCE_VERSION = 1;
const CLAIM_BINDING_VERSION = 1;
const MAX_SEEDS = 10;
const MAX_DEPTH = 2;
const MAX_ATTEMPT_ADMISSIONS = 30;
const MAX_IN_FLIGHT = 4;
const MAX_DURATION_MS = 120_000;
const MAX_SUGGESTIONS = 16;
const MAX_SOURCE_REFS = 4;
const MAX_RUNS_PER_TENANT = 128;
const MAX_DATABASE_BYTES = 64 * 1024 * 1024;
const MAX_DECODED_BYTES_PER_RUN = 100 * 1024 * 1024;
const RESERVED_DECODED_BYTES_PER_HOP = 20 * 1024 * 1024;
const MAX_TENANT_IN_FLIGHT = MAX_RUNS_PER_TENANT * MAX_IN_FLIGHT;
const MAX_TENANT_RESERVED_BYTES = MAX_RUNS_PER_TENANT * MAX_DECODED_BYTES_PER_RUN;
const MAX_DATABASE_PAGES = 16_384;
const MAX_JSON_BYTES = 32 * 1024 * 1024;
const MAX_SQLITE_TIMEOUT_MS = 10_000;
const HEX_SHA256 = /^[a-f0-9]{64}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;

const DEFAULT_LIMITS = Object.freeze({
  maxDepth: 2,
  maxTransportAttemptAdmissions: 30,
  maxInFlightLeases: 4,
  durationMs: 120_000,
  maxSuggestionsPerCompletion: 16,
});

const DEFAULT_TENANT_LIMITS = Object.freeze({
  maxInFlightLeases: MAX_IN_FLIGHT,
  maxReservedDecodedBytes: MAX_DECODED_BYTES_PER_RUN,
});

const ERROR_MESSAGES = Object.freeze({
  FRONTIER_INVALID_INPUT: 'invalid frontier input',
  FRONTIER_DENIED: 'frontier access denied',
  FRONTIER_NOT_FOUND: 'frontier run not found',
  FRONTIER_CONFLICT: 'frontier state conflict',
  FRONTIER_STOPPED: 'frontier run is stopped',
  FRONTIER_STALE_LEASE: 'frontier lease is stale',
  FRONTIER_BUSY: 'frontier store is busy',
  FRONTIER_STORAGE_LIMIT: 'frontier storage limit reached',
  FRONTIER_VERSION: 'unsupported frontier state version',
  FRONTIER_STORAGE: 'frontier storage operation failed',
});

const STOP_REASONS = new Set([
  'cancelled',
  'budget_denied',
  'access_restricted',
  'deadline',
  'attempt_limit',
  'frontier_exhausted',
  'depth_limit',
  'fanout_limit',
  'unresolved_work',
  'adequate_facts',
  'review_required',
]);

const GLOBAL_HALT_REASONS = new Set([
  'cancelled', 'budget_denied', 'access_restricted', 'deadline', 'attempt_limit',
  'unresolved_work', 'adequate_facts', 'review_required',
]);

export class DiscoveryFrontierError extends Error {
  constructor(code = 'FRONTIER_STORAGE') {
    const safeCode = typeof code === 'string' && Object.hasOwn(ERROR_MESSAGES, code)
      ? code : 'FRONTIER_STORAGE';
    super(ERROR_MESSAGES[safeCode]);
    this.name = 'DiscoveryFrontierError';
    this.code = safeCode;
  }
}

function fail(code = 'FRONTIER_INVALID_INPUT') {
  throw new DiscoveryFrontierError(code);
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

function ownRecord(value, allowedKeys) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string' || !allowedKeys.has(key))) return null;
    const copy = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) return null;
      copy[key] = descriptor.value;
    }
    return copy;
  } catch {
    return null;
  }
}

function ownArray(value, maximumLength) {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    if (!lengthDescriptor || !Number.isSafeInteger(lengthDescriptor.value)
      || lengthDescriptor.value < 0 || lengthDescriptor.value > maximumLength) return null;
    const length = lengthDescriptor.value;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== length + 1 || !keys.includes('length')) return null;
    const copied = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) return null;
      copied.push(descriptor.value);
    }
    return copied;
  } catch {
    return null;
  }
}

function validText(value, maximum, { allowEmpty = false } = {}) {
  return typeof value === 'string'
    && value.length <= maximum
    && (allowEmpty || value.length > 0)
    && !value.includes('\0')
    && isWellFormed(value);
}

function validId(value, maximum = 128) {
  return validText(value, maximum) && SAFE_ID.test(value);
}

function stableCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function stableJson(value) {
  const json = JSON.stringify(value);
  if (typeof json !== 'string' || Buffer.byteLength(json, 'utf8') > MAX_JSON_BYTES) fail();
  return json;
}

function digest(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function candidateId(tenantHash, runId, canonicalUrl) {
  return digest(`event-intelligence:frontier-candidate:v1\0${tenantHash}\0${runId}\0${canonicalUrl}`);
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function normalizeUrl(raw) {
  if (!validText(raw, 8_192)) fail();
  try {
    const parsed = parseAndValidateUrl(raw);
    const supplied = new URL(raw);
    if (hasSensitiveUrlMaterial(supplied)) fail();
    return { suppliedUrl: raw, canonicalUrl: parsed.url.href };
  } catch {
    fail();
  }
}

function normalizeLocator(value) {
  const locator = ownRecord(value, new Set(['kind', 'startByte', 'endByte', 'pointer']));
  if (!locator || typeof locator.kind !== 'string') fail();
  if (locator.kind === 'text-range') {
    if (Object.hasOwn(locator, 'pointer')
      || !Number.isSafeInteger(locator.startByte) || locator.startByte < 0
      || !Number.isSafeInteger(locator.endByte) || locator.endByte <= locator.startByte) fail();
    return { kind: 'text-range', startByte: locator.startByte, endByte: locator.endByte };
  }
  if (locator.kind === 'json-pointer') {
    if (Object.hasOwn(locator, 'startByte') || Object.hasOwn(locator, 'endByte')
      || !validText(locator.pointer, 2_048, { allowEmpty: true })
      || (locator.pointer !== '' && !locator.pointer.startsWith('/'))
      || /~(?![01])/.test(locator.pointer)) fail();
    return { kind: 'json-pointer', pointer: locator.pointer };
  }
  fail();
}

function normalizeSourceReference(value, exactUrl) {
  const input = ownRecord(value, new Set(['evidenceId', 'contentHash', 'locator', 'field', 'value']));
  if (!input || !validId(input.evidenceId, 160) || typeof input.contentHash !== 'string'
    || !HEX_SHA256.test(input.contentHash)
    || !validText(input.field, 160) || !validText(input.value, 8_192) || input.value !== exactUrl) fail();
  return {
    evidenceId: input.evidenceId,
    contentHash: input.contentHash,
    locator: normalizeLocator(input.locator),
    field: input.field,
    value: input.value,
  };
}

function normalizeReferences(value, exactUrl, { required, maximum = MAX_SOURCE_REFS } = {}) {
  const raw = value === undefined && !required ? [] : ownArray(value, maximum);
  if (!raw || (required && raw.length === 0)) fail();
  const references = raw.map((reference) => normalizeSourceReference(reference, exactUrl));
  references.sort((left, right) => stableCompare(stableJson(left), stableJson(right)));
  return references;
}

function normalizeSeed(value) {
  const input = ownRecord(value, new Set(['url', 'sourceRefs']));
  if (!input) fail();
  const url = normalizeUrl(input.url);
  const sourceRefs = normalizeReferences(input.sourceRefs, url.suppliedUrl, { required: false });
  return { ...url, sourceRefs };
}

function normalizeSuggestion(value) {
  const input = ownRecord(value, new Set(['url', 'label', 'sourceRefs']));
  if (!input) fail();
  const url = normalizeUrl(input.url);
  const label = input.label === undefined ? null : input.label;
  if (input.label !== undefined && !validText(label, 512)) fail();
  const sourceRefs = normalizeReferences(input.sourceRefs, url.suppliedUrl, { required: true });
  return { ...url, label, sourceRefs };
}

function normalizeLimits(value) {
  if (value === undefined) return { ...DEFAULT_LIMITS };
  const limits = ownRecord(value, new Set(Object.keys(DEFAULT_LIMITS)));
  if (!limits) fail();
  const merged = { ...DEFAULT_LIMITS, ...limits };
  if (!Number.isSafeInteger(merged.maxDepth) || merged.maxDepth < 0 || merged.maxDepth > MAX_DEPTH
    || !Number.isSafeInteger(merged.maxTransportAttemptAdmissions) || merged.maxTransportAttemptAdmissions < 1
      || merged.maxTransportAttemptAdmissions > MAX_ATTEMPT_ADMISSIONS
    || !Number.isSafeInteger(merged.maxInFlightLeases) || merged.maxInFlightLeases < 1
      || merged.maxInFlightLeases > MAX_IN_FLIGHT
    || !Number.isSafeInteger(merged.durationMs) || merged.durationMs < 1 || merged.durationMs > MAX_DURATION_MS
    || !Number.isSafeInteger(merged.maxSuggestionsPerCompletion) || merged.maxSuggestionsPerCompletion < 1
      || merged.maxSuggestionsPerCompletion > MAX_SUGGESTIONS) fail();
  return merged;
}

function normalizeRunInput(value) {
  const input = ownRecord(value, new Set(['runId', 'seeds', 'limits', 'privateRunConfigHash']));
  if (!input || !validId(input.runId, 96)) fail();
  if (input.privateRunConfigHash !== undefined
    && (typeof input.privateRunConfigHash !== 'string' || !/^[a-f0-9]{64}$/.test(input.privateRunConfigHash))) fail();
  const seedsRaw = ownArray(input.seeds, MAX_SEEDS);
  if (!seedsRaw || seedsRaw.length < 1) fail();
  const seeds = seedsRaw.map(normalizeSeed);
  seeds.sort((left, right) => stableCompare(stableJson(left), stableJson(right)));
  const limits = normalizeLimits(input.limits);
  const config = {
    schema: 'ei-private-bounded-frontier/v1', runId: input.runId, seeds, limits,
    ...(input.privateRunConfigHash === undefined ? {} : { privateRunConfigHash: input.privateRunConfigHash }),
  };
  return { runId: input.runId, seeds, limits, config, configJson: stableJson(config), configHash: digest(stableJson(config)) };
}

function normalizeTenantLimits(value) {
  const supplied = value === undefined ? {} : ownRecord(value, new Set(Object.keys(DEFAULT_TENANT_LIMITS)));
  if (!supplied) fail();
  const limits = { ...DEFAULT_TENANT_LIMITS, ...supplied };
  if (!Number.isSafeInteger(limits.maxInFlightLeases) || limits.maxInFlightLeases < 1
    || limits.maxInFlightLeases > MAX_TENANT_IN_FLIGHT
    || !Number.isSafeInteger(limits.maxReservedDecodedBytes)
    || limits.maxReservedDecodedBytes < RESERVED_DECODED_BYTES_PER_HOP
    || limits.maxReservedDecodedBytes > MAX_TENANT_RESERVED_BYTES) fail();
  return Object.freeze(limits);
}

function normalizeWorkerInput(value) {
  const input = ownRecord(value, new Set(['workerId', 'claimKey']));
  if (!input || !validId(input.workerId, 96) || !validId(input.claimKey, 128)) fail();
  return input;
}

function normalizeAttemptInput(value) {
  const input = ownRecord(value, new Set(['leaseToken', 'attemptKey', 'kind', 'previousAttemptKey', 'url']));
  if (!input || !validId(input.leaseToken, 64) || !validId(input.attemptKey, 128)
    || !['initial', 'retry', 'redirect'].includes(input.kind)) fail();
  const url = normalizeUrl(input.url);
  const previousAttemptKey = input.previousAttemptKey;
  if (input.kind === 'initial') {
    if (previousAttemptKey !== undefined) fail();
  } else if (!validId(previousAttemptKey, 128)) fail();
  return { ...input, ...url, previousAttemptKey: previousAttemptKey ?? null };
}

function normalizeCompletionInput(value) {
  const input = ownRecord(value, new Set(['leaseToken', 'completionKey', 'outcome', 'suggestions', 'truncatedCount']));
  if (!input || !validId(input.leaseToken, 64) || !validId(input.completionKey, 128)
    || !['links_observed', 'no_links', 'failed', 'access_restricted'].includes(input.outcome)) fail();
  const suggestionsRaw = ownArray(input.suggestions, MAX_SUGGESTIONS);
  if (!suggestionsRaw) fail();
  const suggestions = suggestionsRaw.map(normalizeSuggestion);
  suggestions.sort((left, right) => stableCompare(stableJson(left), stableJson(right)));
  const truncatedCount = input.truncatedCount ?? 0;
  if (!Number.isSafeInteger(truncatedCount) || truncatedCount < 0 || truncatedCount > 1_000_000) fail();
  if ((input.outcome !== 'links_observed' && (suggestions.length > 0 || truncatedCount > 0))) fail();
  return { leaseToken: input.leaseToken, completionKey: input.completionKey, outcome: input.outcome, suggestions, truncatedCount };
}

function normalizeUnresolvedInput(value) {
  const input = ownRecord(value, new Set(['leaseToken', 'reason']));
  if (!input || !validId(input.leaseToken, 64)
    || !['worker_lost', 'dispatch_state_unknown', 'cancelled_before_dispatch'].includes(input.reason)) fail();
  return input;
}

function isBusy(error) {
  return error?.errcode === 5 || error?.errcode === 6 || error?.code === 'ERR_SQLITE_BUSY';
}

function checkOperationSignal(signal) {
  if (signal?.aborted) fail('FRONTIER_STOPPED');
}

async function retryDelay(deadline, signal) {
  checkOperationSignal(signal);
  const remaining = deadline - performance.now();
  if (remaining <= 0) fail('FRONTIER_BUSY');
  await new Promise((resolve, reject) => {
    let timer;
    const onAbort = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      reject(new DiscoveryFrontierError('FRONTIER_STOPPED'));
    };
    timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, Math.min(8, Math.max(1, remaining)));
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
  checkOperationSignal(signal);
}

function safeStorageError(error) {
  if (error instanceof DiscoveryFrontierError) return error;
  if (error?.errcode === 13 || error?.code === 'ERR_SQLITE_FULL') {
    return new DiscoveryFrontierError('FRONTIER_STORAGE_LIMIT');
  }
  return new DiscoveryFrontierError(isBusy(error) ? 'FRONTIER_BUSY' : 'FRONTIER_STORAGE');
}

function schemaSql() {
  return `
    CREATE TABLE IF NOT EXISTS frontier_tenant_policy (
      tenant_hash TEXT PRIMARY KEY,
      policy_json TEXT NOT NULL,
      policy_hash TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS frontier_runs (
      tenant_hash TEXT NOT NULL,
      run_id TEXT NOT NULL,
      config_hash TEXT NOT NULL,
      config_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      deadline_at_ms INTEGER NOT NULL,
      last_clock_ms INTEGER NOT NULL,
      max_depth INTEGER NOT NULL,
      max_attempts INTEGER NOT NULL,
      max_in_flight INTEGER NOT NULL,
      duration_ms INTEGER NOT NULL,
      max_suggestions INTEGER NOT NULL,
      attempts_admitted INTEGER NOT NULL DEFAULT 0,
      next_observation_sequence INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL CHECK (status IN ('active', 'halted', 'exhausted')),
      halt_reason TEXT,
      PRIMARY KEY (tenant_hash, run_id)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS frontier_candidates (
      tenant_hash TEXT NOT NULL,
      run_id TEXT NOT NULL,
      candidate_id TEXT NOT NULL,
      canonical_url TEXT NOT NULL,
      best_depth INTEGER NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'completed', 'unresolved', 'depth_limited')),
      is_seed INTEGER NOT NULL CHECK (is_seed IN (0, 1)),
      attempts_admitted INTEGER NOT NULL DEFAULT 0,
      last_attempt_key TEXT,
      lease_token TEXT,
      lease_worker_id TEXT,
      PRIMARY KEY (tenant_hash, run_id, candidate_id),
      UNIQUE (tenant_hash, run_id, canonical_url),
      FOREIGN KEY (tenant_hash, run_id) REFERENCES frontier_runs (tenant_hash, run_id)
    ) STRICT;
    CREATE INDEX IF NOT EXISTS frontier_claim_order
      ON frontier_candidates (tenant_hash, run_id, state, best_depth, canonical_url COLLATE BINARY);
    CREATE TABLE IF NOT EXISTS frontier_claims (
      tenant_hash TEXT NOT NULL,
      run_id TEXT NOT NULL,
      claim_key TEXT NOT NULL,
      candidate_id TEXT NOT NULL,
      lease_token TEXT NOT NULL,
      worker_id TEXT NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('leased', 'completed', 'unresolved')),
      resolution_reason TEXT,
      claim_binding_version INTEGER NOT NULL DEFAULT 0 CHECK (claim_binding_version IN (0, 1)),
      claim_observation_sequence INTEGER,
      PRIMARY KEY (tenant_hash, run_id, claim_key),
      UNIQUE (tenant_hash, run_id, lease_token),
      FOREIGN KEY (tenant_hash, run_id, candidate_id)
        REFERENCES frontier_candidates (tenant_hash, run_id, candidate_id)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS frontier_attempts (
      tenant_hash TEXT NOT NULL,
      run_id TEXT NOT NULL,
      attempt_key TEXT NOT NULL,
      attempt_sequence INTEGER NOT NULL,
      candidate_id TEXT NOT NULL,
      claim_key TEXT NOT NULL,
      lease_token TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('initial', 'retry', 'redirect')),
      previous_attempt_key TEXT,
      canonical_url TEXT NOT NULL,
      admitted_at_ms INTEGER NOT NULL,
      PRIMARY KEY (tenant_hash, run_id, attempt_key),
      UNIQUE (tenant_hash, run_id, attempt_sequence),
      FOREIGN KEY (tenant_hash, run_id, claim_key)
        REFERENCES frontier_claims (tenant_hash, run_id, claim_key),
      FOREIGN KEY (tenant_hash, run_id, candidate_id)
        REFERENCES frontier_candidates (tenant_hash, run_id, candidate_id)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS frontier_observations (
      tenant_hash TEXT NOT NULL,
      run_id TEXT NOT NULL,
      sequence INTEGER NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('seed', 'link')),
      parent_candidate_id TEXT,
      target_candidate_id TEXT NOT NULL,
      supplied_url TEXT NOT NULL,
      canonical_url TEXT NOT NULL,
      depth INTEGER NOT NULL,
      label TEXT,
      source_refs_json TEXT NOT NULL,
      disposition TEXT NOT NULL CHECK (disposition IN (
        'seed', 'duplicate', 'cycle', 'depth_limit', 'queued', 'retained_after_stop'
      )),
      outcome TEXT,
      PRIMARY KEY (tenant_hash, run_id, sequence),
      FOREIGN KEY (tenant_hash, run_id, parent_candidate_id)
        REFERENCES frontier_candidates (tenant_hash, run_id, candidate_id),
      FOREIGN KEY (tenant_hash, run_id, target_candidate_id)
        REFERENCES frontier_candidates (tenant_hash, run_id, candidate_id)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS frontier_completions (
      tenant_hash TEXT NOT NULL,
      run_id TEXT NOT NULL,
      completion_key TEXT NOT NULL,
      payload_hash TEXT NOT NULL,
      candidate_id TEXT NOT NULL,
      lease_token TEXT NOT NULL,
      outcome TEXT NOT NULL,
      PRIMARY KEY (tenant_hash, run_id, completion_key),
      FOREIGN KEY (tenant_hash, run_id, candidate_id)
        REFERENCES frontier_candidates (tenant_hash, run_id, candidate_id)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS frontier_stops (
      tenant_hash TEXT NOT NULL,
      run_id TEXT NOT NULL,
      reason TEXT NOT NULL,
      occurred_at_ms INTEGER NOT NULL,
      PRIMARY KEY (tenant_hash, run_id, reason),
      FOREIGN KEY (tenant_hash, run_id) REFERENCES frontier_runs (tenant_hash, run_id)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS frontier_transport_hops (
      tenant_hash TEXT NOT NULL,
      run_id TEXT NOT NULL,
      attempt_key TEXT NOT NULL,
      lease_token TEXT NOT NULL,
      state TEXT NOT NULL CHECK (state IN (
        'reserved', 'dispatch_intent', 'response_received', 'body_complete', 'known_zero', 'unknown'
      )),
      reservation_bytes INTEGER NOT NULL CHECK (reservation_bytes = ${RESERVED_DECODED_BYTES_PER_HOP}),
      decoded_bytes INTEGER,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (tenant_hash, run_id, attempt_key),
      FOREIGN KEY (tenant_hash, run_id, attempt_key)
        REFERENCES frontier_attempts (tenant_hash, run_id, attempt_key)
    ) STRICT;
    CREATE INDEX IF NOT EXISTS frontier_transport_hops_capacity
      ON frontier_transport_hops (tenant_hash, run_id, state);
    CREATE TABLE IF NOT EXISTS frontier_transport_legacy_uncertainty (
      tenant_hash TEXT NOT NULL,
      run_id TEXT NOT NULL,
      reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes = ${MAX_DECODED_BYTES_PER_RUN}),
      PRIMARY KEY (tenant_hash, run_id),
      FOREIGN KEY (tenant_hash, run_id) REFERENCES frontier_runs (tenant_hash, run_id)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS frontier_private_release (
      tenant_hash TEXT NOT NULL,
      run_id TEXT NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('open', 'sealed')),
      sealed_at_ms INTEGER,
      PRIMARY KEY (tenant_hash, run_id),
      FOREIGN KEY (tenant_hash, run_id) REFERENCES frontier_runs (tenant_hash, run_id)
    ) STRICT;
  `;
}

const FENCED_TABLES = Object.freeze([
  'frontier_tenant_policy', 'frontier_runs', 'frontier_candidates', 'frontier_claims',
  'frontier_attempts', 'frontier_observations', 'frontier_completions', 'frontier_stops',
  'frontier_transport_hops', 'frontier_transport_legacy_uncertainty', 'frontier_private_release',
]);

const WRITE_FENCE_SCHEMA = Object.freeze([
  Object.freeze({ type: 'table', name: 'frontier_write_fence', sql: `CREATE TABLE frontier_write_fence (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    protocol_version INTEGER NOT NULL CHECK (protocol_version = ${WRITE_FENCE_VERSION}),
    is_open INTEGER NOT NULL CHECK (is_open IN (0, 1))
  ) STRICT` }),
  ...FENCED_TABLES.flatMap((table) => ['INSERT', 'UPDATE', 'DELETE'].map((operation) => {
    const name = `frontier_write_fence_${table}_${operation.toLowerCase()}`;
    return Object.freeze({ type: 'trigger', name, sql: `CREATE TRIGGER ${name}
      BEFORE ${operation} ON ${table}
      WHEN (SELECT is_open FROM frontier_write_fence
        WHERE singleton = 1 AND protocol_version = ${WRITE_FENCE_VERSION}) IS NOT 1
      BEGIN SELECT RAISE(ABORT, 'frontier write fence closed'); END` });
  })),
]);

function validateWriteFence(database) {
  const objects = database.prepare(`SELECT type, name, sql FROM sqlite_master
    WHERE name GLOB 'frontier_write_fence*'`).all();
  if (objects.length === 0) return false;
  // Never silently repair a partial fence or a committed open guard. Only a
  // complete, closed fence proves that an older writer has been excluded.
  if (objects.length !== WRITE_FENCE_SCHEMA.length) fail('FRONTIER_VERSION');
  for (const expected of WRITE_FENCE_SCHEMA) {
    const actual = objects.find(({ name }) => name === expected.name);
    if (actual?.type !== expected.type || actual.sql !== expected.sql) fail('FRONTIER_VERSION');
  }
  const rows = database.prepare('SELECT singleton, protocol_version, is_open FROM frontier_write_fence').all();
  if (rows.length !== 1 || rows[0].singleton !== 1
    || rows[0].protocol_version !== WRITE_FENCE_VERSION || rows[0].is_open !== 0) fail('FRONTIER_VERSION');
  return true;
}

function installWriteFence(database) {
  for (const { sql } of WRITE_FENCE_SCHEMA) database.exec(sql);
  database.prepare(`INSERT INTO frontier_write_fence (singleton, protocol_version, is_open)
    VALUES (1, ?, 0)`).run(WRITE_FENCE_VERSION);
  if (!validateWriteFence(database)) fail('FRONTIER_VERSION');
}

function validateTenantPolicy(database, tenantHash, tenantPolicy) {
  const policyTable = database.prepare(`SELECT name FROM sqlite_master
    WHERE type = 'table' AND name = 'frontier_tenant_policy'`).get();
  if (!policyTable) fail('FRONTIER_VERSION');
  const policies = database.prepare('SELECT * FROM frontier_tenant_policy').all();
  if (policies.length !== 1 || policies[0].tenant_hash !== tenantHash
    || typeof policies[0].policy_json !== 'string'
    || policies[0].policy_hash !== digest(policies[0].policy_json)) fail('FRONTIER_VERSION');
  if (policies[0].policy_json !== tenantPolicy.json || policies[0].policy_hash !== tenantPolicy.hash) {
    fail('FRONTIER_CONFLICT');
  }
}

async function ensureDirectory(directory) {
  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const stats = await lstat(directory);
    if (stats.isSymbolicLink() || !stats.isDirectory()) fail('FRONTIER_STORAGE');
    await chmod(directory, 0o700);
  } catch (error) {
    if (error instanceof DiscoveryFrontierError) throw error;
    throw safeStorageError(error);
  }
}

function safeIntegerTime(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail('FRONTIER_STORAGE');
  return value;
}

async function openDatabase(directory, tenantHash, tenantPolicy, deadline, signal) {
  const tenantDirectory = path.join(directory, tenantHash);
  const databasePath = path.join(tenantDirectory, 'frontier.sqlite');
  while (true) {
    checkOperationSignal(signal);
    let database;
    try {
      await ensureDirectory(tenantDirectory);
      let priorStats = null;
      try {
        priorStats = await lstat(databasePath);
        if (priorStats.isSymbolicLink() || !priorStats.isFile()) fail('FRONTIER_STORAGE');
      } catch (error) {
        if (error instanceof DiscoveryFrontierError) throw error;
        if (error?.code !== 'ENOENT') throw safeStorageError(error);
      }
      checkOperationSignal(signal);
      // A DatabaseSync busy timeout blocks the event loop, which prevents the
      // caller's deadline and abort listeners from running. Retry SQLITE_BUSY
      // asynchronously instead, with this one absolute operation deadline.
      database = new DatabaseSync(databasePath, { timeout: 0 });
      const openedStats = await lstat(databasePath);
      if (openedStats.isSymbolicLink() || !openedStats.isFile()
        || (priorStats && (openedStats.dev !== priorStats.dev || openedStats.ino !== priorStats.ino))) {
        fail('FRONTIER_STORAGE');
      }
      database.exec(`
        PRAGMA journal_mode = DELETE;
        PRAGMA synchronous = FULL;
        PRAGMA secure_delete = ON;
        PRAGMA trusted_schema = OFF;
        PRAGMA foreign_keys = ON;
        PRAGMA max_page_count = ${MAX_DATABASE_PAGES};
      `);
      database.exec('BEGIN IMMEDIATE');
      try {
        // A peer may finish migration before this connection obtains the lock.
        // Read the version under the lock before choosing binding or validation.
        const version = database.prepare('PRAGMA user_version').get().user_version;
        if (![0, 1, 2, 3, 4, SCHEMA_VERSION].includes(version)) fail('FRONTIER_VERSION');
        const fenced = validateWriteFence(database);
        if (version === SCHEMA_VERSION && !fenced) fail('FRONTIER_VERSION');
        if (fenced || version === 4) validateTenantPolicy(database, tenantHash, tenantPolicy);
        else if (database.prepare(`SELECT name FROM sqlite_master
          WHERE name = 'frontier_tenant_policy'`).get()) fail('FRONTIER_VERSION');
        // An already-opening v1/v2/v3 binary can lower user_version after our
        // commit. Its additive DDL leaves this validated fence and policy intact.
        // Treat those records as authoritative; do not rebind or rerun a legacy
        // migration based on the lowered header. Its later DML remains fenced.
        database.exec(schemaSql());
        const claimColumns = new Set(database.prepare('PRAGMA table_info(frontier_claims)').all()
          .map((column) => column.name));
        if (!fenced && version < 4) {
          if (!claimColumns.has('claim_binding_version')) {
            database.exec(`ALTER TABLE frontier_claims ADD COLUMN claim_binding_version INTEGER NOT NULL DEFAULT 0
              CHECK (claim_binding_version IN (0, 1))`);
          }
          if (!claimColumns.has('claim_observation_sequence')) {
            database.exec('ALTER TABLE frontier_claims ADD COLUMN claim_observation_sequence INTEGER');
          }
        }
        const migratedClaimColumns = new Set(database.prepare('PRAGMA table_info(frontier_claims)').all()
          .map((column) => column.name));
        if (!migratedClaimColumns.has('claim_binding_version')
          || !migratedClaimColumns.has('claim_observation_sequence')) fail('FRONTIER_VERSION');
        if (!fenced && version === 1) {
          // V1 recorded planner admissions but had no durable transport or body
          // accounting. Any such admission may have reached the network and
          // consumed decoded bytes. Preserve that uncertainty as a full-run
          // reservation rather than treating the new ledger as fresh capacity.
          database.prepare(`INSERT OR IGNORE INTO frontier_transport_legacy_uncertainty
            (tenant_hash, run_id, reserved_bytes)
            SELECT tenant_hash, run_id, ${MAX_DECODED_BYTES_PER_RUN}
            FROM frontier_attempts GROUP BY tenant_hash, run_id`).run();
        }
        if (!fenced && version < 4) {
          // Bind once in the same atomic migration. Retain every historical
          // row even when its exposure already exceeds the selected policy.
          database.prepare(`INSERT INTO frontier_tenant_policy (tenant_hash, policy_json, policy_hash)
            VALUES (?, ?, ?)`).run(tenantHash, tenantPolicy.json, tenantPolicy.hash);
        }
        if (!fenced) installWriteFence(database);
        if (version !== SCHEMA_VERSION) database.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
        checkOperationSignal(signal);
        database.exec('COMMIT');
      } catch (error) {
        try { database.exec('ROLLBACK'); } catch { /* Keep the original migration failure. */ }
        throw error;
      }
      await chmod(databasePath, 0o600);
      const pageSize = database.prepare('PRAGMA page_size').get().page_size;
      const pageCount = database.prepare('PRAGMA page_count').get().page_count;
      if (!Number.isSafeInteger(pageSize) || !Number.isSafeInteger(pageCount)
        || pageSize * pageCount > MAX_DATABASE_BYTES) fail('FRONTIER_STORAGE_LIMIT');
      return database;
    } catch (error) {
      try { database?.close(); } catch { /* Close failures do not replace the bounded error. */ }
      if (error instanceof DiscoveryFrontierError) throw error;
      if (!isBusy(error)) throw safeStorageError(error);
      await retryDelay(deadline, signal);
    }
  }
}

function pageBytes(database) {
  const size = database.prepare('PRAGMA page_size').get().page_size;
  const count = database.prepare('PRAGMA page_count').get().page_count;
  if (!Number.isSafeInteger(size) || !Number.isSafeInteger(count)) fail('FRONTIER_STORAGE');
  return size * count;
}

async function transaction(database, callback, deadline, signal, tenantHash, tenantPolicy) {
  let open = false;
  try {
    while (true) {
      checkOperationSignal(signal);
      try {
        database.exec('BEGIN IMMEDIATE');
        break;
      } catch (error) {
        if (!isBusy(error)) throw error;
        await retryDelay(deadline, signal);
      }
    }
    open = true;
    if (!validateWriteFence(database)) fail('FRONTIER_VERSION');
    validateTenantPolicy(database, tenantHash, tenantPolicy);
    const version = database.prepare('PRAGMA user_version').get().user_version;
    if (![0, 1, 2, 3, 4, SCHEMA_VERSION].includes(version)) fail('FRONTIER_VERSION');
    // Only the current writer sees this uncommitted open guard. SQLite excludes
    // every other writer until it is closed and committed, or rolled back.
    if (version !== SCHEMA_VERSION) database.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
    const opened = database.prepare(`UPDATE frontier_write_fence SET is_open = 1
      WHERE singleton = 1 AND protocol_version = ? AND is_open = 0`).run(WRITE_FENCE_VERSION);
    if (opened.changes !== 1) fail('FRONTIER_VERSION');
    const result = callback(database);
    if (pageBytes(database) > MAX_DATABASE_BYTES) fail('FRONTIER_STORAGE_LIMIT');
    const closed = database.prepare(`UPDATE frontier_write_fence SET is_open = 0
      WHERE singleton = 1 AND protocol_version = ? AND is_open = 1`).run(WRITE_FENCE_VERSION);
    if (closed.changes !== 1) fail('FRONTIER_VERSION');
    while (true) {
      checkOperationSignal(signal);
      try {
        database.exec('COMMIT');
        break;
      } catch (error) {
        if (!isBusy(error)) throw error;
        await retryDelay(deadline, signal);
      }
    }
    open = false;
    return result;
  } catch (error) {
    if (open) {
      try { database.exec('ROLLBACK'); } catch { /* SQLite rolls back when the connection closes. */ }
    }
    throw safeStorageError(error);
  }
}

function getRun(database, tenantHash, runId) {
  const run = database.prepare(`SELECT * FROM frontier_runs WHERE tenant_hash = ? AND run_id = ?`)
    .get(tenantHash, runId);
  if (!run) fail('FRONTIER_NOT_FOUND');
  return run;
}

function recordStop(database, tenantHash, runId, reason, nowMs, halt = GLOBAL_HALT_REASONS.has(reason)) {
  if (!STOP_REASONS.has(reason)) fail('FRONTIER_STORAGE');
  database.prepare(`INSERT OR IGNORE INTO frontier_stops (tenant_hash, run_id, reason, occurred_at_ms)
    VALUES (?, ?, ?, ?)`).run(tenantHash, runId, reason, nowMs);
  if (halt) {
    database.prepare(`UPDATE frontier_runs SET status = CASE WHEN status = 'active' THEN 'halted' ELSE status END,
      halt_reason = CASE WHEN status = 'active' THEN ? ELSE halt_reason END
      WHERE tenant_hash = ? AND run_id = ?`).run(reason, tenantHash, runId);
  }
}

function advanceClock(database, tenantHash, run, readClock) {
  let current;
  try { current = safeIntegerTime(readClock()); } catch { fail('FRONTIER_STORAGE'); }
  const nowMs = Math.max(run.last_clock_ms, current);
  database.prepare(`UPDATE frontier_runs SET last_clock_ms = ? WHERE tenant_hash = ? AND run_id = ?`)
    .run(nowMs, tenantHash, run.run_id);
  const updated = { ...run, last_clock_ms: nowMs };
  if (nowMs >= run.deadline_at_ms) {
    recordStop(database, tenantHash, run.run_id, 'deadline', nowMs, true);
    if (run.status === 'active') {
      updated.status = 'halted';
      updated.halt_reason = 'deadline';
    }
  }
  return updated;
}

function candidateRow(database, tenantHash, runId, id) {
  return database.prepare(`SELECT * FROM frontier_candidates
    WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`).get(tenantHash, runId, id);
}

function hasPath(database, tenantHash, runId, startId, targetId) {
  if (startId === targetId) return true;
  const rows = database.prepare(`SELECT parent_candidate_id, target_candidate_id
    FROM frontier_observations WHERE tenant_hash = ? AND run_id = ? AND kind = 'link'`)
    .all(tenantHash, runId);
  const edges = new Map();
  for (const row of rows) {
    const children = edges.get(row.parent_candidate_id) ?? [];
    children.push(row.target_candidate_id);
    edges.set(row.parent_candidate_id, children);
  }
  const pending = [startId];
  const visited = new Set();
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === targetId) return true;
    if (visited.has(current)) continue;
    visited.add(current);
    for (const child of edges.get(current) ?? []) pending.push(child);
  }
  return false;
}

function insertCandidate(database, tenantHash, runId, canonicalUrl, depth, isSeed, maxDepth) {
  const id = candidateId(tenantHash, runId, canonicalUrl);
  let candidate = database.prepare(`SELECT * FROM frontier_candidates
    WHERE tenant_hash = ? AND run_id = ? AND canonical_url = ?`).get(tenantHash, runId, canonicalUrl);
  const existed = Boolean(candidate);
  if (!candidate) {
    const state = depth > maxDepth ? 'depth_limited' : 'queued';
    database.prepare(`INSERT INTO frontier_candidates
      (tenant_hash, run_id, candidate_id, canonical_url, best_depth, state, is_seed)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).run(tenantHash, runId, id, canonicalUrl, depth, state, isSeed ? 1 : 0);
    candidate = candidateRow(database, tenantHash, runId, id);
  } else {
    const bestDepth = Math.min(candidate.best_depth, depth);
    const nextState = candidate.state === 'depth_limited' && bestDepth <= maxDepth ? 'queued' : candidate.state;
    database.prepare(`UPDATE frontier_candidates SET best_depth = ?, is_seed = ? OR is_seed,
      state = ? WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
      .run(bestDepth, isSeed ? 1 : 0, nextState, tenantHash, runId, id);
    candidate = candidateRow(database, tenantHash, runId, id);
  }
  return { candidate, existed };
}

function insertObservation(database, tenantHash, run, { kind, parentCandidateId = null, suppliedUrl,
  canonicalUrl, depth, label = null, sourceRefs, outcome = null }) {
  const { candidate, existed } = insertCandidate(database, tenantHash, run.run_id, canonicalUrl,
    depth, kind === 'seed', run.max_depth);
  let disposition;
  if (kind === 'seed') {
    disposition = existed ? 'duplicate' : 'seed';
  } else if (hasPath(database, tenantHash, run.run_id, candidate.candidate_id, parentCandidateId)) {
    disposition = 'cycle';
  } else if (depth > run.max_depth) {
    disposition = 'depth_limit';
  } else if (existed) {
    disposition = 'duplicate';
  } else if (run.status !== 'active') {
    disposition = 'retained_after_stop';
  } else {
    disposition = 'queued';
  }
  if (disposition === 'depth_limit') {
    recordStop(database, tenantHash, run.run_id, 'depth_limit', run.last_clock_ms, false);
  }
  const currentSequence = database.prepare(`SELECT next_observation_sequence FROM frontier_runs
    WHERE tenant_hash = ? AND run_id = ?`).get(tenantHash, run.run_id).next_observation_sequence;
  database.prepare(`INSERT INTO frontier_observations
    (tenant_hash, run_id, sequence, kind, parent_candidate_id, target_candidate_id, supplied_url,
     canonical_url, depth, label, source_refs_json, disposition, outcome)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(tenantHash, run.run_id, currentSequence, kind, parentCandidateId, candidate.candidate_id,
      suppliedUrl, canonicalUrl, depth, label, stableJson(sourceRefs), disposition, outcome);
  database.prepare(`UPDATE frontier_runs SET next_observation_sequence = ?
    WHERE tenant_hash = ? AND run_id = ?`).run(currentSequence + 1, tenantHash, run.run_id);
  return { candidate, disposition };
}

function tenantCapacityInTransaction(database, tenantHash, limits) {
  // Count a lease once across redirects, using separate SQL tuple columns.
  // Completion/unresolved status cannot release an uncertain transport lease.
  const inFlightLeases = database.prepare(`SELECT COUNT(*) AS count FROM (
    SELECT run_id, lease_token FROM frontier_claims WHERE tenant_hash = ? AND state = 'leased'
    UNION
    SELECT run_id, lease_token FROM frontier_transport_hops WHERE tenant_hash = ?
      AND state IN ('reserved', 'dispatch_intent', 'response_received', 'unknown')
    UNION
    SELECT a.run_id, a.lease_token FROM frontier_attempts AS a
      LEFT JOIN frontier_transport_hops AS h ON h.tenant_hash = a.tenant_hash
        AND h.run_id = a.run_id AND h.attempt_key = a.attempt_key
      WHERE a.tenant_hash = ? AND h.attempt_key IS NULL
  )`).get(tenantHash, tenantHash, tenantHash).count;
  const transport = database.prepare(`SELECT COUNT(*) AS count, COALESCE(SUM(reservation_bytes), 0) AS bytes
    FROM frontier_transport_hops WHERE tenant_hash = ?
      AND state IN ('reserved', 'dispatch_intent', 'response_received', 'unknown')`).get(tenantHash);
  const legacy = database.prepare(`SELECT COUNT(*) AS count, COALESCE(SUM(reserved_bytes), 0) AS bytes
    FROM frontier_transport_legacy_uncertainty WHERE tenant_hash = ?`).get(tenantHash);
  const untrackedAttempts = database.prepare(`SELECT COUNT(*) AS count FROM frontier_attempts AS a
    LEFT JOIN frontier_transport_hops AS h ON h.tenant_hash = a.tenant_hash
      AND h.run_id = a.run_id AND h.attempt_key = a.attempt_key
    WHERE a.tenant_hash = ? AND h.attempt_key IS NULL AND NOT EXISTS (
      SELECT 1 FROM frontier_transport_legacy_uncertainty AS l
      WHERE l.tenant_hash = a.tenant_hash AND l.run_id = a.run_id
    )`).get(tenantHash).count;
  const reservedBytes = transport.bytes + legacy.bytes + untrackedAttempts * RESERVED_DECODED_BYTES_PER_HOP;
  if (![inFlightLeases, transport.count, transport.bytes, legacy.count, legacy.bytes,
    untrackedAttempts, reservedBytes].every((value) => Number.isSafeInteger(value) && value >= 0)) {
    fail('FRONTIER_STORAGE');
  }
  return deepFreeze({ limits, inFlightLeases, reservedBytes,
    availableInFlightLeases: Math.max(0, limits.maxInFlightLeases - inFlightLeases),
    availableReservedBytes: Math.max(0, limits.maxReservedDecodedBytes - reservedBytes),
    unsettledTransportHops: transport.count, untrackedAttempts, legacyUnknownRuns: legacy.count });
}

function admitAttemptInTransaction(database, tenantHash, runIdValue, run, input, tenantLimits) {
  const previous = database.prepare(`SELECT * FROM frontier_attempts
    WHERE tenant_hash = ? AND run_id = ? AND attempt_key = ?`)
    .get(tenantHash, runIdValue, input.attemptKey);
  if (previous) {
    const same = previous.lease_token === input.leaseToken
      && previous.kind === input.kind
      && previous.previous_attempt_key === input.previousAttemptKey
      && previous.canonical_url === input.canonicalUrl;
    if (!same) fail('FRONTIER_CONFLICT');
    return deepFreeze({ state: 'already_admitted', attemptKey: previous.attempt_key,
      sequence: previous.attempt_sequence, admittedAtMs: previous.admitted_at_ms });
  }
  const claim = getClaimByToken(database, tenantHash, runIdValue, input.leaseToken);
  const candidate = claim ? candidateRow(database, tenantHash, runIdValue, claim.candidate_id) : null;
  if (!claim || claim.state !== 'leased' || !candidate || candidate.state !== 'leased'
    || candidate.lease_token !== input.leaseToken) fail('FRONTIER_STALE_LEASE');
  if (run.status !== 'active') return deepFreeze({ state: 'denied', reason: run.halt_reason ?? 'frontier_exhausted' });
  if (run.attempts_admitted >= run.max_attempts) {
    recordStop(database, tenantHash, runIdValue, 'attempt_limit', run.last_clock_ms, true);
    return deepFreeze({ state: 'denied', reason: 'attempt_limit' });
  }
  const latest = database.prepare(`SELECT * FROM frontier_attempts WHERE tenant_hash = ? AND run_id = ?
    AND candidate_id = ? ORDER BY attempt_sequence DESC LIMIT 1`)
    .get(tenantHash, runIdValue, candidate.candidate_id);
  if (input.kind === 'initial') {
    if (latest || input.canonicalUrl !== candidate.canonical_url) fail('FRONTIER_CONFLICT');
  } else {
    if (!latest || latest.attempt_key !== input.previousAttemptKey || latest.lease_token !== input.leaseToken) {
      fail('FRONTIER_CONFLICT');
    }
    if (input.kind === 'retry' && latest.canonical_url !== input.canonicalUrl) fail('FRONTIER_CONFLICT');
    if (input.kind === 'redirect') {
      if (latest.canonical_url === input.canonicalUrl) fail('FRONTIER_CONFLICT');
      const seen = database.prepare(`SELECT 1 AS found FROM frontier_attempts
        WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ? AND canonical_url = ? LIMIT 1`)
        .get(tenantHash, runIdValue, candidate.candidate_id, input.canonicalUrl);
      if (seen) fail('FRONTIER_CONFLICT');
    }
  }
  // A v1 uncertainty row already reserves this run's entire transport budget.
  // New raw admissions cannot hide inside that hold under a larger tenant
  // policy. Exact historical replay was handled before any admission checks.
  const legacyHold = database.prepare(`SELECT 1 AS found FROM frontier_transport_legacy_uncertainty
    WHERE tenant_hash = ? AND run_id = ?`).get(tenantHash, runIdValue);
  if (legacyHold) return deepFreeze({ state: 'denied', reason: 'decoded_budget' });
  const tenantCapacity = tenantCapacityInTransaction(database, tenantHash, tenantLimits);
  // This lease is already counted. Over-limit migrated state permits history
  // and settlement, but cannot admit more work for an existing lease either.
  if (tenantCapacity.inFlightLeases > tenantLimits.maxInFlightLeases) {
    return deepFreeze({ state: 'denied', reason: 'tenant_in_flight_limit' });
  }
  if (tenantCapacity.availableReservedBytes < RESERVED_DECODED_BYTES_PER_HOP) {
    return deepFreeze({ state: 'denied', reason: 'tenant_decoded_budget' });
  }
  const sequence = run.attempts_admitted + 1;
  database.prepare(`INSERT INTO frontier_attempts
    (tenant_hash, run_id, attempt_key, attempt_sequence, candidate_id, claim_key, lease_token,
     kind, previous_attempt_key, canonical_url, admitted_at_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(tenantHash, runIdValue, input.attemptKey, sequence, candidate.candidate_id, claim.claim_key,
      input.leaseToken, input.kind, input.previousAttemptKey, input.canonicalUrl, run.last_clock_ms);
  database.prepare(`UPDATE frontier_runs SET attempts_admitted = ?
    WHERE tenant_hash = ? AND run_id = ?`).run(sequence, tenantHash, runIdValue);
  database.prepare(`UPDATE frontier_candidates SET attempts_admitted = attempts_admitted + 1,
    last_attempt_key = ? WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
    .run(input.attemptKey, tenantHash, runIdValue, candidate.candidate_id);
  if (sequence >= run.max_attempts) {
    recordStop(database, tenantHash, runIdValue, 'attempt_limit', run.last_clock_ms, true);
  }
  return deepFreeze({ state: 'admitted', attemptKey: input.attemptKey,
    sequence, admittedAtMs: run.last_clock_ms, stopAfterThisAdmission: sequence >= run.max_attempts });
}

function safeJsonParse(value) {
  try {
    const parsed = JSON.parse(value);
    if (typeof parsed !== 'object' || parsed === null || !Array.isArray(parsed)) fail('FRONTIER_STORAGE');
    return parsed;
  } catch (error) {
    if (error instanceof DiscoveryFrontierError) throw error;
    fail('FRONTIER_STORAGE');
  }
}

function snapshotInTransaction(database, tenantHash, runId) {
  const run = getRun(database, tenantHash, runId);
  const candidateRows = database.prepare(`SELECT * FROM frontier_candidates
    WHERE tenant_hash = ? AND run_id = ? ORDER BY best_depth, canonical_url COLLATE BINARY, candidate_id COLLATE BINARY`)
    .all(tenantHash, runId);
  const observationRows = database.prepare(`SELECT * FROM frontier_observations
    WHERE tenant_hash = ? AND run_id = ?`).all(tenantHash, runId);
  const attemptRows = database.prepare(`SELECT attempt_key, attempt_sequence, candidate_id, kind,
    previous_attempt_key, canonical_url, admitted_at_ms FROM frontier_attempts
    WHERE tenant_hash = ? AND run_id = ? ORDER BY attempt_sequence`).all(tenantHash, runId);
  const stopRows = database.prepare(`SELECT reason, occurred_at_ms FROM frontier_stops
    WHERE tenant_hash = ? AND run_id = ? ORDER BY reason COLLATE BINARY`).all(tenantHash, runId);
  const completionRows = database.prepare(`SELECT candidate_id, outcome FROM frontier_completions
    WHERE tenant_hash = ? AND run_id = ?`).all(tenantHash, runId);
  const completionByCandidate = new Map(completionRows.map((row) => [row.candidate_id, row.outcome]));
  const observations = observationRows.map((row) => ({
    kind: row.kind,
    parentCandidateId: row.parent_candidate_id,
    targetCandidateId: row.target_candidate_id,
    suppliedUrl: row.supplied_url,
    canonicalUrl: row.canonical_url,
    depth: row.depth,
    ...(row.label === null ? {} : { untrustedLabel: row.label }),
    sourceRefs: safeJsonParse(row.source_refs_json),
    disposition: row.disposition,
    ...(row.outcome === null ? {} : { outcome: row.outcome }),
    sourceAuthority: 'not_evaluated',
  }));
  observations.sort((left, right) => stableCompare(
    stableJson([left.kind, left.parentCandidateId ?? '', left.canonicalUrl, left.suppliedUrl,
      stableJson(left.sourceRefs), left.untrustedLabel ?? '', left.disposition, left.outcome ?? '']),
    stableJson([right.kind, right.parentCandidateId ?? '', right.canonicalUrl, right.suppliedUrl,
      stableJson(right.sourceRefs), right.untrustedLabel ?? '', right.disposition, right.outcome ?? '']),
  ));
  const allReferences = observations.flatMap((item) => item.sourceRefs);
  const refsByCandidate = new Map();
  for (const observation of observations) {
    const references = refsByCandidate.get(observation.targetCandidateId) ?? [];
    references.push(...observation.sourceRefs);
    refsByCandidate.set(observation.targetCandidateId, references);
  }
  const candidates = candidateRows.map((row) => {
    const references = refsByCandidate.get(row.candidate_id) ?? [];
    const uniqueReferences = [...new Map(references.map((reference) => [stableJson(reference), reference])).values()];
    uniqueReferences.sort((left, right) => stableCompare(stableJson(left), stableJson(right)));
    const candidateClaim = database.prepare(`SELECT claim_key, worker_id, state, resolution_reason
      FROM frontier_claims WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
      .get(tenantHash, runId, row.candidate_id);
    return {
      candidateId: row.candidate_id,
      canonicalUrl: row.canonical_url,
      depth: row.best_depth,
      state: row.state,
      seed: row.is_seed === 1,
      admittedAttemptCount: row.attempts_admitted,
      ...(completionByCandidate.has(row.candidate_id)
        ? { completionOutcome: completionByCandidate.get(row.candidate_id) } : {}),
      ...(candidateClaim?.state === 'leased'
        ? { activeLease: { claimKey: candidateClaim.claim_key, workerId: candidateClaim.worker_id } } : {}),
      ...(candidateClaim?.state === 'unresolved' ? { unresolvedReason: candidateClaim.resolution_reason } : {}),
      sourceRefs: uniqueReferences,
      sourceAuthority: 'not_evaluated',
    };
  });
  const refsByHash = new Map();
  for (const reference of allReferences) {
    const evidenceIds = refsByHash.get(reference.contentHash) ?? new Set();
    evidenceIds.add(reference.evidenceId);
    refsByHash.set(reference.contentHash, evidenceIds);
  }
  const duplicateContentGroups = [...refsByHash.entries()]
    .filter(([, ids]) => ids.size > 1)
    .map(([contentHash, ids]) => ({
      contentHash,
      evidenceIds: [...ids].sort(stableCompare),
      independence: 'unknown',
    }))
    .sort((left, right) => stableCompare(left.contentHash, right.contentHash));
  const stops = stopRows.map((row) => ({ reason: row.reason, occurredAtMs: row.occurred_at_ms }));
  const settings = JSON.parse(run.config_json).limits;
  const terminalStop = run.halt_reason
    ?? (run.status === 'exhausted' ? (stops[stops.length - 1]?.reason ?? null) : null);
  return deepFreeze({
    schema: 'ei-private-bounded-frontier/v1',
    runId,
    createdAtMs: run.created_at_ms,
    deadlineAtMs: run.deadline_at_ms,
    lastObservedClockMs: run.last_clock_ms,
    state: run.status,
    stopReason: terminalStop,
    stopReasons: stops,
    limits: settings,
    counters: {
      seedInputs: observations.filter((item) => item.kind === 'seed').length,
      uniqueCandidates: candidates.length,
      transportAttemptAdmissions: run.attempts_admitted,
      inFlightLeases: candidates.filter((candidate) => candidate.state === 'leased').length,
    },
    candidates,
    observations,
    attempts: attemptRows.map((row) => ({
      attemptKey: row.attempt_key,
      sequence: row.attempt_sequence,
      candidateId: row.candidate_id,
      kind: row.kind,
      previousAttemptKey: row.previous_attempt_key,
      canonicalUrl: row.canonical_url,
      admittedAtMs: row.admitted_at_ms,
    })),
    duplicateContentGroups,
    sourceAuthority: 'not_evaluated',
    independentCorroboration: 'not_evaluated',
    usageStatus: 'unknown',
    budgetAuthority: 'not_evaluated',
    transportDispatch: 'not_implemented',
    readiness: 'blocked_no_transport_adapter',
  });
}

function expireOrExhaust(database, tenantHash, run, readClock) {
  const updated = advanceClock(database, tenantHash, run, readClock);
  if (updated.status !== 'active') return updated;
  if (updated.attempts_admitted >= updated.max_attempts) {
    recordStop(database, tenantHash, updated.run_id, 'attempt_limit', updated.last_clock_ms, true);
    return { ...updated, status: 'halted', halt_reason: 'attempt_limit' };
  }
  const counts = database.prepare(`SELECT
    SUM(CASE WHEN state = 'queued' THEN 1 ELSE 0 END) AS queued,
    SUM(CASE WHEN state = 'leased' THEN 1 ELSE 0 END) AS leased,
    SUM(CASE WHEN state = 'depth_limited' THEN 1 ELSE 0 END) AS depth_limited
    FROM frontier_candidates WHERE tenant_hash = ? AND run_id = ?`).get(tenantHash, updated.run_id);
  if ((counts.queued ?? 0) === 0 && (counts.leased ?? 0) === 0) {
    const reason = (counts.depth_limited ?? 0) > 0 ? 'depth_limit' : 'frontier_exhausted';
    recordStop(database, tenantHash, updated.run_id, reason, updated.last_clock_ms, false);
    database.prepare(`UPDATE frontier_runs SET status = 'exhausted', halt_reason = ?
      WHERE tenant_hash = ? AND run_id = ?`).run(reason, tenantHash, updated.run_id);
    return { ...updated, status: 'exhausted', halt_reason: reason };
  }
  return updated;
}

function getClaimByToken(database, tenantHash, runId, leaseToken) {
  return database.prepare(`SELECT * FROM frontier_claims
    WHERE tenant_hash = ? AND run_id = ? AND lease_token = ?`).get(tenantHash, runId, leaseToken);
}

function claimResult(database, tenantHash, runId, claim, replayed) {
  const candidate = candidateRow(database, tenantHash, runId, claim.candidate_id);
  return deepFreeze({
    state: claim.state === 'leased' ? 'claimed' : claim.state,
    replayed,
    claimKey: claim.claim_key,
    leaseToken: claim.lease_token,
    workerId: claim.worker_id,
    candidate: {
      candidateId: candidate.candidate_id,
      canonicalUrl: candidate.canonical_url,
      depth: candidate.best_depth,
      admittedAttemptCount: candidate.attempts_admitted,
    },
  });
}

function candidateClaimBindingInTransaction(database, tenantHash, runId, candidate, claim) {
  if (!candidate || !claim || candidate.candidate_id !== claim.candidate_id
    || candidate.canonical_url !== normalizeUrl(candidate.canonical_url).canonicalUrl
    || candidate.candidate_id !== candidateId(tenantHash, runId, candidate.canonical_url)
    || !validId(claim.claim_key, 128) || !validId(claim.worker_id, 96) || !validId(claim.lease_token, 64)
    || !['leased', 'completed', 'unresolved'].includes(claim.state)
    || ![0, CLAIM_BINDING_VERSION].includes(claim.claim_binding_version)) fail('FRONTIER_STORAGE');

  let claimedCandidate = null;
  if (claim.claim_binding_version === 0) {
    if (claim.claim_observation_sequence !== null) fail('FRONTIER_STORAGE');
  } else {
    const runRow = getRun(database, tenantHash, runId);
    const cutoff = claim.claim_observation_sequence;
    const maxSequence = runRow.next_observation_sequence - 1;
    if (!Number.isSafeInteger(maxSequence) || maxSequence < 1
      || !Number.isSafeInteger(cutoff) || cutoff < 1 || cutoff > maxSequence
      || cutoff > MAX_SEEDS + MAX_ATTEMPT_ADMISSIONS * MAX_SUGGESTIONS) fail('FRONTIER_STORAGE');
    const prefixStats = database.prepare(`SELECT COUNT(*) AS count, MIN(sequence) AS first_sequence,
      MAX(sequence) AS last_sequence FROM frontier_observations
      WHERE tenant_hash = ? AND run_id = ? AND sequence <= ?`).get(tenantHash, runId, cutoff);
    if (prefixStats.count !== cutoff || prefixStats.first_sequence !== 1 || prefixStats.last_sequence !== cutoff) {
      fail('FRONTIER_STORAGE');
    }
    const rows = database.prepare(`SELECT sequence, kind, parent_candidate_id, supplied_url, canonical_url,
      depth, label, disposition, outcome, source_refs_json
      FROM frontier_observations WHERE tenant_hash = ? AND run_id = ? AND target_candidate_id = ?
        AND sequence <= ? ORDER BY sequence`).all(tenantHash, runId, candidate.candidate_id, cutoff);
    if (rows.length === 0 || rows.some((row) => !['seed', 'link'].includes(row.kind)
      || !Number.isSafeInteger(row.depth) || row.depth < 0
      || normalizeUrl(row.supplied_url).canonicalUrl !== row.canonical_url
      || row.canonical_url !== candidate.canonical_url)) fail('FRONTIER_STORAGE');
    const allReferences = [];
    for (const row of rows) {
      allReferences.push(...normalizeReferences(safeJsonParse(row.source_refs_json), row.supplied_url, { required: false }));
    }
    const uniqueReferences = [...new Map(allReferences.map((reference) => [stableJson(reference), reference])).values()];
    uniqueReferences.sort((left, right) => stableCompare(stableJson(left), stableJson(right)));
    const sourceObservations = [...rows].sort((left, right) => stableCompare(
      stableJson([left.kind, left.parent_candidate_id ?? '', left.canonical_url, left.supplied_url,
        stableJson(normalizeReferences(safeJsonParse(left.source_refs_json), left.supplied_url, { required: false })),
        left.label ?? '', left.disposition, left.outcome ?? '']),
      stableJson([right.kind, right.parent_candidate_id ?? '', right.canonical_url, right.supplied_url,
        stableJson(normalizeReferences(safeJsonParse(right.source_refs_json), right.supplied_url, { required: false })),
        right.label ?? '', right.disposition, right.outcome ?? '']),
    ));
    claimedCandidate = {
      candidateId: candidate.candidate_id,
      canonicalUrl: candidate.canonical_url,
      depth: Math.min(...rows.map((row) => row.depth)),
      seed: rows.some((row) => row.kind === 'seed'),
      sourceRefs: uniqueReferences,
      suppliedUrl: sourceObservations[0].supplied_url,
    };
  }

  const completionRows = database.prepare(`SELECT completion_key, payload_hash, candidate_id, lease_token, outcome
    FROM frontier_completions WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
    .all(tenantHash, runId, candidate.candidate_id);
  if (completionRows.length > 1) fail('FRONTIER_STORAGE');
  const completionRow = completionRows[0] ?? null;
  const expectedCandidateState = claim.state === 'leased' ? 'leased' : claim.state;
  if (candidate.state !== expectedCandidateState
    || (claim.state === 'leased' && candidate.lease_token !== claim.lease_token)
    || (claim.state !== 'leased' && candidate.lease_token !== null)) fail('FRONTIER_STORAGE');
  let completion = null;
  if (claim.state === 'completed') {
    if (!completionRow || completionRow.candidate_id !== claim.candidate_id
      || completionRow.lease_token !== claim.lease_token
      || !validId(completionRow.completion_key, 128) || !HEX_SHA256.test(completionRow.payload_hash)
      || !['links_observed', 'no_links', 'failed', 'access_restricted'].includes(completionRow.outcome)) {
      fail('FRONTIER_STORAGE');
    }
    completion = {
      completionKey: completionRow.completion_key,
      outcome: completionRow.outcome,
      payloadHash: completionRow.payload_hash,
    };
  } else if (completionRow) {
    fail('FRONTIER_STORAGE');
  }
  return deepFreeze({
    bindingVersion: claim.claim_binding_version,
    candidate: claimedCandidate,
    claim: {
      claimKey: claim.claim_key,
      workerId: claim.worker_id,
      leaseToken: claim.lease_token,
      candidateId: claim.candidate_id,
      state: claim.state,
    },
    completion,
  });
}

function appendStopSnapshot(database, tenantHash, runId, reason, nowMs, halt) {
  recordStop(database, tenantHash, runId, reason, nowMs, halt);
}

export function createDiscoveryFrontierStore(options) {
  const config = ownRecord(options, new Set(['directory', 'resolveTenant', 'now', 'lockTimeoutMs', 'tenantLimits']));
  if (!config || !validText(config.directory, 4_096) || !path.isAbsolute(config.directory)
    || typeof config.resolveTenant !== 'function'
    || (config.now !== undefined && typeof config.now !== 'function')) fail();
  const lockTimeoutMs = config.lockTimeoutMs ?? 5_000;
  if (!Number.isSafeInteger(lockTimeoutMs) || lockTimeoutMs < 1 || lockTimeoutMs > MAX_SQLITE_TIMEOUT_MS) fail();
  const directory = path.resolve(config.directory);
  const now = config.now ?? Date.now;
  const tenantLimits = normalizeTenantLimits(config.tenantLimits);
  const tenantPolicyJson = stableJson({ schema: 'ei-private-tenant-admission/v1', limits: tenantLimits });
  const tenantPolicy = Object.freeze({ json: tenantPolicyJson, hash: digest(tenantPolicyJson) });
  const tenantScopes = new WeakMap();
  let closed = false;

  function assertOpen() {
    if (closed) fail('FRONTIER_STORAGE');
  }

  async function withScope(scope, operation, signal) {
    assertOpen();
    let scopeInfo;
    try { scopeInfo = tenantScopes.get(scope); } catch { scopeInfo = undefined; }
    if (!scopeInfo) fail('FRONTIER_DENIED');
    checkOperationSignal(signal);
    const deadline = performance.now() + lockTimeoutMs;
    const database = await openDatabase(directory, scopeInfo.tenantHash, tenantPolicy, deadline, signal);
    try {
      assertOpen();
      checkOperationSignal(signal);
      return await transaction(database, (db) => operation(db, scopeInfo), deadline, signal,
        scopeInfo.tenantHash, tenantPolicy);
    } catch (error) {
      throw safeStorageError(error);
    } finally {
      try { database.close(); } catch { /* The public result does not expose driver details. */ }
    }
  }

  async function scopeForAuthenticatedRequest(request) {
    assertOpen();
    let tenantId;
    try { tenantId = await config.resolveTenant(request); } catch { fail('FRONTIER_DENIED'); }
    if (!validText(tenantId, 256)) fail('FRONTIER_DENIED');
    const tenantHash = digest(`event-intelligence:tenant:v1:${tenantId}`);
    const scope = Object.freeze(Object.create(null));
    tenantScopes.set(scope, { tenantHash });
    return scope;
  }

  async function createRun(scope, value, signal) {
    const input = normalizeRunInput(value);
    return withScope(scope, (database, { tenantHash }) => {
      const prior = database.prepare(`SELECT config_hash FROM frontier_runs
        WHERE tenant_hash = ? AND run_id = ?`).get(tenantHash, input.runId);
      if (prior) {
        if (prior.config_hash !== input.configHash) fail('FRONTIER_CONFLICT');
        const run = getRun(database, tenantHash, input.runId);
        expireOrExhaust(database, tenantHash, run, now);
        return snapshotInTransaction(database, tenantHash, input.runId);
      }
      const storedCount = database.prepare(`SELECT COUNT(*) AS count FROM frontier_runs WHERE tenant_hash = ?`)
        .get(tenantHash).count;
      if (storedCount >= MAX_RUNS_PER_TENANT) fail('FRONTIER_STORAGE_LIMIT');
      let clockNow;
      try { clockNow = safeIntegerTime(now()); } catch { fail('FRONTIER_STORAGE'); }
      const deadline = clockNow + input.limits.durationMs;
      if (!Number.isSafeInteger(deadline)) fail('FRONTIER_INVALID_INPUT');
      database.prepare(`INSERT INTO frontier_runs
        (tenant_hash, run_id, config_hash, config_json, created_at_ms, deadline_at_ms, last_clock_ms,
         max_depth, max_attempts, max_in_flight, duration_ms, max_suggestions, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`)
        .run(tenantHash, input.runId, input.configHash, input.configJson, clockNow, deadline, clockNow,
          input.limits.maxDepth, input.limits.maxTransportAttemptAdmissions, input.limits.maxInFlightLeases,
          input.limits.durationMs, input.limits.maxSuggestionsPerCompletion);
      database.prepare(`INSERT INTO frontier_private_release
        (tenant_hash, run_id, state, sealed_at_ms) VALUES (?, ?, 'open', NULL)`)
        .run(tenantHash, input.runId);
      const run = getRun(database, tenantHash, input.runId);
      for (const seed of input.seeds) {
        insertObservation(database, tenantHash, run, {
          kind: 'seed', suppliedUrl: seed.suppliedUrl, canonicalUrl: seed.canonicalUrl,
          depth: 0, sourceRefs: seed.sourceRefs,
        });
      }
      return snapshotInTransaction(database, tenantHash, input.runId);
    }, signal);
  }

  async function claimNext(scope, runIdValue, workerValue, signal) {
    if (!validId(runIdValue, 96)) fail();
    const worker = normalizeWorkerInput(workerValue);
    return withScope(scope, (database, { tenantHash }) => {
      let run = getRun(database, tenantHash, runIdValue);
      run = expireOrExhaust(database, tenantHash, run, now);
      const prior = database.prepare(`SELECT * FROM frontier_claims
        WHERE tenant_hash = ? AND run_id = ? AND claim_key = ?`).get(tenantHash, runIdValue, worker.claimKey);
      if (prior) {
        if (prior.worker_id !== worker.workerId) fail('FRONTIER_CONFLICT');
        return claimResult(database, tenantHash, runIdValue, prior, true);
      }
      const release = database.prepare(`SELECT state FROM frontier_private_release
        WHERE tenant_hash = ? AND run_id = ?`).get(tenantHash, runIdValue);
      if (release?.state === 'sealed') return deepFreeze({ state: 'stopped', reason: 'private_draft_sealed' });
      if (run.status !== 'active') return deepFreeze({ state: 'stopped', reason: run.halt_reason ?? 'frontier_exhausted' });
      const inFlight = database.prepare(`SELECT COUNT(*) AS count FROM frontier_candidates
        WHERE tenant_hash = ? AND run_id = ? AND state = 'leased'`).get(tenantHash, runIdValue).count;
      if (inFlight >= run.max_in_flight) return deepFreeze({ state: 'waiting', reason: 'in_flight_limit' });
      if (tenantCapacityInTransaction(database, tenantHash, tenantLimits).availableInFlightLeases === 0) {
        return deepFreeze({ state: 'waiting', reason: 'tenant_in_flight_limit' });
      }
      const eligible = database.prepare(`SELECT * FROM frontier_candidates
        WHERE tenant_hash = ? AND run_id = ? AND state = 'queued' AND best_depth <= ?`)
        .all(tenantHash, runIdValue, run.max_depth)
        .sort((left, right) => left.best_depth - right.best_depth
          || stableCompare(left.canonical_url, right.canonical_url)
          || stableCompare(left.candidate_id, right.candidate_id));
      if (eligible.length === 0) {
        run = expireOrExhaust(database, tenantHash, run, now);
        return deepFreeze({ state: run.status === 'active' ? 'waiting' : 'empty',
          reason: run.halt_reason ?? 'frontier_exhausted' });
      }
      const candidate = eligible[0];
      const token = randomUUID();
      const observationSequence = run.next_observation_sequence - 1;
      if (!Number.isSafeInteger(observationSequence) || observationSequence < 1
        || observationSequence > MAX_SEEDS + MAX_ATTEMPT_ADMISSIONS * MAX_SUGGESTIONS) fail('FRONTIER_STORAGE');
      const prefixStats = database.prepare(`SELECT COUNT(*) AS count, MIN(sequence) AS first_sequence,
        MAX(sequence) AS last_sequence FROM frontier_observations
        WHERE tenant_hash = ? AND run_id = ? AND sequence <= ?`)
        .get(tenantHash, runIdValue, observationSequence);
      if (prefixStats.count !== observationSequence || prefixStats.first_sequence !== 1
        || prefixStats.last_sequence !== observationSequence) fail('FRONTIER_STORAGE');
      database.prepare(`UPDATE frontier_candidates SET state = 'leased', lease_token = ?, lease_worker_id = ?
        WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ? AND state = 'queued'`)
        .run(token, worker.workerId, tenantHash, runIdValue, candidate.candidate_id);
      database.prepare(`INSERT INTO frontier_claims
        (tenant_hash, run_id, claim_key, candidate_id, lease_token, worker_id, state,
          claim_binding_version, claim_observation_sequence)
        VALUES (?, ?, ?, ?, ?, ?, 'leased', ?, ?)`)
        .run(tenantHash, runIdValue, worker.claimKey, candidate.candidate_id, token, worker.workerId,
          CLAIM_BINDING_VERSION, observationSequence);
      const claim = database.prepare(`SELECT * FROM frontier_claims
        WHERE tenant_hash = ? AND run_id = ? AND claim_key = ?`).get(tenantHash, runIdValue, worker.claimKey);
      return claimResult(database, tenantHash, runIdValue, claim, false);
    }, signal);
  }

  async function admitAttempt(scope, runIdValue, value, signal) {
    if (!validId(runIdValue, 96)) fail();
    const input = normalizeAttemptInput(value);
    return withScope(scope, (database, { tenantHash }) => {
      let run = getRun(database, tenantHash, runIdValue);
      run = advanceClock(database, tenantHash, run, now);
      return admitAttemptInTransaction(database, tenantHash, runIdValue, run, input, tenantLimits);
    }, signal);
  }

  function transportCapacityInTransaction(database, tenantHash, runIdValue) {
    const rows = database.prepare(`SELECT state, reservation_bytes, decoded_bytes
      FROM frontier_transport_hops WHERE tenant_hash = ? AND run_id = ?`).all(tenantHash, runIdValue);
    let reservedBytes = 0;
    let spentBytes = 0;
    const legacyUnknownRuns = database.prepare(`SELECT COUNT(*) AS count
      FROM frontier_transport_legacy_uncertainty WHERE tenant_hash = ? AND run_id = ?`)
      .get(tenantHash, runIdValue).count;
    if (legacyUnknownRuns > 0) reservedBytes += MAX_DECODED_BYTES_PER_RUN;
    const states = Object.create(null);
    for (const row of rows) {
      states[row.state] = (states[row.state] ?? 0) + 1;
      if (['reserved', 'dispatch_intent', 'response_received', 'unknown'].includes(row.state)) {
        reservedBytes += row.reservation_bytes;
      } else if (row.state === 'body_complete') {
        if (!Number.isSafeInteger(row.decoded_bytes) || row.decoded_bytes < 0) fail('FRONTIER_STORAGE');
        spentBytes += row.decoded_bytes;
      }
    }
    if (reservedBytes + spentBytes > MAX_DECODED_BYTES_PER_RUN) fail('FRONTIER_STORAGE');
    return deepFreeze({ reservedBytes, spentBytes,
      availableBytes: MAX_DECODED_BYTES_PER_RUN - reservedBytes - spentBytes, states, legacyUnknownRuns });
  }

  async function admitTransportHop(scope, runIdValue, value, signal) {
    if (!validId(runIdValue, 96)) fail();
    const input = normalizeAttemptInput(value);
    return withScope(scope, (database, { tenantHash }) => {
      let run = advanceClock(database, tenantHash, getRun(database, tenantHash, runIdValue), now);
      const prior = database.prepare(`SELECT state, reservation_bytes, decoded_bytes FROM frontier_transport_hops
        WHERE tenant_hash = ? AND run_id = ? AND attempt_key = ?`)
        .get(tenantHash, runIdValue, input.attemptKey);
      if (prior) {
        const priorAttempt = database.prepare(`SELECT lease_token, kind, previous_attempt_key, canonical_url
          FROM frontier_attempts WHERE tenant_hash = ? AND run_id = ? AND attempt_key = ?`)
          .get(tenantHash, runIdValue, input.attemptKey);
        if (!priorAttempt || priorAttempt.lease_token !== input.leaseToken || priorAttempt.kind !== input.kind
          || priorAttempt.previous_attempt_key !== input.previousAttemptKey
          || priorAttempt.canonical_url !== input.canonicalUrl) fail('FRONTIER_CONFLICT');
        // Durable replay is status inspection only. It never grants a second dispatch.
        return deepFreeze({ state: 'already_admitted', transportState: prior.state,
          capacity: transportCapacityInTransaction(database, tenantHash, runIdValue) });
      }
      const historical = database.prepare(`SELECT 1 AS found FROM frontier_attempts
        WHERE tenant_hash = ? AND run_id = ? AND attempt_key = ?`)
        .get(tenantHash, runIdValue, input.attemptKey);
      if (historical) return deepFreeze({ state: 'already_admitted_without_transport_state',
        capacity: transportCapacityInTransaction(database, tenantHash, runIdValue) });
      const capacity = transportCapacityInTransaction(database, tenantHash, runIdValue);
      const release = database.prepare(`SELECT state FROM frontier_private_release
        WHERE tenant_hash = ? AND run_id = ?`).get(tenantHash, runIdValue);
      if (release?.state === 'sealed') return deepFreeze({ state: 'denied', reason: 'private_draft_sealed', capacity });
      if (capacity.availableBytes < RESERVED_DECODED_BYTES_PER_HOP) {
        return deepFreeze({ state: 'denied', reason: 'decoded_budget', capacity });
      }
      const admission = admitAttemptInTransaction(database, tenantHash, runIdValue, run, input, tenantLimits);
      if (admission.state !== 'admitted') return deepFreeze({ ...admission, capacity });
      database.prepare(`INSERT INTO frontier_transport_hops
        (tenant_hash, run_id, attempt_key, lease_token, state, reservation_bytes, decoded_bytes, updated_at_ms)
        VALUES (?, ?, ?, ?, 'reserved', ?, NULL, ?)`)
        .run(tenantHash, runIdValue, input.attemptKey, input.leaseToken,
          RESERVED_DECODED_BYTES_PER_HOP, run.last_clock_ms);
      const after = transportCapacityInTransaction(database, tenantHash, runIdValue);
      return deepFreeze({ state: 'admitted', attemptKey: admission.attemptKey,
        sequence: admission.sequence, admittedAtMs: admission.admittedAtMs,
        stopAfterThisAdmission: admission.stopAfterThisAdmission, capacity: after });
    }, signal);
  }

  async function updateTransportHop(scope, runIdValue, value, nextState, decodedBytes, signal) {
    if (!validId(runIdValue, 96)) fail();
    const input = ownRecord(value, new Set(['leaseToken', 'attemptKey']));
    if (!input || !validId(input.leaseToken, 64) || !validId(input.attemptKey, 128)) fail();
    return withScope(scope, (database, { tenantHash }) => {
      const run = advanceClock(database, tenantHash, getRun(database, tenantHash, runIdValue), now);
      const row = database.prepare(`SELECT * FROM frontier_transport_hops
        WHERE tenant_hash = ? AND run_id = ? AND attempt_key = ?`)
        .get(tenantHash, runIdValue, input.attemptKey);
      if (!row || row.lease_token !== input.leaseToken) fail('FRONTIER_STALE_LEASE');
      const claim = getClaimByToken(database, tenantHash, runIdValue, input.leaseToken);
      const candidate = claim ? candidateRow(database, tenantHash, runIdValue, claim.candidate_id) : null;
      if (!claim || claim.state !== 'leased' || !candidate || candidate.state !== 'leased'
        || candidate.lease_token !== input.leaseToken) fail('FRONTIER_STALE_LEASE');
      if (row.state !== 'reserved' && row.state !== 'dispatch_intent' && row.state !== 'response_received') {
        return deepFreeze({ state: 'unchanged', transportState: row.state,
          capacity: transportCapacityInTransaction(database, tenantHash, runIdValue) });
      }
      if (nextState === 'dispatch_intent') {
        if (row.state !== 'reserved') return deepFreeze({ state: 'unchanged', transportState: row.state,
          capacity: transportCapacityInTransaction(database, tenantHash, runIdValue) });
        database.prepare(`UPDATE frontier_transport_hops SET state = 'dispatch_intent', updated_at_ms = ?
          WHERE tenant_hash = ? AND run_id = ? AND attempt_key = ? AND state = 'reserved'`)
          .run(run.last_clock_ms, tenantHash, runIdValue, input.attemptKey);
      } else if (nextState === 'response_received') {
        if (row.state === 'response_received') return deepFreeze({ state: 'unchanged', transportState: row.state,
          capacity: transportCapacityInTransaction(database, tenantHash, runIdValue) });
        if (row.state !== 'dispatch_intent') fail('FRONTIER_CONFLICT');
        database.prepare(`UPDATE frontier_transport_hops SET state = 'response_received', updated_at_ms = ?
          WHERE tenant_hash = ? AND run_id = ? AND attempt_key = ? AND state = 'dispatch_intent'`)
          .run(run.last_clock_ms, tenantHash, runIdValue, input.attemptKey);
      } else if (nextState === 'known_zero') {
        if (!['reserved', 'dispatch_intent', 'response_received'].includes(row.state)) fail('FRONTIER_CONFLICT');
        database.prepare(`UPDATE frontier_transport_hops SET state = 'known_zero', decoded_bytes = 0,
          updated_at_ms = ? WHERE tenant_hash = ? AND run_id = ? AND attempt_key = ? AND state = ?`)
          .run(run.last_clock_ms, tenantHash, runIdValue, input.attemptKey, row.state);
      } else if (nextState === 'body_complete') {
        if (row.state !== 'response_received' || !Number.isSafeInteger(decodedBytes)
          || decodedBytes < 0 || decodedBytes > row.reservation_bytes) fail('FRONTIER_CONFLICT');
        database.prepare(`UPDATE frontier_transport_hops SET state = 'body_complete', decoded_bytes = ?,
          updated_at_ms = ? WHERE tenant_hash = ? AND run_id = ? AND attempt_key = ? AND state = 'response_received'`)
          .run(decodedBytes, run.last_clock_ms, tenantHash, runIdValue, input.attemptKey);
      } else {
        if (!['dispatch_intent', 'response_received'].includes(row.state)) fail('FRONTIER_CONFLICT');
        database.prepare(`UPDATE frontier_transport_hops SET state = 'unknown', decoded_bytes = NULL,
          updated_at_ms = ? WHERE tenant_hash = ? AND run_id = ? AND attempt_key = ? AND state = ?`)
          .run(run.last_clock_ms, tenantHash, runIdValue, input.attemptKey, row.state);
      }
      return deepFreeze({ state: 'updated', transportState: nextState,
        capacity: transportCapacityInTransaction(database, tenantHash, runIdValue) });
    }, signal);
  }

  async function markTransportDispatchIntent(scope, runIdValue, input, signal) {
    return updateTransportHop(scope, runIdValue, input, 'dispatch_intent', undefined, signal);
  }

  async function markTransportResponseReceived(scope, runIdValue, input, signal) {
    return updateTransportHop(scope, runIdValue, input, 'response_received', undefined, signal);
  }

  async function settleTransportHopKnownZero(scope, runIdValue, input, signal) {
    return updateTransportHop(scope, runIdValue, input, 'known_zero', undefined, signal);
  }

  async function settleTransportHopBodyComplete(scope, runIdValue, input, decodedBytes, signal) {
    return updateTransportHop(scope, runIdValue, input, 'body_complete', decodedBytes, signal);
  }

  async function markTransportHopUnknown(scope, runIdValue, input, signal) {
    return updateTransportHop(scope, runIdValue, input, 'unknown', undefined, signal);
  }

  async function getTransportProgress(scope, runIdValue, signal) {
    if (!validId(runIdValue, 96)) fail();
    return withScope(scope, (database, { tenantHash }) => {
      getRun(database, tenantHash, runIdValue);
      return transportCapacityInTransaction(database, tenantHash, runIdValue);
    }, signal);
  }

  async function getTenantProgress(scope, signal) {
    return withScope(scope, (database, { tenantHash }) =>
      tenantCapacityInTransaction(database, tenantHash, tenantLimits), signal);
  }

  async function completeCandidate(scope, runIdValue, value, signal) {
    if (!validId(runIdValue, 96)) fail();
    const input = normalizeCompletionInput(value);
    const payloadHash = digest(stableJson({ outcome: input.outcome, suggestions: input.suggestions,
      truncatedCount: input.truncatedCount }));
    return withScope(scope, (database, { tenantHash }) => {
      let run = getRun(database, tenantHash, runIdValue);
      run = advanceClock(database, tenantHash, run, now);
      const priorCompletion = database.prepare(`SELECT * FROM frontier_completions
        WHERE tenant_hash = ? AND run_id = ? AND completion_key = ?`)
        .get(tenantHash, runIdValue, input.completionKey);
      if (priorCompletion) {
        if (priorCompletion.payload_hash !== payloadHash || priorCompletion.lease_token !== input.leaseToken) {
          fail('FRONTIER_CONFLICT');
        }
        return snapshotInTransaction(database, tenantHash, runIdValue);
      }
      const deadlineStop = database.prepare(`SELECT 1 AS found FROM frontier_stops
        WHERE tenant_hash = ? AND run_id = ? AND reason = 'deadline' LIMIT 1`).get(tenantHash, runIdValue);
      if (deadlineStop) fail('FRONTIER_STOPPED');
      const claim = getClaimByToken(database, tenantHash, runIdValue, input.leaseToken);
      const candidate = claim ? candidateRow(database, tenantHash, runIdValue, claim.candidate_id) : null;
      if (!claim || claim.state !== 'leased' || !candidate || candidate.state !== 'leased'
        || candidate.lease_token !== input.leaseToken) fail('FRONTIER_STALE_LEASE');
      if (candidate.attempts_admitted < 1) fail('FRONTIER_CONFLICT');
      if (input.suggestions.length > run.max_suggestions) fail();
      const observedCount = database.prepare(`SELECT COUNT(*) AS count FROM frontier_observations
        WHERE tenant_hash = ? AND run_id = ?`).get(tenantHash, runIdValue).count;
      if (observedCount + input.suggestions.length > MAX_SEEDS + MAX_ATTEMPT_ADMISSIONS * MAX_SUGGESTIONS) {
        fail('FRONTIER_STORAGE_LIMIT');
      }
      database.prepare(`INSERT INTO frontier_completions
        (tenant_hash, run_id, completion_key, payload_hash, candidate_id, lease_token, outcome)
        VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(tenantHash, runIdValue, input.completionKey, payloadHash, candidate.candidate_id,
          input.leaseToken, input.outcome);
      database.prepare(`UPDATE frontier_candidates SET state = 'completed', lease_token = NULL, lease_worker_id = NULL
        WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
        .run(tenantHash, runIdValue, candidate.candidate_id);
      database.prepare(`UPDATE frontier_claims SET state = 'completed'
        WHERE tenant_hash = ? AND run_id = ? AND claim_key = ?`).run(tenantHash, runIdValue, claim.claim_key);
      for (const suggestion of input.suggestions) {
        const parent = candidateRow(database, tenantHash, runIdValue, candidate.candidate_id);
        insertObservation(database, tenantHash, { ...run, status: run.status }, {
          kind: 'link', parentCandidateId: candidate.candidate_id,
          suppliedUrl: suggestion.suppliedUrl, canonicalUrl: suggestion.canonicalUrl,
          depth: parent.best_depth + 1, label: suggestion.label, sourceRefs: suggestion.sourceRefs,
          outcome: input.outcome,
        });
      }
      if (input.truncatedCount > 0) recordStop(database, tenantHash, runIdValue, 'fanout_limit', run.last_clock_ms, false);
      if (input.outcome === 'access_restricted') recordStop(database, tenantHash, runIdValue, 'access_restricted', run.last_clock_ms, true);
      const updated = getRun(database, tenantHash, runIdValue);
      expireOrExhaust(database, tenantHash, updated, now);
      return snapshotInTransaction(database, tenantHash, runIdValue);
    }, signal);
  }

  async function markUnresolved(scope, runIdValue, value, signal) {
    if (!validId(runIdValue, 96)) fail();
    const input = normalizeUnresolvedInput(value);
    return withScope(scope, (database, { tenantHash }) => {
      const run = advanceClock(database, tenantHash, getRun(database, tenantHash, runIdValue), now);
      const claim = getClaimByToken(database, tenantHash, runIdValue, input.leaseToken);
      if (!claim) fail('FRONTIER_STALE_LEASE');
      if (claim.state === 'unresolved') {
        if (claim.resolution_reason !== input.reason) fail('FRONTIER_CONFLICT');
        return snapshotInTransaction(database, tenantHash, runIdValue);
      }
      if (claim.state !== 'leased') fail('FRONTIER_STALE_LEASE');
      const candidate = candidateRow(database, tenantHash, runIdValue, claim.candidate_id);
      if (input.reason === 'cancelled_before_dispatch' && candidate.attempts_admitted !== 0) {
        fail('FRONTIER_CONFLICT');
      }
      database.prepare(`UPDATE frontier_claims SET state = 'unresolved', resolution_reason = ?
        WHERE tenant_hash = ? AND run_id = ? AND claim_key = ?`)
        .run(input.reason, tenantHash, runIdValue, claim.claim_key);
      database.prepare(`UPDATE frontier_candidates SET state = 'unresolved', lease_token = NULL, lease_worker_id = NULL
        WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
        .run(tenantHash, runIdValue, claim.candidate_id);
      recordStop(database, tenantHash, runIdValue, 'unresolved_work', run.last_clock_ms, true);
      return snapshotInTransaction(database, tenantHash, runIdValue);
    }, signal);
  }

  async function stopRun(scope, runIdValue, reason, signal) {
    if (!validId(runIdValue, 96)
      || !['cancelled', 'budget_denied', 'access_restricted', 'adequate_facts', 'review_required', 'deadline'].includes(reason)) fail();
    return withScope(scope, (database, { tenantHash }) => {
      const run = advanceClock(database, tenantHash, getRun(database, tenantHash, runIdValue), now);
      const release = database.prepare(`SELECT state FROM frontier_private_release
        WHERE tenant_hash = ? AND run_id = ?`).get(tenantHash, runIdValue);
      if (release?.state === 'sealed') {
        if (reason === 'deadline') recordStop(database, tenantHash, runIdValue, reason, run.last_clock_ms, true);
        return snapshotInTransaction(database, tenantHash, runIdValue);
      }
      recordStop(database, tenantHash, runIdValue, reason, run.last_clock_ms, true);
      return snapshotInTransaction(database, tenantHash, runIdValue);
    }, signal);
  }

  async function sealPrivateDraft(scope, runIdValue, signal) {
    if (!validId(runIdValue, 96)) fail();
    return withScope(scope, (database, { tenantHash }) => {
      const run = advanceClock(database, tenantHash, getRun(database, tenantHash, runIdValue), now);
      database.prepare(`INSERT OR IGNORE INTO frontier_private_release
        (tenant_hash, run_id, state, sealed_at_ms) VALUES (?, ?, 'open', NULL)`)
        .run(tenantHash, runIdValue);
      const release = database.prepare(`SELECT state FROM frontier_private_release
        WHERE tenant_hash = ? AND run_id = ?`).get(tenantHash, runIdValue);
      if (release?.state === 'sealed') return deepFreeze({ state: 'already_sealed' });
      const stop = database.prepare(`SELECT 1 AS found FROM frontier_stops
        WHERE tenant_hash = ? AND run_id = ? AND reason IN (
          'cancelled', 'budget_denied', 'deadline', 'access_restricted',
          'adequate_facts', 'review_required', 'unresolved_work'
        ) LIMIT 1`)
        .get(tenantHash, runIdValue);
      if (stop) return deepFreeze({ state: 'denied', reason: 'run_stopped' });
      const activeClaims = database.prepare(`SELECT COUNT(*) AS count FROM frontier_candidates
        WHERE tenant_hash = ? AND run_id = ? AND state = 'leased'`).get(tenantHash, runIdValue).count;
      if (activeClaims !== 0) return deepFreeze({ state: 'denied', reason: 'run_incomplete' });
      const capacity = transportCapacityInTransaction(database, tenantHash, runIdValue);
      if (capacity.reservedBytes !== 0) return deepFreeze({ state: 'denied', reason: 'transport_uncertain' });
      database.prepare(`UPDATE frontier_private_release SET state = 'sealed', sealed_at_ms = ?
        WHERE tenant_hash = ? AND run_id = ? AND state = 'open'`)
        .run(run.last_clock_ms, tenantHash, runIdValue);
      return deepFreeze({ state: 'sealed' });
    }, signal);
  }

  async function getSnapshot(scope, runIdValue, signal) {
    if (!validId(runIdValue, 96)) fail();
    return withScope(scope, (database, { tenantHash }) => {
      const run = getRun(database, tenantHash, runIdValue);
      expireOrExhaust(database, tenantHash, run, now);
      return snapshotInTransaction(database, tenantHash, runIdValue);
    }, signal);
  }

  async function getCandidateReceiptBinding(scope, runIdValue, candidateIdValue, signal) {
    if (!validId(runIdValue, 96) || typeof candidateIdValue !== 'string' || !HEX_SHA256.test(candidateIdValue)) fail();
    return withScope(scope, (database, { tenantHash }) => {
      getRun(database, tenantHash, runIdValue);
      const candidate = candidateRow(database, tenantHash, runIdValue, candidateIdValue);
      if (!candidate) fail('FRONTIER_NOT_FOUND');
      const claims = database.prepare(`SELECT * FROM frontier_claims
        WHERE tenant_hash = ? AND run_id = ? AND candidate_id = ?`)
        .all(tenantHash, runIdValue, candidateIdValue);
      if (claims.length === 0) return null;
      if (claims.length !== 1) fail('FRONTIER_STORAGE');
      return candidateClaimBindingInTransaction(database, tenantHash, runIdValue, candidate, claims[0]);
    }, signal);
  }

  return Object.freeze({
    scopeForAuthenticatedRequest,
    createRun,
    claimNext,
    admitAttempt,
    admitTransportHop,
    markTransportDispatchIntent,
    markTransportResponseReceived,
    settleTransportHopKnownZero,
    settleTransportHopBodyComplete,
    markTransportHopUnknown,
    getTransportProgress,
    getTenantProgress,
    completeCandidate,
    markUnresolved,
    stopRun,
    sealPrivateDraft,
    getSnapshot,
    getCandidateReceiptBinding,
    close() { closed = true; },
  });
}
