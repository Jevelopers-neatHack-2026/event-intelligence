import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
  chmod,
  lstat,
  mkdir,
} from 'node:fs/promises';
import { lstatSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import path from 'node:path';
import { types as utilTypes } from 'node:util';
import { readTextPdf, PDF_TEXT_READER_LIMITS } from '../extraction/pdf/index.mjs';
import { PDF_DECODER_VERSION, PDF_READER_CONFIG_VERSION } from '../extraction/pdf/constants.mjs';
import { DETERMINISTIC_EXTRACTION_VERSION, extractDeterministically } from '../extraction/index.mjs';
import { hasSensitiveUrlMaterial, parseAndValidateUrl } from '../security/url-policy.mjs';
import {
  isCompletedControlledSvgFetch,
  verifyControlledSvgIngestWitness,
} from '../security/internal/fetch-lifecycle.mjs';
import { inspectSafeAssetBytes, SAFE_ASSET_POLICY_VERSION } from '../security/assets/inspect.mjs';
import {
  bindPrivateAssetReleaseCandidates,
  createPrivateAssetReleaseCheck,
  finalizePrivateAssetRelease,
  isPrivateAssetReleaseController,
  privateAssetReleaseAuthorityValidDuringFinalization,
  privateAssetReleaseAuthorityForController,
  revokePrivateAssetReleaseAuthority,
  takePrivateAssetReleaseCheck,
} from '../research/private-asset-release.mjs';

const SUPPORTED_SOURCE_KINDS = new Set(['external', 'customer_supplied']);
const FACT_STATUSES = new Set(['sourced', 'inferred', 'customer_supplied', 'missing', 'conflicting']);
const FACT_ORIGINS = new Set(['sourced', 'inferred', 'customer_supplied']);
const FACT_PRECISIONS = new Set(['date', 'local_datetime', 'instant', 'unknown']);
const ERROR_MESSAGES = Object.freeze({
  EVIDENCE_DENIED: 'evidence access denied',
  EVIDENCE_INVALID: 'invalid evidence record',
  EVIDENCE_NOT_FOUND: 'evidence record not found',
  EVIDENCE_EXPIRED: 'evidence payload expired',
  EVIDENCE_BUSY: 'evidence store is busy',
  EVIDENCE_INTEGRITY: 'evidence integrity check failed',
  EVIDENCE_KEY_UNAVAILABLE: 'evidence encryption key unavailable',
  EVIDENCE_CANCELLED: 'evidence materialization cancelled',
  EVIDENCE_STORAGE: 'evidence storage operation failed',
});
const TENANT_SCOPES = new WeakMap();
const EVIDENCE_HANDLES = new WeakMap();
const POSITION_HANDLES = new WeakMap();
const FACT_HANDLES = new WeakMap();
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_TAG_GETTER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, Symbol.toStringTag).get;
const TYPED_ARRAY_LENGTH_GETTER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'length').get;
const TYPED_ARRAY_SET = Uint8Array.prototype.set;
const NATIVE_PROMISE_THEN = Promise.prototype.then;
const ABORT_SIGNAL_ABORTED_GETTER = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const TENANT_QUEUES = new Map();
const SELECTED_BATCH_LIMITS = Object.freeze({
  evidenceCount: 8,
  factCount: 128,
  positionCount: 128,
  sealedBytes: 8 * 1024 * 1024,
  evidenceSealedBytes: 4 * 1024 * 1024,
  factSealedBytes: 512 * 1024,
  decryptedBytes: 8 * 1024 * 1024,
  evidenceDecryptedBytes: 4 * 1024 * 1024,
  factBytes: 2 * 1024 * 1024,
  factRecordBytes: 256 * 1024,
  positionBytes: 1024 * 1024,
  evidencePositionBytes: 512 * 1024,
  positionRecordBytes: 64 * 1024,
  provenanceBytes: 512 * 1024,
  factMetadataBytes: 512 * 1024,
  supportReferences: 4_096,
});
const PRIVATE_RECEIPT_SCHEMA_VERSION = 1;
const PRIVATE_RECEIPT_KIND = 'private-retrieval-receipt';
const PRIVATE_RECEIPT_MAX_PLAINTEXT_BYTES = 512 * 1024;
const PRIVATE_RECEIPT_MAX_ENVELOPE_BYTES = 768 * 1024;
const PRIVATE_RECEIPT_MAX_ROWS_PER_TENANT = 4_096;
const PRIVATE_RECEIPT_MAX_SEALED_BYTES_PER_TENANT = 32 * 1024 * 1024;
const PDF_DERIVED_REPRESENTATION = 'pdf-derived-text';
const PDF_DERIVED_BUNDLE_VERSION = 2;
const PDF_DERIVATION_BINDING_VERSION = 1;
const PDF_DERIVED_DEFAULT_TIMEOUT_MS = 15_000;
const PDF_DERIVED_CONTENT_TYPE = 'application/pdf';
const PDF_DERIVED_MAX_SOURCE_BYTES = 5 * 1024 * 1024;
const ASSET_SOURCE_EXCERPT_REPRESENTATION = 'asset-source-excerpt';
const ASSET_SOURCE_BUNDLE_VERSION = 3;
const ASSET_SOURCE_BINDING_VERSION = 1;
const ASSET_SOURCE_SELECTOR_VERSION = 'ei-asset-source-selector/6';
const ASSET_SOURCE_MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const ASSET_SOURCE_MAX_POSITIONS = 64;
const ASSET_SOURCE_MAX_EXCERPT_BYTES = 8 * 1024;
const ASSET_SOURCE_MAX_EXCERPT_TOTAL_BYTES = 64 * 1024;
const ASSET_SOURCE_MAX_METADATA_BYTES = 64 * 1024;
const ASSET_SOURCE_MAX_DEADLINE_MS = 2_500;
const ASSET_SOURCE_LIMITATIONS = Object.freeze([
  'CSS_BACKGROUND_IMAGES_UNSUPPORTED',
  'FONT_ASSETS_UNSUPPORTED',
  'SRCSET_UNSUPPORTED',
  'DYNAMIC_ASSETS_UNSUPPORTED',
  'ZERO_REDIRECT_DOCUMENTS_ONLY',
  'NO_ASSET_BYTES_FETCHED_OR_INSPECTED',
]);
const CONTROLLED_ASSET_ACQUISITION_POLICY_VERSION = 'ei-private-svg-acquisition/1';
const CONTROLLED_ASSET_MAX_SOURCE_BYTES = 128 * 1024;
const CONTROLLED_ASSET_MAX_TRANSFORMED_BYTES = 512 * 1024;
// These profiles validate immutable encrypted derivations. When extraction or
// selector output changes, add the new writer pair and retain every still-
// readable historical pair here; never reparse or rewrite a sealed bundle.
// Keep historical identifiers literal so a current writer bump cannot make
// its existing records unreadable by changing a shared "current" constant.
const ASSET_SOURCE_READ_PROFILES = new Map([
  ['ei-asset-source-selector/1\u0000ei-deterministic-extraction/1.3.0', Object.freeze({
    selectorVersion: 'ei-asset-source-selector/1',
    extractorVersion: 'ei-deterministic-extraction/1.3.0',
    completeness: 'static-selected-forms-only',
    limitations: ASSET_SOURCE_LIMITATIONS,
  })],
  ['ei-asset-source-selector/2\u0000ei-deterministic-extraction/1.3.0', Object.freeze({
    selectorVersion: 'ei-asset-source-selector/2',
    extractorVersion: 'ei-deterministic-extraction/1.3.0',
    completeness: 'static-selected-forms-only',
    limitations: ASSET_SOURCE_LIMITATIONS,
  })],
  ['ei-asset-source-selector/3\u0000ei-deterministic-extraction/1.3.0', Object.freeze({
    selectorVersion: 'ei-asset-source-selector/3',
    extractorVersion: 'ei-deterministic-extraction/1.3.0',
    completeness: 'static-selected-forms-only',
    limitations: ASSET_SOURCE_LIMITATIONS,
  })],
  ['ei-asset-source-selector/4\u0000ei-deterministic-extraction/1.4.0', Object.freeze({
    selectorVersion: 'ei-asset-source-selector/4',
    extractorVersion: 'ei-deterministic-extraction/1.4.0',
    completeness: 'static-selected-forms-only',
    limitations: ASSET_SOURCE_LIMITATIONS,
  })],
  ['ei-asset-source-selector/5\u0000ei-deterministic-extraction/1.5.0', Object.freeze({
    selectorVersion: 'ei-asset-source-selector/5',
    extractorVersion: 'ei-deterministic-extraction/1.5.0',
    completeness: 'static-selected-forms-only',
    limitations: ASSET_SOURCE_LIMITATIONS,
  })],
  ['ei-asset-source-selector/6\u0000ei-deterministic-extraction/1.6.0', Object.freeze({
    selectorVersion: 'ei-asset-source-selector/6',
    extractorVersion: 'ei-deterministic-extraction/1.6.0',
    completeness: 'static-selected-forms-only',
    limitations: ASSET_SOURCE_LIMITATIONS,
  })],
]);
const ASSET_SOURCE_FORMS = new Set([
  'html-img-src', 'html-icon-link', 'open-graph-image', 'jsonld-image', 'jsonld-logo',
]);
const ASSET_QUARANTINE_REASONS = new Set([
  'invalid_or_empty', 'unresolvable_url', 'unsupported_scheme', 'sensitive_query', 'url_policy_denied',
]);
const ASSET_SENSITIVE_QUERY_KEY = /(?:token|key|auth|code|signature|sig|secret|session|password|credential|invite|ticket|admission)/i;

export class EvidenceStoreError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES.EVIDENCE_STORAGE);
    this.name = 'EvidenceStoreError';
    this.code = Object.hasOwn(ERROR_MESSAGES, code) ? code : 'EVIDENCE_STORAGE';
  }
}

function fail(code) {
  throw new EvidenceStoreError(code);
}

function signalWasAborted(signal) {
  try { return Reflect.apply(ABORT_SIGNAL_ABORTED_GETTER, signal, []); }
  catch { fail('EVIDENCE_INVALID'); }
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

function copyBytes(value, maximum, allowEmpty = false) {
  try {
    if (typeof value === 'string') {
      if (!isWellFormed(value)) fail('EVIDENCE_INVALID');
      const bytes = Buffer.from(value, 'utf8');
      if ((!allowEmpty && bytes.length === 0) || bytes.length > maximum) fail('EVIDENCE_INVALID');
      return bytes;
    }
    if (TYPED_ARRAY_TAG_GETTER.call(value) !== 'Uint8Array') fail('EVIDENCE_INVALID');
    const length = TYPED_ARRAY_LENGTH_GETTER.call(value);
    if (!Number.isSafeInteger(length) || (!allowEmpty && length === 0) || length > maximum) fail('EVIDENCE_INVALID');
    const bytes = new Uint8Array(length);
    TYPED_ARRAY_SET.call(bytes, value);
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  } catch (error) {
    if (error instanceof EvidenceStoreError) throw error;
    fail('EVIDENCE_INVALID');
  }
}

function safeArray(value, maximumLength) {
  if (!Array.isArray(value) || value.length > maximumLength) return null;
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || keys.some((key) => key !== 'length' && (!Number.isSafeInteger(Number(key)) || String(Number(key)) !== key || Number(key) < 0 || Number(key) >= value.length))) return null;
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
      result.push(descriptor.value);
    }
    return result;
  } catch {
    return null;
  }
}

function cloneJsonValue(value, depth = 0, budget = { nodes: 0, bytes: 0, maximumBytes: Number.POSITIVE_INFINITY }) {
  budget.nodes += 1;
  if (budget.nodes > 2000 || depth > 12) fail('EVIDENCE_INVALID');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (value.length > 4000 || !isWellFormed(value)) fail('EVIDENCE_INVALID');
    budget.bytes += Buffer.byteLength(value, 'utf8');
    if (!Number.isSafeInteger(budget.bytes) || budget.bytes > budget.maximumBytes) fail('EVIDENCE_INVALID');
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('EVIDENCE_INVALID');
    return value;
  }
  if (Array.isArray(value)) {
    const items = safeArray(value, 250);
    if (!items) fail('EVIDENCE_INVALID');
    return items.map((item) => cloneJsonValue(item, depth + 1, budget));
  }
  if (isRecord(value)) {
    let keys;
    try { keys = Reflect.ownKeys(value); } catch { fail('EVIDENCE_INVALID'); }
    if (keys.length > 250 || keys.some((key) => typeof key !== 'string' || key === '__proto__' || key === 'constructor' || key === 'prototype')) fail('EVIDENCE_INVALID');
    const result = Object.create(null);
    for (const key of keys) {
      if (key.length > 120 || !isWellFormed(key)) fail('EVIDENCE_INVALID');
      budget.bytes += Buffer.byteLength(key, 'utf8');
      if (!Number.isSafeInteger(budget.bytes) || budget.bytes > budget.maximumBytes) fail('EVIDENCE_INVALID');
      let descriptor;
      try { descriptor = Object.getOwnPropertyDescriptor(value, key); } catch { fail('EVIDENCE_INVALID'); }
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail('EVIDENCE_INVALID');
      result[key] = cloneJsonValue(descriptor.value, depth + 1, budget);
    }
    return result;
  }
  fail('EVIDENCE_INVALID');
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function wipePrivateTree(value) {
  if (Array.isArray(value)) {
    for (const item of value) wipePrivateTree(item);
    for (let index = 0; index < value.length; index += 1) value[index] = null;
    return;
  }
  if (!isRecord(value)) return;
  for (const key of Object.keys(value)) {
    wipePrivateTree(value[key]);
    value[key] = null;
  }
}

function copySynchronousConsumerResult(value) {
  if (value === undefined) return value;
  const copied = cloneJsonValue(value);
  // Preserve normal array iteration and methods while preventing Promise
  // resolution from reading an inherited Array.prototype.then after the final
  // authorization gate. JSON arrays cannot carry own properties, so this inert
  // non-enumerable property is part of the trusted copy only.
  if (Array.isArray(copied)) {
    Object.defineProperty(copied, 'then', {
      value: undefined,
      enumerable: false,
      writable: false,
      configurable: false,
    });
  }
  return deepFreeze(copied);
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function isDigest(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function validTimestamp(value) {
  if (typeof value !== 'string' || value.length > 64) return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|([+-])(\d{2}):(\d{2}))$/i.exec(value);
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, , zone, , offsetHourText, offsetMinuteText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = secondText === undefined ? 0 : Number(secondText);
  if (year < 1 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > daysInMonth[month - 1]) return false;
  if (zone.toUpperCase() !== 'Z'
    && (Number(offsetHourText) > 23 || Number(offsetMinuteText) > 59)) return false;
  return Number.isFinite(Date.parse(value));
}

function validateUrl(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096 || !isWellFormed(value)) fail('EVIDENCE_INVALID');
  let parsed;
  try { parsed = new URL(value); } catch { fail('EVIDENCE_INVALID'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) fail('EVIDENCE_INVALID');
  return parsed;
}

function normalizeSourceUrl(value) {
  const parsed = validateUrl(value);
  parsed.hash = '';
  return parsed.href;
}

function copyLocator(value) {
  const input = ownDataRecord(value, new Set(['kind', 'startByte', 'endByte', 'pointer']));
  if (!input || typeof input.kind !== 'string') fail('EVIDENCE_INVALID');
  if (input.kind === 'text-range') {
    if (!Number.isSafeInteger(input.startByte) || input.startByte < 0
      || !Number.isSafeInteger(input.endByte) || input.endByte <= input.startByte) fail('EVIDENCE_INVALID');
    return Object.freeze({ kind: 'text-range', startByte: input.startByte, endByte: input.endByte });
  }
  if (input.kind === 'json-pointer') {
    if (typeof input.pointer !== 'string' || input.pointer.length > 2048 || !isWellFormed(input.pointer)) fail('EVIDENCE_INVALID');
    if (input.pointer !== '' && !input.pointer.startsWith('/')) fail('EVIDENCE_INVALID');
    if (/~(?![01])/.test(input.pointer)) fail('EVIDENCE_INVALID');
    return Object.freeze({ kind: 'json-pointer', pointer: input.pointer });
  }
  fail('EVIDENCE_INVALID');
}

function copyStoredLocator(value, representation) {
  if (representation === PDF_DERIVED_REPRESENTATION) {
    const input = ownDataRecord(value, new Set([
      'kind', 'pageIndex', 'textIndex', 'x', 'y', 'width', 'height', 'pageWidth', 'pageHeight',
      'rotation', 'coordinateSystem', 'geometry',
    ]));
    if (!input || input.kind !== 'pdf-text-box'
      || !Number.isSafeInteger(input.pageIndex) || input.pageIndex < 0
      || !Number.isSafeInteger(input.textIndex) || input.textIndex < 0
      || ![input.x, input.y, input.width, input.height, input.pageWidth, input.pageHeight].every(Number.isFinite)
      || input.x < 0 || input.y < 0 || input.width < 0 || input.height < 0
      || input.pageWidth <= 0 || input.pageHeight <= 0
      || ![0, 90, 180, 270].includes(input.rotation)
      || input.coordinateSystem !== 'viewport-points-top-left'
      || input.geometry !== 'approximate-text-item') fail('EVIDENCE_INTEGRITY');
    return Object.freeze({
      kind: 'pdf-text-box', pageIndex: input.pageIndex, textIndex: input.textIndex,
      x: input.x, y: input.y, width: input.width, height: input.height,
      pageWidth: input.pageWidth, pageHeight: input.pageHeight, rotation: input.rotation,
      coordinateSystem: input.coordinateSystem, geometry: input.geometry,
    });
  }
  return copyLocator(value);
}

function resolveJsonPointer(root, pointer) {
  if (pointer === '') return root;
  const pieces = pointer.slice(1).split('/').map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'));
  let value = root;
  for (const piece of pieces) {
    if (Array.isArray(value)) {
      if (!/^(?:0|[1-9]\d*)$/.test(piece)) fail('EVIDENCE_INVALID');
      const index = Number(piece);
      if (index >= value.length || !Object.hasOwn(value, index)) fail('EVIDENCE_INVALID');
      value = value[index];
    } else if (isRecord(value) && Object.hasOwn(value, piece)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, piece);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail('EVIDENCE_INVALID');
      value = descriptor.value;
    } else {
      fail('EVIDENCE_INVALID');
    }
  }
  return value;
}

function checkSnapshot(sourceBytes, locator, snapshotBytes) {
  if (locator.kind === 'text-range') {
    if (locator.endByte > sourceBytes.byteLength) fail('EVIDENCE_INVALID');
    const selected = sourceBytes.subarray(locator.startByte, locator.endByte);
    if (!selected.equals(snapshotBytes)) fail('EVIDENCE_INVALID');
    try { new TextDecoder('utf-8', { fatal: true }).decode(selected); } catch { fail('EVIDENCE_INVALID'); }
    return;
  }
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(sourceBytes); } catch { fail('EVIDENCE_INVALID'); }
  let parsed;
  try { parsed = JSON.parse(text); } catch { fail('EVIDENCE_INVALID'); }
  let selected;
  try { selected = resolveJsonPointer(parsed, locator.pointer); } catch { fail('EVIDENCE_INVALID'); }
  let serialized;
  try { serialized = JSON.stringify(selected); } catch { fail('EVIDENCE_INVALID'); }
  if (typeof serialized !== 'string' || !Buffer.from(serialized, 'utf8').equals(snapshotBytes)) fail('EVIDENCE_INVALID');
}

function makeOpaque() {
  return Object.freeze(Object.create(null));
}

function safePublicError(error) {
  if (error instanceof EvidenceStoreError) return error;
  return new EvidenceStoreError('EVIDENCE_STORAGE');
}

function newMaterializationBudget() {
  return {
    sealedBytes: 0,
    decryptedBytes: 0,
    factBytes: 0,
    positionBytes: 0,
    provenanceBytes: 0,
    factMetadataBytes: 0,
    supportReferences: 0,
  };
}

function chargeBudget(budget, field, amount, maximum) {
  if (!Number.isSafeInteger(amount) || amount < 0
    || !Number.isSafeInteger(budget[field] + amount) || budget[field] + amount > maximum) fail('EVIDENCE_INVALID');
  budget[field] += amount;
}

function addProvenanceBytes(budget, amount) {
  chargeBudget(budget, 'provenanceBytes', amount, SELECTED_BATCH_LIMITS.provenanceBytes);
}

function base64DecodedByteLength(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail('EVIDENCE_INTEGRITY');
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  const result = (value.length / 4) * 3 - padding;
  if (!Number.isSafeInteger(result) || result <= 0) fail('EVIDENCE_INTEGRITY');
  return result;
}

function observeNativeRejectedPromise(value) {
  if (!utilTypes.isPromise(value)) return;
  try {
    // Observe only a genuine native Promise. Do not assimilate arbitrary thenables.
    Reflect.apply(NATIVE_PROMISE_THEN, value, [undefined, () => {}]);
  } catch {
    // The final authorization hook still fails closed if observation is unavailable.
  }
}

function awaitAbortableHostOperation(operation, signal) {
  if (signal === undefined) return Promise.resolve().then(operation);
  try { if (signalWasAborted(signal)) fail('EVIDENCE_CANCELLED'); } catch (error) { return Promise.reject(error); }
  const pending = Promise.resolve().then(() => {
    if (signalWasAborted(signal)) fail('EVIDENCE_CANCELLED');
    return operation();
  });
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal.removeEventListener('abort', onAbort);
    const onAbort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      try {
        if (signalWasAborted(signal)) fail('EVIDENCE_CANCELLED');
      } catch (error) { reject(error); }
    };
    signal.addEventListener('abort', onAbort, { once: true });
    if (signalWasAborted(signal)) onAbort();
    pending.then((value) => {
      if (settled) return;
      settled = true;
      cleanup();
      try {
        if (signalWasAborted(signal)) fail('EVIDENCE_CANCELLED');
        resolve(value);
      } catch (error) { reject(error); }
    }, (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    });
  });
}

function sqliteBusy(error) {
  return error?.errcode === 5 || error?.errcode === 6 || error?.code === 'ERR_SQLITE_BUSY';
}

function createLockContext(timeoutMs, externalSignal) {
  const deadlineAt = performance.now() + timeoutMs;
  const controller = new AbortController();
  let failureCode = null;
  const onExternalAbort = () => {
    if (failureCode === null) failureCode = 'EVIDENCE_CANCELLED';
    controller.abort();
  };
  if (externalSignal) {
    if (externalSignal.aborted) onExternalAbort();
    else externalSignal.addEventListener('abort', onExternalAbort, { once: true });
  }
  const timer = setTimeout(() => {
    if (failureCode === null) failureCode = 'EVIDENCE_BUSY';
    controller.abort();
  }, timeoutMs);
  return {
    signal: controller.signal,
    check() {
      // Timer delivery can lag behind a synchronous host callback or SQLite
      // operation. Every existing boundary uses the same original clock budget.
      if (failureCode === null && performance.now() >= deadlineAt) {
        failureCode = 'EVIDENCE_BUSY';
        controller.abort();
      }
      if (failureCode !== null) fail(failureCode);
      if (controller.signal.aborted) fail('EVIDENCE_CANCELLED');
    },
    failure() { return failureCode; },
    close() {
      clearTimeout(timer);
      externalSignal?.removeEventListener('abort', onExternalAbort);
    },
  };
}

function awaitWithLockContext(value, context) {
  try { context.check(); } catch (error) {
    // The caller may already have started native async work. An expired
    // preflight must still observe its rejection while preserving this refusal.
    observeNativeRejectedPromise(value);
    throw error;
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => context.signal.removeEventListener('abort', onAbort);
    const onAbort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      try { context.check(); } catch (error) { reject(error); }
    };
    context.signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(value).then((result) => {
      if (settled) return;
      settled = true;
      cleanup();
      try { context.check(); resolve(result); } catch (error) { reject(error); }
    }, (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    });
  });
}

async function lockRetryDelay(context) {
  context.check();
  await awaitWithLockContext(new Promise((resolve) => setTimeout(resolve, 5)), context);
  context.check();
}

function ensurePrivateReceiptSchema(database) {
  const expected = [
    ['tenant_hash', 'TEXT', 1, 1],
    ['receipt_key', 'TEXT', 1, 2],
    ['schema_version', 'INTEGER', 1, 0],
    ['state', 'TEXT', 1, 0],
    ['key_id', 'TEXT', 0, 0],
    ['payload_hash', 'TEXT', 0, 0],
    ['payload_bytes', 'INTEGER', 0, 0],
    ['expires_at_ms', 'INTEGER', 1, 0],
    ['sealed', 'BLOB', 0, 0],
    ['updated_at_ms', 'INTEGER', 1, 0],
  ];
  const columns = database.prepare('PRAGMA table_info(private_retrieval_receipts)').all();
  if (columns.length !== expected.length || columns.some((column, index) => {
    const [name, type, notNull, primaryKeyPosition] = expected[index];
    return column.name !== name || column.type !== type || column.notnull !== notNull || column.pk !== primaryKeyPosition;
  })) fail('EVIDENCE_STORAGE');
  const version = database.prepare(`SELECT version FROM evidence_extension_schema
    WHERE extension = 'private-retrieval-receipts'`).get();
  if (!version) {
    database.prepare(`INSERT INTO evidence_extension_schema (extension, version)
      VALUES ('private-retrieval-receipts', ?)`).run(PRIVATE_RECEIPT_SCHEMA_VERSION);
    return;
  }
  if (version.version !== PRIVATE_RECEIPT_SCHEMA_VERSION) fail('EVIDENCE_STORAGE');
}

async function withLocalTenantQueue(key, operation, context) {
  const previous = TENANT_QUEUES.get(key) ?? Promise.resolve();
  let release;
  const current = new Promise((resolve) => { release = resolve; });
  const tail = previous.catch(() => {}).then(() => current);
  TENANT_QUEUES.set(key, tail);
  tail.then(() => {
    if (TENANT_QUEUES.get(key) === tail) TENANT_QUEUES.delete(key);
  }, () => {
    if (TENANT_QUEUES.get(key) === tail) TENANT_QUEUES.delete(key);
  });
  try {
    await awaitWithLockContext(previous.catch(() => {}), context);
    context.check();
    return await operation();
  } finally {
    release();
  }
}

async function withTenantLock(directory, timeoutMs, operation, externalSignal, lockOptions = undefined) {
  const context = createLockContext(timeoutMs, externalSignal);
  try {
    const run = async () => {
      const databasePath = path.join(directory, 'evidence.sqlite');
      let database;
      let transactionOpen = false;
      const closeDatabase = () => {
        if (!database) return;
        try { database.close(); } catch { /* close releases any rolled-back transaction */ }
        database = undefined;
      };
      const retryOpen = async () => {
        while (true) {
          context.check();
          let priorStats = null;
          try {
            priorStats = await awaitWithLockContext(lstat(databasePath), context);
            if (priorStats.isSymbolicLink() || !priorStats.isFile()) fail('EVIDENCE_STORAGE');
          } catch (error) {
            if (error?.code !== 'ENOENT') throw error;
          }
          try {
            context.check();
            // timeout: 0 is essential: SQLite's busy handler is synchronous and
            // would prevent this operation's abort/deadline timer from running.
            database = new DatabaseSync(databasePath, { timeout: 0 });
            const openedStats = await awaitWithLockContext(lstat(databasePath), context);
            if (openedStats.isSymbolicLink() || !openedStats.isFile()
              || (priorStats && (openedStats.dev !== priorStats.dev || openedStats.ino !== priorStats.ino))) {
              fail('EVIDENCE_STORAGE');
            }
            database.exec(`
              PRAGMA journal_mode = DELETE;
              PRAGMA synchronous = FULL;
              PRAGMA secure_delete = ON;
              PRAGMA trusted_schema = OFF;
              CREATE TABLE IF NOT EXISTS evidence_manifest (
                tenant_hash TEXT PRIMARY KEY NOT NULL,
                document TEXT NOT NULL
              ) STRICT;
              CREATE TABLE IF NOT EXISTS sealed_bundles (
                kind TEXT NOT NULL CHECK (kind IN ('evidence', 'fact')),
                id TEXT NOT NULL,
                sealed BLOB NOT NULL,
                PRIMARY KEY (kind, id)
              ) STRICT;
              CREATE TABLE IF NOT EXISTS evidence_extension_schema (
                extension TEXT PRIMARY KEY NOT NULL,
                version INTEGER NOT NULL CHECK (version > 0)
              ) STRICT;
              CREATE TABLE IF NOT EXISTS private_retrieval_receipts (
                tenant_hash TEXT NOT NULL,
                receipt_key TEXT NOT NULL,
                schema_version INTEGER NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('pending', 'complete', 'expired')),
                key_id TEXT,
                payload_hash TEXT,
                payload_bytes INTEGER,
                expires_at_ms INTEGER NOT NULL,
                sealed BLOB,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY (tenant_hash, receipt_key)
              ) STRICT;
            `);
            await awaitWithLockContext(chmod(databasePath, 0o600), context);
            return;
          } catch (error) {
            closeDatabase();
            if (!sqliteBusy(error)) throw error;
            await lockRetryDelay(context);
          }
        }
      };
      try {
        await retryOpen();
        if (lockOptions?.beforeBegin) {
          while (true) {
            context.check();
            // This trusted synchronous callback is deliberately outside both the
            // tenant queue and SQLite transaction. A busy retry repeats it after
            // the asynchronous wait, immediately before attempting BEGIN.
            lockOptions.beforeBegin();
            context.check();
            try {
              database.exec('BEGIN IMMEDIATE');
              transactionOpen = true;
            } catch (error) {
              if (!sqliteBusy(error)) throw error;
              await lockRetryDelay(context);
              continue;
            }
            try {
              context.check();
              ensurePrivateReceiptSchema(database);
              context.check();
              const result = operation(database, context.signal);
              if (utilTypes.isPromise(result)) {
                observeNativeRejectedPromise(result);
                fail('EVIDENCE_STORAGE');
              }
              context.check();
              database.exec('COMMIT');
              transactionOpen = false;
              return result;
            } catch (error) {
              if (transactionOpen) {
                try { database.exec('ROLLBACK'); } catch { /* rollback may follow failed COMMIT */ }
                transactionOpen = false;
              }
              if (!sqliteBusy(error)) throw error;
              await lockRetryDelay(context);
            }
          }
        }
        while (true) {
          context.check();
          try {
            database.exec('BEGIN IMMEDIATE');
            transactionOpen = true;
            break;
          } catch (error) {
            if (!sqliteBusy(error)) throw error;
            await lockRetryDelay(context);
          }
        }
        context.check();
        ensurePrivateReceiptSchema(database);
        const pending = Promise.resolve().then(() => {
          context.check();
          return operation(database, context.signal);
        });
        const result = await awaitWithLockContext(pending, context);
        context.check();
        while (true) {
          try {
            context.check();
            database.exec('COMMIT');
            transactionOpen = false;
            break;
          } catch (error) {
            if (!sqliteBusy(error)) throw error;
            await lockRetryDelay(context);
          }
        }
        return result;
      } catch (error) {
        if (transactionOpen) {
          try { database?.exec('ROLLBACK'); } catch { /* SQLite rolls back on close after process errors. */ }
        }
        if (context.failure() !== null) context.check();
        if (sqliteBusy(error)) fail('EVIDENCE_BUSY');
        throw error;
      } finally {
        closeDatabase();
      }
    };
    if (lockOptions?.beforeBegin) return await run();
    return await withLocalTenantQueue(directory, run, context);
  } finally {
    context.close();
  }
}

function emptyManifest(tenantHash) {
  return { schemaVersion: 1, tenantHash, records: Object.create(null), families: Object.create(null), facts: Object.create(null) };
}

function validateManifest(value, tenantHash) {
  if (!isRecord(value) || ![1, 2, 3].includes(value.schemaVersion) || value.tenantHash !== tenantHash
    || !isRecord(value.records) || !isRecord(value.families) || !isRecord(value.facts)) fail('EVIDENCE_INTEGRITY');
  for (const record of Object.values(value.records)) {
    if (!isRecord(record)) continue;
    if (value.schemaVersion === 1 && Object.hasOwn(record, 'representation')) fail('EVIDENCE_INTEGRITY');
    if (record.representation !== undefined
      && (!((record.representation === PDF_DERIVED_REPRESENTATION && value.schemaVersion >= 2)
        || (record.representation === ASSET_SOURCE_EXCERPT_REPRESENTATION && value.schemaVersion === 3))
        || !isDigest(record.derivationDigest))) fail('EVIDENCE_INTEGRITY');
    if (record.representation === undefined && Object.hasOwn(record, 'derivationDigest')) fail('EVIDENCE_INTEGRITY');
  }
  for (const family of Object.values(value.families)) {
    if (isRecord(family) && family.representation !== undefined
      && ![PDF_DERIVED_REPRESENTATION, ASSET_SOURCE_EXCERPT_REPRESENTATION].includes(family.representation)) fail('EVIDENCE_INTEGRITY');
    if (isRecord(family) && family.representation === ASSET_SOURCE_EXCERPT_REPRESENTATION
      && value.schemaVersion !== 3) fail('EVIDENCE_INTEGRITY');
  }
  return value;
}

function encodeSealedPayload(tenantHash, id, kind, serialized, keyId, keyBytes) {
  try {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', keyBytes, iv);
    const aad = Buffer.from(`event-intelligence:evidence:v1:${tenantHash}:${kind}:${id}`, 'utf8');
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(serialized, 'utf8'), cipher.final()]);
    const envelope = {
      version: 1,
      keyId,
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };
    return Buffer.from(JSON.stringify(envelope), 'utf8');
  } catch {
    fail('EVIDENCE_STORAGE');
  }
}

function decodeSealedEnvelope(envelopeBytes, tenantHash, id, kind) {
  let envelope;
  try { envelope = JSON.parse(envelopeBytes.toString('utf8')); } catch { fail('EVIDENCE_INTEGRITY'); }
  const safe = ownDataRecord(envelope, new Set(['version', 'keyId', 'iv', 'tag', 'ciphertext']));
  if (!safe || safe.version !== 1 || typeof safe.keyId !== 'string'
    || safe.keyId.length < 1 || safe.keyId.length > 128 || !/^[A-Za-z0-9._-]+$/.test(safe.keyId)
    || typeof safe.iv !== 'string' || safe.iv.length !== 16 || !/^[A-Za-z0-9+/]{16}$/.test(safe.iv)
    || typeof safe.tag !== 'string' || safe.tag.length !== 24 || !/^[A-Za-z0-9+/]{22}==$/.test(safe.tag)
    || typeof safe.ciphertext !== 'string') fail('EVIDENCE_INTEGRITY');
  base64DecodedByteLength(safe.ciphertext);
  return safe;
}

function decryptSealedPayload(envelope, tenantHash, id, kind, keyBytes, expectedPlaintextBytes) {
  let ciphertext;
  let plaintext;
  try {
    const decipher = createDecipheriv('aes-256-gcm', keyBytes, Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(Buffer.from(`event-intelligence:evidence:v1:${tenantHash}:${kind}:${id}`, 'utf8'));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    ciphertext = Buffer.from(envelope.ciphertext, 'base64');
    if (expectedPlaintextBytes !== undefined && ciphertext.byteLength !== expectedPlaintextBytes) fail('EVIDENCE_INTEGRITY');
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (expectedPlaintextBytes !== undefined && plaintext.byteLength !== expectedPlaintextBytes) fail('EVIDENCE_INTEGRITY');
    return JSON.parse(plaintext.toString('utf8'));
  } catch {
    fail('EVIDENCE_INTEGRITY');
  } finally {
    ciphertext?.fill(0);
    plaintext?.fill(0);
  }
}

function readSealedBundle(database, kind, id) {
  try {
    const maximum = kind === 'evidence'
      ? SELECTED_BATCH_LIMITS.evidenceSealedBytes
      : SELECTED_BATCH_LIMITS.factSealedBytes;
    const length = database.prepare('SELECT length(sealed) AS bytes FROM sealed_bundles WHERE kind = ? AND id = ?').get(kind, id);
    if (!length) fail('EVIDENCE_INTEGRITY');
    if (!Number.isSafeInteger(length.bytes) || length.bytes <= 0) fail('EVIDENCE_INTEGRITY');
    if (length.bytes > maximum) fail('EVIDENCE_INVALID');
    const row = database.prepare('SELECT sealed FROM sealed_bundles WHERE kind = ? AND id = ?').get(kind, id);
    if (!row || row.sealed.byteLength !== length.bytes) fail('EVIDENCE_INTEGRITY');
    return Buffer.from(row.sealed);
  } catch (error) {
    throw safePublicError(error);
  }
}

function preflightSelectedSealedBundleLengths(database, kind, ids, budget) {
  const maximum = kind === 'evidence'
    ? SELECTED_BATCH_LIMITS.evidenceSealedBytes
    : SELECTED_BATCH_LIMITS.factSealedBytes;
  const lengths = new Map();
  for (let start = 0; start < ids.length; start += 500) {
    const chunk = ids.slice(start, start + 500);
    const placeholders = chunk.map(() => '?').join(',');
    let rows;
    try {
      rows = database.prepare(`SELECT id, length(sealed) AS bytes FROM sealed_bundles WHERE kind = ? AND id IN (${placeholders})`)
        .all(kind, ...chunk);
    } catch (error) {
      throw safePublicError(error);
    }
    for (const row of rows) {
      if (!chunk.includes(row.id) || lengths.has(row.id)) fail('EVIDENCE_INTEGRITY');
      if (!Number.isSafeInteger(row.bytes) || row.bytes <= 0) fail('EVIDENCE_INTEGRITY');
      if (row.bytes > maximum) fail('EVIDENCE_INVALID');
      chargeBudget(budget, 'sealedBytes', row.bytes, SELECTED_BATCH_LIMITS.sealedBytes);
      lengths.set(row.id, row.bytes);
    }
  }
  if (lengths.size !== ids.length) fail('EVIDENCE_INTEGRITY');
  return lengths;
}

function copySelectedSealedBundles(database, kind, records, lengths) {
  for (const record of records) {
    try {
      const row = database.prepare('SELECT sealed FROM sealed_bundles WHERE kind = ? AND id = ?').get(kind, record.id);
      if (!row || row.sealed.byteLength !== lengths.get(record.id)) fail('EVIDENCE_INTEGRITY');
      record.sealed = Buffer.from(row.sealed);
    } catch (error) {
      throw safePublicError(error);
    }
  }
}

async function decryptSealedBundle(info, id, kind, sealedBytes, expectedKeyId, resolveKey, budget, signal) {
  if (sealedBytes.byteLength > (kind === 'evidence'
    ? SELECTED_BATCH_LIMITS.evidenceSealedBytes
    : SELECTED_BATCH_LIMITS.factSealedBytes)) fail('EVIDENCE_INVALID');
  const envelope = decodeSealedEnvelope(sealedBytes, info.tenantHash, id, kind);
  if (expectedKeyId && envelope.keyId !== expectedKeyId) fail('EVIDENCE_INTEGRITY');
  const plaintextBytes = base64DecodedByteLength(envelope.ciphertext);
  if (kind === 'evidence') {
    if (plaintextBytes > SELECTED_BATCH_LIMITS.evidenceDecryptedBytes) fail('EVIDENCE_INVALID');
  } else {
    if (plaintextBytes > SELECTED_BATCH_LIMITS.factRecordBytes) fail('EVIDENCE_INVALID');
    chargeBudget(budget, 'factBytes', plaintextBytes, SELECTED_BATCH_LIMITS.factBytes);
  }
  chargeBudget(budget, 'decryptedBytes', plaintextBytes, SELECTED_BATCH_LIMITS.decryptedBytes);
  const key = await resolveKey(info, kind === 'evidence' ? 'payload' : 'fact', envelope.keyId, signal);
  try {
    return decryptSealedPayload(envelope, info.tenantHash, id, kind, key.key, plaintextBytes);
  } finally {
    key.key.fill(0);
  }
}

function validateKeyResult(value, requestedKeyId) {
  const safe = ownDataRecord(value, new Set(['keyId', 'key']));
  if (!safe || typeof safe.keyId !== 'string' || safe.keyId.length < 1 || safe.keyId.length > 128
    || !/^[A-Za-z0-9._-]+$/.test(safe.keyId)) fail('EVIDENCE_KEY_UNAVAILABLE');
  if (requestedKeyId !== undefined && safe.keyId !== requestedKeyId) fail('EVIDENCE_KEY_UNAVAILABLE');
  if (typeof safe.key === 'string') fail('EVIDENCE_KEY_UNAVAILABLE');
  const key = copyBytes(safe.key, 64, false);
  if (key.length !== 32) fail('EVIDENCE_KEY_UNAVAILABLE');
  return { keyId: safe.keyId, key };
}

function validateRetentionResult(value, nowMs, maximumMs, upperBoundMs = Number.POSITIVE_INFINITY) {
  const safe = ownDataRecord(value, new Set(['expiresAtMs', 'policyId', 'policyVersion', 'accessPolicy']));
  if (!safe || !Number.isSafeInteger(safe.expiresAtMs) || safe.expiresAtMs <= nowMs || safe.expiresAtMs > 8_640_000_000_000_000
    || typeof safe.policyId !== 'string' || safe.policyId.length < 1 || safe.policyId.length > 120
    || typeof safe.policyVersion !== 'string' || safe.policyVersion.length < 1 || safe.policyVersion.length > 64
    || safe.accessPolicy !== 'tenant_private') fail('EVIDENCE_DENIED');
  const maxExpiry = nowMs + maximumMs;
  if (!Number.isSafeInteger(maxExpiry)) fail('EVIDENCE_INVALID');
  const expiresAtMs = Math.min(safe.expiresAtMs, maxExpiry, upperBoundMs);
  if (expiresAtMs <= nowMs) fail('EVIDENCE_DENIED');
  return Object.freeze({
    expiresAtMs,
    policyId: safe.policyId,
    policyVersion: safe.policyVersion,
    accessPolicy: 'tenant_private',
  });
}

function stableHmac(key, value) {
  return createHmac('sha256', key).update(value, 'utf8').digest('hex');
}

function assetUrlObservation(value, responseUrl) {
  if (typeof value !== 'string' || value.trim() === '' || value.length > 8_192 || !isWellFormed(value)) {
    return { normalizedSuggestion: null, fetchSuggestion: null, quarantineReason: 'invalid_or_empty' };
  }
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    return { normalizedSuggestion: null, fetchSuggestion: null, quarantineReason: 'url_policy_denied' };
  }
  const rawValue = value.trim();
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(rawValue)?.[1]?.toLowerCase() ?? null;
  if (scheme !== null && scheme !== 'http' && scheme !== 'https') {
    return { normalizedSuggestion: null, fetchSuggestion: null, quarantineReason: 'unsupported_scheme' };
  }
  if (rawValue.includes('\\')) {
    return { normalizedSuggestion: null, fetchSuggestion: null, quarantineReason: 'url_policy_denied' };
  }
  let policyInput = null;
  if (scheme !== null) {
    policyInput = rawValue;
  } else if (rawValue.startsWith('//')) {
    try {
      policyInput = `${new URL(responseUrl).protocol}${rawValue}`;
    } catch {
      return { normalizedSuggestion: null, fetchSuggestion: null, quarantineReason: 'unresolvable_url' };
    }
  }
  if (policyInput !== null) {
    try {
      // Check the original decoded authority before WHATWG URL parsing can
      // canonicalize alternate numeric hosts or non-canonical ports.
      parseAndValidateUrl(policyInput);
    } catch {
      return { normalizedSuggestion: null, fetchSuggestion: null, quarantineReason: 'url_policy_denied' };
    }
  }
  let observed;
  try {
    observed = new URL(rawValue, responseUrl);
  } catch {
    return { normalizedSuggestion: null, fetchSuggestion: null, quarantineReason: 'unresolvable_url' };
  }
  if (observed.protocol !== 'http:' && observed.protocol !== 'https:') {
    return { normalizedSuggestion: null, fetchSuggestion: null, quarantineReason: 'unsupported_scheme' };
  }
  if (hasSensitiveAssetQuery(observed)) {
    return { normalizedSuggestion: null, fetchSuggestion: null, quarantineReason: 'sensitive_query' };
  }
  try {
    const validated = parseAndValidateUrl(observed.href);
    return {
      normalizedSuggestion: observed.href,
      fetchSuggestion: validated.url.href,
      quarantineReason: null,
    };
  } catch {
    return { normalizedSuggestion: null, fetchSuggestion: null, quarantineReason: 'url_policy_denied' };
  }
}

function emptyAttributeNameForAssetForm(sourceForm) {
  if (sourceForm === 'html-img-src') return 'src';
  if (sourceForm === 'html-icon-link') return 'href';
  if (sourceForm === 'open-graph-image') return 'content';
  return null;
}

function emptyHtmlAttributeTokenState(bytes, expectedName) {
  if (!(bytes instanceof Uint8Array) || typeof expectedName !== 'string') return null;
  const token = Buffer.from(bytes).toString('utf8');
  if (!Buffer.from(token, 'utf8').equals(Buffer.from(bytes)) || !isWellFormed(token)) return null;
  let cursor = 0;
  while (cursor < token.length && !/[\t\n\f\r =/>]/.test(token[cursor])) cursor += 1;
  if (cursor === 0 || token.slice(0, cursor).toLowerCase() !== expectedName) return null;
  while (cursor < token.length && /[\t\n\f\r ]/.test(token[cursor])) cursor += 1;
  if (cursor === token.length) return 'missing';
  if (token[cursor] !== '=') return null;
  cursor += 1;
  while (cursor < token.length && /[\t\n\f\r ]/.test(token[cursor])) cursor += 1;
  if (cursor === token.length) return 'empty';
  const quote = token[cursor];
  return (quote === '"' || quote === "'") && token.slice(cursor) === `${quote}${quote}` ? 'empty' : null;
}

function hasSensitiveAssetQuery(value) {
  let parsed;
  try { parsed = value instanceof URL ? value : new URL(value); } catch { return true; }
  for (const key of parsed.searchParams.keys()) {
    if (ASSET_SENSITIVE_QUERY_KEY.test(key)) return true;
  }
  return false;
}

function assetDerivationMaterial(sourceContentHash, assetSource, positions) {
  return {
    bindingVersion: assetSource.bindingVersion,
    representation: ASSET_SOURCE_EXCERPT_REPRESENTATION,
    sourceContentHash,
    sourceUrl: assetSource.sourceUrl,
    sourceKind: assetSource.sourceKind,
    extractorVersion: assetSource.extractorVersion,
    selectorVersion: assetSource.selectorVersion,
    completeness: assetSource.completeness,
    limitations: assetSource.limitations,
    candidates: assetSource.candidates.map((candidate, index) => ({
      ...candidate,
      locator: positions[index].locator,
      excerptHash: positions[index].contentHash,
    })),
  };
}

function normalizeControlledAssetProvenance(value) {
  const raw = ownDataRecord(value, new Set([
    'schemaVersion', 'policyVersion', 'policyId', 'role', 'inspectionPolicyVersion',
    'sourceEvidenceId', 'sourceEvidenceVersion', 'sourceContentHash', 'sourceDerivationDigest',
    'sourceUrl', 'candidateId', 'positionIndex', 'sourceForm', 'sourceLocator', 'excerptHash', 'field', 'value',
    'assetUrl', 'sourceBytesHash', 'transformedBytesHash',
  ]));
  if (!raw || raw.schemaVersion !== 1 || raw.policyVersion !== CONTROLLED_ASSET_ACQUISITION_POLICY_VERSION
    || typeof raw.policyId !== 'string' || !/^[A-Za-z0-9._:-]{1,96}$/.test(raw.policyId)
    || !['fetched-source', 'transformed'].includes(raw.role)
    || raw.inspectionPolicyVersion !== 'svg-static-geometry/1'
    || !validUuid(raw.sourceEvidenceId) || !Number.isSafeInteger(raw.sourceEvidenceVersion) || raw.sourceEvidenceVersion < 1
    || !isDigest(raw.sourceContentHash) || !isDigest(raw.sourceDerivationDigest)
    || typeof raw.sourceUrl !== 'string' || raw.sourceUrl.length > 8_192
    || typeof raw.candidateId !== 'string' || !/^asset-[0-9]{2}$/.test(raw.candidateId)
    || !Number.isSafeInteger(raw.positionIndex) || raw.positionIndex < 0 || raw.positionIndex >= 64
    || !ASSET_SOURCE_FORMS.has(raw.sourceForm) || !isDigest(raw.excerptHash)
    || typeof raw.field !== 'string' || raw.field.length < 1 || raw.field.length > 160 || !isWellFormed(raw.field)
    || typeof raw.value !== 'string' || raw.value.length < 1 || raw.value.length > 8_192 || !isWellFormed(raw.value)
    || typeof raw.assetUrl !== 'string' || raw.assetUrl.length < 1 || raw.assetUrl.length > 8_192
    || typeof raw.sourceBytesHash !== 'string' || !isDigest(raw.sourceBytesHash)
    || !isDigest(raw.transformedBytesHash)) fail('EVIDENCE_INVALID');
  const copiedSourceLocator = copyLocator(raw.sourceLocator);
  if (copiedSourceLocator.kind !== 'text-range') fail('EVIDENCE_INVALID');
  // Receipt plaintext is wiped after sealing. Own a mutable locator here so
  // cleanup never attempts to mutate a frozen object returned by copyLocator.
  const sourceLocator = { ...copiedSourceLocator };
  const sourceUrl = raw.sourceUrl;
  validateUrl(sourceUrl);
  const assetUrl = validateUrl(raw.assetUrl).href;
  if (hasSensitiveAssetQuery(sourceUrl) || assetUrl !== raw.assetUrl || hasSensitiveAssetQuery(assetUrl)) fail('EVIDENCE_INVALID');
  return {
    schemaVersion: 1,
    policyVersion: raw.policyVersion,
    policyId: raw.policyId,
    role: raw.role,
    inspectionPolicyVersion: raw.inspectionPolicyVersion,
    sourceEvidenceId: raw.sourceEvidenceId,
    sourceEvidenceVersion: raw.sourceEvidenceVersion,
    sourceContentHash: raw.sourceContentHash,
    sourceDerivationDigest: raw.sourceDerivationDigest,
    sourceUrl,
    candidateId: raw.candidateId,
    positionIndex: raw.positionIndex,
    sourceForm: raw.sourceForm,
    sourceLocator,
    excerptHash: raw.excerptHash,
    field: raw.field,
    value: raw.value,
    assetUrl,
    sourceBytesHash: raw.sourceBytesHash,
    transformedBytesHash: raw.transformedBytesHash,
  };
}

function controlledAssetProvenanceMatchesBytes(provenance, bytes, contentHash) {
  if (!provenance || provenance.role === undefined || contentHash !== digest(bytes)) return false;
  return provenance.role === 'fetched-source'
    ? provenance.sourceBytesHash === contentHash && bytes.byteLength <= CONTROLLED_ASSET_MAX_SOURCE_BYTES
    : provenance.transformedBytesHash === contentHash && bytes.byteLength <= CONTROLLED_ASSET_MAX_TRANSFORMED_BYTES;
}

function controlledAssetSourceMatches(provenance, evidence) {
  const metadata = evidence?.metadata;
  const source = evidence?.source;
  const matches = source?.assetSource?.candidates?.filter((entry) => entry.candidateId === provenance?.candidateId) ?? [];
  const candidate = evidence?.candidate ?? (matches.length === 1 ? matches[0] : null);
  const excerptPosition = candidate ? evidence.positions?.[candidate.positionIndex] : null;
  let excerptMatches = false;
  if (typeof candidate?.value === 'string') {
    const bytes = Buffer.from(candidate.value, 'utf8');
    excerptMatches = isWellFormed(candidate.value) && bytes.toString('utf8') === candidate.value
      && digest(bytes) === provenance?.excerptHash && candidate.value === provenance?.value;
    bytes.fill(0);
  } else if (excerptPosition?.contentBase64 && excerptPosition.contentHash === provenance?.excerptHash) {
    try {
      const excerpt = Buffer.from(excerptPosition.contentBase64, 'base64');
      excerptMatches = excerpt.toString('base64') === excerptPosition.contentBase64
        && digest(excerpt) === provenance.excerptHash
        && excerpt.toString('utf8') === provenance.value
        && Buffer.from(provenance.value, 'utf8').equals(excerpt);
      excerpt.fill(0);
    } catch {
      excerptMatches = false;
    }
  } else if (excerptPosition && excerptPosition.contentHash === provenance?.excerptHash) {
    // Generic materialization deliberately omits excerpt bytes. Callers that
    // authenticate controlled purpose must separately reopen the exact stored
    // candidate with readAssetSourceCandidateBinding before accepting it.
    excerptMatches = true;
  }
  return Boolean(provenance && metadata && source && candidate && excerptMatches
    && metadata.evidenceId === provenance.sourceEvidenceId
    && metadata.version === provenance.sourceEvidenceVersion
    && metadata.contentHash === provenance.sourceContentHash
    && metadata.representation === ASSET_SOURCE_EXCERPT_REPRESENTATION
    && metadata.derivationDigest === provenance.sourceDerivationDigest
    && source.sourceUrl === provenance.sourceUrl
    && source.contentHash === provenance.sourceContentHash
    && source.redirectChain.length === 0
    && source.assetSource.derivationDigest === provenance.sourceDerivationDigest
    && candidate.positionIndex === provenance.positionIndex
    && candidate.sourceForm === provenance.sourceForm
    && candidate.field === provenance.field
    && candidate.fetchSuggestion === provenance.assetUrl
    && candidate.quarantineReason === null
    && candidate.excerptHash === provenance.excerptHash
    && JSON.stringify(candidate.locator) === JSON.stringify(provenance.sourceLocator));
}

function normalizeAssetAcquisitionBinding(value) {
  const raw = ownDataRecord(value, new Set([
    'schemaVersion', 'policyVersion', 'policyId', 'sourceEvidenceId', 'sourceEvidenceVersion',
    'sourceContentHash', 'sourceDerivationDigest', 'sourceUrl', 'candidateId', 'positionIndex',
    'sourceForm', 'sourceLocator', 'excerptHash', 'field', 'value', 'assetUrl',
  ]));
  if (!raw || raw.schemaVersion !== 1 || raw.policyVersion !== CONTROLLED_ASSET_ACQUISITION_POLICY_VERSION
    || typeof raw.policyId !== 'string' || !/^[A-Za-z0-9._:-]{1,96}$/.test(raw.policyId)
    || !validUuid(raw.sourceEvidenceId) || !Number.isSafeInteger(raw.sourceEvidenceVersion) || raw.sourceEvidenceVersion < 1
    || !isDigest(raw.sourceContentHash) || !isDigest(raw.sourceDerivationDigest)
    || typeof raw.sourceUrl !== 'string' || raw.sourceUrl.length > 8_192
    || typeof raw.candidateId !== 'string' || !/^asset-[0-9]{2}$/.test(raw.candidateId)
    || !Number.isSafeInteger(raw.positionIndex) || raw.positionIndex < 0 || raw.positionIndex >= 64
    || !ASSET_SOURCE_FORMS.has(raw.sourceForm) || !isDigest(raw.excerptHash)
    || typeof raw.field !== 'string' || raw.field.length < 1 || raw.field.length > 160 || !isWellFormed(raw.field)
    || typeof raw.value !== 'string' || raw.value.length < 1 || raw.value.length > 8_192 || !isWellFormed(raw.value)
    || typeof raw.assetUrl !== 'string' || raw.assetUrl.length < 1 || raw.assetUrl.length > 8_192) fail('EVIDENCE_INVALID');
  const copiedSourceLocator = copyLocator(raw.sourceLocator);
  if (copiedSourceLocator.kind !== 'text-range') fail('EVIDENCE_INVALID');
  const sourceLocator = { ...copiedSourceLocator };
  const sourceUrl = raw.sourceUrl;
  validateUrl(sourceUrl);
  const assetUrl = validateUrl(raw.assetUrl).href;
  if (assetUrl !== raw.assetUrl || hasSensitiveAssetQuery(sourceUrl) || hasSensitiveAssetQuery(assetUrl)) fail('EVIDENCE_INVALID');
  return {
    schemaVersion: 1,
    policyVersion: raw.policyVersion,
    policyId: raw.policyId,
    sourceEvidenceId: raw.sourceEvidenceId,
    sourceEvidenceVersion: raw.sourceEvidenceVersion,
    sourceContentHash: raw.sourceContentHash,
    sourceDerivationDigest: raw.sourceDerivationDigest,
    sourceUrl,
    candidateId: raw.candidateId,
    positionIndex: raw.positionIndex,
    sourceForm: raw.sourceForm,
    sourceLocator,
    excerptHash: raw.excerptHash,
    field: raw.field,
    value: raw.value,
    assetUrl,
  };
}

function normalizeAssetSuggestionBindings(value) {
  const suggestions = safeArray(value, 16);
  if (!suggestions) fail('EVIDENCE_INVALID');
  const normalized = suggestions.map(normalizeAssetAcquisitionBinding);
  const keys = normalized.map((item) => JSON.stringify([item.sourceEvidenceId, item.candidateId, item.assetUrl]));
  if (new Set(keys).size !== keys.length || new Set(normalized.map((item) => item.assetUrl)).size !== normalized.length) {
    fail('EVIDENCE_INVALID');
  }
  return normalized;
}

function normalizeAssetAcquisitionCompletion(value) {
  const raw = ownDataRecord(value, new Set([
    'schemaVersion', 'policyVersion', 'inspectionPolicyVersion', 'binding',
    'sourceBytesHash', 'transformedBytesHash', 'originalEvidence', 'transformedEvidence',
  ]));
  if (!raw || raw.schemaVersion !== 1 || raw.policyVersion !== CONTROLLED_ASSET_ACQUISITION_POLICY_VERSION
    || raw.inspectionPolicyVersion !== 'svg-static-geometry/1'
    || !isDigest(raw.sourceBytesHash) || !isDigest(raw.transformedBytesHash)) fail('EVIDENCE_INVALID');
  const binding = normalizeAssetAcquisitionBinding(raw.binding);
  const evidence = (input) => {
    const item = ownDataRecord(input, new Set(['evidenceId', 'version', 'contentHash', 'byteLength']));
    if (!item || !validUuid(item.evidenceId) || !Number.isSafeInteger(item.version) || item.version < 1
      || !isDigest(item.contentHash) || !Number.isSafeInteger(item.byteLength) || item.byteLength < 1
      || item.byteLength > CONTROLLED_ASSET_MAX_TRANSFORMED_BYTES) fail('EVIDENCE_INVALID');
    return { evidenceId: item.evidenceId, version: item.version, contentHash: item.contentHash, byteLength: item.byteLength };
  };
  const originalEvidence = evidence(raw.originalEvidence);
  const transformedEvidence = evidence(raw.transformedEvidence);
  if (originalEvidence.evidenceId === transformedEvidence.evidenceId
    || originalEvidence.contentHash !== raw.sourceBytesHash
    || transformedEvidence.contentHash !== raw.transformedBytesHash
    || originalEvidence.byteLength > CONTROLLED_ASSET_MAX_SOURCE_BYTES) fail('EVIDENCE_INVALID');
  return {
    schemaVersion: 1,
    policyVersion: raw.policyVersion,
    inspectionPolicyVersion: raw.inspectionPolicyVersion,
    binding,
    sourceBytesHash: raw.sourceBytesHash,
    transformedBytesHash: raw.transformedBytesHash,
    originalEvidence,
    transformedEvidence,
  };
}

function validateAssetReceiptCrossBinding(candidateBinding, acquisition, evidenceRefs, outcome = null, code = 'EVIDENCE_INVALID') {
  if (candidateBinding === undefined && acquisition === undefined) return;
  if (candidateBinding && !acquisition && ['failed', 'access_restricted'].includes(outcome)) {
    const reference = evidenceRefs.find((item) => item.evidenceId === candidateBinding.sourceEvidenceId);
    if (!reference || reference.version !== candidateBinding.sourceEvidenceVersion
      || reference.contentHash !== candidateBinding.sourceContentHash
      || reference.representation !== ASSET_SOURCE_EXCERPT_REPRESENTATION
      || reference.derivationDigest !== candidateBinding.sourceDerivationDigest) fail(code);
    return;
  }
  if (!candidateBinding || !acquisition
    || JSON.stringify(candidateBinding) !== JSON.stringify(acquisition.binding)) fail(code);
  const byId = new Map(evidenceRefs.map((item) => [item.evidenceId, item]));
  for (const artifact of [acquisition.originalEvidence, acquisition.transformedEvidence]) {
    const reference = byId.get(artifact.evidenceId);
    if (!reference || reference.version !== artifact.version || reference.contentHash !== artifact.contentHash
      || reference.representation !== 'raw' || reference.derivationDigest !== null
      || reference.positions.length < 1 || reference.positions.length > 128) fail(code);
    let endByte = 0;
    for (const position of reference.positions) {
      if (position.locator.kind !== 'text-range' || position.locator.startByte !== endByte
        || position.locator.endByte <= endByte) fail(code);
      endByte = position.locator.endByte;
    }
    if (endByte !== artifact.byteLength) fail(code);
  }
}

function validateAssetReceiptMaterialized(candidateBinding, acquisition, evidenceViews, outcome = null, code = 'EVIDENCE_INVALID') {
  if (candidateBinding === undefined && acquisition === undefined) return;
  if (!candidateBinding || (!acquisition && !['failed', 'access_restricted'].includes(outcome))) fail(code);
  const byId = new Map(evidenceViews.map((item) => [item.metadata.evidenceId, item]));
  const source = byId.get(candidateBinding.sourceEvidenceId);
  if (!controlledAssetSourceMatches(candidateBinding, source)) fail(code);
  if (!acquisition) return;
  for (const [artifact, role, hash] of [
    [acquisition.originalEvidence, 'fetched-source', acquisition.sourceBytesHash],
    [acquisition.transformedEvidence, 'transformed', acquisition.transformedBytesHash],
  ]) {
    const view = byId.get(artifact.evidenceId);
    const controlled = view?.source?.controlledAsset;
    if (!view || view.metadata.version !== artifact.version || view.metadata.contentHash !== artifact.contentHash
      || artifact.contentHash !== hash || view.source.sourceUrl !== candidateBinding.assetUrl
      || view.source.redirectChain.length !== 0 || view.source.contentType.toLowerCase().split(';', 1)[0].trim() !== 'image/svg+xml'
      || !controlled || controlled.role !== role
      || controlled.policyVersion !== candidateBinding.policyVersion
      || controlled.policyId !== candidateBinding.policyId
      || controlled.sourceEvidenceId !== candidateBinding.sourceEvidenceId
      || controlled.sourceEvidenceVersion !== candidateBinding.sourceEvidenceVersion
      || controlled.sourceContentHash !== candidateBinding.sourceContentHash
      || controlled.sourceDerivationDigest !== candidateBinding.sourceDerivationDigest
      || controlled.candidateId !== candidateBinding.candidateId
      || controlled.positionIndex !== candidateBinding.positionIndex
      || controlled.sourceForm !== candidateBinding.sourceForm
      || JSON.stringify(controlled.sourceLocator) !== JSON.stringify(candidateBinding.sourceLocator)
      || controlled.excerptHash !== candidateBinding.excerptHash
      || controlled.field !== candidateBinding.field || controlled.value !== candidateBinding.value
      || controlled.assetUrl !== candidateBinding.assetUrl
      || controlled.sourceBytesHash !== acquisition.sourceBytesHash
      || controlled.transformedBytesHash !== acquisition.transformedBytesHash) fail(code);
  }
}

function validateAssetSuggestionBindings(assetSuggestions, suggestions, evidenceRefs, evidenceViews,
  code = 'EVIDENCE_INVALID') {
  const byId = new Map(evidenceRefs.map((item) => [item.evidenceId, item]));
  const materializedById = new Map(evidenceViews.map((item) => [item.metadata.evidenceId, item]));
  for (const binding of assetSuggestions) {
    const reference = byId.get(binding.sourceEvidenceId);
    const materialized = materializedById.get(binding.sourceEvidenceId);
    if (!reference || reference.version !== binding.sourceEvidenceVersion
      || reference.contentHash !== binding.sourceContentHash
      || reference.representation !== ASSET_SOURCE_EXCERPT_REPRESENTATION
      || reference.derivationDigest !== binding.sourceDerivationDigest) fail(code);
    if (!controlledAssetSourceMatches(binding, materialized)) fail(code);
    const ref = {
      evidenceId: binding.sourceEvidenceId,
      contentHash: binding.sourceContentHash,
      locator: binding.sourceLocator,
      field: binding.field,
      value: binding.assetUrl,
    };
    const found = suggestions.some((suggestion) => suggestion.url === binding.assetUrl
      && suggestion.sourceRefs.some((candidateRef) => JSON.stringify(candidateRef) === JSON.stringify(ref)));
    if (!found) fail(code);
  }
}

function assetJsonPointerParts(value) {
  if (typeof value !== 'string' || value.length > 2_048 || !isWellFormed(value)
    || (value !== '' && !value.startsWith('/')) || /~(?![01])/.test(value)) return null;
  if (value === '') return [];
  return value.slice(1).split('/').map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'));
}

function validAssetJsonPath(parts, sourceForm) {
  let cursor = 0;
  while (/^(?:0|[1-9][0-9]*)$/.test(parts[cursor] ?? '')) cursor += 1;
  const expectedProperty = sourceForm === 'jsonld-logo' ? 'logo' : 'image';
  if (parts[cursor]?.toLowerCase() !== expectedProperty) return false;
  cursor += 1;
  while (/^(?:0|[1-9][0-9]*)$/.test(parts[cursor] ?? '')) cursor += 1;
  if (cursor === parts.length) return true;
  return ['url', 'contenturl', '@id'].includes(parts[cursor]?.toLowerCase()) && cursor + 1 === parts.length;
}

function validAssetAssociation(value, sourceForm) {
  if (!isRecord(value)) return false;
  if (value.kind === 'unassigned-page') {
    return Object.keys(value).length === 1
      && ['html-img-src', 'html-icon-link', 'open-graph-image'].includes(sourceForm);
  }
  if (value.kind === 'entity-source-claim') {
    const entityPointerParts = assetJsonPointerParts(value.entityPointer);
    const assetPointerParts = assetJsonPointerParts(value.assetPointer);
    return Object.keys(value).length === 6
      && ['jsonld-image', 'jsonld-logo'].includes(sourceForm)
      && ['event', 'organization'].includes(value.entityKind)
      && typeof value.entityId === 'string' && value.entityId.length > 0 && value.entityId.length <= 4_096
      && Number.isSafeInteger(value.blockIndex) && value.blockIndex >= 0 && value.blockIndex < 32
      && entityPointerParts !== null && assetPointerParts !== null && assetPointerParts.length > entityPointerParts.length
      && entityPointerParts.every((part, index) => assetPointerParts[index] === part)
      && value.entityId === `${value.entityKind}:script-${value.blockIndex}:${value.entityPointer}`
      && validAssetJsonPath(assetPointerParts.slice(entityPointerParts.length), sourceForm);
  }
  if (value.kind === 'nested-entity-source-claim') {
    const parentPointerParts = assetJsonPointerParts(value.parentPointer);
    const assetPointerParts = assetJsonPointerParts(value.assetPointer);
    const entityId = typeof value.parentEntityId === 'string'
      ? /^event:script-(0|[1-9][0-9]*):(.*)$/.exec(value.parentEntityId)
      : null;
    const relative = parentPointerParts && assetPointerParts
      && parentPointerParts.length < assetPointerParts.length
      && parentPointerParts.every((part, index) => assetPointerParts[index] === part)
      ? assetPointerParts.slice(parentPointerParts.length)
      : null;
    let organizerIndex = 0;
    while (/^(?:0|[1-9][0-9]*)$/.test(relative?.[organizerIndex] ?? '')) organizerIndex += 1;
    return Object.keys(value).length === 6
      && ['jsonld-image', 'jsonld-logo'].includes(sourceForm)
      && value.parentEntityKind === 'event'
      && typeof value.parentEntityId === 'string' && value.parentEntityId.length > 0 && value.parentEntityId.length <= 4_096
      && value.roleHint === 'organizer'
      && parentPointerParts !== null && assetPointerParts !== null && relative !== null
      && entityId !== null && Number(entityId[1]) < 32 && entityId[2] === value.parentPointer
      && relative[organizerIndex]?.toLowerCase() === 'organizer'
      && validAssetJsonPath(relative.slice(organizerIndex + 1), sourceForm);
  }
  return false;
}

function validateAssetSourceProvenance(value, record, sourceUrl, positionsById, budget) {
  const stored = ownDataRecord(value, new Set([
    'bindingVersion', 'selectorVersion', 'extractorVersion', 'sourceUrl', 'sourceKind',
    'completeness', 'limitations', 'candidates', 'derivationDigest',
  ]));
  const profile = stored && ASSET_SOURCE_READ_PROFILES.get(`${stored.selectorVersion}\u0000${stored.extractorVersion}`);
  if (!stored || stored.bindingVersion !== ASSET_SOURCE_BINDING_VERSION
    || !profile
    || stored.sourceUrl !== sourceUrl || stored.sourceKind !== 'external'
    || stored.completeness !== profile.completeness
    || !Array.isArray(stored.limitations)
    || JSON.stringify(stored.limitations) !== JSON.stringify(profile.limitations)
    || !isDigest(stored.derivationDigest) || stored.derivationDigest !== record.derivationDigest) fail('EVIDENCE_INTEGRITY');
  try {
    parseAndValidateUrl(stored.sourceUrl);
    if (hasSensitiveAssetQuery(stored.sourceUrl)) fail('EVIDENCE_INTEGRITY');
  } catch { fail('EVIDENCE_INTEGRITY'); }
  const candidates = safeArray(stored.candidates, ASSET_SOURCE_MAX_POSITIONS);
  if (!candidates || candidates.length !== record.positionIds.length || candidates.length === 0) fail('EVIDENCE_INTEGRITY');
  const validated = [];
  const emptyAttributeTokenChecks = [];
  let previousStart = -1;
  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = ownDataRecord(candidates[index], new Set([
      'candidateId', 'positionIndex', 'sourceForm', 'field', 'relationHint', 'association',
      'locator', 'excerptHash', 'normalizedSuggestion', 'fetchSuggestion', 'quarantineReason',
      'role', 'permission', 'inspection', 'excerptKind',
    ]));
    const positionId = record.positionIds[index];
    const position = positionsById.get(positionId);
    const locator = candidate ? copyLocator(candidate.locator) : null;
    if (!candidate || !position || candidate.candidateId !== `asset-${String(index + 1).padStart(2, '0')}`
      || candidate.positionIndex !== index || !ASSET_SOURCE_FORMS.has(candidate.sourceForm)
      || typeof candidate.field !== 'string' || candidate.field.length < 1 || candidate.field.length > 160
      || (candidate.relationHint !== null && (typeof candidate.relationHint !== 'string' || candidate.relationHint.length > 80))
      || !validAssetAssociation(candidate.association, candidate.sourceForm)
      || locator?.kind !== 'text-range' || locator.startByte < previousStart
      || JSON.stringify(locator) !== JSON.stringify(position.locator)
      || position.byteLength !== locator.endByte - locator.startByte
      || !isDigest(candidate.excerptHash) || candidate.excerptHash !== position.contentHash
      || (candidate.normalizedSuggestion !== null && typeof candidate.normalizedSuggestion !== 'string')
      || (candidate.fetchSuggestion !== null && typeof candidate.fetchSuggestion !== 'string')
      || (candidate.quarantineReason !== null && !ASSET_QUARANTINE_REASONS.has(candidate.quarantineReason))
      || (candidate.quarantineReason === null) !== (candidate.fetchSuggestion !== null)
      || (candidate.role !== 'unknown' || candidate.permission !== 'unknown' || candidate.inspection !== 'pending')) {
      fail('EVIDENCE_INTEGRITY');
    }
    const hasExcerptKind = profile.selectorVersion === 'ei-asset-source-selector/3'
      || profile.selectorVersion === 'ei-asset-source-selector/4'
      || profile.selectorVersion === 'ei-asset-source-selector/5'
      || profile.selectorVersion === 'ei-asset-source-selector/6';
    if (hasExcerptKind) {
      if (!Object.hasOwn(candidate, 'excerptKind')
        || !['url-value', 'html-empty-attribute-token'].includes(candidate.excerptKind)) fail('EVIDENCE_INTEGRITY');
      if (candidate.excerptKind === 'html-empty-attribute-token') {
        const attributeName = emptyAttributeNameForAssetForm(candidate.sourceForm);
        const encodedContent = position.contentBase64;
        if (!attributeName || typeof encodedContent !== 'string'
          || candidate.quarantineReason !== 'invalid_or_empty'
          || candidate.normalizedSuggestion !== null || candidate.fetchSuggestion !== null) fail('EVIDENCE_INTEGRITY');
        emptyAttributeTokenChecks.push({ position, attributeName });
      }
    } else if (Object.hasOwn(candidate, 'excerptKind')) {
      fail('EVIDENCE_INTEGRITY');
    }
    if (candidate.fetchSuggestion !== null) {
      try {
        const valid = parseAndValidateUrl(candidate.fetchSuggestion).url.href;
        if (valid !== candidate.fetchSuggestion || candidate.fetchSuggestion.includes('#')) fail('EVIDENCE_INTEGRITY');
      } catch { fail('EVIDENCE_INTEGRITY'); }
      let suggestion;
      try { suggestion = new URL(candidate.normalizedSuggestion); } catch { fail('EVIDENCE_INTEGRITY'); }
      if (suggestion.href !== candidate.normalizedSuggestion || (suggestion.protocol !== 'http:' && suggestion.protocol !== 'https:')) {
        fail('EVIDENCE_INTEGRITY');
      }
      for (const key of suggestion.searchParams.keys()) {
        if (ASSET_SENSITIVE_QUERY_KEY.test(key)) fail('EVIDENCE_INTEGRITY');
      }
      let normalizedFetchSuggestion;
      try { normalizedFetchSuggestion = parseAndValidateUrl(suggestion.href).url.href; } catch { fail('EVIDENCE_INTEGRITY'); }
      if (normalizedFetchSuggestion !== candidate.fetchSuggestion) fail('EVIDENCE_INTEGRITY');
    } else if (candidate.normalizedSuggestion !== null) {
      fail('EVIDENCE_INTEGRITY');
    }
    previousStart = locator.startByte;
    const copy = {
      candidateId: candidate.candidateId,
      positionIndex: candidate.positionIndex,
      sourceForm: candidate.sourceForm,
      field: candidate.field,
      relationHint: candidate.relationHint,
      association: cloneJsonValue(candidate.association),
      locator,
      excerptHash: candidate.excerptHash,
      ...(hasExcerptKind ? { excerptKind: candidate.excerptKind } : {}),
      normalizedSuggestion: candidate.normalizedSuggestion,
      fetchSuggestion: candidate.fetchSuggestion,
      quarantineReason: candidate.quarantineReason,
      role: 'unknown',
      permission: 'unknown',
      inspection: 'pending',
    };
    addProvenanceBytes(budget, Buffer.byteLength(JSON.stringify(copy), 'utf8'));
    validated.push(copy);
  }
  const assetSourceMetadata = {
    bindingVersion: stored.bindingVersion,
    selectorVersion: stored.selectorVersion,
    extractorVersion: stored.extractorVersion,
    sourceUrl: stored.sourceUrl,
    sourceKind: stored.sourceKind,
    completeness: stored.completeness,
    limitations: [...stored.limitations],
    candidates: validated,
  };
  if (Buffer.byteLength(JSON.stringify(assetSourceMetadata), 'utf8') > ASSET_SOURCE_MAX_METADATA_BYTES) fail('EVIDENCE_INTEGRITY');
  const assetSource = {
    ...assetSourceMetadata,
    derivationDigest: stored.derivationDigest,
  };
  const expectedDigest = digest(Buffer.from(JSON.stringify(assetDerivationMaterial(record.contentHash, assetSource, record.positionIds.map((id) => ({
    locator: positionsById.get(id).locator,
    contentHash: positionsById.get(id).contentHash,
  })))), 'utf8'));
  if (expectedDigest !== record.derivationDigest) fail('EVIDENCE_INTEGRITY');
  for (const { position, attributeName } of emptyAttributeTokenChecks) {
    let excerpt;
    try {
      excerpt = Buffer.from(position.contentBase64, 'base64');
      if (excerpt.byteLength !== position.byteLength || emptyHtmlAttributeTokenState(excerpt, attributeName) === null) {
        fail('EVIDENCE_INTEGRITY');
      }
    } finally {
      excerpt?.fill(0);
    }
  }
  return deepFreeze(assetSource);
}

function frozenMetadata(record) {
  if (record.state === 'expired') return Object.freeze({ evidenceId: record.id, state: 'expired', positionCount: 0 });
  return Object.freeze({
    evidenceId: record.id,
    version: record.version,
    previousEvidenceId: record.previousId ?? null,
    contentHash: record.contentHash,
    duplicateGroupId: record.duplicateGroupId,
    retrievedAt: record.retrievedAt,
    createdAt: record.createdAt,
    expiresAt: new Date(record.expiresAtMs).toISOString(),
    policyId: record.policyId,
    policyVersion: record.policyVersion,
    accessPolicy: 'tenant_private',
    state: record.state,
    positionCount: record.positionIds?.length ?? 0,
    ...(record.representation === PDF_DERIVED_REPRESENTATION || record.representation === ASSET_SOURCE_EXCERPT_REPRESENTATION ? {
      representation: record.representation,
      derivationDigest: record.derivationDigest,
    } : {}),
  });
}

function validUuid(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function scopeInfo(scope) {
  const info = TENANT_SCOPES.get(scope);
  if (!info) fail('EVIDENCE_DENIED');
  return info;
}

function evidenceInfo(scope, handle) {
  const info = scopeInfo(scope);
  const reference = EVIDENCE_HANDLES.get(handle);
  if (!reference || reference.tenantHash !== info.tenantHash || reference.tenantId !== info.tenantId) fail('EVIDENCE_DENIED');
  return { ...info, evidenceId: reference.evidenceId };
}

function newEvidenceHandle(info, evidenceId) {
  const handle = makeOpaque();
  EVIDENCE_HANDLES.set(handle, Object.freeze({ tenantId: info.tenantId, tenantHash: info.tenantHash, evidenceId }));
  return handle;
}

function newPositionHandle(info, evidenceId, positionId, sourceKind, representation = 'raw') {
  const handle = makeOpaque();
  POSITION_HANDLES.set(handle, Object.freeze({ tenantId: info.tenantId, tenantHash: info.tenantHash, evidenceId, positionId, sourceKind, representation }));
  return handle;
}

function newFactHandle(info, factId) {
  const handle = makeOpaque();
  FACT_HANDLES.set(handle, Object.freeze({ tenantId: info.tenantId, tenantHash: info.tenantHash, factId }));
  return handle;
}

function validateFactField(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 160 || !/^[A-Za-z0-9_.:-]+$/.test(value)) fail('EVIDENCE_INVALID');
  return value;
}

function validateMethod(value, required) {
  if (value === undefined && !required) return null;
  const safe = ownDataRecord(value, new Set(['name', 'version']));
  if (!safe || typeof safe.name !== 'string' || safe.name.length < 1 || safe.name.length > 120
    || typeof safe.version !== 'string' || safe.version.length < 1 || safe.version.length > 64) fail('EVIDENCE_INVALID');
  return Object.freeze({ name: safe.name, version: safe.version });
}

function extractValue(input, cloneBudget) {
  const value = ownDataRecord(input, new Set([
    'rawValue', 'normalizedValue', 'precision', 'field', 'status', 'supports', 'method', 'reason', 'candidates', 'originStatus',
  ]));
  if (!value || !Object.hasOwn(value, 'rawValue') || !Object.hasOwn(value, 'normalizedValue')) fail('EVIDENCE_INVALID');
  const rawValue = cloneJsonValue(value.rawValue, 0, cloneBudget);
  const normalizedValue = cloneJsonValue(value.normalizedValue, 0, cloneBudget);
  let precision;
  if (Object.hasOwn(value, 'precision')) {
    if (!FACT_PRECISIONS.has(value.precision)) fail('EVIDENCE_INVALID');
    precision = value.precision;
  }
  return Object.freeze({ rawValue, normalizedValue, ...(precision ? { precision } : {}) });
}

function extractSupports(value, maximum = 64) {
  const items = safeArray(value, maximum);
  if (!items) fail('EVIDENCE_INVALID');
  const result = [];
  for (const item of items) {
    const support = ownDataRecord(item, new Set(['evidence', 'position', 'contentHash']));
    if (!support || !isDigest(support.contentHash)) fail('EVIDENCE_INVALID');
    result.push(support);
  }
  return result;
}

function freezeFact(value) {
  return deepFreeze(value);
}

export function createEvidenceStore(options) {
  const config = ownDataRecord(options, new Set([
    'directory', 'resolveTenant', 'resolveKey', 'resolveRetention', 'authorizePrivateAccess',
    'authorizePrivateAccessCurrent', 'consumePrivatePayload',
    'now', 'maxSourceBytes', 'maxPositionBytes', 'maxPositionCount', 'maxStoredPayloadBytes', 'maxRetentionMs',
    'lockTimeoutMs',
  ]));
  if (!config || typeof config.directory !== 'string' || config.directory.length === 0
    || typeof config.resolveTenant !== 'function' || typeof config.resolveKey !== 'function'
    || typeof config.resolveRetention !== 'function') fail('EVIDENCE_INVALID');
  if (config.authorizePrivateAccess !== undefined && typeof config.authorizePrivateAccess !== 'function') fail('EVIDENCE_INVALID');
  if (config.authorizePrivateAccessCurrent !== undefined && typeof config.authorizePrivateAccessCurrent !== 'function') fail('EVIDENCE_INVALID');
  if (config.consumePrivatePayload !== undefined && typeof config.consumePrivatePayload !== 'function') fail('EVIDENCE_INVALID');
  const limits = {
    now: config.now ?? (() => Date.now()),
    maxSourceBytes: config.maxSourceBytes ?? 5 * 1024 * 1024,
    maxPositionBytes: config.maxPositionBytes ?? 64 * 1024,
    maxPositionCount: config.maxPositionCount ?? 128,
    maxStoredPayloadBytes: config.maxStoredPayloadBytes ?? 512 * 1024,
    maxRetentionMs: config.maxRetentionMs ?? 30 * 24 * 60 * 60 * 1000,
    lockTimeoutMs: config.lockTimeoutMs ?? 5_000,
  };
  for (const [key, value] of Object.entries(limits)) {
    if (key !== 'now' && (!Number.isSafeInteger(value) || value <= 0)) fail('EVIDENCE_INVALID');
  }
  if (typeof limits.now !== 'function') fail('EVIDENCE_INVALID');

  const rootDirectory = path.resolve(config.directory);

  function currentTime() {
    let time;
    try { time = limits.now(); } catch { fail('EVIDENCE_STORAGE'); }
    if (!Number.isSafeInteger(time) || time < 0) fail('EVIDENCE_STORAGE');
    return time;
  }

  async function tenantDirectory(info) {
    try {
      await mkdir(rootDirectory, { recursive: true, mode: 0o700 });
      const rootStats = await lstat(rootDirectory);
      if (rootStats.isSymbolicLink() || !rootStats.isDirectory()) fail('EVIDENCE_STORAGE');
      await chmod(rootDirectory, 0o700);
      const directory = path.join(rootDirectory, info.tenantHash);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const stats = await lstat(directory);
      if (stats.isSymbolicLink() || !stats.isDirectory()) fail('EVIDENCE_STORAGE');
      await chmod(directory, 0o700);
      return directory;
    } catch (error) {
      throw safePublicError(error);
    }
  }

  function readManifest(database, tenantHash) {
    try {
      const length = database.prepare('SELECT length(CAST(document AS BLOB)) AS bytes FROM evidence_manifest WHERE tenant_hash = ?').get(tenantHash);
      if (!length) return emptyManifest(tenantHash);
      if (!Number.isSafeInteger(length.bytes) || length.bytes <= 0) fail('EVIDENCE_INTEGRITY');
      if (length.bytes > 16 * 1024 * 1024) fail('EVIDENCE_INTEGRITY');
      const row = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(tenantHash);
      if (!row || Buffer.byteLength(row.document, 'utf8') !== length.bytes) fail('EVIDENCE_INTEGRITY');
      let value;
      try { value = JSON.parse(row.document); } catch { fail('EVIDENCE_INTEGRITY'); }
      return validateManifest(value, tenantHash);
    } catch (error) {
      throw safePublicError(error);
    }
  }

  function writeManifest(database, manifest) {
    try {
      const document = JSON.stringify(manifest);
      if (Buffer.byteLength(document, 'utf8') > 16 * 1024 * 1024) fail('EVIDENCE_STORAGE');
      database.prepare(`INSERT INTO evidence_manifest (tenant_hash, document) VALUES (?, ?)
        ON CONFLICT (tenant_hash) DO UPDATE SET document = excluded.document`).run(manifest.tenantHash, document);
    } catch (error) {
      throw safePublicError(error);
    }
  }

  function privateReceiptKey(info, runId, candidateId) {
    return digest(Buffer.from(`event-intelligence:private-receipt:v1\0${info.tenantHash}\0${runId}\0${candidateId}`, 'utf8'));
  }

  async function sealPrivateReceipt(info, receiptKey, value, signal) {
    let serialized;
    try { serialized = JSON.stringify(value); } catch { fail('EVIDENCE_INVALID'); }
    if (typeof serialized !== 'string') fail('EVIDENCE_INVALID');
    const plaintext = Buffer.from(serialized, 'utf8');
    let key;
    try {
      if (plaintext.byteLength <= 0 || plaintext.byteLength > PRIVATE_RECEIPT_MAX_PLAINTEXT_BYTES) fail('EVIDENCE_INVALID');
      const payloadHash = digest(plaintext);
      key = await resolveKey(info, 'payload', undefined, signal);
      const sealed = encodeSealedPayload(info.tenantHash, receiptKey, PRIVATE_RECEIPT_KIND, serialized, key.keyId, key.key);
      if (sealed.byteLength > PRIVATE_RECEIPT_MAX_ENVELOPE_BYTES) {
        sealed.fill(0);
        fail('EVIDENCE_INVALID');
      }
      return { keyId: key.keyId, payloadHash, payloadBytes: plaintext.byteLength, sealed };
    } finally {
      key?.key.fill(0);
      plaintext.fill(0);
    }
  }

  async function openPrivateReceipt(info, receiptKey, row, signal) {
    if (!row || !Buffer.isBuffer(row.sealed) || row.sealed.byteLength <= 0
      || row.sealed.byteLength > PRIVATE_RECEIPT_MAX_ENVELOPE_BYTES
      || row.key_id === null || !isDigest(row.payload_hash)
      || !Number.isSafeInteger(row.payload_bytes) || row.payload_bytes <= 0
      || row.payload_bytes > PRIVATE_RECEIPT_MAX_PLAINTEXT_BYTES) fail('EVIDENCE_INTEGRITY');
    const envelope = decodeSealedEnvelope(row.sealed, info.tenantHash, receiptKey, PRIVATE_RECEIPT_KIND);
    if (envelope.keyId !== row.key_id) fail('EVIDENCE_INTEGRITY');
    const encryptedBytes = base64DecodedByteLength(envelope.ciphertext);
    if (encryptedBytes !== row.payload_bytes) fail('EVIDENCE_INTEGRITY');
    const key = await resolveKey(info, 'payload', envelope.keyId, signal);
    let value;
    let hashBytes;
    let transferred = false;
    try {
      value = decryptSealedPayload(envelope, info.tenantHash, receiptKey, PRIVATE_RECEIPT_KIND, key.key, row.payload_bytes);
      const serialized = JSON.stringify(value);
      if (typeof serialized !== 'string') fail('EVIDENCE_INTEGRITY');
      hashBytes = Buffer.from(serialized, 'utf8');
      if (digest(hashBytes) !== row.payload_hash) fail('EVIDENCE_INTEGRITY');
      transferred = true;
      return value;
    } finally {
      hashBytes?.fill(0);
      key.key.fill(0);
      if (!transferred && value !== undefined) wipePrivateTree(value);
    }
  }

  function normalizePrivateReceiptBase(inputValue) {
    const input = ownDataRecord(inputValue, new Set(['runId', 'configHash', 'candidate', 'claim']));
    if (!input || typeof input.runId !== 'string' || input.runId.length < 1 || input.runId.length > 96
      || !isWellFormed(input.runId) || /[\u0000-\u001f\u007f]/.test(input.runId)
      || !isDigest(input.configHash)) fail('EVIDENCE_INVALID');
    const rawCandidate = ownDataRecord(input.candidate,
      new Set(['candidateId', 'canonicalUrl', 'suppliedUrl', 'depth', 'seed', 'sourceRefs', 'assetAcquisition']));
    if (!rawCandidate || !isDigest(rawCandidate.candidateId) || typeof rawCandidate.canonicalUrl !== 'string'
      || rawCandidate.canonicalUrl.length > 8_192 || !Number.isSafeInteger(rawCandidate.depth)
      || rawCandidate.depth < 0 || rawCandidate.depth > 2 || typeof rawCandidate.seed !== 'boolean') fail('EVIDENCE_INVALID');
    const canonical = validateUrl(rawCandidate.canonicalUrl).href;
    if (canonical !== rawCandidate.canonicalUrl) fail('EVIDENCE_INVALID');
    let suppliedUrl;
    if (Object.hasOwn(rawCandidate, 'suppliedUrl')) {
      if (typeof rawCandidate.suppliedUrl !== 'string' || rawCandidate.suppliedUrl.length < 1
        || rawCandidate.suppliedUrl.length > 8_192 || !isWellFormed(rawCandidate.suppliedUrl)) fail('EVIDENCE_INVALID');
      let validatedSuppliedUrl;
      try { validatedSuppliedUrl = parseAndValidateUrl(rawCandidate.suppliedUrl); }
      catch { fail('EVIDENCE_INVALID'); }
      if (hasSensitiveUrlMaterial(new URL(rawCandidate.suppliedUrl))
        || validatedSuppliedUrl.url.href !== canonical) fail('EVIDENCE_INVALID');
      suppliedUrl = rawCandidate.suppliedUrl;
    }
    const sourceRefsInput = safeArray(rawCandidate.sourceRefs, 250);
    if (!sourceRefsInput) fail('EVIDENCE_INVALID');
    const sourceRefs = sourceRefsInput.map((value) => {
      const reference = ownDataRecord(value, new Set(['evidenceId', 'contentHash', 'locator', 'field', 'value']));
      if (!reference || !validUuid(reference.evidenceId) || !isDigest(reference.contentHash)
        || typeof reference.field !== 'string' || reference.field.length < 1 || reference.field.length > 120
        || !isWellFormed(reference.field) || typeof reference.value !== 'string'
        || reference.value.length < 1 || reference.value.length > 8_192 || !isWellFormed(reference.value)) fail('EVIDENCE_INVALID');
      return {
        evidenceId: reference.evidenceId,
        contentHash: reference.contentHash,
        // Receipt callers wipe their normalized plaintext tree after sealing or
        // lookup. Copy the validated frozen locator into owned mutable data so
        // cleanup never tries to mutate the caller's immutable provenance.
        locator: { ...copyLocator(reference.locator) },
        field: reference.field,
        value: reference.value,
      };
    });
    const candidate = {
      candidateId: rawCandidate.candidateId,
      canonicalUrl: canonical,
      ...(suppliedUrl === undefined ? {} : { suppliedUrl }),
      depth: rawCandidate.depth,
      seed: rawCandidate.seed,
      sourceRefs,
      ...(Object.hasOwn(rawCandidate, 'assetAcquisition')
        ? { assetAcquisition: normalizeAssetAcquisitionBinding(rawCandidate.assetAcquisition) } : {}),
    };
    const rawClaim = ownDataRecord(input.claim, new Set(['claimKey', 'workerId', 'leaseToken']));
    if (!rawClaim || typeof rawClaim.claimKey !== 'string' || rawClaim.claimKey.length < 1 || rawClaim.claimKey.length > 192
      || !/^[A-Za-z0-9._:-]+$/.test(rawClaim.claimKey)
      || typeof rawClaim.workerId !== 'string' || rawClaim.workerId.length < 1 || rawClaim.workerId.length > 192
      || !/^[A-Za-z0-9._:-]+$/.test(rawClaim.workerId) || !validUuid(rawClaim.leaseToken)) fail('EVIDENCE_INVALID');
    return {
      runId: input.runId,
      configHash: input.configHash,
      candidate,
      claim: { claimKey: rawClaim.claimKey, workerId: rawClaim.workerId, leaseToken: rawClaim.leaseToken },
    };
  }

  function normalizePrivateReceiptCompletion(value) {
    const input = ownDataRecord(value, new Set([
      'completionKey', 'outcome', 'suggestions', 'limitations', 'identity',
      'truncatedCount', 'omittedSuggestions', 'sourceLinkCandidatesOmittedCount',
      'assetAcquisition', 'assetSuggestions',
    ]));
    if (!input || typeof input.completionKey !== 'string' || input.completionKey.length < 1
      || input.completionKey.length > 192 || !/^[A-Za-z0-9._:-]+$/.test(input.completionKey)
      || !['links_observed', 'no_links', 'failed', 'access_restricted'].includes(input.outcome)) fail('EVIDENCE_INVALID');
    const budget = { nodes: 0, bytes: 0, maximumBytes: PRIVATE_RECEIPT_MAX_PLAINTEXT_BYTES - 8_192 };
    const suggestionsInput = safeArray(input.suggestions, 16);
    if (!suggestionsInput) fail('EVIDENCE_INVALID');
    const metadataKeys = ['truncatedCount', 'omittedSuggestions', 'sourceLinkCandidatesOmittedCount'];
    const metadataCount = metadataKeys.filter((key) => Object.hasOwn(input, key)).length;
    if (metadataCount !== 0 && metadataCount !== metadataKeys.length) fail('EVIDENCE_INVALID');
    const hasOmissionMetadata = metadataCount === metadataKeys.length;
    const suggestions = suggestionsInput.map((suggestion) => hasOmissionMetadata
      ? normalizePrivateReceiptLinkSuggestion(suggestion, budget)
      : cloneJsonValue(suggestion, 0, budget));
    const limitationsInput = safeArray(input.limitations, 64);
    if (!limitationsInput || limitationsInput.some((item) => typeof item !== 'string'
      || item.length < 1 || item.length > 120 || !/^[a-z0-9_:-]+$/.test(item))) fail('EVIDENCE_INVALID');
    const rawIdentity = ownDataRecord(input.identity,
      new Set(['entityCandidates', 'occurrenceCandidates', 'transitionLinks', 'unresolvedTransitions']));
    if (!rawIdentity) fail('EVIDENCE_INVALID');
    const entityCandidates = safeArray(rawIdentity.entityCandidates, 23);
    const occurrenceCandidates = safeArray(rawIdentity.occurrenceCandidates, 23);
    const transitionLinks = safeArray(rawIdentity.transitionLinks, 64);
    const unresolvedTransitions = safeArray(rawIdentity.unresolvedTransitions, 64);
    if (!entityCandidates || !occurrenceCandidates || !transitionLinks || !unresolvedTransitions) fail('EVIDENCE_INVALID');
    const identity = {
      entityCandidates: entityCandidates.map((item) => cloneJsonValue(item, 0, budget)),
      occurrenceCandidates: occurrenceCandidates.map((item) => cloneJsonValue(item, 0, budget)),
      transitionLinks: transitionLinks.map((item) => cloneJsonValue(item, 0, budget)),
      unresolvedTransitions: unresolvedTransitions.map((item) => cloneJsonValue(item, 0, budget)),
    };
    if ((input.outcome === 'links_observed') !== (suggestions.length > 0)) fail('EVIDENCE_INVALID');
    const completion = {
      completionKey: input.completionKey,
      outcome: input.outcome,
      suggestions,
      limitations: [...limitationsInput],
      identity,
      ...(Object.hasOwn(input, 'assetAcquisition')
        ? { assetAcquisition: normalizeAssetAcquisitionCompletion(input.assetAcquisition) } : {}),
      ...(Object.hasOwn(input, 'assetSuggestions')
        ? { assetSuggestions: normalizeAssetSuggestionBindings(input.assetSuggestions) } : {}),
    };
    if (!hasOmissionMetadata) return completion;
    const truncatedCount = input.truncatedCount;
    const omittedSuggestionsInput = safeArray(input.omittedSuggestions, 16);
    const sourceLinkCandidatesOmittedCount = input.sourceLinkCandidatesOmittedCount;
    if (!Number.isSafeInteger(truncatedCount) || truncatedCount < 0 || truncatedCount > 16
      || !omittedSuggestionsInput || truncatedCount !== omittedSuggestionsInput.length
      || !Number.isSafeInteger(sourceLinkCandidatesOmittedCount)
      || sourceLinkCandidatesOmittedCount < 0 || sourceLinkCandidatesOmittedCount > 1_000_000
      || suggestions.length + omittedSuggestionsInput.length > 16
      || (input.outcome !== 'links_observed' && truncatedCount > 0)) {
      fail('EVIDENCE_INVALID');
    }
    completion.truncatedCount = truncatedCount;
    completion.omittedSuggestions = omittedSuggestionsInput.map((suggestion) =>
      normalizePrivateReceiptLinkSuggestion(suggestion, budget));
    completion.sourceLinkCandidatesOmittedCount = sourceLinkCandidatesOmittedCount;
    return completion;
  }

  function normalizePrivateReceiptLinkSuggestion(value, budget) {
    const input = ownDataRecord(value, new Set(['url', 'sourceRefs']));
    if (!input || typeof input.url !== 'string' || input.url.length < 1 || input.url.length > 2_048
      || !isWellFormed(input.url)) fail('EVIDENCE_INVALID');
    const url = validateUrl(input.url);
    if (hasSensitiveUrlMaterial(url) || url.href !== input.url) fail('EVIDENCE_INVALID');
    const sourceRefsInput = safeArray(input.sourceRefs, 4);
    if (!sourceRefsInput || sourceRefsInput.length < 1) fail('EVIDENCE_INVALID');
    const sourceRefs = sourceRefsInput.map((referenceValue) => {
      const reference = ownDataRecord(referenceValue,
        new Set(['evidenceId', 'contentHash', 'locator', 'field', 'value']));
      if (!reference || !validUuid(reference.evidenceId) || !isDigest(reference.contentHash)
        || typeof reference.field !== 'string' || reference.field.length < 1 || reference.field.length > 120
        || !isWellFormed(reference.field) || reference.value !== input.url) fail('EVIDENCE_INVALID');
      return {
        evidenceId: reference.evidenceId,
        contentHash: reference.contentHash,
        locator: { ...copyLocator(reference.locator) },
        field: reference.field,
        value: reference.value,
      };
    });
    sourceRefs.sort((left, right) => {
      const leftValue = JSON.stringify(left);
      const rightValue = JSON.stringify(right);
      return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
    });
    const unique = new Set(sourceRefs.map((reference) => JSON.stringify(reference)));
    if (unique.size !== sourceRefs.length) fail('EVIDENCE_INVALID');
    budget.nodes += sourceRefs.length * 6 + 2;
    budget.bytes += Buffer.byteLength(JSON.stringify({ url: input.url, sourceRefs }), 'utf8');
    if (budget.nodes > 20_000 || budget.bytes > budget.maximumBytes) fail('EVIDENCE_INVALID');
    return { url: input.url, sourceRefs };
  }

  function validatePrivateReceiptSuggestionEvidence(completion, evidenceRefs, code = 'EVIDENCE_INVALID') {
    if (!Object.hasOwn(completion, 'omittedSuggestions')) return;
    const referencesByEvidence = new Map(evidenceRefs.map((reference) => [reference.evidenceId, reference]));
    for (const suggestion of [...completion.suggestions, ...completion.omittedSuggestions]) {
      for (const sourceRef of suggestion.sourceRefs) {
        const evidence = referencesByEvidence.get(sourceRef.evidenceId);
        const locatorKey = JSON.stringify(sourceRef.locator);
        if (!evidence || evidence.contentHash !== sourceRef.contentHash
          || !evidence.positions.some((position) => JSON.stringify(position.locator) === locatorKey)) fail(code);
      }
    }
  }

  function validatePrivateReceiptReferences(value) {
    const input = ownDataRecord(value, new Set(['evidenceRefs', 'factRefs']));
    if (!input) fail('EVIDENCE_INTEGRITY');
    const evidenceInput = safeArray(input.evidenceRefs, 8);
    const factInput = safeArray(input.factRefs, 128);
    if (!evidenceInput || !factInput) fail('EVIDENCE_INTEGRITY');
    let totalPositions = 0;
    const evidenceRefs = evidenceInput.map((entry) => {
      const reference = ownDataRecord(entry, new Set([
        'evidenceId', 'version', 'contentHash', 'representation', 'derivationDigest', 'positions',
      ]));
      if (!reference || !validUuid(reference.evidenceId) || !Number.isSafeInteger(reference.version)
        || reference.version < 1 || !isDigest(reference.contentHash)
        || !['raw', 'pdf-derived-text', 'asset-source-excerpt'].includes(reference.representation)
        || (reference.derivationDigest !== null && !isDigest(reference.derivationDigest))) fail('EVIDENCE_INTEGRITY');
      const positionsInput = safeArray(reference.positions, 128);
      if (!positionsInput) fail('EVIDENCE_INTEGRITY');
      totalPositions += positionsInput.length;
      if (totalPositions > 128) fail('EVIDENCE_INTEGRITY');
      const positions = positionsInput.map((positionValue) => {
        const position = ownDataRecord(positionValue, new Set(['locator', 'contentHash']));
        if (!position || !isDigest(position.contentHash)) fail('EVIDENCE_INTEGRITY');
        return { locator: copyStoredLocator(position.locator, reference.representation), contentHash: position.contentHash };
      });
      return {
        evidenceId: reference.evidenceId,
        version: reference.version,
        contentHash: reference.contentHash,
        representation: reference.representation,
        derivationDigest: reference.derivationDigest,
        positions,
      };
    });
    const factRefs = factInput.map((entry) => {
      const reference = ownDataRecord(entry, new Set([
        'factId', 'field', 'status', 'valueHash', 'supportEvidenceIds', 'supportContentHashes', 'supports',
      ]));
      if (!reference || !validUuid(reference.factId) || typeof reference.field !== 'string'
        || reference.field.length < 1 || reference.field.length > 120 || !FACT_STATUSES.has(reference.status)
        || !isDigest(reference.valueHash)) fail('EVIDENCE_INTEGRITY');
      const supportEvidenceIds = safeArray(reference.supportEvidenceIds, 128);
      const supportContentHashes = safeArray(reference.supportContentHashes, 128);
      const supportsInput = safeArray(reference.supports, 512);
      if (!supportEvidenceIds || !supportContentHashes || !supportsInput
        || supportEvidenceIds.some((id) => !validUuid(id))
        || supportContentHashes.some((hash) => !isDigest(hash))) fail('EVIDENCE_INTEGRITY');
      const supports = supportsInput.map((supportValue) => {
        const support = ownDataRecord(supportValue, new Set([
          'evidenceId', 'positionId', 'contentHash', 'duplicateGroupId',
        ]));
        if (!support || !validUuid(support.evidenceId) || !validUuid(support.positionId)
          || !isDigest(support.contentHash) || !isDigest(support.duplicateGroupId)) fail('EVIDENCE_INTEGRITY');
        return {
          evidenceId: support.evidenceId,
          positionId: support.positionId,
          contentHash: support.contentHash,
          duplicateGroupId: support.duplicateGroupId,
        };
      });
      if (JSON.stringify([...new Set(supportEvidenceIds)].sort()) !== JSON.stringify(supportEvidenceIds)
        || JSON.stringify([...new Set(supportContentHashes)].sort()) !== JSON.stringify(supportContentHashes)
        || JSON.stringify([...new Set(supports.map((support) => support.evidenceId))].sort()) !== JSON.stringify(supportEvidenceIds)
        || JSON.stringify([...new Set(supports.map((support) => support.contentHash))].sort()) !== JSON.stringify(supportContentHashes)) {
        fail('EVIDENCE_INTEGRITY');
      }
      return {
        factId: reference.factId,
        field: reference.field,
        status: reference.status,
        valueHash: reference.valueHash,
        supportEvidenceIds,
        supportContentHashes,
        supports,
      };
    });
    if (new Set(evidenceRefs.map((reference) => reference.evidenceId)).size !== evidenceRefs.length
      || new Set(factRefs.map((reference) => reference.factId)).size !== factRefs.length) fail('EVIDENCE_INTEGRITY');
    return { evidenceRefs, factRefs };
  }

  function receiptReferencesForMaterialized(info, materialized) {
    const evidenceRefs = (materialized?.evidence ?? []).map((item) => {
      const handleInfo = EVIDENCE_HANDLES.get(item.handle);
      if (!handleInfo || handleInfo.tenantHash !== info.tenantHash) fail('EVIDENCE_DENIED');
      return {
        evidenceId: handleInfo.evidenceId,
        version: item.metadata.version,
        contentHash: item.metadata.contentHash,
        representation: item.metadata.representation ?? 'raw',
        derivationDigest: item.metadata.derivationDigest ?? null,
        positions: item.positions.map((position) => ({
          locator: cloneJsonValue(position.locator),
          contentHash: position.contentHash,
        })),
      };
    });
    const factRefs = (materialized?.facts ?? []).map((fact) => {
      const factSupports = [];
      const sourceCandidates = fact.status === 'conflicting' ? fact.candidates : [fact];
      for (const sourceFact of sourceCandidates) {
        for (const support of sourceFact.supports ?? []) {
          const evidenceInfo = EVIDENCE_HANDLES.get(support.evidence);
          const positionInfo = POSITION_HANDLES.get(support.position);
          if (!evidenceInfo || !positionInfo || evidenceInfo.tenantHash !== info.tenantHash
            || positionInfo.tenantHash !== info.tenantHash || evidenceInfo.evidenceId !== positionInfo.evidenceId) {
            fail('EVIDENCE_INTEGRITY');
          }
          factSupports.push({
            evidenceId: evidenceInfo.evidenceId,
            positionId: positionInfo.positionId,
            contentHash: support.contentHash,
            duplicateGroupId: support.duplicateGroupId,
          });
        }
      }
      const fingerprintBytes = Buffer.from(JSON.stringify({
        factId: fact.factId,
        field: fact.field,
        status: fact.status,
        rawValue: fact.rawValue,
        normalizedValue: fact.normalizedValue,
        precision: fact.precision,
        candidates: fact.status === 'conflicting' ? fact.candidates.map((candidate) => ({
          originStatus: candidate.originStatus,
          rawValue: candidate.rawValue,
          normalizedValue: candidate.normalizedValue,
          precision: candidate.precision,
          supports: candidate.supports.map((support) => ({
            contentHash: support.contentHash,
            duplicateGroupId: support.duplicateGroupId,
          })),
        })) : undefined,
        supports: factSupports,
      }), 'utf8');
      let valueHash;
      try { valueHash = digest(fingerprintBytes); } finally { fingerprintBytes.fill(0); }
      return {
        factId: fact.factId,
        field: fact.field,
        status: fact.status,
        valueHash,
        supportEvidenceIds: [...new Set(factSupports.map((support) => support.evidenceId))].sort(),
        supportContentHashes: [...new Set(factSupports.map((support) => support.contentHash))].sort(),
        supports: factSupports,
      };
    });
    return { evidenceRefs, factRefs };
  }

  async function privateReceiptRowSnapshot(info, directory, receiptKey, signal) {
    return withExpiryAwareTenantLock(info, directory, async (database) => {
      const nowMs = currentTime();
      expirePrivateReceipts(database, info.tenantHash, nowMs, receiptKey);
      const row = database.prepare(`SELECT schema_version, state, key_id, payload_hash, payload_bytes,
        expires_at_ms, sealed, updated_at_ms FROM private_retrieval_receipts
        WHERE tenant_hash = ? AND receipt_key = ?`).get(info.tenantHash, receiptKey);
      if (!row) return null;
      if (row.schema_version !== PRIVATE_RECEIPT_SCHEMA_VERSION || !['pending', 'complete', 'expired'].includes(row.state)
        || !Number.isSafeInteger(row.expires_at_ms) || !Number.isSafeInteger(row.updated_at_ms)) fail('EVIDENCE_INTEGRITY');
      if (row.state === 'expired') return { state: 'expired', expiresAtMs: row.expires_at_ms };
      if (row.state === 'pending' || row.state === 'complete') {
        if (typeof row.key_id !== 'string' || !isDigest(row.payload_hash)
          || !Number.isSafeInteger(row.payload_bytes) || row.payload_bytes <= 0
          || row.payload_bytes > PRIVATE_RECEIPT_MAX_PLAINTEXT_BYTES
          || row.sealed === null || row.sealed.byteLength <= 0
          || row.sealed.byteLength > PRIVATE_RECEIPT_MAX_ENVELOPE_BYTES) fail('EVIDENCE_INTEGRITY');
      }
      return {
        state: row.state,
        key_id: row.key_id,
        payload_hash: row.payload_hash,
        payload_bytes: row.payload_bytes,
        expiresAtMs: row.expires_at_ms,
        updatedAtMs: row.updated_at_ms,
        sealed: row.sealed === null ? null : Buffer.from(row.sealed),
      };
    }, signal);
  }

  function privateReceiptRowMatchesSync(info, directory, receiptKey, expected) {
    const databasePath = path.join(directory, 'evidence.sqlite');
    let database;
    try {
      const before = lstatSync(databasePath);
      if (before.isSymbolicLink() || !before.isFile()) fail('EVIDENCE_STORAGE');
      database = new DatabaseSync(databasePath, { readOnly: true, timeout: 0 });
      const after = lstatSync(databasePath);
      if (after.isSymbolicLink() || !after.isFile() || before.dev !== after.dev || before.ino !== after.ino) {
        fail('EVIDENCE_STORAGE');
      }
      database.exec('PRAGMA trusted_schema = OFF');
      const row = database.prepare(`SELECT schema_version, state, key_id, payload_hash, payload_bytes,
        expires_at_ms, sealed, updated_at_ms FROM private_retrieval_receipts
        WHERE tenant_hash = ? AND receipt_key = ?`).get(info.tenantHash, receiptKey);
      if (!row || row.schema_version !== PRIVATE_RECEIPT_SCHEMA_VERSION || row.state !== expected.state
        || row.key_id !== expected.key_id || row.payload_hash !== expected.payload_hash
        || row.payload_bytes !== expected.payload_bytes || row.expires_at_ms !== expected.expiresAtMs
        || row.updated_at_ms !== expected.updatedAtMs || !row.sealed || !expected.sealed) return false;
      return Buffer.from(row.sealed).equals(expected.sealed);
    } catch (error) {
      if (error instanceof EvidenceStoreError) throw error;
      if (sqliteBusy(error)) fail('EVIDENCE_BUSY');
      fail('EVIDENCE_STORAGE');
    } finally {
      try { database?.close(); } catch { /* close read snapshot */ }
    }
  }

  async function resolveKey(info, purpose, keyId, signal) {
    try {
      const resolved = await awaitAbortableHostOperation(
        () => config.resolveKey(Object.freeze({ tenantId: info.tenantId, purpose, ...(keyId ? { keyId } : {}) })),
        signal,
      );
      return validateKeyResult(resolved, keyId);
    } catch (error) {
      if (error instanceof EvidenceStoreError) throw error;
      fail('EVIDENCE_KEY_UNAVAILABLE');
    }
  }

  async function encryptBundle(info, id, kind, data, signal) {
    let serialized;
    try { serialized = JSON.stringify(data); } catch { fail('EVIDENCE_INVALID'); }
    if (typeof serialized !== 'string') fail('EVIDENCE_INVALID');
    const plaintextBytes = Buffer.byteLength(serialized, 'utf8');
    const maximum = kind === 'evidence'
      ? SELECTED_BATCH_LIMITS.evidenceDecryptedBytes
      : SELECTED_BATCH_LIMITS.factRecordBytes;
    if (plaintextBytes <= 0 || plaintextBytes > maximum) fail('EVIDENCE_INVALID');
    const key = await resolveKey(info, kind === 'evidence' ? 'payload' : 'fact', undefined, signal);
    try {
      return {
        keyId: key.keyId,
        bytes: encodeSealedPayload(info.tenantHash, id, kind, serialized, key.keyId, key.key),
      };
    } finally {
      key.key.fill(0);
    }
  }

  async function decryptBundle(info, id, kind, database, expectedKeyId, signal) {
    const envelopeBytes = readSealedBundle(database, kind, id);
    try {
      const envelope = decodeSealedEnvelope(envelopeBytes, info.tenantHash, id, kind);
      if (expectedKeyId && envelope.keyId !== expectedKeyId) fail('EVIDENCE_INTEGRITY');
      const plaintextBytes = base64DecodedByteLength(envelope.ciphertext);
      const maximum = kind === 'evidence'
        ? SELECTED_BATCH_LIMITS.evidenceDecryptedBytes
        : SELECTED_BATCH_LIMITS.factRecordBytes;
      if (plaintextBytes > maximum) fail('EVIDENCE_INVALID');
      const key = await resolveKey(info, kind === 'evidence' ? 'payload' : 'fact', envelope.keyId, signal);
      try {
        return decryptSealedPayload(envelope, info.tenantHash, id, kind, key.key, plaintextBytes);
      } finally {
        key.key.fill(0);
      }
    } finally {
      envelopeBytes.fill(0);
    }
  }

  async function authorize(info, request, action, evidenceIds, factIds = [], signal) {
    if (typeof config.authorizePrivateAccess !== 'function') fail('EVIDENCE_DENIED');
    let result;
    try {
      result = await awaitAbortableHostOperation(() => config.authorizePrivateAccess(Object.freeze({
        tenantId: info.tenantId,
        request,
        action,
        evidenceIds: Object.freeze([...new Set(evidenceIds)]),
        factIds: Object.freeze([...new Set(factIds)]),
      })), signal);
    } catch (error) {
      if (error instanceof EvidenceStoreError) throw error;
      fail('EVIDENCE_DENIED');
    }
    if (result !== true) fail('EVIDENCE_DENIED');
  }

  function authorizeCurrent(info, request, action, evidenceIds, factIds = []) {
    if (typeof config.authorizePrivateAccessCurrent !== 'function') fail('EVIDENCE_DENIED');
    let result;
    try {
      result = config.authorizePrivateAccessCurrent(Object.freeze({
        tenantId: info.tenantId,
        request,
        action,
        evidenceIds: Object.freeze([...new Set(evidenceIds)]),
        factIds: Object.freeze([...new Set(factIds)]),
      }));
    } catch {
      fail('EVIDENCE_DENIED');
    }
    if (result !== true) {
      observeNativeRejectedPromise(result);
      fail('EVIDENCE_DENIED');
    }
  }

  function checkCancellation(signal) {
    if (signal === undefined) return;
    if (signalWasAborted(signal)) fail('EVIDENCE_CANCELLED');
  }

  async function resolveRetention(info, kind, nowMs, sourceKind, upperBoundMs, retentionHandle, signal) {
    let result;
    try {
      result = await awaitAbortableHostOperation(() => config.resolveRetention(Object.freeze({
        tenantId: info.tenantId,
        kind,
        sourceKind,
        nowMs,
        ...(Number.isSafeInteger(upperBoundMs) ? { sourceExpiresAtMs: upperBoundMs } : {}),
        ...(retentionHandle !== undefined ? { retentionHandle } : {}),
      })), signal);
    } catch (error) {
      if (error instanceof EvidenceStoreError) throw error;
      fail('EVIDENCE_DENIED');
    }
    return validateRetentionResult(result, nowMs, limits.maxRetentionMs, upperBoundMs);
  }

  function expirePrivateReceipts(database, tenantHash, nowMs, receiptKey = undefined) {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) fail('EVIDENCE_STORAGE');
    const totals = database.prepare(`SELECT COUNT(*) AS row_count,
      COALESCE(SUM(length(sealed)), 0) AS sealed_bytes
      FROM private_retrieval_receipts WHERE tenant_hash = ?`).get(tenantHash);
    if (!totals || !Number.isSafeInteger(totals.row_count) || totals.row_count < 0
      || totals.row_count > PRIVATE_RECEIPT_MAX_ROWS_PER_TENANT
      || !Number.isSafeInteger(totals.sealed_bytes) || totals.sealed_bytes < 0
      || totals.sealed_bytes > PRIVATE_RECEIPT_MAX_SEALED_BYTES_PER_TENANT) fail('EVIDENCE_STORAGE');
    const unsupported = database.prepare(`SELECT COUNT(*) AS count FROM private_retrieval_receipts
      WHERE tenant_hash = ? AND schema_version <> ?`).get(tenantHash, PRIVATE_RECEIPT_SCHEMA_VERSION);
    if (!unsupported || !Number.isSafeInteger(unsupported.count) || unsupported.count !== 0) fail('EVIDENCE_INTEGRITY');
    const keyFilter = receiptKey === undefined ? '' : ' AND receipt_key = ?';
    const expiredPredicate = `(((state IN ('pending', 'complete') AND expires_at_ms <= ?)
      OR (state = 'expired' AND (key_id IS NOT NULL OR payload_hash IS NOT NULL
        OR payload_bytes IS NOT NULL OR sealed IS NOT NULL)))${keyFilter})`;
    const countParameters = receiptKey === undefined
      ? [tenantHash, nowMs]
      : [tenantHash, nowMs, receiptKey];
    const expired = database.prepare(`SELECT COUNT(*) AS count FROM private_retrieval_receipts
      WHERE tenant_hash = ? AND ${expiredPredicate}`).get(...countParameters);
    if (!expired || !Number.isSafeInteger(expired.count) || expired.count < 0
      || expired.count > totals.row_count) fail('EVIDENCE_INTEGRITY');
    if (expired.count === 0) return 0;
    const updateParameters = receiptKey === undefined
      ? [nowMs, tenantHash, nowMs]
      : [nowMs, tenantHash, nowMs, receiptKey];
    const updated = database.prepare(`UPDATE private_retrieval_receipts SET state = 'expired', key_id = NULL,
      payload_hash = NULL, payload_bytes = NULL, sealed = NULL, updated_at_ms = ?
      WHERE tenant_hash = ? AND ${expiredPredicate}`).run(...updateParameters);
    if (updated.changes !== expired.count) fail('EVIDENCE_STORAGE');
    return expired.count;
  }

  function expireRecords(database, manifest, nowMs) {
    let changed = false;
    for (const record of Object.values(manifest.records)) {
      if (record.state === 'available' && record.expiresAtMs <= nowMs) {
        record.state = 'expired';
        for (const key of [
          'familyId', 'version', 'previousId', 'contentHash', 'duplicateGroupId', 'retrievedAt', 'createdAt', 'createdAtMs',
          'retrievedAtMs', 'expiresAtMs', 'policyId', 'policyVersion', 'sourceKeyId', 'sourceKeyHmac',
          'encryptionKeyId', 'positionIds', 'positionHashes', 'representation', 'derivationDigest',
        ]) delete record[key];
        database.prepare('DELETE FROM sealed_bundles WHERE kind = ? AND id = ?').run('evidence', record.id);
        changed = true;
      }
    }
    for (const fact of Object.values(manifest.facts)) {
      if (fact.state === 'available' && fact.expiresAtMs <= nowMs) {
        fact.state = 'expired';
        for (const key of [
          'status', 'createdAt', 'createdAtMs', 'expiresAtMs', 'policyId', 'policyVersion', 'encryptionKeyId',
          'supportEvidenceIds', 'supportContentHashes',
        ]) delete fact[key];
        database.prepare('DELETE FROM sealed_bundles WHERE kind = ? AND id = ?').run('fact', fact.id);
        changed = true;
      }
    }
    for (const [familyId, family] of Object.entries(manifest.families)) {
      family.recordIds = family.recordIds.filter((id) => manifest.records[id]?.state === 'available');
      if (family.recordIds.length === 0) delete manifest.families[familyId];
      else {
        for (const id of family.recordIds) {
          const record = manifest.records[id];
          if (record.previousId && manifest.records[record.previousId]?.state === 'expired') delete record.previousId;
        }
      }
    }
    expirePrivateReceipts(database, manifest.tenantHash, nowMs);
    if (changed) writeManifest(database, manifest);
    return changed;
  }

  async function persistExpirySweep(info, directory, signal) {
    await withTenantLock(directory, limits.lockTimeoutMs, async (database) => {
      const manifest = await readManifest(database, info.tenantHash);
      await expireRecords(database, manifest, currentTime());
    }, signal);
  }

  async function withExpiryCleanup(info, directory, operation, signal) {
    try {
      return await operation();
    } catch (operationError) {
      if (operationError instanceof EvidenceStoreError && operationError.code === 'EVIDENCE_CANCELLED') {
        throw operationError;
      }
      if (signal !== undefined && signalWasAborted(signal)) throw safePublicError(operationError);
      // The operation transaction has already rolled back. Persist only a fresh
      // expiry sweep in its own transaction, so a failed mutation never commits.
      try {
        await persistExpirySweep(info, directory, signal);
      } catch (cleanupError) {
        throw safePublicError(cleanupError);
      }
      throw operationError;
    }
  }

  async function withExpiryAwareTenantLock(info, directory, operation, signal, lockOptions = undefined) {
    return withExpiryCleanup(info, directory, () => withTenantLock(
      directory, limits.lockTimeoutMs, operation, signal, lockOptions,
    ), signal);
  }

  function makeFinalStateVerifier(info, directory, evidenceIds, factIds) {
    const databasePath = path.join(directory, 'evidence.sqlite');
    let database;
    try {
      const uniqueEvidenceIds = [...new Set(evidenceIds)];
      const uniqueFactIds = [...new Set(factIds)];
      const before = lstatSync(databasePath);
      if (before.isSymbolicLink() || !before.isFile()) fail('EVIDENCE_STORAGE');
      database = new DatabaseSync(databasePath, { readOnly: true, timeout: 0 });
      const after = lstatSync(databasePath);
      if (after.isSymbolicLink() || !after.isFile() || before.dev !== after.dev || before.ino !== after.ino) {
        fail('EVIDENCE_STORAGE');
      }
      database.exec('PRAGMA trusted_schema = OFF');
      const manifestLengthStatement = database.prepare(
        'SELECT length(CAST(document AS BLOB)) AS bytes FROM evidence_manifest WHERE tenant_hash = ?',
      );
      const manifestStatement = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?');
      const totalBundleCountStatement = database.prepare('SELECT COUNT(*) AS count FROM sealed_bundles');
      const prepareCountStatements = (kind, ids) => {
        const batches = [];
        for (let offset = 0; offset < ids.length; offset += 500) {
          const values = ids.slice(offset, offset + 500);
          batches.push({
            statement: database.prepare(`SELECT COUNT(*) AS count FROM sealed_bundles WHERE kind = '${kind}' AND id IN (${values.map(() => '?').join(',')})`),
            values,
          });
        }
        return batches;
      };
      const evidenceCountStatements = prepareCountStatements('evidence', uniqueEvidenceIds);
      const factCountStatements = prepareCountStatements('fact', uniqueFactIds);
      const countRows = (batches) => batches.reduce((total, batch) => total + Number(batch.statement.get(...batch.values).count), 0);
      return {
        check(snapshot) {
          let row;
          let evidenceBundleCount;
          let factBundleCount;
          let totalBundleCount;
          try {
            database.exec('BEGIN');
            const length = manifestLengthStatement.get(info.tenantHash);
            if (length && (!Number.isSafeInteger(length.bytes) || length.bytes <= 0 || length.bytes > 16 * 1024 * 1024)) {
              fail('EVIDENCE_INTEGRITY');
            }
            row = manifestStatement.get(info.tenantHash);
            if (length && (!row || Buffer.byteLength(row.document, 'utf8') !== length.bytes)) fail('EVIDENCE_INTEGRITY');
            if (!length && row) fail('EVIDENCE_INTEGRITY');
            evidenceBundleCount = countRows(evidenceCountStatements);
            factBundleCount = countRows(factCountStatements);
            totalBundleCount = Number(totalBundleCountStatement.get().count);
            database.exec('COMMIT');
          } catch (error) {
            try { database.exec('ROLLBACK'); } catch { /* rollback may follow a failed BEGIN or COMMIT */ }
            if (error instanceof EvidenceStoreError) throw error;
            if (error?.errcode === 5 || error?.errcode === 6 || error?.code === 'ERR_SQLITE_BUSY') fail('EVIDENCE_BUSY');
            fail('EVIDENCE_STORAGE');
          }
          if (!row) {
            if (snapshot.manifestPresentAtSnapshot !== false
              || snapshot.evidence.length !== 0 || snapshot.facts.length !== 0 || totalBundleCount !== 0) {
              fail('EVIDENCE_INTEGRITY');
            }
            return;
          }
          if (evidenceBundleCount !== uniqueEvidenceIds.length || factBundleCount !== uniqueFactIds.length) {
            fail('EVIDENCE_EXPIRED');
          }
          let parsed;
          try { parsed = JSON.parse(row.document); } catch { fail('EVIDENCE_INTEGRITY'); }
          const manifest = validateManifest(parsed, info.tenantHash);
          const sameValues = (left, right, fields) => fields.every((field) => JSON.stringify(left[field]) === JSON.stringify(right[field]));
          for (const expected of snapshot.evidence) {
            const current = manifest.records[expected.id];
            if (!current || current.state !== 'available') fail('EVIDENCE_EXPIRED');
            if (!sameValues(expected, current, [
              'id', 'state', 'version', 'contentHash', 'duplicateGroupId', 'retrievedAt',
              'createdAt', 'createdAtMs', 'retrievedAtMs', 'expiresAtMs', 'policyId', 'policyVersion',
              'encryptionKeyId', 'positionIds', 'positionHashes', 'representation', 'derivationDigest',
            ])) fail('EVIDENCE_INTEGRITY');
            const expectedPreviousId = expected.previousId ?? null;
            const currentPreviousId = current.previousId ?? null;
            const samePreviousId = expectedPreviousId === currentPreviousId;
            const expiredPredecessorWasUnlinked = expectedPreviousId !== null
              && currentPreviousId === null
              && manifest.records[expectedPreviousId]?.state === 'expired';
            if (!samePreviousId && !expiredPredecessorWasUnlinked) fail('EVIDENCE_INTEGRITY');
            // The public metadata must reflect the persisted, expiry-cleaned
            // linkage that passed this final check.
            expected.previousId = currentPreviousId;
          }
          for (const expected of snapshot.facts) {
            const current = manifest.facts[expected.id];
            if (!current || current.state !== 'available') fail('EVIDENCE_EXPIRED');
            if (!sameValues(expected, current, [
              'id', 'status', 'state', 'createdAt', 'createdAtMs', 'expiresAtMs', 'policyId', 'policyVersion',
              'encryptionKeyId', 'supportEvidenceIds', 'supportContentHashes',
            ])) fail('EVIDENCE_INTEGRITY');
          }
          const publicationTime = currentTime();
          if (snapshot.evidence.some((record) => record.expiresAtMs <= publicationTime)
            || snapshot.facts.some((fact) => fact.expiresAtMs <= publicationTime)) fail('EVIDENCE_EXPIRED');
        },
        close() {
          database?.close();
          database = null;
        },
      };
    } catch (error) {
      database?.close();
      if (error instanceof EvidenceStoreError) throw error;
      if (error?.errcode === 5 || error?.errcode === 6 || error?.code === 'ERR_SQLITE_BUSY') fail('EVIDENCE_BUSY');
      fail('EVIDENCE_STORAGE');
    }
  }

  function commitNewBundle(database, kind, id, sealedBytes) {
    try {
      database.prepare('INSERT INTO sealed_bundles (kind, id, sealed) VALUES (?, ?, ?)').run(kind, id, sealedBytes);
    } catch (error) {
      throw safePublicError(error);
    }
  }

  function copyEvidenceRecord(record, positionLimit = limits.maxPositionCount, budget) {
    if (!isRecord(record) || record.state !== 'available' || !validUuid(record.id)
      || !Number.isSafeInteger(record.expiresAtMs) || !Number.isSafeInteger(record.version)
      || !isDigest(record.contentHash) || !isDigest(record.duplicateGroupId)
      || !validTimestamp(record.retrievedAt) || !Number.isSafeInteger(record.retrievedAtMs)
      || !Number.isSafeInteger(record.createdAtMs) || typeof record.encryptionKeyId !== 'string'
      || record.encryptionKeyId.length < 1 || record.encryptionKeyId.length > 128) {
      fail('EVIDENCE_INTEGRITY');
    }
    if ((record.representation !== undefined
      && (![PDF_DERIVED_REPRESENTATION, ASSET_SOURCE_EXCERPT_REPRESENTATION].includes(record.representation)
        || !isDigest(record.derivationDigest)))
      || (record.representation === undefined && Object.hasOwn(record, 'derivationDigest'))) fail('EVIDENCE_INTEGRITY');
    const effectivePositionLimit = Math.min(limits.maxPositionCount, positionLimit);
    if (!Array.isArray(record.positionIds)) fail('EVIDENCE_INTEGRITY');
    if (record.positionIds.length > limits.maxPositionCount) fail('EVIDENCE_INTEGRITY');
    if (record.positionIds.length > effectivePositionLimit) fail('EVIDENCE_INVALID');
    const positionIds = safeArray(record.positionIds, effectivePositionLimit);
    if (!positionIds || positionIds.length === 0 || positionIds.some((id) => !validUuid(id))) fail('EVIDENCE_INTEGRITY');
    if (!isRecord(record.positionHashes)) fail('EVIDENCE_INTEGRITY');
    const positionHashKeys = Object.keys(record.positionHashes);
    if (positionHashKeys.length !== positionIds.length
      || positionHashKeys.some((id) => !positionIds.includes(id))) fail('EVIDENCE_INTEGRITY');
    const positionHashes = Object.create(null);
    for (const id of positionIds) {
      const descriptor = Object.getOwnPropertyDescriptor(record.positionHashes, id);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !isDigest(descriptor.value)) fail('EVIDENCE_INTEGRITY');
      positionHashes[id] = descriptor.value;
    }
    if (budget) {
      const metadataBytes = 256 + Buffer.byteLength(record.id + record.contentHash + record.duplicateGroupId
        + record.retrievedAt + (record.createdAt ?? '') + (record.policyId ?? '') + (record.policyVersion ?? '')
        + record.encryptionKeyId, 'utf8')
        + positionIds.length * (36 + 64);
      addProvenanceBytes(budget, metadataBytes);
    }
    return {
      id: record.id,
      state: record.state,
      version: record.version,
      previousId: record.previousId ?? null,
      contentHash: record.contentHash,
      duplicateGroupId: record.duplicateGroupId,
      retrievedAt: record.retrievedAt,
      createdAt: record.createdAt,
      createdAtMs: record.createdAtMs,
      retrievedAtMs: record.retrievedAtMs,
      expiresAtMs: record.expiresAtMs,
      policyId: record.policyId,
      policyVersion: record.policyVersion,
      encryptionKeyId: record.encryptionKeyId,
      positionIds,
      positionHashes: cloneJsonValue(positionHashes),
      ...(record.representation === PDF_DERIVED_REPRESENTATION || record.representation === ASSET_SOURCE_EXCERPT_REPRESENTATION ? {
        representation: record.representation,
        derivationDigest: record.derivationDigest,
      } : {}),
    };
  }

  function copyFactRecord(record, budget) {
    if (!isRecord(record) || record.state !== 'available' || !validUuid(record.id)
      || !FACT_STATUSES.has(record.status) || !Number.isSafeInteger(record.expiresAtMs)
      || !Number.isSafeInteger(record.createdAtMs) || typeof record.encryptionKeyId !== 'string') fail('EVIDENCE_INTEGRITY');
    if (!Array.isArray(record.supportEvidenceIds) || !Array.isArray(record.supportContentHashes)) fail('EVIDENCE_INTEGRITY');
    const metadataEntries = record.supportEvidenceIds.length + record.supportContentHashes.length;
    const metadataBytes = 192 + Buffer.byteLength(record.id + record.status + record.encryptionKeyId
      + (record.policyId ?? '') + (record.policyVersion ?? ''), 'utf8')
      + record.supportEvidenceIds.length * 36 + record.supportContentHashes.length * 64;
    if (metadataEntries > 4_096) fail('EVIDENCE_INTEGRITY');
    if (budget) {
      chargeBudget(budget, 'factMetadataBytes', metadataBytes, SELECTED_BATCH_LIMITS.factMetadataBytes);
      chargeBudget(budget, 'supportReferences', metadataEntries, SELECTED_BATCH_LIMITS.supportReferences);
      addProvenanceBytes(budget, metadataBytes);
    }
    const supportEvidenceIds = safeArray(record.supportEvidenceIds, 2_048);
    const supportContentHashes = safeArray(record.supportContentHashes, 2_048);
    if (!supportEvidenceIds || supportEvidenceIds.some((id) => !validUuid(id))
      || !supportContentHashes || supportContentHashes.some((hash) => !isDigest(hash))) fail('EVIDENCE_INTEGRITY');
    return {
      id: record.id,
      status: record.status,
      state: record.state,
      createdAt: record.createdAt,
      createdAtMs: record.createdAtMs,
      expiresAtMs: record.expiresAtMs,
      policyId: record.policyId,
      policyVersion: record.policyVersion,
      encryptionKeyId: record.encryptionKeyId,
      supportEvidenceIds,
      supportContentHashes,
    };
  }

  function materializeEvidenceBundle(info, record, bundle, budget) {
    const representation = record.representation ?? 'raw';
    if (representation !== 'raw' && representation !== PDF_DERIVED_REPRESENTATION
      && representation !== ASSET_SOURCE_EXCERPT_REPRESENTATION) fail('EVIDENCE_INTEGRITY');
    const expectedBundleVersion = representation === PDF_DERIVED_REPRESENTATION ? PDF_DERIVED_BUNDLE_VERSION
      : representation === ASSET_SOURCE_EXCERPT_REPRESENTATION ? ASSET_SOURCE_BUNDLE_VERSION : 1;
    if (!isRecord(bundle)
      || bundle.schemaVersion !== expectedBundleVersion
      || (representation === PDF_DERIVED_REPRESENTATION
        ? bundle.representation !== PDF_DERIVED_REPRESENTATION || record.derivationDigest !== bundle.derivationDigest
          || Object.hasOwn(bundle, 'assetSource')
        : representation === ASSET_SOURCE_EXCERPT_REPRESENTATION
          ? bundle.representation !== ASSET_SOURCE_EXCERPT_REPRESENTATION || record.derivationDigest !== bundle.derivationDigest
            || Object.hasOwn(bundle, 'derivedPdf')
          : Object.hasOwn(bundle, 'representation') || Object.hasOwn(bundle, 'derivedPdf')
            || Object.hasOwn(bundle, 'derivationDigest') || Object.hasOwn(bundle, 'assetSource'))) {
      fail('EVIDENCE_INTEGRITY');
    }
    const storedSource = ownDataRecord(bundle.source, new Set([
      'sourceUrl', 'canonicalUrl', 'redirectChain', 'contentType', 'sourceKind', 'retrievedAt', 'retrievedAtMs', 'contentHash',
      'controlledAsset',
    ]));
    if (!storedSource || !SUPPORTED_SOURCE_KINDS.has(storedSource.sourceKind)
      || typeof storedSource.sourceUrl !== 'string' || typeof storedSource.canonicalUrl !== 'string'
      || typeof storedSource.contentType !== 'string' || storedSource.contentType.length < 1
      || storedSource.contentType.length > 160 || !/^[\x20-\x7e]+$/.test(storedSource.contentType)
      || !validTimestamp(storedSource.retrievedAt) || storedSource.retrievedAt !== record.retrievedAt
      || storedSource.retrievedAtMs !== record.retrievedAtMs || !isDigest(storedSource.contentHash)
      || storedSource.contentHash !== record.contentHash) fail('EVIDENCE_INTEGRITY');
    validateUrl(storedSource.sourceUrl);
    validateUrl(storedSource.canonicalUrl);
    const redirects = safeArray(storedSource.redirectChain, 20);
    if (!redirects || redirects.some((url) => typeof url !== 'string')) fail('EVIDENCE_INTEGRITY');
    for (const url of redirects) validateUrl(url);

    const controlledAsset = storedSource.controlledAsset === undefined
      ? null : normalizeControlledAssetProvenance(storedSource.controlledAsset);
    if (controlledAsset && (storedSource.sourceKind !== 'external'
      || storedSource.contentType.toLowerCase().split(';', 1)[0].trim() !== 'image/svg+xml'
      || storedSource.sourceUrl !== controlledAsset.assetUrl || redirects.length !== 0)) fail('EVIDENCE_INTEGRITY');

    const sourceDescriptorBytes = 256 + Buffer.byteLength(
      storedSource.sourceUrl + storedSource.canonicalUrl + storedSource.contentType
        + storedSource.sourceKind + storedSource.retrievedAt + storedSource.contentHash,
      'utf8',
    ) + redirects.reduce((sum, url) => sum + Buffer.byteLength(url, 'utf8'), 0);
    addProvenanceBytes(budget, sourceDescriptorBytes);

    let derivedPdf = null;
    let pageMetadata = null;
    let assetSource = null;
    if (representation === PDF_DERIVED_REPRESENTATION) {
      if (storedSource.contentType.toLowerCase().split(';', 1)[0].trim() !== PDF_DERIVED_CONTENT_TYPE) fail('EVIDENCE_INTEGRITY');
      const stored = ownDataRecord(bundle.derivedPdf, new Set([
        'bindingVersion', 'decoder', 'completeness', 'requiresInspection', 'limits', 'pages', 'textBoxCount', 'derivationDigest',
      ]));
      const decoder = ownDataRecord(stored?.decoder, new Set(['name', 'version', 'configVersion']));
      const rawLimits = ownDataRecord(stored?.limits, new Set([
        'maxInputBytes', 'maxPages', 'maxPagePoints', 'maxTextCodeUnits', 'maxTextItemCodeUnits',
        'maxTextItems', 'maxOutputBytes', 'addressSpaceBytes', 'maxCpuSeconds', 'maxWallMilliseconds',
      ]));
      const pageValues = safeArray(stored?.pages, PDF_TEXT_READER_LIMITS.maxPages);
      if (!stored || stored.bindingVersion !== PDF_DERIVATION_BINDING_VERSION
        || !decoder || decoder.name !== 'pdfjs-dist' || decoder.version !== PDF_DECODER_VERSION
        || decoder.configVersion !== PDF_READER_CONFIG_VERSION
        || stored.completeness !== 'incomplete-text-only' || stored.requiresInspection !== true
        || !rawLimits || !pageValues || pageValues.length < 1
        || !Number.isSafeInteger(stored.textBoxCount) || stored.textBoxCount < 1
        || stored.textBoxCount > PDF_TEXT_READER_LIMITS.maxTextItems
        || stored.derivationDigest !== record.derivationDigest || !isDigest(stored.derivationDigest)) fail('EVIDENCE_INTEGRITY');
      const limitEntries = Object.entries(rawLimits);
      if (limitEntries.length !== 10 || limitEntries.some(([key, value]) =>
        !Number.isSafeInteger(value) || value <= 0 || value > PDF_TEXT_READER_LIMITS[key === 'addressSpaceBytes'
          ? 'maxAddressSpaceBytes' : key === 'maxWallMilliseconds' ? 'maxTimeoutMs' : key])) fail('EVIDENCE_INTEGRITY');
      const limitsCopy = Object.fromEntries(limitEntries);
      pageMetadata = pageValues.map((value, index) => {
        const page = ownDataRecord(value, new Set([
          'pageIndex', 'width', 'height', 'rotation', 'coordinateSystem', 'textPresence', 'requiresInspection', 'textBoxCount',
        ]));
        if (!page || page.pageIndex !== index || ![page.width, page.height].every(Number.isFinite)
          || page.width <= 0 || page.height <= 0
          || page.width > PDF_TEXT_READER_LIMITS.maxPagePoints || page.height > PDF_TEXT_READER_LIMITS.maxPagePoints
          || ![0, 90, 180, 270].includes(page.rotation)
          || page.coordinateSystem !== 'viewport-points-top-left'
          || !['text-present', 'no-embedded-text'].includes(page.textPresence)
          || page.requiresInspection !== true
          || !Number.isSafeInteger(page.textBoxCount) || page.textBoxCount < 0
          || page.textBoxCount > PDF_TEXT_READER_LIMITS.maxTextItems
          || (page.textBoxCount === 0) !== (page.textPresence === 'no-embedded-text')) fail('EVIDENCE_INTEGRITY');
        return {
          pageIndex: page.pageIndex, width: page.width, height: page.height, rotation: page.rotation,
          coordinateSystem: page.coordinateSystem, textPresence: page.textPresence,
          requiresInspection: true, textBoxCount: page.textBoxCount,
        };
      });
      if (pageMetadata.reduce((sum, page) => sum + page.textBoxCount, 0) !== stored.textBoxCount
        || stored.textBoxCount !== record.positionIds.length) fail('EVIDENCE_INTEGRITY');
      derivedPdf = {
        bindingVersion: stored.bindingVersion,
        decoder: { name: decoder.name, version: decoder.version, configVersion: decoder.configVersion },
        completeness: stored.completeness,
        requiresInspection: true,
        limits: limitsCopy,
        pages: pageMetadata,
        textBoxCount: stored.textBoxCount,
        derivationDigest: stored.derivationDigest,
      };
      addProvenanceBytes(budget, Buffer.byteLength(JSON.stringify(derivedPdf), 'utf8'));
    }

    const bundledPositions = safeArray(bundle.positions, Math.min(limits.maxPositionCount, SELECTED_BATCH_LIMITS.positionCount));
    if (!bundledPositions || bundledPositions.length !== record.positionIds.length) fail('EVIDENCE_INTEGRITY');
    const positionById = new Map();
    let recordPositionBytes = 0;
    let controlledAssetCoveredBytes = 0;
    const controlledAssetChunks = [];
    const seenPageText = new Set();
    for (const value of bundledPositions) {
      const stored = ownDataRecord(value, new Set(['id', 'locator', 'contentHash', 'content']));
      if (!stored || !validUuid(stored.id) || !isDigest(stored.contentHash) || typeof stored.content !== 'string'
        || positionById.has(stored.id)) fail('EVIDENCE_INTEGRITY');
      const positionBytes = base64DecodedByteLength(stored.content);
      const recordPositionLimit = Math.min(limits.maxPositionBytes, SELECTED_BATCH_LIMITS.positionRecordBytes);
      if (positionBytes > recordPositionLimit) fail('EVIDENCE_INVALID');
      recordPositionBytes += positionBytes;
      if (!Number.isSafeInteger(recordPositionBytes)
        || recordPositionBytes > Math.min(limits.maxStoredPayloadBytes, SELECTED_BATCH_LIMITS.evidencePositionBytes)) fail('EVIDENCE_INVALID');
      if (representation === ASSET_SOURCE_EXCERPT_REPRESENTATION
        && (positionBytes > ASSET_SOURCE_MAX_EXCERPT_BYTES
          || recordPositionBytes > ASSET_SOURCE_MAX_EXCERPT_TOTAL_BYTES)) fail('EVIDENCE_INTEGRITY');
      chargeBudget(budget, 'positionBytes', positionBytes, SELECTED_BATCH_LIMITS.positionBytes);
      const locator = copyStoredLocator(stored.locator, representation);
      if (representation === ASSET_SOURCE_EXCERPT_REPRESENTATION
        && locator.endByte > ASSET_SOURCE_MAX_SOURCE_BYTES) fail('EVIDENCE_INTEGRITY');
      if (representation === PDF_DERIVED_REPRESENTATION) {
        const page = pageMetadata[locator.pageIndex];
        if (!page || locator.textIndex >= page.textBoxCount || locator.pageWidth !== page.width
          || locator.pageHeight !== page.height || locator.rotation !== page.rotation
          || locator.coordinateSystem !== page.coordinateSystem
          || locator.x + locator.width > page.width + 0.01 || locator.y + locator.height > page.height + 0.01) fail('EVIDENCE_INTEGRITY');
        const key = `${locator.pageIndex}:${locator.textIndex}`;
        if (seenPageText.has(key)) fail('EVIDENCE_INTEGRITY');
        seenPageText.add(key);
      }
      const locatorBytes = Buffer.byteLength(JSON.stringify(locator), 'utf8');
      addProvenanceBytes(budget, locatorBytes + 128);
      const bytes = Buffer.from(stored.content, 'base64');
      try {
        if (bytes.toString('base64') !== stored.content || bytes.byteLength !== positionBytes
          || digest(bytes) !== stored.contentHash || record.positionHashes[stored.id] !== stored.contentHash) fail('EVIDENCE_INTEGRITY');
        if (controlledAsset) {
          if (locator.kind !== 'text-range' || locator.startByte !== controlledAssetCoveredBytes
            || locator.endByte - locator.startByte !== bytes.byteLength) fail('EVIDENCE_INTEGRITY');
          controlledAssetCoveredBytes = locator.endByte;
          controlledAssetChunks.push(Buffer.from(bytes));
        }
      } finally {
        bytes.fill(0);
      }
      positionById.set(stored.id, {
        locator,
        contentHash: stored.contentHash,
        byteLength: positionBytes,
        ...(representation === ASSET_SOURCE_EXCERPT_REPRESENTATION || controlledAsset ? { contentBase64: stored.content } : {}),
      });
    }
    if (controlledAsset) {
      const completeBytes = Buffer.concat(controlledAssetChunks, controlledAssetCoveredBytes);
      try {
        if (!controlledAssetProvenanceMatchesBytes(controlledAsset, completeBytes, record.contentHash)) fail('EVIDENCE_INTEGRITY');
      } finally {
        completeBytes.fill(0);
        for (const chunk of controlledAssetChunks) chunk.fill(0);
      }
    }
    if (record.positionIds.some((id) => !positionById.has(id))) fail('EVIDENCE_INTEGRITY');
    if (representation === PDF_DERIVED_REPRESENTATION) {
      for (const page of pageMetadata) {
        for (let textIndex = 0; textIndex < page.textBoxCount; textIndex += 1) {
          if (!seenPageText.has(`${page.pageIndex}:${textIndex}`)) fail('EVIDENCE_INTEGRITY');
        }
      }
      const derivationMaterial = {
        bindingVersion: derivedPdf.bindingVersion,
        sourceContentHash: storedSource.contentHash,
        decoder: derivedPdf.decoder,
        completeness: derivedPdf.completeness,
        requiresInspection: derivedPdf.requiresInspection,
        limits: derivedPdf.limits,
        pages: pageMetadata,
        positions: record.positionIds.map((id) => {
          const position = positionById.get(id);
          return { locator: position.locator, contentHash: position.contentHash };
        }),
      };
      if (digest(Buffer.from(JSON.stringify(derivationMaterial), 'utf8')) !== record.derivationDigest) fail('EVIDENCE_INTEGRITY');
    } else if (representation === ASSET_SOURCE_EXCERPT_REPRESENTATION) {
      assetSource = validateAssetSourceProvenance(bundle.assetSource, record, storedSource.sourceUrl, positionById, budget);
    }
    const positions = record.positionIds.map((id) => {
      const position = positionById.get(id);
      return Object.freeze({
        handle: newPositionHandle(info, record.id, id, storedSource.sourceKind, representation),
        locator: deepFreeze(cloneJsonValue(position.locator)),
        contentHash: position.contentHash,
      });
    });
    return Object.freeze({
      handle: newEvidenceHandle(info, record.id),
      metadata: frozenMetadata(record),
      source: deepFreeze({
        sourceUrl: storedSource.sourceUrl,
        canonicalUrl: storedSource.canonicalUrl,
        redirectChain: [...redirects],
        contentType: storedSource.contentType,
        sourceKind: storedSource.sourceKind,
        retrievedAt: storedSource.retrievedAt,
        retrievedAtMs: storedSource.retrievedAtMs,
        contentHash: storedSource.contentHash,
        ...(derivedPdf ? { derivedPdf: deepFreeze(cloneJsonValue(derivedPdf)) } : {}),
        ...(assetSource ? { assetSource } : {}),
        ...(controlledAsset ? { controlledAsset: deepFreeze(cloneJsonValue(controlledAsset)) } : {}),
      }),
      positions: Object.freeze(positions),
    });
  }

  function collectFactSupports(record, stored, budget) {
    if (!isRecord(stored) || stored.status !== record.status) fail('EVIDENCE_INTEGRITY');
    const supports = [];
    const takeSupports = (value, maximum) => {
      if (!Array.isArray(value) || value.length > maximum) fail('EVIDENCE_INTEGRITY');
      // Charge before copying or constructing public support handles. Repeated
      // references count each time because each one occupies returned memory.
      chargeBudget(budget, 'supportReferences', value.length, SELECTED_BATCH_LIMITS.supportReferences);
      return safeArray(value, maximum);
    };
    if (stored.status === 'missing') {
      if (Object.hasOwn(stored, 'supports') && (!Array.isArray(stored.supports) || stored.supports.length !== 0)) fail('EVIDENCE_INTEGRITY');
    } else if (stored.status === 'conflicting') {
      const candidates = safeArray(stored.candidates, 32);
      if (!candidates || candidates.length < 2) fail('EVIDENCE_INTEGRITY');
      for (const candidate of candidates) {
        const safeCandidate = ownDataRecord(candidate, new Set(['originStatus', 'rawValue', 'normalizedValue', 'precision', 'method', 'supports']));
        if (!safeCandidate || !FACT_ORIGINS.has(safeCandidate.originStatus)) fail('EVIDENCE_INTEGRITY');
        const candidateSupports = takeSupports(safeCandidate.supports, 64);
        if (!candidateSupports || candidateSupports.length === 0) fail('EVIDENCE_INTEGRITY');
        supports.push(...candidateSupports);
      }
    } else {
      const factSupports = takeSupports(stored.supports, 64);
      if (!factSupports || factSupports.length === 0) fail('EVIDENCE_INTEGRITY');
      supports.push(...factSupports);
    }
    const evidenceIds = new Set();
    const hashes = new Set();
    for (const supportValue of supports) {
      const support = ownDataRecord(supportValue, new Set([
        'evidenceId', 'positionId', 'contentHash', 'sourceKind', 'duplicateGroupId',
      ]));
      if (!support || !validUuid(support.evidenceId) || !validUuid(support.positionId)
        || !isDigest(support.contentHash) || !SUPPORTED_SOURCE_KINDS.has(support.sourceKind)
        || !isDigest(support.duplicateGroupId)) fail('EVIDENCE_INTEGRITY');
      addProvenanceBytes(budget, 192 + Buffer.byteLength(
        support.evidenceId + support.positionId + support.contentHash + support.sourceKind + support.duplicateGroupId,
        'utf8',
      ));
      evidenceIds.add(support.evidenceId);
      hashes.add(support.contentHash);
    }
    if (JSON.stringify([...evidenceIds].sort()) !== JSON.stringify([...record.supportEvidenceIds].sort())
      || JSON.stringify([...hashes].sort()) !== JSON.stringify([...record.supportContentHashes].sort())) fail('EVIDENCE_INTEGRITY');
    return supports;
  }

  function validateMaterializedFact(record, stored, evidenceById, budget) {
    const supports = collectFactSupports(record, stored, budget);
    for (const supportValue of supports) {
      const support = ownDataRecord(supportValue, new Set([
        'evidenceId', 'positionId', 'contentHash', 'sourceKind', 'duplicateGroupId',
      ]));
      const evidence = evidenceById.get(support.evidenceId);
      const supportedPosition = evidence?.positions.find((position) => POSITION_HANDLES.get(position.handle)?.positionId === support.positionId);
      const supportedPositionInfo = supportedPosition ? POSITION_HANDLES.get(supportedPosition.handle) : null;
      if (!evidence || evidence.metadata.contentHash !== support.contentHash
        || evidence.metadata.duplicateGroupId !== support.duplicateGroupId
        || evidence.source.sourceKind !== support.sourceKind
        || !supportedPositionInfo || supportedPositionInfo.representation !== 'raw') {
        fail('EVIDENCE_INTEGRITY');
      }
    }
  }

  async function materializeSelectedInternal(
    scope,
    selectionValue,
    request,
    signal,
    action,
    returnMode = 'selected',
    evidenceLimit = 8,
    deferCurrentAuthorization = false,
    finalizationHook,
  ) {
    const info = scopeInfo(scope);
    checkCancellation(signal);
    const budget = newMaterializationBudget();
    const selection = ownDataRecord(selectionValue, new Set(['evidence', 'facts']));
    if (!selection) fail('EVIDENCE_INVALID');
    const evidenceHandles = safeArray(selection.evidence, Math.max(
      SELECTED_BATCH_LIMITS.evidenceCount,
      Math.min(evidenceLimit, SELECTED_BATCH_LIMITS.positionCount),
    ));
    const factHandles = safeArray(selection.facts, SELECTED_BATCH_LIMITS.factCount);
    if (!evidenceHandles || !factHandles || evidenceHandles.length + factHandles.length === 0) fail('EVIDENCE_INVALID');
    const explicitEvidenceIds = [];
    const factIds = [];
    for (const handle of evidenceHandles) {
      const evidence = evidenceInfo(scope, handle);
      explicitEvidenceIds.push(evidence.evidenceId);
    }
    for (const handle of factHandles) {
      const fact = FACT_HANDLES.get(handle);
      if (!fact || fact.tenantHash !== info.tenantHash || fact.tenantId !== info.tenantId) fail('EVIDENCE_DENIED');
      factIds.push(fact.factId);
    }
    if (new Set(explicitEvidenceIds).size !== explicitEvidenceIds.length || new Set(factIds).size !== factIds.length) fail('EVIDENCE_INVALID');

    const directory = await tenantDirectory(info);
    let snapshot;
    let finalVerifier;
    try {
      snapshot = await withExpiryAwareTenantLock(info, directory, async (database) => {
        const factRecords = [];
        const evidenceRecords = [];
        let transferred = false;
        try {
          const manifest = await readManifest(database, info.tenantHash);
          await expireRecords(database, manifest, currentTime());
          const evidenceIds = [...explicitEvidenceIds];
          for (const factId of factIds) {
            const current = manifest.facts[factId];
            if (!current) fail('EVIDENCE_NOT_FOUND');
            if (current.state !== 'available') fail('EVIDENCE_EXPIRED');
            const copied = copyFactRecord(current, budget);
            factRecords.push(copied);
            for (const evidenceId of copied.supportEvidenceIds) {
              if (!evidenceIds.includes(evidenceId)) evidenceIds.push(evidenceId);
              if (evidenceIds.length > evidenceLimit) fail('EVIDENCE_INVALID');
            }
          }
          if (evidenceIds.length > evidenceLimit || new Set(evidenceIds).size !== evidenceIds.length) fail('EVIDENCE_INVALID');
          let selectedPositionCount = 0;
          const effectivePositionLimit = Math.min(limits.maxPositionCount, SELECTED_BATCH_LIMITS.positionCount);
          for (const evidenceId of evidenceIds) {
            const current = manifest.records[evidenceId];
            if (!current) fail('EVIDENCE_NOT_FOUND');
            if (current.state !== 'available') fail('EVIDENCE_EXPIRED');
            const copied = copyEvidenceRecord(current, effectivePositionLimit - selectedPositionCount, budget);
            selectedPositionCount += copied.positionIds.length;
            if (selectedPositionCount > effectivePositionLimit) fail('EVIDENCE_INVALID');
            evidenceRecords.push(copied);
          }
          const evidenceLengths = preflightSelectedSealedBundleLengths(
            database,
            'evidence',
            evidenceRecords.map((record) => record.id),
            budget,
          );
          const factLengths = preflightSelectedSealedBundleLengths(
            database,
            'fact',
            factRecords.map((record) => record.id),
            budget,
          );
          copySelectedSealedBundles(database, 'evidence', evidenceRecords, evidenceLengths);
          copySelectedSealedBundles(database, 'fact', factRecords, factLengths);
          const nowMs = currentTime();
          if (evidenceRecords.some((record) => record.expiresAtMs <= nowMs)
            || factRecords.some((record) => record.expiresAtMs <= nowMs)) fail('EVIDENCE_EXPIRED');
          transferred = true;
          return { evidence: evidenceRecords, facts: factRecords, budget };
        } finally {
          if (!transferred) {
            for (const record of evidenceRecords) record.sealed?.fill(0);
            for (const record of factRecords) record.sealed?.fill(0);
          }
        }
      }, signal);

      checkCancellation(signal);
      const evidenceIds = snapshot.evidence.map((record) => record.id);
      await authorize(info, request, action, evidenceIds, factIds, signal);
      checkCancellation(signal);

      const evidenceViews = [];
      const evidenceById = new Map();
      for (const record of snapshot.evidence) {
        const bundle = await decryptSealedBundle(info, record.id, 'evidence', record.sealed, record.encryptionKeyId, resolveKey, snapshot.budget, signal);
        try {
          checkCancellation(signal);
          const view = materializeEvidenceBundle(info, record, bundle, snapshot.budget);
          evidenceViews.push(view);
          evidenceById.set(record.id, view);
        } finally {
          // The decrypted JSON tree contains base64 position content; discard it as
          // soon as the public metadata and opaque position handles are made.
          wipePrivateTree(bundle);
        }
      }
      const factViews = [];
      for (const record of snapshot.facts) {
        const stored = await decryptSealedBundle(info, record.id, 'fact', record.sealed, record.encryptionKeyId, resolveKey, snapshot.budget, signal);
        try {
          checkCancellation(signal);
          validateMaterializedFact(record, stored, evidenceById, snapshot.budget);
          factViews.push(publicFact(info, record.id, stored));
        } finally {
          wipePrivateTree(stored);
        }
      }

      checkCancellation(signal);
      finalVerifier = makeFinalStateVerifier(info, directory, evidenceIds, factIds);
      // Everything that can await, including key resolution, has completed; no
      // DB/write lock is held. appendFact defers this hook until its final CAS prep.
      if (!deferCurrentAuthorization) authorizeCurrent(info, request, action, evidenceIds, factIds);
      // Keep this synchronous tail together: current persisted state, every selected
      // record's retention deadline, cancellation, then immutable result release.
      finalVerifier.check(snapshot);
      checkCancellation(signal);
      const refreshedEvidenceViews = evidenceViews.map((view) => {
        const record = snapshot.evidence.find((candidate) => candidate.id === view.metadata.evidenceId);
        if (!record) fail('EVIDENCE_INTEGRITY');
        return Object.freeze({ ...view, metadata: frozenMetadata(record) });
      });
      const materialized = deepFreeze({ evidence: refreshedEvidenceViews, facts: factViews });
      if (finalizationHook !== undefined) {
        if (typeof finalizationHook !== 'function') fail('EVIDENCE_INVALID');
        const hookResult = finalizationHook({
          snapshot,
          finalVerifier,
          evidenceIds: Object.freeze([...evidenceIds]),
          factIds: Object.freeze([...factIds]),
          materialized,
        });
        if (hookResult !== undefined) fail('EVIDENCE_INVALID');
        checkCancellation(signal);
      }
      if (returnMode === 'fact') return materialized.facts[0];
      if (returnMode === 'positions') return materialized.evidence[0].positions;
      return materialized;
    } catch (error) {
      if (!(error instanceof EvidenceStoreError && error.code === 'EVIDENCE_CANCELLED')) {
        try { await persistExpirySweep(info, directory, signal); } catch (cleanupError) { throw safePublicError(cleanupError); }
      }
      throw safePublicError(error);
    } finally {
      finalVerifier?.close();
      for (const record of snapshot?.evidence ?? []) record.sealed.fill(0);
      for (const record of snapshot?.facts ?? []) record.sealed.fill(0);
    }
  }

  async function materializeSelected(scope, selection, request, signal) {
    return materializeSelectedInternal(scope, selection, request, signal, 'materialize_selected');
  }

  /**
   * Reopens the selected records and role-separated assets for a one-shot
   * synchronous finalizer. This preflight does not release evidence: the
   * returned opaque check must be consumed by finalizeControlledAssetRelease
   * after this promise settles, so queued work from the async callbacks has
   * run before the final current-state/authority check and projection.
   */
  async function revalidateControlledAssetRelease(scope, inputValue, request, signal) {
    const info = scopeInfo(scope);
    checkCancellation(signal);
    const input = ownDataRecord(inputValue, new Set([
      'runId', 'policyDigest', 'releaseController', 'evidence', 'facts', 'assetGroups',
      'beforeFinalization', 'finalizeHostAuthority',
    ]));
    if (!input || typeof input.runId !== 'string' || input.runId.length < 1 || input.runId.length > 96
      || !isDigest(input.policyDigest) || !isPrivateAssetReleaseController(input.releaseController)
      || typeof input.beforeFinalization !== 'function'
      || typeof input.finalizeHostAuthority !== 'function') fail('EVIDENCE_INVALID');
    const releaseAuthority = privateAssetReleaseAuthorityForController(input.releaseController);
    if (!releaseAuthority) fail('EVIDENCE_INVALID');
    const evidenceValues = safeArray(input.evidence, SELECTED_BATCH_LIMITS.evidenceCount);
    const factValues = safeArray(input.facts, SELECTED_BATCH_LIMITS.factCount);
    const assetGroupValues = safeArray(input.assetGroups, 8);
    if (!evidenceValues || !factValues || !assetGroupValues
      || evidenceValues.length + factValues.length === 0) fail('EVIDENCE_INVALID');

    const copyReference = (value) => {
      const reference = ownDataRecord(value, new Set(['handle', 'metadata']));
      const metadata = reference && ownDataRecord(reference.metadata, new Set([
        'evidenceId', 'version', 'previousEvidenceId', 'contentHash', 'duplicateGroupId',
        'retrievedAt', 'createdAt', 'expiresAt', 'policyId', 'policyVersion', 'accessPolicy',
        'state', 'positionCount', 'representation', 'derivationDigest',
      ]));
      if (!reference || !metadata || !validUuid(metadata.evidenceId)
        || !Number.isSafeInteger(metadata.version) || metadata.version < 1
        || (metadata.previousEvidenceId !== null && !validUuid(metadata.previousEvidenceId))
        || !isDigest(metadata.contentHash) || !isDigest(metadata.duplicateGroupId)
        || !validTimestamp(metadata.retrievedAt) || !validTimestamp(metadata.createdAt) || !validTimestamp(metadata.expiresAt)
        || typeof metadata.policyId !== 'string' || metadata.policyId.length < 1 || metadata.policyId.length > 128
        || typeof metadata.policyVersion !== 'string' || metadata.policyVersion.length < 1 || metadata.policyVersion.length > 128
        || metadata.accessPolicy !== 'tenant_private' || metadata.state !== 'available'
        || !Number.isSafeInteger(metadata.positionCount) || metadata.positionCount < 1
        || (metadata.representation !== undefined
          && ![PDF_DERIVED_REPRESENTATION, ASSET_SOURCE_EXCERPT_REPRESENTATION].includes(metadata.representation))
        || (metadata.representation === undefined && Object.hasOwn(metadata, 'derivationDigest'))
        || (metadata.representation !== undefined && !isDigest(metadata.derivationDigest))) fail('EVIDENCE_INVALID');
      const evidence = evidenceInfo(scope, reference.handle);
      if (metadata.evidenceId !== evidence.evidenceId) fail('EVIDENCE_DENIED');
      return Object.freeze({
        evidenceId: evidence.evidenceId,
        handle: reference.handle,
        metadata: Object.freeze({ ...metadata }),
      });
    };
    const evidenceReferences = evidenceValues.map(copyReference);
    const factIds = factValues.map((handle) => {
      const fact = FACT_HANDLES.get(handle);
      if (!fact || fact.tenantHash !== info.tenantHash || fact.tenantId !== info.tenantId) fail('EVIDENCE_DENIED');
      return fact.factId;
    });
    if (evidenceReferences.length === 0 || new Set(evidenceReferences.map((item) => item.evidenceId)).size !== evidenceReferences.length
      || new Set(factIds).size !== factIds.length) fail('EVIDENCE_INVALID');

    const assetGroups = assetGroupValues.map((value) => {
      const group = ownDataRecord(value, new Set(['candidateId', 'evidence']));
      if (!group || typeof group.candidateId !== 'string' || !/^[A-Za-z0-9_-]{1,160}$/.test(group.candidateId)) {
        fail('EVIDENCE_INVALID');
      }
      const roles = safeArray(group.evidence, 2);
      if (!roles || roles.length !== 2) fail('EVIDENCE_INVALID');
      const copiedRoles = roles.map(copyReference);
      if (new Set(copiedRoles.map((item) => item.evidenceId)).size !== copiedRoles.length) fail('EVIDENCE_INVALID');
      return Object.freeze({ candidateId: group.candidateId, evidence: Object.freeze(copiedRoles) });
    });
    if (new Set(assetGroups.map((item) => item.candidateId)).size !== assetGroups.length) fail('EVIDENCE_INVALID');
    const allReferenceMap = new Map();
    for (const reference of [...evidenceReferences, ...assetGroups.flatMap((group) => group.evidence)]) {
      const previous = allReferenceMap.get(reference.evidenceId);
      if (previous && JSON.stringify(previous.metadata) !== JSON.stringify(reference.metadata)) fail('EVIDENCE_INTEGRITY');
      allReferenceMap.set(reference.evidenceId, reference);
    }
    if (allReferenceMap.size > SELECTED_BATCH_LIMITS.evidenceCount + 16) fail('EVIDENCE_INVALID');

    const directory = await tenantDirectory(info);
    let snapshot;
    let finalVerifier;
    let retainedReleaseCheck = false;
    try {
      snapshot = await withExpiryAwareTenantLock(info, directory, async (database) => {
        const manifest = await readManifest(database, info.tenantHash);
        await expireRecords(database, manifest, currentTime());
        const budget = newMaterializationBudget();
        const evidenceRecords = [];
        let selectedPositionCount = 0;
        const selectedPositionLimit = Math.min(limits.maxPositionCount, SELECTED_BATCH_LIMITS.positionCount);
        for (const reference of evidenceReferences) {
          const record = manifest.records[reference.evidenceId];
          if (!record) fail('EVIDENCE_NOT_FOUND');
          if (record.state !== 'available') fail('EVIDENCE_EXPIRED');
          const copied = copyEvidenceRecord(record, selectedPositionLimit - selectedPositionCount, budget);
          selectedPositionCount += copied.positionIds.length;
          if (selectedPositionCount > selectedPositionLimit) fail('EVIDENCE_INVALID');
          if (JSON.stringify(frozenMetadata(copied)) !== JSON.stringify(reference.metadata)) fail('EVIDENCE_INTEGRITY');
          evidenceRecords.push(copied);
        }
        // Controlled source and transformed records are role-separated. Each
        // retains the host position-count ceiling, including bounded chunking;
        // these role positions do not become public selected positions.
        for (const group of assetGroups) {
          for (const reference of group.evidence) {
            const record = manifest.records[reference.evidenceId];
            if (!record) fail('EVIDENCE_NOT_FOUND');
            if (record.state !== 'available') fail('EVIDENCE_EXPIRED');
            const copied = copyEvidenceRecord(record, Math.min(limits.maxPositionCount, SELECTED_BATCH_LIMITS.positionCount), budget);
            if (JSON.stringify(frozenMetadata(copied)) !== JSON.stringify(reference.metadata)) fail('EVIDENCE_INTEGRITY');
            if (!evidenceRecords.some((existing) => existing.id === copied.id)) evidenceRecords.push(copied);
          }
        }
        const factRecords = [];
        const supportEvidenceIds = new Set();
        for (const factId of factIds) {
          const record = manifest.facts[factId];
          if (!record) fail('EVIDENCE_NOT_FOUND');
          if (record.state !== 'available') fail('EVIDENCE_EXPIRED');
          const copied = copyFactRecord(record, budget);
          factRecords.push(copied);
          for (const evidenceId of copied.supportEvidenceIds) supportEvidenceIds.add(evidenceId);
        }
        const selectedEvidenceIds = new Set(evidenceReferences.map((item) => item.evidenceId));
        if ([...supportEvidenceIds].some((evidenceId) => !selectedEvidenceIds.has(evidenceId))) fail('EVIDENCE_INTEGRITY');
        const publicationTime = currentTime();
        if (evidenceRecords.some((record) => record.expiresAtMs <= publicationTime)
          || factRecords.some((record) => record.expiresAtMs <= publicationTime)) fail('EVIDENCE_EXPIRED');
        return { evidence: evidenceRecords, facts: factRecords, manifestPresentAtSnapshot: true };
      }, signal);

      checkCancellation(signal);
      const originalEvidenceIds = evidenceReferences.map((item) => item.evidenceId);
      const allFactAndCoreEvidenceIds = [...originalEvidenceIds];
      for (const factId of factIds) {
        const record = snapshot.facts.find((item) => item.id === factId);
        if (!record) fail('EVIDENCE_INTEGRITY');
        for (const supportId of record.supportEvidenceIds) {
          if (!allFactAndCoreEvidenceIds.includes(supportId)) allFactAndCoreEvidenceIds.push(supportId);
        }
      }
      const allRoleIds = assetGroups.flatMap((group) => group.evidence.map((item) => item.evidenceId));
      await authorize(info, request, 'read_private_evidence', [...allFactAndCoreEvidenceIds, ...allRoleIds], factIds, signal);
      checkCancellation(signal);

      let activeCandidateIds = await awaitAbortableHostOperation(
        () => input.beforeFinalization(Object.freeze({
          candidateIds: Object.freeze(assetGroups.map((group) => group.candidateId)),
        })),
        signal,
      );
      const copiedActiveCandidateIds = safeArray(activeCandidateIds, assetGroups.length);
      if (!copiedActiveCandidateIds
        || copiedActiveCandidateIds.some((id) => typeof id !== 'string' || !assetGroups.some((group) => group.candidateId === id))
        || new Set(copiedActiveCandidateIds).size !== copiedActiveCandidateIds.length) fail('EVIDENCE_INVALID');
      activeCandidateIds = [...copiedActiveCandidateIds];

      const finalEvidenceIds = () => [
        ...allFactAndCoreEvidenceIds,
        ...assetGroups.filter((group) => activeCandidateIds.includes(group.candidateId))
          .flatMap((group) => group.evidence.map((item) => item.evidenceId)),
      ];
      const runHostFinalizer = () => {
        let decision;
        try { decision = input.finalizeHostAuthority(Object.freeze({ candidateIds: Object.freeze([...activeCandidateIds]) })); }
        catch { fail('EVIDENCE_DENIED'); }
        if (decision !== null && (typeof decision === 'object' || typeof decision === 'function')) {
          observeNativeRejectedPromise(decision);
          const copied = ownDataRecord(decision, new Set(['releaseAuthorized', 'candidateIds']));
          const returnedCandidateIds = copied && safeArray(copied.candidateIds, assetGroups.length);
          if (!copied || typeof copied.releaseAuthorized !== 'boolean' || !returnedCandidateIds
            || returnedCandidateIds.some((id) => typeof id !== 'string'
              || !activeCandidateIds.includes(id) || !assetGroups.some((group) => group.candidateId === id))
            || new Set(returnedCandidateIds).size !== returnedCandidateIds.length) fail('EVIDENCE_INVALID');
          if (copied.releaseAuthorized !== true) fail('EVIDENCE_DENIED');
          activeCandidateIds = [...returnedCandidateIds];
          return;
        }
        fail('EVIDENCE_INVALID');
      };

      // This callback runs before the returned promise settles. The caller's
      // await therefore drains any microtasks it schedules before invoking the
      // final synchronous coordinator/store release point.
      runHostFinalizer();
      const finalCandidateIds = [...activeCandidateIds].sort();
      try {
        bindPrivateAssetReleaseCandidates(releaseAuthority, {
          tenantId: info.tenantId,
          runId: input.runId,
          policyDigest: input.policyDigest,
          candidateIds: finalCandidateIds,
        });
      } catch { fail('EVIDENCE_DENIED'); }
      finalVerifier = makeFinalStateVerifier(info, directory, finalEvidenceIds(), factIds);
      checkCancellation(signal);
      const releaseCheck = createPrivateAssetReleaseCheck({
        tenantHash: info.tenantHash,
        tenantId: info.tenantId,
        runId: input.runId,
        policyDigest: input.policyDigest,
        releaseAuthority,
        releaseController: input.releaseController,
        finalEvidenceIds: finalEvidenceIds(),
        factIds: [...factIds],
        evidenceReferences,
        candidateIds: finalCandidateIds,
        snapshot,
        finalVerifier,
      });
      retainedReleaseCheck = true;
      return Object.freeze({ releaseCheck, candidateIds: Object.freeze(finalCandidateIds) });
    } catch (error) {
      revokePrivateAssetReleaseAuthority(releaseAuthority, 'store_release_revalidation_failed');
      if (!(error instanceof EvidenceStoreError && error.code === 'EVIDENCE_CANCELLED')) {
        try { await persistExpirySweep(info, directory, signal); } catch (cleanupError) { throw safePublicError(cleanupError); }
      }
      throw safePublicError(error);
    } finally {
      if (!retainedReleaseCheck) {
        finalVerifier?.close();
        for (const record of snapshot?.evidence ?? []) record.sealed?.fill(0);
        for (const record of snapshot?.facts ?? []) record.sealed?.fill(0);
      }
    }
  }

  function finalizeControlledAssetRelease(scope, releaseCheck, request, signal, inputValue) {
    const info = scopeInfo(scope);
    const state = takePrivateAssetReleaseCheck(releaseCheck);
    if (!state || state.tenantHash !== info.tenantHash || state.tenantId !== info.tenantId) {
      if (state) {
        revokePrivateAssetReleaseAuthority(state.releaseAuthority, 'release_check_scope_mismatch');
        state.finalVerifier?.close();
        for (const record of state.snapshot?.evidence ?? []) record.sealed?.fill(0);
        for (const record of state.snapshot?.facts ?? []) record.sealed?.fill(0);
      }
      fail('EVIDENCE_DENIED');
    }
    try {
      const input = ownDataRecord(inputValue, new Set([
        'releaseController', 'runId', 'policyDigest', 'deadlineAtMonotonic', 'candidateIds', 'project',
      ]));
      const candidateIds = input && safeArray(input.candidateIds, 8);
      const releaseAuthority = input && privateAssetReleaseAuthorityForController(input.releaseController);
      if (!input || !isPrivateAssetReleaseController(input.releaseController) || !releaseAuthority
        || input.runId !== state.runId || input.policyDigest !== state.policyDigest
        || !Number.isFinite(input.deadlineAtMonotonic) || typeof input.project !== 'function'
        || !candidateIds || JSON.stringify([...candidateIds].sort()) !== JSON.stringify(state.candidateIds)) {
        fail('EVIDENCE_INVALID');
      }
      const authorityBinding = {
        tenantId: info.tenantId,
        runId: state.runId,
        policyDigest: state.policyDigest,
        deadlineAtMonotonic: input.deadlineAtMonotonic,
        candidateIds: state.candidateIds,
      };
      if (state.releaseController !== input.releaseController) fail('EVIDENCE_DENIED');
      try {
        return finalizePrivateAssetRelease(releaseAuthority, authorityBinding, () => {
          checkCancellation(signal);
          authorizeCurrent(info, request, 'read_private_evidence', state.finalEvidenceIds, state.factIds);
          if (!privateAssetReleaseAuthorityValidDuringFinalization(releaseAuthority, authorityBinding)) {
            fail('EVIDENCE_DENIED');
          }
          state.finalVerifier.check({
            evidence: state.snapshot.evidence.filter((record) => state.finalEvidenceIds.includes(record.id)),
            facts: state.snapshot.facts,
            manifestPresentAtSnapshot: state.snapshot.manifestPresentAtSnapshot,
          });
          checkCancellation(signal);
          if (!privateAssetReleaseAuthorityValidDuringFinalization(releaseAuthority, authorityBinding)) {
            fail('EVIDENCE_DENIED');
          }
          const currentEvidenceMetadata = state.evidenceReferences.map((reference) => {
            const record = state.snapshot.evidence.find((item) => item.id === reference.evidenceId);
            if (!record) fail('EVIDENCE_INTEGRITY');
            return frozenMetadata(record);
          });
          const result = input.project(Object.freeze({
            currentEvidenceMetadata: Object.freeze(currentEvidenceMetadata),
            candidateIds: Object.freeze([...state.candidateIds]),
          }));
          return result;
        });
      } catch (error) {
        if (error instanceof EvidenceStoreError) throw error;
        fail('EVIDENCE_DENIED');
      }
    } catch (error) {
      revokePrivateAssetReleaseAuthority(state.releaseAuthority, 'controlled_release_finalization_failed');
      throw safePublicError(error);
    } finally {
      state.finalVerifier?.close();
      for (const record of state.snapshot?.evidence ?? []) record.sealed?.fill(0);
      for (const record of state.snapshot?.facts ?? []) record.sealed?.fill(0);
    }
  }

  function discardControlledAssetRelease(scope, releaseCheck) {
    const info = scopeInfo(scope);
    const state = takePrivateAssetReleaseCheck(releaseCheck);
    if (!state) return false;
    try {
      const matchesScope = state.tenantHash === info.tenantHash && state.tenantId === info.tenantId;
      revokePrivateAssetReleaseAuthority(state.releaseAuthority, 'release_check_discarded');
      return matchesScope;
    } finally {
      state.finalVerifier?.close();
      for (const record of state.snapshot?.evidence ?? []) record.sealed?.fill(0);
      for (const record of state.snapshot?.facts ?? []) record.sealed?.fill(0);
    }
  }

  async function createScope(request) {
    let tenantId;
    try { tenantId = await config.resolveTenant(request); } catch { fail('EVIDENCE_DENIED'); }
    if (typeof tenantId !== 'string' || tenantId.length < 1 || tenantId.length > 256 || !isWellFormed(tenantId)) fail('EVIDENCE_DENIED');
    const tenantHash = digest(Buffer.from(`event-intelligence:tenant:v1:${tenantId}`, 'utf8'));
    const scope = makeOpaque();
    TENANT_SCOPES.set(scope, Object.freeze({ tenantId, tenantHash }));
    return scope;
  }

  async function ingestEvidenceInternal(scope, inputValue, signal, snapshotAttempt = 0,
    controlledAsset = null, retentionCeiling = null) {
    const info = scopeInfo(scope);
    checkCancellation(signal);
    const input = ownDataRecord(inputValue, new Set([
      'sourceUrl', 'canonicalUrl', 'redirectChain', 'content', 'contentType', 'retrievedAt', 'sourceKind', 'positions', 'retentionHandle',
    ]));
    if (!input || typeof input.sourceUrl !== 'string' || !SUPPORTED_SOURCE_KINDS.has(input.sourceKind)
      || !validTimestamp(input.retrievedAt) || typeof input.contentType !== 'string'
      || input.contentType.length < 1 || input.contentType.length > 160 || !/^[\x20-\x7e]+$/.test(input.contentType)
      || !input.retentionHandle || typeof input.retentionHandle !== 'object') fail('EVIDENCE_INVALID');
    validateUrl(input.sourceUrl);
    const originalUrl = input.sourceUrl;
    const canonicalUrl = input.canonicalUrl === undefined ? normalizeSourceUrl(originalUrl) : normalizeSourceUrl(input.canonicalUrl);
    const redirectChainInput = input.redirectChain === undefined ? [] : safeArray(input.redirectChain, 20);
    if (!redirectChainInput) fail('EVIDENCE_INVALID');
    const redirectChain = redirectChainInput.map((item) => validateUrl(item).href);
    const sourceByteLimit = controlledAsset
      ? Math.min(limits.maxSourceBytes, controlledAsset.role === 'fetched-source'
        ? CONTROLLED_ASSET_MAX_SOURCE_BYTES : CONTROLLED_ASSET_MAX_TRANSFORMED_BYTES)
      : limits.maxSourceBytes;
    const sourceBytes = copyBytes(input.content, sourceByteLimit);
    const sourceContentHash = digest(sourceBytes);
    if (controlledAsset && !controlledAssetProvenanceMatchesBytes(controlledAsset, sourceBytes, sourceContentHash)) {
      sourceBytes.fill(0);
      fail('EVIDENCE_INVALID');
    }
    const positionInputs = safeArray(input.positions, limits.maxPositionCount);
    if (!positionInputs) {
      sourceBytes.fill(0);
      fail('EVIDENCE_INVALID');
    }
    const positions = [];
    let positionTotal = 0;
    try {
      for (const item of positionInputs) {
        const position = ownDataRecord(item, new Set(['locator', 'content']));
        if (!position || !Object.hasOwn(position, 'locator') || !Object.hasOwn(position, 'content')) fail('EVIDENCE_INVALID');
        const locator = copyLocator(position.locator);
        const bytes = copyBytes(position.content, controlledAsset
          ? Math.min(limits.maxPositionBytes, SELECTED_BATCH_LIMITS.positionRecordBytes)
          : limits.maxPositionBytes);
        positionTotal += bytes.byteLength;
        if (positionTotal > (controlledAsset
          ? Math.min(limits.maxStoredPayloadBytes, SELECTED_BATCH_LIMITS.evidencePositionBytes)
          : limits.maxStoredPayloadBytes)) fail('EVIDENCE_INVALID');
        checkSnapshot(sourceBytes, locator, bytes);
        positions.push({ id: randomUUID(), locator, contentHash: digest(bytes), bytes });
      }
      if (positions.length === 0) fail('EVIDENCE_INVALID');
    } catch (error) {
      sourceBytes.fill(0);
      for (const position of positions) position.bytes.fill(0);
      throw error instanceof EvidenceStoreError ? error : new EvidenceStoreError('EVIDENCE_INVALID');
    }
    let activeIndexKey;
    let sealed;
    let sealedBytes;
    let duplicateBytes;
    let directory;
    const historicalIndexKeys = [];
    const retryWithFreshSnapshot = async () => {
      checkCancellation(signal);
      if (snapshotAttempt >= 7) fail('EVIDENCE_BUSY');
      sourceBytes.fill(0);
      for (const position of positions) position.bytes.fill(0);
      activeIndexKey?.key.fill(0);
      sealed?.bytes.fill(0);
      duplicateBytes?.fill(0);
      for (const key of historicalIndexKeys) key.fill(0);
      return ingestEvidenceInternal(scope, inputValue, signal, snapshotAttempt + 1, controlledAsset, retentionCeiling);
    };
    try {
      const sourceKind = input.sourceKind;
      const nowMs = currentTime();
      const retrievedAtMs = Date.parse(input.retrievedAt);
      const retention = await resolveRetention(info, 'evidence', nowMs, sourceKind, undefined, input.retentionHandle, signal);
      checkCancellation(signal);
      activeIndexKey = await resolveKey(info, 'source-index', undefined, signal);
      checkCancellation(signal);
      const sourceIdentity = controlledAsset
        ? `controlled-svg:v2:${controlledAsset.policyVersion}:${controlledAsset.policyId}:${controlledAsset.role}`
          + `\u0000${sourceKind}\u0000${normalizeSourceUrl(canonicalUrl)}\u0000${JSON.stringify({
            inspectionPolicyVersion: controlledAsset.inspectionPolicyVersion,
            sourceEvidenceId: controlledAsset.sourceEvidenceId,
            sourceEvidenceVersion: controlledAsset.sourceEvidenceVersion,
            sourceContentHash: controlledAsset.sourceContentHash,
            sourceDerivationDigest: controlledAsset.sourceDerivationDigest,
            sourceUrl: controlledAsset.sourceUrl,
            candidateId: controlledAsset.candidateId,
            positionIndex: controlledAsset.positionIndex,
            sourceForm: controlledAsset.sourceForm,
            sourceLocator: controlledAsset.sourceLocator,
            excerptHash: controlledAsset.excerptHash,
            field: controlledAsset.field,
            value: controlledAsset.value,
            assetUrl: controlledAsset.assetUrl,
            // The transformed role depends on these exact fetched bytes even
            // when safe normalization produces a hash already stored elsewhere.
            ...(controlledAsset.role === 'transformed'
              ? { sourceBytesHash: controlledAsset.sourceBytesHash } : {}),
          })}`
        : `${sourceKind}\u0000${normalizeSourceUrl(canonicalUrl)}`;
      directory = await tenantDirectory(info);
      const snapshot = await withExpiryAwareTenantLock(info, directory, async (database) => {
        const manifest = await readManifest(database, info.tenantHash);
        const transactionTime = currentTime();
        await expireRecords(database, manifest, transactionTime);
        let expiresAtMs = retention.expiresAtMs;
        if (retentionCeiling) {
          const ceilingRecord = manifest.records[retentionCeiling.evidenceId];
          if (!ceilingRecord || ceilingRecord.state !== 'available'
            || ceilingRecord.version !== retentionCeiling.version
            || ceilingRecord.contentHash !== retentionCeiling.contentHash
            || ceilingRecord.expiresAtMs <= transactionTime) fail('EVIDENCE_EXPIRED');
          expiresAtMs = Math.min(expiresAtMs, ceilingRecord.expiresAtMs);
        }
        if (expiresAtMs <= transactionTime) fail('EVIDENCE_EXPIRED');
        const row = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
        const document = row?.document ?? null;
        return {
          document,
          expiresAtMs,
          manifest: document === null ? emptyManifest(info.tenantHash) : validateManifest(JSON.parse(document), info.tenantHash),
        };
      }, signal);

      const families = Object.values(snapshot.manifest.families);
      let family = families.find((candidate) => candidate.sourceKeyId === activeIndexKey.keyId
        && candidate.sourceKeyHmac === stableHmac(activeIndexKey.key, sourceIdentity));
      if (!family) {
        for (const candidate of families) {
          if (candidate.sourceKeyId === activeIndexKey.keyId) continue;
          const oldIndexKey = await resolveKey(info, 'source-index', candidate.sourceKeyId, signal);
          historicalIndexKeys.push(oldIndexKey.key);
          if (candidate.sourceKeyHmac === stableHmac(oldIndexKey.key, sourceIdentity)) {
            family = candidate;
            break;
          }
        }
      }
      const priorIds = family ? [...family.recordIds] : [];
      const latestId = priorIds.at(-1);
      const latest = latestId ? snapshot.manifest.records[latestId] : null;
      if (latest?.state === 'available' && latest.contentHash === sourceContentHash) {
        if (retentionCeiling && latest.expiresAtMs > snapshot.expiresAtMs) fail('EVIDENCE_INVALID');
        const duplicateRecord = copyEvidenceRecord(latest);
        duplicateBytes = await withExpiryAwareTenantLock(info, directory, async (database) => {
          const row = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
          if ((row?.document ?? null) !== snapshot.document) return null;
          if (currentTime() >= latest.expiresAtMs) fail('EVIDENCE_EXPIRED');
          return readSealedBundle(database, 'evidence', latest.id);
        }, signal);
        if (!duplicateBytes) return await retryWithFreshSnapshot();
        const budget = newMaterializationBudget();
        const existing = await decryptSealedBundle(
          info, latest.id, 'evidence', duplicateBytes, latest.encryptionKeyId, resolveKey, budget, signal,
        );
        try {
          const view = materializeEvidenceBundle(info, duplicateRecord, existing, budget);
          if (controlledAsset && JSON.stringify(view.source.controlledAsset) !== JSON.stringify(controlledAsset)) {
            fail('EVIDENCE_INTEGRITY');
          }
          if (currentTime() >= latest.expiresAtMs) fail('EVIDENCE_EXPIRED');
          const stillCurrent = await withExpiryAwareTenantLock(info, directory, async (database, lockSignal) => {
            checkCancellation(lockSignal);
            const row = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
            if ((row?.document ?? null) !== snapshot.document) return false;
            if (currentTime() >= latest.expiresAtMs) fail('EVIDENCE_EXPIRED');
            const count = Number(database.prepare('SELECT COUNT(*) AS count FROM sealed_bundles WHERE kind = ? AND id = ?')
              .get('evidence', latest.id).count);
            if (count !== 1) fail('EVIDENCE_INTEGRITY');
            checkCancellation(lockSignal);
            return true;
          }, signal);
          if (!stillCurrent) return await retryWithFreshSnapshot();
          return Object.freeze({
            evidence: view.handle,
            positions: Object.freeze(view.positions.map((position) => position.handle)),
            created: false,
            metadata: view.metadata,
          });
        } finally {
          wipePrivateTree(existing);
        }
      }

      const familyId = family?.id ?? randomUUID();
      const evidenceId = randomUUID();
      const version = family ? (family.versionCount ?? priorIds.length) + 1 : 1;
      const positionIds = positions.map((position) => position.id);
      const positionHashes = Object.fromEntries(positions.map((position) => [position.id, position.contentHash]));
      const bundle = {
        schemaVersion: 1,
        source: {
          sourceUrl: originalUrl,
          canonicalUrl,
          redirectChain,
          contentType: input.contentType,
          sourceKind,
          retrievedAt: input.retrievedAt,
          retrievedAtMs,
          contentHash: sourceContentHash,
          ...(controlledAsset ? { controlledAsset } : {}),
        },
        positions: positions.map((position) => ({
          id: position.id,
          locator: position.locator,
          contentHash: position.contentHash,
          content: position.bytes.toString('base64'),
        })),
      };
      sealed = await encryptBundle(info, evidenceId, 'evidence', bundle, signal);
      sealedBytes = sealed.bytes;
      checkCancellation(signal);
      const committedAtMs = currentTime();
      if (snapshot.expiresAtMs <= committedAtMs) fail('EVIDENCE_EXPIRED');
      const duplicateGroupId = digest(Buffer.from(`event-intelligence:duplicate:v1:${info.tenantHash}:${sourceContentHash}`, 'utf8'));
      const record = {
        id: evidenceId,
        version,
        previousId: latest?.id ?? null,
        contentHash: sourceContentHash,
        duplicateGroupId,
        retrievedAt: input.retrievedAt,
        createdAt: new Date(committedAtMs).toISOString(),
        createdAtMs: committedAtMs,
        retrievedAtMs,
        expiresAtMs: snapshot.expiresAtMs,
        policyId: retention.policyId,
        policyVersion: retention.policyVersion,
        state: 'available',
        encryptionKeyId: sealed.keyId,
        positionIds,
        positionHashes,
      };
      const committed = await withExpiryAwareTenantLock(info, directory, async (database, lockSignal) => {
        checkCancellation(lockSignal);
        const row = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
        if ((row?.document ?? null) !== snapshot.document) return false;
        if (snapshot.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        const manifest = snapshot.document === null
          ? emptyManifest(info.tenantHash)
          : validateManifest(JSON.parse(row.document), info.tenantHash);
        if (manifest.records[evidenceId]) fail('EVIDENCE_BUSY');
        manifest.records[evidenceId] = record;
        let currentFamily = family ? manifest.families[family.id] : null;
        if (family && !currentFamily) fail('EVIDENCE_BUSY');
        if (!currentFamily) {
          currentFamily = {
            id: familyId,
            sourceKeyId: activeIndexKey.keyId,
            sourceKeyHmac: stableHmac(activeIndexKey.key, sourceIdentity),
            versionCount: 0,
            recordIds: [],
          };
          manifest.families[familyId] = currentFamily;
        }
        currentFamily.recordIds.push(evidenceId);
        currentFamily.versionCount = version;
        await commitNewBundle(database, 'evidence', evidenceId, sealedBytes);
        await writeManifest(database, manifest);
        checkCancellation(lockSignal);
        if (snapshot.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        return true;
      }, signal);
      if (!committed) return await retryWithFreshSnapshot();
      return Object.freeze({
        evidence: newEvidenceHandle(info, evidenceId),
        positions: Object.freeze(positions.map((position) => newPositionHandle(info, evidenceId, position.id, sourceKind))),
        created: true,
        metadata: frozenMetadata(record),
      });
    } catch (error) {
      if (directory && error instanceof EvidenceStoreError && error.code === 'EVIDENCE_EXPIRED') {
        try { await persistExpirySweep(info, directory, signal); } catch (cleanupError) { throw safePublicError(cleanupError); }
      }
      throw safePublicError(error);
    } finally {
      sourceBytes.fill(0);
      for (const position of positions) position.bytes.fill(0);
      activeIndexKey?.key.fill(0);
      sealed?.bytes.fill(0);
      duplicateBytes?.fill(0);
      for (const key of historicalIndexKeys) key.fill(0);
    }
  }

  async function ingestEvidence(scope, input, signal) {
    return ingestEvidenceInternal(scope, input, signal);
  }

  async function ingestControlledAssetEvidence(scope, inputValue, request, signal) {
    const info = scopeInfo(scope);
    const input = ownDataRecord(inputValue, new Set([
      'document', 'retentionHandle', 'retentionCeiling', 'provenance', 'witness',
    ]));
    const ceilingInput = ownDataRecord(input?.retentionCeiling, new Set(['evidence', 'version', 'contentHash']));
    const document = ownDataRecord(input?.document, new Set(['url', 'contentType', 'bytes', 'fetchedAt', 'redirects']));
    if (!input || !document || !validTimestamp(document.fetchedAt) || !input.retentionHandle
      || typeof input.retentionHandle !== 'object'
      || !ceilingInput || !Number.isSafeInteger(ceilingInput.version) || ceilingInput.version < 1
      || !isDigest(ceilingInput.contentHash)) fail('EVIDENCE_INVALID');
    const ceilingInfo = evidenceInfo(scope, ceilingInput.evidence);
    if (ceilingInfo.tenantHash !== info.tenantHash || ceilingInfo.tenantId !== info.tenantId) fail('EVIDENCE_DENIED');
    const provenance = normalizeControlledAssetProvenance(input.provenance);
    if (provenance.sourceEvidenceId !== ceilingInfo.evidenceId
      || provenance.sourceEvidenceVersion !== ceilingInput.version
      || provenance.sourceContentHash !== ceilingInput.contentHash) fail('EVIDENCE_INVALID');
    if (document.url !== provenance.assetUrl || document.contentType !== 'image/svg+xml'
      || document.redirects !== 0 || !isCompletedControlledSvgFetch(input.document, provenance.assetUrl)
      || !(await verifyControlledSvgIngestWitness(input.witness, input.document, provenance, 'before-ingest'))) {
      fail('EVIDENCE_INVALID');
    }
    const maximum = Math.min(limits.maxSourceBytes, CONTROLLED_ASSET_MAX_SOURCE_BYTES);
    const sourceBytes = copyBytes(document.bytes, maximum);
    let storedBytes;
    let inspection;
    try {
      if (digest(sourceBytes) !== provenance.sourceBytesHash
        || sourceBytes.byteLength > CONTROLLED_ASSET_MAX_SOURCE_BYTES) fail('EVIDENCE_INVALID');
      await authorize(info, request, 'ingest_controlled_asset_evidence', [ceilingInfo.evidenceId], [], signal);
      authorizeCurrent(info, request, 'ingest_controlled_asset_evidence', [ceilingInfo.evidenceId], []);
      const sourceHandle = ceilingInput.evidence;
      const currentSource = await materializeSelectedInternal(
        scope,
        { evidence: [sourceHandle], facts: [] },
        request,
        signal,
        'ingest_controlled_asset_evidence',
        'selected',
        1,
      );
      const parent = currentSource.evidence[0];
      if (!controlledAssetSourceMatches(provenance, parent)) fail('EVIDENCE_INVALID');
      inspection = inspectSafeAssetBytes(sourceBytes, { contentType: 'image/svg+xml', signal });
      if (!inspection || inspection.action !== 'transformed'
        || inspection.policyVersion !== SAFE_ASSET_POLICY_VERSION
        || inspection.sourceHash !== provenance.sourceBytesHash
        || inspection.transformedHash !== provenance.transformedBytesHash) fail('EVIDENCE_INVALID');
      const transformed = inspection.copyTransformedBytes();
      storedBytes = provenance.role === 'fetched-source' ? Buffer.from(sourceBytes) : copyBytes(transformed, Math.min(
        limits.maxSourceBytes,
        CONTROLLED_ASSET_MAX_TRANSFORMED_BYTES,
        SELECTED_BATCH_LIMITS.evidencePositionBytes,
      ));
      transformed.fill(0);
      if (!controlledAssetProvenanceMatchesBytes(provenance, storedBytes, digest(storedBytes))) fail('EVIDENCE_INVALID');
      const chunkMaximum = Math.min(limits.maxPositionBytes, SELECTED_BATCH_LIMITS.positionRecordBytes);
      if (!Number.isSafeInteger(chunkMaximum) || chunkMaximum < 1
        || storedBytes.byteLength > Math.min(limits.maxStoredPayloadBytes, SELECTED_BATCH_LIMITS.evidencePositionBytes)) fail('EVIDENCE_INVALID');
      const positions = [];
      for (let startByte = 0; startByte < storedBytes.byteLength; startByte += chunkMaximum) {
        if (positions.length >= Math.min(limits.maxPositionCount, SELECTED_BATCH_LIMITS.positionCount)) fail('EVIDENCE_INVALID');
        const endByte = Math.min(storedBytes.byteLength, startByte + chunkMaximum);
        positions.push({
          locator: Object.freeze({ kind: 'text-range', startByte, endByte }),
          content: storedBytes.subarray(startByte, endByte),
        });
      }
      const stored = await ingestEvidenceInternal(scope, {
        sourceUrl: provenance.assetUrl,
        content: storedBytes,
        contentType: 'image/svg+xml',
        retrievedAt: document.fetchedAt,
        sourceKind: 'external',
        positions,
        retentionHandle: input.retentionHandle,
      }, signal, 0, provenance, {
        evidenceId: ceilingInfo.evidenceId,
        version: ceilingInput.version,
        contentHash: ceilingInput.contentHash,
      });
      if (!(await verifyControlledSvgIngestWitness(input.witness, input.document, provenance, 'after-ingest'))) {
        fail('EVIDENCE_INVALID');
      }
      authorizeCurrent(info, request, 'ingest_controlled_asset_evidence', [ceilingInfo.evidenceId, stored.metadata.evidenceId], []);
      return Object.freeze({ outcome: 'stored', ...stored });
    } finally {
      sourceBytes.fill(0);
      storedBytes?.fill(0);
      inspection?.dispose?.();
    }
  }

  async function ingestAssetSourceEvidence(scope, inputValue, request, signal) {
    const info = scopeInfo(scope);
    const assetPositionLimit = Math.min(
      ASSET_SOURCE_MAX_POSITIONS,
      limits.maxPositionCount,
      SELECTED_BATCH_LIMITS.positionCount,
    );
    const assetPositionBytesLimit = Math.min(
      ASSET_SOURCE_MAX_EXCERPT_BYTES,
      limits.maxPositionBytes,
      SELECTED_BATCH_LIMITS.positionRecordBytes,
    );
    const assetPositionTotalBytesLimit = Math.min(
      ASSET_SOURCE_MAX_EXCERPT_TOTAL_BYTES,
      limits.maxStoredPayloadBytes,
      SELECTED_BATCH_LIMITS.evidencePositionBytes,
    );
    const input = ownDataRecord(inputValue, new Set(['document', 'retentionHandle']));
    const documentInput = ownDataRecord(input?.document, new Set(['url', 'contentType', 'bytes', 'fetchedAt', 'redirects', 'image']));
    if (!input || !documentInput || typeof documentInput.url !== 'string'
      || typeof documentInput.contentType !== 'string' || documentInput.contentType.length < 1
      || documentInput.contentType.length > 160 || !/^[\x20-\x7e]+$/.test(documentInput.contentType)
      || !validTimestamp(documentInput.fetchedAt) || documentInput.redirects !== 0
      || typeof documentInput.bytes === 'string'
      || !input.retentionHandle || typeof input.retentionHandle !== 'object') fail('EVIDENCE_INVALID');
    const contentType = documentInput.contentType.toLowerCase().split(';', 1)[0].trim();
    if (!['text/html', 'application/xhtml+xml', 'application/ld+json'].includes(contentType)) fail('EVIDENCE_INVALID');
    const sourceUrl = documentInput.url;
    try {
      parseAndValidateUrl(sourceUrl);
      if (hasSensitiveAssetQuery(sourceUrl)) {
        return Object.freeze({ outcome: 'rejected', code: 'SOURCE_URL_POLICY_DENIED' });
      }
    } catch {
      return Object.freeze({ outcome: 'rejected', code: 'SOURCE_URL_POLICY_DENIED' });
    }
    const sourceBytes = copyBytes(documentInput.bytes, Math.min(limits.maxSourceBytes, ASSET_SOURCE_MAX_SOURCE_BYTES));
    const sourceContentHash = digest(sourceBytes);
    const retrievedAt = documentInput.fetchedAt;
    const retrievedAtMs = Date.parse(retrievedAt);
    const sourceKind = 'external';
    const parserDocument = Object.freeze({ url: sourceUrl, contentType: documentInput.contentType, bytes: sourceBytes, fetchedAt: retrievedAt });
    const retentionStartMs = currentTime();
    let retention;
    let activeIndexKey;
    let payloadKey;
    let sealedBytes;
    const historicalIndexKeys = [];
    const positions = [];
    const candidateBuffers = [];
    let directoryForCleanup;
    try {
      checkCancellation(signal);
      retention = await resolveRetention(info, 'evidence', retentionStartMs, sourceKind, undefined, input.retentionHandle, signal);
      if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
      let extraction;
      try {
        extraction = await extractDeterministically(parserDocument, {
          signal,
          limits: {
            maxDocumentBytes: ASSET_SOURCE_MAX_SOURCE_BYTES,
            maxAssetSources: assetPositionLimit,
            parseTimeoutMs: ASSET_SOURCE_MAX_DEADLINE_MS,
          },
        });
      } catch {
        checkCancellation(signal);
        if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        return Object.freeze({ outcome: 'rejected', code: 'SOURCE_EXTRACTION_FAILURE' });
      }
      checkCancellation(signal);
      if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
      if (!extraction || extraction.sourceHash !== `sha256:${sourceContentHash}`
        || extraction.extractorVersion !== DETERMINISTIC_EXTRACTION_VERSION) fail('EVIDENCE_INTEGRITY');
      if (extraction.status === 'CANCELED' || extraction.termination === 'CANCELED') fail('EVIDENCE_CANCELLED');
      if (extraction.status === 'RESOURCE_LIMIT' || extraction.termination !== null || extraction.assetSourcesTruncated) {
        return Object.freeze({ outcome: 'rejected', code: 'SOURCE_EXTRACTION_INCOMPLETE' });
      }
      if (extraction.status === 'ACCESS_RESTRICTED') {
        return Object.freeze({ outcome: 'rejected', code: 'SOURCE_ACCESS_RESTRICTED' });
      }
      if (extraction.status === 'JS_REQUIRED') {
        return Object.freeze({ outcome: 'rejected', code: 'SOURCE_DYNAMIC_OR_INCOMPLETE' });
      }
      if (['INVALID_INPUT', 'UNSUPPORTED_MEDIA', 'UNSUPPORTED_ENCODING', 'MALFORMED_ENCODING'].includes(extraction.status)) {
        return Object.freeze({ outcome: 'rejected', code: 'SOURCE_UNSUPPORTED_OR_MALFORMED' });
      }
      const parserDiagnostics = safeArray(extraction.diagnostics, 128);
      if (!parserDiagnostics) fail('EVIDENCE_INTEGRITY');
      if (parserDiagnostics.some((diagnostic) => ['MALFORMED_XHTML', 'XHTML_DTD_UNSUPPORTED', 'HTML_PARSER_FAILURE']
        .includes(diagnostic?.code))) {
        return Object.freeze({ outcome: 'rejected', code: 'SOURCE_UNSUPPORTED_OR_MALFORMED' });
      }
      const jsonLdBlocks = safeArray(extraction.jsonLdBlocks, 32);
      if (!jsonLdBlocks) fail('EVIDENCE_INTEGRITY');
      if (jsonLdBlocks.some((block) => block?.status === 'malformed')) {
        return Object.freeze({ outcome: 'rejected', code: 'SOURCE_UNSUPPORTED_OR_MALFORMED' });
      }
      if (jsonLdBlocks.some((block) => block?.status === 'resource_limited')) {
        return Object.freeze({ outcome: 'rejected', code: 'SOURCE_EXTRACTION_INCOMPLETE' });
      }
      const assetInputs = safeArray(extraction.assetSources, assetPositionLimit);
      if (!assetInputs) return Object.freeze({ outcome: 'rejected', code: 'ASSET_CANDIDATE_LIMIT' });
      if (assetInputs.length === 0) return Object.freeze({ outcome: 'no-candidates', code: 'NO_STATIC_ASSET_CANDIDATES' });
      const currentProfile = ASSET_SOURCE_READ_PROFILES.get(`${ASSET_SOURCE_SELECTOR_VERSION}\u0000${extraction.extractorVersion}`);
      if (!currentProfile || currentProfile.extractorVersion !== DETERMINISTIC_EXTRACTION_VERSION) fail('EVIDENCE_INTEGRITY');

      const ordered = assetInputs.map((item) => {
        const asset = ownDataRecord(item, new Set([
          'candidate', 'sourceForm', 'association', 'urlPolicyValue', 'emptyAttributeToken',
        ]));
        const candidate = ownDataRecord(asset?.candidate, new Set([
          'field', 'rawValue', 'normalizedValue', 'source', 'suggestionOnly', 'urlSuggestion', 'property',
        ]));
        const candidateSource = ownDataRecord(candidate?.source, new Set(['kind', 'locator', 'jsonPointer', 'property']));
        const hasEmptyAttributeToken = Boolean(asset && Object.hasOwn(asset, 'emptyAttributeToken'));
        const emptyAttributeToken = hasEmptyAttributeToken
          ? ownDataRecord(asset.emptyAttributeToken, new Set(['attributeName', 'valueState', 'locator']))
          : null;
        if (!asset || !candidate || !candidateSource || typeof asset.urlPolicyValue !== 'string'
          || (hasEmptyAttributeToken && !emptyAttributeToken)
          || !ASSET_SOURCE_FORMS.has(asset.sourceForm)
          || typeof candidate.field !== 'string' || candidate.field.length < 1 || candidate.field.length > 160
          || !validAssetAssociation(asset.association, asset.sourceForm)
          || !['asset-source', 'open-graph', 'jsonld'].includes(candidateSource.kind)) fail('EVIDENCE_INTEGRITY');

        let locator;
        let excerptKind = 'url-value';
        if (emptyAttributeToken) {
          const attributeName = emptyAttributeNameForAssetForm(asset.sourceForm);
          const sourceValueLocator = ownDataRecord(candidateSource.locator, new Set(['kind', 'startByte', 'endByte']));
          if (!attributeName || candidateSource.kind !== (asset.sourceForm === 'open-graph-image' ? 'open-graph' : 'asset-source')
            || emptyAttributeToken.attributeName !== attributeName
            || !['missing', 'empty'].includes(emptyAttributeToken.valueState)
            || typeof candidate.rawValue !== 'string' || candidate.rawValue !== ''
            || candidate.normalizedValue !== '' || asset.urlPolicyValue !== ''
            || !sourceValueLocator || sourceValueLocator.kind !== 'text-range'
            || !Number.isSafeInteger(sourceValueLocator.startByte) || sourceValueLocator.startByte < 0
            || sourceValueLocator.startByte !== sourceValueLocator.endByte
            || sourceValueLocator.endByte > sourceBytes.length) fail('EVIDENCE_INTEGRITY');
          locator = copyLocator(emptyAttributeToken.locator);
          if (locator.kind !== 'text-range' || locator.endByte > sourceBytes.length
            || locator.startByte > sourceValueLocator.startByte || locator.endByte < sourceValueLocator.startByte) fail('EVIDENCE_INTEGRITY');
          excerptKind = 'html-empty-attribute-token';
        } else {
          locator = copyLocator(candidateSource.locator);
          if (locator.kind !== 'text-range' || locator.endByte > sourceBytes.length) fail('EVIDENCE_INTEGRITY');
        }
        const excerptLength = locator.endByte - locator.startByte;
        if (excerptLength < 1 || excerptLength > assetPositionBytesLimit) fail('EVIDENCE_INVALID');
        const excerpt = Buffer.from(sourceBytes.subarray(locator.startByte, locator.endByte));
        candidateBuffers.push(excerpt);
        if (emptyAttributeToken) {
          if (emptyHtmlAttributeTokenState(excerpt, emptyAttributeNameForAssetForm(asset.sourceForm)) !== emptyAttributeToken.valueState) {
            excerpt.fill(0);
            fail('EVIDENCE_INTEGRITY');
          }
        } else if (excerpt.toString('utf8') !== candidate.rawValue || !isWellFormed(candidate.rawValue)) {
          excerpt.fill(0);
          fail('EVIDENCE_INTEGRITY');
        }
        const normalized = typeof candidate.normalizedValue === 'string' ? candidate.normalizedValue : null;
        const observation = assetUrlObservation(asset.urlPolicyValue, sourceUrl);
        const relationHint = typeof candidate.property === 'string' ? candidate.property
          : typeof candidateSource.property === 'string' ? candidateSource.property : null;
        const sortPointer = typeof candidateSource.jsonPointer === 'string' ? candidateSource.jsonPointer : '';
        return {
          sourceForm: asset.sourceForm,
          field: candidate.field,
          relationHint,
          association: cloneJsonValue(asset.association),
          locator,
          excerptKind,
          excerpt,
          contentHash: digest(excerpt),
          ...observation,
          sortPointer,
        };
      });
      ordered.sort((left, right) => left.locator.startByte - right.locator.startByte
        || left.locator.endByte - right.locator.endByte
        || left.sourceForm.localeCompare(right.sourceForm)
        || left.sortPointer.localeCompare(right.sortPointer));
      if (ordered.length > assetPositionLimit) fail('EVIDENCE_INVALID');
      let excerptBytesTotal = 0;
      for (let index = 0; index < ordered.length; index += 1) {
        excerptBytesTotal += ordered[index].excerpt.byteLength;
        if (!Number.isSafeInteger(excerptBytesTotal) || excerptBytesTotal > assetPositionTotalBytesLimit) fail('EVIDENCE_INVALID');
        positions.push({
          id: randomUUID(),
          locator: ordered[index].locator,
          contentHash: ordered[index].contentHash,
          bytes: ordered[index].excerpt,
        });
      }
      const candidates = ordered.map((candidate, index) => ({
        candidateId: `asset-${String(index + 1).padStart(2, '0')}`,
        positionIndex: index,
        sourceForm: candidate.sourceForm,
        field: candidate.field,
        relationHint: candidate.relationHint,
        association: candidate.association,
        locator: candidate.locator,
        excerptHash: candidate.contentHash,
        excerptKind: candidate.excerptKind,
        normalizedSuggestion: candidate.normalizedSuggestion,
        fetchSuggestion: candidate.fetchSuggestion,
        quarantineReason: candidate.quarantineReason,
        role: 'unknown',
        permission: 'unknown',
        inspection: 'pending',
      }));
      const assetSource = {
        bindingVersion: ASSET_SOURCE_BINDING_VERSION,
        selectorVersion: ASSET_SOURCE_SELECTOR_VERSION,
        extractorVersion: extraction.extractorVersion,
        sourceUrl,
        sourceKind,
        completeness: currentProfile.completeness,
        limitations: [...currentProfile.limitations],
        candidates,
      };
      const assetMetadataBytes = Buffer.byteLength(JSON.stringify(assetSource), 'utf8');
      if (!Number.isSafeInteger(assetMetadataBytes) || assetMetadataBytes > ASSET_SOURCE_MAX_METADATA_BYTES) fail('EVIDENCE_INVALID');
      const derivationDigest = digest(Buffer.from(JSON.stringify(assetDerivationMaterial(sourceContentHash, assetSource, positions)), 'utf8'));
      assetSource.derivationDigest = derivationDigest;
      const sourceProvenance = {
        sourceUrl,
        canonicalUrl: normalizeSourceUrl(sourceUrl),
        redirectChain: [],
        contentType: documentInput.contentType,
        sourceKind,
        retrievedAt,
        retrievedAtMs,
        contentHash: sourceContentHash,
      };
      const provenanceBytes = Buffer.byteLength(JSON.stringify({ source: sourceProvenance, assetSource }), 'utf8')
        + positions.reduce((sum, position) => sum + Buffer.byteLength(JSON.stringify(position.locator), 'utf8') + 128, 0);
      if (!Number.isSafeInteger(provenanceBytes) || provenanceBytes > SELECTED_BATCH_LIMITS.provenanceBytes) fail('EVIDENCE_INVALID');
      const positionIds = positions.map((position) => position.id);
      const positionHashes = Object.fromEntries(positions.map((position) => [position.id, position.contentHash]));
      const bundle = {
        schemaVersion: ASSET_SOURCE_BUNDLE_VERSION,
        representation: ASSET_SOURCE_EXCERPT_REPRESENTATION,
        derivationDigest,
        source: sourceProvenance,
        assetSource,
        positions: positions.map((position) => ({
          id: position.id,
          locator: position.locator,
          contentHash: position.contentHash,
          content: position.bytes.toString('base64'),
        })),
      };
      const serialized = JSON.stringify(bundle);
      if (Buffer.byteLength(serialized, 'utf8') > SELECTED_BATCH_LIMITS.evidenceDecryptedBytes) fail('EVIDENCE_INVALID');
      checkCancellation(signal);
      if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');

      const action = 'ingest_asset_source_evidence';
      activeIndexKey = await resolveKey(info, 'source-index', undefined, signal);
      const sourceIdentity = `event-intelligence:source-family:${ASSET_SOURCE_EXCERPT_REPRESENTATION}:v1\u0000${sourceKind}\u0000${normalizeSourceUrl(sourceUrl)}`;
      const currentFamilyHmac = stableHmac(activeIndexKey.key, sourceIdentity);
      const directory = await tenantDirectory(info);
      directoryForCleanup = directory;
      const snapshot = await withExpiryAwareTenantLock(info, directory, async (database) => {
        const manifest = await readManifest(database, info.tenantHash);
        await expireRecords(database, manifest, currentTime());
        const row = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
        return { document: row?.document ?? null };
      }, signal);
      const manifest = snapshot.document === null ? emptyManifest(info.tenantHash)
        : validateManifest(JSON.parse(snapshot.document), info.tenantHash);
      const sourceFamilies = Object.values(manifest.families)
        .filter((family) => family.representation === ASSET_SOURCE_EXCERPT_REPRESENTATION);
      if (sourceFamilies.length > 256) fail('EVIDENCE_BUSY');
      let family = sourceFamilies.find((candidate) => candidate.sourceKeyId === activeIndexKey.keyId
        && candidate.sourceKeyHmac === currentFamilyHmac);
      if (!family) {
        for (const candidate of sourceFamilies) {
          if (candidate.sourceKeyId === activeIndexKey.keyId) continue;
          const oldIndexKey = await resolveKey(info, 'source-index', candidate.sourceKeyId, signal);
          historicalIndexKeys.push(oldIndexKey.key);
          if (candidate.sourceKeyHmac === stableHmac(oldIndexKey.key, sourceIdentity)) {
            family = candidate;
            break;
          }
        }
      }
      const familyRecordIds = family ? safeArray(family.recordIds, 100_000) : [];
      if (!familyRecordIds) fail('EVIDENCE_INTEGRITY');
      const existingRecord = familyRecordIds.map((id) => manifest.records[id]).find((candidate) =>
        candidate?.state === 'available' && candidate.representation === ASSET_SOURCE_EXCERPT_REPRESENTATION
          && candidate.contentHash === sourceContentHash && candidate.derivationDigest === derivationDigest);
      if (existingRecord) {
        const existingSnapshot = copyEvidenceRecord(existingRecord, ASSET_SOURCE_MAX_POSITIONS);
        await authorize(info, request, action, [existingRecord.id], [], signal);
        checkCancellation(signal);
        authorizeCurrent(info, request, action, [existingRecord.id]);
        checkCancellation(signal);
        if (existingRecord.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        if (existingRecord.expiresAtMs > retention.expiresAtMs) fail('EVIDENCE_DENIED');
        await withTenantLock(directory, limits.lockTimeoutMs, (database, lockSignal) => {
          checkCancellation(lockSignal);
          if (existingRecord.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
          const currentRow = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
          if ((currentRow?.document ?? null) !== snapshot.document) fail('EVIDENCE_BUSY');
          const bundleCount = Number(database.prepare('SELECT COUNT(*) AS count FROM sealed_bundles WHERE kind = ? AND id = ?')
            .get('evidence', existingRecord.id).count);
          if (bundleCount !== 1) fail('EVIDENCE_EXPIRED');
          checkCancellation(lockSignal);
          if (existingRecord.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        }, signal, {
          beforeBegin: () => {
            authorizeCurrent(info, request, action, [existingRecord.id]);
            checkCancellation(signal);
          },
        });
        checkCancellation(signal);
        if (existingRecord.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        return Object.freeze({
          outcome: 'stored',
          evidence: newEvidenceHandle(info, existingRecord.id),
          positions: Object.freeze(existingSnapshot.positionIds.map((id) => newPositionHandle(
            info, existingRecord.id, id, sourceKind, ASSET_SOURCE_EXCERPT_REPRESENTATION,
          ))),
          created: false,
          metadata: frozenMetadata(existingSnapshot),
        });
      }

      const activeFamily = family;
      const latestId = activeFamily?.recordIds.at(-1);
      const latest = latestId ? manifest.records[latestId] : null;
      const evidenceId = randomUUID();
      payloadKey = await resolveKey(info, 'payload', undefined, signal);
      sealedBytes = encodeSealedPayload(info.tenantHash, evidenceId, 'evidence', serialized, payloadKey.keyId, payloadKey.key);
      await authorize(info, request, action, [evidenceId], [], signal);
      checkCancellation(signal);
      authorizeCurrent(info, request, action, [evidenceId]);
      checkCancellation(signal);
      const finalNow = currentTime();
      if (retention.expiresAtMs <= finalNow) fail('EVIDENCE_EXPIRED');
      const nowIso = new Date(finalNow).toISOString();
      const version = activeFamily ? (activeFamily.versionCount ?? activeFamily.recordIds.length) + 1 : 1;
      const familyId = activeFamily?.id ?? randomUUID();
      const record = {
        id: evidenceId,
        version,
        previousId: latest?.id ?? null,
        contentHash: sourceContentHash,
        duplicateGroupId: digest(Buffer.from(`event-intelligence:duplicate:v1:${info.tenantHash}:${sourceContentHash}`, 'utf8')),
        retrievedAt,
        createdAt: nowIso,
        createdAtMs: finalNow,
        retrievedAtMs,
        expiresAtMs: retention.expiresAtMs,
        policyId: retention.policyId,
        policyVersion: retention.policyVersion,
        state: 'available',
        encryptionKeyId: payloadKey.keyId,
        positionIds,
        positionHashes,
        representation: ASSET_SOURCE_EXCERPT_REPRESENTATION,
        derivationDigest,
      };
      await withTenantLock(directory, limits.lockTimeoutMs, (database, lockSignal) => {
        checkCancellation(lockSignal);
        if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        const currentRow = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
        if ((currentRow?.document ?? null) !== snapshot.document) fail('EVIDENCE_BUSY');
        const currentManifest = snapshot.document === null ? emptyManifest(info.tenantHash)
          : validateManifest(JSON.parse(currentRow.document), info.tenantHash);
        if (currentManifest.records[evidenceId]) fail('EVIDENCE_BUSY');
        currentManifest.schemaVersion = Math.max(currentManifest.schemaVersion, ASSET_SOURCE_BUNDLE_VERSION);
        currentManifest.records[evidenceId] = record;
        let currentFamily = activeFamily ? currentManifest.families[activeFamily.id] : null;
        if (activeFamily && !currentFamily) fail('EVIDENCE_BUSY');
        if (!currentFamily) {
          currentFamily = {
            id: familyId,
            representation: ASSET_SOURCE_EXCERPT_REPRESENTATION,
            sourceKeyId: activeIndexKey.keyId,
            sourceKeyHmac: currentFamilyHmac,
            versionCount: 0,
            recordIds: [],
          };
          currentManifest.families[familyId] = currentFamily;
        }
        if (currentFamily.representation !== ASSET_SOURCE_EXCERPT_REPRESENTATION) fail('EVIDENCE_INTEGRITY');
        currentFamily.recordIds.push(evidenceId);
        currentFamily.versionCount = version;
        const manifestDocument = JSON.stringify(currentManifest);
        if (Buffer.byteLength(manifestDocument, 'utf8') > 16 * 1024 * 1024) fail('EVIDENCE_STORAGE');
        database.prepare('INSERT INTO sealed_bundles (kind, id, sealed) VALUES (?, ?, ?)').run('evidence', evidenceId, sealedBytes);
        database.prepare(`INSERT INTO evidence_manifest (tenant_hash, document) VALUES (?, ?)
          ON CONFLICT (tenant_hash) DO UPDATE SET document = excluded.document`).run(info.tenantHash, manifestDocument);
        checkCancellation(lockSignal);
        if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
      }, signal, {
        beforeBegin: () => {
          authorizeCurrent(info, request, action, [evidenceId]);
          checkCancellation(signal);
        },
      });
      checkCancellation(signal);
      if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
      return Object.freeze({
        outcome: 'stored',
        evidence: newEvidenceHandle(info, evidenceId),
        positions: Object.freeze(positions.map((position) => newPositionHandle(
          info, evidenceId, position.id, sourceKind, ASSET_SOURCE_EXCERPT_REPRESENTATION,
        ))),
        created: true,
        metadata: frozenMetadata(record),
      });
    } catch (error) {
      if (error instanceof EvidenceStoreError && error.code === 'EVIDENCE_EXPIRED' && directoryForCleanup) {
        try { await persistExpirySweep(info, directoryForCleanup, signal); } catch (cleanupError) { throw safePublicError(cleanupError); }
      }
      throw safePublicError(error);
    } finally {
      sourceBytes.fill(0);
      for (const position of positions) position.bytes.fill(0);
      for (const bytes of candidateBuffers) bytes.fill(0);
      activeIndexKey?.key.fill(0);
      payloadKey?.key.fill(0);
      for (const key of historicalIndexKeys) key.fill(0);
      sealedBytes?.fill(0);
    }
  }

  async function ingestDerivedPdfEvidence(scope, inputValue, request, signal) {
    const info = scopeInfo(scope);
    const input = ownDataRecord(inputValue, new Set([
      'sourceUrl', 'canonicalUrl', 'redirectChain', 'content', 'contentType', 'retrievedAt', 'sourceKind',
      'retentionHandle', 'readerOptions',
    ]));
    if (!input || typeof input.sourceUrl !== 'string' || !SUPPORTED_SOURCE_KINDS.has(input.sourceKind)
      || !validTimestamp(input.retrievedAt) || typeof input.contentType !== 'string'
      || input.contentType.length < 1 || input.contentType.length > 160 || !/^[\x20-\x7e]+$/.test(input.contentType)
      || input.contentType.toLowerCase().split(';', 1)[0].trim() !== PDF_DERIVED_CONTENT_TYPE
      || !input.retentionHandle || typeof input.retentionHandle !== 'object') fail('EVIDENCE_INVALID');
    validateUrl(input.sourceUrl);
    const sourceUrl = input.sourceUrl;
    const canonicalUrl = input.canonicalUrl === undefined ? normalizeSourceUrl(sourceUrl) : normalizeSourceUrl(input.canonicalUrl);
    const redirectsInput = input.redirectChain === undefined ? [] : safeArray(input.redirectChain, 20);
    if (!redirectsInput) fail('EVIDENCE_INVALID');
    const redirectChain = redirectsInput.map((item) => validateUrl(item).href);
    const readerInput = input.readerOptions === undefined
      ? Object.create(null)
      : ownDataRecord(input.readerOptions, new Set(['timeoutMs', 'maxTextCodeUnits', 'maxOutputBytes']));
    if (!readerInput) fail('EVIDENCE_INVALID');
    const sourceLimit = Math.min(limits.maxSourceBytes, PDF_DERIVED_MAX_SOURCE_BYTES, PDF_TEXT_READER_LIMITS.maxInputBytes);
    // A PDF source is the exact fetched byte stream. Accepting text here would
    // re-encode bytes and make the stored source digest describe a conversion,
    // not the original document supplied by the fetch boundary.
    if (!(input.content instanceof Uint8Array)) fail('EVIDENCE_INVALID');
    const sourceBytes = copyBytes(input.content, sourceLimit);
    const sourceContentHash = digest(sourceBytes);
    const retrievedAtMs = Date.parse(input.retrievedAt);
    const retentionStartMs = currentTime();
    let retention;
    let activeIndexKey;
    let payloadKey;
    let sealedBytes;
    const historicalIndexKeys = [];
    let positions = [];
    let directoryForCleanup;
    try {
      checkCancellation(signal);
      // Resolve the source's already-authorized retention deadline before starting
      // the killable decoder. Decode time never resets or extends this deadline.
      retention = await resolveRetention(info, 'evidence', retentionStartMs, input.sourceKind, undefined, input.retentionHandle, signal);
      if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
      const timeoutMs = readerInput.timeoutMs ?? PDF_DERIVED_DEFAULT_TIMEOUT_MS;
      const effectiveTextLimit = Math.min(
        PDF_TEXT_READER_LIMITS.maxTextCodeUnits,
        limits.maxStoredPayloadBytes,
        SELECTED_BATCH_LIMITS.evidenceDecryptedBytes,
      );
      const effectiveOutputLimit = Math.min(
        PDF_TEXT_READER_LIMITS.maxOutputBytes,
        SELECTED_BATCH_LIMITS.evidenceDecryptedBytes,
        Math.max(4_096, limits.maxStoredPayloadBytes),
      );
      const maxTextCodeUnits = readerInput.maxTextCodeUnits ?? effectiveTextLimit;
      const maxOutputBytes = readerInput.maxOutputBytes ?? effectiveOutputLimit;
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > PDF_TEXT_READER_LIMITS.maxTimeoutMs
        || !Number.isSafeInteger(maxTextCodeUnits) || maxTextCodeUnits < 1
        || maxTextCodeUnits > effectiveTextLimit
        || !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 4_096
        || maxOutputBytes > effectiveOutputLimit) fail('EVIDENCE_INVALID');

      let readResult;
      try {
        readResult = await readTextPdf(sourceBytes, { signal, timeoutMs, maxTextCodeUnits, maxOutputBytes });
      } catch {
        checkCancellation(signal);
        if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        return Object.freeze({ outcome: 'rejected', code: 'DECODER_FAILURE' });
      }
      checkCancellation(signal);
      if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
      if (!readResult || readResult.kind === 'rejected') {
        const code = readResult?.code;
        return Object.freeze({ outcome: 'rejected', code: typeof code === 'string' ? code : 'DECODER_FAILURE' });
      }
      if (readResult.documentSha256 !== sourceContentHash || readResult.decoder?.name !== 'pdfjs-dist'
        || readResult.decoder.version !== PDF_DECODER_VERSION || readResult.decoder.configVersion !== PDF_READER_CONFIG_VERSION
        || readResult.networkAttemptCount !== 0 || readResult.completeness !== 'incomplete-text-only'
        || readResult.requiresInspection !== true || !isRecord(readResult.limits)) fail('EVIDENCE_INTEGRITY');
      if (readResult.kind === 'no-text') {
        if (readResult.code !== 'NO_EMBEDDED_TEXT') fail('EVIDENCE_INTEGRITY');
        return Object.freeze({ outcome: 'no-text', code: 'NO_EMBEDDED_TEXT', requiresInspection: true });
      }
      if (readResult.kind !== 'observation') fail('EVIDENCE_INTEGRITY');

      const pageInputs = safeArray(readResult.pages, PDF_TEXT_READER_LIMITS.maxPages);
      if (!pageInputs || pageInputs.length < 1) fail('EVIDENCE_INTEGRITY');
      const pageMetadata = [];
      positions = [];
      let positionBytesTotal = 0;
      const positionMaximum = Math.min(limits.maxPositionCount, SELECTED_BATCH_LIMITS.positionCount);
      const positionByteMaximum = Math.min(limits.maxPositionBytes, SELECTED_BATCH_LIMITS.positionRecordBytes);
      const totalByteMaximum = Math.min(limits.maxStoredPayloadBytes, SELECTED_BATCH_LIMITS.evidencePositionBytes);
      for (let pageIndex = 0; pageIndex < pageInputs.length; pageIndex += 1) {
        const page = ownDataRecord(pageInputs[pageIndex], new Set([
          'pageIndex', 'width', 'height', 'rotation', 'coordinateSystem', 'textPresence', 'requiresInspection', 'textBoxes',
        ]));
        const boxes = safeArray(page?.textBoxes, PDF_TEXT_READER_LIMITS.maxTextItems);
        if (!page || page.pageIndex !== pageIndex || ![page.width, page.height].every(Number.isFinite)
          || page.width <= 0 || page.height <= 0 || page.width > PDF_TEXT_READER_LIMITS.maxPagePoints
          || page.height > PDF_TEXT_READER_LIMITS.maxPagePoints || ![0, 90, 180, 270].includes(page.rotation)
          || page.coordinateSystem !== 'viewport-points-top-left' || page.requiresInspection !== true
          || !['text-present', 'no-embedded-text'].includes(page.textPresence) || !boxes
          || (boxes.length > 0 && page.textPresence !== 'text-present')
          || (boxes.length === 0 && page.textPresence !== 'no-embedded-text')) fail('EVIDENCE_INTEGRITY');
        pageMetadata.push({
          pageIndex, width: page.width, height: page.height, rotation: page.rotation,
          coordinateSystem: page.coordinateSystem, textPresence: page.textPresence,
          requiresInspection: true, textBoxCount: boxes.length,
        });
        for (let textIndex = 0; textIndex < boxes.length; textIndex += 1) {
          const box = ownDataRecord(boxes[textIndex], new Set(['x', 'y', 'width', 'height', 'text', 'geometry']));
          if (!box || typeof box.text !== 'string' || box.text.length === 0 || !isWellFormed(box.text)
            || box.text.length > PDF_TEXT_READER_LIMITS.maxTextItemCodeUnits || box.geometry !== 'approximate-text-item'
            || ![box.x, box.y, box.width, box.height].every(Number.isFinite)
            || box.x < 0 || box.y < 0 || box.width < 0 || box.height < 0
            || box.x + box.width > page.width + 0.01 || box.y + box.height > page.height + 0.01) fail('EVIDENCE_INTEGRITY');
          if (positions.length >= positionMaximum) fail('EVIDENCE_INVALID');
          const content = Buffer.from(box.text, 'utf8');
          if (content.toString('utf8') !== box.text || content.byteLength > positionByteMaximum) {
            content.fill(0);
            fail('EVIDENCE_INVALID');
          }
          positionBytesTotal += content.byteLength;
          if (!Number.isSafeInteger(positionBytesTotal) || positionBytesTotal > totalByteMaximum) {
            content.fill(0);
            fail('EVIDENCE_INVALID');
          }
          const locator = Object.freeze({
            kind: 'pdf-text-box', pageIndex, textIndex,
            x: box.x, y: box.y, width: box.width, height: box.height,
            pageWidth: page.width, pageHeight: page.height, rotation: page.rotation,
            coordinateSystem: page.coordinateSystem, geometry: box.geometry,
          });
          positions.push({ id: randomUUID(), locator, contentHash: digest(content), bytes: content });
        }
      }
      if (positions.length === 0) fail('EVIDENCE_INTEGRITY');

      const limitsCopy = {
        maxInputBytes: readResult.limits.maxInputBytes,
        maxPages: readResult.limits.maxPages,
        maxPagePoints: readResult.limits.maxPagePoints,
        maxTextCodeUnits: readResult.limits.maxTextCodeUnits,
        maxTextItemCodeUnits: readResult.limits.maxTextItemCodeUnits,
        maxTextItems: readResult.limits.maxTextItems,
        maxOutputBytes: readResult.limits.maxOutputBytes,
        addressSpaceBytes: readResult.limits.addressSpaceBytes,
        maxCpuSeconds: readResult.limits.maxCpuSeconds,
        maxWallMilliseconds: readResult.limits.maxWallMilliseconds,
      };
      if (Object.values(limitsCopy).some((value) => !Number.isSafeInteger(value) || value <= 0)) fail('EVIDENCE_INTEGRITY');
      const derivedPdf = {
        bindingVersion: PDF_DERIVATION_BINDING_VERSION,
        decoder: { name: readResult.decoder.name, version: readResult.decoder.version, configVersion: readResult.decoder.configVersion },
        completeness: readResult.completeness,
        requiresInspection: true,
        limits: limitsCopy,
        pages: pageMetadata,
        textBoxCount: positions.length,
      };
      const derivationMaterial = {
        bindingVersion: derivedPdf.bindingVersion,
        sourceContentHash,
        decoder: derivedPdf.decoder,
        completeness: derivedPdf.completeness,
        requiresInspection: derivedPdf.requiresInspection,
        limits: derivedPdf.limits,
        pages: pageMetadata,
        positions: positions.map((position) => ({ locator: position.locator, contentHash: position.contentHash })),
      };
      const derivationDigest = digest(Buffer.from(JSON.stringify(derivationMaterial), 'utf8'));
      derivedPdf.derivationDigest = derivationDigest;
      const sourceProvenance = {
        sourceUrl, canonicalUrl, redirectChain, contentType: input.contentType,
        sourceKind: input.sourceKind, retrievedAt: input.retrievedAt, retrievedAtMs, contentHash: sourceContentHash,
      };
      const provenanceBytes = Buffer.byteLength(JSON.stringify({ source: sourceProvenance, derivedPdf }), 'utf8')
        + positions.reduce((sum, position) => sum + Buffer.byteLength(JSON.stringify(position.locator), 'utf8') + 128, 0);
      if (!Number.isSafeInteger(provenanceBytes) || provenanceBytes > SELECTED_BATCH_LIMITS.provenanceBytes) fail('EVIDENCE_INVALID');
      const positionIds = positions.map((position) => position.id);
      const positionHashes = Object.fromEntries(positions.map((position) => [position.id, position.contentHash]));
      const bundle = {
        schemaVersion: PDF_DERIVED_BUNDLE_VERSION,
        representation: PDF_DERIVED_REPRESENTATION,
        derivationDigest,
        source: sourceProvenance,
        derivedPdf,
        positions: positions.map((position) => ({
          id: position.id, locator: position.locator, contentHash: position.contentHash, content: position.bytes.toString('base64'),
        })),
      };
      const serialized = JSON.stringify(bundle);
      if (Buffer.byteLength(serialized, 'utf8') > SELECTED_BATCH_LIMITS.evidenceDecryptedBytes) fail('EVIDENCE_INVALID');

      const action = 'ingest_derived_pdf_evidence';
      activeIndexKey = await resolveKey(info, 'source-index', undefined, signal);
      const derivedIdentity = `event-intelligence:source-family:pdf-derived:v1\u0000${input.sourceKind}\u0000${normalizeSourceUrl(canonicalUrl)}`;
      const currentFamilyHmac = stableHmac(activeIndexKey.key, derivedIdentity);
      const directory = await tenantDirectory(info);
      directoryForCleanup = directory;
      const snapshot = await withExpiryAwareTenantLock(info, directory, async (database) => {
        const manifest = await readManifest(database, info.tenantHash);
        await expireRecords(database, manifest, currentTime());
        const row = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
        return { document: row?.document ?? null };
      }, signal);
      let manifest = snapshot.document === null ? emptyManifest(info.tenantHash) : validateManifest(JSON.parse(snapshot.document), info.tenantHash);
      const derivedFamilies = Object.values(manifest.families).filter((family) => family.representation === PDF_DERIVED_REPRESENTATION);
      if (derivedFamilies.length > 256) fail('EVIDENCE_BUSY');
      let family = derivedFamilies.find((candidate) => candidate.sourceKeyId === activeIndexKey.keyId
        && candidate.sourceKeyHmac === currentFamilyHmac);
      if (!family) {
        for (const candidate of derivedFamilies) {
          if (candidate.sourceKeyId === activeIndexKey.keyId) continue;
          const oldIndexKey = await resolveKey(info, 'source-index', candidate.sourceKeyId, signal);
          historicalIndexKeys.push(oldIndexKey.key);
          if (candidate.sourceKeyHmac === stableHmac(oldIndexKey.key, derivedIdentity)) {
            family = candidate;
            break;
          }
        }
      }
      const familyRecordIds = family ? safeArray(family.recordIds, 100_000) : [];
      if (!familyRecordIds) fail('EVIDENCE_INTEGRITY');
      const existingRecord = familyRecordIds.map((id) => manifest.records[id]).find((candidate) =>
        candidate?.state === 'available' && candidate.representation === PDF_DERIVED_REPRESENTATION
          && candidate.contentHash === sourceContentHash && candidate.derivationDigest === derivationDigest);
      if (existingRecord) {
        const existingSnapshot = copyEvidenceRecord(existingRecord, limits.maxPositionCount);
        await authorize(info, request, action, [existingRecord.id], [], signal);
        checkCancellation(signal);
        authorizeCurrent(info, request, action, [existingRecord.id]);
        checkCancellation(signal);
        if (existingRecord.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        if (existingRecord.expiresAtMs > retention.expiresAtMs) fail('EVIDENCE_DENIED');
        await withTenantLock(directory, limits.lockTimeoutMs, (database, lockSignal) => {
          checkCancellation(lockSignal);
          if (existingRecord.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
          const currentRow = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
          if ((currentRow?.document ?? null) !== snapshot.document) fail('EVIDENCE_BUSY');
          const bundleCount = Number(database.prepare('SELECT COUNT(*) AS count FROM sealed_bundles WHERE kind = ? AND id = ?').get('evidence', existingRecord.id).count);
          if (bundleCount !== 1) fail('EVIDENCE_EXPIRED');
          checkCancellation(lockSignal);
          if (existingRecord.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        }, signal, {
          beforeBegin: () => {
            authorizeCurrent(info, request, action, [existingRecord.id]);
            checkCancellation(signal);
          },
        });
        checkCancellation(signal);
        if (existingRecord.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        return Object.freeze({
          outcome: 'stored', evidence: newEvidenceHandle(info, existingRecord.id),
          positions: Object.freeze(existingSnapshot.positionIds.map((id) => newPositionHandle(info, existingRecord.id, id, input.sourceKind, PDF_DERIVED_REPRESENTATION))),
          created: false, metadata: frozenMetadata(existingSnapshot),
        });
      }

      const activeFamily = family;
      const latestId = activeFamily?.recordIds.at(-1);
      const latest = latestId ? manifest.records[latestId] : null;
      const evidenceId = randomUUID();
      payloadKey = await resolveKey(info, 'payload', undefined, signal);
      sealedBytes = encodeSealedPayload(info.tenantHash, evidenceId, 'evidence', serialized, payloadKey.keyId, payloadKey.key);
      await authorize(info, request, action, [evidenceId], [], signal);
      checkCancellation(signal);
      authorizeCurrent(info, request, action, [evidenceId]);
      checkCancellation(signal);
      const finalNow = currentTime();
      if (retention.expiresAtMs <= finalNow) fail('EVIDENCE_EXPIRED');
      const nowIso = new Date(finalNow).toISOString();
      const version = activeFamily ? (activeFamily.versionCount ?? activeFamily.recordIds.length) + 1 : 1;
      const familyId = activeFamily?.id ?? randomUUID();
      const record = {
        id: evidenceId,
        version,
        previousId: latest?.id ?? null,
        contentHash: sourceContentHash,
        duplicateGroupId: digest(Buffer.from(`event-intelligence:duplicate:v1:${info.tenantHash}:${sourceContentHash}`, 'utf8')),
        retrievedAt: input.retrievedAt,
        createdAt: nowIso,
        createdAtMs: finalNow,
        retrievedAtMs,
        expiresAtMs: retention.expiresAtMs,
        policyId: retention.policyId,
        policyVersion: retention.policyVersion,
        state: 'available',
        encryptionKeyId: payloadKey.keyId,
        positionIds,
        positionHashes,
        representation: PDF_DERIVED_REPRESENTATION,
        derivationDigest,
      };

      await withTenantLock(directory, limits.lockTimeoutMs, (database, lockSignal) => {
        checkCancellation(lockSignal);
        if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        const currentRow = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
        if ((currentRow?.document ?? null) !== snapshot.document) fail('EVIDENCE_BUSY');
        const currentManifest = snapshot.document === null
          ? emptyManifest(info.tenantHash)
          : validateManifest(JSON.parse(currentRow.document), info.tenantHash);
        if (currentManifest.records[evidenceId]) fail('EVIDENCE_BUSY');
        currentManifest.schemaVersion = Math.max(currentManifest.schemaVersion, PDF_DERIVED_BUNDLE_VERSION);
        currentManifest.records[evidenceId] = record;
        let currentFamily = activeFamily ? currentManifest.families[activeFamily.id] : null;
        if (activeFamily && !currentFamily) fail('EVIDENCE_BUSY');
        if (!currentFamily) {
          currentFamily = {
            id: familyId,
            representation: PDF_DERIVED_REPRESENTATION,
            sourceKeyId: activeIndexKey.keyId,
            sourceKeyHmac: currentFamilyHmac,
            versionCount: 0,
            recordIds: [],
          };
          currentManifest.families[familyId] = currentFamily;
        }
        if (currentFamily.representation !== PDF_DERIVED_REPRESENTATION) fail('EVIDENCE_INTEGRITY');
        currentFamily.recordIds.push(evidenceId);
        currentFamily.versionCount = version;
        const document = JSON.stringify(currentManifest);
        if (Buffer.byteLength(document, 'utf8') > 16 * 1024 * 1024) fail('EVIDENCE_STORAGE');
        database.prepare('INSERT INTO sealed_bundles (kind, id, sealed) VALUES (?, ?, ?)').run('evidence', evidenceId, sealedBytes);
        database.prepare(`INSERT INTO evidence_manifest (tenant_hash, document) VALUES (?, ?)
          ON CONFLICT (tenant_hash) DO UPDATE SET document = excluded.document`).run(info.tenantHash, document);
        checkCancellation(lockSignal);
        if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
      }, signal, {
        beforeBegin: () => {
          authorizeCurrent(info, request, action, [evidenceId]);
          checkCancellation(signal);
        },
      });
      checkCancellation(signal);
      if (retention.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
      return Object.freeze({
        outcome: 'stored', evidence: newEvidenceHandle(info, evidenceId),
        positions: Object.freeze(positions.map((position) => newPositionHandle(info, evidenceId, position.id, input.sourceKind, PDF_DERIVED_REPRESENTATION))),
        created: true, metadata: frozenMetadata(record),
      });
    } catch (error) {
      if (error instanceof EvidenceStoreError && error.code === 'EVIDENCE_EXPIRED') {
        if (directoryForCleanup) {
          try { await persistExpirySweep(info, directoryForCleanup, signal); } catch (cleanupError) { throw safePublicError(cleanupError); }
        }
      }
      throw safePublicError(error);
    } finally {
      sourceBytes.fill(0);
      for (const position of positions) position.bytes.fill(0);
      sealedBytes?.fill(0);
      activeIndexKey?.key.fill(0);
      payloadKey?.key.fill(0);
      for (const key of historicalIndexKeys) key.fill(0);
    }
  }

  async function lookupEvidence(scope, evidenceId, signal) {
    const info = scopeInfo(scope);
    checkCancellation(signal);
    if (!validUuid(evidenceId)) fail('EVIDENCE_NOT_FOUND');
    const directory = await tenantDirectory(info);
    try {
      return await withExpiryAwareTenantLock(info, directory, async (database) => {
        const manifest = await readManifest(database, info.tenantHash);
        await expireRecords(database, manifest, currentTime());
        if (!manifest.records[evidenceId]) fail('EVIDENCE_NOT_FOUND');
        return newEvidenceHandle(info, evidenceId);
      }, signal);
    } catch (error) {
      throw safePublicError(error);
    }
  }

  async function getEvidenceMetadata(scope, handle) {
    const info = evidenceInfo(scope, handle);
    const directory = await tenantDirectory(info);
    try {
      return await withExpiryAwareTenantLock(info, directory, async (database) => {
        const manifest = await readManifest(database, info.tenantHash);
        await expireRecords(database, manifest, currentTime());
        const record = manifest.records[info.evidenceId];
        if (!record) fail('EVIDENCE_NOT_FOUND');
        return frozenMetadata(record);
      });
    } catch (error) {
      throw safePublicError(error);
    }
  }

  async function listEvidencePositions(scope, handle, request) {
    return materializeSelectedInternal(
      scope,
      { evidence: [handle], facts: [] },
      request,
      undefined,
      'list_evidence_positions',
      'positions',
    );
  }

  async function withPrivatePayloadInternal(scope, handle, request, signal, controlledAssetRead = false,
    assetSourceCandidateId = null) {
    const info = evidenceInfo(scope, handle);
    if (!controlledAssetRead && assetSourceCandidateId === null
      && typeof config.consumePrivatePayload !== 'function') fail('EVIDENCE_DENIED');
    checkCancellation(signal);
    const directory = await tenantDirectory(info);
    const budget = newMaterializationBudget();
    let snapshot;
    let bundle;
    let finalVerifier;
    let positions = [];
    let assetBytes;
    let sourceSnapshot;
    let authorizationEvidenceIds = [info.evidenceId];
    try {
      snapshot = await withExpiryAwareTenantLock(info, directory, async (database) => {
        const manifest = await readManifest(database, info.tenantHash);
        await expireRecords(database, manifest, currentTime());
        const record = manifest.records[info.evidenceId];
        if (!record) fail('EVIDENCE_NOT_FOUND');
        if (record.state !== 'available') fail('EVIDENCE_EXPIRED');
        const copied = copyEvidenceRecord(record, Math.min(limits.maxPositionCount, SELECTED_BATCH_LIMITS.positionCount), budget);
        const sealed = readSealedBundle(database, 'evidence', record.id);
        if (copied.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        return { ...copied, sealed, budget };
      }, signal);
      await authorize(info, request, 'read_private_evidence', [info.evidenceId], [], signal);
      bundle = await decryptSealedBundle(info, info.evidenceId, 'evidence', snapshot.sealed, snapshot.encryptionKeyId, resolveKey, budget, signal);
      const view = materializeEvidenceBundle(info, snapshot, bundle, budget);
      let privatePayloadBytes = 0;
      positions = bundle.positions.map((position) => {
        const contentBytes = base64DecodedByteLength(position.content);
        privatePayloadBytes += contentBytes;
        if (!Number.isSafeInteger(privatePayloadBytes)
          || privatePayloadBytes > Math.min(limits.maxStoredPayloadBytes, SELECTED_BATCH_LIMITS.evidencePositionBytes)) fail('EVIDENCE_INVALID');
        return Object.freeze({
          locator: deepFreeze(cloneJsonValue(position.locator)),
          contentHash: position.contentHash,
          content: Buffer.from(position.content, 'base64'),
        });
      });
      if (controlledAssetRead) {
        const controlled = view.source.controlledAsset;
        if (!controlled || positions.length < 1) fail('EVIDENCE_INTEGRITY');
        const sourceHandle = newEvidenceHandle(info, controlled.sourceEvidenceId);
        const currentSource = await readAssetSourceCandidateBinding(
          scope, sourceHandle, controlled.candidateId, request, signal,
        );
        if (!controlledAssetSourceMatches(controlled, currentSource)) fail('EVIDENCE_EXPIRED');
        sourceSnapshot = await withExpiryAwareTenantLock(info, directory, async (database) => {
          const manifest = await readManifest(database, info.tenantHash);
          await expireRecords(database, manifest, currentTime());
          const record = manifest.records[controlled.sourceEvidenceId];
          if (!record || record.state !== 'available' || record.version !== controlled.sourceEvidenceVersion
            || record.contentHash !== controlled.sourceContentHash || record.expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
          return copyEvidenceRecord(record, Math.min(limits.maxPositionCount, SELECTED_BATCH_LIMITS.positionCount), budget);
        }, signal);
        authorizationEvidenceIds = [info.evidenceId, controlled.sourceEvidenceId];
        const ordered = [...positions].sort((left, right) => left.locator.startByte - right.locator.startByte);
        const chunks = [];
        let covered = 0;
        try {
          for (const position of ordered) {
            if (position.locator.kind !== 'text-range' || position.locator.startByte !== covered
              || position.locator.endByte - position.locator.startByte !== position.content.byteLength) fail('EVIDENCE_INTEGRITY');
            covered = position.locator.endByte;
            chunks.push(position.content);
          }
          assetBytes = Buffer.concat(chunks, covered);
        } catch (error) {
          for (const chunk of chunks) if (chunk !== assetBytes) chunk.fill(0);
          throw error;
        }
        if (!controlledAssetProvenanceMatchesBytes(controlled, assetBytes, snapshot.contentHash)) fail('EVIDENCE_INTEGRITY');
      }
      let assetSourceCandidate;
      if (assetSourceCandidateId !== null) {
        if (typeof assetSourceCandidateId !== 'string' || !/^asset-[0-9]{2}$/.test(assetSourceCandidateId)
          || snapshot.representation !== ASSET_SOURCE_EXCERPT_REPRESENTATION || !view.source.assetSource
          || view.source.assetSource.sourceUrl !== view.source.sourceUrl
          || view.source.redirectChain.length !== 0) fail('EVIDENCE_INVALID');
        const matches = view.source.assetSource.candidates.filter((candidate) => candidate.candidateId === assetSourceCandidateId);
        if (matches.length !== 1) fail('EVIDENCE_INVALID');
        const candidate = matches[0];
        const position = positions[candidate.positionIndex];
        if (!position || candidate.quarantineReason !== null || candidate.fetchSuggestion === null
          || candidate.excerptHash !== position.contentHash
          || JSON.stringify(candidate.locator) !== JSON.stringify(position.locator)
          || position.content.byteLength < 1 || position.content.byteLength > ASSET_SOURCE_MAX_EXCERPT_BYTES
          || digest(position.content) !== candidate.excerptHash) fail('EVIDENCE_INTEGRITY');
        let value;
        try {
          value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(position.content);
        } catch {
          fail('EVIDENCE_INTEGRITY');
        }
        if (!isWellFormed(value) || value.length < 1 || value.length > 8_192
          || !Buffer.from(value, 'utf8').equals(position.content)) fail('EVIDENCE_INTEGRITY');
        assetSourceCandidate = Object.freeze({
          candidateId: candidate.candidateId,
          positionIndex: candidate.positionIndex,
          sourceForm: candidate.sourceForm,
          locator: deepFreeze(cloneJsonValue(candidate.locator)),
          excerptHash: candidate.excerptHash,
          field: candidate.field,
          fetchSuggestion: candidate.fetchSuggestion,
          quarantineReason: candidate.quarantineReason,
          value,
        });
      }
      finalVerifier = makeFinalStateVerifier(info, directory, authorizationEvidenceIds, []);
      authorizeCurrent(info, request, 'read_private_evidence', authorizationEvidenceIds);
      finalVerifier.check({ evidence: [snapshot, ...(sourceSnapshot ? [sourceSnapshot] : [])], facts: [] });
      if (currentTime() >= snapshot.expiresAtMs) fail('EVIDENCE_EXPIRED');
      let consumed;
      if (controlledAssetRead) {
        if (!assetBytes) fail('EVIDENCE_INTEGRITY');
      } else if (assetSourceCandidateId === null) {
        try {
          consumed = config.consumePrivatePayload(Object.freeze({
            tenantId: info.tenantId,
            evidenceId: info.evidenceId,
            metadata: frozenMetadata(snapshot),
            source: view.source,
            positions: Object.freeze(positions),
            request,
          }));
        } catch {
          fail('EVIDENCE_DENIED');
        }
      }
      if (!controlledAssetRead && assetSourceCandidateId === null && utilTypes.isPromise(consumed)) {
        observeNativeRejectedPromise(consumed);
        fail('EVIDENCE_DENIED');
      }
      if (!controlledAssetRead && assetSourceCandidateId === null) {
        try {
          consumed = copySynchronousConsumerResult(consumed);
        } catch {
          fail('EVIDENCE_DENIED');
        }
      }
      // The trusted consumer is synchronous, but it can reenter the host and
      // mutate the request or the persisted record. Revalidate before returning
      // its result, with no awaited work or write transaction held.
      authorizeCurrent(info, request, 'read_private_evidence', authorizationEvidenceIds);
      finalVerifier.check({ evidence: [snapshot, ...(sourceSnapshot ? [sourceSnapshot] : [])], facts: [] });
      if (currentTime() >= snapshot.expiresAtMs) fail('EVIDENCE_EXPIRED');
      if (controlledAssetRead) {
        const result = Object.freeze({
          evidenceId: info.evidenceId,
          metadata: frozenMetadata(snapshot),
          source: view.source,
          bytes: assetBytes,
        });
        assetBytes = undefined;
        return result;
      }
      if (assetSourceCandidateId !== null) {
        return Object.freeze({
          evidenceId: info.evidenceId,
          metadata: frozenMetadata(snapshot),
          source: view.source,
          candidate: assetSourceCandidate,
        });
      }
      return consumed;
    } catch (error) {
      if (error instanceof EvidenceStoreError && error.code === 'EVIDENCE_EXPIRED') {
        try { await persistExpirySweep(info, directory, signal); } catch (cleanupError) { throw safePublicError(cleanupError); }
      } else if (!(error instanceof EvidenceStoreError)) {
        try { await persistExpirySweep(info, directory, signal); } catch (cleanupError) { throw safePublicError(cleanupError); }
      }
      throw safePublicError(error);
    } finally {
      assetBytes?.fill(0);
      for (const position of positions) position.content.fill(0);
      snapshot?.sealed.fill(0);
      if (bundle) wipePrivateTree(bundle);
      finalVerifier?.close();
    }
  }

  async function withPrivatePayload(scope, handle, request) {
    return withPrivatePayloadInternal(scope, handle, request, undefined, false);
  }

  async function readAssetSourceCandidateBinding(scope, handle, candidateId, request, signal) {
    return withPrivatePayloadInternal(scope, handle, request, signal, false, candidateId);
  }

  async function readControlledAssetBytes(scope, handle, request, signal) {
    return withPrivatePayloadInternal(scope, handle, request, signal, true);
  }

  async function parseFactInput(inputValue) {
    const allowed = new Set(['field', 'status', 'rawValue', 'normalizedValue', 'precision', 'supports', 'method', 'reason', 'candidates']);
    const input = ownDataRecord(inputValue, allowed);
    if (!input || typeof input.field !== 'string' || !FACT_STATUSES.has(input.status)) fail('EVIDENCE_INVALID');
    const field = validateFactField(input.field);
    const valueBudget = { nodes: 0, bytes: 0, maximumBytes: SELECTED_BATCH_LIMITS.factRecordBytes };
    if (input.status === 'missing') {
      if (['rawValue', 'normalizedValue', 'precision', 'supports', 'method', 'candidates'].some((key) => Object.hasOwn(input, key))) fail('EVIDENCE_INVALID');
      if (input.reason !== undefined && (typeof input.reason !== 'string' || input.reason.length > 120 || !/^[A-Za-z0-9_.:-]+$/.test(input.reason))) fail('EVIDENCE_INVALID');
      return { field, status: 'missing', reason: input.reason ?? 'not_observed' };
    }
    if (input.status === 'conflicting') {
      if (['rawValue', 'normalizedValue', 'precision', 'supports', 'method', 'reason'].some((key) => Object.hasOwn(input, key))) fail('EVIDENCE_INVALID');
      const candidates = safeArray(input.candidates, 32);
      if (!candidates || candidates.length < 2) fail('EVIDENCE_INVALID');
      const parsedCandidates = candidates.map((candidate) => {
        const item = ownDataRecord(candidate, new Set(['originStatus', 'rawValue', 'normalizedValue', 'precision', 'supports', 'method']));
        if (!item || !FACT_ORIGINS.has(item.originStatus)) fail('EVIDENCE_INVALID');
        const value = extractValue(item, valueBudget);
        const method = validateMethod(item.method, item.originStatus === 'inferred');
        const supports = extractSupports(item.supports);
        if (supports.length === 0) fail('EVIDENCE_INVALID');
        return { originStatus: item.originStatus, ...value, method, supports };
      });
      return { field, status: 'conflicting', candidates: parsedCandidates };
    }
    if (Object.hasOwn(input, 'reason') || Object.hasOwn(input, 'candidates')) fail('EVIDENCE_INVALID');
    const value = extractValue(input, valueBudget);
    const method = validateMethod(input.method, input.status === 'inferred');
    const supports = extractSupports(input.supports);
    if (supports.length === 0) fail('EVIDENCE_INVALID');
    return { field, status: input.status, ...value, method, supports };
  }

  async function appendFact(scope, inputValue, request, signal) {
    const info = scopeInfo(scope);
    checkCancellation(signal);
    const parsed = await parseFactInput(inputValue);
    checkCancellation(signal);
    const allSupports = parsed.status === 'conflicting'
      ? parsed.candidates.flatMap((candidate) => candidate.supports)
      : parsed.supports ?? [];
    const supportRefs = allSupports.map((support) => {
      const evidence = EVIDENCE_HANDLES.get(support.evidence);
      const position = POSITION_HANDLES.get(support.position);
      if (!evidence || !position || evidence.tenantHash !== info.tenantHash || position.tenantHash !== info.tenantHash
        || evidence.evidenceId !== position.evidenceId || position.representation !== 'raw'
        || !isDigest(support.contentHash)) fail('EVIDENCE_INVALID');
      return { support, evidenceId: evidence.evidenceId, positionId: position.positionId, sourceKind: position.sourceKind };
    });
    const evidenceIds = supportRefs.map((reference) => reference.evidenceId);
    const directory = await tenantDirectory(info);
    let sealed;
    try {
      const uniqueEvidence = new Map();
      for (const support of supportRefs) uniqueEvidence.set(support.evidenceId, support.support.evidence);
      let materialized = null;
      if (uniqueEvidence.size > 0) {
        materialized = await materializeSelectedInternal(
          scope,
          { evidence: [...uniqueEvidence.values()], facts: [] },
          request,
          signal,
          'validate_fact_support',
          'selected',
          Math.min(SELECTED_BATCH_LIMITS.positionCount, limits.maxPositionCount),
          true,
        );
      } else {
        await authorize(info, request, 'validate_fact_support', [], [], signal);
      }
      checkCancellation(signal);

      const evidenceById = new Map((materialized?.evidence ?? []).map((evidence) => [
        EVIDENCE_HANDLES.get(evidence.handle)?.evidenceId,
        evidence,
      ]));
      for (const reference of supportRefs) {
        const evidence = evidenceById.get(reference.evidenceId);
        const record = evidence?.metadata;
        const position = evidence?.positions.find((candidate) =>
          POSITION_HANDLES.get(candidate.handle)?.positionId === reference.positionId);
        const receivedLocator = POSITION_HANDLES.get(reference.support.position);
        if (!record || !position || !receivedLocator || receivedLocator.positionId !== reference.positionId
          || record.representation !== undefined
          || record.contentHash !== reference.support.contentHash) fail('EVIDENCE_INVALID');
        reference.sourceContentHash = record.contentHash;
        reference.positionContentHash = position.contentHash;
        reference.duplicateGroupId = record.duplicateGroupId;
        if (reference.sourceKind === 'customer_supplied'
          && parsed.status !== 'customer_supplied' && parsed.status !== 'conflicting') fail('EVIDENCE_INVALID');
      }
      if (parsed.status === 'customer_supplied' && !supportRefs.some((reference) => reference.sourceKind === 'customer_supplied')) fail('EVIDENCE_INVALID');
      if (parsed.status === 'conflicting') {
        for (const candidate of parsed.candidates) {
          const candidateRefs = candidate.supports.map((support) => supportRefs.find((reference) => reference.support === support)).filter(Boolean);
          if (candidateRefs.length !== candidate.supports.length) fail('EVIDENCE_INVALID');
          if (candidate.originStatus === 'customer_supplied' && !candidateRefs.some((reference) => reference.sourceKind === 'customer_supplied')) fail('EVIDENCE_INVALID');
          if (candidate.originStatus !== 'customer_supplied' && candidateRefs.some((reference) => reference.sourceKind === 'customer_supplied')) fail('EVIDENCE_INVALID');
        }
      }

      // Capture the exact post-expiry manifest before calling retention/key hosts.
      // The final write CAS below compares this byte-for-byte inside BEGIN IMMEDIATE.
      const snapshot = await withExpiryAwareTenantLock(info, directory, async (database) => {
        const manifest = await readManifest(database, info.tenantHash);
        await expireRecords(database, manifest, currentTime());
        const row = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
        const document = row?.document ?? null;
        return {
          document,
          manifest: document === null ? emptyManifest(info.tenantHash) : validateManifest(JSON.parse(document), info.tenantHash),
        };
      }, signal);
      const supportRecords = [...new Set(evidenceIds)].map((id) => snapshot.manifest.records[id]);
      if (supportRecords.some((record) => !record || record.state !== 'available')) fail('EVIDENCE_EXPIRED');
      for (const reference of supportRefs) {
        const record = snapshot.manifest.records[reference.evidenceId];
        if (!record || record.representation !== undefined || record.contentHash !== reference.sourceContentHash
          || !record.positionIds.includes(reference.positionId)
          || record.positionHashes[reference.positionId] !== reference.positionContentHash) fail('EVIDENCE_INVALID');
      }
      const nowMs = currentTime();
      const supportExpiry = supportRecords.length ? Math.min(...supportRecords.map((record) => record.expiresAtMs)) : undefined;
      const factRetention = await resolveRetention(info, 'fact', nowMs, parsed.status, supportExpiry, undefined, signal);
      checkCancellation(signal);
      const afterRetention = currentTime();
      if (factRetention.expiresAtMs <= afterRetention
        || supportRecords.some((record) => record.expiresAtMs <= afterRetention)) fail('EVIDENCE_EXPIRED');
      const factId = randomUUID();
      const normalized = serializeFactForStorage(parsed, supportRefs);
      sealed = await encryptBundle(info, factId, 'fact', normalized, signal);
      checkCancellation(signal);
      authorizeCurrent(info, request, 'validate_fact_support', evidenceIds, []);
      checkCancellation(signal);
      const createdAtMs = currentTime();
      if (factRetention.expiresAtMs <= createdAtMs
        || supportRecords.some((record) => record.expiresAtMs <= createdAtMs)) fail('EVIDENCE_EXPIRED');
      const factMetadata = {
        id: factId,
        status: parsed.status,
        state: 'available',
        createdAt: new Date(createdAtMs).toISOString(),
        createdAtMs,
        expiresAtMs: factRetention.expiresAtMs,
        policyId: factRetention.policyId,
        policyVersion: factRetention.policyVersion,
        encryptionKeyId: sealed.keyId,
        supportEvidenceIds: [...new Set(evidenceIds)],
        supportContentHashes: [...new Set(supportRefs.map((reference) => reference.support.contentHash))],
      };
      return await withExpiryAwareTenantLock(info, directory, (database, lockSignal) => {
        checkCancellation(lockSignal);
        const currentRow = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
        if ((currentRow?.document ?? null) !== snapshot.document) fail('EVIDENCE_BUSY');
        const manifest = snapshot.document === null
          ? emptyManifest(info.tenantHash)
          : validateManifest(JSON.parse(currentRow.document), info.tenantHash);
        if (manifest.facts[factId]) fail('EVIDENCE_BUSY');
        const commitTime = currentTime();
        if (factRetention.expiresAtMs <= commitTime
          || supportRecords.some((record) => record.expiresAtMs <= commitTime
            || manifest.records[record.id]?.state !== 'available'
            || manifest.records[record.id]?.expiresAtMs !== record.expiresAtMs)) fail('EVIDENCE_EXPIRED');
        commitNewBundle(database, 'fact', factId, sealed.bytes);
        manifest.facts[factId] = factMetadata;
        writeManifest(database, manifest);
        checkCancellation(lockSignal);
        const beforeCommit = currentTime();
        if (factRetention.expiresAtMs <= beforeCommit
          || supportRecords.some((record) => record.expiresAtMs <= beforeCommit)) fail('EVIDENCE_EXPIRED');
        return newFactHandle(info, factId);
      }, signal, {
        beforeBegin: () => {
          authorizeCurrent(info, request, 'validate_fact_support', evidenceIds, []);
          checkCancellation(signal);
        },
      });
    } catch (error) {
      if (!(error instanceof EvidenceStoreError && error.code === 'EVIDENCE_CANCELLED')) {
        try { await persistExpirySweep(info, directory, signal); } catch (cleanupError) { throw safePublicError(cleanupError); }
      }
      throw safePublicError(error);
    } finally {
      sealed?.bytes.fill(0);
    }
  }

  function serializeFactForStorage(parsed, supportRefs) {
    const refs = supportRefs.map((reference) => ({
      evidenceId: reference.evidenceId,
      positionId: reference.positionId,
      contentHash: reference.support.contentHash,
      sourceKind: reference.sourceKind,
      duplicateGroupId: reference.duplicateGroupId,
    }));
    if (parsed.status === 'missing') return { field: parsed.field, status: parsed.status, reason: parsed.reason, supports: [] };
    if (parsed.status === 'conflicting') {
      let offset = 0;
      const candidates = parsed.candidates.map((candidate) => {
        const supports = candidate.supports.map(() => refs[offset++]);
        return { ...candidate, supports };
      });
      return { field: parsed.field, status: parsed.status, candidates };
    }
    return { ...parsed, supports: refs };
  }

  function publicFact(info, factId, stored) {
    const reviveSupport = (support) => Object.freeze({
      evidence: newEvidenceHandle(info, support.evidenceId),
      position: newPositionHandle(info, support.evidenceId, support.positionId, support.sourceKind),
      contentHash: support.contentHash,
      duplicateGroupId: support.duplicateGroupId,
      independence: 'unknown',
    });
    if (stored.status === 'missing') return freezeFact({ factId, field: stored.field, status: 'missing', reason: stored.reason, supports: Object.freeze([]) });
    if (stored.status === 'conflicting') {
      return freezeFact({
        factId,
        field: stored.field,
        status: 'conflicting',
        candidates: stored.candidates.map((candidate) => ({
          originStatus: candidate.originStatus,
          rawValue: cloneJsonValue(candidate.rawValue),
          normalizedValue: cloneJsonValue(candidate.normalizedValue),
          ...(candidate.precision ? { precision: candidate.precision } : {}),
          ...(candidate.method ? { method: cloneJsonValue(candidate.method) } : {}),
          supports: candidate.supports.map(reviveSupport),
        })),
      });
    }
    return freezeFact({
      factId,
      field: stored.field,
      status: stored.status,
      rawValue: cloneJsonValue(stored.rawValue),
      normalizedValue: cloneJsonValue(stored.normalizedValue),
      ...(stored.precision ? { precision: stored.precision } : {}),
      ...(stored.method ? { method: cloneJsonValue(stored.method) } : {}),
      supports: stored.supports.map(reviveSupport),
    });
  }

  async function lookupFact(scope, factId, signal) {
    const info = scopeInfo(scope);
    checkCancellation(signal);
    if (!validUuid(factId)) fail('EVIDENCE_NOT_FOUND');
    const directory = await tenantDirectory(info);
    try {
      return await withExpiryAwareTenantLock(info, directory, async (database) => {
        const manifest = await readManifest(database, info.tenantHash);
        await expireRecords(database, manifest, currentTime());
        if (!manifest.facts[factId]) fail('EVIDENCE_NOT_FOUND');
        return newFactHandle(info, factId);
      }, signal);
    } catch (error) {
      throw safePublicError(error);
    }
  }

  async function readFact(scope, handle, request) {
    return materializeSelectedInternal(
      scope,
      { evidence: [], facts: [handle] },
      request,
      undefined,
      'read_fact',
      'fact',
      limits.maxPositionCount,
    );
  }

  async function listFacts(scope, request) {
    const info = scopeInfo(scope);
    const budget = newMaterializationBudget();
    const directory = await tenantDirectory(info);
    let snapshot;
    let finalVerifier;
    let factIds = [];
    let evidenceIds = [];
    try {
      snapshot = await withExpiryAwareTenantLock(info, directory, async (database) => {
        const facts = [];
        let transferred = false;
        try {
          const manifestPresentAtSnapshot = Boolean(database.prepare(
            'SELECT 1 AS present FROM evidence_manifest WHERE tenant_hash = ?',
          ).get(info.tenantHash));
          const manifest = await readManifest(database, info.tenantHash);
          await expireRecords(database, manifest, currentTime());
          const active = Object.values(manifest.facts).filter((fact) => fact.state === 'available');
          if (active.length > 1000) fail('EVIDENCE_INVALID');
          for (const fact of active) facts.push(copyFactRecord(fact, budget));
          const lengths = preflightSelectedSealedBundleLengths(database, 'fact', facts.map((fact) => fact.id), budget);
          copySelectedSealedBundles(database, 'fact', facts, lengths);
          const nowMs = currentTime();
          if (facts.some((fact) => fact.expiresAtMs <= nowMs)) fail('EVIDENCE_EXPIRED');
          transferred = true;
          return {
            facts,
            evidenceIds: [...new Set(facts.flatMap((fact) => fact.supportEvidenceIds))],
            budget,
            manifestPresentAtSnapshot,
          };
        } finally {
          if (!transferred) for (const fact of facts) fact.sealed?.fill(0);
        }
      });
      factIds = snapshot.facts.map((fact) => fact.id);
      evidenceIds = snapshot.evidenceIds;
    } catch (error) {
      throw safePublicError(error);
    }
    try {
      await authorize(info, request, 'list_facts', evidenceIds, factIds);
      const result = [];
      for (const fact of snapshot.facts) {
        const stored = await decryptSealedBundle(info, fact.id, 'fact', fact.sealed, fact.encryptionKeyId, resolveKey, snapshot.budget);
        try {
          collectFactSupports(fact, stored, snapshot.budget);
          result.push(publicFact(info, fact.id, stored));
        } finally {
          wipePrivateTree(stored);
        }
      }
      finalVerifier = makeFinalStateVerifier(info, directory, evidenceIds, factIds);
      authorizeCurrent(info, request, 'list_facts', evidenceIds, factIds);
      finalVerifier.check({
        evidence: [],
        facts: snapshot.facts,
        manifestPresentAtSnapshot: snapshot.manifestPresentAtSnapshot,
      });
      return deepFreeze(result);
    } catch (error) {
      try { await persistExpirySweep(info, directory); } catch (cleanupError) { throw safePublicError(cleanupError); }
      throw safePublicError(error);
    } finally {
      finalVerifier?.close();
      for (const fact of snapshot?.facts ?? []) fact.sealed.fill(0);
    }
  }

  async function purgeExpired(scope, signal) {
    checkCancellation(signal);
    const info = scopeInfo(scope);
    const directory = await tenantDirectory(info);
    checkCancellation(signal);
    try {
      return await withExpiryAwareTenantLock(info, directory, (database, lockSignal) => {
        checkCancellation(lockSignal);
        const manifest = readManifest(database, info.tenantHash);
        const nowMs = currentTime();
        const beforeEvidence = Object.values(manifest.records)
          .filter((record) => record.state === 'available' && record.expiresAtMs <= nowMs).length;
        const beforeFacts = Object.values(manifest.facts)
          .filter((fact) => fact.state === 'available' && fact.expiresAtMs <= nowMs).length;
        expireRecords(database, manifest, nowMs);
        checkCancellation(lockSignal);
        // Preserve the historical return value: this count covers source evidence and facts.
        // Private receipt ciphertext is reported separately by integritySnapshot.
        return beforeEvidence + beforeFacts;
      }, signal);
    } catch (error) {
      throw safePublicError(error);
    }
  }

  async function integritySnapshot(scope) {
    const info = scopeInfo(scope);
    const directory = await tenantDirectory(info);
    try {
      return await withExpiryAwareTenantLock(info, directory, async (database) => {
        const manifest = await readManifest(database, info.tenantHash);
        await expireRecords(database, manifest, currentTime());
        const row = database.prepare('SELECT COUNT(*) AS count FROM sealed_bundles').get();
        const receiptRow = database.prepare(`SELECT COUNT(*) AS count FROM private_retrieval_receipts
          WHERE tenant_hash = ? AND sealed IS NOT NULL`).get(info.tenantHash);
        if (!Number.isSafeInteger(row.count) || !Number.isSafeInteger(receiptRow.count)) fail('EVIDENCE_INTEGRITY');
        return Object.freeze({
          availableEvidence: Object.values(manifest.records).filter((record) => record.state === 'available').length,
          expiredEvidence: Object.values(manifest.records).filter((record) => record.state === 'expired').length,
          availableFacts: Object.values(manifest.facts).filter((fact) => fact.state === 'available').length,
          expiredFacts: Object.values(manifest.facts).filter((fact) => fact.state === 'expired').length,
          encryptedPayloadRecords: row.count,
          encryptedPrivateReceiptRecords: receiptRow.count,
        });
      });
    } catch (error) {
      throw safePublicError(error);
    }
  }

  function normalizePrivateReceiptLookup(inputValue) {
    const input = ownDataRecord(inputValue, new Set(['runId', 'configHash', 'candidate']));
    if (!input) fail('EVIDENCE_INVALID');
    const normalized = normalizePrivateReceiptBase({
      ...input,
      claim: {
        claimKey: 'receipt.lookup',
        workerId: 'receipt.lookup',
        leaseToken: '00000000-0000-4000-8000-000000000000',
      },
    });
    return { runId: normalized.runId, configHash: normalized.configHash, candidate: normalized.candidate };
  }

  function sameReceiptBinding(value, binding) {
    if (!value || value.schemaVersion !== PRIVATE_RECEIPT_SCHEMA_VERSION
      || value.tenantId !== binding.tenantId || value.runId !== binding.runId
      || value.configHash !== binding.configHash
      || JSON.stringify(value.candidate) !== JSON.stringify(binding.candidate)) return false;
    if (binding.claim === undefined) return true;
    const claim = ownDataRecord(value.claim, new Set(['claimKey', 'workerId', 'leaseToken']));
    return claim !== null
      && claim.claimKey === binding.claim.claimKey
      && claim.workerId === binding.claim.workerId
      && claim.leaseToken === binding.claim.leaseToken;
  }

  async function beginPrivateRunReceipt(scope, inputValue, request, signal) {
    const info = scopeInfo(scope);
    checkCancellation(signal);
    const base = normalizePrivateReceiptBase(inputValue);
    const receiptKey = privateReceiptKey(info, base.runId, base.candidate.candidateId);
    const body = { schemaVersion: PRIVATE_RECEIPT_SCHEMA_VERSION, tenantId: info.tenantId, ...base, phase: 'pending' };
    const sealed = await sealPrivateReceipt(info, receiptKey, body, signal);
    let directory;
    try {
      directory = await tenantDirectory(info);
      authorizeCurrent(info, request, 'write_private_run_receipt', [], []);
      checkCancellation(signal);
      const now = currentTime();
      const expiresAtMs = now + limits.maxRetentionMs;
      if (!Number.isSafeInteger(expiresAtMs)) fail('EVIDENCE_INVALID');
      const result = await withExpiryAwareTenantLock(info, directory, (database, lockSignal) => {
        checkCancellation(lockSignal);
        const existing = database.prepare(`SELECT state, payload_hash, expires_at_ms FROM private_retrieval_receipts
          WHERE tenant_hash = ? AND receipt_key = ?`).get(info.tenantHash, receiptKey);
        if (existing) {
          if (!['pending', 'complete', 'expired'].includes(existing.state)) fail('EVIDENCE_INTEGRITY');
          if (existing.state === 'pending' && existing.payload_hash !== sealed.payloadHash) fail('EVIDENCE_INTEGRITY');
          return { state: existing.state, created: false };
        }
        const totals = database.prepare(`SELECT COUNT(*) AS row_count,
          COALESCE(SUM(length(sealed)), 0) AS sealed_bytes
          FROM private_retrieval_receipts WHERE tenant_hash = ?`).get(info.tenantHash);
        if (totals.row_count >= PRIVATE_RECEIPT_MAX_ROWS_PER_TENANT
          || totals.sealed_bytes + sealed.sealed.byteLength > PRIVATE_RECEIPT_MAX_SEALED_BYTES_PER_TENANT) {
          fail('EVIDENCE_STORAGE');
        }
        const insertedAt = currentTime();
        if (expiresAtMs <= insertedAt) fail('EVIDENCE_EXPIRED');
        database.prepare(`INSERT INTO private_retrieval_receipts
          (tenant_hash, receipt_key, schema_version, state, key_id, payload_hash, payload_bytes,
            expires_at_ms, sealed, updated_at_ms)
          VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)`)
          .run(info.tenantHash, receiptKey, PRIVATE_RECEIPT_SCHEMA_VERSION, sealed.keyId,
            sealed.payloadHash, sealed.payloadBytes, expiresAtMs, sealed.sealed, insertedAt);
        checkCancellation(lockSignal);
        return { state: 'pending', created: true };
      }, signal, {
        beforeBegin: () => {
          authorizeCurrent(info, request, 'write_private_run_receipt', [], []);
          checkCancellation(signal);
        },
      });
      if (result.state === 'expired') return Object.freeze({ state: 'expired', created: false });
      return Object.freeze(result);
    } catch (error) {
      throw safePublicError(error);
    } finally {
      sealed.sealed.fill(0);
      wipePrivateTree(body);
    }
  }

  async function finalizePrivateRunReceipt(scope, inputValue, request, signal) {
    const info = scopeInfo(scope);
    checkCancellation(signal);
    const input = ownDataRecord(inputValue, new Set([
      'runId', 'configHash', 'candidate', 'claim', 'completion', 'selection',
    ]));
    if (!input) fail('EVIDENCE_INVALID');
    const base = normalizePrivateReceiptBase({
      runId: input.runId,
      configHash: input.configHash,
      candidate: input.candidate,
      claim: input.claim,
    });
    const completion = normalizePrivateReceiptCompletion(input.completion);
    const selection = ownDataRecord(input.selection, new Set(['evidence', 'facts']));
    if (!selection) fail('EVIDENCE_INVALID');
    const evidenceHandles = safeArray(selection.evidence, 8);
    const factHandles = safeArray(selection.facts, 128);
    if (!evidenceHandles || !factHandles) fail('EVIDENCE_INVALID');
    const directEvidenceIds = evidenceHandles.map((handle) => {
      const record = EVIDENCE_HANDLES.get(handle);
      if (!record || record.tenantHash !== info.tenantHash || record.tenantId !== info.tenantId) fail('EVIDENCE_DENIED');
      return record.evidenceId;
    });
    const selectedFactIds = factHandles.map((handle) => {
      const record = FACT_HANDLES.get(handle);
      if (!record || record.tenantHash !== info.tenantHash || record.tenantId !== info.tenantId) fail('EVIDENCE_DENIED');
      return record.factId;
    });
    if (new Set(directEvidenceIds).size !== directEvidenceIds.length
      || new Set(selectedFactIds).size !== selectedFactIds.length) fail('EVIDENCE_INVALID');
    const receiptKey = privateReceiptKey(info, base.runId, base.candidate.candidateId);
    const directory = await tenantDirectory(info);
    let pendingSnapshot;
    let pendingBody;
    let materialized;
    let body;
    let sealed;
    try {
      pendingSnapshot = await privateReceiptRowSnapshot(info, directory, receiptKey, signal);
      if (!pendingSnapshot || pendingSnapshot.state === 'expired') fail('EVIDENCE_EXPIRED');
      pendingBody = await openPrivateReceipt(info, receiptKey, pendingSnapshot, signal);
      if (!sameReceiptBinding(pendingBody, { ...base, tenantId: info.tenantId })) fail('EVIDENCE_INTEGRITY');
      if (!['pending', 'complete'].includes(pendingBody.phase)
        || pendingSnapshot.state !== pendingBody.phase) fail('EVIDENCE_INTEGRITY');

      if (directEvidenceIds.length + selectedFactIds.length > 0) {
        materialized = await materializeSelectedInternal(
          scope,
          { evidence: evidenceHandles, facts: factHandles },
          request,
          signal,
          'write_private_run_receipt',
          'selected',
          8,
          true,
        );
      } else {
        await authorize(info, request, 'write_private_run_receipt', [], [], signal);
      }
      checkCancellation(signal);

      const { evidenceRefs, factRefs } = receiptReferencesForMaterialized(info, materialized);
      validatePrivateReceiptSuggestionEvidence(completion, evidenceRefs);
      validateAssetReceiptCrossBinding(base.candidate.assetAcquisition, completion.assetAcquisition,
        evidenceRefs, completion.outcome);
      validateAssetReceiptMaterialized(base.candidate.assetAcquisition, completion.assetAcquisition,
        materialized?.evidence ?? [], completion.outcome);
      validateAssetSuggestionBindings(completion.assetSuggestions ?? [], completion.suggestions,
        evidenceRefs, materialized?.evidence ?? []);
      for (const binding of completion.assetSuggestions ?? []) {
        const currentCandidate = await readAssetSourceCandidateBinding(
          scope, newEvidenceHandle(info, binding.sourceEvidenceId), binding.candidateId, request, signal,
        );
        if (!controlledAssetSourceMatches(binding, currentCandidate)) fail('EVIDENCE_EXPIRED');
      }
      const evidenceIds = evidenceRefs.map((reference) => reference.evidenceId);
      const factIds = factRefs.map((reference) => reference.factId);
      if (evidenceRefs.length > 8 || factRefs.length > 128
        || new Set(evidenceIds).size !== evidenceIds.length || new Set(factIds).size !== factIds.length) fail('EVIDENCE_INVALID');

      const manifestSnapshot = await withExpiryAwareTenantLock(info, directory, async (database) => {
        const manifest = await readManifest(database, info.tenantHash);
        await expireRecords(database, manifest, currentTime());
        const row = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
        const document = row?.document ?? null;
        const currentManifest = document === null ? emptyManifest(info.tenantHash)
          : validateManifest(JSON.parse(document), info.tenantHash);
        let expiresAtMs = currentTime() + limits.maxRetentionMs;
        if (!Number.isSafeInteger(expiresAtMs)) fail('EVIDENCE_INVALID');
        for (const reference of evidenceRefs) {
          const record = currentManifest.records[reference.evidenceId];
          if (!record || record.state !== 'available' || record.version !== reference.version
            || record.contentHash !== reference.contentHash
            || (record.representation ?? 'raw') !== reference.representation
            || (record.derivationDigest ?? null) !== reference.derivationDigest) fail('EVIDENCE_EXPIRED');
          expiresAtMs = Math.min(expiresAtMs, record.expiresAtMs);
        }
        for (const reference of factRefs) {
          const record = currentManifest.facts[reference.factId];
          if (!record || record.state !== 'available' || record.status !== reference.status
            || record.supportEvidenceIds.slice().sort().join('\0') !== reference.supportEvidenceIds.join('\0')
            || record.supportContentHashes.slice().sort().join('\0') !== reference.supportContentHashes.join('\0')) fail('EVIDENCE_EXPIRED');
          expiresAtMs = Math.min(expiresAtMs, record.expiresAtMs);
        }
        if (expiresAtMs <= currentTime()) fail('EVIDENCE_EXPIRED');
        return { document, manifest: currentManifest, expiresAtMs };
      }, signal);

      body = {
        schemaVersion: PRIVATE_RECEIPT_SCHEMA_VERSION,
        tenantId: info.tenantId,
        ...base,
        phase: 'complete',
        completion,
        evidenceRefs,
        factRefs,
      };
      sealed = await sealPrivateReceipt(info, receiptKey, body, signal);
      authorizeCurrent(info, request, 'write_private_run_receipt', evidenceIds, factIds);
      checkCancellation(signal);
      const committed = await withExpiryAwareTenantLock(info, directory, (database, lockSignal) => {
        checkCancellation(lockSignal);
        const manifestRow = database.prepare('SELECT document FROM evidence_manifest WHERE tenant_hash = ?').get(info.tenantHash);
        if ((manifestRow?.document ?? null) !== manifestSnapshot.document) fail('EVIDENCE_BUSY');
        const currentTimeMs = currentTime();
        if (manifestSnapshot.expiresAtMs <= currentTimeMs) fail('EVIDENCE_EXPIRED');
        const currentManifest = manifestSnapshot.document === null ? emptyManifest(info.tenantHash)
          : validateManifest(JSON.parse(manifestRow.document), info.tenantHash);
        for (const reference of evidenceRefs) {
          const record = currentManifest.records[reference.evidenceId];
          if (!record || record.state !== 'available' || record.version !== reference.version
            || record.contentHash !== reference.contentHash || record.expiresAtMs <= currentTimeMs) fail('EVIDENCE_EXPIRED');
        }
        for (const reference of factRefs) {
          const record = currentManifest.facts[reference.factId];
          if (!record || record.state !== 'available' || record.expiresAtMs <= currentTimeMs
            || record.status !== reference.status) fail('EVIDENCE_EXPIRED');
        }
        const row = database.prepare(`SELECT schema_version, state, key_id, payload_hash, payload_bytes,
          expires_at_ms, sealed, updated_at_ms FROM private_retrieval_receipts
          WHERE tenant_hash = ? AND receipt_key = ?`).get(info.tenantHash, receiptKey);
        if (!row || row.schema_version !== PRIVATE_RECEIPT_SCHEMA_VERSION
          || row.state !== pendingSnapshot.state || row.key_id !== pendingSnapshot.key_id
          || row.payload_hash !== pendingSnapshot.payload_hash || row.payload_bytes !== pendingSnapshot.payload_bytes
          || row.expires_at_ms !== pendingSnapshot.expiresAtMs || row.updated_at_ms !== pendingSnapshot.updatedAtMs
          || !row.sealed || !Buffer.from(row.sealed).equals(pendingSnapshot.sealed)) fail('EVIDENCE_BUSY');
        if (row.state === 'complete') {
          if (row.payload_hash !== sealed.payloadHash) fail('EVIDENCE_INTEGRITY');
          return 'already_complete';
        }
        if (row.state !== 'pending' || row.expires_at_ms <= currentTimeMs) fail('EVIDENCE_EXPIRED');
        const totals = database.prepare(`SELECT COALESCE(SUM(length(sealed)), 0) AS sealed_bytes
          FROM private_retrieval_receipts WHERE tenant_hash = ?`).get(info.tenantHash);
        const existingEnvelopeBytes = Buffer.from(row.sealed).byteLength;
        if (totals.sealed_bytes - existingEnvelopeBytes + sealed.sealed.byteLength
          > PRIVATE_RECEIPT_MAX_SEALED_BYTES_PER_TENANT) fail('EVIDENCE_STORAGE');
        database.prepare(`UPDATE private_retrieval_receipts SET state = 'complete', key_id = ?, payload_hash = ?,
          payload_bytes = ?, expires_at_ms = ?, sealed = ?, updated_at_ms = ?
          WHERE tenant_hash = ? AND receipt_key = ? AND state = 'pending'`)
          .run(sealed.keyId, sealed.payloadHash, sealed.payloadBytes,
            Math.min(row.expires_at_ms, manifestSnapshot.expiresAtMs), sealed.sealed, currentTimeMs,
            info.tenantHash, receiptKey);
        checkCancellation(lockSignal);
        return 'complete';
      }, signal, {
        beforeBegin: () => {
          authorizeCurrent(info, request, 'write_private_run_receipt', evidenceIds, factIds);
          checkCancellation(signal);
        },
      });
      return Object.freeze({ state: committed });
    } catch (error) {
      throw safePublicError(error);
    } finally {
      pendingSnapshot?.sealed?.fill(0);
      if (pendingBody) wipePrivateTree(pendingBody);
      if (body) wipePrivateTree(body);
      sealed?.sealed.fill(0);
    }
  }

  async function readPrivateRunReceipt(scope, inputValue, request, signal) {
    const info = scopeInfo(scope);
    checkCancellation(signal);
    const lookup = normalizePrivateReceiptLookup(inputValue);
    const receiptKey = privateReceiptKey(info, lookup.runId, lookup.candidate.candidateId);
    const directory = await tenantDirectory(info);
    let row;
    let body;
    try {
      row = await privateReceiptRowSnapshot(info, directory, receiptKey, signal);
      if (!row) return Object.freeze({ state: 'missing' });
      if (row.state === 'expired') return Object.freeze({ state: 'expired' });
      body = await openPrivateReceipt(info, receiptKey, row, signal);
      if (!sameReceiptBinding(body, { ...lookup, tenantId: info.tenantId })) {
        return Object.freeze({ state: 'mismatch' });
      }
      const base = normalizePrivateReceiptBase({
        runId: body.runId,
        configHash: body.configHash,
        candidate: body.candidate,
        claim: body.claim,
      });
      if (!['pending', 'complete'].includes(body.phase) || body.phase !== row.state
        || JSON.stringify(base) !== JSON.stringify({
          runId: body.runId,
          configHash: body.configHash,
          candidate: body.candidate,
          claim: body.claim,
        })) fail('EVIDENCE_INTEGRITY');
      if (body.phase === 'pending') {
        await authorize(info, request, 'read_private_run_receipt', [], [], signal);
        authorizeCurrent(info, request, 'read_private_run_receipt', [], []);
        checkCancellation(signal);
        if (currentTime() >= row.expiresAtMs || !privateReceiptRowMatchesSync(info, directory, receiptKey, row)) {
          fail(currentTime() >= row.expiresAtMs ? 'EVIDENCE_EXPIRED' : 'EVIDENCE_BUSY');
        }
        return Object.freeze({ state: 'pending', ...base });
      }

      const header = ownDataRecord(body, new Set([
        'schemaVersion', 'tenantId', 'runId', 'configHash', 'candidate', 'claim', 'phase',
        'completion', 'evidenceRefs', 'factRefs',
      ]));
      if (!header || header.schemaVersion !== PRIVATE_RECEIPT_SCHEMA_VERSION) fail('EVIDENCE_INTEGRITY');
      const completion = normalizePrivateReceiptCompletion(body.completion);
      const { evidenceRefs, factRefs } = validatePrivateReceiptReferences({
        evidenceRefs: body.evidenceRefs,
        factRefs: body.factRefs,
      });
      validatePrivateReceiptSuggestionEvidence(completion, evidenceRefs, 'EVIDENCE_INTEGRITY');
      validateAssetReceiptCrossBinding(base.candidate.assetAcquisition, completion.assetAcquisition,
        evidenceRefs, completion.outcome, 'EVIDENCE_INTEGRITY');
      if (evidenceRefs.length === 0 && factRefs.length === 0
        && (completion.identity.entityCandidates.length > 0 || completion.identity.occurrenceCandidates.length > 0
          || completion.identity.transitionLinks.length > 0 || completion.identity.unresolvedTransitions.length > 0
          || completion.suggestions.length > 0)) fail('EVIDENCE_INTEGRITY');
      const evidenceHandles = [];
      for (const reference of evidenceRefs) {
        evidenceHandles.push(await lookupEvidence(scope, reference.evidenceId, signal));
      }
      const factHandles = [];
      for (const reference of factRefs) factHandles.push(await lookupFact(scope, reference.factId, signal));
      const evidenceIds = evidenceRefs.map((reference) => reference.evidenceId);
      const factIds = factRefs.map((reference) => reference.factId);
      let materialized;
      if (evidenceIds.length + factIds.length > 0) {
        const finalizationHook = ({ snapshot, finalVerifier, materialized: current }) => {
          const actual = receiptReferencesForMaterialized(info, current);
          if (JSON.stringify(actual.evidenceRefs) !== JSON.stringify(evidenceRefs)
            || JSON.stringify(actual.factRefs) !== JSON.stringify(factRefs)) fail('EVIDENCE_INTEGRITY');
          if (currentTime() >= row.expiresAtMs
            || !privateReceiptRowMatchesSync(info, directory, receiptKey, row)) fail('EVIDENCE_EXPIRED');
        validateAssetSuggestionBindings(completion.assetSuggestions ?? [], completion.suggestions,
          evidenceRefs, current.evidence, 'EVIDENCE_INTEGRITY');
          authorizeCurrent(info, request, 'read_private_run_receipt', evidenceIds, factIds);
          checkCancellation(signal);
          finalVerifier.check(snapshot);
          if (currentTime() >= row.expiresAtMs
            || !privateReceiptRowMatchesSync(info, directory, receiptKey, row)) fail('EVIDENCE_EXPIRED');
        };
        materialized = await materializeSelectedInternal(
          scope,
          { evidence: evidenceHandles, facts: factHandles },
          request,
          signal,
          'read_private_run_receipt',
          'selected',
          8,
          true,
          finalizationHook,
        );
      } else {
        await authorize(info, request, 'read_private_run_receipt', [], [], signal);
        if (currentTime() >= row.expiresAtMs
          || !privateReceiptRowMatchesSync(info, directory, receiptKey, row)) fail('EVIDENCE_EXPIRED');
        authorizeCurrent(info, request, 'read_private_run_receipt', [], []);
        checkCancellation(signal);
        if (currentTime() >= row.expiresAtMs
          || !privateReceiptRowMatchesSync(info, directory, receiptKey, row)) fail('EVIDENCE_EXPIRED');
        materialized = { evidence: Object.freeze([]), facts: Object.freeze([]) };
      }
      validateAssetReceiptMaterialized(base.candidate.assetAcquisition, completion.assetAcquisition,
        materialized.evidence, completion.outcome, 'EVIDENCE_INTEGRITY');
      validateAssetSuggestionBindings(completion.assetSuggestions ?? [], completion.suggestions,
        evidenceRefs, materialized.evidence, 'EVIDENCE_INTEGRITY');
      const result = deepFreeze({
        state: 'complete',
        runId: base.runId,
        configHash: base.configHash,
        candidate: cloneJsonValue(base.candidate),
        claim: cloneJsonValue(base.claim),
        completionKey: completion.completionKey,
        outcome: completion.outcome,
        suggestions: completion.suggestions,
        omissionMetadataVersion: Object.hasOwn(completion, 'omittedSuggestions') ? 1 : 0,
        truncatedCount: completion.truncatedCount ?? 0,
        omittedSuggestions: completion.omittedSuggestions ?? Object.freeze([]),
        sourceLinkCandidatesOmittedCount: completion.sourceLinkCandidatesOmittedCount ?? 0,
        limitations: completion.limitations,
        identity: completion.identity,
        ...(completion.assetAcquisition ? { assetAcquisition: completion.assetAcquisition } : {}),
        ...(completion.assetSuggestions ? { assetSuggestions: completion.assetSuggestions } : {}),
        evidenceIds: Object.freeze(evidenceIds),
        facts: materialized.facts,
      });
      return result;
    } catch (error) {
      throw safePublicError(error);
    } finally {
      row?.sealed?.fill(0);
      if (body) wipePrivateTree(body);
    }
  }

  return Object.freeze({
    scopeForAuthenticatedRequest: createScope,
    ingestEvidence,
    ingestControlledAssetEvidence,
    ingestAssetSourceEvidence,
    ingestDerivedPdfEvidence,
    lookupEvidence,
    getEvidenceMetadata,
    listEvidencePositions,
    materializeSelected,
    withPrivatePayload,
    readAssetSourceCandidateBinding,
    readControlledAssetBytes,
    revalidateControlledAssetRelease,
    finalizeControlledAssetRelease,
    discardControlledAssetRelease,
    appendFact,
    lookupFact,
    readFact,
    listFacts,
    purgeExpired,
    integritySnapshot,
    beginPrivateRunReceipt,
    finalizePrivateRunReceipt,
    readPrivateRunReceipt,
  });
}
