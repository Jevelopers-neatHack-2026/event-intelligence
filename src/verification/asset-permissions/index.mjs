import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { isPromise, isProxy } from 'node:util/types';
import {
  getQuestionDefinition,
  QUESTION_REGISTRY_SCHEMA_VERSION,
  QUESTION_REGISTRY_VERSION,
} from '../../decisions/questions/registry.mjs';
import {
  inspectSafeAssetBytes,
  SAFE_ASSET_LIMITS,
  SAFE_ASSET_POLICY_VERSION,
} from '../../security/assets/inspect.mjs';

/**
 * Private EI implementation boundary. This is not a shared-contracts schema or
 * a source of approval authority.
 */
export const ASSET_PERMISSION_SELECTION_VERSION = 'asset-permission-selection/1';
export const ASSET_PERMISSION_SELECTION_LIMITS = Object.freeze({
  maxCandidates: 8,
  maxTotalSourceBytes: 1024 * 1024,
  maxReferenceBytes: 192,
  maxOperationMs: 1500,
  maxHandleAgeMs: 60_000,
  maxOutstandingSelections: 32,
  maxConcurrentOperations: 16,
  maxOutstandingAdapterCalls: 16,
});

const REQUEST_VERSION = 'asset-permission-request/1';
const HANDOFF_VERSION = 'asset-permission-handoff/1';
const BRAND_ROLE_QUESTION_ID = 'Q-EI-BRAND-ROLE:v1';
const brandRoleDefinition = getQuestionDefinition(BRAND_ROLE_QUESTION_ID);
const brandRoles = new Set(brandRoleDefinition?.outputLabels ?? []);
const handoffRoles = new Set(['favicon', 'logo', 'poster', 'photo']);
const SHA256_RE = /^[a-f0-9]{64}$/;
const REF_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,191}$/;

const requestKeys = [
  'requestVersion', 'tenantRef', 'scopeRef', 'organizationRef', 'occurrenceRef',
  'editionRef', 'packageVersion', 'intendedUse',
];
const requestRefKeys = [
  'tenantRef', 'scopeRef', 'organizationRef', 'occurrenceRef', 'editionRef',
  'packageVersion', 'intendedUse',
];
const candidateKeys = [
  'candidateRef', 'assetRef', 'assetVersion', 'tenantRef', 'scopeRef',
  'organizationRef', 'occurrenceRef', 'editionRef', 'packageVersion', 'intendedUse',
  'sourceRef', 'evidenceRef', 'contentType', 'sourceHash', 'transformedHash',
  'bytes', 'roleEvidence', 'approvalClaim',
];
const roleEvidenceKeys = [
  'questionId', 'registryVersion', 'schemaVersion', 'rubricVersion', 'definitionHash',
  'targetRef', 'candidateRef', 'assetRef', 'assetVersion', 'tenantRef', 'scopeRef',
  'organizationRef', 'occurrenceRef', 'editionRef', 'packageVersion', 'intendedUse',
  'sourceRef', 'sourceHash', 'transformedHash', 'observationRef', 'observationHash',
  'observerRef', 'modelRef', 'regionRef', 'uncertaintyRef', 'role',
];
const approvalClaimKeys = ['approvalRef', 'declaredExpiresAtMs', 'revocationRef'];
const optionKeys = ['signal', 'deadlineAtMs'];
const adapterKeys = [
  'readAuthorization', 'verifyRoleEvidence', 'recheckRoleEvidence',
  'verifyPermission', 'recheckPermission', 'publishHandoff',
];

const hashPatternBytes = new TextEncoder();
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'length')?.get;
const typedArrayBufferGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer')?.get;
const typedArrayByteOffsetGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset')?.get;
const typedArraySet = Uint8Array.prototype.set;
const arrayBufferByteLengthGetter = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength')?.get;
const abortSignalAbortedGetter = typeof AbortSignal === 'function'
  ? Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.get
  : undefined;
const eventTargetPrototype = typeof AbortSignal === 'function'
  ? Object.getPrototypeOf(AbortSignal.prototype)
  : null;
const eventTargetAdd = eventTargetPrototype?.addEventListener;
const eventTargetRemove = eventTargetPrototype?.removeEventListener;
const AbortControllerIntrinsic = globalThis.AbortController;
const setTimeoutIntrinsic = globalThis.setTimeout;
const clearTimeoutIntrinsic = globalThis.clearTimeout;
const nativePromisePrototype = Promise.prototype;
const nativePromiseThen = Promise.prototype.then;
const ABORTED_BEFORE_ADAPTER = Symbol('aborted-before-adapter');

function observeOrdinaryNativePromise(value) {
  try {
    if (!value || typeof value !== 'object' || isProxy(value) || !isPromise(value)) return;
    if (Object.getPrototypeOf(value) !== nativePromisePrototype
      || Object.getOwnPropertyDescriptor(value, 'constructor') !== undefined) return;
    nativePromiseThen.call(value, undefined, () => undefined);
  } catch {
    // Exotic or malformed promise-like values are outside the sync-hook contract.
  }
}

export class AssetPermissionSelectionError extends Error {
  constructor(code) {
    super(code);
    this.name = 'AssetPermissionSelectionError';
    this.code = code;
  }
}

function fail(code) {
  throw new AssetPermissionSelectionError(code);
}

function isWellFormedUnicode(value) {
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

function snapshotRecord(value, allowedKeys, requiredKeys = allowedKeys) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || isProxy(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string' || !allowedKeys.includes(key))) return null;
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
      result[key] = descriptor.value;
    }
    for (const key of requiredKeys) {
      if (!Object.hasOwn(result, key)) return null;
    }
    return result;
  } catch {
    return null;
  }
}

function snapshotArray(value, maximum) {
  try {
    if (!Array.isArray(value) || isProxy(value)) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => key !== 'length' && (typeof key !== 'string' || !/^(0|[1-9]\d*)$/.test(key)))) return null;
    const lengthDescriptor = descriptors.length;
    if (!lengthDescriptor || !Object.hasOwn(lengthDescriptor, 'value')) return null;
    const length = lengthDescriptor.value;
    if (!Number.isSafeInteger(length) || length < 0 || length > maximum) return null;
    if (keys.some((key) => key !== 'length' && Number(key) >= length)) return null;
    const result = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
      result.push(descriptor.value);
    }
    return result;
  } catch {
    return null;
  }
}

function isReference(value) {
  if (typeof value !== 'string' || !isWellFormedUnicode(value) || !REF_RE.test(value)) return false;
  return hashPatternBytes.encode(value).length <= ASSET_PERMISSION_SELECTION_LIMITS.maxReferenceBytes;
}

function isHash(value) {
  return typeof value === 'string' && SHA256_RE.test(value);
}

function isSafeIntegerTime(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function copyBytes(candidate, maximum) {
  try {
    if (isProxy(candidate) || !ArrayBuffer.isView(candidate)) return null;
    const prototype = Object.getPrototypeOf(candidate);
    if (prototype !== Uint8Array.prototype && prototype !== Buffer.prototype) return null;
    const length = typedArrayLengthGetter.call(candidate);
    const offset = typedArrayByteOffsetGetter.call(candidate);
    const backing = typedArrayBufferGetter.call(candidate);
    const backingLength = arrayBufferByteLengthGetter.call(backing);
    if (!Number.isSafeInteger(length) || length < 1 || length > maximum
      || !Number.isSafeInteger(offset) || offset < 0
      || !Number.isSafeInteger(backingLength) || offset + length > backingLength) return null;
    const result = new Uint8Array(length);
    typedArraySet.call(result, candidate);
    return result;
  } catch {
    return null;
  }
}

function isAbortSignal(value) {
  if (value === null) return true;
  if (!value || typeof value !== 'object' || isProxy(value) || !abortSignalAbortedGetter) return false;
  try {
    abortSignalAbortedGetter.call(value);
    return true;
  } catch {
    return false;
  }
}

function snapshotOptions(value) {
  if (value === undefined) return { signal: null, deadlineAtMs: null };
  const data = snapshotRecord(value, optionKeys, []);
  if (!data) fail('INVALID_INPUT');
  const signal = data.signal ?? null;
  const deadlineAtMs = data.deadlineAtMs ?? null;
  if (!isAbortSignal(signal)) fail('INVALID_INPUT');
  if (deadlineAtMs !== null && (!Number.isFinite(deadlineAtMs) || deadlineAtMs < 0)) fail('INVALID_INPUT');
  return { signal, deadlineAtMs };
}

function abortOperation(operation, code) {
  if (operation.abortReason !== null) return;
  operation.abortReason = code;
  operation.controller.abort(code);
}

function makeOperation(options) {
  const startedAt = performance.now();
  const localDeadline = startedAt + ASSET_PERMISSION_SELECTION_LIMITS.maxOperationMs;
  const deadlineAtMs = options.deadlineAtMs === null
    ? localDeadline
    : Math.min(localDeadline, options.deadlineAtMs);
  if (options.signal && abortSignalAbortedGetter.call(options.signal)) fail('CANCELLED');
  if (deadlineAtMs <= startedAt) fail('DEADLINE_EXCEEDED');
  const controller = new AbortControllerIntrinsic();
  const operation = {
    callerSignal: options.signal,
    signal: controller.signal,
    deadlineAtMs,
    controller,
    abortReason: null,
    callerAbortListener: null,
    deadlineTimer: null,
    finished: false,
  };
  try {
    if (operation.callerSignal) {
      operation.callerAbortListener = () => abortOperation(operation, 'CANCELLED');
      eventTargetAdd.call(operation.callerSignal, 'abort', operation.callerAbortListener, { once: true });
      if (abortSignalAbortedGetter.call(operation.callerSignal)) abortOperation(operation, 'CANCELLED');
    }
    const remainingMs = Math.max(0, deadlineAtMs - performance.now());
    operation.deadlineTimer = setTimeoutIntrinsic(
      () => abortOperation(operation, 'DEADLINE_EXCEEDED'),
      remainingMs,
    );
    if (operation.abortReason !== null) fail(operation.abortReason);
    return operation;
  } catch (error) {
    if (operation.deadlineTimer !== null) clearTimeoutIntrinsic(operation.deadlineTimer);
    if (operation.callerSignal && operation.callerAbortListener) {
      eventTargetRemove.call(operation.callerSignal, 'abort', operation.callerAbortListener);
    }
    throw error;
  }
}

function beginOperation(options, resourceState) {
  if (resourceState.activeOperations >= ASSET_PERMISSION_SELECTION_LIMITS.maxConcurrentOperations) fail('LIMIT_EXCEEDED');
  resourceState.activeOperations += 1;
  try {
    const operation = makeOperation(options);
    operation.resourceState = resourceState;
    return operation;
  } catch (error) {
    resourceState.activeOperations -= 1;
    throw error;
  }
}

function finishOperation(operation) {
  if (!operation || operation.finished) return;
  operation.finished = true;
  if (operation.deadlineTimer !== null) clearTimeoutIntrinsic(operation.deadlineTimer);
  if (operation.callerSignal && operation.callerAbortListener) {
    eventTargetRemove.call(operation.callerSignal, 'abort', operation.callerAbortListener);
  }
  operation.resourceState.activeOperations -= 1;
}

function checkOperation(operation) {
  if (operation.callerSignal && abortSignalAbortedGetter.call(operation.callerSignal)) {
    abortOperation(operation, 'CANCELLED');
  }
  if (operation.abortReason !== null) fail(operation.abortReason);
  if (performance.now() >= operation.deadlineAtMs) {
    abortOperation(operation, 'DEADLINE_EXCEEDED');
    fail('DEADLINE_EXCEEDED');
  }
}

async function awaitAdapter(callback, argument, operation, assertCurrent) {
  checkOperation(operation);
  if (operation.resourceState.activeAdapterCalls >= ASSET_PERMISSION_SELECTION_LIMITS.maxOutstandingAdapterCalls) {
    fail('LIMIT_EXCEEDED');
  }
  operation.resourceState.activeAdapterCalls += 1;
  let abortListener;
  const abortPromise = new Promise((resolve) => {
    abortListener = () => resolve({ kind: 'aborted' });
    eventTargetAdd.call(operation.signal, 'abort', abortListener, { once: true });
    if (abortSignalAbortedGetter.call(operation.signal)) resolve({ kind: 'aborted' });
  });
  const callbackPromise = Promise.resolve()
    .then(() => {
      if (abortSignalAbortedGetter.call(operation.signal)) return ABORTED_BEFORE_ADAPTER;
      // Queued work can exhaust the deadline before its timer is delivered.
      checkOperation(operation);
      return callback(argument, operation.signal);
    })
    .then((value) => value === ABORTED_BEFORE_ADAPTER
      ? { kind: 'aborted' }
      : { kind: 'value', value }, () => ({ kind: 'error' }))
    .finally(() => { operation.resourceState.activeAdapterCalls -= 1; });
  let outcome;
  try {
    outcome = await Promise.race([callbackPromise, abortPromise]);
  } finally {
    if (abortListener) eventTargetRemove.call(operation.signal, 'abort', abortListener);
  }
  if (outcome.kind === 'aborted') checkOperation(operation);
  checkOperation(operation);
  if (outcome.kind === 'error') fail('AUTHORITY_UNAVAILABLE');
  assertCurrent();
  return outcome.value;
}

function canonicalRequest(request) {
  return JSON.stringify(requestKeys.map((key) => [key, request[key]]));
}

function snapshotRequest(value) {
  const data = snapshotRecord(value, requestKeys);
  if (!data || data.requestVersion !== REQUEST_VERSION) fail('INVALID_INPUT');
  for (const key of requestRefKeys) {
    if (!isReference(data[key])) fail('INVALID_INPUT');
  }
  return Object.freeze(Object.fromEntries(requestKeys.map((key) => [key, data[key]])));
}

function requestHash(request) {
  return sha256(Buffer.from(canonicalRequest(request), 'utf8'));
}

function candidateDescriptor(value, request) {
  const data = snapshotRecord(value, candidateKeys);
  if (!data) fail('INVALID_INPUT');
  const references = [
    'candidateRef', 'assetRef', 'assetVersion', 'tenantRef', 'scopeRef',
    'organizationRef', 'occurrenceRef', 'editionRef', 'packageVersion', 'intendedUse',
    'sourceRef', 'evidenceRef',
  ];
  if (references.some((key) => !isReference(data[key]))) fail('INVALID_INPUT');
  if (typeof data.contentType !== 'string' || data.contentType.length > 128 || !isWellFormedUnicode(data.contentType)) {
    fail('INVALID_INPUT');
  }
  if (!isHash(data.sourceHash) || !isHash(data.transformedHash)) fail('INVALID_INPUT');

  const role = snapshotRecord(data.roleEvidence, roleEvidenceKeys);
  if (!role) fail('INVALID_INPUT');
  for (const key of [
    'questionId', 'registryVersion', 'schemaVersion', 'rubricVersion', 'definitionHash', 'targetRef',
    'candidateRef', 'assetRef', 'assetVersion', 'tenantRef', 'scopeRef', 'organizationRef',
    'occurrenceRef', 'editionRef', 'packageVersion', 'intendedUse', 'sourceRef', 'observationRef',
    'observerRef', 'modelRef', 'regionRef', 'uncertaintyRef',
  ]) {
    if (!isReference(role[key])) fail('INVALID_INPUT');
  }
  if (!isHash(role.sourceHash) || !isHash(role.transformedHash) || !isHash(role.observationHash)) fail('INVALID_INPUT');
  if (typeof role.role !== 'string' || !brandRoles.has(role.role)) fail('INVALID_INPUT');

  const claim = snapshotRecord(data.approvalClaim, approvalClaimKeys);
  if (!claim || !isReference(claim.approvalRef) || !isReference(claim.revocationRef)
    || !isSafeIntegerTime(claim.declaredExpiresAtMs)) fail('INVALID_INPUT');

  const bytes = copyBytes(data.bytes, SAFE_ASSET_LIMITS.maxSourceBytes);
  if (!bytes) fail('INVALID_INPUT');
  const candidate = Object.freeze(Object.fromEntries(references.map((key) => [key, data[key]]).concat([
    ['contentType', data.contentType],
    ['sourceHash', data.sourceHash],
    ['transformedHash', data.transformedHash],
    ['roleEvidence', Object.freeze(Object.fromEntries(roleEvidenceKeys.map((key) => [key, role[key]])))],
    ['approvalClaim', Object.freeze(Object.fromEntries(approvalClaimKeys.map((key) => [key, claim[key]])))],
  ])));
  const scopeMatches = requestRefKeys.every((key) => candidate[key] === request[key]);
  return { candidate, bytes, scopeMatches };
}

function candidateIdentity(request, candidate, inspection) {
  const role = candidate.roleEvidence;
  return Object.freeze({
    version: ASSET_PERMISSION_SELECTION_VERSION,
    requestHash: requestHash(request),
    candidateRef: candidate.candidateRef,
    assetRef: candidate.assetRef,
    assetVersion: candidate.assetVersion,
    tenantRef: candidate.tenantRef,
    scopeRef: candidate.scopeRef,
    organizationRef: candidate.organizationRef,
    occurrenceRef: candidate.occurrenceRef,
    editionRef: candidate.editionRef,
    packageVersion: candidate.packageVersion,
    intendedUse: candidate.intendedUse,
    sourceRef: candidate.sourceRef,
    evidenceRef: candidate.evidenceRef,
    contentType: inspection.contentType,
    sourceHash: inspection.sourceHash,
    transformedHash: inspection.transformedHash,
    inspectionPolicyVersion: inspection.policyVersion,
    questionId: role.questionId,
    registryVersion: role.registryVersion,
    schemaVersion: role.schemaVersion,
    rubricVersion: role.rubricVersion,
    definitionHash: role.definitionHash,
    targetRef: role.targetRef,
    observationRef: role.observationRef,
    observationHash: role.observationHash,
    observerRef: role.observerRef,
    modelRef: role.modelRef,
    regionRef: role.regionRef,
    uncertaintyRef: role.uncertaintyRef,
    role: role.role,
  });
}

function roleEvidenceMatches(candidate, identity) {
  const role = candidate.roleEvidence;
  const expectedDefinition = brandRoleDefinition;
  return Boolean(expectedDefinition)
    && role.questionId === BRAND_ROLE_QUESTION_ID
    && role.registryVersion === QUESTION_REGISTRY_VERSION
    && role.schemaVersion === QUESTION_REGISTRY_SCHEMA_VERSION
    && role.rubricVersion === expectedDefinition.rubricVersion
    && role.definitionHash === expectedDefinition.definitionHash
    && role.candidateRef === identity.candidateRef
    && role.assetRef === identity.assetRef
    && role.assetVersion === identity.assetVersion
    && role.tenantRef === identity.tenantRef
    && role.scopeRef === identity.scopeRef
    && role.organizationRef === identity.organizationRef
    && role.occurrenceRef === identity.occurrenceRef
    && role.editionRef === identity.editionRef
    && role.packageVersion === identity.packageVersion
    && role.intendedUse === identity.intendedUse
    && role.sourceRef === identity.sourceRef
    && role.sourceHash === identity.sourceHash
    && role.transformedHash === identity.transformedHash
    && role.uncertaintyRef === identity.uncertaintyRef
    && role.observationRef.length > 0
    && role.observationHash.length === 64;
}

function snapshotAuthorization(value, request, digest) {
  const keys = [
    'status', 'requestHash', 'tenantRef', 'scopeRef', 'organizationRef', 'occurrenceRef',
    'editionRef', 'packageVersion', 'intendedUse', 'principalRef', 'subjectRef',
    'authorizationRevision',
  ];
  const data = snapshotRecord(value, keys);
  if (!data || !['authorized', 'denied'].includes(data.status)
    || data.requestHash !== digest
    || requestRefKeys.some((key) => data[key] !== request[key])
    || !isReference(data.principalRef) || !isReference(data.subjectRef)
    || !isReference(data.authorizationRevision)) fail('AUTHORITY_UNAVAILABLE');
  return Object.freeze(Object.fromEntries(keys.map((key) => [key, data[key]])));
}

function freezeArgument(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeArgument));
  if (value && typeof value === 'object') {
    const output = Object.create(null);
    for (const key of Object.keys(value)) output[key] = freezeArgument(value[key]);
    return Object.freeze(output);
  }
  return value;
}

function createContext(request, digest, operation, adapters, originalPrincipal = null) {
  const context = {
    request,
    requestHash: digest,
    operation,
    adapters,
    originalPrincipal,
    currentAuthorization: null,
    roleDecisions: [],
    permissionDecisions: [],
  };
  context.assertCurrent = () => {
    checkOperation(operation);
    if (typeof adapters.readAuthorization !== 'function') fail('AUTHORITY_UNAVAILABLE');
    let raw;
    try {
      raw = adapters.readAuthorization(freezeArgument({ request, requestHash: digest }));
    } catch {
      checkOperation(operation);
      fail('AUTHORITY_UNAVAILABLE');
    }
    observeOrdinaryNativePromise(raw);
    checkOperation(operation);
    let authorization;
    try {
      authorization = snapshotAuthorization(raw, request, digest);
    } catch (error) {
      checkOperation(operation);
      throw error;
    }
    if (authorization.status !== 'authorized') fail('AUTHORIZATION_DENIED');
    if (context.originalPrincipal
      && (authorization.principalRef !== context.originalPrincipal.principalRef
        || authorization.subjectRef !== context.originalPrincipal.subjectRef)) fail('PRINCIPAL_CHANGED');
    context.currentAuthorization = authorization;

    for (const entry of context.roleDecisions) {
      if (typeof adapters.recheckRoleEvidence !== 'function') fail('AUTHORITY_UNAVAILABLE');
      let result;
      try {
        result = adapters.recheckRoleEvidence(freezeArgument({
          request,
          requestHash: digest,
          authorization,
          identity: entry.identity,
          decision: entry.decision,
        }));
      } catch {
        checkOperation(operation);
        fail('AUTHORITY_UNAVAILABLE');
      }
      observeOrdinaryNativePromise(result);
      checkOperation(operation);
      let checked;
      try {
        checked = snapshotRoleRecheck(result, authorization, entry);
      } catch (error) {
        checkOperation(operation);
        throw error;
      }
      if (checked.status !== 'current') fail('ROLE_EVIDENCE_STALE');
    }
    for (const entry of context.permissionDecisions) {
      if (entry.decision.expiresAtMs <= Date.now()) fail('PERMISSION_STALE');
      if (typeof adapters.recheckPermission !== 'function') fail('AUTHORITY_UNAVAILABLE');
      let result;
      try {
        result = adapters.recheckPermission(freezeArgument({
          request,
          requestHash: digest,
          authorization,
          identity: entry.identity,
          decision: entry.decision,
        }));
      } catch {
        checkOperation(operation);
        fail('AUTHORITY_UNAVAILABLE');
      }
      observeOrdinaryNativePromise(result);
      checkOperation(operation);
      let checked;
      try {
        checked = snapshotPermissionRecheck(result, authorization, entry);
      } catch (error) {
        checkOperation(operation);
        throw error;
      }
      if (checked.status !== 'current') fail('PERMISSION_STALE');
    }
    checkOperation(operation);
    return authorization;
  };
  context.currentAuthorization = context.assertCurrent();
  return context;
}

const roleDecisionKeys = [
  'version', 'status', 'requestHash', 'candidateRef', 'assetRef', 'assetVersion', 'tenantRef', 'scopeRef',
  'organizationRef', 'occurrenceRef', 'editionRef', 'packageVersion', 'intendedUse',
  'sourceRef', 'evidenceRef', 'contentType', 'sourceHash', 'transformedHash', 'inspectionPolicyVersion',
  'questionId', 'registryVersion', 'schemaVersion', 'rubricVersion', 'definitionHash', 'targetRef',
  'observationRef', 'observationHash', 'observerRef', 'modelRef', 'regionRef', 'uncertaintyRef', 'role',
  'associationStatus', 'decisionRef', 'authorityRevision', 'evidenceRevision',
];

function snapshotRoleDecision(value, identity, authorization) {
  const data = snapshotRecord(value, roleDecisionKeys);
  if (!data || !['eligible', 'review', 'rejected'].includes(data.status)) fail('AUTHORITY_UNAVAILABLE');
  for (const key of Object.keys(identity)) {
    if (data[key] !== identity[key]) fail('AUTHORITY_UNAVAILABLE');
  }
  if (!isReference(data.decisionRef) || !isReference(data.authorityRevision)
    || !isReference(data.evidenceRevision)) fail('AUTHORITY_UNAVAILABLE');
  if (data.authorityRevision !== authorization.authorizationRevision) fail('AUTHORITY_UNAVAILABLE');
  if (!['confirmed', 'unconfirmed', 'mismatch', 'unknown'].includes(data.associationStatus)) fail('AUTHORITY_UNAVAILABLE');
  return Object.freeze(Object.fromEntries(roleDecisionKeys.map((key) => [key, data[key]])));
}

function snapshotRoleRecheck(value, authorization, entry) {
  const keys = [
    'status', 'requestHash', 'candidateRef', 'transformedHash', 'decisionRef',
    'authorizationRevision', 'evidenceRevision',
  ];
  const data = snapshotRecord(value, keys);
  if (!data || !['current', 'stale'].includes(data.status)
    || data.requestHash !== entry.identity.requestHash
    || data.candidateRef !== entry.identity.candidateRef
    || data.transformedHash !== entry.identity.transformedHash
    || data.decisionRef !== entry.decision.decisionRef
    || data.authorizationRevision !== authorization.authorizationRevision
    || data.evidenceRevision !== entry.decision.evidenceRevision) fail('AUTHORITY_UNAVAILABLE');
  return data;
}

const permissionDecisionKeys = [
  'version', 'status', 'requestHash', 'candidateRef', 'assetRef', 'assetVersion', 'tenantRef', 'scopeRef',
  'organizationRef', 'occurrenceRef', 'editionRef', 'packageVersion', 'intendedUse',
  'candidateTenantRef', 'candidateScopeRef', 'candidateOrganizationRef', 'candidateOccurrenceRef',
  'candidateEditionRef', 'candidatePackageVersion', 'candidateIntendedUse', 'sourceRef', 'evidenceRef',
  'sourceHash', 'transformedHash', 'approvalRef', 'declaredExpiresAtMs', 'revocationRef',
  'approvedHash', 'expiresAtMs', 'revocationStatus', 'decisionRef', 'issuerRef', 'approverRef',
  'verifierRef', 'authorityRevision', 'permissionRevision', 'revocationRevision',
];

function permissionIdentity(request, candidate, inspected) {
  const claim = candidate.approvalClaim;
  return Object.freeze({
    version: ASSET_PERMISSION_SELECTION_VERSION,
    requestHash: requestHash(request),
    candidateRef: candidate.candidateRef,
    assetRef: candidate.assetRef,
    assetVersion: candidate.assetVersion,
    tenantRef: request.tenantRef,
    scopeRef: request.scopeRef,
    organizationRef: request.organizationRef,
    occurrenceRef: request.occurrenceRef,
    editionRef: request.editionRef,
    packageVersion: request.packageVersion,
    intendedUse: request.intendedUse,
    candidateTenantRef: candidate.tenantRef,
    candidateScopeRef: candidate.scopeRef,
    candidateOrganizationRef: candidate.organizationRef,
    candidateOccurrenceRef: candidate.occurrenceRef,
    candidateEditionRef: candidate.editionRef,
    candidatePackageVersion: candidate.packageVersion,
    candidateIntendedUse: candidate.intendedUse,
    sourceRef: candidate.sourceRef,
    evidenceRef: candidate.evidenceRef,
    sourceHash: inspected.sourceHash,
    transformedHash: inspected.transformedHash,
    approvalRef: claim.approvalRef,
    declaredExpiresAtMs: claim.declaredExpiresAtMs,
    revocationRef: claim.revocationRef,
  });
}

function snapshotPermissionDecision(value, identity, authorization) {
  const data = snapshotRecord(value, permissionDecisionKeys);
  if (!data || !['authorized', 'denied', 'revoked', 'expired', 'review'].includes(data.status)) {
    fail('AUTHORITY_UNAVAILABLE');
  }
  for (const key of Object.keys(identity)) {
    if (data[key] !== identity[key]) fail('AUTHORITY_UNAVAILABLE');
  }
  if (data.approvedHash !== identity.transformedHash
    || !isSafeIntegerTime(data.expiresAtMs)
    || data.expiresAtMs !== identity.declaredExpiresAtMs
    || !['active', 'revoked', 'unknown'].includes(data.revocationStatus)
    || !isReference(data.decisionRef) || !isReference(data.issuerRef)
    || !isReference(data.approverRef) || !isReference(data.verifierRef)
    || !isReference(data.authorityRevision) || !isReference(data.permissionRevision)
    || !isReference(data.revocationRevision)) fail('AUTHORITY_UNAVAILABLE');
  if (data.authorityRevision !== authorization.authorizationRevision) fail('AUTHORITY_UNAVAILABLE');
  return Object.freeze(Object.fromEntries(permissionDecisionKeys.map((key) => [key, data[key]])));
}

function snapshotPermissionRecheck(value, authorization, entry) {
  const keys = [
    'status', 'requestHash', 'candidateRef', 'transformedHash', 'decisionRef',
    'authorizationRevision', 'permissionRevision', 'revocationRevision',
  ];
  const data = snapshotRecord(value, keys);
  if (!data || !['current', 'stale'].includes(data.status)
    || data.requestHash !== entry.identity.requestHash
    || data.candidateRef !== entry.identity.candidateRef
    || data.transformedHash !== entry.identity.transformedHash
    || data.decisionRef !== entry.decision.decisionRef
    || data.authorizationRevision !== authorization.authorizationRevision
    || data.permissionRevision !== entry.decision.permissionRevision
    || data.revocationRevision !== entry.decision.revocationRevision) fail('AUTHORITY_UNAVAILABLE');
  return data;
}

function diagnostic(candidateRef, code) {
  return Object.freeze({ candidateRef, code });
}

async function inspectAndSelectCandidate(context, parsed, diagnostics) {
  const { request, operation, adapters } = context;
  const { candidate, bytes, scopeMatches } = parsed;
  const inspection = inspectSafeAssetBytes(bytes, {
    contentType: candidate.contentType,
    signal: operation.signal ?? undefined,
    deadlineAtMs: operation.deadlineAtMs,
  });
  if (inspection.action !== 'transformed' || inspection.contentType !== 'image/svg+xml') {
    diagnostics.push(diagnostic(candidate.candidateRef, 'INSPECTION_NOT_TRANSFORMED'));
    return null;
  }
  const transformedBytes = inspection.copyTransformedBytes();
  if (!transformedBytes || !inspection.matchesTransformedBytes(transformedBytes)
    || inspection.sourceHash !== candidate.sourceHash
    || inspection.transformedHash !== candidate.transformedHash
    || sha256(transformedBytes) !== inspection.transformedHash) {
    diagnostics.push(diagnostic(candidate.candidateRef, 'HASH_MISMATCH'));
    return null;
  }

  const identity = candidateIdentity(request, candidate, inspection);
  const roleMatches = scopeMatches && roleEvidenceMatches(candidate, identity);
  let roleDecision = null;
  if (roleMatches && typeof adapters.verifyRoleEvidence === 'function'
    && typeof adapters.recheckRoleEvidence === 'function') {
    context.assertCurrent();
    const authorization = context.currentAuthorization;
    const raw = await awaitAdapter(adapters.verifyRoleEvidence, freezeArgument({
      request,
      requestHash: context.requestHash,
      authorization,
      identity,
      observation: candidate.roleEvidence,
    }), operation, context.assertCurrent);
    roleDecision = snapshotRoleDecision(raw, identity, authorization);
    if (roleDecision.status === 'eligible') {
      context.roleDecisions.push({ identity, decision: roleDecision });
      context.assertCurrent();
    }
  }

  let permissionDecision = null;
  const permission = permissionIdentity(request, candidate, inspection);
  if (typeof adapters.verifyPermission === 'function' && typeof adapters.recheckPermission === 'function') {
    context.assertCurrent();
    const authorization = context.currentAuthorization;
    const raw = await awaitAdapter(adapters.verifyPermission, freezeArgument({
      request,
      requestHash: context.requestHash,
      authorization,
      identity: permission,
      claim: candidate.approvalClaim,
    }), operation, context.assertCurrent);
    permissionDecision = snapshotPermissionDecision(raw, permission, authorization);
    if (permissionDecision.status === 'authorized') {
      context.permissionDecisions.push({ identity: permission, decision: permissionDecision });
      context.assertCurrent();
    }
  }

  const roleEligible = scopeMatches && roleDecision?.status === 'eligible'
    && roleDecision.associationStatus === 'confirmed'
    && handoffRoles.has(identity.role);
  const permissionEligible = scopeMatches && permissionDecision?.status === 'authorized'
    && permissionDecision.revocationStatus === 'active'
    && permissionDecision.approvedHash === inspection.transformedHash
    && permissionDecision.expiresAtMs > Date.now();
  if (!scopeMatches) diagnostics.push(diagnostic(candidate.candidateRef, 'SCOPE_MISMATCH'));
  if (!roleEligible) diagnostics.push(diagnostic(candidate.candidateRef,
    !roleMatches || !roleDecision ? 'ROLE_EVIDENCE_UNVERIFIED' : 'ROLE_EVIDENCE_REVIEW'));
  if (!permissionEligible) diagnostics.push(diagnostic(candidate.candidateRef,
    !permissionDecision ? 'PERMISSION_VERIFIER_UNAVAILABLE' : 'PERMISSION_NOT_CURRENT'));
  if (!roleEligible || !permissionEligible) return null;

  return Object.freeze({
    candidate,
    inspection,
    transformedBytes,
    identity,
    roleDecision,
    permissionDecision,
  });
}

function snapshotPublishResult(value, requestHashValue, selectionId) {
  const data = snapshotRecord(value, ['status', 'requestHash', 'selectionId', 'handoffRef'], ['status', 'requestHash', 'selectionId']);
  if (!data || !['published', 'rejected'].includes(data.status)
    || data.requestHash !== requestHashValue || data.selectionId !== selectionId) fail('PUBLISH_REJECTED');
  if (data.status === 'published' && !isReference(data.handoffRef)) fail('PUBLISH_REJECTED');
  if (data.status === 'rejected' && data.handoffRef !== undefined) fail('PUBLISH_REJECTED');
  return Object.freeze({ status: data.status, handoffRef: data.handoffRef ?? null });
}

function validAdapters(value) {
  const data = snapshotRecord(value, adapterKeys, []);
  if (!data) fail('INVALID_INPUT');
  for (const key of Object.keys(data)) {
    if (typeof data[key] !== 'function') fail('INVALID_INPUT');
  }
  return Object.freeze(data);
}

function isThenableWithoutInvoking(value) {
  try {
    if (!value || (typeof value !== 'object' && typeof value !== 'function')) return false;
    let current = value;
    while (current !== null) {
      if (isProxy(current)) return true;
      const descriptor = Object.getOwnPropertyDescriptor(current, 'then');
      if (descriptor) return typeof descriptor.value === 'function' || typeof descriptor.get === 'function';
      current = Object.getPrototypeOf(current);
    }
    return false;
  } catch {
    return true;
  }
}

function runWithOperation(options, resourceState, callback) {
  const operation = beginOperation(options, resourceState);
  return Promise.resolve()
    .then(() => callback(operation))
    .finally(() => finishOperation(operation));
}

/**
 * Create a private selector. All authorization callbacks are host-installed
 * trust boundaries. A client supplied record is never promoted by this module.
 */
export function createAssetPermissionSelector(adapterInput) {
  const adapters = validAdapters(adapterInput);
  const states = new Map();
  const expiredHandles = new WeakSet();
  const resourceState = { activeOperations: 0, activeAdapterCalls: 0 };
  const emptyArray = Object.freeze([]);

  function clearSelectionState(handle, state, expired = false) {
    if (states.get(handle) === state) states.delete(handle);
    if (expired) expiredHandles.add(handle);
    if (state.expiryTimer !== null) clearTimeoutIntrinsic(state.expiryTimer);
    state.expiryTimer = null;
    state.consumed = true;
    state.request = null;
    state.requestHash = null;
    state.selectionId = null;
    state.principalRef = null;
    state.subjectRef = null;
    state.assets = emptyArray;
    state.diagnostics = emptyArray;
  }

  function purgeExpiredSelections() {
    const now = performance.now();
    let purged = 0;
    for (const [handle, state] of states) {
      if (now - state.createdAtMonotonic >= ASSET_PERMISSION_SELECTION_LIMITS.maxHandleAgeMs) {
        clearSelectionState(handle, state, true);
        purged += 1;
      }
    }
    return purged;
  }

  function scheduleSelectionExpiry(handle, state) {
    const elapsed = performance.now() - state.createdAtMonotonic;
    const remaining = Math.max(1, ASSET_PERMISSION_SELECTION_LIMITS.maxHandleAgeMs - elapsed);
    state.expiryTimer = setTimeoutIntrinsic(() => {
      if (states.get(handle) !== state) return;
      if (performance.now() - state.createdAtMonotonic >= ASSET_PERMISSION_SELECTION_LIMITS.maxHandleAgeMs) {
        clearSelectionState(handle, state, true);
      } else {
        scheduleSelectionExpiry(handle, state);
      }
    }, remaining);
    if (typeof state.expiryTimer?.unref === 'function') state.expiryTimer.unref();
  }

  function detachSelectionState(handle, state) {
    if (states.get(handle) === state) states.delete(handle);
    if (state.expiryTimer !== null) clearTimeoutIntrinsic(state.expiryTimer);
    state.expiryTimer = null;
  }

  const api = Object.freeze({
    async select(input, optionsInput) {
      purgeExpiredSelections();
      const selectionInput = snapshotRecord(input, ['request', 'candidates']);
      if (!selectionInput) fail('INVALID_INPUT');
      const request = snapshotRequest(selectionInput.request);
      const digest = requestHash(request);
      const candidateValues = snapshotArray(selectionInput.candidates, ASSET_PERMISSION_SELECTION_LIMITS.maxCandidates);
      if (!candidateValues) fail('INVALID_INPUT');
      const optionSnapshot = snapshotOptions(optionsInput);
      const parsed = [];
      const seenCandidates = new Set();
      const seenAssets = new Set();
      let totalBytes = 0;
      for (const value of candidateValues) {
        const item = candidateDescriptor(value, request);
        if (seenCandidates.has(item.candidate.candidateRef) || seenAssets.has(item.candidate.assetRef)) fail('INVALID_INPUT');
        seenCandidates.add(item.candidate.candidateRef);
        seenAssets.add(item.candidate.assetRef);
        totalBytes += item.bytes.length;
        if (totalBytes > ASSET_PERMISSION_SELECTION_LIMITS.maxTotalSourceBytes) fail('LIMIT_EXCEEDED');
        parsed.push(item);
      }

      return runWithOperation(optionSnapshot, resourceState, async (operation) => {
        const context = createContext(request, digest, operation, adapters);
        const originalPrincipal = context.currentAuthorization;
        context.originalPrincipal = originalPrincipal;

        const diagnostics = [];
        const selected = [];
        try {
          for (const item of parsed) {
            checkOperation(operation);
            const result = await inspectAndSelectCandidate(context, item, diagnostics);
            context.assertCurrent();
            checkOperation(operation);
            if (result) selected.push(result);
          }
          context.assertCurrent();
          checkOperation(operation);
        } catch (error) {
          checkOperation(operation);
          if (error instanceof AssetPermissionSelectionError) throw error;
          fail('AUTHORITY_UNAVAILABLE');
        }

        purgeExpiredSelections();
        if (states.size >= ASSET_PERMISSION_SELECTION_LIMITS.maxOutstandingSelections) fail('LIMIT_EXCEEDED');
        const handle = Object.freeze(Object.create(null));
        const selectionId = randomUUID();
        const state = {
          consumed: false,
          createdAtMonotonic: performance.now(),
          expiryTimer: null,
          request,
          requestHash: digest,
          selectionId,
          principalRef: originalPrincipal.principalRef,
          subjectRef: originalPrincipal.subjectRef,
          assets: Object.freeze(selected),
          diagnostics: Object.freeze(diagnostics.slice(0, ASSET_PERMISSION_SELECTION_LIMITS.maxCandidates * 2)),
        };
        states.set(handle, state);
        try {
          scheduleSelectionExpiry(handle, state);
        } catch {
          clearSelectionState(handle, state);
          fail('LIMIT_EXCEEDED');
        }
        try {
          checkOperation(operation);
        } catch (error) {
          clearSelectionState(handle, state);
          throw error;
        }
        return Object.freeze({
          version: ASSET_PERMISSION_SELECTION_VERSION,
          selectionId,
          handle,
          referenceImageCount: selected.length,
          fallbackRequired: selected.length === 0,
        });
      });
    },

    async handoff(handle, requestInput, optionsInput) {
      purgeExpiredSelections();
      const isHandle = handle && typeof handle === 'object' && !isProxy(handle);
      const state = isHandle ? states.get(handle) : null;
      if (!state || state.consumed) {
        if (isHandle && expiredHandles.has(handle)) fail('SELECTION_EXPIRED');
        fail('INVALID_SELECTION');
      }
      if (performance.now() - state.createdAtMonotonic >= ASSET_PERMISSION_SELECTION_LIMITS.maxHandleAgeMs) {
        clearSelectionState(handle, state, true);
        fail('SELECTION_EXPIRED');
      }
      state.consumed = true;
      detachSelectionState(handle, state);
      try {
        const request = snapshotRequest(requestInput);
        const digest = requestHash(request);
        if (digest !== state.requestHash || canonicalRequest(request) !== canonicalRequest(state.request)) fail('REQUEST_MISMATCH');
        const optionSnapshot = snapshotOptions(optionsInput);
        return await runWithOperation(optionSnapshot, resourceState, async (operation) => {
          const context = createContext(request, digest, operation, adapters, {
            principalRef: state.principalRef,
            subjectRef: state.subjectRef,
          });
          const freshAssets = [];

          try {
            for (const selected of state.assets) {
              checkOperation(operation);
              const { candidate, inspection, transformedBytes, identity } = selected;
              if (!inspection.matchesTransformedBytes(transformedBytes)
                || sha256(transformedBytes) !== identity.transformedHash
                || identity.sourceHash !== inspection.sourceHash
                || identity.transformedHash !== inspection.transformedHash
                || identity.assetVersion !== candidate.assetVersion
                || !requestRefKeys.every((key) => identity[key] === request[key])) fail('ASSET_SNAPSHOT_MISMATCH');

              if (typeof adapters.verifyRoleEvidence !== 'function'
                || typeof adapters.recheckRoleEvidence !== 'function'
                || typeof adapters.verifyPermission !== 'function'
                || typeof adapters.recheckPermission !== 'function') fail('AUTHORITY_UNAVAILABLE');

              context.assertCurrent();
              const authorization = context.currentAuthorization;
              const rawRole = await awaitAdapter(adapters.verifyRoleEvidence, freezeArgument({
                request,
                requestHash: digest,
                authorization,
                identity,
                observation: candidate.roleEvidence,
                handoffRevalidation: true,
              }), operation, context.assertCurrent);
              const roleDecision = snapshotRoleDecision(rawRole, identity, authorization);
              if (roleDecision.status !== 'eligible' || roleDecision.associationStatus !== 'confirmed'
                || !handoffRoles.has(identity.role)) fail('ROLE_EVIDENCE_STALE');
              context.roleDecisions.push({ identity, decision: roleDecision });
              context.assertCurrent();

              const permission = permissionIdentity(request, candidate, inspection);
              context.assertCurrent();
              const permissionAuthorization = context.currentAuthorization;
              const rawPermission = await awaitAdapter(adapters.verifyPermission, freezeArgument({
                request,
                requestHash: digest,
                authorization: permissionAuthorization,
                identity: permission,
                claim: candidate.approvalClaim,
                handoffRevalidation: true,
              }), operation, context.assertCurrent);
              const permissionDecision = snapshotPermissionDecision(rawPermission, permission, permissionAuthorization);
              if (permissionDecision.status !== 'authorized'
                || permissionDecision.revocationStatus !== 'active'
                || permissionDecision.approvedHash !== identity.transformedHash
                || permissionDecision.expiresAtMs <= Date.now()) fail('PERMISSION_DENIED');
              context.permissionDecisions.push({ identity: permission, decision: permissionDecision });
              context.assertCurrent();

              freshAssets.push({ selected, roleDecision, permissionDecision });
            }
          } catch (error) {
            checkOperation(operation);
            if (error instanceof AssetPermissionSelectionError) throw error;
            fail('AUTHORITY_UNAVAILABLE');
          }

          checkOperation(operation);
          context.assertCurrent();
          if (typeof adapters.publishHandoff !== 'function') fail('AUTHORITY_UNAVAILABLE');

          const assets = freshAssets.map(({ selected, roleDecision, permissionDecision }) => {
            const bytes = selected.inspection.copyTransformedBytes();
            if (!bytes || !selected.inspection.matchesTransformedBytes(bytes)
              || sha256(bytes) !== selected.identity.transformedHash) fail('ASSET_SNAPSHOT_MISMATCH');
            return Object.freeze({
              candidateRef: selected.identity.candidateRef,
              assetRef: selected.identity.assetRef,
              assetVersion: selected.identity.assetVersion,
              organizationRef: selected.identity.organizationRef,
              occurrenceRef: selected.identity.occurrenceRef,
              editionRef: selected.identity.editionRef,
              packageVersion: selected.identity.packageVersion,
              intendedUse: selected.identity.intendedUse,
              sourceRef: selected.identity.sourceRef,
              evidenceRef: selected.identity.evidenceRef,
              role: selected.identity.role,
              roleQuestionId: selected.identity.questionId,
              roleRegistryVersion: selected.identity.registryVersion,
              roleSchemaVersion: selected.identity.schemaVersion,
              roleRubricVersion: selected.identity.rubricVersion,
              roleDefinitionHash: selected.identity.definitionHash,
              roleTargetRef: selected.identity.targetRef,
              observationRef: selected.identity.observationRef,
              observationHash: selected.identity.observationHash,
              observerRef: selected.identity.observerRef,
              modelRef: selected.identity.modelRef,
              regionRef: selected.identity.regionRef,
              uncertaintyRef: selected.identity.uncertaintyRef,
              inspectionPolicyVersion: SAFE_ASSET_POLICY_VERSION,
              sourceHash: selected.identity.sourceHash,
              transformedHash: selected.identity.transformedHash,
              approvalRef: selected.candidate.approvalClaim.approvalRef,
              issuerRef: permissionDecision.issuerRef,
              approverRef: permissionDecision.approverRef,
              permissionDecisionRef: permissionDecision.decisionRef,
              permissionRevision: permissionDecision.permissionRevision,
              revocationRef: permissionDecision.revocationRef,
              revocationRevision: permissionDecision.revocationRevision,
              expiresAtMs: permissionDecision.expiresAtMs,
              roleDecisionRef: roleDecision.decisionRef,
              roleEvidenceRevision: roleDecision.evidenceRevision,
              bytes,
            });
          });
          const fallbackRequired = assets.length === 0;
          const payload = Object.freeze({
            version: HANDOFF_VERSION,
            selectionId: state.selectionId,
            request,
            mode: fallbackRequired ? 'original-artwork' : 'permitted-reference-images',
            permittedAssets: Object.freeze(assets),
            referenceImages: Object.freeze(assets),
            fallback: fallbackRequired ? Object.freeze({ mode: 'original-artwork' }) : null,
          });
          const publishContextSnapshot = freezeArgument({
            version: ASSET_PERMISSION_SELECTION_VERSION,
            requestHash: digest,
            selectionId: state.selectionId,
            authorization: context.currentAuthorization,
            roleDecisions: context.roleDecisions.map((entry) => ({
              candidateRef: entry.identity.candidateRef,
              decisionRef: entry.decision.decisionRef,
              evidenceRevision: entry.decision.evidenceRevision,
            })),
            permissionDecisions: context.permissionDecisions.map((entry) => ({
              candidateRef: entry.identity.candidateRef,
              decisionRef: entry.decision.decisionRef,
              permissionRevision: entry.decision.permissionRevision,
              revocationRevision: entry.decision.revocationRevision,
              transformedHash: entry.identity.transformedHash,
            })),
            finalBoundary: 'host-must-atomically-revalidate-current-authorization-and-permissions',
          });
          const publishContext = Object.freeze({
            ...publishContextSnapshot,
            deadlineAtMs: operation.deadlineAtMs,
            signal: operation.signal,
          });
          checkOperation(operation);
          context.assertCurrent();
          checkOperation(operation);
          let rawPublished;
          try {
            rawPublished = adapters.publishHandoff(payload, publishContext);
          } catch {
            checkOperation(operation);
            fail('PUBLISH_REJECTED');
          }
          observeOrdinaryNativePromise(rawPublished);
          checkOperation(operation);
          const asynchronousPublish = isThenableWithoutInvoking(rawPublished);
          checkOperation(operation);
          if (asynchronousPublish) fail('PUBLISH_NOT_SYNCHRONOUS');
          const published = snapshotPublishResult(rawPublished, digest, state.selectionId);
          if (published.status !== 'published') fail('PUBLISH_REJECTED');
          checkOperation(operation);
          return Object.freeze({
            status: fallbackRequired ? 'fallback_published' : 'published',
            selectionId: state.selectionId,
            handoffRef: published.handoffRef,
            permittedAssetCount: assets.length,
          });
        });
      } finally {
        clearSelectionState(handle, state);
      }
    },

    purgeExpired() {
      return purgeExpiredSelections();
    },
  });

  return api;
}
