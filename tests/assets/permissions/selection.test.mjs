import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import {
  getQuestionDefinition,
  QUESTION_REGISTRY_SCHEMA_VERSION,
  QUESTION_REGISTRY_VERSION,
} from '../../../src/decisions/questions/registry.mjs';
import {
  AssetPermissionSelectionError,
  ASSET_PERMISSION_SELECTION_LIMITS,
  createAssetPermissionSelector,
} from '../../../src/verification/asset-permissions/index.mjs';
import { inspectSafeAssetBytes, SAFE_ASSET_LIMITS } from '../../../src/security/assets/inspect.mjs';

const NativeMap = globalThis.Map;
const nativeSetTimeout = globalThis.setTimeout;
const nativeClearTimeout = globalThis.clearTimeout;
const eventTargetPrototype = Object.getPrototypeOf(AbortSignal.prototype);
const nativeAddEventListener = eventTargetPrototype.addEventListener;
const nativeRemoveEventListener = eventTargetPrototype.removeEventListener;
const trackedSelectorMaps = [];
const trackedSelectorTimers = [];
const trackedSelectorAbortListeners = new Set();

class InstrumentedMap extends NativeMap {
  constructor(...args) {
    super(...args);
    trackedSelectorMaps.push(this);
  }
}

function instrumentedTimer(callback, delayMs) {
  const timer = {
    callback,
    delayMs,
    cleared: false,
    unrefCalled: false,
    unref() { this.unrefCalled = true; },
  };
  trackedSelectorTimers.push(timer);
  return timer;
}

let instrumentedPermissionModule;
try {
  globalThis.Map = InstrumentedMap;
  globalThis.setTimeout = (callback, delayMs) => instrumentedTimer(callback, delayMs);
  globalThis.clearTimeout = (timer) => { if (timer) timer.cleared = true; };
  eventTargetPrototype.addEventListener = function addEventListener(type, listener, ...args) {
    if (type === 'abort') trackedSelectorAbortListeners.add(listener);
    return nativeAddEventListener.call(this, type, listener, ...args);
  };
  eventTargetPrototype.removeEventListener = function removeEventListener(type, listener, ...args) {
    if (type === 'abort') trackedSelectorAbortListeners.delete(listener);
    return nativeRemoveEventListener.call(this, type, listener, ...args);
  };
  instrumentedPermissionModule = await import(new URL('../../../src/verification/asset-permissions/index.mjs?lifecycle-check', import.meta.url));
} finally {
  globalThis.Map = NativeMap;
  globalThis.setTimeout = nativeSetTimeout;
  globalThis.clearTimeout = nativeClearTimeout;
  eventTargetPrototype.addEventListener = nativeAddEventListener;
  eventTargetPrototype.removeEventListener = nativeRemoveEventListener;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
const SVG_SOURCE = `<svg xmlns="${SVG_NS}" width="16" height="16"><rect x="1.00" y="2" width="8" height="9" fill="#0aF"/></svg>`;
const BRAND_ROLE = getQuestionDefinition('Q-EI-BRAND-ROLE:v1');
const request = Object.freeze({
  requestVersion: 'asset-permission-request/1',
  tenantRef: 'tenant:one',
  scopeRef: 'scope:project-one',
  organizationRef: 'organization:one',
  occurrenceRef: 'occurrence:fall-show',
  editionRef: 'edition:2026',
  packageVersion: 'package:7',
  intendedUse: 'event-promotion',
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function makeCandidate(overrides = {}) {
  const sourceBytes = Buffer.from(SVG_SOURCE, 'utf8');
  const inspected = inspectSafeAssetBytes(sourceBytes, { contentType: 'image/svg+xml' });
  assert.equal(inspected.action, 'transformed');
  const identity = {
    candidateRef: 'candidate:one',
    assetRef: 'asset:logo-one',
    assetVersion: 'asset-version:4',
    tenantRef: request.tenantRef,
    scopeRef: request.scopeRef,
    organizationRef: request.organizationRef,
    occurrenceRef: request.occurrenceRef,
    editionRef: request.editionRef,
    packageVersion: request.packageVersion,
    intendedUse: request.intendedUse,
    sourceRef: 'source:page-one',
    evidenceRef: 'evidence:asset-one',
    contentType: 'image/svg+xml',
    sourceHash: inspected.sourceHash,
    transformedHash: inspected.transformedHash,
  };
  const roleEvidence = {
    questionId: 'Q-EI-BRAND-ROLE:v1',
    registryVersion: QUESTION_REGISTRY_VERSION,
    schemaVersion: QUESTION_REGISTRY_SCHEMA_VERSION,
    rubricVersion: BRAND_ROLE.rubricVersion,
    definitionHash: BRAND_ROLE.definitionHash,
    targetRef: 'target:brand-role-one',
    candidateRef: identity.candidateRef,
    assetRef: identity.assetRef,
    assetVersion: identity.assetVersion,
    tenantRef: identity.tenantRef,
    scopeRef: identity.scopeRef,
    organizationRef: identity.organizationRef,
    occurrenceRef: identity.occurrenceRef,
    editionRef: identity.editionRef,
    packageVersion: identity.packageVersion,
    intendedUse: identity.intendedUse,
    sourceRef: identity.sourceRef,
    sourceHash: identity.sourceHash,
    transformedHash: identity.transformedHash,
    observationRef: 'observation:logo-one',
    observationHash: sha256('structured-observation:logo-one'),
    observerRef: 'observer:local-fixture',
    modelRef: 'model:jev-candidate-only',
    regionRef: 'region:one',
    uncertaintyRef: 'uncertainty:one',
    role: 'logo',
  };
  const candidate = {
    ...identity,
    bytes: sourceBytes,
    roleEvidence,
    approvalClaim: {
      approvalRef: 'approval:external-one',
      declaredExpiresAtMs: Date.now() + 60_000,
      revocationRef: 'revocation:external-one',
    },
  };
  return { candidate: { ...candidate, ...overrides }, sourceBytes, inspected };
}

function createHost(options = {}) {
  const state = {
    principalRef: options.principalRef ?? 'principal:one',
    subjectRef: options.subjectRef ?? 'subject:one',
    authorizationRevision: options.authorizationRevision ?? 'authorization:1',
    authorized: options.authorized ?? true,
    permissionRevision: options.permissionRevision ?? 'permission:1',
    revocationRevision: options.revocationRevision ?? 'revocation:1',
    revoked: options.revoked ?? false,
    permissionStatus: options.permissionStatus ?? 'authorized',
    roleStatus: options.roleStatus ?? 'eligible',
    associationStatus: options.associationStatus ?? 'confirmed',
    approvedHash: options.approvedHash,
    issuerRef: options.issuerRef ?? 'issuer:external-one',
    approverRef: options.approverRef ?? 'actor:external-one',
    overridePermissionIdentity: options.overridePermissionIdentity,
    failPermissionCandidateRef: options.failPermissionCandidateRef,
    onRole: options.onRole,
    onPermission: options.onPermission,
    onPublish: options.onPublish,
    calls: { role: 0, permission: 0, authorization: 0, publish: 0 },
    permissionIdentities: [],
    published: [],
  };

  const adapters = {
    readAuthorization({ request: scopedRequest, requestHash }) {
      state.calls.authorization += 1;
      return {
        status: state.authorized ? 'authorized' : 'denied',
        requestHash,
        tenantRef: scopedRequest.tenantRef,
        scopeRef: scopedRequest.scopeRef,
        organizationRef: scopedRequest.organizationRef,
        occurrenceRef: scopedRequest.occurrenceRef,
        editionRef: scopedRequest.editionRef,
        packageVersion: scopedRequest.packageVersion,
        intendedUse: scopedRequest.intendedUse,
        principalRef: state.principalRef,
        subjectRef: state.subjectRef,
        authorizationRevision: state.authorizationRevision,
      };
    },
    async verifyRoleEvidence(input, signal) {
      state.calls.role += 1;
      if (options.onRole) await options.onRole(input, signal, state);
      return {
        ...input.identity,
        status: state.roleStatus,
        associationStatus: state.associationStatus,
        decisionRef: `role-decision:${input.identity.candidateRef}`,
        authorityRevision: input.authorization.authorizationRevision,
        evidenceRevision: `role-evidence:${input.identity.candidateRef}:1`,
      };
    },
    recheckRoleEvidence(input) {
      return {
        status: 'current',
        requestHash: input.requestHash,
        candidateRef: input.identity.candidateRef,
        transformedHash: input.identity.transformedHash,
        decisionRef: input.decision.decisionRef,
        authorizationRevision: input.authorization.authorizationRevision,
        evidenceRevision: input.decision.evidenceRevision,
      };
    },
    async verifyPermission(input, signal) {
      state.calls.permission += 1;
      state.permissionIdentities.push(input.identity);
      if (options.onPermission) await options.onPermission(input, signal, state);
      if (state.failPermissionCandidateRef === input.identity.candidateRef) throw new Error('fixture failure');
      const identity = state.overridePermissionIdentity
        ? { ...input.identity, ...state.overridePermissionIdentity(input) }
        : input.identity;
      return {
        ...identity,
        status: state.revoked ? 'revoked' : state.permissionStatus,
        approvedHash: state.approvedHash ?? input.identity.transformedHash,
        expiresAtMs: input.identity.declaredExpiresAtMs,
        revocationStatus: state.revoked ? 'revoked' : 'active',
        decisionRef: `permission-decision:${input.identity.candidateRef}`,
        issuerRef: state.issuerRef,
        approverRef: state.approverRef,
        verifierRef: 'verifier:host-one',
        authorityRevision: input.authorization.authorizationRevision,
        permissionRevision: state.permissionRevision,
        revocationRevision: state.revocationRevision,
      };
    },
    recheckPermission(input) {
      return {
        status: state.revoked || !state.authorized ? 'stale' : 'current',
        requestHash: input.requestHash,
        candidateRef: input.identity.candidateRef,
        transformedHash: input.identity.transformedHash,
        decisionRef: input.decision.decisionRef,
        authorizationRevision: input.authorization.authorizationRevision,
        permissionRevision: input.decision.permissionRevision,
        revocationRevision: input.decision.revocationRevision,
      };
    },
    publishHandoff(payload, context) {
      state.calls.publish += 1;
      if (options.onPublish) options.onPublish(payload, context, state);
      if (!state.authorized || context.authorization.status !== 'authorized'
        || state.authorizationRevision !== context.authorization.authorizationRevision) {
        return { status: 'rejected', requestHash: context.requestHash, selectionId: context.selectionId };
      }
      if (payload.permittedAssets.some((asset) => {
        const permission = context.permissionDecisions.find((entry) => entry.candidateRef === asset.candidateRef);
        return state.revoked || !permission
          || permission.permissionRevision !== state.permissionRevision
          || permission.revocationRevision !== state.revocationRevision
          || asset.expiresAtMs <= Date.now()
          || sha256(asset.bytes) !== asset.transformedHash;
      })) {
        return { status: 'rejected', requestHash: context.requestHash, selectionId: context.selectionId };
      }
      state.published.push(payload);
      return {
        status: 'published',
        requestHash: context.requestHash,
        selectionId: context.selectionId,
        handoffRef: `handoff:${context.selectionId}`,
      };
    },
  };

  return { state, adapters };
}

function errorCode(code) {
  return (error) => error instanceof AssetPermissionSelectionError && error.code === code;
}

function select(selector, candidates, options) {
  return selector.select({ request, candidates }, options);
}

test('selects only inspected transformed bytes after current trusted role and exact permission checks', async () => {
  const fixture = makeCandidate();
  const host = createHost();
  const selector = createAssetPermissionSelector(host.adapters);
  const selected = await select(selector, [fixture.candidate]);

  assert.equal(selected.referenceImageCount, 1);
  assert.equal(selected.fallbackRequired, false);
  assert.equal(host.state.calls.role, 1);
  assert.equal(host.state.calls.permission, 1);
  assert.equal(host.state.calls.publish, 0);
  assert.equal(host.state.calls.authorization >= 3, true);

  fixture.sourceBytes.fill(0);
  fixture.candidate.assetVersion = 'asset-version:mutated';
  fixture.candidate.roleEvidence.role = 'unknown';
  fixture.candidate.approvalClaim.approvalRef = 'approval:mutated';
  const handed = await selector.handoff(selected.handle, request);
  assert.equal(handed.status, 'published');
  assert.equal(handed.permittedAssetCount, 1);
  const payload = host.state.published[0];
  const asset = payload.permittedAssets[0];
  assert.equal(payload.mode, 'permitted-reference-images');
  assert.equal(asset.sourceHash, fixture.inspected.sourceHash);
  assert.equal(asset.transformedHash, fixture.inspected.transformedHash);
  assert.notEqual(asset.sourceHash, asset.transformedHash);
  assert.equal(sha256(asset.bytes), asset.transformedHash);
  assert.deepEqual(asset.bytes, fixture.inspected.copyTransformedBytes());
  assert.equal(Object.hasOwn(payload, 'rawSourceBytes'), false);
  assert.equal(host.state.calls.role, 2);
  assert.equal(host.state.calls.permission, 2);
});

test('checks each role label while role suggestions and favorable judgments never grant permission', async (t) => {
  for (const role of ['favicon', 'logo', 'poster', 'photo', 'unrelated', 'unknown']) {
    await t.test(role, async () => {
      const fixture = makeCandidate();
      fixture.candidate.roleEvidence.role = role;
      const host = createHost();
      const selector = createAssetPermissionSelector(host.adapters);
      const selected = await select(selector, [fixture.candidate]);
      assert.equal(selected.referenceImageCount, ['favicon', 'logo', 'poster', 'photo'].includes(role) ? 1 : 0);
      assert.equal(host.state.calls.permission, 1, 'permission lookup is independent of role');
    });
  }

  const favorableRoleButDeniedPermission = makeCandidate();
  const deniedHost = createHost({ permissionStatus: 'denied' });
  const deniedSelector = createAssetPermissionSelector(deniedHost.adapters);
  const denied = await select(deniedSelector, [favorableRoleButDeniedPermission.candidate]);
  assert.equal(denied.referenceImageCount, 0);
  assert.equal(denied.fallbackRequired, true);
  assert.equal(deniedHost.state.calls.role, 1);
  assert.equal(deniedHost.state.calls.permission, 1);

  const untrustedIssuer = makeCandidate();
  const issuerHost = createHost({
    permissionStatus: 'denied',
    issuerRef: 'issuer:forged',
    approverRef: 'actor:unauthorized',
  });
  const issuerSelector = createAssetPermissionSelector(issuerHost.adapters);
  const issuerFallback = await select(issuerSelector, [untrustedIssuer.candidate]);
  assert.equal(issuerFallback.referenceImageCount, 0);
  assert.equal(issuerHost.state.calls.publish, 0);

  const lowConfidence = makeCandidate();
  const reviewHost = createHost({ roleStatus: 'review', associationStatus: 'unknown' });
  const reviewSelector = createAssetPermissionSelector(reviewHost.adapters);
  const review = await select(reviewSelector, [lowConfidence.candidate]);
  assert.equal(review.referenceImageCount, 0);
});

test('wrong organization and unconfirmed association stay out of the reference set', async () => {
  const wrongCompany = makeCandidate();
  wrongCompany.candidate.organizationRef = 'organization:other';
  const wrongHost = createHost();
  const wrongSelector = createAssetPermissionSelector(wrongHost.adapters);
  const wrong = await select(wrongSelector, [wrongCompany.candidate]);
  assert.equal(wrong.referenceImageCount, 0);
  assert.equal(wrongHost.state.calls.permission, 1);
  assert.equal(wrongHost.state.permissionIdentities[0].candidateOrganizationRef, 'organization:other');
  assert.equal(wrongHost.state.permissionIdentities[0].organizationRef, request.organizationRef);

  const crossTenant = makeCandidate();
  crossTenant.candidate.tenantRef = 'tenant:other';
  const tenantHost = createHost();
  const tenantSelector = createAssetPermissionSelector(tenantHost.adapters);
  const tenantFallback = await select(tenantSelector, [crossTenant.candidate]);
  assert.equal(tenantFallback.referenceImageCount, 0);
  assert.equal(tenantHost.state.calls.permission, 1);
  assert.equal(tenantHost.state.permissionIdentities[0].candidateTenantRef, 'tenant:other');

  const uncertain = makeCandidate();
  const uncertainHost = createHost({ associationStatus: 'unconfirmed' });
  const uncertainSelector = createAssetPermissionSelector(uncertainHost.adapters);
  const uncertainResult = await select(uncertainSelector, [uncertain.candidate]);
  assert.equal(uncertainResult.referenceImageCount, 0);
  assert.equal(uncertainHost.state.calls.permission, 1);
});

test('forged client approval fields and missing host verifiers cannot promote candidate bytes', async () => {
  const forged = makeCandidate();
  forged.candidate.approvalClaim.approved = true;
  const forgedHost = createHost();
  const forgedSelector = createAssetPermissionSelector(forgedHost.adapters);
  await assert.rejects(select(forgedSelector, [forged.candidate]), errorCode('INVALID_INPUT'));
  assert.equal(forgedHost.state.calls.publish, 0);

  const fixture = makeCandidate();
  const noVerifier = createAssetPermissionSelector({
    readAuthorization: createHost().adapters.readAuthorization,
    publishHandoff(payload, context) {
      assert.deepEqual(payload.permittedAssets, []);
      assert.deepEqual(payload.referenceImages, []);
      assert.equal(payload.mode, 'original-artwork');
      assert.deepEqual(payload.fallback, { mode: 'original-artwork' });
      assert.equal(context.permissionDecisions.length, 0);
      return { status: 'published', requestHash: context.requestHash, selectionId: context.selectionId, handoffRef: 'handoff:empty' };
    },
  });
  const fallback = await select(noVerifier, [fixture.candidate]);
  assert.equal(fallback.referenceImageCount, 0);
  const handed = await noVerifier.handoff(fallback.handle, request);
  assert.equal(handed.status, 'fallback_published');
  assert.equal(handed.permittedAssetCount, 0);
});

test('transformed bytes require an exact transformed-hash approval and exact version/scope/use', async () => {
  const sourceOnly = makeCandidate();
  const sourceOnlyHost = createHost({ approvedHash: sourceOnly.inspected.sourceHash });
  const sourceOnlySelector = createAssetPermissionSelector(sourceOnlyHost.adapters);
  await assert.rejects(select(sourceOnlySelector, [sourceOnly.candidate]), errorCode('AUTHORITY_UNAVAILABLE'));
  assert.equal(sourceOnlyHost.state.calls.publish, 0);

  const wrongVersion = makeCandidate();
  const versionHost = createHost({
    overridePermissionIdentity: () => ({ assetVersion: 'asset-version:wrong' }),
  });
  const versionSelector = createAssetPermissionSelector(versionHost.adapters);
  await assert.rejects(select(versionSelector, [wrongVersion.candidate]), errorCode('AUTHORITY_UNAVAILABLE'));

  const wrongScope = makeCandidate();
  wrongScope.candidate.scopeRef = 'scope:other';
  const scopeHost = createHost();
  const scopeSelector = createAssetPermissionSelector(scopeHost.adapters);
  const scopeFallback = await select(scopeSelector, [wrongScope.candidate]);
  assert.equal(scopeFallback.referenceImageCount, 0);

  const wrongUse = makeCandidate();
  wrongUse.candidate.intendedUse = 'unrelated-use';
  const useHost = createHost();
  const useSelector = createAssetPermissionSelector(useHost.adapters);
  const useFallback = await select(useSelector, [wrongUse.candidate]);
  assert.equal(useFallback.referenceImageCount, 0);
});

test('active-content SVG and deceptive content types never produce fallback source bytes', async () => {
  const activeSource = `<svg xmlns="${SVG_NS}" width="16" height="16"><script>fetch('https://example.invalid')</script></svg>`;
  const activeBytes = Buffer.from(activeSource);
  const unsafe = makeCandidate({
    bytes: activeBytes,
    sourceHash: sha256(activeBytes),
    transformedHash: '0'.repeat(64),
  });
  const host = createHost();
  const selector = createAssetPermissionSelector(host.adapters);
  const result = await select(selector, [unsafe.candidate]);
  assert.equal(result.referenceImageCount, 0);
  assert.equal(host.state.calls.publish, 0);
  assert.equal(host.state.calls.permission, 0);

  const deceptive = makeCandidate({ contentType: 'image/png' });
  const deceptiveResult = await select(selector, [deceptive.candidate]);
  assert.equal(deceptiveResult.referenceImageCount, 0);
  assert.equal(host.state.calls.publish, 0);
});

test('revocation and principal changes between selection and handoff deny all publication', async (t) => {
  await t.test('permission revoked after selection', async () => {
    const fixture = makeCandidate();
    const host = createHost();
    const selector = createAssetPermissionSelector(host.adapters);
    const selected = await select(selector, [fixture.candidate]);
    host.state.revoked = true;
    await assert.rejects(selector.handoff(selected.handle, request), errorCode('PERMISSION_DENIED'));
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('authenticated principal changes after selection', async () => {
    const fixture = makeCandidate();
    const host = createHost();
    const selector = createAssetPermissionSelector(host.adapters);
    const selected = await select(selector, [fixture.candidate]);
    host.state.principalRef = 'principal:two';
    host.state.subjectRef = 'subject:two';
    await assert.rejects(selector.handoff(selected.handle, request), errorCode('PRINCIPAL_CHANGED'));
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('request scope cannot be changed for a stored selection', async () => {
    const fixture = makeCandidate();
    const host = createHost();
    const selector = createAssetPermissionSelector(host.adapters);
    const selected = await select(selector, [fixture.candidate]);
    await assert.rejects(selector.handoff(selected.handle, { ...request, packageVersion: 'package:8' }), errorCode('REQUEST_MISMATCH'));
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('approval expires after selection', async () => {
    const fixture = makeCandidate();
    fixture.candidate.approvalClaim.declaredExpiresAtMs = Date.now() + 40;
    const host = createHost();
    const selector = createAssetPermissionSelector(host.adapters);
    const selected = await select(selector, [fixture.candidate]);
    assert.equal(selected.referenceImageCount, 1);
    await delay(55);
    await assert.rejects(selector.handoff(selected.handle, request), errorCode('PERMISSION_DENIED'));
    assert.equal(host.state.calls.publish, 0);
  });
});

test('host final boundary rejects a permission revision changed immediately before publication', async () => {
  const fixture = makeCandidate();
  const host = createHost({ onPublish: (_payload, _context, state) => { state.permissionRevision = 'permission:2'; } });
  const selector = createAssetPermissionSelector(host.adapters);
  const selected = await select(selector, [fixture.candidate]);
  await assert.rejects(selector.handoff(selected.handle, request), errorCode('PUBLISH_REJECTED'));
  assert.equal(host.state.calls.publish, 1);
  assert.equal(host.state.published.length, 0);
});

test('cancellation, deadline, and authorization changes during async verification fail closed', async (t) => {
  await t.test('cancelled permission verification', async () => {
    const fixture = makeCandidate();
    const controller = new AbortController();
    const host = createHost({ onPermission: () => controller.abort() });
    const selector = createAssetPermissionSelector(host.adapters);
    await assert.rejects(select(selector, [fixture.candidate], { signal: controller.signal }), errorCode('CANCELLED'));
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('deadline while permission verification is pending', async () => {
    const fixture = makeCandidate();
    const host = createHost({ onPermission: async () => delay(30) });
    const selector = createAssetPermissionSelector(host.adapters);
    await assert.rejects(select(selector, [fixture.candidate], { deadlineAtMs: performance.now() + 5 }), errorCode('DEADLINE_EXCEEDED'));
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('server authorization revoked by callback completion', async () => {
    const fixture = makeCandidate();
    const host = createHost({
      onPermission: (_input, _signal, state) => { state.authorized = false; },
    });
    const selector = createAssetPermissionSelector(host.adapters);
    await assert.rejects(select(selector, [fixture.candidate]), errorCode('AUTHORIZATION_DENIED'));
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('principal changes while callback is pending', async () => {
    const fixture = makeCandidate();
    const host = createHost({
      onPermission: (_input, _signal, state) => {
        state.principalRef = 'principal:two';
        state.subjectRef = 'subject:two';
      },
    });
    const selector = createAssetPermissionSelector(host.adapters);
    await assert.rejects(select(selector, [fixture.candidate]), errorCode('PRINCIPAL_CHANGED'));
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('claim expires during async permission verification', async () => {
    const fixture = makeCandidate();
    fixture.candidate.approvalClaim.declaredExpiresAtMs = Date.now() + 5;
    const host = createHost({ onPermission: async () => delay(15) });
    const selector = createAssetPermissionSelector(host.adapters);
    await assert.rejects(select(selector, [fixture.candidate]), errorCode('PERMISSION_STALE'));
    assert.equal(host.state.calls.publish, 0);
  });
});

test('one malformed async decision prevents the whole multi-asset selection from being handed off', async () => {
  const first = makeCandidate();
  first.candidate.candidateRef = 'candidate:first';
  first.candidate.assetRef = 'asset:first';
  first.candidate.roleEvidence.candidateRef = 'candidate:first';
  first.candidate.roleEvidence.assetRef = 'asset:first';
  const second = makeCandidate();
  second.candidate.candidateRef = 'candidate:second';
  second.candidate.assetRef = 'asset:second';
  second.candidate.roleEvidence.candidateRef = 'candidate:second';
  second.candidate.roleEvidence.assetRef = 'asset:second';
  const host = createHost({ failPermissionCandidateRef: 'candidate:second' });
  const selector = createAssetPermissionSelector(host.adapters);
  await assert.rejects(select(selector, [first.candidate, second.candidate]), errorCode('AUTHORITY_UNAVAILABLE'));
  assert.equal(host.state.calls.permission, 2);
  assert.equal(host.state.calls.publish, 0);
});

test('input records, candidate count, byte caps, and output hashes are bounded and fail closed', async (t) => {
  await t.test('accessor', async () => {
    const fixture = makeCandidate();
    Object.defineProperty(fixture.candidate, 'candidateRef', { enumerable: true, get: () => 'candidate:evil' });
    const host = createHost();
    const selector = createAssetPermissionSelector(host.adapters);
    await assert.rejects(select(selector, [fixture.candidate]), errorCode('INVALID_INPUT'));
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('proxy', async () => {
    const fixture = makeCandidate();
    const selector = createAssetPermissionSelector(createHost().adapters);
    await assert.rejects(select(selector, [new Proxy(fixture.candidate, {})]), errorCode('INVALID_INPUT'));
  });

  await t.test('candidate count limit', async () => {
    const selector = createAssetPermissionSelector(createHost().adapters);
    await assert.rejects(select(selector, Array.from({ length: ASSET_PERMISSION_SELECTION_LIMITS.maxCandidates + 1 }, () => makeCandidate().candidate)), errorCode('INVALID_INPUT'));
  });

  await t.test('declared output hash mismatch', async () => {
    const fixture = makeCandidate({ transformedHash: 'a'.repeat(64) });
    fixture.candidate.roleEvidence.transformedHash = 'a'.repeat(64);
    const host = createHost();
    const selector = createAssetPermissionSelector(host.adapters);
    const selected = await select(selector, [fixture.candidate]);
    assert.equal(selected.referenceImageCount, 0);
    assert.equal(host.state.calls.permission, 0);
  });

  await t.test('per-source byte cap', async () => {
    const oversized = makeCandidate({ bytes: Buffer.alloc(SAFE_ASSET_LIMITS.maxSourceBytes + 1) });
    const selector = createAssetPermissionSelector(createHost().adapters);
    await assert.rejects(select(selector, [oversized.candidate]), errorCode('INVALID_INPUT'));
  });
});

test('a selection handle is opaque, scoped, and one-use', async () => {
  const fixture = makeCandidate();
  const host = createHost();
  const selector = createAssetPermissionSelector(host.adapters);
  const selected = await select(selector, [fixture.candidate]);
  assert.deepEqual(Object.keys(selected.handle), []);
  assert.equal(Object.isFrozen(selected.handle), true);
  const clone = Object.freeze(Object.create(null));
  await assert.rejects(selector.handoff(clone, request), errorCode('INVALID_SELECTION'));
  await selector.handoff(selected.handle, request);
  await assert.rejects(selector.handoff(selected.handle, request), errorCode('INVALID_SELECTION'));
});

test('final publication receives only the exact sanitized bytes and host version references', async () => {
  const fixture = makeCandidate();
  const host = createHost();
  const selector = createAssetPermissionSelector(host.adapters);
  const selected = await select(selector, [fixture.candidate]);
  await selector.handoff(selected.handle, request);
  const payload = host.state.published[0];
  const asset = payload.permittedAssets[0];
  assert.equal(asset.bytes instanceof Uint8Array, true);
  assert.equal(asset.transformedHash, sha256(asset.bytes));
  assert.equal(asset.permissionRevision, 'permission:1');
  assert.equal(asset.revocationRevision, 'revocation:1');
  assert.equal(asset.expiresAtMs, fixture.candidate.approvalClaim.declaredExpiresAtMs);
  assert.equal(payload.referenceImages.length, 1);
  assert.equal(payload.fallback, null);
});

test('the selector-owned signal cancels cooperative role and permission lookups during select and handoff', async (t) => {
  await t.test('selection role lookup times out without a caller signal', async () => {
    const fixture = makeCandidate();
    let observedSignal;
    const host = createHost({
      onRole: async (_input, signal) => {
        observedSignal = signal;
        await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
        await delay(5);
        throw new Error('LATE_PRIVATE_VERIFIER_FAILURE');
      },
    });
    const selector = createAssetPermissionSelector(host.adapters);
    await assert.rejects(select(selector, [fixture.candidate], {
      deadlineAtMs: performance.now() + 25,
    }), errorCode('DEADLINE_EXCEEDED'));
    assert.equal(observedSignal instanceof AbortSignal, true);
    assert.equal(observedSignal.aborted, true);
    await delay(10);
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('selection role lookup timeout also links a supplied caller signal', async () => {
    const fixture = makeCandidate();
    const caller = new AbortController();
    let observedSignal;
    const host = createHost({
      onRole: async (_input, signal) => {
        observedSignal = signal;
        await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
      },
    });
    const selector = createAssetPermissionSelector(host.adapters);
    await assert.rejects(select(selector, [fixture.candidate], {
      signal: caller.signal,
      deadlineAtMs: performance.now() + 25,
    }), errorCode('DEADLINE_EXCEEDED'));
    assert.equal(observedSignal instanceof AbortSignal, true);
    assert.notEqual(observedSignal, caller.signal);
    assert.equal(observedSignal.aborted, true);
    assert.equal(caller.signal.aborted, false);
  });

  await t.test('selection permission lookup gets an operation signal separate from the caller signal', async () => {
    const fixture = makeCandidate();
    const caller = new AbortController();
    let observedSignal;
    const host = createHost({
      onPermission: async (_input, signal) => {
        observedSignal = signal;
        await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
      },
    });
    const selector = createAssetPermissionSelector(host.adapters);
    await assert.rejects(select(selector, [fixture.candidate], {
      signal: caller.signal,
      deadlineAtMs: performance.now() + 25,
    }), errorCode('DEADLINE_EXCEEDED'));
    assert.equal(observedSignal instanceof AbortSignal, true);
    assert.notEqual(observedSignal, caller.signal);
    assert.equal(observedSignal.aborted, true);
    assert.equal(caller.signal.aborted, false);
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('selection permission lookup timeout works without a caller signal', async () => {
    const fixture = makeCandidate();
    let observedSignal;
    const host = createHost({
      onPermission: async (_input, signal) => {
        observedSignal = signal;
        await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
      },
    });
    const selector = createAssetPermissionSelector(host.adapters);
    await assert.rejects(select(selector, [fixture.candidate], {
      deadlineAtMs: performance.now() + 25,
    }), errorCode('DEADLINE_EXCEEDED'));
    assert.equal(observedSignal instanceof AbortSignal, true);
    assert.equal(observedSignal.aborted, true);
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('handoff role lookup observes its operation deadline without a caller signal', async () => {
    const fixture = makeCandidate();
    let observedSignal;
    const host = createHost({
      onRole: async (input, signal) => {
        if (!input.handoffRevalidation) return;
        observedSignal = signal;
        await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
      },
    });
    const selector = createAssetPermissionSelector(host.adapters);
    const selected = await select(selector, [fixture.candidate]);
    await assert.rejects(selector.handoff(selected.handle, request, {
      deadlineAtMs: performance.now() + 25,
    }), errorCode('DEADLINE_EXCEEDED'));
    assert.equal(observedSignal instanceof AbortSignal, true);
    assert.equal(observedSignal.aborted, true);
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('handoff role lookup timeout also links a supplied caller signal', async () => {
    const fixture = makeCandidate();
    const caller = new AbortController();
    let observedSignal;
    const host = createHost({
      onRole: async (input, signal) => {
        if (!input.handoffRevalidation) return;
        observedSignal = signal;
        await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
      },
    });
    const selector = createAssetPermissionSelector(host.adapters);
    const selected = await select(selector, [fixture.candidate]);
    await assert.rejects(selector.handoff(selected.handle, request, {
      signal: caller.signal,
      deadlineAtMs: performance.now() + 25,
    }), errorCode('DEADLINE_EXCEEDED'));
    assert.equal(observedSignal instanceof AbortSignal, true);
    assert.notEqual(observedSignal, caller.signal);
    assert.equal(observedSignal.aborted, true);
    assert.equal(caller.signal.aborted, false);
  });

  await t.test('handoff permission lookup observes its operation deadline while caller remains live', async () => {
    const fixture = makeCandidate();
    const caller = new AbortController();
    let observedSignal;
    const host = createHost({
      onPermission: async (input, signal) => {
        if (!input.handoffRevalidation) return;
        observedSignal = signal;
        await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
        await delay(5);
      },
    });
    const selector = createAssetPermissionSelector(host.adapters);
    const selected = await select(selector, [fixture.candidate]);
    await assert.rejects(selector.handoff(selected.handle, request, {
      signal: caller.signal,
      deadlineAtMs: performance.now() + 25,
    }), errorCode('DEADLINE_EXCEEDED'));
    assert.equal(observedSignal instanceof AbortSignal, true);
    assert.notEqual(observedSignal, caller.signal);
    assert.equal(observedSignal.aborted, true);
    assert.equal(caller.signal.aborted, false);
    await delay(10);
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('handoff permission lookup timeout works without a caller signal', async () => {
    const fixture = makeCandidate();
    let observedSignal;
    const host = createHost({
      onPermission: async (input, signal) => {
        if (!input.handoffRevalidation) return;
        observedSignal = signal;
        await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
      },
    });
    const selector = createAssetPermissionSelector(host.adapters);
    const selected = await select(selector, [fixture.candidate]);
    await assert.rejects(selector.handoff(selected.handle, request, {
      deadlineAtMs: performance.now() + 25,
    }), errorCode('DEADLINE_EXCEEDED'));
    assert.equal(observedSignal instanceof AbortSignal, true);
    assert.equal(observedSignal.aborted, true);
    assert.equal(host.state.calls.publish, 0);
  });
});

for (const stage of ['select', 'handoff']) {
  for (const target of ['role', 'permission']) {
    for (const stop of ['deadline', 'cancellation']) {
      test(`queued verifier entry respects ${stop} during ${stage} ${target}`, async (t) => {
        const fixture = makeCandidate();
        const host = createHost();
        const caller = new AbortController();
        const observations = { stage, target, stop, armedAt: null, stoppedAt: null, entries: [] };
        let active = false;
        let authorizationChecks = 0;
        let deadlineAtMs;

        function queueStop() {
          if (!active || observations.armedAt !== null) return;
          observations.armedAt = performance.now();
          queueMicrotask(() => {
            if (stop === 'deadline') {
              // Expire the original deadline before native timer delivery. No
              // timer or clock is replaced, and the callback has not started.
              while (performance.now() < deadlineAtMs + 75) { /* bounded fixture delay */ }
            } else {
              caller.abort();
            }
            observations.stoppedAt = performance.now();
          });
        }

        const readAuthorization = host.adapters.readAuthorization;
        host.adapters.readAuthorization = (input) => {
          const result = readAuthorization(input);
          if (active && target === 'role' && ++authorizationChecks === 2) queueStop();
          return result;
        };
        const recheckRole = host.adapters.recheckRoleEvidence;
        host.adapters.recheckRoleEvidence = (input) => {
          const result = recheckRole(input);
          // The first retained role decision is checked in the continuation
          // that schedules permission verification, after the role await.
          if (active && target === 'permission') queueStop();
          return result;
        };
        for (const [name, key] of [['role', 'verifyRoleEvidence'], ['permission', 'verifyPermission']]) {
          const verifier = host.adapters[key];
          host.adapters[key] = (input, signal) => {
            if (active) observations.entries.push({ name, enteredAt: performance.now(), aborted: signal.aborted });
            return verifier(input, signal);
          };
        }

        const selector = createAssetPermissionSelector(host.adapters);
        const selected = stage === 'handoff' ? await select(selector, [fixture.candidate]) : null;
        const initialCalls = { ...host.state.calls };
        deadlineAtMs = performance.now() + 800;
        active = true;
        let result;
        let error;
        try {
          result = stage === 'select'
            ? await select(selector, [fixture.candidate], { signal: caller.signal, deadlineAtMs })
            : await selector.handoff(selected.handle, request, { signal: caller.signal, deadlineAtMs });
        } catch (caught) {
          error = caught;
        }
        observations.deadlineAtMs = deadlineAtMs;
        observations.errorCode = error?.code ?? null;
        observations.calls = Object.fromEntries(['role', 'permission', 'publish'].map((key) => [
          key, host.state.calls[key] - initialCalls[key],
        ]));
        t.diagnostic(JSON.stringify(observations));
        assert.ok(observations.armedAt !== null && observations.armedAt < deadlineAtMs,
          'the stop was queued while the operation was still valid');
        assert.ok(observations.stoppedAt !== null, 'the queued stop actually ran');
        if (stop === 'deadline') assert.ok(observations.stoppedAt >= deadlineAtMs + 75);
        assert.ok(error instanceof AssetPermissionSelectionError);
        assert.equal(error.code, stop === 'deadline' ? 'DEADLINE_EXCEEDED' : 'CANCELLED');
        assert.equal(result, undefined);
        assert.equal(observations.entries.filter((entry) => entry.name === target).length, 0,
          'no queued verifier may start after cancellation or the original deadline');
        assert.equal(observations.calls.role, target === 'role' ? 0 : 1);
        assert.equal(observations.calls.permission, 0);
        assert.equal(observations.calls.publish, 0);
        assert.equal(host.state.published.length, 0);

        active = false;
        await delay(0);
        if (selected) {
          await assert.rejects(selector.handoff(selected.handle, request), errorCode('INVALID_SELECTION'));
        }
        const recovered = await select(selector, [fixture.candidate]);
        assert.equal(recovered.referenceImageCount, 1);
        assert.equal((await selector.handoff(recovered.handle, request)).status, 'published');
      });
    }
  }
}

test('caller cancellation is distinct from the internal timeout and reaches cooperative adapters', async (t) => {
  await t.test('explicit abort during a lookup', async () => {
    const fixture = makeCandidate();
    const caller = new AbortController();
    let observedSignal;
    const host = createHost({
      onPermission: (_input, signal) => new Promise((resolve) => {
        observedSignal = signal;
        signal.addEventListener('abort', resolve, { once: true });
        caller.abort();
      }),
    });
    const selector = createAssetPermissionSelector(host.adapters);
    await assert.rejects(select(selector, [fixture.candidate], { signal: caller.signal }), errorCode('CANCELLED'));
    assert.equal(observedSignal?.aborted, true);
    assert.equal(host.state.calls.publish, 0);
  });

  await t.test('pre-aborted caller signal never invokes a verifier', async () => {
    const fixture = makeCandidate();
    const caller = new AbortController();
    caller.abort();
    const host = createHost();
    const selector = createAssetPermissionSelector(host.adapters);
    await assert.rejects(select(selector, [fixture.candidate], { signal: caller.signal }), errorCode('CANCELLED'));
    assert.equal(host.state.calls.role, 0);
    assert.equal(host.state.calls.permission, 0);
  });

  await t.test('default 1,500 ms bound aborts a cooperative role lookup', async () => {
    const fixture = makeCandidate();
    let observedSignal;
    const host = createHost({
      onRole: async (_input, signal) => {
        observedSignal = signal;
        await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
      },
    });
    const selector = createAssetPermissionSelector(host.adapters);
    const startedAt = performance.now();
    await assert.rejects(select(selector, [fixture.candidate]), errorCode('DEADLINE_EXCEEDED'));
    const elapsedMs = performance.now() - startedAt;
    assert.equal(observedSignal?.aborted, true);
    assert.equal(elapsedMs >= ASSET_PERMISSION_SELECTION_LIMITS.maxOperationMs - 40, true);
    assert.equal(elapsedMs < ASSET_PERMISSION_SELECTION_LIMITS.maxOperationMs + 500, true);
  });
});

test('deadline crossing inside synchronous final publication cannot return a handoff', async () => {
  const host = createHost();
  const originalNowDescriptor = Object.getOwnPropertyDescriptor(performance, 'now');
  const beforePublication = performance.now();
  const deadlineAtMs = beforePublication + 100;
  let pastDeadline = false;
  Object.defineProperty(performance, 'now', {
    configurable: true,
    value: () => (pastDeadline ? deadlineAtMs + 1 : beforePublication),
  });
  host.adapters.publishHandoff = (_payload, context) => {
    pastDeadline = true;
    return {
      status: 'published',
      requestHash: context.requestHash,
      selectionId: context.selectionId,
      handoffRef: 'handoff:too-late',
    };
  };
  const selector = createAssetPermissionSelector(host.adapters);
  const selected = await select(selector, []);
  try {
    await assert.rejects(selector.handoff(selected.handle, request, { deadlineAtMs }), errorCode('DEADLINE_EXCEEDED'));
    assert.equal(host.state.published.length, 0);
  } finally {
    if (originalNowDescriptor) Object.defineProperty(performance, 'now', originalNowDescriptor);
    else delete performance.now;
  }
});

test('ordinary native promises from synchronous hooks are observed and remain typed denials', async (t) => {
  const hookCases = [
    ['readAuthorization', 'AUTHORITY_UNAVAILABLE'],
    ['recheckRoleEvidence', 'AUTHORITY_UNAVAILABLE'],
    ['recheckPermission', 'AUTHORITY_UNAVAILABLE'],
    ['publishHandoff', 'PUBLISH_NOT_SYNCHRONOUS'],
  ];
  for (const [hook, expectedCode] of hookCases) {
    for (const settlement of ['fulfilled', 'rejected']) {
      await t.test(`${hook} returns an ordinary ${settlement} Promise`, async () => {
        const fixture = makeCandidate();
        const host = createHost();
        const adapters = {
          ...host.adapters,
          [hook]: (...args) => {
            if (hook === 'publishHandoff') host.state.calls.publish += 1;
            return settlement === 'fulfilled'
              ? Promise.resolve({})
              : Promise.reject(new Error('PRIVATE_PROMISE_MARKER'));
          },
        };
        const selector = createAssetPermissionSelector(adapters);
        if (hook === 'publishHandoff') {
          const selected = await select(selector, [fixture.candidate]);
          await assert.rejects(selector.handoff(selected.handle, request), errorCode(expectedCode));
          assert.equal(host.state.calls.publish, 1);
          assert.equal(host.state.published.length, 0);
        } else {
          await assert.rejects(select(selector, [fixture.candidate]), errorCode(expectedCode));
          assert.equal(host.state.calls.publish, 0);
        }
      });
    }
  }
});

test('hostile then accessors and proxies from synchronous hooks are rejected without invoking hooks', async (t) => {
  await t.test('authorization proxy traps are not invoked', async () => {
    const fixture = makeCandidate();
    let traps = 0;
    const host = createHost();
    const selector = createAssetPermissionSelector({
      ...host.adapters,
      readAuthorization: () => new Proxy({}, {
        get() { traps += 1; throw new Error('proxy get'); },
        ownKeys() { traps += 1; throw new Error('proxy keys'); },
        getOwnPropertyDescriptor() { traps += 1; throw new Error('proxy descriptor'); },
      }),
    });
    await assert.rejects(select(selector, [fixture.candidate]), errorCode('AUTHORITY_UNAVAILABLE'));
    assert.equal(traps, 0);
  });

  await t.test('an exotic native Promise constructor accessor is not invoked', async () => {
    const fixture = makeCandidate();
    let getters = 0;
    const returned = Promise.resolve({});
    Object.defineProperty(returned, 'constructor', {
      get() { getters += 1; throw new Error('constructor getter'); },
    });
    const host = createHost();
    const selector = createAssetPermissionSelector({
      ...host.adapters,
      readAuthorization: () => returned,
    });
    await assert.rejects(select(selector, [fixture.candidate]), errorCode('AUTHORITY_UNAVAILABLE'));
    assert.equal(getters, 0);
  });

  await t.test('publisher then and constructor accessors are not invoked', async () => {
    const fixture = makeCandidate();
    let getters = 0;
    const host = createHost();
    const selector = createAssetPermissionSelector({
      ...host.adapters,
      publishHandoff() {
        const result = {};
        Object.defineProperties(result, {
          then: { get() { getters += 1; throw new Error('then getter'); } },
          constructor: { get() { getters += 1; throw new Error('constructor getter'); } },
          [Symbol.species]: { get() { getters += 1; throw new Error('species getter'); } },
        });
        return result;
      },
    });
    const selected = await select(selector, [fixture.candidate]);
    await assert.rejects(selector.handoff(selected.handle, request), errorCode('PUBLISH_NOT_SYNCHRONOUS'));
    assert.equal(getters, 0);
    assert.equal(host.state.published.length, 0);
  });

  await t.test('publisher proxy traps are not invoked', async () => {
    const fixture = makeCandidate();
    let traps = 0;
    const host = createHost();
    const selector = createAssetPermissionSelector({
      ...host.adapters,
      publishHandoff() {
        return new Proxy({}, {
          get() { traps += 1; throw new Error('proxy get'); },
          getOwnPropertyDescriptor() { traps += 1; throw new Error('proxy descriptor'); },
        });
      },
    });
    const selected = await select(selector, [fixture.candidate]);
    await assert.rejects(selector.handoff(selected.handle, request), errorCode('PUBLISH_NOT_SYNCHRONOUS'));
    assert.equal(traps, 0);
    assert.equal(host.state.published.length, 0);
  });
});

test('native rejected promises from each synchronous hook do not crash a default Node child process', () => {
  const fixture = makeCandidate();
  const moduleUrl = new URL('../../../src/verification/asset-permissions/index.mjs', import.meta.url).href;
  const candidateJson = JSON.stringify(fixture.candidate);
  const requestJson = JSON.stringify(request);
  const childScript = `
import { createAssetPermissionSelector } from ${JSON.stringify(moduleUrl)};
const request = ${requestJson};
const candidate = JSON.parse(${JSON.stringify(candidateJson)});
candidate.bytes = Uint8Array.from(candidate.bytes.data);
const hooks = ['readAuthorization', 'recheckRoleEvidence', 'recheckPermission', 'publishHandoff'];
function baseAdapters() {
  return {
    readAuthorization({ request: r, requestHash }) {
      return { status: 'authorized', requestHash, tenantRef:r.tenantRef, scopeRef:r.scopeRef,
        organizationRef:r.organizationRef, occurrenceRef:r.occurrenceRef, editionRef:r.editionRef,
        packageVersion:r.packageVersion, intendedUse:r.intendedUse, principalRef:'principal:one',
        subjectRef:'subject:one', authorizationRevision:'authorization:1' };
    },
    verifyRoleEvidence({ identity, authorization }) {
      return { ...identity, status:'eligible', associationStatus:'confirmed', decisionRef:'role-decision:one',
        authorityRevision:authorization.authorizationRevision, evidenceRevision:'role-evidence:1' };
    },
    recheckRoleEvidence({ requestHash, identity, decision, authorization }) {
      return { status:'current', requestHash, candidateRef:identity.candidateRef,
        transformedHash:identity.transformedHash, decisionRef:decision.decisionRef,
        authorizationRevision:authorization.authorizationRevision, evidenceRevision:decision.evidenceRevision };
    },
    verifyPermission({ identity, authorization }) {
      return { ...identity, status:'authorized', approvedHash:identity.transformedHash,
        expiresAtMs:identity.declaredExpiresAtMs, revocationStatus:'active', decisionRef:'permission-decision:one',
        issuerRef:'issuer:one', approverRef:'actor:one', verifierRef:'verifier:one',
        authorityRevision:authorization.authorizationRevision, permissionRevision:'permission:1',
        revocationRevision:'revocation:1' };
    },
    recheckPermission({ requestHash, identity, decision, authorization }) {
      return { status:'current', requestHash, candidateRef:identity.candidateRef,
        transformedHash:identity.transformedHash, decisionRef:decision.decisionRef,
        authorizationRevision:authorization.authorizationRevision, permissionRevision:decision.permissionRevision,
        revocationRevision:decision.revocationRevision };
    },
    publishHandoff(_payload, context) {
      return { status:'published', requestHash:context.requestHash, selectionId:context.selectionId, handoffRef:'handoff:one' };
    },
  };
}
const errors = [];
for (const hook of hooks) {
  const adapters = baseAdapters();
  adapters[hook] = () => Promise.reject(new Error('PRIVATE_REJECTION_MARKER'));
  const selector = createAssetPermissionSelector(adapters);
  try {
    const selected = await selector.select({ request, candidates:[candidate] });
    if (hook === 'publishHandoff') await selector.handoff(selected.handle, request);
  } catch (error) {
    errors.push(error.code);
  }
}
await new Promise((resolve) => setTimeout(resolve, 20));
process.stdout.write(JSON.stringify(errors));
`;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', childScript], {
    cwd: process.cwd(),
    encoding: 'utf8',
    timeout: 10_000,
  });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), [
    'AUTHORITY_UNAVAILABLE',
    'AUTHORITY_UNAVAILABLE',
    'AUTHORITY_UNAVAILABLE',
    'PUBLISH_NOT_SYNCHRONOUS',
  ]);
  assert.equal(child.stderr.includes('PRIVATE_REJECTION_MARKER'), false);
});

test('concurrent operation and detached adapter work remain under finite per-selector caps', async (t) => {
  await t.test('active operation slots are capped and reclaimed after caller cancellation', async () => {
    const controllers = Array.from({ length: ASSET_PERMISSION_SELECTION_LIMITS.maxConcurrentOperations }, () => new AbortController());
    const fixture = makeCandidate();
    const host = createHost({
      onRole: async (_input, signal) => new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true })),
    });
    const selector = createAssetPermissionSelector(host.adapters);
    const operations = controllers.map((controller) => select(selector, [fixture.candidate], { signal: controller.signal }));
    for (let turn = 0; turn < 20 && host.state.calls.role < ASSET_PERMISSION_SELECTION_LIMITS.maxConcurrentOperations; turn += 1) {
      await Promise.resolve();
    }
    assert.equal(host.state.calls.role, ASSET_PERMISSION_SELECTION_LIMITS.maxConcurrentOperations);
    await assert.rejects(select(selector, [fixture.candidate]), errorCode('LIMIT_EXCEEDED'));
    for (const controller of controllers) controller.abort();
    const results = await Promise.allSettled(operations);
    assert.equal(results.every((result) => result.status === 'rejected' && result.reason.code === 'CANCELLED'), true);
    const fallback = await selector.select({ request, candidates: [] });
    await selector.handoff(fallback.handle, request);
  });

  await t.test('timed-out callbacks that ignore abort remain counted until settlement', async () => {
    const pendingResolvers = [];
    let shouldBlock = true;
    const fixture = makeCandidate();
    const host = createHost({
      onRole: async () => {
        if (!shouldBlock) return;
        await new Promise((resolve) => pendingResolvers.push(resolve));
      },
    });
    const selector = createAssetPermissionSelector(host.adapters);
    const operations = Array.from({ length: ASSET_PERMISSION_SELECTION_LIMITS.maxOutstandingAdapterCalls }, () => select(
      selector,
      [fixture.candidate],
      { deadlineAtMs: performance.now() + 30 },
    ));
    const results = await Promise.allSettled(operations);
    assert.equal(results.every((result) => result.status === 'rejected' && result.reason.code === 'DEADLINE_EXCEEDED'), true);
    assert.equal(pendingResolvers.length, ASSET_PERMISSION_SELECTION_LIMITS.maxOutstandingAdapterCalls);

    await assert.rejects(select(selector, [fixture.candidate]), errorCode('LIMIT_EXCEEDED'));
    assert.equal(host.state.calls.role, ASSET_PERMISSION_SELECTION_LIMITS.maxOutstandingAdapterCalls);
    for (const resolve of pendingResolvers) resolve();
    await delay(0);
    shouldBlock = false;
    const recovered = await select(selector, [fixture.candidate]);
    assert.equal(recovered.referenceImageCount, 1);
    await selector.handoff(recovered.handle, request);
  });
});

function makeUnknownCandidate() {
  const candidate = makeCandidate().candidate;
  candidate.candidateRef = 'candidate:unknown-lifecycle';
  candidate.assetRef = 'asset:unknown-lifecycle';
  candidate.roleEvidence.candidateRef = candidate.candidateRef;
  candidate.roleEvidence.assetRef = candidate.assetRef;
  candidate.roleEvidence.targetRef = 'target:unknown-lifecycle';
  candidate.roleEvidence.role = 'unknown';
  return candidate;
}

function instrumentedSelector(adapters) {
  globalThis.Map = InstrumentedMap;
  try {
    return instrumentedPermissionModule.createAssetPermissionSelector(adapters);
  } finally {
    globalThis.Map = NativeMap;
  }
}

function instrumentedStateFor(handle) {
  const map = trackedSelectorMaps.find((candidateMap) => candidateMap.has(handle));
  assert.ok(map, 'selector-owned state map contains the retained handle');
  return { map, state: map.get(handle) };
}

function assertSelectorStateReleased(map, handle, state) {
  assert.equal(map.has(handle), false);
  assert.equal(state.assets.length, 0);
  assert.equal(state.diagnostics.length, 0);
  assert.equal(state.request, null);
  assert.equal(state.requestHash, null);
  assert.equal(state.selectionId, null);
  assert.equal(state.principalRef, null);
  assert.equal(state.subjectRef, null);
  assert.equal(state.expiryTimer, null);
}

function assertSelectorOperationResourcesClean() {
  assert.equal(trackedSelectorAbortListeners.size, 0, 'selector-installed abort listeners are removed');
  assert.equal(trackedSelectorTimers.filter((timer) => timer.delayMs < ASSET_PERMISSION_SELECTION_LIMITS.maxHandleAgeMs / 2)
    .every((timer) => timer.cleared), true, 'operation deadline timers are cleared');
}

test('deadline aborts the owned signal and clears its operation timer and abort listener', async () => {
  const fixture = makeCandidate();
  const host = createHost();
  const baseVerifyRole = host.adapters.verifyRoleEvidence;
  let observedSignal;
  host.adapters.verifyRoleEvidence = async (input, signal) => {
    observedSignal = signal;
    await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
    return baseVerifyRole(input, signal);
  };
  const selector = instrumentedSelector(host.adapters);
  const timerStart = trackedSelectorTimers.length;
  const pending = selector.select({ request, candidates: [fixture.candidate] });
  for (let turn = 0; turn < 20 && !observedSignal; turn += 1) await Promise.resolve();
  assert.equal(observedSignal instanceof AbortSignal, true);
  const deadlineTimer = trackedSelectorTimers.slice(timerStart)
    .find((timer) => timer.delayMs < ASSET_PERMISSION_SELECTION_LIMITS.maxHandleAgeMs / 2);
  assert.ok(deadlineTimer);
  deadlineTimer.callback();
  await assert.rejects(pending, { code: 'DEADLINE_EXCEEDED' });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(observedSignal.aborted, true);
  assert.equal(deadlineTimer.cleared, true);
  assertSelectorOperationResourcesClean();
  assert.equal(host.state.published.length, 0);
});

test('consumed handles clear private snapshots and diagnostics after successful and failed handoff', async () => {
  const candidate = makeCandidate().candidate;
  const excluded = makeUnknownCandidate();
  const host = createHost();
  const selector = instrumentedSelector(host.adapters);
  const caller = new AbortController();
  const selected = await selector.select({ request, candidates: [candidate, excluded] }, { signal: caller.signal });
  const { map, state } = instrumentedStateFor(selected.handle);
  assert.equal(state.assets.length, 1);
  assert.equal(state.diagnostics.length > 0, true);
  const expiryTimer = state.expiryTimer;
  await selector.handoff(selected.handle, request, { signal: caller.signal });
  assertSelectorStateReleased(map, selected.handle, state);
  assert.equal(expiryTimer.cleared, true);
  assertSelectorOperationResourcesClean();

  const failedHost = createHost();
  const failedSelector = instrumentedSelector(failedHost.adapters);
  const failedSelection = await failedSelector.select({ request, candidates: [candidate, excluded] });
  const failed = instrumentedStateFor(failedSelection.handle);
  failedHost.state.revoked = true;
  await assert.rejects(failedSelector.handoff(failedSelection.handle, request), { code: 'PERMISSION_DENIED' });
  assertSelectorStateReleased(failed.map, failedSelection.handle, failed.state);
  assert.equal(failedHost.state.published.length, 0);
  assertSelectorOperationResourcesClean();
});

test('abandoned handles expire by monotonic time, can be explicitly purged, and are also timer-purged', async () => {
  const originalNowDescriptor = Object.getOwnPropertyDescriptor(performance, 'now');
  const originalDateNow = Date.now;
  let monotonicNow = 50_000;
  Object.defineProperty(performance, 'now', { configurable: true, value: () => monotonicNow });
  try {
    const host = createHost();
    const selector = instrumentedSelector(host.adapters);
    const candidate = makeUnknownCandidate();
    const selected = await selector.select({ request, candidates: [candidate] });
    const { map, state } = instrumentedStateFor(selected.handle);
    assert.equal(state.assets.length, 0);
    assert.equal(state.diagnostics.length > 0, true);
    const originalWallTime = originalDateNow();
    Date.now = () => originalWallTime - 10_000_000;

    monotonicNow += ASSET_PERMISSION_SELECTION_LIMITS.maxHandleAgeMs - 10;
    assert.equal(selector.purgeExpired(), 0);
    assert.equal(map.has(selected.handle), true);
    monotonicNow += 11;
    assert.equal(selector.purgeExpired(), 1);
    assertSelectorStateReleased(map, selected.handle, state);
    await assert.rejects(selector.handoff(selected.handle, request), { code: 'SELECTION_EXPIRED' });

    const timerSelected = await selector.select({ request, candidates: [candidate] });
    const timerState = instrumentedStateFor(timerSelected.handle);
    const expiryTimer = timerState.state.expiryTimer;
    assert.equal(expiryTimer.delayMs >= ASSET_PERMISSION_SELECTION_LIMITS.maxHandleAgeMs - 1, true);
    monotonicNow += ASSET_PERMISSION_SELECTION_LIMITS.maxHandleAgeMs + 1;
    expiryTimer.callback();
    assertSelectorStateReleased(timerState.map, timerSelected.handle, timerState.state);
    assert.equal(expiryTimer.cleared, true);
  } finally {
    Date.now = originalDateNow;
    if (originalNowDescriptor) Object.defineProperty(performance, 'now', originalNowDescriptor);
    else delete performance.now;
  }
});

test('outstanding-selection capacity is finite and reclaimed after one-use handoff', async () => {
  const host = createHost();
  const selector = instrumentedSelector(host.adapters);
  const selections = [];
  for (let index = 0; index < ASSET_PERMISSION_SELECTION_LIMITS.maxOutstandingSelections; index += 1) {
    selections.push(await selector.select({ request, candidates: [] }));
  }
  await assert.rejects(selector.select({ request, candidates: [] }), { code: 'LIMIT_EXCEEDED' });
  await selector.handoff(selections[0].handle, request);
  const next = await selector.select({ request, candidates: [] });
  assert.ok(next.handle);
  assertSelectorOperationResourcesClean();
});

test('concurrent handoff is one-use and releases retained state once', async () => {
  const candidate = makeCandidate().candidate;
  const host = createHost();
  const selector = instrumentedSelector(host.adapters);
  const selected = await selector.select({ request, candidates: [candidate] });
  const { map, state } = instrumentedStateFor(selected.handle);
  const outcomes = await Promise.allSettled([
    selector.handoff(selected.handle, request),
    selector.handoff(selected.handle, request),
  ]);
  assert.deepEqual(outcomes.map((outcome) => outcome.status).sort(), ['fulfilled', 'rejected']);
  assert.equal(outcomes.find((outcome) => outcome.status === 'rejected').reason.code, 'INVALID_SELECTION');
  assert.equal(host.state.published.length, 1);
  assertSelectorStateReleased(map, selected.handle, state);
  assertSelectorOperationResourcesClean();
});
