import { createPrivacyBoundary } from '../../src/privacy/boundary.mjs';
import { createReviewedSourceContext, REVIEWED_SOURCE_CONTEXT_SCHEMA,
  type ReviewedSourceContextOptions, type ReviewedSourceContextHandle,
  type SourceContextReviewDecision } from '../../src/privacy/reviewed-source-context.mjs';
import type { EvidenceHandle } from '../../src/evidence/store.mjs';

// Compile-only synthetic composition. This consumer is never executed.
type AuthenticatedRequest = { principal: { tenantId: string }; allowPrivate: boolean };
declare const request: AuthenticatedRequest;
declare const evidence: EvidenceHandle;
const boundary = createPrivacyBoundary<AuthenticatedRequest>({ resolveTenant: (request) => request.principal.tenantId });
const options: ReviewedSourceContextOptions<AuthenticatedRequest> = {
  boundary,
  purpose: 'compile-only-context/1',
  evidenceStoreOptions: {
    directory: '/compile-only-fixture',
    resolveTenant: (request) => request.principal.tenantId,
    resolveKey: () => ({ keyId: 'compile-only-key', key: new Uint8Array(32) }),
    resolveRetention: ({ nowMs }) => ({ expiresAtMs: nowMs + 1_000, policyId: 'compile-fixture', policyVersion: '1', accessPolicy: 'tenant_private' }),
    authorizePrivateAccess: ({ tenantId, request }) => request.principal.tenantId === tenantId && request.allowPrivate,
    authorizePrivateAccessCurrent: ({ tenantId, request }) => request.principal.tenantId === tenantId && request.allowPrivate,
  },
  authorizeContextCurrent: ({ tenantId, request }) => request.principal.tenantId === tenantId && request.allowPrivate,
  reviewContext(input): SourceContextReviewDecision {
    const sourceText: string = input.readSourceText();
    const signal: AbortSignal = input.signal;
    void signal;
    return {
      status: 'approved', schema: input.schema, purpose: input.purpose,
      tenantId: input.tenantId, recordId: input.recordId, sourceDigest: input.sourceDigest,
      evidenceId: input.evidenceId, sourceUrl: input.source.sourceUrl,
      reviewVersion: 'compile-only-review/1', completeForPurpose: true, criticalNoticesReviewed: true,
      ranges: [{ startByte: 0, endByte: Buffer.byteLength(sourceText) }],
    };
  },
};
const adapter = createReviewedSourceContext(options);
const scope = boundary.scopeForAuthenticatedRequest(request);
const started = boundary.begin(scope, { modality: 'plain_text', content: 'Compile fixture' });
const derivative = boundary.publish(scope, started.session);
const context: ReviewedSourceContextHandle = await adapter.review({ scope, derivative, evidence, request });
const value = await adapter.materialize({ scope, context, request });
const privateOnly: 'tenant_private' = value.visibility;
const notDispatched: 'not_dispatched' = value.dispatchStatus;
const notAdopted: false = value.canonicalAdoption;
const schema: typeof REVIEWED_SOURCE_CONTEXT_SCHEMA = value.schema;
void [privateOnly, notDispatched, notAdopted, schema];
adapter.revoke(scope, context);
boundary.revokeSourceAssociation(scope, derivative);

// @ts-expect-error serialized objects cannot manufacture context capabilities
adapter.materialize({ scope, context: {}, request });
// @ts-expect-error derivative must be issued by the real boundary
adapter.review({ scope, derivative: {}, evidence, request });
// @ts-expect-error complete source replacement text is not request input
adapter.review({ scope, derivative, evidence, request, text: 'replacement' });
// @ts-expect-error the configured authenticated request cannot be replaced by a browser tenant field
adapter.materialize({ scope, context, request: { tenantId: 'browser' } });
// @ts-expect-error materialized context is immutable
value.segments[0]!.text = 'replacement';
// @ts-expect-error public release/canonical adoption is not supplied by this adapter
const publicGrant: true = value.canonicalAdoption;
void publicGrant;
const invalidAuthority: ReviewedSourceContextOptions<AuthenticatedRequest> = {
  ...options,
  // @ts-expect-error current authorization must be synchronous; promises are not grants
  authorizeContextCurrent: async () => true,
};
void invalidAuthority;
const invalidStore: ReviewedSourceContextOptions<AuthenticatedRequest> = {
  ...options,
  evidenceStoreOptions: {
    ...options.evidenceStoreOptions,
    // @ts-expect-error the private payload bridge belongs to this concrete adapter
    consumePrivatePayload: () => 'caller source replacement',
  },
};
void invalidStore;
