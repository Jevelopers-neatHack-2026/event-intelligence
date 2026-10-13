import { createHash } from 'node:crypto';
import { createScopedReuseStore } from '../../../src/cache/reuse/store.mjs';
import { createReviewedPublicCacheRevalidation } from '../../../src/cache/reuse/public-revalidation.mjs';
import { SafeFetcher } from '../../../src/security/controlled-fetch.mjs';
import { createTestSeam } from '../../../src/security/internal/test-seams.mjs';

// A genuinely separate process reopens the durable synthetic admission. It has
// no original-source authority or allowed network and cannot silently readmit.
const [directory, profileRef, admissionRef] = process.argv.slice(2);
const request = { principal: { tenantId: 'synthetic-tenant', actorId: 'synthetic-actor' } };
let attemptedNetwork = 0;
let retainedSourceCalls = 0;
const store = createScopedReuseStore({ directory,
  resolveTenant: (r) => r?.principal?.tenantId,
  resolveActor: (r) => r?.principal?.actorId,
  authorizeAction: ({ action, details }) => action !== 'freshness.observe' || details?.scopeKind === 'public_profile',
  authorizeCurrentRequest: ({ expectedTenantId, expectedActorId, request: r }) =>
    r?.principal?.tenantId === expectedTenantId && r?.principal?.actorId === expectedActorId,
  authorizeBoundary: (input) => input.details?.scopeKind === 'public_profile'
    ? { authorized: true, tenantId: input.tenantId, actorId: input.actorId, eventId: input.eventId,
      action: input.action, field: input.field, nowMs: Date.now() } : false,
  resolveKey: ({ tenantId, scope, purpose, keyId }) => {
    const selected = keyId ?? `${scope}:${purpose}:1`;
    return { keyId: selected, key: createHash('sha256').update(`${tenantId}:${selected}:synthetic-cache-key`).digest() };
  },
  resolveRetention: () => { throw new Error('A historical replay cannot readmit'); },
});
const scope = await store.scopeForAuthenticatedRequest(request);
const coordinator = createReviewedPublicCacheRevalidation({ store,
  safeFetcher: new SafeFetcher(createTestSeam({ validateUrl() { attemptedNetwork += 1; throw new Error('Network denied'); } })),
  readRetainedPublicSource() { retainedSourceCalls += 1; throw new Error('Replay must use the durable admission'); },
});
const result = await coordinator.refresh(scope, request, { scopeKind: 'public_profile', profileRef, admissionRef });
process.stdout.write(`${JSON.stringify({ result, attemptedNetwork, retainedSourceCalls })}\n`);
