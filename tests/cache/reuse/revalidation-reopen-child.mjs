import { createHash } from 'node:crypto';
import { createScopedReuseStore } from '../../../src/cache/reuse/store.mjs';
import { createPrivateCacheRevalidation } from '../../../src/cache/reuse/revalidation.mjs';
import { SafeFetcher } from '../../../src/security/controlled-fetch.mjs';
import { createTestSeam } from '../../../src/security/internal/test-seams.mjs';

// Separate-process recovery of a synthetic admission; all network work is denied.
const [directory, profileRef, admissionRef] = process.argv.slice(2);
const request = { principal: { tenantId: 'synthetic-tenant', actorId: 'synthetic-actor' } };
let attemptedNetwork = 0;
let retainedSourceCalls = 0;
const store = createScopedReuseStore({
  directory,
  resolveTenant: (r) => r?.principal?.tenantId,
  resolveActor: (r) => r?.principal?.actorId,
  authorizeAction: () => true,
  authorizeCurrentRequest: ({ expectedTenantId, expectedActorId, request: r }) => r?.principal?.tenantId === expectedTenantId && r?.principal?.actorId === expectedActorId,
  authorizeBoundary: (input) => ({ authorized: true, tenantId: input.tenantId, actorId: input.actorId,
    eventId: input.eventId, action: input.action, field: input.field, nowMs: Date.now() }),
  resolveKey: ({ tenantId, scope, purpose, keyId }) => {
    const selected = keyId ?? `${scope}:${purpose}:1`;
    return { keyId: selected, key: createHash('sha256').update(`${tenantId}:${selected}:synthetic-cache-key`).digest() };
  },
  resolveRetention: () => { throw new Error('Recovery cannot re-admit'); },
});
const scope = await store.scopeForAuthenticatedRequest(request);
const coordinator = createPrivateCacheRevalidation({ store,
  safeFetcher: new SafeFetcher(createTestSeam({ validateUrl() { attemptedNetwork += 1; throw new Error('Network denied'); } })),
  readRetainedSource() { retainedSourceCalls += 1; throw new Error('Recovery must read the persisted admission result'); },
});
const result = await coordinator.refresh(scope, request, { profileRef, scopeKind: 'tenant_private', admissionRef });
process.stdout.write(`${JSON.stringify({ result, attemptedNetwork, retainedSourceCalls })}\n`);
