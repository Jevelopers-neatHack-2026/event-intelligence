import {
  createDiscoveryFrontierStore,
  type FrontierSnapshot,
  type FrontierTenantProgress,
} from '../../../src/discovery/planner/frontier.mjs';

const store = createDiscoveryFrontierStore({
  directory: '/tmp/private-frontier',
  resolveTenant: (request: { readonly tenant: string }) => request.tenant,
  tenantLimits: { maxInFlightLeases: 4, maxReservedDecodedBytes: 100 * 1024 * 1024 },
});

async function consumer(request: { readonly tenant: string }): Promise<FrontierSnapshot> {
  const scope = await store.scopeForAuthenticatedRequest(request);
  const tenantProgress: FrontierTenantProgress = await store.getTenantProgress(scope);
  const outstanding: number = tenantProgress.reservedBytes;
  // @ts-expect-error tenant policy fields accept numeric bounds, not caller labels
  const forgedLimit: import('../../../src/discovery/planner/frontier.mjs').FrontierTenantLimits = { maxInFlightLeases: 'trusted' };
  // @ts-expect-error the tenant progress reader requires an issuer-backed scope
  void store.getTenantProgress({ tenant: request.tenant });
  void outstanding;
  void forgedLimit;
  const snapshot = await store.createRun(scope, {
    runId: 'typed-run',
    seeds: [{ url: 'https://events.example.com/seed' }],
    limits: { maxDepth: 1, maxTransportAttemptAdmissions: 4, maxInFlightLeases: 2 },
  });
  const remainsUnknown: 'not_evaluated' = snapshot.sourceAuthority;
  // @ts-expect-error the private frontier does not declare a URL authoritative
  const official: boolean = snapshot.sourceAuthority;
  void remainsUnknown;
  void official;
  return snapshot;
}

void consumer;
