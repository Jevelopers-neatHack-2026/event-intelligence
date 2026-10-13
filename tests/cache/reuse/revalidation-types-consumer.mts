import { createPrivateCacheRevalidation, type RefreshSourceBinding, type PrivateRefreshResult } from '../../../src/cache/reuse/revalidation.mjs';
import type { ReuseStore, ScopedReuseScope } from '../../../src/cache/reuse/store.mjs';
import type { SafeFetcher, RetrievedDocument } from '../../../src/security/index.mjs';

declare const store: ReuseStore;
declare const scope: ScopedReuseScope;
declare const safeFetcher: SafeFetcher;
declare const document: RetrievedDocument;
declare const bytes: Uint8Array;

const coordinator = createPrivateCacheRevalidation({ store, safeFetcher,
  readRetainedSource: ({ binding, signal, phase }) => {
    const exact: RefreshSourceBinding = binding;
    const supportedPhase: 'bind' | 'prepare' | 'dispatch' | 'commit' = phase;
    const aborted: boolean = signal.aborted;
    void supportedPhase; void aborted;
    return { binding: exact, representation: 'full_original_response', bytes, validUntilMs: binding.expiresAtMs };
  },
});
await coordinator.bindSource(scope, {}, { profileRef: 'profile', scopeKind: 'tenant_private', sourceRef: 'source', evidenceId: 'evidence', evidenceVersion: 1, document });
const result: PrivateRefreshResult = await coordinator.refresh(scope, {}, { profileRef: 'profile', scopeKind: 'tenant_private', admissionRef: 'admission' });
const usage: 'unknown' = result.usage;
const hold: 'finance_reconciliation_required' = result.holdDisposition;
void usage; void hold;
if (result.status === 'completed') {
  const status: 'not_modified' | 'body_changed' | 'removed' | 'outage' = result.receipt.observationStatus;
  void status;
} else {
  // @ts-expect-error An unresolved transport has no authenticated local completion receipt.
  result.receipt.observationRef;
}
// @ts-expect-error The private-profile coordinator cannot substitute for the separate reviewed-public source/authority binding.
await coordinator.refresh(scope, {}, { profileRef: 'profile', scopeKind: 'public_profile', admissionRef: 'admission' });
// @ts-expect-error A caller cannot supply an observation to bypass native transport provenance.
await coordinator.refresh(scope, {}, { profileRef: 'profile', scopeKind: 'tenant_private', admissionRef: 'admission', observation: { status: 'not_modified' } });
// @ts-expect-error Retained evidence resolution is required; no authority-free fallback exists.
createPrivateCacheRevalidation({ store, safeFetcher });
// @ts-expect-error Local HTTP completion does not establish financial settlement.
const settled: 'completed' = result.usage;
void settled;
