import {
  createReviewedPublicCacheRevalidation,
  type ReviewedPublicSourceMapping,
  type ReviewedPublicSourceBinding,
  type ReviewedPublicRefreshResult,
} from '../../../src/cache/reuse/public-revalidation.mjs';
import type { ReuseStore, ScopedReuseScope } from '../../../src/cache/reuse/store.mjs';
import type { RetrievedDocument, SafeFetcher } from '../../../src/security/index.mjs';
import type { RefreshSourceBinding } from '../../../src/cache/reuse/revalidation.mjs';

declare const store: ReuseStore;
declare const scope: ScopedReuseScope;
declare const safeFetcher: SafeFetcher;
declare const document: RetrievedDocument;
declare const bytes: Uint8Array;
declare const mapping: ReviewedPublicSourceMapping;
declare const sourceAccessRevoked: boolean;

const coordinator = createReviewedPublicCacheRevalidation({ store, safeFetcher,
  readRetainedPublicSource: ({ binding, phase, signal }) => {
    const actual: ReviewedPublicSourceBinding = binding;
    const scopeKind: 'public_profile' = actual.scopeKind;
    const profileDomain: 'scoped-reuse-reviewed-publication-content-key/v1' = actual.profileHashDomain;
    const bodyDomain: 'safe-fetch-decoded-entity-bytes/v1' = actual.bodyHashDomain;
    const operationPhase: 'bind' | 'prepare' | 'dispatch' | 'commit' = phase;
    void scopeKind; void profileDomain; void bodyDomain; void operationPhase; void signal.aborted;
    // @ts-expect-error A public publication key is not the private original-body profile domain.
    const privateBinding: RefreshSourceBinding = actual;
    void privateBinding;
    if (sourceAccessRevoked) return { status: 'source_access_revoked', binding, mapping };
    return { binding, mapping, representation: 'full_original_response', bytes, validUntilMs: binding.expiresAtMs };
  },
});
await coordinator.bindSource(scope, {}, { scopeKind: 'public_profile', profileRef: 'profile',
  sourceRef: 'source', evidenceId: 'evidence', evidenceVersion: 1, document });
const result: ReviewedPublicRefreshResult = await coordinator.refresh(scope, {}, {
  scopeKind: 'public_profile', profileRef: 'profile', admissionRef: 'admission',
});
const usage: 'unknown' = result.usage;
const hold: 'finance_reconciliation_required' = result.holdDisposition;
void usage; void hold;
if (result.status === 'completed') {
  const receipt = result.receipt;
  if (receipt.effectKind === 'observation') {
    const observationRef: string = receipt.observationRef;
    const status: 'not_modified' | 'outage' = receipt.observationStatus;
    void observationRef; void status;
    // @ts-expect-error Observation success does not invent invalidation event references.
    receipt.invalidationEventRefs;
  } else {
    const refs: readonly string[] = receipt.invalidationEventRefs;
    void refs;
    if (receipt.reason === 'source_body_changed') {
      // @ts-expect-error Changed unreviewed bytes have no newly published observation.
      const observationRef: string = receipt.observationRef;
      void observationRef;
    } else {
      const status: 'removed' = receipt.observationStatus;
      void status;
    }
  }
} else {
  // @ts-expect-error Unknown intent cannot assert a joined response/effect receipt.
  result.receipt.responseRef;
}
// @ts-expect-error There is no fallback from public read permission to source/mutation authority.
createReviewedPublicCacheRevalidation({ store, safeFetcher });
// @ts-expect-error Explicit publication-link/evidence mapping is mandatory, even for actual bytes.
createReviewedPublicCacheRevalidation({ store, safeFetcher, readRetainedPublicSource: ({ binding }) => ({ binding, representation: 'full_original_response', bytes, validUntilMs: binding.expiresAtMs }) });
// @ts-expect-error A public refresh cannot become a tenant-private refresh.
await coordinator.refresh(scope, {}, { scopeKind: 'tenant_private', profileRef: 'profile', admissionRef: 'admission' });
// @ts-expect-error A caller cannot inject a source observation or HTTP status to bypass provenance.
await coordinator.refresh(scope, {}, { scopeKind: 'public_profile', profileRef: 'profile', admissionRef: 'admission', observation: { status: 'not_modified' } });
// @ts-expect-error Local response/effect completion never means financial settlement.
const settled: 'completed' = result.usage;
void settled;
