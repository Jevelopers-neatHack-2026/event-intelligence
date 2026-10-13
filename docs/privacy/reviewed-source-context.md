# Private reviewed source context

Refs [EI-09 #9](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/9).
This is an internal, opt-in composition for a trusted host. It supplies a private
source-context review path alongside the existing three-field public derivative.
It is not an elected research contract, a public API, a model authorization, or a
consumer acceptance record.

## Why this component exists

`PrivacyBoundary.publish` deletes its retained original after committing the
reviewed public facts. `exportDerivative` returns only the record ID, modality,
trust tag, and allowlisted event name, date and venue. Those facts cannot serve as
complete source context for a later factuality or privacy review. A caller-supplied
replacement document or matching hash would not establish permission to use it.

The boundary now retains a separate, private association between its genuine
derivative and the reviewed source digest. The association keeps the original
retention deadline and supports irreversible revocation. It carries no raw source
and does not change `exportDerivative` or existing cache, telemetry, decision and
creative serialization. Its internal accessor requires the genuine boundary,
tenant scope and derivative. The digest identifies the reviewed bytes; it grants
no source access.

The adjacent `createReviewedSourceContext` adapter constructs the actual
`EvidenceStore` with trusted storage, key, retention and authorization options.
It owns the store's private-payload consumer. An unforgeable per-operation request
capability connects that consumer to the active review. Neither a request-supplied
store implementation nor a caller-supplied payload callback is accepted. Ordinary
direct `withPrivatePayload` calls on this store refuse; the bridge is private to
the adapter. Other store methods keep their existing authorization behavior.

## Review and materialization

The host supplies a genuine derivative, a genuine retained-evidence handle, its
boundary tenant scope, and the current authenticated request. The adapter then:

1. Reopens the encrypted evidence through the concrete store. Store scope, keys,
   current private access, persisted state and retention are checked by the
   existing store implementation.
2. Requires the store's tenant and complete-source digest to match the genuine
   derivative association. The retained representation must reconstruct the
   entire source from contiguous exact `text-range` positions. Each position hash
   and the reconstructed complete-source hash must match. A few field excerpts,
   gaps, overlaps, a different source or a derived representation refuse.
3. Runs the existing deterministic extractor on those exact retained bytes. The
   component makes no network or provider request. Incomplete or unsupported
   extraction and access-restriction signals refuse before the trusted reviewer.
4. Gives an explicitly configured trusted reviewer a temporary private read
   capability and the detected status notices. The reviewer must approve a named
   purpose, the exact tenant, derivative record, evidence record, source URL and
   source digest, with an explicit review-policy version and coverage assertions.
5. Accepts only sorted, nonoverlapping byte ranges from the approved decision.
   Output strings are decoded from those exact retained ranges. Replacement text,
   malformed UTF-8 boundaries, extra decision fields and incomplete coverage
   assertions refuse.
6. Reopens the actual retained source after the reviewer finishes. Changed keys,
   permissions, source identity, retention or revocation prevent issuance. A
   successful review returns an opaque process-local context capability.

`materialize` reopens the retained source and checks current context authority
again on every call. It returns an immutable private snapshot containing the
approved exact source segments, their byte ranges, the preserved status notices
and source provenance. It carries `visibility: tenant_private`,
`trust: untrusted_external`, `canonicalAdoption: false` and
`dispatchStatus: not_dispatched`. Source content remains untrusted evidence; it
does not become system instructions, tool policy or permission.

The context capability serializes as an empty object. A copied, JSON-round-tripped,
prototype-derived, cross-adapter or cross-tenant handle cannot reopen it. Already
returned private snapshots are ordinary authorized in-memory results, not ongoing
access capabilities. They must stay in the host's private flow; this component
does not retract copies a trusted consumer has already received.

## Critical notices and privacy

The existing extractor supplies visible/plain-text status mentions and structured
`eventStatus` candidates. Each detected source range must be contained in an
explicitly reviewed context range. Omission returns `CRITICAL_NOTICE_OMITTED`.
The adapter does not silently append unreviewed text or drop a cancellation,
postponement, rescheduling or date-change notice to fit a smaller context.

The detection vocabulary and source ranges are those of the pinned local
extractor; they are not a universal language or semantic-coverage guarantee. The
trusted reviewer must also assert that the context is complete for the configured
purpose and that critical notices were reviewed. A missing reviewer fails closed.
If a notice's exact source range also contains private material that cannot be
included, the reviewer must reject it. Plain-text status observations may cover
the entire document, so a mixed private/public document can legitimately refuse
this conservative path.

The private reviewer can inspect raw retained text only while its operation,
source association and current host authorization remain valid. Review-approved
segments are never added to the public derivative or automatically serialized
through the existing privacy flows. Synthetic tests check that legitimate event
facts and a postponement notice remain usable while an unapproved private canary
and instruction text are absent from the materialized context and public flows.
That is local fixture evidence, not a live privacy audit or downstream prompt
acceptance.

## Current authority and lifetime

Three independent conditions are required: the genuine boundary association,
the store's own current evidence access, and the host's synchronous
`authorizeContextCurrent` callback for the exact action, purpose, tenant, derivative
and evidence record. That callback must re-derive current authenticated identity
and the current ACL. Returning a caller permission flag, a source's approval
claim, a Promise or a thenable does not satisfy its contract. No default allow
implementation exists.

The association expires at the original privacy-source deadline. Reopening the
store or reviewing again does not extend that deadline. Context materialization
also respects the earliest observed evidence expiry. The adapter exposes
`revoke(scope, context)` for a context and the boundary exposes
`revokeSourceAssociation(scope, derivative)` for every context linked to that
derivative. Both commit their terminal state before notifying abort listeners.
Revoking this private association does not rewrite the existing public facts.

Cancellation, original deadline exhaustion, revocation and current-authority
changes are checked before and after trusted work and again after asynchronous
review and store access. Reentrant operations on one adapter receive typed
`BUSY`; revocation remains available during an operation. Pending native Promise
rejections are observed before cancellation can leave them detached. Late private
read capabilities refuse, and a completed/canceled attempt releases the adapter
for a new operation.

An invalid ordinary native Promise returned by synchronous current authorization
has both its fulfillment and rejection discarded before refusal. The observer
does not forward a fulfilled value or inspect a later `then` getter on that value.
Strict native child regressions cover both invalid Promise outcomes, a normal
boolean authorization and subsequent review/materialization recovery, without
installing rejection or exception handlers. Custom Promise constructors/species
and replaced runtime intrinsics remain outside the trusted callback contract;
host adapters must handle those results before returning a synchronous boolean.

The configured clocks, key manager and authority callbacks remain trusted host
code. The elapsed deadline does not preempt synchronous JavaScript or an external
host callback. Captured byte buffers are cleared on operation cleanup; JavaScript
strings and already authorized copies cannot be reliably zeroized. Contexts,
derivatives and revocation state are process-local. Restarted use requires fresh
host scope and review; encrypted evidence can be reopened through the store's
existing durable path. No new durable context schema or cross-process revocation
claim is introduced.

## Supported representations and bounds

| Input or operation | Bound or behavior |
| --- | --- |
| Source MIME | UTF-8 HTML, XHTML, JSON-LD or plain text supported by the existing extractor |
| Source provenance | Exact raw retained representation; derived PDF, asset excerpts and controlled image representations refuse |
| Original modality | Existing text modalities only; this adapter performs no OCR, image inspection or PDF reading |
| Retained source | At most 512 KiB, reconstructed from at most 128 contiguous text-range positions |
| Store limits | Existing independent limits still apply, including 64 KiB per materialized position and 512 KiB total position bytes |
| Approved output | At most 32 nonoverlapping ranges and 16 KiB total source bytes |
| Detected notices | At most 64 visible/plain-text and structured status observations |
| Elapsed operation | Configurable 1–12,000 ms from the original start; default 12,000 ms |
| Concurrent operations | One active review or materialization per adapter; another receives `BUSY` |

The oversized-source test deliberately proves an **upstream EvidenceStore
refusal** before this adapter's consumer runs. Separate incomplete-representation
tests exercise the reachable adapter-owned refusal path. Neither result is an
accepted media-reader or full support-matrix claim.

## Trusted host composition

The configuration values below are app-owned ports, not inferred grants:

```js
const contexts = createReviewedSourceContext({
  boundary: privacyBoundary,
  evidenceStoreOptions: trustedEvidenceOptions,
  purpose: trustedReviewPurpose,
  reviewContext: trustedPrivateContextReviewer,
  authorizeContextCurrent: trustedCurrentContextAuthority,
});

const storeScope = await contexts.evidenceStore.scopeForAuthenticatedRequest(request);
const evidence = await contexts.evidenceStore.lookupEvidence(storeScope, retainedEvidenceId);
const context = await contexts.review({
  scope: privacyScope, derivative, evidence, request, signal,
});
const privateContext = await contexts.materialize({
  scope: privacyScope, context, request, signal,
});
```

The host must select the actual purpose and review policy and supply current
identity, keys, retention and permissions. This private interface is a local
proposal for composition; it does not select a shared-contracts mapping or
establish an agent-harness, Product or Creative consumer acknowledgment. The
existing question composer and provider/Finance routes are unchanged. A later
consumer must explicitly integrate and validate this context before any model
handoff. This work contributes local mechanisms to EI-09 AC3–AC5; the broader
accepted journey, adversarial consumer checks and accountable acceptance remain
separate outcomes.

## Verification

Use Node 22.23.3 and the locked dependencies/host TypeScript compiler:

```sh
node tools/verify-reviewed-source-context.mjs
make verify CASE=content-privacy MODE=mock
./node_modules/.bin/tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM --types node --skipLibCheck false tests/reviewed-source-context/types-consumer.mts
npm run typecheck
```

The dedicated workflow runs these checks without changing the shared verifier's
case inventory. Its verifier fails on any failed, canceled, skipped, TODO or
uncompleted test. Tests execute the actual adapter, parser, privacy boundary and
native SQLite store with independently synthetic source content, encryption keys,
tenant requests and reviewer decisions. They make no provider calls. No live
review policy, provider result, consumer ACK or issue closure follows from a
passing mock check. PR evidence records exact revisions, commands and outcomes,
including retained failed runs.
