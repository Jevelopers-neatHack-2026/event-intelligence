import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { createPrivacyBoundary } from '../../src/privacy/boundary.mjs';
import { createReviewedSourceContext, REVIEWED_SOURCE_CONTEXT_SCHEMA } from '../../src/privacy/reviewed-source-context.mjs';

// Independent synthetic source, keys and host authority; actual native Promise,
// SQLite and strict process handling. No rejection/exception handler is installed.
const [mode, directory] = process.argv.slice(2);
assert.ok(['fulfilled-with-late-then', 'rejected-native', 'allow'].includes(mode));
assert.equal(typeof directory, 'string');
assert.ok(process.execArgv.includes('--unhandled-rejections=strict'));
const source = 'Harbor Lights. The event is postponed; new date pending.';
const epoch = Date.parse('2026-10-12T12:00:00.000Z');
const request = Object.freeze({ principal: Object.freeze({ tenantId: 'synthetic-tenant' }) });
const boundary = createPrivacyBoundary({
  resolveTenant: (value) => value.principal.tenantId,
  now: () => epoch,
  retentionMs: 60_000,
  reviewPublicFacts: (input) => ({
    status: 'approved', tenantId: input.tenantId, sourceDigest: input.sourceDigest,
    facts: { event_name: 'Harbor Lights', event_date: '2027-06-20', venue: 'Civic Hall' },
  }),
});
const scope = boundary.scopeForAuthenticatedRequest(request);
const started = boundary.begin(scope, { modality: 'plain_text', content: source });
await boundary.prepare(scope, started.session);
const derivative = boundary.publish(scope, started.session);
const retention = Object.freeze(Object.create(null));
const privateAuthority = ({ tenantId, request: current }) => current === request
  && tenantId === request.principal.tenantId;
let allowRecovery = false;
let getterCalls = 0;
let reviewerCalls = 0;
const adapter = createReviewedSourceContext({
  boundary,
  purpose: 'synthetic-strict-authority-observer/1',
  evidenceStoreOptions: {
    directory,
    resolveTenant: (value) => value.principal.tenantId,
    resolveKey: ({ tenantId, purpose }) => ({ keyId: `${purpose}-synthetic-v1`,
      key: createHash('sha256').update(`${tenantId}:${purpose}:synthetic-key`).digest() }),
    resolveRetention: ({ tenantId, retentionHandle }) => {
      assert.equal(retentionHandle, retention);
      assert.equal(tenantId, request.principal.tenantId);
      return { expiresAtMs: epoch + 60_000, policyId: 'synthetic-strict-observer',
        policyVersion: '1', accessPolicy: 'tenant_private' };
    },
    authorizePrivateAccess: privateAuthority,
    authorizePrivateAccessCurrent: privateAuthority,
    now: () => epoch,
  },
  authorizeContextCurrent: (input) => {
    assert.ok(privateAuthority(input));
    if (allowRecovery || mode === 'allow') return true;
    if (mode === 'rejected-native') return Promise.reject(new Error('SYNTHETIC_AUTHORITY_REJECTION'));
    const payload = {};
    // Fulfill first, while this ordinary object is not a thenable. Forwarding
    // that settled value later must not inspect a subsequently installed getter.
    const fulfilled = Promise.resolve(payload);
    Object.defineProperty(payload, 'then', { get() {
      getterCalls += 1;
      throw new Error('SYNTHETIC_FULFILLED_AUTHORITY_THEN_GETTER');
    } });
    return fulfilled;
  },
  reviewContext: (input) => {
    reviewerCalls += 1;
    assert.equal(input.readSourceText(), source);
    return { status: 'approved', schema: input.schema, purpose: input.purpose,
      tenantId: input.tenantId, recordId: input.recordId, sourceDigest: input.sourceDigest,
      evidenceId: input.evidenceId, sourceUrl: input.source.sourceUrl,
      reviewVersion: 'synthetic-strict-review/1', completeForPurpose: true,
      criticalNoticesReviewed: true, ranges: [{ startByte: 0, endByte: Buffer.byteLength(source) }] };
  },
});
const evidenceScope = await adapter.evidenceStore.scopeForAuthenticatedRequest(request);
const stored = await adapter.evidenceStore.ingestEvidence(evidenceScope, {
  sourceUrl: 'https://context.example.test/strict-observer', content: source,
  contentType: 'text/plain; charset=utf-8', retrievedAt: new Date(epoch - 1_000).toISOString(),
  sourceKind: 'external', retentionHandle: retention,
  positions: [{ locator: { kind: 'text-range', startByte: 0, endByte: Buffer.byteLength(source) }, content: source }],
});
const input = () => ({ scope, derivative, evidence: stored.evidence, request });
let firstOutcome;
if (mode === 'allow') {
  assert.ok(await adapter.review(input()));
  firstOutcome = 'approved';
} else {
  await assert.rejects(adapter.review(input()), { name: 'ReviewedSourceContextError', code: 'AUTHORITY_DENIED' });
  firstOutcome = 'AUTHORITY_DENIED';
}
const reviewerCallsBeforeRecovery = reviewerCalls;
process.stdout.write(`STRICT_AUTHORITY_REFUSAL=${firstOutcome}\n`);
await nextTurn();
await nextTurn();
assert.equal(getterCalls, 0);
assert.equal(reviewerCallsBeforeRecovery, mode === 'allow' ? 1 : 0);
allowRecovery = true;
const recovered = await adapter.review(input());
const value = await adapter.materialize({ scope, context: recovered, request });
assert.equal(value.schema, REVIEWED_SOURCE_CONTEXT_SCHEMA);
assert.equal(value.segments[0].text, source);
assert.ok(value.criticalNotices.some((notice) => notice.text.includes('postponed')));
assert.equal(value.canonicalAdoption, false);
assert.equal(value.dispatchStatus, 'not_dispatched');
assert.equal(getterCalls, 0);
process.stdout.write(`STRICT_AUTHORITY_PROBE_JSON=${JSON.stringify({
  mode, firstOutcome, getterCalls, reviewerCallsBeforeRecovery,
  completedNativeTurns: true, recovered: true, providerActivity: 'none',
  fixtureOrigin: 'synthetic source, keys and host authority',
})}\n`);
