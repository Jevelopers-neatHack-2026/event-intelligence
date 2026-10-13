import assert from 'node:assert/strict';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { harness, respond } from './support.mjs';

const [stage, mode] = process.argv.slice(2);
const stages = new Set(['start', 'candidate', 'release']);
const modes = new Set(['rejected', 'late-rejected', 'fulfilled-true', 'poisoned-fulfillment', 'thenable-getter']);
assert.ok(stages.has(stage) && modes.has(mode));

const cleanup = [];
const h = await harness({ after: (callback) => cleanup.push(callback) }, {
  respond: (_request, response) => respond(response, 200, { 'content-type': 'text/html' },
    '<html><body><p>Synthetic source without identity claims.</p></body></html>'),
});
let calls = 0;
let getterReads = 0;
let rejectLate;
try {
  const result = await h.run(`followup-auth-${stage}-${mode}`, {
    authorizeCurrent: (_request, context) => {
      if (context.stage !== stage) return true;
      calls += 1;
      if (mode === 'rejected') return Promise.reject(new Error('SYNTHETIC_INVALID_AUTHORITY'));
      if (mode === 'late-rejected') return new Promise((_resolve, reject) => { rejectLate = reject; });
      if (mode === 'fulfilled-true') return Promise.resolve(true);
      if (mode === 'poisoned-fulfillment') {
        const fulfilled = {};
        const native = Promise.resolve(fulfilled);
        Object.defineProperty(fulfilled, 'then', { get() {
          getterReads += 1;
          throw new Error('SYNTHETIC_FULFILLED_VALUE_MUST_NOT_BE_ADOPTED');
        } });
        return native;
      }
      return Object.defineProperty({}, 'then', { get() {
        getterReads += 1;
        throw new Error('SYNTHETIC_THENABLE_GETTER_MUST_NOT_RUN');
      } });
    },
  });
  assert.equal(calls, 1, 'the requested synchronous authorization boundary was reached once');
  assert.equal(result.draft, null);
  assert.equal(Object.hasOwn(result, 'sourceAuthorityReview'), false);
  assert.ok(result.limitations.includes(stage === 'start' ? 'authorization_denied' : 'authorization_revoked'),
    JSON.stringify(result));
  assert.equal(h.paths.length, stage === 'release' ? 1 : 0, 'denial does not dispatch another request');
  if (rejectLate) rejectLate(new Error('SYNTHETIC_LATE_INVALID_AUTHORITY'));
  await nextTurn();
  await nextTurn();
  assert.equal(getterReads, 0);

  const recovered = await h.run(`followup-recovered-${stage}-${mode}`);
  assert.equal(recovered.draft, null);
  assert.equal(recovered.sourceAuthorityReview?.authority, 'unknown');
  assert.equal(recovered.sourceAuthorityReview?.execution, 'not_dispatched');
  assert.equal(recovered.sourceAuthorityReview?.questions.length, 1);
  assert.deepEqual(recovered.sourceAuthorityReview.questions[0].evidenceRefs, []);
  assert.equal(h.paths.length, stage === 'release' ? 2 : 1);
  process.stdout.write(`NATIVE_FOLLOWUP_AUTH_JSON=${JSON.stringify({
    stage, mode, calls, getterReads, recovered: true, nativeIntrinsicsAndHandlersUnmodified: true,
    fixture: 'actual local HTTP and SQLite with synthetic source and authority', providerActivity: 'none',
  })}\n`);
} finally {
  for (const callback of cleanup.reverse()) await callback();
}
