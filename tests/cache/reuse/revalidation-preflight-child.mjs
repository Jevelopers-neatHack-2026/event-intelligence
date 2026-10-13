import assert from 'node:assert/strict';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { createRevalidationContext } from '../../../src/cache/reuse/revalidation-context.mjs';
import { revalidationFixture } from './revalidation-support.mjs';

// Native strict rejection handling is intentional. There is no rejection or
// uncaught-exception handler that could turn a process failure into a pass.
const mode = process.argv[2];
assert.ok(process.execArgv.includes('--unhandled-rejections=strict'));

if (mode === 'native-only') {
  let thenReads = 0;
  const thenable = Object.defineProperty({}, 'then', { get() { thenReads += 1; throw new Error('unexpected then read'); } });
  for (const stop of ['cancelled', 'closed']) {
    const controller = new AbortController();
    const context = createRevalidationContext({ signal: controller.signal, timeoutMs: 10_000, readRetainedSource() {} });
    if (stop === 'cancelled') controller.abort();
    else context.close();
    const expected = stop === 'cancelled' ? 'REVALIDATION_CANCELLED' : 'REVALIDATION_DENIED';
    try {
      const rejected = Promise.reject(new Error('synthetic native rejection'));
      Object.defineProperty(rejected, 'then', { get() { thenReads += 1; throw new Error('unexpected Promise then read'); } });
      await assert.rejects(context.wait(rejected), { code: expected });
      await assert.rejects(context.wait(thenable), { code: expected });
    } finally { context.close(); }
  }
  await nextTurn();
  await nextTurn();
  assert.equal(thenReads, 0);
  process.stdout.write(JSON.stringify({ mode, nativeTurnsCompleted: true, thenReads }));
} else {
  assert.ok(['normal', 'abort-deny', 'abort-throw', 'deadline-deny', 'deadline-throw'].includes(mode));
  const cleanup = [];
  try {
    // Real loopback SafeFetcher and encrypted durable stores; principals,
    // permissions and callback faults are synthetic, with no Finance issuer.
    const env = await revalidationFixture({ after(fn) { cleanup.push(fn); } });
    await env.bind();
    const controller = new AbortController();
    const ordinary = env.options.authorizeCurrentRequest;
    let armed = false;
    let callbackEntries = 0;
    await env.reopen({ authorizeCurrentRequest(input) {
      if (armed && input.action === 'freshness.observe' && ++callbackEntries === 1 && mode !== 'normal') {
        if (mode.startsWith('abort-')) controller.abort();
        else {
          // Let the real monotonic deadline expire during this synchronous
          // trusted callback. Clocks, timers, Promises and SQLite are unchanged.
          assert.equal(Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 400), 'timed-out');
        }
        if (mode.endsWith('-throw')) throw new Error('synthetic authorization failure');
        return false;
      }
      return ordinary(input);
    } });
    const admission = await env.admit();
    const before = env.snapshot();
    const requestsBefore = env.state.requests.length;
    const coordinator = env.makeCoordinator({ timeoutMs: mode.startsWith('deadline-') ? 250 : 10_000 });
    const input = { profileRef: env.profile.profileRef, scopeKind: 'tenant_private', admissionRef: admission.admissionRef };
    const result = { mode };
    armed = true;
    if (mode === 'normal') {
      const completed = await coordinator.refresh(env.scope, env.authRequest, input, { signal: controller.signal });
      result.status = completed.status;
      result.httpStatus = completed.receipt.httpStatus;
      assert.equal(env.state.requests.length, requestsBefore + 1);
    } else {
      const errorCode = mode.startsWith('abort-') ? 'REVALIDATION_CANCELLED' : 'REVALIDATION_DEADLINE';
      await assert.rejects(coordinator.refresh(env.scope, env.authRequest, input, { signal: controller.signal }), { code: errorCode });
      result.errorCode = errorCode;
      assert.equal(env.state.requests.length, requestsBefore);
      assert.deepEqual(env.snapshot(), before);
      result.beforeDispatchUnchanged = true;
    }
    await nextTurn();
    await nextTurn();
    result.nativeTurnsCompleted = true;
    if (mode !== 'normal') {
      armed = false;
      await env.reopen();
      assert.deepEqual(env.snapshot(), before);
      result.reopenedStateUnchanged = true;
      const recovered = await env.refresh(admission.admissionRef);
      result.recoveryStatus = recovered.status;
      result.recoveryHttpStatus = recovered.receipt.httpStatus;
      assert.equal(env.state.requests.length, requestsBefore + 1);
      assert.equal(env.snapshot().flights[0].usage, 'unknown');
    }
    result.callbackEntries = callbackEntries;
    result.financeCalls = env.state.financeCalls;
    assert.equal(result.financeCalls, 0);
    process.stdout.write(JSON.stringify(result));
  } finally {
    for (const close of cleanup.reverse()) await close();
  }
}
