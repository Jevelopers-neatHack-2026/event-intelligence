import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { performance } from 'node:perf_hooks';
import { SafeFetcher } from '../../../src/security/controlled-fetch.mjs';
import { runWithSafeFetchLifecycle } from '../../../src/security/internal/fetch-lifecycle.mjs';
import { revalidationFixture } from './revalidation-support.mjs';
import { createCertificate, fixtureUrl, localTestSeam, respond, startFixture } from '../../security/support.mjs';

// These controls use actual local HTTP/cache/evidence paths and synthetic host
// authority. The native entry guards below prevent a late socket/TLS attempt;
// no remote DNS, provider request or production approval is involved.
const sleeper = new Int32Array(new SharedArrayBuffer(4));
function holdEventLoopUntil(deadline) {
  while (performance.now() < deadline) {
    Atomics.wait(sleeper, 0, 0, Math.max(1, deadline - performance.now()));
  }
}

test('refresh transport keeps the original deadline after retained source preparation', async (t) => {
  const env = await revalidationFixture(t);
  await env.bind();
  const admission = await env.admit();
  let resolverDeadline;
  let preparationHeld = false;
  const preparationTimes = {};
  const fetcher = new SafeFetcher(localTestSeam({
    port: Number(new URL(env.sourceUrl).port),
    resolveOverride(_hostname, options) {
      resolverDeadline = options.deadline;
      return { addresses: ['127.0.0.1'], aliases: [] };
    },
  }));
  // This success control checks propagation of the original deadline, not a
  // one-second performance promise from a shared CI runner. The deliberately
  // expired native-boundary controls below retain their shorter exact budgets.
  const timeoutMs = 5_000;
  const coordinator = env.makeCoordinator({
    safeFetcher: fetcher,
    timeoutMs,
    async readRetainedSource(input) {
      if (input.phase === 'prepare') {
        preparationHeld = true;
        preparationTimes.started = performance.now();
        await new Promise((resolve) => setTimeout(resolve, 200));
        preparationTimes.finished = performance.now();
      }
      return env.readRetainedSource(input);
    },
  });
  const startedBefore = performance.now();
  const pending = coordinator.refresh(env.scope, env.authRequest, {
    profileRef: env.profile.profileRef, scopeKind: 'tenant_private', admissionRef: admission.admissionRef,
  });
  const startedAfter = performance.now();
  let result;
  let outcome = 'pending';
  try {
    result = await pending;
    outcome = result.status;
  } catch (error) {
    outcome = error.code ?? error.name;
    throw error;
  } finally {
    t.diagnostic(JSON.stringify({ startedBefore, startedAfter, finishedAt: performance.now(),
      timeoutMs, preparationTimes, resolverDeadline: resolverDeadline ?? null, outcome }));
  }
  assert.equal(preparationHeld, true);
  assert.equal(result.status, 'completed');
  assert.equal(result.receipt.responseKind, 'not_modified');
  assert.ok(Number.isFinite(resolverDeadline));
  assert.ok(resolverDeadline >= startedBefore + timeoutMs,
    'transport must retain the original budget rather than substitute an earlier deadline');
  assert.ok(resolverDeadline <= startedAfter + timeoutMs,
    'retained-source preparation must consume the same absolute transport budget');
  assert.equal(env.state.requests.length, 2);
  assert.equal(env.snapshot().observations.length, 2);
  assert.equal(env.snapshot().profile.retrievedAtMs, Date.parse(env.document.fetchedAt));
  assert.equal(env.snapshot().flights[0].usage, 'unknown');
  assert.equal(env.state.financeCalls, 0);
});

for (const stop of ['deadline', 'cancellation']) {
  test(`the final native socket boundary observes ${stop} before abort timer delivery`, async (t) => {
    let received = 0;
    const server = await startFixture((_request, response) => {
      received += 1;
      respond(response, 200, { 'content-type': 'text/plain' }, 'unexpected late request');
    });
    t.after(() => server.close());
    const controller = new AbortController();
    const fetcher = new SafeFetcher(localTestSeam({ port: server.port }));
    const originalAddRequest = http.Agent.prototype.addRequest;
    const originalConnect = net.connect;
    const timeoutMs = 500;
    let guardReached = false;
    let lateNativeEntries = 0;
    let signalAbortedAfterHold;
    let started;
    http.Agent.prototype.addRequest = function (...args) {
      guardReached = true;
      assert.ok(performance.now() < started + timeoutMs, 'native request enters before the controlled stop');
      if (stop === 'deadline') holdEventLoopUntil(started + timeoutMs + 30);
      else controller.abort();
      signalAbortedAfterHold = this.connection.signal.aborted;
      return Reflect.apply(originalAddRequest, this, args);
    };
    net.connect = function () {
      lateNativeEntries += 1;
      throw new Error('test guard refused the late native socket before connection');
    };
    try {
      started = performance.now();
      const result = runWithSafeFetchLifecycle(fetcher, {}, { totalMilliseconds: timeoutMs },
        () => fetcher.fetch(fixtureUrl(server.port), { signal: controller.signal }));
      await assert.rejects(result, { code: stop === 'deadline' ? 'DEADLINE_EXCEEDED' : 'CANCELED' });
    } finally {
      http.Agent.prototype.addRequest = originalAddRequest;
      net.connect = originalConnect;
      t.diagnostic(JSON.stringify({ stop, guardReached, lateNativeEntries, signalAbortedAfterHold, received }));
    }
    assert.equal(guardReached, true);
    assert.equal(signalAbortedAfterHold, stop === 'cancellation', 'deadline timer delivery is deliberately withheld');
    assert.equal(lateNativeEntries, 0);
    assert.equal(received, 0);
  });
}

test('the native TLS boundary preserves the deadline after a connected-peer callback', async (t) => {
  const certificate = await createCertificate();
  t.after(() => certificate.close());
  let received = 0;
  const server = await startFixture((_request, response) => {
    received += 1;
    respond(response, 200, { 'content-type': 'text/plain' }, 'unexpected late TLS request');
  }, { certificate });
  t.after(() => server.close());
  const timeoutMs = 500;
  let started;
  let peerReached = false;
  let lateTlsEntries = 0;
  const fetcher = new SafeFetcher(localTestSeam({
    port: server.port, certificate,
    onDial() {
      peerReached = true;
      assert.ok(performance.now() < started + timeoutMs, 'the controlled TCP connection precedes the deadline');
      holdEventLoopUntil(started + timeoutMs + 30);
    },
  }));
  const originalTlsConnect = tls.connect;
  tls.connect = function () {
    lateTlsEntries += 1;
    throw new Error('test guard refused the late native TLS entry before handshake');
  };
  try {
    started = performance.now();
    await assert.rejects(runWithSafeFetchLifecycle(fetcher, {}, { totalMilliseconds: timeoutMs },
      () => fetcher.fetch(fixtureUrl(server.port, '/', 'fixture.example.test', 'https:'))), { code: 'DEADLINE_EXCEEDED' });
  } finally {
    tls.connect = originalTlsConnect;
    t.diagnostic(JSON.stringify({ peerReached, lateTlsEntries, received }));
  }
  assert.equal(peerReached, true);
  assert.equal(lateTlsEntries, 0);
  assert.equal(received, 0);
});

test('malformed private deadlines cannot invoke accessors, coercion, proxy traps or the operation', () => {
  let untrustedCalls = 0;
  let operations = 0;
  const values = [undefined, null, true, '500', 500n, NaN, Infinity, -Infinity, -1, Number.MAX_SAFE_INTEGER + 1,
    { valueOf() { untrustedCalls += 1; return 500; } }];
  const invalidOptions = values.map((deadlineAtMonotonic) => ({ deadlineAtMonotonic }));
  invalidOptions.push(Object.defineProperty({}, 'deadlineAtMonotonic', {
    enumerable: true, get() { untrustedCalls += 1; return 500; },
  }));
  invalidOptions.push(new Proxy({ deadlineAtMonotonic: 500 }, {
    getPrototypeOf() { untrustedCalls += 1; return Object.prototype; },
    ownKeys() { untrustedCalls += 1; return ['deadlineAtMonotonic']; },
  }));
  invalidOptions.push({ deadlineAtMonotonic: 500, unknownClockDomain: 'wall' });
  for (const options of invalidOptions) {
    assert.throws(() => runWithSafeFetchLifecycle(new SafeFetcher(), {}, options, () => { operations += 1; }), TypeError);
  }
  assert.equal(untrustedCalls, 0);
  assert.equal(operations, 0);
});

for (const mode of ['fetch', 'fetchSvgAsset']) {
  test(`an expired private deadline stops ${mode} before DNS or native transport`, async (t) => {
    let resolutions = 0;
    let received = 0;
    const server = await startFixture((_request, response) => {
      received += 1;
      respond(response, 200, { 'content-type': 'text/plain' }, 'unexpected');
    });
    t.after(() => server.close());
    const fetcher = new SafeFetcher(localTestSeam({ port: server.port, resolveOverride() {
      resolutions += 1;
      return { addresses: ['127.0.0.1'], aliases: [] };
    } }));
    await assert.rejects(runWithSafeFetchLifecycle(fetcher, {}, { deadlineAtMonotonic: 0 },
      () => fetcher[mode](fixtureUrl(server.port))), { code: 'DEADLINE_EXCEEDED' });
    assert.equal(resolutions, 0);
    assert.equal(received, 0);
  });
}

test('public document and SVG options cannot install a private lifecycle deadline', async (t) => {
  let resolutions = 0;
  const server = await startFixture((_request, response) => respond(response, 200, {}, 'unexpected'));
  t.after(() => server.close());
  const fetcher = new SafeFetcher(localTestSeam({ port: server.port, resolveOverride() {
    resolutions += 1;
    return { addresses: ['127.0.0.1'], aliases: [] };
  } }));
  for (const mode of ['fetch', 'fetchSvgAsset']) {
    await assert.rejects(fetcher[mode](fixtureUrl(server.port), { deadlineAtMonotonic: performance.now() + 30_000 }),
      { code: 'POLICY_DENIED' });
  }
  assert.equal(resolutions, 0);
});

test('a later private deadline cannot enlarge the relative transport budget', async (t) => {
  const server = await startFixture((_request, response) => respond(response, 200, {}, 'unexpected'));
  t.after(() => server.close());
  const timeoutMs = 1_000;
  let resolverDeadline;
  let hookReached = false;
  let nativeEntries = 0;
  const fetcher = new SafeFetcher(localTestSeam({ port: server.port, resolveOverride(_host, options) {
    resolverDeadline = options.deadline;
    return { addresses: ['127.0.0.1'], aliases: [] };
  } }));
  const originalRequest = http.request;
  http.request = function () {
    nativeEntries += 1;
    throw new Error('test guard prevented a native request after the shorter relative deadline');
  };
  try {
    const startBefore = performance.now();
    const pending = runWithSafeFetchLifecycle(fetcher, { onDispatchIntent() {
      hookReached = true;
      assert.ok(performance.now() < startBefore + timeoutMs);
      holdEventLoopUntil(startBefore + timeoutMs + 30);
    } }, { totalMilliseconds: timeoutMs, deadlineAtMonotonic: startBefore + 20_000 },
    () => fetcher.fetch(fixtureUrl(server.port)));
    const startAfter = performance.now();
    await assert.rejects(pending, { code: 'DEADLINE_EXCEEDED' });
    assert.ok(resolverDeadline <= startAfter + timeoutMs);
  } finally { http.request = originalRequest; }
  assert.equal(hookReached, true);
  assert.equal(nativeEntries, 0);
});

for (const protocol of ['http:', 'https:']) {
  test(`cancellation after the connected-peer guard prevents ${protocol} socket handoff`, async (t) => {
    const certificate = protocol === 'https:' ? await createCertificate() : undefined;
    if (certificate) t.after(() => certificate.close());
    let received = 0;
    const server = await startFixture((_request, response) => {
      received += 1;
      respond(response, 200, { 'content-type': 'text/plain' }, 'unexpected');
    }, certificate ? { certificate } : {});
    t.after(() => server.close());
    const controller = new AbortController();
    let connectedPeers = 0;
    let tlsEntries = 0;
    const fetcher = new SafeFetcher(localTestSeam({ port: server.port, certificate, onDial() {
      connectedPeers += 1;
      controller.abort();
    } }));
    const originalTlsConnect = tls.connect;
    tls.connect = function () {
      tlsEntries += 1;
      throw new Error('test guard prevented TLS after cancellation');
    };
    try {
      await assert.rejects(fetcher.fetch(fixtureUrl(server.port, '/', 'fixture.example.test', protocol),
        { signal: controller.signal }), { code: 'CANCELED' });
    } finally { tls.connect = originalTlsConnect; }
    assert.equal(connectedPeers, 1, 'the initial permitted local TCP connection precedes cancellation');
    assert.equal(tlsEntries, 0);
    assert.equal(received, 0);
  });
}
