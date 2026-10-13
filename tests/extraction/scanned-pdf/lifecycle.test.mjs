import assert from "node:assert/strict";
import crypto from "node:crypto";
import { once } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { performance } from "node:perf_hooks";
import { mock, test } from "node:test";
import { readScannedPdf } from "../../../src/extraction/scanned-pdf/index.mjs";
import { imagePdf, RGBA_2X2 } from "./fixtures.mjs";
import { framed, heldChild, interceptSpawns, protocolChild, validHeader } from "./process-helpers.mjs";

test("pre-aborted input never spawns a native worker", async () => {
  const controller = new AbortController(); controller.abort();
  let spawned = 0;
  const restore = interceptSpawns(() => { spawned += 1; assert.fail("unexpected spawn"); });
  try {
    assert.equal((await readScannedPdf(imagePdf(), { signal: controller.signal })).code, "CANCELLED");
    assert.equal(spawned, 0);
  } finally { restore(); }
});

test("active cancellation waits for actual close and reaping before recovery", async () => {
  const controller = new AbortController();
  let closed = false, child;
  const restore = interceptSpawns((real, command, args, options) => {
    child = real(command, args, options);
    child.once("spawn", () => controller.abort());
    child.once("close", () => { closed = true; });
    return child;
  });
  try {
    const result = await readScannedPdf(imagePdf(), { signal: controller.signal });
    assert.equal(result.code, "CANCELLED");
    assert.equal(closed, true);
    assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
  } finally { restore(); }
  assert.equal((await readScannedPdf(imagePdf())).kind, "decoded");
});

test("queued deadline spends the original allowance and never starts that worker", async () => {
  const firstController = new AbortController();
  let firstChild, calls = 0;
  const restore = interceptSpawns((real, _command, _args, options) => {
    calls += 1;
    firstChild = heldChild(real, options);
    return firstChild;
  });
  let first;
  try {
    first = readScannedPdf(imagePdf(), { signal: firstController.signal, timeoutMs: 5000 });
    await once(firstChild, "spawn");
    const queued = await readScannedPdf(imagePdf(), { timeoutMs: 100 });
    assert.equal(queued.code, "TIMEOUT");
    assert.equal(calls, 1);
  } finally {
    firstController.abort();
    if (first) assert.equal((await first).code, "CANCELLED");
    restore();
  }
  assert.equal((await readScannedPdf(imagePdf())).kind, "decoded");
});

test("queued cancellation removes the request without creating a process", async () => {
  const firstController = new AbortController(), queuedController = new AbortController();
  let firstChild, calls = 0;
  const restore = interceptSpawns((real, _command, _args, options) => {
    calls += 1; firstChild = heldChild(real, options); return firstChild;
  });
  let first;
  try {
    first = readScannedPdf(imagePdf(), { signal: firstController.signal, timeoutMs: 5000 });
    await once(firstChild, "spawn");
    const queued = readScannedPdf(imagePdf(), { signal: queuedController.signal });
    queuedController.abort();
    assert.equal((await queued).code, "CANCELLED");
    assert.equal(calls, 1);
  } finally {
    firstController.abort();
    if (first) await first;
    restore();
  }
});

test("one active and four waiting jobs bound the module-wide queue", async () => {
  const controllers = Array.from({ length: 5 }, () => new AbortController());
  const pending = [];
  let child, calls = 0;
  const restore = interceptSpawns((real, _command, _args, options) => {
    calls += 1; child = heldChild(real, options); return child;
  });
  try {
    pending.push(readScannedPdf(imagePdf(), { signal: controllers[0].signal, timeoutMs: 5000 }));
    await once(child, "spawn");
    for (let index = 1; index < 5; index += 1) pending.push(readScannedPdf(imagePdf(), { signal: controllers[index].signal, timeoutMs: 5000 }));
    assert.equal((await readScannedPdf(imagePdf())).code, "QUEUE_FULL");
    assert.equal(calls, 1);
  } finally {
    for (const controller of controllers.slice(1)) controller.abort();
    controllers[0].abort();
    for (const result of await Promise.all(pending)) assert.equal(result.code, "CANCELLED");
    restore();
  }
  assert.equal((await readScannedPdf(imagePdf())).kind, "decoded");
});

test("active timeout kills the actual process and waits for close", async (t) => {
  const input = imagePdf();
  let closed = false, child, spawnAttempts = 0, spawnAfterMs, closeCode, closeSignal;
  let started;
  const restore = interceptSpawns((real, _command, _args, options) => {
    spawnAttempts += 1;
    spawnAfterMs = performance.now() - started;
    child = heldChild(real, options);
    child.once("close", (code, signal) => { closed = true; closeCode = code; closeSignal = signal; });
    return child;
  });
  const observations = {};
  try {
    // A spent admission allowance must refuse before launch. It cannot prove
    // active-child termination, which needs its own observed launch phase.
    const originalHash = crypto.createHash;
    let delayed = false;
    const delayAdmission = mock.method(crypto, "createHash", (...args) => {
      if (!delayed) {
        delayed = true;
        const until = performance.now() + 200;
        while (performance.now() < until) { /* Synthetic synchronous admission delay. */ }
      }
      return originalHash(...args);
    });
    syncBuiltinESMExports();
    try {
      started = performance.now();
      const result = await readScannedPdf(input, { timeoutMs: 150 });
      observations.admission = { delayed, resultCode: result.code, spawnAttempts };
      assert.equal(delayed, true);
      assert.equal(result.code, "TIMEOUT");
      assert.equal(spawnAttempts, 0);
    } finally { delayAdmission.mock.restore(); syncBuiltinESMExports(); }

    // Retain one original allowance through real kill, close and reaping.
    // Leave enough of it for runtime validation to reach the active phase.
    const timeoutMs = 3000;
    started = performance.now();
    const result = await readScannedPdf(input, { timeoutMs });
    observations.active = {
      timeoutMs, spawnAttempts, spawnAfterMs, elapsedMs: performance.now() - started,
      resultCode: result.code, childPid: child?.pid ?? null, closed, closeCode, closeSignal,
    };
    assert.ok(child?.pid, "the timed request entered an actual child");
    assert.equal(spawnAttempts, 1);
    assert.ok(spawnAfterMs < timeoutMs, "launch occurred before the original deadline");
    assert.equal(result.code, "TIMEOUT");
    assert.equal(closed, true);
    assert.equal(closeCode, null);
    assert.equal(closeSignal, "SIGKILL", "the timeout killed the held child rather than waiting for its natural exit");
    assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
  } finally { restore(); t.diagnostic(JSON.stringify(observations)); }
  assert.equal((await readScannedPdf(imagePdf())).kind, "decoded");
});

test("parent frame hashing cannot renew an already spent deadline", async () => {
  const input = imagePdf(), header = validHeader(input);
  let enteredHash = false, closed = false;
  const restoreSpawn = interceptSpawns((real, _command, _args, options) => {
    const child = protocolChild(real, framed(header, RGBA_2X2), options);
    child.once("close", () => { closed = true; });
    return child;
  });
  const original = crypto.createHash;
  const replacement = mock.method(crypto, "createHash", (...args) => {
    const instance = original(...args);
    const update = instance.update;
    instance.update = function (data, ...rest) {
      if (Buffer.isBuffer(data) && data.length === 16 && !enteredHash) {
        enteredHash = true;
        const until = performance.now() + 1100;
        while (performance.now() < until) { /* Deliberately delay the parent, not the decoder. */ }
      }
      return update.call(this, data, ...rest);
    };
    return instance;
  });
  syncBuiltinESMExports();
  try {
    const result = await readScannedPdf(input, { timeoutMs: 1000 });
    assert.equal(enteredHash, true, "the synchronous validation phase was entered");
    assert.equal(closed, true);
    assert.equal(result.code, "TIMEOUT");
  } finally {
    replacement.mock.restore(); syncBuiltinESMExports(); restoreSpawn();
  }
  assert.equal((await readScannedPdf(imagePdf())).kind, "decoded");
});

test("child environment and launch limits are fixed and exclude inherited provider/proxy settings", async () => {
  let observed;
  const restore = interceptSpawns((real, command, args, options) => {
    observed = { command, args, options };
    return real(command, args, options);
  });
  try {
    assert.equal((await readScannedPdf(imagePdf())).kind, "decoded");
    assert.equal(observed.command, "/usr/bin/prlimit");
    assert.deepEqual(observed.options.env, { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" });
    assert.equal(observed.options.detached, true);
    assert.deepEqual(observed.options.stdio, ["pipe", "pipe", "ignore"]);
    assert.ok(observed.args.includes("--as=1073741824:1073741824"));
    assert.ok(observed.args.includes("--cpu=5:5"));
    assert.ok(observed.args.includes("-I") && observed.args.includes("-S") && observed.args.includes("-B"));
  } finally { restore(); }
});
