import test from "node:test";
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { readLocalOcr } from "../../../src/extraction/local-ocr/index.mjs";
import { input } from "./helpers.mjs";
import { fakeWorkers, turn } from "./fake-worker.mjs";

test("synthetic launch binds prlimit, verified Python, fixed OCR worker and minimal single-thread environment", async (t) => {
  const control = fakeWorkers(t);
  assert.equal((await readLocalOcr(input())).kind, "observed");
  const child = control.seen[0];
  assert.equal(child.command, "/usr/bin/prlimit");
  assert.ok(child.args.includes("--as=1073741824:1073741824"));
  assert.ok(child.args.includes("--cpu=5:5"));
  assert.ok(child.args.includes("--nofile=64:64"));
  assert.deepEqual(child.args.slice(-5, -2), ["-I", "-S", "-B"]);
  assert.equal(child.args.at(-1), "--recognize");
  assert.equal(child.options.detached, true);
  assert.deepEqual(child.options.stdio, ["pipe", "pipe", "ignore"]);
  assert.deepEqual(child.options.env, { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8", OMP_THREAD_LIMIT: "1", OMP_NUM_THREADS: "1" });
});

test("synthetic child exit alone cannot release output or the active slot before close", async (t) => {
  const control = fakeWorkers(t, () => {});
  let settled = false;
  const pending = readLocalOcr(input()).then((value) => { settled = true; return value; });
  await turn();
  control.seen[0].emit("exit", 0, null);
  await turn(); assert.equal(settled, false);
  control.seen[0].reply();
  assert.equal((await pending).kind, "observed");
});

test("synthetic cancellation kills the group and waits for real close before recovery", async (t) => {
  const control = fakeWorkers(t, (_child, index) => { if (index > 0) _child.reply(); });
  const controller = new AbortController();
  let settled = false;
  const pending = readLocalOcr(input(), { signal: controller.signal }).then((value) => { settled = true; return value; });
  await turn();
  control.seen[0].onKill = () => {};
  controller.abort("PRIVATE REASON");
  await turn(); assert.equal(settled, false); assert.equal(control.kills.length, 1);
  const next = readLocalOcr(input());
  await turn(); assert.equal(control.seen.length, 1);
  control.seen[0].close(null, "SIGKILL");
  assert.equal((await pending).code, "CANCELLED");
  assert.equal((await next).kind, "observed");
});

test("synthetic timeout kills and reaps before the next queued request can start", async (t) => {
  const control = fakeWorkers(t, (child, index) => { if (index > 0) child.reply(); });
  const pending = readLocalOcr(input(), { timeoutMs: 500 });
  await turn(); control.seen[0].onKill = () => {};
  const next = readLocalOcr(input());
  await delay(550);
  assert.equal(control.kills.length, 1); assert.equal(control.seen.length, 1);
  control.seen[0].close(null, "SIGKILL");
  assert.equal((await pending).code, "TIMEOUT");
  assert.equal((await next).kind, "observed");
});

test("synthetic queued request retains its original deadline and never reaches spawn after expiry", async (t) => {
  const control = fakeWorkers(t, () => {});
  const first = readLocalOcr(input(), { timeoutMs: 5000 });
  const queued = readLocalOcr(input(), { timeoutMs: 500 });
  assert.equal((await queued).code, "TIMEOUT");
  assert.equal(control.seen.length, 1);
  control.seen[0].reply(); assert.equal((await first).kind, "observed");
});

test("synthetic queued cancellation does not terminate the active unrelated request", async (t) => {
  const control = fakeWorkers(t, () => {});
  const first = readLocalOcr(input());
  const controller = new AbortController();
  const queued = readLocalOcr(input(), { signal: controller.signal });
  controller.abort();
  assert.equal((await queued).code, "CANCELLED");
  assert.equal(control.kills.length, 0); assert.equal(control.seen.length, 1);
  control.seen[0].reply(); assert.equal((await first).kind, "observed");
});

test("synthetic concurrency/queue ceilings deny the sixth request then recover every admitted request", async (t) => {
  const control = fakeWorkers(t, (child, index) => { if (index > 0) child.reply(); });
  const admitted = Array.from({ length: 5 }, () => readLocalOcr(input()));
  assert.equal((await readLocalOcr(input())).code, "QUEUE_FULL");
  assert.equal(control.seen.length, 1);
  control.seen[0].reply();
  assert.ok((await Promise.all(admitted)).every((value) => value.kind === "observed"));
  assert.equal(control.seen.length, 5);
});

test("synthetic native crash yields a fixed refusal and the next request recovers", async (t) => {
  fakeWorkers(t, (child, index) => { if (index === 0) child.close(null, "SIGSEGV"); else child.reply(); });
  assert.equal((await readLocalOcr(input())).code, "OCR_FAILURE");
  assert.equal((await readLocalOcr(input())).kind, "observed");
});

test("synthetic output overflow kills without exposing partial words and recovers", async (t) => {
  const control = fakeWorkers(t, (child, index) => {
    if (index === 0) child.stdout.write(Buffer.alloc(524289, 65)); else child.reply();
  });
  const refusal = await readLocalOcr(input());
  assert.equal(refusal.code, "OUTPUT_LIMIT"); assert.equal(refusal.words, undefined);
  assert.equal(control.kills.length, 1);
  assert.equal((await readLocalOcr(input())).kind, "observed");
});

test("synthetic synchronous spawn failure is sanitized and does not strand the queue", async (t) => {
  t.mock.method(childProcess, "spawn", () => { throw new Error("PRIVATE PATH"); });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  assert.equal((await readLocalOcr(input())).code, "OCR_FAILURE");
  assert.equal((await readLocalOcr(input())).code, "OCR_FAILURE");
});

test("synthetic parent validation remains inside the original deadline after a successful child close", async (t) => {
  // Install the hook only after forming the synthetic reply, so it proves entry
  // into parent validation instead of consuming the worker/queue allowance.
  let entered = false;
  const original = Buffer.byteLength;
  fakeWorkers(t, (child) => child.reply((value) => {
    t.mock.method(Buffer, "byteLength", function (text, ...args) {
      if (text === "TOKEN" && !entered) {
        entered = true;
        const until = performance.now() + 2100;
        while (performance.now() < until) { /* Deterministic delayed event-loop dispatch. */ }
      }
      return original.call(this, text, ...args);
    });
    return value;
  }));
  const result = await readLocalOcr(input(), { timeoutMs: 2000 });
  assert.equal(entered, true, "parent validation callback must actually be entered");
  assert.equal(result.kind, "rejected"); assert.equal(result.code, "TIMEOUT");
});

test("synthetic cancellation during parent validation cannot escape as observed text", async (t) => {
  const controller = new AbortController(); let entered = false;
  const original = Buffer.byteLength;
  fakeWorkers(t, (child) => child.reply((value) => {
    t.mock.method(Buffer, "byteLength", function (text, ...args) {
      if (text === "TOKEN" && !entered) { entered = true; controller.abort(); }
      return original.call(this, text, ...args);
    });
    return value;
  }));
  const result = await readLocalOcr(input(), { signal: controller.signal });
  assert.equal(entered, true); assert.equal(result.code, "CANCELLED");
});
