import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { types } from "node:util";
import { PassThrough } from "node:stream";
import vm from "node:vm";

// Synthetic protocol harness only: no PDF decoding, real child, or Linux
// containment is exercised. It loads the production reader source unchanged.
const root = process.argv[2];
assert.equal(typeof root, "string");
const sourcePath = path.join(root, "src/extraction/pdf/reader.mjs");
const source = readFileSync(sourcePath, "utf8");
const children = [];
const killAttempts = [];
const mockProcess = {
  platform: "linux",
  execPath: process.execPath,
  kill: (...args) => killAttempts.push(args),
};

function spawn() {
  const child = new EventEmitter();
  child.pid = 900_000 + children.length;
  child.stdout = new PassThrough();
  child.stdin = new PassThrough();
  child.stdin.resume();
  child.kill = (signal) => killAttempts.push([child.pid, signal]);
  children.push(child);
  return child;
}

const context = vm.createContext({
  Buffer,
  Uint8Array,
  URL,
  process: mockProcess,
  setTimeout,
  clearTimeout,
});
const readerModule = new vm.SourceTextModule(source, {
  context,
  identifier: pathToFileURL(sourcePath).href,
  initializeImportMeta(meta) {
    meta.url = pathToFileURL(sourcePath).href;
  },
});

await readerModule.link(async (specifier) => {
  let exports;
  if (specifier === "./constants.mjs") {
    return new vm.SourceTextModule(
      readFileSync(path.join(root, "src/extraction/pdf/constants.mjs"), "utf8"),
      { context },
    );
  }
  if (specifier === "node:crypto") exports = { createHash };
  if (specifier === "node:child_process") exports = { spawn };
  if (specifier === "node:fs") {
    exports = {
      existsSync: () => true,
      realpathSync: (value) => value,
      statSync: () => ({ isFile: () => true, uid: 0, mode: 0o100755 }),
    };
  }
  if (specifier === "node:url") exports = { fileURLToPath };
  if (specifier === "node:util") exports = { types };
  if (specifier === "node:path") exports = { default: path };
  assert.ok(exports, `unexpected reader import ${specifier}`);
  return new vm.SyntheticModule(
    Object.keys(exports),
    function setSyntheticExports() {
      for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
    },
    { context },
  );
});
await readerModule.evaluate();

const reader = readerModule.namespace;
const sourcePdf = readFileSync(path.join(root, "tests/extraction/pdf/fixtures/text-multipage.pdf"));
const progressLine = (pageIndex) => Buffer.from(`${JSON.stringify({ kind: "progress", pageIndex })}\n`);
const flushData = () => new Promise((resolve) => setImmediate(resolve));
const outputLimits = {
  maxInputBytes: 20 * 1024 * 1024,
  maxPages: 20,
  maxPagePoints: 14_400,
  maxTextCodeUnits: 100_000,
  maxTextItemCodeUnits: 20_000,
  maxTextItems: 2_000,
  maxOutputBytes: 2 * 1024 * 1024,
  addressSpaceBytes: 6 * 1024 * 1024 * 1024,
  maxCpuSeconds: 15,
  maxWallMilliseconds: 20_000,
};

function resultLine() {
  return Buffer.from(`${JSON.stringify({
    kind: "result",
    observationKind: "observation",
    decoderVersion: "6.4.299",
    configVersion: "ei-text-pdf/1",
    networkAttemptCount: 0,
    completeness: "incomplete-text-only",
    limits: outputLimits,
    pages: [{
      pageIndex: 0,
      width: 612,
      height: 792,
      rotation: 0,
      coordinateSystem: "viewport-points-top-left",
      requiresInspection: true,
      textPresence: "text-present",
      textBoxes: [{
        text: "queued job success",
        geometry: "approximate-text-item",
        x: 10,
        y: 20,
        width: 100,
        height: 12,
      }],
    }],
  })}\n`);
}

async function cancellationAndQueueRecovery() {
  const controller = new AbortController();
  const progress = [];
  let cancelledSettled = false;
  let queuedSettled = false;
  const cancelledPromise = reader.readTextPdf(sourcePdf, {
    timeoutMs: 5_000,
    signal: controller.signal,
    onPageComplete(pageIndex) {
      progress.push(pageIndex);
      if (pageIndex === 0) controller.abort();
    },
  });
  cancelledPromise.then(() => { cancelledSettled = true; });
  const queuedPromise = reader.readTextPdf(sourcePdf, { timeoutMs: 5_000 });
  queuedPromise.then(() => { queuedSettled = true; });
  const cancelledChild = children[0];

  assert.equal(children.length, 1, "queued work must wait for the active child close");
  cancelledChild.stdout.write(progressLine(0));
  await flushData();
  assert.equal(controller.signal.aborted, true);
  assert.ok(killAttempts.some(([pid]) => pid === -cancelledChild.pid));
  assert.equal(cancelledSettled, false, "cancellation must wait for child close");

  cancelledChild.stdout.write(progressLine(1));
  await flushData();
  assert.deepEqual(progress, [0], "fragmented progress after cancellation is ignored");
  assert.equal(cancelledSettled, false, "late stdout must not resolve before close");
  assert.equal(queuedSettled, false);
  assert.equal(children.length, 1, "the queue must remain blocked until close");

  cancelledChild.emit("close", null, "SIGKILL");
  await flushData();
  const cancelled = await cancelledPromise;
  assert.equal(cancelled.code, "CANCELLED");
  assert.equal("pages" in cancelled, false);
  assert.equal(cancelledSettled, true);
  assert.equal(children.length, 2, "the queued child starts after close");

  const queuedChild = children[1];
  queuedChild.stdout.write(progressLine(0));
  queuedChild.stdout.write(resultLine());
  await flushData();
  queuedChild.emit("close", 0, null);
  await flushData();
  const recovered = await queuedPromise;
  assert.equal(recovered.kind, "observation");
  assert.equal(recovered.pages[0].textBoxes[0].text, "queued job success");
  assert.equal(queuedSettled, true);
  return { cancelledCode: cancelled.code, queuedKind: recovered.kind, progress };
}

async function callbackFailureAndOutputAccounting() {
  const progress = [];
  let failedSettled = false;
  const failedPromise = reader.readTextPdf(sourcePdf, {
    timeoutMs: 5_000,
    maxOutputBytes: 4_096,
    onPageComplete(pageIndex) {
      progress.push(pageIndex);
      if (pageIndex === 0) throw new Error("synthetic callback failure");
    },
  });
  failedPromise.then(() => { failedSettled = true; });
  const failedChild = children[2];

  failedChild.stdout.write(progressLine(0));
  await flushData();
  assert.ok(killAttempts.some(([pid]) => pid === -failedChild.pid));
  assert.equal(failedSettled, false, "callback failure must wait for child close");

  failedChild.stdout.write(progressLine(1));
  await flushData();
  assert.deepEqual(progress, [0], "fragmented progress after callback failure is ignored");

  // The full chunk counts against the output ceiling but cannot replace the
  // earlier CALLBACK_FAILED decision or be appended to the parser buffer.
  failedChild.stdout.write(Buffer.alloc(4_096, 0x61));
  await flushData();
  assert.equal(failedSettled, false);
  failedChild.emit("close", null, "SIGKILL");
  await flushData();
  const failed = await failedPromise;
  assert.equal(failed.code, "CALLBACK_FAILED", "first terminal error takes precedence");
  assert.equal("pages" in failed, false);
  assert.equal(failedSettled, true);
  return { code: failed.code, progress };
}

const cancellation = await cancellationAndQueueRecovery();
const callbackFailure = await callbackFailureAndOutputAccounting();
console.log(JSON.stringify({
  mode: "synthetic-fragmented-stream-lifecycle",
  sourceSha256: createHash("sha256").update(source).digest("hex"),
  cancellation,
  callbackFailure,
  childCount: children.length,
  killAttemptCount: killAttempts.length,
}));
