// Each scenario owns a fresh Node module pool. Faults never modify production files.
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import { performance } from "node:perf_hooks";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { fixture, hash, runtimeDirectory } from "./fixtures.mjs";

const mode = process.argv[2];
const productionWorker = fileURLToPath(new URL("../../../src/extraction/jpeg-webp/decode-worker.py", import.meta.url));
const faultWorker = fileURLToPath(new URL("./worker-fault.py", import.meta.url));
const realSpawn = childProcess.spawn;
const entries = [];
const controller = new AbortController();
const stall = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
let workerMode = mode.startsWith("frame-") ? mode : mode;
let canary;
let canaryConnections = 0;
if (mode === "network-url") {
  canary = net.createServer((socket) => {
    canaryConnections += 1;
    socket.end("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
  });
  await new Promise((resolve) => canary.listen(0, "127.0.0.1", resolve));
  const port = canary.address().port;
  await new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1");
    socket.on("error", reject); socket.resume(); socket.on("end", resolve);
  });
  assert.equal(canaryConnections, 1, "positive loopback control must reach the canary");
  canaryConnections = 0;
  workerMode = "network-url:" + port;
}
if (["active-cancel", "active-timeout", "queue-timeout", "queue-late", "saturation"].includes(mode)) workerMode = "sleep";
const realModes = ["pre-spawn-timeout", "pre-spawn-cancel", "return-timeout", "return-cancel", "normalized-timeout", "normalized-cancel", "spawn-throw"];
if (realModes.includes(mode)) workerMode = undefined;
let normalizeHook = 0;
if (mode.startsWith("normalized-")) {
  const realHash = crypto.createHash;
  crypto.createHash = function (...args) {
    const result = realHash(...args), update = result.update, digest = result.digest;
    let isPng = false;
    result.update = function (bytes, ...rest) {
      if (Buffer.isBuffer(bytes) && bytes.toString("hex", 0, 8) === "89504e470d0a1a0a") isPng = true;
      return update.call(this, bytes, ...rest);
    };
    result.digest = function (...digestArgs) {
      const value = digest.apply(this, digestArgs);
      if (isPng && normalizeHook === 0) {
        normalizeHook += 1;
        if (mode === "normalized-timeout") stall(1600);
        else controller.abort();
      }
      return value;
    };
    return result;
  };
}

let spawnAttempts = 0;
childProcess.spawn = function (command, args, options) {
  if (command !== "/usr/bin/prlimit" || !args.includes(productionWorker)) return realSpawn(command, args, options);
  spawnAttempts += 1;
  const first = spawnAttempts === 1;
  if (first && mode === "spawn-throw") throw new Error("Synthetic spawn exception");
  if (first && mode === "pre-spawn-timeout") stall(1100);
  if (first && mode === "pre-spawn-cancel") controller.abort();
  const originalArgs = [...args];
  const targetMode = first ? workerMode : undefined;
  if (targetMode) {
    args = [...args];
    const index = args.indexOf(productionWorker);
    args.splice(index, 1, faultWorker, targetMode, productionWorker);
    options = { ...options, stdio: [...options.stdio, "pipe"] };
  }
  const child = realSpawn(command, args, options);
  let resolveEntry;
  const entry = { child, pid: child.pid, spawnAt: performance.now(), stdinEnds: 0, closed: false,
    packets: [], originalArgs, environmentKeys: Object.keys(options.env).sort(),
    entry: new Promise((resolve) => { resolveEntry = resolve; }) };
  entries.push(entry);
  const end = child.stdin.end;
  child.stdin.end = function (...endArgs) { entry.stdinEnds += 1; return end.apply(this, endArgs); };
  if (targetMode) {
    let pending = "";
    child.stdio[3].on("data", (bytes) => {
      pending += bytes.toString();
      while (pending.includes("\n")) {
        const at = pending.indexOf("\n"); const line = pending.slice(0, at); pending = pending.slice(at + 1);
        const packet = JSON.parse(line); entry.packets.push(packet);
        if (packet.phase === "decode-entry") resolveEntry(packet);
      }
    });
  }
  child.prependOnceListener("close", (code, signal) => {
    entry.closed = true; entry.exitCode = code; entry.signal = signal; entry.closedAt = performance.now();
    if (first && ["return-timeout", "queue-late"].includes(mode)) stall(mode === "return-timeout" ? 1600 : 1300);
    if (first && mode === "return-cancel") controller.abort();
  });
  return child;
};
syncBuiltinESMExports();
const { createStaticJpegWebpReader } = await import("../../../src/extraction/jpeg-webp/index.mjs");
const reader = () => createStaticJpegWebpReader({ runtimeDirectory: runtimeDirectory() });
const { bytes, expected } = fixture("jpeg-gray-baseline");
const started = performance.now();
const timeoutMs = mode === "cpu" ? 10000 : mode === "active-timeout" ? 2000 :
  ["return-timeout", "normalized-timeout"].includes(mode) ? 1500 : mode === "pre-spawn-timeout" ? 1000 : 5000;
const pending = reader().read(bytes, { signal: controller.signal, timeoutMs });
async function entered() {
  assert.equal(entries.length, 1);
  let timer;
  try {
    return await Promise.race([entries[0].entry, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("Required decoder phase was not entered")), 4000);
    })]);
  } finally { clearTimeout(timer); }
}
let result, secondary;
if (mode === "active-cancel") {
  await entered(); const cancelledAt = performance.now(); controller.abort(); result = await pending;
  assert.equal(result.code, "CANCELLED"); assert.ok(performance.now() - cancelledAt < 750);
} else if (mode === "active-timeout") {
  await entered(); result = await pending; assert.equal(result.code, "TIMEOUT");
} else if (mode === "queue-timeout" || mode === "queue-late") {
  await entered();
  const queued = reader().read(bytes, { timeoutMs: mode === "queue-late" ? 1200 : 100 });
  if (mode === "queue-late") controller.abort();
  secondary = await queued;
  assert.equal(secondary.code, "TIMEOUT"); assert.equal(spawnAttempts, 1, "expired queued work must never enter spawn");
  controller.abort(); result = await pending; assert.equal(result.code, "CANCELLED");
} else if (mode === "saturation") {
  await entered();
  const controllers = Array.from({ length: 4 }, () => new AbortController());
  const queued = controllers.map((item) => reader().read(bytes, { signal: item.signal }));
  secondary = await reader().read(bytes);
  assert.equal(secondary.code, "QUEUE_FULL"); assert.equal(spawnAttempts, 1);
  for (const item of controllers) item.abort();
  assert.deepEqual((await Promise.all(queued)).map((x) => x.code), Array(4).fill("CANCELLED"));
  controller.abort(); result = await pending; assert.equal(result.code, "CANCELLED");
} else {
  result = await pending;
}
if (mode === "pre-spawn-timeout") { assert.equal(result.code, "TIMEOUT"); assert.equal(entries[0].stdinEnds, 0); }
if (mode === "pre-spawn-cancel") { assert.equal(result.code, "CANCELLED"); assert.equal(entries[0].stdinEnds, 0); }
if (mode === "return-timeout" || mode === "normalized-timeout") assert.equal(result.code, "TIMEOUT");
if (mode === "return-cancel" || mode === "normalized-cancel") assert.equal(result.code, "CANCELLED");
if (mode.startsWith("normalized-")) assert.equal(normalizeHook, 1, "must cross actual final normalization, not fail during setup");
if (["cpu", "abi", "exit", "spawn-throw"].includes(mode)) assert.equal(result.code, "DECODER_FAILURE");
if (mode === "cpu") { assert.equal(entries[0].signal, "SIGKILL"); assert.ok(performance.now() - started < 10000); }
if (mode === "memory") assert.equal(result.code, "RESOURCE_LIMIT");
if (mode.startsWith("network-")) assert.equal(result.code, "REMOTE_RESOURCE_ATTEMPT");
if (["subprocess", "file-read", "file-read-swallowed", "file-write"].includes(mode)) assert.equal(result.code, "RESOURCE_LIMIT");
if (mode === "fd") {
  assert.equal(result.kind, "decoded");
  const packet = entries[0].packets.find((x) => x.phase === "fd-cap");
  assert.ok(packet && packet.opened > 0 && packet.opened < 64); assert.deepEqual(packet.limit, [64, 64]);
}
for (const entry of entries) {
  assert.ok(entry.closed, "result cannot release a still-open child");
  assert.throws(() => process.kill(entry.pid, 0), { code: "ESRCH" });
  assert.deepEqual(entry.environmentKeys, ["LANG", "LC_ALL", "PATH"]);
  const packet = entry.packets.find((x) => x.phase === "decode-entry");
  if (packet) {
    assert.deepEqual(packet.limits, { as: [536870912, 536870912], cpu: [5, 5], nofile: [64, 64], fsize: [0, 0] });
    assert.deepEqual(packet.environmentKeys, ["LANG", "LC_ALL", "PATH"]);
  }
}
const firstEntries = entries.map(({ child, entry, ...value }) => value);
const recovery = await reader().read(bytes);
assert.equal(recovery.kind, "decoded", JSON.stringify(recovery));
assert.equal(recovery.rgbaSha256, expected.expectedRgbaSha256);
assert.equal(hash(recovery.copyNormalizedBytes()), recovery.normalizedSha256);
if (canary) {
  await new Promise((resolve) => canary.close(resolve));
  assert.equal(canaryConnections, 0, "guarded decoder must make no secondary request");
}
process.stdout.write(JSON.stringify({ mode, result, secondary, elapsedMs: performance.now() - started,
  normalizeHook, canaryConnections, firstEntries, recovery: { kind: recovery.kind, sourceSha256: recovery.sourceSha256,
    rgbaSha256: recovery.rgbaSha256, normalizedSha256: recovery.normalizedSha256 } }) + "\n");
