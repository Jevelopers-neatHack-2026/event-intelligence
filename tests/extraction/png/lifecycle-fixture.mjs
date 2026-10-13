// Test-only process instrumentation. Production exposes no spawn/worker/clock hook.
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import { once } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { performance } from "node:perf_hooks";
import { png } from "./fixtures.mjs";

const mode = process.argv[2];
const originalSpawn = childProcess.spawn;
const originalHash = crypto.createHash;
const originalTimer = globalThis.setTimeout;
const originalFrom = Buffer.from;
const rawCopyController = new AbortController();
const children = [];
const records = [];
const output = { mode, syntheticInputs: true, records };
let firstSpawnResolve;
const firstSpawn = new Promise((resolve) => { firstSpawnResolve = resolve; });
let started = 0;
let timeoutMs = 1000;
let parentHashCount = 0;
const holdFirst = !["profile", "late-return", "raw-copy-timeout", "raw-copy-cancel"].includes(mode);
const safety = originalTimer(() => {
  for (const child of children) {
    try { process.kill(-child.pid, "SIGKILL"); } catch { /* absent */ }
  }
  process.stderr.write("PNG lifecycle fixture exceeded its independent safety timeout\n");
  process.exit(1);
}, 12000);

function busyUntil(deadline) {
  while (performance.now() < deadline) { /* Deliberately delay callback delivery in this test process. */ }
}

childProcess.spawn = (command, args, options) => {
  const child = originalSpawn(command, args, options);
  children.push(child);
  const record = {
    command, args, cwd: options.cwd, env: options.env, detached: options.detached,
    stdio: options.stdio, pid: child.pid, closed: false,
  };
  records.push(record);
  if (holdFirst && records.length === 1) {
    // Hold delivery at a real child-pipe boundary. The worker cannot finish its
    // byte collection until stdin ends; no production callback/clock is added.
    child.stdin.end = () => {
      record.inputEndHeld = true;
      return child.stdin;
    };
  }
  child.once("spawn", () => {
    record.spawned = true;
    if (records.length === 1) {
      firstSpawnResolve(child);
    }
  });
  child.once("close", (code, signal) => {
    record.closed = true;
    record.exitCode = code;
    record.signal = signal;
    if (mode === "cancel-delayed-close" && records.length === 1) busyUntil(started + timeoutMs + 40);
  });
  return child;
};

if (mode === "queued-deadline") {
  // The queued deadline is still the real performance clock. Only its timer
  // callback delivery is delayed, forcing the dispatch-time expiry guard to run.
  globalThis.setTimeout = (callback, delay, ...args) =>
    originalTimer(callback, delay < 100 ? 2000 : delay, ...args);
}
if (mode === "late-return") {
  crypto.createHash = (...args) => {
    const hash = originalHash(...args);
    const sequence = ++parentHashCount;
    if (sequence === 2) {
      const digest = hash.digest;
      hash.digest = function (...digestArgs) {
        const value = digest.apply(this, digestArgs);
        busyUntil(started + timeoutMs + 40);
        output.parentValidationDelayed = true;
        return value;
      };
    }
    return hash;
  };
}
if (mode.startsWith("raw-copy-")) {
  Buffer.from = function (value, ...args) {
    const result = originalFrom.call(this, value, ...args);
    if (!output.rawCopyPhase && records[0]?.closed && Buffer.isBuffer(value) &&
        value.length === 4 && value[0] === 1 && value[1] === 2 && value[2] === 3 && value[3] === 4) {
      const enteredAt = performance.now();
      assert.ok(enteredAt < started + timeoutMs, "The actual raw copy must begin before the original deadline.");
      output.rawCopyPhase = { enteredAt, originalDeadline: started + timeoutMs, childClosed: true };
      if (mode === "raw-copy-timeout") busyUntil(started + timeoutMs + 40);
      else rawCopyController.abort();
    }
    return result;
  };
}
syncBuiltinESMExports();
const { readStaticPng, STATIC_PNG_READER_LIMITS } = await import("../../../src/extraction/png/index.mjs");

function inputHeld(child) {
  assert.equal(records[0].spawned, true);
  assert.equal(records[0].inputEndHeld, true, "The actual stdin.end boundary must have been reached.");
  assert.equal(records[0].closed, false);
  assert.equal(child.exitCode, null);
  assert.equal(child.signalCode, null);
  assert.equal(process.kill(child.pid, 0), true, "The admitted owned child must still be alive.");
}

function reaped(index) {
  assert.equal(records[index].closed, true, "Promise settlement must follow the actual close event.");
  assert.throws(() => process.kill(records[index].pid, 0), { code: "ESRCH" });
}

async function recover(expectedSpawns) {
  const result = await readStaticPng(png());
  assert.equal(result.kind, "decoded", JSON.stringify(result));
  assert.deepEqual([...result.copyRgbaBytes()], [1, 2, 3, 4]);
  assert.equal(records.length, expectedSpawns);
  assert.ok(records.every((record) => record.closed));
  output.recovery = result.kind;
}

async function run() {
  if (mode === "profile") {
    // Ambient values are synthetic poison; none may enter the actual reader child.
    process.env.NODE_OPTIONS = "--require=/untrusted-must-not-load.cjs";
    process.env.NODE_PATH = "/untrusted-modules";
    process.env.HTTP_PROXY = "http://example.invalid:1";
    process.env.NODE_USE_ENV_PROXY = "1";
    process.env.PNG_PRIVATE_TEST_SECRET = "synthetic-never-in-child";
    const result = await readStaticPng(png());
    assert.equal(result.kind, "decoded", JSON.stringify(result));
    const first = records[0];
    assert.deepEqual(first.env, { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" });
    assert.equal(first.command, "/usr/bin/prlimit");
    assert.deepEqual(first.args.slice(0, 5), [
      "--as=" + STATIC_PNG_READER_LIMITS.maxAddressSpaceBytes,
      "--cpu=" + STATIC_PNG_READER_LIMITS.maxCpuSeconds,
      "--core=0", "--nofile=" + STATIC_PNG_READER_LIMITS.maxOpenFiles, "--",
    ]);
    assert.equal(first.detached, true);
    assert.deepEqual(first.stdio, ["pipe", "pipe", "ignore"]);
    assert.ok(first.args.includes("--permission"));
    assert.ok(first.args.includes("--allow-fs-read=" + first.cwd));
    assert.ok(first.args.includes("--max-old-space-size=" + STATIC_PNG_READER_LIMITS.maxHeapMiB));
    reaped(0);
    const workerAt = first.args.findIndex((arg) => arg.endsWith("/decode-worker.mjs"));
    const probeCode = [
      "const fs=require('node:fs');",
      "const p={fsReadOutside:process.permission.has('fs.read','/etc/hosts'),",
      "fsWrite:process.permission.has('fs.write'),child:process.permission.has('child'),",
      "worker:process.permission.has('worker'),addons:process.permission.has('addons'),",
      "env:Object.keys(process.env).sort()};",
      "console.log(JSON.stringify({permissions:p,limits:fs.readFileSync('/proc/self/limits','utf8')}));",
      "setInterval(()=>{},1000);",
    ].join("");
    // Separate synthetic probe: same observed OS/Node/env prefix, with one
    // additional read grant for its own kernel-limit record and a probe entrypoint.
    const probeArgs = [...first.args.slice(0, workerAt), "--allow-fs-read=/proc/self/limits", "-e", probeCode];
    const probe = originalSpawn(first.command, probeArgs, {
      cwd: first.cwd, env: first.env, detached: true, stdio: ["pipe", "pipe", "pipe"],
    });
    children.push(probe);
    let probeError = "";
    probe.stderr.on("data", (data) => { probeError += data; });
    const ready = await once(probe.stdout, "data");
    const probeReadback = JSON.parse(String(ready[0]));
    output.permissionProbe = probeReadback.permissions;
    output.syntheticProbeArgs = probeArgs;
    assert.deepEqual(output.permissionProbe, {
      fsReadOutside: false, fsWrite: false, child: false, worker: false, addons: false,
      env: ["LANG", "LC_ALL", "PATH"],
    }, probeError);
    const limits = probeReadback.limits;
    output.probeKernelLimits = limits;
    assert.match(limits, /^Max cpu time\s+5\s+5\s+seconds[ \t]*$/m);
    assert.match(limits, /^Max core file size\s+0\s+0\s+bytes[ \t]*$/m);
    assert.match(limits, /^Max open files\s+64\s+64\s+files[ \t]*$/m);
    assert.match(limits, /^Max address space\s+6442450944\s+6442450944\s+bytes[ \t]*$/m);
    const closed = once(probe, "close");
    process.kill(-probe.pid, "SIGKILL");
    await closed;
    assert.throws(() => process.kill(probe.pid, 0), { code: "ESRCH" });
    return;
  }
  if (mode === "late-return") {
    started = performance.now();
    const result = await readStaticPng(png(), { timeoutMs });
    assert.equal(output.parentValidationDelayed, true, "The actual parent derivative hash must be reached.");
    assert.equal(result.code, "TIMEOUT", JSON.stringify(result));
    assert.equal(Object.hasOwn(result, "copyNormalizedBytes"), false);
    assert.equal(Object.hasOwn(result, "copyRgbaBytes"), false);
    reaped(0);
    await recover(2);
    return;
  }
  if (mode.startsWith("raw-copy-")) {
    timeoutMs = 3000;
    started = performance.now();
    const result = await readStaticPng(png(), { signal: rawCopyController.signal, timeoutMs });
    assert.ok(output.rawCopyPhase, "The actual decoded raw copy must be reached, not a setup failure.");
    assert.equal(result.code, mode === "raw-copy-timeout" ? "TIMEOUT" : "CANCELLED", JSON.stringify(result));
    assert.equal(result.copyNormalizedBytes, undefined);
    assert.equal(result.copyRgbaBytes, undefined);
    reaped(0);
    await recover(2);
    return;
  }
  const firstController = new AbortController();
  if (["timeout", "cancel-delayed-close"].includes(mode)) timeoutMs = 1000;
  else timeoutMs = 5000;
  started = performance.now();
  const first = readStaticPng(png(), { signal: firstController.signal, timeoutMs });
  const child = await firstSpawn;
  inputHeld(child); // A required actual-caller phase, not a relative delay guess.
  output.inputEndHeldConfirmed = true;
  if (mode === "timeout") {
    assert.equal((await first).code, "TIMEOUT");
    reaped(0);
    await recover(2);
  } else if (mode === "cancel" || mode === "cancel-delayed-close") {
    firstController.abort("synthetic private reason");
    const result = await first;
    assert.equal(result.code, "CANCELLED");
    assert.equal(JSON.stringify(result).includes("private reason"), false);
    reaped(0);
    await recover(2);
  } else if (mode === "queued-cancel") {
    const queuedController = new AbortController();
    const queued = readStaticPng(png(), { signal: queuedController.signal });
    queuedController.abort();
    assert.equal((await queued).code, "CANCELLED");
    assert.equal(records.length, 1, "Cancelled queued work must not start a child.");
    firstController.abort();
    assert.equal((await first).code, "CANCELLED");
    reaped(0);
    await recover(2);
  } else if (mode === "queued-deadline") {
    const queuedStarted = performance.now();
    const queued = readStaticPng(png(), { timeoutMs: 40 });
    busyUntil(queuedStarted + 80);
    firstController.abort();
    assert.equal((await first).code, "CANCELLED");
    assert.equal((await queued).code, "TIMEOUT");
    assert.equal(records.length, 1, "An expired queued job must not renew its allowance or spawn.");
    reaped(0);
    await recover(2);
  } else if (mode === "saturation") {
    const controllers = Array.from({ length: 4 }, () => new AbortController());
    const queued = controllers.map((controller) => readStaticPng(png(), { signal: controller.signal }));
    assert.equal((await readStaticPng(png())).code, "QUEUE_FULL");
    assert.equal(records.length, 1);
    controllers.forEach((controller) => controller.abort());
    assert.deepEqual((await Promise.all(queued)).map((result) => result.code), Array(4).fill("CANCELLED"));
    firstController.abort();
    assert.equal((await first).code, "CANCELLED");
    reaped(0);
    await recover(2);
  } else {
    throw new Error("Unknown fixture mode");
  }
}

try {
  await run();
  output.outcome = "pass";
} finally {
  clearTimeout(safety);
  globalThis.setTimeout = originalTimer;
  childProcess.spawn = originalSpawn;
  crypto.createHash = originalHash;
  Buffer.from = originalFrom;
  syncBuiltinESMExports();
  for (const child of children) {
    if (child.exitCode === null && child.signalCode === null) {
      const closed = once(child, "close").catch(() => undefined);
      try { process.kill(-child.pid, "SIGKILL"); } catch { /* absent */ }
      await closed;
    }
  }
}
process.stdout.write(JSON.stringify(output) + "\n");
