import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { realpathSync, statSync } from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { types } from "node:util";
import { fileURLToPath } from "node:url";
import { crc32 } from "node:zlib";
import {
  PNG_CONFIG_VERSION, PNG_DECODER, PNG_ERROR_CODES, PNG_LIMITS, PNG_NODE_VERSION,
  PNG_PROTOCOL, PNG_ZLIB_VERSION,
} from "./constants.mjs";

const PRLIMIT = "/usr/bin/prlimit";
const WORKER = fileURLToPath(new URL("./decode-worker.mjs", import.meta.url));
const WORKER_DIRECTORY = path.dirname(WORKER);
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength").get;
const byteOffset = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteOffset").get;
const arrayBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer").get;
const bufferLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;
const copyInto = Uint8Array.prototype.set;
const isAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted").get;
const addListener = EventTarget.prototype.addEventListener;
const removeListener = EventTarget.prototype.removeEventListener;
const queue = [];
let activeWorkers = 0;

export const STATIC_PNG_READER_LIMITS = PNG_LIMITS;

function rejected(code, sourceSha256) {
  return Object.freeze({ kind: "rejected", code, sourceSha256, decoder: PNG_DECODER });
}

function optionsFrom(options) {
  try {
    if (options === undefined) options = {};
    if (!options || typeof options !== "object" || types.isProxy(options) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(options))) return { error: "INVALID_OPTIONS" };
    const descriptors = Object.getOwnPropertyDescriptors(options);
    for (const key of Reflect.ownKeys(descriptors)) {
      if (!["signal", "timeoutMs", "maxOutputBytes"].includes(key) ||
          !Object.hasOwn(descriptors[key], "value")) return { error: "INVALID_OPTIONS" };
    }
    const signal = descriptors.signal?.value;
    if (signal !== undefined && (!signal || types.isProxy(signal) || typeof signal !== "object")) {
      return { error: "INVALID_OPTIONS" };
    }
    if (signal !== undefined) isAborted.call(signal); // Native brand, no caller getter.
    const timeoutMs = descriptors.timeoutMs?.value ?? PNG_LIMITS.defaultTimeoutMs;
    const maxOutputBytes = descriptors.maxOutputBytes?.value ?? PNG_LIMITS.maxOutputBytes;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > PNG_LIMITS.maxTimeoutMs ||
        !Number.isInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > PNG_LIMITS.maxOutputBytes ||
        descriptors.timeoutMs?.value === null || descriptors.maxOutputBytes?.value === null) {
      return { error: "INVALID_LIMIT" };
    }
    return { signal, timeoutMs, maxOutputBytes };
  } catch {
    return { error: "INVALID_OPTIONS" };
  }
}

function inputFrom(input) {
  try {
    if (!input || typeof input !== "object" || types.isProxy(input) ||
        ![Uint8Array.prototype, Buffer.prototype].includes(Object.getPrototypeOf(input))) {
      return { error: "INVALID_INPUT" };
    }
    const length = byteLength.call(input);
    if (length === 0) return { error: "INVALID_INPUT" };
    if (length > PNG_LIMITS.maxInputBytes) return { error: "INPUT_TOO_LARGE" };
    const backing = arrayBuffer.call(input);
    bufferLength.call(backing); // Reject SharedArrayBuffer; no concurrent writer.
    const view = new Uint8Array(backing, byteOffset.call(input), length);
    const bytes = Buffer.alloc(length);
    copyInto.call(bytes, view);
    return { bytes, sourceSha256: createHash("sha256").update(bytes).digest("hex") };
  } catch {
    return { error: "INVALID_INPUT" };
  }
}

function isolationAvailable() {
  if (process.platform !== "linux") return false;
  try {
    const resolved = realpathSync(PRLIMIT);
    const stat = statSync(resolved);
    return resolved === PRLIMIT && stat.isFile() && stat.uid === 0 &&
      (stat.mode & 0o111) !== 0 && (stat.mode & 0o022) === 0;
  } catch {
    return false;
  }
}

function stopCode(job) {
  if (job.terminationCode) return job.terminationCode;
  if (performance.now() >= job.deadline) return "TIMEOUT";
  if (job.options.signal && isAborted.call(job.options.signal)) return "CANCELLED";
  return undefined;
}

function cleanup(job) {
  clearTimeout(job.timer);
  if (job.options.signal) removeListener.call(job.options.signal, "abort", job.abortListener);
}

function finishQueued(job, code) {
  if (job.state !== "queued") return;
  const index = queue.indexOf(job);
  if (index >= 0) queue.splice(index, 1);
  job.state = "finished";
  cleanup(job);
  job.resolve(rejected(code, job.sourceSha256));
}

function kill(job) {
  if (!job.child?.pid || job.childClosed) return;
  try {
    process.kill(-job.child.pid, "SIGKILL");
  } catch {
    try { job.child.kill("SIGKILL"); } catch { /* close still decides completion. */ }
  }
}

function terminate(job, code) {
  if (job.state !== "running" || job.terminationCode) return;
  job.terminationCode = code;
  kill(job);
}

function pump() {
  while (activeWorkers < PNG_LIMITS.maxConcurrency && queue.length > 0) {
    const job = queue.shift();
    const code = stopCode(job);
    if (code) {
      finishQueued(job, code);
      continue;
    }
    job.state = "running";
    activeWorkers += 1;
    runIsolated(job).then((result) => {
      const terminal = stopCode(job); // Original deadline, also after frame/hash work.
      job.state = "finished";
      cleanup(job);
      activeWorkers -= 1;
      job.resolve(terminal ? rejected(terminal, job.sourceSha256) : result);
      pump();
    });
  }
}

function enqueue(job) {
  if (activeWorkers >= PNG_LIMITS.maxConcurrency && queue.length >= PNG_LIMITS.maxQueued) {
    return Promise.resolve(rejected("QUEUE_FULL", job.sourceSha256));
  }
  return new Promise((resolve) => {
    job.resolve = resolve;
    job.state = "queued";
    job.abortListener = () => {
      const code = stopCode(job) ?? "CANCELLED";
      if (job.state === "queued") finishQueued(job, code);
      else terminate(job, code);
    };
    job.timer = setTimeout(() => {
      if (job.state === "queued") finishQueued(job, "TIMEOUT");
      else terminate(job, "TIMEOUT");
    }, Math.max(0, job.deadline - performance.now()));
    if (job.options.signal) addListener.call(job.options.signal, "abort", job.abortListener, { once: true });
    queue.push(job);
    pump();
  });
}

function validNormalizedPng(bytes, header) {
  if (bytes.length < 57 || bytes.toString("hex", 0, 8) !== "89504e470d0a1a0a" ||
      bytes.readUInt32BE(8) !== 13 || bytes.toString("ascii", 12, 16) !== "IHDR" ||
      bytes.readUInt32BE(16) !== header.width || bytes.readUInt32BE(20) !== header.height ||
      bytes.toString("hex", 24, 29) !== "0806000000") return false;
  const idatLength = bytes.readUInt32BE(33);
  if (bytes.toString("ascii", 37, 41) !== "IDAT" || idatLength + 57 !== bytes.length ||
      bytes.toString("hex", bytes.length - 12) !== "0000000049454e44ae426082") return false;
  return crc32(bytes.subarray(12, 29)) === bytes.readUInt32BE(29) &&
    crc32(bytes.subarray(37, bytes.length - 16)) === bytes.readUInt32BE(bytes.length - 16);
}

function frameResult(job, parts, size) {
  const bad = () => rejected("PROTOCOL_ERROR", job.sourceSha256);
  try {
    const frame = Buffer.concat(parts, size);
    if (frame.length < 4) return bad();
    const headerLength = frame.readUInt32BE(0);
    if (headerLength < 2 || headerLength > PNG_LIMITS.maxHeaderBytes || headerLength + 4 > frame.length) return bad();
    const header = JSON.parse(frame.toString("utf8", 4, 4 + headerLength));
    if (!header || typeof header !== "object" || Array.isArray(header)) return bad();
    const common = ["kind", "protocol", "configVersion", "nodeVersion", "zlibVersion",
      "sourceSha256", "networkApiAttemptCount", "maxOutputBytes", "normalizedByteLength"];
    const specific = header.kind === "decoded"
      ? ["width", "height", "sourceColorType", "decodedRgbaBytes", "rgbaSha256", "normalizedSha256"] : ["code"];
    const keys = [...common, ...specific];
    if (Object.keys(header).length !== keys.length || !keys.every((key) => Object.hasOwn(header, key)) ||
        header.protocol !== PNG_PROTOCOL || header.configVersion !== PNG_CONFIG_VERSION ||
        header.nodeVersion !== PNG_NODE_VERSION || header.zlibVersion !== PNG_ZLIB_VERSION ||
        header.sourceSha256 !== job.sourceSha256 || header.maxOutputBytes !== job.options.maxOutputBytes ||
        !Number.isInteger(header.networkApiAttemptCount) || header.networkApiAttemptCount < 0) return bad();
    const payload = frame.subarray(4 + headerLength);
    if (header.normalizedByteLength !== payload.length) return bad();
    if (header.kind === "rejected") {
      if (payload.length !== 0 || !PNG_ERROR_CODES.includes(header.code)) return bad();
      return rejected(header.networkApiAttemptCount === 0 ? header.code : "REMOTE_RESOURCE_ATTEMPT", job.sourceSha256);
    }
    if (header.kind !== "decoded" || payload.length > job.options.maxOutputBytes ||
        !Number.isInteger(header.width) || header.width < 1 || header.width > PNG_LIMITS.maxDimension ||
        !Number.isInteger(header.height) || header.height < 1 || header.height > PNG_LIMITS.maxRows ||
        header.width * header.height > PNG_LIMITS.maxPixels || ![2, 6].includes(header.sourceColorType) ||
        header.decodedRgbaBytes !== header.width * header.height * 4 ||
        typeof header.rgbaSha256 !== "string" || !/^[a-f0-9]{64}$/.test(header.rgbaSha256) ||
        typeof header.normalizedSha256 !== "string" || !/^[a-f0-9]{64}$/.test(header.normalizedSha256) ||
        !validNormalizedPng(payload, header) ||
        createHash("sha256").update(payload).digest("hex") !== header.normalizedSha256) return bad();
    if (header.networkApiAttemptCount !== 0) return rejected("REMOTE_RESOURCE_ATTEMPT", job.sourceSha256);
    // Own bytes are never exposed; each consumer obtains a new mutable copy.
    const normalized = Buffer.from(payload);
    return Object.freeze({
      kind: "decoded", completeness: "incomplete-pixels-only", requiresInspection: true,
      sourceSha256: job.sourceSha256, decoder: PNG_DECODER,
      limits: Object.freeze({ ...PNG_LIMITS, timeoutMs: job.options.timeoutMs, maxOutputBytes: job.options.maxOutputBytes }),
      width: header.width, height: header.height, sourceColorType: header.sourceColorType,
      outputColorType: 6, decodedRgbaBytes: header.decodedRgbaBytes, rgbaSha256: header.rgbaSha256,
      normalizedSha256: header.normalizedSha256, normalizedByteLength: normalized.length,
      networkApiAttemptCount: 0,
      copyNormalizedBytes() { return new Uint8Array(normalized); },
    });
  } catch {
    return bad();
  }
}

function runIsolated(job) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(PRLIMIT, [
        "--as=" + PNG_LIMITS.maxAddressSpaceBytes,
        "--cpu=" + PNG_LIMITS.maxCpuSeconds,
        "--core=0", "--nofile=" + PNG_LIMITS.maxOpenFiles, "--",
        process.execPath, "--disable-wasm-trap-handler",
        "--max-old-space-size=" + PNG_LIMITS.maxHeapMiB,
        "--permission", "--allow-fs-read=" + WORKER_DIRECTORY,
        WORKER, String(job.options.maxOutputBytes),
      ], {
        cwd: WORKER_DIRECTORY, env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
        detached: true, stdio: ["pipe", "pipe", "ignore"],
      });
    } catch {
      resolve(rejected("DECODER_FAILURE", job.sourceSha256));
      return;
    }
    job.child = child;
    const parts = [];
    let size = 0;
    child.once("spawn", () => { if (job.terminationCode) kill(job); });
    child.once("error", () => terminate(job, stopCode(job) ?? "DECODER_FAILURE"));
    child.stdout.on("error", () => terminate(job, stopCode(job) ?? "DECODER_FAILURE"));
    child.stdin.on("error", () => terminate(job, stopCode(job) ?? "DECODER_FAILURE"));
    child.stdout.on("data", (data) => {
      if (job.terminationCode) return;
      size += data.length;
      if (size > job.options.maxOutputBytes + PNG_LIMITS.maxHeaderBytes + 4) {
        terminate(job, "OUTPUT_LIMIT");
      } else {
        parts.push(data);
      }
    });
    child.once("close", (exitCode, signal) => {
      job.childClosed = true;
      const terminal = stopCode(job);
      if (terminal) resolve(rejected(terminal, job.sourceSha256));
      else if (exitCode !== 0 || signal) resolve(rejected("DECODER_FAILURE", job.sourceSha256));
      else resolve(frameResult(job, parts, size));
    });
    const terminal = stopCode(job);
    if (terminal) terminate(job, terminal);
    try { child.stdin.end(job.bytes); } catch { terminate(job, stopCode(job) ?? "DECODER_FAILURE"); }
  });
}

/** Internal byte-only reader. A decoded derivative is still unreviewed, incomplete evidence. */
export async function readStaticPng(input, options) {
  const started = performance.now();
  const normalized = optionsFrom(options);
  if (normalized.error) return rejected(normalized.error);
  if (normalized.signal && isAborted.call(normalized.signal)) return rejected("CANCELLED");
  const snapshot = inputFrom(input);
  if (snapshot.error) return rejected(snapshot.error);
  const deadline = started + normalized.timeoutMs;
  if (performance.now() >= deadline) return rejected("TIMEOUT", snapshot.sourceSha256);
  if (process.versions.node !== PNG_NODE_VERSION || process.versions.zlib !== PNG_ZLIB_VERSION) {
    return rejected("DECODER_UNAVAILABLE", snapshot.sourceSha256);
  }
  if (!isolationAvailable()) return rejected("ISOLATION_UNAVAILABLE", snapshot.sourceSha256);
  return enqueue({ ...snapshot, options: normalized, deadline });
}
