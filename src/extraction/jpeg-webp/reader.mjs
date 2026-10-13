import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { types } from "node:util";
import { fileURLToPath } from "node:url";
import { RASTER_CONFIG_VERSION, RASTER_DECODER, RASTER_ERROR_CODES, RASTER_LIMITS,
  RASTER_NODE_VERSION, RASTER_PROTOCOL, RASTER_RUNTIME_SCHEMA, RASTER_WHEEL_SHA256 } from "./constants.mjs";
import { inspectStaticRasterProfile } from "./profile.mjs";
import { normalizeRgba, normalizedPngLength } from "./rgba-png.mjs";

const PRLIMIT = "/usr/bin/prlimit";
const WORKER = fileURLToPath(new URL("./decode-worker.py", import.meta.url));
const WORKER_DIRECTORY = path.dirname(WORKER);
const typedArray = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(typedArray, "byteLength").get;
const byteOffset = Object.getOwnPropertyDescriptor(typedArray, "byteOffset").get;
const arrayBuffer = Object.getOwnPropertyDescriptor(typedArray, "buffer").get;
const bufferLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;
const copyInto = Uint8Array.prototype.set;
const isAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted").get;
const addListener = EventTarget.prototype.addEventListener;
const removeListener = EventTarget.prototype.removeEventListener;
const queue = [];
let activeWorkers = 0; // Shared across factories in this canonical module instance.

export const STATIC_JPEG_WEBP_READER_LIMITS = RASTER_LIMITS;

function rejected(code, sourceSha256) {
  return Object.freeze({ kind: "rejected", code, sourceSha256, decoder: RASTER_DECODER });
}
function record(value, allowed) {
  if (!value || typeof value !== "object" || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return undefined;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(descriptors)) {
    if (!allowed.includes(key) || !Object.hasOwn(descriptors[key], "value")) return undefined;
  }
  return descriptors;
}
function optionsFrom(options) {
  try {
    const descriptors = record(options === undefined ? {} : options, ["signal", "timeoutMs", "maxOutputBytes"]);
    if (!descriptors) return { error: "INVALID_OPTIONS" };
    const signal = descriptors.signal?.value;
    if (signal !== undefined) {
      if (!signal || typeof signal !== "object" || types.isProxy(signal)) return { error: "INVALID_OPTIONS" };
      isAborted.call(signal);
    }
    const timeoutMs = descriptors.timeoutMs?.value ?? RASTER_LIMITS.defaultTimeoutMs;
    const maxOutputBytes = descriptors.maxOutputBytes?.value ?? RASTER_LIMITS.maxOutputBytes;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > RASTER_LIMITS.maxTimeoutMs ||
        !Number.isInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > RASTER_LIMITS.maxOutputBytes ||
        descriptors.timeoutMs?.value === null || descriptors.maxOutputBytes?.value === null) return { error: "INVALID_LIMIT" };
    return { signal, timeoutMs, maxOutputBytes };
  } catch { return { error: "INVALID_OPTIONS" }; }
}
function snapshot(input) {
  try {
    if (!input || typeof input !== "object" || types.isProxy(input) ||
        ![Uint8Array.prototype, Buffer.prototype].includes(Object.getPrototypeOf(input))) return { error: "INVALID_INPUT" };
    const length = byteLength.call(input);
    if (length === 0) return { error: "INVALID_INPUT" };
    if (length > RASTER_LIMITS.maxInputBytes) return { error: "INPUT_TOO_LARGE" };
    const backing = arrayBuffer.call(input);
    bufferLength.call(backing); // Native brand rejects SharedArrayBuffer.
    const view = new Uint8Array(backing, byteOffset.call(input), length);
    const bytes = Buffer.alloc(length);
    copyInto.call(bytes, view);
    return { bytes, sourceSha256: createHash("sha256").update(bytes).digest("hex") };
  } catch { return { error: "INVALID_INPUT" }; }
}
function isolationAvailable() {
  if (process.platform !== "linux" || process.arch !== "x64") return false;
  try {
    const resolved = realpathSync(PRLIMIT), stat = statSync(resolved);
    return resolved === PRLIMIT && stat.isFile() && stat.uid === 0 &&
      (stat.mode & 0o111) !== 0 && (stat.mode & 0o022) === 0;
  } catch { return false; }
}
function runtimeFrom(directory) {
  try {
    if (realpathSync(directory) !== directory) return undefined;
    const marker = path.join(directory, "runtime.json");
    const stat = lstatSync(marker);
    if (!stat.isFile() || stat.size < 1 || stat.size > RASTER_LIMITS.maxRuntimeManifestBytes) return undefined;
    const bytes = readFileSync(marker);
    if (bytes.length !== stat.size) return undefined;
    const manifest = JSON.parse(bytes.toString("utf8"));
    const python = path.join(directory, "bin", "python");
    if (manifest.schema !== RASTER_RUNTIME_SCHEMA || manifest.pythonVersion !== RASTER_DECODER.pythonVersion ||
        manifest.pillowVersion !== RASTER_DECODER.pillowVersion || manifest.wheelSha256 !== RASTER_WHEEL_SHA256 ||
        manifest.architecture !== "x86_64" || manifest.implementation !== "CPython" ||
        realpathSync(python) !== manifest.pythonExecutable || !statSync(python).isFile()) return undefined;
    return { python, manifestSha256: createHash("sha256").update(bytes).digest("hex") };
  } catch { return undefined; }
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
  const at = queue.indexOf(job);
  if (at >= 0) queue.splice(at, 1);
  job.state = "finished";
  cleanup(job);
  job.resolve(rejected(code, job.sourceSha256));
}
function kill(job) {
  if (!job.child?.pid || job.childClosed) return;
  try { process.kill(-job.child.pid, "SIGKILL"); }
  catch { try { job.child.kill("SIGKILL"); } catch { /* Keep the slot until actual close. */ } }
}
function terminate(job, code) {
  if (job.state !== "running" || job.terminationCode) return;
  job.terminationCode = code;
  kill(job);
}
function complete(job, result) {
  // A returned frame, hashing and normalization never renew the original budget.
  const terminal = stopCode(job);
  job.state = "finished";
  cleanup(job);
  activeWorkers -= 1;
  job.resolve(terminal ? rejected(terminal, job.sourceSha256) : result);
  queueMicrotask(pump); // Do not start another synchronous admission before delivery.
}
function pump() {
  while (activeWorkers < RASTER_LIMITS.maxConcurrency && queue.length > 0) {
    const job = queue.shift();
    const code = stopCode(job);
    if (code) { finishQueued(job, code); continue; }
    job.state = "running";
    activeWorkers += 1;
    runIsolated(job).then((result) => complete(job, result));
  }
}
function enqueue(job) {
  if (activeWorkers >= RASTER_LIMITS.maxConcurrency && queue.length >= RASTER_LIMITS.maxQueued) {
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

function frameResult(job, parts, size) {
  const bad = () => rejected("PROTOCOL_ERROR", job.sourceSha256);
  try {
    const frame = Buffer.concat(parts, size);
    if (frame.length < 4) return bad();
    const length = frame.readUInt32BE(0);
    if (length < 2 || length > RASTER_LIMITS.maxHeaderBytes || length + 4 > frame.length) return bad();
    const raw = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(frame.subarray(4, 4 + length));
    const header = JSON.parse(raw);
    if (!header || typeof header !== "object" || Array.isArray(header)) return bad();
    const canonical = JSON.stringify(Object.fromEntries(Object.entries(header).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)));
    if (canonical !== raw) return bad(); // Reject duplicate keys and noncanonical framing.
    const common = ["protocol", "configVersion", "pythonVersion", "pillowVersion", "jpegVersion", "webpVersion",
      "wheelSha256", "runtimeManifestSha256", "sourceSha256", "networkApiAttemptCount", "decodedRgbaBytes", "kind"];
    const keys = [...common, ...(header.kind === "decoded"
      ? ["sourceFormat", "encoding", "width", "height", "sourceMode", "frames", "rgbaSha256"] : ["code"])];
    if (Object.keys(header).length !== keys.length || !keys.every((key) => Object.hasOwn(header, key)) ||
        header.protocol !== RASTER_PROTOCOL || header.configVersion !== RASTER_CONFIG_VERSION ||
        header.pythonVersion !== RASTER_DECODER.pythonVersion || header.pillowVersion !== RASTER_DECODER.pillowVersion ||
        header.jpegVersion !== RASTER_DECODER.jpegVersion || header.webpVersion !== RASTER_DECODER.webpVersion ||
        header.wheelSha256 !== RASTER_WHEEL_SHA256 || header.runtimeManifestSha256 !== job.runtime.manifestSha256 ||
        header.sourceSha256 !== job.sourceSha256 || !Number.isSafeInteger(header.networkApiAttemptCount) ||
        header.networkApiAttemptCount < 0) return bad();
    const pixels = frame.subarray(4 + length);
    if (header.kind === "rejected") {
      if (pixels.length !== 0 || header.decodedRgbaBytes !== 0 || !RASTER_ERROR_CODES.includes(header.code)) return bad();
      return rejected(header.networkApiAttemptCount === 0 ? header.code : "REMOTE_RESOURCE_ATTEMPT", job.sourceSha256);
    }
    if (header.kind !== "decoded" || Object.entries(job.profile).some(([key, value]) => header[key] !== value) ||
        header.decodedRgbaBytes !== job.profile.width * job.profile.height * 4 || pixels.length !== header.decodedRgbaBytes ||
        typeof header.rgbaSha256 !== "string" || !/^[a-f0-9]{64}$/.test(header.rgbaSha256) ||
        createHash("sha256").update(pixels).digest("hex") !== header.rgbaSha256) return bad();
    if (header.networkApiAttemptCount !== 0) return rejected("REMOTE_RESOURCE_ATTEMPT", job.sourceSha256);
    const terminal = stopCode(job);
    if (terminal) return rejected(terminal, job.sourceSha256);
    const result = normalizeRgba(pixels, header.width, header.height, job.options.maxOutputBytes);
    if (result.kind !== "normalized") return rejected(result.code, job.sourceSha256);
    const normalized = result.normalized;
    // Retain only owned samples, not the framed worker buffer. The original
    // deadline is checked again by complete() after this bounded copy.
    const rgba = Buffer.from(pixels);
    return Object.freeze({
      kind: "decoded", completeness: "incomplete-pixels-only", requiresInspection: true,
      sourceSha256: job.sourceSha256, decoder: RASTER_DECODER,
      runtimeManifestSha256: job.runtime.manifestSha256, ...job.profile,
      limits: Object.freeze({ ...RASTER_LIMITS, timeoutMs: job.options.timeoutMs, maxOutputBytes: job.options.maxOutputBytes }),
      outputColorType: 6, decodedRgbaBytes: pixels.length, rgbaSha256: result.rgbaSha256,
      normalizedSha256: result.normalizedSha256, normalizedByteLength: normalized.length,
      networkApiAttemptCount: 0,
      copyNormalizedBytes() { return new Uint8Array(normalized); },
      copyRgbaBytes() { return new Uint8Array(rgba); },
    });
  } catch { return bad(); }
}
function runIsolated(job) {
  return new Promise((resolve) => {
    job.runtime = runtimeFrom(job.runtimeDirectory);
    if (!job.runtime) { resolve(rejected("DECODER_UNAVAILABLE", job.sourceSha256)); return; }
    const terminal = stopCode(job);
    if (terminal) { resolve(rejected(terminal, job.sourceSha256)); return; }
    let child;
    try {
      child = spawn(PRLIMIT, [
        "--as=" + RASTER_LIMITS.maxAddressSpaceBytes, "--cpu=" + RASTER_LIMITS.maxCpuSeconds,
        "--core=0", "--fsize=0", "--nofile=" + RASTER_LIMITS.maxOpenFiles, "--",
        job.runtime.python, "-I", "-S", "-B", WORKER, job.runtimeDirectory, job.runtime.manifestSha256,
        JSON.stringify({ sourceSha256: job.sourceSha256, profile: job.profile, maxOutputBytes: job.options.maxOutputBytes }),
      ], { cwd: WORKER_DIRECTORY, env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
        detached: true, stdio: ["pipe", "pipe", "pipe"] });
    } catch { resolve(rejected("DECODER_FAILURE", job.sourceSha256)); return; }
    job.child = child;
    const parts = [];
    let size = 0, stderrBytes = 0;
    child.once("spawn", () => {
      const code = stopCode(job);
      if (code) { terminate(job, code); kill(job); return; }
      try { child.stdin.end(job.bytes); }
      catch { terminate(job, stopCode(job) ?? "DECODER_FAILURE"); }
    });
    child.once("error", () => terminate(job, stopCode(job) ?? "DECODER_FAILURE"));
    child.stdin.on("error", () => terminate(job, stopCode(job) ?? "DECODER_FAILURE"));
    child.stdout.on("error", () => terminate(job, stopCode(job) ?? "DECODER_FAILURE"));
    child.stderr.on("error", () => terminate(job, stopCode(job) ?? "DECODER_FAILURE"));
    child.stdout.on("data", (data) => {
      const code = stopCode(job);
      if (code) { terminate(job, code); return; }
      size += data.length;
      if (size > job.profile.width * job.profile.height * 4 + RASTER_LIMITS.maxHeaderBytes + 4) terminate(job, "OUTPUT_LIMIT");
      else parts.push(data);
    });
    child.stderr.on("data", (data) => {
      stderrBytes += data.length;
      if (stderrBytes > RASTER_LIMITS.maxStderrBytes) terminate(job, "OUTPUT_LIMIT");
    });
    child.once("close", (exitCode, signal) => {
      job.childClosed = true;
      const code = stopCode(job);
      if (code) resolve(rejected(code, job.sourceSha256));
      else if (exitCode !== 0 || signal || stderrBytes !== 0) resolve(rejected("DECODER_FAILURE", job.sourceSha256));
      else resolve(frameResult(job, parts, size));
    });
  });
}

/** Trusted host configuration is separate from untrusted input bytes/options. */
export function createStaticJpegWebpReader(configuration) {
  let runtimeDirectory;
  try {
    const descriptors = record(configuration, ["runtimeDirectory"]);
    runtimeDirectory = descriptors?.runtimeDirectory?.value;
    if (typeof runtimeDirectory !== "string" || runtimeDirectory.length > 4096 || runtimeDirectory.includes("\0") ||
        !path.isAbsolute(runtimeDirectory) || path.resolve(runtimeDirectory) !== runtimeDirectory) throw new Error();
  } catch { throw new TypeError("An explicit canonical static JPEG/WebP runtime directory is required"); }
  return Object.freeze({
    read(input, options) {
      const started = performance.now();
      const normalized = optionsFrom(options);
      const refuse = (code, sha) => Promise.resolve(rejected(code, sha));
      if (normalized.error) return refuse(normalized.error);
      if (normalized.signal && isAborted.call(normalized.signal)) return refuse("CANCELLED");
      const copied = snapshot(input);
      if (copied.error) return refuse(copied.error);
      const deadline = started + normalized.timeoutMs;
      const inspected = inspectStaticRasterProfile(copied.bytes);
      if (performance.now() >= deadline) return refuse("TIMEOUT", copied.sourceSha256);
      if (inspected.kind === "rejected") return refuse(inspected.code, copied.sourceSha256);
      if (normalizedPngLength(inspected.profile.width, inspected.profile.height) > normalized.maxOutputBytes) return refuse("OUTPUT_LIMIT", copied.sourceSha256);
      if (process.versions.node !== RASTER_NODE_VERSION) return refuse("DECODER_UNAVAILABLE", copied.sourceSha256);
      if (!isolationAvailable()) return refuse("ISOLATION_UNAVAILABLE", copied.sourceSha256);
      return enqueue({ ...copied, profile: inspected.profile, runtimeDirectory, options: normalized, deadline });
    },
  });
}
