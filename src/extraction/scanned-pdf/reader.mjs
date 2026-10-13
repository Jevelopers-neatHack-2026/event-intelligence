import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { types } from "node:util";
import { fileURLToPath } from "node:url";
import profile from "./profile.json" with { type: "json" };

const CONFIG = Object.freeze({ ...profile });
const PRLIMIT = "/usr/bin/prlimit";
const WORKER = fileURLToPath(new URL("./worker.py", import.meta.url));
const DIRECTORY = path.dirname(WORKER);
const MANIFEST = fileURLToPath(new URL("../../../tools/scanned-pdf/runtime/manifest.json", import.meta.url));
const typedArray = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(typedArray, "byteLength").get;
const byteOffset = Object.getOwnPropertyDescriptor(typedArray, "byteOffset").get;
const arrayBuffer = Object.getOwnPropertyDescriptor(typedArray, "buffer").get;
const bufferLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;
const copyInto = Uint8Array.prototype.set;
const isAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted").get;
const addListener = EventTarget.prototype.addEventListener;
const removeListener = EventTarget.prototype.removeEventListener;
const utf8 = new TextDecoder("utf-8", { fatal: true });
const queue = [];
let active = 0;

export const SCANNED_PDF_LIMITS = Object.freeze(Object.fromEntries(
  Object.entries(CONFIG).filter(([key]) => key.startsWith("max") || key === "defaultTimeoutMs"),
));
export const SCANNED_PDF_ERRORS = Object.freeze([
  "INVALID_INPUT", "INPUT_TOO_LARGE", "INVALID_OPTIONS", "INVALID_LIMIT", "CANCELLED", "TIMEOUT",
  "QUEUE_FULL", "DECODER_UNAVAILABLE", "RUNTIME_MISMATCH", "ISOLATION_UNAVAILABLE", "DECODER_FAILURE",
  "PROTOCOL_ERROR", "OUTPUT_LIMIT", "PAGE_LIMIT", "DIMENSION_LIMIT", "PIXEL_LIMIT", "STRUCTURE_LIMIT",
  "MALFORMED_PDF", "UNSUPPORTED_PDF_FEATURE", "ENCRYPTED_PDF", "ACTIVE_CONTENT", "REMOTE_RESOURCE",
  "DAMAGED_IMAGE", "INCOMPLETE_RENDER",
]);
const ENGINE = Object.freeze({
  name: "PDFium", version: CONFIG.pdfiumVersion, bindings: "pypdfium2@" + CONFIG.wrapperVersion,
});
const hex = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const rejected = (code, sourceSha256) => Object.freeze({
  kind: "rejected", code, sourceSha256, profile: CONFIG.profile, engine: ENGINE,
});

function optionsFrom(options) {
  try {
    if (options === undefined) options = {};
    if (!options || typeof options !== "object" || types.isProxy(options) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(options))) return { error: "INVALID_OPTIONS" };
    const descriptors = Object.getOwnPropertyDescriptors(options);
    for (const key of Reflect.ownKeys(descriptors)) {
      if (!["signal", "timeoutMs", "maxOutputBytes", "deadlineAtMs"].includes(key) ||
          !Object.hasOwn(descriptors[key], "value")) return { error: "INVALID_OPTIONS" };
    }
    const signal = descriptors.signal?.value;
    if (signal !== undefined) {
      if (!signal || typeof signal !== "object" || types.isProxy(signal)) return { error: "INVALID_OPTIONS" };
      isAborted.call(signal);
    }
    const timeoutMs = descriptors.timeoutMs?.value ?? CONFIG.defaultTimeoutMs;
    const maxOutputBytes = descriptors.maxOutputBytes?.value ?? CONFIG.maxOutputBytes;
    const deadlineAtMs = descriptors.deadlineAtMs?.value;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > CONFIG.maxTimeoutMs ||
        !Number.isInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > CONFIG.maxOutputBytes ||
        descriptors.timeoutMs?.value === null || descriptors.maxOutputBytes?.value === null ||
        (deadlineAtMs !== undefined && (!Number.isFinite(deadlineAtMs) || deadlineAtMs < 0 || deadlineAtMs > Number.MAX_SAFE_INTEGER))) return { error: "INVALID_LIMIT" };
    return { signal, timeoutMs, maxOutputBytes, deadlineAtMs };
  } catch {
    return { error: "INVALID_OPTIONS" };
  }
}

function inputFrom(input) {
  try {
    if (!input || typeof input !== "object" || types.isProxy(input) ||
        ![Uint8Array.prototype, Buffer.prototype].includes(Object.getPrototypeOf(input))) return { error: "INVALID_INPUT" };
    const length = byteLength.call(input);
    if (length === 0) return { error: "INVALID_INPUT" };
    if (length > CONFIG.maxInputBytes) return { error: "INPUT_TOO_LARGE" };
    const backing = arrayBuffer.call(input);
    bufferLength.call(backing); // SharedArrayBuffer cannot supply stable source bytes.
    const bytes = Buffer.alloc(length);
    copyInto.call(bytes, new Uint8Array(backing, byteOffset.call(input), length));
    return { bytes, sourceSha256: hash(bytes) };
  } catch {
    return { error: "INVALID_INPUT" };
  }
}

function runtimeFromDisk() {
  try {
    if (process.platform !== "linux" || process.arch !== "x64") return { error: "ISOLATION_UNAVAILABLE" };
    const limiter = statSync(PRLIMIT);
    if (realpathSync(PRLIMIT) !== PRLIMIT || !limiter.isFile() || limiter.uid !== 0 ||
        !(limiter.mode & 0o111) || limiter.mode & 0o022) return { error: "ISOLATION_UNAVAILABLE" };
    const info = statSync(MANIFEST);
    if (!info.isFile() || info.size > 256 * 1024) return { error: "RUNTIME_MISMATCH" };
    const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
    const descriptor = manifest.descriptor;
    if (!descriptor || descriptor.schema !== 1 || descriptor.pythonVersion !== CONFIG.pythonVersion ||
        descriptor.platform !== "Linux" || descriptor.machine !== "x86_64" ||
        descriptor.startup?.isolated !== 1 || descriptor.startup?.noSite !== 1 || descriptor.startup?.dontWriteBytecode !== 1 ||
        descriptor.pdfiumVersion !== CONFIG.pdfiumVersion || !hex(manifest.closureSha256) ||
        typeof descriptor.python !== "string" || !path.isAbsolute(descriptor.python) ||
        !Array.isArray(descriptor.files) || descriptor.files.length < 1 || descriptor.files.length > 512) {
      return { error: "RUNTIME_MISMATCH" };
    }
    const python = realpathSync(descriptor.python);
    const matches = descriptor.files.filter((file) => file.path === python);
    const limiters = descriptor.files.filter((file) => file.path === PRLIMIT);
    const executable = statSync(python);
    if (limiters.length !== 1 || limiter.size > 4 * 1024 * 1024 || limiter.size !== limiters[0].bytes ||
        !hex(limiters[0].sha256) || hash(readFileSync(PRLIMIT)) !== limiters[0].sha256) {
      return { error: "RUNTIME_MISMATCH" };
    }
    if (python !== descriptor.python || matches.length !== 1 || !executable.isFile() ||
        !(executable.mode & 0o111) || executable.mode & 0o022 ||
        executable.size > 64 * 1024 * 1024 || executable.size !== matches[0].bytes ||
        !hex(matches[0].sha256) || hash(readFileSync(python)) !== matches[0].sha256) {
      return { error: "RUNTIME_MISMATCH" };
    }
    return { python, closureSha256: manifest.closureSha256 };
  } catch {
    return { error: "DECODER_UNAVAILABLE" };
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
  try { process.kill(-job.child.pid, "SIGKILL"); }
  catch { try { job.child.kill("SIGKILL"); } catch { /* Actual close remains mandatory. */ } }
}

function terminate(job, code) {
  if (job.state !== "running" || job.terminationCode) return;
  job.terminationCode = code;
  kill(job);
}

function pump() {
  while (active < CONFIG.maxConcurrency && queue.length) {
    const job = queue.shift();
    const code = stopCode(job);
    if (code) {
      finishQueued(job, code);
      continue;
    }
    active += 1;
    job.state = "running";
    runIsolated(job).then((result) => {
      const terminal = stopCode(job); // Includes queue, bootstrap, native work and parent verification.
      job.state = "finished";
      cleanup(job);
      active -= 1;
      job.resolve(terminal ? rejected(terminal, job.sourceSha256) : result);
      pump();
    });
  }
}

function enqueue(job) {
  if (active >= CONFIG.maxConcurrency && queue.length >= CONFIG.maxQueued) {
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

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function frameResult(job, chunks, size) {
  const bad = () => rejected("PROTOCOL_ERROR", job.sourceSha256);
  try {
    const frame = Buffer.concat(chunks, size);
    if (frame.length < 4) return bad();
    const headerLength = frame.readUInt32BE(0);
    if (headerLength < 2 || headerLength > CONFIG.maxHeaderBytes || headerLength + 4 > frame.length) return bad();
    const header = JSON.parse(utf8.decode(frame.subarray(4, 4 + headerLength)));
    const common = ["kind", "protocol", "profile", "pythonVersion", "pdfiumVersion", "sourceSha256",
      "closureSha256", "syscallPolicy", "enforcementControlsPassed", "maxOutputBytes"];
    if (!exactKeys(header, [...common, header.kind === "decoded" ? "pages" : "code"]) ||
        header.protocol !== CONFIG.protocol || header.profile !== CONFIG.profile ||
        header.pythonVersion !== CONFIG.pythonVersion || header.pdfiumVersion !== CONFIG.pdfiumVersion ||
        header.syscallPolicy !== CONFIG.syscallPolicy || header.maxOutputBytes !== job.options.maxOutputBytes ||
        ![0, 8].includes(header.enforcementControlsPassed)) return bad();
    const payload = frame.subarray(4 + headerLength);
    if (header.kind === "rejected") {
      if (payload.length || !SCANNED_PDF_ERRORS.includes(header.code) ||
          (header.sourceSha256 !== null && header.sourceSha256 !== job.sourceSha256) ||
          (header.closureSha256 !== null && header.closureSha256 !== job.runtime.closureSha256)) return bad();
      return rejected(header.code, job.sourceSha256);
    }
    if (header.kind !== "decoded" || header.sourceSha256 !== job.sourceSha256 ||
        header.closureSha256 !== job.runtime.closureSha256 || header.enforcementControlsPassed !== 8 ||
        !Array.isArray(header.pages) || header.pages.length < 1 || header.pages.length > CONFIG.maxPages) return bad();
    let offset = 0;
    let pixels = 0;
    const pages = [];
    for (const [index, page] of header.pages.entries()) {
      if (!exactKeys(page, ["page", "width", "height", "pageWidthPoints", "pageHeightPoints", "byteLength", "sha256"]) ||
          page.page !== index + 1 || !Number.isInteger(page.width) || !Number.isInteger(page.height) ||
          page.width < 1 || page.height < 1 || page.width > CONFIG.maxImageDimension || page.height > CONFIG.maxImageDimension ||
          page.width * page.height > CONFIG.maxPagePixels ||
          !Number.isFinite(page.pageWidthPoints) || !Number.isFinite(page.pageHeightPoints) ||
          page.pageWidthPoints <= 0 || page.pageHeightPoints <= 0 ||
          page.pageWidthPoints > CONFIG.maxPagePoints || page.pageHeightPoints > CONFIG.maxPagePoints ||
          page.byteLength !== page.width * page.height * 4 || !hex(page.sha256)) return bad();
      pixels += page.width * page.height;
      if (pixels > CONFIG.maxTotalPixels || offset + page.byteLength > payload.length) return bad();
      const bytes = Buffer.from(payload.subarray(offset, offset + page.byteLength));
      if (hash(bytes) !== page.sha256) return bad();
      for (let alpha = 3; alpha < bytes.length; alpha += 4) if (bytes[alpha] !== 255) return bad();
      offset += bytes.length;
      pages.push(Object.freeze({
        ...page, sourceSha256: job.sourceSha256, format: "rgba8", colorSpace: "device-rgb",
        coordinateSystem: "top-left-pixels", stride: page.width * 4,
        copyRgbaBytes() { return new Uint8Array(bytes); },
      }));
    }
    if (offset !== payload.length || offset > job.options.maxOutputBytes) return bad();
    return Object.freeze({
      kind: "decoded", completeness: "incomplete-pixels-only", requiresInspection: true,
      sourceSha256: job.sourceSha256, profile: CONFIG.profile, engine: ENGINE,
      pages: Object.freeze(pages), totalRgbaBytes: offset,
      limits: Object.freeze({ ...SCANNED_PDF_LIMITS, timeoutMs: job.options.timeoutMs, maxOutputBytes: job.options.maxOutputBytes }),
      syscallPolicy: CONFIG.syscallPolicy, enforcementControlsPassed: 8,
    });
  } catch { return bad(); }
}

function runIsolated(job) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(PRLIMIT, [
        "--as=" + CONFIG.maxAddressSpaceBytes + ":" + CONFIG.maxAddressSpaceBytes,
        "--cpu=" + CONFIG.maxCpuSeconds + ":" + CONFIG.maxCpuSeconds,
        "--core=0:0", "--nofile=" + CONFIG.maxOpenFiles + ":" + CONFIG.maxOpenFiles, "--",
        job.runtime.python, "-I", "-S", "-B", WORKER, "--render", String(job.options.maxOutputBytes),
      ], { cwd: DIRECTORY, env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
        detached: true, stdio: ["pipe", "pipe", "ignore"] });
    } catch {
      resolve(rejected("DECODER_FAILURE", job.sourceSha256));
      return;
    }
    job.child = child;
    const chunks = [];
    let size = 0;
    child.once("spawn", () => { if (job.terminationCode) kill(job); });
    child.once("error", () => terminate(job, stopCode(job) ?? "DECODER_FAILURE"));
    child.stdout.on("error", () => terminate(job, stopCode(job) ?? "DECODER_FAILURE"));
    child.stdin.on("error", () => terminate(job, stopCode(job) ?? "DECODER_FAILURE"));
    child.stdout.on("data", (data) => {
      if (job.terminationCode) return;
      size += data.length;
      if (size > job.options.maxOutputBytes + CONFIG.maxHeaderBytes + 4) terminate(job, "OUTPUT_LIMIT");
      else chunks.push(data);
    });
    child.once("close", (exitCode, signal) => {
      job.childClosed = true;
      const terminal = stopCode(job);
      if (terminal) resolve(rejected(terminal, job.sourceSha256));
      else if (exitCode !== 0 || signal) resolve(rejected("DECODER_FAILURE", job.sourceSha256));
      else resolve(frameResult(job, chunks, size));
    });
    const terminal = stopCode(job);
    if (terminal) terminate(job, terminal);
    try { child.stdin.end(job.bytes); } catch { terminate(job, stopCode(job) ?? "DECODER_FAILURE"); }
  });
}

/** Private byte-only raster observation. It neither performs OCR nor accepts event facts. */
export async function readScannedPdf(input, options) {
  const started = performance.now();
  const normalized = optionsFrom(options);
  if (normalized.error) return rejected(normalized.error);
  if (normalized.signal && isAborted.call(normalized.signal)) return rejected("CANCELLED");
  // Same-process performance.now() deadline is lower-only, including a delayed
  // caller handoff. It never grants a fresh duration to the next component.
  const deadline = Math.min(started + normalized.timeoutMs, normalized.deadlineAtMs ?? Infinity);
  if (performance.now() >= deadline) return rejected("TIMEOUT");
  const snapshot = inputFrom(input);
  if (snapshot.error) return rejected(snapshot.error);
  if (performance.now() >= deadline) return rejected("TIMEOUT", snapshot.sourceSha256);
  if (process.versions.node !== CONFIG.nodeVersion) return rejected("DECODER_UNAVAILABLE", snapshot.sourceSha256);
  const runtime = runtimeFromDisk();
  if (performance.now() >= deadline) return rejected("TIMEOUT", snapshot.sourceSha256);
  if (runtime.error) return rejected(runtime.error, snapshot.sourceSha256);
  return enqueue({ ...snapshot, options: normalized, runtime, deadline });
}
