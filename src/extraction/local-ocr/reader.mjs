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
const MANIFEST = fileURLToPath(new URL("../../../tools/local-ocr/runtime/manifest.json", import.meta.url));
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

export const LOCAL_OCR_LIMITS = Object.freeze(Object.fromEntries(
  Object.entries(CONFIG).filter(([key]) => key.startsWith("max") || key === "defaultTimeoutMs"),
));
export const LOCAL_OCR_ERRORS = Object.freeze([
  "INVALID_INPUT", "INVALID_PROVENANCE", "INPUT_TOO_LARGE", "DIMENSION_LIMIT", "PIXEL_LIMIT", "UNSUPPORTED_RASTER",
  "INVALID_OPTIONS", "INVALID_LIMIT", "CANCELLED", "TIMEOUT", "QUEUE_FULL", "OCR_UNAVAILABLE", "RUNTIME_MISMATCH",
  "MODEL_UNAVAILABLE", "ISOLATION_UNAVAILABLE", "OCR_FAILURE", "PROTOCOL_ERROR", "OUTPUT_LIMIT", "INVALID_OCR_OUTPUT",
]);
const ENGINE = Object.freeze({ name: "Tesseract", version: CONFIG.tesseractVersion, language: "eng",
  modelSha256: CONFIG.modelSha256, oem: 1, pageSegmentationMode: 6 });
const hex = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const hash = (value) => createHash("sha256").update(value).digest("hex");
const rejected = (code, provenance) => Object.freeze({ kind: "rejected", code, provenance,
  profile: CONFIG.profile, engine: ENGINE });

function valuesFrom(value, keys) {
  if (!value || typeof value !== "object" || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return undefined;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result = {};
  for (const key of Reflect.ownKeys(descriptors)) {
    if (!keys.includes(key) || !Object.hasOwn(descriptors[key], "value")) return undefined;
    result[key] = descriptors[key].value;
  }
  return result;
}

function optionsFrom(options) {
  try {
    const values = valuesFrom(options === undefined ? {} : options, ["signal", "timeoutMs", "maxTextBytes", "maxWords"]);
    if (!values) return { error: "INVALID_OPTIONS" };
    const signal = values.signal;
    if (signal !== undefined) {
      if (!signal || typeof signal !== "object" || types.isProxy(signal)) return { error: "INVALID_OPTIONS" };
      isAborted.call(signal);
    }
    const timeoutMs = values.timeoutMs === undefined ? CONFIG.defaultTimeoutMs : values.timeoutMs;
    const maxTextBytes = values.maxTextBytes === undefined ? CONFIG.maxTextBytes : values.maxTextBytes;
    const maxWords = values.maxWords === undefined ? CONFIG.maxWords : values.maxWords;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > CONFIG.maxTimeoutMs ||
        !Number.isInteger(maxTextBytes) || maxTextBytes < 1 || maxTextBytes > CONFIG.maxTextBytes ||
        !Number.isInteger(maxWords) || maxWords < 1 || maxWords > CONFIG.maxWords) return { error: "INVALID_LIMIT" };
    return { signal, timeoutMs, maxTextBytes, maxWords };
  } catch { return { error: "INVALID_OPTIONS" }; }
}

function inputFrom(input) {
  try {
    const values = valuesFrom(input, ["bytes", "width", "height", "format", "source"]);
    if (!values || Object.keys(values).length !== 5) return { error: "INVALID_INPUT" };
    const { width, height, format } = values;
    if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1) return { error: "INVALID_INPUT" };
    if (width > CONFIG.maxDimension || height > CONFIG.maxDimension) return { error: "DIMENSION_LIMIT" };
    if (width * height > CONFIG.maxPixels) return { error: "PIXEL_LIMIT" };
    if (!["gray8", "rgba8"].includes(format)) return { error: "UNSUPPORTED_RASTER" };
    const source = valuesFrom(values.source, ["sha256", "page", "derivativeSha256"]);
    if (!source || Object.keys(source).length !== 3 || !hex(source.sha256) || !hex(source.derivativeSha256) ||
        !Number.isInteger(source.page) || source.page < 1 || source.page > CONFIG.maxPageNumber) return { error: "INVALID_PROVENANCE" };
    const inputBytes = values.bytes;
    if (!inputBytes || typeof inputBytes !== "object" || types.isProxy(inputBytes) ||
        ![Uint8Array.prototype, Buffer.prototype].includes(Object.getPrototypeOf(inputBytes))) return { error: "INVALID_INPUT" };
    const length = byteLength.call(inputBytes);
    if (length > CONFIG.maxInputBytes) return { error: "INPUT_TOO_LARGE" };
    const channels = format === "gray8" ? 1 : 4;
    if (length !== width * height * channels) return { error: "INVALID_INPUT" };
    const backing = arrayBuffer.call(inputBytes);
    bufferLength.call(backing); // Stable snapshots reject SharedArrayBuffer backing.
    const bytes = Buffer.alloc(length);
    copyInto.call(bytes, new Uint8Array(backing, byteOffset.call(inputBytes), length));
    if (channels === 4) for (let offset = 3; offset < bytes.length; offset += 4) {
      if (bytes[offset] !== 255) return { error: "UNSUPPORTED_RASTER" };
    }
    const rasterSha256 = hash(bytes);
    if (source.derivativeSha256 !== rasterSha256) return { error: "INVALID_PROVENANCE" };
    const provenance = Object.freeze({ sourceSha256: source.sha256, page: source.page,
      derivativeSha256: rasterSha256, width, height, format, coordinateSystem: "top-left-pixels",
      sourceBinding: "caller-supplied-unverified" });
    return { bytes, width, height, format, rasterSha256, provenance };
  } catch { return { error: "INVALID_INPUT" }; }
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
        descriptor.threadPolicy?.OMP_THREAD_LIMIT !== "1" || descriptor.threadPolicy?.OMP_NUM_THREADS !== "1" ||
        descriptor.tesseractVersion !== CONFIG.tesseractVersion || descriptor.leptonicaVersion !== CONFIG.leptonicaVersion ||
        descriptor.modelSha256 !== CONFIG.modelSha256 || !hex(manifest.closureSha256) ||
        typeof descriptor.python !== "string" || !path.isAbsolute(descriptor.python) ||
        !Array.isArray(descriptor.files) || descriptor.files.length < 1 || descriptor.files.length > 512) return { error: "RUNTIME_MISMATCH" };
    const python = realpathSync(descriptor.python);
    const matches = descriptor.files.filter((file) => file.path === python);
    const limiters = descriptor.files.filter((file) => file.path === PRLIMIT);
    const executable = statSync(python);
    if (limiters.length !== 1 || limiter.size > 4 * 1024 * 1024 || limiter.size !== limiters[0].bytes ||
        !hex(limiters[0].sha256) || hash(readFileSync(PRLIMIT)) !== limiters[0].sha256) return { error: "RUNTIME_MISMATCH" };
    if (python !== descriptor.python || matches.length !== 1 || !executable.isFile() ||
        !(executable.mode & 0o111) || executable.mode & 0o022 || executable.size > 64 * 1024 * 1024 ||
        executable.size !== matches[0].bytes || !hex(matches[0].sha256) || hash(readFileSync(python)) !== matches[0].sha256) return { error: "RUNTIME_MISMATCH" };
    return { python, closureSha256: manifest.closureSha256 };
  } catch { return { error: "OCR_UNAVAILABLE" }; }
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
  job.resolve(rejected(code, job.provenance));
}

function kill(job) {
  if (!job.child?.pid || job.childClosed) return;
  try { process.kill(-job.child.pid, "SIGKILL"); }
  catch { try { job.child.kill("SIGKILL"); } catch { /* The real close event remains required. */ } }
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
    if (code) { finishQueued(job, code); continue; }
    active += 1;
    job.state = "running";
    runIsolated(job).then((result) => {
      const terminal = stopCode(job); // Includes synchronous parent verification after native close.
      job.state = "finished";
      cleanup(job);
      active -= 1;
      job.resolve(terminal ? rejected(terminal, job.provenance) : result);
      pump();
    });
  }
}

function enqueue(job) {
  if (active >= CONFIG.maxConcurrency && queue.length >= CONFIG.maxQueued) return Promise.resolve(rejected("QUEUE_FULL", job.provenance));
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
  const bad = () => rejected("PROTOCOL_ERROR", job.provenance);
  try {
    const value = JSON.parse(utf8.decode(Buffer.concat(chunks, size)));
    if (value.kind === "rejected") {
      if (!exactKeys(value, ["kind", "protocol", "profile", "code", "rasterSha256", "closureSha256", "enforcementControlsPassed"]) ||
          value.protocol !== CONFIG.protocol || value.profile !== CONFIG.profile || !LOCAL_OCR_ERRORS.includes(value.code) ||
          ![0, 8].includes(value.enforcementControlsPassed) ||
          (value.rasterSha256 !== null && value.rasterSha256 !== job.rasterSha256) ||
          (value.closureSha256 !== null && value.closureSha256 !== job.runtime.closureSha256)) return bad();
      return rejected(value.code, job.provenance);
    }
    if (!exactKeys(value, ["kind", "protocol", "profile", "tesseractVersion", "modelSha256", "closureSha256", "syscallPolicy",
      "enforcementControlsPassed", "rasterSha256", "width", "height", "format", "maxTextBytes", "maxWords", "tokenUtf8Bytes", "words"]) ||
        value.kind !== "observed" || value.protocol !== CONFIG.protocol || value.profile !== CONFIG.profile ||
        value.tesseractVersion !== CONFIG.tesseractVersion || value.modelSha256 !== CONFIG.modelSha256 ||
        value.closureSha256 !== job.runtime.closureSha256 || value.syscallPolicy !== CONFIG.syscallPolicy ||
        value.enforcementControlsPassed !== 8 || value.rasterSha256 !== job.rasterSha256 ||
        value.width !== job.width || value.height !== job.height || value.format !== job.format ||
        value.maxTextBytes !== job.options.maxTextBytes || value.maxWords !== job.options.maxWords ||
        !Array.isArray(value.words) || value.words.length > job.options.maxWords) return bad();
    let count = 0;
    let prior = [0, 0, 0, 0];
    const words = [];
    for (const word of value.words) {
      if (!exactKeys(word, ["text", "confidence", "block", "paragraph", "line", "word", "box"]) ||
          typeof word.text !== "string" || !word.text.length || !word.text.isWellFormed() || /[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/u.test(word.text) ||
          !Number.isFinite(word.confidence) || word.confidence < 0 || word.confidence > 100 ||
          !exactKeys(word.box, ["left", "top", "width", "height"])) return bad();
      const identity = [word.block, word.paragraph, word.line, word.word];
      if (identity.some((part) => !Number.isInteger(part) || part < 1 || part > CONFIG.maxWords)) return bad();
      let comparison = 0;
      for (let index = 0; index < 4; index += 1) if (identity[index] !== prior[index]) {
        comparison = identity[index] - prior[index]; break;
      }
      if (comparison <= 0) return bad();
      prior = identity;
      const box = word.box;
      if (Object.values(box).some((part) => !Number.isInteger(part)) || box.left < 0 || box.top < 0 ||
          box.width < 1 || box.height < 1 || box.left + box.width > job.width || box.top + box.height > job.height) return bad();
      count += Buffer.byteLength(word.text, "utf8");
      if (count > job.options.maxTextBytes) return bad();
      words.push(Object.freeze({ ...word, box: Object.freeze({ ...box }), provenance: job.provenance,
        confidenceMeaning: "uncalibrated-engine-score", requiresReview: true }));
    }
    if (value.tokenUtf8Bytes !== count) return bad();
    return Object.freeze({ kind: "observed", status: words.length ? "text-observations" : "no-text-observed",
      completeness: "incomplete-unverified-ocr", requiresReview: true, profile: CONFIG.profile, engine: ENGINE,
      provenance: job.provenance, words: Object.freeze(words), tokenUtf8Bytes: count,
      syscallPolicy: CONFIG.syscallPolicy, enforcementControlsPassed: 8,
      limits: Object.freeze({ ...LOCAL_OCR_LIMITS, timeoutMs: job.options.timeoutMs,
        maxTextBytes: job.options.maxTextBytes, maxWords: job.options.maxWords }) });
  } catch { return bad(); }
}

function runIsolated(job) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(PRLIMIT, ["--as=" + CONFIG.maxAddressSpaceBytes + ":" + CONFIG.maxAddressSpaceBytes,
        "--cpu=" + CONFIG.maxCpuSeconds + ":" + CONFIG.maxCpuSeconds, "--core=0:0",
        "--nofile=" + CONFIG.maxOpenFiles + ":" + CONFIG.maxOpenFiles, "--", job.runtime.python,
        "-I", "-S", "-B", WORKER, "--recognize"], {
        cwd: path.dirname(WORKER), env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8",
          OMP_THREAD_LIMIT: "1", OMP_NUM_THREADS: "1" }, detached: true, stdio: ["pipe", "pipe", "ignore"],
      });
    } catch { resolve(rejected("OCR_FAILURE", job.provenance)); return; }
    job.child = child;
    const chunks = [];
    let size = 0;
    child.once("spawn", () => { if (stopCode(job)) terminate(job, stopCode(job)); if (job.terminationCode) kill(job); });
    child.once("error", () => terminate(job, stopCode(job) ?? "OCR_FAILURE"));
    child.stdout.on("error", () => terminate(job, stopCode(job) ?? "OCR_FAILURE"));
    child.stdin.on("error", () => terminate(job, stopCode(job) ?? "OCR_FAILURE"));
    child.stdout.on("data", (data) => {
      const terminal = stopCode(job);
      if (terminal) { terminate(job, terminal); return; }
      size += data.length;
      if (size > CONFIG.maxOutputBytes) terminate(job, "OUTPUT_LIMIT");
      else chunks.push(data);
    });
    child.once("close", (exitCode, signal) => {
      job.childClosed = true;
      const terminal = stopCode(job);
      if (terminal) resolve(rejected(terminal, job.provenance));
      else if (exitCode !== 0 || signal) resolve(rejected("OCR_FAILURE", job.provenance));
      else resolve(frameResult(job, chunks, size));
    });
    const header = Buffer.from(JSON.stringify({ width: job.width, height: job.height, format: job.format,
      rasterSha256: job.rasterSha256, maxTextBytes: job.options.maxTextBytes, maxWords: job.options.maxWords }));
    const length = Buffer.alloc(4);
    length.writeUInt32BE(header.length);
    const terminal = stopCode(job);
    if (terminal) terminate(job, terminal);
    try { child.stdin.end(Buffer.concat([length, header, job.bytes])); }
    catch { terminate(job, stopCode(job) ?? "OCR_FAILURE"); }
  });
}

/** Private supplied-pixel OCR. Every word remains an uncertain, unverified observation. */
export async function readLocalOcr(input, options) {
  const started = performance.now();
  const normalized = optionsFrom(options);
  if (normalized.error) return rejected(normalized.error);
  if (normalized.signal && isAborted.call(normalized.signal)) return rejected("CANCELLED");
  const snapshot = inputFrom(input);
  if (snapshot.error) return rejected(snapshot.error);
  const deadline = started + normalized.timeoutMs;
  if (performance.now() >= deadline) return rejected("TIMEOUT", snapshot.provenance);
  if (process.versions.node !== CONFIG.nodeVersion) return rejected("OCR_UNAVAILABLE", snapshot.provenance);
  const runtime = runtimeFromDisk();
  if (performance.now() >= deadline) return rejected("TIMEOUT", snapshot.provenance);
  if (runtime.error) return rejected(runtime.error, snapshot.provenance);
  return enqueue({ ...snapshot, options: normalized, runtime, deadline });
}
