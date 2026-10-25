import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync, realpathSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { types } from "node:util";
import path from "node:path";

import { PDF_DECODER_VERSION, PDF_LIMITS, PDF_READER_CONFIG_VERSION } from "./constants.mjs";

const PRLIMIT_PATH = "/usr/bin/prlimit";
const WORKER_PATH = fileURLToPath(new URL("./decode-worker.mjs", import.meta.url));
const ADDRESS_SPACE_BYTES = 6 * 1024 * 1024 * 1024;
const MAX_CPU_SECONDS = 15;
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_TIMEOUT_MS = 20_000;
const MAX_OUTPUT_BYTES = PDF_LIMITS.maxOutputBytes;
const MAX_TEXT_CODE_UNITS = PDF_LIMITS.maxTextCodeUnits;
const MAX_CONCURRENCY = 1;
const MAX_QUEUED = 4;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength").get;
const byteOffset = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteOffset").get;
const arrayBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer").get;
const bufferLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;
const copyInto = Uint8Array.prototype.set;

const queue = [];
let activeWorkers = 0;

const ERROR_CODES = Object.freeze({
  invalid_input: "INVALID_INPUT",
  input_limit: "INPUT_TOO_LARGE",
  invalid_limit: "INVALID_LIMIT",
  malformed_pdf: "MALFORMED_PDF",
  encrypted_pdf: "ENCRYPTED_PDF",
  active_or_unsupported_feature: "ACTIVE_PDF_FEATURE",
  remote_reference: "REMOTE_REFERENCE",
  unsupported_pdf_feature: "UNSUPPORTED_PDF_FEATURE",
  remote_resource_attempt: "REMOTE_RESOURCE_ATTEMPT",
  page_limit: "PAGE_LIMIT",
  dimension_limit: "DIMENSION_LIMIT",
  text_limit: "TEXT_LIMIT",
  output_limit: "OUTPUT_LIMIT",
  structure_limit: "RESOURCE_LIMIT",
  invalid_geometry: "MALFORMED_PDF",
  no_pages: "MALFORMED_PDF",
  decoder_version_mismatch: "DECODER_UNAVAILABLE",
  decoder_failure: "DECODER_FAILURE",
});

function freeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function baseResult(documentSha256) {
  return {
    documentSha256,
    decoder: {
      name: "pdfjs-dist",
      version: PDF_DECODER_VERSION,
      configVersion: PDF_READER_CONFIG_VERSION,
    },
  };
}

function rejected(code, documentSha256, details = {}) {
  return freeze({ kind: "rejected", code, ...baseResult(documentSha256), ...details });
}

function isolationAvailable() {
  if (process.platform !== "linux" || !existsSync(PRLIMIT_PATH)) return false;
  try {
    const actual = realpathSync(PRLIMIT_PATH);
    const details = statSync(actual);
    return (
      actual === PRLIMIT_PATH &&
      details.isFile() &&
      details.uid === 0 &&
      (details.mode & 0o111) !== 0 &&
      (details.mode & 0o022) === 0
    );
  } catch {
    return false;
  }
}

function snapshotInput(input) {
  try {
    if (!types.isUint8Array(input)) {
      return { error: "INVALID_INPUT" };
    }
    const length = byteLength.call(input);
    if (length === 0) return { error: "INVALID_INPUT" };
    if (length > PDF_LIMITS.maxInputBytes) {
      return { error: "INPUT_TOO_LARGE" };
    }
    const backing = arrayBuffer.call(input);
    bufferLength.call(backing); // Shared backing cannot supply stable input bytes.
    const view = new Uint8Array(backing, byteOffset.call(input), length);
    const bytes = Buffer.alloc(length);
    copyInto.call(bytes, view);
    const documentSha256 = createHash("sha256").update(bytes).digest("hex");
    const header = bytes.subarray(0, Math.min(1024, bytes.length));
    const eofWindow = bytes.subarray(Math.max(0, bytes.length - 2048));
    if (!header.includes(Buffer.from("%PDF-")) || !eofWindow.includes(Buffer.from("%%EOF"))) {
      return { error: "MALFORMED_PDF", documentSha256 };
    }
    return { bytes, documentSha256 };
  } catch {
    return { error: "INVALID_INPUT" };
  }
}

function normalizedOptions(options) {
  try {
    if (options === undefined) options = {};
    if (options === null || typeof options !== "object" || Array.isArray(options)) {
      return { error: "INVALID_OPTIONS" };
    }
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxTextCodeUnits = options.maxTextCodeUnits ?? MAX_TEXT_CODE_UNITS;
    const maxOutputBytes = options.maxOutputBytes ?? MAX_OUTPUT_BYTES;
    if (
      !Number.isInteger(timeoutMs) ||
      timeoutMs < 1 ||
      timeoutMs > MAX_TIMEOUT_MS ||
      !Number.isInteger(maxTextCodeUnits) ||
      maxTextCodeUnits < 1 ||
      maxTextCodeUnits > MAX_TEXT_CODE_UNITS ||
      !Number.isInteger(maxOutputBytes) ||
      maxOutputBytes < 4096 ||
      maxOutputBytes > MAX_OUTPUT_BYTES
    ) {
      return { error: "INVALID_LIMIT" };
    }
    if (options.signal !== undefined &&
        (!options.signal || typeof options.signal.addEventListener !== "function" ||
       typeof options.signal.removeEventListener !== "function" ||
         typeof options.signal.aborted !== "boolean")) {
      return { error: "INVALID_OPTIONS" };
    }
    if (options.onPageComplete !== undefined && typeof options.onPageComplete !== "function") {
      return { error: "INVALID_OPTIONS" };
    }
    return {
      timeoutMs,
      maxTextCodeUnits,
      maxOutputBytes,
      signal: options.signal,
      onPageComplete: options.onPageComplete,
    };
  } catch {
    return { error: "INVALID_OPTIONS" };
  }
}

function enqueue(job) {
  if (job.options.signal?.aborted) {
    return Promise.resolve(rejected("CANCELLED", job.documentSha256));
  }
  if (activeWorkers >= MAX_CONCURRENCY && queue.length >= MAX_QUEUED) {
    return Promise.resolve(rejected("QUEUE_FULL", job.documentSha256));
  }
  return new Promise((resolve) => {
    job.resolve = resolve;
    job.state = "queued";
    job.abortListener = () => {
      if (job.state === "queued") {
        const index = queue.indexOf(job);
        if (index >= 0) queue.splice(index, 1);
        job.state = "finished";
        clearTimeout(job.deadlineTimer);
        job.options.signal.removeEventListener("abort", job.abortListener);
        resolve(rejected("CANCELLED", job.documentSha256));
      } else if (job.state === "running") {
        terminate(job, "CANCELLED");
      }
    };
    job.deadlineTimer = setTimeout(() => {
      if (job.state === "queued") {
        const index = queue.indexOf(job);
        if (index >= 0) queue.splice(index, 1);
        job.state = "finished";
        job.options.signal?.removeEventListener("abort", job.abortListener);
        resolve(rejected("TIMEOUT", job.documentSha256));
      } else if (job.state === "running") {
        terminate(job, "TIMEOUT");
      }
    }, job.options.timeoutMs);
    job.deadlineTimer.unref();
    job.options.signal?.addEventListener("abort", job.abortListener, { once: true });
    queue.push(job);
    pump();
  });
}

function pump() {
  while (activeWorkers < MAX_CONCURRENCY && queue.length > 0) {
    const job = queue.shift();
    if (job.options.signal?.aborted) {
      job.state = "finished";
      clearTimeout(job.deadlineTimer);
      job.options.signal.removeEventListener("abort", job.abortListener);
      job.resolve(rejected("CANCELLED", job.documentSha256));
      continue;
    }
    activeWorkers += 1;
    job.state = "running";
    runIsolated(job).then(
      (result) => finishWorker(job, result),
      () => finishWorker(job, rejected("DECODER_FAILURE", job.documentSha256)),
    );
  }
}

function finishWorker(job, result) {
  job.state = "finished";
  clearTimeout(job.deadlineTimer);
  job.options.signal?.removeEventListener("abort", job.abortListener);
  activeWorkers -= 1;
  pump();
  job.resolve(
    job.terminationCode
      ? rejected(job.terminationCode, job.documentSha256)
      : result,
  );
}

function killProcessGroup(child) {
  if (!child?.pid) return;
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    try {
      child.kill("SIGKILL");
    } catch {
      // The close event still decides the final typed result.
    }
  }
}

function terminate(job, code) {
  if (job.terminationCode || job.state !== "running") return;
  job.terminationCode = code;
  killProcessGroup(job.child);
}

function parseWorkerLine(job, line) {
  if (job.finalMessage) {
    terminate(job, "PROTOCOL_ERROR");
    return;
  }
  let message;
  try {
    message = JSON.parse(line.toString("utf8"));
  } catch {
    terminate(job, "PROTOCOL_ERROR");
    return;
  }
  if (message?.kind === "progress") {
    if (!Number.isInteger(message.pageIndex) || message.pageIndex <= job.lastPageIndex) {
      terminate(job, "PROTOCOL_ERROR");
      return;
    }
    job.lastPageIndex = message.pageIndex;
    try {
      job.options.onPageComplete?.(message.pageIndex);
    } catch {
      terminate(job, "CALLBACK_FAILED");
    }
    return;
  }
  if (message?.kind === "result" || message?.kind === "error") {
    job.finalMessage = message;
    return;
  }
  terminate(job, "PROTOCOL_ERROR");
}

function publicWorkerError(code, hash, attemptCount) {
  const mapped = ERROR_CODES[code] ?? "DECODER_FAILURE";
  return rejected(mapped, hash, { networkAttemptCount: attemptCount });
}

function validateWorkerResult(message, job) {
  if (
    message.decoderVersion !== PDF_DECODER_VERSION ||
    message.configVersion !== PDF_READER_CONFIG_VERSION ||
    message.networkAttemptCount !== 0 ||
    !Array.isArray(message.pages) ||
    !["observation", "no-text"].includes(message.observationKind) ||
    message.completeness !== "incomplete-text-only" ||
    !message.limits ||
    message.limits.maxInputBytes !== PDF_LIMITS.maxInputBytes ||
    message.limits.maxPages !== PDF_LIMITS.maxPages ||
    message.limits.maxPagePoints !== PDF_LIMITS.maxPagePoints ||
    message.limits.maxTextCodeUnits !== job.options.maxTextCodeUnits ||
    message.limits.maxTextItemCodeUnits !== PDF_LIMITS.maxTextItemCodeUnits ||
    message.limits.maxTextItems !== PDF_LIMITS.maxTextItems ||
    message.limits.maxOutputBytes !== job.options.maxOutputBytes ||
    message.limits.addressSpaceBytes !== ADDRESS_SPACE_BYTES ||
    message.limits.maxCpuSeconds !== MAX_CPU_SECONDS ||
    message.limits.maxWallMilliseconds !== MAX_TIMEOUT_MS
  ) {
    return rejected("PROTOCOL_ERROR", job.documentSha256);
  }
  const pages = message.pages;
  if (pages.length < 1 || pages.length > PDF_LIMITS.maxPages) {
    return rejected("PROTOCOL_ERROR", job.documentSha256);
  }
  let observedTextCodeUnits = 0;
  let observedTextItems = 0;
  for (let index = 0; index < pages.length; index += 1) {
    const page = pages[index];
    if (
      page.pageIndex !== index ||
      !Number.isFinite(page.width) ||
      !Number.isFinite(page.height) ||
      page.width <= 0 ||
      page.height <= 0 ||
      page.width > PDF_LIMITS.maxPagePoints ||
      page.height > PDF_LIMITS.maxPagePoints ||
      ![0, 90, 180, 270].includes(page.rotation) ||
      page.coordinateSystem !== "viewport-points-top-left" ||
      page.requiresInspection !== true ||
      !["text-present", "no-embedded-text"].includes(page.textPresence) ||
      !Array.isArray(page.textBoxes)
    ) {
      return rejected("PROTOCOL_ERROR", job.documentSha256);
    }
    for (const box of page.textBoxes) {
      if (
        typeof box.text !== "string" ||
        box.text.length === 0 ||
        box.text.length > PDF_LIMITS.maxTextItemCodeUnits ||
        box.geometry !== "approximate-text-item" ||
        ![box.x, box.y, box.width, box.height].every(Number.isFinite) ||
        box.x < 0 || box.y < 0 || box.width < 0 || box.height < 0 ||
        box.x + box.width > page.width + 0.01 ||
        box.y + box.height > page.height + 0.01
      ) {
        return rejected("PROTOCOL_ERROR", job.documentSha256);
      }
      observedTextCodeUnits += box.text.length;
      observedTextItems += 1;
      if (
        observedTextCodeUnits > job.options.maxTextCodeUnits ||
        observedTextItems > PDF_LIMITS.maxTextItems
      ) {
        return rejected("PROTOCOL_ERROR", job.documentSha256);
      }
    }
    if (
      (page.textBoxes.length > 0 && page.textPresence !== "text-present") ||
      (page.textBoxes.length === 0 && page.textPresence !== "no-embedded-text")
    ) {
      return rejected("PROTOCOL_ERROR", job.documentSha256);
    }
  }
  if (message.observationKind === "no-text" && pages.some((page) => page.textBoxes.length > 0)) {
    return rejected("PROTOCOL_ERROR", job.documentSha256);
  }
  if (message.observationKind === "observation" && !pages.some((page) => page.textBoxes.length > 0)) {
    return rejected("PROTOCOL_ERROR", job.documentSha256);
  }
  const common = {
    ...baseResult(job.documentSha256),
    completeness: "incomplete-text-only",
    limits: message.limits,
    pages,
    networkAttemptCount: 0,
  };
  return freeze(
    message.observationKind === "no-text"
      ? { kind: "no-text", code: "NO_EMBEDDED_TEXT", requiresInspection: true, ...common }
      : { kind: "observation", completeness: "incomplete-text-only", requiresInspection: true, ...common },
  );
}

function runIsolated(job) {
  return new Promise((resolve) => {
    const child = spawn(
      PRLIMIT_PATH,
      [
        `--as=${ADDRESS_SPACE_BYTES}:${ADDRESS_SPACE_BYTES}`,
        `--cpu=${MAX_CPU_SECONDS}:${MAX_CPU_SECONDS}`,
        "--core=0:0",
        "--nofile=64:64",
        "--",
        process.execPath,
        "--disable-wasm-trap-handler",
        "--max-old-space-size=512",
        WORKER_PATH,
        String(job.options.maxTextCodeUnits),
        String(job.options.maxOutputBytes),
      ],
      {
        cwd: path.dirname(WORKER_PATH),
        env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
        detached: true,
        stdio: ["pipe", "pipe", "ignore"],
        windowsHide: true,
      },
    );
    job.child = child;
    job.lastPageIndex = -1;
    job.outputBytes = 0;
    job.pendingOutput = Buffer.alloc(0);
    job.finalMessage = null;
    let spawnFailed = false;

    child.on("error", () => {
      spawnFailed = true;
      terminate(job, "ISOLATION_UNAVAILABLE");
    });
    child.stdout.on("data", (chunk) => {
      if (chunk.byteLength > job.options.maxOutputBytes - job.outputBytes) {
        job.outputBytes = job.options.maxOutputBytes + 1;
        terminate(job, "OUTPUT_LIMIT");
        return;
      }
      job.outputBytes += chunk.byteLength;
      // Count buffered pipe data, but never parse or deliver progress after
      // the first terminal decision. Saturating above keeps accounting bounded.
      if (job.terminationCode) return;
      job.pendingOutput = Buffer.concat([job.pendingOutput, chunk]);
      while (true) {
        const newline = job.pendingOutput.indexOf(0x0a);
        if (newline < 0) break;
        const line = job.pendingOutput.subarray(0, newline);
        job.pendingOutput = job.pendingOutput.subarray(newline + 1);
        if (line.byteLength === 0) {
          terminate(job, "PROTOCOL_ERROR");
          return;
        }
        parseWorkerLine(job, line);
        if (job.terminationCode) return;
      }
    });
    child.stdin.on("error", () => {
      terminate(job, "DECODER_FAILURE");
    });
    child.on("close", (exitCode, signal) => {
      if (
        job.terminationCode || spawnFailed || job.pendingOutput.length !== 0 ||
        exitCode !== 0 || signal !== null || !job.finalMessage
      ) {
        // The worker has no reason to leave a child process behind. Kill any
        // remaining process in its dedicated group before resolving a failure.
        killProcessGroup(child);
      }
      job.child = null;
      if (job.terminationCode) {
        resolve(rejected(job.terminationCode, job.documentSha256));
        return;
      }
      if (spawnFailed) {
        resolve(rejected("ISOLATION_UNAVAILABLE", job.documentSha256));
        return;
      }
      if (job.pendingOutput.length !== 0 || exitCode !== 0 || signal !== null || !job.finalMessage) {
        const resourceExit = signal === "SIGKILL" || signal === "SIGABRT" || exitCode === 134;
        resolve(rejected(resourceExit ? "RESOURCE_LIMIT" : "DECODER_FAILURE", job.documentSha256));
        return;
      }
      const message = job.finalMessage;
      if (message.kind === "error") {
        resolve(publicWorkerError(message.code, job.documentSha256, message.networkAttemptCount));
      } else {
        resolve(validateWorkerResult(message, job));
      }
    });

    try {
      child.stdin.end(job.bytes);
    } catch {
      terminate(job, "DECODER_FAILURE");
    }
  });
}

/**
 * Read a bounded immutable PDF byte snapshot in a killable, OS-limited child.
 * The result is untrusted derived text and always requires later inspection.
 */
export function readTextPdf(input, options) {
  const normalized = normalizedOptions(options);
  if (normalized.error) return Promise.resolve(rejected(normalized.error));
  const snapshot = snapshotInput(input);
  if (snapshot.error) return Promise.resolve(rejected(snapshot.error, snapshot.documentSha256));
  if (normalized.signal?.aborted) {
    return Promise.resolve(rejected("CANCELLED", snapshot.documentSha256));
  }
  if (!isolationAvailable()) {
    return Promise.resolve(rejected("ISOLATION_UNAVAILABLE", snapshot.documentSha256));
  }
  return enqueue({
    bytes: snapshot.bytes,
    documentSha256: snapshot.documentSha256,
    options: normalized,
    state: "new",
  });
}

export const PDF_TEXT_READER_LIMITS = freeze({
  maxInputBytes: PDF_LIMITS.maxInputBytes,
  maxPages: PDF_LIMITS.maxPages,
  maxPagePoints: PDF_LIMITS.maxPagePoints,
  maxTextCodeUnits: PDF_LIMITS.maxTextCodeUnits,
  maxTextItemCodeUnits: PDF_LIMITS.maxTextItemCodeUnits,
  maxTextItems: PDF_LIMITS.maxTextItems,
  maxOutputBytes: MAX_OUTPUT_BYTES,
  maxAddressSpaceBytes: ADDRESS_SPACE_BYTES,
  maxCpuSeconds: MAX_CPU_SECONDS,
  maxTimeoutMs: MAX_TIMEOUT_MS,
  maxConcurrency: MAX_CONCURRENCY,
  maxQueued: MAX_QUEUED,
});
