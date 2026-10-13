import { performance } from "node:perf_hooks";
import { types } from "node:util";
import { record, snapshot, inspectPdf, copyPage, inspectOcr } from "./validation.mjs";
import { PROFILE, PDF_ENGINE, PDF_PROFILE, OCR_ENGINE, OCR_PROFILE, SCANNED_PDF_OCR_LIMITS as LIMITS } from "./profile.mjs";

const isAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted").get;
const addListener = EventTarget.prototype.addEventListener;
const removeListener = EventTarget.prototype.removeEventListener;
const refuse = (code, sourceSha256, details = {}) => Object.freeze({ kind: "rejected", profile: PROFILE, code, sourceSha256, ...details });

function optionsFrom(value) {
  try {
    const options = record(value === undefined ? {} : value, ["signal", "timeoutMs", "maxWords", "maxTextBytes", "maxOutputBytes"], false);
    if (!options) return { error: "INVALID_OPTIONS" };
    const signal = options.signal;
    if (signal !== undefined) {
      if (!signal || typeof signal !== "object" || types.isProxy(signal)) return { error: "INVALID_OPTIONS" };
      isAborted.call(signal);
    }
    const result = { signal };
    for (const [key, maximum, defaultValue] of [["timeoutMs", LIMITS.maxTimeoutMs, LIMITS.defaultTimeoutMs],
      ["maxWords", LIMITS.maxWords, LIMITS.maxWords], ["maxTextBytes", LIMITS.maxTextBytes, LIMITS.maxTextBytes],
      ["maxOutputBytes", LIMITS.maxOutputBytes, LIMITS.maxOutputBytes]]) {
      const chosen = options[key] === undefined ? defaultValue : options[key];
      if (!Number.isInteger(chosen) || chosen < 1 || chosen > maximum) return { error: "INVALID_LIMIT" };
      result[key] = chosen;
    }
    return result;
  } catch { return { error: "INVALID_OPTIONS" }; }
}

function stopped(job) {
  if (job.terminationCode) return job.terminationCode;
  if (performance.now() >= job.deadline) return "TIMEOUT";
  if (job.options.signal && isAborted.call(job.options.signal)) return "CANCELLED";
  return undefined;
}

function stageOptions(job, maximum, extras) {
  const code = stopped(job);
  if (code) return { error: code };
  return { signal: job.controller.signal, deadlineAtMs: job.deadline,
    timeoutMs: Math.max(1, Math.min(maximum, Math.floor(job.deadline - performance.now()))), ...extras };
}

/** Internal trusted dependency seam for tests; callers use the fixed index export. */
export function createScannedPdfOcrReader(dependencies) {
  const ports = record(dependencies, ["readPdf", "readOcr"]);
  if (!ports || typeof ports.readPdf !== "function" || typeof ports.readOcr !== "function" ||
      types.isProxy(ports.readPdf) || types.isProxy(ports.readOcr)) throw new TypeError("Exact trusted reader functions are required");
  const queue = [];
  let active = 0;

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
    job.resolve(refuse(code, job.sourceSha256, { stage: "admission" }));
  }

  function terminate(job, code) {
    if (job.state !== "running" || job.terminationCode) return;
    job.terminationCode = code;
    // The real reader promises settle only after their owned child closes.
    // Never race them away or replace cleanup with a fresh timeout allowance.
    job.controller.abort();
  }

  async function run(job) {
    const failure = (code, componentCode) => refuse(code, job.sourceSha256,
      { stage: job.stage, ...(job.page === undefined ? {} : { page: job.page }), ...(componentCode === undefined ? {} : { componentCode }) });
    try {
      job.stage = "render";
      const renderOptions = stageOptions(job, PDF_PROFILE.maxTimeoutMs, { maxOutputBytes: LIMITS.maxPixelBytes });
      if (renderOptions.error) return failure(renderOptions.error);
      const renderedPromise = ports.readPdf(job.bytes, renderOptions);
      if (!types.isPromise(renderedPromise)) return failure("STAGE_PROTOCOL_ERROR");
      const rendered = await renderedPromise;
      if (stopped(job)) return failure(stopped(job));
      let pdf;
      try { pdf = inspectPdf(rendered, job.sourceSha256, renderOptions); }
      catch { return failure("STAGE_PROTOCOL_ERROR"); }
      if (stopped(job)) return failure(stopped(job));
      if (pdf.rejected) return failure("PDF_REJECTED", pdf.rejected);
      const pages = [];
      let totalWords = 0, tokenUtf8Bytes = 0;
      for (const page of pdf.pages) {
        job.page = page.page;
        job.stage = "pixels";
        if (stopped(job)) return failure(stopped(job));
        if (totalWords >= job.options.maxWords || tokenUtf8Bytes >= job.options.maxTextBytes) return failure("OUTPUT_LIMIT");
        let bytes;
        try { bytes = copyPage(page); } catch { return failure("STAGE_PROTOCOL_ERROR"); }
        if (stopped(job)) return failure(stopped(job));
        job.stage = "ocr";
        const options = stageOptions(job, OCR_PROFILE.maxTimeoutMs,
          { maxWords: job.options.maxWords - totalWords, maxTextBytes: job.options.maxTextBytes - tokenUtf8Bytes });
        if (options.error) return failure(options.error);
        const observedPromise = ports.readOcr({ bytes, width: page.width, height: page.height, format: "rgba8",
          source: { sha256: job.sourceSha256, page: page.page, derivativeSha256: page.sha256 } }, options);
        if (!types.isPromise(observedPromise)) return failure("STAGE_PROTOCOL_ERROR");
        const observed = await observedPromise;
        if (stopped(job)) return failure(stopped(job));
        let checked;
        try { checked = inspectOcr(observed, job.sourceSha256, page, options); }
        catch { return failure("STAGE_PROTOCOL_ERROR"); }
        if (stopped(job)) return failure(stopped(job));
        if (checked.rejected) return failure("OCR_REJECTED", checked.rejected);
        pages.push(checked);
        totalWords += checked.words.length;
        tokenUtf8Bytes += checked.tokenUtf8Bytes;
      }
      job.stage = "aggregate";
      delete job.page;
      const result = Object.freeze({ kind: "observed", profile: PROFILE, completeness: "incomplete-unverified-ocr", requiresReview: true,
        sourceSha256: job.sourceSha256, sourceBinding: "local-pdf-reader-byte-chain", sourceAuthority: "unverified",
        decoder: Object.freeze({ ...PDF_ENGINE, profile: PDF_PROFILE.profile, syscallPolicy: PDF_PROFILE.syscallPolicy, enforcementControlsPassed: 8 }),
        observer: Object.freeze({ ...OCR_ENGINE, profile: OCR_PROFILE.profile, syscallPolicy: OCR_PROFILE.syscallPolicy, enforcementControlsPassed: 8 }),
        pages: Object.freeze(pages), totalPages: pages.length, totalPixels: pdf.totalPixels, totalWords, tokenUtf8Bytes,
        limits: Object.freeze({ ...LIMITS, timeoutMs: job.options.timeoutMs, maxWords: job.options.maxWords,
          maxTextBytes: job.options.maxTextBytes, maxOutputBytes: job.options.maxOutputBytes }) });
      if (Buffer.byteLength(JSON.stringify(result), "utf8") > job.options.maxOutputBytes) return failure("OUTPUT_LIMIT");
      const terminal = stopped(job); // Also covers freezing and complete serialization.
      return terminal ? failure(terminal) : result;
    } catch { return failure(stopped(job) ?? "STAGE_FAILURE"); }
  }

  function pump() {
    while (active < LIMITS.maxConcurrency && queue.length) {
      const job = queue.shift();
      const code = stopped(job);
      if (code) { finishQueued(job, code); continue; }
      active += 1;
      job.state = "running";
      run(job).then((result) => {
        const terminal = stopped(job);
        job.state = "finished";
        cleanup(job);
        active -= 1;
        job.resolve(terminal ? refuse(terminal, job.sourceSha256, { stage: job.stage }) : result);
        queueMicrotask(pump);
      });
    }
  }

  return function readScannedPdfOcr(input, options) {
    const started = performance.now();
    const normalized = optionsFrom(options);
    if (normalized.error) return Promise.resolve(refuse(normalized.error));
    if (normalized.signal && isAborted.call(normalized.signal)) return Promise.resolve(refuse("CANCELLED"));
    const deadline = started + normalized.timeoutMs;
    const source = snapshot(input);
    if (source.error) return Promise.resolve(refuse(source.error));
    if (performance.now() >= deadline) return Promise.resolve(refuse("TIMEOUT", source.sha256));
    if (active >= LIMITS.maxConcurrency && queue.length >= LIMITS.maxQueued) return Promise.resolve(refuse("QUEUE_FULL", source.sha256));
    return new Promise((resolve) => {
      const job = { bytes: source.bytes, sourceSha256: source.sha256, options: normalized, deadline, resolve,
        controller: new AbortController(), state: "queued", stage: "admission" };
      job.abortListener = () => {
        const code = stopped(job) ?? "CANCELLED";
        if (job.state === "queued") finishQueued(job, code); else terminate(job, code);
      };
      job.timer = setTimeout(() => {
        if (job.state === "queued") finishQueued(job, "TIMEOUT"); else terminate(job, "TIMEOUT");
      }, Math.max(1, Math.ceil(deadline - performance.now())));
      if (normalized.signal) addListener.call(normalized.signal, "abort", job.abortListener, { once: true });
      queue.push(job);
      pump();
    });
  };
}
