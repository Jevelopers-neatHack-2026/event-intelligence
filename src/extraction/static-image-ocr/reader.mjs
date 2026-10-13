import { performance } from "node:perf_hooks";
import { types } from "node:util";
import { record, snapshot, sourceFormat, inspectImage, copyImage, inspectOcr } from "./validation.mjs";
import { PROFILE, PNG_LIMITS, RASTER_LIMITS, OCR_ENGINE, OCR_PROFILE, STATIC_IMAGE_OCR_LIMITS as LIMITS } from "./profile.mjs";

const now = performance.now.bind(performance);
const isAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted").get;
const addListener = EventTarget.prototype.addEventListener;
const removeListener = EventTarget.prototype.removeEventListener;
const refuse = (code, sourceSha256, details = {}) => Object.freeze({ kind: "rejected", profile: PROFILE, code, sourceSha256, ...details });
// Shared by every factory in this canonical module instance, including distinct runtimes.
const queue = [];
let active = 0;

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
  if (now() >= job.deadline) return "TIMEOUT";
  if (job.options.signal && isAborted.call(job.options.signal)) return "CANCELLED";
  return undefined;
}
function stageOptions(job, maximum, extras) {
  const code = stopped(job);
  if (code) return { error: code };
  return { signal: job.controller.signal, deadlineAtMs: job.deadline,
    timeoutMs: Math.max(1, Math.min(maximum, Math.floor(job.deadline - now()))), ...extras };
}
function cleanup(job) {
  clearTimeout(job.timer);
  if (job.options.signal) removeListener.call(job.options.signal, "abort", job.abortListener);
  job.bytes = null;
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
  // Real stage promises settle only after their owned native child closes.
  // Observe them through closure; do not race them away or renew cleanup time.
  job.controller.abort();
}
function complete(job, result) {
  const terminal = stopped(job);
  job.state = "finished";
  cleanup(job);
  active -= 1;
  job.resolve(terminal ? refuse(terminal, job.sourceSha256, { stage: job.stage }) : result);
  queueMicrotask(pump);
}
function pump() {
  while (active < LIMITS.maxConcurrency && queue.length) {
    const job = queue.shift();
    const code = stopped(job);
    if (code) { finishQueued(job, code); continue; }
    active += 1;
    job.state = "running";
    job.run(job).then((result) => complete(job, result), () => complete(job, refuse("STAGE_FAILURE", job.sourceSha256, { stage: job.stage })));
  }
}

/** Internal fixed-function test seam; the public factory never accepts these ports. */
export function createStaticImageOcrReaderWithPorts(dependencies) {
  const ports = record(dependencies, ["readPng", "readJpegWebp", "readOcr"]);
  if (!ports || Object.values(ports).some((port) => typeof port !== "function" || types.isProxy(port))) {
    throw new TypeError("Exact trusted reader functions are required");
  }
  async function run(job) {
    const failure = (code, componentCode) => refuse(code, job.sourceSha256,
      { stage: job.stage, ...(componentCode === undefined ? {} : { componentCode }) });
    try {
      job.stage = "decode";
      const decodeLimits = job.format === "png" ? PNG_LIMITS : RASTER_LIMITS;
      // The report cap is separate. Never silently redefine the decoder's normalized-byte cap.
      const decodeOptions = stageOptions(job, decodeLimits.maxTimeoutMs, { maxOutputBytes: decodeLimits.maxOutputBytes });
      if (decodeOptions.error) return failure(decodeOptions.error);
      const pending = (job.format === "png" ? ports.readPng : ports.readJpegWebp)(job.bytes, decodeOptions);
      if (!types.isPromise(pending)) return failure("STAGE_PROTOCOL_ERROR");
      let decoded = await pending;
      if (stopped(job)) return failure(stopped(job));
      let checked;
      try { checked = inspectImage(decoded, job.sourceSha256, job.format, decodeOptions); }
      catch { return failure("STAGE_PROTOCOL_ERROR"); }
      if (stopped(job)) return failure(stopped(job));
      if (checked.rejected) return failure("IMAGE_REJECTED", checked.rejected);
      job.stage = "pixels";
      let pixels;
      try { pixels = copyImage(checked); } catch { return failure("STAGE_PROTOCOL_ERROR"); }
      if (stopped(job)) return failure(stopped(job));
      if (pixels.error) return failure(pixels.error);
      // Drop retained decoder result/accessors once the separately owned pixels are checked.
      decoded = null;
      checked.receiver = null;
      checked.copyRgbaBytes = null;
      job.bytes = null;
      job.stage = "ocr";
      const options = stageOptions(job, OCR_PROFILE.maxTimeoutMs,
        { maxWords: job.options.maxWords, maxTextBytes: job.options.maxTextBytes });
      if (options.error) return failure(options.error);
      const observedPromise = ports.readOcr({ bytes: pixels.bytes, width: checked.image.width, height: checked.image.height, format: "rgba8",
        source: { sha256: job.sourceSha256, page: 1, derivativeSha256: checked.image.rgbaSha256 } }, options);
      if (!types.isPromise(observedPromise)) return failure("STAGE_PROTOCOL_ERROR");
      const observed = await observedPromise;
      if (stopped(job)) return failure(stopped(job));
      let observations;
      try { observations = inspectOcr(observed, job.sourceSha256, checked.image, options); }
      catch { return failure("STAGE_PROTOCOL_ERROR"); }
      if (stopped(job)) return failure(stopped(job));
      if (observations.rejected) return failure("OCR_REJECTED", observations.rejected);
      job.stage = "aggregate";
      const result = Object.freeze({ kind: "observed", profile: PROFILE, completeness: "incomplete-unverified-ocr", requiresReview: true,
        sourceSha256: job.sourceSha256, sourceBinding: "local-static-image-reader-byte-chain", sourceAuthority: "unverified",
        image: checked.image, decoder: Object.freeze({ ...checked.decoder, networkPolicy: "cooperative-api-guard-only" }),
        observer: Object.freeze({ ...OCR_ENGINE, profile: OCR_PROFILE.profile, syscallPolicy: OCR_PROFILE.syscallPolicy, enforcementControlsPassed: 8 }),
        ...observations, limits: Object.freeze({ ...LIMITS, timeoutMs: job.options.timeoutMs, maxWords: job.options.maxWords,
          maxTextBytes: job.options.maxTextBytes, maxOutputBytes: job.options.maxOutputBytes }) });
      if (Buffer.byteLength(JSON.stringify(result), "utf8") > job.options.maxOutputBytes) return failure("OUTPUT_LIMIT");
      const terminal = stopped(job); // Covers complete freezing and serialization before delivery.
      return terminal ? failure(terminal) : result;
    } catch { return failure(stopped(job) ?? "STAGE_FAILURE"); }
  }
  return function readStaticImageOcr(input, options) {
    const started = now();
    const normalized = optionsFrom(options);
    if (normalized.error) return Promise.resolve(refuse(normalized.error));
    if (normalized.signal && isAborted.call(normalized.signal)) return Promise.resolve(refuse("CANCELLED"));
    const deadline = started + normalized.timeoutMs;
    if (now() >= deadline) return Promise.resolve(refuse("TIMEOUT"));
    if (active >= LIMITS.maxConcurrency && queue.length >= LIMITS.maxQueued) return Promise.resolve(refuse("QUEUE_FULL"));
    const source = snapshot(input);
    if (source.error) return Promise.resolve(refuse(source.error));
    if (now() >= deadline) return Promise.resolve(refuse("TIMEOUT", source.sha256));
    const format = sourceFormat(source.bytes);
    if (!format) return Promise.resolve(refuse("UNSUPPORTED_FORMAT", source.sha256));
    return new Promise((resolve) => {
      const job = { run, bytes: source.bytes, sourceSha256: source.sha256, format, options: normalized, deadline, resolve,
        controller: new AbortController(), state: "queued", stage: "admission" };
      job.abortListener = () => {
        const code = stopped(job) ?? "CANCELLED";
        if (job.state === "queued") finishQueued(job, code); else terminate(job, code);
      };
      job.timer = setTimeout(() => {
        if (job.state === "queued") finishQueued(job, "TIMEOUT"); else terminate(job, "TIMEOUT");
      }, Math.max(1, Math.ceil(deadline - now())));
      if (normalized.signal) addListener.call(normalized.signal, "abort", job.abortListener, { once: true });
      queue.push(job);
      pump();
    });
  };
}
