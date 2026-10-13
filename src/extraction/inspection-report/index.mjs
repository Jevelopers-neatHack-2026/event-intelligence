import { createHash } from "node:crypto";
import { types } from "node:util";
import { DETERMINISTIC_EXTRACTION_VERSION, EXTRACTION_LIMITS } from "../index.mjs";
import { PDF_TEXT_READER_LIMITS } from "../pdf/index.mjs";

export const INSPECTION_REPORT_VERSION = "ei-local-inspection-report/1";
export const INSPECTION_MATRIX_SCHEMA = "ei-local-inspection-support-matrix/1";
export const INSPECTION_REPORT_LIMITS = Object.freeze({
  maxObservations: 32,
  maxExecutions: 16,
  maxSourceBytes: 20 * 1024 * 1024,
  maxTotalSourceBytes: 64 * 1024 * 1024,
  maxArtifactBytes: 1024 * 1024,
  maxSummaryBytes: 512 * 1024,
  maxResultBytes: 4 * 1024 * 1024,
  maxReportBytes: 2 * 1024 * 1024,
  maxJsonDepth: 64,
  maxJsonNodes: 100_000,
  maxCases: 100_000,
});

const FORMATS = ["html", "xhtml", "plain-text", "json-ld", "text-pdf", "scanned-pdf", "png", "jpeg", "webp"];
const COMPONENTS = ["deterministic-extraction", "text-pdf"];
const MODES = ["mock", "recorded", "sandbox", "live"];
const HASH = /^[a-f0-9]{64}$/;
const REVISION = /^[a-f0-9]{40}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const matches = (pattern, value) => typeof value === "string" && pattern.test(value);
const STATUSES = ["PARTIAL", "NO_ANSWER", "JS_REQUIRED", "ACCESS_RESTRICTED", "UNSUPPORTED_MEDIA", "UNSUPPORTED_ENCODING", "MALFORMED_ENCODING", "RESOURCE_LIMIT", "CANCELED", "INVALID_INPUT"];
const PDF_ERRORS = ["INVALID_INPUT", "INVALID_OPTIONS", "INVALID_LIMIT", "INPUT_TOO_LARGE", "MALFORMED_PDF", "ENCRYPTED_PDF", "ACTIVE_PDF_FEATURE", "REMOTE_REFERENCE", "REMOTE_RESOURCE_ATTEMPT", "UNSUPPORTED_PDF_FEATURE", "PAGE_LIMIT", "DIMENSION_LIMIT", "TEXT_LIMIT", "OUTPUT_LIMIT", "RESOURCE_LIMIT", "NO_EMBEDDED_TEXT", "ISOLATION_UNAVAILABLE", "QUEUE_FULL", "CANCELLED", "TIMEOUT", "CALLBACK_FAILED", "PROTOCOL_ERROR", "DECODER_UNAVAILABLE", "DECODER_FAILURE"];
const BYTE_PROTOTYPES = [Uint8Array.prototype, Buffer.prototype];
const BYTE_METADATA = Object.getOwnPropertyDescriptors(Object.getPrototypeOf(Uint8Array.prototype));
const BYTE_OVERRIDES = ["buffer", "byteLength", "byteOffset", "length", "valueOf", "toString", "toJSON", Symbol.toPrimitive, Symbol.iterator];

export class InspectionReportError extends Error {
  constructor(code) {
    super(code);
    this.name = "InspectionReportError";
    this.code = code;
  }
}

function requireThat(ok, code = "INVALID_INPUT") {
  if (!ok) throw new InspectionReportError(code);
}
function sha256(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function equal(left, right) { return canonical(left) === canonical(right); }
function integer(value, max = INSPECTION_REPORT_LIMITS.maxCases) {
  return Number.isSafeInteger(value) && value >= 0 && value <= max;
}
function record(value) {
  requireThat(value !== null && typeof value === "object" && !types.isProxy(value) && !Array.isArray(value));
  requireThat([Object.prototype, null].includes(Object.getPrototypeOf(value)));
  const descriptors = Object.getOwnPropertyDescriptors(value);
  requireThat(Reflect.ownKeys(descriptors).every((key) => typeof key === "string" && "value" in descriptors[key] && descriptors[key].enumerable));
  return value;
}
function dataArray(value, maximum) {
  requireThat(!types.isProxy(value) && Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype);
  const length = Object.getOwnPropertyDescriptor(value, "length")?.value;
  requireThat(Number.isSafeInteger(length) && length >= 0);
  requireThat(length <= maximum, "RESOURCE_LIMIT");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  requireThat(Reflect.ownKeys(descriptors).length === length + 1);
  const copy = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[index];
    requireThat(descriptor && "value" in descriptor && descriptor.enumerable);
    copy.push(descriptor.value);
  }
  return copy;
}
function bytes(value, maximum, code = "RESOURCE_LIMIT") {
  requireThat(!types.isProxy(value) && types.isUint8Array(value));
  requireThat(BYTE_PROTOTYPES.includes(Object.getPrototypeOf(value)));
  requireThat(BYTE_OVERRIDES.every((key) => !Object.hasOwn(value, key)));
  // Read native view slots and copy a new ordinary view. Caller getters,
  // conversion hooks and subclass methods cannot run or change the byte bound.
  const length = Reflect.apply(BYTE_METADATA.byteLength.get, value, []);
  requireThat(length > 0 && length <= maximum, code);
  const buffer = Reflect.apply(BYTE_METADATA.buffer.get, value, []);
  requireThat(!types.isSharedArrayBuffer(buffer));
  const offset = Reflect.apply(BYTE_METADATA.byteOffset.get, value, []);
  try { return Buffer.from(new Uint8Array(buffer, offset, length)); }
  catch { throw new InspectionReportError("INVALID_INPUT"); }
}
function freeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

// Copy only JSON data. Accessors, sparse arrays, class instances, cycles, lossy
// values and unexpected toJSON behavior cannot silently alter a result digest.
function jsonCopy(value, maximum = INSPECTION_REPORT_LIMITS.maxResultBytes) {
  let nodes = 0;
  let size = 0;
  const ancestors = new Set();
  function visit(v, depth) {
    requireThat(++nodes <= INSPECTION_REPORT_LIMITS.maxJsonNodes && depth <= INSPECTION_REPORT_LIMITS.maxJsonDepth, "RESOURCE_LIMIT");
    if (v === null || typeof v === "boolean") { size += 5; return v; }
    if (typeof v === "number") { requireThat(Number.isFinite(v) && !Object.is(v, -0)); size += 32; return v; }
    if (typeof v === "string") { size += Buffer.byteLength(v) + 2; requireThat(size <= maximum, "RESOURCE_LIMIT"); return v; }
    requireThat(v !== null && typeof v === "object" && !types.isProxy(v) && !ancestors.has(v));
    ancestors.add(v);
    let result;
    if (Array.isArray(v)) {
      requireThat(Object.getPrototypeOf(v) === Array.prototype && v.length <= INSPECTION_REPORT_LIMITS.maxJsonNodes, "RESOURCE_LIMIT");
      const ds = Object.getOwnPropertyDescriptors(v);
      requireThat(Reflect.ownKeys(ds).length === v.length + 1);
      result = [];
      for (let i = 0; i < v.length; i += 1) {
        requireThat(ds[i] && "value" in ds[i] && ds[i].enumerable);
        result.push(visit(ds[i].value, depth + 1));
      }
    } else {
      record(v);
      result = {};
      for (const key of Object.keys(v).sort()) {
        size += Buffer.byteLength(key) + 4;
        requireThat(size <= maximum, "RESOURCE_LIMIT");
        Object.defineProperty(result, key, { value: visit(Object.getOwnPropertyDescriptor(v, key).value, depth + 1), enumerable: true, writable: true, configurable: true });
      }
    }
    ancestors.delete(v);
    return result;
  }
  const copy = visit(value, 0);
  requireThat(Buffer.byteLength(JSON.stringify(copy)) <= maximum, "RESOURCE_LIMIT");
  return copy;
}
function canonical(value) { return JSON.stringify(jsonCopy(value)) + "\n"; }

// A bounded JSON reader rejects duplicate (including escape-equivalent) keys.
// JSON.parse by itself would let a second pin or a second pass count win.
function parseJson(input, maximum) {
  const owned = bytes(input, maximum);
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(owned); }
  catch { throw new InspectionReportError("INVALID_JSON"); }
  let pos = 0;
  let nodes = 0;
  function space() { while (/[\t\n\r ]/.test(text[pos] ?? "x")) pos += 1; }
  function string() {
    const start = pos++;
    while (pos < text.length) {
      const char = text[pos++];
      if (char === "\\") pos += 1;
      else if (char === '"') {
        try { return JSON.parse(text.slice(start, pos)); } catch { break; }
      }
    }
    throw new InspectionReportError("INVALID_JSON");
  }
  function value(depth) {
    space();
    requireThat(++nodes <= INSPECTION_REPORT_LIMITS.maxJsonNodes && depth <= INSPECTION_REPORT_LIMITS.maxJsonDepth, "RESOURCE_LIMIT");
    if (text[pos] === '"') return string();
    if (text[pos] === "{" || text[pos] === "[") {
      const object = text[pos++] === "{";
      const close = object ? "}" : "]";
      const result = object ? Object.create(null) : [];
      const keys = new Set();
      space();
      if (text[pos] === close) { pos += 1; return result; }
      while (pos < text.length) {
        let key;
        if (object) {
          space(); requireThat(text[pos] === '"', "INVALID_JSON"); key = string();
          requireThat(!keys.has(key), "DUPLICATE_KEY"); keys.add(key);
          space(); requireThat(text[pos++] === ":", "INVALID_JSON");
        }
        const child = value(depth + 1);
        if (object) result[key] = child; else result.push(child);
        space();
        if (text[pos] === close) { pos += 1; return result; }
        requireThat(text[pos++] === ",", "INVALID_JSON");
      }
      throw new InspectionReportError("INVALID_JSON");
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(pos))?.[0];
    requireThat(token !== undefined, "INVALID_JSON"); pos += token.length;
    const result = JSON.parse(token);
    requireThat(typeof result !== "number" || (Number.isFinite(result) && !Object.is(result, -0)), "INVALID_JSON");
    return result;
  }
  const result = value(0); space(); requireThat(pos === text.length, "INVALID_JSON");
  return result;
}

function validatePins(pins) {
  const p = jsonCopy(pins, INSPECTION_REPORT_LIMITS.maxArtifactBytes);
  record(p);
  requireThat(equal(Object.keys(p).sort(), ["evidenceSchema", "package", "sourceRevision", "supportMatrix"]));
  requireThat(matches(REVISION, p.sourceRevision));
  for (const key of ["package", "evidenceSchema", "supportMatrix"]) {
    record(p[key]);
    const fields = key === "evidenceSchema" ? ["id", "sha256", "version", "versionPointer"] : ["sha256", "version"];
    requireThat(equal(Object.keys(p[key]).sort(), fields));
    requireThat(matches(HASH, p[key].sha256) && typeof p[key].version === "string" && p[key].version.length > 0 && p[key].version.length <= 128);
  }
  requireThat(typeof p.evidenceSchema.id === "string" && p.evidenceSchema.id.length > 0 && p.evidenceSchema.id.length <= 512);
  requireThat(typeof p.evidenceSchema.versionPointer === "string" && p.evidenceSchema.versionPointer.length <= 256);
  return p;
}
function pointer(root, path) {
  requireThat(path === "" || (path.startsWith("/") && !/~(?:[^01]|$)/.test(path)), "INVALID_POINTER");
  let current = root;
  if (path === "") return current;
  for (const piece of path.slice(1).split("/")) {
    const key = piece.replace(/~1/g, "/").replace(/~0/g, "~");
    requireThat(current !== null && typeof current === "object" && Object.hasOwn(current, key), "PIN_MISMATCH");
    current = current[key];
  }
  return current;
}
function artifact(input, pin) {
  const owned = bytes(input, INSPECTION_REPORT_LIMITS.maxArtifactBytes);
  requireThat(sha256(owned) === pin.sha256, "PIN_MISMATCH");
  return parseJson(owned, INSPECTION_REPORT_LIMITS.maxArtifactBytes);
}
function selectedArtifacts(input, pins) {
  record(input);
  const pkg = artifact(input.package, pins.package);
  requireThat(pkg.version === pins.package.version, "PIN_MISMATCH");
  const evidence = artifact(input.evidenceSchema, pins.evidenceSchema);
  requireThat(evidence.$id === pins.evidenceSchema.id && pointer(evidence, pins.evidenceSchema.versionPointer) === pins.evidenceSchema.version, "PIN_MISMATCH");
  const matrix = artifact(input.supportMatrix, pins.supportMatrix);
  requireThat(matrix.schemaVersion === INSPECTION_MATRIX_SCHEMA, "UNSUPPORTED_VERSION");
  requireThat(matrix.version === pins.supportMatrix.version, "PIN_MISMATCH");
  requireThat(Array.isArray(matrix.requiredFormats) && matrix.requiredFormats.length > 0 && matrix.requiredFormats.length <= FORMATS.length);
  requireThat(matrix.requiredFormats.every((f) => FORMATS.includes(f)) && new Set(matrix.requiredFormats).size === matrix.requiredFormats.length, "INVALID_MATRIX");
  return { requiredFormats: [...matrix.requiredFormats].sort() };
}

function parseExecution(input, expectedPins, requiredMode) {
  record(input);
  requireThat(matches(ID, input.id) && COMPONENTS.includes(input.component));
  requireThat(MODES.includes(input.mode) && ["local-synthetic", "recorded"].includes(input.origin));
  requireThat(input.origin !== "local-synthetic" || input.mode === "mock", "INVALID_MODE");
  requireThat(equal(validatePins(input.pins), expectedPins), "PIN_MISMATCH");
  requireThat(integer(input.expectedCases) && input.expectedCases > 0);
  requireThat(input.exitCode === null || integer(input.exitCode, 255));
  requireThat(input.signal === null || ["SIGTERM", "SIGKILL", "SIGABRT", "SIGINT"].includes(input.signal));
  const raw = bytes(input.summaryBytes, INSPECTION_REPORT_LIMITS.maxSummaryBytes);
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw); }
  catch { throw new InspectionReportError("INVALID_SUMMARY"); }
  let counts;
  if (input.format === "verify-summary") {
    requireThat(input.component === "deterministic-extraction", "INVALID_SUMMARY");
    const lines = text.split(/\r?\n/).filter((line) => line.startsWith("VERIFY_SUMMARY_JSON="));
    requireThat(lines.length === 1, lines.length > 1 ? "DUPLICATE_SUMMARY" : "MISSING_SUMMARY");
    const summary = parseJson(Buffer.from(lines[0].slice("VERIFY_SUMMARY_JSON=".length)), INSPECTION_REPORT_LIMITS.maxSummaryBytes);
    requireThat(summary.case === input.component && summary.mode === input.mode && summary.exit_code === input.exitCode, "INVALID_SUMMARY");
    counts = { total: summary.terminal_cases, passed: summary.passed_cases, failed: summary.failed_cases, skipped: summary.skipped_cases, todo: summary.todo_cases, cancelled: summary.cancelled_cases };
    requireThat(summary.expected_cases === input.expectedCases && integer(summary.test_files) && summary.test_files > 0, "COUNT_MISMATCH");
    requireThat(["passed", "failed", "blocked"].includes(summary.status), "INVALID_SUMMARY");
    const clean = input.exitCode === 0 && input.signal === null && counts.total === input.expectedCases && counts.passed === input.expectedCases && [counts.failed, counts.skipped, counts.todo, counts.cancelled].every((v) => v === 0);
    requireThat((summary.status === "passed") === clean, "FALSE_PASS");
  } else if (input.format === "node-tap") {
    requireThat(input.component === "text-pdf", "INVALID_SUMMARY");
    const fields = { total: "tests", passed: "pass", failed: "fail", skipped: "skipped", todo: "todo", cancelled: "cancelled" };
    counts = {};
    for (const [key, name] of Object.entries(fields)) {
      const matches = [...text.matchAll(new RegExp(`^# ${name} (\\d+)\\r?$`, "gm"))];
      requireThat(matches.length === 1, matches.length > 1 ? "DUPLICATE_SUMMARY" : "MISSING_SUMMARY");
      counts[key] = Number(matches[0][1]);
    }
    const plans = [...text.matchAll(/^1\.\.(\d+)\r?$/gm)];
    requireThat(plans.length === 1 && Number(plans[0][1]) === counts.total, "COUNT_MISMATCH");
    // This adapter supports the existing flat text-PDF TAP route. A forged
    // terminal footer must not erase an earlier top-level failure or skip.
    const verdicts = [...text.matchAll(/^(not ok|ok) (\d+)(?: - ([^\r\n]*))?\r?$/gm)];
    requireThat(verdicts.length === counts.total && verdicts.every((v, index) => Number(v[2]) === index + 1), "COUNT_MISMATCH");
    const cleanVerdicts = verdicts.filter((v) => v[1] === "ok" && !/ # (?:SKIP|TODO)(?:\s|$)/i.test(v[3] ?? "")).length;
    requireThat(cleanVerdicts === counts.passed, "FALSE_PASS");
  } else throw new InspectionReportError("UNSUPPORTED_SUMMARY");
  requireThat(Object.values(counts).every((n) => integer(n)), "COUNT_MISMATCH");
  requireThat(counts.total === counts.passed + counts.failed + counts.skipped + counts.todo + counts.cancelled, "COUNT_MISMATCH");
  const complete = counts.total === input.expectedCases && counts.passed === input.expectedCases && input.exitCode === 0 && input.signal === null && input.mode === requiredMode && input.mode === "mock" && input.origin === "local-synthetic";
  return { id: input.id, component: input.component, mode: input.mode, origin: input.origin, format: input.format, summary: { domain: "execution-stdout-bytes", sha256: sha256(raw), bytes: raw.length }, expectedCases: input.expectedCases, counts, exitCode: input.exitCode, signal: input.signal, complete };
}

function range(locator, sourceBytes) {
  record(locator);
  requireThat(locator.kind === "text-range" && integer(locator.startByte, sourceBytes.length) && integer(locator.endByte, sourceBytes.length) && locator.startByte <= locator.endByte, "INVALID_LOCATOR");
  return sourceBytes.subarray(locator.startByte, locator.endByte);
}
function deterministic(result, sourceBytes, format, sourceMetadata, declaredLimits) {
  requireThat(["html", "xhtml", "plain-text", "json-ld"].includes(format), "FORMAT_MISMATCH");
  requireThat(result.extractorVersion === DETERMINISTIC_EXTRACTION_VERSION, "UNSUPPORTED_VERSION");
  requireThat(STATUSES.includes(result.status) && [null, "CANCELED", "RESOURCE_LIMIT", "PARSER_DEADLINE"].includes(result.termination));
  requireThat(equal(result.parserVersions, { html: "parse5@8.0.1", htmlStream: "parse5-parser-stream@8.0.0", xml: "sax@1.6.1", json: `node@${process.versions.node}/JSON.parse+ei-json-index@1` }), "UNSUPPORTED_VERSION");
  requireThat(result.sourceHash === `sha256:${sha256(sourceBytes)}` && result.source?.contentHash === result.sourceHash, "SOURCE_HASH_MISMATCH");
  const meta = jsonCopy(sourceMetadata);
  requireThat(typeof meta.url === "string" && typeof meta.fetchedAt === "string" && typeof meta.contentType === "string");
  requireThat(result.source.url === meta.url && result.source.fetchedAt === meta.fetchedAt && result.source.contentType === meta.contentType, "SOURCE_METADATA_MISMATCH");
  const mime = { html: "text/html", xhtml: "application/xhtml+xml", "plain-text": "text/plain", "json-ld": "application/ld+json" }[format];
  requireThat(meta.contentType.split(";", 1)[0].trim().toLowerCase() === mime, "FORMAT_MISMATCH");
  const limits = jsonCopy(declaredLimits);
  requireThat(equal(Object.keys(limits).sort(), Object.keys(EXTRACTION_LIMITS).sort()), "INVALID_LIMITS");
  for (const key of Object.keys(EXTRACTION_LIMITS)) requireThat(integer(limits[key], EXTRACTION_LIMITS[key]) && limits[key] > 0, "INVALID_LIMITS");
  requireThat(sourceBytes.length <= limits.maxDocumentBytes, "RESOURCE_LIMIT");
  const groups = ["canonicalSuggestions", "pageMetadata", "visibleText", "statusMentions", "accessSignals", "assetSources", "events", "organizations", "conflicts", "ambiguities", "jsonLdBlocks", "diagnostics"];
  requireThat(groups.every((g) => Array.isArray(result[g])));
  const candidates = [...result.canonicalSuggestions, ...result.pageMetadata, ...result.visibleText, ...result.statusMentions, ...result.accessSignals, ...result.assetSources.map((a) => a.candidate), ...result.events.flatMap((e) => e.candidates), ...result.organizations.flatMap((e) => e.candidates), ...result.conflicts.flatMap((c) => c.candidates)];
  const locators = candidates.map((candidate) => {
    record(candidate); record(candidate.source);
    const raw = range(candidate.source.locator, sourceBytes);
    requireThat(typeof candidate.rawValue === "string" && raw.equals(Buffer.from(candidate.rawValue, "utf8")), "SOURCE_SLICE_MISMATCH");
    // The complete result remains separately hashed. Only the declared byte
    // range may enter this view; extra input metadata must not be disclosed.
    const { kind, startByte, endByte } = candidate.source.locator;
    return { kind, startByte, endByte, rawSha256: sha256(raw) };
  });
  for (const entity of [...result.events, ...result.organizations]) if (entity.source !== null) range(entity.source.locator, sourceBytes);
  for (const block of result.jsonLdBlocks) range(block.locator, sourceBytes);
  return { componentVersion: result.extractorVersion, parserVersions: result.parserVersions, status: result.status, termination: result.termination, nativeSourceHash: result.sourceHash, sourceMetadataSha256: sha256(Buffer.from(canonical(meta))), declaredLimits: limits, limitsEvidence: "caller-declared; result does not echo effective limits", counts: Object.fromEntries(groups.map((g) => [g, result[g].length])), locators, completeness: "source-candidates-only", requiresInspection: true };
}
function pdf(result, sourceBytes, format) {
  requireThat(format === "text-pdf", "FORMAT_MISMATCH");
  requireThat(equal(result.decoder, { name: "pdfjs-dist", version: "6.4.299", configVersion: "ei-text-pdf/1" }), "UNSUPPORTED_VERSION");
  requireThat(result.documentSha256 === sha256(sourceBytes), "SOURCE_HASH_MISMATCH");
  requireThat(["observation", "no-text", "rejected"].includes(result.kind));
  if (result.kind === "rejected") {
    requireThat(PDF_ERRORS.includes(result.code));
    requireThat(result.networkAttemptCount === undefined || integer(result.networkAttemptCount));
    return { componentVersion: "ei-text-pdf/1", decoder: result.decoder, status: result.code, kind: "rejected", nativeSourceHash: result.documentSha256, completeness: "rejected", requiresInspection: true };
  }
  requireThat(result.completeness === "incomplete-text-only" && result.requiresInspection === true && result.networkAttemptCount === 0, "INVALID_COMPLETENESS");
  const limits = record(result.limits);
  const fixed = { maxInputBytes: PDF_TEXT_READER_LIMITS.maxInputBytes, maxPages: PDF_TEXT_READER_LIMITS.maxPages, maxPagePoints: PDF_TEXT_READER_LIMITS.maxPagePoints, maxTextItemCodeUnits: PDF_TEXT_READER_LIMITS.maxTextItemCodeUnits, maxTextItems: PDF_TEXT_READER_LIMITS.maxTextItems, addressSpaceBytes: PDF_TEXT_READER_LIMITS.maxAddressSpaceBytes, maxCpuSeconds: PDF_TEXT_READER_LIMITS.maxCpuSeconds, maxWallMilliseconds: PDF_TEXT_READER_LIMITS.maxTimeoutMs };
  for (const [key, v] of Object.entries(fixed)) requireThat(limits[key] === v, "INVALID_LIMITS");
  requireThat(integer(limits.maxTextCodeUnits, PDF_TEXT_READER_LIMITS.maxTextCodeUnits) && limits.maxTextCodeUnits > 0 && integer(limits.maxOutputBytes, PDF_TEXT_READER_LIMITS.maxOutputBytes) && limits.maxOutputBytes >= 4096, "INVALID_LIMITS");
  requireThat(Array.isArray(result.pages) && result.pages.length > 0 && result.pages.length <= limits.maxPages, "INVALID_LOCATOR");
  let textUnits = 0;
  let items = 0;
  const pages = result.pages.map((p, index) => {
    requireThat(p.pageIndex === index && [p.width, p.height].every((v) => Number.isFinite(v) && v > 0 && v <= limits.maxPagePoints) && [0, 90, 180, 270].includes(p.rotation) && p.coordinateSystem === "viewport-points-top-left" && p.requiresInspection === true && Array.isArray(p.textBoxes), "INVALID_LOCATOR");
    const boxes = p.textBoxes.map((b) => {
      requireThat(typeof b.text === "string" && b.text.length > 0 && b.text.length <= limits.maxTextItemCodeUnits && b.geometry === "approximate-text-item", "INVALID_LOCATOR");
      requireThat([b.x, b.y, b.width, b.height].every((v) => Number.isFinite(v) && v >= 0) && b.x + b.width <= p.width + 0.01 && b.y + b.height <= p.height + 0.01, "INVALID_LOCATOR");
      textUnits += b.text.length; items += 1;
      return { x: b.x, y: b.y, width: b.width, height: b.height, geometry: b.geometry, textSha256: sha256(Buffer.from(b.text, "utf8")), textHashDomain: "derived-text-utf8" };
    });
    requireThat(p.textPresence === (boxes.length ? "text-present" : "no-embedded-text"), "INVALID_COMPLETENESS");
    return { pageIndex: index, width: p.width, height: p.height, rotation: p.rotation, coordinateSystem: p.coordinateSystem, textPresence: p.textPresence, requiresInspection: true, boxes };
  });
  requireThat(textUnits <= limits.maxTextCodeUnits && items <= limits.maxTextItems, "RESOURCE_LIMIT");
  requireThat((result.kind === "no-text") === (items === 0), "INVALID_COMPLETENESS");
  if (result.kind === "no-text") requireThat(result.code === "NO_EMBEDDED_TEXT", "INVALID_COMPLETENESS");
  const projectedLimits = { ...fixed, maxTextCodeUnits: limits.maxTextCodeUnits, maxOutputBytes: limits.maxOutputBytes };
  return { componentVersion: "ei-text-pdf/1", decoder: result.decoder, status: result.kind, nativeSourceHash: result.documentSha256, completeness: "incomplete-text-only", requiresInspection: true, limits: projectedLimits, networkAttemptCount: 0, networkEvidence: "reader API counter; not native-host attestation", pages };
}

/** Compose local integrity evidence. Input origins and source revisions are
 * checked host selections, never issuer trust or proof of test execution. */
export function composeInspectionReport(input) {
  try { return composeValidatedInput(input); }
  catch (error) {
    if (error instanceof InspectionReportError) throw error;
    throw new InspectionReportError("INVALID_INPUT");
  }
}

function composeValidatedInput(input) {
  record(input);
  const pins = validatePins(input.expectedPins);
  const matrix = selectedArtifacts(input.artifacts, pins);
  requireThat(MODES.includes(input.requiredMode));
  requireThat(["missing", "held", "selected-unaccepted"].includes(input.mappingState));
  const executionInputs = dataArray(input.executions, INSPECTION_REPORT_LIMITS.maxExecutions);
  const observationInputs = dataArray(input.observations, INSPECTION_REPORT_LIMITS.maxObservations);
  const byId = (a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  const executions = executionInputs.map((e) => parseExecution(e, pins, input.requiredMode)).sort(byId);
  requireThat(new Set(executions.map((e) => e.id)).size === executions.length, "DUPLICATE_ID");
  requireThat(new Set(executions.map((e) => e.component)).size === executions.length, "DUPLICATE_COMPONENT");
  const executionMap = new Map(executions.map((e) => [e.id, e]));
  let totalSourceBytes = 0;
  const observations = observationInputs.map((o) => {
    record(o);
    requireThat(matches(ID, o.id) && COMPONENTS.includes(o.component) && FORMATS.includes(o.format));
    requireThat(equal(validatePins(o.pins), pins), "PIN_MISMATCH");
    requireThat(matches(HASH, o.expectedSourceSha256));
    const source = bytes(o.sourceBytes, INSPECTION_REPORT_LIMITS.maxSourceBytes);
    totalSourceBytes += source.length;
    requireThat(totalSourceBytes <= INSPECTION_REPORT_LIMITS.maxTotalSourceBytes, "RESOURCE_LIMIT");
    requireThat(sha256(source) === o.expectedSourceSha256, "SOURCE_HASH_MISMATCH");
    const result = jsonCopy(o.result);
    const resultBytes = Buffer.from(canonical(result));
    const view = o.component === "deterministic-extraction" ? deterministic(result, source, o.format, o.sourceMetadata, o.declaredLimits) : pdf(result, source, o.format);
    const execution = executionMap.get(o.executionId);
    requireThat(execution && execution.component === o.component, "EXECUTION_BINDING_MISMATCH");
    return { id: o.id, component: o.component, format: o.format, executionId: execution.id, source: { domain: "original-source-bytes", sha256: sha256(source), bytes: source.length }, result: { domain: "canonical-component-result-json", sha256: sha256(resultBytes), bytes: resultBytes.length }, view };
  }).sort(byId);
  requireThat(new Set(observations.map((o) => o.id)).size === observations.length, "DUPLICATE_ID");
  requireThat(new Set(observations.map((o) => `${o.component}:${o.source.sha256}:${o.format}`)).size === observations.length, "DUPLICATE_OBSERVATION");
  const missingFormats = matrix.requiredFormats.filter((f) => !observations.some((o) => o.format === f));
  const prerequisite = executions.find((e) => e.component === "deterministic-extraction");
  const reasons = ["ACCOUNTABLE_ACCEPTANCE_NOT_RECORDED", `CANONICAL_MAPPING_${input.mappingState.toUpperCase().replaceAll("-", "_")}`];
  if (!prerequisite) reasons.push("DETERMINISTIC_PREREQUISITE_MISSING");
  else if (!prerequisite.complete) reasons.push("DETERMINISTIC_PREREQUISITE_INCOMPLETE");
  if (missingFormats.length) reasons.push("REQUIRED_FORMATS_MISSING");
  if (executions.some((e) => !e.complete)) reasons.push("EXECUTION_INCOMPLETE");
  if (executions.some((e) => e.mode !== input.requiredMode)) reasons.push("MODE_MISMATCH");
  if (input.requiredMode !== "mock" || executions.some((e) => e.origin !== "local-synthetic")) reasons.push("RECORDED_OR_PROVIDER_EXECUTION_NOT_AUTHENTICATED");
  if (observations.some((o) => o.view.requiresInspection)) reasons.push("INSPECTION_OR_FACT_REVIEW_REQUIRED");
  const limitation = observations.some((o) => o.component === "deterministic-extraction" ? o.view.status !== "PARTIAL" && o.view.status !== "NO_ANSWER" : o.view.completeness === "rejected");
  if (limitation) reasons.push("COMPONENT_LIMITATION");
  const report = freeze(jsonCopy({ schemaVersion: INSPECTION_REPORT_VERSION, pins, pinAuthority: "checked-host-selection-only", requiredMode: input.requiredMode, mappingState: input.mappingState, overall: "incomplete", acceptance: { evaluated: false, satisfiedIds: [], ownerAcknowledgements: [] }, providerActivity: "not established by report validation", financeAuthority: "none", requiredFormats: matrix.requiredFormats, missingFormats, declaredCoverage: prerequisite?.complete && missingFormats.length === 0 && executions.every((e) => e.complete) && !limitation ? "complete" : "incomplete", prerequisiteDeterministicReport: prerequisite?.summary ?? null, executions, observations, reasons: reasons.sort() }));
  const encoded = Buffer.from(canonical(report));
  requireThat(encoded.length <= INSPECTION_REPORT_LIMITS.maxReportBytes, "RESOURCE_LIMIT");
  return Object.freeze({ report, sha256: sha256(encoded), byteLength: encoded.length, copyBytes: () => new Uint8Array(encoded) });
}

/** Recompute all source/result/artifact/summary joins, then require exact
 * canonical bytes. Neither a supplied digest nor well-formed JSON is sufficient. */
export function validateInspectionReport(reportBytes, expectedSha256, input) {
  try {
    requireThat(matches(HASH, expectedSha256));
    const supplied = bytes(reportBytes, INSPECTION_REPORT_LIMITS.maxReportBytes);
    requireThat(sha256(supplied) === expectedSha256, "REPORT_HASH_MISMATCH");
    const parsed = parseJson(supplied, INSPECTION_REPORT_LIMITS.maxReportBytes);
    requireThat(parsed?.schemaVersion === INSPECTION_REPORT_VERSION, "UNSUPPORTED_VERSION");
    const recomputed = composeInspectionReport(input);
    requireThat(supplied.equals(Buffer.from(recomputed.copyBytes())), "REPORT_BYTES_MISMATCH");
    return recomputed;
  } catch (error) {
    if (error instanceof InspectionReportError) throw error;
    throw new InspectionReportError("INVALID_INPUT");
  }
}
