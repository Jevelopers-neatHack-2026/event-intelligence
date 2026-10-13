// Pure local evidence composition. No decoder, OCR worker, URL or callback runs here.
import { InspectionReportError } from "./index.mjs";
import { validateInspectionMediaReport } from "./media.mjs";
import { array, bytes, canonical, check, data, exactKeys, freeze, hash, identity, integer, isHash, isId, parseJson, record, same } from "./media-data.mjs";
import { PROFILE as IMAGE_PROFILE, STATIC_IMAGE_OCR_LIMITS, STATIC_IMAGE_OCR_ERRORS, PNG_DECODER, RASTER_DECODER } from "../static-image-ocr/profile.mjs";
import { PROFILE as PDF_PROFILE, SCANNED_PDF_OCR_LIMITS, SCANNED_PDF_OCR_ERRORS, PDF_ENGINE, OCR_ENGINE } from "../scanned-pdf-ocr/profile.mjs";

export const INSPECTION_OCR_REPORT_VERSION = "ei-local-inspection-ocr-report/1";
export const INSPECTION_OCR_REPORT_LIMITS = Object.freeze({ maxObservations: 32, maxExecutions: 2, maxResultBytes: 1024 * 1024,
  maxTotalResultBytes: 4 * 1024 * 1024, maxReportBytes: 8 * 1024 * 1024, maxSummaryBytes: 1024 * 1024,
  maxStderrBytes: 256 * 1024, maxRuntimeBytes: 512 * 1024, maxPages: 4, maxWords: 2048, maxTextBytes: 32768 });
const L = INSPECTION_OCR_REPORT_LIMITS;
const COMPONENTS = ["static-image-ocr", "scanned-pdf-ocr"];
const FORMATS = ["png", "jpeg", "webp", "scanned-pdf"];
const COUNTS = ["tests", "pass", "fail", "cancelled", "skipped", "todo"];
const FILES = Object.fromEntries(COMPONENTS.map((c) => [c, ["admission", "protocol", "lifecycle", "deadline-overlay", "reader"].map((n) => `tests/extraction/${c}/${n}.test.mjs`)]));
const MODES = {
  "static-image-ocr": "synthetic sources; actual PNG/JPEG/WebP-to-Tesseract native composition, child-close and recovery; separately simulated stage/protocol/admission cases; no provider calls",
  "scanned-pdf-ocr": "synthetic PDF/raster sources; real PDFium-to-Tesseract composition and native child recovery; separately simulated stage/protocol/queue cases; no provider calls",
};
const EXPECTED = { "static-image-ocr": 137, "scanned-pdf-ocr": 143 };
const byId = (a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
const decoderPdf = { ...PDF_ENGINE, profile: "classic-full-page-rgb-flate-v1", syscallPolicy: "linux-x86_64-preloaded-default-deny-v1", enforcementControlsPassed: 8 };
const observer = { ...OCR_ENGINE, profile: "english-lstm-single-block-raster-v1", syscallPolicy: "linux-x86_64-single-thread-ocr-default-deny-v1", enforcementControlsPassed: 8 };

function selected(value, expected, max, domain) {
  check(isHash(expected)); const owned = bytes(value, max);
  check(hash(owned) === expected, "ARTIFACT_HASH_MISMATCH"); return { owned, identity: identity(owned, domain) };
}
function keys(value, required, optional = []) {
  record(value); const names = Object.keys(value);
  check(required.every((k) => names.includes(k)) && names.every((k) => required.includes(k) || optional.includes(k)), "INVALID_SHAPE");
}
function effectiveLimits(actual, limits) {
  exactKeys(actual, [...Object.keys(limits), "timeoutMs"]);
  for (const [name, maximum] of Object.entries(limits)) {
    check(["maxWords", "maxTextBytes", "maxOutputBytes"].includes(name) ? integer(actual[name], maximum, 1) : actual[name] === maximum, "INVALID_LIMITS");
  }
  check(integer(actual.timeoutMs, limits.maxTimeoutMs, 1), "INVALID_LIMITS");
}
function provenance(value, expected) {
  exactKeys(value, ["sourceSha256", "derivativeSha256", "page", "width", "height", "format", "coordinateSystem", "sourceBinding"]);
  check(same(value, { ...expected, format: "rgba8", coordinateSystem: "top-left-pixels", sourceBinding: "caller-supplied-unverified" }), "PROVENANCE_MISMATCH");
}
function words(result, expected, limits) {
  provenance(result.provenance, expected);
  const list = array(result.words, limits.maxWords); let total = 0;
  for (const w of list) {
    exactKeys(w, ["text", "confidence", "confidenceMeaning", "requiresReview", "block", "paragraph", "line", "word", "box", "provenance"]);
    check(typeof w.text === "string" && w.text.length > 0 && w.text.isWellFormed() && !/[\u0000-\u001f\u007f]/.test(w.text), "INVALID_WORD");
    total += Buffer.byteLength(w.text); check(total <= limits.maxTextBytes, "RESOURCE_LIMIT");
    check(typeof w.confidence === "number" && Number.isFinite(w.confidence) && w.confidence >= 0 && w.confidence <= 100 && w.confidenceMeaning === "uncalibrated-engine-score" && w.requiresReview === true, "INVALID_WORD");
    for (const k of ["block", "paragraph", "line", "word"]) check(integer(w[k], 2147483647, 1), "INVALID_WORD");
    exactKeys(w.box, ["left", "top", "width", "height"]);
    check(integer(w.box.left, expected.width) && integer(w.box.top, expected.height) && integer(w.box.width, expected.width, 1) && integer(w.box.height, expected.height, 1) && w.box.left + w.box.width <= expected.width && w.box.top + w.box.height <= expected.height, "INVALID_GEOMETRY");
    provenance(w.provenance, expected);
  }
  check(result.tokenUtf8Bytes === total, "COUNT_MISMATCH");
  check(result.status === (list.length ? "text-observations" : "no-text-observed"), "STATUS_MISMATCH");
  return { words: list.length, tokenUtf8Bytes: total };
}
function execution(input, base, runtime) {
  exactKeys(input, ["id", "component", "pins", "mode", "origin", "stdoutBytes", "stderrBytes", "childStderrBytes", "exitCode", "signal", "callerRecordBytes", "expectedCallerRecordSha256"]);
  check(isId(input.id) && COMPONENTS.includes(input.component));
  check(same(data(input.pins), base.pins), "PIN_MISMATCH");
  check(["mock", "recorded", "sandbox", "live"].includes(input.mode) && ["local-synthetic", "recorded"].includes(input.origin));
  check(input.exitCode === null || integer(input.exitCode, 255));
  check(input.signal === null || ["SIGTERM", "SIGKILL", "SIGABRT", "SIGINT"].includes(input.signal));
  const stdout = bytes(input.stdoutBytes, L.maxSummaryBytes, true), stderr = bytes(input.stderrBytes, L.maxStderrBytes, true);
  const child = input.childStderrBytes === null ? null : bytes(input.childStderrBytes, L.maxStderrBytes, true);
  let callerRecord = null, callerRecords = [];
  if (input.callerRecordBytes === null) check(input.expectedCallerRecordSha256 === null);
  else {
    const bound = selected(input.callerRecordBytes, input.expectedCallerRecordSha256, L.maxSummaryBytes, "supplied-ocr-caller-record-bytes");
    const c = parseJson(bound.owned, L.maxSummaryBytes);
    exactKeys(c, ["schemaVersion", "executionId", "component", "source", "records"]);
    check(c.schemaVersion === "ei-local-ocr-caller-observations/1" && c.executionId === input.id && c.component === input.component, "CALLER_RECORD_MISMATCH");
    check(same(c.source, base.source.observed), "CALLER_RECORD_MISMATCH");
    callerRecords = array(c.records, L.maxObservations);
    for (const r of callerRecords) {
      exactKeys(r, ["id", "mediaObservationId", "resultSha256", "providedSourceSha256"]);
      check(isId(r.id) && isId(r.mediaObservationId) && isHash(r.resultSha256) && (r.providedSourceSha256 === null || isHash(r.providedSourceSha256)), "CALLER_RECORD_MISMATCH");
    }
    check(new Set(callerRecords.map((r) => r.id)).size === callerRecords.length, "DUPLICATE_ID");
    callerRecord = bound.identity;
  }
  let text; try { text = new TextDecoder("utf-8", { fatal: true }).decode(stdout); } catch { throw new InspectionReportError("INVALID_SUMMARY"); }
  const matches = [...text.matchAll(/^\{[^\r\n]*\}\r?$/gm)]; check(matches.length <= 1, "DUPLICATE_SUMMARY");
  const out = { id: input.id, component: input.component, mode: input.mode, origin: input.origin,
    stdout: identity(stdout, "ocr-wrapper-stdout-bytes"), stderr: identity(stderr, "ocr-wrapper-stderr-bytes"),
    childStderr: child === null ? null : identity(child, "ocr-child-stderr-bytes"), exitCode: input.exitCode, signal: input.signal,
    callerRecord, callerRecords, callerAuthority: "separately supplied caller record; not an issuer signature or suite-to-call identity proof" };
  if (!matches.length) return { ...out, counts: null, complete: false, state: "missing-summary" };
  const match = matches[0]; check(text.slice(match.index + match[0].length).trim() === "", "NONTERMINAL_SUMMARY");
  const n = parseJson(Buffer.from(match[0]), L.maxSummaryBytes), tap = Buffer.from(text.slice(0, match.index)); record(n);
  check(n.mode === MODES[input.component] && n.expectedTests === EXPECTED[input.component] && same(n.files, FILES[input.component]) && n.node === "22.23.3", "UNSUPPORTED_SUMMARY");
  const counts = {}; exactKeys(n.counts, COUNTS);
  for (const name of COUNTS) {
    const found = [...tap.toString().matchAll(new RegExp("^# " + name + " (\\d+)\\r?$", "gm"))]; check(found.length <= 1, "DUPLICATE_SUMMARY");
    counts[name] = found.length ? Number(found[0][1]) : null;
    check(n.counts[name] === counts[name], "COUNT_MISMATCH");
  }
  if (Object.values(counts).every((v) => v !== null)) {
    check(counts.tests === counts.pass + counts.fail + counts.cancelled + counts.skipped + counts.todo, "COUNT_MISMATCH");
    const verdicts = [...tap.toString().matchAll(/^(not ok|ok) (\d+)(?: - ([^\r\n]*))?\r?$/gm)], plans = [...tap.toString().matchAll(/^1\.\.(\d+)\r?$/gm)];
    check(plans.length === 1 && Number(plans[0][1]) === counts.tests && verdicts.length === counts.tests && verdicts.every((v, i) => Number(v[2]) === i + 1), "COUNT_MISMATCH");
    check(verdicts.filter((v) => v[1] === "ok" && !/ # (?:SKIP|TODO)(?:\s|$)/i.test(v[3] ?? "")).length === counts.pass, "FALSE_PASS");
  }
  check(isHash(n.stdoutSha256) && hash(tap) === n.stdoutSha256 && isHash(n.stderrSha256), "SUMMARY_HASH_MISMATCH");
  if (child !== null) check(hash(child) === n.stderrSha256, "SUMMARY_HASH_MISMATCH");
  check(typeof n.complete === "boolean" && typeof n.sourceUnchanged === "boolean");
  const markers = array(input.component === "static-image-ocr" ? n.runtimeMarkers : n.runtime, 2);
  // Current static-image verifier names this boolean runtimeMarkersUnchanged.
  const unchanged = input.component === "static-image-ocr" ? n.runtimeMarkersUnchanged : n.runtimeUnchanged;
  check(typeof unchanged === "boolean");
  const ocr = markers.filter((m) => { record(m); return input.component === "static-image-ocr" ? m.name === "local-ocr" : typeof m.path === "string" && m.path.endsWith("tools/local-ocr/runtime/manifest.json"); });
  const mediaComponent = input.component === "static-image-ocr" ? "static-jpeg-webp" : "scanned-pdf";
  const mediaRuntime = base.runtimeReceipts.find((r) => r.component === mediaComponent)?.manifest;
  const mediaMarkers = markers.filter((m) => input.component === "static-image-ocr" ? m.name === "static-raster" : typeof m.path === "string" && m.path.endsWith("tools/scanned-pdf/runtime/manifest.json"));
  const runtimeBound = markers.length === 2 && ocr.length === 1 && runtime !== null && ocr[0].sha256 === runtime.sha256 && ocr[0].bytes === runtime.bytes && mediaMarkers.length === 1 && mediaRuntime !== undefined && mediaMarkers[0].sha256 === mediaRuntime.sha256 && mediaMarkers[0].bytes === mediaRuntime.bytes;
  const clean = counts.tests === EXPECTED[input.component] && counts.pass === counts.tests && COUNTS.slice(2).every((k) => counts[k] === 0);
  if (n.complete) check(clean && n.exitCode === 0 && n.signal === null && n.executionError === null && n.sourceUnchanged && unchanged === true, "FALSE_PASS");
  const sourceMatches = same(n.source, base.source.observed);
  const complete = n.complete && clean && sourceMatches && base.source.complete && runtimeBound && child !== null && input.exitCode === 0 && input.signal === null && input.mode === "mock" && base.requiredMode === "mock" && input.origin === "local-synthetic";
  return { ...out, counts, complete, state: complete ? "complete-local-execution" : "incomplete-execution", nativeMode: n.mode,
    sourceMatches, runtimeBound, childStderrBound: child !== null,
    authority: "bound supplied execution bytes; no signature, native issuer trust or provider authorization" };
}

function observation(input, base, executions, budget) {
  exactKeys(input, ["id", "component", "mediaObservationId", "executionId", "result", "expectedResultSha256"]);
  check(isId(input.id) && COMPONENTS.includes(input.component) && isId(input.mediaObservationId) && isId(input.executionId));
  check(executions.get(input.executionId)?.component === input.component, "EXECUTION_BINDING_MISMATCH");
  const media = base.observations.find((o) => o.id === input.mediaObservationId); check(media, "MEDIA_BINDING_MISMATCH");
  const pdf = input.component === "scanned-pdf-ocr";
  check(pdf ? media.component === "scanned-pdf" : ["static-png", "static-jpeg-webp"].includes(media.component), "MEDIA_BINDING_MISMATCH");
  // Native early refusal objects own sourceSha256: undefined. Omit only
  // declared absent refusal metadata; never synthesize the native source hash.
  record(input.result);
  let supplied = input.result;
  if (input.result.kind === "rejected") {
    supplied = Object.fromEntries(Object.entries(input.result).filter(([key, value]) => value !== undefined || !["sourceSha256", "stage", "componentCode", "page"].includes(key)));
  }
  const r = data(supplied, L.maxResultBytes), encoded = Buffer.from(canonical(r));
  check(isHash(input.expectedResultSha256) && hash(encoded) === input.expectedResultSha256, "RESULT_HASH_MISMATCH");
  budget.bytes += encoded.length; check(budget.bytes <= L.maxTotalResultBytes, "RESOURCE_LIMIT");
  record(r); check(r.profile === (pdf ? PDF_PROFILE : IMAGE_PROFILE), "UNSUPPORTED_VERSION");
  const caller = executions.get(input.executionId).callerRecords.find((row) => row.id === input.id);
  if (caller) check(caller.mediaObservationId === media.id && caller.resultSha256 === input.expectedResultSha256 && caller.providedSourceSha256 === (media.source?.sha256 ?? null), "CALLER_RECORD_MISMATCH");
  const out = { id: input.id, component: input.component, format: media.format, mediaObservationId: media.id, executionId: input.executionId,
    result: identity(encoded, "ocr-result-canonical-json-bytes"),
    originalSource: media.source, nativeIssuerAuthority: "not established by caller-supplied structural data",
    sourceAuthority: "unverified", factInference: "none", requiresReview: true,
    callerRecordBound: caller !== undefined,
    executionAttribution: caller ? "result/source digests match supplied caller record; suite coverage remains separate" : "separately supplied observation; no caller execution join" };
  if (r.kind === "rejected") {
    keys(r, ["kind", "profile", "code"], ["sourceSha256", "stage", "componentCode", ...(pdf ? ["page"] : [])]);
    check((pdf ? SCANNED_PDF_OCR_ERRORS : STATIC_IMAGE_OCR_ERRORS).includes(r.code), "INVALID_STATUS");
    if (r.sourceSha256 !== undefined) check(media.source !== null && r.sourceSha256 === media.source.sha256, "SOURCE_HASH_MISMATCH");
    if (r.stage !== undefined) check((pdf ? ["admission", "render", "pixels", "ocr", "aggregate"] : ["admission", "decode", "pixels", "ocr", "aggregate"]).includes(r.stage));
    if (r.page !== undefined) check(integer(r.page, L.maxPages, 1));
    if (r.componentCode !== undefined) check(typeof r.componentCode === "string" && /^[A-Z][A-Z_]{0,63}$/.test(r.componentCode));
    return { ...out, binding: "refused-component-result", observation: r };
  }
  const common = ["kind", "profile", "completeness", "requiresReview", "sourceSha256", "sourceBinding", "sourceAuthority", "decoder", "observer", "tokenUtf8Bytes", "limits"];
  exactKeys(r, [...common, ...(pdf ? ["pages", "totalPages", "totalPixels", "totalWords"] : ["status", "image", "provenance", "words"])]);
  check(r.kind === "observed" && r.completeness === "incomplete-unverified-ocr" && r.requiresReview === true && r.sourceAuthority === "unverified", "INVALID_STATUS");
  check(r.sourceBinding === (pdf ? "local-pdf-reader-byte-chain" : "local-static-image-reader-byte-chain"), "PROVENANCE_MISMATCH");
  check(media.source !== null && r.sourceSha256 === media.source.sha256, "SOURCE_HASH_MISMATCH");
  check(media.native.kind === "decoded", "MEDIA_BINDING_MISMATCH");
  check(same(r.observer, observer), "UNSUPPORTED_VERSION");
  effectiveLimits(r.limits, pdf ? SCANNED_PDF_OCR_LIMITS : STATIC_IMAGE_OCR_LIMITS);
  check(encoded.length <= r.limits.maxOutputBytes, "RESOURCE_LIMIT");
  let missingRaw = false, totalWords = 0, totalText = 0;
  if (pdf) {
    check(same(r.decoder, decoderPdf), "UNSUPPORTED_VERSION");
    const pages = array(r.pages, L.maxPages); check(pages.length > 0 && pages.length === r.totalPages && pages.length === media.native.pages.length, "COUNT_MISMATCH");
    let pixels = 0;
    for (const [i, page] of pages.entries()) {
      exactKeys(page, ["page", "sourceSha256", "derivativeSha256", "width", "height", "pageWidthPoints", "pageHeightPoints", "pixelByteLength", "format", "coordinateSystem", "status", "provenance", "words", "tokenUtf8Bytes"]);
      const prior = media.native.pages[i], raw = media.derivatives.find((d) => d.role === "page-rgba8" && d.page === i + 1);
      check(page.page === i + 1 && page.sourceSha256 === r.sourceSha256 && page.derivativeSha256 === prior.sha256 && page.width === prior.width && page.height === prior.height && page.pageWidthPoints === prior.pageWidthPoints && page.pageHeightPoints === prior.pageHeightPoints && page.pixelByteLength === prior.byteLength && page.format === "rgba8" && page.coordinateSystem === "top-left-pixels", "PROVENANCE_MISMATCH");
      if (!raw) missingRaw = true;
      else check(raw.sha256 === page.derivativeSha256 && raw.bytes === page.pixelByteLength && raw.rgbaHashVerified === true, "DERIVATIVE_HASH_MISMATCH");
      const count = words(page, { sourceSha256: r.sourceSha256, derivativeSha256: page.derivativeSha256, page: page.page, width: page.width, height: page.height }, r.limits);
      totalWords += count.words; totalText += count.tokenUtf8Bytes; pixels += page.width * page.height;
    }
    check(r.totalPixels === pixels && pixels <= r.limits.maxTotalPixels && r.totalWords === totalWords && r.tokenUtf8Bytes === totalText, "COUNT_MISMATCH");
  } else {
    const prior = media.native, im = r.image, isPng = media.component === "static-png";
    exactKeys(im, ["sourceFormat", "encoding", "sourceMode", "width", "height", "pixelByteLength", "rgbaSha256", "normalizedSha256", "normalizedByteLength", ...(!isPng ? ["runtimeManifestSha256"] : [])]);
    check(same(r.decoder, { ...(isPng ? PNG_DECODER : RASTER_DECODER), networkPolicy: "cooperative-api-guard-only" }), "UNSUPPORTED_VERSION");
    check(im.sourceFormat === media.format && im.width === prior.width && im.height === prior.height && im.pixelByteLength === prior.decodedRgbaBytes && im.rgbaSha256 === prior.rgbaSha256 && im.normalizedSha256 === prior.normalizedSha256 && im.normalizedByteLength === prior.normalizedByteLength, "PROVENANCE_MISMATCH");
    check(im.encoding === (isPng ? (prior.sourceColorType === 2 ? "rgb8" : "rgba8") : prior.encoding) && im.sourceMode === (isPng ? (prior.sourceColorType === 2 ? "RGB" : "RGBA") : prior.sourceMode), "PROVENANCE_MISMATCH");
    if (!isPng) check(im.runtimeManifestSha256 === prior.runtimeManifestSha256, "RUNTIME_MISMATCH");
    const raw = media.derivatives.find((d) => d.role === "image-rgba8");
    if (!raw) missingRaw = true;
    else check(raw.sha256 === im.rgbaSha256 && raw.bytes === im.pixelByteLength && raw.rgbaHashVerified === true && raw.alpha.opaque === im.width * im.height, "DERIVATIVE_HASH_MISMATCH");
    const count = words(r, { sourceSha256: r.sourceSha256, derivativeSha256: im.rgbaSha256, page: 1, width: im.width, height: im.height }, r.limits);
    totalWords = count.words; totalText = count.tokenUtf8Bytes;
  }
  check(totalWords <= r.limits.maxWords && totalText <= r.limits.maxTextBytes, "RESOURCE_LIMIT");
  return { ...out, binding: missingRaw ? "unbound-missing-raw-bytes" : "bound-supplied-byte-domains", observation: r,
    pixelDomainAuthority: "independently hashed supplied copies; no cross-decode equivalence or OCR issuer attestation",
    totalWords, tokenUtf8Bytes: totalText };
}

function compose(input) {
  exactKeys(input, ["prerequisite", "runtimeReceipt", "requiredFormats", "executions", "observations"]);
  exactKeys(input.prerequisite, ["input", "reportBytes", "expectedSha256"]);
  const prerequisite = validateInspectionMediaReport(input.prerequisite.reportBytes, input.prerequisite.expectedSha256, input.prerequisite.input), base = prerequisite.report;
  let runtime = null;
  if (input.runtimeReceipt !== null) {
    exactKeys(input.runtimeReceipt, ["bytes", "expectedSha256"]);
    runtime = selected(input.runtimeReceipt.bytes, input.runtimeReceipt.expectedSha256, L.maxRuntimeBytes, "selected-local-ocr-runtime-manifest-bytes").identity;
  }
  const requiredFormats = array(input.requiredFormats, 4); check(requiredFormats.every((f) => FORMATS.includes(f)) && new Set(requiredFormats).size === requiredFormats.length, "INVALID_FORMAT");
  const executions = array(input.executions, L.maxExecutions).map((e) => execution(e, base, runtime)).sort(byId);
  check(new Set(executions.map((e) => e.id)).size === executions.length && new Set(executions.map((e) => e.component)).size === executions.length, "DUPLICATE_ID");
  const budget = { bytes: 0 }, executionMap = new Map(executions.map((e) => [e.id, e]));
  const observations = array(input.observations, L.maxObservations).map((o) => observation(o, base, executionMap, budget)).sort(byId);
  check(new Set(observations.map((o) => o.id)).size === observations.length, "DUPLICATE_ID");
  check(new Set(observations.map((o) => o.component + ":" + o.mediaObservationId + ":" + o.result.sha256)).size === observations.length, "DUPLICATE_OBSERVATION");
  const missingFormats = requiredFormats.filter((f) => !observations.some((o) => o.format === f && o.binding === "bound-supplied-byte-domains"));
  const reasons = new Set(base.reasons);
  if (missingFormats.length) reasons.add("OCR_REQUIRED_FORMATS_MISSING");
  if (runtime === null) reasons.add("OCR_RUNTIME_RECEIPT_MISSING");
  if (executions.some((e) => !e.complete)) reasons.add("OCR_EXECUTION_INCOMPLETE");
  if (observations.some((o) => o.binding !== "bound-supplied-byte-domains")) reasons.add("OCR_OBSERVATION_LIMITATION");
  if (observations.some((o) => !o.callerRecordBound)) reasons.add("OCR_CALLER_RECORD_MISSING");
  for (const e of executions) for (const r of e.callerRecords) check(observations.some((o) => o.id === r.id && o.executionId === e.id), "CALLER_RECORD_MISMATCH");
  reasons.add("OCR_REQUIRES_REVIEW");
  const report = freeze({ schemaVersion: INSPECTION_OCR_REPORT_VERSION, pins: base.pins, pinAuthority: "checked-host-selection-only",
    overall: "incomplete", acceptance: { evaluated: false, satisfiedIds: [], ownerAcknowledgements: [] }, financeAuthority: "none", factInference: "none",
    prerequisite: { ...identity(prerequisite.copyBytes(), "inspection-media-report-bytes"), report: base }, runtimeReceipt: runtime,
    runtimeAuthority: "selected byte identity only; installation, model execution and host trust are not reattested",
    requiredFormats: [...requiredFormats].sort(), missingFormats: missingFormats.sort(), executions, observations, totalResultBytes: budget.bytes,
    reasons: [...reasons].sort(), authority: "private local report; OCR words remain untrusted observations, never accepted facts, permissions or consumer ACKs" });
  // Use a larger outer bound explicitly; prerequisite has already enforced its own ceilings.
  const encoded = Buffer.from(JSON.stringify(data(report, L.maxReportBytes)) + "\n"); check(encoded.length <= L.maxReportBytes, "RESOURCE_LIMIT");
  return Object.freeze({ report, sha256: hash(encoded), byteLength: encoded.length, copyBytes: () => new Uint8Array(encoded) });
}
export function composeInspectionOcrReport(input) {
  try { return compose(input); } catch (e) { if (e instanceof InspectionReportError) throw e; throw new InspectionReportError("INVALID_INPUT"); }
}
export function validateInspectionOcrReport(reportBytes, expectedSha256, input) {
  try {
    const supplied = selected(reportBytes, expectedSha256, L.maxReportBytes, "inspection-ocr-report-bytes").owned;
    check(parseJson(supplied, L.maxReportBytes).schemaVersion === INSPECTION_OCR_REPORT_VERSION, "UNSUPPORTED_VERSION");
    const result = composeInspectionOcrReport(input);
    check(supplied.equals(Buffer.from(result.copyBytes())), "REPORT_BYTES_MISMATCH"); return result;
  } catch (e) { if (e instanceof InspectionReportError) throw e; throw new InspectionReportError("INVALID_INPUT"); }
}
