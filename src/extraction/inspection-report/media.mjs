import { crc32 } from "node:zlib";
import { InspectionReportError, validateInspectionReport } from "./index.mjs";
import { PNG_DECODER, PNG_ERROR_CODES, PNG_LIMITS } from "../png/constants.mjs";
import { RASTER_DECODER, RASTER_ERROR_CODES, RASTER_LIMITS, RASTER_WHEEL_SHA256 } from "../jpeg-webp/constants.mjs";
import { SCANNED_PDF_ERRORS, SCANNED_PDF_LIMITS } from "../scanned-pdf/index.mjs";
import profile from "../scanned-pdf/profile.json" with { type: "json" };
import { array, bytes, canonical, check, data, exactKeys, freeze, hash, identity, integer, isHash, isId, isRevision, parseJson, record, same } from "./media-data.mjs";

export const INSPECTION_MEDIA_REPORT_VERSION = "ei-local-inspection-media-report/1";
export const INSPECTION_MEDIA_PROJECTION_VERSION = "ei-native-media-data-projection/1";
export const INSPECTION_SOURCE_SNAPSHOT_VERSION = "ei-inspection-source-snapshot/1";
export const INSPECTION_MEDIA_REPORT_LIMITS = Object.freeze({
  maxObservations: 32, maxExecutions: 3, maxPages: 4,
  maxSourceBytes: 20 * 1024 * 1024, maxTotalSourceBytes: 64 * 1024 * 1024,
  maxDerivativeBytes: 20 * 1024 * 1024, maxTotalDerivativeBytes: 64 * 1024 * 1024,
  maxSummaryBytes: 1024 * 1024, maxStderrBytes: 256 * 1024,
  maxSourceReceiptBytes: 1024 * 1024, maxSourceFiles: 4096,
  maxRuntimeReceiptBytes: 256 * 1024, maxReportBytes: 4 * 1024 * 1024,
});
const L = INSPECTION_MEDIA_REPORT_LIMITS;
const COMPONENTS = ["static-png", "static-jpeg-webp", "scanned-pdf"];
const MODES = ["mock", "recorded", "sandbox", "live"];
const PDF_ENGINE = Object.freeze({ name: "PDFium", version: profile.pdfiumVersion, bindings: "pypdfium2@" + profile.wrapperVersion });
const PDF_WHEEL = "11f281613fa22313d9c7ab89947665e84eccf8ebe40e1198a84a88352305648d";
const CASES = Object.freeze({
  "static-png": { expected: 93, files: ["core", "reader", "lifecycle", "network", "protocol"].map((name) => "tests/extraction/png/" + name + ".test.mjs"), mode: "local synthetic PNG bytes; actual Linux children; no provider calls" },
  "static-jpeg-webp": { expected: 158, files: ["reader", "profile", "native-validation", "webp-native", "normalization", "lifecycle", "protocol", "network", "runtime", "setup"].map((name) => "tests/extraction/jpeg-webp/" + name + ".test.mjs"), mode: "synthetic JPEG/WebP fixtures; actual pinned native decodes and Linux child resource/lifecycle controls; local loopback canary; no provider calls" },
  "scanned-pdf": { expected: 99, files: ["reader", "lifecycle", "protocol", "native-boundary", "runtime"].map((name) => "tests/extraction/scanned-pdf/" + name + ".test.mjs"), mode: "synthetic PDF/pixel fixtures; real PDFium and native syscall/process controls; separately synthetic protocol producers; no provider requests" },
});
const byId = (a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
const safePath = (value) => typeof value === "string" && value.length > 0 && value.length <= 512 && !value.includes("\\") && !value.startsWith("/") && !/[\u0000-\u001f\u007f]/.test(value) && value.split("/").every((piece) => piece !== "" && piece !== "." && piece !== "..");

function selectedBytes(value, expected, maximum, domain, allowEmpty = false) {
  check(isHash(expected)); const owned = bytes(value, maximum, allowEmpty);
  check(hash(owned) === expected, "ARTIFACT_HASH_MISMATCH");
  return { owned, identity: identity(owned, domain) };
}
function sourceSnapshot(value) {
  exactKeys(value, ["schemaVersion", "revision", "tree", "dirty", "files"]);
  check(value.schemaVersion === INSPECTION_SOURCE_SNAPSHOT_VERSION, "UNSUPPORTED_VERSION");
  check(isRevision(value.revision) && isRevision(value.tree) && typeof value.dirty === "boolean");
  const files = array(value.files, L.maxSourceFiles); check(files.length > 0);
  let previous = "";
  for (const file of files) {
    exactKeys(file, ["path", "mode", "bytes", "sha256"]);
    check(safePath(file.path) && file.path > previous, "INVALID_SOURCE_PATH"); previous = file.path;
    check(integer(file.mode, 0o777) && integer(file.bytes, 128 * 1024 * 1024) && isHash(file.sha256));
  }
  return { ...value, fileMapSha256: hash(JSON.stringify(files)) };
}
function sourceBinding(input, pins) {
  record(input); check(isRevision(input.selectedTree));
  const before = selectedBytes(input.beforeBytes, input.expectedBeforeSha256, L.maxSourceReceiptBytes, "source-snapshot-json-bytes");
  const after = selectedBytes(input.afterBytes, input.expectedAfterSha256, L.maxSourceReceiptBytes, "source-snapshot-json-bytes");
  const first = sourceSnapshot(parseJson(before.owned, L.maxSourceReceiptBytes));
  const last = sourceSnapshot(parseJson(after.owned, L.maxSourceReceiptBytes));
  const matchesSelection = first.revision === pins.sourceRevision && first.tree === input.selectedTree && last.revision === pins.sourceRevision && last.tree === input.selectedTree;
  const unchanged = same(first, last);
  return {
    before: before.identity, after: after.identity,
    selectedTree: input.selectedTree, selectedRevision: pins.sourceRevision,
    observed: { revision: first.revision, tree: first.tree, dirty: first.dirty, files: first.files.length, sha256: first.fileMapSha256 },
    afterObserved: { revision: last.revision, tree: last.tree, dirty: last.dirty, files: last.files.length, sha256: last.fileMapSha256 },
    matchesSelection, unchanged, complete: matchesSelection && unchanged && !first.dirty && !last.dirty,
    authority: "byte-bound host source snapshots; not an execution signature or repository acceptance",
  };
}
function runtimeReceipts(input) {
  const result = new Map();
  for (const item of array(input, 2)) {
    record(item); check(["static-jpeg-webp", "scanned-pdf"].includes(item.component));
    check(!result.has(item.component), "DUPLICATE_COMPONENT");
    const artifact = selectedBytes(item.bytes, item.expectedSha256, L.maxRuntimeReceiptBytes, "native-runtime-manifest-bytes");
    const manifest = parseJson(artifact.owned, L.maxRuntimeReceiptBytes);
    record(manifest);
    let files, closure = null;
    if (item.component === "static-jpeg-webp") {
      check(manifest.schema === "ei-static-raster-runtime/1" && manifest.pythonVersion === "3.12.14" && manifest.implementation === "CPython" && manifest.architecture === "x86_64" && manifest.pillowVersion === "12.3.0" && manifest.jpegVersion === "6.2" && manifest.webpVersion === "1.6.0" && manifest.wheelSha256 === RASTER_WHEEL_SHA256, "RUNTIME_MISMATCH");
      check(manifest.wheelFilename === "pillow-12.3.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl" && manifest.sitePackages === "lib/python3.12/site-packages", "RUNTIME_MISMATCH");
      check(typeof manifest.pythonExecutable === "string" && manifest.pythonExecutable.startsWith("/") && isHash(manifest.pythonSha256), "RUNTIME_MISMATCH");
      files = array(manifest.files, 512);
    } else {
      const d = record(manifest.descriptor);
      check(d.schema === 1 && d.pythonVersion === profile.pythonVersion && d.platform === "Linux" && d.machine === "x86_64" && d.wheelSha256 === PDF_WHEEL && d.pdfiumVersion === profile.pdfiumVersion, "RUNTIME_MISMATCH");
      check(same(d.startup, { isolated: 1, noSite: 1, dontWriteBytecode: 1 }) && typeof d.python === "string" && d.python.startsWith("/"), "RUNTIME_MISMATCH");
      check(isHash(manifest.closureSha256) && hash(canonical(d).slice(0, -1)) === manifest.closureSha256, "RUNTIME_MISMATCH");
      closure = manifest.closureSha256; files = array(d.files, 512);
    }
    check(files.length > 0, "RUNTIME_MISMATCH"); const paths = new Set();
    for (const f of files) {
      record(f); check(typeof f.path === "string" && f.path.length <= 2048 && isHash(f.sha256) && integer(f.bytes, 256 * 1024 * 1024), "RUNTIME_MISMATCH");
      check(!paths.has(f.path), "RUNTIME_MISMATCH"); paths.add(f.path);
      if (item.component === "static-jpeg-webp") check(safePath(f.path), "RUNTIME_MISMATCH");
      else check(f.path.startsWith("/") && !/[\u0000-\u001f\u007f]/.test(f.path) && integer(f.mode, 0o777), "RUNTIME_MISMATCH");
    }
    result.set(item.component, { component: item.component, manifest: artifact.identity, files: files.length, closureSha256: closure,
      authority: "selected receipt bytes; runtime file installation and host authority are not reattested by the report" });
  }
  return result;
}

function tapSummary(text) {
  const counts = {};
  for (const name of ["tests", "pass", "fail", "cancelled", "skipped", "todo"]) {
    const found = [...text.matchAll(new RegExp("^# " + name + " (\\d+)\\r?$", "gm"))];
    check(found.length <= 1, "DUPLICATE_SUMMARY"); counts[name] = found.length ? Number(found[0][1]) : null;
  }
  if (Object.values(counts).some((value) => value === null)) return null;
  check(Object.values(counts).every((n) => integer(n, 100_000)), "COUNT_MISMATCH");
  check(counts.tests === counts.pass + counts.fail + counts.cancelled + counts.skipped + counts.todo, "COUNT_MISMATCH");
  const plans = [...text.matchAll(/^1\.\.(\d+)\r?$/gm)];
  check(plans.length === 1 && Number(plans[0][1]) === counts.tests, "COUNT_MISMATCH");
  const verdicts = [...text.matchAll(/^(not ok|ok) (\d+)(?: - ([^\r\n]*))?\r?$/gm)];
  check(verdicts.length === counts.tests && verdicts.every((v, i) => Number(v[2]) === i + 1), "COUNT_MISMATCH");
  const clean = verdicts.filter((v) => v[1] === "ok" && !/ # (?:SKIP|TODO)(?:\s|$)/i.test(v[3] ?? "")).length;
  check(clean === counts.pass, "FALSE_PASS");
  return counts;
}
function execution(input, pins, requiredMode, source) {
  record(input); check(isId(input.id) && COMPONENTS.includes(input.component));
  check(same(data(input.pins), pins), "PIN_MISMATCH");
  check(MODES.includes(input.mode) && ["local-synthetic", "recorded"].includes(input.origin));
  check(input.exitCode === null || integer(input.exitCode, 255));
  check(input.signal === null || ["SIGTERM", "SIGKILL", "SIGABRT", "SIGINT"].includes(input.signal));
  const stdout = bytes(input.stdoutBytes, L.maxSummaryBytes, true), stderr = bytes(input.stderrBytes, L.maxStderrBytes, true);
  const childStderr = input.childStderrBytes === null ? null : bytes(input.childStderrBytes, L.maxStderrBytes, true);
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(stdout); }
  catch { throw new InspectionReportError("INVALID_SUMMARY"); }
  const matches = [...text.matchAll(/^\{[^\r\n]*\}\r?$/gm)];
  check(matches.length <= 1, "DUPLICATE_SUMMARY");
  const chosen = CASES[input.component];
  const common = { id: input.id, component: input.component, declaredMode: input.mode, origin: input.origin,
    stdout: identity(stdout, "execution-wrapper-stdout-bytes"), stderr: identity(stderr, "execution-wrapper-stderr-bytes"),
    childStderr: childStderr === null ? null : identity(childStderr, "execution-child-stderr-bytes"),
    expectedCases: chosen.expected, exitCode: input.exitCode, signal: input.signal };
  if (!matches.length) return { ...common, nativeMode: null, counts: null, nativeDeclaredComplete: false, complete: false, state: "missing-summary" };
  const match = matches[0]; check(text.slice(match.index + match[0].length).trim() === "", "NONTERMINAL_SUMMARY");
  const native = parseJson(Buffer.from(match[0]), L.maxSummaryBytes);
  check(native.mode === chosen.mode && native.expectedTests === chosen.expected && same(native.files, chosen.files), "UNSUPPORTED_SUMMARY");
  check(typeof native.complete === "boolean");
  const tapBytes = Buffer.from(text.slice(0, match.index)), counts = tapSummary(tapBytes.toString("utf8"));
  const reported = data(native.counts); record(reported);
  check(same(Object.keys(reported).sort(), ["tests", "pass", "fail", "cancelled", "skipped", "todo"].sort()), "COUNT_MISMATCH");
  check(Object.values(reported).every((n) => n === null || integer(n, 100_000)), "COUNT_MISMATCH");
  check(counts === null ? !native.complete : same(counts, reported), "COUNT_MISMATCH");
  let nativeSourceMatches = true, childStderrMatches = true;
  if (input.component === "static-png") check(same(native.runtime, { node: PNG_DECODER.nodeVersion, zlib: PNG_DECODER.zlibVersion }), "UNSUPPORTED_VERSION");
  else if (input.component === "static-jpeg-webp") {
    check(same(native.runtime, RASTER_DECODER), "UNSUPPORTED_VERSION");
    check(native.childStatus === null || integer(native.childStatus, 255));
    check(native.childSignal === null || typeof native.childSignal === "string");
    check(native.childError === null || typeof native.childError === "string");
    if (native.complete) check(native.childStatus === 0 && native.childSignal === null && native.childError === null, "FALSE_PASS");
  } else {
    check(native.node === profile.nodeVersion && typeof native.sourceUnchanged === "boolean", "UNSUPPORTED_VERSION");
    record(native.source);
    check(isRevision(native.source.revision) && isRevision(native.source.tree) && typeof native.source.dirty === "boolean" && integer(native.source.files, L.maxSourceFiles, 1) && isHash(native.source.sha256));
    nativeSourceMatches = same(native.source, source.observed) && native.sourceUnchanged;
    check(isHash(native.stdoutSha256) && hash(tapBytes) === native.stdoutSha256, "SUMMARY_HASH_MISMATCH");
    check(isHash(native.stderrSha256));
    childStderrMatches = childStderr !== null && hash(childStderr) === native.stderrSha256;
    if (childStderr !== null) check(childStderrMatches, "SUMMARY_HASH_MISMATCH");
    if (native.complete) check(native.sourceUnchanged, "FALSE_PASS");
  }
  const cleanCases = counts !== null && counts.tests === chosen.expected && counts.pass === chosen.expected && ["fail", "cancelled", "skipped", "todo"].every((key) => counts[key] === 0);
  if (native.complete) check(cleanCases, "FALSE_PASS");
  const complete = native.complete && cleanCases && input.exitCode === 0 && input.signal === null && input.mode === "mock" && input.mode === requiredMode && input.origin === "local-synthetic" && source.complete && nativeSourceMatches && childStderrMatches;
  return { ...common, nativeMode: native.mode, nativeProviderMode: "mock", nativeDeclaredComplete: native.complete, counts: reported,
    tap: identity(tapBytes, "execution-child-tap-bytes"), nativeSourceMatches, childStderrMatches,
    complete, state: complete ? "complete-local-execution" : "incomplete-execution" };
}

function effectiveLimits(actual, limits) {
  exactKeys(actual, [...Object.keys(limits), "timeoutMs"]);
  for (const [key, value] of Object.entries(limits)) {
    if (key === "maxOutputBytes") check(integer(actual[key], value, 1), "INVALID_LIMITS");
    else check(actual[key] === value, "INVALID_LIMITS");
  }
  check(integer(actual.timeoutMs, limits.maxTimeoutMs, 1), "INVALID_LIMITS");
}
function normalizedPng(payload, width, height) {
  check(payload.length >= 57 && payload.subarray(0, 8).toString("hex") === "89504e470d0a1a0a", "DERIVATIVE_FORMAT_MISMATCH");
  let at = 8;
  for (const type of ["IHDR", "IDAT", "IEND"]) {
    check(at + 12 <= payload.length, "DERIVATIVE_FORMAT_MISMATCH");
    const size = payload.readUInt32BE(at), end = at + size + 8;
    check(end + 4 <= payload.length && payload.toString("ascii", at + 4, at + 8) === type, "DERIVATIVE_FORMAT_MISMATCH");
    check(crc32(payload.subarray(at + 4, end)) === payload.readUInt32BE(end), "DERIVATIVE_FORMAT_MISMATCH");
    if (type === "IHDR") check(size === 13 && payload.readUInt32BE(at + 8) === width && payload.readUInt32BE(at + 12) === height && payload.toString("hex", at + 16, end) === "0806000000", "DERIVATIVE_FORMAT_MISMATCH");
    if (type === "IDAT") check(size > 0, "DERIVATIVE_FORMAT_MISMATCH");
    if (type === "IEND") check(size === 0, "DERIVATIVE_FORMAT_MISMATCH");
    at = end + 4;
  }
  check(at === payload.length, "DERIVATIVE_FORMAT_MISMATCH");
}
function observation(input, pins, executions, runtimes, budget) {
  record(input); check(isId(input.id) && COMPONENTS.includes(input.component));
  check(same(data(input.pins), pins), "PIN_MISMATCH");
  const expectedFormat = input.component === "static-png" ? ["png"] : input.component === "static-jpeg-webp" ? ["jpeg", "webp"] : ["scanned-pdf"];
  check(expectedFormat.includes(input.format), "FORMAT_MISMATCH");
  const boundExecution = executions.get(input.executionId);
  check(boundExecution?.component === input.component, "EXECUTION_BINDING_MISMATCH");
  let source = null;
  if (input.sourceBytes === null) check(input.expectedSourceSha256 === null);
  else {
    check(isHash(input.expectedSourceSha256)); source = bytes(input.sourceBytes, L.maxSourceBytes, true);
    check(hash(source) === input.expectedSourceSha256, "SOURCE_HASH_MISMATCH");
    budget.source += source.length; check(budget.source <= L.maxTotalSourceBytes, "RESOURCE_LIMIT");
  }
  const projection = data(input.projection); exactKeys(projection, ["schemaVersion", "component", "result"]);
  check(projection.schemaVersion === INSPECTION_MEDIA_PROJECTION_VERSION && projection.component === input.component, "UNSUPPORTED_VERSION");
  const r = record(projection.result), isPdf = input.component === "scanned-pdf", isPng = input.component === "static-png";
  const derivatives = array(input.derivatives, L.maxPages);
  check(["decoded", "rejected"].includes(r.kind)); check(r.sourceSha256 === null || isHash(r.sourceSha256));
  if (r.sourceSha256 !== null) check(source !== null && hash(source) === r.sourceSha256, "SOURCE_HASH_MISMATCH");
  if (isPdf) check(r.profile === profile.profile && same(r.engine, PDF_ENGINE), "UNSUPPORTED_VERSION");
  else check(same(r.decoder, isPng ? PNG_DECODER : RASTER_DECODER), "UNSUPPORTED_VERSION");
  const nativeSource = { sha256: r.sourceSha256, verifiedAgainstProvidedBytes: r.sourceSha256 !== null, evidence: r.sourceSha256 === null ? "not returned by native component; no hash inferred" : "native field equals independently hashed original source bytes" };
  const out = { id: input.id, component: input.component, format: input.format, executionId: input.executionId,
    source: source === null ? null : identity(source, "original-source-bytes"),
    sourceAvailability: source === null ? "not supplied; non-byte invocation cannot establish source identity" : "provided original bytes",
    projection: identity(Buffer.from(canonical(projection)), "native-media-data-projection-json"),
    native: r, nativeSource, derivatives: [], omittedMethods: [],
    textOrFacts: "none; pixel output and geometry are not OCR, facts, permissions or acceptance" };
  if (r.kind === "rejected") {
    exactKeys(r, isPdf ? ["kind", "code", "sourceSha256", "profile", "engine"] : ["kind", "code", "sourceSha256", "decoder"]);
    check((isPdf ? SCANNED_PDF_ERRORS : isPng ? PNG_ERROR_CODES : RASTER_ERROR_CODES).includes(r.code), "UNSUPPORTED_REFUSAL");
    check(derivatives.length === 0, "REJECTED_DERIVATIVE");
    return { ...out, limitsEvidence: "not returned on native refusal", runtimeBinding: "not established by refused result", runtimeReceiptComplete: false };
  }
  check(source !== null && source.length > 0 && r.sourceSha256 !== null, "SOURCE_HASH_MISMATCH");
  check(r.completeness === "incomplete-pixels-only" && r.requiresInspection === true, "INVALID_COMPLETENESS");
  const limits = isPdf ? SCANNED_PDF_LIMITS : isPng ? PNG_LIMITS : RASTER_LIMITS;
  effectiveLimits(r.limits, limits); check(source.length <= limits.maxInputBytes, "RESOURCE_LIMIT");
  function derivative(item, expectedHash, expectedLength, role, page) {
    record(item); exactKeys(item, ["role", "page", "bytes", "expectedSha256"]);
    check(item.role === role && item.page === page, "DERIVATIVE_FORMAT_MISMATCH");
    check(isHash(expectedHash) && item.expectedSha256 === expectedHash, "DERIVATIVE_HASH_MISMATCH");
    const owned = bytes(item.bytes, L.maxDerivativeBytes);
    budget.derivative += owned.length; check(budget.derivative <= L.maxTotalDerivativeBytes, "RESOURCE_LIMIT");
    check(owned.length === expectedLength, "DERIVATIVE_LENGTH_MISMATCH");
    check(hash(owned) === item.expectedSha256, "DERIVATIVE_HASH_MISMATCH");
    return owned;
  }
  if (isPdf) {
    exactKeys(r, ["kind", "completeness", "requiresInspection", "sourceSha256", "profile", "engine", "pages", "totalRgbaBytes", "limits", "syscallPolicy", "enforcementControlsPassed"]);
    check(r.syscallPolicy === profile.syscallPolicy && r.enforcementControlsPassed === 8, "INVALID_ISOLATION_EVIDENCE");
    const pages = array(r.pages, L.maxPages); check(pages.length > 0 && derivatives.length === pages.length, "INVALID_PAGE_SEQUENCE");
    let total = 0, pixels = 0;
    for (const [index, page] of pages.entries()) {
      exactKeys(page, ["page", "sourceSha256", "width", "height", "pageWidthPoints", "pageHeightPoints", "byteLength", "sha256", "format", "colorSpace", "coordinateSystem", "stride"]);
      check(page.page === index + 1 && page.sourceSha256 === r.sourceSha256, "INVALID_PAGE_SEQUENCE");
      check(integer(page.width, limits.maxImageDimension, 1) && integer(page.height, limits.maxImageDimension, 1) && page.width * page.height <= limits.maxPagePixels, "INVALID_GEOMETRY");
      check([page.pageWidthPoints, page.pageHeightPoints].every((n) => Number.isFinite(n) && n > 0 && n <= limits.maxPagePoints), "INVALID_GEOMETRY");
      check(page.format === "rgba8" && page.colorSpace === "device-rgb" && page.coordinateSystem === "top-left-pixels" && page.stride === page.width * 4, "DERIVATIVE_FORMAT_MISMATCH");
      check(page.byteLength === page.width * page.height * 4, "DERIVATIVE_LENGTH_MISMATCH");
      const owned = derivative(derivatives[index], page.sha256, page.byteLength, "page-rgba8", page.page);
      for (let at = 3; at < owned.length; at += 4) check(owned[at] === 255, "INVALID_ALPHA");
      total += owned.length; pixels += page.width * page.height;
      out.derivatives.push({ ...identity(owned, "scanned-page-opaque-rgba8-bytes"), page: page.page, role: "page-rgba8", width: page.width, height: page.height, stride: page.stride, coordinateSystem: page.coordinateSystem,
        pageWidthPoints: page.pageWidthPoints, pageHeightPoints: page.pageHeightPoints, rgbaHashVerified: true });
    }
    check(total === r.totalRgbaBytes && total <= r.limits.maxOutputBytes && pixels <= limits.maxTotalPixels, "RESOURCE_LIMIT");
    return { ...out, omittedMethods: ["pages[].copyRgbaBytes"], limitsEvidence: "native projected effective limits; no provider budget",
      runtimeReceiptComplete: runtimes.has(input.component), runtimeBinding: "selected host receipt; closure hash is not returned by the public reader result",
      isolationEvidence: "eight reported native syscall controls; no broader host acceptance" };
  }
  const rasterKeys = ["kind", "completeness", "requiresInspection", "sourceSha256", "decoder", "limits", "width", "height", "outputColorType", "decodedRgbaBytes", "rgbaSha256", "normalizedSha256", "normalizedByteLength", "networkApiAttemptCount"];
  exactKeys(r, isPng ? [...rasterKeys, "sourceColorType"] : [...rasterKeys, "runtimeManifestSha256", "sourceFormat", "encoding", "sourceMode", "frames"]);
  check(integer(r.width, limits.maxDimension, 1) && integer(r.height, limits.maxDimension, 1) && r.width * r.height <= limits.maxPixels, "INVALID_GEOMETRY");
  check(r.outputColorType === 6 && r.decodedRgbaBytes === r.width * r.height * 4 && isHash(r.rgbaSha256) && r.networkApiAttemptCount === 0, "INVALID_PIXELS");
  if (isPng) check([2, 6].includes(r.sourceColorType));
  else {
    check(r.sourceFormat === input.format && r.frames === 1, "FORMAT_MISMATCH");
    check((r.sourceFormat === "jpeg" ? ["baseline", "progressive"] : ["lossy", "lossless"]).includes(r.encoding), "FORMAT_MISMATCH");
    check((r.sourceFormat === "jpeg" ? ["L", "RGB"] : ["RGB", "RGBA"]).includes(r.sourceMode), "FORMAT_MISMATCH");
    check(isHash(r.runtimeManifestSha256), "RUNTIME_MISMATCH");
    const runtime = runtimes.get(input.component);
    if (runtime) check(runtime.manifest.sha256 === r.runtimeManifestSha256, "RUNTIME_MISMATCH");
  }
  check(derivatives.length === 1 && integer(r.normalizedByteLength, r.limits.maxOutputBytes, 1), "DERIVATIVE_LENGTH_MISMATCH");
  const owned = derivative(derivatives[0], r.normalizedSha256, r.normalizedByteLength, "normalized-png", null);
  normalizedPng(owned, r.width, r.height);
  return { ...out, derivatives: [{ ...identity(owned, "normalized-png-bytes"), page: null, role: "normalized-png", width: r.width, height: r.height, coordinateSystem: "image-pixels" }],
    omittedMethods: ["copyNormalizedBytes"], limitsEvidence: "native projected effective limits; no provider budget",
    componentReportedRgba: { domain: "decoded-rgba8-sample-bytes", sha256: r.rgbaSha256, bytes: r.decodedRgbaBytes, verified: false,
      reason: "copied derivative is PNG; this composer does not inflate it or claim independently verified RGBA samples" },
    runtimeReceiptComplete: isPng || runtimes.has(input.component), runtimeBinding: isPng ? "exact declared Node/zlib profile; no external runtime receipt" : "native result hash equals selected runtime receipt bytes when present",
    networkEvidence: isPng ? "guarded JavaScript API counter only; not native-egress attestation" : "cooperative Python API counter only; not native-egress attestation" };
}

function compose(input) {
  record(input); const p = record(input.prerequisite);
  const prerequisite = validateInspectionReport(p.reportBytes, p.expectedSha256, p.input);
  const base = prerequisite.report, pins = base.pins;
  const source = sourceBinding(input.source, pins), runtimes = runtimeReceipts(input.runtimeReceipts);
  const executions = array(input.executions, L.maxExecutions).map((e) => execution(e, pins, base.requiredMode, source)).sort(byId);
  check(new Set(executions.map((e) => e.id)).size === executions.length, "DUPLICATE_ID");
  check(new Set(executions.map((e) => e.component)).size === executions.length, "DUPLICATE_COMPONENT");
  const executionMap = new Map(executions.map((e) => [e.id, e]));
  const budget = { source: base.observations.reduce((total, o) => total + o.source.bytes, 0), derivative: 0 };
  const observations = array(input.observations, L.maxObservations).map((o) => observation(o, pins, executionMap, runtimes, budget)).sort(byId);
  check(observations.length + base.observations.length <= L.maxObservations, "RESOURCE_LIMIT");
  check(new Set([...base.observations, ...observations].map((o) => o.id)).size === observations.length + base.observations.length, "DUPLICATE_ID");
  check(new Set(observations.map((o) => o.component + ":" + (o.source?.sha256 ?? o.id) + ":" + o.format)).size === observations.length, "DUPLICATE_OBSERVATION");
  const allFormats = [...base.observations, ...observations].map((o) => o.format);
  const missingFormats = base.requiredFormats.filter((f) => !allFormats.includes(f));
  const reasons = new Set(base.reasons.filter((r) => r !== "REQUIRED_FORMATS_MISSING"));
  if (missingFormats.length) reasons.add("REQUIRED_FORMATS_MISSING");
  if (!source.complete) reasons.add("SOURCE_BINDING_INCOMPLETE");
  if (executions.some((e) => !e.complete)) reasons.add("MEDIA_EXECUTION_INCOMPLETE");
  if (observations.some((o) => o.native.kind === "rejected" || o.source === null)) reasons.add("MEDIA_COMPONENT_LIMITATION");
  if (observations.some((o) => o.native.kind === "decoded" && !o.runtimeReceiptComplete)) reasons.add("RUNTIME_RECEIPT_MISSING");
  if (observations.some((o) => o.componentReportedRgba)) reasons.add("COMPONENT_RGBA_DOMAIN_NOT_INDEPENDENTLY_VERIFIED");
  const blockers = ["DETERMINISTIC_PREREQUISITE_MISSING", "DETERMINISTIC_PREREQUISITE_INCOMPLETE", "EXECUTION_INCOMPLETE", "COMPONENT_LIMITATION", "MODE_MISMATCH", "RECORDED_OR_PROVIDER_EXECUTION_NOT_AUTHENTICATED", "REQUIRED_FORMATS_MISSING", "SOURCE_BINDING_INCOMPLETE", "MEDIA_EXECUTION_INCOMPLETE", "MEDIA_COMPONENT_LIMITATION", "RUNTIME_RECEIPT_MISSING"];
  const report = freeze(data({ schemaVersion: INSPECTION_MEDIA_REPORT_VERSION, pins, pinAuthority: "checked-host-selection-only",
    mappingState: base.mappingState, requiredMode: base.requiredMode, overall: "incomplete",
    acceptance: { evaluated: false, satisfiedIds: [], ownerAcknowledgements: [] }, providerActivity: "not established by report validation", financeAuthority: "none", ocrOrFactInference: "none",
    prerequisite: { ...identity(Buffer.from(prerequisite.copyBytes()), "local-inspection-report-v1-bytes"), report: base },
    source, runtimeReceipts: [...runtimes.values()].sort((a, b) => a.component < b.component ? -1 : 1),
    requiredFormats: base.requiredFormats, missingFormats, declaredCoverage: blockers.some((r) => reasons.has(r)) ? "incomplete" : "complete",
    executions, observations, totalProvidedSourceBytes: budget.source, totalDerivativeBytes: budget.derivative,
    reasons: [...reasons].sort(), authority: "local evidence composition; no canonical mapping, grant, host trust, provider result, Creative ACK or global acceptance is created" }));
  const encoded = Buffer.from(canonical(report)); check(encoded.length <= L.maxReportBytes, "RESOURCE_LIMIT");
  return Object.freeze({ report, sha256: hash(encoded), byteLength: encoded.length, copyBytes: () => new Uint8Array(encoded) });
}
export function composeInspectionMediaReport(input) {
  try { return compose(input); }
  catch (error) { if (error instanceof InspectionReportError) throw error; throw new InspectionReportError("INVALID_INPUT"); }
}
export function validateInspectionMediaReport(reportBytes, expectedSha256, input) {
  try {
    check(isHash(expectedSha256)); const supplied = bytes(reportBytes, L.maxReportBytes);
    check(hash(supplied) === expectedSha256, "REPORT_HASH_MISMATCH");
    const parsed = parseJson(supplied, L.maxReportBytes); check(parsed.schemaVersion === INSPECTION_MEDIA_REPORT_VERSION, "UNSUPPORTED_VERSION");
    const recomputed = composeInspectionMediaReport(input);
    check(supplied.equals(Buffer.from(recomputed.copyBytes())), "REPORT_BYTES_MISMATCH"); return recomputed;
  } catch (error) { if (error instanceof InspectionReportError) throw error; throw new InspectionReportError("INVALID_INPUT"); }
}
