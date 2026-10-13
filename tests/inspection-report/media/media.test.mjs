import assert from "node:assert/strict";
import test, { before } from "node:test";
import { crc32 } from "node:zlib";
import { composeInspectionMediaReport, validateInspectionMediaReport, INSPECTION_MEDIA_REPORT_LIMITS } from "../../../src/extraction/inspection-report/media.mjs";
import { InspectionReportError } from "../../../src/extraction/inspection-report/index.mjs";
import { actualMediaFixture, projectedObservation, recoverScannedChildStderr, changeNativeSummary, changeSnapshot, refreshPrerequisite, copy, hash, jsonBytes } from "./support.mjs";

let fixture;
before(async () => { fixture = await actualMediaFixture(); });
const input = () => copy(fixture.input);
const png = (value) => value.observations.find((o) => o.id === "png-rgba");
const jpeg = (value) => value.observations.find((o) => o.id === "jpeg-rgb-baseline");
const pdf = (value) => value.observations.find((o) => o.id === "pdf-scan-two");
function refused(value, code) { assert.throws(() => composeInspectionMediaReport(value), (error) => error instanceof InspectionReportError && (!code || error.code === code), code); }

test("actual original bytes, native encoded PNG and independent raw image/PDF pixels compose an immutable incomplete aggregate", () => {
  const f = input(), artifact = composeInspectionMediaReport(f), report = artifact.report;
  assert.equal(report.overall, "incomplete"); assert.equal(report.acceptance.evaluated, false);
  assert.deepEqual(report.acceptance.satisfiedIds, []); assert.deepEqual(report.acceptance.ownerAcknowledgements, []);
  assert.equal(report.ocrOrFactInference, "none"); assert.equal(report.financeAuthority, "none");
  assert.deepEqual(report.missingFormats, []);
  assert.equal(report.declaredCoverage, report.source.complete ? "complete" : "incomplete");
  assert.deepEqual(report.executions.map((e) => e.expectedCases).sort((a, b) => a - b), [99, 107, 160]);
  assert.ok(report.executions.every((e) => e.nativeDeclaredComplete));
  assert.equal(report.prerequisite.sha256, f.prerequisite.expectedSha256);
  const normalized = report.observations.find((o) => o.id === "png-rgba");
  assert.equal(normalized.derivatives[0].domain, "normalized-png-bytes");
  assert.equal(normalized.componentReportedRgba.verified, true);
  assert.equal(normalized.derivatives[1].domain, "decoded-rgba8-sample-bytes");
  assert.equal(normalized.derivatives[1].rgbaHashVerified, true);
  assert.equal(normalized.derivatives[1].stride, normalized.native.width * 4);
  assert.equal(normalized.derivatives[1].sha256, hash(png(f).derivatives[1].bytes));
  assert.equal(report.reasons.includes("COMPONENT_RGBA_DOMAIN_NOT_INDEPENDENTLY_VERIFIED"), false);
  const scanned = report.observations.find((o) => o.id === "pdf-scan-two");
  assert.deepEqual(scanned.derivatives.map((d) => d.page), [1, 2]);
  assert.equal(scanned.derivatives[0].domain, "scanned-page-opaque-rgba8-bytes");
  assert.equal(scanned.derivatives[0].pageWidthPoints, 72);
  assert.equal(scanned.derivatives[0].width, 2);
  assert.equal(scanned.derivatives[0].rgbaHashVerified, true);
  assert.equal(artifact.sha256, hash(artifact.copyBytes()));
  assert.equal(validateInspectionMediaReport(artifact.copyBytes(), artifact.sha256, f).sha256, artifact.sha256);
  const owned = artifact.copyBytes(); owned.fill(0);
  assert.equal(hash(artifact.copyBytes()), artifact.sha256);
  assert.ok(Object.isFrozen(report)); assert.ok(Object.isFrozen(scanned.native.pages[0]));
  fixture.capture("composed-media-report.json", artifact.copyBytes());
});

test("stable inputs and reordered independent observations/executions yield identical report bytes", () => {
  const a = input(), b = input(); b.observations.reverse(); b.executions.reverse(); b.runtimeReceipts.reverse();
  assert.equal(composeInspectionMediaReport(a).sha256, composeInspectionMediaReport(b).sha256);
});

test("original source and derivative hashes remain separate even when each expected digest is valid elsewhere", () => {
  const f = input(); png(f).sourceBytes = png(f).derivatives[0].bytes; png(f).expectedSourceSha256 = hash(png(f).sourceBytes);
  refused(f, "SOURCE_HASH_MISMATCH");
});

for (const [name, mutate, code] of [
  ["source bytes", (f) => { png(f).sourceBytes[0] ^= 1; }, "SOURCE_HASH_MISMATCH"],
  ["original expected hash", (f) => { png(f).expectedSourceSha256 = "0".repeat(64); }, "SOURCE_HASH_MISMATCH"],
  ["native source hash", (f) => { png(f).projection.result.sourceSha256 = "0".repeat(64); }, "SOURCE_HASH_MISMATCH"],
  ["derivative bytes", (f) => { png(f).derivatives[0].bytes[30] ^= 1; }, "DERIVATIVE_HASH_MISMATCH"],
  ["derivative sidecar hash", (f) => { png(f).derivatives[0].expectedSha256 = "0".repeat(64); }, "DERIVATIVE_HASH_MISMATCH"],
  ["native normalized hash", (f) => { png(f).projection.result.normalizedSha256 = "0".repeat(64); }, "DERIVATIVE_HASH_MISMATCH"],
  ["native normalized length", (f) => { png(f).projection.result.normalizedByteLength++; }, "DERIVATIVE_LENGTH_MISMATCH"],
  ["RGBA count", (f) => { png(f).projection.result.decodedRgbaBytes++; }, "INVALID_PIXELS"],
  ["PNG dimensions", (f) => { png(f).projection.result.width = 0; }, "INVALID_GEOMETRY"],
  ["PNG output color type", (f) => { png(f).projection.result.outputColorType = 2; }, "INVALID_PIXELS"],
  ["PNG role", (f) => { png(f).derivatives[0].role = "page-rgba8"; }, "DERIVATIVE_FORMAT_MISMATCH"],
  ["PNG page alias", (f) => { png(f).derivatives[0].page = 1; }, "DERIVATIVE_FORMAT_MISMATCH"],
  ["JPEG format", (f) => { jpeg(f).format = "webp"; }, "FORMAT_MISMATCH"],
  ["JPEG encoding", (f) => { jpeg(f).projection.result.encoding = "lossless"; }, "FORMAT_MISMATCH"],
  ["JPEG color mode", (f) => { jpeg(f).projection.result.sourceMode = "CMYK"; }, "FORMAT_MISMATCH"],
  ["JPEG frame count", (f) => { jpeg(f).projection.result.frames = 2; }, "FORMAT_MISMATCH"],
  ["JPEG runtime hash", (f) => { jpeg(f).projection.result.runtimeManifestSha256 = "0".repeat(64); }, "RUNTIME_MISMATCH"],
  ["native decoder version", (f) => { jpeg(f).projection.result.decoder.pillowVersion = "12.4.0"; }, "UNSUPPORTED_VERSION"],
  ["projection version", (f) => { png(f).projection.schemaVersion = "ei-native-media-data-projection/2"; }, "UNSUPPORTED_VERSION"],
  ["complete assertion", (f) => { png(f).projection.result.completeness = "complete"; }, "INVALID_COMPLETENESS"],
  ["network counter", (f) => { png(f).projection.result.networkApiAttemptCount = 1; }, "INVALID_PIXELS"],
  ["lower-only timeout", (f) => { png(f).projection.result.limits.timeoutMs = 10001; }, "INVALID_LIMITS"],
  ["fixed native cap", (f) => { png(f).projection.result.limits.maxPixels++; }, "INVALID_LIMITS"],
  ["zero output limit", (f) => { png(f).projection.result.limits.maxOutputBytes = 0; }, "INVALID_LIMITS"],
  ["PDF engine version", (f) => { pdf(f).projection.result.engine.version = "future"; }, "UNSUPPORTED_VERSION"],
  ["PDF zero-based page", (f) => { pdf(f).projection.result.pages[0].page = 0; }, "INVALID_PAGE_SEQUENCE"],
  ["PDF duplicated page", (f) => { pdf(f).projection.result.pages[1].page = 1; }, "INVALID_PAGE_SEQUENCE"],
  ["PDF reordered pages", (f) => { pdf(f).projection.result.pages.reverse(); }, "INVALID_PAGE_SEQUENCE"],
  ["PDF missing later page", (f) => { pdf(f).derivatives.pop(); }, "INVALID_PAGE_SEQUENCE"],
  ["PDF page source", (f) => { pdf(f).projection.result.pages[1].sourceSha256 = "0".repeat(64); }, "INVALID_PAGE_SEQUENCE"],
  ["PDF byte stride", (f) => { pdf(f).projection.result.pages[0].stride = 1; }, "DERIVATIVE_FORMAT_MISMATCH"],
  ["PDF PNG alias", (f) => { pdf(f).projection.result.pages[0].format = "png"; }, "DERIVATIVE_FORMAT_MISMATCH"],
  ["PDF text coordinate alias", (f) => { pdf(f).projection.result.pages[0].coordinateSystem = "viewport-points-top-left"; }, "DERIVATIVE_FORMAT_MISMATCH"],
  ["PDF nonfinite points", (f) => { pdf(f).projection.result.pages[0].pageWidthPoints = Infinity; }, "INVALID_INPUT"],
  ["PDF zero points", (f) => { pdf(f).projection.result.pages[0].pageWidthPoints = 0; }, "INVALID_GEOMETRY"],
  ["PDF copied length", (f) => { pdf(f).derivatives[1].bytes = pdf(f).derivatives[1].bytes.subarray(1); }, "DERIVATIVE_LENGTH_MISMATCH"],
  ["PDF copied hash", (f) => { pdf(f).derivatives[1].bytes[0] ^= 1; }, "DERIVATIVE_HASH_MISMATCH"],
  ["PDF total bytes", (f) => { pdf(f).projection.result.totalRgbaBytes++; }, "RESOURCE_LIMIT"],
  ["PDF native control count", (f) => { pdf(f).projection.result.enforcementControlsPassed = 7; }, "INVALID_ISOLATION_EVIDENCE"],
  ["execution binding", (f) => { png(f).executionId = "scanned-pdf"; }, "EXECUTION_BINDING_MISMATCH"],
  ["duplicate observation ID", (f) => { f.observations[1].id = f.observations[0].id; }, "DUPLICATE_ID"],
  ["duplicate source/format", (f) => { const o = copy(png(f)); o.id = "another-copy"; f.observations.push(o); }, "DUPLICATE_OBSERVATION"],
  ["duplicate execution", (f) => { f.executions.push(copy(f.executions[0])); }, "RESOURCE_LIMIT"],
  ["execution ID borrowed from the prerequisite", (f) => { f.executions[0].id = f.prerequisite.input.executions[0].id; }, "DUPLICATE_ID"],
  ["duplicate runtime receipt", (f) => { f.runtimeReceipts[1] = copy(f.runtimeReceipts[0]); }, "DUPLICATE_COMPONENT"],
  ["runtime digest", (f) => { f.runtimeReceipts[0].expectedSha256 = "0".repeat(64); }, "ARTIFACT_HASH_MISMATCH"],
  ["source receipt digest", (f) => { f.source.expectedBeforeSha256 = "0".repeat(64); }, "ARTIFACT_HASH_MISMATCH"],
]) test("rejects inconsistent " + name + " without producing a partial report", () => { const f = input(); mutate(f); refused(f, code); });

test("hash-consistent transparent PDF bytes still violate the opaque admitted profile", () => {
  const f = input(), o = pdf(f); o.derivatives[0].bytes[3] = 0;
  const h = hash(o.derivatives[0].bytes); o.derivatives[0].expectedSha256 = h; o.projection.result.pages[0].sha256 = h;
  refused(f, "INVALID_ALPHA");
});
test("matching derivative digest cannot turn arbitrary bytes into normalized PNG", (t) => {
  const f = input(), o = png(f), d = o.derivatives[0]; d.bytes = new Uint8Array(d.bytes.length);
  d.expectedSha256 = hash(d.bytes); o.projection.result.normalizedSha256 = d.expectedSha256;
  refused(f, "DERIVATIVE_FORMAT_MISMATCH");

  // Mutate actual native fixture output; exercise only the pure report framing
  // check here, without claiming a fresh decoder invocation for each mutation.
  const valid = composeInspectionMediaReport(input());
  let refusedTypes = 0;
  for (const id of ["png-rgba", "jpeg-rgb-baseline", "webp-rgba-lossless"]) {
    const original = input().observations.find((item) => item.id === id).derivatives[0].bytes;
    let at = 8;
    for (const type of ["IHDR", "IDAT", "IEND"]) {
      const originalBytes = Buffer.from(original);
      const end = at + originalBytes.readUInt32BE(at) + 8;
      assert.deepEqual(originalBytes.subarray(at + 4, at + 8), Buffer.from(type, "ascii"));
      for (let byte = 0; byte < 4; byte += 1) {
        const changed = input(), observation = changed.observations.find((item) => item.id === id);
        const derivative = observation.derivatives[0], payload = Buffer.from(derivative.bytes);
        payload[at + 4 + byte] |= 0x80;
        payload.writeUInt32BE(crc32(payload.subarray(at + 4, end)), end);
        derivative.bytes = payload;
        derivative.expectedSha256 = hash(payload);
        observation.projection.result.normalizedSha256 = derivative.expectedSha256;
        t.diagnostic(`normalized PNG high-bit control: ${id} ${type} byte ${byte}; matching CRC and SHA256 ${derivative.expectedSha256}`);
        refused(changed, "DERIVATIVE_FORMAT_MISMATCH");
        refusedTypes += 1;
      }
      at = end + 4;
    }
    assert.equal(at, original.length);
  }
  assert.equal(refusedTypes, 36);
  assert.equal(composeInspectionMediaReport(input()).sha256, valid.sha256);
  t.diagnostic("normalized PNG high-bit controls: 36 refused; unchanged valid composition recovered");
});
test("a component-reported RGBA digest is retained explicitly unverified without pretending to decode PNG", () => {
  const f = input(); png(f).derivatives.pop(); png(f).projection.result.rgbaSha256 = "1".repeat(64);
  const o = composeInspectionMediaReport(f).report.observations.find((o) => o.id === "png-rgba");
  assert.equal(o.componentReportedRgba.sha256, "1".repeat(64)); assert.equal(o.componentReportedRgba.verified, false);
});

for (const [name, mutate] of [
  ["native PNG metadata", (f) => { png(f).projection.result.privateText = "PRIVATE_CANARY"; }],
  ["native PNG limits", (f) => { png(f).projection.result.limits.privateText = "PRIVATE_CANARY"; }],
  ["native JPEG metadata", (f) => { jpeg(f).projection.result.privateText = "PRIVATE_CANARY"; }],
  ["native JPEG limits", (f) => { jpeg(f).projection.result.limits.privateText = "PRIVATE_CANARY"; }],
  ["native PDF limits", (f) => { pdf(f).projection.result.limits.privateText = "PRIVATE_CANARY"; }],
  ["native PDF page", (f) => { pdf(f).projection.result.pages[0].privateText = "PRIVATE_CANARY"; }],
  ["projection envelope", (f) => { png(f).projection.privateText = "PRIVATE_CANARY"; }],
]) test("does not copy undeclared private fields from " + name, () => { const f = input(); mutate(f); refused(f); });

for (const [name, mutate] of [
  ["selected pins", (text) => { text.expectedPins.privateText = "PRIVATE_CANARY"; }],
  ["deterministic locator", (text) => { text.observations[0].result.visibleText[0].source.locator.privateText = "PRIVATE_CANARY"; }],
  ["native text-PDF limits", (text) => { text.observations[2].result.limits.privateText = "PRIVATE_CANARY"; }],
]) test("v1 prerequisite cannot disclose undeclared " + name + " in the aggregate", () => {
  const f = input();
  try {
    refreshPrerequisite(f, mutate);
    assert.equal(Buffer.from(composeInspectionMediaReport(f).copyBytes()).includes(Buffer.from("PRIVATE_CANARY")), false);
  } catch (error) { if (!(error instanceof InspectionReportError)) throw error; }
});

test("unused runtime metadata is hashed but never copied into the report", () => {
  const f = input(), r = f.runtimeReceipts[0], value = JSON.parse(Buffer.from(r.bytes).toString());
  value.privateText = "PRIVATE_CANARY"; r.bytes = jsonBytes(value); r.expectedSha256 = hash(r.bytes);
  for (const o of f.observations.filter((o) => o.component === "static-jpeg-webp")) o.projection.result.runtimeManifestSha256 = r.expectedSha256;
  assert.equal(Buffer.from(composeInspectionMediaReport(f).copyBytes()).includes(Buffer.from("PRIVATE_CANARY")), false);
});
test("the selected PDF runtime closure retains Python ASCII JSON encoding for non-ASCII paths", () => {
  const f = input(), r = f.runtimeReceipts.find((r) => r.component === "scanned-pdf");
  const value = JSON.parse(Buffer.from(r.bytes).toString());
  // Synthetic receipt encoding control only: this does not run or attest a
  // renamed runtime. The installed actual receipt is preserved in the fixture.
  value.descriptor.python = "/synthetic/\u00e9/\ud83d\ude00/python";
  const sorted = (v) => Array.isArray(v) ? v.map(sorted) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sorted(v[k])])) : v;
  const ascii = JSON.stringify(sorted(value.descriptor)).replace(/[\u007f-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  value.closureSha256 = hash(ascii); r.bytes = jsonBytes(value); r.expectedSha256 = hash(r.bytes);
  const observed = composeInspectionMediaReport(f).report.runtimeReceipts.find((r) => r.component === "scanned-pdf");
  assert.equal(observed.closureSha256, value.closureSha256);
  value.closureSha256 = hash(JSON.stringify(sorted(value.descriptor))); r.bytes = jsonBytes(value); r.expectedSha256 = hash(r.bytes);
  refused(f, "RUNTIME_MISMATCH");
});

for (const [name, mutate] of [
  ["missing required media", (f) => { f.observations = f.observations.filter((o) => o.format !== "webp"); }],
  ["missing runtime receipt", (f) => { f.runtimeReceipts = []; }],
  ["source became dirty", (f) => { changeSnapshot(f, "after", (s) => { s.dirty = true; }); }],
  ["source changed revision", (f) => { changeSnapshot(f, "after", (s) => { s.revision = "0".repeat(40); }); }],
  ["source changed file", (f) => { changeSnapshot(f, "after", (s) => { s.files[0].sha256 = "0".repeat(64); }); }],
  ["selected other tree", (f) => { f.source.selectedTree = "0".repeat(40); }],
  ["unknown wrapper outcome", (f) => { f.executions[0].exitCode = null; f.executions[0].signal = "SIGTERM"; }],
  ["missing required summary", (f) => { f.executions[0].stdoutBytes = Buffer.alloc(0); f.executions[0].exitCode = 1; }],
  ["recorded input origin", (f) => { f.executions[0].origin = "recorded"; }],
  ["live relabel attempt", (f) => { f.executions[0].mode = "live"; }],
  ["unavailable child stderr", (f) => { f.executions.find((e) => e.component === "scanned-pdf").childStderrBytes = null; }],
]) test("retains incomplete state for " + name, () => {
  const f = input(); mutate(f); const r = composeInspectionMediaReport(f).report;
  assert.equal(r.declaredCoverage, "incomplete"); assert.equal(r.overall, "incomplete"); assert.equal(r.acceptance.evaluated, false);
});

for (const [name, mutate, code] of [
  ["traversal source path", (s) => { s.files[0].path = "../escape"; }, "INVALID_SOURCE_PATH"],
  ["absolute source path", (s) => { s.files[0].path = "/tmp/escape"; }, "INVALID_SOURCE_PATH"],
  ["duplicate source path", (s) => { s.files[1].path = s.files[0].path; }, "INVALID_SOURCE_PATH"],
  ["source receipt private field", (s) => { s.privateText = "PRIVATE_CANARY"; }, "INVALID_INPUT"],
]) test("rejects " + name, () => { const f = input(); changeSnapshot(f, "before", mutate); refused(f, code); });

for (const [name, mutate, code] of [
  ["lower expected native case count", (s) => { s.expectedTests--; }, "UNSUPPORTED_SUMMARY"],
  ["omitted required native file", (s) => { s.files.pop(); }, "UNSUPPORTED_SUMMARY"],
  ["native provider mode rewrite", (s) => { s.mode = "live"; }, "UNSUPPORTED_SUMMARY"],
  ["false passed count", (s) => { s.counts.pass++; }, "COUNT_MISMATCH"],
]) test("rejects summary " + name, () => { const f = input(); changeNativeSummary(f, "static-png", mutate); refused(f, code); });

test("duplicate and nonterminal native summaries cannot erase the first outcome", () => {
  const f = input(), e = f.executions[0], line = Buffer.from(e.stdoutBytes).toString().split("\n").find((x) => x.startsWith("{"));
  e.stdoutBytes = Buffer.concat([e.stdoutBytes, Buffer.from(line + "\n")]); refused(f, "DUPLICATE_SUMMARY");
  const g = input(); g.executions[0].stdoutBytes = Buffer.concat([g.executions[0].stdoutBytes, Buffer.from("unexpected later output\n")]); refused(g, "NONTERMINAL_SUMMARY");
});
test("an earlier native TAP failure cannot be replaced by a green footer", () => {
  const f = input(); changeNativeSummary(f, "static-png", () => {}, (tap) => tap.replace(/^ok 1 /m, "not ok 1 "));
  refused(f, "FALSE_PASS");
});
for (const [status, directive] of [["fail", "not ok"], ["skipped", "ok"]]) test("honest raw native " + status + " remains failed/incomplete evidence", () => {
  const f = input(); changeNativeSummary(f, "static-png", (s) => { s.complete = false; s.counts.pass--; s.counts[status]++; },
    (tap) => tap.replace(/^ok 1 - ([^\n]*)/m, directive + " 1 - $1" + (status === "skipped" ? " # SKIP required unavailable" : ""))
      .replace(/^# pass 107$/m, "# pass 106").replace(new RegExp("^# " + status + " 0$", "m"), "# " + status + " 1"));
  f.executions.find((e) => e.component === "static-png").exitCode = 1;
  const e = composeInspectionMediaReport(f).report.executions.find((e) => e.component === "static-png");
  assert.equal(e.counts[status], 1); assert.equal(e.complete, false);
});

test("PDF child TAP and child stderr retain their own digest domains", () => {
  assert.notEqual(fixture.input.executions.find((e) => e.component === "scanned-pdf").childStderrBytes, null, "actual native wrapper recovery must be available in this required control");
  const f = input(); changeNativeSummary(f, "scanned-pdf", (s) => { s.stderrSha256 = "0".repeat(64); }); refused(f, "SUMMARY_HASH_MISMATCH");
  const g = input(), e = g.executions.find((e) => e.component === "scanned-pdf");
  e.stderrBytes = Buffer.from("wrapper-only diagnostic\n");
  const r = composeInspectionMediaReport(g).report.executions.find((e) => e.component === "scanned-pdf");
  assert.notEqual(r.stderr.sha256, r.childStderr.sha256);
});
test("bounded child-stderr recovery retains the wrapper and refuses ambiguous or unavailable byte framing", () => {
  const actual = fixture.input.executions.find((e) => e.component === "scanned-pdf");
  const before = Buffer.from(actual.stderrBytes), child = Buffer.from(actual.childStderrBytes);
  const recovered = recoverScannedChildStderr(before, hash(child));
  assert.deepEqual(recovered.bytes, child); assert.deepEqual(before, Buffer.from(actual.stderrBytes));
  assert.equal(recovered.evidence.childByteLength, child.length);
  assert.equal(recoverScannedChildStderr(Buffer.from("same\nsame\n"), hash("same\n")).bytes, null);
  assert.equal(recoverScannedChildStderr(Buffer.from("different\n"), hash("child\n")).bytes, null);
  assert.equal(recoverScannedChildStderr(Buffer.from("x\n".repeat(256)), hash("x\n")).bytes, null);
  assert.equal(recoverScannedChildStderr(Buffer.alloc(256 * 1024 + 1), hash("")).bytes, null);
  assert.deepEqual(recoverScannedChildStderr(Buffer.alloc(0), hash("")).bytes, Buffer.alloc(0));
});

for (const location of ["input", "observations", "observation", "projection", "pages", "page", "source", "runtime", "executions", "derivatives", "derivative"]) test("never executes proxy traps at " + location, () => {
  let f = input(), calls = 0; const proxy = (v) => new Proxy(v, { get() { calls++; throw Error("trap"); }, getPrototypeOf() { calls++; throw Error("trap"); }, ownKeys() { calls++; throw Error("trap"); } });
  if (location === "input") f = proxy(f);
  if (location === "observations") f.observations = proxy(f.observations);
  if (location === "observation") f.observations[0] = proxy(f.observations[0]);
  if (location === "projection") png(f).projection = proxy(png(f).projection);
  if (location === "pages") pdf(f).projection.result.pages = proxy(pdf(f).projection.result.pages);
  if (location === "page") pdf(f).projection.result.pages[0] = proxy(pdf(f).projection.result.pages[0]);
  if (location === "source") f.source = proxy(f.source);
  if (location === "runtime") f.runtimeReceipts[0] = proxy(f.runtimeReceipts[0]);
  if (location === "executions") f.executions = proxy(f.executions);
  if (location === "derivatives") png(f).derivatives = proxy(png(f).derivatives);
  if (location === "derivative") png(f).derivatives[0] = proxy(png(f).derivatives[0]);
  refused(f); assert.equal(calls, 0);
});
test("accessor/sparse/custom arrays and native copy functions are refused without execution", () => {
  let calls = 0;
  const a = input(); Object.defineProperty(a.observations, "0", { get() { calls++; return png(a); }, enumerable: true }); refused(a);
  const b = input(); delete b.observations[0]; refused(b);
  const c = input(); Object.setPrototypeOf(c.observations, class extends Array {}.prototype); refused(c);
  const d = input(); png(d).projection.result.copyNormalizedBytes = () => { calls++; return new Uint8Array(); }; refused(d);
  const e = input(); Object.defineProperty(png(e).projection.result, "width", { get() { calls++; return 1; }, enumerable: true }); refused(e);
  assert.equal(calls, 0);
});
test("native byte slots enforce bounds without shadow getters or subclass methods", () => {
  let calls = 0;
  const a = input(), shadow = new Uint8Array(INSPECTION_MEDIA_REPORT_LIMITS.maxDerivativeBytes + 1);
  Object.defineProperty(shadow, "byteLength", { get() { calls++; return 1; } }); png(a).derivatives[0].bytes = shadow; refused(a);
  const b = input(); class Hostile extends Uint8Array { valueOf() { calls++; return this; } }
  png(b).derivatives[0].bytes = new Hostile(4); refused(b);
  const c = input(); png(c).derivatives[0].bytes = new Uint8Array(new SharedArrayBuffer(4)); refused(c);
  const d = input(), detached = new Uint8Array(4); structuredClone(detached, { transfer: [detached.buffer] }); png(d).derivatives[0].bytes = detached; refused(d);
  assert.equal(calls, 0);
});
for (const [name, mutate] of [
  ["source bytes", (f) => { png(f).sourceBytes = new Uint8Array(INSPECTION_MEDIA_REPORT_LIMITS.maxSourceBytes + 1); }],
  ["derivative bytes", (f) => { png(f).derivatives[0].bytes = new Uint8Array(INSPECTION_MEDIA_REPORT_LIMITS.maxDerivativeBytes + 1); }],
  ["execution stdout", (f) => { f.executions[0].stdoutBytes = new Uint8Array(INSPECTION_MEDIA_REPORT_LIMITS.maxSummaryBytes + 1); }],
  ["execution stderr", (f) => { f.executions[0].stderrBytes = new Uint8Array(INSPECTION_MEDIA_REPORT_LIMITS.maxStderrBytes + 1); }],
  ["source receipt", (f) => { f.source.beforeBytes = new Uint8Array(INSPECTION_MEDIA_REPORT_LIMITS.maxSourceReceiptBytes + 1); }],
  ["runtime receipt", (f) => { f.runtimeReceipts[0].bytes = new Uint8Array(INSPECTION_MEDIA_REPORT_LIMITS.maxRuntimeReceiptBytes + 1); }],
  ["observation inventory", (f) => { f.observations = Array.from({ length: INSPECTION_MEDIA_REPORT_LIMITS.maxObservations + 1 }, () => png(f)); }],
  ["page inventory", (f) => { pdf(f).projection.result.pages = Array.from({ length: 5 }, () => copy(pdf(f).projection.result.pages[0])); }],
]) test("rejects an actual over-limit " + name + " input before partial output", () => { const f = input(); mutate(f); refused(f, "RESOURCE_LIMIT"); });
test("the aggregate source cap includes original text/PDF and all media representations", () => {
  const f = input(), source = new Uint8Array(16 * 1024 * 1024), expected = hash(source), decoder = png(f).projection.result.decoder;
  f.observations = Array.from({ length: 4 }, (_, index) => ({ id: "bounded-cancel-" + index, component: "static-png", format: "png", pins: f.prerequisite.input.expectedPins,
    executionId: "static-png", sourceBytes: source, expectedSourceSha256: expected,
    projection: { schemaVersion: "ei-native-media-data-projection/1", component: "static-png", result: { kind: "rejected", code: "CANCELLED", sourceSha256: null, decoder } }, derivatives: [] }));
  refused(f, "RESOURCE_LIMIT");
});
test("valid Buffer and Uint8Array subviews bind only their visible bytes", () => {
  const f = input(), a = composeInspectionMediaReport(f);
  for (const o of f.observations) {
    const source = Buffer.concat([Buffer.from([0]), o.sourceBytes, Buffer.from([0])]); o.sourceBytes = new Uint8Array(source.buffer, source.byteOffset + 1, source.length - 2);
    for (const d of o.derivatives) { const joined = Buffer.concat([Buffer.from([0]), d.bytes, Buffer.from([0])]); d.bytes = joined.subarray(1, -1); }
  }
  assert.equal(composeInspectionMediaReport(f).sha256, a.sha256);
});

test("report bytes, schema, prerequisite and duplicate JSON keys are checked by reconstruction", () => {
  const f = input(), a = composeInspectionMediaReport(f), corrupted = a.copyBytes(); corrupted[0] ^= 1;
  assert.throws(() => validateInspectionMediaReport(corrupted, a.sha256, f), { code: "REPORT_HASH_MISMATCH" });
  const changed = JSON.parse(Buffer.from(a.copyBytes()).toString()); changed.overall = "complete";
  const b = jsonBytes(changed); assert.throws(() => validateInspectionMediaReport(b, hash(b), f), { code: "REPORT_BYTES_MISMATCH" });
  changed.schemaVersion = "future"; const c = jsonBytes(changed); assert.throws(() => validateInspectionMediaReport(c, hash(c), f), { code: "UNSUPPORTED_VERSION" });
  const duplicate = Buffer.from('{"schemaVersion":"ei-local-inspection-media-report/2","schemaVersion":"ei-local-inspection-media-report/2"}');
  assert.throws(() => validateInspectionMediaReport(duplicate, hash(duplicate), f), { code: "DUPLICATE_KEY" });
  f.prerequisite.reportBytes[0] ^= 1; refused(f, "REPORT_HASH_MISMATCH");
});

for (const component of ["static-png", "static-jpeg-webp", "scanned-pdf"]) test("actual " + component + " cancellation, typed refusal, output-limit failure and fresh recovery remain separate", async () => {
  const f = input(), source = component === "static-png" ? fixture.png() : component === "static-jpeg-webp" ? fixture.fixture("jpeg-rgb-baseline").bytes : fixture.imagePdf();
  const read = component === "static-png" ? fixture.readStaticPng : component === "static-jpeg-webp" ? fixture.raster.read : fixture.readScannedPdf;
  const format = component === "static-png" ? "png" : component === "static-jpeg-webp" ? "jpeg" : "scanned-pdf";
  const controller = new AbortController(); controller.abort();
  const cancelled = await read(source, { signal: controller.signal }); assert.equal(cancelled.kind, "rejected"); assert.equal(cancelled.code, "CANCELLED");
  const limited = await read(source, { maxOutputBytes: 1 }); assert.equal(limited.kind, "rejected"); assert.equal(limited.code, "OUTPUT_LIMIT");
  const malformed = await read(Buffer.from("invalid media")); assert.equal(malformed.kind, "rejected");
  const fresh = await read(source); assert.equal(fresh.kind, "decoded");
  const selected = f.prerequisite.input.expectedPins;
  for (const [label, native, bytes] of [["cancelled", cancelled, source], ["limited", limited, source], ["malformed", malformed, Buffer.from("invalid media")]]) {
    const attempt = input(); attempt.observations = attempt.observations.filter((o) => o.component !== component);
    attempt.observations.push(projectedObservation(component, format, component + "-" + label, native, bytes, selected));
    const report = composeInspectionMediaReport(attempt).report, observation = report.observations.find((o) => o.id === component + "-" + label);
    assert.equal(report.declaredCoverage, "incomplete"); assert.equal(observation.native.code, native.code); assert.deepEqual(observation.derivatives, []);
    assert.equal(observation.nativeSource.sha256, native.sourceSha256 ?? null);
  }
  const invalidInput = await read(null); assert.equal(invalidInput.kind, "rejected"); assert.equal(invalidInput.code, "INVALID_INPUT");
  const unknown = input(); unknown.observations = unknown.observations.filter((o) => o.component !== component);
  unknown.observations.push(projectedObservation(component, format, component + "-nonbyte", invalidInput, null, selected));
  const absent = composeInspectionMediaReport(unknown).report.observations.find((o) => o.id === component + "-nonbyte");
  assert.equal(absent.source, null); assert.equal(absent.nativeSource.sha256, null);
});

test("constructor configuration exceptions are not invented as native decoder result codes", () => {
  const f = input(); jpeg(f).projection.result = { kind: "rejected", code: "TypeError", sourceSha256: null, decoder: jpeg(f).projection.result.decoder };
  jpeg(f).derivatives = []; refused(f, "UNSUPPORTED_REFUSAL");
});


for (const [component, select] of [["PNG", png], ["JPEG", jpeg]]) {
  for (const [name, mutate, code] of [
    ["changed raw bytes", (o) => { o.derivatives[1].bytes[0] ^= 1; }, "DERIVATIVE_HASH_MISMATCH"],
    ["wrong raw sidecar", (o) => { o.derivatives[1].expectedSha256 = "0".repeat(64); }, "DERIVATIVE_HASH_MISMATCH"],
    ["wrong reported raw hash", (o) => { o.projection.result.rgbaSha256 = "0".repeat(64); }, "DERIVATIVE_HASH_MISMATCH"],
    ["short raw copy", (o) => { o.derivatives[1].bytes = o.derivatives[1].bytes.subarray(1); }, "DERIVATIVE_LENGTH_MISMATCH"],
    ["encoded PNG in the raw slot", (o) => { o.derivatives[1].bytes = o.derivatives[0].bytes; o.derivatives[1].expectedSha256 = o.derivatives[0].expectedSha256; }, "DERIVATIVE_HASH_MISMATCH"],
    ["scanned-page raw role", (o) => { o.derivatives[1].role = "page-rgba8"; }, "DERIVATIVE_FORMAT_MISMATCH"],
    ["invented raw page", (o) => { o.derivatives[1].page = 1; }, "DERIVATIVE_FORMAT_MISMATCH"],
    ["undeclared raw metadata", (o) => { o.derivatives[1].privateText = "PRIVATE_RAW_CANARY"; }, "INVALID_INPUT"],
  ]) test(component + " raw-byte join rejects " + name, () => { const f = input(); mutate(select(f)); refused(f, code); });

  test(component + " missing raw bytes remain unverified/incomplete and cannot borrow the encoded hash", () => {
    const f = input(); select(f).derivatives.pop();
    const report = composeInspectionMediaReport(f).report;
    const o = report.observations.find((o) => o.id === select(f).id);
    assert.equal(report.declaredCoverage, "incomplete"); assert.equal(o.componentReportedRgba.verified, false);
    assert.ok(report.reasons.includes("COMPONENT_RGBA_DOMAIN_NOT_INDEPENDENTLY_VERIFIED"));
    assert.equal(o.derivatives.length, 1); assert.equal(o.derivatives[0].domain, "normalized-png-bytes");
    assert.equal(report.acceptance.evaluated, false);
  });

  test(component + " actual raw-copy isolation, tamper refusal and original-copy recovery remain separately attributable", async () => {
    const f = input(), source = select(f).sourceBytes;
    const native = await (component === "PNG" ? fixture.readStaticPng(source) : fixture.raster.read(source));
    assert.equal(native.kind, "decoded");
    const first = native.copyRgbaBytes(), second = native.copyRgbaBytes(), encoded = native.copyNormalizedBytes();
    assert.notEqual(first.buffer, second.buffer); assert.equal(hash(first), native.rgbaSha256);
    assert.equal(hash(encoded), native.normalizedSha256); assert.notEqual(hash(encoded), hash(first));
    const actual = projectedObservation(select(f).component, select(f).format, "copy-recovery", native, source, f.prerequisite.input.expectedPins);
    f.observations = f.observations.filter((o) => o.id !== select(f).id); f.observations.push(actual);
    const before = composeInspectionMediaReport(f);
    first[0] ^= 1; assert.equal(hash(second), native.rgbaSha256); assert.equal(hash(native.copyRgbaBytes()), native.rgbaSha256);
    actual.derivatives[1].bytes = first; refused(f, "DERIVATIVE_HASH_MISMATCH");
    actual.derivatives[1].bytes = native.copyRgbaBytes();
    assert.equal(composeInspectionMediaReport(f).sha256, before.sha256);
    assert.equal(before.report.acceptance.evaluated, false);
  });
}

test("actual PNG alpha values remain distinct transparent/translucent/opaque samples without flattening", async () => {
  const source = fixture.png({ width: 3, height: 1, scanlines: Buffer.from([0, 11, 22, 33, 0, 44, 55, 66, 128, 77, 88, 99, 255]) });
  const native = await fixture.readStaticPng(source); assert.equal(native.kind, "decoded");
  const f = input(); f.observations.push(projectedObservation("static-png", "png", "alpha-three", native, source, f.prerequisite.input.expectedPins));
  const result = composeInspectionMediaReport(f).report.observations.find((o) => o.id === "alpha-three");
  const raw = result.derivatives[1];
  assert.deepEqual([raw.alpha.transparent, raw.alpha.translucent, raw.alpha.opaque, raw.alpha.total], [1, 1, 1, 3]);
  assert.equal(raw.format, "rgba8"); assert.equal(raw.coordinateSystem, "top-left-pixels"); assert.equal(raw.stride, 12);
  assert.deepEqual([...native.copyRgbaBytes()], [11, 22, 33, 0, 44, 55, 66, 128, 77, 88, 99, 255]);
  assert.match(result.componentReportedRgba.normalizedPixelEquivalence, /not independently established/);
  assert.equal(result.textOrFacts.startsWith("none;"), true);
});

test("duplicate, reordered or raw-only raster derivatives cannot replace the normalized representation", () => {
  const a = input(); png(a).derivatives.reverse(); refused(a, "DERIVATIVE_FORMAT_MISMATCH");
  const b = input(); png(b).derivatives.push(copy(png(b).derivatives[1])); refused(b, "DERIVATIVE_LENGTH_MISMATCH");
  const c = input(); png(c).derivatives.shift(); refused(c, "DERIVATIVE_FORMAT_MISMATCH");
});

test("raw slots reject proxy, accessor and shared byte inputs without executing caller code", () => {
  let calls = 0;
  const a = input(); png(a).derivatives[1] = new Proxy(png(a).derivatives[1], { get() { calls++; throw Error("trap"); }, ownKeys() { calls++; throw Error("trap"); } }); refused(a);
  const b = input(); Object.defineProperty(png(b).derivatives[1], "bytes", { get() { calls++; return new Uint8Array(4); }, enumerable: true }); refused(b);
  const c = input(); png(c).derivatives[1].bytes = new Uint8Array(new SharedArrayBuffer(4)); refused(c);
  const d = input(); png(d).projection.result.copyRgbaBytes = () => { calls++; return new Uint8Array(4); }; refused(d);
  assert.equal(calls, 0);
});

test("the existing aggregate derivative ceiling charges normalized and independently copied raw bytes together", async () => {
  // One actual native decoded maximum-pixel result is reused as a deliberately
  // repeated input. The byte admission bound must run before any report/dedupe
  // completion, without treating the repetitions as accepted source evidence.
  const source = fixture.png({ width: 4096, height: 1024, scanlines: Buffer.alloc((4096 * 4 + 1) * 1024) });
  const native = await fixture.readStaticPng(source); assert.equal(native.kind, "decoded", JSON.stringify(native));
  const f = input(), one = projectedObservation("static-png", "png", "large-copy", native, source, f.prerequisite.input.expectedPins);
  assert.equal(one.derivatives[1].bytes.length, 16 * 1024 * 1024);
  assert.ok(one.derivatives[0].bytes.length > 0);
  f.observations = Array.from({ length: 4 }, (_, index) => ({ ...one, id: "large-copy-" + index }));
  refused(f, "RESOURCE_LIMIT");
});

test("a schema1 report cannot be relabeled as the raw-verified schema2 format", () => {
  const f = input(), old = JSON.parse(Buffer.from(composeInspectionMediaReport(f).copyBytes()).toString());
  old.schemaVersion = "ei-local-inspection-media-report/1";
  const oldBytes = jsonBytes(old);
  assert.throws(() => validateInspectionMediaReport(oldBytes, hash(oldBytes), f), { code: "UNSUPPORTED_VERSION" });
});
