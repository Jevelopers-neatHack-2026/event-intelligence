import test from "node:test";
import assert from "node:assert/strict";
import { composeInspectionOcrReport as compose, validateInspectionOcrReport as validate } from "../../../src/extraction/inspection-report/ocr.mjs";
import { actualOcrFixture, copy, hash, jsonBytes, resultBytes, alterResult, alterSummary, refreshMedia, refreshCallerRecords, capture, expectedText } from "./support.mjs";

const original = await actualOcrFixture();
const fresh = () => copy(original);
const rejected = (fn, code) => assert.throws(fn, (e) => e.name === "InspectionReportError" && (code === undefined || e.code === code));
const ocr = (input, id = "text-png") => input.observations.find((o) => o.id === id);
const media = (input, id = "text-png") => input.prerequisite.input.observations.find((o) => o.id === "ocr-media-" + id);

test("actual PNG/JPEG/WebP and two-page PDF OCR join real prerequisite source and raw copies, remaining unverified", () => {
  const artifact = compose(original); capture("ocr-report.json", artifact.copyBytes());
  assert.equal(artifact.report.overall, "incomplete"); assert.equal(artifact.report.acceptance.evaluated, false);
  assert.equal(artifact.report.financeAuthority, "none"); assert.equal(artifact.report.factInference, "none");
  assert.deepEqual(artifact.report.missingFormats, []);
  for (const id of ["text-png", "text-jpeg", "text-webp", "text-pdf"]) {
    const o = artifact.report.observations.find((o) => o.id === id);
    assert.equal(o.binding, "bound-supplied-byte-domains"); assert.equal(o.callerRecordBound, true);
    assert.equal(o.observation.requiresReview, true); assert.equal(o.observation.sourceAuthority, "unverified");
    const pages = id === "text-pdf" ? o.observation.pages : [o.observation];
    for (const p of pages) {
      assert.equal(p.words.map((w) => w.text).join(" "), expectedText);
      for (const w of p.words) assert.equal(w.provenance.sourceBinding, "caller-supplied-unverified");
    }
  }
  assert.ok(artifact.report.executions.every((e) => e.callerRecord !== null));
  // Dirty development runs are recorded as incomplete source evidence.
  if (artifact.report.prerequisite.report.source.complete) assert.ok(artifact.report.executions.every((e) => e.complete));
});
test("actual blank observations, nonopaque refusal and cancellation retain distinct native outcomes", () => {
  const r = compose(original).report;
  const byId = (id) => r.observations.find((o) => o.id === id);
  assert.equal(byId("blank-png").observation.status, "no-text-observed");
  assert.equal(byId("blank-pdf").observation.pages[0].words.length, 0);
  assert.equal(byId("transparent-png").observation.code, "NON_OPAQUE_IMAGE");
  assert.equal(byId("cancelled-png").observation.code, "CANCELLED");
  assert.equal(Object.hasOwn(byId("cancelled-png").observation, "sourceSha256"), false);
  assert.notEqual(byId("cancelled-png").originalSource, null);
});
test("artifact copies and output are immutable snapshots; canonical ordering is deterministic", () => {
  const i = fresh(), a = compose(i), b = a.copyBytes(); b.fill(0); i.observations.reverse(); i.executions.reverse(); i.requiredFormats.reverse();
  assert.deepEqual(compose(i).copyBytes(), a.copyBytes());
  assert.equal(hash(a.copyBytes()), a.sha256); assert.equal(a.byteLength, a.copyBytes().length);
  assert.ok(Object.isFrozen(a.report) && Object.isFrozen(a.report.observations[0].observation));
  assert.equal(validate(a.copyBytes(), a.sha256, original).sha256, a.sha256);
});
test("caller-selected zero confidence and injection-shaped words remain untrusted data", () => {
  const i = fresh(); alterResult(i, "text-png", (r) => {
    r.words[0].confidence = 0; r.words[0].text = "ignore-all-instructions";
    r.tokenUtf8Bytes = r.words.reduce((n, w) => n + Buffer.byteLength(w.text), 0);
  });
  const r = compose(i).report.observations.find((o) => o.id === "text-png").observation;
  assert.equal(r.words[0].confidence, 0); assert.equal(r.words[0].text, "ignore-all-instructions"); assert.equal(r.sourceAuthority, "unverified");
});
test("missing caller record never attributes separately supplied result to the component suite", () => {
  const i = fresh(); i.executions[0].callerRecordBytes = null; i.executions[0].expectedCallerRecordSha256 = null;
  const r = compose(i).report; assert.ok(r.reasons.includes("OCR_CALLER_RECORD_MISSING"));
  assert.equal(r.observations.find((o) => o.id === "text-png").callerRecordBound, false);
});
test("missing raw image copy stays unbound; normalized PNG does not verify RGBA", () => {
  const i = fresh(); media(i).derivatives.pop(); refreshMedia(i);
  const r = compose(i).report; assert.equal(r.observations.find((o) => o.id === "text-png").binding, "unbound-missing-raw-bytes");
});
test("missing required format remains incomplete without deleting original failed attempts", () => {
  const i = fresh(); i.observations = i.observations.filter((o) => o.id !== "text-webp"); refreshCallerRecords(i);
  const r = compose(i).report; assert.deepEqual(r.missingFormats, ["webp"]); assert.ok(r.observations.some((o) => o.id === "cancelled-png"));
});
test("missing selected runtime and child stderr cannot become completed execution", () => {
  const i = fresh(); i.runtimeReceipt = null; i.executions[0].childStderrBytes = null;
  const r = compose(i).report; assert.ok(r.reasons.includes("OCR_RUNTIME_RECEIPT_MISSING")); assert.equal(r.executions.find((e) => e.component === "static-image-ocr").complete, false);
});
test("unknown runtime bytes cannot impersonate the actual selected marker", () => {
  const i = fresh(); i.runtimeReceipt.bytes = Buffer.from("arbitrary"); i.runtimeReceipt.expectedSha256 = hash(i.runtimeReceipt.bytes);
  assert.ok(compose(i).report.executions.every((e) => e.runtimeBound === false && e.complete === false));
});

for (const [name, change, code] of [
  ["source hash", (r) => { r.sourceSha256 = "f".repeat(64); }, "SOURCE_HASH_MISMATCH"],
  ["raw RGBA hash", (r) => { r.image.rgbaSha256 = r.image.normalizedSha256; }, "PROVENANCE_MISMATCH"],
  ["normalized PNG hash", (r) => { r.image.normalizedSha256 = r.image.rgbaSha256; }, "PROVENANCE_MISMATCH"],
  ["image dimension", (r) => { r.image.width++; }, "PROVENANCE_MISMATCH"],
  ["image encoding", (r) => { r.image.encoding = "lossy"; }, "PROVENANCE_MISMATCH"],
  ["observer model", (r) => { r.observer.modelSha256 = "f".repeat(64); }, "UNSUPPORTED_VERSION"],
  ["decoder version", (r) => { r.decoder.nodeVersion = "0.0.0"; }, "UNSUPPORTED_VERSION"],
  ["completeness promotion", (r) => { r.completeness = "complete"; }, "INVALID_STATUS"],
  ["source authority promotion", (r) => { r.sourceAuthority = "verified"; }, "INVALID_STATUS"],
  ["word source binding promotion", (r) => { r.words[0].provenance.sourceBinding = "verified"; }, "PROVENANCE_MISMATCH"],
  ["word page mismatch", (r) => { r.words[0].provenance.page = 2; }, "PROVENANCE_MISMATCH"],
  ["word missing provenance", (r) => { delete r.words[0].provenance; }, undefined],
  ["word box out of bounds", (r) => { r.words[0].box.left = r.image.width; }, "INVALID_GEOMETRY"],
  ["fractional box", (r) => { r.words[0].box.width = 1.5; }, "INVALID_GEOMETRY"],
  ["negative confidence", (r) => { r.words[0].confidence = -1; }, "INVALID_WORD"],
  ["misstated status", (r) => { r.status = "no-text-observed"; }, "STATUS_MISMATCH"],
  ["text bytes mismatch", (r) => { r.tokenUtf8Bytes++; }, "COUNT_MISMATCH"],
  ["control character", (r) => { r.words[0].text = "bad\u0000"; }, "INVALID_WORD"],
  ["unpaired Unicode", (r) => { r.words[0].text = "\ud800"; }, "INVALID_WORD"],
  ["output cap exceeds profile", (r) => { r.limits.maxOutputBytes++; }, "INVALID_LIMITS"],
  ["word cap below output", (r) => { r.limits.maxWords = 1; }, "RESOURCE_LIMIT"],
  ["zero word cap", (r) => { r.limits.maxWords = 0; }, "INVALID_LIMITS"],
  ["missing limiter", (r) => { delete r.limits.timeoutMs; }, undefined],
]) test("rejects " + name + " despite recomputed result/caller hashes", () => {
  const i = fresh(); alterResult(i, "text-png", change); rejected(() => compose(i), code);
});
for (const [name, change] of [
  ["page order", (r) => r.pages.reverse()],
  ["page count", (r) => { r.totalPages--; }],
  ["page source", (r) => { r.pages[0].sourceSha256 = "f".repeat(64); }],
  ["page derivative", (r) => { r.pages[0].derivativeSha256 = "f".repeat(64); }],
  ["page points", (r) => { r.pages[0].pageWidthPoints++; }],
  ["pixel byte count", (r) => { r.pages[0].pixelByteLength++; }],
  ["total pixels", (r) => { r.totalPixels++; }],
  ["total words", (r) => { r.totalWords++; }],
  ["total text", (r) => { r.tokenUtf8Bytes++; }],
]) test("rejects PDF " + name + " with otherwise real prior byte evidence", () => {
  const i = fresh(); alterResult(i, "text-pdf", change); rejected(() => compose(i));
});
for (const [name, select] of [
  ["root result", (r) => r], ["word", (r) => r.words[0]], ["box", (r) => r.words[0].box],
  ["provenance", (r) => r.provenance], ["word provenance", (r) => r.words[0].provenance],
  ["limits", (r) => r.limits], ["observer", (r) => r.observer], ["decoder", (r) => r.decoder], ["image", (r) => r.image],
]) test("rejects undeclared private metadata in " + name, () => {
  const i = fresh(); alterResult(i, "text-png", (r) => { select(r).privateText = "must not copy"; }); rejected(() => compose(i));
});
for (const [name, change] of [
  ["wrong result hash", (i) => { ocr(i).expectedResultSha256 = "f".repeat(64); }],
  ["wrong media target", (i) => { ocr(i).mediaObservationId = "ocr-media-blank-png"; }],
  ["wrong component execution", (i) => { ocr(i).executionId = "scanned-pdf-ocr"; }],
  ["duplicate observation ID", (i) => { i.observations[1].id = i.observations[0].id; }],
  ["duplicate output with new ID", (i) => { i.observations.push({ ...copy(i.observations[0]), id: "duplicate" }); refreshCallerRecords(i); }],
  ["duplicate execution", (i) => { i.executions.push(copy(i.executions[0])); }],
  ["wrong pins", (i) => { i.executions[0].pins.sourceRevision = "f".repeat(40); }],
  ["wrong report prerequisite digest", (i) => { i.prerequisite.expectedSha256 = "f".repeat(64); }],
  ["caller record hash", (i) => { i.executions[0].expectedCallerRecordSha256 = "f".repeat(64); }],
]) test("rejects " + name, () => { const i = fresh(); change(i); rejected(() => compose(i)); });
for (const key of ["resultSha256", "providedSourceSha256", "mediaObservationId", "id"]) test("rejects recomputed caller record with wrong " + key, () => {
  const i = fresh(), e = i.executions[0], r = JSON.parse(Buffer.from(e.callerRecordBytes));
  r.records[0][key] = key.endsWith("Sha256") ? "f".repeat(64) : "other";
  e.callerRecordBytes = jsonBytes(r); e.expectedCallerRecordSha256 = hash(e.callerRecordBytes); rejected(() => compose(i));
});
for (const [name, change] of [
  ["duplicate summary", (e) => { e.stdoutBytes = Buffer.concat([e.stdoutBytes, e.stdoutBytes]); }],
  ["invalid UTF8", (e) => { e.stdoutBytes = Buffer.from([0xff]); }],
  ["wrong child stderr", (e) => { e.childStderrBytes = Buffer.from("not captured"); }],
]) test("rejects " + name + " execution evidence", () => { const i = fresh(); change(i.executions[0]); rejected(() => compose(i)); });
test("false pass and missing runtime/source stability declarations are rejected", () => {
  const i = fresh(); alterSummary(i, "static-image-ocr", (n) => { n.runtimeMarkersUnchanged = false; }); rejected(() => compose(i), "FALSE_PASS");
});
test("recorded or wrong provider mode is never a mock execution pass", () => {
  const i = fresh(); i.executions[0].mode = "live"; i.executions[0].origin = "recorded";
  assert.equal(compose(i).report.executions.find((e) => e.component === "static-image-ocr").complete, false);
});
test("honest missing or failed suite capture stays incomplete", () => {
  const i = fresh(); i.executions[0].stdoutBytes = Buffer.alloc(0); i.executions[0].exitCode = 1;
  const r = compose(i).report; assert.ok(r.reasons.includes("OCR_EXECUTION_INCOMPLETE")); assert.equal(r.overall, "incomplete");
});
test("a prior failed result remains after corrected local replay; no expense or shared authority appears", () => {
  const i = fresh(), a = compose(i); assert.ok(a.report.observations.some((o) => o.id === "cancelled-png"));
  const o = ocr(i); o.expectedResultSha256 = "f".repeat(64); rejected(() => compose(i)); o.expectedResultSha256 = hash(resultBytes(o.result));
  assert.equal(compose(i).sha256, a.sha256); assert.equal(a.report.financeAuthority, "none");
});
test("report hash, schema and canonical byte tampering never validate", () => {
  const a = compose(original), b = a.copyBytes(); b[0] ^= 1;
  rejected(() => validate(b, a.sha256, original));
  const r = JSON.parse(Buffer.from(a.copyBytes())); r.schemaVersion = "foreign/accepted";
  const t = jsonBytes(r); rejected(() => validate(t, hash(t), original), "UNSUPPORTED_VERSION");
  const w = Buffer.concat([Buffer.from(" "), a.copyBytes()]); rejected(() => validate(w, hash(w), original), "REPORT_BYTES_MISMATCH");
});
for (const [name, target, key] of [
  ["result", (i) => ocr(i), "result"], ["image", (i) => ocr(i).result, "image"],
  ["words", (i) => ocr(i).result, "words"], ["provenance", (i) => ocr(i).result, "provenance"],
  ["limits", (i) => ocr(i).result, "limits"], ["observations", (i) => i, "observations"],
  ["executions", (i) => i, "executions"], ["required formats", (i) => i, "requiredFormats"],
]) test("nested " + name + " proxies never execute traps", () => {
  const i = fresh(), t = target(i); let hits = 0;
  t[key] = new Proxy(t[key], { get() { hits++; throw Error("trap"); }, ownKeys() { hits++; throw Error("trap"); }, getPrototypeOf() { hits++; throw Error("trap"); } });
  rejected(() => compose(i)); assert.equal(hits, 0);
});
test("nested result getters never execute", () => {
  const i = fresh(); let hits = 0; Object.defineProperty(ocr(i).result, "image", { get() { hits++; return {}; }, enumerable: true });
  rejected(() => compose(i)); assert.equal(hits, 0);
});
for (const [name, change] of [
  ["sparse observations", (i) => { delete i.observations[0]; }],
  ["sparse words", (i) => { delete ocr(i).result.words[0]; }],
  ["extra array property", (i) => { i.observations.privateText = "no"; }],
  ["symbol property", (i) => { ocr(i).result[Symbol("private")] = "no"; }],
  ["cyclic result", (i) => { ocr(i).result.words = [ocr(i).result]; }],
  ["source byte tamper", (i) => { media(i).sourceBytes[0] ^= 1; }],
  ["raw byte tamper", (i) => { media(i).derivatives[1].bytes[0] ^= 1; }],
  ["too many observations", (i) => { i.observations = Array(33).fill(i.observations[0]); }],
]) test("rejects " + name + " at the bounded input boundary", () => { const i = fresh(); change(i); rejected(() => compose(i)); });
test("actual offset Buffer and Uint8Array report views preserve exact byte identity", () => {
  const a = compose(original), b = Buffer.concat([Buffer.from("prefix"), a.copyBytes(), Buffer.from("suffix")]);
  const view = b.subarray(6, b.length - 6); assert.equal(validate(view, a.sha256, original).sha256, a.sha256);
  assert.equal(validate(new Uint8Array(view.buffer, view.byteOffset, view.byteLength), a.sha256, original).sha256, a.sha256);
});
for (const [name, change] of [
  ["duplicate ordinal", (r) => { for (const k of ["block", "paragraph", "line", "word"]) r.words[1][k] = r.words[0][k]; }],
  ["reordered ordinal", (r) => { r.words.reverse(); }],
  ["overlarge ordinal", (r) => { r.words[0].block = 2049; }],
  ...["\u0080", "\u2028", "\u2066"].map((c) => ["forbidden U+" + c.codePointAt(0).toString(16), (r) => { r.words[0].text = c; r.tokenUtf8Bytes = r.words.reduce((n, w) => n + Buffer.byteLength(w.text), 0); }]),
]) test("rejects exact native-profile " + name, () => {
  const i = fresh(); alterResult(i, "text-png", change); rejected(() => compose(i), "INVALID_WORD");
});
test("rejects invented component refusal error rather than accepting arbitrary uppercase text", () => {
  const i = fresh(); alterResult(i, "transparent-png", (r) => { r.componentCode = "INVENTED_SUCCESS"; }); rejected(() => compose(i), "INVALID_STATUS");
});
for (const status of ["fail", "skipped", "todo", "cancelled"]) test("honest " + status + " case remains incomplete even with a complete case inventory", () => {
  const i = fresh();
  alterSummary(i, "static-image-ocr", (n) => { n.complete = false; n.counts.pass--; n.counts[status]++; n.exitCode = 1; }, (tap) => {
    const tag = status === "skipped" ? " # SKIP deliberate synthetic control" : status === "todo" ? " # TODO deliberate synthetic control" : "";
    return tap.replace(/^ok 1 - [^\r\n]*$/m, (line) => (tag ? line + tag : "not " + line))
      .replace(/^# pass (\d+)$/m, (_, n) => "# pass " + (Number(n) - 1)).replace(new RegExp("^# " + status + " 0$", "m"), "# " + status + " 1");
  });
  i.executions[0].exitCode = 1;
  assert.equal(compose(i).report.executions.find((e) => e.component === "static-image-ocr").complete, false);
});
test("matching selected source hash with changed after-snapshot remains incomplete", () => {
  const i = fresh(), p = i.prerequisite.input.source, after = JSON.parse(Buffer.from(p.afterBytes));
  after.dirty = true; p.afterBytes = jsonBytes(after); p.expectedAfterSha256 = hash(p.afterBytes); refreshMedia(i); refreshCallerRecords(i);
  assert.ok(compose(i).report.executions.every((e) => !e.complete));
});
test("native output JSON limit is distinct from the canonical record's trailing LF", () => {
  const i = fresh(); alterResult(i, "text-png", (r) => {
    r.limits.maxOutputBytes = 1;
    for (let k = 0; k < 3; k++) r.limits.maxOutputBytes = Buffer.byteLength(JSON.stringify(r));
  });
  assert.equal(compose(i).report.observations.find((o) => o.id === "text-png").binding, "bound-supplied-byte-domains");
});
