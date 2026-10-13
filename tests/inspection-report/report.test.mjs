import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { before, test } from "node:test";
import { readTextPdf } from "../../src/extraction/pdf/index.mjs";
import { composeInspectionReport, validateInspectionReport, INSPECTION_REPORT_LIMITS } from "../../src/extraction/inspection-report/index.mjs";
import { actualFixture, copy, hash, jsonBytes, replaceSummary } from "./support.mjs";

let base;
before(async () => { base = await actualFixture(); });
const reject = (fn, code) => assert.throws(fn, { name: "InspectionReportError", code });

test("actual HTML/text and Linux PDF outputs bind distinct source/result/report domains", () => {
  const artifact = composeInspectionReport(base);
  const r = artifact.report;
  assert.equal(r.prerequisiteDeterministicReport.sha256, hash(base.executions[0].summaryBytes));
  assert.equal(r.prerequisiteDeterministicReport.domain, "execution-stdout-bytes");
  assert.equal(r.observations[0].source.sha256, base.observations[0].expectedSourceSha256);
  assert.equal(r.observations[0].view.nativeSourceHash, "sha256:" + r.observations[0].source.sha256);
  const pdf = r.observations.find((o) => o.component === "text-pdf");
  assert.equal(pdf.view.nativeSourceHash, pdf.source.sha256);
  assert.notEqual(pdf.result.sha256, pdf.source.sha256);
  assert.notEqual(artifact.sha256, pdf.result.sha256);
  assert.equal(pdf.view.pages[1].rotation, 90);
  assert.equal(pdf.view.pages[0].boxes[0].textHashDomain, "derived-text-utf8");
  assert.equal(r.observations[0].view.counts.events, 2);
  assert.equal(r.overall, "incomplete");
  assert.equal(r.declaredCoverage, "incomplete");
  assert.deepEqual(r.missingFormats, ["jpeg", "png", "scanned-pdf", "webp"]);
  assert.deepEqual(r.acceptance, { evaluated: false, satisfiedIds: [], ownerAcknowledgements: [] });
  assert.equal(r.financeAuthority, "none");
  assert.equal(validateInspectionReport(artifact.copyBytes(), artifact.sha256, base).sha256, artifact.sha256);
  const text = Buffer.from(artifact.copyBytes()).toString();
  assert.ok(!text.includes("Community Night") && !text.includes("Café Night") && !text.includes("events.example.test"));
});

test("reordered inventory and repeated composition produce exact deterministic bytes", () => {
  const reordered = copy(base);
  reordered.observations.reverse(); reordered.executions.reverse();
  const first = composeInspectionReport(base);
  assert.deepEqual(composeInspectionReport(reordered).copyBytes(), first.copyBytes());
  assert.deepEqual(composeInspectionReport(base).copyBytes(), first.copyBytes());
});

for (const [name, index, addMetadata] of [
  ["deterministic locator", 0, (result, marker) => { result.visibleText[0].source.locator.privateText = marker; }],
  ["native PDF limits", 2, (result, marker) => { result.limits.privateText = marker; }],
]) test(`unknown ${name} metadata is omitted while the complete original result stays bound`, () => {
  const input = copy(base);
  const prior = composeInspectionReport(base);
  const marker = `EI_SYNTHETIC_PRIVATE_METADATA_${index}`;
  addMetadata(input.observations[index].result, marker);
  const originalResultBytes = jsonBytes(input.observations[index].result);
  const artifact = composeInspectionReport(input);
  const id = input.observations[index].id;
  const before = prior.report.observations.find((observation) => observation.id === id);
  const after = artifact.report.observations.find((observation) => observation.id === id);
  assert.deepEqual(after.view, before.view);
  assert.notEqual(after.result.sha256, before.result.sha256);
  assert.equal(Buffer.from(artifact.copyBytes()).toString("utf8").includes(marker), false);
  assert.deepEqual(jsonBytes(input.observations[index].result), originalResultBytes);
  assert.equal(validateInspectionReport(artifact.copyBytes(), artifact.sha256, input).sha256, artifact.sha256);
  reject(() => validateInspectionReport(prior.copyBytes(), prior.sha256, input), "REPORT_BYTES_MISMATCH");
  assert.equal(artifact.report.overall, "incomplete");
});

for (const recordName of ["root", "package", "evidenceSchema", "supportMatrix"]) {
  test(`unknown ${recordName} pin fields refuse at every selection boundary`, () => {
    for (const boundary of ["consistent selection", "execution", "observation"]) {
      const input = copy(base);
      const pins = copy(input.expectedPins);
      const target = recordName === "root" ? pins : pins[recordName];
      target.privateText = "EI_SYNTHETIC_PRIVATE_PIN_METADATA";
      if (boundary === "consistent selection") {
        input.expectedPins = pins;
        for (const execution of input.executions) execution.pins = pins;
        for (const observation of input.observations) observation.pins = pins;
      } else if (boundary === "execution") input.executions[0].pins = pins;
      else input.observations[0].pins = pins;
      reject(() => composeInspectionReport(input), "INVALID_INPUT");
      assert.equal(composeInspectionReport(base).report.overall, "incomplete");
    }
  });
}

test("copies, returned views and prior failure receipts cannot be overwritten by retry", () => {
  const failed = copy(base); const count = failed.executions[0].expectedCases;
  failed.executions[0].exitCode = 1;
  replaceSummary(failed, { status: "failed", exit_code: 1, passed_cases: count - 1, failed_cases: 1 });
  const before = composeInspectionReport(failed); const original = before.copyBytes();
  const after = composeInspectionReport(base);
  assert.notEqual(before.sha256, after.sha256);
  assert.equal(before.report.executions[0].counts.failed, 1);
  assert.equal(after.report.executions[0].counts.failed, 0);
  const external = before.copyBytes(); external.fill(0);
  assert.deepEqual(before.copyBytes(), original);
  assert.throws(() => { before.report.overall = "passed"; }, TypeError);
  assert.equal(validateInspectionReport(original, before.sha256, failed).sha256, before.sha256);
});

for (const [name, update, code] of [
  ["expected original hash", (x) => { x.observations[0].expectedSourceSha256 = "0".repeat(64); }, "SOURCE_HASH_MISMATCH"],
  ["changed retained source", (x) => { x.observations[0].sourceBytes[0] ^= 1; }, "SOURCE_HASH_MISMATCH"],
  ["native deterministic hash prefix", (x) => { x.observations[0].result.sourceHash = x.observations[0].expectedSourceSha256; }, "SOURCE_HASH_MISMATCH"],
  ["PDF source/result hash alias", (x) => { x.observations[2].result.documentSha256 = hash(jsonBytes(x.observations[2].result)); }, "SOURCE_HASH_MISMATCH"],
  ["source retrieval metadata", (x) => { x.observations[0].sourceMetadata.fetchedAt = "2026-10-12T00:00:00Z"; }, "SOURCE_METADATA_MISMATCH"],
  ["format alias", (x) => { x.observations[0].format = "png"; }, "FORMAT_MISMATCH"],
  ["raw text slice", (x) => { x.observations[0].result.visibleText[0].rawValue += " fabricated"; }, "SOURCE_SLICE_MISMATCH"],
  ["out of bounds text locator", (x) => { x.observations[0].result.visibleText[0].source.locator.endByte = x.observations[0].sourceBytes.length + 1; }, "INVALID_LOCATOR"],
  ["extractor version", (x) => { x.observations[0].result.extractorVersion = "ei-deterministic-extraction/999"; }, "UNSUPPORTED_VERSION"],
  ["parser version", (x) => { x.observations[0].result.parserVersions.html = "parse5@999"; }, "UNSUPPORTED_VERSION"],
  ["declared extractor limit enlargement", (x) => { x.observations[0].declaredLimits.maxDocumentBytes += 1; }, "INVALID_LIMITS"],
  ["native decoder version", (x) => { x.observations[2].result.decoder.version = "7.0.0"; }, "UNSUPPORTED_VERSION"],
  ["PDF completeness promotion", (x) => { x.observations[2].result.completeness = "complete"; }, "INVALID_COMPLETENESS"],
  ["PDF inspection bypass", (x) => { x.observations[2].result.requiresInspection = false; }, "INVALID_COMPLETENESS"],
  ["PDF output limit enlargement", (x) => { x.observations[2].result.limits.maxOutputBytes += 1; }, "INVALID_LIMITS"],
  ["PDF ordinal reassignment", (x) => { x.observations[2].result.pages[1].pageIndex = 0; }, "INVALID_LOCATOR"],
  ["PDF coordinate domain alias", (x) => { x.observations[2].result.pages[0].coordinateSystem = "original-byte-range"; }, "INVALID_LOCATOR"],
  ["PDF out of page geometry", (x) => { x.observations[2].result.pages[0].textBoxes[0].width = 100000; }, "INVALID_LOCATOR"],
  ["execution/source join", (x) => { x.observations[0].executionId = "pdf"; }, "EXECUTION_BINDING_MISMATCH"],
]) test(`refuses ${name} tampering`, () => {
  const input = copy(base); update(input); reject(() => composeInspectionReport(input), code);
  assert.equal(composeInspectionReport(base).report.overall, "incomplete");
});

for (const artifact of ["package", "evidenceSchema", "supportMatrix"]) test(`checks exact ${artifact} bytes, not a caller digest alone`, () => {
  const input = copy(base); input.artifacts[artifact] = Buffer.concat([input.artifacts[artifact], Buffer.from(" ")]);
  reject(() => composeInspectionReport(input), "PIN_MISMATCH");
});

test("pins cannot be mixed across revisions or component report selections", () => {
  const input = copy(base); input.executions[0].pins = copy(input.expectedPins);
  input.executions[0].pins.sourceRevision = "a".repeat(40);
  reject(() => composeInspectionReport(input), "PIN_MISMATCH");
  input.executions[0].pins = copy(input.expectedPins);
  input.observations[0].pins = copy(input.expectedPins);
  input.observations[0].pins.supportMatrix.version = "another-release/2";
  reject(() => composeInspectionReport(input), "PIN_MISMATCH");
});

test("schema version uses its explicit existing JSON pointer, without an inferred alias", () => {
  const input = copy(base);
  input.expectedPins.evidenceSchema.version = "2.0.0";
  reject(() => composeInspectionReport(input), "PIN_MISMATCH");
  input.expectedPins.evidenceSchema.version = "1.0.0";
  input.expectedPins.evidenceSchema.versionPointer = "/properties/~2schema_version/const";
  reject(() => composeInspectionReport(input), "INVALID_POINTER");
});

test("unknown local matrix/report versions refuse with actionable typed errors", () => {
  const input = copy(base); const matrix = JSON.parse(Buffer.from(input.artifacts.supportMatrix));
  matrix.schemaVersion = "ei-local-inspection-support-matrix/2";
  input.artifacts.supportMatrix = jsonBytes(matrix);
  input.expectedPins.supportMatrix.sha256 = hash(input.artifacts.supportMatrix);
  reject(() => composeInspectionReport(input), "UNSUPPORTED_VERSION");
  const artifact = composeInspectionReport(base); const r = copy(artifact.report); r.schemaVersion = "ei-local-inspection-report/2";
  const encoded = jsonBytes(r); reject(() => validateInspectionReport(encoded, hash(encoded), base), "UNSUPPORTED_VERSION");
});

test("a selected inventory can be complete while aggregate acceptance stays incomplete", () => {
  const input = copy(base); const matrix = JSON.parse(Buffer.from(input.artifacts.supportMatrix));
  matrix.requiredFormats = ["html", "plain-text", "text-pdf"];
  input.artifacts.supportMatrix = jsonBytes(matrix); input.expectedPins.supportMatrix.sha256 = hash(input.artifacts.supportMatrix);
  input.mappingState = "selected-unaccepted";
  const r = composeInspectionReport(input).report;
  assert.equal(r.declaredCoverage, "complete");
  assert.equal(r.overall, "incomplete");
  assert.ok(r.reasons.includes("CANONICAL_MAPPING_SELECTED_UNACCEPTED"));
  input.mappingState = "accepted";
  reject(() => composeInspectionReport(input), "INVALID_INPUT");
});

test("missing results and missing prerequisite cannot become passes through inventory selection", () => {
  const input = copy(base); input.observations = []; input.executions = [];
  const r = composeInspectionReport(input).report;
  assert.equal(r.prerequisiteDeterministicReport, null);
  assert.equal(r.declaredCoverage, "incomplete");
  assert.equal(r.missingFormats.length, 7);
  assert.ok(r.reasons.includes("DETERMINISTIC_PREREQUISITE_MISSING"));
});

for (const field of ["failed", "skipped", "todo", "cancelled"]) test(`required ${field} results stay explicitly incomplete`, () => {
  const input = copy(base); const e = input.executions[0]; e.exitCode = 1;
  replaceSummary(input, { status: "failed", exit_code: 1, passed_cases: e.expectedCases - 1, [field + "_cases"]: 1 });
  const r = composeInspectionReport(input).report;
  assert.equal(r.executions[0].counts[field], 1);
  assert.equal(r.executions[0].complete, false);
  assert.ok(r.reasons.includes("DETERMINISTIC_PREREQUISITE_INCOMPLETE"));
});

test("mode mismatch and recorded origin do not supply a live or current execution grant", () => {
  const input = copy(base); input.requiredMode = "live"; input.executions[0].origin = "recorded";
  const r = composeInspectionReport(input).report;
  assert.equal(r.declaredCoverage, "incomplete");
  assert.ok(r.reasons.includes("MODE_MISMATCH"));
  assert.ok(r.reasons.includes("RECORDED_OR_PROVIDER_EXECUTION_NOT_AUTHENTICATED"));
  assert.equal(r.acceptance.evaluated, false);
  input.requiredMode = "mock";
  assert.equal(composeInspectionReport(input).report.executions[0].complete, false);
  input.executions[0].origin = "local-synthetic"; input.executions[0].mode = "live";
  replaceSummary(input, { mode: "live" });
  reject(() => composeInspectionReport(input), "INVALID_MODE");
});

test("duplicate summary lines, duplicate JSON keys and summary laundering are rejected", () => {
  const input = copy(base); const e = input.executions[0];
  e.summaryBytes = Buffer.concat([e.summaryBytes, e.summaryBytes]);
  reject(() => composeInspectionReport(input), "DUPLICATE_SUMMARY");
  e.summaryBytes = Buffer.from(base.executions[0].summaryBytes.toString().replace('"passed_cases":', '"passed_cases":0,"passed_cases":'));
  reject(() => composeInspectionReport(input), "DUPLICATE_KEY");
  e.summaryBytes = copy(base.executions[0].summaryBytes);
  replaceSummary(input, { failed_cases: 1 });
  reject(() => composeInspectionReport(input), "FALSE_PASS");
});

test("truncated TAP, duplicate terminal counts and wrong expected counts refuse", () => {
  const input = copy(base); const e = input.executions[1];
  e.summaryBytes = Buffer.from(e.summaryBytes).subarray(0, 80);
  reject(() => composeInspectionReport(input), "MISSING_SUMMARY");
  e.summaryBytes = Buffer.concat([base.executions[1].summaryBytes, Buffer.from("\n# pass 14\n")]);
  reject(() => composeInspectionReport(input), "DUPLICATE_SUMMARY");
  e.summaryBytes = copy(base.executions[1].summaryBytes); e.expectedCases += 1;
  assert.equal(composeInspectionReport(input).report.executions[1].complete, false);
});

test("duplicate ids, repeated source observations and competing component summaries refuse", () => {
  const input = copy(base); input.observations.push(copy(input.observations[0]));
  reject(() => composeInspectionReport(input), "DUPLICATE_ID");
  input.observations.at(-1).id = "second-name";
  reject(() => composeInspectionReport(input), "DUPLICATE_OBSERVATION");
  input.observations.pop(); input.executions.push({ ...input.executions[0], id: "replacement" });
  reject(() => composeInspectionReport(input), "DUPLICATE_COMPONENT");
});

test("hash-preserving metadata edits, byte tampering and duplicate report keys cannot validate", () => {
  const a = composeInspectionReport(base); const tampered = copy(a.report); tampered.overall = "passed";
  const encoded = jsonBytes(tampered);
  reject(() => validateInspectionReport(encoded, hash(encoded), base), "REPORT_BYTES_MISMATCH");
  reject(() => validateInspectionReport(a.copyBytes(), "0".repeat(64), base), "REPORT_HASH_MISMATCH");
  const duplicate = Buffer.from(Buffer.from(a.copyBytes()).toString().replace('"overall":', '"overall":"passed","overall":'));
  reject(() => validateInspectionReport(duplicate, hash(duplicate), base), "DUPLICATE_KEY");
  const changed = copy(base); changed.observations[0].result.diagnostics.push({ code: "ADDED_RESULT" });
  reject(() => validateInspectionReport(a.copyBytes(), a.sha256, changed), "REPORT_BYTES_MISMATCH");
});

test("IDs cannot be filesystem paths and summaries cannot escape via a filename input", () => {
  const input = copy(base); input.observations[0].id = "../../private";
  reject(() => composeInspectionReport(input), "INVALID_INPUT");
  input.observations[0].id = "html-source"; input.executions[0].summaryBytes = "/tmp/report.json";
  reject(() => composeInspectionReport(input), "INVALID_INPUT");
});

test("numeric and coercible-array identifiers are rejected without silent string conversion", () => {
  for (const id of [12, ["html-source"]]) {
    const input = copy(base); input.observations[0].id = id;
    reject(() => composeInspectionReport(input), "INVALID_INPUT");
  }
});

test("TAP pass footers cannot erase an earlier actual failure line", () => {
  const input = copy(base);
  input.executions[1].summaryBytes = Buffer.from(Buffer.from(input.executions[1].summaryBytes).toString().replace(/^ok 1 -/m, "not ok 1 -"));
  reject(() => composeInspectionReport(input), "FALSE_PASS");
});

test("duplicate and unknown required formats fail even when their matrix hash is recomputed", () => {
  for (const requiredFormats of [["html", "html"], ["arbitrary-remote-format"]]) {
    const input = copy(base); const matrix = JSON.parse(Buffer.from(input.artifacts.supportMatrix));
    matrix.requiredFormats = requiredFormats; input.artifacts.supportMatrix = jsonBytes(matrix);
    input.expectedPins.supportMatrix.sha256 = hash(input.artifacts.supportMatrix);
    reject(() => composeInspectionReport(input), "INVALID_MATRIX");
  }
});

test("malformed UTF-8 and excessive JSON depth refuse without emitting an artifact", () => {
  const input = copy(base); input.artifacts.supportMatrix = Buffer.from([0xc3, 0x28]);
  input.expectedPins.supportMatrix.sha256 = hash(input.artifacts.supportMatrix);
  reject(() => composeInspectionReport(input), "INVALID_JSON");
  const nested = copy(base); let deep = "leaf";
  for (let i = 0; i < 70; i += 1) deep = { value: deep };
  nested.observations[0].result.extra = deep;
  reject(() => composeInspectionReport(nested), "RESOURCE_LIMIT");
});

test("owned byte and JSON limits fail before an oversized report is emitted", () => {
  const input = copy(base); input.artifacts.supportMatrix = new Uint8Array(INSPECTION_REPORT_LIMITS.maxArtifactBytes + 1);
  reject(() => composeInspectionReport(input), "RESOURCE_LIMIT");
  input.artifacts.supportMatrix = base.artifacts.supportMatrix;
  input.observations = Array.from({ length: INSPECTION_REPORT_LIMITS.maxObservations + 1 }, () => base.observations[0]);
  reject(() => composeInspectionReport(input), "RESOURCE_LIMIT");
  input.observations = base.observations; input.executions[0].summaryBytes = new Uint8Array(INSPECTION_REPORT_LIMITS.maxSummaryBytes + 1);
  reject(() => composeInspectionReport(input), "RESOURCE_LIMIT");
});

test("accessors, cycles, nonfinite numbers and sparse results cannot alter canonical bytes", () => {
  const input = copy(base); let invoked = 0;
  Object.defineProperty(input.observations[0].result, "injected", { enumerable: true, configurable: true, get() { invoked += 1; return "grant"; } });
  reject(() => composeInspectionReport(input), "INVALID_INPUT"); assert.equal(invoked, 0);
  delete input.observations[0].result.injected;
  input.observations[0].result.cycle = input.observations[0].result;
  reject(() => composeInspectionReport(input), "INVALID_INPUT");
  delete input.observations[0].result.cycle;
  input.observations[0].result.nan = NaN;
  reject(() => composeInspectionReport(input), "INVALID_INPUT");
  delete input.observations[0].result.nan;
  input.observations[0].result.diagnostics = new Array(1);
  reject(() => composeInspectionReport(input), "INVALID_INPUT");
});

test("raw input arrays cannot replace observation or execution validation", () => {
  const prior = composeInspectionReport(base);
  const outcomes = [];
  let invoked = 0;
  for (const field of ["executions", "observations"]) {
    for (const attack of ["own map", "hidden map", "subclass map", "element accessor", "extra symbol", "sparse", "hidden element"]) {
      const input = copy(base);
      const original = input[field];
      const forged = () => { invoked += 1; return copy(prior.report[field]); };
      if (attack.endsWith("map")) {
        // An accepted report view cannot substitute for validation of damaged
        // original evidence, even when supplied by a method on a real Array.
        if (field === "executions") original[0].summaryBytes = Buffer.from("not an execution summary");
        else original[0].sourceBytes = Uint8Array.of(0);
        if (attack === "subclass map") {
          class ReplacingArray extends Array { map() { return forged(); } }
          input[field] = new ReplacingArray(...original);
        } else Object.defineProperty(original, "map", { value: forged, enumerable: attack === "own map" });
      } else if (attack === "element accessor") {
        const first = original[0];
        Object.defineProperty(original, "0", { enumerable: true, get() { invoked += 1; return first; } });
      } else if (attack === "extra symbol") original[Symbol("unexpected")] = "ignored metadata";
      else if (attack === "sparse") input[field] = new Array(1);
      else Object.defineProperty(original, "0", { value: original[0], enumerable: false });
      try {
        const result = composeInspectionReport(input);
        outcomes.push({ field, attack, accepted: true, sameReportDespiteInputChange: result.sha256 === prior.sha256 });
      } catch (error) {
        outcomes.push({ field, attack, name: error.name, code: error.code });
      }
    }
  }
  assert.deepEqual(outcomes, ["executions", "observations"].flatMap((field) =>
    ["own map", "hidden map", "subclass map", "element accessor", "extra symbol", "sparse", "hidden element"].map((attack) =>
      ({ field, attack, name: "InspectionReportError", code: "INVALID_INPUT" }))));
  assert.equal(invoked, 0, "input methods and accessors must not run before typed refusal");
});

test("proxy traps and byte-view overrides cannot run during input validation", () => {
  const outcomes = [];
  let invoked = 0;
  const traps = Object.fromEntries(["get", "getPrototypeOf", "ownKeys", "getOwnPropertyDescriptor"].map((name) =>
    [name, (...args) => { invoked += 1; return Reflect[name](...args); }]));
  const attempt = (label, input) => {
    const before = invoked;
    try {
      composeInspectionReport(input);
      outcomes.push({ label, accepted: true, invoked: invoked - before });
    } catch (error) {
      outcomes.push({ label, name: error.name, code: error.code, invoked: invoked - before });
    }
  };
  for (const label of ["input proxy", "pins proxy", "array proxy", "result proxy", "byte proxy"]) {
    let input = copy(base);
    if (label === "input proxy") input = new Proxy(input, traps);
    else if (label === "pins proxy") input.expectedPins = new Proxy(input.expectedPins, traps);
    else if (label === "array proxy") input.observations = new Proxy(input.observations, traps);
    else if (label === "result proxy") input.observations[0].result = new Proxy(input.observations[0].result, traps);
    else input.observations[0].sourceBytes = new Proxy(input.observations[0].sourceBytes, traps);
    attempt(label, input);
  }
  for (const field of ["buffer", "byteLength", "byteOffset", "length"]) {
    const input = copy(base);
    const source = input.observations[0].sourceBytes;
    const nativeValue = source[field];
    Object.defineProperty(source, field, { get() { invoked += 1; return nativeValue; } });
    attempt(`byte ${field} accessor`, input);
  }
  const subclassInput = copy(base);
  class SourceBytes extends Uint8Array { get byteLength() { invoked += 1; return super.byteLength; } }
  subclassInput.observations[0].sourceBytes = new SourceBytes(subclassInput.observations[0].sourceBytes);
  attempt("byte subclass", subclassInput);
  assert.deepEqual(outcomes, ["input proxy", "pins proxy", "array proxy", "result proxy", "byte proxy", "byte buffer accessor", "byte byteLength accessor", "byte byteOffset accessor", "byte length accessor", "byte subclass"].map((label) =>
    ({ label, name: "InspectionReportError", code: "INVALID_INPUT", invoked: 0 })));
  assert.equal(invoked, 0);
});

test("malformed optional substructures still return sanitized typed refusal", () => {
  const input = copy(base); delete input.observations[0].result.events[0].source;
  reject(() => composeInspectionReport(input), "INVALID_INPUT");
  const other = copy(base); other.observations[2].result.pages[0] = null;
  reject(() => composeInspectionReport(other), "INVALID_INPUT");
  const nullReport = Buffer.from("null");
  reject(() => validateInspectionReport(nullReport, hash(nullReport), base), "UNSUPPORTED_VERSION");
});

test("actual scanned no-text and encrypted-PDF refusal retain their limitation without invented facts", async () => {
  for (const [fixture, expected] of [["scanned.pdf", "no-text"], ["encrypted.pdf", "rejected"]]) {
    const input = copy(base); const source = await readFile(new URL(`../extraction/pdf/fixtures/${fixture}`, import.meta.url));
    const result = await readTextPdf(source);
    assert.equal(result.kind, expected);
    input.observations[2] = { ...input.observations[2], sourceBytes: source, expectedSourceSha256: hash(source), result };
    const r = composeInspectionReport(input).report;
    const view = r.observations.find((o) => o.component === "text-pdf").view;
    assert.equal(view.requiresInspection, true);
    assert.equal(r.overall, "incomplete");
    if (expected === "no-text") assert.deepEqual(view.pages[0].boxes, []);
    else { assert.equal(view.status, "ENCRYPTED_PDF"); assert.ok(r.reasons.includes("COMPONENT_LIMITATION")); }
  }
});
