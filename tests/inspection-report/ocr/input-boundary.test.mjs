import test from "node:test";
import assert from "node:assert/strict";
import { composeInspectionOcrReport as compose, validateInspectionOcrReport as validate, INSPECTION_OCR_REPORT_LIMITS as limits } from "../../../src/extraction/inspection-report/ocr.mjs";
import { evaluateInspectionCompletion } from "../../../tools/verify-inspection-report.mjs";

const rejects = (fn) => assert.throws(fn, (e) => e.name === "InspectionReportError");
for (const [name, value] of [["null", null], ["array", []], ["string", "input"], ["number", 3], ["function", () => {}], ["date", new Date()], ["missing fields", {}]]) {
  test("rejects " + name + " at root", () => rejects(() => compose(value)));
}
test("root proxy traps never run", () => {
  let hits = 0; const x = new Proxy({}, { ownKeys() { hits++; return []; }, getPrototypeOf() { hits++; return Object.prototype; }, get() { hits++; } });
  rejects(() => compose(x)); assert.equal(hits, 0);
});
test("root accessors and custom descriptors never execute", () => {
  let hits = 0; const x = { get prerequisite() { hits++; return {}; } };
  rejects(() => compose(x)); assert.equal(hits, 0);
});
test("report-byte proxy cannot execute traps", () => {
  let hits = 0; const x = new Proxy(new Uint8Array(1), { get() { hits++; } });
  rejects(() => validate(x, "f".repeat(64), {})); assert.equal(hits, 0);
});
test("oversized typed view with shadow byteLength cannot bypass native-slot limit", () => {
  let hits = 0; const x = new Uint8Array(limits.maxReportBytes + 1); Object.defineProperty(x, "byteLength", { get() { hits++; return 1; } });
  rejects(() => validate(x, "f".repeat(64), {})); assert.equal(hits, 0);
});
test("typed-array subclasses and shared memory are refused without conversion hooks", () => {
  let hits = 0; class Custom extends Uint8Array { valueOf() { hits++; return []; } }
  rejects(() => validate(new Custom(1), "f".repeat(64), {}));
  rejects(() => validate(new Uint8Array(new SharedArrayBuffer(1)), "f".repeat(64), {})); assert.equal(hits, 0);
});
test("detached input is a typed refusal", () => {
  const x = new Uint8Array(1); structuredClone(x, { transfer: [x.buffer] }); rejects(() => validate(x, "f".repeat(64), {}));
});
for (const key of ["failed", "skipped", "todo", "cancelled"]) test("dedicated completion rejects required " + key + " terminal evidence", () => {
  const counts = { passed: 2, failed: 0, skipped: 0, todo: 0, cancelled: 0 }; counts[key] = 1;
  assert.equal(evaluateInspectionCompletion([{ success: true, counts }], 3, 3).complete, false);
});
test("dedicated completion rejects duplicate aggregate, missing and extra cases", () => {
  const r = { success: true, counts: { passed: 3, failed: 0, skipped: 0, todo: 0, cancelled: 0 } };
  assert.equal(evaluateInspectionCompletion([r, r], 3, 3).complete, false);
  assert.equal(evaluateInspectionCompletion([r], 2, 3).complete, false);
  assert.equal(evaluateInspectionCompletion([r], 4, 3).complete, false);
  assert.equal(evaluateInspectionCompletion([r], 3, 3).complete, true);
});
