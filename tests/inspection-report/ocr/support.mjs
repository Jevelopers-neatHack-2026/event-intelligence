import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { actualMediaFixture, projectedObservation, sourceSnapshot, ROOT, hash, jsonBytes, recoverScannedChildStderr } from "../media/support.mjs";
import { composeInspectionMediaReport } from "../../../src/extraction/inspection-report/media.mjs";
import { canonical } from "../../../src/extraction/inspection-report/media-data.mjs";
import { createStaticImageOcrReader } from "../../../src/extraction/static-image-ocr/index.mjs";
import { readScannedPdfOcr } from "../../../src/extraction/scanned-pdf-ocr/index.mjs";
import { encodedPng, image, expectedText } from "../../extraction/static-image-ocr/fixtures.mjs";
import { textPdf, blankPdf } from "../../extraction/scanned-pdf-ocr/fixtures.mjs";
export { hash, jsonBytes, expectedText };
export const copy = (x) => structuredClone(x);
export const resultBytes = (r) => Buffer.from(canonical(r.kind === "rejected" ? Object.fromEntries(Object.entries(r).filter(([, v]) => v !== undefined)) : r));
export function capture(name, value) {
  const directory = process.env.EI_INSPECTION_OCR_REPORT_CAPTURE;
  if (!directory) return;
  assert.ok(path.isAbsolute(directory));
  assert.ok(path.relative(ROOT, directory).startsWith(".." + path.sep));
  mkdirSync(directory, { recursive: true }); writeFileSync(path.join(directory, name), value, { flag: "wx" });
}
export function refreshMedia(input) {
  const artifact = composeInspectionMediaReport(input.prerequisite.input);
  input.prerequisite.reportBytes = artifact.copyBytes(); input.prerequisite.expectedSha256 = artifact.sha256;
}
export function refreshCallerRecords(input) {
  const base = composeInspectionMediaReport(input.prerequisite.input).report;
  for (const e of input.executions) {
    const records = input.observations.filter((o) => o.executionId === e.id).map((o) => ({ id: o.id, mediaObservationId: o.mediaObservationId,
      resultSha256: o.expectedResultSha256, providedSourceSha256: base.observations.find((m) => m.id === o.mediaObservationId)?.source?.sha256 ?? null }));
    e.callerRecordBytes = jsonBytes({ schemaVersion: "ei-local-ocr-caller-observations/1", executionId: e.id, component: e.component, source: base.source.observed, records });
    e.expectedCallerRecordSha256 = hash(e.callerRecordBytes);
  }
}
export function alterResult(input, id, change) {
  const o = input.observations.find((o) => o.id === id); change(o.result);
  o.expectedResultSha256 = hash(resultBytes(o.result)); refreshCallerRecords(input);
}
export function alterSummary(input, component, change, alterTap = (x) => x) {
  const e = input.executions.find((e) => e.component === component);
  const text = Buffer.from(e.stdoutBytes).toString(), start = text.lastIndexOf("\n{") + 1;
  assert.ok(start > 0); const n = JSON.parse(text.slice(start)); const tap = alterTap(text.slice(0, start));
  change(n); n.stdoutSha256 = hash(tap); e.stdoutBytes = Buffer.from(tap + JSON.stringify(n) + "\n");
}
function run(component, pins) {
  const args = ["tools/verify-" + component + ".mjs"], env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const c = spawnSync(process.execPath, args, { cwd: ROOT, env, encoding: "buffer", maxBuffer: 2 * 1024 * 1024, timeout: 180000 });
  capture(component + ".stdout", c.stdout ?? Buffer.alloc(0)); capture(component + ".stderr", c.stderr ?? Buffer.alloc(0));
  capture(component + ".command.json", jsonBytes({ executable: process.execPath, args, cwd: ROOT, exitCode: c.status, signal: c.signal, error: c.error?.code ?? null,
    mode: "actual existing native composition route over synthetic local bytes; no provider calls" }));
  assert.equal(c.error, undefined); assert.equal(c.status, 0, c.stdout?.toString() + c.stderr?.toString()); assert.equal(c.signal, null);
  const n = JSON.parse(c.stdout.toString().trim().split("\n").at(-1));
  const recovered = recoverScannedChildStderr(c.stderr, n.stderrSha256);
  capture(component + ".child-stderr-recovery.json", jsonBytes(recovered.evidence));
  assert.notEqual(recovered.bytes, null, "required native child stderr binding must be available");
  capture(component + ".child-stderr", recovered.bytes);
  return { id: component, component, pins, mode: "mock", origin: "local-synthetic", stdoutBytes: c.stdout, stderrBytes: c.stderr,
    childStderrBytes: recovered.bytes, exitCode: c.status, signal: c.signal, callerRecordBytes: null, expectedCallerRecordSha256: null };
}
export async function actualOcrFixture() {
  const f = await actualMediaFixture();
  const mediaInput = f.input, pins = mediaInput.prerequisite.input.expectedPins, before = sourceSnapshot();
  const reader = createStaticImageOcrReader({ runtimeDirectory: process.env.EI_STATIC_IMAGE_OCR_RASTER_RUNTIME });
  const observations = [];
  async function add(id, component, source) {
    const pdf = component === "scanned-pdf-ocr";
    const native = pdf ? await f.readScannedPdf(source) : source.subarray(0, 8).toString("hex") === "89504e470d0a1a0a" ? await f.readStaticPng(source) : await f.raster.read(source);
    assert.equal(native.kind, "decoded", JSON.stringify(native));
    const format = pdf ? "scanned-pdf" : native.sourceFormat ?? "png", mediaId = "ocr-media-" + id;
    mediaInput.observations.push(projectedObservation(pdf ? "scanned-pdf" : format === "png" ? "static-png" : "static-jpeg-webp", format, mediaId, native, source, pins));
    const result = pdf ? await readScannedPdfOcr(source) : await reader.read(source);
    const o = { id, component, mediaObservationId: mediaId, executionId: component, result, expectedResultSha256: hash(resultBytes(result)) };
    observations.push(o); capture(id + ".native-result.json", resultBytes(result)); return o;
  }
  await add("text-png", "static-image-ocr", encodedPng().bytes);
  await add("text-jpeg", "static-image-ocr", image("english-baseline.jpeg").bytes);
  await add("text-webp", "static-image-ocr", image("english-lossless.webp").bytes);
  await add("blank-png", "static-image-ocr", encodedPng({ blank: true }).bytes);
  const transparent = await add("transparent-png", "static-image-ocr", encodedPng({ transparent: true }).bytes);
  assert.equal(transparent.result.code, "NON_OPAQUE_IMAGE");
  await add("text-pdf", "scanned-pdf-ocr", textPdf(2));
  await add("blank-pdf", "scanned-pdf-ocr", blankPdf());
  // Real earliest refusal and subsequent recovery are kept as separate attempts.
  const controller = new AbortController(); controller.abort();
  const canceled = await reader.read(encodedPng().bytes, { signal: controller.signal });
  assert.equal(canceled.code, "CANCELLED"); assert.equal(canceled.sourceSha256, undefined);
  observations.push({ id: "cancelled-png", component: "static-image-ocr", mediaObservationId: "ocr-media-text-png", executionId: "static-image-ocr", result: canceled, expectedResultSha256: hash(resultBytes(canceled)) });
  const recovered = await reader.read(encodedPng({ blank: true }).bytes); assert.equal(recovered.kind, "observed");
  capture("cancellation-and-recovery.json", jsonBytes({ cancelled: canceled, recovered, mode: "actual local reader calls; no provider requests" }));
  const executions = [run("static-image-ocr", pins), run("scanned-pdf-ocr", pins)];
  assert.deepEqual(sourceSnapshot(), before, "all actual callers and component routes preserve source bytes/modes");
  const runtime = readFileSync(path.join(ROOT, "tools/local-ocr/runtime/manifest.json"));
  const artifact = composeInspectionMediaReport(mediaInput);
  const input = { prerequisite: { input: mediaInput, reportBytes: artifact.copyBytes(), expectedSha256: artifact.sha256 },
    runtimeReceipt: { bytes: runtime, expectedSha256: hash(runtime) }, requiredFormats: ["png", "jpeg", "webp", "scanned-pdf"], executions, observations };
  refreshCallerRecords(input);
  for (const e of input.executions) capture(e.component + ".caller-record.json", e.callerRecordBytes);
  capture("fixture-origin.json", jsonBytes({ source: before, authority: "actual native calls over synthetic local byte fixtures; selected schema/matrix pins remain unaccepted; caller records are not signed issuer evidence",
    observations: observations.map(({ id, mediaObservationId, expectedResultSha256 }) => ({ id, mediaObservationId, expectedResultSha256 })), runtimeSha256: hash(runtime) }));
  return input;
}
