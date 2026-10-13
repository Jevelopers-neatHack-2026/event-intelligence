import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { getEventListeners } from "node:events";
import { deflateSync } from "node:zlib";
import { readPngOutcome, createJpegWebpOutcomeReader, readScannedPdfOutcome, readTextPdfOutcome } from "../../../src/extraction/inspection-outcomes/index.mjs";
import { wrapReaderResult } from "../../../src/extraction/inspection-outcomes/internal.mjs";
import { readStaticPng, STATIC_PNG_READER_LIMITS } from "../../../src/extraction/png/index.mjs";
import { createStaticJpegWebpReader, STATIC_JPEG_WEBP_READER_LIMITS } from "../../../src/extraction/jpeg-webp/index.mjs";
import { readScannedPdf, SCANNED_PDF_LIMITS } from "../../../src/extraction/scanned-pdf/index.mjs";
import { readTextPdf, PDF_TEXT_READER_LIMITS } from "../../../src/extraction/pdf/index.mjs";
import { png, chunk } from "../png/fixtures.mjs";
import { fixture, runtimeDirectory, jpegSegment, webpChunk, webpContainer } from "../jpeg-webp/fixtures.mjs";
import { imagePdf, RGBA_2X2 } from "../scanned-pdf/fixtures.mjs";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const pdf = (name) => readFileSync(new URL("../pdf/fixtures/" + name, import.meta.url));
const raster = createJpegWebpOutcomeReader({ runtimeDirectory: runtimeDirectory() });
const nativeRaster = createStaticJpegWebpReader({ runtimeDirectory: runtimeDirectory() });
const jpeg = fixture("jpeg-rgb-baseline").bytes;
const webp = fixture("webp-rgba-lossless").bytes;
const sof = jpeg.indexOf(Buffer.from([255, 0xc0]));
assert.ok(sof > 0);
const change = (bytes, edit) => { const copy = Buffer.from(bytes); edit(copy); return copy; };
const insertJpeg = (part) => Buffer.concat([jpeg.subarray(0, 2), part, jpeg.subarray(2)]);
const routes = {
  png: { read: readPngOutcome, native: readStaticPng, input: () => png(), kind: "decoded" },
  "jpeg-webp": { read: raster.read, native: nativeRaster.read, input: () => Buffer.from(jpeg), kind: "decoded" },
  "scanned-pdf": { read: readScannedPdfOutcome, native: readScannedPdf, input: () => imagePdf(), kind: "decoded" },
  "text-pdf": { read: readTextPdfOutcome, native: readTextPdf, input: () => pdf("text-multipage.pdf"), kind: "observation" },
};
function observed(out, kind = "decoded") {
  assert.equal(out.kind, "reader-result", JSON.stringify(out));
  assert.equal(out.category, "OBSERVATION", JSON.stringify(out));
  assert.equal(out.reason, null);
  assert.equal(out.result.kind, kind);
  assert.equal(out.result.requiresInspection, true);
  assert.ok(out.result.completeness.startsWith("incomplete-"));
  assert.ok(Object.isFrozen(out) && Object.isFrozen(out.result));
  for (const key of ["accepted", "facts", "authority", "permission", "consumerAck"]) assert.equal(Object.hasOwn(out, key), false);
  return out.result;
}
function refused(out, code, resource = false) {
  assert.equal(out.kind, "reader-result", JSON.stringify(out));
  assert.equal(out.category, resource ? "RESOURCE_LIMIT" : code, JSON.stringify(out));
  assert.equal(out.reason, code);
  assert.equal(out.result.kind, "rejected");
  assert.equal(out.result.code, code);
  assert.equal(Object.hasOwn(out.result, "pages"), false);
  assert.equal(Object.hasOwn(out.result, "copyRgbaBytes"), false);
  assert.equal(Object.hasOwn(out.result, "copyNormalizedBytes"), false);
  return out.result;
}
async function refusalRecovery(reader, bytes, code, options, resource = true) {
  const route = routes[reader];
  const out = await route.read(bytes, options);
  refused(out, code, resource);
  observed(await route.read(route.input()), route.kind);
  return out;
}
// Literal synthetic outline hierarchy reaches the actual text-reader structural
// policy. This is PDF input, not a fabricated decoder result or mapper callback.
function outlinePdf(depth) {
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R /Outlines 4 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>",
    "<< /Type /Outlines /First 5 0 R /Last 5 0 R /Count " + depth + " >>",
  ];
  for (let i = 0; i < depth; i++) objects.push("<< /Title (Synthetic " + i + ") /Parent " +
    (i === 0 ? 4 : i + 4) + " 0 R /Dest [3 0 R /Fit] " +
    (i + 1 < depth ? "/First " + (i + 6) + " 0 R /Last " + (i + 6) + " 0 R /Count " + (depth - i - 1) : "") + " >>");
  let output = "%PDF-1.7\n";
  const offsets = [0];
  for (const [i, object] of objects.entries()) { offsets.push(Buffer.byteLength(output)); output += (i + 1) + " 0 obj\n" + object + "\nendobj\n"; }
  const xref = Buffer.byteLength(output);
  output += "xref\n0 " + (objects.length + 1) + "\n0000000000 65535 f \n" +
    offsets.slice(1).map((offset) => String(offset).padStart(10, "0") + " 00000 n \n").join("") +
    "trailer\n<< /Size " + (objects.length + 1) + " /Root 1 0 R >>\nstartxref\n" + xref + "\n%%EOF\n";
  return Buffer.from(output);
}

test("png actual positive keeps source and incomplete observation", { timeout: 30000 }, async () => {
  const route = routes["png"], input = route.input();
  const result = observed(await route.read(input), route.kind);
  assert.equal(result.sourceSha256 ?? result.documentSha256, hash(input));
  if (result.copyRgbaBytes) {
    const first = result.copyRgbaBytes(); assert.equal(hash(first), result.rgbaSha256);
    first.fill(0); assert.equal(hash(result.copyRgbaBytes()), result.rgbaSha256);
    assert.equal(hash(result.copyNormalizedBytes()), result.normalizedSha256);
  }
  if ("png" === "scanned-pdf") {
    assert.deepEqual(Buffer.from(result.pages[0].copyRgbaBytes()), RGBA_2X2);
    assert.equal(result.pages[0].sourceSha256, hash(input));
    assert.equal(result.enforcementControlsPassed, 8);
  }
});

test("png exact actual native result identity is retained by private wrapping", { timeout: 30000 }, async () => {
  const route = routes["png"];
  const actual = await route.native(route.input());
  assert.equal(actual.kind, route.kind);
  const outcome = wrapReaderResult("png", actual);
  assert.strictEqual(outcome.result, actual);
  observed(outcome, route.kind);
});

test("jpeg-webp actual positive keeps source and incomplete observation", { timeout: 30000 }, async () => {
  const route = routes["jpeg-webp"], input = route.input();
  const result = observed(await route.read(input), route.kind);
  assert.equal(result.sourceSha256 ?? result.documentSha256, hash(input));
  if (result.copyRgbaBytes) {
    const first = result.copyRgbaBytes(); assert.equal(hash(first), result.rgbaSha256);
    first.fill(0); assert.equal(hash(result.copyRgbaBytes()), result.rgbaSha256);
    assert.equal(hash(result.copyNormalizedBytes()), result.normalizedSha256);
  }
  if ("jpeg-webp" === "scanned-pdf") {
    assert.deepEqual(Buffer.from(result.pages[0].copyRgbaBytes()), RGBA_2X2);
    assert.equal(result.pages[0].sourceSha256, hash(input));
    assert.equal(result.enforcementControlsPassed, 8);
  }
});

test("jpeg-webp exact actual native result identity is retained by private wrapping", { timeout: 30000 }, async () => {
  const route = routes["jpeg-webp"];
  const actual = await route.native(route.input());
  assert.equal(actual.kind, route.kind);
  const outcome = wrapReaderResult("jpeg-webp", actual);
  assert.strictEqual(outcome.result, actual);
  observed(outcome, route.kind);
});

test("scanned-pdf actual positive keeps source and incomplete observation", { timeout: 30000 }, async () => {
  const route = routes["scanned-pdf"], input = route.input();
  const result = observed(await route.read(input), route.kind);
  assert.equal(result.sourceSha256 ?? result.documentSha256, hash(input));
  if (result.copyRgbaBytes) {
    const first = result.copyRgbaBytes(); assert.equal(hash(first), result.rgbaSha256);
    first.fill(0); assert.equal(hash(result.copyRgbaBytes()), result.rgbaSha256);
    assert.equal(hash(result.copyNormalizedBytes()), result.normalizedSha256);
  }
  if ("scanned-pdf" === "scanned-pdf") {
    assert.deepEqual(Buffer.from(result.pages[0].copyRgbaBytes()), RGBA_2X2);
    assert.equal(result.pages[0].sourceSha256, hash(input));
    assert.equal(result.enforcementControlsPassed, 8);
  }
});

test("scanned-pdf exact actual native result identity is retained by private wrapping", { timeout: 30000 }, async () => {
  const route = routes["scanned-pdf"];
  const actual = await route.native(route.input());
  assert.equal(actual.kind, route.kind);
  const outcome = wrapReaderResult("scanned-pdf", actual);
  assert.strictEqual(outcome.result, actual);
  observed(outcome, route.kind);
});

test("text-pdf actual positive keeps source and incomplete observation", { timeout: 30000 }, async () => {
  const route = routes["text-pdf"], input = route.input();
  const result = observed(await route.read(input), route.kind);
  assert.equal(result.sourceSha256 ?? result.documentSha256, hash(input));
  if (result.copyRgbaBytes) {
    const first = result.copyRgbaBytes(); assert.equal(hash(first), result.rgbaSha256);
    first.fill(0); assert.equal(hash(result.copyRgbaBytes()), result.rgbaSha256);
    assert.equal(hash(result.copyNormalizedBytes()), result.normalizedSha256);
  }
  if ("text-pdf" === "scanned-pdf") {
    assert.deepEqual(Buffer.from(result.pages[0].copyRgbaBytes()), RGBA_2X2);
    assert.equal(result.pages[0].sourceSha256, hash(input));
    assert.equal(result.enforcementControlsPassed, 8);
  }
});

test("text-pdf exact actual native result identity is retained by private wrapping", { timeout: 30000 }, async () => {
  const route = routes["text-pdf"];
  const actual = await route.native(route.input());
  assert.equal(actual.kind, route.kind);
  const outcome = wrapReaderResult("text-pdf", actual);
  assert.strictEqual(outcome.result, actual);
  observed(outcome, route.kind);
});

test("WebP actual lossless decode retains alpha and derivative identity", { timeout: 30000 }, async () => {
  const result = observed(await raster.read(webp));
  assert.equal(result.sourceFormat, "webp"); assert.equal(result.sourceSha256, hash(webp));
  assert.equal(hash(result.copyRgbaBytes()), result.rgbaSha256);
  assert.equal(result.copyRgbaBytes().some((value, i) => i % 4 === 3 && value !== 255), true);
});

test("text PDF no-text remains incomplete and is not a resource refusal", { timeout: 30000 }, async () => {
  const out = await readTextPdfOutcome(pdf("scanned.pdf"));
  const result = observed(out, "no-text"); assert.equal(result.code, "NO_EMBEDDED_TEXT");
  assert.equal(result.pages[0].textPresence, "no-embedded-text");
});

test("PNG input ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("png", Buffer.alloc(STATIC_PNG_READER_LIMITS.maxInputBytes + 1), "INPUT_TOO_LARGE", undefined);
});

test("PNG dimension ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("png", png({ width: 4097 }), "DIMENSION_LIMIT", undefined);
});

test("PNG chunk work ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("png", png({ dataParts: [...Array.from({ length: 1022 }, () => Buffer.alloc(0)), deflateSync(Buffer.from([0,1,2,3,4]))] }), "RESOURCE_LIMIT", undefined);
});

test("PNG inflation ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("png", png({ scanlines: Buffer.alloc(1024 * 1024) }), "RESOURCE_LIMIT", undefined);
});

test("PNG output ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("png", png(), "OUTPUT_LIMIT", { maxOutputBytes: 1 });
});

test("JPEG input ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("jpeg-webp", Buffer.alloc(STATIC_JPEG_WEBP_READER_LIMITS.maxInputBytes + 1), "INPUT_TOO_LARGE", undefined);
});

test("JPEG dimension ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("jpeg-webp", change(jpeg, (b) => b.writeUInt16BE(4097, sof + 7)), "DIMENSION_LIMIT", undefined);
});

test("JPEG segment work ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("jpeg-webp", insertJpeg(Buffer.concat(Array.from({ length: 1025 }, () => jpegSegment(0xdd, Buffer.from([0,0]))))), "RESOURCE_LIMIT", undefined);
});

test("JPEG output ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("jpeg-webp", jpeg, "OUTPUT_LIMIT", { maxOutputBytes: 1 });
});

test("WebP dimension ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("jpeg-webp", change(webp, (b) => b.writeUInt32LE(((b.readUInt32LE(21) & 0xffffc000) | 4096) >>> 0, 21)), "DIMENSION_LIMIT", undefined);
});

test("WebP chunk work ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("jpeg-webp", webpContainer(Array.from({ length: 1025 }, () => webpChunk("JUNK", Buffer.alloc(0)))), "RESOURCE_LIMIT", undefined);
});

test("scanned PDF input ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("scanned-pdf", Buffer.alloc(SCANNED_PDF_LIMITS.maxInputBytes + 1), "INPUT_TOO_LARGE", undefined);
});

test("scanned PDF page ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("scanned-pdf", imagePdf([{}, {}, {}, {}, {}]), "PAGE_LIMIT", undefined);
});

test("scanned PDF image dimension ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("scanned-pdf", imagePdf([{ width: 4097 }]), "DIMENSION_LIMIT", undefined);
});

test("scanned PDF pixel ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("scanned-pdf", imagePdf([{ width: 4096, height: 4096 }]), "PIXEL_LIMIT", undefined);
});

test("scanned PDF structural dictionary ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("scanned-pdf", imagePdf([{}], { catalogExtra: Array.from({ length: 33 }, (_, i) => "/Synthetic" + i + " 1").join(" ") }), "STRUCTURE_LIMIT", undefined);
});

test("scanned PDF output ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("scanned-pdf", imagePdf(), "OUTPUT_LIMIT", { maxOutputBytes: 15 });
});

test("scanned PDF zero geometry retains validity-or-ceiling reason rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("scanned-pdf", imagePdf([{ height: 0 }]), "DIMENSION_LIMIT", undefined);
});

test("scanned PDF fractional geometry retains validity-or-ceiling reason rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("scanned-pdf", imagePdf([{ width: 2.5 }]), "DIMENSION_LIMIT", undefined);
});

test("text PDF input ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("text-pdf", Buffer.alloc(PDF_TEXT_READER_LIMITS.maxInputBytes + 1), "INPUT_TOO_LARGE", undefined);
});

test("text PDF dimension ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("text-pdf", pdf("giant-dimensions.pdf"), "DIMENSION_LIMIT", undefined);
});

test("text PDF page ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("text-pdf", pdf("over-pages.pdf"), "PAGE_LIMIT", undefined);
});

test("text PDF extracted-text ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("text-pdf", pdf("text-overflow.pdf"), "TEXT_LIMIT", { maxTextCodeUnits: 1000 });
});

test("text PDF output ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("text-pdf", pdf("text-overflow.pdf"), "OUTPUT_LIMIT", { maxOutputBytes: 4096 });
});

test("text PDF actual outline-depth ceiling rejects whole result and recovers", { timeout: 30000 }, async () => {
  await refusalRecovery("text-pdf", outlinePdf(129), "RESOURCE_LIMIT", undefined);
});

test("PNG malformed bytes remains distinct with recovery", { timeout: 30000 }, async () => {
  const out = await refusalRecovery("png", Buffer.from("synthetic-secret-token"), "MALFORMED_PNG", undefined, false);
  assert.equal(JSON.stringify(out).includes("synthetic-secret"), false);
});

test("PNG unsupported metadata remains distinct with recovery", { timeout: 30000 }, async () => {
  const out = await refusalRecovery("png", png({ before: [chunk("tEXt")] }), "UNSUPPORTED_PNG_FEATURE", undefined, false);
  assert.equal(JSON.stringify(out).includes("synthetic-secret"), false);
});

test("JPEG malformed framing remains distinct with recovery", { timeout: 30000 }, async () => {
  const out = await refusalRecovery("jpeg-webp", jpeg.subarray(0, jpeg.length - 1), "MALFORMED_IMAGE", undefined, false);
  assert.equal(JSON.stringify(out).includes("synthetic-secret"), false);
});

test("JPEG unsupported color remains distinct with recovery", { timeout: 30000 }, async () => {
  const out = await refusalRecovery("jpeg-webp", fixture("jpeg-cmyk").bytes, "UNSUPPORTED_FEATURE", undefined, false);
  assert.equal(JSON.stringify(out).includes("synthetic-secret"), false);
});

test("scanned PDF malformed dictionary remains distinct with recovery", { timeout: 30000 }, async () => {
  const out = await refusalRecovery("scanned-pdf", imagePdf([{ imageExtra: "/Width 2" }]), "MALFORMED_PDF", undefined, false);
  assert.equal(JSON.stringify(out).includes("synthetic-secret"), false);
});

test("scanned PDF unsupported profile remains distinct with recovery", { timeout: 30000 }, async () => {
  const out = await refusalRecovery("scanned-pdf", imagePdf([{ bits: 16 }]), "UNSUPPORTED_PDF_FEATURE", undefined, false);
  assert.equal(JSON.stringify(out).includes("synthetic-secret"), false);
});

test("scanned PDF external resource refusal remains distinct with recovery", { timeout: 30000 }, async () => {
  const out = await refusalRecovery("scanned-pdf", imagePdf([{ imageExtra: "/F (synthetic-secret-path)" }]), "REMOTE_RESOURCE", undefined, false);
  assert.equal(JSON.stringify(out).includes("synthetic-secret"), false);
});

test("text PDF malformed framing remains distinct with recovery", { timeout: 30000 }, async () => {
  const out = await refusalRecovery("text-pdf", pdf("malformed.pdf"), "MALFORMED_PDF", undefined, false);
  assert.equal(JSON.stringify(out).includes("synthetic-secret"), false);
});

test("text PDF active feature refusal remains distinct with recovery", { timeout: 30000 }, async () => {
  const out = await refusalRecovery("text-pdf", pdf("javascript-open-action.pdf"), "ACTIVE_PDF_FEATURE", undefined, false);
  assert.equal(JSON.stringify(out).includes("synthetic-secret"), false);
});

test("text PDF remote reference refusal remains distinct with recovery", { timeout: 30000 }, async () => {
  const out = await refusalRecovery("text-pdf", pdf("uri-link.pdf"), "REMOTE_REFERENCE", undefined, false);
  assert.equal(JSON.stringify(out).includes("synthetic-secret"), false);
});

test("png pre-aborted native signal preserves cancellation", { timeout: 30000 }, async () => {
  const route = routes["png"], controller = new AbortController();
  controller.abort(new Error("synthetic-sensitive-reason"));
  const out = await route.read(route.input(), { signal: controller.signal });
  refused(out, "CANCELLED"); assert.equal(JSON.stringify(out).includes("synthetic-sensitive"), false);
  observed(await route.read(route.input()), route.kind);
});

test("png active cancellation waits for actual child close and recovers", { timeout: 30000 }, async () => {
  const route = routes["png"], controller = new AbortController();
  const original = childProcess.spawn; const children = []; const closed = new Set();
  childProcess.spawn = function (...args) {
    const child = original.apply(this, args); children.push(child);
    child.once("close", () => closed.add(child));
    child.once("spawn", () => controller.abort("synthetic-private-abort"));
    return child;
  };
  syncBuiltinESMExports();
  let out;
  try { out = await route.read(route.input(), { signal: controller.signal }); }
  finally { childProcess.spawn = original; syncBuiltinESMExports(); }
  refused(out, "CANCELLED"); assert.equal(children.length, 1, "must enter a genuine native worker");
  assert.equal(closed.size, 1, "reader settles after actual close");
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  observed(await route.read(route.input()), route.kind);
});

test("png existing deadline refusal remains TIMEOUT and recovers", { timeout: 30000 }, async () => {
  const route = routes["png"];
  const options = { deadlineAtMs: 0 };
  refused(await route.read(route.input(), options), "TIMEOUT");
  observed(await route.read(route.input()), route.kind);
});

test("png hostile input cannot invoke proxy getters or conversion hooks", { timeout: 30000 }, async () => {
  const route = routes["png"]; let calls = 0;
  const hostile = new Proxy(route.input(), { get() { calls++; throw new Error("synthetic-sensitive"); }, getPrototypeOf() { calls++; throw new Error("synthetic-sensitive"); } });
  const result = await route.read(hostile);
  assert.equal(result.kind, "boundary-failure"); assert.equal(result.reason, "INVALID_INPUT"); assert.equal(calls, 0);
  assert.equal(JSON.stringify(result).includes("synthetic-sensitive"), false);
  const input = route.input();
  for (const key of ["buffer", "byteOffset", "byteLength"]) Object.defineProperty(input, key, { get() { calls++; throw new Error("not invoked"); } });
  input.valueOf = () => { calls++; throw new Error("not invoked"); };
  observed(await route.read(input), route.kind); assert.equal(calls, 0);
});

test("png hostile options and arbitrary callbacks fail closed without invocation", { timeout: 30000 }, async () => {
  const route = routes["png"]; let calls = 0;
  for (const options of [
    Object.defineProperty({}, "timeoutMs", { get() { calls++; throw new Error("synthetic-secret"); } }),
    new Proxy({}, { ownKeys() { calls++; throw new Error("synthetic-secret"); } }),
    { decoder() { calls++; } }, { onPageComplete() { calls++; } }, { timeoutMs: { valueOf() { calls++; } } },
  ]) {
    const result = await route.read(route.input(), options);
    assert.equal(result.kind, "boundary-failure"); assert.equal(result.reason, "INVALID_OPTIONS");
    assert.equal(JSON.stringify(result).includes("synthetic-secret"), false);
  }
  assert.equal(calls, 0); observed(await route.read(route.input()), route.kind);
});

test("png native signal overrides cannot become caller callbacks", { timeout: 30000 }, async () => {
  const route = routes["png"], controller = new AbortController(); let calls = 0;
  Object.defineProperties(controller.signal, {
    aborted: { get() { calls++; throw new Error("signal getter"); } },
    addEventListener: { value() { calls++; throw new Error("signal method"); } },
    removeEventListener: { value() { calls++; throw new Error("signal method"); } },
  });
  observed(await route.read(route.input(), { signal: controller.signal }), route.kind);
  assert.equal(calls, 0); assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("jpeg-webp pre-aborted native signal preserves cancellation", { timeout: 30000 }, async () => {
  const route = routes["jpeg-webp"], controller = new AbortController();
  controller.abort(new Error("synthetic-sensitive-reason"));
  const out = await route.read(route.input(), { signal: controller.signal });
  refused(out, "CANCELLED"); assert.equal(JSON.stringify(out).includes("synthetic-sensitive"), false);
  observed(await route.read(route.input()), route.kind);
});

test("jpeg-webp active cancellation waits for actual child close and recovers", { timeout: 30000 }, async () => {
  const route = routes["jpeg-webp"], controller = new AbortController();
  const original = childProcess.spawn; const children = []; const closed = new Set();
  childProcess.spawn = function (...args) {
    const child = original.apply(this, args); children.push(child);
    child.once("close", () => closed.add(child));
    child.once("spawn", () => controller.abort("synthetic-private-abort"));
    return child;
  };
  syncBuiltinESMExports();
  let out;
  try { out = await route.read(route.input(), { signal: controller.signal }); }
  finally { childProcess.spawn = original; syncBuiltinESMExports(); }
  refused(out, "CANCELLED"); assert.equal(children.length, 1, "must enter a genuine native worker");
  assert.equal(closed.size, 1, "reader settles after actual close");
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  observed(await route.read(route.input()), route.kind);
});

test("jpeg-webp existing deadline refusal remains TIMEOUT and recovers", { timeout: 30000 }, async () => {
  const route = routes["jpeg-webp"];
  const options = { deadlineAtMs: 0 };
  refused(await route.read(route.input(), options), "TIMEOUT");
  observed(await route.read(route.input()), route.kind);
});

test("jpeg-webp hostile input cannot invoke proxy getters or conversion hooks", { timeout: 30000 }, async () => {
  const route = routes["jpeg-webp"]; let calls = 0;
  const hostile = new Proxy(route.input(), { get() { calls++; throw new Error("synthetic-sensitive"); }, getPrototypeOf() { calls++; throw new Error("synthetic-sensitive"); } });
  const result = await route.read(hostile);
  assert.equal(result.kind, "boundary-failure"); assert.equal(result.reason, "INVALID_INPUT"); assert.equal(calls, 0);
  assert.equal(JSON.stringify(result).includes("synthetic-sensitive"), false);
  const input = route.input();
  for (const key of ["buffer", "byteOffset", "byteLength"]) Object.defineProperty(input, key, { get() { calls++; throw new Error("not invoked"); } });
  input.valueOf = () => { calls++; throw new Error("not invoked"); };
  observed(await route.read(input), route.kind); assert.equal(calls, 0);
});

test("jpeg-webp hostile options and arbitrary callbacks fail closed without invocation", { timeout: 30000 }, async () => {
  const route = routes["jpeg-webp"]; let calls = 0;
  for (const options of [
    Object.defineProperty({}, "timeoutMs", { get() { calls++; throw new Error("synthetic-secret"); } }),
    new Proxy({}, { ownKeys() { calls++; throw new Error("synthetic-secret"); } }),
    { decoder() { calls++; } }, { onPageComplete() { calls++; } }, { timeoutMs: { valueOf() { calls++; } } },
  ]) {
    const result = await route.read(route.input(), options);
    assert.equal(result.kind, "boundary-failure"); assert.equal(result.reason, "INVALID_OPTIONS");
    assert.equal(JSON.stringify(result).includes("synthetic-secret"), false);
  }
  assert.equal(calls, 0); observed(await route.read(route.input()), route.kind);
});

test("jpeg-webp native signal overrides cannot become caller callbacks", { timeout: 30000 }, async () => {
  const route = routes["jpeg-webp"], controller = new AbortController(); let calls = 0;
  Object.defineProperties(controller.signal, {
    aborted: { get() { calls++; throw new Error("signal getter"); } },
    addEventListener: { value() { calls++; throw new Error("signal method"); } },
    removeEventListener: { value() { calls++; throw new Error("signal method"); } },
  });
  observed(await route.read(route.input(), { signal: controller.signal }), route.kind);
  assert.equal(calls, 0); assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("scanned-pdf pre-aborted native signal preserves cancellation", { timeout: 30000 }, async () => {
  const route = routes["scanned-pdf"], controller = new AbortController();
  controller.abort(new Error("synthetic-sensitive-reason"));
  const out = await route.read(route.input(), { signal: controller.signal });
  refused(out, "CANCELLED"); assert.equal(JSON.stringify(out).includes("synthetic-sensitive"), false);
  observed(await route.read(route.input()), route.kind);
});

test("scanned-pdf active cancellation waits for actual child close and recovers", { timeout: 30000 }, async () => {
  const route = routes["scanned-pdf"], controller = new AbortController();
  const original = childProcess.spawn; const children = []; const closed = new Set();
  childProcess.spawn = function (...args) {
    const child = original.apply(this, args); children.push(child);
    child.once("close", () => closed.add(child));
    child.once("spawn", () => controller.abort("synthetic-private-abort"));
    return child;
  };
  syncBuiltinESMExports();
  let out;
  try { out = await route.read(route.input(), { signal: controller.signal }); }
  finally { childProcess.spawn = original; syncBuiltinESMExports(); }
  refused(out, "CANCELLED"); assert.equal(children.length, 1, "must enter a genuine native worker");
  assert.equal(closed.size, 1, "reader settles after actual close");
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  observed(await route.read(route.input()), route.kind);
});

test("scanned-pdf existing deadline refusal remains TIMEOUT and recovers", { timeout: 30000 }, async () => {
  const route = routes["scanned-pdf"];
  const options = { deadlineAtMs: 0 };
  refused(await route.read(route.input(), options), "TIMEOUT");
  observed(await route.read(route.input()), route.kind);
});

test("scanned-pdf hostile input cannot invoke proxy getters or conversion hooks", { timeout: 30000 }, async () => {
  const route = routes["scanned-pdf"]; let calls = 0;
  const hostile = new Proxy(route.input(), { get() { calls++; throw new Error("synthetic-sensitive"); }, getPrototypeOf() { calls++; throw new Error("synthetic-sensitive"); } });
  const result = await route.read(hostile);
  assert.equal(result.kind, "boundary-failure"); assert.equal(result.reason, "INVALID_INPUT"); assert.equal(calls, 0);
  assert.equal(JSON.stringify(result).includes("synthetic-sensitive"), false);
  const input = route.input();
  for (const key of ["buffer", "byteOffset", "byteLength"]) Object.defineProperty(input, key, { get() { calls++; throw new Error("not invoked"); } });
  input.valueOf = () => { calls++; throw new Error("not invoked"); };
  observed(await route.read(input), route.kind); assert.equal(calls, 0);
});

test("scanned-pdf hostile options and arbitrary callbacks fail closed without invocation", { timeout: 30000 }, async () => {
  const route = routes["scanned-pdf"]; let calls = 0;
  for (const options of [
    Object.defineProperty({}, "timeoutMs", { get() { calls++; throw new Error("synthetic-secret"); } }),
    new Proxy({}, { ownKeys() { calls++; throw new Error("synthetic-secret"); } }),
    { decoder() { calls++; } }, { onPageComplete() { calls++; } }, { timeoutMs: { valueOf() { calls++; } } },
  ]) {
    const result = await route.read(route.input(), options);
    assert.equal(result.kind, "boundary-failure"); assert.equal(result.reason, "INVALID_OPTIONS");
    assert.equal(JSON.stringify(result).includes("synthetic-secret"), false);
  }
  assert.equal(calls, 0); observed(await route.read(route.input()), route.kind);
});

test("scanned-pdf native signal overrides cannot become caller callbacks", { timeout: 30000 }, async () => {
  const route = routes["scanned-pdf"], controller = new AbortController(); let calls = 0;
  Object.defineProperties(controller.signal, {
    aborted: { get() { calls++; throw new Error("signal getter"); } },
    addEventListener: { value() { calls++; throw new Error("signal method"); } },
    removeEventListener: { value() { calls++; throw new Error("signal method"); } },
  });
  observed(await route.read(route.input(), { signal: controller.signal }), route.kind);
  assert.equal(calls, 0); assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("text-pdf pre-aborted native signal preserves cancellation", { timeout: 30000 }, async () => {
  const route = routes["text-pdf"], controller = new AbortController();
  controller.abort(new Error("synthetic-sensitive-reason"));
  const out = await route.read(route.input(), { signal: controller.signal });
  refused(out, "CANCELLED"); assert.equal(JSON.stringify(out).includes("synthetic-sensitive"), false);
  observed(await route.read(route.input()), route.kind);
});

test("text-pdf active cancellation waits for actual child close and recovers", { timeout: 30000 }, async () => {
  const route = routes["text-pdf"], controller = new AbortController();
  const original = childProcess.spawn; const children = []; const closed = new Set();
  childProcess.spawn = function (...args) {
    const child = original.apply(this, args); children.push(child);
    child.once("close", () => closed.add(child));
    child.once("spawn", () => controller.abort("synthetic-private-abort"));
    return child;
  };
  syncBuiltinESMExports();
  let out;
  try { out = await route.read(route.input(), { signal: controller.signal }); }
  finally { childProcess.spawn = original; syncBuiltinESMExports(); }
  refused(out, "CANCELLED"); assert.equal(children.length, 1, "must enter a genuine native worker");
  assert.equal(closed.size, 1, "reader settles after actual close");
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  observed(await route.read(route.input()), route.kind);
});

test("text-pdf existing deadline refusal remains TIMEOUT and recovers", { timeout: 30000 }, async () => {
  const route = routes["text-pdf"];
  const options = { timeoutMs: 1 };
  refused(await route.read(route.input(), options), "TIMEOUT");
  observed(await route.read(route.input()), route.kind);
});

test("text-pdf hostile input cannot invoke proxy getters or conversion hooks", { timeout: 30000 }, async () => {
  const route = routes["text-pdf"]; let calls = 0;
  const hostile = new Proxy(route.input(), { get() { calls++; throw new Error("synthetic-sensitive"); }, getPrototypeOf() { calls++; throw new Error("synthetic-sensitive"); } });
  const result = await route.read(hostile);
  assert.equal(result.kind, "boundary-failure"); assert.equal(result.reason, "INVALID_INPUT"); assert.equal(calls, 0);
  assert.equal(JSON.stringify(result).includes("synthetic-sensitive"), false);
  const input = route.input();
  for (const key of ["buffer", "byteOffset", "byteLength"]) Object.defineProperty(input, key, { get() { calls++; throw new Error("not invoked"); } });
  input.valueOf = () => { calls++; throw new Error("not invoked"); };
  observed(await route.read(input), route.kind); assert.equal(calls, 0);
});

test("text-pdf hostile options and arbitrary callbacks fail closed without invocation", { timeout: 30000 }, async () => {
  const route = routes["text-pdf"]; let calls = 0;
  for (const options of [
    Object.defineProperty({}, "timeoutMs", { get() { calls++; throw new Error("synthetic-secret"); } }),
    new Proxy({}, { ownKeys() { calls++; throw new Error("synthetic-secret"); } }),
    { decoder() { calls++; } }, { onPageComplete() { calls++; } }, { timeoutMs: { valueOf() { calls++; } } },
  ]) {
    const result = await route.read(route.input(), options);
    assert.equal(result.kind, "boundary-failure"); assert.equal(result.reason, "INVALID_OPTIONS");
    assert.equal(JSON.stringify(result).includes("synthetic-secret"), false);
  }
  assert.equal(calls, 0); observed(await route.read(route.input()), route.kind);
});

test("text-pdf native signal overrides cannot become caller callbacks", { timeout: 30000 }, async () => {
  const route = routes["text-pdf"], controller = new AbortController(); let calls = 0;
  Object.defineProperties(controller.signal, {
    aborted: { get() { calls++; throw new Error("signal getter"); } },
    addEventListener: { value() { calls++; throw new Error("signal method"); } },
    removeEventListener: { value() { calls++; throw new Error("signal method"); } },
  });
  observed(await route.read(route.input(), { signal: controller.signal }), route.kind);
  assert.equal(calls, 0); assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("text PDF new subset rejects absolute-deadline and progress-callback options", { timeout: 30000 }, async () => {
  for (const options of [{ deadlineAtMs: 0 }, { onPageComplete() { assert.fail("callback"); } }]) {
    const out = await readTextPdfOutcome(pdf("text-multipage.pdf"), options);
    assert.equal(out.kind, "boundary-failure"); assert.equal(out.reason, "INVALID_OPTIONS");
  }
});

test("invalid trusted raster configuration returns fixed failure without getters", { timeout: 30000 }, async () => {
  let calls = 0;
  const configuration = Object.defineProperty({}, "runtimeDirectory", { get() { calls++; throw new Error("synthetic-path-secret"); } });
  const out = await createJpegWebpOutcomeReader(configuration).read(jpeg);
  assert.equal(out.kind, "boundary-failure"); assert.equal(out.reason, "INVALID_CONFIGURATION");
  assert.equal(calls, 0); assert.equal(JSON.stringify(out).includes("synthetic-path-secret"), false);
});

test("unavailable actual raster runtime remains unavailable and valid runtime recovers", { timeout: 30000 }, async () => {
  const out = await createJpegWebpOutcomeReader({ runtimeDirectory: "/ei-synthetic-absent-runtime" }).read(jpeg);
  refused(out, "DECODER_UNAVAILABLE"); observed(await raster.read(jpeg));
});

test("a queued PNG cancellation never starts its own native child", { timeout: 30000 }, async () => {
  const original = childProcess.spawn; const active = new AbortController(), queued = new AbortController();
  const children = []; let entered, timer;
  const entry = new Promise((resolve, reject) => {
    entered = resolve; timer = setTimeout(() => reject(new Error("actual native entry not observed")), 5000);
  });
  childProcess.spawn = function (...args) {
    const child = original.apply(this, args); children.push(child);
    child.once("spawn", () => { process.kill(child.pid, "SIGSTOP"); entered(); });
    return child;
  };
  syncBuiltinESMExports();
  let first, second;
  try {
    first = readPngOutcome(png(), { signal: active.signal });
    await entry; clearTimeout(timer);
    second = readPngOutcome(png(), { signal: queued.signal });
    queued.abort(); refused(await second, "CANCELLED");
    assert.equal(children.length, 1);
    active.abort(); refused(await first, "CANCELLED");
  } finally {
    clearTimeout(timer); active.abort(); queued.abort();
    for (const child of children) { try { child.kill("SIGKILL"); } catch {} }
    childProcess.spawn = original; syncBuiltinESMExports();
    if (first) await first; if (second) await second;
  }
  observed(await readPngOutcome(png()));
});
