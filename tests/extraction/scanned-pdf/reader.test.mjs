import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { deflateSync } from "node:zlib";
import { readScannedPdf, SCANNED_PDF_LIMITS } from "../../../src/extraction/scanned-pdf/index.mjs";
import { imagePdf, repeatedRgb, RGB_2X2, RGBA_2X2 } from "./fixtures.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");
async function decoded(input, options) {
  const result = await readScannedPdf(input, options);
  assert.equal(result.kind, "decoded", JSON.stringify(result));
  return result;
}

test("actual PDFium decodes and rasterizes known RGB pixels after native sealing", async () => {
  const input = imagePdf();
  const result = await decoded(input);
  assert.deepEqual(Buffer.from(result.pages[0].copyRgbaBytes()), RGBA_2X2);
  assert.equal(result.pages[0].sha256, hash(RGBA_2X2));
  assert.equal(result.sourceSha256, hash(input));
  assert.equal(result.enforcementControlsPassed, 8);
  assert.equal(result.syscallPolicy, "linux-x86_64-preloaded-default-deny-v1");
});

test("one-pixel native BGR stride becomes one exact opaque RGBA pixel", async () => {
  const result = await decoded(imagePdf([{ width: 1, height: 1, rgb: Buffer.from([17, 83, 211]) }]));
  assert.deepEqual([...result.pages[0].copyRgbaBytes()], [17, 83, 211, 255]);
});

test("escaped PDF image names agree across the admission parser and actual PDFium", async () => {
  const result = await decoded(imagePdf([{ imageName: "#53can" }]));
  assert.deepEqual(Buffer.from(result.pages[0].copyRgbaBytes()), RGBA_2X2);
});

test("odd-width two-row raster preserves each independently chosen pixel and row order", async () => {
  const rgb = Buffer.from([1, 2, 3, 50, 100, 150, 0, 255, 17, 99, 88, 77, 255, 0, 0, 0, 0, 255]);
  const expected = Buffer.from([1, 2, 3, 255, 50, 100, 150, 255, 0, 255, 17, 255, 99, 88, 77, 255, 255, 0, 0, 255, 0, 0, 255, 255]);
  const result = await decoded(imagePdf([{ width: 3, height: 2, rgb }]));
  assert.deepEqual(Buffer.from(result.pages[0].copyRgbaBytes()), expected);
});

test("raster uses embedded image resolution with separate original page point geometry", async () => {
  const result = await decoded(imagePdf([{ points: [612, 792] }]));
  assert.deepEqual(Buffer.from(result.pages[0].copyRgbaBytes()), RGBA_2X2);
  assert.equal(result.pages[0].pageWidthPoints, 612);
  assert.equal(result.pages[0].pageHeightPoints, 792);
  assert.equal(result.pages[0].width, 2);
  assert.equal(result.pages[0].height, 2);
});

test("four supported pages keep sequential source/page/derivative identities", async () => {
  const input = imagePdf([{}, { rgb: Buffer.alloc(12) }, {}, { points: [300.5, 400.25] }]);
  const result = await decoded(input);
  assert.deepEqual(result.pages.map((p) => p.page), [1, 2, 3, 4]);
  assert.ok(result.pages.every((p) => p.sourceSha256 === hash(input)));
  assert.equal(result.totalRgbaBytes, 64);
  assert.notEqual(result.pages[0].sha256, result.pages[1].sha256);
  assert.equal(result.pages[0].sha256, result.pages[2].sha256);
});

test("numeric page geometry and exact raster observations never create OCR or facts", async () => {
  const result = await decoded(imagePdf());
  assert.equal(result.completeness, "incomplete-pixels-only");
  assert.equal(result.requiresInspection, true);
  for (const key of ["text", "facts", "event", "confidence", "permission", "usage", "provider"]) assert.ok(!Object.hasOwn(result, key));
  assert.equal(result.pages[0].colorSpace, "device-rgb");
});

test("returned metadata is frozen and every returned pixel array owns a new copy", async () => {
  const result = await decoded(imagePdf());
  const first = result.pages[0].copyRgbaBytes();
  first.fill(0);
  assert.deepEqual(Buffer.from(result.pages[0].copyRgbaBytes()), RGBA_2X2);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.pages) && Object.isFrozen(result.pages[0]));
  assert.throws(() => { result.pages[0].width = 99; }, TypeError);
});

test("a sliced byte view hashes only its exact snapshotted range", async () => {
  const input = imagePdf();
  const enclosing = Buffer.concat([Buffer.from("prefix"), input, Buffer.from("suffix")]);
  const result = await decoded(new Uint8Array(enclosing.buffer, enclosing.byteOffset + 6, input.length));
  assert.equal(result.sourceSha256, hash(input));
});

test("source mutation after invocation cannot change the copied source or raster", async () => {
  const input = imagePdf();
  const original = hash(input);
  const promise = readScannedPdf(input);
  input.fill(0);
  const result = await promise;
  assert.equal(result.kind, "decoded");
  assert.equal(result.sourceSha256, original);
  assert.deepEqual(Buffer.from(result.pages[0].copyRgbaBytes()), RGBA_2X2);
});

test("intrinsic byte access never calls shadowed byte getters or conversion hooks", async () => {
  const input = imagePdf();
  for (const key of ["byteLength", "buffer", "byteOffset"]) Object.defineProperty(input, key, { get() { assert.fail("caller getter invoked"); } });
  input.valueOf = () => assert.fail("caller conversion invoked");
  assert.equal((await readScannedPdf(input)).kind, "decoded");
});

const refusals = [
  ["fifth page", () => imagePdf([{}, {}, {}, {}, {}]), "PAGE_LIMIT"],
  ["oversized image width", () => imagePdf([{ width: 4097 }]), "DIMENSION_LIMIT"],
  ["zero image height", () => imagePdf([{ height: 0 }]), "DIMENSION_LIMIT"],
  ["fractional image width", () => imagePdf([{ width: 2.5 }]), "DIMENSION_LIMIT"],
  ["oversized page points", () => imagePdf([{ points: [14401, 2] }]), "DIMENSION_LIMIT"],
  ["negative page points", () => imagePdf([{ points: [-2, 2] }]), "DIMENSION_LIMIT"],
  ["per-page pixel ceiling", () => imagePdf([{ width: 4096, height: 4096 }]), "PIXEL_LIMIT"],
  ["16-bit samples", () => imagePdf([{ bits: 16 }]), "UNSUPPORTED_PDF_FEATURE"],
  ["CMYK source", () => imagePdf([{ colorSpace: "DeviceCMYK" }]), "UNSUPPORTED_PDF_FEATURE"],
  ["JPEG source filter outside this subset", () => imagePdf([{ filter: "DCTDecode" }]), "UNSUPPORTED_PDF_FEATURE"],
  ["prediction dictionary", () => imagePdf([{ imageExtra: "/DecodeParms << /Predictor 12 >>" }]), "UNSUPPORTED_PDF_FEATURE"],
  ["image transparency mask", () => imagePdf([{ imageExtra: "/SMask 4 0 R" }]), "UNSUPPORTED_PDF_FEATURE"],
  ["optional page rotation", () => imagePdf([{ pageExtra: "/Rotate 90" }]), "UNSUPPORTED_PDF_FEATURE"],
  ["annotations", () => imagePdf([{ pageExtra: "/Annots []" }]), "UNSUPPORTED_PDF_FEATURE"],
  ["font resources", () => imagePdf([{ resourceExtra: "/Font << >>" }]), "UNSUPPORTED_PDF_FEATURE"],
  ["unsupported content clipping", () => imagePdf([{ content: "q\n0 0 1 1 re W n\n2 0 0 2 0 0 cm\n/Scan Do\nQ\n" }]), "UNSUPPORTED_PDF_FEATURE"],
  ["unknown content operator", () => imagePdf([{ content: "q\n2 0 0 2 0 0 cm\n/Scan Do\nQ\nBT ET\n" }]), "UNSUPPORTED_PDF_FEATURE"],
  ["incomplete paint transform", () => imagePdf([{ content: "q\n1 0 0 2 0 0 cm\n/Scan Do\nQ\n" }]), "UNSUPPORTED_PDF_FEATURE"],
  ["content stream compression", () => imagePdf([{ contentExtra: "/Filter /FlateDecode" }]), "UNSUPPORTED_PDF_FEATURE"],
  ["active catalog open action", () => imagePdf([{}], { catalogExtra: "/OpenAction 1 0 R" }), "ACTIVE_CONTENT"],
  ["escaped JavaScript name", () => imagePdf([{}], { catalogExtra: "/Java#53cript 1 0 R" }), "ACTIVE_CONTENT"],
  ["XFA", () => imagePdf([{}], { catalogExtra: "/XFA 1 0 R" }), "ACTIVE_CONTENT"],
  ["attachment", () => imagePdf([{}], { catalogExtra: "/EmbeddedFiles 1 0 R" }), "ACTIVE_CONTENT"],
  ["external stream file", () => imagePdf([{ imageExtra: "/F (owned-synthetic-path)" }]), "REMOTE_RESOURCE"],
  ["URI action", () => imagePdf([{}], { catalogExtra: "/URI (https://invalid.example/synthetic)" }), "REMOTE_RESOURCE"],
  ["encryption", () => imagePdf([{}], { trailerExtra: "/Encrypt 1 0 R" }), "ENCRYPTED_PDF"],
  ["duplicate dictionary key", () => imagePdf([{ imageExtra: "/Width 2" }]), "MALFORMED_PDF"],
  ["extra unreferenced object", () => imagePdf([{}], { changeObjects(objects) { objects.push(Buffer.from("<< /Type /Catalog >>")); } }), "UNSUPPORTED_PDF_FEATURE"],
  ["damaged Flate checksum", () => imagePdf([{ compressed: Buffer.from("789c0000000000", "hex") }]), "DAMAGED_IMAGE"],
  ["short decoded image", () => imagePdf([{ rgb: RGB_2X2.subarray(0, 9) }]), "DAMAGED_IMAGE"],
  ["long decoded image", () => imagePdf([{ rgb: Buffer.concat([RGB_2X2, Buffer.from([1])]) }]), "DAMAGED_IMAGE"],
  ["truncated compressed stream", () => imagePdf([{ compressed: deflateSync(RGB_2X2).subarray(0, -1) }]), "DAMAGED_IMAGE"],
  ["compressed trailing byte", () => imagePdf([{ compressed: Buffer.concat([deflateSync(RGB_2X2), Buffer.from([0])]) }]), "DAMAGED_IMAGE"],
  ["second compressed stream", () => imagePdf([{ compressed: Buffer.concat([deflateSync(RGB_2X2), deflateSync(Buffer.alloc(0))]) }]), "DAMAGED_IMAGE"],
  ["wrong declared image length", () => imagePdf([{ declaredLength: 1 }]), "MALFORMED_PDF"],
  ["invalid xref offset", () => {
    const source = imagePdf(); const needle = Buffer.from("0000000009 00000 n");
    const at = source.indexOf(needle); assert.ok(at > 0); source[at + 9] = 56; return source;
  }, "MALFORMED_PDF"],
  ["incremental/trailing content", () => imagePdf([{}], { trailing: "1 0 obj\n<< >>\nendobj\n" }), "UNSUPPORTED_PDF_FEATURE"],
  ["object-stream era header outside elected profile", () => imagePdf([{}], { header: "%PDF-2.0\n" }), "UNSUPPORTED_PDF_FEATURE"],
];
for (const [name, create, code] of refusals) {
  test("reject " + name + " and recover on the next actual decode", async () => {
    const result = await readScannedPdf(create());
    assert.equal(result.kind, "rejected", JSON.stringify(result));
    assert.equal(result.code, code, JSON.stringify(result));
    assert.equal((await decoded(imagePdf())).pages[0].sha256, hash(RGBA_2X2));
  });
}

test("aggregate pixels across pages share one ceiling", async () => {
  const page = { width: 2049, height: 1024, rgb: repeatedRgb(2049, 1024) };
  const result = await readScannedPdf(imagePdf([page, page]));
  assert.equal(result.kind, "rejected");
  assert.equal(result.code, "PIXEL_LIMIT");
});

test("exact output budget passes; one byte below refuses the whole derivative", async () => {
  assert.equal((await readScannedPdf(imagePdf(), { maxOutputBytes: 15 })).code, "OUTPUT_LIMIT");
  assert.equal((await decoded(imagePdf(), { maxOutputBytes: 16 })).totalRgbaBytes, 16);
});

test("exact total-pixel ceiling renders through the real decoder", async () => {
  const width = 4096, height = 1024;
  const result = await decoded(imagePdf([{ width, height, rgb: repeatedRgb(width, height) }]));
  assert.equal(result.totalRgbaBytes, SCANNED_PDF_LIMITS.maxOutputBytes);
  const bytes = result.pages[0].copyRgbaBytes();
  assert.equal(bytes.length, width * height * 4);
  assert.deepEqual([...bytes.subarray(-4)], [17, 83, 211, 255]);
});

test("oversized source bytes are refused before runtime acquisition", async () => {
  const result = await readScannedPdf(Buffer.alloc(SCANNED_PDF_LIMITS.maxInputBytes + 1));
  assert.equal(result.code, "INPUT_TOO_LARGE");
  assert.equal(result.sourceSha256, undefined);
});

test("a supported source at the exact input ceiling remains bounded and decodes", async () => {
  let padding = SCANNED_PDF_LIMITS.maxInputBytes - imagePdf().length - 30;
  let input;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    input = imagePdf([{}], { header: "%PDF-1.7\n%" + "a".repeat(padding) + "\n" });
    if (input.length === SCANNED_PDF_LIMITS.maxInputBytes) break;
    padding += SCANNED_PDF_LIMITS.maxInputBytes - input.length;
  }
  assert.equal(input.length, SCANNED_PDF_LIMITS.maxInputBytes);
  const result = await decoded(input);
  assert.deepEqual(Buffer.from(result.pages[0].copyRgbaBytes()), RGBA_2X2);
});

test("empty, path, proxy, shared and subclass inputs cannot become byte requests", async () => {
  class Custom extends Uint8Array {}
  for (const input of [Buffer.alloc(0), "file.pdf", new URL("https://invalid.example/"), new Proxy(imagePdf(), {}),
    new Uint8Array(new SharedArrayBuffer(2)), new Custom(4)]) {
    assert.equal((await readScannedPdf(input)).code, "INVALID_INPUT");
  }
});

test("invalid options and caller getters are refused without invocation", async () => {
  const options = { get signal() { assert.fail("signal getter invoked"); } };
  assert.equal((await readScannedPdf(imagePdf(), options)).code, "INVALID_OPTIONS");
  for (const invalid of [null, new Proxy({}, {}), { url: "https://invalid.example" }, { signal: {} }, { [Symbol("extra")]: 1 }]) {
    assert.equal((await readScannedPdf(imagePdf(), invalid)).code, "INVALID_OPTIONS");
  }
});

test("caller limits may only tighten the fixed ceilings", async () => {
  for (const options of [{ timeoutMs: 0 }, { timeoutMs: null }, { timeoutMs: 30001 }, { timeoutMs: NaN },
    { maxOutputBytes: 0 }, { maxOutputBytes: null }, { maxOutputBytes: 16777217 }]) {
    assert.equal((await readScannedPdf(imagePdf(), options)).code, "INVALID_LIMIT");
  }
});
