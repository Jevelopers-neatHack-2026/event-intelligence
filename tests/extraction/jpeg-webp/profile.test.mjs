import assert from "node:assert/strict";
import test from "node:test";
import { inspectStaticRasterProfile } from "../../../src/extraction/jpeg-webp/profile.mjs";
import { createStaticJpegWebpReader } from "../../../src/extraction/jpeg-webp/index.mjs";
import { fixture, jpegSegment, runtimeDirectory, webpChunk, webpChunks, webpContainer } from "./fixtures.mjs";

const jpeg = fixture("jpeg-rgb-baseline").bytes;
const lossy = fixture("webp-rgb-lossy").bytes;
const lossless = fixture("webp-rgba-lossless").bytes;
const alphaChunks = webpChunks(fixture("webp-rgba-lossy").bytes);
assert.deepEqual(alphaChunks.map((x) => x.type), ["VP8X", "ALPH", "VP8 "]);
const reader = createStaticJpegWebpReader({ runtimeDirectory: runtimeDirectory() });
const cloneEdit = (source, edit) => { const copy = Buffer.from(source); edit(copy); return copy; };
const insertJpeg = (segment) => Buffer.concat([jpeg.subarray(0, 2), segment, jpeg.subarray(2)]);
const sof = jpeg.indexOf(Buffer.from([255, 0xc0]));
const sos = jpeg.indexOf(Buffer.from([255, 0xda]));
assert.ok(sof > 0 && sos > sof);
const alteredChunks = (edit) => {
  const chunks = alphaChunks.map((x) => ({ type: x.type, data: Buffer.from(x.data) }));
  edit(chunks); return webpContainer(chunks.map((x) => webpChunk(x.type, x.data)));
};
const cases = [
  ["unsupported encrypted-PDF marker remains outside the image profile", Buffer.from("%PDF-1.7\n1 0 obj <</Encrypt 2 0 R>> endobj"), "UNSUPPORTED_FORMAT"],
  ["a URL string encoded as bytes is not fetched", Buffer.from("https://example.invalid/image.jpg"), "UNSUPPORTED_FORMAT"],
  ["JPEG truncated EOI", jpeg.subarray(0, jpeg.length - 1), "MALFORMED_IMAGE"],
  ["JPEG truncated segment length", Buffer.from([255, 0xd8, 255, 0xdb, 0]), "MALFORMED_IMAGE"],
  ["JPEG segment length below two", insertJpeg(Buffer.from([255, 0xdb, 0, 1])), "MALFORMED_IMAGE"],
  ["JPEG trailing script polyglot", Buffer.concat([jpeg, Buffer.from("<script>synthetic()</script>")]), "MALFORMED_IMAGE"],
  ["concatenated JPEG files", Buffer.concat([jpeg, jpeg]), "MALFORMED_IMAGE"],
  ["nested JPEG SOI", insertJpeg(Buffer.from([255, 0xd8])), "MALFORMED_IMAGE"],
  ["JPEG EOI before any scan", Buffer.from([255, 0xd8, 255, 0xd9]), "MALFORMED_IMAGE"],
  ["JPEG byte stuffing outside entropy", insertJpeg(Buffer.from([255, 0])), "MALFORMED_IMAGE"],
  ["JPEG restart outside entropy", insertJpeg(Buffer.from([255, 0xd3])), "MALFORMED_IMAGE"],
  ["JPEG deferred-height DNL", insertJpeg(jpegSegment(0xdc, Buffer.from([0, 3]))), "UNSUPPORTED_FEATURE"],
  ["JPEG non-8-bit sample precision", cloneEdit(jpeg, (b) => { b[sof + 4] = 12; }), "UNSUPPORTED_FEATURE"],
  ["JPEG unsupported SOF family", cloneEdit(jpeg, (b) => { b[sof + 1] = 0xc1; }), "UNSUPPORTED_FEATURE"],
  ["JPEG CMYK/Adobe color semantics", fixture("jpeg-cmyk").bytes, "UNSUPPORTED_FEATURE"],
  ["JPEG EXIF orientation", fixture("jpeg-exif-orientation").bytes, "UNSUPPORTED_FEATURE"],
  ["JPEG ICC profile", insertJpeg(jpegSegment(0xe2, Buffer.from("ICC_PROFILE\0synthetic"))), "UNSUPPORTED_FEATURE"],
  ["JPEG MPF/MPO secondary image", insertJpeg(jpegSegment(0xe2, Buffer.from("MPF\0synthetic"))), "UNSUPPORTED_FEATURE"],
  ["JPEG XMP metadata", insertJpeg(jpegSegment(0xe1, Buffer.from("http://ns.adobe.com/xap/1.0/\0synthetic"))), "UNSUPPORTED_FEATURE"],
  ["JPEG comment", insertJpeg(jpegSegment(0xfe, Buffer.from("untrusted comment"))), "UNSUPPORTED_FEATURE"],
  ["JPEG JFIF physical density", cloneEdit(jpeg, (b) => { b[13] = 1; }), "UNSUPPORTED_FEATURE"],
  ["JPEG duplicated JFIF header", insertJpeg(jpeg.subarray(2, 20)), "UNSUPPORTED_FEATURE"],
  ["JPEG zero/deferred height", cloneEdit(jpeg, (b) => b.writeUInt16BE(0, sof + 5)), "MALFORMED_IMAGE"],
  ["JPEG dimension limit", cloneEdit(jpeg, (b) => b.writeUInt16BE(4097, sof + 7)), "DIMENSION_LIMIT"],
  ["JPEG product-of-dimensions limit", cloneEdit(jpeg, (b) => { b.writeUInt16BE(3000, sof + 7); b.writeUInt16BE(2000, sof + 5); }), "DIMENSION_LIMIT"],
  ["JPEG invalid SOS components", cloneEdit(jpeg, (b) => { b[sos + 4] = 0; }), "MALFORMED_IMAGE"],
  ["JPEG segment-count cap", insertJpeg(Buffer.concat(Array.from({ length: 1025 }, () => jpegSegment(0xdd, Buffer.from([0, 0]))))), "RESOURCE_LIMIT"],
  ["WebP RIFF size mismatch", cloneEdit(lossy, (b) => b.writeUInt32LE(b.readUInt32LE(4) - 1, 4)), "MALFORMED_IMAGE"],
  ["WebP non-ASCII RIFF signature", cloneEdit(lossy, (b) => { b[0] |= 0x80; }), "UNSUPPORTED_FORMAT"],
  ["WebP non-ASCII image FourCC", cloneEdit(lossy, (b) => { b[12] |= 0x80; }), "UNSUPPORTED_FEATURE"],
  ["WebP truncated container", lossy.subarray(0, lossy.length - 1), "MALFORMED_IMAGE"],
  ["WebP trailing script polyglot", Buffer.concat([lossy, Buffer.from("<script/>")]), "MALFORMED_IMAGE"],
  ["WebP duplicate image chunks", webpContainer([...webpChunks(lossless), ...webpChunks(lossless)].map((x) => webpChunk(x.type, x.data))), "UNSUPPORTED_FEATURE"],
  ["WebP unknown hidden chunk", webpContainer([webpChunk("JUNK", Buffer.from("ignored?")), ...webpChunks(lossy).map((x) => webpChunk(x.type, x.data))]), "UNSUPPORTED_FEATURE"],
  ["WebP nonzero odd-chunk padding", webpContainer([webpChunk("JUNK", Buffer.from([1]), 1)]), "MALFORMED_IMAGE"],
  ["WebP ICC profile", fixture("webp-icc").bytes, "UNSUPPORTED_FEATURE"],
  ["WebP EXIF profile", fixture("webp-exif").bytes, "UNSUPPORTED_FEATURE"],
  ["WebP XMP profile", fixture("webp-xmp").bytes, "UNSUPPORTED_FEATURE"],
  ["WebP actual two-frame animation", fixture("webp-animation").bytes, "UNSUPPORTED_FEATURE"],
  ["WebP animation flag without animation chunks", alteredChunks((c) => { c[0].data[0] |= 2; }), "UNSUPPORTED_FEATURE"],
  ["WebP metadata flag without corresponding chunks", alteredChunks((c) => { c[0].data[0] |= 8; }), "UNSUPPORTED_FEATURE"],
  ["WebP reserved feature flag", alteredChunks((c) => { c[0].data[0] |= 0x80; }), "UNSUPPORTED_FEATURE"],
  ["WebP reserved extended-header byte", alteredChunks((c) => { c[0].data[2] = 1; }), "UNSUPPORTED_FEATURE"],
  ["WebP canvas mismatch", alteredChunks((c) => { c[0].data.writeUIntLE(15, 4, 3); }), "MALFORMED_IMAGE"],
  ["WebP canvas dimension cap", alteredChunks((c) => { c[0].data.writeUIntLE(4096, 4, 3); }), "DIMENSION_LIMIT"],
  ["WebP ALPH after VP8", alteredChunks((c) => { [c[1], c[2]] = [c[2], c[1]]; }), "UNSUPPORTED_FEATURE"],
  ["WebP ALPH with VP8L", alteredChunks((c) => { c[2] = webpChunks(lossless)[0]; }), "UNSUPPORTED_FEATURE"],
  ["WebP ALPH reserved bits", alteredChunks((c) => { c[1].data[0] |= 0x80; }), "UNSUPPORTED_FEATURE"],
  ["WebP ALPH missing payload", alteredChunks((c) => { c[1].data = Buffer.from([0]); }), "MALFORMED_IMAGE"],
  ["WebP VP8 interframe", cloneEdit(lossy, (b) => { b[20] |= 1; }), "UNSUPPORTED_FEATURE"],
  ["WebP VP8 scaling bits", cloneEdit(lossy, (b) => { b[27] |= 0x40; }), "UNSUPPORTED_FEATURE"],
  ["WebP lossless unsupported version", cloneEdit(lossless, (b) => { b[24] |= 0x20; }), "UNSUPPORTED_FEATURE"],
  ["WebP lossless dimension cap", cloneEdit(lossless, (b) => { const bits = b.readUInt32LE(21); b.writeUInt32LE(((bits & 0xffffc000) | 4096) >>> 0, 21); }), "DIMENSION_LIMIT"],
  ["WebP chunk-count cap", webpContainer(Array.from({ length: 1025 }, () => webpChunk("JUNK", Buffer.alloc(0)))), "RESOURCE_LIMIT"],
];

for (const [name, bytes, code] of cases) {
  test("container-policy refusal: " + name, async () => {
    const inspected = inspectStaticRasterProfile(bytes);
    assert.equal(inspected.kind, "rejected", JSON.stringify(inspected)); assert.equal(inspected.code, code);
    const result = await reader.read(bytes);
    assert.equal(result.kind, "rejected"); assert.equal(result.code, code);
    assert.equal(result.copyNormalizedBytes, undefined); assert.equal(result.rgbaSha256, undefined);
  });
}

test("native loading rejects a structurally framed JPEG with no entropy", async () => {
  const start = sos + 2 + jpeg.readUInt16BE(sos + 2);
  const bytes = Buffer.concat([jpeg.subarray(0, start), Buffer.from([255, 0xd9])]);
  assert.equal(inspectStaticRasterProfile(bytes).kind, "profile", "control must reach the codec after container validation");
  const result = await reader.read(bytes);
  assert.equal(result.kind, "rejected", JSON.stringify(result));
  assert.equal(result.code, "DECODER_FAILURE");
  assert.equal(result.copyNormalizedBytes, undefined);
});

test("native loading rejects a valid WebP dimension header without compressed pixels", async () => {
  const source = webpChunks(lossless)[0];
  const bytes = webpContainer([webpChunk("VP8L", source.data.subarray(0, 5))]);
  assert.equal(inspectStaticRasterProfile(bytes).kind, "profile", "control must reach the codec");
  const result = await reader.read(bytes);
  assert.equal(result.kind, "rejected"); assert.equal(result.code, "MALFORMED_IMAGE");
});

test("no entropy or pixel result is inferred from the container-only helper", () => {
  const result = inspectStaticRasterProfile(fixture("jpeg-rgb-progressive").bytes);
  assert.equal(result.kind, "profile"); assert.equal(result.profile.encoding, "progressive");
  assert.ok(Object.isFrozen(result.profile));
  assert.equal(result.rgbaSha256, undefined); assert.equal(result.copyNormalizedBytes, undefined);
});
