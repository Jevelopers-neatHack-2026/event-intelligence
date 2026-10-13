import assert from "node:assert/strict";
import test from "node:test";
import { createStaticJpegWebpReader } from "../../../src/extraction/jpeg-webp/index.mjs";
import { inspectStaticRasterProfile } from "../../../src/extraction/jpeg-webp/profile.mjs";
import { fixture, jpegSegment, runtimeDirectory } from "./fixtures.mjs";

const reader = createStaticJpegWebpReader({ runtimeDirectory: runtimeDirectory() });
const baseline = fixture("jpeg-rgb-baseline").bytes;
const firstSos = baseline.indexOf(Buffer.from([255, 0xda]));
const entropy = firstSos + 2 + baseline.readUInt16BE(firstSos + 2);
const progressive = fixture("jpeg-rgb-progressive").bytes;
const lastSos = progressive.lastIndexOf(Buffer.from([255, 0xda]));
const lastEntropy = lastSos + 2 + progressive.readUInt16BE(lastSos + 2);
const restart = Buffer.from(fixture("jpeg-restart-stuffed").bytes);
const firstRestart = restart.indexOf(Buffer.from([255, 0xd0]));
assert.ok(firstRestart > 0); restart[firstRestart + 1] = 0xd7;
const cases = [
  ["half a baseline entropy segment", Buffer.concat([baseline.subarray(0, entropy + Math.floor((baseline.length - 2 - entropy) / 2)), Buffer.from([255, 0xd9])])],
  ["one entropy byte for a complete baseline image", Buffer.concat([baseline.subarray(0, entropy + 1), Buffer.from([255, 0xd9])])],
  ["truncated final progressive scan", Buffer.concat([progressive.subarray(0, lastEntropy + Math.floor((progressive.length - 2 - lastEntropy) / 2)), Buffer.from([255, 0xd9])])],
  ["wrong restart sequence requiring native repair", restart],
  ["fatal native quantization-table length", Buffer.concat([baseline.subarray(0, 2), jpegSegment(0xdb, Buffer.from([0])), baseline.subarray(2)])],
];
for (const [name, bytes] of cases) {
  test("same-wheel strict JPEG validation rejects " + name + " and recovers", async () => {
    assert.equal(inspectStaticRasterProfile(bytes).kind, "profile", "must exercise the native completeness check");
    const result = await reader.read(bytes);
    assert.equal(result.kind, "rejected", JSON.stringify(result));
    assert.equal(result.code, "DECODER_FAILURE");
    assert.equal(result.rgbaSha256, undefined); assert.equal(result.copyNormalizedBytes, undefined);
    const recovery = await reader.read(baseline);
    assert.equal(recovery.kind, "decoded");
    assert.equal(recovery.rgbaSha256, fixture("jpeg-rgb-baseline").expected.expectedRgbaSha256);
  });
}
