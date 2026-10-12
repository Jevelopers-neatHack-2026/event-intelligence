// Synthetic child frames exercise parent validation. Separate reader/lifecycle
// tests execute the actual fixed decoder; these frames are not decode evidence.
import test from "node:test";
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { createHash } from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import { deflateSync } from "node:zlib";
import { PNG_CONFIG_VERSION, PNG_NODE_VERSION, PNG_PROTOCOL, PNG_ZLIB_VERSION } from "../../../src/extraction/png/constants.mjs";
import { png, referenceCrc } from "./fixtures.mjs";

const originalSpawn = childProcess.spawn;
const source = png();
const normalizedCompressed = deflateSync(Buffer.from([0, 1, 2, 3, 4]), { level: 9 });
const normalizedControl = png({ compressed: normalizedCompressed });
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
let nextSynthetic;
let closes = 0;
let syntheticStarts = 0;
childProcess.spawn = (command, args, options) => {
  if (nextSynthetic) {
    const synthetic = nextSynthetic;
    nextSynthetic = undefined;
    syntheticStarts += 1;
    const at = args.findIndex((arg) => arg.endsWith("/decode-worker.mjs"));
    const code = "process.stdin.resume();process.stdin.on('end',()=>{" +
      "process.stdout.write(Buffer.from('" + synthetic.frame.toString("base64") +
      "','base64'),()=>{process.exitCode=" + (synthetic.exitCode ?? 0) + ";});});";
    args = [...args.slice(0, at), "-e", code];
  }
  const child = originalSpawn(command, args, options);
  child.once("close", () => { closes += 1; });
  return child;
};
syncBuiltinESMExports();
const { readStaticPng } = await import("../../../src/extraction/png/index.mjs");

function framed(changes = {}, bytes = normalizedControl) {
  const header = {
    kind: "decoded", width: 1, height: 1, sourceColorType: 6, decodedRgbaBytes: 4,
    rgbaSha256: digest(Buffer.from([1, 2, 3, 4])), normalizedSha256: digest(bytes),
    protocol: PNG_PROTOCOL, configVersion: PNG_CONFIG_VERSION,
    nodeVersion: PNG_NODE_VERSION, zlibVersion: PNG_ZLIB_VERSION,
    sourceSha256: digest(source), networkApiAttemptCount: 0,
    maxOutputBytes: 20 * 1024 * 1024, normalizedByteLength: bytes.length, ...changes,
  };
  const json = Buffer.from(JSON.stringify(header));
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(json.length);
  return Buffer.concat([prefix, json, bytes]);
}

const badCrc = Buffer.from(normalizedControl);
badCrc[29] ^= 1;
const badMethod = Buffer.from(normalizedCompressed);
badMethod[0] = 0x79;
const dictionaryHeader = Buffer.from(normalizedCompressed);
dictionaryHeader[1] = 0xf9;
const reservedBlock = Buffer.from(normalizedCompressed);
reservedBlock[2] = (reservedBlock[2] & ~6) | 6;
const highBitIhdr = Buffer.from(normalizedControl);
highBitIhdr[12] |= 0x80;
highBitIhdr.writeUInt32BE(referenceCrc(highBitIhdr.subarray(12, 29)), 29);
const highBitIdat = Buffer.from(normalizedControl);
highBitIdat[37] |= 0x80;
highBitIdat.writeUInt32BE(referenceCrc(highBitIdat.subarray(37, highBitIdat.length - 16)), highBitIdat.length - 16);
for (const [name, synthetic, expected, options] of [
  ["valid frame control", { frame: framed() }, "decoded"],
  ["absent frame", { frame: Buffer.alloc(0) }, "PROTOCOL_ERROR"],
  ["header over cap", { frame: Buffer.from("00001001", "hex") }, "PROTOCOL_ERROR"],
  ["invalid JSON", { frame: Buffer.from("000000027b7b", "hex") }, "PROTOCOL_ERROR"],
  ["unknown header field", { frame: framed({ url: "private-synthetic-marker" }) }, "PROTOCOL_ERROR"],
  ["wrong source hash", { frame: framed({ sourceSha256: "0".repeat(64) }) }, "PROTOCOL_ERROR"],
  ["wrong runtime", { frame: framed({ nodeVersion: "unreviewed" }) }, "PROTOCOL_ERROR"],
  ["wrong dimensions", { frame: framed({ width: 2, decodedRgbaBytes: 8 }) }, "PROTOCOL_ERROR"],
  ["wrong derivative hash", { frame: framed({ normalizedSha256: "0".repeat(64) }) }, "PROTOCOL_ERROR"],
  ["bad PNG CRC with matching hash", { frame: framed({}, badCrc) }, "PROTOCOL_ERROR"],
  ["empty IDAT with matching CRC and hash", { frame: framed({}, png({ compressed: Buffer.alloc(0) })) }, "PROTOCOL_ERROR"],
  ["truncated zlib envelope with matching CRC and hash", { frame: framed({}, png({ compressed: Buffer.from("78da0000000000", "hex") })) }, "PROTOCOL_ERROR"],
  ["empty zlib stream with matching CRC and hash", { frame: framed({}, png({ compressed: deflateSync(Buffer.alloc(0), { level: 9 }) })) }, "PROTOCOL_ERROR"],
  ["invalid zlib method with matching CRC and hash", { frame: framed({}, png({ compressed: badMethod })) }, "PROTOCOL_ERROR"],
  ["preset dictionary header with matching CRC and hash", { frame: framed({}, png({ compressed: dictionaryHeader })) }, "PROTOCOL_ERROR"],
  ["unreviewed encoder header with matching CRC and hash", { frame: framed({}, source) }, "PROTOCOL_ERROR"],
  ["reserved first deflate block with matching CRC and hash", { frame: framed({}, png({ compressed: reservedBlock })) }, "PROTOCOL_ERROR"],
  ["high-bit IHDR type with matching CRC and hash", { frame: framed({}, highBitIhdr) }, "PROTOCOL_ERROR"],
  ["high-bit IDAT type with matching CRC and hash", { frame: framed({}, highBitIdat) }, "PROTOCOL_ERROR"],
  ["wrong payload length", { frame: framed({ normalizedByteLength: 1 }) }, "PROTOCOL_ERROR"],
  ["trailing bytes", { frame: Buffer.concat([framed(), Buffer.from([0])]) }, "PROTOCOL_ERROR"],
  ["negative network count", { frame: framed({ networkApiAttemptCount: -1 }) }, "PROTOCOL_ERROR"],
  ["network attempt", { frame: framed({ networkApiAttemptCount: 1 }) }, "REMOTE_RESOURCE_ATTEMPT"],
  ["nonzero exit", { frame: framed(), exitCode: 1 }, "DECODER_FAILURE"],
  ["excessive stdout", { frame: Buffer.alloc(5000) }, "OUTPUT_LIMIT", { maxOutputBytes: 16 }],
]) {
  test("synthetic protocol: " + name + " then actual decoder recovery", async () => {
    const before = closes;
    const starts = syntheticStarts;
    nextSynthetic = synthetic;
    const result = await readStaticPng(source, options);
    assert.equal(closes, before + 1, "The actual synthetic child must close before settlement.");
    assert.equal(syntheticStarts, starts + 1);
    if (expected === "decoded") assert.equal(result.kind, expected, JSON.stringify(result));
    else {
      assert.equal(result.kind, "rejected");
      assert.equal(result.code, expected, JSON.stringify(result));
      assert.equal(Object.hasOwn(result, "copyNormalizedBytes"), false);
      assert.equal(JSON.stringify(result).includes("private-synthetic-marker"), false);
    }
    const recovered = await readStaticPng(source);
    assert.equal(recovered.kind, "decoded", JSON.stringify(recovered));
    assert.equal(closes, before + 2);
    assert.equal(syntheticStarts, starts + 1, "Recovery must execute the actual fixed decoder.");
  });
}

test.after(() => {
  childProcess.spawn = originalSpawn;
  syncBuiltinESMExports();
});
