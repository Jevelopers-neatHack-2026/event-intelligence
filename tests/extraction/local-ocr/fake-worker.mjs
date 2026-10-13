// Synthetic protocol/lifecycle helper only. This never establishes native OCR or isolation.
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { readFileSync } from "node:fs";
import profile from "../../../src/extraction/local-ocr/profile.json" with { type: "json" };
const closureSha256 = JSON.parse(readFileSync(new URL("../../../tools/local-ocr/runtime/manifest.json", import.meta.url))).closureSha256;

export function observe(header, text = "TOKEN") {
  return { kind: "observed", protocol: profile.protocol, profile: profile.profile,
    tesseractVersion: profile.tesseractVersion, modelSha256: profile.modelSha256, closureSha256,
    syscallPolicy: profile.syscallPolicy, enforcementControlsPassed: 8, rasterSha256: header.rasterSha256,
    width: header.width, height: header.height, format: header.format, maxTextBytes: header.maxTextBytes,
    maxWords: header.maxWords, tokenUtf8Bytes: Buffer.byteLength(text), words: [{ text, confidence: 0,
      block: 1, paragraph: 1, line: 1, word: 1, box: { left: 1, top: 1, width: 30, height: 12 } }] };
}

export function fakeWorkers(t, plan = (child) => child.reply()) {
  const seen = [];
  const kills = [];
  t.mock.method(childProcess, "spawn", (command, args, options) => {
    const child = new EventEmitter();
    child.pid = 2147483647;
    child.stdout = new PassThrough();
    child.command = command; child.args = args; child.options = options;
    child.close = (code = 0, signal = null) => { child.emit("close", code, signal); };
    child.reply = (mutate = (value) => value) => {
      const value = mutate(observe(child.header));
      child.stdout.write(Buffer.isBuffer(value) ? value : JSON.stringify(value));
      child.stdout.end(); child.close();
    };
    child.kill = () => { kills.push("child"); if (child.onKill) child.onKill(); else child.close(null, "SIGKILL"); return true; };
    const chunks = [];
    child.stdin = new Writable({
      write(chunk, _encoding, next) { chunks.push(Buffer.from(chunk)); next(); },
      final(next) {
        const frame = Buffer.concat(chunks); const length = frame.readUInt32BE(0);
        child.header = JSON.parse(frame.subarray(4, length + 4)); child.pixels = frame.subarray(length + 4);
        next(); setImmediate(() => plan(child, seen.indexOf(child)));
      },
    });
    seen.push(child); queueMicrotask(() => child.emit("spawn")); return child;
  });
  t.mock.method(process, "kill", () => {
    kills.push("group"); const child = seen.at(-1);
    if (child.onKill) child.onKill(); else child.close(null, "SIGKILL"); return true;
  });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  return { seen, kills };
}

export const turn = () => new Promise((resolve) => setImmediate(resolve));
