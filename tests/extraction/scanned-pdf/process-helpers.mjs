import childProcess from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { mock } from "node:test";
import profile from "../../../src/extraction/scanned-pdf/profile.json" with { type: "json" };
import { RGBA_2X2 } from "./fixtures.mjs";

export function interceptSpawns(handler) {
  const real = childProcess.spawn;
  const replacement = mock.method(childProcess, "spawn", (...args) => handler(real, ...args));
  syncBuiltinESMExports();
  return () => { replacement.mock.restore(); syncBuiltinESMExports(); };
}

export function framed(header, payload = Buffer.alloc(0)) {
  const encoded = Buffer.from(JSON.stringify(header));
  const size = Buffer.alloc(4);
  size.writeUInt32BE(encoded.length);
  return Buffer.concat([size, encoded, payload]);
}

export function validHeader(input) {
  const manifest = JSON.parse(readFileSync(new URL("../../../tools/scanned-pdf/runtime/manifest.json", import.meta.url)));
  const sha = (data) => createHash("sha256").update(data).digest("hex");
  return {
    kind: "decoded", protocol: profile.protocol, profile: profile.profile,
    pythonVersion: profile.pythonVersion, pdfiumVersion: profile.pdfiumVersion,
    sourceSha256: sha(input), closureSha256: manifest.closureSha256,
    syscallPolicy: profile.syscallPolicy, enforcementControlsPassed: 8,
    maxOutputBytes: profile.maxOutputBytes,
    pages: [{ page: 1, width: 2, height: 2, pageWidthPoints: 2, pageHeightPoints: 2,
      byteLength: 16, sha256: sha(RGBA_2X2) }],
  };
}

/** An actual process delivering synthetic protocol bytes, never a decoder result. */
export function protocolChild(real, frame, options, { exitCode = 0, delayMs = 0 } = {}) {
  const program = "process.stdin.resume();setTimeout(()=>{process.stdout.write(Buffer.from(" +
    JSON.stringify(frame.toString("base64")) + ",'base64'),()=>process.exit(" + exitCode + "));}," + delayMs + ")";
  return real(process.execPath, ["-e", program], options);
}

/** A trusted stall fixture; the parent must kill and reap it within the original allowance. */
export function heldChild(real, options) {
  return real(process.execPath, ["-e", "process.stdin.resume();setTimeout(()=>process.exit(2),10000)"], options);
}
