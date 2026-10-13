import { createHash } from "node:crypto";
import { installPngNetworkGuard } from "./network-guard.mjs";
import {
  PNG_CONFIG_VERSION, PNG_ERROR_CODES, PNG_LIMITS, PNG_NODE_VERSION, PNG_PROTOCOL, PNG_ZLIB_VERSION,
} from "./constants.mjs";

const guard = installPngNetworkGuard();
const { decodeStaticPngForWorker } = await import("./core.mjs");
const maxOutputBytes = Number(process.argv[2]);
const parts = [];
let size = 0;

async function emit(result, sourceSha256) {
  const { normalized, ...metadata } = result;
  const payload = normalized ?? Buffer.alloc(0);
  const header = Buffer.from(JSON.stringify({
    ...metadata,
    protocol: PNG_PROTOCOL,
    configVersion: PNG_CONFIG_VERSION,
    nodeVersion: process.versions.node,
    zlibVersion: process.versions.zlib,
    sourceSha256: sourceSha256 ?? null,
    networkApiAttemptCount: guard.attemptCount,
    maxOutputBytes,
    normalizedByteLength: payload.length,
  }));
  if (header.length > PNG_LIMITS.maxHeaderBytes) throw new Error("PNG header limit");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(header.length);
  const frame = Buffer.concat([length, header, payload]);
  await new Promise((resolve, reject) => {
    process.stdout.write(frame, (error) => error ? reject(error) : resolve());
  });
}

try {
  if (process.versions.node !== PNG_NODE_VERSION || process.versions.zlib !== PNG_ZLIB_VERSION) {
    await emit({ kind: "rejected", code: "DECODER_UNAVAILABLE" });
  } else if (!Number.isInteger(maxOutputBytes) || maxOutputBytes < 1 ||
      maxOutputBytes > PNG_LIMITS.maxOutputBytes) {
    await emit({ kind: "rejected", code: "INVALID_LIMIT" });
  } else {
    for await (const part of process.stdin) {
      size += part.length;
      if (size > PNG_LIMITS.maxInputBytes) throw Object.assign(new Error("PNG input limit"), { code: "INPUT_TOO_LARGE" });
      parts.push(part);
    }
    const bytes = Buffer.concat(parts, size);
    const sourceSha256 = createHash("sha256").update(bytes).digest("hex");
    const result = decodeStaticPngForWorker(bytes, maxOutputBytes);
    await emit(guard.attemptCount === 0 ? result : { kind: "rejected", code: "REMOTE_RESOURCE_ATTEMPT" }, sourceSha256);
  }
} catch (error) {
  try {
    await emit({
      kind: "rejected",
      code: PNG_ERROR_CODES.includes(error?.code) ? error.code : "DECODER_FAILURE",
    });
  } catch {
    process.exitCode = 1;
  }
}
