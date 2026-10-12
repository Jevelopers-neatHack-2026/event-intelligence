// Private implementation profile, not a shared-contracts enum or research API.
export const PNG_CONFIG_VERSION = "ei-static-png/1";
export const PNG_NODE_VERSION = "22.23.3";
export const PNG_ZLIB_VERSION = "1.3.1-e00f703";
export const PNG_PROTOCOL = "ei-static-png-worker/1";

export const PNG_LIMITS = Object.freeze({
  maxInputBytes: 10 * 1024 * 1024,
  maxDimension: 4096,
  maxPixels: 4 * 1024 * 1024,
  maxRows: 4096,
  maxInflatedBytes: 4 * 4 * 1024 * 1024 + 4096,
  maxOutputBytes: 20 * 1024 * 1024,
  maxChunks: 1024,
  maxHeaderBytes: 4096,
  maxAddressSpaceBytes: 6 * 1024 * 1024 * 1024,
  maxCpuSeconds: 5,
  maxOpenFiles: 64,
  maxHeapMiB: 256,
  defaultTimeoutMs: 5000,
  maxTimeoutMs: 10000,
  maxConcurrency: 1,
  maxQueued: 4,
});

export const PNG_ERROR_CODES = Object.freeze([
  "INVALID_INPUT", "INVALID_OPTIONS", "INVALID_LIMIT", "INPUT_TOO_LARGE",
  "MALFORMED_PNG", "UNSUPPORTED_PNG_FEATURE", "DIMENSION_LIMIT",
  "RESOURCE_LIMIT", "OUTPUT_LIMIT", "CANCELLED", "TIMEOUT", "QUEUE_FULL",
  "ISOLATION_UNAVAILABLE", "DECODER_UNAVAILABLE", "DECODER_FAILURE",
  "PROTOCOL_ERROR", "REMOTE_RESOURCE_ATTEMPT",
]);

export const PNG_DECODER = Object.freeze({
  name: "node-zlib-static-png",
  nodeVersion: PNG_NODE_VERSION,
  zlibVersion: PNG_ZLIB_VERSION,
  configVersion: PNG_CONFIG_VERSION,
});
