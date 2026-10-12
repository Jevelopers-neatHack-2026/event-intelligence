// Private local decoder profile; not a canonical contract or an inspection result.
export const RASTER_CONFIG_VERSION = "ei-static-jpeg-webp/1";
export const RASTER_PROTOCOL = "ei-static-jpeg-webp-worker/1";
export const RASTER_NODE_VERSION = "22.23.3";
export const RASTER_PYTHON_VERSION = "3.12.14";
export const RASTER_PILLOW_VERSION = "12.3.0";
export const RASTER_WHEEL_SHA256 = "78cb2c6865a35ab8ff8b75fd122f6033b92a62c82801110e48ddd6c936a45d91";
export const RASTER_RUNTIME_SCHEMA = "ei-static-raster-runtime/1";
export const RASTER_LIMITS = Object.freeze({
  maxInputBytes: 10 * 1024 * 1024,
  maxDimension: 4096,
  maxPixels: 4 * 1024 * 1024,
  maxFrames: 1,
  maxSegments: 1024,
  maxDecodedBytes: 16 * 1024 * 1024,
  maxOutputBytes: 20 * 1024 * 1024,
  maxHeaderBytes: 4096,
  maxStderrBytes: 16 * 1024,
  maxRuntimeManifestBytes: 256 * 1024,
  maxAddressSpaceBytes: 512 * 1024 * 1024,
  maxCpuSeconds: 5,
  maxOpenFiles: 64,
  defaultTimeoutMs: 5000,
  maxTimeoutMs: 10000,
  maxConcurrency: 1,
  maxQueued: 4,
});
export const RASTER_ERROR_CODES = Object.freeze([
  "INVALID_INPUT", "INVALID_OPTIONS", "INVALID_LIMIT", "INPUT_TOO_LARGE",
  "UNSUPPORTED_FORMAT", "UNSUPPORTED_FEATURE", "MALFORMED_IMAGE", "DIMENSION_LIMIT",
  "RESOURCE_LIMIT", "OUTPUT_LIMIT", "CANCELLED", "TIMEOUT", "QUEUE_FULL",
  "ISOLATION_UNAVAILABLE", "DECODER_UNAVAILABLE", "DECODER_FAILURE",
  "PROTOCOL_ERROR", "REMOTE_RESOURCE_ATTEMPT",
]);
export const RASTER_DECODER = Object.freeze({
  name: "pillow-static-jpeg-webp",
  configVersion: RASTER_CONFIG_VERSION,
  nodeVersion: RASTER_NODE_VERSION,
  pythonVersion: RASTER_PYTHON_VERSION,
  pillowVersion: RASTER_PILLOW_VERSION,
  jpegVersion: "6.2",
  webpVersion: "1.6.0",
  jpegValidation: "libjpeg-coefficients-no-warnings/1",
  jpegLibrarySha256: "6d7c754529b30aff22efaaf88ba02061714591702c03f297f00ccb32ee6d9d9a",
  webpValidation: "exact-chunk-native-completion/1",
  webpLibrarySha256: "7df9ad3680dd09d756511334791c8c896207863816eb2910840e5fc4ae10028a",
  wheelSha256: RASTER_WHEEL_SHA256,
  normalization: "rgba8-png-stored-deflate/1",
});
