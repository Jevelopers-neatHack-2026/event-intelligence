// Repository-private fixed composition, absent from the package export map.
import { createStaticJpegWebpReader } from "../jpeg-webp/index.mjs";
import { readStaticPng } from "../png/index.mjs";
import { readLocalOcr } from "../local-ocr/index.mjs";
import { record } from "./validation.mjs";
import { createStaticImageOcrReaderWithPorts } from "./reader.mjs";
export { STATIC_IMAGE_OCR_LIMITS, STATIC_IMAGE_OCR_ERRORS } from "./profile.mjs";

/** Trusted host configuration only; untrusted requests supply bytes and lower limits. */
export function createStaticImageOcrReader(configuration) {
  const config = record(configuration, ["runtimeDirectory"]);
  if (!config) throw new TypeError("An explicit trusted JPEG/WebP runtime directory is required");
  const raster = createStaticJpegWebpReader(config);
  return Object.freeze({ read: createStaticImageOcrReaderWithPorts({ readPng: readStaticPng, readJpegWebp: raster.read, readOcr: readLocalOcr }) });
}
