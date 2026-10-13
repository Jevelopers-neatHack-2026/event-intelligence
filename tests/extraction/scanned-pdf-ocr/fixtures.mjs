import { fixture, expectedText } from "../local-ocr/helpers.mjs";
import { imagePdf, repeatedRgb } from "../scanned-pdf/fixtures.mjs";
export { expectedText, imagePdf };
export function textPdf(count = 1) {
  const raster = fixture();
  const rgb = Buffer.alloc(raster.bytes.length * 3);
  for (let index = 0; index < raster.bytes.length; index += 1) rgb.fill(raster.bytes[index], index * 3, index * 3 + 3);
  return imagePdf(Array.from({ length: count }, () => ({ width: raster.width, height: raster.height, rgb })));
}
export const blankPdf = (count = 1) => imagePdf(Array.from({ length: count }, () => ({ width: 100, height: 40, rgb: repeatedRgb(100, 40, [255, 255, 255]) })));
