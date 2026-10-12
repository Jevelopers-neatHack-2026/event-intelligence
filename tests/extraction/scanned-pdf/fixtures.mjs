import { deflateSync } from "node:zlib";

export const RGB_2X2 = Buffer.from([255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255]);
export const RGBA_2X2 = Buffer.from("ff0000ff00ff00ff0000ffffffffffff", "hex");
const bytes = (value) => Buffer.isBuffer(value) ? value : Buffer.from(value);
function stream(dictionary, content, declaredLength = content.length) {
  return Buffer.concat([bytes("<< " + dictionary + " /Length " + declaredLength + " >>\nstream\n"), content, bytes("\nendstream")]);
}

/** Synthetic document construction; no sampled customer/public-source document. */
export function imagePdf(pages = [{}], options = {}) {
  const objects = [
    bytes("<< /Type /Catalog /Pages 2 0 R " + (options.catalogExtra ?? "") + " >>"),
    bytes("<< /Type /Pages /Kids [" + pages.map((_, i) => (3 + i * 3) + " 0 R").join(" ") +
      "] /Count " + pages.length + " >>"),
  ];
  for (const [index, page] of pages.entries()) {
    const width = page.width ?? 2, height = page.height ?? 2;
    const points = page.points ?? [width, height];
    const imageId = 4 + index * 3, contentsId = 5 + index * 3;
    const rgb = page.rgb ?? RGB_2X2;
    const name = page.imageName ?? "Scan";
    const compressed = page.compressed ?? deflateSync(rgb, { level: 9 });
    const content = bytes(page.content ?? ("q\n" + points[0] + " 0 0 " + points[1] + " 0 0 cm\n/" + name + " Do\nQ\n"));
    objects.push(bytes("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 " + points.join(" ") +
      "] /Resources << /XObject << /" + name + " " + imageId + " 0 R >> " + (page.resourceExtra ?? "") +
      " >> /Contents " + contentsId + " 0 R " + (page.pageExtra ?? "") + " >>"));
    objects.push(stream("/Type /XObject /Subtype /Image /Width " + width + " /Height " + height +
      " /ColorSpace /" + (page.colorSpace ?? "DeviceRGB") + " /BitsPerComponent " + (page.bits ?? 8) +
      " /Filter /" + (page.filter ?? "FlateDecode") + " " + (page.imageExtra ?? ""), compressed, page.declaredLength));
    objects.push(stream(page.contentExtra ?? "", content));
  }
  options.changeObjects?.(objects);
  let output = bytes(options.header ?? "%PDF-1.7\n");
  const offsets = [0];
  for (const [index, object] of objects.entries()) {
    offsets.push(output.length);
    output = Buffer.concat([output, bytes((index + 1) + " 0 obj\n"), bytes(object), bytes("\nendobj\n")]);
  }
  const xref = output.length;
  output = Buffer.concat([output, bytes("xref\n0 " + (objects.length + 1) + "\n0000000000 65535 f \n" +
    offsets.slice(1).map((offset) => String(offset).padStart(10, "0") + " 00000 n \n").join("") +
    "trailer\n<< /Size " + (objects.length + 1) + " /Root 1 0 R " + (options.trailerExtra ?? "") +
    " >>\nstartxref\n" + xref + "\n%%EOF\n" + (options.trailing ?? ""))]);
  return output;
}

export function repeatedRgb(width, height, color = [17, 83, 211]) {
  const output = Buffer.alloc(width * height * 3);
  for (let index = 0; index < output.length; index += 3) output.set(color, index);
  return output;
}
