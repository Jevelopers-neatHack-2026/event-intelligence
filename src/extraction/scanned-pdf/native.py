"""Actual PDFium object/image/page decoding after the caller installs seccomp."""
import ctypes as C
import hashlib
import math
from policy import reject


def rgba_bitmap(pdf, bitmap, width, height, require_bgra=False):
    if not bitmap or pdf.FPDFBitmap_GetWidth(bitmap) != width or pdf.FPDFBitmap_GetHeight(bitmap) != height:
        reject("DAMAGED_IMAGE")
    fmt = pdf.FPDFBitmap_GetFormat(bitmap)
    if fmt not in (pdf.FPDFBitmap_BGR, pdf.FPDFBitmap_BGRA) or (require_bgra and fmt != pdf.FPDFBitmap_BGRA):
        reject("UNSUPPORTED_PDF_FEATURE")
    channels = 3 if fmt == pdf.FPDFBitmap_BGR else 4
    stride = pdf.FPDFBitmap_GetStride(bitmap)
    if not width*channels <= stride <= width*channels+3:
        reject("DECODER_FAILURE")
    pointer = pdf.FPDFBitmap_GetBuffer(bitmap)
    if not pointer:
        reject("DECODER_FAILURE")
    packed = C.string_at(pointer, stride*height)
    rgba = bytearray(width*height*4)
    for y in range(height):
        row = packed[y*stride:y*stride+width*channels]
        out = y*width*4
        rgba[out:out+width*4:4] = row[2::channels]
        rgba[out+1:out+width*4:4] = row[1::channels]
        rgba[out+2:out+width*4:4] = row[0::channels]
        rgba[out+3:out+width*4:4] = b"\xff"*width if channels == 3 else row[3::4]
    return bytes(rgba)


def render(pdf, data, expected_pages, pause, limits, max_output_bytes):
    source = C.create_string_buffer(data)
    document = pdf.FPDF_LoadMemDocument64(source, len(data), None)
    if not document:
        reject("MALFORMED_PDF")
    outputs = []
    total = 0
    try:
        if (pdf.FPDF_GetPageCount(document) != len(expected_pages) or
            pdf.FPDF_GetFormType(document) != pdf.FORMTYPE_NONE or
            pdf.FPDFDoc_GetJavaScriptActionCount(document) != 0 or
            pdf.FPDFDoc_GetAttachmentCount(document) != 0):
            reject("UNSUPPORTED_PDF_FEATURE")
        for index, expected in enumerate(expected_pages):
            width, height = expected["width"], expected["height"]
            total += width*height*4
            if total > max_output_bytes:
                reject("OUTPUT_LIMIT")
            page = pdf.FPDF_LoadPage(document, index)
            if not page:
                reject("MALFORMED_PDF")
            image_bitmap = bitmap = None
            rendering = False
            try:
                if (pdf.FPDFPage_GetRotation(page) != 0 or pdf.FPDFPage_GetAnnotCount(page) != 0 or
                    pdf.FPDFPage_CountObjects(page) != 1):
                    reject("UNSUPPORTED_PDF_FEATURE")
                for observed, wanted in (
                    (pdf.FPDF_GetPageWidthF(page), expected["pageWidthPoints"]),
                    (pdf.FPDF_GetPageHeightF(page), expected["pageHeightPoints"]),
                ):
                    if not math.isfinite(observed) or not math.isclose(observed, wanted, rel_tol=1e-6):
                        reject("MALFORMED_PDF")
                image = pdf.FPDFPage_GetObject(page, 0)
                if not image or pdf.FPDFPageObj_GetType(image) != pdf.FPDF_PAGEOBJ_IMAGE:
                    reject("UNSUPPORTED_PDF_FEATURE")
                active = pdf.FPDF_BOOL()
                if not pdf.FPDFPageObj_GetIsActive(image, C.byref(active)) or not active.value:
                    reject("UNSUPPORTED_PDF_FEATURE")
                # The admitted content grammar contains no clipping operator or
                # form. The full raster is also compared below, pixel for pixel.
                # PDFium CountPaths returns -1 for its absent internal clip ref,
                # so a non-null outer clip handle is not evidence of extra paths.
                matrix = pdf.FS_MATRIX()
                if not pdf.FPDFPageObj_GetMatrix(image, C.byref(matrix)):
                    reject("DECODER_FAILURE")
                wanted_matrix = (expected["pageWidthPoints"], 0, 0, expected["pageHeightPoints"], 0, 0)
                if not all(math.isfinite(getattr(matrix, name)) and
                           math.isclose(getattr(matrix, name), value, abs_tol=1e-6, rel_tol=1e-6)
                           for name, value in zip(("a", "b", "c", "d", "e", "f"), wanted_matrix)):
                    reject("UNSUPPORTED_PDF_FEATURE")
                metadata = pdf.FPDF_IMAGEOBJ_METADATA()
                if not pdf.FPDFImageObj_GetImageMetadata(image, page, C.byref(metadata)):
                    reject("DAMAGED_IMAGE")
                if (metadata.width != width or metadata.height != height or metadata.bits_per_pixel != 24 or
                    metadata.colorspace != pdf.FPDF_COLORSPACE_DEVICERGB):
                    reject("UNSUPPORTED_PDF_FEATURE")
                image_bitmap = pdf.FPDFImageObj_GetBitmap(image)
                image_rgba = rgba_bitmap(pdf, image_bitmap, width, height)
                expected_rgba = bytearray(width*height*4)
                expected_rgba[0::4] = expected["rgb"][0::3]
                expected_rgba[1::4] = expected["rgb"][1::3]
                expected_rgba[2::4] = expected["rgb"][2::3]
                expected_rgba[3::4] = b"\xff"*(width*height)
                if image_rgba != expected_rgba:
                    reject("DAMAGED_IMAGE")
                bitmap = pdf.FPDFBitmap_Create(width, height, 1)
                if not bitmap or not pdf.FPDFBitmap_FillRect(bitmap, 0, 0, width, height, 0xffffffff):
                    reject("DECODER_FAILURE")
                rendering = True
                status = pdf.FPDF_RenderPageBitmap_Start(bitmap, page, 0, 0, width, height, 0, 0, C.byref(pause))
                if status != pdf.FPDF_RENDER_DONE:
                    reject("DECODER_FAILURE")
                rgba = rgba_bitmap(pdf, bitmap, width, height, require_bgra=True)
                # Render success alone can conceal PDFium's tolerant damaged-image
                # fallback. This full-page profile requires the exact native image.
                if rgba != image_rgba:
                    reject("INCOMPLETE_RENDER")
                outputs.append({
                    "page": index+1, "width": width, "height": height,
                    "pageWidthPoints": expected["pageWidthPoints"],
                    "pageHeightPoints": expected["pageHeightPoints"],
                    "byteLength": len(rgba), "sha256": hashlib.sha256(rgba).hexdigest(),
                    "bytes": rgba,
                })
            finally:
                if rendering:
                    pdf.FPDF_RenderPage_Close(page)
                if bitmap:
                    pdf.FPDFBitmap_Destroy(bitmap)
                if image_bitmap:
                    pdf.FPDFBitmap_Destroy(image_bitmap)
                pdf.FPDF_ClosePage(page)
    finally:
        pdf.FPDF_CloseDocument(document)
    return outputs
