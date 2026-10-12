"""Fixed C API calls; no filename, language, configuration or model supplied by pixels."""
import ctypes as C
import math
from errors import reject

def bind(library, name, arguments, result):
    function = getattr(library, name)
    function.argtypes, function.restype = arguments, result
    return function

class Engine:
    def __init__(self, site, profile):
        self.handle = None
        self.lept = C.CDLL(str(site/"usr/lib/x86_64-linux-gnu/liblept.so.5.0.4"), mode=C.RTLD_GLOBAL)
        self.library = C.CDLL(str(site/"usr/lib/x86_64-linux-gnu/libtesseract.so.5.0.3"), use_errno=True)
        library = self.library
        self.version = bind(library, "TessVersion", [], C.c_char_p)().decode("ascii")
        lept_version = bind(self.lept, "getLeptonicaVersion", [], C.c_void_p)
        free = bind(C.CDLL(None), "free", [C.c_void_p], None)
        pointer = lept_version()
        try:
            actual_lept = C.string_at(pointer).decode("ascii")
        finally:
            free(pointer)
        if self.version != profile["tesseractVersion"] or actual_lept != "leptonica-"+profile["leptonicaVersion"]:
            reject("RUNTIME_MISMATCH")
        self.create = bind(library, "TessBaseAPICreate", [], C.c_void_p)
        self.delete = bind(library, "TessBaseAPIDelete", [C.c_void_p], None)
        self.init = bind(library, "TessBaseAPIInit2", [C.c_void_p, C.c_char_p, C.c_char_p, C.c_int], C.c_int)
        self.set_mode = bind(library, "TessBaseAPISetPageSegMode", [C.c_void_p, C.c_int], None)
        get_mode = bind(library, "TessBaseAPIGetPageSegMode", [C.c_void_p], C.c_int)
        get_oem = bind(library, "TessBaseAPIOem", [C.c_void_p], C.c_int)
        loaded = bind(library, "TessBaseAPIGetLoadedLanguagesAsVector", [C.c_void_p], C.POINTER(C.c_char_p))
        delete_array = bind(library, "TessDeleteTextArray", [C.POINTER(C.c_char_p)], None)
        self.set_image = bind(library, "TessBaseAPISetImage", [C.c_void_p, C.c_void_p, C.c_int, C.c_int, C.c_int, C.c_int], None)
        self.recognize = bind(library, "TessBaseAPIRecognize", [C.c_void_p, C.c_void_p], C.c_int)
        self.get_tsv = bind(library, "TessBaseAPIGetTsvText", [C.c_void_p, C.c_int], C.c_void_p)
        self.delete_text = bind(library, "TessDeleteText", [C.c_void_p], None)
        self.strnlen = bind(C.CDLL(None), "strnlen", [C.c_void_p, C.c_size_t], C.c_size_t)
        self.handle = self.create()
        if not self.handle or self.init(self.handle, str(site/"usr/share/tesseract-ocr/5/tessdata").encode(), b"eng", 1) != 0:
            self.close()
            reject("MODEL_UNAVAILABLE")
        languages = loaded(self.handle)
        try:
            if not languages or languages[0] != b"eng" or languages[1] is not None or get_oem(self.handle) != 1:
                reject("RUNTIME_MISMATCH")
        finally:
            if languages:
                delete_array(languages)
        self.set_mode(self.handle, 6)
        if get_mode(self.handle) != 6:
            reject("RUNTIME_MISMATCH")

    def close(self):
        if self.handle:
            self.delete(self.handle)
            self.handle = None

    def read(self, pixels, width, height, channels, profile, max_text_bytes, max_words):
        buffer = C.create_string_buffer(pixels)
        self.set_image(self.handle, buffer, width, height, channels, width*channels)
        if self.recognize(self.handle, None) != 0:
            reject("OCR_FAILURE")
        pointer = self.get_tsv(self.handle, 0)
        if not pointer:
            reject("OCR_FAILURE")
        try:
            length = self.strnlen(pointer, profile["maxTsvBytes"]+1)
            if length > profile["maxTsvBytes"]:
                reject("OUTPUT_LIMIT")
            data = C.string_at(pointer, length)
        finally:
            self.delete_text(pointer)
        return parse_tsv(data, width, height, max_text_bytes, max_words)

def parse_tsv(data, width, height, max_text_bytes, max_words):
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError:
        reject("INVALID_OCR_OUTPUT")
    words, seen = [], set()
    text_bytes = 0
    prior = (0, 0, 0, 0)
    # Tesseract's C GetTsvText emits no header. Require the exact top-level page
    # row and every subsequent row's geometry; never truncate a large result.
    # Only the C API's LF record separator may be consumed. splitlines() would
    # silently erase an embedded terminal CR from a token before validation.
    rows = text.split("\n")
    if rows[-1] != "":
        reject("INVALID_OCR_OUTPUT")
    rows = rows[:-1]
    if not rows or len(rows) > max_words*5+1:
        reject("OUTPUT_LIMIT" if rows else "INVALID_OCR_OUTPUT")
    for index, row in enumerate(rows):
        fields = row.split("\t")
        if len(fields) != 12:
            reject("INVALID_OCR_OUTPUT")
        try:
            if any(not item.isascii() or not item.isdecimal() for item in fields[:10]):
                reject("INVALID_OCR_OUTPUT")
            level, page, block, paragraph, line, word, left, top, box_width, box_height = map(int, fields[:10])
            confidence = float(fields[10])
        except (ValueError, OverflowError):
            reject("INVALID_OCR_OUTPUT")
        if not 1 <= level <= 5 or page != 1 or not math.isfinite(confidence):
            reject("INVALID_OCR_OUTPUT")
        if not 0 <= left <= width or not 0 <= top <= height or box_width < 0 or box_height < 0 or left+box_width > width or top+box_height > height:
            reject("INVALID_OCR_OUTPUT")
        if index == 0 and (level, block, paragraph, line, word, left, top, box_width, box_height, confidence, fields[11]) != (1, 0, 0, 0, 0, 0, 0, width, height, -1, ""):
            reject("INVALID_OCR_OUTPUT")
        if level != 5:
            if fields[11] or confidence != -1 or (level == 1 and index != 0):
                reject("INVALID_OCR_OUTPUT")
            continue
        token = fields[11]
        identity = (block, paragraph, line, word)
        if (not token or any(ord(char) < 32 or 127 <= ord(char) <= 159 or
                            0x2028 <= ord(char) <= 0x202e or 0x2066 <= ord(char) <= 0x2069 for char in token) or
            not 0 <= confidence <= 100 or min(identity) < 1 or
            identity <= prior or identity in seen or box_width < 1 or box_height < 1):
            reject("INVALID_OCR_OUTPUT")
        text_bytes += len(token.encode("utf-8"))
        if len(words) >= max_words or text_bytes > max_text_bytes:
            reject("OUTPUT_LIMIT")
        prior = identity
        seen.add(identity)
        words.append({"text":token, "confidence":confidence, "block":block, "paragraph":paragraph,
                      "line":line, "word":word, "box":{"left":left, "top":top, "width":box_width, "height":box_height}})
    return words, text_bytes
