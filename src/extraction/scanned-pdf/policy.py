"""A strict classic-PDF admission profile, not a general PDF parser or renderer."""
import math
import re
import zlib


class Rejection(Exception):
    def __init__(self, code):
        self.code = code


def reject(code):
    raise Rejection(code)


class Name(str):
    pass


class Ref(tuple):
    pass


class Stream:
    def __init__(self, dictionary, data):
        self.dictionary = dictionary
        self.data = data


SPECIAL = {
    "Encrypt": "ENCRYPTED_PDF",
    **{key: "REMOTE_RESOURCE" for key in ("URI", "GoToR", "GoToE", "F", "FFilter", "FDecodeParms")},
    **{key: "ACTIVE_CONTENT" for key in (
        "OpenAction", "AA", "JavaScript", "JS", "Launch", "SubmitForm", "ImportData",
        "Rendition", "RichMedia", "Movie", "Sound", "XFA", "AcroForm", "EmbeddedFiles", "EF", "AF")},
}
WHITE = b"\x00\t\n\f\r "
DELIMITERS = WHITE + b"()<>[]{}/%"
NUMBER = re.compile(rb"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)\Z")


class Lexer:
    def __init__(self, data, limits):
        self.data = data
        self.pos = 0
        self.count = 0
        self.limits = limits

    def space(self):
        while self.pos < len(self.data):
            value = self.data[self.pos]
            if value in WHITE:
                self.pos += 1
            elif value == 37:
                while self.pos < len(self.data) and self.data[self.pos] not in b"\r\n":
                    self.pos += 1
            else:
                break

    def token(self):
        self.space()
        self.count += 1
        if self.count > self.limits["maxTokens"]:
            reject("STRUCTURE_LIMIT")
        if self.pos == len(self.data):
            reject("MALFORMED_PDF")
        start = self.pos
        if self.data[start:start+2] in (b"<<", b">>"):
            self.pos += 2
            return self.data[start:self.pos]
        first = self.data[start]
        if first in b"[]":
            self.pos += 1
            return bytes([first])
        if first in b"(){}<>":
            reject("UNSUPPORTED_PDF_FEATURE")
        if first == 47:
            self.pos += 1
            start = self.pos
            while self.pos < len(self.data) and self.data[self.pos] not in DELIMITERS:
                self.pos += 1
            value = self.data[start:self.pos]
            if not value or len(value) > 192:
                reject("STRUCTURE_LIMIT")
            def escape(match):
                return bytes([int(match[1], 16)])
            value = re.sub(rb"#([0-9A-Fa-f]{2})", escape, value)
            if len(value) > 64 or any(x < 33 or x > 126 for x in value) or b"#" in value:
                reject("UNSUPPORTED_PDF_FEATURE")
            return Name(value.decode("ascii"))
        while self.pos < len(self.data) and self.data[self.pos] not in DELIMITERS:
            self.pos += 1
        value = self.data[start:self.pos]
        if not value or len(value) > 64:
            reject("MALFORMED_PDF")
        if NUMBER.fullmatch(value):
            number = float(value) if b"." in value else int(value)
            if not math.isfinite(number) or abs(number) > 2**31:
                reject("STRUCTURE_LIMIT")
            return number
        return value

    def expect(self, wanted):
        actual = self.token()
        if actual != wanted or (type(wanted) is int and type(actual) is not int):
            reject("MALFORMED_PDF")

    def value(self, depth=0):
        if depth > self.limits["maxDepth"]:
            reject("STRUCTURE_LIMIT")
        token = self.token()
        if token == b"<<":
            result = {}
            while True:
                key = self.token()
                if key == b">>":
                    return result
                if type(key) is not Name or key in result:
                    reject("MALFORMED_PDF")
                if key in SPECIAL:
                    reject(SPECIAL[key])
                if len(result) >= 32:
                    reject("STRUCTURE_LIMIT")
                result[key] = self.value(depth+1)
        if token == b"[":
            result = []
            while True:
                saved = self.pos
                if self.token() == b"]":
                    return result
                self.pos = saved
                if len(result) >= 32:
                    reject("STRUCTURE_LIMIT")
                result.append(self.value(depth+1))
        if type(token) is int:
            saved = self.pos
            next_value = self.token()
            if type(next_value) is int:
                third = self.token()
                if third == b"R":
                    if token < 1 or next_value != 0:
                        reject("UNSUPPORTED_PDF_FEATURE")
                    return Ref((token, 0))
            self.pos = saved
        if type(token) in (int, float, Name):
            return token
        reject("UNSUPPORTED_PDF_FEATURE")


def keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        reject("UNSUPPORTED_PDF_FEATURE")


def is_number(value):
    return type(value) in (int, float) and math.isfinite(value)


def parse_objects(data, limits):
    if not re.match(rb"%PDF-1\.[4-7](?:\r\n|\r|\n)", data):
        reject("UNSUPPORTED_PDF_FEATURE")
    lexer = Lexer(data, limits)
    objects = {}
    offsets = {}
    while True:
        lexer.space()
        offset = lexer.pos
        token = lexer.token()
        if token == b"xref":
            xref_offset = offset
            break
        if type(token) is not int or token != len(objects)+1:
            reject("UNSUPPORTED_PDF_FEATURE")
        if len(objects) >= limits["maxObjects"]:
            reject("STRUCTURE_LIMIT")
        lexer.expect(0)
        lexer.expect(b"obj")
        value = lexer.value()
        saved = lexer.pos
        if lexer.token() == b"stream":
            if type(value) is not dict or type(value.get("Length")) is not int or value["Length"] < 0:
                reject("UNSUPPORTED_PDF_FEATURE")
            if data[lexer.pos:lexer.pos+2] == b"\r\n":
                lexer.pos += 2
            elif data[lexer.pos:lexer.pos+1] == b"\n":
                lexer.pos += 1
            else:
                reject("MALFORMED_PDF")
            end = lexer.pos + value["Length"]
            if end > len(data):
                reject("MALFORMED_PDF")
            content = data[lexer.pos:end]
            lexer.pos = end
            lexer.expect(b"endstream")
            value = Stream(value, content)
        else:
            lexer.pos = saved
        lexer.expect(b"endobj")
        objects[token] = value
        offsets[token] = offset
    lexer.expect(0)
    lexer.expect(len(objects)+1)
    lexer.expect(0)
    lexer.expect(65535)
    lexer.expect(b"f")
    for index in objects:
        lexer.expect(offsets[index])
        lexer.expect(0)
        lexer.expect(b"n")
    lexer.expect(b"trailer")
    trailer = lexer.value()
    keys(trailer, ("Size", "Root"))
    if trailer["Size"] != len(objects)+1 or type(trailer["Size"]) is not int:
        reject("MALFORMED_PDF")
    lexer.expect(b"startxref")
    lexer.expect(xref_offset)
    # Do not let comment skipping turn incremental updates or trailing bytes into a pass.
    if not re.fullmatch(rb"[\x00\t\n\f\r ]*%%EOF[\x00\t\n\f\r ]*", data[lexer.pos:]):
        reject("UNSUPPORTED_PDF_FEATURE")
    return objects, trailer["Root"]


def admit(data, limits):
    objects, root = parse_objects(data, limits)
    used = set()
    def get(ref):
        if type(ref) is not Ref or ref[0] not in objects or ref[0] in used:
            reject("UNSUPPORTED_PDF_FEATURE")
        used.add(ref[0])
        return objects[ref[0]]
    catalog = get(root)
    keys(catalog, ("Type", "Pages"))
    if catalog["Type"] != Name("Catalog"):
        reject("MALFORMED_PDF")
    pages_ref = catalog["Pages"]
    pages = get(pages_ref)
    keys(pages, ("Type", "Kids", "Count"))
    if pages["Type"] != Name("Pages") or type(pages["Kids"]) is not list or type(pages["Count"]) is not int:
        reject("MALFORMED_PDF")
    if pages["Count"] < 1 or pages["Count"] > limits["maxPages"]:
        reject("PAGE_LIMIT")
    if pages["Count"] != len(pages["Kids"]):
        reject("MALFORMED_PDF")
    result = []
    total_pixels = 0
    for page_ref in pages["Kids"]:
        page = get(page_ref)
        keys(page, ("Type", "Parent", "MediaBox", "Resources", "Contents"))
        if page["Type"] != Name("Page") or page["Parent"] != pages_ref:
            reject("MALFORMED_PDF")
        box = page["MediaBox"]
        if type(box) is not list or len(box) != 4 or not all(is_number(x) for x in box) or box[:2] != [0, 0]:
            reject("UNSUPPORTED_PDF_FEATURE")
        pw, ph = box[2:]
        if not (0 < pw <= limits["maxPagePoints"] and 0 < ph <= limits["maxPagePoints"]):
            reject("DIMENSION_LIMIT")
        resources = page["Resources"]
        keys(resources, ("XObject",))
        images = resources["XObject"]
        if type(images) is not dict or len(images) != 1:
            reject("UNSUPPORTED_PDF_FEATURE")
        image_name, image_ref = next(iter(images.items()))
        image = get(image_ref)
        if type(image) is not Stream:
            reject("UNSUPPORTED_PDF_FEATURE")
        meta = image.dictionary
        keys(meta, ("Type", "Subtype", "Width", "Height", "ColorSpace", "BitsPerComponent", "Filter", "Length"))
        if (meta["Type"] != Name("XObject") or meta["Subtype"] != Name("Image") or
            meta["ColorSpace"] != Name("DeviceRGB") or meta["BitsPerComponent"] != 8 or
            type(meta["BitsPerComponent"]) is not int or meta["Filter"] != Name("FlateDecode")):
            reject("UNSUPPORTED_PDF_FEATURE")
        width, height = meta["Width"], meta["Height"]
        if type(width) is not int or type(height) is not int or not (
            1 <= width <= limits["maxImageDimension"] and 1 <= height <= limits["maxImageDimension"]
        ):
            reject("DIMENSION_LIMIT")
        pixels = width*height
        total_pixels += pixels
        if pixels > limits["maxPagePixels"] or total_pixels > limits["maxTotalPixels"]:
            reject("PIXEL_LIMIT")
        contents = get(page["Contents"])
        if type(contents) is not Stream:
            reject("UNSUPPORTED_PDF_FEATURE")
        keys(contents.dictionary, ("Length",))
        if len(contents.data) > limits["maxContentBytes"]:
            reject("STRUCTURE_LIMIT")
        command = Lexer(contents.data, limits)
        expected = (b"q", pw, 0, 0, ph, 0, 0, b"cm", image_name, b"Do", b"Q")
        for wanted in expected:
            actual = command.token()
            if actual != wanted or (type(wanted) is Name and type(actual) is not Name):
                reject("UNSUPPORTED_PDF_FEATURE")
        command.space()
        if command.pos != len(contents.data):
            reject("UNSUPPORTED_PDF_FEATURE")
        try:
            decoder = zlib.decompressobj()
            rgb = decoder.decompress(image.data, pixels*3+1)
            if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data or len(rgb) != pixels*3:
                reject("DAMAGED_IMAGE")
        except zlib.error:
            reject("DAMAGED_IMAGE")
        result.append({"width":width, "height":height, "pageWidthPoints":pw,
                       "pageHeightPoints":ph, "rgb":rgb})
    if used != set(objects):
        reject("UNSUPPORTED_PDF_FEATURE")
    return result
