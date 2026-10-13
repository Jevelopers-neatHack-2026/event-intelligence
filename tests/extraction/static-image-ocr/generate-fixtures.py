"""Reproduce synthetic encoder fixtures with the already pinned Pillow runtime.

No source/provider download. The existing OCR raster and font notice retain their
own provenance; this script adds only deterministic encodings and local hashes.
"""
import sys
# Fixture generation must not add unmanifested bytecode to the exact decoder
# installation. Use -B at invocation as well, before any imports in this script.
sys.dont_write_bytecode = True
import gzip, hashlib, io, json, pathlib
from PIL import Image, __version__

assert __version__ == '12.3.0'
HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE.parent / 'local-ocr/fixtures/english-gray8.raw.gz'
raw = gzip.decompress(SOURCE.read_bytes())
assert len(raw) == 220000
assert hashlib.sha256(raw).hexdigest() == '50f86c14d6b77e84ffb70a933a80ab9a0cb0226d2301f1044b024414ee43d168'
image = Image.frombytes('L', (1000, 220), raw).convert('RGB')
out = HERE / 'fixtures'
out.mkdir(exist_ok=True)
records = []
for name, fmt, options in [
    ('english-baseline.jpeg', 'JPEG', {'quality':95, 'subsampling':0, 'progressive':False}),
    ('english-progressive.jpeg', 'JPEG', {'quality':95, 'subsampling':0, 'progressive':True}),
    ('english-lossless.webp', 'WEBP', {'lossless':True, 'method':6}),
    ('english-lossy.webp', 'WEBP', {'quality':90, 'lossless':False, 'method':6}),
    ('transparent.webp', 'WEBP', {'lossless':True, 'exact':True}),
]:
    actual = image if name != 'transparent.webp' else Image.frombytes('RGBA',(2,2),bytes([25,30,40,0,50,60,70,255,80,90,100,255,110,120,130,255]))
    encoded = io.BytesIO(); actual.save(encoded, format=fmt, **options); data = encoded.getvalue()
    path = out / name; path.write_bytes(data)
    with Image.open(io.BytesIO(data)) as check:
        check.load(); pixels=check.convert('RGBA').tobytes()
        records.append({'file':name, 'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest(),
                        'width':check.width,'height':check.height,'rgbaSha256':hashlib.sha256(pixels).hexdigest(),
                        'encoderOptions':options})
manifest = {'origin':'synthetic existing local OCR test raster; no customer or public source', 'pillowVersion':__version__,
            'source':'../../local-ocr/fixtures/english-gray8.raw.gz','sourceRawSha256':hashlib.sha256(raw).hexdigest(),
            'sourceCompressedSha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            'fontNotice':'../../local-ocr/fixtures/font-notice.txt',
            'fontNoticeSha256':hashlib.sha256((SOURCE.parent/'font-notice.txt').read_bytes()).hexdigest(),
            'pixelOracle':'separate local decode using this pinned Pillow library; not an independent codec or OCR accuracy evaluation',
            'fixtures':records}
(out/'provenance.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'fixtures':len(records),'pillow':__version__,'sourceSha256':manifest['sourceRawSha256']}))
