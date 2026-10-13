"""Regenerate synthetic labelled pixels; opt-in maintainer tool, not the test path."""
from pathlib import Path
import hashlib
from PIL import Image, ImageDraw, ImageFont, __version__
assert __version__ == '12.3.0'
font_path = Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
assert hashlib.sha256(font_path.read_bytes()).hexdigest() == 'ae7b7855e115a5966d8b1b3f80f254ccc117ec86f9965e202ee2940453837280'
image = Image.new('RGB', (1200, 340), 'white')
draw, font = ImageDraw.Draw(image), ImageFont.truetype(str(font_path), 48)
for index, text in enumerate(['Title: Community Night', 'Date: 03/04/2026', 'Venue: Sample Hall']):
    draw.text((35, 25 + index * 100), text, font=font, fill='black')
image.save(Path(__file__).with_name('labelled.png'), compress_level=9)
assert hashlib.sha256(Path(__file__).with_name('labelled.png').read_bytes()).hexdigest() == '2bd746b0551b9f91c1d524c692a1866262e1374784611765d9c35634b2a23212'
