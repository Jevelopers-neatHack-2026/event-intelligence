"""Synthetic C-API TSV boundary vectors; these are not model-accuracy evaluations."""
import json
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3]/"src/extraction/local-ocr"))
from errors import Rejection
from native import parse_tsv

page = "1\t1\t0\t0\t0\t0\t0\t0\t100\t40\t-1\t\n"
word = "5\t1\t1\t1\t1\t1\t5\t6\t40\t12\t50.5\tTICKET\n"
second = word.replace("1\t5\t6", "2\t50\t6").replace("TICKET", "STUB")
cases = [
 ("valid uncertain literal", page+word, 100, 10, None),
 ("zero confidence retained", page+word.replace("50.5", "0"), 100, 10, None),
 ("empty page retained", page, 100, 10, None),
 ("two ordered words", page+word+second, 100, 10, None),
 ("missing page", word, 100, 10, "INVALID_OCR_OUTPUT"),
 ("empty output", "", 100, 10, "INVALID_OCR_OUTPUT"),
 ("duplicated page", page+page, 100, 10, "INVALID_OCR_OUTPUT"),
 ("invalid columns", page+word.replace("TICKET", "TICKET\tMORE"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("nonfinite score", page+word.replace("50.5", "nan"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("infinite score", page+word.replace("50.5", "inf"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("negative score", page+word.replace("50.5", "-1"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("overrange score", page+word.replace("50.5", "100.01"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("negative geometry", page+word.replace("5\t6\t40", "-1\t6\t40"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("out of bounds box", page+word.replace("40\t12", "101\t12"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("zero box width", page+word.replace("40\t12", "0\t12"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("wrong page", page+word.replace("5\t1\t1", "5\t2\t1"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("wrong first page geometry", page.replace("100\t40", "99\t40"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("repeated word identity", page+word+word, 100, 10, "INVALID_OCR_OUTPUT"),
 ("word budget", page+word+second, 100, 1, "OUTPUT_LIMIT"),
 ("text budget", page+word, 5, 10, "OUTPUT_LIMIT"),
 ("bidi control", page+word.replace("TICKET", "TICK\u202eET"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("NUL control", page+word.replace("TICKET", "TICK\x00ET"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("terminal CR is not silently stripped", page+word.replace("TICKET", "TICKET\r"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("Unicode paragraph separator", page+word.replace("TICKET", "TICK\u2029ET"), 100, 10, "INVALID_OCR_OUTPUT"),
 ("word in metadata row", page+word.replace("5\t1", "4\t1", 1), 100, 10, "INVALID_OCR_OUTPUT"),
 ("invalid UTF8", (page+word).encode()+b"\xff", 100, 10, "INVALID_OCR_OUTPUT"),
]
results = []
for name, data, text_limit, word_limit, expected in cases:
    error = None
    try:
        words, count = parse_tsv(data.encode() if isinstance(data, str) else data, 100, 40, text_limit, word_limit)
        assert count == sum(len(item["text"].encode()) for item in words)
    except Rejection as failure:
        error = failure.code
    results.append({"name":name, "expected":expected, "actual":error, "passed":error == expected})
print(json.dumps({"mode":"synthetic native TSV vectors, not OCR accuracy evidence", "cases":results}))
if not all(item["passed"] for item in results):
    raise SystemExit(1)
