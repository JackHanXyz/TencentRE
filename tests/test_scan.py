# -*- coding: utf-8 -*-
"""静态线索扫描自测。"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tencre import scan  # noqa: E402

SAMPLE = "\n".join([
    "const url = 'https://api.example.com/v1/login';",
    "const algo = 'AES-256-CBC';",
    "let access_token = 'abc';",
    "const k = '0123456789abcdef0123456789abcdef';",
    "const blob = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0MjQyNDI=';",
    "// just a comment line",
])


class TestScan(unittest.TestCase):
    def test_scan_text_kinds(self):
        kinds = {h.kind for h in scan.scan_text(SAMPLE)}
        self.assertIn("url", kinds)
        self.assertIn("crypto", kinds)
        self.assertIn("secret", kinds)
        self.assertIn("hex", kinds)
        self.assertIn("b64", kinds)

    def test_filter_kind(self):
        hits = scan.scan_text(SAMPLE, kinds={"url"})
        self.assertTrue(hits)
        self.assertTrue(all(h.kind == "url" for h in hits))

    def test_scan_dir(self):
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "a.js"), "w", encoding="utf-8") as f:
                f.write(SAMPLE)
            with open(os.path.join(tmp, "b.bin"), "wb") as f:
                f.write(b"\x00\x01\x02\x00")
            hits = scan.scan_dir(tmp, exts={".js"})
            self.assertTrue(any(h.file.endswith("a.js") for h in hits))
            self.assertFalse(any(h.file.endswith("b.bin") for h in hits))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_summarize(self):
        counts = scan.summarize(scan.scan_text(SAMPLE))
        self.assertGreaterEqual(counts.get("url", 0), 1)


if __name__ == "__main__":
    unittest.main()