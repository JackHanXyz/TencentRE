# -*- coding: utf-8 -*-
"""微信 .dat 解密自测：密钥反推、暴力探测、单文件与目录批量。"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tencre import wxdat  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n" + b"fake-png-body" * 4
JPG = b"\xff\xd8\xff\xe0" + b"fake-jpg-body" * 5


def _make_dat(magic, key):
    plain = magic + b"payload-" + bytes(range(32))
    return bytes(b ^ key for b in plain), plain


class TestWxDat(unittest.TestCase):
    def test_detect_png(self):
        dat, _ = _make_dat(PNG, 0x5A)
        key, ext, _magic = wxdat.detect_key(dat)
        self.assertEqual(key, 0x5A)
        self.assertEqual(ext, ".png")

    def test_detect_jpg(self):
        dat, _ = _make_dat(JPG, 0xE1)
        key, ext, _magic = wxdat.detect_key(dat)
        self.assertEqual(key, 0xE1)
        self.assertEqual(ext, ".jpg")

    def test_decrypt_roundtrip(self):
        dat, plain = _make_dat(PNG, 0x17)
        out, ext, key = wxdat.decrypt_dat(dat)
        self.assertEqual(out, plain)
        self.assertEqual(ext, ".png")
        self.assertEqual(key, 0x17)

    def test_brute_key(self):
        dat, _ = _make_dat(b"GIF89a", 0xC3)
        key, ext = wxdat.brute_key(dat)
        self.assertEqual(key, 0xC3)
        self.assertEqual(ext, ".gif")

    def test_unknown_raises(self):
        with self.assertRaises(wxdat.WxDatError):
            wxdat.decrypt_dat(b"\x01\x02\x03\x04random")

    def test_file_and_tree(self):
        tmp = tempfile.mkdtemp()
        try:
            src = os.path.join(tmp, "in")
            os.makedirs(os.path.join(src, "sub"))
            with open(os.path.join(src, "a.dat"), "wb") as f:
                f.write(_make_dat(PNG, 0x33)[0])
            with open(os.path.join(src, "sub", "b.dat"), "wb") as f:
                f.write(_make_dat(JPG, 0x44)[0])
            with open(os.path.join(src, "ignored.txt"), "wb") as f:
                f.write(b"not a dat")

            outdir = os.path.join(tmp, "out")
            stats = wxdat.decrypt_tree(src, outdir=outdir, verbose=False)
            self.assertEqual(stats["total"], 2)
            self.assertEqual(stats["ok"], 2)
            self.assertTrue(os.path.isfile(os.path.join(outdir, "a.png")))
            self.assertTrue(os.path.isfile(os.path.join(outdir, "sub", "b.jpg")))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()