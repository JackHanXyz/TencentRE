# -*- coding: utf-8 -*-
"""asar 自测：打包/列举/解包往返，以及（若存在）读取真实 QQ NT application.asar。"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tencre import asar  # noqa: E402

QQ_ASAR = r"D:\QQNT\versions\9.9.35-52892\resources\app\application.asar"


class TestAsarRoundtrip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _build_src(self):
        src = os.path.join(self.tmp, "src")
        os.makedirs(os.path.join(src, "sub", "deep"))
        files = {
            "index.html": b"<html>hello</html>",
            "app.js": b"console.log('hi');" * 10,
            "sub/a.json": b'{"k": 1}',
            "sub/deep/b.bin": bytes(range(256)),
            "unicode-\u4e2d\u6587.txt": "内容".encode("utf-8"),
        }
        for rel, data in files.items():
            p = os.path.join(src, *rel.split("/"))
            with open(p, "wb") as f:
                f.write(data)
        return src, files

    def test_pack_list_extract(self):
        src, files = self._build_src()
        archive = os.path.join(self.tmp, "out.asar")
        n = asar.pack(src, archive)
        self.assertEqual(n, len(files))

        listed = set(asar.list_files(archive))
        self.assertEqual(listed, set(files.keys()))

        dest = os.path.join(self.tmp, "dest")
        asar.extract_all(archive, dest)
        for rel, data in files.items():
            p = os.path.join(dest, *rel.split("/"))
            self.assertTrue(os.path.isfile(p), "缺少 %s" % rel)
            with open(p, "rb") as f:
                self.assertEqual(f.read(), data, rel)

    def test_cat_single(self):
        src, files = self._build_src()
        archive = os.path.join(self.tmp, "out.asar")
        asar.pack(src, archive)
        got = asar.read_file(archive, "sub/deep/b.bin")
        self.assertEqual(got, files["sub/deep/b.bin"])

    def test_info(self):
        src, files = self._build_src()
        archive = os.path.join(self.tmp, "out.asar")
        asar.pack(src, archive)
        d = asar.info(archive)
        self.assertEqual(d["entries"], len(files))
        self.assertEqual(d["content_bytes"], sum(len(v) for v in files.values()))
        self.assertIn(".js", d["by_ext"])
        self.assertTrue(d["largest"])

    def test_bad_magic(self):
        bad = os.path.join(self.tmp, "bad.asar")
        with open(bad, "wb") as f:
            f.write(b"\x09\x00\x00\x00" + b"\x00" * 8)
        with self.assertRaises(asar.AsarError):
            asar.read_archive(bad)


@unittest.skipUnless(os.path.isfile(QQ_ASAR), "本机无 QQ NT application.asar")
class TestRealQQAsar(unittest.TestCase):
    def test_read_real_archive(self):
        files = asar.list_files(QQ_ASAR)
        self.assertGreater(len(files), 100, "真实 asar 文件数异常偏少")
        # 抽取一个内部文本文件读取，验证偏移计算正确
        target = next((p for p in files if p.endswith(".json")), None)
        self.assertIsNotNone(target)
        data = asar.read_file(QQ_ASAR, target)
        self.assertGreater(len(data), 0)


if __name__ == "__main__":
    unittest.main()