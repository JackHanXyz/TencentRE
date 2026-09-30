# -*- coding: utf-8 -*-
"""QQ TEA 自测：分组往返、QQ 分帧往返、长度规则、确定性向量。"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tencre import tea  # noqa: E402

KEY = b"1234567890abcdef"


def _seeded_rand(seed=b"vector"):
    counter = {"n": 0}

    def rnd(n):
        counter["n"] += 1
        return hashlib.sha256(seed + b"|" + str(counter["n"]).encode()).digest()[:n]

    return rnd


class TestTeaBlock(unittest.TestCase):
    def test_block_roundtrip(self):
        block = bytes(range(8))
        enc = tea.tea_encrypt_block(block, KEY)
        self.assertEqual(len(enc), 8)
        self.assertNotEqual(enc, block)
        self.assertEqual(tea.tea_decrypt_block(enc, KEY), block)

    def test_block_known_constant(self):
        # 16 轮 TEA 的确定性回归基线（锁定实现，防止无意改动）
        key0 = b"\x00" * 16
        enc = tea.tea_encrypt_block(b"\x00" * 8, key0)
        self.assertEqual(enc.hex(), "a889f798182d8083")
        self.assertEqual(tea.tea_decrypt_block(enc, key0), b"\x00" * 8)

    def test_bad_key_len(self):
        with self.assertRaises(tea.QQTEAError):
            tea.tea_encrypt_block(b"\x00" * 8, b"short")


class TestQQTEA(unittest.TestCase):
    def test_roundtrip_sizes(self):
        for n in list(range(0, 40)) + [100, 255, 1000, 4096]:
            data = os.urandom(n)
            ct = tea.qq_encrypt(data, KEY)
            self.assertEqual(len(ct) % 8, 0, "密文长度应为 8 的倍数")
            self.assertEqual(len(ct), n + tea._pad_count(n) + 10)
            self.assertEqual(tea.qq_decrypt(ct, KEY), data, "长度 %d 往返失败" % n)

    def test_deterministic_vector(self):
        data = b"QQTEA-test-vector"
        ct1 = tea.qq_encrypt(data, KEY, randfunc=_seeded_rand(b"v1"))
        ct2 = tea.qq_encrypt(data, KEY, randfunc=_seeded_rand(b"v1"))
        self.assertEqual(ct1, ct2, "相同随机源应得到相同密文")
        self.assertEqual(tea.qq_decrypt(ct1, KEY), data)

    def test_random_padding_varies(self):
        data = b"same plaintext"
        self.assertNotEqual(tea.qq_encrypt(data, KEY), tea.qq_encrypt(data, KEY),
                            "随机填充应使两次密文不同")

    def test_bad_cipher(self):
        with self.assertRaises(tea.QQTEAError):
            tea.qq_decrypt(b"\x00" * 7, KEY)


if __name__ == "__main__":
    unittest.main()