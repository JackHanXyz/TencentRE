# -*- coding: utf-8 -*-
"""QQ TEA（OICQ TEA）加解密。

实现依据：腾讯公开的登录页 JS（c_login_2.js）中 `TEA` 对象所揭示的算法，
即「填充 -> QQCBC 交织 -> 16 轮标准 TEA」。这是一个独立、可读的重实现，
不包含任何私有常量。

要点（与标准 TEA / CBC 的差异）：
    * 16 轮（标准 TEA 通常 32 轮），delta = 0x9E3779B9；
    * 结果按网络序（大端）存取；
    * 明文先做填充：附加 1 字节长度标识 + 随机数 + 2 字节随机 + 明文 + 7 字节 0；
    * 交织（`r()`）在标准 CBC 之外多做一次异或：
        x_i = b_i XOR c_{i-1}
        c_i = E(x_i) XOR x_{i-1}
      （i=0 时 c_{-1}=0、x_{-1}=0）
"""

import os

__all__ = ["tea_encrypt_block", "tea_decrypt_block", "qq_encrypt", "qq_decrypt", "QQTEAError"]

MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9
ROUNDS = 16


class QQTEAError(ValueError):
    """QQ TEA 加解密相关错误。"""


def _key_words(key):
    if len(key) != 16:
        raise QQTEAError("TEA 密钥必须为 16 字节，当前为 %d 字节" % len(key))
    return [int.from_bytes(key[i * 4:i * 4 + 4], "big") for i in range(4)]


def tea_encrypt_block(block8, key):
    """加密单个 8 字节分组（大端）。block8/key 为 bytes，返回 8 字节 bytes。"""
    if len(block8) != 8:
        raise QQTEAError("TEA 分组必须为 8 字节")
    k = _key_words(key)
    v0 = int.from_bytes(block8[0:4], "big")
    v1 = int.from_bytes(block8[4:8], "big")
    total = 0
    for _ in range(ROUNDS):
        total = (total + DELTA) & MASK
        v0 = (v0 + ((((v1 << 4) & MASK) + k[0]) ^ (v1 + total) ^ ((v1 >> 5) + k[1]))) & MASK
        v1 = (v1 + ((((v0 << 4) & MASK) + k[2]) ^ (v0 + total) ^ ((v0 >> 5) + k[3]))) & MASK
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def tea_decrypt_block(block8, key):
    """解密单个 8 字节分组（大端）。"""
    if len(block8) != 8:
        raise QQTEAError("TEA 分组必须为 8 字节")
    k = _key_words(key)
    v0 = int.from_bytes(block8[0:4], "big")
    v1 = int.from_bytes(block8[4:8], "big")
    total = (DELTA * ROUNDS) & MASK
    for _ in range(ROUNDS):
        v1 = (v1 - ((((v0 << 4) & MASK) + k[2]) ^ (v0 + total) ^ ((v0 >> 5) + k[3]))) & MASK
        v0 = (v0 - ((((v1 << 4) & MASK) + k[0]) ^ (v1 + total) ^ ((v1 >> 5) + k[1]))) & MASK
        total = (total - DELTA) & MASK
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def _pad_count(n):
    """计算填充字节数 a，使 (n + a + 10) 为 8 的倍数。"""
    a = (n + 10) % 8
    if a != 0:
        a = 8 - a
    return a


def qq_encrypt(data, key, randfunc=None):
    """QQ TEA 加密。

    data: bytes 明文；key: 16 字节密钥。
    randfunc(n)->bytes 可注入确定性随机源，便于生成可复现的测试向量。
    """
    if randfunc is None:
        def randfunc(n):
            return os.urandom(n)

    data = bytes(data)
    n = len(data)
    pad = _pad_count(n)
    out = bytearray(n + pad + 10)
    h = bytearray(8)          # 当前明文分组（交织用）
    z = bytearray(8)          # 交织 IV / 上一明文块 x_{i-1}
    state = {"A": 0, "w": 0, "first": True, "idx": 0}

    h[0] = (randfunc(1)[0] & 0xF8) | pad          # 低 3 位存填充数
    for c in range(1, pad + 1):
        h[c] = randfunc(1)[0]
    state["idx"] = pad + 1

    def r():
        A, w, idx, first = state["A"], state["w"], state["idx"], state["first"]
        for b in range(8):
            h[b] ^= z[b] if first else out[w + b]
        enc = tea_encrypt_block(bytes(h), key)
        for b in range(8):
            out[A + b] = enc[b] ^ z[b]             # 比标准 CBC 多一次异或
            z[b] = h[b]
        state["w"] = A
        state["A"] = A + 8
        state["idx"] = 0
        state["first"] = False

    # 2 字节随机填充
    e = 1
    while e <= 2:
        if state["idx"] < 8:
            h[state["idx"]] = randfunc(1)[0]
            state["idx"] += 1
            e += 1
        if state["idx"] == 8:
            r()

    # 明文
    ci = 0
    rem = n
    while rem > 0:
        if state["idx"] < 8:
            h[state["idx"]] = data[ci]
            state["idx"] += 1
            ci += 1
            rem -= 1
        if state["idx"] == 8:
            r()

    # 7 字节 0 收尾
    e = 1
    while e <= 7:
        if state["idx"] < 8:
            h[state["idx"]] = 0
            state["idx"] += 1
            e += 1
        if state["idx"] == 8:
            r()

    return bytes(out)


def qq_decrypt(cipher, key):
    """QQ TEA 解密，返回去掉填充后的明文。"""
    cipher = bytes(cipher)
    if len(cipher) < 16 or len(cipher) % 8 != 0:
        raise QQTEAError("密文长度必须为 8 的倍数且 >= 16，当前为 %d" % len(cipher))

    nblocks = len(cipher) // 8
    padded = bytearray(len(cipher))
    x_prev = None
    c_prev = None
    for i in range(nblocks):
        c_i = cipher[i * 8:(i + 1) * 8]
        if i == 0:
            x_i = tea_decrypt_block(c_i, key)              # x_0 = D(c_0)
        else:
            mix = bytes(a ^ b for a, b in zip(c_i, x_prev))  # c_i XOR x_{i-1}
            x_i = tea_decrypt_block(mix, key)
        b_i = x_i if i == 0 else bytes(a ^ b for a, b in zip(x_i, c_prev))
        padded[i * 8:(i + 1) * 8] = b_i
        x_prev = x_i
        c_prev = c_i

    pad = padded[0] & 0x07
    body = len(padded) - pad - 10
    if body < 0:
        raise QQTEAError("解密结果长度异常，密钥可能不正确")
    start = pad + 3
    return bytes(padded[start:start + body])