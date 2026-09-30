# -*- coding: utf-8 -*-
"""微信 PC 端 .dat 文件解密。

微信 PC 端把聊天图片逐个字节与**单个字节**异或后落盘为 .dat。密钥不在文件头里
显式保存，但可由常见图片格式的文件头反推：

    密钥 = 原文首字节 magic[0] XOR 密文首字节 dat[0]
    且满足 magic[1] XOR dat[1] == 密钥（第二字节自校验）

解密即对整个文件逐字节再异或一次（异或自反）。本模块同时支持批量目录处理与
未知密钥时的暴力探测（遍历 0..255 检查是否命中已知格式头）。
"""

import os

__all__ = ["MAGICS", "detect_key", "decrypt_dat", "decrypt_file", "decrypt_tree", "WxDatError"]

# (文件头前缀, 扩展名)。顺序影响探测优先级，长的/更特征的放前面。
MAGICS = [
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"\xff\xd8\xff", ".jpg"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"BM", ".bmp"),
    (b"II*\x00", ".tiff"),
    (b"MM\x00*", ".tiff"),
    (b"RIFF", ".webp"),
    (b"%PDF", ".pdf"),
    (b"PK\x03\x04", ".zip"),
]


class WxDatError(ValueError):
    """微信 .dat 解密相关错误。"""


def _match_magic(data, offset=0):
    """返回与 data[offset:] 匹配的 (magic, ext)，否则 None。"""
    for magic, ext in MAGICS:
        if data[offset:offset + len(magic)] == magic:
            return magic, ext
    return None


def detect_key(data):
    """由已知文件头反推异或密钥。

    返回 (key, ext, magic)；无法识别时返回 (None, None, None)。
    """
    if len(data) < 2:
        return None, None, None
    for magic, ext in MAGICS:
        if len(magic) < 2:
            continue
        key = magic[0] ^ data[0]
        # 用 magic 的其余字节自校验，避免误判
        if all((data[i] ^ key) == magic[i] for i in range(1, len(magic))):
            return key, ext, magic
    return None, None, None


def brute_key(data, min_len=16):
    """未知格式时暴力探测：遍历 0..255，返回能解出已知文件头的密钥。

    返回 (key, ext) 或 (None, None)。
    """
    if len(data) < 4:
        return None, None
    head = bytes(data[:max(min_len, 8)])
    for key in range(256):
        dec = bytes(b ^ key for b in head)
        m = _match_magic(dec)
        if m:
            return key, m[1]
    return None, None


def xor_bytes(data, key):
    return bytes(b ^ key for b in bytes(data))


def decrypt_dat(data):
    """解密一段 .dat 内容，返回 (明文 bytes, 扩展名, 密钥)。

    先按已知头反推密钥；失败则暴力探测。均失败时抛 WxDatError。
    """
    key, ext, _ = detect_key(data)
    if key is None:
        key, ext = brute_key(data)
    if key is None:
        raise WxDatError("无法识别该 .dat 的异或密钥（不是微信图片，或已损坏）")
    return xor_bytes(data, key), ext, key


def decrypt_file(src, dst=None, verbose=False):
    """解密单个 .dat 文件。

    dst 规则：
        * None           -> 在 src 同目录下生成 <同名><扩展名>
        * 已存在的目录   -> 放入该目录，用源文件名（去 .dat）+ 扩展名
        * 以 .dat 结尾   -> 替换扩展名为实际格式
        * 其它路径       -> 原样写入
    返回 (输出路径, 扩展名, 密钥)。
    """
    with open(src, "rb") as f:
        data = f.read()
    plain, ext, key = decrypt_dat(data)
    if dst is None:
        dst = os.path.splitext(src)[0] + ext
    elif os.path.isdir(dst):
        dst = os.path.join(dst, os.path.splitext(os.path.basename(src))[0] + ext)
    elif dst.lower().endswith(".dat"):
        dst = os.path.splitext(dst)[0] + ext
    with open(dst, "wb") as f:
        f.write(plain)
    if verbose:
        print("  %s -> %s  (ext=%s, xor_key=0x%02X)" % (src, dst, ext, key))
    return dst, ext, key


def decrypt_tree(root, outdir=None, keep_structure=True, verbose=True):
    """递归解密目录下所有 .dat 文件。

    outdir 为空时原地输出；否则按 keep_structure 决定是否保留子目录层级。
    返回统计字典 {"total", "ok", "fail", "results": {src: (dst, ext, key)}}。
    """
    stats = {"total": 0, "ok": 0, "fail": 0, "results": {}}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if not name.lower().endswith(".dat"):
                continue
            src = os.path.join(dirpath, name)
            stats["total"] += 1
            if outdir is None:
                dst = None
            else:
                rel = os.path.relpath(dirpath, root) if keep_structure else ""
                target_dir = os.path.join(outdir, rel) if rel not in ("", ".") else outdir
                os.makedirs(target_dir, exist_ok=True)
                dst = os.path.join(target_dir, name)       # 保留 .dat，交由 decrypt_file 替换
            try:
                out, ext, key = decrypt_file(src, dst=dst, verbose=verbose)
                stats["ok"] += 1
                stats["results"][src] = (out, ext, key)
            except (WxDatError, OSError) as e:
                stats["fail"] += 1
                if verbose:
                    print("  [跳过] %s：%s" % (src, e))
    return stats