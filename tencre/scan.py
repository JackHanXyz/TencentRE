# -*- coding: utf-8 -*-
"""静态线索扫描。

面向逆向的“粗筛”工具：在客户端的 JS / 配置 / 文本资源里找出与协议、加密、
密钥相关的线索，缩小后续人工分析的搜索范围。支持普通目录，也支持直接扫描
asar 归档（无需解包落盘）。

只做正则匹配与上下文摘录，不执行任何被扫描的内容。
"""

import os
import re

__all__ = ["PATTERNS", "scan_text", "scan_file", "scan_dir", "scan_asar", "Hit"]

# (类别, 说明, 正则)。正则均用于 ASCII 文本，避免回溯爆炸。
PATTERNS = [
    ("url", "网络地址", re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,200}")),
    ("crypto", "加密算法/接口", re.compile(
        r"\b(AES|DES|RSA|HMAC|SHA1|SHA256|SHA512|MD5|TEA|XTEA|XXTEA|RC4|"
        r"encrypt|decrypt|sign|signature|salt|iv)\b", re.IGNORECASE)),
    ("secret", "疑似密钥/口令关键字", re.compile(
        r"\b(secret|apikey|api_key|access_token|privatekey|private_key|"
        r"passwd|password|passphrase|appkey|app_key)\b", re.IGNORECASE)),
    ("hex", "长十六进制串", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
    ("b64", "疑似 Base64 大块", re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")),
]


class Hit(object):
    """一条扫描命中。"""

    __slots__ = ("kind", "desc", "file", "line", "text")

    def __init__(self, kind, desc, file, line, text):
        self.kind = kind
        self.desc = desc
        self.file = file
        self.line = line
        self.text = text

    def __repr__(self):
        return "<Hit %s %s:%s %s>" % (self.kind, self.file, self.line, self.text)


def scan_text(text, filename="<memory>", kinds=None):
    """扫描一段文本，产出 Hit 列表。"""
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for kind, desc, rx in PATTERNS:
            if kinds and kind not in kinds:
                continue
            m = rx.search(line)
            if m:
                snippet = m.group(0)
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."
                hits.append(Hit(kind, desc, filename, lineno, snippet))
    return hits


def scan_file(path, kinds=None, max_bytes=8 * 1024 * 1024, encoding="utf-8"):
    """扫描单个文本文件。超大或非文本文件会被跳过（返回空列表）。"""
    try:
        if os.path.getsize(path) > max_bytes:
            return []
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return []
    if b"\x00" in raw[:4096]:          # 简单判定为二进制
        return []
    try:
        text = raw.decode(encoding, "ignore")
    except Exception:
        return []
    return scan_text(text, filename=path, kinds=kinds)


def scan_dir(root, kinds=None, exts=None, max_bytes=8 * 1024 * 1024):
    """递归扫描目录。exts 为扩展名白名单（如 {'.js', '.json'}），None 表示全部。"""
    hits = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if exts and os.path.splitext(name)[1].lower() not in exts:
                continue
            hits.extend(scan_file(os.path.join(dirpath, name), kinds=kinds, max_bytes=max_bytes))
    return hits


def scan_asar(archive, kinds=None, max_bytes=8 * 1024 * 1024):
    """直接扫描 asar 归档内的文本条目，无需解包落盘。"""
    from . import asar as _asar

    header, content_offset = _asar.read_archive(archive)
    hits = []
    with open(archive, "rb") as f:
        for path, info in _asar.iter_entries(header):
            if info.get("unpacked"):
                continue
            size = int(info["size"])
            if size > max_bytes:
                continue
            f.seek(content_offset + int(info["offset"]))
            raw = f.read(size)
            if b"\x00" in raw[:4096]:
                continue
            try:
                text = raw.decode("utf-8", "ignore")
            except Exception:
                continue
            hits.extend(scan_text(text, filename=path, kinds=kinds))
    return hits


def summarize(hits):
    """按类别统计命中数。"""
    counts = {}
    for h in hits:
        counts[h.kind] = counts.get(h.kind, 0) + 1
    return counts