# -*- coding: utf-8 -*-
"""Electron asar 归档读写。

asar 是 Electron 应用打包资源用的简单归档格式（QQ NT 的
`resources/app/application.asar` 即此格式）。结构：

    [u32le = 4]                      # size pickle 的载荷长度
    [u32le = header_buf 长度]         # 头部 pickle 总长
    [header_buf]                     # pickle: [u32 payloadLen][u32 jsonLen][json][pad]
    [content...]                     # 各文件内容，偏移相对 content 起点

文件条目形如 {"size": 123, "offset": "0"}；目录条目形如 {"files": {...}}。
标记 "unpacked": true 的条目其内容不在归档里，而在同名的 `<archive>.unpacked/`
目录下。

本模块提供 list / extract / pack，纯标准库实现。
"""

import hashlib
import json
import os
import struct

__all__ = ["AsarError", "read_archive", "iter_entries", "list_files",
           "extract_all", "extract_file", "pack", "read_file", "verify_integrity"]


class AsarError(ValueError):
    """asar 读写相关错误。"""


def _u32(b):
    return struct.unpack("<I", b)[0]


def read_archive(path):
    """读取 asar 头部。

    返回 (header_dict, content_offset)。
    """
    with open(path, "rb") as f:
        head8 = f.read(8)
        if len(head8) < 8:
            raise AsarError("文件过小，不是有效的 asar：%s" % path)
        first = _u32(head8[0:4])
        if first != 4:
            raise AsarError("asar 魔数异常（期望首字段为 4，实际为 %d）" % first)
        size = _u32(head8[4:8])
        header_buf = f.read(size)
        if len(header_buf) < size:
            raise AsarError("asar 头部被截断")
    if len(header_buf) < 8:
        raise AsarError("asar 头部 pickle 过小")
    json_len = _u32(header_buf[4:8])
    json_bytes = header_buf[8:8 + json_len]
    try:
        header = json.loads(json_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise AsarError("asar 头部 JSON 解析失败：%s" % e)
    return header, 8 + size


def iter_entries(header, prefix=""):
    """递归遍历头部，产出 (路径, 条目信息)。目录不产出，仅产出文件。"""
    for name, info in header.get("files", {}).items():
        path = (prefix + "/" + name) if prefix else name
        if "files" in info:
            for item in iter_entries(info, path):
                yield item
        else:
            yield path, info


def list_files(path):
    """返回归档内所有文件路径列表。"""
    header, _ = read_archive(path)
    return [p for p, _ in iter_entries(header)]


def read_file(archive, entry):
    """读取单个文件条目的内容（支持 unpacked）。"""
    header, content_offset = read_archive(archive)
    for p, info in iter_entries(header):
        if p == entry:
            return _read_entry(archive, content_offset, info, p)
    raise AsarError("归档内不存在：%s" % entry)


def _read_entry(archive, content_offset, info, entry_path):
    if info.get("unpacked"):
        unpacked_path = os.path.join(archive + ".unpacked", *entry_path.split("/"))
        with open(unpacked_path, "rb") as f:
            return f.read()
    offset = int(info["offset"])
    size = int(info["size"])
    with open(archive, "rb") as f:
        f.seek(content_offset + offset)
        return f.read(size)


def extract_all(archive, dest):
    """把归档全部解包到 dest 目录。返回解出的文件数。"""
    header, content_offset = read_archive(archive)
    count = 0
    with open(archive, "rb") as f:
        for path, info in iter_entries(header):
            target = os.path.join(dest, *path.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if info.get("unpacked"):
                src = os.path.join(archive + ".unpacked", *path.split("/"))
                if os.path.isfile(src):
                    with open(src, "rb") as sf, open(target, "wb") as df:
                        df.write(sf.read())
                else:
                    continue
            else:
                f.seek(content_offset + int(info["offset"]))
                with open(target, "wb") as df:
                    df.write(f.read(int(info["size"])))
            count += 1
    return count


def extract_file(archive, entry, dest):
    """解出归档内单个文件到 dest 路径。"""
    header, content_offset = read_archive(archive)
    for p, info in iter_entries(header):
        if p == entry:
            data = _read_entry(archive, content_offset, info, p)
            os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(data)
            return dest
    raise AsarError("归档内不存在：%s" % entry)


def _build_header(src_dir):
    """遍历目录，构建 asar 头部与内容清单。返回 (header, [(相对路径, 绝对路径)])。"""
    entries = []

    def walk(abs_dir, rel_dir):
        node = {"files": {}}
        for name in sorted(os.listdir(abs_dir)):
            abs_path = os.path.join(abs_dir, name)
            rel_path = (rel_dir + "/" + name) if rel_dir else name
            if os.path.isdir(abs_path):
                node["files"][name] = walk(abs_path, rel_path)
            else:
                entries.append((rel_path, abs_path))
                node["files"][name] = {"size": os.path.getsize(abs_path)}
        return node

    root = walk(src_dir, "")
    offset = 0
    for rel_path, abs_path in entries:
        size = os.path.getsize(abs_path)
        # 定位该文件在 header 里的节点，写入 offset（字符串）
        parts = rel_path.split("/")
        node = root
        for part in parts[:-1]:
            node = node["files"][part]
        node["files"][parts[-1]]["offset"] = str(offset)
        offset += size
    return root, entries


def pack(src_dir, out_archive):
    """把一个目录打包为 asar。返回写入的文件数。"""
    if not os.path.isdir(src_dir):
        raise AsarError("目录不存在：%s" % src_dir)
    header, entries = _build_header(src_dir)

    json_bytes = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    str_part = struct.pack("<I", len(json_bytes)) + json_bytes
    str_part += b"\x00" * ((4 - len(str_part) % 4) % 4)
    header_buf = struct.pack("<I", len(str_part)) + str_part
    size = len(header_buf)

    with open(out_archive, "wb") as f:
        f.write(struct.pack("<I", 4))
        f.write(struct.pack("<I", size))
        f.write(header_buf)
        for _rel, abs_path in entries:
            with open(abs_path, "rb") as sf:
                f.write(sf.read())
    return len(entries)


def verify_integrity(archive, on_fail=None):
    """按头部 integrity 字段校验每个条目的 SHA256。

    返回 (ok, fail, skipped)；fail>0 时通过 on_fail(path, 期望, 实际) 回调上报。
    """
    header, content_offset = read_archive(archive)
    ok = fail = skipped = 0
    with open(archive, "rb") as f:
        for path, info in iter_entries(header):
            integ = info.get("integrity")
            if not integ or "blocks" not in integ or info.get("unpacked"):
                skipped += 1
                continue
            f.seek(content_offset + int(info["offset"]))
            raw = f.read(int(info["size"]))
            block_size = int(integ.get("blockSize", len(raw) or 1))
            blocks = integ["blocks"]
            good = True
            for i, expect in enumerate(blocks):
                chunk = raw[i * block_size:(i + 1) * block_size]
                if hashlib.sha256(chunk).hexdigest() != expect:
                    good = False
                    if on_fail:
                        on_fail(path, expect, hashlib.sha256(chunk).hexdigest())
                    break
            if good:
                ok += 1
            else:
                fail += 1
    return ok, fail, skipped