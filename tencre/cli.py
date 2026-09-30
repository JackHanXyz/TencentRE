# -*- coding: utf-8 -*-
"""TencentRE 命令行入口。

用法示例：
    python -m tencre tea enc --key 1234567890abcdef --text hello --hex
    python -m tencre tea dec --key 1234567890abcdef --in cipher.bin --out plain.bin
    python -m tencre wxdat ./Image --out ./out
    python -m tencre asar list application.asar
    python -m tencre asar extract application.asar ./app_out
    python -m tencre asar pack ./app_out repacked.asar
    python -m tencre scan ./app_out --kind url --kind crypto
"""

import argparse
import base64
import hashlib
import os
import sys

from . import __version__, asar, scan, tea, wxdat


def _parse_key(raw):
    """把命令行密钥解析为 16 字节。32 位十六进制按 hex 解析，否则取 ASCII。"""
    if raw is None:
        raise SystemExit("缺少密钥（--key）")
    s = raw.strip()
    if len(s) == 32:
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
    b = s.encode("utf-8")
    if len(b) != 16:
        raise SystemExit("密钥需为 16 字节 ASCII 或 32 位十六进制，当前 %d 字节" % len(b))
    return b


def _cipher_enc(args):
    """密文侧的编码：raw / hex / b64，默认 hex。"""
    if getattr(args, "raw", False):
        return "raw"
    if getattr(args, "b64", False):
        return "b64"
    return "hex"


def _encode(data, enc):
    if enc == "hex":
        return data.hex().encode("ascii")
    if enc == "b64":
        return base64.b64encode(data)
    return data


def _decode(blob, enc):
    if enc == "hex":
        return bytes.fromhex(blob.decode("ascii").strip())
    if enc == "b64":
        return base64.b64decode(blob)
    return blob


def _read_plaintext(args):
    """enc 的明文输入：--text 按 UTF-8，--in 读原始字节，否则 stdin。"""
    if args.text is not None:
        return args.text.encode("utf-8")
    if args.infile:
        with open(args.infile, "rb") as f:
            return f.read()
    return sys.stdin.buffer.read()


def _read_cipher(args):
    """dec 的密文输入，按密文侧编码解析。"""
    if args.text is not None:
        blob = args.text.encode("utf-8")
    elif args.infile:
        with open(args.infile, "rb") as f:
            blob = f.read()
    else:
        blob = sys.stdin.buffer.read()
    return _decode(blob, _cipher_enc(args))


def _emit(args, blob):
    if args.out:
        with open(args.out, "wb") as f:
            f.write(blob)
        print("[+] 已写入 %s（%d 字节）" % (args.out, len(blob)))
    else:
        sys.stdout.buffer.write(blob)
        sys.stdout.buffer.write(b"\n")


def _randfunc_from(args):
    if getattr(args, "seed", None) is None:
        return None
    seed = args.seed.encode("utf-8")
    counter = {"n": 0}

    def rnd(n):
        counter["n"] += 1
        h = hashlib.sha256(seed + b"|" + str(counter["n"]).encode()).digest()
        return h[:n]

    return rnd


def cmd_tea(args):
    key = _parse_key(args.key)
    if args.action == "enc":
        out = tea.qq_encrypt(_read_plaintext(args), key, randfunc=_randfunc_from(args))
        _emit(args, _encode(out, _cipher_enc(args)))
    else:
        out = tea.qq_decrypt(_read_cipher(args), key)
        if args.out:
            _emit(args, out)
        else:
            try:
                sys.stdout.write(out.decode("utf-8") + "\n")
            except UnicodeDecodeError:
                sys.stdout.buffer.write(out + b"\n")
    return 0


def cmd_wxdat(args):
    target = args.path
    if os.path.isdir(target):
        stats = wxdat.decrypt_tree(target, outdir=args.out,
                                   keep_structure=not args.flat, verbose=not args.quiet)
        print("[+] 共 %d 个 .dat：成功 %d，失败 %d" % (stats["total"], stats["ok"], stats["fail"]))
        return 0 if stats["fail"] == 0 else 1

    if args.brute:
        with open(target, "rb") as f:
            key, ext = wxdat.brute_key(f.read())
        print("[*] 暴力探测：key=%s ext=%s"
              % ("0x%02X" % key if key is not None else None, ext))
    out, ext, key = wxdat.decrypt_file(target, dst=args.out, verbose=not args.quiet)
    print("[+] %s -> %s (ext=%s, xor_key=0x%02X)" % (target, out, ext, key))
    return 0


def cmd_asar(args):
    if args.action == "list":
        files = asar.list_files(args.archive)
        for p in files:
            print(p)
        print("[+] 共 %d 个文件" % len(files))
    elif args.action == "extract":
        n = asar.extract_all(args.archive, args.dest)
        print("[+] 已解包 %d 个文件到 %s" % (n, args.dest))
    elif args.action == "cat":
        data = asar.read_file(args.archive, args.entry)
        sys.stdout.buffer.write(data)
    elif args.action == "pack":
        n = asar.pack(args.src, args.out)
        print("[+] 已打包 %d 个文件到 %s" % (n, args.out))
    elif args.action == "verify":
        def on_fail(path, expect, actual):
            print("  [不一致] %s 期望 %s 实际 %s" % (path, expect[:16], actual[:16]))

        ok, fail, skipped = asar.verify_integrity(args.archive, on_fail=on_fail)
        print("[+] 完整性校验：通过 %d，失败 %d，跳过 %d（无 integrity 字段）" % (ok, fail, skipped))
        return 1 if fail else 0
    return 0


def cmd_scan(args):
    kinds = set(args.kind) if args.kind else None
    if args.asar:
        hits = scan.scan_asar(args.path, kinds=kinds)
    elif os.path.isdir(args.path):
        exts = set(args.ext) if args.ext else None
        hits = scan.scan_dir(args.path, kinds=kinds, exts=exts)
    else:
        hits = scan.scan_file(args.path, kinds=kinds)

    for h in hits:
        print("%-7s %s:%d  %s" % (h.kind, h.file, h.line, h.text))
    counts = scan.summarize(hits)
    print("[+] 命中 %d 条：%s" % (len(hits),
          ", ".join("%s=%d" % (k, v) for k, v in sorted(counts.items())) or "无"))
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="tencre", description="TencentRE —— 腾讯客户端逆向分析工具集")
    p.add_argument("--version", action="version", version="TencentRE %s" % __version__)
    sub = p.add_subparsers(dest="command", required=True)

    # tea
    t = sub.add_parser("tea", help="QQ TEA 加解密")
    t.add_argument("action", choices=["enc", "dec"])
    t.add_argument("--key", required=True, help="16 字节 ASCII 或 32 位十六进制")
    t.add_argument("--text", help="直接给定字符串输入")
    t.add_argument("--in", dest="infile", help="输入文件")
    t.add_argument("--out", help="输出文件；enc 未给定时输出到 stdout")
    t.add_argument("--hex", action="store_true", help="密文侧按十六进制（默认）")
    t.add_argument("--b64", action="store_true", help="密文侧按 Base64")
    t.add_argument("--raw", action="store_true", help="密文侧按原始字节")
    t.add_argument("--seed", help="确定性随机种子（便于复现密文）")
    t.set_defaults(func=cmd_tea)

    # wxdat
    w = sub.add_parser("wxdat", help="微信 PC 端 .dat 图片解密")
    w.add_argument("path", help=".dat 文件或包含 .dat 的目录")
    w.add_argument("--out", help="输出文件 / 输出目录")
    w.add_argument("--flat", action="store_true", help="目录模式下不保留子目录层级")
    w.add_argument("--brute", action="store_true", help="单文件模式下额外打印暴力探测结果")
    w.add_argument("--quiet", action="store_true")
    w.set_defaults(func=cmd_wxdat)

    # asar
    a = sub.add_parser("asar", help="Electron asar 归档读写")
    a.add_argument("action", choices=["list", "extract", "cat", "pack", "verify"])
    a.add_argument("archive", nargs="?", help="asar 文件（list/extract/cat）")
    a.add_argument("src", nargs="?", help="源目录（pack）")
    a.add_argument("--dest", help="解包目标目录（extract）")
    a.add_argument("--entry", help="归档内路径（cat）")
    a.add_argument("--out", help="输出 asar 路径（pack）")
    a.set_defaults(func=cmd_asar)

    # scan
    s = sub.add_parser("scan", help="静态线索扫描")
    s.add_argument("path", help="目录 / 文件 / asar")
    s.add_argument("--asar", action="store_true", help="把 path 当作 asar 归档扫描")
    s.add_argument("--kind", action="append", help="限定类别：url/crypto/secret/hex/b64")
    s.add_argument("--ext", action="append", help="限定扩展名，如 --ext .js")
    s.set_defaults(func=cmd_scan)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())