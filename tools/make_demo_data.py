# -*- coding: utf-8 -*-
"""生成演示数据，便于在没有真实客户端数据时验证各模块。

用法：
    python tools/make_demo_data.py [输出目录]        # 默认 build/demo

会生成：
    build/demo/wechat_dat/*.dat      伪造的“微信图片 .dat”（单字节异或）
    build/demo/src_tree/...          一棵小目录树，用于打包成 asar
    build/demo/demo.asar             由 src_tree 打包而成
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tencre import asar  # noqa: E402

SAMPLES = {
    "photo_01.dat": (b"\x89PNG\r\n\x1a\n" + b"demo-png-content" * 8, 0x5A),
    "photo_02.dat": (b"\xff\xd8\xff\xe0" + b"demo-jpg-content" * 8, 0x23),
    "sticker.dat": (b"GIF89a" + b"demo-gif-content" * 8, 0xC3),
}

TREE = {
    "index.html": b"<html><body>demo</body></html>",
    "main.js": b"const url = 'https://api.example.com/v1/sign';",
    "static/app.js": b"function hmac(k, d) {} /* AES-256 */",
    "static/data.bin": bytes(range(256)),
}


def main(outdir):
    dat_dir = os.path.join(outdir, "wechat_dat")
    os.makedirs(dat_dir, exist_ok=True)
    for name, (plain, key) in SAMPLES.items():
        with open(os.path.join(dat_dir, name), "wb") as f:
            f.write(bytes(b ^ key for b in plain))

    src = os.path.join(outdir, "src_tree")
    for rel, data in TREE.items():
        p = os.path.join(src, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)

    archive = os.path.join(outdir, "demo.asar")
    n = asar.pack(src, archive)

    print("[+] 演示数据已生成于 %s" % os.path.abspath(outdir))
    print("    - 微信 .dat 样例：%s" % dat_dir)
    print("    - asar 样例：%s（%d 个文件）" % (archive, n))
    print("\n验证：")
    print("    python -m tencre wxdat %s --out %s/out" % (dat_dir, outdir))
    print("    python -m tencre asar list %s" % archive)
    print("    python -m tencre scan %s --asar --kind url" % archive)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "demo"))