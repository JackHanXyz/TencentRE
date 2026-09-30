# TencentRE

面向腾讯客户端（QQ / 微信 / Electron 系 QQ NT）的逆向分析工具集 —— 纯 Python 标准库，零第三方依赖。

> **TencentRE** 把逆向过程中反复用到的几件事做成顺手的小工具：还原 QQ 的 TEA 加解密、
> 批量解密微信 PC 端的 .dat 图片、读写 Electron 的 asar 归档（QQ NT 的
> `application.asar`），以及从解包资源里粗筛协议 / 加密线索。
> 目标是「一个命令解决一类重复劳动」，让注意力留给真正需要人的分析。

[![Python](https://img.shields.io/badge/python-%3E%3D3.6-3776AB.svg)](https://python.org)
[![Deps](https://img.shields.io/badge/dependencies-none-success.svg)](#)
[![tests](https://github.com/JackHanXyz/TencentRE/actions/workflows/tests.yml/badge.svg)](https://github.com/JackHanXyz/TencentRE/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> [!WARNING]
> 仅供**个人学习、安全研究与协议互操作性分析**。请在**你自己拥有或已获授权**的数据上使用。
> 请遵守所在地法律法规与相关软件的服务条款，作者不对任何滥用负责。

---

## 特性

- **零第三方依赖**：仅用 Python 标准库，`git clone` 即可运行。
- **QQ TEA 加解密**：按腾讯公开算法还原的「填充 → QQCBC 交织 → 16 轮 TEA」，加解密可往返。
- **微信 .dat 解密**：自动识别图片格式并反推异或密钥，支持单文件与整目录批量。
- **asar 读写**：列举 / 解包 / 打包 / 单文件提取 / 完整性校验，纯 Python 实现。
- **静态线索扫描**：在 JS / 配置 / 文本资源里扫 URL、加密接口、密钥关键字、长十六进制与 Base64 块。
- **自带演示数据**：一条命令生成样例，无需真实客户端数据即可跑通全部流程。

## 快速开始

```bash
git clone https://github.com/JackHanXyz/TencentRE.git
cd TencentRE

# 方式一：直接运行（无需安装）
python -m tencre --help

# 方式二：安装为命令
pip install .
tencre --help
```

生成演示数据并验证：

```bash
python tools/make_demo_data.py
python -m tencre wxdat build/demo/wechat_dat --out build/demo/out
python -m tencre asar list build/demo/demo.asar
python -m tencre scan build/demo/src_tree --kind url --kind crypto
```

跑测试：

```bash
python -m unittest discover -s tests -v
```

## 目录结构

```
TencentRE/
├── tencre/                工具集主包（纯标准库）
│   ├── tea.py                QQ TEA 加解密
│   ├── wxdat.py              微信 .dat 图片解密
│   ├── asar.py               Electron asar 读写 / 校验
│   ├── scan.py               静态线索扫描
│   └── cli.py                命令行入口
├── tests/                 单元测试（含真机 asar 校验）
├── tools/
│   └── make_demo_data.py      生成演示数据
├── setup.py
└── README.md
```

## QQ TEA（`tea`）

实现依据腾讯公开登录页 JS 中 `TEA` 对象所揭示的算法，独立重写，**不含任何私有常量**：

- 16 轮标准 TEA（`delta = 0x9E3779B9`），结果按**网络序**存取；
- 明文填充：`1 字节长度标识（低 3 位存填充数）+ 随机填充 + 2 字节随机 + 明文 + 7 字节 0`；
- 交织在标准 CBC 之外**多做一次异或**：`x_i = b_i XOR c_{i-1}`，`c_i = E(x_i) XOR x_{i-1}`。

```bash
# 加密（输出十六进制；--seed 可复现密文）
python -m tencre tea enc --key 1234567890abcdef --text "hello QQ TEA" --seed demo

# 解密
python -m tencre tea dec --key 1234567890abcdef --text <上面的十六进制>

# 密文侧可换 Base64 / 原始字节
python -m tencre tea enc --key 1234567890abcdef --in plain.bin --b64 --out cipher.txt
python -m tencre tea dec --key 1234567890abcdef --in cipher.bin --raw --out plain.bin
```

> 密钥为 16 字节：命令行里写 16 个 ASCII 字符，或 32 位十六进制。

## 微信 .dat 解密（`wxdat`）

微信 PC 端把图片逐字节与**单个字节**异或后落盘。密钥由文件头反推：

```
密钥 = 图片头字节 magic[0] XOR 密文首字节 dat[0]，且 magic[1] XOR dat[1] == 密钥
```

解密即再异或一次（异或自反）；无法由已知头反推时回退到遍历 0..255 的暴力探测。

```bash
# 单文件
python -m tencre wxdat 1a2b3c.dat

# 整目录批量（默认保留子目录层级）
python -m tencre wxdat "D:\...\FileStorage\Image" --out ./out
```

内置识别的格式：PNG / JPEG / GIF / BMP / TIFF / WebP / PDF / ZIP。

## asar 读写（`asar`）

Electron 应用（含 QQ NT）把资源打包为 asar。本模块支持列举、解包、打包、取单文件与按头部
`integrity` 做 SHA256 校验。

```bash
python -m tencre asar list application.asar
python -m tencre asar extract application.asar ./app_out
python -m tencre asar cat application.asar path/to/file.json --out file.json
python -m tencre asar pack ./app_out repacked.asar
python -m tencre asar info application.asar
python -m tencre asar verify application.asar
```

**实测结论（本机 QQ NT 9.9.35）**：`application.asar` 能被正确解析；对全部 **1438** 个带
`integrity` 的条目做 SHA256 校验，**1438 通过 / 0 失败**，说明偏移与内容解析字节级正确。
同时发现：该 asar 内各 `.js` 条目是**密文**（`size` 很小、内容为随机字节，`integrity` 是对
密文做的），即 QQ NT 对其 JS 资源另有加密，需在运行时由原生模块解密 —— 这属于本工具范围之外，
在此如实说明，避免误导。

## 静态线索扫描（`scan`）

在客户端资源里做「粗筛」，缩小人工分析范围。只做正则匹配与上下文摘录，**不执行**被扫描内容。

```bash
python -m tencre scan ./app_out --kind url --kind crypto --ext .js
python -m tencre scan application.asar --asar --kind secret
```

类别：`url`（网络地址）、`crypto`（加密算法/接口）、`secret`（密钥/口令关键字）、
`hex`（长十六进制串）、`b64`（疑似 Base64 大块）。

## 测试

`tests/` 覆盖 TEA 分组与分帧往返、微信 .dat 密钥反推与批量、asar 打包/列举/解包往返与
错误处理、扫描匹配；若本机存在 QQ NT 的 `application.asar`，还会自动做一次真机读取校验
（不存在则跳过）。

```bash
python -m unittest discover -s tests -v
```

## 免责声明

本项目按「现状」提供，不附带任何明示或暗示的担保。请仅在你拥有或已获授权的数据上使用，
并自行确保使用方式符合所在地法律法规及所涉软件的服务条款。作者不对因使用本项目造成的
任何直接或间接损失负责。

若你是相关权利人并认为本项目不妥，请提 issue，我们会配合处理。

## 许可

[MIT](LICENSE) — 可自由使用与修改。