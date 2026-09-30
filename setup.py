# -*- coding: utf-8 -*-
"""TencentRE 安装脚本。

安装（可选）：pip install .
安装后可用 `tencre` 命令；未安装时用 `python -m tencre`。
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="tencre",
    version="1.0.0",
    description="腾讯客户端逆向分析工具集：QQ TEA / 微信 .dat / Electron asar / 静态线索扫描",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=("tests", "tools")),
    python_requires=">=3.6",
    entry_points={"console_scripts": ["tencre=tencre.cli:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)