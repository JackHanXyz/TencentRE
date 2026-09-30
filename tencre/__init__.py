# -*- coding: utf-8 -*-
"""TencentRE —— 腾讯客户端逆向分析工具集。

零第三方依赖（仅标准库），面向 QQ / 微信 / Electron 系客户端（QQ NT）的
密码学与文件格式逆向研究。

子模块：
    tea     QQ TEA（OICQ TEA）加解密
    wxdat   微信 PC 端 .dat 图片解密
    asar    Electron asar 归档读写（QQ NT application.asar）
    scan    静态线索扫描（从解包资源里找协议 / 密钥线索）
"""

__version__ = "1.0.0"
__all__ = ["tea", "wxdat", "asar", "scan"]