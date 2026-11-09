# -*- coding: utf-8 -*-
"""字体元数据提取（T2 实现 · 迁移自 poc/poc_scan.py extract_meta）。"""
from __future__ import annotations

from pathlib import Path

from fontTools.ttLib import TTFont


def decode_fs_type(fs) -> str:
    """OS/2 fsType 位掩码解码（OpenType 规范）。"""
    if fs is None:
        return "unknown"
    if fs & 0x0002:
        return "restricted(禁止嵌入)"
    if fs & 0x0004:
        return "preview_print(预览打印)"
    if fs & 0x0008:
        return "editable(可编辑嵌入)"
    if fs == 0:
        return "allowed(无限制)"
    return f"other(0x{fs:04x})"


def extract_metadata(path: Path) -> dict:
    """提取 OpenType name 表 + OS/2 fsType。

    parse_status 为技术维度（ok / unsupported_eot / error:xxx），
    **不产生任何版权结论**（版权判定在 analyze_risks）。
    """
    rec: dict = {"parse_status": "ok"}
    ext = path.suffix.lower()
    if ext == ".eot":
        rec["parse_status"] = "unsupported_eot"
        return rec
    try:
        font = TTFont(str(path), fontNumber=0, lazy=True)
        name = font["name"]

        def n(i: int):
            v = name.getDebugName(i)
            return v.strip() if v else None

        rec.update({
            "family": n(1), "subfamily": n(2), "full_name": n(4),
            "ps_name": n(6), "version": n(5),
            "copyright": n(0), "trademark": n(7), "manufacturer": n(8),
            "designer": n(9), "vendor_url": n(11),
            "license_text": n(13), "license_url": n(14),
        })
        if "OS/2" in font:
            fs = int(font["OS/2"].fsType)
            rec["fs_type"] = fs
            rec["embedding"] = decode_fs_type(fs)
        else:
            rec["fs_type"] = None
            rec["embedding"] = "unknown"
        font.close()
    except Exception as e:  # noqa: BLE001 损坏文件如实标注
        rec["parse_status"] = f"error:{e.__class__.__name__}"
    return rec
