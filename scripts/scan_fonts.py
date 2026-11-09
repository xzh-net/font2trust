# -*- coding: utf-8 -*-
"""字体文件发现（T2 实现 · 迁移自 poc/poc_scan.py scan_fonts）。"""
from __future__ import annotations

import hashlib
from pathlib import Path

from .scan_projects import iter_files


def scan_fonts(root: Path, exts: set[str], exclude_dirs: set[str]) -> list[dict]:
    """按扩展名发现字体文件，计算 SHA256（字体身份主键）。

    返回: [{"path"(posix相对路径), "ext", "size", "sha256"}]
    """
    out = []
    for p in iter_files(root, exclude_dirs):
        if p.suffix.lower() in exts:
            out.append({
                "path": p.relative_to(root).as_posix(),
                "ext": p.suffix.lower(),
                "size": p.stat().st_size,
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            })
    return out


def unique_by_sha(fonts: list[dict]) -> list[dict]:
    """按 sha256 去重（同字节文件跨目录视为同一资产）。"""
    seen, uniq = set(), []
    for f in fonts:
        if f["sha256"] not in seen:
            seen.add(f["sha256"])
            uniq.append(f)
    return uniq
