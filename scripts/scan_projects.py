# -*- coding: utf-8 -*-
"""项目文件遍历（T2 实现 · 迁移自 poc/poc_scan.py iter_files）。"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator


def iter_files(root: Path, exclude_dirs: set[str]) -> Iterator[Path]:
    """递归遍历仓库文件，跳过排除目录（目录名精确匹配）。"""
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in exclude_dirs for part in p.parts):
            continue
        yield p


def inventory(root: Path, exclude_dirs: set[str]) -> list[str]:
    """文件清单（posix 相对路径），供许可证分类与覆盖率统计使用。"""
    return [p.relative_to(root).as_posix() for p in iter_files(root, exclude_dirs)]


def build_excludes(cfg: dict) -> set[str]:
    """由 scanner.yaml 组装排除集合：
    基础 exclude_dirs + （scan_dependencies=false 时）exclude_dirs_when_deps_off。"""
    excl = set(cfg.get("exclude_dirs") or [])
    if not cfg.get("general", {}).get("scan_dependencies", False):
        excl |= set(cfg.get("exclude_dirs_when_deps_off") or [])
    return excl
