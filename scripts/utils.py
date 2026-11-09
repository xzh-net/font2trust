# -*- coding: utf-8 -*-
"""公共工具：配置加载（含环境变量插值）、日志、哈希、路径。

配置插值语法（详见 docs/实施方案.md §8）:
    ${VAR}          取环境变量，缺失则报错
    ${VAR:-default} 取环境变量，缺失用默认值
敏感信息（GitLab token / SMTP 密码）只写环境变量名，不落盘。
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import sys
from pathlib import Path

import yaml

# 项目根目录（scripts/ 的上一级）
PROJECT_ROOT = Path(__file__).resolve().parent.parent

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}")


def _expand_env(text: str) -> str:
    def repl(m: re.Match) -> str:
        name, has_default, default = m.group(1), m.group(2), m.group(3)
        val = os.environ.get(name)
        if val is not None:
            return val
        if has_default is not None:
            return default
        raise KeyError(f"环境变量 {name} 未设置且无默认值")

    return _ENV_RE.sub(repl, text)


def load_config(path: str | Path) -> dict:
    """加载 YAML 配置并做 ${ENV:-default} 插值。"""
    p = Path(path)
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    if not p.exists():
        raise FileNotFoundError(f"配置文件不存在: {p}")
    raw = p.read_text(encoding="utf-8")
    data = yaml.safe_load(_expand_env(raw))
    return data or {}


def setup_logging(level: str = "INFO", log_file: str | Path | None = None) -> logging.Logger:
    """控制台 + 可选文件日志。"""
    logger = logging.getLogger("font_compliance")
    logger.setLevel(getattr(logging, (level or "INFO").upper(), logging.INFO))
    for h in logger.handlers[:]:        # 关闭旧句柄(防文件句柄泄漏/目录锁)
        h.close()
    logger.handlers.clear()
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    if log_file:
        lp = Path(log_file)
        if not lp.is_absolute():
            lp = PROJECT_ROOT / lp
        lp.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(lp, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


def sha256_file(path: str | Path) -> str:
    """文件 SHA256（字体身份与历史对比主键）。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def norm_name(s: str | None) -> str:
    """名称归一化（字体系列匹配用）：仅保留小写字母数字。"""
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def rel_posix(path: Path, root: Path) -> str:
    """相对路径，统一 posix 分隔符（跨平台结果一致）。"""
    return path.relative_to(root).as_posix()
