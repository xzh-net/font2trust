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
    """控制台 + 可选文件日志。

    - Windows 控制台按 UTF-8 输出(修复中文乱码)
    - 文件日志 mode="w": current/run.log 只保留**本次**运行(批次日志随归档留存)
    """
    try:                                  # 控制台编码: GBK 终端下中文/路径乱码
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:                     # noqa: BLE001 重定向流不可重配则忽略
        pass
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
        fh = logging.FileHandler(lp, encoding="utf-8", mode="w")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


# URL 凭证 userinfo: //user:pass@ 或 //token@
_CRED_RE = re.compile(r"//[^/\s:@]+(?::[^/\s@]*)?@")
_TOKEN_RE = re.compile(r"\b(?:glpat|gldt|glcb|glrt)-[A-Za-z0-9_\-]+")


def redact_credentials(text: str) -> tuple[str, int]:
    """把任意文本中的 URL 凭证与 GitLab token 替换为 ***，返回 (文本, 命中数)。

    用于产物落盘前的兜底脱敏（P0-2 缺陷修复）：报告/归档可能被分发，
    任何写入磁盘的文本都不得含凭证。
    """
    text, n1 = _CRED_RE.subn("//***@", text or "")
    text, n2 = _TOKEN_RE.subn("***", text)
    return text, n1 + n2


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
