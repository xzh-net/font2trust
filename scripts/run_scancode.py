# -*- coding: utf-8 -*-
"""ScanCode 许可证扫描封装（T4 实现 · 迁移自 poc/poc_scan.py run_scancode）。

设计要点:
    - 可选组件: 找不到 scancode -> status=skipped, 不中断流水线
    - 逐文件表达式 file_licenses: 供 T5 与字体元数据交叉验证(识别 != 核实)
    - 路径规范化: 去掉 scancode 自动加的根目录前缀, 统一 posix 分隔符
    - 复用模式: 已有输出 json 且解析成功则跳过重扫(迭代调试用)
    - 安装: pip install scancode-toolkit（离线环境用 wheels 包）
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("font_compliance")


def find_scancode() -> str | None:
    """定位 scancode 可执行文件: 环境变量 SCANCODE_PATH > PATH > 同 Python Scripts 目录。"""
    exe = os.environ.get("SCANCODE_PATH") or shutil.which("scancode")
    if exe:
        return exe
    cand = Path(sys.executable).parent / (
        "scancode.exe" if os.name == "nt" else "scancode")
    return str(cand) if cand.exists() else None


def parse_scancode_json(out_json: Path, root: Path) -> dict:
    """解析 ScanCode 输出: 汇总统计 + 逐文件表达式。"""
    try:
        data = json.loads(out_json.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return {"status": "failed", "reason": f"JSON 解析失败: {e}",
                "file_licenses": {}}
    prefix = root.name + "/"
    licenses: dict[str, int] = {}
    copyrights: list[str] = []
    file_licenses: dict[str, str] = {}
    for res in data.get("files", []):
        if res.get("type") == "directory":
            continue
        expr = res.get("detected_license_expression") or res.get("license_expression")
        rel = (res.get("path") or "").replace("\\", "/")
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
        # 回退剥离: 缓存生成时的根目录名与当前不一致(如 fixture 改名)时,
        # 按"剥掉首段后路径在 root 下真实存在"纠正(不依赖目录名)
        if not (root / rel).exists() and "/" in rel:
            tail = rel.split("/", 1)[1]
            if (root / tail).exists():
                rel = tail
        if expr:
            file_licenses[rel] = expr
            licenses[expr] = licenses.get(expr, 0) + 1
        for c in res.get("copyrights", [])[:1]:
            statement = c.get("value") if isinstance(c, dict) else str(c)
            if statement and statement not in copyrights:
                copyrights.append(statement)
    return {"status": "ok", "license_files_count": len(file_licenses),
            "licenses": licenses, "copyrights": copyrights[:20],
            "file_licenses": file_licenses}


def run_scancode(root: Path, out_json: Path, timeout: int = 1800,
                 reuse: bool = False) -> dict:
    """执行 ScanCode 扫描（-cl: 许可证+版权）。"""
    if reuse and out_json.exists():
        res = parse_scancode_json(out_json, root)
        if res.get("status") == "ok":
            res["reused"] = True
            log.info("ScanCode 复用缓存: %s (%d 文件命中)", out_json,
                     res.get("license_files_count", 0))
            return res

    exe = find_scancode()
    if not exe:
        log.warning("未安装 scancode, 跳过许可证扫描(可选组件)")
        return {"status": "skipped", "reason": "未安装 scancode",
                "file_licenses": {}}

    out_json.parent.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "-cl", "--json-pp", str(out_json), "--processes", "4",
           "--timeout", "60", str(root)]
    log.info("ScanCode 扫描中(超时 %ds): %s", timeout, root)
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if not out_json.exists():
            return {"status": "failed",
                    "reason": (r.stderr or r.stdout).decode("utf-8", "replace")[:400],
                    "file_licenses": {}}
    except subprocess.TimeoutExpired:
        return {"status": "failed", "reason": f"超时 {timeout}s",
                "file_licenses": {}}
    except Exception as e:  # noqa: BLE001
        return {"status": "failed", "reason": str(e), "file_licenses": {}}
    return parse_scancode_json(out_json, root)
