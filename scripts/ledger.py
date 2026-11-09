# -*- coding: utf-8 -*-
"""字体授权台账生成（T6 实现 · 迁移自 poc/poc_scan.py write_ledger）。

台账 = 证据记录（docs/实施方案.md §15.3）：
    15 字段主表 + 文件明细行；"审核人及日期"白名单 active 后显示登记信息，
    否则显示"待技术部负责人确认"。授权结论以人工签署为准。
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from .analyze_risks import perm_and_limit


def write_ledger(series: list, repo_name: str, out_path: Path) -> None:
    """生成 Markdown 台账（每字体一行主表 + 文件明细行）。"""
    lines = [
        f"# 字体授权台账 — {repo_name}", "",
        f"- 生成时间: {dt.datetime.now():%Y-%m-%d %H:%M:%S}",
        "- 说明: 本台账为**证据记录**; 授权结论中仅「已确认允许」来自人工核实"
        "(白名单 active), 其余为扫描器证据性判断; "
        "证据原文见各字体 `font-compliance/<字体>/` 目录。", "",
        "| 字体名称 | 版本 | 来源组件 | 文件(格式) | SHA256(代表) | 引用情况 | "
        "许可证 | 适用对象 | 允许使用方式 | 使用限制 | 授权结论 | 使用状态 | "
        "风险/审核 | 证据目录 | 审核人及日期 |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for s in series:
        fmts = ",".join(sorted({f["ext"].lstrip(".") for f in s["files"]}))
        sha = ((s["files"][0].get("sha256") or "")[:16] + "…") if s["files"] else "-"
        refs = sum(1 for f in s["files"] if f.get("referenced"))
        lic = (s.get("license_expression") or s.get("license_spdx")
               or s.get("license_status"))
        perm, limit = perm_and_limit(
            s.get("license_expression") or s.get("license_spdx"))
        reviewer = ("白名单已登记(见 config/whitelist.yaml)"
                    if s.get("license_status") == "已核实"
                    else "待技术部负责人确认")
        lines.append(
            f"| {s['family']} | {s.get('font_version') or '未记录'} | "
            f"{s.get('source_package') or '未推导'}"
            f"{'@' + s['source_version'] if s.get('source_version') else ''} | "
            f"{len(s['files'])} ({fmts}) | `{sha}` | "
            f"{refs}/{len(s['files'])} 文件被CSS引用 | "
            f"{lic} | 字体文件 | {perm} | {limit} | "
            f"**{s.get('authorization_conclusion')}** | {s.get('usage_status')} | "
            f"{s.get('risk_level')}/{s.get('review_status')} | "
            f"`{s.get('evidence_dir')}` | {reviewer} |")
        for f in s["files"]:
            lines.append(
                f"| ↳ {Path(f['path']).name} | | | | "
                f"`{(f.get('sha256') or '')[:16]}…` | "
                f"{'已引用' if f.get('referenced') else '未见引用'} | "
                f"解析:{f.get('parse_status')} fsType:{f.get('fs_type')} | "
                f"| | | | | | | |")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
