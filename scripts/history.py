# -*- coding: utf-8 -*-
"""历史归档（T8 实现 · 纯文件，不做 sqlite 持久化）。

决策（2026-11-09, docs/实施方案.md §6.3）:
    每次运行将全部产物复制到 reports/history/<run_id>/，
    按 history.keep_runs 保留最近 N 批次自动清理。

归档内容: report.html / report.json / 字体授权台账.md / summary 等
          （大文件不进库；批次回溯与审计靠归档文件本身）。
run_id: 时间戳 YYYYMMDD-HHMMSS，目录名天然可排序。
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import shutil
from pathlib import Path

from .utils import PROJECT_ROOT

log = logging.getLogger("font_compliance")

HISTORY_DIR = PROJECT_ROOT / "reports" / "history"


def make_run_id(now: dt.datetime | None = None) -> str:
    now = now or dt.datetime.now()
    return now.strftime("%Y%m%d-%H%M%S")


def archive_run(current_dir: Path, history_dir: Path | None = None,
                run_id: str | None = None, keep: int = 52) -> Path:
    """把 current_dir 全量产物复制到 history/<run_id>/，并按 keep 清理最旧批次。

    返回归档目录路径。
    """
    current_dir = Path(current_dir)
    history_dir = Path(history_dir or HISTORY_DIR)
    run_id = run_id or make_run_id()
    dest = history_dir / run_id
    n = 2
    while dest.exists():                       # 同秒重复执行防冲突
        dest = history_dir / f"{run_id}-{n}"
        n += 1
    dest.mkdir(parents=True)

    copied = 0
    for p in current_dir.rglob("*"):
        if p.is_file():
            target = dest / p.relative_to(current_dir)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
            copied += 1
    log.info("历史归档: %s (%d 个文件)", dest, copied)

    if keep and keep > 0:
        prune(history_dir, keep)
    return dest


def list_runs(history_dir: Path | None = None) -> list[Path]:
    """已归档批次（按 run_id 升序，即时间顺序）。"""
    history_dir = Path(history_dir or HISTORY_DIR)
    if not history_dir.exists():
        return []
    return sorted([d for d in history_dir.iterdir() if d.is_dir()],
                  key=lambda d: d.name)


def prune(history_dir: Path, keep: int) -> list[str]:
    """保留最近 keep 个批次，删除更旧的。返回被删除的批次名。
    删除带一次重试（Windows 瞬时文件锁防护）。"""
    import time
    runs = list_runs(history_dir)
    removed = []
    for d in (runs[:-keep] if len(runs) > keep else []):
        for attempt in range(2):
            try:
                shutil.rmtree(d)
                removed.append(d.name)
                log.info("清理过期批次: %s", d.name)
                break
            except OSError:
                if attempt == 0:
                    time.sleep(1.0)      # 瞬时锁(杀毒/索引)后重试一次
                else:
                    log.warning("清理失败(保留): %s", d.name)
    return removed


def load_latest_report(history_dir: Path | None = None) -> dict | None:
    """读取最近一批次的 report.json（供文件级环比/追溯使用）。"""
    runs = list_runs(history_dir)
    for d in reversed(runs):
        f = d / "report.json"
        if f.exists():
            try:
                return json.loads(f.read_text(encoding="utf-8"))
            except Exception as e:  # noqa: BLE001
                log.warning("历史报告解析失败 %s: %s", f, e)
    return None


def _index_findings(rep: dict) -> dict:
    """把一份报告里的风险对象展平成 {稳定ID: 摘要}（文件级对比的键）。"""
    from .analyze_risks import norm_name

    idx: dict[str, dict] = {}
    for s in rep.get("font_series", []):
        key = "font:" + norm_name(s.get("family")) + "|" + (
            s.get("source_package") or "-")
        idx[key] = {"type": "font_series", "title": s.get("family"),
                    "risk_level": s.get("risk_level"),
                    "conclusion": s.get("authorization_conclusion"),
                    "license_status": s.get("license_status")}
    for c in rep.get("repo_license", {}).get("third_party", []):
        key = "comp:" + (c.get("source_dir") or c.get("component") or "")
        idx[key] = {"type": "repo_component", "title": c.get("component"),
                    "risk_level": c.get("risk_level"),
                    "conclusion": None,
                    "license_status": c.get("license_status")}
    return idx


def compare_with_previous(current: dict,
                          history_dir: Path | None = None) -> dict:
    """文件级环比（无 DB）: 本次结果 vs 最近已归档批次。

    返回: {"available", "previous_run", "added", "resolved", "changed",
           "unchanged"} —— changed 含等级/结论/许可证状态变化明细。
    注意: 调用时机应在 archive_run 之前（否则"上一批次"就是本次）。
    """
    prev = load_latest_report(history_dir)
    if prev is None:
        return {"available": False, "reason": "无历史批次"}
    cur_idx = _index_findings(current)
    prv_idx = _index_findings(prev)
    added = [dict(cur_idx[k], key=k) for k in cur_idx.keys() - prv_idx.keys()]
    resolved = [dict(prv_idx[k], key=k) for k in prv_idx.keys() - cur_idx.keys()]
    changed, unchanged = [], []
    for k in cur_idx.keys() & prv_idx.keys():
        c, p = cur_idx[k], prv_idx[k]
        diff = {f: {"was": p[f], "now": c[f]}
                for f in ("risk_level", "conclusion", "license_status")
                if c.get(f) != p.get(f)}
        if diff:
            changed.append(dict(c, key=k, diff=diff))
        else:
            unchanged.append(dict(c, key=k))
    prev_run = None
    runs = list_runs(history_dir)
    if runs:
        prev_run = runs[-1].name
    return {"available": True, "previous_run": prev_run,
            "added": added, "resolved": resolved,
            "changed": changed, "unchanged": unchanged}
