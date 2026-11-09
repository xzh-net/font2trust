# -*- coding: utf-8 -*-
"""编排入口（T10）：单命令端到端执行全流水线。

流水线（docs/实施方案.md §2, v1.3）:
    git_sync → scan_projects → scan_fonts → extract_metadata → scan_css
    → run_scancode(可选) → analyze_risks → generate_report + ledger + evidence
    → history 环比(文件级) → send_email(占位) → history.archive_run

用法:
    python -m scripts.main                              # 默认配置
    python -m scripts.main --skip-scancode              # 跳过许可证扫描
    python -m scripts.main --reuse-scancode             # 复用扫描缓存(迭代)
    python -m scripts.main --no-email                   # 跳过邮件环节
    python -m scripts.main --projects config/xxx.yaml   # 指定仓库清单

退出码: 0=成功(含降级: scancode缺失/邮件占位) 1=配置或执行错误
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import sys
from pathlib import Path

from .analyze_risks import (assess_family, build_component_exprs,
                            build_repo_license, find_license_files,
                            group_fonts, index_component_licenses,
                            load_rules, load_whitelist)
from .evidence import build_evidence
from .generate_report import generate_report
from .git_sync import _mask, sync_repo
from .history import archive_run, compare_with_previous
from .ledger import write_ledger
from .run_scancode import run_scancode
from .scan_css import (detect_version_mismatch, finalize_css_refs,
                       scan_css)
from .scan_fonts import scan_fonts
from .scan_projects import build_excludes, inventory
from .extract_metadata import extract_metadata
from .send_email import send_email
from .utils import PROJECT_ROOT, load_config, setup_logging

log = logging.getLogger("font_compliance")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="font2trust",
                                description="字体版权合规检测系统")
    p.add_argument("--config", default="config/scanner.yaml", help="全局配置")
    p.add_argument("--projects", default="config/projects.yaml", help="仓库清单")
    p.add_argument("--skip-scancode", action="store_true", help="跳过许可证扫描")
    p.add_argument("--reuse-scancode", action="store_true", help="复用扫描缓存")
    p.add_argument("--no-email", action="store_true", help="跳过邮件环节")
    return p


def _iter_targets(proj_cfg: dict, workspace: Path):
    """产出 (name, url, local_mode) 目标列表（manual/local 两模式）。"""
    mode = proj_cfg.get("mode", "manual")
    if mode == "local":
        for lp in proj_cfg.get("local_paths") or []:
            p = Path(lp)
            yield p.name, (str(p) if p.is_absolute()
                           else str(PROJECT_ROOT / lp)), True
        return
    for proj in proj_cfg.get("projects") or []:
        if proj.get("enabled"):
            yield proj["name"], proj["url"], False


def _scan_one(name: str, url: str, local_mode: bool, cfg: dict,
              args, current: Path, rules: dict, whitelist: list) -> dict | None:
    """单仓库扫描: 同步 → 扫描 → 评估 → 组装结果。失败返回 None。"""
    workspace = PROJECT_ROOT / cfg["general"]["workspace"]
    excl = build_excludes(cfg)
    exts = set(cfg.get("font_extensions") or [])

    repo = sync_repo(name, url, workspace / name, local_mode=local_mode)
    log.info("[%s] 同步: %s %s", name, repo.get("mode"),
             repo.get("warning") or repo.get("error") or "")
    if not repo["ok"]:
        return None
    root = Path(repo["path"])

    # TP2/TP3 字体扫描与元数据
    fonts = scan_fonts(root, exts, excl)
    for f in fonts:
        f["meta"] = extract_metadata(root / f["path"])
    ok = sum(1 for f in fonts if f["meta"].get("parse_status") == "ok")
    log.info("[%s] 文件 %d | 字体 %d (解析成功 %d)", name,
             len(inventory(root, excl)), len(fonts), ok)

    # TP4 CSS 引用
    refs = scan_css(root, fonts, excl)
    log.info("[%s] 字体引用 %d", name, len(refs))

    # TP5 ScanCode（可选组件）
    if args.skip_scancode:
        sc = {"status": "skipped", "reason": "--skip-scancode",
              "file_licenses": {}}
    else:
        cache = current / f"scancode_{name}.json"
        reuse = args.reuse_scancode
        # 缓存身份校验: 换仓库后禁止复用旧许可证数据(配置感知, 缺陷修复)
        if reuse and cache.exists():
            marker = current / f"scancode_{name}.origin"
            from .git_sync import _strip_cred
            ident = _strip_cred(url.split("#")[0])
            saved = (marker.read_text(encoding="utf-8").strip()
                     if marker.exists() else None)
            if saved is None:
                log.warning("扫描缓存无身份标记, 按配置仓库校验后仍复用 "
                            "(建议重扫一次以写入标记)")
            elif saved != ident:
                log.warning("扫描缓存属于其他仓库, 忽略 --reuse-scancode")
                reuse = False
        sc = run_scancode(root, cache,
                          timeout=int(cfg.get("scancode", {}).get("timeout", 1800)),
                          reuse=reuse)
        if sc.get("status") == "ok":
            from .git_sync import _strip_cred
            (current / f"scancode_{name}.origin").write_text(
                _strip_cred(url.split("#")[0]), encoding="utf-8")
    log.info("[%s] ScanCode: %s%s", name, sc.get("status"),
             " (缓存)" if sc.get("reused") else
             f" {sc.get('reason', '')}" if sc.get("status") != "ok" else "")

    # TP6 风险与授权结论
    license_files = find_license_files(root)
    ctx = {"root": root,
           "file_licenses": sc.get("file_licenses", {}),
           "component_licenses": index_component_licenses(license_files),
           "component_exprs": build_component_exprs(
               sc.get("file_licenses", {})),
           "rules": rules, "whitelist": whitelist}
    series = group_fonts(fonts, refs)
    series = [assess_family(g, ctx) for g in series]
    finalize_css_refs(refs, series)
    detect_version_mismatch(series, refs)
    series.sort(key=lambda x: (-{"high": 3, "medium": 2, "low": 1,
                                 "info": 0}.get(x["risk_level"], 0),
                               x["family"]))
    log.info("[%s] 授权结论: %s", name,
             {c: sum(1 for s in series if s["authorization_conclusion"] == c)
              for c in ("已确认允许", "已确认不允许", "授权待确认",
                        "技术无法判断")})

    # TP7 仓库许可证(五分类/三口径)
    inv = inventory(root, excl)
    rl = build_repo_license(root, inv, sc.get("file_licenses", {}),
                            license_files)

    return {
        "format": "poc-report-v2.1",
        # source 存脱敏 URL: 报告/归档可能入库, 严禁带凭证(缺陷修复)
        "repo": {"name": name, "source": _mask(url), "clone": repo},
        "coverage": {
            "files_total": len(inv),
            "font_series": len(series),
            "font_files": len(fonts),
            "font_files_unique": sum(len(s["files"]) for s in series),
            "parse_ok": ok, "parse_fail": len(fonts) - ok,
            "css_refs": len(refs), "scancode": sc.get("status"),
            "license_files": len(license_files),
            "own_files": rl["own"]["file_count"],
            "third_party_files": rl["third_party_file_count"],
        },
        "font_series": series, "css_refs": refs, "repo_license": rl,
        "scancode": {k: v for k, v in sc.items() if k != "file_licenses"},
        "rules": {"commercial_keywords": rules["commercial_keywords"],
                  "commercial_keyword_count": len(rules["commercial_keywords"])},
    }


def _build_summary(results: list) -> dict:
    """邮件与 summary.md 共用的统计摘要。"""
    series_all = [s for r in results for s in r.get("font_series", [])]
    comps = [c for r in results
             for c in r.get("repo_license", {}).get("third_party", [])]
    conclusions, risk = {}, {}
    for s in series_all:
        c = s.get("authorization_conclusion", "授权待确认")
        conclusions[c] = conclusions.get(c, 0) + 1
        lv = s.get("risk_level", "info")
        risk[lv] = risk.get(lv, 0) + 1
    tasks = sum(1 for s in series_all
                if s.get("authorization_conclusion") != "已确认允许")
    tasks += sum(len(s.get("alerts") or []) for s in series_all)
    tasks += len([1 for r in results
                  for _ in r.get("repo_license", {}).get("own", {})
                  .get("copyleft_suspects", [])])
    return {
        "title": "字体版权合规检测报告",
        "gen_time": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "repos": "、".join(r["repo"]["name"] for r in results),
        "font_series": len(series_all),
        "font_files": sum(len(s["files"]) for s in series_all),
        "conclusions": conclusions, "risk": risk,
        "components_instances": len(comps),
        "task_count": tasks,
        "note": ("；".join(
            f"{r['repo']['name']}: " + "、".join(
                f"{k} {v}" for k, v in
                (r.get('repo_license', {}).get('own', {}).get('categories') or {}).items())
            for r in results) or "-"),
    }


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = load_config(args.config)
        proj_cfg = load_config(args.projects)
    except Exception as e:  # noqa: BLE001
        print(f"配置加载失败: {e}", file=sys.stderr)
        return 1

    reports_dir = PROJECT_ROOT / cfg.get("general", {}).get("reports_dir", "reports")
    current = reports_dir / "current"
    current.mkdir(parents=True, exist_ok=True)
    log = setup_logging(cfg.get("general", {}).get("log_level", "INFO"),
                        current / "run.log")
    started = dt.datetime.now()
    log.info("===== 扫描开始 %s =====", started.strftime("%Y-%m-%d %H:%M:%S"))

    try:
        rules = load_rules(PROJECT_ROOT / "config" / "license_rules.yaml")
        whitelist = load_whitelist(PROJECT_ROOT / "config" / "whitelist.yaml")
    except Exception as e:  # noqa: BLE001
        log.error("规则/白名单加载失败: %s", e)
        return 1
    log.info("白名单 active 条目: %d", len(whitelist))

    results = []
    for name, url, local_mode in _iter_targets(proj_cfg,
                                               PROJECT_ROOT / "workspace"):
        r = _scan_one(name, url, local_mode, cfg, args, current,
                      rules, whitelist)
        if r:
            results.append(r)
    if not results:
        log.error("无有效扫描目标或全部失败(config/projects.yaml)")
        return 1

    # 报告 + 台账 + 证据目录
    combined = results if len(results) > 1 else results[0]
    html_path, json_path = generate_report(combined, current)
    for r in results:
        nm = r["repo"]["name"]
        ledger_name = ("字体授权台账.md" if len(results) == 1
                       else f"字体授权台账_{nm}.md")
        write_ledger(r["font_series"], nm, current / ledger_name)
        build_evidence(r["font_series"], nm)
    summary = _build_summary(results)

    # 文件级环比（须在归档前, 否则"上一批次"就是本次）
    cmp_res = compare_with_previous(combined,
                                    reports_dir / "history")
    if cmp_res.get("available"):
        log.info("环比 vs %s: 新增 %d / 消退 %d / 变化 %d / 未变 %d",
                 cmp_res["previous_run"], len(cmp_res["added"]),
                 len(cmp_res["resolved"]), len(cmp_res["changed"]),
                 len(cmp_res["unchanged"]))
    else:
        log.info("环比: %s（首个批次）", cmp_res.get("reason"))

    # summary.md
    lines = [f"# 扫描汇总 {summary['gen_time']}", "",
             f"- 仓库: {summary['repos']}",
             f"- 字体系列/文件: {summary['font_series']} / {summary['font_files']}",
             f"- 授权结论: {summary['conclusions']}",
             f"- 风险等级: {summary['risk']}",
             f"- 整改任务: {summary['task_count']}", "",
             "> 免责声明: 自动检测风险提示，不构成侵权结论。"]
    (current / "summary.md").write_text("\n".join(lines), encoding="utf-8")

    # 邮件（占位: enabled=false 仅渲染预览, 须在归档前以便入档）
    if args.no_email:
        log.info("邮件: --no-email 跳过")
    else:
        email_cfg = load_config(PROJECT_ROOT / "config" / "email.yaml")
        res = send_email(summary, html_path, email_cfg,
                         preview_path=current / "email_preview.html")
        log.info("邮件: %s %s", res.get("status"), res.get("path")
                 or res.get("error") or "")

    # 历史归档（文件级, 无 DB）
    keep = int(cfg.get("history", {}).get("keep_runs", 52))
    dest = archive_run(current, reports_dir / "history", keep=keep)
    elapsed = (dt.datetime.now() - started).total_seconds()
    log.info("===== 完成 %.1fs | 归档 %s =====", elapsed, dest.name)
    print(f"\n报告: {html_path}\n台账/证据: current/ + font-compliance/\n"
          f"归档: {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
