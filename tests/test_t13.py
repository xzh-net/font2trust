# -*- coding: utf-8 -*-
"""T13 验收测试：多仓库端到端（P0-1 缺陷修复回归）。

背景: main 在 ≥2 仓库时把 combined 作为 list 传给 compare_with_previous,
      原实现按 dict 调用 .get -> AttributeError -> exit 1 且产物半写。
      本测试用两个 local 仓库跑完整流水线, 断言:
        1) 退出码 0, report.json 为 list(2 仓库)
        2) summary / 双台账 / 证据目录 / 历史归档 全部落盘
        3) 第二次运行环比正常输出(不再崩溃)
        4) 产物不含凭证; 正式 font-compliance/ 不被污染

运行: python tests/test_t13.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.main import main as run_pipeline               # noqa: E402
from scripts.utils import PROJECT_ROOT, redact_credentials  # noqa: E402

FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "repo_baseline"
BACKEND = PROJECT_ROOT / "workspace" / "backend"


def main() -> int:
    repos = [p for p in (FIXTURE, BACKEND) if p.exists()]
    assert len(repos) == 2, (
        f"需要两个本地仓库做多仓库基线, 实际找到 {len(repos)}: {repos}")
    print(f"0) 前提: 多仓库 {', '.join(p.name for p in repos)}")

    real_evid = PROJECT_ROOT / "font-compliance"

    def _snap():
        return {str(p): p.stat().st_mtime for p in real_evid.rglob("*")
                if p.is_file()} if real_evid.exists() else {}

    before = _snap()

    import logging
    lg = logging.getLogger("font_compliance")
    with tempfile.TemporaryDirectory() as td:
        try:
            tdp = Path(td)
            reports = tdp / "reports"
            (reports / "current").mkdir(parents=True)
            cfg_yaml = tdp / "scanner.yaml"
            cfg_yaml.write_text(
                "general: {workspace: workspace, reports_dir: %s, "
                "evidence_dir: %s, log_level: INFO}\n"
                "font_extensions: [.ttf, .otf, .ttc, .woff, .woff2, .eot]\n"
                "exclude_dirs: [.git, .svn, __pycache__, .venv, venv, .idea, .vscode]\n"
                "exclude_dirs_when_deps_off: [node_modules, vendor]\n"
                "scancode: {timeout: 1800}\nhistory: {keep_runs: 52}\n"
                % (str(reports), str(tdp / "font-compliance")), encoding="utf-8")
            proj_yaml = tdp / "projects.yaml"
            proj_yaml.write_text(
                "mode: local\nlocal_paths:\n"
                + "".join(f"  - {str(p).replace(chr(92), '/')}\n" for p in repos)
                + "projects: []\nexclude: []\n", encoding="utf-8")

            argv = ["--config", str(cfg_yaml), "--projects", str(proj_yaml),
                    "--skip-scancode", "--no-email"]

            # ---- 第一次运行: 多仓库必须成功 ----
            rc = run_pipeline(list(argv))
            assert rc == 0, f"多仓库运行退出码 {rc}(P0-1 未修复?)"
            current = reports / "current"
            rep = json.loads((current / "report.json").read_text(encoding="utf-8"))
            assert isinstance(rep, list) and len(rep) == 2, type(rep)
            series_n = sum(len(r["font_series"]) for r in rep)
            print(f"1) 第一次运行: exit 0, report.json=list(2), 字体系列合计 {series_n} ✅")

            # summary 与报告一致(修复前: 崩溃导致 summary 停留在上一次的旧值)
            summary = (current / "summary.md").read_text(encoding="utf-8")
            assert f"字体系列/文件: {series_n}" in summary, summary
            assert f"计划 2 / 成功 2 / 失败 0" in summary, summary
            ledgers = list(current.glob("字体授权台账*.md"))
            assert len(ledgers) == 2, [p.name for p in ledgers]
            evid_dirs = [p for p in (tdp / "font-compliance").iterdir()
                         if p.is_dir()]
            assert len(evid_dirs) == series_n, (len(evid_dirs), series_n)
            batches = [p for p in (reports / "history").iterdir() if p.is_dir()]
            assert len(batches) == 1, batches
            # 扫描任务清单(P1b): 计划/成功/失败 + 报告 00 区块
            plan = json.loads((current / "scan_plan.json").read_text(
                encoding="utf-8"))
            assert plan["counts"] == {"planned": 2, "scanned": 2,
                                      "failed": 0, "skipped": 0}, plan["counts"]
            assert {p["name"] for p in plan["planned"]} == {r["repo"]["name"]
                                                            for r in rep}
            html0 = (current / "report.html").read_text(encoding="utf-8")
            assert "00｜扫描任务清单" in html0 and "计划 <b>2</b>" in html0
            print(f"2) 产物一致: summary={series_n}系列, 双台账, "
                  f"证据目录×{len(evid_dirs)}, 归档×1, 任务清单 计划2/成功2 ✅")

            # ---- 凭证兜底 ----
            for p in (current / "report.json", current / "report.html"):
                _, hits = redact_credentials(p.read_text(encoding="utf-8"))
                assert hits == 0, f"{p.name} 含凭证 {hits} 处"
            print("3) 凭证检查: report.json/html 均无 URL 凭证 ✅")

            # ---- 第二次运行: 多仓库环比不得崩溃; 本次开仓库级并发(P1c) ----
            cfg_yaml.write_text(
                "general: {workspace: workspace, reports_dir: %s, "
                "evidence_dir: %s, log_level: INFO, repo_concurrency: 2}\n"
                "font_extensions: [.ttf, .otf, .ttc, .woff, .woff2, .eot]\n"
                "exclude_dirs: [.git, .svn, __pycache__, .venv, venv, .idea, "
                ".vscode, unpackage]\n"
                "exclude_dirs_when_deps_off: [node_modules, vendor]\n"
                "scancode: {timeout: 1800}\nhistory: {keep_runs: 52}\n"
                % (str(reports), str(tdp / "font-compliance")), encoding="utf-8")
            rc2 = run_pipeline(list(argv))
            assert rc2 == 0, f"第二次多仓库运行退出码 {rc2}"
            log_text = (current / "run.log").read_text(encoding="utf-8")
            assert "环比" in log_text, "第二次运行未输出环比信息"
            batches2 = [p for p in (reports / "history").iterdir() if p.is_dir()]
            assert len(batches2) == 2, len(batches2)
            print(f"4) 第二次运行: exit 0 + 环比输出 + 归档×{len(batches2)} ✅")

            # ---- 隔离守卫 ----
            assert _snap() == before, "测试污染了正式 font-compliance/ 目录"
            print("5) 隔离校验: 正式 font-compliance/ 未被测试改动 ✅")
        finally:
            for h in lg.handlers[:]:
                h.close()
            lg.handlers.clear()

    print("\nT13 ACCEPT: PASS  (多仓库端到端 / P0-1 回归)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
