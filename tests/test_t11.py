# -*- coding: utf-8 -*-
"""T11 端到端冒烟测试：单命令全流水线（离线可重复）。

覆盖: 配置加载 → local 模式同步 → 字体/CSS/ScanCode(缓存) → 结论引擎
      → 五区块报告 + 台账 + 证据目录 → 邮件占位 → 历史归档 → 文件级环比(第二次运行)

运行: python tests/test_t11.py
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.main import main as run_pipeline               # noqa: E402
from scripts.utils import PROJECT_ROOT                      # noqa: E402

CACHE = PROJECT_ROOT / "tests" / "fixtures" / "scancode_baseline.json"
BACKEND = PROJECT_ROOT / "workspace" / "backend"


def main() -> int:
    # 稳定 fixture: 优先基线仓库(已知 3 字体基线); 否则用正式 workspace
    # (workspace 内容随 projects.yaml 变化, 不宜作固定基线)
    fixture_base = PROJECT_ROOT / "tests" / "fixtures" / "repo_baseline"
    repo = fixture_base if fixture_base.exists() else BACKEND
    is_baseline_repo = repo == fixture_base
    assert repo.exists(), "缺少仓库克隆(先执行一次正式运行或重建 fixture)"
    assert CACHE.exists(), f"缺少 ScanCode 缓存: {CACHE}"
    print(f"0) 前提: fixture {repo.name} (基线仓库={is_baseline_repo}) + 扫描缓存")

    import logging
    lg = logging.getLogger("font_compliance")
    with tempfile.TemporaryDirectory() as td:
        try:
            tdp = Path(td)
            reports = tdp / "reports"
            current = reports / "current"
            current.mkdir(parents=True)
            # 预置扫描缓存(避免冒烟时全量重扫)——文件名须与仓库名一致:
            # local 模式目标名取目录名(fixture=repo_baseline), 写成 scancode_backend
            # 会导致缓存永远命中不了 -> 每次冒烟都跑全量 ScanCode(实测 439s)
            shutil.copy2(CACHE, current / f"scancode_{repo.name}.json")

            # 测试配置: 报告/证据目录全部指向临时区(修复: 测试污染正式产物 P1-3)
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
                "mode: local\nlocal_paths: [%s]\nprojects: []\n"
                % str(repo).replace("\\", "/"), encoding="utf-8")

            argv = ["--config", str(cfg_yaml), "--projects", str(proj_yaml),
                    "--reuse-scancode"]

            # 污染守卫: 正式 font-compliance/ 在测试前后必须完全不变 (P1-3)
            real_evid = PROJECT_ROOT / "font-compliance"

            def _snap():
                return {str(p): p.stat().st_mtime for p in real_evid.rglob("*")
                        if p.is_file()} if real_evid.exists() else {}

            before = _snap()

            # ---- 第一次运行 ----
            rc = run_pipeline(list(argv))
            assert rc == 0, f"退出码 {rc}"
            html = (current / "report.html").read_text(encoding="utf-8")
            assert "02｜字体授权结论" in html and "不构成侵权结论" in html
            for ph in ("$series_rows", "$concl_rows", "$remed_rows"):
                assert ph not in html, f"占位符残留: {ph}"
            assert (current / "字体授权台账.md").exists()
            assert (current / "summary.md").exists()
            assert (current / "email_preview.html").exists()
            assert (current / "run.log").exists()
            batches = sorted(p for p in (reports / "history").iterdir()
                             if p.is_dir())
            assert len(batches) == 1 and (batches[0] / "report.json").exists()
            evid = list((tdp / "font-compliance").rglob("LICENSE.txt"))
            assert len(evid) >= 1, f"证据目录缺失: {len(evid)}"
            # 凭证兜底: 任何落盘产物不得含 URL 凭证/gitlab token (P0-2)
            from scripts.utils import redact_credentials
            for p in (current / "report.json", current / "report.html"):
                _, hits = redact_credentials(p.read_text(encoding="utf-8"))
                assert hits == 0, f"{p.name} 含凭证 {hits} 处"
            print(f"1) 第一次运行: 报告/台账/邮件预览/归档({batches[0].name})/"
                  f"证据({len(evid)}) 全部就位, 产物无凭证 ✅")

            # ---- 第二次运行: 文件级环比必须生效 ----
            rc2 = run_pipeline(list(argv))
            assert rc2 == 0
            log_text = (current / "run.log").read_text(encoding="utf-8")
            assert "环比 vs" in log_text, "第二次运行未输出环比"
            batches2 = sorted(p for p in (reports / "history").iterdir()
                              if p.is_dir())
            assert len(batches2) == 2, f"应有 2 个批次, 实际 {len(batches2)}"
            print("2) 第二次运行: 2 批次归档 + 环比输出生效 ✅")

            # ---- 结论一致性 ----
            import json
            rep = json.loads((current / "report.json").read_text(encoding="utf-8"))
            results = rep if isinstance(rep, list) else [rep]
            conclusions = [s["authorization_conclusion"]
                           for r in results for s in r["font_series"]]
            valid = {"已确认允许", "已确认不允许", "授权待确认", "技术无法判断"}
            assert all(c in valid for c in conclusions), conclusions
            if is_baseline_repo:
                assert conclusions == ["已确认允许"] * 3, conclusions
                print(f"3) 结论基线(POC fixture): {conclusions} ✅")
            else:
                print(f"3) 结论一致性: {len(conclusions)} 系列全部合法取值 ✅")

            # 污染守卫收口: 两次运行后正式证据目录必须与测试前逐字节一致
            assert _snap() == before, "测试污染了正式 font-compliance/ 目录"
            print("4) 隔离校验: 正式 font-compliance/ 未被测试改动 ✅")
        finally:
            # 无论成败都释放日志句柄(防临时目录锁, Windows)——须在 with 内,
            # 否则临时目录清理先于句柄关闭执行
            for h in lg.handlers[:]:
                h.close()
            lg.handlers.clear()

    print("\nT11 ACCEPT: PASS  (端到端冒烟)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
