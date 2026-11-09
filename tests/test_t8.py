# -*- coding: utf-8 -*-
"""T8 验收测试：历史归档（文件级, 无 sqlite）。

运行: python tests/test_t8.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.history import archive_run, list_runs, load_latest_report, prune  # noqa: E402


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        current = tdp / "current"
        history = tdp / "history"
        current.mkdir()
        (current / "report.html").write_text("<html>run1</html>", encoding="utf-8")
        (current / "report.json").write_text(
            json.dumps({"format": "poc-report-v2.1", "seq": 1}), encoding="utf-8")
        (current / "字体授权台账.md").write_text("# 台账", encoding="utf-8")

        # 1) 首次归档
        a1 = archive_run(current, history, run_id="20261109-100000", keep=52)
        files = sorted(p.name for p in a1.rglob("*") if p.is_file())
        assert files == ["report.html", "report.json", "字体授权台账.md"], files
        print(f"1) 归档: {a1.name} 含 3 个产物文件 ✅")

        # 2) 第二批次 + keep=1 清理
        (current / "report.json").write_text(
            json.dumps({"format": "poc-report-v2.1", "seq": 2}), encoding="utf-8")
        archive_run(current, history, run_id="20261110-100000", keep=1)
        runs = list_runs(history)
        assert len(runs) == 1 and runs[0].name == "20261110-100000", \
            [r.name for r in runs]
        print(f"2) 保留策略: keep=1 -> 仅存最新 {runs[0].name}, 旧批次已清理 ✅")

        # 3) 最新报告读取（供追溯）
        rep = load_latest_report(history)
        assert rep and rep["seq"] == 2, rep
        print("3) load_latest_report: 读到最新批次 report.json ✅")

        # 4) run_id 冲突防呆（同 ID 两次归档）
        (current / "report.html").write_text("<html>run3</html>", encoding="utf-8")
        a3 = archive_run(current, history, run_id="20261110-100000", keep=52)
        assert a3.name != "20261110-100000", a3.name
        print(f"4) 同名防呆: {a3.name} ✅")

        # 5) prune 返回被清理清单
        removed = prune(history, keep=1)
        assert removed and len(list_runs(history)) == 1
        print(f"5) prune 清单返回: {removed} ✅")

    # 6) 无 DB 依赖确认（仅允许决策说明中提及, 不允许导入）
    import scripts.history as h
    src = open(h.__file__, encoding="utf-8").read()
    assert "import sqlite3" not in src and "sqlite3." not in src
    print("6) 无 sqlite 导入: 确认 ✅")

    print("\nT8 ACCEPT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
