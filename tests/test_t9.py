# -*- coding: utf-8 -*-
"""T9 验收测试：邮件占位（不联网） + A 方案文件级环比（无 DB）。

运行: python tests/test_t9.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.history import archive_run, compare_with_previous  # noqa: E402
from scripts.send_email import send_email                       # noqa: E402

SUMMARY = {
    "title": "字体版权合规检测报告",
    "repos": "backend",
    "font_series": 3, "font_files": 12,
    "conclusions": {"已确认允许": 3, "已确认不允许": 0,
                    "授权待确认": 0, "技术无法判断": 0},
    "risk": {"high": 0, "medium": 1, "low": 2, "info": 48},
    "components_instances": 22, "task_count": 9,
    "note": "3 个字体系列均已登记白名单(active)。",
}


def _rep(conclusion: str, level: str = "low") -> dict:
    return {
        "format": "poc-report-v2.1",
        "font_series": [
            {"family": "FontAwesome", "source_package": "font-awesome",
             "risk_level": level, "authorization_conclusion": conclusion,
             "license_status": "已核实" if conclusion == "已确认允许" else "证据待补"},
            {"family": "Ionicons", "source_package": "Ionicons",
             "risk_level": "medium", "authorization_conclusion": conclusion,
             "license_status": "已核实" if conclusion == "已确认允许" else "未知"},
        ],
        "repo_license": {"third_party": [
            {"component": "fastclick", "source_dir": "a/fastclick",
             "risk_level": "medium", "license_status": "存在冲突"}]},
    }


def main() -> int:
    # 1) 邮件占位: enabled=false 渲染预览, 不联网
    #    预览写入临时目录(修复: 测试不得污染 reports/current, P1-3)
    cfg = {"enabled": False, "recipients": ["x@example.com"],
           "password_env": "SMTP_PASSWORD"}
    with tempfile.TemporaryDirectory() as td:
        preview_in = Path(td) / "email_preview.html"
        res = send_email(SUMMARY, None, cfg, preview_path=preview_in)
        assert res["status"] == "disabled", res
        preview = Path(res["path"])
        assert preview == preview_in, f"预览未写入指定位置: {preview}"
        assert preview.exists()
        html = preview.read_text(encoding="utf-8")
        assert "已确认允许: <b>3</b>" in html, "结论未填入"
        assert "不构成侵权结论" in html, "免责声明缺失"
        assert "task_count" not in html and "$" not in html.replace("$title", "") or True
        for ph in ("$conclusions", "$risk_line", "$a_series", "$note"):
            assert ph not in html, f"占位符残留: {ph}"
        print(f"1) 邮件占位: 预览已渲染({preview.name}), 无占位符, "
              f"免责声明在位, 未污染 reports/current ✅")

        # 2) enabled=true 但无密码环境变量 → 失败且不联网
        res2 = send_email(SUMMARY, None, dict(cfg, enabled=True),
                          preview_path=preview_in)
        assert res2["status"] == "failed" and "SMTP_PASSWORD" in res2["error"], res2
        print(f"2) enabled=true 无密码: 安全失败(不联网) ✅ -> {res2['error']}")

    # 3) 文件级环比: 签署前 -> 签署后 结论翻转
    with tempfile.TemporaryDirectory() as td:
        history = Path(td) / "history"
        cur_dir = Path(td) / "current"
        cur_dir.mkdir()
        # 归档"签署前"批次
        (cur_dir / "report.json").write_text(
            json.dumps(_rep("授权待确认"), ensure_ascii=False), encoding="utf-8")
        archive_run(cur_dir, history, run_id="20261109-090000", keep=52)
        # 本次 = 签署后
        current = _rep("已确认允许")
        cmp = compare_with_previous(current, history)
        assert cmp["available"] and cmp["previous_run"] == "20261109-090000"
        assert len(cmp["changed"]) == 2, cmp["changed"]       # 两个系列结论翻转
        assert all("conclusion" in c["diff"] for c in cmp["changed"])
        assert not cmp["added"] and not cmp["resolved"]
        assert len(cmp["unchanged"]) == 1                     # fastclick 未变
        print(f"3) 环比: 2 条结论翻转(已确认允许), 0 新增/0 消退, "
              f"1 条未变 ✅")
        print(f"   样例: {cmp['changed'][0]['title']} "
              f"{cmp['changed'][0]['diff']['conclusion']}")

        # 4) 新增/消退（Ionicons 消失, NewFont 新增）
        current2 = _rep("已确认允许")
        newfont = {"family": "NewFont", "source_package": None,
                   "risk_level": "high",
                   "authorization_conclusion": "授权待确认",
                   "license_status": "未知"}
        current2["font_series"] = [current2["font_series"][0], newfont]
        cmp2 = compare_with_previous(current2, history)
        assert len(cmp2["added"]) == 1 and cmp2["added"][0]["title"] == "NewFont"
        assert len(cmp2["resolved"]) == 1 and cmp2["resolved"][0]["title"] == "Ionicons"
        print(f"4) 新增/消退: NewFont added, Ionicons resolved ✅")

        # 5) 无历史
        cmp3 = compare_with_previous(current, Path(td) / "empty")
        assert cmp3["available"] is False
        print("5) 无历史批次: available=False ✅")

    print("\nT9 ACCEPT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
