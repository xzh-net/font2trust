# -*- coding: utf-8 -*-
"""T7 验收测试：五区块报告生成（结构 + 数据 + 占位符 + JSON）。

运行: python tests/test_t7.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_t5 import build_ctx                               # noqa: E402

from scripts.analyze_risks import (build_repo_license,      # noqa: E402
                                   assess_family, group_fonts,
                                   load_rules, load_whitelist)
from scripts.extract_metadata import extract_metadata       # noqa: E402
from scripts.generate_report import generate_report         # noqa: E402
from scripts.ledger import write_ledger                     # noqa: E402
from scripts.evidence import build_evidence                 # noqa: E402
from scripts.scan_projects import build_excludes, inventory  # noqa: E402
from scripts.scan_css import finalize_css_refs, detect_version_mismatch  # noqa: E402
from scripts.utils import load_config                       # noqa: E402


def main() -> int:
    cfg = load_config("config/scanner.yaml")
    rules = load_rules("config/license_rules.yaml")
    wl = load_whitelist("config/whitelist.yaml")
    fonts, refs, ctx, excl, sc, lics = build_ctx(cfg, wl, rules)

    # 组装完整结果（模拟流水线）
    series = group_fonts(fonts, refs)
    series = [assess_family(g, ctx) for g in series]
    finalize_css_refs(refs, series)
    detect_version_mismatch(series, refs)
    rl = build_repo_license(ctx["root"], inventory(ctx["root"], excl),
                            sc["file_licenses"], lics)
    inv = inventory(ctx["root"], excl)
    result = {
        "format": "poc-report-v2.1",
        "repo": {"name": "backend", "source": "-", "clone": {"mode": "local"}},
        "coverage": {
            "files_total": len(inv), "font_series": len(series),
            "font_files": sum(len(s["files"]) for s in series),
            "font_files_unique": sum(len(s["files"]) for s in series),
            "parse_ok": sum(1 for s in series for f in s["files"]
                            if f["parse_status"] == "ok"),
            "parse_fail": sum(1 for s in series for f in s["files"]
                              if f["parse_status"] != "ok"),
            "css_refs": len(refs), "scancode": sc["status"],
            "license_files": len(lics),
            "own_files": rl["own"]["file_count"],
            "third_party_files": rl["third_party_file_count"],
        },
        "font_series": series, "css_refs": refs, "repo_license": rl,
        "scancode": {k: v for k, v in sc.items() if k != "file_licenses"},
        "rules": {"commercial_keywords": rules["commercial_keywords"],
                  "commercial_keyword_count": len(rules["commercial_keywords"])},
    }

    with tempfile.TemporaryDirectory() as td:
        html_path, json_path = generate_report(result, Path(td))
        html = html_path.read_text(encoding="utf-8")
        data = json.loads(json_path.read_text(encoding="utf-8"))

    # 1) 五区块结构
    blocks = ["01｜字体使用总览", "02｜字体授权结论", "03｜授权证据详情",
              "04｜问题整改清单", "05｜CSS 引用与部署关系"]
    missing = [b for b in blocks if b not in html]
    assert not missing, f"缺区块: {missing}"
    print(f"1) 五区块结构: 全部在位 ✅")

    # 2) 关键数据
    assert "已确认允许：3" in html, "四结论统计错误"
    assert "不构成侵权结论" in html, "免责声明缺失"
    assert "Glyphicons" in html and "已确认允许" in html
    assert "署名义务" in html and "重复部署资源" in html, "整改任务缺失"
    assert "version_mismatch" in html, "版本告警缺失"
    print("2) 关键数据: 四结论3/免责声明/整改任务/版本告警 ✅")

    # 3) 占位符全部替换
    for ph in ("$series_rows", "$concl_rows", "$remed_rows", "$css_rows",
               "$repo_rows", "$coverage_rows", "$asset_chips", "$kw_list"):
        assert ph not in html, f"占位符未替换: {ph}"
    print("3) 占位符: 全部替换 ✅")

    # 4) JSON 可读 + 结构
    assert data["format"] == "poc-report-v2.1"
    assert len(data["font_series"]) == 3
    assert all(s["authorization_conclusion"] == "已确认允许"
               for s in data["font_series"])
    print(f"4) JSON: 3 系列全部已确认允许 ✅")

    print("\nT7 ACCEPT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
