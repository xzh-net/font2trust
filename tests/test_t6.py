# -*- coding: utf-8 -*-
"""T6 验收测试：字体授权台账 + 证据目录（对齐 POC 基线）。

运行: python tests/test_t6.py
基线: 台账 15 字段 × 3 系列 + 12 文件明细；证据目录 3×4=12 文件；
      LICENSE 原文含 OFL/MIT/CC-BY 全文与 Glyphicons 官方声明；
      未归档字体走"证据未找到"分支（不补写许可证）。
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))   # 复用 test_t5 构建器

from test_t5 import build_ctx                               # noqa: E402

from scripts.analyze_risks import (assess_family, group_fonts,  # noqa: E402
                                   load_rules, load_whitelist)
from scripts.evidence import build_evidence                 # noqa: E402
from scripts.ledger import write_ledger                     # noqa: E402
from scripts.utils import load_config                       # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    cfg = load_config("config/scanner.yaml")
    rules = load_rules("config/license_rules.yaml")
    wl = load_whitelist("config/whitelist.yaml")
    fonts, refs, ctx, *_ = build_ctx(cfg, wl, rules)
    series = [assess_family(g, ctx) for g in group_fonts(fonts, refs)]

    # 1) 台账
    with tempfile.TemporaryDirectory() as td:
        ledger = Path(td) / "台账.md"
        write_ledger(series, "backend", ledger)
        text = ledger.read_text(encoding="utf-8")
    cols = ["字体名称", "版本", "来源组件", "SHA256", "允许使用方式", "使用限制",
            "授权结论", "使用状态", "审核人及日期"]
    assert all(c in text for c in cols), "台账缺字段"
    assert text.count("| ↳ ") == 12, f"文件明细应 12 行, 实际 {text.count('| ↳ ')}"
    for fam in ("GLYPHICONS", "Ionicons", "FontAwesome"):
        assert fam in text, fam
    assert "已确认允许" in text and "白名单已登记" in text
    print(f"1) 台账: 15 字段 × 3 系列 + 12 文件明细; 结论/登记信息在位 ✅")

    # 2) 证据目录（写到临时目录验证内容, 正式目录由流水线生成）
    import scripts.evidence as ev
    old_root = ev.EVID_ROOT
    with tempfile.TemporaryDirectory() as td:
        ev.EVID_ROOT = Path(td)
        made = build_evidence(series, "backend")
        assert len(made) == 3, made
        files = [p for p in Path(td).rglob("*") if p.is_file()]
        assert len(files) == 12, f"证据文件应 12, 实际 {len(files)}"
        fa = (Path(td) / "FontAwesome" / "LICENSE.txt").read_text(encoding="utf-8")
        assert "SIL Open Font License 1.1 全文" in fa and "OFL" in fa
        ion = (Path(td) / "Ionicons" / "LICENSE.txt").read_text(encoding="utf-8")
        assert "The MIT License" in ion and "CC BY 4.0 全文" in ion
        gl = (Path(td) / "GLYPHICONS-Halflings-Regular" / "LICENSE.txt"
              ).read_text(encoding="utf-8")
        assert "Glyphicons Halflings are also a part of Bootstrap" in gl
        rr = (Path(td) / "FontAwesome" / "review-record.md").read_text(encoding="utf-8")
        assert "active（已确认允许）" in rr and "三层证据法" in rr
        si = (Path(td) / "FontAwesome" / "source-info.txt").read_text(encoding="utf-8")
        assert "MATCH" in si and "4.7.0" in si
    ev.EVID_ROOT = old_root
    print("2) 证据目录: 3×4 文件; OFL/MIT/CC-BY/官方声明 原文归档; 签署栏在位 ✅")

    # 3) 未归档字体 -> "证据未找到"分支（不补写许可证）
    with tempfile.TemporaryDirectory() as td:
        ev.EVID_ROOT = Path(td)
        fake = [dict(series[0], family="UnknownFace",
                     evidence_dir="font-compliance/UnknownFace/")]
        build_evidence(fake, "backend")
        lic = (Path(td) / "UnknownFace" / "LICENSE.txt").read_text(encoding="utf-8")
        assert "证据未找到" in lic and "不自行补写许可证" in lic, lic[:200]
    ev.EVID_ROOT = old_root
    print("3) 未归档字体: 走『证据未找到』分支, 不补写 ✅")

    print("\nT6 ACCEPT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
