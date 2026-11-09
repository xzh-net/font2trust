# -*- coding: utf-8 -*-
"""T5 验收测试：风险与授权结论引擎（对齐 POC v2.1→白名单签署后基线）。

运行: python tests/test_t5.py
基线:
  - 归组: 3 系列（文件 4/3/5，EOT 已并入，sha256 跨目录去重）
  - 白名单 active:  授权结论 = 已确认允许 ×3，license_status = 已核实 ×3
  - 白名单空(模拟未签署): 授权结论 = 授权待确认 ×3；离子体证据含"组件许可证不继承"
  - 组件: 实例22 / 唯一11 / 重复文件32；fastclick、slimscroll = 存在冲突
  - 五分类合计 == 遍历文件数；第三方 64 文件；copyleft 待确认 ≥ 4
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.analyze_risks import (build_component_exprs,   # noqa: E402
                                   build_repo_license, assess_family,
                                   assess_component, group_fonts,
                                   find_license_files, index_component_licenses,
                                   load_rules, load_whitelist)
from scripts.extract_metadata import extract_metadata         # noqa: E402
from scripts.run_scancode import run_scancode                # noqa: E402
from scripts.scan_css import scan_css                        # noqa: E402
from scripts.scan_fonts import scan_fonts                    # noqa: E402
from scripts.scan_projects import build_excludes, inventory  # noqa: E402
from scripts.utils import load_config                        # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT / "tests" / "fixtures" / "repo_baseline"
CACHE = ROOT / "tests" / "fixtures" / "scancode_baseline.json"


def build_ctx(cfg, whitelist, rules):
    excl = build_excludes(cfg)
    fonts = scan_fonts(REPO, set(cfg["font_extensions"]), excl)
    for f in fonts:
        f["meta"] = extract_metadata(REPO / f["path"])
    refs = scan_css(REPO, fonts, excl)
    sc = run_scancode(REPO, CACHE, reuse=True)
    assert sc["status"] == "ok", sc
    lics = find_license_files(REPO)
    ctx = {"root": REPO,
           "file_licenses": sc["file_licenses"],
           "component_licenses": index_component_licenses(lics),
           "component_exprs": build_component_exprs(sc["file_licenses"]),
           "rules": rules, "whitelist": whitelist}
    return fonts, refs, ctx, excl, sc, lics


def main() -> int:
    cfg = load_config("config/scanner.yaml")
    rules = load_rules("config/license_rules.yaml")
    wl_active = load_whitelist("config/whitelist.yaml")
    assert len(wl_active) == 3, f"白名单 active 应为 3, 实际 {len(wl_active)}"

    fonts, refs, ctx, excl, sc, lics = build_ctx(cfg, wl_active, rules)
    series = group_fonts(fonts, refs)
    assert len(series) == 3, f"系列数 {len(series)} != 3"
    sizes = {s["family"]: len(s["files"]) for s in series}
    assert sorted(sizes.values()) == [3, 4, 5], sizes
    locs = {s["family"]: sum(len(f["locations"]) for f in s["files"])
            for s in series}
    assert sorted(locs.values()) == [6, 8, 10], locs
    print(f"1) 归组: 3 系列, 文件 {sorted(sizes.values())}, 位置 {sorted(locs.values())} ✅")

    # 路径A: 白名单 active
    assessed = [assess_family(s, ctx) for s in series]
    conclusions = [s["authorization_conclusion"] for s in assessed]
    assert conclusions == ["已确认允许"] * 3, conclusions
    assert all(s["license_status"] == "已核实" for s in assessed)
    levels = sorted(s["risk_level"] for s in assessed)
    assert levels == ["low", "low", "medium"], levels   # glyphicons fsType 保留中危
    assert all(s["usage_status"] == "存在引用但未确认运行时使用" for s in assessed)
    print(f"2) 白名单 active: 已确认允许 ×3, 等级 {levels} ✅")

    # 路径B: 白名单空（模拟签署前）
    ctx2 = dict(ctx, whitelist=[])
    assessed2 = [assess_family(s, ctx2) for s in series]
    assert [s["authorization_conclusion"] for s in assessed2] == ["授权待确认"] * 3
    ion = next(s for s in assessed2 if "ionicon" in s["family"].lower())
    assert "组件级许可证线索" in " ".join(ion["evidence"]), ion["evidence"]
    assert "component_license_not_inherited" in ion["rules_hit"]
    print("3) 白名单空: 授权待确认 ×3 + 组件许可证不继承证据 ✅")

    # 组件评估单测: 歧义表达式
    c1 = assess_component(["mit AND unknown-license-reference"], [])
    assert c1["license_status"] == "存在冲突" and c1["risk_level"] == "medium"
    c2 = assess_component(["mit OR gpl-2.0"], [])
    assert c2["license_status"] == "存在冲突"
    print("4) 组件歧义单测: unknown/OR -> 存在冲突 ✅")

    # 仓库许可证: 五分类 + 三口径
    inv = inventory(REPO, excl)
    rl = build_repo_license(REPO, inv, sc["file_licenses"], lics)
    cats = rl["own"]["categories"]
    assert sum(cats.values()) == len(inv), (sum(cats.values()), len(inv))
    assert rl["third_party_file_count"] == 64, rl["third_party_file_count"]
    st = rl["component_stats"]
    assert (st["instances"], st["unique_components"], st["duplicate_files"]) \
        == (22, 11, 32), st
    by_name = {c["component"]: c for c in rl["third_party"]
               if c["component"] in ("fastclick", "jquery-slimscroll")}
    assert by_name["fastclick"]["license_status"] == "存在冲突"
    assert by_name["jquery-slimscroll"]["license_status"] == "存在冲突"
    assert len(rl["own"]["copyleft_suspects"]) >= 4
    print(f"5) 五分类合计 {sum(cats.values())} == 遍历 {len(inv)}; "
          f"三口径 {st}; copyleft {len(rl['own']['copyleft_suspects'])} 条 ✅")
    print(f"   分类: {cats}")

    print("\nT5 ACCEPT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
