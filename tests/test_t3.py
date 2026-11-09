# -*- coding: utf-8 -*-
"""T3 验收测试：CSS 引用识别（对齐 POC 基线 + 评审误判回归断言）。

运行: python tests/test_t3.py
基线: 48 条引用 = @font-face/本地字体 28 + font-family 20；
      回归: 注释中 fontawesome.io 不误判、通用族不计、版本冲突告警存在。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.scan_css import (detect_version_mismatch, finalize_css_refs,  # noqa: E402
                              scan_css)
from scripts.scan_fonts import scan_fonts                  # noqa: E402
from scripts.scan_projects import build_excludes           # noqa: E402
from scripts.extract_metadata import extract_metadata      # noqa: E402
from scripts.utils import load_config                     # noqa: E402

REPO = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "repo_baseline"


def main() -> int:
    cfg = load_config("config/scanner.yaml")
    excl = build_excludes(cfg)
    fonts = scan_fonts(REPO, set(cfg["font_extensions"]), excl)
    for f in fonts:
        f["meta"] = extract_metadata(REPO / f["path"])

    refs = scan_css(REPO, fonts, excl)
    kinds = {}
    for r in refs:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    print(f"1) 引用总数: {len(refs)} | 类型: {kinds}")
    assert len(refs) == 48, f"基线 48 != {len(refs)}"
    assert kinds.get("@font-face/本地字体") == 28, kinds
    assert kinds.get("font-family") == 20, kinds

    # 回归1: 注释中的 fontawesome.io 不再被误判为 CDN（POC R5-2）
    bad = [r for r in refs if "fontawesome.io" in (r["value"] or "")]
    assert not bad, f"注释 URL 误判残留: {bad}"
    # 回归2: 压缩 CSS 的 @font-face 不再错配 sans-serif（POC R5-1）
    bad2 = [r for r in refs if r["kind"] == "@font-face"
            and (r.get("value") or "").lower() == "sans-serif"]
    assert not bad2, f"@font-face 错配残留: {bad2}"
    print("2) 误判回归: 注释URL/压缩CSS错配 均无残留 ✅")

    # 证据链 + 版本冲突（需要系列结构，此处按 family 构造最小系列）
    fam_map: dict[str, dict] = {}
    for f in fonts:
        m = f["meta"]
        fam = m.get("full_name") or m.get("family") or Path(f["path"]).stem
        g = fam_map.setdefault(fam, {"family": fam, "family_norm": fam,
                                     "font_version": m.get("version"),
                                     "files": []})
        g["files"].append(f)
    series = list(fam_map.values())
    finalize_css_refs(refs, series)
    detect_version_mismatch(series, refs)

    linked = sum(1 for r in refs if r.get("linked_series"))
    print(f"3) 证据链关联: {linked} 条挂到字体系列 ✅")
    assert linked > 0

    fa = next(s for s in series if "awesome" in s["family"].lower()
              and s.get("font_version"))   # 取可解析且带版本的组(EOT组无版本)
    import re as _re
    hint_norm = [_re.sub(r"[^a-z0-9]", "", h.lower())
                 for h in fa.get("css_font_families", [])]
    assert any(h.startswith("fontawesome5") for h in hint_norm), hint_norm
    assert any("version_mismatch" in a for a in fa.get("alerts", [])), \
        fa.get("alerts")
    print(f"4) 版本冲突告警: FontAwesome 命中 version_mismatch ✅")
    print(f"   {fa['alerts'][0]}")

    print("\nT3 ACCEPT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
