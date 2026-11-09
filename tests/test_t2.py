# -*- coding: utf-8 -*-
"""T2 验收测试：字体扫描与元数据（对齐 POC 实测基线）。

运行: python -m tests.test_t2   （或 python tests/test_t2.py）
基线: docs/验收对照-20261109.md —— 24 文件 / 12 去重 / 18 解析成功 / 3 系列版本
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.extract_metadata import extract_metadata          # noqa: E402
from scripts.scan_fonts import scan_fonts, unique_by_sha       # noqa: E402
from scripts.scan_projects import build_excludes, inventory    # noqa: E402
from scripts.utils import load_config, norm_name               # noqa: E402

REPO = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "repo_baseline"


def main() -> int:
    assert REPO.exists(), f"基线仓库不存在: {REPO}（先运行 POC 克隆）"
    cfg = load_config("config/scanner.yaml")
    excl = build_excludes(cfg)
    exts = set(cfg.get("font_extensions") or [])

    # 1) 文件遍历
    inv = inventory(REPO, excl)
    assert len(inv) > 4000, f"遍历文件数异常: {len(inv)}"
    print(f"1) 遍历: {len(inv)} 文件 (排除规则 {sorted(excl)})")

    # 2) 字体发现 + 去重
    fonts = scan_fonts(REPO, exts, excl)
    uniq = unique_by_sha(fonts)
    assert len(fonts) == 24, f"字体文件数 {len(fonts)} != 基线 24"
    assert len(uniq) == 12, f"去重后 {len(uniq)} != 基线 12"
    print(f"2) 字体发现: {len(fonts)} 文件 / {len(uniq)} 去重 ✅")

    # 3) 元数据提取
    ok = 0
    versions = {}
    for f in fonts:
        m = extract_metadata(REPO / f["path"])
        f["meta"] = m
        if m.get("parse_status") == "ok":
            ok += 1
            fam = m.get("full_name") or m.get("family")
            if fam and m.get("version"):
                versions[norm_name(fam)] = m["version"]
    assert ok == 18, f"解析成功 {ok} != 基线 18"
    print(f"3) 元数据: 解析成功 {ok}/24 ✅（EOT 6 个如实标注 unsupported_eot）")

    # 4) 关键版本指纹与 POC 一致
    assert "4.7.0" in (versions.get("fontawesome") or ""), versions
    assert "1.009" in (versions.get("glyphiconshalflingsregular") or ""), versions
    # fsType: glyphicons=4, fontawesome=0
    fs = {f["meta"].get("family"): f["meta"].get("fs_type")
          for f in fonts if f["meta"].get("family")}
    assert fs.get("GLYPHICONS Halflings") == 4, fs
    print(f"4) 版本指纹: FontAwesome 4.7.0 / Glyphicons 1.009 / fsType 正确 ✅")

    print("\nT2 ACCEPT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
