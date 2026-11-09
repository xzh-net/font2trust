# -*- coding: utf-8 -*-
"""T4 验收测试：ScanCode 封装（复用解析 + 全新扫描双路径）。

运行: python tests/test_t4.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.run_scancode import find_scancode, run_scancode   # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "tests" / "fixtures" / "repo_baseline"
CACHE = ROOT / "tests" / "fixtures" / "scancode_baseline.json"

MIT_TEXT = """MIT License

Copyright (c) 2026 Test

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.
"""


def main() -> int:
    exe = find_scancode()
    assert exe, "未找到 scancode 可执行文件"
    print(f"1) scancode 定位: {exe}")

    # 路径A: 复用既有缓存（解析/规范化/逐文件表达式）
    assert CACHE.exists(), f"缺少基线缓存: {CACHE}"
    res = run_scancode(BACKEND, CACHE, reuse=True)
    assert res["status"] == "ok" and res.get("reused"), res
    fl = res["file_licenses"]
    fa_keys = [k for k in fl if k.endswith("fontawesome-webfont.ttf")]
    assert fa_keys, "未解析出 fontawesome-webfont.ttf 的表达式"
    assert "ofl" in fl[fa_keys[0]].lower(), fl[fa_keys[0]]
    assert not any(k.startswith("backend/") for k in fl), "根目录前缀未剥离"
    assert all("\\" not in k for k in fl), "路径未统一 posix"
    print(f"2) 复用解析: {len(fl)} 文件命中; FA 表达式 = {fl[fa_keys[0]]} ✅")

    # 路径B: 全新扫描（验证 CLI 调用链）
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "LICENSE").write_text(MIT_TEXT, encoding="utf-8")
        out = tdp / "out" / "scancode.json"
        res2 = run_scancode(tdp, out, timeout=300)
        assert res2["status"] == "ok", res2.get("reason")
        exprs = list(res2["file_licenses"].values())
        assert any("mit" in e.lower() for e in exprs), exprs
        print(f"3) 全新扫描: ok, 许可证 {res2['licenses']} ✅")

    print("\nT4 ACCEPT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
