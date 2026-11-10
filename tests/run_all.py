# -*- coding: utf-8 -*-
"""测试汇总执行器: 逐个运行 tests/test_t*.py, 输出 PASS/FAIL 汇总表。

用法:
    python tests/run_all.py            # 全量
    python tests/run_all.py t5 t13     # 只跑指定编号

退出码: 0=全部通过, 1=存在失败(供 CI/调度判读)
"""
from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

try:                       # Windows GBK 控制台: 统一 UTF-8 输出(修复乱码/编码崩溃)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:          # noqa: BLE001
    pass

ROOT = Path(__file__).resolve().parent.parent


def _key(p: Path) -> tuple:
    m = re.search(r"t(\d+)", p.name)
    return (int(m.group(1)) if m else 999, p.name)


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    tests = sorted((ROOT / "tests").glob("test_t*.py"), key=_key)
    if argv:
        want = {a.lower().lstrip("t") for a in argv}
        tests = [t for t in tests if re.search(r"t(\d+)", t.name)
                 and re.search(r"t(\d+)", t.name).group(1) in want]
    if not tests:
        print("未匹配到测试文件", file=sys.stderr)
        return 1

    rows, failed = [], 0
    t0 = time.time()
    for t in tests:
        start = time.time()
        status = "PASS"
        try:
            p = subprocess.run([sys.executable, str(t)], cwd=str(ROOT),
                               capture_output=True, encoding="utf-8",
                               errors="replace", timeout=900)
            out = (p.stdout or "") + (p.stderr or "")
            if p.returncode != 0:
                status = "FAIL"
        except subprocess.TimeoutExpired:
            out, status = "", "TIMEOUT"
        elapsed = time.time() - start
        tail = next((ln.strip() for ln in reversed(out.splitlines())
                     if ln.strip()), "")
        rows.append((t.name, status, f"{elapsed:.1f}s", tail[:70]))
        if status != "PASS":
            failed += 1
            print(f"\n----- {t.name} {status} 输出 -----\n{out[-3000:]}")

    w = max(len(r[0]) for r in rows)
    print("\n================ 测试汇总 ================")
    for name, status, sec, tail in rows:
        print(f"{name:<{w}}  {status:<5} {sec:>7}  {tail}")
    total = time.time() - t0
    print(f"------------------------------------------")
    print(f"合计 {len(rows)} 项, 通过 {len(rows) - failed}, 失败 {failed} "
          f"(耗时 {total:.1f}s)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
