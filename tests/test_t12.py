# -*- coding: utf-8 -*-
"""T12 缺陷回归：projects.yaml 配置变更感知（用户报告: 改仓库地址仍扫旧仓库）。

根因: 克隆缓存按 name 存放, 目录存在时直接 git pull —— pull 用的是克隆时
      写死的旧 origin, 忽略配置中的新 URL/分支。
修复: 仓库切换->重建缓存 / 仅凭证变化->set-url / 分支切换->checkout(失败重建)。

运行: python tests/test_t12.py
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.git_sync import _strip_cred, sync_repo   # noqa: E402


def _git(args: list, cwd: Path) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True, capture_output=True, cwd=str(cwd), timeout=60)


def _make_repo(path: Path, files: dict, branch: str | None = None) -> str:
    """造一个本地 git 仓库, 返回 file:// URL。"""
    path.mkdir(parents=True)
    _git(["init", "-q", "-b", "master"], path)
    for name, content in files.items():
        (path / name).write_text(content, encoding="utf-8")
    _git(["add", "-A"], path)
    _git(["commit", "-q", "-m", "init"], path)
    if branch:
        _git(["checkout", "-q", "-b", branch], path)
        (path / f"{branch}.txt").write_text(branch, encoding="utf-8")
        _git(["add", "-A"], path)
        _git(["commit", "-q", "-m", branch], path)
        _git(["checkout", "-q", "master"], path)
    return path.resolve().as_uri()


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        url_a = _make_repo(tdp / "repoA", {"A.txt": "a"})
        url_b = _make_repo(tdp / "repoB", {"B.txt": "b"}, branch="dev")
        dest = tdp / "cache" / "proj"

        # 1) 首次 clone A
        r1 = sync_repo("proj", url_a, dest)
        assert r1["ok"] and r1["mode"] == "clone", r1
        assert (dest / "A.txt").exists()
        print(f"1) 首次 clone A: {r1['mode']} ✅")

        # 2) 重复同步(同仓库同分支) -> pull, 不重建
        r2 = sync_repo("proj", url_a, dest)
        assert r2["ok"] and r2["mode"] == "pull", r2
        print(f"2) 同配置重复同步: {r2['mode']} ✅")

        # 3) **缺陷场景**: 配置改为仓库 B -> 必须感知并重建
        r3 = sync_repo("proj", url_b, dest)
        assert r3["ok"], r3
        assert (dest / "B.txt").exists(), "仍为旧仓库内容(缺陷未修复)"
        assert not (dest / "A.txt").exists()
        origin = subprocess.run(["git", "-C", str(dest), "remote", "get-url",
                                 "origin"], check=True, capture_output=True,
                                timeout=30).stdout.decode().strip()
        assert _strip_cred(origin) == _strip_cred(url_b), origin
        print(f"3) 仓库切换感知: 重建为 B, origin 已更新 ({r3['mode']}) ✅")

        # 4) 分支切换: B 仓库 master -> #dev
        r4 = sync_repo("proj", url_b + "#dev", dest)
        assert r4["ok"], r4
        head = subprocess.run(["git", "-C", str(dest), "rev-parse", "--abbrev-ref",
                               "HEAD"], check=True, capture_output=True,
                              timeout=30).stdout.decode().strip()
        assert head == "dev" and (dest / "dev.txt").exists(), (head,)
        print(f"4) 分支切换感知: HEAD={head}, dev.txt 在位 ({r4['mode']}) ✅")

        # 5) 同配置再次同步 -> 直接 pull, 不折腾
        r5 = sync_repo("proj", url_b + "#dev", dest)
        assert r5["ok"] and r5["mode"] == "pull", r5
        print(f"5) 配置未变: {r5['mode']} ✅")

        # 6) 凭证脱敏
        from scripts.git_sync import _mask
        masked = _mask("http://oauth2:SECRET123@host/x.git")
        assert "SECRET123" not in masked and "***" in masked, masked
        print(f"6) 日志脱敏: {masked} ✅")

    print("\nT12 ACCEPT: PASS  (配置变更感知缺陷修复)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
