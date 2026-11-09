# -*- coding: utf-8 -*-
"""仓库同步（T2 实现 · 迁移自 poc/poc_scan.py sync_repo）。"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger("font_compliance")


def _remote_origin(dest: Path) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(dest), "remote", "get-url", "origin"],
            check=True, capture_output=True, timeout=30,
        ).stdout.decode("utf-8", "replace").strip()
    except Exception:  # noqa: BLE001
        return ""


def _strip_cred(url: str) -> str:
    """去掉 URL 中的凭证(userinfo), 只留仓库本体用于比较。"""
    return re.sub(r"//[^/@]+@", "//", url or "")


def _mask(url: str) -> str:
    """日志脱敏: 凭证部分替换为 ***。"""
    return re.sub(r"//([^/@]+)@", "//***@", url or "")


def _rmtree_robust(path: Path, retries: int = 3) -> bool:
    """删除目录树: Windows 只读文件(如 .git/objects)先清属性再重试。"""
    import time
    for i in range(retries):
        try:
            shutil.rmtree(path)
            return True
        except PermissionError:
            for p in path.rglob("*"):          # 清只读位
                try:
                    p.chmod(0o666)
                except OSError:
                    pass
            try:
                path.chmod(0o777)
            except OSError:
                pass
            time.sleep(0.5)
        except OSError:
            time.sleep(0.5)
    return False


def sync_repo(name: str, url: str, dest: Path, local_mode: bool = False,
              timeout: int = 600) -> dict:
    """clone/pull 远端仓库；local 模式直接使用已有目录。

    - URL 后缀 `#branch` 指定分支（如 ...repo.git#develop）
    - **配置变更感知(缺陷修复)**: 修改 projects.yaml 后
        * 仓库切换(去凭证后 URL 不同) -> 删除缓存重建 clone
        * 仅凭证变化 -> git remote set-url 更新
        * 分支切换 -> checkout, 失败则重建 clone
    - pull 失败但本地有缓存 -> 降级为 cache 模式继续扫描（不中断）
    - 日志与错误信息对凭证脱敏
    """
    branch = None
    if not local_mode and "#" in url:
        url, branch = url.rsplit("#", 1)

    if local_mode:
        p = Path(url)
        if not p.exists():
            return {"name": name, "path": str(p), "ok": False, "error": "目录不存在"}
        return {"name": name, "path": str(p), "ok": True, "mode": "local"}

    def _clone() -> dict:
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd += ["--branch", branch]
        cmd += [url, str(dest)]
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=timeout)
            return {"name": name, "path": str(dest), "ok": True, "mode": "clone"}
        except subprocess.CalledProcessError as e:
            return {"name": name, "path": str(dest), "ok": False,
                    "error": _mask(e.stderr.decode("utf-8", "replace")[:300])}
        except Exception as e:  # noqa: BLE001
            return {"name": name, "path": str(dest), "ok": False,
                    "error": _mask(str(e))}

    def _reclone(reason: str) -> dict:
        log.warning("%s %s -> 重建克隆缓存", name, reason)
        if not _rmtree_robust(dest):
            return {"name": name, "path": str(dest), "ok": False,
                    "error": "旧缓存删除失败(重试后仍被占用)"}
        return _clone()

    if dest.exists():
        origin = _remote_origin(dest)
        # 1) 仓库切换: 配置 URL 与本地 origin 指向不同仓库 -> 重建
        if not origin or _strip_cred(origin) != _strip_cred(url):
            return _reclone(f"配置仓库变更 ({_mask(origin) or '无origin'})"
                            f" -> {_mask(url)}")
        # 2) 仅凭证变化 -> 更新 origin
        if origin != url:
            log.info("%s 凭证/URL 细节变更, 更新 origin", name)
            try:
                subprocess.run(["git", "-C", str(dest), "remote", "set-url",
                                "origin", url], check=True,
                               capture_output=True, timeout=30)
            except Exception as e:  # noqa: BLE001
                return {"name": name, "path": str(dest), "ok": True,
                        "mode": "cache",
                        "warning": f"set-url 失败, 沿用原 origin: {e}"}
        # 3) 分支切换 -> checkout, 失败则重建
        if branch:
            cur = ""
            try:
                cur = subprocess.run(
                    ["git", "-C", str(dest), "rev-parse", "--abbrev-ref", "HEAD"],
                    check=True, capture_output=True, timeout=30,
                ).stdout.decode("utf-8", "replace").strip()
            except Exception:  # noqa: BLE001
                pass
            if cur and cur != branch:
                try:
                    subprocess.run(["git", "-C", str(dest), "checkout", branch],
                                   check=True, capture_output=True, timeout=120)
                except Exception:  # noqa: BLE001 分支不在浅克隆中 -> 重建
                    return _reclone(f"分支变更 {cur} -> {branch}")
        # 4) 拉取
        try:
            subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"],
                           check=True, capture_output=True, timeout=min(timeout, 300))
            return {"name": name, "path": str(dest), "ok": True, "mode": "pull"}
        except Exception as e:  # noqa: BLE001 降级继续
            log.warning("%s pull 失败, 使用本地缓存: %s", name, e)
            return {"name": name, "path": str(dest), "ok": True, "mode": "cache",
                    "warning": f"pull 失败, 使用本地缓存: {e}"}

    return _clone()
