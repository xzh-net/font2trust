# -*- coding: utf-8 -*-
"""T15 验收测试：GitLab 项目发现器（P1a，mock API，不依赖真实 GitLab）。

覆盖: 分页 / 401 与缺 token 显式失败 / 组与 membership 两种口径 /
      exclude·空仓·活跃度过滤 / 目录命名与同名冲突 / host 改写 / ref 后缀

运行: python tests/test_t15.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scripts.discover_gitlab as dg                    # noqa: E402
from scripts.discover_gitlab import discover, to_targets  # noqa: E402

REAL_API = dg._api_get


def _proj(pid: int, pwn: str, days: int = 5, empty: bool = False) -> dict:
    from datetime import datetime, timedelta, timezone
    iso = (datetime.now(timezone.utc) - timedelta(days=days)
           ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"id": pid, "name": pwn.rsplit("/", 1)[-1],
            "path_with_namespace": pwn, "default_branch": "main",
            "last_activity_at": iso, "empty_repo": empty,
            "http_url_to_repo": f"http://106.124.139.155:8088/{pwn}.git",
            "web_url": f"http://106.124.139.155:8088/{pwn}"}


def _install(handler):
    dg._api_get = handler


def _base(**over) -> dict:
    cfg = {"host": "http://192.168.2.209:8088", "token_env": "GITLAB_TOKEN",
           "groups": ["huier"], "include_subgroups": True, "archived": False,
           "ref": "default", "refs": {}, "exclude": [],
           "last_activity_within_days": None}
    cfg.update(over)
    return cfg


def main() -> int:
    # 1) 分页 + 组口径 + host 改写 + 命名
    calls: list = []

    def h1(host, token, path, params=None, timeout=30):
        calls.append((path, dict(params or {})))
        page = int((params or {}).get("page", 1))
        if path == "/api/v4/groups/huier/projects":
            if page == 1:
                return 200, [_proj(1, "huier/a/foo"),
                             _proj(2, "huier/b/foo")], {"X-Next-Page": "2"}
            if page == 2:
                return 200, [_proj(3, "huier/a/bar")], {}
            return 200, [], {}
        return 404, {"error": "nf"}, {}

    _install(h1)
    d = discover(_base(), "TOK")
    assert d["ok"] and d["count"] == 3, d
    assert d["scope"] == "groups+subgroups"
    assert all(p["url"].startswith("http://192.168.2.209:8088/")
               for p in d["projects"]), "host 未改写"
    assert len({p["target_name"] for p in d["projects"]}) == 3, "目录名冲突"
    assert "per_page" in calls[0][1] and calls[0][1]["page"] == 1
    print(f"1) 分页(2页/3项目) + 组口径 + host 改写 + 命名唯一 ✅")

    # 2) 同名项目(叶子相同) → 目录名必须不同
    assert dg.target_name("g1/huier-datacenter", 11, set()) != \
        dg.target_name("g2/huier-datacenter", 12, set())
    bad = dg.target_name('a/b<c>d:"e"|f?g*h', 9, set())
    assert not any(c in bad for c in '<>:"|?*'), bad
    print(f"2) 命名: 叶子同名区分 / 非法字符清洗 → {bad} ✅")

    # 3) 401 显式失败(不静默降级)
    _install(lambda *a, **k: (401, {"error": "401 Unauthorized"}, {}))
    d = discover(_base(), "BAD")
    assert d["ok"] is False and "认证失败" in d["error"], d
    assert "BAD" not in d["error"], "错误信息回显了 token"
    print(f"3) 401 → 显式失败且不回显 token: {d['error'][:46]}... ✅")

    # 4) 缺 token 显式失败
    d = discover(_base(), "")
    assert d["ok"] is False and "GITLAB_TOKEN" in d["error"], d
    print(f"4) 缺 token → 显式失败: {d['error'][:40]}... ✅")

    # 5) 过滤: exclude / 空仓库 / 活跃度
    def h2(host, token, path, params=None, timeout=30):
        if path.startswith("/api/v4/groups/"):
            return 200, [_proj(1, "huier/x/keep"),
                         _proj(2, "huier/x/skipme"),
                         _proj(3, "huier/x/empty", empty=True),
                         _proj(4, "huier/x/old", days=500)], {}
        return 404, {}, {}

    _install(h2)
    d = discover(_base(exclude=["huier/x/skipme"],
                       last_activity_within_days=365), "TOK")
    assert d["ok"], d
    paths = [p["path"] for p in d["projects"]]
    assert paths == ["huier/x/keep"], paths
    reasons = {s["path"]: s["reason"] for s in d["skipped"]}
    assert "配置 exclude 排除" in reasons["huier/x/skipme"]
    assert reasons["huier/x/empty"] == "空仓库"
    assert "500 天未活动" in reasons["huier/x/old"], reasons
    print(f"5) 过滤: exclude/空仓/活跃度 → 保留 {paths}，跳过 {len(reasons)} ✅")

    # 5b) include 白名单(分批上线): 只留选中项, 其余逐条记 skipped
    d2 = discover(_base(include=["huier/x/keep"]), "TOK")
    assert [p["path"] for p in d2["projects"]] == ["huier/x/keep"], d2
    r2 = {s["path"]: s["reason"] for s in d2["skipped"]}
    assert r2["huier/x/skipme"] == "include 白名单未选中", r2
    assert len(r2) == 3, r2
    print(f"5b) include 试点白名单: 保留 1, 跳过 {len(r2)} 逐条记原因 ✅")

    # 6) groups 为空 → 回退 membership 口径
    seen = {}

    def h3(host, token, path, params=None, timeout=30):
        seen["path"] = path
        return 200, [_proj(9, "only/mem")], {}

    _install(h3)
    d = discover(_base(groups=[]), "TOK")
    assert d["ok"] and d["scope"] == "membership", d
    assert seen["path"] == "/api/v4/projects"
    assert seen.get("membership") in (None, "true")
    print(f"6) groups 空 → membership 口径回退 ✅")

    # 7) ref 后缀: default 不加, 指定分支加, refs 覆盖
    def h4(host, token, path, params=None, timeout=30):
        return 200, [_proj(1, "huier/x/a"), _proj(2, "huier/x/b")], {}

    _install(h4)
    d = discover(_base(ref="master", refs={"huier/x/b": "uat"}), "TOK")
    urls = {p["path"]: p["clone_url"] for p in d["projects"]}
    assert urls["huier/x/a"].endswith("#master"), urls
    assert urls["huier/x/b"].endswith("#uat"), urls
    assert to_targets(d)[0][1].endswith(("#master", "#uat"))
    print(f"7) ref: 默认分支后缀 + 按项目覆盖 ✅")

    # 8) 组返回 0 项目 → 显式失败(不产出空清单冒充成功)
    _install(lambda *a, **k: (200, [], {}))
    d = discover(_base(), "TOK")
    assert d["ok"] is False and "0 个项目" in d["error"], d
    print("8) 发现 0 项目 → 显式失败 ✅")

    dg._api_get = REAL_API
    print("\nT15 ACCEPT: PASS  (GitLab 项目发现器)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
