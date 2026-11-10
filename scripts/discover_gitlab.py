# -*- coding: utf-8 -*-
"""GitLab 项目发现（P1a 实现 · auto 模式的清单来源）。

设计（docs/实施方案.md §17）:
    - 范围口径: auto.groups 指定组 + include_subgroups（可审计；groups 为空时
      回退 membership=true，即 token 可见的全部项目）
    - 分页: GET /api/v4/...?per_page=100 跟 X-Next-Page 拉全量
    - 过滤: archived / last_activity_within_days / auto.exclude
    - ref:    auto.ref(default|分支) + auto.refs 按 path_with_namespace 覆盖
    - 命名:   path_with_namespace → 目录名(路径安全 + 冲突序号)，按 project.id 去重
    - 凭证:   API 走 PRIVATE-TOKEN 头；返回的 URL **不含凭证**（克隆凭证由
              git_sync 以 http.extraHeader 注入，不写入 .git/config）
    - 落盘:   清单由 main 写入 reports/current/projects_discovered.json（进归档，
              = "计划扫描什么"的审计证据）

安全: token 只在内存/请求头使用，不打印、不写入任何产物。
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

log = logging.getLogger("font_compliance")

INVALID_CHARS = set('<>:"/\\|?*')


# ---------------------------------------------------------------- HTTP


def _api_get(host: str, token: str, path: str,
             params: dict | None = None, timeout: int = 30):
    """GET {host}/api/v4/... → (status, data, headers)。"""
    url = host.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"PRIVATE-TOKEN": token})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(body) if body else None), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode("utf-8", "replace")[:300]}, {}
    except Exception as e:  # noqa: BLE001
        return 0, {"error": str(e)[:300]}, {}


def _paged(host: str, token: str, path: str, params: dict,
           err: list | None = None) -> list:
    """按 X-Next-Page 分页拉全量；出错时把 (status, msg) 记入 err 并返回已取数据。"""
    out, page = [], 1
    while True:
        st, data, hdr = _api_get(host, token, path,
                                 dict(params, page=page, per_page=100))
        if st != 200:
            if err is not None:
                err.append((st, str(data)[:200]))
            return out
        if not isinstance(data, list) or not data:
            return out
        out.extend(data)
        nxt = hdr.get("X-Next-Page") or hdr.get("x-next-page") or ""
        if not nxt:
            return out
        try:
            page = int(nxt)
        except ValueError:
            return out


def _err_message(err: list) -> str:
    """把 HTTP 错误翻成可执行的提示（不回显 token）。"""
    if not err:
        return ""
    st, msg = err[0]
    if st in (401, 403):
        return (f"GitLab 认证失败 HTTP {st}: token 无效/过期/权限不足"
                f"(需 read_api scope) — {msg[:120]}")
    if st == 404:
        return f"GitLab 返回 404: 组不存在或 token 无权访问 — {msg[:120]}"
    if st == 0:
        return f"GitLab 不可达: {msg[:160]}"
    return f"GitLab API HTTP {st}: {msg[:160]}"


# ---------------------------------------------------------------- 命名


def target_name(path_with_namespace: str, proj_id: int, used: set) -> str:
    """项目路径 → workspace 目录名：路径安全、可读、冲突加序号。

    实测冲突: huier/iacp/backend/huier-datacenter 与
              huier/iacp/frontend/huier-datacenter 叶子同名 → 必须用全路径。
    """
    s = path_with_namespace.replace("/", "__")
    s = "".join("_" if c in INVALID_CHARS else c for c in s)
    s = re.sub(r"\s+", "-", s).strip(". ")[:80]
    base = s or f"project-{proj_id}"
    name, n = base, 2
    while name in used:
        name, n = f"{base}-{n}", n + 1
    used.add(name)
    return name


# ---------------------------------------------------------------- 发现


def _rewrite_host(url: str, host: str) -> str:
    """把 API 返回的仓库地址改写为 auto.host。

    实测(2026-11-10): GitLab external_url 配的是公网地址
    (http://106.124.139.155:8088), 而本机实际可达的是配置里的
    192.168.2.209:8088 —— 直接用 API 返回值克隆会走错地址。
    """
    try:
        u, h = urllib.parse.urlsplit(url), urllib.parse.urlsplit(host)
        if u.netloc and h.netloc and u.netloc != h.netloc:
            return urllib.parse.urlunsplit(
                (h.scheme, h.netloc, u.path, u.query, u.fragment))
    except Exception:  # noqa: BLE001 解析失败则原样返回
        pass
    return url


def discover(auto_cfg: dict, token: str) -> dict:
    """按 auto 配置发现项目，返回清单（结构见模块 docstring）。

    ok=False 时 error 为人类可读原因；调用方必须**显式失败**，不得静默降级。
    """
    host = (auto_cfg.get("host") or "").rstrip("/")
    if not host:
        return {"ok": False, "error": "auto.host 未配置(GitLab 地址)"}
    if not token:
        return {"ok": False,
                "error": f"缺少 token: 请设置环境变量 "
                         f"{auto_cfg.get('token_env', 'GITLAB_TOKEN')}"}
    groups = [str(g).strip() for g in (auto_cfg.get("groups") or [])
              if str(g).strip()]
    include_sub = bool(auto_cfg.get("include_subgroups", True))
    archived = bool(auto_cfg.get("archived", False))

    err: list = []
    raw: list = []
    scope = ""
    if groups:
        scope = "groups+subgroups"
        for g in groups:
            gid = urllib.parse.quote(g, safe="")
            raw.extend(_paged(host, token, f"/api/v4/groups/{gid}/projects", {
                "include_subgroups": str(include_sub).lower(),
                "archived": str(archived).lower(),
                "simple": "true", "order_by": "last_activity_at",
                "sort": "desc"}, err))
    else:
        scope = "membership"
        raw = _paged(host, token, "/api/v4/projects", {
            "membership": "true", "archived": str(archived).lower(),
            "simple": "true", "order_by": "last_activity_at",
            "sort": "desc"}, err)
    if err:
        return {"ok": False, "error": _err_message(err),
                "groups": groups, "scope": scope}

    # 去重(组间共享/重复返回) + 过滤
    incl = {str(x).strip() for x in (auto_cfg.get("include") or [])
            if str(x).strip()}
    excl = {str(x).strip() for x in (auto_cfg.get("exclude") or [])}
    within = auto_cfg.get("last_activity_within_days")
    now = datetime.now(timezone.utc)
    seen: set[int] = set()
    projects, skipped = [], []
    for p in raw:
        pid = p.get("id")
        if pid in seen:
            continue
        seen.add(pid)
        pwn = p.get("path_with_namespace") or p.get("path") or str(pid)
        if incl and pwn not in incl:
            skipped.append({"path": pwn, "reason": "include 白名单未选中"})
            continue
        if pwn in excl:
            skipped.append({"path": pwn, "reason": "配置 exclude 排除"})
            continue
        if p.get("empty_repo"):
            skipped.append({"path": pwn, "reason": "空仓库"})
            continue
        days = None
        iso = p.get("last_activity_at")
        if iso and within:
            try:
                d = datetime.fromisoformat(iso.replace("Z", "+00:00"))
                days = (now - d).days
            except ValueError:
                days = None
            if days is not None and days > int(within):
                skipped.append({"path": pwn,
                                "reason": f"{days} 天未活动(阈值 {within})"})
                continue
        url = _rewrite_host(
            p.get("http_url_to_repo") or (p.get("web_url", "") + ".git"), host)
        ref_map = auto_cfg.get("refs") or {}
        ref = str(ref_map.get(pwn) or auto_cfg.get("ref") or "default")
        projects.append({
            "id": pid, "path": pwn, "name": p.get("name"),
            "default_branch": p.get("default_branch") or None,
            "last_activity_at": iso, "days_inactive": days,
            "url": url, "ref": None if ref in ("", "default") else ref,
        })

    if not projects:
        return {"ok": False, "groups": groups, "scope": scope,
                "error": ("发现 0 个项目: 组路径写错 / token 无权限 / "
                          "全部被 exclude 或活跃度过滤排除"
                          f"（原始返回 {len(raw)} 条）")}

    # 目录命名(按 id 去重后的稳定命名)
    used: set[str] = set()
    for p in projects:
        p["target_name"] = target_name(p["path"], p["id"], used)
        p["clone_url"] = p["url"] + (f"#{p['ref']}" if p["ref"] else "")

    log.info("GitLab 发现: %d 个项目(口径 %s, 组 %d 个, 过滤掉 %d)",
             len(projects), scope, len(groups), len(skipped))
    return {"ok": True, "host": host, "scope": scope, "groups": groups,
            "count": len(projects), "projects": projects, "skipped": skipped,
            "discovered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}


def to_targets(disc: dict) -> list[tuple[str, str]]:
    """发现结果 → main 的目标列表 [(name, url)]（不含 local_mode）。"""
    return [(p["target_name"], p["clone_url"]) for p in disc.get("projects", [])]


def load_discovery(path) -> dict | None:
    """读取上次发现清单（--discover-fallback / 审计回溯用）。"""
    try:
        return json.loads(open(path, encoding="utf-8").read())
    except Exception:  # noqa: BLE001
        return None
