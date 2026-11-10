# -*- coding: utf-8 -*-
"""风险与授权结论引擎（T5 实现 · 迁移自 poc/poc_scan.py assess_family 等）。

核心原则（docs/实施方案.md §15.1，引擎强制执行）:
    扫描只收集证据，不替代授权判断。
    - "已确认允许" 唯一入口 = whitelist.yaml 中 status=active（人工签署）
    - "已确认不允许" 仅由人工判定产生，扫描器永不自动输出
    - 组件许可证不自动继承给组件内字体
    - 识别 != 核实: 无原文归档/范围核对最高只到"证据待补"

四维度输出:
    risk_level / review_status / tech_status / license_status
    + authorization_conclusion / usage_status（见 assess_family docstring）
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import yaml

log = logging.getLogger("font_compliance")

# 第三方组件目录标记（注意: 不含 external —— 常见 Java 包名段, 会误判自有代码）
# uni_modules = uni-app 插件目录(等同前端 node_modules 生态)。2026-11-10 修复(P1-4):
#   缺失时该目录内字体被判"来源不明→高危"，实际来源可从路径直接推导。
# 可在 config/license_rules.yaml 用 third_party_markers 追加更多目录(不覆盖内置)。
THIRD_PARTY_MARKERS = ("bower_components", "node_modules", "vendor",
                       "third_party", "uni_modules")
REPO_LICENSE_RE = re.compile(
    r"^(LICENSE|LICENCE|COPYING|OFL|NOTICE)(\.(\w+))?$", re.I)
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
             "bower.json", "package.json", "composer.lock", "poetry.lock"}
GENERATED_PAT = re.compile(
    r"auto-?generated|code generated|do not edit|@generated", re.I)
CODE_EXTS = {".java", ".js", ".ts", ".vue", ".xml", ".css", ".html", ".sql"}
# 等级严重度（叠加取最高）；授权结论四类见 §15.2
LEVEL_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
LEVEL_LABEL = {"high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
REVIEW_STATUS = {"pending": "待确认", "evaluating": "待评估",
                 "verified": "已核实", "fixed": "已整改", "none": "—"}


# ---------------------------------------------------------------- 规则与白名单


def load_rules(path: str | Path) -> dict:
    """加载 config/license_rules.yaml: 词库 + 许可证分类（引擎运行依赖）。

    可选键 third_party_markers: 追加第三方目录标记（配置驱动, 不覆盖内置）。
    """
    global THIRD_PARTY_MARKERS
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    keywords = [a.strip() for a in
                (data.get("commercial_keywords") or "").split("|") if a.strip()]
    extra = [str(m).strip() for m in (data.get("third_party_markers") or [])
             if str(m).strip()]
    if extra:
        THIRD_PARTY_MARKERS = tuple(dict.fromkeys(THIRD_PARTY_MARKERS + tuple(extra)))
    return {
        "commercial_keywords": keywords,
        "open_spdx": set(data.get("open_spdx") or []),
        "restrict_spdx": set(data.get("restrict_spdx") or []),
    }


def load_whitelist(path: str | Path) -> list[dict]:
    """加载白名单，仅 status=active 生效（"已确认允许"的唯一入口）。"""
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as e:  # noqa: BLE001
        log.warning("白名单解析失败: %s", e)
        return []
    return [e for e in (data.get("entries") or []) if e.get("status") == "active"]


def load_whitelist_all(path: str | Path) -> list[dict]:
    """加载全部白名单条目(含 pending_review/revoked)，供证据目录展示登记状态。"""
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as e:  # noqa: BLE001
        log.warning("白名单解析失败: %s", e)
        return []
    return list(data.get("entries") or [])


# ---------------------------------------------------------------- 许可证识别


def guess_spdx(license_text: str | None, license_url: str | None) -> str:
    """name 表许可证文本/URL → 标准化 SPDX 猜测（识别 ≠ 核实）。"""
    blob = f"{license_text or ''} {license_url or ''}".lower()
    if not blob.strip():
        return "unknown"
    if "sil open font license" in blob or "scripts.sil.org/ofl" in blob:
        return "OFL-1.1"
    if "apache license" in blob and "version 2.0" in blob:
        return "Apache-2.0"
    if re.search(r"\bmit license\b", blob):
        return "MIT"
    if "affero" in blob:
        return "AGPL"
    if "gnu general public license" in blob:
        return "GPL"
    if "creative commons" in blob and ("noncommercial" in blob or "nc/" in blob):
        return "CC-NC"
    if "ubuntu font license" in blob:
        return "UFL-1.0"
    return "custom"


def is_open_expr(expr: str) -> bool:
    e = expr.lower()
    return bool(re.search(r"ofl|apache-2\.0|\bmit\b|bsd|unlicense|cc0", e)) and \
        not re.search(r"gpl|agpl|nc\b|noncommercial", e)


def is_restrict_expr(expr: str) -> bool:
    return bool(re.search(r"gpl|agpl|noncommercial|\bnc\b|cc-by-nc", expr.lower()))


def ambiguity(expr: str | None) -> str | None:
    """表达式歧义（评审 P0-2/P0-3）: unknown 部分 / OR 选项未选择。"""
    if not expr:
        return None
    if "unknown" in expr:
        return "含 unknown-license-reference, 无法识别部分待确认"
    if re.search(r"\bOR\b", expr):
        return "存在 OR 关系(许可选项未选择), 需选择证据"
    return None


def max_level(a: str, b: str) -> str:
    return a if LEVEL_ORDER.get(a, 0) >= LEVEL_ORDER.get(b, 0) else b


def norm_name(s: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


# 尾部字重/样式词（白名单登记名常省略, 如 "...Halflings" vs "...Halflings Regular"）
# 注意: **不含** sc/mono —— SC=简体中文区域后缀(Noto Sans SC)、Mono=独立子族,
#       剥离会把不同字体误判为同族(白名单误放行方向, T14 §3 实测抓出)。
_STYLE_SUFFIX_RE = re.compile(
    r"(regular|bold|italic|light|medium|thin|semibold|extrabold|black|"
    r"condensed|oblique|book|roman)$")


def norm_name_loose(s: str | None) -> str:
    """名称归一化（宽松）: 归一化 + 剥离尾部样式词（结果过短则不剥）。

    P1-5 缺陷修复: 白名单按精确名匹配时, 带 "Regular" 等后缀的系列名
    匹配不上已签署条目, 结论会静默从"已确认允许"回退。
    """
    n = norm_name(s)
    while len(n) > 6:
        m = _STYLE_SUFFIX_RE.search(n)
        if not m:
            break
        stripped = n[: m.start()]
        if len(stripped) < 6:
            break
        n = stripped
    return n


def whitelist_name_match(entry_family: str | None, family: str | None) -> bool:
    """白名单条目名与扫描系列名是否匹配（精确 或 宽松等价）。"""
    a, b = norm_name(entry_family), norm_name(family)
    if not a or not b:
        return False
    return a == b or norm_name_loose(entry_family) == norm_name_loose(family)


def find_whitelist_entry(family: str | None, files: list,
                         whitelist: list | None) -> dict | None:
    """命中白名单条目: 名称匹配(精确/宽松) 或 sha256 精确豁免, 按登记顺序取首个。

    files: 字体系列的文件条目(含 sha256)。whitelist 应为 status=active 条目。
    """
    for e in whitelist or []:
        if whitelist_name_match(e.get("font_family"), family):
            return e
        sha = (e.get("sha256") or "").lower()
        if sha and any((f.get("sha256") or "").lower() == sha for f in files):
            return e
    return None


def perm_and_limit(spdix_or_expr: str | None) -> tuple[str, str]:
    """按已识别许可证推导 允许的使用方式 / 使用限制（台账与报告共用）。"""
    lic = (spdix_or_expr or "").lower()
    if "ofl" in lic:
        return "商用、嵌入、分发、修改", "保留版权与许可证声明 (OFL)"
    if "mit" in lic and "gpl" not in lic:
        return "商用、嵌入、分发、修改", "保留版权与许可声明 (MIT)"
    if re.search(r"cc.*by|by.*4\.0", lic):
        return "商用、嵌入、分发", "必须署名 (CC BY)"
    return "待确认", "待确认"


# ---------------------------------------------------------------- 来源推导


def derive_source(rel_path: str) -> dict:
    """从路径推导来源组件；Java 源码树内目录段是包名，不判第三方。"""
    rp = "/" + rel_path.replace("\\", "/")
    if "/src/main/java/" in rp or "/src/test/java/" in rp:
        return {"source_package": None, "source_dir": None, "third_party": False}
    parts = rel_path.replace("\\", "/").split("/")
    for marker in THIRD_PARTY_MARKERS:
        if marker in parts:
            i = parts.index(marker)
            pkg = parts[i + 1] if i + 1 < len(parts) else None
            return {"source_package": pkg,
                    "source_dir": "/".join(parts[: i + 2]),
                    "third_party": True}
    return {"source_package": None, "source_dir": None, "third_party": False}


def _repo_url(data: dict):
    r = data.get("repository")
    if isinstance(r, dict):
        return r.get("url")
    if isinstance(r, str):
        return r
    return data.get("homepage")


def load_component_meta(root: Path, source_dir: str | None) -> dict:
    """组件版本/来源: 组件目录清单(.bower.json等)；无清单如实报"未记录"。"""
    info = {"source_version": None, "source_url": None, "source_meta_file": None}
    if not source_dir:
        return info
    base = root / source_dir
    for fname in (".bower.json", "bower.json", "package.json"):
        f = base / fname
        if f.exists():
            try:
                data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                info["source_version"] = data.get("version")
                info["source_url"] = _repo_url(data)
                info["source_meta_file"] = f"{source_dir}/{fname}"
                break
            except Exception:  # noqa: BLE001
                pass
    return info


def find_license_files(root: Path) -> list[str]:
    """仓库内许可证类文件清单（posix 相对路径）。"""
    hits = []
    for p in root.rglob("*"):
        if p.is_file() and REPO_LICENSE_RE.match(p.name) and ".git" not in p.parts:
            hits.append(p.relative_to(root).as_posix())
    return sorted(hits)


def index_component_licenses(license_files: list[str]) -> dict:
    """按组件目录归组: {source_dir: [license_file, ...]}。"""
    idx: dict[str, list[str]] = {}
    for lf in license_files:
        src = derive_source(lf)
        if src["source_dir"]:
            idx.setdefault(src["source_dir"], []).append(lf)
    return idx


def build_component_exprs(file_licenses: dict) -> dict:
    """组件级许可证线索: {source_dir: [表达式...]}（**不继承给字体**）。"""
    out: dict[str, set] = {}
    for rel, expr in file_licenses.items():
        s = derive_source(rel)
        if s["source_dir"]:
            out.setdefault(s["source_dir"], set()).add(expr)
    return {k: sorted(v) for k, v in out.items()}
# __PART2__
# ---------------------------------------------------------------- 系列归组


def group_fonts(font_records: list, css_refs: list) -> list[dict]:
    """R3 两级统计: 字体系列(风险主体) -> 文件(整改对象)。

    - 同系列不同格式归为一组；组内按 sha256 合并跨目录相同文件
    - R4 关联推定: 不可解析格式(EOT)按 文件名+来源 并入已有组
    """
    referenced = set()
    for r in css_refs:
        if r.get("value") and r.get("kind") != "font-family":
            referenced.add(Path(r["value"].split("?")[0]).name.lower())
    groups: dict[tuple, dict] = {}

    def new_group(fam: str, fam_norm: str, src: dict) -> dict:
        key = (fam_norm.lower(), src["source_package"] or "-")
        if key not in groups:
            groups[key] = {
                "family": fam, "family_norm": fam_norm,
                "source_package": src["source_package"],
                "source_dir": src["source_dir"],
                "third_party": src["third_party"],
                "files": [], "_by_sha": {}}
        return groups[key]

    def add_file(g: dict, f: dict) -> None:
        meta = f.get("meta", {})
        sha = f["sha256"]
        if sha in g["_by_sha"]:
            g["_by_sha"][sha]["locations"].append(f["path"])
            return
        entry = {
            "path": f["path"], "ext": f["ext"], "sha256": sha,
            "locations": [f["path"]],
            "family_name": meta.get("family"), "ps_name": meta.get("ps_name"),
            "parse_status": meta.get("parse_status"),
            "fs_type": meta.get("fs_type"), "embedding": meta.get("embedding"),
            "font_version": meta.get("version"),
            "copyright": (meta.get("copyright") or "")[:200],
            "license_text": (meta.get("license_text") or "")[:300],
            "license_url": meta.get("license_url"),
            "referenced": Path(f["path"]).name.lower() in referenced,
        }
        g["files"].append(entry)
        g["_by_sha"][sha] = entry

    for f in font_records:                      # 第一遍: 可解析字体按 family 归组
        meta = f.get("meta", {})
        if meta.get("parse_status") != "ok":
            continue
        fam = meta.get("full_name") or meta.get("family") or Path(f["path"]).stem
        fam_norm = re.sub(
            r"[-_ ]?(regular|bold|italic|light|medium|thin|semibold|oblique)\d*$",
            "", fam, flags=re.I).strip() or fam
        add_file(new_group(fam, fam_norm, derive_source(f["path"])), f)

    for f in font_records:                      # 第二遍: EOT 按 stem 关联并入
        if f.get("meta", {}).get("parse_status") == "ok":
            continue
        stem = Path(f["path"]).stem.lower()
        src = derive_source(f["path"])
        target = None
        for g in groups.values():
            if (g["source_package"] or "-") != (src["source_package"] or "-"):
                continue
            if any(Path(e["path"]).stem.lower() == stem for e in g["files"]):
                target = g
                break
        if target is None:
            target = new_group(Path(f["path"]).stem, stem, src)
        add_file(target, f)
    return list(groups.values())


# ---------------------------------------------------------------- 四维评估


def assess_family(g: dict, ctx: dict) -> dict:
    """证据收集 -> 许可证状态 -> 风险等级 -> 审核状态 -> 授权结论 + 使用状态。"""
    files = g["files"]
    parseable = [f for f in files if f["parse_status"] == "ok"]
    unparsable = [f for f in files if f["parse_status"] != "ok"]
    evidence: list[str] = []
    rules_hit: list[str] = []
    rules = ctx.get("rules", {})

    # 证据1: name 表许可证元数据（字体文件自身）
    lic_text = next((f["license_text"] for f in parseable if f["license_text"]), None)
    lic_url = next((f["license_url"] for f in parseable if f["license_url"]), None)
    spdx = guess_spdx(lic_text, lic_url)

    # 证据2: ScanCode 对字体文件自身的匹配（仅字体文件路径）
    exprs = {ctx["file_licenses"].get(loc) for f in files
             for loc in f["locations"]}
    exprs.discard(None)
    license_expression = sorted(exprs)[0] if exprs else None

    # 证据3: 组件目录 LICENSE 原文
    comp_lic = ctx["component_licenses"].get(g["source_dir"] or "", [])
    # 证据4: 来源组件
    src = load_component_meta(ctx["root"], g["source_dir"])
    # 证据5: 组件级许可证线索（不继承给字体）
    comp_exprs = ctx.get("component_exprs", {}).get(g["source_dir"] or "", [])
    # 证据6: 商业字体名称线索（仅辅助识别，不参与定级）
    fam_blob = (g["family"] + " " + " ".join(
        f.get("license_text") or "" for f in parseable)).lower()
    commercial_hits = [kw for kw in rules.get("commercial_keywords", [])
                       if kw.lower() in fam_blob]
    # 证据7: 白名单（人工核实登记；名称宽松匹配 + sha256 精确豁免, P1-5）
    wl = find_whitelist_entry(g["family"], files, ctx.get("whitelist"))

    # ---- 许可证状态与基础风险（仅字体文件自身证据） ----
    font_basis = bool(lic_text or lic_url or license_expression)
    amb = ambiguity(license_expression)

    if wl:
        license_status = "已核实"
        level = "low"
        rules_hit.append("whitelist_hit")
        evidence.append(
            f"白名单命中: {wl.get('font_family')} / {wl.get('license')} / "
            f"来源 {wl.get('source', '-')}; 授权条件: {wl.get('conditions', '-')}; "
            f"登记依据: {wl.get('evidence', '-')}")
    elif not font_basis:
        license_status = "未知"
        if g["source_package"]:
            level = "medium"
            rules_hit.append("meta_license_missing")
            evidence.append(
                "name表许可证字段为空, 字体文件自身无 ScanCode 匹配; "
                f"来源组件={g['source_package']}"
                + (f"(版本 {src['source_version']})" if src["source_version"]
                   else "(版本未记录)")
                + ("; 组件内有 LICENSE 原文" if comp_lic
                   else "; 组件内未找到 LICENSE 文件"))
            if comp_exprs:
                evidence.append("组件级许可证线索: " + "; ".join(comp_exprs[:3])
                                + " —— 组件许可证不自动适用于组件内字体文件, "
                                  "字体授权需单独核实")
                rules_hit.append("component_license_not_inherited")
        else:
            # P1-4: "来源不明"须同时无路径线索**且**无版权声明线索;
            # 有版权声明=可追溯来源, 降为中危待评估, 不产生"暂停发布"级告警
            cps = sorted({(f.get("copyright") or "").strip() for f in files
                          if (f.get("copyright") or "").strip()})
            if cps:
                level = "medium"
                rules_hit.append("source_clue_no_auth")
                evidence.append(
                    "许可证字段为空, 且无法从路径推导来源组件; 但存在版权声明线索: "
                    + "; ".join(c[:80] for c in cps[:2])
                    + " —— 可据此追溯来源(图标平台导出记录/上游发行包), "
                      "补齐授权依据前不得视为已授权")
            else:
                level = "high"
                rules_hit.append("source_unknown_no_auth")
                evidence.append("许可证字段为空, 且无法从路径推导来源组件"
                                "、无任何版权声明线索, 无法提供授权依据")
        if not parseable:
            rules_hit.append("unparsable")
            exts = ",".join(sorted({f["ext"] for f in unparsable}))
            evidence.append(f"格式 {exts} 不支持解析(技术限制), 不产生版权结论")
    elif amb:
        license_status = "存在冲突"
        level = "medium"
        rules_hit.append("license_conflict")
        evidence.append(f"ScanCode 匹配存在歧义: {license_expression}（{amb}）")
    elif spdx in rules.get("open_spdx", set()) or (
            license_expression and is_open_expr(license_expression)):
        license_status = "证据待补"
        level = "low"
        rules_hit.append("license_identified")
        basis = license_expression or lic_url or "name表许可证字段"
        evidence.append(f"已识别许可证线索: {basis}")
        if lic_url and not lic_text:
            evidence.append(f"仅有许可证 URL({lic_url}) —— URL 是线索, "
                            "不能代替归档的许可证原文")
        if comp_lic:
            evidence.append(f"组件内 LICENSE 原文: {', '.join(comp_lic[:3])}"
                            " —— 仍需核对适用版本与使用/分发条件后方可标已核实")
        else:
            evidence.append("未找到许可证原文文件; 补齐 原文归档+版本+适用范围核对 "
                            "后方可标记已核实")
    elif spdx in rules.get("restrict_spdx", set()) or (
            license_expression and is_restrict_expr(license_expression)):
        license_status = "已识别"
        level = "medium"
        rules_hit.append("restrictive_license")
        evidence.append("已识别限制性许可证: "
                        + (spdx if spdx != "custom" else license_expression)
                        + "; 需结合分发方式、链接方式评估, 不凭名称判违规")
    else:
        license_status = "已识别"
        level = "low"
        rules_hit.append("license_custom")
        evidence.append("存在非标准/自定义许可证信息: "
                        + (lic_url or license_expression or "")[:80]
                        + " —— 待人工确认适用性")

    # ---- fsType 叠加（措辞按评审 P1-5 模板） ----
    fs_values = {f["fs_type"] for f in parseable if f.get("fs_type") is not None}
    fs_restrict = None
    if any(v & 0x0002 for v in fs_values):
        fs_restrict = "0x0002(Restricted: 禁止嵌入)"
    elif any(v & 0x0004 for v in fs_values):
        fs_restrict = "0x0004(Preview & Print: 预览和打印)"
    if fs_restrict:
        level = max_level(level, "medium")
        rules_hit.append("fs_embed_restriction")
        evidence.append(
            f"字体嵌入限制: fsType={fs_restrict}。"
            "技术说明: 该标志表示字体嵌入权限受限, 需结合实际字体交付方式、"
            "浏览器加载方式、字体授权条款及项目分发方式进行核实。"
            "风险结论: 当前证据不足以认定侵权, 也不足以确认所有使用场景均符合授权。")
        if g["source_package"]:
            evidence.append(f"注意: {g['source_package']} 组件整体许可证不自动覆盖"
                            "组件内第三方字体, 字体授权条件需单独核实")
    elif parseable:
        evidence.append("fsType=0(无嵌入限制, 不作为版权风险证据)")

    if commercial_hits:      # 名称线索不参与定级（评审 P2-9）
        evidence.append("商业字体名称线索(仅辅助识别, 不代表授权状态或侵权结论): "
                        + ", ".join(commercial_hits))
        rules_hit.append("commercial_name_hint")

    if unparsable and parseable:
        evidence.append(
            f"组内 {len(unparsable)} 个文件格式不支持解析"
            f"({','.join(sorted({f['ext'] for f in unparsable}))}), "
            "其版权判定继承同系列可解析格式的证据")

    # ---- 审核状态 / 技术状态（与风险等级分离） ----
    if license_status == "已核实":
        review = "verified"
    elif fs_restrict or "restrictive_license" in rules_hit:
        review = "evaluating"
    elif level == "info":
        review = "none"
    else:
        review = "pending"
    if not parseable:
        tech_status = "不支持"
    elif unparsable:
        tech_status = "部分不支持"
    else:
        tech_status = "正常"

    # ---- 授权结论（四类；扫描器只给证据性结论） ----
    if wl:
        conclusion = "已确认允许"
    elif (not parseable and not license_expression and not comp_lic
          and not lic_text and not lic_url):
        conclusion = "技术无法判断"
    else:
        conclusion = "授权待确认"
    # "已确认不允许"需人工判定, 扫描器不自动产生

    # ---- 使用状态（与结论独立） ----
    usage = ("存在引用但未确认运行时使用" if any(f["referenced"] for f in files)
             else "未发现引用")

    # ---- 处置建议 ----
    if level == "high":
        suggestion = "暂停发布或替换; 联系来源方补充授权证明"
    elif license_status == "存在冲突":
        suggestion = "消除表达式歧义: 定位 unknown 来源 / 补充 OR 许可选择证据"
    elif fs_restrict:
        suggestion = "核对原始字体授权协议及实际使用方式(交付/加载/分发方式)"
    elif license_status == "未知":
        suggestion = (f"查找许可证文件与来源(组件: {g['source_package'] or '未知'}), "
                      "补充字体级授权依据")
    elif license_status == "证据待补":
        suggestion = "补齐许可证原文归档、适用版本与范围核对后, 再申请标记已核实"
    elif level == "medium":
        suggestion = "结合分发方式评估限制性条款, 必要时法务确认"
    elif level == "low":
        suggestion = "记录许可证线索与来源, 待人工核对后归档"
    else:
        suggestion = "仅记录, 无需处理"
    if "source_clue_no_auth" in rules_hit:
        suggestion += "; 有版权声明线索, 可先据此追溯来源再决定是否替换"

    versions = sorted({f["font_version"] for f in files if f.get("font_version")})
    out = {k: v for k, v in g.items() if not k.startswith("_")}
    out.update({
        "font_version": versions[0] if versions else None,
        "font_versions_all": versions,
        "source_version": src["source_version"],
        "source_url": src["source_url"],
        "source_meta_file": src["source_meta_file"],
        "license_spdx": spdx if spdx != "unknown" else None,
        "license_expression": license_expression,
        "license_files": comp_lic[:5],
        "license_status": license_status,
        "authorization_conclusion": conclusion,
        "usage_status": usage,
        "evidence_dir": "font-compliance/" + re.sub(
            r"[^A-Za-z0-9]+", "-", g["family"]).strip("-") + "/",
        "evidence": evidence,
        "risk_level": level,
        "review_status": REVIEW_STATUS[review],
        "tech_status": tech_status,
        "rules_hit": rules_hit,
        "suggestion": suggestion,
        "commercial_hits": commercial_hits,
        "referenced": any(f["referenced"] for f in files),
        "alerts": [],
    })
    return out
# __PART3__
# ---------------------------------------------------------------- 组件评估


def assess_component(exprs: list, license_files: list) -> dict:
    """组件级评估（评审 P0-2/P0-3）: 识别 != 核实。
    unknown / OR 歧义 -> 存在冲突；无原文最高只到"已识别/证据待补"。"""
    if not exprs and not license_files:
        return {"license_status": "未知", "risk_level": "medium",
                "review_status": "待确认",
                "note": "未匹配到许可证文本且无 LICENSE 文件; 需查上游发行包"}
    conflict_notes, restrict, open_all = [], False, True
    for e in exprs:
        if "unknown" in e:
            conflict_notes.append(f"「{e}」含无法识别部分")
        if re.search(r"\bOR\b", e):
            conflict_notes.append(f"「{e}」存在 OR 选项未选择")
        if is_restrict_expr(e):
            restrict = True
        if not is_open_expr(e):
            open_all = False
    if conflict_notes:
        return {"license_status": "存在冲突", "risk_level": "medium",
                "review_status": "待确认",
                "note": "; ".join(conflict_notes) + "; 整体不得标已核实"}
    if restrict or not open_all:
        return {"license_status": "已识别", "risk_level": "medium",
                "review_status": "待评估",
                "note": "含限制性/未识别许可证, 需结合分发方式、链接方式评估"}
    if license_files:
        return {"license_status": "证据待补", "risk_level": "low",
                "review_status": "待确认",
                "note": f"有 LICENSE 原文 {len(license_files)} 份; "
                        "待核对适用版本与使用/分发条件后方可标已核实"}
    return {"license_status": "已识别", "risk_level": "low",
            "review_status": "待确认",
            "note": "已识别许可证但组件内无原文文件; 补发行包原文+版本+条件核对 "
                    "后方可标已核实"}


# ---------------------------------------------------------------- 仓库许可证


def _marker_of(rel: str) -> str | None:
    parts = rel.split("/")
    for m in THIRD_PARTY_MARKERS:
        if m in parts:
            return m
    return None


def _is_generated(root: Path, rel: str) -> bool:
    """自动生成代码启发式: 路径/文件名 或 文件头标记（评审 P1-7）。"""
    p = rel.lower()
    if re.search(r"(\.generated\.|_generated\.|\.gen\.)", p) or "/generated/" in p:
        return True
    if Path(p).suffix not in CODE_EXTS:
        return False
    try:
        head = (root / rel).open("rb").read(400).decode("utf-8", "ignore")
        return bool(GENERATED_PAT.search(head))
    except Exception:  # noqa: BLE001
        return False


def build_repo_license(root: Path, all_files: list[str], file_licenses: dict,
                       license_files: list[str]) -> dict:
    """自有代码五分类 + 组件实例评估 + 唯一/实例/重复三口径统计。

    all_files: posix 相对路径列表（scan_projects.inventory）
    """
    import hashlib

    third: dict[str, dict] = {}
    own_exprs: dict[str, int] = {}
    categories: dict[str, int] = {}
    third_sha: dict[str, set] = {}
    copyleft_suspects: list[str] = []
    lock_files = 0

    def bump(key: str) -> None:
        categories[key] = categories.get(key, 0) + 1

    for rel in all_files:
        base = Path(rel).name
        expr = file_licenses.get(rel)
        marker = _marker_of(rel)
        src = derive_source(rel)

        if src["third_party"]:
            bump("Vendor引入代码" if marker == "vendor" else "第三方组件代码")
            c = third.setdefault(src["source_dir"], {
                "component": src["source_package"], "file_count": 0,
                "exprs": set(), "shas": set()})
            c["file_count"] += 1
            if expr:
                c["exprs"].add(expr)
            try:
                sha = hashlib.sha256((root / rel).read_bytes()).hexdigest()
                c["shas"].add(sha)
                third_sha.setdefault(sha, set()).add(src["source_dir"])
            except Exception:  # noqa: BLE001
                pass
        elif base in LOCKFILES:
            bump("依赖清单")
            lock_files += 1
        elif _is_generated(root, rel):
            bump("自动生成代码")
        elif expr and re.search(r"\b(gpl|lgpl|cpl)[- ]?\d|agpl", expr, re.I):
            # 自有路径检出 copyleft -> 来源待确认（评审 P1-7, 不凭名称判违规）
            bump("来源待确认代码")
            if len(copyleft_suspects) < 10:
                copyleft_suspects.append(f"{rel} => {expr}")
        else:
            bump("项目自有代码")
            if expr:
                own_exprs[expr] = own_exprs.get(expr, 0) + 1

    root_lic = [lf for lf in license_files if "/" not in lf]
    instances = []
    for d, c in sorted(third.items()):
        comp_lic = [lf for lf in license_files if lf.startswith(d + "/")][:5]
        a = assess_component(sorted(c["exprs"]), comp_lic)
        instances.append({
            "component": c["component"], "source_dir": d,
            "file_count": c["file_count"],
            "exprs": sorted(c["exprs"])[:8],
            "license_files": comp_lic,
            **a,   # license_status / risk_level / review_status / note
        })

    # 三口径（评审 P1-8）: 唯一组件(名称+许可证主体) / 实例 / 跨实例重复文件
    unique = {(i["component"], tuple(i["exprs"])) for i in instances}
    duplicate_files = sum(1 for _, dirs in third_sha.items() if len(dirs) > 1)

    return {
        "own": {
            "file_count": categories.get("项目自有代码", 0),
            "lockfile_count": lock_files,
            "license_files": root_lic,
            "declared": ("已声明(见 " + ", ".join(root_lic) + ")" if root_lic
                         else "未声明(仓库根无 LICENSE/COPYING; 内部项目属正常情况)"),
            "detected_exprs": dict(sorted(own_exprs.items(),
                                          key=lambda x: -x[1])[:10]),
            "categories": categories,
            "copyleft_suspects": copyleft_suspects,
        },
        "third_party": instances,
        "third_party_file_count": sum(c["file_count"] for c in third.values()),
        "component_stats": {
            "unique_components": len(unique),
            "instances": len(instances),
            "duplicate_files": duplicate_files,
        },
        "note": "组件按实例(目录)记录; 识别 != 核实, 已核实需 原文+版本+适用范围+"
                "条件核对; 聚合表达式仅作原始证据; GPL/AGPL 需结合分发方式评估, "
                "不凭名称判违规",
    }
