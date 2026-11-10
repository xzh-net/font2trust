# -*- coding: utf-8 -*-
"""报告生成（T7 实现 · 五区块结构，迁移自 poc/report_html.py）。

输出:
    report.html —— 五区块(01 总览 / 02 授权结论 / 03 证据详情 / 04 整改清单 /
                    05 CSS 链) + 06 组件合规 + 07 名称线索 + 免责声明
    report.json —— 机读原始数据
模板: templates/report.html（与代码分离，样式调整不动逻辑）
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from pathlib import Path
from string import Template

from .analyze_risks import LEVEL_LABEL, perm_and_limit
from .utils import PROJECT_ROOT

log = logging.getLogger("font_compliance")

BADGE_CLS = {"high": "badge-high", "medium": "badge-medium",
             "low": "badge-low", "info": "badge-info"}
REVIEW_CLS = {"待确认": "rv-pending", "待评估": "rv-eval",
              "已核实": "rv-ok", "已整改": "rv-fixed", "—": "rv-none"}
LIC_CLS = {"已识别": "lc-id", "证据待补": "lc-sup", "已核实": "lc-ok",
           "存在冲突": "lc-conf", "未知": "lc-unk"}
CONCL_CLS = {"已确认允许": "cc-allow", "已确认不允许": "cc-deny",
             "授权待确认": "cc-pending", "技术无法判断": "cc-tech"}
CONCL_ORDER = ["已确认允许", "已确认不允许", "授权待确认", "技术无法判断"]
RULE_CN = {
    "meta_license_missing": "字体许可证元数据缺失",
    "fs_embed_restriction": "存在嵌入限制标志(fsType)",
    "fs_embed_preview_print": "存在预览打印嵌入限制(fsType)",
    "license_conflict": "许可证表达式存在歧义(unknown/OR)",
    "component_license_not_inherited": "组件许可证不可直接继承给字体",
    "unparsable": "存在不可解析格式(EOT)",
    "whitelist_hit": "白名单命中",
    "source_unknown_no_auth": "来源不明且无授权依据",
    "license_identified": "已识别许可证线索(待证据核实)",
    "restrictive_license": "限制性许可证",
    "commercial_name_hint": "商业字体名称线索",
    "license_custom": "非标准许可证文本",
}


def esc(s) -> str:
    return (str(s if s is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def badge(level: str) -> str:
    return (f'<span class="badge {BADGE_CLS.get(level, "badge-info")}">'
            f'{LEVEL_LABEL.get(level, level)}</span>')


def rv_badge(text) -> str:
    t = text or "—"
    return f'<span class="rv {REVIEW_CLS.get(t, "rv-none")}">{esc(t)}</span>'


def lc_badge(text) -> str:
    key = (text or "未知").split("(")[0]
    return f'<span class="lc {LIC_CLS.get(key, "lc-unk")}">{esc(text)}</span>'


def cc_badge(text) -> str:
    return f'<span class="cc {CONCL_CLS.get(text, "cc-tech")}">{esc(text)}</span>'


def coverage_rows(reports: list) -> str:
    rows = []
    for r in reports:
        c = r["coverage"]
        rows.append(
            f'<tr><td><b>{esc(r["repo"]["name"])}</b></td>'
            f'<td>{c.get("files_total", 0)}</td>'
            f'<td>{c.get("font_series", 0)} / {c.get("font_files", 0)}'
            f'（去重 {c.get("font_files_unique", 0)}）</td>'
            f'<td>{c.get("parse_ok", 0)} / {c.get("parse_fail", 0)}</td>'
            f'<td>{c.get("css_refs", 0)}</td>'
            f'<td>{esc(c.get("scancode"))}</td>'
            f'<td>{c.get("license_files", 0)}</td>'
            f'<td>{c.get("own_files", 0)} / {c.get("third_party_files", 0)}</td></tr>')
    return "\n".join(rows) or '<tr><td colspan="8" class="muted">无数据</td></tr>'


def files_block(s) -> str:
    lines = []
    for f in s["files"]:
        meta = (f"{f.get('ext')} · sha256:{(f.get('sha256') or '')[:12]} · "
                f"解析:{f.get('parse_status')} · fsType:{f.get('fs_type')} · "
                f"{'CSS已引用' if f.get('referenced') else '未见引用'}")
        lines.append(f'<div class="f">📁 {esc(f.get("path"))}</div>'
                     f'<div class="muted">{esc(meta)}</div>')
        for loc in f.get("locations", [])[1:]:
            lines.append(f'<div class="loc">└ 相同文件位置: {esc(loc)}</div>')
    return (f'<details><summary>{len(s["files"])} 文件 · '
            f'{sum(len(f.get("locations", [])) for f in s["files"])} 位置</summary>'
            f'<div class="filelist">{"".join(lines)}</div></details>')


def reasons_of(s) -> str:
    return "；".join(RULE_CN.get(r, r) for r in s.get("rules_hit", [])) or "-"


def concl_rows(reports: list) -> str:
    rows = []
    for r in reports:
        for s in r.get("font_series", []):
            rows.append(
                f'<tr data-level="{s["risk_level"]}">'
                f"<td><b>{esc(s['family'])}</b></td>"
                f"<td>{cc_badge(s.get('authorization_conclusion'))}</td>"
                f"<td>{esc(s.get('usage_status'))}</td>"
                f"<td>{lc_badge(s.get('license_status'))}</td>"
                f"<td>{esc(s.get('font_version') or '未记录')}<br>"
                f'<span class="muted">{esc(s.get("source_package") or "未推导")}</span></td>'
                f'<td class="ev">{esc(reasons_of(s))}</td>'
                f'<td class="sug">{esc(s.get("suggestion"))}</td>'
                f'<td class="path">{esc(s.get("evidence_dir"))}</td></tr>')
    return "\n".join(rows) or '<tr><td colspan="8" class="muted">无字体系列</td></tr>'
# __PART2__
def series_rows(reports: list) -> str:
    rows = []
    for r in reports:
        for s in r.get("font_series", []):
            fam = esc(s["family"])
            if s.get("commercial_hits"):
                fam += ('<span class="hit">名称线索: '
                        + esc(", ".join(s["commercial_hits"])) + "</span>")
            ver = esc(s.get("font_version") or "版本未记录")
            hints = s.get("css_font_families") or []
            hint = (f'<div class="muted">CSS: {esc(" | ".join(hints))}</div>'
                    if hints else "")
            alerts = "".join(f'<span class="alert">⚠️ {esc(a)}</span>'
                             for a in (s.get("alerts") or []))
            src = esc(s.get("source_package") or "未推导出组件")
            if s.get("source_version"):
                src += f' <span class="muted">@{esc(s["source_version"])}</span>'
            if s.get("source_url"):
                src += (f'<br><a href="{esc(s["source_url"])}" target="_blank">'
                        f'{esc(s["source_url"])}</a>')
            src += ('<br><span class="muted">上游标签与哈希比对见 '
                    f'{esc(s.get("evidence_dir"))}source-info.txt</span>')
            lic = lc_badge(s.get("license_status") or "未知")
            if s.get("license_expression"):
                lic += f'<br><span class="muted">{esc(s["license_expression"])}</span>'
            if s.get("license_spdx"):
                lic += f'<br><span class="muted">{esc(s["license_spdx"])}</span>'
            lic += (f'<br><code class="muted">{esc(s.get("evidence_dir"))}'
                    f'LICENSE.txt</code>')
            perm, limit = perm_and_limit(
                s.get("license_expression") or s.get("license_spdx"))
            scope = f"<b>允许</b>: {esc(perm)}<br><b>限制</b>: {esc(limit)}"
            ev = "<ul class='ev'>" + "".join(
                f"<li>{esc(e)}</li>" for e in s.get("evidence", [])) + "</ul>"
            wl = ("active（已确认允许）" if s.get("license_status") == "已核实"
                  else "pending_review（待负责人确认）")
            audit = (f"{rv_badge(s.get('review_status'))} {badge(s['risk_level'])}"
                     f"<br>技术: {esc(s.get('tech_status'))}"
                     f"<br>白名单: {esc(wl)}"
                     f"<br><code class='muted'>{esc(s.get('evidence_dir'))}"
                     f"review-record.md</code>"
                     f"<br><span class='muted'>签署: 待负责人签</span>")
            rows.append(
                f'<tr data-level="{s["risk_level"]}"'
                f'{" data-commercial=\"1\"" if s.get("commercial_hits") else ""}>'
                f"<td><b>{fam}</b><div class='muted'>{ver}</div>{hint}{alerts}</td>"
                f"<td>{src}</td><td>{lic}</td><td>{scope}</td>"
                f'<td class="ev">{ev}</td><td>{audit}</td>'
                f"<td>{files_block(s)}</td></tr>")
    return "\n".join(rows) or (
        '<tr><td colspan="7" class="muted">未发现字体文件</td></tr>')


def remediation_rows(reports: list) -> str:
    """整改清单（五类整改方式映射, 责任人/期限占位）。"""
    tasks = []
    for r in reports:
        for s in r.get("font_series", []):
            if s.get("authorization_conclusion") != "已确认允许":
                action = ("③ 找不到许可证→追溯上游/归档原文并登记白名单"
                          if s.get("license_status") in ("未知", "存在冲突")
                          else "① 已确认允许前置：复核证据并登记白名单(active)")
                if s.get("tech_status") == "不支持":
                    action += "；⑤ 不可解析格式→人工检查"
                tasks.append((s["family"], reasons_of(s), action,
                              f"{len(s['files'])} 文件 / "
                              f"{sum(len(f.get('locations', [])) for f in s['files'])} 位置",
                              "待指派", "待定", "待复查"))
            for a in s.get("alerts", []):
                tasks.append((s["family"], a,
                              "④ 清理未用/遗留引用（确认 Font Awesome 5 引用是否生效）",
                              "CSS 引用", "前端", "待定", "待复查"))
            if s.get("usage_status") == "未发现引用":
                tasks.append((s["family"], "未发现 CSS 引用",
                              "④ 字体未被实际使用→清理（确认部署后删除）",
                              f"{len(s['files'])} 文件", "待指派", "待定", "待复查"))
        own = r.get("repo_license", {}).get("own", {})
        for sus in (own.get("copyleft_suspects") or [])[:5]:
            tasks.append(("来源待确认文件", sus,
                          "③ 追溯来源→归类第三方组件（补充目录标记）",
                          "1 文件", "待指派", "待定", "待复查"))
        st = r.get("repo_license", {}).get("component_stats", {})
        if st.get("duplicate_files"):
            tasks.append(("重复部署资源",
                          f"两模块字体/组件字节级相同（重复文件 {st['duplicate_files']}）",
                          "确认部署清单：仅部署一份则清理重复（未确认前不删除）",
                          f"重复文件 {st['duplicate_files']}", "部署负责人",
                          "待定", "待复查"))
        tasks.append(("署名义务",
                      "Glyphicons（CC BY 惯例）与 Material Icons（CC BY 4.0）建议署名",
                      "① 已确认允许的前置：页脚补充署名",
                      "页脚/关于页", "前端", "待定", "待复查"))
    rows = []
    for i, t in enumerate(tasks, 1):
        rows.append(
            f'<tr data-level="medium"><td>{i}</td><td><b>{esc(t[0])}</b></td>'
            f'<td class="ev">{esc(t[1])}</td><td>{esc(t[2])}</td>'
            f'<td>{esc(t[3])}</td><td>{esc(t[4])}</td><td>{esc(t[5])}</td>'
            f'<td>{esc(t[6])}</td></tr>')
    return "\n".join(rows) or '<tr><td colspan="8" class="muted">无整改任务</td></tr>'


def css_rows(reports: list) -> str:
    rows = []
    for r in reports:
        for c in r.get("css_refs", []):
            lv = c.get("risk_level", "info")
            exists = c.get("exists")
            link = ("已关联本地文件" if exists is True
                    else '<span class="hit">关联缺失</span>' if exists is False
                    else ("未关联(可能系统/通用字体)"
                          if c.get("kind") == "font-family"
                          else "远程字体资源(CDN)"))
            chain = c.get("linked_series")
            chain_html = (f'<span class="chain">→ {esc(chain)} → 见03许可证证据</span>'
                          if chain else '<span class="muted">—</span>')
            rows.append(
                f'<tr data-level="{lv}"><td>{esc(c.get("kind"))}</td>'
                f'<td class="path">{esc(c.get("file"))}:{c.get("line")}</td>'
                f'<td class="path">{esc(c.get("value"))}'
                + (f' <span class="muted">({esc(c.get("format"))})</span>'
                   if c.get("format") else "") + "</td>"
                f"<td>{esc(c.get('format') or '-')}</td>"
                f"<td>{link}</td><td>{chain_html}</td>"
                f'<td class="sug">{esc(c.get("suggestion"))}</td></tr>')
    return "\n".join(rows) or '<tr><td colspan="7" class="muted">无字体引用</td></tr>'


def repo_rows(reports: list) -> str:
    rows = []
    for r in reports:
        for c in r.get("repo_license", {}).get("third_party", []):
            lv = c.get("risk_level", "medium")
            exprs = ", ".join(c.get("exprs") or []) or "未匹配到许可证文本"
            lic_files = ", ".join(c.get("license_files") or []) or "无"
            rows.append(
                f'<tr data-level="{lv}"><td>{badge(lv)}</td>'
                f"<td>{rv_badge(c.get('review_status', '—'))}</td>"
                f"<td>{lc_badge(c.get('license_status', '未知'))}</td>"
                f"<td><b>{esc(c.get('component'))}</b><br>"
                f'<span class="path muted">{esc(c.get("source_dir"))}</span></td>'
                f"<td>{c.get('file_count', 0)}</td>"
                f'<td class="path">{esc(exprs)}</td>'
                f'<td class="path">{esc(lic_files)}</td>'
                f'<td class="sug">{esc(c.get("note"))}</td></tr>')
    return "\n".join(rows) or '<tr><td colspan="8" class="muted">无第三方组件</td></tr>'


def _norm(s) -> str:
    import re
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def plan_block(plan: dict | None) -> dict:
    """00｜扫描任务清单 区块字段（P1b: 覆盖可自证）。

    plan 由 main 传入; 缺省时给占位值(旧版/单测调用不传也不会报错)。
    """
    if not plan:
        return {"p_planned": "-", "p_scanned": "-", "p_failed": "-",
                "p_skipped": "-", "p_mode": "-", "p_scope": "-",
                "p_note": "本次调用未提供扫描任务清单。",
                "p_plan_rows": '<tr><td colspan="3" class="muted">无清单</td></tr>'}
    c = plan.get("counts", {})
    scanned = {s.get("name"): s for s in plan.get("scanned", [])}
    failed = {f.get("name"): f for f in plan.get("failed", [])}
    rows = []
    for p in plan.get("planned", []):
        n = p.get("name", "?")
        if n in scanned:
            s = scanned[n]
            state, detail = "✅ 成功", (f"文件 {s.get('files')} · 字体系列 "
                                       f"{s.get('series')} · 字体文件 "
                                       f"{s.get('fonts')}")
        elif n in failed:
            f = failed[n]
            state = "❌ 失败"
            detail = f"[{f.get('stage')}] {f.get('error')}"
        else:
            state, detail = "⏭ 未执行", "—"
        rows.append(f"<tr><td>{esc(n)}</td><td>{state}</td>"
                    f"<td>{esc(str(detail))}</td></tr>")
    for s in plan.get("skipped", []):
        rows.append(f"<tr><td>{esc(str(s.get('path')))}</td><td>⏭ 过滤</td>"
                    f"<td>{esc(str(s.get('reason')))}</td></tr>")
    note_parts = []
    if plan.get("host"):
        note_parts.append(f"发现来源: {esc(str(plan['host']))}"
                          f"（口径 {esc(str(plan.get('scope') or '-'))}）")
    if plan.get("fallback_reason"):
        note_parts.append(f"⚠️ 使用上次发现清单，原因: "
                          f"{esc(str(plan['fallback_reason']))}")
    note_parts.append("本区块用于证明扫描覆盖：计划数与成功/失败/过滤逐条可核对。")
    return {
        "p_planned": c.get("planned", 0), "p_scanned": c.get("scanned", 0),
        "p_failed": c.get("failed", 0), "p_skipped": c.get("skipped", 0),
        "p_mode": esc(str(plan.get("mode") or "-")),
        "p_scope": esc(str(plan.get("scope") or "-")),
        "p_note": " ｜ ".join(note_parts),
        "p_plan_rows": "\n".join(rows)
                        or '<tr><td colspan="3" class="muted">无计划项</td></tr>',
    }


def generate_report(result, out_dir: Path,
                    templates_dir: Path | None = None,
                    plan: dict | None = None) -> tuple[Path, Path]:
    """生成 report.html + report.json。

    result: 单个扫描结果 dict（poc_report 结构）或其列表（多仓库）。
    plan:   扫描任务清单（计划/成功/失败/过滤），渲染 00 区块。
    返回 (html_path, json_path)。
    """
    reports = result if isinstance(result, list) else [result]
    templates_dir = templates_dir or (PROJECT_ROOT / "templates")
    tpl_path = templates_dir / "report.html"
    tpl = Template(tpl_path.read_text(encoding="utf-8"))

    series_all = [s for r in reports for s in r.get("font_series", [])]
    css_all = [c for r in reports for c in r.get("css_refs", [])]

    # 01 总览
    a = {
        "series": len(series_all),
        "files": sum(len(s["files"]) for s in series_all),
        "locs": sum(sum(len(f.get("locations", [])) for f in s["files"])
                    for s in series_all),
        "ref": sum(1 for s in series_all for f in s["files"] if f.get("referenced")),
        "ok": sum(1 for s in series_all for f in s["files"]
                  if f.get("parse_status") == "ok"),
    }
    a["unref"] = a["files"] - a["ref"]
    a["fail"] = a["files"] - a["ok"]
    namefams = sorted({c["value"] for c in css_all if c["kind"] == "font-family"})
    a["namefam"] = len(namefams)

    asset_chips = " · ".join(
        f"{esc(s['family'])}({len(s['files'])})" for s in series_all) or "无"
    sys_words = ("serif", "sans-serif", "monospace", "helvetica", "arial",
                 "menlo", "monaco", "consolas", "courier", "system-ui", "inherit")
    name_chips = []
    for n in namefams:
        low = n.lower()
        if any(w in low for w in sys_words) and not any(
                w in low for w in ("awesome", "glyphicon", "ionicon")):
            name_chips.append(
                f'<span class="chip sys">🔤 {esc(n)}（系统/通用回退）</span>')
        else:
            miss = not any(_norm(n) in _norm(s["family"])
                           or _norm(s["family"]) in _norm(n)
                           for s in series_all)
            cls, tag = (("chip miss", "⚠️ 仓库无对应字体文件") if miss
                        else ("chip", "✅ 有对应字体"))
            name_chips.append(f'<span class="chip {cls}">🔤 {esc(n)} — {tag}</span>')

    # 02 四结论 + 使用状态
    cc = {k: 0 for k in CONCL_ORDER}
    uu = {"正在使用": 0, "存在引用但未确认运行时使用": 0, "未发现引用": 0}
    for s in series_all:
        c = s.get("authorization_conclusion", "授权待确认")
        cc[c] = cc.get(c, 0) + 1
        u = s.get("usage_status", "")
        uu[u] = uu.get(u, 0) + 1

    # 06 组件统计
    comps = [c for r in reports
             for c in r.get("repo_license", {}).get("third_party", [])]
    stats_all = [r["repo_license"].get("component_stats", {}) for r in reports]
    st = {
        "instances": len(comps),
        "unique": sum(s.get("unique_components", 0) for s in stats_all),
        "dup": sum(s.get("duplicate_files", 0) for s in stats_all),
        "low": sum(1 for c in comps if c.get("risk_level") == "low"),
        "medium": sum(1 for c in comps if c.get("risk_level") == "medium"),
        "pending": sum(1 for c in comps if c.get("review_status") == "待确认"),
    }

    # 05 部署模块
    modules = sorted({f["path"].split("/")[0] for s in series_all
                      for f in s["files"] if "/" in f["path"]})
    deploy_note = ("<br><b>包含相同字体的模块</b>：" + "、".join(
        f"<code>{esc(m)}</code>" for m in modules)) if modules else ""

    rules_cfg = reports[0].get("rules", {})
    kw = rules_cfg.get("commercial_keywords") or []

    own_cat_parts, own_expr_parts, copyleft_parts = [], [], []
    for r in reports:
        own = r.get("repo_license", {}).get("own", {})
        cats = own.get("categories") or {}
        own_cat_parts.append(r["repo"]["name"] + ": "
                             + "、".join(f"{k} {v}" for k, v in cats.items()))
        for e, n in (own.get("detected_exprs") or {}).items():
            own_expr_parts.append(f"{esc(e)} <span class='muted'>(×{n})</span>")
        for s in (own.get("copyleft_suspects") or [])[:5]:
            copyleft_parts.append(f"<li>{esc(s)}</li>")
    copyleft_block = ""
    if copyleft_parts:
        copyleft_block = ('<br><span class="muted">来源待确认代码：</span>'
                          f'<ul class="ev">{"".join(copyleft_parts)}</ul>')

    html = tpl.substitute(
        title="代码字体版权合规检测报告",
        gen_time=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        repos="、".join(r["repo"]["name"] for r in reports),
        a_series=a["series"], a_files=a["files"], a_locs=a["locs"],
        a_ref=a["ref"], a_unref=a["unref"], a_ok=a["ok"], a_fail=a["fail"],
        a_namefam=a["namefam"],
        asset_chips=asset_chips, name_chips="".join(name_chips),
        coverage_rows=coverage_rows(reports),
        c_allow=cc.get("已确认允许", 0), c_deny=cc.get("已确认不允许", 0),
        c_pending=cc.get("授权待确认", 0), c_tech=cc.get("技术无法判断", 0),
        u_using=uu.get("正在使用", 0),
        u_ref=uu.get("存在引用但未确认运行时使用", 0),
        u_noref=uu.get("未发现引用", 0),
        concl_rows=concl_rows(reports),
        series_rows=series_rows(reports),
        remed_rows=remediation_rows(reports),
        deploy_note=deploy_note,
        css_rows=css_rows(reports),
        st_instances=st["instances"], st_unique=st["unique"], st_dup=st["dup"],
        st_low=st["low"], st_medium=st["medium"], st_pending=st["pending"],
        own_categories="<br>".join(own_cat_parts),
        own_declared="；".join(
            f'{r["repo"]["name"]}: '
            f'{r.get("repo_license", {}).get("own", {}).get("declared", "-")}'
            for r in reports),
        own_exprs="；".join(own_expr_parts) or '<span class="muted">无</span>',
        copyleft_block=copyleft_block,
        repo_rows=repo_rows(reports),
        kw_count=rules_cfg.get("commercial_keyword_count", len(kw)),
        kw_hits=sum(1 for s in series_all if s.get("commercial_hits")),
        kw_list=esc("、".join(kw)),
        **plan_block(plan),
    )

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "report.html"
    json_path = out_dir / "report.json"
    html_path.write_text(html, encoding="utf-8")
    json_path.write_text(
        json.dumps(reports if isinstance(result, list) else result,
                   ensure_ascii=False, indent=2), encoding="utf-8")

    leftover = [ph for ph in ("$series_rows", "$concl_rows", "$remed_rows",
                              "$css_rows", "$repo_rows") if ph in html]
    if leftover:
        log.warning("模板占位符未替换: %s", leftover)
    log.info("报告生成: %s (资产 %s 系列/结论 %s)", html_path,
             a["series"], cc)
    return html_path, json_path
