# -*- coding: utf-8 -*-
"""字体证据目录生成（T6 实现 · 迁移自 poc/build_evidence.py）。

输出: font-compliance/<字体>/
    font-files.txt    文件清单(路径/格式/哈希/引用状态)
    source-info.txt   来源(组件/上游标签/哈希比对结论)
    LICENSE.txt       许可证原文或官方声明(含出处) + 适用对象说明
    review-record.md  核实记录(方法/结论/条件/签署栏)

原则（§15.3）: 找不到许可证原文时如实记录"证据未找到"，**绝不自行补写许可证**。
许可证原文源: license_sources/（离线随包部署, 已含 OFL/MIT/CC-BY 全文与官方声明）。
哈希比对/上游标签为 2026-11-09 核实归档事实(docs/核实报告-20261109.md)。
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from .utils import PROJECT_ROOT

SRC = PROJECT_ROOT / "license_sources"
EVID_ROOT = PROJECT_ROOT / "font-compliance"

# 哈希比对结论（核实归档, 2026-11-09 三层证据法执行结果）
HASH_VERIFY = {
    "fontawesome": "MATCH ✅ 本地 ttf SHA256==官方 Font-Awesome@4.7.0 发行文件",
    "ionicons": "MATCH ✅ 本地 ttf SHA256==官方 driftyco/ionicons@v2.0.1 发行文件",
    "glyphicon": "MATCH ✅ 本地 ttf SHA256==官方 twbs/bootstrap@v3.4.1 发行文件",
}
UPSTREAM = {
    "fontawesome": ("FortAwesome/Font-Awesome", "4.7.0",
                    "https://cdn.jsdelivr.net/gh/FortAwesome/Font-Awesome@4.7.0/"),
    "ionicons": ("driftyco/ionicons",
                 "v2.0.1 (CSS 头部标注 v2.0.0, 字体文件 2.0.0→2.0.1 未变)",
                 "https://cdn.jsdelivr.net/gh/driftyco/ionicons@v2.0.1/"),
    "glyphicon": ("twbs/bootstrap", "v3.4.1 (字体版本 1.009)",
                  "https://cdn.jsdelivr.net/gh/twbs/bootstrap@v3.4.1/"),
}
# (许可证正文文件(None=官方声明文件), 适用对象说明)
LICENSE_PACK = {
    "fontawesome": ("FontAwesome-README-license.md",
                    "字体文件 = SIL OFL 1.1 (附 OFL 全文); CSS/LESS/Sass 代码 = MIT; "
                    "文档 = CC BY 3.0"),
    "ionicons": ("ionicons-LICENSE.txt",
                 "字体与代码 = MIT (附 MIT 正文); 衍生自 Google Material 的图标 = "
                 "CC BY 4.0 (需署名, 附全文)"),
    "glyphicon": ("glyphicons-official-statement.txt",
                  "字体文件 = 依 Glyphicons 官方声明随 Bootstrap 分发"
                  "(与 Bootstrap 同许可); 建议保留 glyphicons.com 署名"),
}
CONDITIONS = {
    "fontawesome": "保留版权与许可证声明 (OFL 要求); 保留 Font Awesome 署名",
    "ionicons": "保留 MIT 声明; 界面/文档保留 Material Icons 署名 (CC BY 4.0)",
    "glyphicon": "建议页脚保留 glyphicons.com 署名链接 (官方声明为可选但建议)",
}


def key_of(family: str) -> str:
    f = (family or "").lower()
    if "awesome" in f:
        return "fontawesome"
    if "ionicon" in f:
        return "ionicons"
    if "glyphicon" in f:
        return "glyphicon"
    return "other"


def _read_src(name: str) -> str:
    p = SRC / name
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


def build_evidence(series: list, repo_name: str) -> list[str]:
    """生成各字体证据目录，返回生成路径列表。"""
    made: list[str] = []
    for s in series:
        k = key_of(s["family"])
        rel = (s.get("evidence_dir") or "").replace("\\", "/").strip("/")
        if rel.startswith("font-compliance/"):
            rel = rel[len("font-compliance/"):]
        d = EVID_ROOT / (rel or s["family"])
        d.mkdir(parents=True, exist_ok=True)
        up = UPSTREAM.get(k, ("未知", "未知", ""))

        # 1) font-files.txt
        ff = [f"# 字体文件清单 — {s['family']}", f"# 仓库: {repo_name}",
              f"# 生成: {dt.datetime.now():%Y-%m-%d %H:%M:%S}", ""]
        for f in s["files"]:
            ff += [
                f"文件: {f['path']}",
                f"  格式: {f['ext']}  解析: {f.get('parse_status')}  "
                f"fsType: {f.get('fs_type')} ({f.get('embedding')})",
                f"  SHA256: {f.get('sha256')}",
                f"  引用: {'CSS 已引用' if f.get('referenced') else '未见引用'}",
            ]
            for loc in f.get("locations", [])[1:]:
                ff.append(f"  相同文件位置: {loc}")
            ff.append("")
        (d / "font-files.txt").write_text("\n".join(ff), encoding="utf-8")

        # 2) source-info.txt
        si = [
            f"# 来源信息 — {s['family']}", "",
            f"来源组件(路径推导): {s.get('source_package') or '未推导'}",
            f"组件版本(仓库清单): {s.get('source_version') or '未记录(无清单文件)'}",
            f"字体版本(name 表): {s.get('font_version') or '未记录'}",
            f"上游仓库: {up[0]}  标签: {up[1]}",
            f"上游地址: {up[2]}",
            f"哈希比对: {HASH_VERIFY.get(k, '未执行(需上游可比对文件)')}",
            "本地版权: " + ("; ".join(sorted(
                {(f.get('copyright') or '')[:80] for f in s['files']
                 if f.get('copyright')})) or "未记录"),
            "", "来源核实详情见 docs/核实报告-20261109.md",
        ]
        (d / "source-info.txt").write_text("\n".join(si), encoding="utf-8")

        # 3) LICENSE.txt（找不到则如实记录, 不补写）
        pack = LICENSE_PACK.get(k)
        if pack is None:
            body = ("[证据未找到] 未在仓库与上游归档到许可证原文。\n"
                    "处置: 继续追溯上游发行包/官方仓库/版本标签/采购授权材料, "
                    "或评估替换; **不自行补写许可证**。\n")
            subject = "未找到许可证原文 — 证据未找到"
        else:
            body = _read_src(pack[0])
            subject = pack[1]
            if k == "fontawesome":
                body += ("\n\n" + "=" * 60
                         + "\n[SIL Open Font License 1.1 全文 (SPDX)]\n\n"
                         + _read_src("OFL-1.1.txt"))
            if k == "ionicons":
                body += ("\n\n" + "=" * 60
                         + "\n[CC BY 4.0 全文 (图标衍生部分, SPDX)]\n\n"
                         + _read_src("CC-BY-4.0.txt"))
        head = (f"# 许可证原文/官方授权声明 — {s['family']}\n"
                f"# 适用对象: {subject}\n"
                f"# 来源: {up[2] or '官方声明页'} (获取日期 2026-11-09)\n"
                f"# 注意: 本文件为原文归档, 不做改写; 授权结论见 review-record.md\n"
                + "=" * 60 + "\n\n")
        (d / "LICENSE.txt").write_text(head + body, encoding="utf-8")

        # 4) review-record.md
        rr = f"""# 核实记录 — {s['family']}

| 项 | 内容 |
|---|---|
| 核实日期 | 2026-11-09 |
| 核实方法 | 三层证据法：本地文件声明 + 上游官方原文 + 官方发行文件 SHA256 比对 |
| 字体版本 | {s.get('font_version') or '未记录'} |
| 上游来源 | {up[0]} @{up[1]} |
| 哈希比对 | {HASH_VERIFY.get(k, '未执行')} |
| 许可证 | {subject} |
| 授权条件 | {CONDITIONS.get(k, '待确认')} |
| **当前授权结论** | **{s.get('authorization_conclusion')}**（扫描器证据性判断） |
| 使用状态 | {s.get('usage_status')} |
| 风险/审核状态 | {s.get('risk_level')} / {s.get('review_status')} |
| 白名单状态 | {'active（已确认允许）' if s.get('license_status') == '已核实' else 'pending_review（待负责人确认转 active）'} |
| 关联文档 | docs/核实报告-20261109.md · config/whitelist.yaml |

## 整改方式（管理方案 §15.4 五类对照）

| 情况 | 本字体适用 |
|---|---|
| ① 已确认允许 → 保留并补充版权声明 | {'☑ 白名单已 active' if s.get('license_status') == '已核实' else '☐ 白名单转 active 后适用'} |
| ② 已确认不允许 → 删除/替换 | ☐ 当前无此证据（需人工判定） |
| ③ 找不到许可证 → 追溯上游 | {'☑ 已完成追溯与归档' if pack else '☐ 待追溯'} |
| ④ 字体未被实际使用 → 清理 | {'☐ 见使用状态: ' + str(s.get('usage_status'))} |
| ⑤ 技术无法判断 → 补充人工检查 | ☐ 见 tech_status: {s.get('tech_status')} |

## 签署

- 核实执行：POC 自动化 + 证据归档（2026-11-09）
- 审核确认：________________（技术部负责人）　日期：____________
"""
        (d / "review-record.md").write_text(rr, encoding="utf-8")
        made.append(str(d))
    return made
