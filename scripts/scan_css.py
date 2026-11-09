# -*- coding: utf-8 -*-
"""CSS/代码字体引用识别（T3 实现 · 迁移自 poc/poc_scan.py scan_css + main 后处理）。

实现要点（POC 评审 R5/P1-6/P2-10 修正均已吸收）:
    - 注释剥离（保留字符长度与换行 → 行号不失真）
    - @font-face 块级解析（花括号匹配；src 全列表 + format/weight/style）
    - url() 分类: 本地字体 / CDN 字体（仅已知端点与字体扩展名）/ 非字体资源不计
    - font-family 声明: 纯通用族不计；与实际字体资产分开统计
    - finalize_css_refs(): 风险等级 + 证据链关联（CSS → 字体系列）
    - detect_version_mismatch(): 字体版本 vs CSS 版本提示（技术告警，非版权违规）
"""
from __future__ import annotations

import re
from pathlib import Path

from .scan_projects import iter_files

FONT_EXTS = {".ttf", ".otf", ".ttc", ".woff", ".woff2", ".eot"}
CSS_EXTS = {".css", ".scss", ".less", ".vue", ".html", ".htm",
            ".js", ".jsx", ".ts", ".tsx"}
FONT_CDN_HOSTS = ("fonts.googleapis.com", "fonts.gstatic.com",
                  "fonts.bootstrapcdn.com")
GENERIC_FAMILIES = {"serif", "sans-serif", "monospace", "cursive", "fantasy",
                    "system-ui", "inherit", "initial", "unset",
                    "ui-sans-serif", "ui-serif", "ui-monospace", "monaco",
                    "consolas", "courier new"}


def blank_comments(text: str) -> str:
    """注释替换为空格（保留换行与长度，行号不失真）。
    修复 POC R5-1: 文件头注释里的项目主页/License 地址不再被识别为字体引用。"""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def match_block(text: str, start: int) -> tuple[str, int]:
    """从 { 之后取花括号匹配块，返回 (block_text, end_index)。"""
    depth, i, n = 1, start, len(text)
    while i < n and depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[start:i], i


def classify_url(url: str, css_path: Path, font_basenames: set) -> dict | None:
    """URL 分类: 本地字体 / CDN 字体 / 非字体资源(不计)。
    修复 POC R5-2: 只有字体扩展名或已知字体 CDN 端点才计入引用。"""
    clean = url.split("?")[0].split("#")[0]
    ext = Path(clean).suffix.lower()
    if url.startswith(("http://", "https://", "//")):
        host = re.sub(r"^(https?:)?//", "", url).split("/")[0].lower()
        if ext in FONT_EXTS or any(host.endswith(h) for h in FONT_CDN_HOSTS):
            return {"kind": "CDN字体", "value": url[:160], "exists": None}
        return None                      # 主页/License 地址等 -> 不计
    if ext in FONT_EXTS:
        local = (css_path.parent / clean).resolve()
        exists = local.exists() or Path(clean).name.lower() in font_basenames
        return {"kind": "本地字体", "value": url[:160], "exists": exists}
    return None


def scan_css(root: Path, font_records: list, exclude_dirs: set[str]) -> list[dict]:
    """块级解析 CSS/模板中的字体引用。"""
    font_basenames = {Path(f["path"]).name.lower() for f in font_records}
    scanned_families = {(f.get("meta", {}).get("family") or "").lower()
                        for f in font_records}
    refs: list[dict] = []

    for p in iter_files(root, exclude_dirs):
        if p.suffix.lower() not in CSS_EXTS:
            continue
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        text = blank_comments(raw)
        rel = p.relative_to(root).as_posix()

        def line_of(idx: int, _t: str = text) -> int:
            return _t.count("\n", 0, idx) + 1

        # 1) @font-face 块级解析（src 全列表）
        face_spans: list[tuple[int, int]] = []
        for m in re.finditer(r"@font-face\s*\{", text, re.I):
            block, end = match_block(text, m.end())
            face_spans.append((m.start(), end))
            fam_m = re.search(r"font-family\s*:\s*([^;]+)", block, re.I)
            fam = fam_m.group(1).strip().strip("'\"") if fam_m else None
            extra = []
            weight = re.search(r"font-weight\s*:\s*([^;]+)", block, re.I)
            style = re.search(r"font-style\s*:\s*([^;]+)", block, re.I)
            if weight:
                extra.append("weight=" + weight.group(1).strip()[:20])
            if style:
                extra.append("style=" + style.group(1).strip()[:20])
            srcs = re.findall(
                r"url\(\s*['\"]?([^'\")\s]+)['\"]?\s*\)"
                r"(?:\s*format\(\s*['\"]?([\w-]+)['\"]?\s*\))?",
                block, re.I)
            if not srcs:
                refs.append({"file": rel, "line": line_of(m.start()),
                             "kind": "@font-face", "family": fam,
                             "value": fam or "@font-face", "exists": None,
                             "format": None, "extra": "; ".join(extra)})
            for url, fmt in srcs:
                c = classify_url(url, p, font_basenames)
                if not c:
                    continue
                refs.append({"file": rel, "line": line_of(m.start()),
                             "kind": "@font-face/" + c["kind"], "family": fam,
                             "value": c["value"], "exists": c["exists"],
                             "format": fmt or None, "extra": "; ".join(extra)})

        def in_face(idx: int, _sp=face_spans) -> bool:
            return any(s <= idx < e for s, e in _sp)

        # 2) @font-face 之外的 url() 字体引用
        for m in re.finditer(r"url\(\s*['\"]?([^'\")\s]+)['\"]?\s*\)", text, re.I):
            if in_face(m.start()):
                continue
            c = classify_url(m.group(1), p, font_basenames)
            if c:
                refs.append({"file": rel, "line": line_of(m.start()),
                             "kind": c["kind"], "family": None,
                             "value": c["value"], "exists": c["exists"],
                             "format": None, "extra": ""})

        # 3) font-family 声明（纯通用族不计；修复 R5-3 不再误标 @font-face）
        for m in re.finditer(r"font-family\s*:\s*([^;}{]+)", text, re.I):
            if in_face(m.start()):
                continue
            parts = [x.strip().strip("'\"") for x in m.group(1).split(",")]
            parts = [x for x in parts if x]
            if not parts or all(x.lower() in GENERIC_FAMILIES for x in parts):
                continue
            linked = any(x.lower() in scanned_families for x in parts)
            refs.append({"file": rel, "line": line_of(m.start()),
                         "kind": "font-family", "family": ", ".join(parts[:4]),
                         "value": ", ".join(parts[:6])[:160],
                         "exists": linked, "format": None, "extra": ""})

    # 去重（压缩 CSS 单行多规则会产生重复）
    seen, uniq = set(), []
    for r in refs:
        key = (r["file"], r["kind"], r["value"][:80])
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    return uniq


def finalize_css_refs(css_refs: list[dict], series: list[dict]) -> None:
    """后处理（迁移自 poc main）: 风险等级 + 证据链关联。
    - 仅"本地字体文件缺失"为中危；font-family 声明仅记录为信息
    - linked_series: CSS → 字体系列（P2-10 证据链）"""
    for c in css_refs:
        if "本地字体" in c["kind"] and c.get("exists") is False:
            c["risk_level"] = "medium"
            c["suggestion"] = "引用的字体文件不在仓库内, 确认授权与来源"
        else:
            c["risk_level"] = "info"
            c["suggestion"] = ("记录引用关系(可能为系统/通用字体)"
                               if c["kind"] == "font-family"
                               else "记录引用关系")
        c["linked_series"] = None
        fam = c.get("family") or ""
        f_norm = re.sub(r"[^a-z0-9]", "", fam.lower())
        val = Path((c.get("value") or "").split("?")[0]).name.lower()
        for s in series:
            s_norm = re.sub(r"[^a-z0-9]", "",
                            (s.get("family_norm") or s.get("family") or "").lower())
            by_fam = len(f_norm) >= 6 and (s_norm in f_norm or f_norm in s_norm)
            by_file = (c.get("kind") != "font-family" and any(
                Path(e["path"]).name.lower() == val for e in s.get("files", [])))
            if by_fam or by_file:
                c["linked_series"] = s.get("family")
                break


def _major(text) -> str | None:
    if not text:
        return None
    m = re.search(r"(\d+)(?:\.\d+)*", str(text))
    return m.group(1) if m else None


def detect_version_mismatch(series: list[dict], css_refs: list[dict]) -> None:
    """字体版本 vs CSS 版本提示（P1-6，技术告警，非版权违规）。
    为每个系列填充 css_font_families 与 alerts。"""
    hints = sorted({c["family"] for c in css_refs if c.get("family")
                    and c.get("kind") in ("font-family", "@font-face")})
    for s in series:
        s_norm = re.sub(r"[^a-z0-9]",
                        "", (s.get("family_norm") or s.get("family") or "").lower())
        s_major = _major(s.get("font_version"))
        s.setdefault("css_font_families", [])
        s.setdefault("alerts", [])
        for fam in hints:
            f_norm = re.sub(r"[^a-z0-9]", "", fam.lower())
            if not (len(s_norm) >= 6 and (s_norm in f_norm or f_norm in s_norm)):
                continue
            if fam not in s["css_font_families"]:
                s["css_font_families"].append(fam)
            hint = _major(fam)
            if hint and s_major and hint != s_major:
                s["alerts"].append(
                    f"version_mismatch: CSS 引用「{fam}」与字体文件版本 "
                    f"{s.get('font_version')} 不一致(技术告警, 非版权违规)")
