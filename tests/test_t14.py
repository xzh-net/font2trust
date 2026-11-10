# -*- coding: utf-8 -*-
"""T14 回归测试：来源推导 / high 判定 / 白名单匹配 / 环比身份（P1-4·P1-5·P1-6）。

1) uni_modules 等插件目录可从路径推导来源 -> 不再判"来源不明→高危"
2) 有版权声明线索(无路径来源) -> 中危·待追溯; 无线索才 high
3) 白名单名称带样式后缀仍可命中(名称宽松匹配), sha256 失效不丢签署结果
4) 环比遇仓库变更 -> 跳过, 不再把"换仓库"报成"风险消退"
5) _index_findings 兼容多仓库 list; redact_credentials 兜底脱敏

运行: python tests/test_t14.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.analyze_risks import (   # noqa: E402
    assess_family, derive_source, find_whitelist_entry, load_rules,
    load_whitelist_all, norm_name_loose, whitelist_name_match)
from scripts.history import (_index_findings,           # noqa: E402
                             compare_with_previous)
from scripts.utils import redact_credentials            # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _group(family: str, copyright_: str, source_package=None,
           source_dir=None) -> dict:
    """构造 assess_family 所需的最小字体系列(单文件, fsType=0)。"""
    return {
        "family": family, "family_norm": family,
        "source_package": source_package, "source_dir": source_dir,
        "third_party": bool(source_package),
        "files": [{
            "path": "static/x.ttf", "ext": ".ttf", "sha256": "ab" * 32,
            "locations": ["static/x.ttf"], "family_name": family,
            "ps_name": family, "parse_status": "ok", "fs_type": 0,
            "embedding": "allowed(无限制)", "font_version": "Version 1.0",
            "copyright": copyright_, "license_text": "", "license_url": None,
            "referenced": True,
        }],
    }


def _ctx(rules: dict, whitelist: list) -> dict:
    return {"root": Path(tempfile.gettempdir()),
            "file_licenses": {}, "component_licenses": {},
            "component_exprs": {}, "rules": rules, "whitelist": whitelist}


def main() -> int:
    rules = load_rules(ROOT / "config" / "license_rules.yaml")

    # 1) 来源推导: uni_modules 插件目录
    src = derive_source("uni_modules/uni-icons/components/uni-icons/x.ttf")
    assert src["third_party"] and src["source_package"] == "uni-icons", src
    assert derive_source("bower_components/fa/x.ttf")["source_package"] == "fa"
    assert derive_source("src/main/java/com/a/B.java")["third_party"] is False
    print(f"1) 来源推导: uni_modules -> {src['source_package']} "
          f"(third_party={src['third_party']}) ✅")

    # 2) high 判定: 版权线索降级, 无线索才 high
    a = assess_family(_group("iconfont", "Created by iconfont"), _ctx(rules, []))
    assert a["risk_level"] == "medium" and "source_clue_no_auth" in a["rules_hit"], \
        (a["risk_level"], a["rules_hit"])
    assert "暂停发布" not in a["suggestion"], a["suggestion"]
    b = assess_family(_group("MysteryFont", ""), _ctx(rules, []))
    assert b["risk_level"] == "high" and "source_unknown_no_auth" in b["rules_hit"], \
        (b["risk_level"], b["rules_hit"])
    c = assess_family(_group("uniicons", "", "uni-icons",
                             "uni_modules/uni-icons"), _ctx(rules, []))
    assert c["risk_level"] == "medium" and c["source_package"] == "uni-icons", c
    assert all(x["authorization_conclusion"] == "授权待确认"
               for x in (a, b, c)), "结论仍为授权待确认(等级与结论分离)"
    print(f"2) high 判定: 有版权线索={a['risk_level']}/无线索={b['risk_level']}/"
          f"可推导来源={c['risk_level']}; 三者结论均 授权待确认 ✅")

    # 3) 白名单: 名称宽松匹配 + sha256 兜底
    assert whitelist_name_match("GLYPHICONS Halflings",
                                "GLYPHICONS Halflings Regular")
    assert not whitelist_name_match("Noto Sans", "Noto Sans SC")
    wl_all = load_whitelist_all(ROOT / "config" / "whitelist.yaml")
    g = _group("GLYPHICONS Halflings Regular", "")
    g["files"][0]["sha256"] = "ff" * 32          # 模拟文件被重建, 哈希失效
    entry = find_whitelist_entry(g["family"], g["files"],
                                 [dict(e, sha256=None) for e in wl_all])
    assert entry and entry["font_family"] == "GLYPHICONS Halflings", entry
    hit = assess_family(g, _ctx(rules, [dict(entry, sha256=None)]))
    assert hit["authorization_conclusion"] == "已确认允许" and \
        "whitelist_hit" in hit["rules_hit"], hit["rules_hit"]
    miss = assess_family(_group("NotRegistered", ""), _ctx(rules, wl_all))
    assert miss["authorization_conclusion"] == "授权待确认"
    print(f"3) 白名单: 后缀名+哈希失效仍命中({entry['font_family']}) -> "
          f"{hit['authorization_conclusion']}; 未登记字体仍待确认 ✅")

    # 4) 环比身份: 换仓库跳过
    def _rep(src_url: str) -> dict:
        return {"format": "poc-report-v2.1",
                "repo": {"name": "backend", "source": src_url,
                         "clone": {"path": "workspace/backend"}},
                "font_series": [{"family": "FontAwesome",
                                 "source_package": "font-awesome",
                                 "risk_level": "low",
                                 "authorization_conclusion": "已确认允许",
                                 "license_status": "已核实"}],
                "repo_license": {"third_party": []}}

    with tempfile.TemporaryDirectory() as td:
        hist = Path(td) / "history"
        cur = Path(hist) / "20261110-100000"
        cur.mkdir(parents=True)
        (cur / "report.json").write_text(
            json.dumps(_rep("http://oauth2:tok@host/a.git"),
                       ensure_ascii=False), encoding="utf-8")
        same = compare_with_previous(
            _rep("http://other-tok@host/a.git"), hist)   # 仅凭证不同
        assert same["available"], same
        diff = compare_with_previous(_rep("http://host/b.git"), hist)
        assert diff["available"] is False and "仓库变更" in diff["reason"], diff
        print(f"4) 环比身份: 同仓库(换凭证)可比 ✅ / 换仓库跳过 -> "
              f"{diff['reason'][:38]}... ✅")

    # 5) 多仓库 list 兼容 + 脱敏兜底
    idx = _index_findings([_rep("http://h/a.git"), _rep("http://h/b.git")])
    assert "font:fontawesome|font-awesome" in idx, list(idx)
    assert "glpat-ABC123" not in redact_credentials(
        "http://u:glpat-ABC123@h/g.git")[0]
    txt, n = redact_credentials("http://u:glpat-ABC123@h/g.git")
    assert n == 1 and txt == "http://***@h/g.git", (txt, n)
    print(f"5) 多仓库索引: {len(idx)} 条 ✅ / 脱敏: {txt} ✅")

    print("\nT14 ACCEPT: PASS  (规则/匹配/环比回归)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
