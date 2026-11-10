# -*- coding: utf-8 -*-
"""T16 验收测试：容量控制与扫描任务清单（P1b + P1c）。

覆盖: unpackage 排除而 dist 保留（合规对象不误伤）/ 单仓失败隔离返回失败记录 /
      scan_plan 渲染 00 区块（计划·成功·失败·过滤）/ 未传 plan 不崩

运行: python tests/test_t16.py
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.analyze_risks import load_rules, load_whitelist   # noqa: E402
from scripts.generate_report import generate_report            # noqa: E402
from scripts.main import _scan_one                             # noqa: E402
from scripts.scan_projects import build_excludes, inventory    # noqa: E402
from scripts.utils import load_config                         # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _fake_result(name: str = "demo") -> dict:
    return {
        "format": "poc-report-v2.1",
        "repo": {"name": name, "source": "http://***@host/x.git",
                 "clone": {"path": "workspace/x", "ok": True, "mode": "local"}},
        "coverage": {"files_total": 10, "font_series": 1, "font_files": 1,
                     "font_files_unique": 1, "parse_ok": 1, "parse_fail": 0,
                     "css_refs": 0, "scancode": "skipped", "license_files": 0,
                     "own_files": 10, "third_party_files": 0},
        "font_series": [{
            "family": "DemoFont", "font_version": "1.0",
            "source_package": None, "source_dir": None, "third_party": False,
            "license_status": "未知", "authorization_conclusion": "授权待确认",
            "usage_status": "未发现引用", "risk_level": "medium",
            "review_status": "待确认", "tech_status": "正常",
            "evidence_dir": "font-compliance/DemoFont/",
            "evidence": ["无"], "rules_hit": [], "alerts": [],
            "commercial_hits": [], "referenced": False,
            "suggestion": "补授权依据",
            "files": [{"path": "static/a.ttf", "ext": ".ttf",
                       "sha256": "ab" * 32, "locations": ["static/a.ttf"],
                       "family_name": "DemoFont", "ps_name": "DemoFont",
                       "parse_status": "ok", "fs_type": 0,
                       "embedding": "allowed(无限制)", "font_version": "1.0",
                       "copyright": "", "license_text": "", "license_url": None,
                       "referenced": False}],
        }],
        "css_refs": [], "repo_license": {"third_party": [],
                                         "own": {"categories": {},
                                                 "declared": "-",
                                                 "detected_exprs": {},
                                                 "copyleft_suspects": [],
                                                 "license_files": [],
                                                 "file_count": 10,
                                                 "lockfile_count": 0}},
        "scancode": {"status": "skipped"},
        "rules": {"commercial_keywords": [], "commercial_keyword_count": 0},
    }


def _plan() -> dict:
    return {
        "generated_at": "2026-11-10 12:00:00", "mode": "auto",
        "host": "http://192.168.2.209:8088", "scope": "groups+subgroups",
        "counts": {"planned": 3, "scanned": 1, "failed": 1, "skipped": 1},
        "planned": [{"name": "repo_ok", "url": "http://***@h/a.git", "local": False},
                    {"name": "repo_bad", "url": "http://***@h/b.git", "local": False},
                    {"name": "repo_notrun", "url": "http://***@h/c.git", "local": False}],
        "scanned": [{"name": "repo_ok", "files": 10, "fonts": 1, "series": 1}],
        "failed": [{"name": "repo_bad", "stage": "sync",
                    "error": "fatal: repository not found"}],
        "skipped": [{"path": "g/old-repo", "reason": "500 天未活动(阈值 365)"}],
    }


def main() -> int:
    cfg = load_config("config/scanner.yaml")

    # 1) 容量: unpackage 排除, 第三方 dist 保留(合规对象), node_modules 排除
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        for rel in ("static/a.ttf", "unpackage/dist/build/x.js",
                    "wxcomponents/vant/dist/y.js", "node_modules/p/z.js",
                    "pages/b.vue"):
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x", encoding="utf-8")
        excl = build_excludes(cfg)
        inv = inventory(repo, excl)
        assert "unpackage/dist/build/x.js" not in inv, inv
        assert "node_modules/p/z.js" not in inv, inv
        assert "wxcomponents/vant/dist/y.js" in inv, "第三方 dist 被误排除!"
        assert "static/a.ttf" in inv and "pages/b.vue" in inv, inv
        assert "unpackage" in excl, "scanner.yaml 未排除 unpackage"
        print(f"1) 排除策略: unpackage/node_modules 排除, dist 保留 "
              f"(剩余 {len(inv)} 文件) ✅")

    # 2) 单仓失败隔离 → 返回失败记录(stage=sync)
    args = argparse.Namespace(skip_scancode=True, reuse_scancode=False)
    rules = load_rules(ROOT / "config" / "license_rules.yaml")
    wl = load_whitelist(ROOT / "config" / "whitelist.yaml")
    with tempfile.TemporaryDirectory() as td:
        r, f = _scan_one("ghost", str(Path(td) / "no-such-dir"), True, cfg,
                         args, Path(td), rules, wl)
        assert r is None and f, (r, f)
        assert f["name"] == "ghost" and f["stage"] == "sync", f
        assert f["error"], f
        print(f"2) 失败隔离: (None, stage={f['stage']}) "
              f"{f['error'][:30]}... ✅")

    # 3) 报告 00 区块: 计划/成功/失败/过滤 逐条可见
    with tempfile.TemporaryDirectory() as td:
        html_path, json_path = generate_report(_fake_result(), Path(td),
                                               plan=_plan())
        html = html_path.read_text(encoding="utf-8")
        assert "00｜扫描任务清单（覆盖自证）" in html, "缺 00 区块"
        for token in ("计划 <b>3</b>", "成功 <b>1</b>", "失败 <b>1</b>",
                      "过滤 <b>1</b>", "repo_bad", "repository not found",
                      "500 天未活动", "groups+subgroups"):
            assert token in html, f"00 区块缺: {token}"
        assert "❌ 失败" in html and "⏭ 过滤" in html
        assert json_path.exists()
        print("3) 报告 00 区块: 计划3/成功1/失败1/过滤1 + 失败与过滤明细 ✅")

    # 4) 未传 plan(旧调用/单测) 不崩, 且有占位
    with tempfile.TemporaryDirectory() as td:
        html_path, _ = generate_report(_fake_result(), Path(td))
        html = html_path.read_text(encoding="utf-8")
        assert "00｜扫描任务清单" in html and "无清单" in html
        print("4) plan 缺省: 00 区块占位, 不抛异常 ✅")

    # 5) scan_plan.json 结构(与 main 输出一致的最小契约)
    p = _plan()
    assert set(p["counts"]) == {"planned", "scanned", "failed", "skipped"}
    assert all(k in p for k in ("planned", "scanned", "failed", "skipped"))
    json.dumps(p, ensure_ascii=False)
    print("5) scan_plan 契约: counts/planned/scanned/failed/skipped ✅")

    print("\nT16 ACCEPT: PASS  (容量控制 + 扫描任务清单)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
