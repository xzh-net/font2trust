# -*- coding: utf-8 -*-
"""邮件通知（T9 实现 · 占位期 enabled=false）。

行为（docs/实施方案.md §10 T9 验收）:
    enabled=false → 仅渲染 reports/current/email_preview.html，**不联网**
    enabled=true  → SMTP 发送（SSL/STARTTLS、多收件人、抄送、附带 report.html）
敏感项: 密码只读 email_config.password_env 指定的环境变量，不落盘不进日志。
二期接入（P2）: 真实 SMTP 参数 + 收件人 + 发送策略（only_on_risk）。
"""
from __future__ import annotations

import datetime as dt
import logging
import os
from pathlib import Path
from string import Template

from .utils import PROJECT_ROOT

log = logging.getLogger("font_compliance")

TEMPLATE = PROJECT_ROOT / "templates" / "email_template.html"
PREVIEW_PATH = PROJECT_ROOT / "reports" / "current" / "email_preview.html"


def _build_summary_html(summary: dict) -> tuple[str, dict]:
    """把扫描摘要填入邮件模板，返回 (html, 占位符字典)。"""
    cc = summary.get("conclusions") or {}
    risk = summary.get("risk") or {}
    conclusions = " ｜ ".join(
        f"{k}: <b>{v}</b>" for k, v in cc.items()) or "-"
    risk_line = " ｜ ".join(f"{k}: {v}" for k, v in risk.items() if k != "info") \
        or "-"
    fields = {
        "title": summary.get("title", "字体版权合规检测报告"),
        "gen_time": summary.get("gen_time")
        or dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "repos": summary.get("repos", "-"),
        "a_series": summary.get("font_series", 0),
        "a_files": summary.get("font_files", 0),
        "conclusions": conclusions,
        "risk_line": risk_line,
        "st_instances": summary.get("components_instances", 0),
        "task_count": summary.get("task_count", 0),
        "note": summary.get("note", "扫描完成，详见报告。"),
    }
    html = Template(TEMPLATE.read_text(encoding="utf-8")).substitute(fields)
    return html, fields


def send_email(summary: dict, report_html: Path | None,
               email_config: dict,
               preview_path: Path | None = None) -> dict:
    """返回 {"status": "sent|disabled|failed", "path": ..., "error": ...}
    preview_path: 占位期预览输出位置（默认 reports/current/email_preview.html）。"""
    html, _ = _build_summary_html(summary)

    if not email_config.get("enabled"):
        # 占位期: 仅渲染预览, 不联网
        out = Path(preview_path) if preview_path else PREVIEW_PATH
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html, encoding="utf-8")
        log.info("邮件占位: 已渲染预览 %s (enabled=false, 未联网)", out.name)
        return {"status": "disabled", "path": str(out)}

    # ---- enabled=true: 真实 SMTP（二期接入参数后启用） ----
    import smtplib
    from email.mime.base import MIMEBase
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    password_env = email_config.get("password_env", "SMTP_PASSWORD")
    password = os.environ.get(password_env, "")
    if not password:
        return {"status": "failed",
                "error": f"环境变量 {password_env} 未设置（密码不落盘）"}

    msg = MIMEMultipart("mixed")
    msg["Subject"] = (f'{email_config.get("subject_prefix", "[字体合规]")}'
                      f'{summary.get("title", "")}')
    msg["From"] = email_config.get("from", "")
    recipients = list(email_config.get("recipients") or [])
    cc = list(email_config.get("cc") or [])
    if not recipients:
        return {"status": "failed", "error": "无收件人(recipients 为空)"}
    msg["To"] = ", ".join(recipients)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg.attach(MIMEText(html, "html", "utf-8"))

    if report_html and report_html.exists() and email_config.get("attach_report"):
        part = MIMEBase("application", "octet-stream")
        part.set_payload(report_html.read_bytes())
        import email.encoders
        email.encoders.encode_base64(part)
        part.add_header("Content-Disposition",
                        f'attachment; filename="{report_html.name}"')
        msg.attach(part)

    host, port = email_config.get("host"), int(email_config.get("port", 465))
    try:
        if email_config.get("use_ssl", True):
            server = smtplib.SMTP_SSL(host, port, timeout=30)
        else:
            server = smtplib.SMTP(host, port, timeout=30)
            server.starttls()
        server.login(email_config.get("username", ""), password)
        server.sendmail(msg["From"], recipients + cc,
                        msg.as_string())
        server.quit()
        log.info("邮件已发送: %d 收件人", len(recipients) + len(cc))
        return {"status": "sent", "count": len(recipients) + len(cc)}
    except Exception as e:  # noqa: BLE001
        log.error("邮件发送失败: %s", e)
        return {"status": "failed", "error": str(e)}
