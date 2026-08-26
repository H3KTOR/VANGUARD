"""pdf_reporter.py -- generates a SOC-style PDF report summarizing recent
VANGUARD activity: incident counts by severity/status, top offending
source IPs, active firewall bans, and host resource trends.

Uses ReportLab's platypus layer (Paragraph/Table/Spacer flowables) rather
than the low-level canvas API, so the report reflows cleanly regardless of
how many incidents/rules are included.

This module only ever writes the single output PDF file the caller
specifies -- it never touches any other path and never shells out.
"""

from __future__ import annotations

import statistics
from datetime import datetime, timezone
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

import database

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#dc2626"),
    "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#d97706"),
    "LOW": colors.HexColor("#16a34a"),
}

BRAND_DARK = colors.HexColor("#0f172a")
BRAND_MUTED = colors.HexColor("#64748b")
BRAND_LIGHT_BG = colors.HexColor("#f8fafc")


def _styles():
    base = getSampleStyleSheet()
    base.add(
        ParagraphStyle(
            name="VanguardTitle",
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=BRAND_DARK,
            spaceAfter=2,
        )
    )
    base.add(
        ParagraphStyle(
            name="VanguardSubtitle",
            fontName="Helvetica",
            fontSize=10,
            textColor=BRAND_MUTED,
            spaceAfter=18,
        )
    )
    base.add(
        ParagraphStyle(
            name="SectionHeading",
            fontName="Helvetica-Bold",
            fontSize=13,
            textColor=BRAND_DARK,
            spaceBefore=18,
            spaceAfter=8,
        )
    )
    base.add(
        ParagraphStyle(
            name="BodySmall",
            fontName="Helvetica",
            fontSize=9,
            textColor=BRAND_MUTED,
            leading=13,
        )
    )
    return base


def _severity_summary_table(by_severity: dict[str, int], styles) -> Table:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    header = ["Severity", "Count"]
    rows = [header] + [[sev, str(by_severity.get(sev, 0))] for sev in order]
    table = Table(rows, colWidths=[2.2 * inch, 1.5 * inch])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_LIGHT_BG]),
    ]
    for i, sev in enumerate(order, start=1):
        if sev in SEVERITY_COLORS:
            style_cmds.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS[sev]))
            style_cmds.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    table.setStyle(TableStyle(style_cmds))
    return table


def _top_ips_table(top_ips: list[tuple[str, int]]) -> Table:
    header = ["Source IP", "Incident Count"]
    rows = [header] + [[ip, str(count)] for ip, count in top_ips] if top_ips else [header, ["(none)", "0"]]
    table = Table(rows, colWidths=[3.0 * inch, 2.0 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica-Oblique" if not top_ips else "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_LIGHT_BG]),
            ]
        )
    )
    return table


def _recent_incidents_table(incidents: list[database.Incident]) -> Table:
    header = ["ID", "Detected At (UTC)", "Type", "Source IP", "Severity", "Risk", "Status"]
    rows = [header]
    for inc in incidents:
        rows.append(
            [
                str(inc.id),
                inc.detected_at.strftime("%Y-%m-%d %H:%M") if inc.detected_at else "\u2014",
                inc.type.replace("_", " "),
                inc.source_ip,
                inc.severity,
                str(inc.risk_score),
                inc.status.replace("_", " "),
            ]
        )
    if len(rows) == 1:
        rows.append(["\u2014", "\u2014", "No incidents in this period", "\u2014", "\u2014", "\u2014", "\u2014"])

    table = Table(
        rows,
        colWidths=[0.4 * inch, 1.15 * inch, 1.35 * inch, 1.15 * inch, 0.75 * inch, 0.5 * inch, 0.95 * inch],
    )
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_LIGHT_BG]),
    ]
    for i, inc in enumerate(incidents, start=1):
        color = SEVERITY_COLORS.get(inc.severity)
        if color:
            style_cmds.append(("TEXTCOLOR", (4, i), (4, i), color))
            style_cmds.append(("FONTNAME", (4, i), (4, i), "Helvetica-Bold"))
    table.setStyle(TableStyle(style_cmds))
    return table


def _metrics_summary(metrics: list[database.SystemMetric]) -> dict[str, float]:
    if not metrics:
        return {"cpu_avg": 0.0, "cpu_max": 0.0, "mem_avg": 0.0, "mem_max": 0.0, "disk_latest": 0.0}
    cpu_vals = [m.cpu_percent for m in metrics]
    mem_vals = [m.memory_percent for m in metrics]
    return {
        "cpu_avg": statistics.mean(cpu_vals),
        "cpu_max": max(cpu_vals),
        "mem_avg": statistics.mean(mem_vals),
        "mem_max": max(mem_vals),
        "disk_latest": metrics[-1].disk_percent,
    }


def generate_report(
    output_path: str,
    db_path: Optional[str] = None,
    *,
    since_hours: int = 24,
    max_incidents_listed: int = 30,
) -> str:
    """Builds the full SOC PDF report and writes it to output_path.
    Returns output_path on success (mirrors the shape callers expect from
    main.py's `report` command for a clean success message).
    """
    summary = database.get_summary_counts(db_path, since_hours=since_hours)
    incidents = database.get_recent_incidents(db_path, limit=max_incidents_listed, since_hours=since_hours)
    active_rules = database.get_active_firewall_rules(db_path)
    metrics = database.get_metrics_since(db_path, since_hours=since_hours)
    metric_summary = _metrics_summary(metrics)

    styles = _styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=LETTER,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        title="VANGUARD SOC Report",
    )

    story = []
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph("VANGUARD Security Operations Report", styles["VanguardTitle"]))
    story.append(
        Paragraph(
            f"Reporting window: last {since_hours}h &nbsp;&middot;&nbsp; Generated: {generated_at}",
            styles["VanguardSubtitle"],
        )
    )

    story.append(Paragraph("Executive Summary", styles["SectionHeading"]))
    story.append(
        Paragraph(
            f"VANGUARD detected <b>{summary['total_incidents']}</b> security incident(s) in the last "
            f"{since_hours} hour(s). There are currently <b>{summary['active_bans']}</b> IP address(es) "
            f"actively banned at the firewall level and <b>{summary['whitelisted']}</b> whitelisted. "
            f"Average host CPU utilization was <b>{metric_summary['cpu_avg']:.1f}%</b> "
            f"(peak {metric_summary['cpu_max']:.1f}%); average memory utilization was "
            f"<b>{metric_summary['mem_avg']:.1f}%</b> (peak {metric_summary['mem_max']:.1f}%).",
            styles["BodySmall"],
        )
    )

    story.append(Paragraph("Incidents by Severity", styles["SectionHeading"]))
    story.append(_severity_summary_table(summary["by_severity"], styles))

    story.append(Paragraph("Top Source IPs", styles["SectionHeading"]))
    story.append(_top_ips_table(summary["top_source_ips"]))

    story.append(Paragraph("Active Firewall Bans", styles["SectionHeading"]))
    if active_rules:
        rule_rows = [["IP Address", "Source", "Reason", "Banned At (UTC)"]]
        for rule in active_rules[:30]:
            rule_rows.append(
                [
                    rule.ip_address,
                    rule.source,
                    (rule.reason or "")[:60],
                    rule.banned_at.strftime("%Y-%m-%d %H:%M") if rule.banned_at else "\u2014",
                ]
            )
        rules_table = Table(rule_rows, colWidths=[1.3 * inch, 1.0 * inch, 2.7 * inch, 1.3 * inch])
        rules_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_LIGHT_BG]),
                ]
            )
        )
        story.append(rules_table)
    else:
        story.append(Paragraph("No active firewall bans at report time.", styles["BodySmall"]))

    story.append(Paragraph(f"Incident Log (most recent {max_incidents_listed})", styles["SectionHeading"]))
    story.append(_recent_incidents_table(incidents))

    story.append(Spacer(1, 24))
    story.append(
        Paragraph(
            "Generated automatically by the VANGUARD v3.0 Python toolkit (toolkit/pdf_reporter.py). "
            "This report reads directly from the platform's SQLite database and does not execute any "
            "external commands.",
            styles["BodySmall"],
        )
    )

    doc.build(story)
    return output_path
