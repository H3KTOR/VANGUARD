#!/usr/bin/env python3
"""main.py -- VANGUARD v3.0 Python Toolkit CLI entry point.

Three subcommands, each a thin, readable wrapper around the corresponding
module (ai_analyst / threat_sync / pdf_reporter):

    vanguard-toolkit analyze   [--db-path PATH] [--limit N] [--since-hours H]
                               [--status S] [--provider anthropic|openai]
                               [--no-persist]
    vanguard-toolkit sync      [--db-path PATH] [--feed-url URL]
                               [--min-level N] [--max-ips N]
                               [--ban-hours H] [--dry-run]
    vanguard-toolkit report    [--db-path PATH] [--output PATH]
                               [--since-hours H] [--max-incidents N]

Run `vanguard-toolkit --help` or `vanguard-toolkit <command> --help` for
full flag documentation (Typer auto-generates this from the signatures
below).

Per the project's toolkit safety constraint, nothing in this CLI (or the
modules it calls) ever shells out to the OS -- every operation is either a
direct SQLite query (database.py) or a plain HTTPS request (ai_analyst.py,
threat_sync.py), plus local in-process PDF rendering (pdf_reporter.py).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import ai_analyst
import database
import pdf_reporter
import threat_sync

app = typer.Typer(
    name="vanguard-toolkit",
    help="VANGUARD v3.0 Python companion CLI: AI incident analysis, OSINT threat sync, and PDF SOC reports.",
    add_completion=False,
)
console = Console()

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
}


def _fail(message: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {message}")
    raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


@app.command()
def analyze(
    db_path: Optional[str] = typer.Option(
        None, "--db-path", help="Path to the VANGUARD SQLite database (default: $VANGUARD_DB_PATH or ./vanguard.db)."
    ),
    limit: int = typer.Option(10, "--limit", "-n", help="Maximum number of incidents to analyze."),
    since_hours: int = typer.Option(24, "--since-hours", help="Only consider incidents detected within this window."),
    status: Optional[str] = typer.Option(
        None, "--status", help="Filter by incident status (open, auto_blocked, investigating, resolved, false_positive)."
    ),
    provider: Optional[str] = typer.Option(
        None, "--provider", help="Force a specific LLM provider (anthropic|openai). Default: auto-detect from env vars."
    ),
    no_persist: bool = typer.Option(
        False, "--no-persist", help="Print results without writing them back to incidents.ai_analysis."
    ),
):
    """Run AI forensic analysis on the most recent incidents."""
    try:
        verdicts = ai_analyst.analyze_recent(
            db_path,
            limit=limit,
            since_hours=since_hours,
            status=status,
            persist=not no_persist,
            provider=provider,
        )
    except database.DatabaseNotFoundError as exc:
        _fail(str(exc))
    except ai_analyst.AIAnalystConfigError as exc:
        _fail(str(exc))

    if not verdicts:
        console.print("[yellow]No incidents found matching the given filters.[/yellow]")
        raise typer.Exit(code=0)

    for v in verdicts:
        sev_style = "bold red" if v.recommended_action == "escalate" else "bold cyan"
        title = Text(f"Incident #{v.incident_id} \u2014 {v.source_ip} ({v.incident_type})", style="bold white")
        body = Text()
        body.append("Likely intent:      ", style="dim")
        body.append(f"{v.likely_intent}\n", style="bold")
        body.append("Sophistication:      ", style="dim")
        body.append(f"{v.threat_actor_sophistication}\n")
        body.append("Confidence:          ", style="dim")
        body.append(f"{v.confidence:.0%}\n")
        body.append("Recommended action:  ", style="dim")
        body.append(f"{v.recommended_action.upper()}\n", style=sev_style)
        body.append("MITRE ATT&CK:        ", style="dim")
        body.append(f"{', '.join(v.mitre_attack_techniques) or '(none identified)'}\n")
        body.append("\n")
        body.append(v.summary, style="italic")
        console.print(Panel(body, title=title, subtitle=f"{v.provider}/{v.model}", border_style="blue"))

    persisted_note = "" if no_persist else " (persisted to incidents.ai_analysis)"
    console.print(f"\n[green]Analyzed {len(verdicts)} incident(s).[/green]{persisted_note}")


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------


@app.command()
def sync(
    db_path: Optional[str] = typer.Option(None, "--db-path", help="Path to the VANGUARD SQLite database."),
    feed_url: str = typer.Option(threat_sync.DEFAULT_FEED_URL, "--feed-url", help="OSINT plaintext IP-list feed URL."),
    min_level: int = typer.Option(
        3, "--min-level", help="Minimum corroboration level to accept (ipsum-format feeds only; 0 = accept all)."
    ),
    max_ips: int = typer.Option(200, "--max-ips", help="Maximum number of new IPs to stage per run."),
    ban_hours: int = typer.Option(
        threat_sync.DEFAULT_BAN_DURATION_HOURS, "--ban-hours", help="TTL, in hours, for the staged firewall_rules row."
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Fetch and de-duplicate without writing to the database."),
):
    """Fetch a public OSINT malicious-IP feed and stage new bans into firewall_rules."""
    try:
        result = threat_sync.sync_malicious_ips(
            db_path,
            feed_url=feed_url,
            min_level=min_level,
            max_ips=max_ips,
            ban_duration_hours=ban_hours,
            dry_run=dry_run,
        )
    except database.DatabaseNotFoundError as exc:
        _fail(str(exc))
    except threat_sync.ThreatFeedError as exc:
        _fail(str(exc))

    table = Table(title="Threat Intel Sync Result", show_header=False, box=None, padding=(0, 2))
    table.add_row("Feed URL", result.feed_url)
    table.add_row("IPs fetched from feed", str(result.fetched_count))
    table.add_row("IPs meeting min-level filter", str(result.valid_ip_count))
    table.add_row("Already blocked/whitelisted (skipped)", str(result.already_blocked_count))
    table.add_row(
        "Newly staged" if not dry_run else "Would stage (dry run)",
        f"[bold green]{len(result.inserted_ips)}[/bold green]",
    )
    console.print(table)

    if result.inserted_ips:
        preview = ", ".join(result.inserted_ips[:15])
        more = f" ... and {len(result.inserted_ips) - 15} more" if len(result.inserted_ips) > 15 else ""
        console.print(f"\n[dim]{preview}{more}[/dim]")


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@app.command()
def report(
    db_path: Optional[str] = typer.Option(None, "--db-path", help="Path to the VANGUARD SQLite database."),
    output: str = typer.Option(
        "vanguard_soc_report.pdf", "--output", "-o", help="Output PDF file path."
    ),
    since_hours: int = typer.Option(24, "--since-hours", help="Reporting window, in hours."),
    max_incidents: int = typer.Option(30, "--max-incidents", help="Maximum number of incidents listed in the log table."),
):
    """Generate a SOC-style PDF report summarizing recent incidents and system health."""
    try:
        out_path = pdf_reporter.generate_report(
            output, db_path, since_hours=since_hours, max_incidents_listed=max_incidents
        )
    except database.DatabaseNotFoundError as exc:
        _fail(str(exc))

    resolved = Path(out_path).resolve()
    console.print(f"[green]Report generated:[/green] {resolved}")


if __name__ == "__main__":
    app()
