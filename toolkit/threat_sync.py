"""threat_sync.py -- pull public OSINT malicious-IP feeds and stage them
as `firewall_rules` rows in the shared VANGUARD database.

Design notes:
  - Uses well-known, no-API-key-required plaintext IP list feeds so the
    toolkit works out of the box with zero configuration. The primary
    feed is stamparm/ipsum (aggregates 30+ public blocklists and scores
    each IP by how many lists it appears on); `--min-level` filters by
    that corroboration score.
  - Only ever issues a plain HTTPS GET against the configured feed URL(s)
    -- no shelling out to curl/wget, per the toolkit's safety constraint.
  - Writes are batched into a SINGLE short transaction (one connection,
    one commit) rather than one commit per IP, both for performance and
    to minimize how long a write lock is held against the live Go
    daemon's WAL-mode database.
  - Never re-inserts an IP that already has an active firewall_rules row
    (whether from the OSINT sync, Autopilot, or a manual block) --
    de-duplication happens in-process before the transaction even opens,
    so a duplicate feed entry doesn't need Autopilot-level whitelist
    conflict handling.
  - Mirrors the same `source` column semantics the Go side defines in
    internal/database/models.go (FirewallSource*): this module always
    writes `source="threat_intel"`, a value the Go schema treats as just
    another string (SQLite has no CHECK constraint on it), clearly
    distinguishing OSINT-sourced bans from autopilot/manual/honeypot ones
    in the dashboard's "Source" column.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

import database

DEFAULT_FEED_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
"""ipsum "level 3" = IPs reported by at least 3 independent public
blocklists -- a reasonable default confidence bar that avoids flooding
firewall_rules with single-source, potentially noisy reports."""

SOURCE_LABEL = "threat_intel"
DEFAULT_BAN_DURATION_HOURS = 72
REQUEST_TIMEOUT_SECONDS = 15


class ThreatFeedError(RuntimeError):
    """Raised when the OSINT feed cannot be fetched or parsed."""


@dataclass
class SyncResult:
    feed_url: str
    fetched_count: int
    valid_ip_count: int
    already_blocked_count: int
    inserted_count: int
    inserted_ips: list[str]


def _is_valid_public_ip(candidate: str) -> bool:
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    # Never stage loopback/private/link-local/multicast ranges -- a feed
    # entry like 127.0.0.1 or 10.0.0.5 is either a parsing artifact or
    # actively dangerous to ban (could be the box's own management IP).
    return not (addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_multicast or addr.is_reserved)


def fetch_malicious_ips(feed_url: str = DEFAULT_FEED_URL, *, min_level: int = 0) -> list[str]:
    """Fetches and parses a plaintext OSINT feed.

    Supports two common plaintext formats transparently:
      - bare IP per line ("1.2.3.4")
      - ipsum's native format ("1.2.3.4\\t7"  -- IP, tab, corroboration
        level); `min_level` filters on the second column when present.
    Lines starting with '#' (comments) and blank lines are ignored.
    """
    try:
        resp = requests.get(feed_url, timeout=REQUEST_TIMEOUT_SECONDS)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise ThreatFeedError(f"Failed to fetch threat feed from {feed_url}: {exc}") from exc

    ips: list[str] = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        ip_candidate = parts[0]
        if len(parts) >= 2 and min_level > 0:
            try:
                level = int(parts[1])
            except ValueError:
                level = 0
            if level < min_level:
                continue
        if _is_valid_public_ip(ip_candidate):
            ips.append(ip_candidate)
    return ips


def sync_malicious_ips(
    db_path: Optional[str] = None,
    *,
    feed_url: str = DEFAULT_FEED_URL,
    min_level: int = 3,
    max_ips: int = 200,
    ban_duration_hours: int = DEFAULT_BAN_DURATION_HOURS,
    dry_run: bool = False,
) -> SyncResult:
    """Fetches the feed, filters out IPs already present as an active
    firewall_rules row, and inserts the remainder (capped at max_ips per
    run to avoid a single sync ballooning the table) in one transaction.

    dry_run=True performs the fetch and de-duplication but skips the
    INSERT/commit entirely, returning exactly what *would* have been
    inserted -- used by `toolkit report`-style previews and by the CLI's
    `--dry-run` flag.
    """
    raw_ips = fetch_malicious_ips(feed_url, min_level=min_level)
    candidate_ips = raw_ips[:max_ips]

    unban_at = datetime.now(timezone.utc) + timedelta(hours=ban_duration_hours)
    reason = f"OSINT threat intelligence match (feed: {feed_url}, min_level={min_level})"

    inserted_ips: list[str] = []
    already_blocked = 0

    with database.connect_readwrite(db_path) as conn:
        for ip in candidate_ips:
            if database.ip_already_blocked_or_whitelisted(conn, ip):
                already_blocked += 1
                continue
            if not dry_run:
                database.insert_firewall_rule(
                    conn,
                    ip_address=ip,
                    reason=reason,
                    source=SOURCE_LABEL,
                    unban_at=unban_at,
                )
            inserted_ips.append(ip)
        if not dry_run:
            conn.commit()

    return SyncResult(
        feed_url=feed_url,
        fetched_count=len(raw_ips),
        valid_ip_count=len(candidate_ips),
        already_blocked_count=already_blocked,
        inserted_count=0 if dry_run else len(inserted_ips),
        inserted_ips=inserted_ips,
    )
