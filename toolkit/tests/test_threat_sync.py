"""tests/test_threat_sync.py -- unit tests for threat_sync.py.

`requests.get` is mocked in every test so this suite never makes a real
HTTP call to the ipsum OSINT feed. `database.connect_readwrite` and its
helpers are likewise mocked/monkeypatched so no real SQLite file is ever
opened -- sync_malicious_ips() is exercised purely against fakes.

Covered behavior:
  - IP validity/exclusion filter (_is_valid_public_ip): rejects loopback,
    private, link-local, multicast, reserved, and malformed input;
    accepts ordinary public IPv4/IPv6 addresses
  - fetch_malicious_ips: bare-IP format, ipsum's "IP\\tlevel" format,
    min_level filtering, comment/blank-line skipping, mixed-validity
    feeds (invalid/private lines silently dropped)
  - fetch_malicious_ips raises ThreatFeedError on network/HTTP failure
  - sync_malicious_ips: de-duplicates already-blocked IPs, respects
    max_ips cap, dry_run performs no writes/commit, a real run inserts
    and commits exactly once
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

import database
import threat_sync


# ---------------------------------------------------------------------------
# _is_valid_public_ip
# ---------------------------------------------------------------------------


class TestIsValidPublicIp:
    @pytest.mark.parametrize(
        "ip",
        [
            "185.220.101.5",
            "8.8.8.8",
            "203.0.114.9",  # NOTE: 203.0.113.0/24 is TEST-NET-3 (reserved); this is a normal-looking public IP
            "2001:4860:4860::8888",  # public IPv6 (Google DNS)
        ],
    )
    def test_accepts_ordinary_public_ips(self, ip):
        assert threat_sync._is_valid_public_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",  # loopback
            "10.0.0.5",  # private
            "172.16.0.1",  # private
            "192.168.1.1",  # private
            "169.254.1.1",  # link-local
            "224.0.0.1",  # multicast
            "240.0.0.1",  # reserved
            "::1",  # IPv6 loopback
            "fe80::1",  # IPv6 link-local
        ],
    )
    def test_excludes_loopback_private_link_local_multicast_reserved(self, ip):
        assert threat_sync._is_valid_public_ip(ip) is False

    @pytest.mark.parametrize("garbage", ["not-an-ip", "999.999.999.999", "", "1.2.3", "DROP TABLE"])
    def test_rejects_malformed_input(self, garbage):
        assert threat_sync._is_valid_public_ip(garbage) is False


# ---------------------------------------------------------------------------
# fetch_malicious_ips
# ---------------------------------------------------------------------------


def mock_feed_response(text: str) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    resp.raise_for_status = MagicMock()
    return resp


class TestFetchMaliciousIps:
    def test_parses_bare_ip_per_line_format(self):
        feed_text = "185.220.101.5\n45.155.205.1\n# a comment\n\n91.240.118.60\n"
        with patch.object(requests, "get", return_value=mock_feed_response(feed_text)) as mock_get:
            ips = threat_sync.fetch_malicious_ips("https://example.test/feed.txt")

        mock_get.assert_called_once_with("https://example.test/feed.txt", timeout=threat_sync.REQUEST_TIMEOUT_SECONDS)
        assert ips == ["185.220.101.5", "45.155.205.1", "91.240.118.60"]

    def test_parses_ipsum_tab_level_format_and_filters_by_min_level(self):
        feed_text = "185.220.101.5\t8\n45.155.205.1\t2\n91.240.118.60\t5\n"
        with patch.object(requests, "get", return_value=mock_feed_response(feed_text)):
            ips = threat_sync.fetch_malicious_ips("https://example.test/feed.txt", min_level=3)

        # Only level >= 3 survives; the level=2 entry is filtered out.
        assert ips == ["185.220.101.5", "91.240.118.60"]

    def test_min_level_zero_disables_level_filtering(self):
        feed_text = "185.220.101.5\t1\n45.155.205.1\t0\n"
        with patch.object(requests, "get", return_value=mock_feed_response(feed_text)):
            ips = threat_sync.fetch_malicious_ips("https://example.test/feed.txt", min_level=0)

        assert ips == ["185.220.101.5", "45.155.205.1"]

    def test_excludes_private_and_loopback_lines_from_feed(self):
        feed_text = "185.220.101.5\n10.0.0.5\n127.0.0.1\n45.155.205.1\n"
        with patch.object(requests, "get", return_value=mock_feed_response(feed_text)):
            ips = threat_sync.fetch_malicious_ips("https://example.test/feed.txt")

        assert ips == ["185.220.101.5", "45.155.205.1"]

    def test_excludes_malformed_lines(self):
        feed_text = "185.220.101.5\nnot-an-ip\n\n45.155.205.1\n"
        with patch.object(requests, "get", return_value=mock_feed_response(feed_text)):
            ips = threat_sync.fetch_malicious_ips("https://example.test/feed.txt")

        assert ips == ["185.220.101.5", "45.155.205.1"]

    def test_skips_comment_and_blank_lines(self):
        feed_text = "# ipsum blocklist\n\n# generated 2026-08-26\n185.220.101.5\n"
        with patch.object(requests, "get", return_value=mock_feed_response(feed_text)):
            ips = threat_sync.fetch_malicious_ips("https://example.test/feed.txt")

        assert ips == ["185.220.101.5"]

    def test_returns_empty_list_for_empty_feed(self):
        with patch.object(requests, "get", return_value=mock_feed_response("")):
            ips = threat_sync.fetch_malicious_ips("https://example.test/feed.txt")

        assert ips == []

    def test_raises_threat_feed_error_on_request_exception(self):
        with patch.object(requests, "get", side_effect=requests.ConnectionError("DNS failure")):
            with pytest.raises(threat_sync.ThreatFeedError, match="Failed to fetch threat feed"):
                threat_sync.fetch_malicious_ips("https://example.test/feed.txt")

    def test_raises_threat_feed_error_on_http_error_status(self):
        resp = MagicMock()
        resp.raise_for_status.side_effect = requests.HTTPError("503 Service Unavailable")
        with patch.object(requests, "get", return_value=resp):
            with pytest.raises(threat_sync.ThreatFeedError):
                threat_sync.fetch_malicious_ips("https://example.test/feed.txt")


# ---------------------------------------------------------------------------
# sync_malicious_ips
# ---------------------------------------------------------------------------


class TestSyncMaliciousIps:
    def _mock_conn_context(self, monkeypatch, is_blocked_fn=None):
        """Patches database.connect_readwrite to yield a MagicMock
        connection via a context manager, and stubs
        ip_already_blocked_or_whitelisted / insert_firewall_rule so no
        real SQLite is touched."""
        fake_conn = MagicMock()

        class FakeContextManager:
            def __enter__(self_inner):
                return fake_conn

            def __exit__(self_inner, *exc):
                return False

        monkeypatch.setattr(database, "connect_readwrite", MagicMock(return_value=FakeContextManager()))
        monkeypatch.setattr(
            database,
            "ip_already_blocked_or_whitelisted",
            MagicMock(side_effect=is_blocked_fn or (lambda conn, ip: False)),
        )
        insert_mock = MagicMock(return_value=1)
        monkeypatch.setattr(database, "insert_firewall_rule", insert_mock)
        return fake_conn, insert_mock

    def test_sync_inserts_new_ips_and_commits_once(self, monkeypatch):
        fake_conn, insert_mock = self._mock_conn_context(monkeypatch)
        feed_text = "185.220.101.5\n45.155.205.1\n"
        with patch.object(requests, "get", return_value=mock_feed_response(feed_text)):
            result = threat_sync.sync_malicious_ips(db_path="/fake/path.db", min_level=0)

        assert result.inserted_count == 2
        assert set(result.inserted_ips) == {"185.220.101.5", "45.155.205.1"}
        assert insert_mock.call_count == 2
        fake_conn.commit.assert_called_once()

    def test_sync_skips_already_blocked_ips(self, monkeypatch):
        fake_conn, insert_mock = self._mock_conn_context(
            monkeypatch, is_blocked_fn=lambda conn, ip: ip == "185.220.101.5"
        )
        feed_text = "185.220.101.5\n45.155.205.1\n"
        with patch.object(requests, "get", return_value=mock_feed_response(feed_text)):
            result = threat_sync.sync_malicious_ips(db_path="/fake/path.db", min_level=0)

        assert result.inserted_count == 1
        assert result.inserted_ips == ["45.155.205.1"]
        assert result.already_blocked_count == 1
        insert_mock.assert_called_once()

    def test_sync_respects_max_ips_cap(self, monkeypatch):
        fake_conn, insert_mock = self._mock_conn_context(monkeypatch)
        feed_text = "\n".join(f"1.2.3.{i}" for i in range(1, 11))  # 10 candidate public IPs
        with patch.object(requests, "get", return_value=mock_feed_response(feed_text)):
            result = threat_sync.sync_malicious_ips(db_path="/fake/path.db", min_level=0, max_ips=3)

        assert result.fetched_count == 10
        assert result.valid_ip_count == 3
        assert result.inserted_count == 3
        assert insert_mock.call_count == 3

    def test_dry_run_performs_no_inserts_or_commit(self, monkeypatch):
        fake_conn, insert_mock = self._mock_conn_context(monkeypatch)
        feed_text = "185.220.101.5\n45.155.205.1\n"
        with patch.object(requests, "get", return_value=mock_feed_response(feed_text)):
            result = threat_sync.sync_malicious_ips(db_path="/fake/path.db", min_level=0, dry_run=True)

        insert_mock.assert_not_called()
        fake_conn.commit.assert_not_called()
        # dry_run still reports what *would* have been inserted...
        assert set(result.inserted_ips) == {"185.220.101.5", "45.155.205.1"}
        # ...but the summary count is explicitly zero since nothing was written.
        assert result.inserted_count == 0

    def test_sync_passes_insert_firewall_rule_the_threat_intel_source_label(self, monkeypatch):
        fake_conn, insert_mock = self._mock_conn_context(monkeypatch)
        feed_text = "185.220.101.5\n"
        with patch.object(requests, "get", return_value=mock_feed_response(feed_text)):
            threat_sync.sync_malicious_ips(db_path="/fake/path.db", min_level=0)

        _, kwargs = insert_mock.call_args
        assert kwargs["source"] == threat_sync.SOURCE_LABEL
        assert kwargs["ip_address"] == "185.220.101.5"
        assert kwargs["unban_at"] is not None

    def test_sync_propagates_threat_feed_error_without_opening_db_connection(self, monkeypatch):
        connect_mock = MagicMock()
        monkeypatch.setattr(database, "connect_readwrite", connect_mock)
        with patch.object(requests, "get", side_effect=requests.ConnectionError("timeout")):
            with pytest.raises(threat_sync.ThreatFeedError):
                threat_sync.sync_malicious_ips(db_path="/fake/path.db")

        connect_mock.assert_not_called()

    def test_sync_result_reports_accurate_counts_with_mixed_outcomes(self, monkeypatch):
        fake_conn, insert_mock = self._mock_conn_context(
            monkeypatch, is_blocked_fn=lambda conn, ip: ip == "1.1.1.1"
        )
        feed_text = "1.1.1.1\n2.2.2.2\n3.3.3.3\n"
        with patch.object(requests, "get", return_value=mock_feed_response(feed_text)):
            result = threat_sync.sync_malicious_ips(db_path="/fake/path.db", min_level=0)

        assert result.fetched_count == 3
        assert result.valid_ip_count == 3
        assert result.already_blocked_count == 1
        assert result.inserted_count == 2
