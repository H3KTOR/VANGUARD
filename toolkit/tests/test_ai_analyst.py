"""tests/test_ai_analyst.py -- unit tests for ai_analyst.py.

Everything that would otherwise make a real network call (the Anthropic
SDK client, the OpenAI SDK client) is mocked with unittest.mock so this
suite never needs ANTHROPIC_API_KEY / OPENAI_API_KEY set nor touches the
network. database.py is never given a real DB file here either --
analyze_incident() takes an already-constructed database.Incident object,
and analyze_recent() has its database.* calls monkeypatched.

Covered behavior:
  - provider auto-detection (Anthropic preferred over OpenAI when both
    configured; OpenAI used when only it is configured; clear
    AIAnalystConfigError when neither is configured)
  - ForensicVerdict JSON parsing from a well-formed model response
  - defensive parsing of a response wrapped in ```json fences
  - AIAnalystResponseError raised on genuinely invalid JSON
  - analyze_recent's per-incident graceful degradation: one failing
    incident produces a synthetic "escalate" verdict without aborting
    the rest of the batch, and persistence is still attempted for it
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import ai_analyst
import database


def make_incident(**overrides) -> database.Incident:
    defaults = dict(
        id=1,
        type="ssh_bruteforce",
        source_ip="185.220.101.5",
        severity="CRITICAL",
        risk_score=92,
        status="open",
        attempt_count=37,
        ai_analysis=None,
        metadata={"failed_logins": 37, "usernames": ["root", "admin"]},
        detected_at=datetime(2026, 8, 26, 8, 0, 0, tzinfo=timezone.utc),
        resolved_at=None,
        created_at=datetime(2026, 8, 26, 8, 0, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return database.Incident(**defaults)


VALID_VERDICT_JSON = json.dumps(
    {
        "likely_intent": "Credential stuffing against SSH",
        "threat_actor_sophistication": "automated_bot",
        "confidence": 0.87,
        "recommended_action": "block",
        "summary": "Repeated failed SSH logins from a single IP targeting common usernames.",
        "mitre_attack_techniques": ["T1110", "T1110.001"],
    }
)


# ---------------------------------------------------------------------------
# Provider selection
# ---------------------------------------------------------------------------


class TestSelectProvider:
    def test_prefers_anthropic_when_both_keys_set(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-test")
        provider, model = ai_analyst._select_provider()
        assert provider == "anthropic"
        assert "claude" in model.lower()

    def test_falls_back_to_openai_when_only_openai_key_set(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-test")
        provider, model = ai_analyst._select_provider()
        assert provider == "openai"
        assert "gpt" in model.lower()

    def test_raises_config_error_when_no_keys_set(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ai_analyst.AIAnalystConfigError):
            ai_analyst._select_provider()

    def test_respects_custom_model_env_overrides(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        monkeypatch.setenv("VANGUARD_ANTHROPIC_MODEL", "claude-custom-model")
        provider, model = ai_analyst._select_provider()
        assert provider == "anthropic"
        assert model == "claude-custom-model"


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------


class TestParseVerdictJson:
    def test_parses_clean_json(self):
        parsed = ai_analyst._parse_verdict_json(VALID_VERDICT_JSON)
        assert parsed["likely_intent"] == "Credential stuffing against SSH"
        assert parsed["confidence"] == 0.87
        assert parsed["mitre_attack_techniques"] == ["T1110", "T1110.001"]

    def test_strips_markdown_json_fences_defensively(self):
        fenced = f"```json\n{VALID_VERDICT_JSON}\n```"
        parsed = ai_analyst._parse_verdict_json(fenced)
        assert parsed["recommended_action"] == "block"

    def test_strips_bare_fences_without_json_tag(self):
        fenced = f"```\n{VALID_VERDICT_JSON}\n```"
        parsed = ai_analyst._parse_verdict_json(fenced)
        assert parsed["recommended_action"] == "block"

    def test_raises_response_error_on_invalid_json(self):
        with pytest.raises(ai_analyst.AIAnalystResponseError):
            ai_analyst._parse_verdict_json("this is not json at all")

    def test_response_error_includes_raw_snippet_for_debugging(self):
        garbage = "totally not json " * 5
        with pytest.raises(ai_analyst.AIAnalystResponseError) as exc_info:
            ai_analyst._parse_verdict_json(garbage)
        assert "totally not json" in str(exc_info.value)


# ---------------------------------------------------------------------------
# analyze_incident -- mocked provider calls
# ---------------------------------------------------------------------------


class TestAnalyzeIncident:
    def test_analyze_incident_with_mocked_anthropic_call(self, monkeypatch):
        incident = make_incident()
        monkeypatch.setattr(ai_analyst, "_call_anthropic", MagicMock(return_value=VALID_VERDICT_JSON))

        verdict = ai_analyst.analyze_incident(incident, provider="anthropic")

        assert isinstance(verdict, ai_analyst.ForensicVerdict)
        assert verdict.incident_id == 1
        assert verdict.source_ip == "185.220.101.5"
        assert verdict.recommended_action == "block"
        assert verdict.confidence == 0.87
        assert verdict.provider == "anthropic"
        assert "T1110" in verdict.mitre_attack_techniques

    def test_analyze_incident_with_mocked_openai_call(self, monkeypatch):
        incident = make_incident(id=2, source_ip="10.20.30.40")
        monkeypatch.setattr(ai_analyst, "_call_openai", MagicMock(return_value=VALID_VERDICT_JSON))

        verdict = ai_analyst.analyze_incident(incident, provider="openai")

        assert verdict.incident_id == 2
        assert verdict.provider == "openai"
        assert verdict.likely_intent == "Credential stuffing against SSH"

    def test_analyze_incident_to_json_round_trips(self, monkeypatch):
        incident = make_incident()
        monkeypatch.setattr(ai_analyst, "_call_anthropic", MagicMock(return_value=VALID_VERDICT_JSON))
        verdict = ai_analyst.analyze_incident(incident, provider="anthropic")

        round_tripped = json.loads(verdict.to_json())
        assert round_tripped["incident_id"] == 1
        assert round_tripped["recommended_action"] == "block"

    def test_analyze_incident_raises_on_malformed_llm_response(self, monkeypatch):
        incident = make_incident()
        monkeypatch.setattr(ai_analyst, "_call_anthropic", MagicMock(return_value="not valid json"))

        with pytest.raises(ai_analyst.AIAnalystResponseError):
            ai_analyst.analyze_incident(incident, provider="anthropic")

    def test_analyze_incident_rejects_unknown_provider_override(self):
        incident = make_incident()
        with pytest.raises(ai_analyst.AIAnalystConfigError):
            ai_analyst.analyze_incident(incident, provider="some_unknown_provider")

    def test_call_anthropic_uses_sdk_client_correctly(self, monkeypatch):
        """Verifies _call_anthropic itself (one layer deeper): mocks the
        anthropic module's client so no real network call is made, and
        checks the text is extracted from the response content blocks."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

        fake_text_block = MagicMock()
        fake_text_block.type = "text"
        fake_text_block.text = VALID_VERDICT_JSON
        fake_response = MagicMock()
        fake_response.content = [fake_text_block]

        fake_client = MagicMock()
        fake_client.messages.create.return_value = fake_response

        fake_anthropic_module = MagicMock()
        fake_anthropic_module.Anthropic.return_value = fake_client

        with patch.dict("sys.modules", {"anthropic": fake_anthropic_module}):
            result = ai_analyst._call_anthropic("system prompt", "user prompt", "claude-test-model")

        assert result == VALID_VERDICT_JSON
        fake_client.messages.create.assert_called_once()
        _, kwargs = fake_client.messages.create.call_args
        assert kwargs["model"] == "claude-test-model"
        assert kwargs["system"] == "system prompt"

    def test_call_openai_uses_sdk_client_correctly(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-test")

        fake_message = MagicMock()
        fake_message.content = VALID_VERDICT_JSON
        fake_choice = MagicMock()
        fake_choice.message = fake_message
        fake_response = MagicMock()
        fake_response.choices = [fake_choice]

        fake_client = MagicMock()
        fake_client.chat.completions.create.return_value = fake_response

        fake_openai_module = MagicMock()
        fake_openai_module.OpenAI.return_value = fake_client

        with patch.dict("sys.modules", {"openai": fake_openai_module}):
            result = ai_analyst._call_openai("system prompt", "user prompt", "gpt-test-model")

        assert result == VALID_VERDICT_JSON
        fake_client.chat.completions.create.assert_called_once()
        _, kwargs = fake_client.chat.completions.create.call_args
        assert kwargs["model"] == "gpt-test-model"


# ---------------------------------------------------------------------------
# analyze_recent -- batch + graceful degradation
# ---------------------------------------------------------------------------


class TestAnalyzeRecent:
    def test_analyze_recent_persists_verdict_for_each_incident(self, monkeypatch):
        incidents = [make_incident(id=1), make_incident(id=2, source_ip="9.9.9.9")]
        monkeypatch.setattr(database, "get_recent_incidents", MagicMock(return_value=incidents))
        monkeypatch.setattr(
            ai_analyst,
            "analyze_incident",
            MagicMock(
                side_effect=lambda incident, provider=None: ai_analyst.ForensicVerdict(
                    incident_id=incident.id,
                    source_ip=incident.source_ip,
                    incident_type=incident.type,
                    likely_intent="test",
                    threat_actor_sophistication="unknown",
                    confidence=0.5,
                    recommended_action="monitor",
                    summary="test summary",
                    mitre_attack_techniques=[],
                    provider="anthropic",
                    model="claude-test",
                )
            ),
        )
        set_analysis_mock = MagicMock()
        monkeypatch.setattr(database, "set_incident_ai_analysis", set_analysis_mock)

        verdicts = ai_analyst.analyze_recent(db_path="/fake/path.db", limit=10, persist=True)

        assert len(verdicts) == 2
        assert set_analysis_mock.call_count == 2
        set_analysis_mock.assert_any_call("/fake/path.db", 1, verdicts[0].to_json())

    def test_analyze_recent_does_not_persist_when_persist_false(self, monkeypatch):
        incidents = [make_incident(id=1)]
        monkeypatch.setattr(database, "get_recent_incidents", MagicMock(return_value=incidents))
        monkeypatch.setattr(
            ai_analyst,
            "analyze_incident",
            MagicMock(
                return_value=ai_analyst.ForensicVerdict(
                    incident_id=1,
                    source_ip="1.2.3.4",
                    incident_type="ssh_bruteforce",
                    likely_intent="x",
                    threat_actor_sophistication="unknown",
                    confidence=0.1,
                    recommended_action="monitor",
                    summary="x",
                    mitre_attack_techniques=[],
                    provider="anthropic",
                    model="claude-test",
                )
            ),
        )
        set_analysis_mock = MagicMock()
        monkeypatch.setattr(database, "set_incident_ai_analysis", set_analysis_mock)

        ai_analyst.analyze_recent(db_path="/fake/path.db", persist=False)

        set_analysis_mock.assert_not_called()

    def test_analyze_recent_gracefully_degrades_on_per_incident_failure(self, monkeypatch):
        """One incident's analyze_incident() call raises; the batch must
        still complete with a synthetic 'escalate' verdict for that
        incident instead of aborting the whole run."""
        good_incident = make_incident(id=1, source_ip="1.1.1.1")
        bad_incident = make_incident(id=2, source_ip="2.2.2.2")
        monkeypatch.setattr(
            database, "get_recent_incidents", MagicMock(return_value=[good_incident, bad_incident])
        )

        def fake_analyze(incident, provider=None):
            if incident.id == 2:
                raise ai_analyst.AIAnalystResponseError("LLM returned garbage")
            return ai_analyst.ForensicVerdict(
                incident_id=incident.id,
                source_ip=incident.source_ip,
                incident_type=incident.type,
                likely_intent="Credential stuffing",
                threat_actor_sophistication="automated_bot",
                confidence=0.9,
                recommended_action="block",
                summary="ok",
                mitre_attack_techniques=["T1110"],
                provider="anthropic",
                model="claude-test",
            )

        monkeypatch.setattr(ai_analyst, "analyze_incident", fake_analyze)
        set_analysis_mock = MagicMock()
        monkeypatch.setattr(database, "set_incident_ai_analysis", set_analysis_mock)

        verdicts = ai_analyst.analyze_recent(db_path="/fake/path.db", persist=True)

        assert len(verdicts) == 2
        good_verdict, bad_verdict = verdicts
        assert good_verdict.recommended_action == "block"

        # The failing incident gets a synthetic, non-crashing fallback verdict.
        assert bad_verdict.incident_id == 2
        assert bad_verdict.recommended_action == "escalate"
        assert bad_verdict.likely_intent == "analysis_failed"
        assert "LLM returned garbage" in bad_verdict.summary

        # Both verdicts -- including the failure one -- are still persisted.
        assert set_analysis_mock.call_count == 2
        set_analysis_mock.assert_any_call("/fake/path.db", 2, bad_verdict.to_json())

    def test_analyze_recent_forwards_filter_kwargs_to_database_layer(self, monkeypatch):
        get_recent_mock = MagicMock(return_value=[])
        monkeypatch.setattr(database, "get_recent_incidents", get_recent_mock)

        ai_analyst.analyze_recent(
            db_path="/fake/path.db", limit=5, since_hours=48, status="open", persist=False
        )

        get_recent_mock.assert_called_once_with("/fake/path.db", limit=5, since_hours=48, status="open")

    def test_analyze_recent_returns_empty_list_when_no_incidents(self, monkeypatch):
        monkeypatch.setattr(database, "get_recent_incidents", MagicMock(return_value=[]))
        verdicts = ai_analyst.analyze_recent(db_path="/fake/path.db")
        assert verdicts == []
