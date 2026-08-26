"""ai_analyst.py -- LLM-powered forensic analysis of recent VANGUARD incidents.

Reads the latest incidents straight from the shared SQLite database
(database.py, read-only connection), sends a structured forensic-analysis
prompt to whichever LLM provider is configured, and returns/optionally
persists a strict JSON verdict per incident: likely intent, confidence,
recommended action, and a plain-English summary an on-call human can act
on immediately.

Provider selection is automatic and dependency-light:
  - If ANTHROPIC_API_KEY is set and the `anthropic` package is installed,
    Claude is used.
  - Else if OPENAI_API_KEY is set and the `openai` package is installed,
    OpenAI is used.
  - Otherwise, raises AIAnalystConfigError with a clear remediation
    message rather than silently no-op'ing.

This module NEVER shells out and NEVER writes to the filesystem except
through database.py's dedicated write helper -- it only makes outbound
HTTPS calls to the configured LLM provider's REST API.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from typing import Any, Optional

import database

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AIAnalystConfigError(RuntimeError):
    """Raised when no usable LLM provider/SDK/API key combination is found."""


class AIAnalystResponseError(RuntimeError):
    """Raised when the LLM's response could not be parsed as the expected
    strict-JSON forensic verdict schema, even after the retry."""


# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------


@dataclass
class ForensicVerdict:
    incident_id: int
    source_ip: str
    incident_type: str
    likely_intent: str
    threat_actor_sophistication: str  # "opportunistic" | "targeted" | "automated_bot" | "unknown"
    confidence: float  # 0.0 - 1.0
    recommended_action: str  # "block" | "monitor" | "escalate" | "ignore"
    summary: str
    mitre_attack_techniques: list[str]
    provider: str
    model: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) forensic analyst \
embedded inside VANGUARD, an automated Linux intrusion detection/prevention platform. \
You will be given one structured security incident record (JSON) produced by \
VANGUARD's deterministic detection engine and risk-scoring rules.

Your job: produce a concise, decision-ready forensic verdict a human analyst \
can act on in under 10 seconds of reading. Be specific and grounded ONLY in \
the evidence provided -- never invent details (e.g. do not claim to have \
seen a CVE number, username, or payload that isn't in the record).

You MUST respond with ONLY a single valid JSON object (no markdown fences, \
no prose before or after) matching exactly this schema:

{
  "likely_intent": "<short phrase, e.g. 'Credential stuffing against SSH'>",
  "threat_actor_sophistication": "opportunistic|targeted|automated_bot|unknown",
  "confidence": <float 0.0-1.0>,
  "recommended_action": "block|monitor|escalate|ignore",
  "summary": "<2-4 sentence plain-English forensic summary>",
  "mitre_attack_techniques": ["<T-code>", ...]
}
"""


def _build_user_prompt(incident: database.Incident) -> str:
    record = {
        "incident_id": incident.id,
        "type": incident.type,
        "source_ip": incident.source_ip,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "attempt_count": incident.attempt_count,
        "detected_at": incident.detected_at.isoformat() if incident.detected_at else None,
        "metadata": incident.metadata,
    }
    return (
        "Analyze this VANGUARD incident record and return the forensic verdict JSON:\n\n"
        + json.dumps(record, indent=2, default=str)
    )


# ---------------------------------------------------------------------------
# Provider clients
# ---------------------------------------------------------------------------


def _call_anthropic(system_prompt: str, user_prompt: str, model: str) -> str:
    import anthropic  # local import: optional dependency

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    resp = client.messages.create(
        model=model,
        max_tokens=1024,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")


def _call_openai(system_prompt: str, user_prompt: str, model: str) -> str:
    from openai import OpenAI  # local import: optional dependency

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        response_format={"type": "json_object"},
        temperature=0.2,
    )
    return resp.choices[0].message.content or ""


def _select_provider() -> tuple[str, str]:
    """Returns (provider_name, model_name) for whichever provider is
    usable, preferring Anthropic when both are configured (arbitrary but
    documented tie-break: Claude is this project's primary reference
    model per the project's own tooling)."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            import anthropic  # noqa: F401

            return "anthropic", os.environ.get("VANGUARD_ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")
        except ImportError:
            pass
    if os.environ.get("OPENAI_API_KEY"):
        try:
            import openai  # noqa: F401

            return "openai", os.environ.get("VANGUARD_OPENAI_MODEL", "gpt-4o-mini")
        except ImportError:
            pass
    raise AIAnalystConfigError(
        "No usable LLM provider found. Set ANTHROPIC_API_KEY (with the "
        "`anthropic` package installed) or OPENAI_API_KEY (with the "
        "`openai` package installed), then retry."
    )


def _parse_verdict_json(raw: str) -> dict[str, Any]:
    text = raw.strip()
    # Some models wrap JSON in ```json fences even when explicitly told not
    # to -- strip that defensively rather than failing the whole run.
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AIAnalystResponseError(f"LLM did not return valid JSON: {exc}\nRaw response: {raw[:500]}") from exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_incident(incident: database.Incident, *, provider: Optional[str] = None) -> ForensicVerdict:
    """Runs one incident through the configured LLM and returns a
    validated ForensicVerdict. Does NOT write to the database -- callers
    (main.py) decide whether/when to persist via database.set_incident_ai_analysis.
    """
    provider_name, model = (provider, None) if provider else _select_provider()
    if provider and not model:
        # Explicit provider override without a model override -- fall back
        # to that provider's default model.
        model = {
            "anthropic": os.environ.get("VANGUARD_ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929"),
            "openai": os.environ.get("VANGUARD_OPENAI_MODEL", "gpt-4o-mini"),
        }.get(provider_name)
        if model is None:
            raise AIAnalystConfigError(f"Unknown provider override: {provider_name!r}")

    user_prompt = _build_user_prompt(incident)

    if provider_name == "anthropic":
        raw = _call_anthropic(SYSTEM_PROMPT, user_prompt, model)
    elif provider_name == "openai":
        raw = _call_openai(SYSTEM_PROMPT, user_prompt, model)
    else:
        raise AIAnalystConfigError(f"Unsupported provider: {provider_name!r}")

    parsed = _parse_verdict_json(raw)

    return ForensicVerdict(
        incident_id=incident.id,
        source_ip=incident.source_ip,
        incident_type=incident.type,
        likely_intent=str(parsed.get("likely_intent", "unknown")),
        threat_actor_sophistication=str(parsed.get("threat_actor_sophistication", "unknown")),
        confidence=float(parsed.get("confidence", 0.0)),
        recommended_action=str(parsed.get("recommended_action", "monitor")),
        summary=str(parsed.get("summary", "")),
        mitre_attack_techniques=list(parsed.get("mitre_attack_techniques", [])),
        provider=provider_name,
        model=model,
    )


def analyze_recent(
    db_path: Optional[str] = None,
    *,
    limit: int = 10,
    since_hours: Optional[int] = 24,
    status: Optional[str] = None,
    persist: bool = True,
    provider: Optional[str] = None,
) -> list[ForensicVerdict]:
    """Fetches the most recent matching incidents and runs each one
    through analyze_incident(). Errors on an individual incident are
    logged into its own verdict (recommended_action="escalate", summary
    explaining the failure) rather than aborting the whole batch -- a
    single malformed record or transient API hiccup shouldn't block
    analysis of every other incident in the run.
    """
    incidents = database.get_recent_incidents(
        db_path, limit=limit, since_hours=since_hours, status=status
    )
    verdicts: list[ForensicVerdict] = []
    for incident in incidents:
        try:
            verdict = analyze_incident(incident, provider=provider)
        except (AIAnalystResponseError, Exception) as exc:  # noqa: BLE001 -- deliberately broad, see docstring
            verdict = ForensicVerdict(
                incident_id=incident.id,
                source_ip=incident.source_ip,
                incident_type=incident.type,
                likely_intent="analysis_failed",
                threat_actor_sophistication="unknown",
                confidence=0.0,
                recommended_action="escalate",
                summary=f"AI analysis failed for this incident: {exc}",
                mitre_attack_techniques=[],
                provider=provider or "unknown",
                model="unknown",
            )
        verdicts.append(verdict)
        if persist:
            database.set_incident_ai_analysis(db_path, incident.id, verdict.to_json())
    return verdicts
