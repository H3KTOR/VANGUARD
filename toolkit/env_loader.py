"""env_loader.py -- minimal, dependency-free `.env` file support.

VANGUARD's Python toolkit already depends on several packages (typer,
rich, requests, reportlab, openai, anthropic), so pulling in
python-dotenv purely to read `KEY=VALUE` lines would be a needless extra
dependency for ~20 lines of logic. This module is that logic, written to
mirror the Go core's own minimal dotenv loader
(core/cmd/vanguard/dotenv.go) so both halves of VANGUARD behave
identically for local development:

  - Looks for a `.env` file in the current working directory (override
    with the VANGUARD_ENV_FILE env var).
  - Applies every `KEY=VALUE` line to os.environ via os.environ.setdefault,
    so real environment variables (or a production secrets manager) always
    take precedence over a stray `.env` file.
  - A missing `.env` file is not an error -- this is the expected state in
    production, where secrets should come from the environment directly
    (e.g. inherited from systemd's EnvironmentFile=, or a cron job's own
    environment) rather than a checked-out `.env` file.
  - Malformed lines and comments (`#...`) are silently skipped.

Needed by the toolkit for: ANTHROPIC_API_KEY, OPENAI_API_KEY,
VANGUARD_ANTHROPIC_MODEL, VANGUARD_OPENAI_MODEL, VANGUARD_DB_PATH.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | None = None) -> int:
    """Load KEY=VALUE pairs from a .env file into os.environ.

    Returns the number of variables actually set (i.e. that were not
    already present in the environment). Existing environment variables
    are NEVER overwritten -- this function only fills in gaps.
    """
    env_path = Path(path or os.environ.get("VANGUARD_ENV_FILE", ".env"))
    if not env_path.is_file():
        return 0

    loaded = 0
    try:
        raw = env_path.read_text(encoding="utf-8")
    except OSError:
        return 0

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        # Strip one layer of matching quotes: KEY="value with spaces"
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key in os.environ:
            continue  # real environment always wins
        os.environ[key] = value
        loaded += 1

    return loaded
