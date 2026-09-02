"""test_env_loader.py -- unit tests for env_loader.load_dotenv.

Every test uses a temp directory (pytest's tmp_path fixture) for the
.env file and carefully snapshots/restores os.environ, so this suite
never touches the real filesystem's working-directory .env or leaks
environment state into other tests -- consistent with the toolkit
test suite's "never hit real APIs or DBs" ethos extended to "never
mutate real process state either".
"""

from __future__ import annotations

import os

import pytest

import env_loader


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Ensure the test-specific keys used below don't leak in/out."""
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "TELEGRAM_BOT_TOKEN", "FOO", "QUOTED", "ALREADY_SET"):
        monkeypatch.delenv(key, raising=False)
    yield


def test_load_dotenv_returns_zero_when_file_missing(tmp_path):
    missing_path = tmp_path / "does_not_exist.env"
    assert env_loader.load_dotenv(str(missing_path)) == 0


def test_load_dotenv_sets_simple_key_value_pairs(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("ANTHROPIC_API_KEY=sk-ant-test123\nOPENAI_API_KEY=sk-oai-test456\n")

    loaded = env_loader.load_dotenv(str(env_file))

    assert loaded == 2
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-test123"
    assert os.environ["OPENAI_API_KEY"] == "sk-oai-test456"


def test_load_dotenv_skips_comments_and_blank_lines(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("# this is a comment\n\nFOO=bar\n   \n# another comment\n")

    loaded = env_loader.load_dotenv(str(env_file))

    assert loaded == 1
    assert os.environ["FOO"] == "bar"


def test_load_dotenv_strips_matching_quotes(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text('QUOTED="hello world"\n')

    env_loader.load_dotenv(str(env_file))

    assert os.environ["QUOTED"] == "hello world"


def test_load_dotenv_never_overwrites_existing_env_var(tmp_path, monkeypatch):
    monkeypatch.setenv("ALREADY_SET", "real-value-from-environment")
    env_file = tmp_path / ".env"
    env_file.write_text("ALREADY_SET=value-from-dotenv-should-be-ignored\n")

    loaded = env_loader.load_dotenv(str(env_file))

    assert loaded == 0
    assert os.environ["ALREADY_SET"] == "real-value-from-environment"


def test_load_dotenv_skips_malformed_lines_without_equals(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("THIS_LINE_HAS_NO_EQUALS_SIGN\nFOO=bar\n")

    loaded = env_loader.load_dotenv(str(env_file))

    assert loaded == 1
    assert os.environ["FOO"] == "bar"


def test_load_dotenv_skips_lines_with_empty_key(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("=orphan_value\nFOO=bar\n")

    loaded = env_loader.load_dotenv(str(env_file))

    assert loaded == 1
    assert "FOO" in os.environ
