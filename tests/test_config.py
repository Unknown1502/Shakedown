"""`.env` loading: values reach os.environ, real environment wins, nothing is ever echoed."""
import os

from shakedown.config import load_dotenv


def test_loads_values_and_strips_quotes_and_comments(tmp_path, monkeypatch):
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("NEBIUS_PROJECT_ID", raising=False)
    env = tmp_path / ".env"
    env.write_text('# comment\nNEBIUS_API_KEY="abc123"\n\nNEBIUS_PROJECT_ID = proj-1  \nnot a line\n', encoding="utf-8")

    loaded = load_dotenv(env)

    assert os.environ["NEBIUS_API_KEY"] == "abc123"
    assert os.environ["NEBIUS_PROJECT_ID"] == "proj-1"
    assert sorted(loaded) == ["NEBIUS_API_KEY", "NEBIUS_PROJECT_ID"]


def test_existing_environment_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "from-shell")
    env = tmp_path / ".env"
    env.write_text("NEBIUS_API_KEY=from-file\n", encoding="utf-8")

    assert load_dotenv(env) == []
    assert os.environ["NEBIUS_API_KEY"] == "from-shell"


def test_empty_values_are_ignored_and_missing_file_is_fine(tmp_path, monkeypatch):
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text("TAVILY_API_KEY=\n", encoding="utf-8")

    assert load_dotenv(env) == []
    assert "TAVILY_API_KEY" not in os.environ
    assert load_dotenv(tmp_path / "missing.env") == []
