from __future__ import annotations

from pathlib import Path

from malware_analyzer.config.settings import get_settings


def test_settings_default_output_dir() -> None:
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.output_dir == Path("output")


def test_settings_env_override(monkeypatch) -> None:
    monkeypatch.setenv("MSA_WORKERS", "7")
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.workers == 7

    monkeypatch.delenv("MSA_WORKERS", raising=False)
    get_settings.cache_clear()
