from __future__ import annotations

from pathlib import Path

from malware_analyzer.config.settings import get_settings, save_settings_overrides


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


def test_settings_yaml_override(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text('workers: 9\nbazaar_api_key: "abc123"\n', encoding="utf-8")

    monkeypatch.setenv("MSA_CONFIG_FILE", str(config_path))
    monkeypatch.delenv("MSA_WORKERS", raising=False)
    get_settings.cache_clear()

    settings = get_settings()
    assert settings.workers == 9
    assert settings.bazaar_api_key == "abc123"


def test_settings_env_precedence_over_yaml(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("workers: 9\n", encoding="utf-8")

    monkeypatch.setenv("MSA_CONFIG_FILE", str(config_path))
    monkeypatch.setenv("MSA_WORKERS", "5")
    get_settings.cache_clear()

    settings = get_settings()
    assert settings.workers == 5


def test_save_settings_overrides_persists_yaml(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "runtime-config.yaml"
    monkeypatch.setenv("MSA_CONFIG_FILE", str(config_path))
    get_settings.cache_clear()

    written_path = save_settings_overrides({"bazaar_api_key": "saved-key"})
    assert written_path == config_path
    assert config_path.exists()

    get_settings.cache_clear()
    settings = get_settings()
    assert settings.bazaar_api_key == "saved-key"
