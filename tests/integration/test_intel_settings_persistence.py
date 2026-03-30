from __future__ import annotations

from malware_analyzer.config.settings import get_settings
from malware_analyzer.gui.views.intel_view import IntelView


def test_intel_view_persists_api_key_and_reloads(tmp_path, monkeypatch, qapp) -> None:
    config_path = tmp_path / "config.yaml"
    monkeypatch.setenv("MSA_CONFIG_FILE", str(config_path))
    get_settings.cache_clear()

    view = IntelView()
    captured_payloads: list[dict[str, object]] = []
    view.fetch_requested.connect(lambda payload: captured_payloads.append(payload))

    view.api_key_edit.setText("persisted-key-2026")
    view._emit_fetch_request()

    assert captured_payloads
    assert str(captured_payloads[0].get("api_key", "")) == "persisted-key-2026"
    assert config_path.exists()

    get_settings.cache_clear()
    settings = get_settings()
    assert settings.bazaar_api_key == "persisted-key-2026"

    reopened = IntelView()
    assert reopened.api_key_edit.text().strip() == "persisted-key-2026"

    reopened.deleteLater()
    view.deleteLater()
