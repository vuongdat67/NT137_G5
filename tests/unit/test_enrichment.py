from __future__ import annotations

from pathlib import Path

from malware_analyzer.core.enrichment import build_enrichment
from malware_analyzer.core.identifier import identify


def test_enrichment_classifies_strings_and_base64(tmp_path: Path) -> None:
    payload = (
        b"http://example.org/gate.php\x00"
        b"185.220.101.45\x00"
        b"HKEY_LOCAL_MACHINE\\SOFTWARE\\evil\x00"
        b"Global\\RansomMutex_2026\x00"
        b"U0dWc2JHOGdWMjl5YkdRPQ==\x00"
    )
    sample = tmp_path / "strings.bin"
    sample.write_bytes(payload)

    file_info = identify(sample)
    features = build_enrichment(sample, file_info)

    assert any("example.org" in item for item in features.get("strings_url", []))
    assert "185.220.101.45" in features.get("strings_ip", [])
    assert any("HKEY_LOCAL_MACHINE" in item for item in features.get("strings_registry", []))
    assert any("Global\\RansomMutex_2026" in item for item in features.get("strings_mutex", []))
    assert int(features.get("strings_b64_count", 0)) >= 1
