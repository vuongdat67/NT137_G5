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


def test_enrichment_includes_parser_prefixed_fields(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ\x90\x00dummy")

    file_info = identify(sample)

    monkeypatch.setattr(
        "malware_analyzer.core.enrichment.parse_file",
        lambda path, info, data: {
            "api_imports": ["KERNEL32.dll!CreateFileA"],
            "pe_exports": ["ExportedFunc"],
            "pe_sections_count": 3,
            "apk_permissions_count": 0,
        },
    )
    monkeypatch.setattr("malware_analyzer.core.enrichment.yara_scan_file", lambda path, **kwargs: [])
    monkeypatch.setattr("malware_analyzer.core.enrichment.yara_scan_bytes", lambda data, **kwargs: [])

    features = build_enrichment(sample, file_info)

    assert features.get("pe_exports") == ["ExportedFunc"]
    assert int(features.get("pe_sections_count", 0)) == 3
    assert int(features.get("apk_permissions_count", 0)) == 0
