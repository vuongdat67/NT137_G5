from __future__ import annotations

from pathlib import Path

from malware_analyzer.detection.yara_engine import scan_file


def test_scan_file_matches_local_rule(tmp_path: Path) -> None:
    rule_dir = tmp_path / "rules" / "yara"
    rule_dir.mkdir(parents=True, exist_ok=True)
    rule_path = rule_dir / "local_test.yar"
    rule_path.write_text(
        "rule Local_Test_Marker { strings: $a = \"HELLO_MARKER_123\" condition: $a }",
        encoding="utf-8",
    )

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"prefix HELLO_MARKER_123 suffix")

    matches = scan_file(sample, rules_dir=rule_dir)
    assert "Local_Test_Marker" in matches
