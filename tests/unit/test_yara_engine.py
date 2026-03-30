from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from malware_analyzer.detection.yara_engine import clear_rule_cache, scan_bytes, scan_file


def test_scan_file_matches_local_rule(tmp_path: Path) -> None:
    clear_rule_cache()
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


def test_scan_bytes_thread_safe_parallel_reads(tmp_path: Path) -> None:
    clear_rule_cache()
    rule_dir = tmp_path / "rules" / "yara"
    rule_dir.mkdir(parents=True, exist_ok=True)
    rule_path = rule_dir / "parallel_test.yar"
    rule_path.write_text(
        "rule Parallel_Test_Marker { strings: $a = \"THREAD_SAFE_2026\" condition: $a }",
        encoding="utf-8",
    )

    payload = b"prefix THREAD_SAFE_2026 suffix"

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(scan_bytes, payload, rule_dir) for _ in range(24)]
        results = [future.result() for future in futures]

    assert results
    for matches in results:
        assert "Parallel_Test_Marker" in matches
