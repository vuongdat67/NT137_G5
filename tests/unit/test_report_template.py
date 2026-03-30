from __future__ import annotations

from pathlib import Path

from malware_analyzer.reports.generator import generate_html


def test_single_report_template_contains_phase9_sections(tmp_path: Path) -> None:
    payload = {
        "sha256": "a" * 64,
        "file_name": "sample.exe",
        "file_path": "C:/samples/sample.exe",
        "platform": "Windows",
        "file_type": "PE32",
        "heuristic_score": 88,
        "heuristic_verdict": "MALICIOUS",
        "heuristic_triggers": ["Process injection API combo"],
        "yara_matches": ["Rule.Local"],
        "yara_matches_remote": ["Rule.Remote"],
        "api_imports": ["KERNEL32.dll!CreateFileA"],
        "strings": ["CreateRemoteThread", "VirtualAlloc"],
        "strings_url": ["http://example.invalid"],
        "strings_ip": ["1.2.3.4"],
        "cfg_nodes": 3,
        "cfg_edges": 2,
        "cfg_graph_edges": [[0, 1], [1, 2]],
    }

    out = tmp_path / "single_report.html"
    generate_html(payload, out)

    html = out.read_text(encoding="utf-8")
    assert "File Metadata" in html
    assert "Heuristic Score Gauge" in html
    assert "YARA Matches" in html
    assert "Import Table" in html
    assert "Strings" in html
