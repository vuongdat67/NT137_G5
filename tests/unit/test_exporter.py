from __future__ import annotations

import csv
import json
from pathlib import Path

from malware_analyzer.core.hashing import hash_file
from malware_analyzer.core.identifier import identify
from malware_analyzer.core.models import ScanResult
from malware_analyzer.storage.exporter import export_csv, export_jsonl


def _build_result(path: Path) -> ScanResult:
    return ScanResult(file_info=identify(path), hash_result=hash_file(path))


def test_export_jsonl(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello" * 200)
    output = tmp_path / "out.jsonl"

    export_jsonl(output, [_build_result(sample)])

    lines = output.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["file_name"] == "sample.bin"


def test_export_csv_with_empty_results(tmp_path: Path) -> None:
    output = tmp_path / "out.csv"

    export_csv(output, [])

    with output.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    assert len(rows) == 1
    assert "file_name" in rows[0]
