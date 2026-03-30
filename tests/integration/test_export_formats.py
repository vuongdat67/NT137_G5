from __future__ import annotations

import csv
import json
from pathlib import Path

from malware_analyzer.storage.exporter import export_csv, export_feature_matrix, export_jsonl, export_yara


def test_export_formats_for_dataset_rows(tmp_path: Path) -> None:
    rows = [
        {
            "sha256": "a" * 64,
            "file_name": "sample-a.exe",
            "file_path": "C:/samples/sample-a.exe",
            "file_size": 4096,
            "file_type": "PE32",
            "platform": "Windows",
            "packed": 1,
            "score": 88.5,
            "local_score": 55.0,
            "intel_score": 90.0,
            "family": "Win.Injector.Generic",
            "source": "MalwareBazaar",
            "strings": ["CreateRemoteThread", "VirtualAlloc", "http://bad.example"],
            "cfg_nodes": 12,
            "cfg_edges": 20,
            "cfg_cyclomatic": 10,
            "strings_total_count": 123,
            "strings_b64_count": 4,
            "api_risk_score": 76.5,
        }
    ]

    jsonl_path = tmp_path / "dataset.jsonl"
    csv_path = tmp_path / "dataset.csv"
    yara_path = tmp_path / "dataset.yar"
    matrix_path = tmp_path / "feature_matrix.csv"

    export_jsonl(jsonl_path, rows)
    export_csv(csv_path, rows)
    export_yara(yara_path, rows, rule_prefix="DatasetRule")
    export_feature_matrix(matrix_path, rows)

    payload = json.loads(jsonl_path.read_text(encoding="utf-8").strip())
    assert payload["file_name"] == "sample-a.exe"

    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        csv_rows = list(reader)
    assert len(csv_rows) == 1
    assert csv_rows[0]["sha256"] == "a" * 64

    yara_text = yara_path.read_text(encoding="utf-8")
    assert "rule DatasetRule_0001" in yara_text

    with matrix_path.open("r", encoding="utf-8", newline="") as handle:
        matrix_rows = list(csv.DictReader(handle))
    assert len(matrix_rows) == 1
    assert matrix_rows[0]["platform"] == "Windows"
