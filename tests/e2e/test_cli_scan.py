from __future__ import annotations

import json
from pathlib import Path
import uuid

from click.testing import CliRunner

from malware_analyzer.cli.commands import cli


def _payload(sha256: str, name: str, md5: str = "") -> dict[str, object]:
    return {
        "sha256": sha256,
        "file_name": name,
        "file_path": f"/tmp/{name}",
        "file_size": 1024,
        "file_type": "PE32",
        "platform": "Windows",
        "architecture": "x86",
        "mime_type": "application/octet-stream",
        "packed": 0,
        "packer": "",
        "md5": md5,
        "sha1": "",
        "tlsh": "",
        "ssdeep": "",
        "imphash": "",
        "local_score": 11.0,
        "intel_score": 0.0,
        "score": 11.0,
        "family": "Win.Generic",
        "family_confidence": "low",
        "source": "Local",
        "tags": "triage",
        "notes": "",
        "ml_score": 0.0,
        "heuristic_score": 11.0,
    }


def test_cli_scan_supports_no_heuristic_and_yara_override(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MALWARE_MARKER_12345")

    rules_dir = tmp_path / "rules" / "yara"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "marker.yar").write_text(
        'rule MarkerRule { strings: $a = "MALWARE_MARKER_12345" ascii condition: $a }',
        encoding="utf-8",
    )

    out_dir = tmp_path / "output"
    monkeypatch.setenv("MSA_OUTPUT_DIR", str(out_dir))

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            str(sample),
            "--format",
            "json",
            "--output",
            str(out_dir),
            "--yara",
            str(rules_dir),
            "--no-heuristic",
        ],
    )

    assert result.exit_code == 0
    jsonl_files = sorted(out_dir.glob("scan_*.jsonl"))
    assert jsonl_files

    first_line = jsonl_files[0].read_text(encoding="utf-8").splitlines()[0]
    payload = json.loads(first_line)
    assert payload["heuristic_verdict"] == "DISABLED"
    assert float(payload["heuristic_score"]) == 0.0
    assert "MarkerRule" in payload.get("yara_matches", [])



def test_cli_db_commands_export_import_tag_and_dedupe(tmp_path: Path, monkeypatch) -> None:
    sample_sha = uuid.uuid4().hex + uuid.uuid4().hex
    out_dir = tmp_path / "output"
    monkeypatch.setenv("MSA_OUTPUT_DIR", str(out_dir))

    import_file = tmp_path / "import.jsonl"
    import_file.write_text(json.dumps(_payload(sample_sha, "sample-a.exe")) + "\n", encoding="utf-8")

    runner = CliRunner()

    imported = runner.invoke(cli, ["db", "import", str(import_file)])
    assert imported.exit_code == 0
    assert "Inserted: 1" in imported.output

    tagged = runner.invoke(cli, ["db", "tag", sample_sha, "--add", "urgent", "--remove", "triage"])
    assert tagged.exit_code == 0
    assert "urgent" in tagged.output

    export_path = tmp_path / "db-export.jsonl"
    exported = runner.invoke(
        cli,
        [
            "db",
            "export",
            "--format",
            "jsonl",
            "--platform",
            "Windows",
            "--output",
            str(export_path),
        ],
    )
    assert exported.exit_code == 0
    assert export_path.exists()

    deduped = runner.invoke(cli, ["db", "dedupe"])
    assert deduped.exit_code == 0
    assert "Removed duplicates:" in deduped.output
