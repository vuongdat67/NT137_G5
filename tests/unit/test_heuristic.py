from __future__ import annotations

import json

from malware_analyzer.core.models import FileInfo, FileType
from malware_analyzer.detection import heuristic
from malware_analyzer.detection.heuristic import score_features


def test_heuristic_process_injection_combo_scores_high() -> None:
    info = FileInfo(
        file_path="sample.exe",
        file_name="sample.exe",
        file_size=12345,
        file_type=FileType.PE32,
        platform="Windows",
    )
    features = {
        "api_imports": [
            "kernel32.dll!VirtualAlloc",
            "kernel32.dll!WriteProcessMemory",
            "kernel32.dll!CreateRemoteThread",
        ],
        "packed": True,
        "strings_url": ["http://evil.test/c2"],
        "yara_matches": ["Windows_Process_Injection_APIs"],
    }

    result = score_features(info, features)
    assert float(result["heuristic_score"]) >= 40.0
    assert str(result["heuristic_verdict"]) in {"SUSPICIOUS", "MALICIOUS"}


def test_heuristic_loads_override_weights_from_config(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "heuristic_rules.json"
    config_path.write_text(
        json.dumps(
            {
                "weights": {
                    "process_injection_combo": 5,
                },
                "thresholds": {
                    "malicious": 90,
                    "suspicious": 80,
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(heuristic, "_candidate_config_paths", lambda: [config_path])
    heuristic._load_heuristic_config.cache_clear()

    info = FileInfo(
        file_path="sample.exe",
        file_name="sample.exe",
        file_size=12345,
        file_type=FileType.PE32,
        platform="Windows",
    )
    features = {
        "api_imports": [
            "kernel32.dll!VirtualAlloc",
            "kernel32.dll!WriteProcessMemory",
            "kernel32.dll!CreateRemoteThread",
        ],
    }
    result = score_features(info, features)

    assert float(result["heuristic_score"]) < 80.0
    assert str(result["heuristic_verdict"]) == "CLEAN"

    heuristic._load_heuristic_config.cache_clear()
