from __future__ import annotations

from malware_analyzer.core.models import FileInfo, FileType
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
