from __future__ import annotations

from malware_analyzer.core.extractors.api_extractor import extract_api_features


def test_api_extractor_classifies_scores_and_maps_mitre() -> None:
    imports = [
        "KERNEL32.dll!VirtualAlloc",
        "KERNEL32.dll!WriteProcessMemory",
        "KERNEL32.dll!CreateRemoteThread",
        "KERNEL32.dll!LoadLibraryA",
        "ADVAPI32.dll!RegSetValue",
    ]

    features = extract_api_features(imports)

    assert float(features["api_risk_score"]) > 0.0
    assert str(features["api_risk_level"]) in {"low", "medium", "high"}

    category_hits = features["api_category_hits"]
    assert "PROCESS_INJECTION" in category_hits
    assert len(category_hits["PROCESS_INJECTION"]) >= 2

    mitre = features["api_mitre_attack"]
    assert "PROCESS_INJECTION" in mitre
    assert any(str(item).startswith("T") for item in mitre["PROCESS_INJECTION"])
