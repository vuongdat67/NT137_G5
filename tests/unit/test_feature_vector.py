from __future__ import annotations

import json

from malware_analyzer.core.extractors.feature_vector import (
    build_feature_vector,
    to_dict,
    to_jsonl_line,
    validate_schema,
)
from malware_analyzer.core.models import FileInfo, FileType, HashResult, ScanResult


def test_feature_vector_build_serialize_and_validate() -> None:
    scan = ScanResult(
        file_info=FileInfo(
            file_path="sample.exe",
            file_name="sample.exe",
            file_size=1024,
            file_type=FileType.PE32,
            platform="Windows",
        ),
        hash_result=HashResult(
            md5="a" * 32,
            sha1="b" * 40,
            sha256="c" * 64,
            sha512="d" * 128,
            tlsh=None,
            ssdeep=None,
            imphash=None,
        ),
        features={
            "heuristic_score": 42.0,
            "heuristic_verdict": "SUSPICIOUS",
            "heuristic_triggers": ["Process injection API combo"],
            "yara_matches": ["Windows_Process_Injection_APIs"],
            "similar_samples": [{"sha256": "e" * 64, "similarity_score": 87.5, "reason": "imphash"}],
            "api_imports": ["KERNEL32.dll!VirtualAlloc"],
        },
    )

    document = build_feature_vector(scan)
    payload = to_dict(document)
    schema_obj = validate_schema(document)
    line = to_jsonl_line(document)
    parsed = json.loads(line)

    assert payload["file_info"]["file_name"] == "sample.exe"
    assert payload["hash_result"]["sha512"] == "d" * 128
    assert payload["heuristic"]["verdict"] == "SUSPICIOUS"
    assert payload["yara_matches"] == ["Windows_Process_Injection_APIs"]
    assert parsed["features"]["api_imports"] == ["KERNEL32.dll!VirtualAlloc"]
    assert schema_obj.schema_version
