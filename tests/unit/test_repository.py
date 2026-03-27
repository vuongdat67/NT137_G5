from __future__ import annotations

from pathlib import Path
from time import sleep

from malware_analyzer.config.settings import get_settings
from malware_analyzer.core.hashing import hash_file
from malware_analyzer.core.identifier import identify
from malware_analyzer.core.models import ScanResult
from malware_analyzer.storage.repository import SampleQuery, SampleRepository


def _build_scan_result(path: Path) -> ScanResult:
    return ScanResult(file_info=identify(path), hash_result=hash_file(path))


def test_repository_insert_and_query(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MSA_OUTPUT_DIR", str(tmp_path / "output"))
    get_settings.cache_clear()

    repo = SampleRepository()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc" * 200)
    sample2 = tmp_path / "sample2.bin"
    sample2.write_bytes(b"xyz" * 300)

    repo.upsert_scan_result(_build_scan_result(sample))
    repo.upsert_scan_result(_build_scan_result(sample2))

    assert repo.count_samples() == 2
    rows = repo.list_samples(SampleQuery(page=1, page_size=10))
    assert len(rows) == 2

    first_sha = str(rows[0]["sha256"])
    second_sha = str(rows[1]["sha256"])

    data = repo.get_sample(first_sha)
    assert data is not None
    assert data["file_name"] in {"sample.bin", "sample2.bin"}

    intel_entries = [
        {
            "sha256_hash": first_sha,
            "signature": "Spyware",
            "tags": ["android", "sms"],
            "imphash": "shared-imphash",
        },
        {
            "sha256_hash": second_sha,
            "signature": "Spyware",
            "tags": ["android", "banker"],
            "imphash": "shared-imphash",
        },
    ]
    updated, skipped = repo.apply_intel_entries(intel_entries, source="MalwareBazaar")
    assert updated == 2
    assert skipped == 0

    updated_local = repo.update_manual_tags([first_sha, second_sha], "triage, urgent")
    assert updated_local == 2

    sleep(0.01)
    filtered = repo.list_samples(
        SampleQuery(
            source="MalwareBazaar",
            tags="triage",
            score_min=0,
            score_max=100,
            date_from="2000-01-01",
            date_to="2100-01-01",
            page=1,
            page_size=10,
        )
    )
    assert len(filtered) == 2
    assert filtered[0]["family"] == "Spyware"
    assert "triage" in str(filtered[0]["tags"])

    similar = repo.find_similar_samples(first_sha)
    assert len(similar) >= 1
    reason_text = str(similar[0].get("reason", ""))
    assert any(token in reason_text for token in ["imphash", "family", "tlsh", "ssdeep"])

    monkeypatch.delenv("MSA_OUTPUT_DIR", raising=False)
    get_settings.cache_clear()
