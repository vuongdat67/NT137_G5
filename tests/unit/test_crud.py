from __future__ import annotations

import csv
import json
from pathlib import Path

from malware_analyzer.config.settings import get_settings
from malware_analyzer.storage.crud import QueryOptions, SampleCRUD
from malware_analyzer.storage.database import init_db


SHA1 = "1" * 64
SHA2 = "2" * 64
SHA3 = "3" * 64


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


def test_crud_insert_query_update_delete_and_dedupe(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MSA_OUTPUT_DIR", str(tmp_path / "output"))
    get_settings.cache_clear()
    init_db()

    crud = SampleCRUD()

    inserted, updated = crud.insert_sample(_payload(SHA1, "a.bin", md5="abc"))
    assert inserted is True
    assert updated is False
    assert crud.exists(SHA1) is True

    inserted_batch, updated_batch, skipped_batch = crud.insert_batch(
        [
            _payload(SHA2, "b.bin", md5="abc"),
            _payload(SHA3, "c.bin", md5="def"),
        ]
    )
    assert inserted_batch == 2
    assert updated_batch == 0
    assert skipped_batch == 0

    row = crud.get_by_sha256(SHA1)
    assert row is not None
    assert row["file_name"] == "a.bin"

    queried = crud.query_samples(QueryOptions(page=1, page_size=10, platform="Windows"))
    assert len(queried) == 3

    stats = crud.get_stats()
    assert stats["total"] == 3
    assert stats["windows"] == 3

    assert crud.update_tags(SHA1, "triage,urgent") is True
    assert crud.update_family(SHA1, "Win.Injector.Generic") is True
    assert crud.update_notes(SHA1, "analyst-note") is True
    assert crud.update_ml_score(SHA1, 77.7) is True

    after_update = crud.get_by_sha256(SHA1)
    assert after_update is not None
    assert str(after_update["family"]) == "Win.Injector.Generic"
    assert "urgent" in str(after_update["tags"])
    assert str(after_update["notes"]) == "analyst-note"
    assert float(after_update["ml_score"]) == 77.7

    removed_duplicates = crud.deduplicate()
    assert removed_duplicates >= 1

    removed_filtered = crud.delete_by_filter(QueryOptions(page=1, page_size=100, family="Win.Generic"))
    assert removed_filtered >= 1

    assert crud.delete_sample(SHA1) is True
    assert crud.exists(SHA1) is False

    monkeypatch.delenv("MSA_OUTPUT_DIR", raising=False)
    get_settings.cache_clear()


def test_crud_merge_jsonl(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MSA_OUTPUT_DIR", str(tmp_path / "output"))
    get_settings.cache_clear()
    init_db()

    jsonl = tmp_path / "merge.jsonl"
    payloads = [
        _payload(SHA1, "m1.bin"),
        _payload(SHA2, "m2.bin"),
    ]
    jsonl.write_text("\n".join(json.dumps(item) for item in payloads), encoding="utf-8")

    crud = SampleCRUD()
    inserted, updated, skipped = crud.merge_jsonl(jsonl)
    assert inserted == 2
    assert updated == 0
    assert skipped == 0

    monkeypatch.delenv("MSA_OUTPUT_DIR", raising=False)
    get_settings.cache_clear()


def test_crud_merge_csv(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MSA_OUTPUT_DIR", str(tmp_path / "output"))
    get_settings.cache_clear()
    init_db()

    csv_path = tmp_path / "merge.csv"
    rows = [
        {
            "sha256": SHA1,
            "file_name": "from_csv_1.bin",
            "file_path": "/tmp/from_csv_1.bin",
            "file_size": "2048",
            "platform": "Windows",
            "source": "Local",
        },
        {
            "sha256": SHA2,
            "file_name": "from_csv_2.bin",
            "file_path": "/tmp/from_csv_2.bin",
            "file_size": "1024",
            "platform": "Android",
            "source": "MalwareBazaar",
        },
    ]

    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    crud = SampleCRUD()
    inserted, updated, skipped = crud.merge_csv(csv_path)
    assert inserted == 2
    assert updated == 0
    assert skipped == 0

    first = crud.get_by_sha256(SHA1)
    second = crud.get_by_sha256(SHA2)
    assert first is not None and first["file_name"] == "from_csv_1.bin"
    assert second is not None and second["platform"] == "Android"

    monkeypatch.delenv("MSA_OUTPUT_DIR", raising=False)
    get_settings.cache_clear()


def test_crud_merge_csv_large_field(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MSA_OUTPUT_DIR", str(tmp_path / "output"))
    get_settings.cache_clear()
    init_db()

    csv_path = tmp_path / "merge_large.csv"
    large_value = "A" * 200_000
    rows = [
        {
            "sha256": SHA1,
            "file_name": "large_field.bin",
            "file_path": "/tmp/large_field.bin",
            "file_size": "2048",
            "platform": "Windows",
            "source": "Local",
            "raw_json": json.dumps({"note": large_value}),
        }
    ]

    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    crud = SampleCRUD()
    inserted, updated, skipped = crud.merge_csv(csv_path)
    assert inserted == 1
    assert updated == 0
    assert skipped == 0

    sample = crud.get_by_sha256(SHA1)
    assert sample is not None
    assert sample["file_name"] == "large_field.bin"

    monkeypatch.delenv("MSA_OUTPUT_DIR", raising=False)
    get_settings.cache_clear()
