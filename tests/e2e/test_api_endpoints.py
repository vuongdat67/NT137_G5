from __future__ import annotations

import time
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from malware_analyzer.api.main import app


client = TestClient(app)


def test_api_health_and_stats_shape() -> None:
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json().get("status") == "ok"

    stats = client.get("/api/stats")
    assert stats.status_code == 200
    payload = stats.json()
    assert "total" in payload
    assert "source" in payload
    assert "platform" in payload



def test_api_scan_file_and_sample_lifecycle(tmp_path: Path) -> None:
    sample = tmp_path / "api-scan.bin"
    sample.write_bytes(uuid.uuid4().hex.encode("ascii") + b"_payload")

    scanned = client.post("/api/scan/file", json={"path": str(sample)})
    assert scanned.status_code == 200
    body = scanned.json()
    assert "sha256" in body
    sha256 = str(body["sha256"])
    assert len(sha256) == 64

    detail = client.get(f"/api/samples/{sha256}")
    assert detail.status_code == 200

    patched = client.patch(
        f"/api/samples/{sha256}",
        json={"tags": "api,e2e", "family": "Test.E2E", "family_confidence": "high"},
    )
    assert patched.status_code == 200
    assert patched.json().get("updated") is True

    exported = client.get("/api/samples/export?format=jsonl")
    assert exported.status_code == 200
    assert exported.json().get("format") == "jsonl"

    deleted = client.delete(f"/api/samples/{sha256}")
    assert deleted.status_code == 200
    assert int(deleted.json().get("deleted", 0)) >= 1



def test_api_scan_batch_job_flow(tmp_path: Path) -> None:
    files = []
    for index in range(2):
        path = tmp_path / f"batch-{index}.bin"
        path.write_bytes(f"batch-{index}-{uuid.uuid4().hex}".encode("ascii"))
        files.append(str(path))

    queued = client.post("/api/scan/batch", json={"paths": files, "workers": 1, "skip_duplicates": False})
    assert queued.status_code == 200
    job_id = queued.json()["job_id"]

    final_payload: dict[str, object] = {}
    for _ in range(80):
        status = client.get(f"/api/scan/jobs/{job_id}?recent_offset=0&recent_limit=10")
        assert status.status_code == 200
        final_payload = status.json()
        if final_payload.get("status") in {"completed", "failed", "cancelled"}:
            break
        time.sleep(0.05)

    assert final_payload.get("queued") == 2
    assert int(str(final_payload.get("processed", 0) or 0)) >= 2
    assert final_payload.get("status") == "completed"



def test_api_intel_routes_with_monkeypatched_client(monkeypatch) -> None:
    fake_entry = {
        "sha256_hash": "f" * 64,
        "signature": "Test.Family",
        "tags": ["banker", "stealer"],
    }

    def _fake_query(self, query, api_key=None):
        return [fake_entry]

    monkeypatch.setattr("malware_analyzer.api.routes.intelligence.BazaarClient.query", _fake_query)

    fetched = client.post(
        "/api/intel/fetch",
        json={"mode": "By Tag", "value": "exe", "limit": 1, "api_key": "", "apply_to_db": False},
    )
    assert fetched.status_code == 200
    assert fetched.json().get("fetched") == 1

    by_hash = client.post("/api/intel/fetch/" + ("f" * 64) + "?apply_to_db=false")
    assert by_hash.status_code == 200
    assert by_hash.json().get("fetched") == 1
