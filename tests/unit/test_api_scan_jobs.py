from __future__ import annotations

from fastapi.testclient import TestClient

from malware_analyzer.api.main import _scan_jobs, _scan_jobs_lock, app


client = TestClient(app)


def test_scan_job_status_recent_files_pagination() -> None:
    job_id = "job-pagination-test"
    recent_files = [
        {
            "path": f"C:/samples/file_{index}.bin",
            "status": "scanned",
            "sha256": f"hash_{index}",
            "error": "",
        }
        for index in range(120)
    ]

    with _scan_jobs_lock:
        _scan_jobs[job_id] = {
            "job_id": job_id,
            "status": "running",
            "queued": 120,
            "processed": 42,
            "scanned": 40,
            "skipped": 1,
            "failed": 1,
            "current_file": "C:/samples/file_42.bin",
            "cancel_requested": False,
            "recent_files": recent_files,
            "errors": [],
        }

    try:
        response = client.get(f"/api/scan/jobs/{job_id}?recent_offset=10&recent_limit=15")
        assert response.status_code == 200
        payload = response.json()

        assert payload["job_id"] == job_id
        assert payload["recent_files_total"] == 120
        assert payload["recent_files_offset"] == 10
        assert payload["recent_files_limit"] == 15
        assert payload["recent_files_has_more"] is True
        assert len(payload["recent_files"]) == 15
        assert payload["recent_files"][0]["path"].endswith("file_10.bin")
    finally:
        with _scan_jobs_lock:
            _scan_jobs.pop(job_id, None)
