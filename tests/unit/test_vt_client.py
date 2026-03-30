from __future__ import annotations

import httpx

from malware_analyzer.intelligence import vt_client
from malware_analyzer.intelligence.vt_client import VirusTotalClient


class _FakeResponse:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> object:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://www.virustotal.com/api/v3/files/test")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("request failed", request=request, response=response)


class _FakeClient:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response
        self.calls: list[str] = []

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def get(self, url: str) -> _FakeResponse:
        self.calls.append(url)
        return self._response



def test_vt_get_report_success(monkeypatch) -> None:
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "harmless": 10,
                    "undetected": 3,
                }
            }
        }
    }
    fake_client = _FakeClient(_FakeResponse(200, payload))

    monkeypatch.setenv("MSA_VT_API_KEY", "demo")
    monkeypatch.setattr(vt_client.httpx, "Client", lambda *args, **kwargs: fake_client)

    client = VirusTotalClient()
    report = client.get_report("a" * 64)

    assert report == payload
    assert client.last_error == ""
    assert len(fake_client.calls) == 1



def test_vt_get_report_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("MSA_VT_API_KEY", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    client = VirusTotalClient()
    report = client.get_report("a" * 64)

    assert report is None
    assert "missing" in client.last_error.lower()



def test_vt_get_family_and_detection_ratio(monkeypatch) -> None:
    payload = {
        "data": {
            "attributes": {
                "popular_threat_classification": {
                    "suggested_threat_label": "trojan.redline"
                },
                "last_analysis_stats": {
                    "malicious": 7,
                    "suspicious": 1,
                    "harmless": 11,
                    "undetected": 9,
                    "timeout": 2,
                },
            }
        }
    }

    client = VirusTotalClient()
    monkeypatch.setattr(client, "get_report", lambda *args, **kwargs: payload)

    family = client.get_family("b" * 64)
    detected, total = client.get_detection_ratio("b" * 64)

    assert family == "trojan.redline"
    assert detected == 8
    assert total == 30



def test_vt_rate_limit_matches_free_tier() -> None:
    client = VirusTotalClient()
    assert client._min_interval_seconds == 15.0
