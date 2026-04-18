from __future__ import annotations

from pathlib import Path

from malware_analyzer.core.enrichment import TOP_OPCODES, _build_dex_cfg_androguard, build_enrichment
from malware_analyzer.core.identifier import identify


def test_enrichment_classifies_strings_and_base64(tmp_path: Path) -> None:
    payload = (
        b"http://example.org/gate.php\x00"
        b"185.220.101.45\x00"
        b"HKEY_LOCAL_MACHINE\\SOFTWARE\\evil\x00"
        b"Global\\RansomMutex_2026\x00"
        b"U0dWc2JHOGdWMjl5YkdRPQ==\x00"
    )
    sample = tmp_path / "strings.bin"
    sample.write_bytes(payload)

    file_info = identify(sample)
    features = build_enrichment(sample, file_info)

    assert any("example.org" in item for item in features.get("strings_url", []))
    assert "185.220.101.45" in features.get("strings_ip", [])
    assert any("HKEY_LOCAL_MACHINE" in item for item in features.get("strings_registry", []))
    assert any("Global\\RansomMutex_2026" in item for item in features.get("strings_mutex", []))
    assert int(features.get("strings_b64_count", 0)) >= 1


def test_enrichment_includes_parser_prefixed_fields(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ\x90\x00dummy")

    file_info = identify(sample)

    monkeypatch.setattr(
        "malware_analyzer.core.enrichment.parse_file",
        lambda path, info, data: {
            "api_imports": ["KERNEL32.dll!CreateFileA"],
            "pe_exports": ["ExportedFunc"],
            "pe_sections_count": 3,
            "apk_permissions_count": 0,
        },
    )
    monkeypatch.setattr("malware_analyzer.core.enrichment.yara_scan_file", lambda path, **kwargs: [])
    monkeypatch.setattr("malware_analyzer.core.enrichment.yara_scan_bytes", lambda data, **kwargs: [])

    features = build_enrichment(sample, file_info)

    assert features.get("pe_exports") == ["ExportedFunc"]
    assert int(features.get("pe_sections_count", 0)) == 3
    assert int(features.get("apk_permissions_count", 0)) == 0


# ---------------------------------------------------------------------------
# Normalized CFG features
# ---------------------------------------------------------------------------

def test_enrichment_normalized_cfg_features_present(tmp_path: Path, monkeypatch) -> None:
    """Normalized CFG keys are always present in build_enrichment() output."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"X" * 4096)

    file_info = identify(sample)
    monkeypatch.setattr("malware_analyzer.core.enrichment.yara_scan_file", lambda path, **kw: [])
    monkeypatch.setattr("malware_analyzer.core.enrichment.yara_scan_bytes", lambda data, **kw: [])

    features = build_enrichment(sample, file_info)

    for key in ("cfg_nodes_per_kb", "cfg_cyclomatic_per_kb", "cfg_loop_density", "cfg_edge_density"):
        assert key in features, f"Missing normalized CFG feature: {key}"
        assert isinstance(features[key], float)


def test_enrichment_normalized_cfg_values_scale_with_file_size(tmp_path: Path, monkeypatch) -> None:
    """cfg_nodes_per_kb should differ between a small and large file given same CFG."""
    def _fake_cfg(*args, **kwargs):
        return {"nodes": 10, "edges": 12, "cyclomatic": 4, "graph_edges": [], "source": "estimated", "estimated": True}

    monkeypatch.setattr("malware_analyzer.core.enrichment._estimate_cfg", _fake_cfg)
    monkeypatch.setattr("malware_analyzer.core.enrichment.yara_scan_file", lambda path, **kw: [])
    monkeypatch.setattr("malware_analyzer.core.enrichment.yara_scan_bytes", lambda data, **kw: [])

    small = tmp_path / "small.bin"
    small.write_bytes(b"X" * 1024)  # 1 KB
    large = tmp_path / "large.bin"
    large.write_bytes(b"X" * 102400)  # 100 KB

    feat_small = build_enrichment(small, identify(small))
    feat_large = build_enrichment(large, identify(large))

    assert float(feat_small["cfg_nodes_per_kb"]) > float(feat_large["cfg_nodes_per_kb"])


# ---------------------------------------------------------------------------
# Opcode ML features
# ---------------------------------------------------------------------------

def test_enrichment_opcode_features_present(tmp_path: Path, monkeypatch) -> None:
    """op_* keys for all TOP_OPCODES appear in build_enrichment() output as ints."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"dummy" * 100)

    file_info = identify(sample)
    monkeypatch.setattr("malware_analyzer.core.enrichment.yara_scan_file", lambda path, **kw: [])
    monkeypatch.setattr("malware_analyzer.core.enrichment.yara_scan_bytes", lambda data, **kw: [])

    features = build_enrichment(sample, file_info)

    for op in TOP_OPCODES:
        key = f"op_{op}"
        assert key in features, f"Missing opcode feature: {key}"
        assert isinstance(features[key], int), f"{key} must be int, got {type(features[key])}"


def test_enrichment_opcode_features_non_negative(tmp_path: Path, monkeypatch) -> None:
    """All op_* values are >= 0."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x55\x89\xe5\x83\xec\x10" * 50)  # prologue-like bytes

    monkeypatch.setattr("malware_analyzer.core.enrichment.yara_scan_file", lambda path, **kw: [])
    monkeypatch.setattr("malware_analyzer.core.enrichment.yara_scan_bytes", lambda data, **kw: [])

    features = build_enrichment(sample, identify(sample))

    for op in TOP_OPCODES:
        assert int(features[f"op_{op}"]) >= 0


# ---------------------------------------------------------------------------
# DEX CFG via Androguard
# ---------------------------------------------------------------------------

def test_dex_cfg_androguard_returns_none_when_unavailable(monkeypatch, tmp_path: Path) -> None:
    """Returns None gracefully when Androguard is not installed."""
    monkeypatch.setattr("malware_analyzer.core.enrichment._AnalyzeAPK", None)
    result = _build_dex_cfg_androguard(tmp_path / "dummy.apk")
    assert result is None


def test_dex_cfg_androguard_returns_valid_structure(monkeypatch, tmp_path: Path) -> None:
    """When Androguard succeeds, returns a dict with nodes/edges/cyclomatic."""

    class _FakeBlock:
        childs = [[None, None, None], [None, None, None]]

    class _FakeMethod:
        def get_basic_blocks(self):
            return [_FakeBlock(), _FakeBlock(), _FakeBlock()]

    class _FakeDx:
        def get_methods(self):
            return [_FakeMethod(), _FakeMethod()]

    def _fake_analyze(path: str):
        return None, None, _FakeDx()

    monkeypatch.setattr("malware_analyzer.core.enrichment._AnalyzeAPK", _fake_analyze)

    result = _build_dex_cfg_androguard(tmp_path / "dummy.apk")

    assert result is not None
    assert result["nodes"] > 0
    assert result["source"] == "androguard-dex"
    assert result["estimated"] is False
    assert isinstance(result["graph_edges"], list)
