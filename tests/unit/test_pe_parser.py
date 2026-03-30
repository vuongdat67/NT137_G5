from __future__ import annotations

from pathlib import Path

from malware_analyzer.core.models import FileInfo, FileType
from malware_analyzer.core.parsers.pe_parser import PEParser


def _pe_info() -> FileInfo:
    return FileInfo(
        file_path="dummy.exe",
        file_name="dummy.exe",
        file_size=2048,
        file_type=FileType.PE32,
        platform="Windows",
    )


def test_pe_parser_prefers_lief_primary(monkeypatch) -> None:
    parser = PEParser()
    calls = {"lief": 0, "pefile": 0}

    def fake_lief(self, path: Path, data: bytes) -> dict[str, object]:
        calls["lief"] += 1
        return {
            "api_imports": ["KERNEL32.dll!CreateFileA"],
            "pe_sections": [
                {
                    "name": ".text",
                    "virtual_size": 128,
                    "raw_size": 128,
                    "entropy": 5.0,
                    "writable": False,
                    "executable": True,
                }
            ],
        }

    def fake_pefile(self, path: Path, data: bytes) -> dict[str, object]:
        calls["pefile"] += 1
        return {"api_imports": ["SHOULD_NOT_BE_USED"]}

    monkeypatch.setattr("malware_analyzer.core.parsers.pe_parser.lief", object())
    monkeypatch.setattr("malware_analyzer.core.parsers.pe_parser.pefile", object())
    monkeypatch.setattr(PEParser, "_parse_with_lief", fake_lief)
    monkeypatch.setattr(PEParser, "_parse_with_pefile", fake_pefile)

    parsed = parser.parse(Path("dummy.exe"), _pe_info(), b"TEST")

    assert calls["lief"] == 1
    assert calls["pefile"] == 0
    assert parsed.get("pe_parser_backend") == "lief"
    assert parsed.get("api_imports") == ["KERNEL32.dll!CreateFileA"]


def test_pe_parser_fallbacks_to_pefile_when_lief_fails(monkeypatch) -> None:
    parser = PEParser()
    calls = {"lief": 0, "pefile": 0}

    def fake_lief(self, path: Path, data: bytes) -> dict[str, object]:
        calls["lief"] += 1
        return {}

    def fake_pefile(self, path: Path, data: bytes) -> dict[str, object]:
        calls["pefile"] += 1
        return {
            "api_imports": ["KERNEL32.dll!VirtualProtect"],
            "pe_sections": [
                {
                    "name": ".text",
                    "virtual_size": 256,
                    "raw_size": 256,
                    "entropy": 6.0,
                    "writable": True,
                    "executable": True,
                }
            ],
        }

    monkeypatch.setattr("malware_analyzer.core.parsers.pe_parser.lief", object())
    monkeypatch.setattr("malware_analyzer.core.parsers.pe_parser.pefile", object())
    monkeypatch.setattr(PEParser, "_parse_with_lief", fake_lief)
    monkeypatch.setattr(PEParser, "_parse_with_pefile", fake_pefile)

    parsed = parser.parse(Path("dummy.exe"), _pe_info(), b"ABCD")

    assert calls["lief"] == 1
    assert calls["pefile"] == 1
    assert parsed.get("pe_parser_backend") == "pefile"


def test_pe_parser_extracts_strings_and_self_modifying_hints(monkeypatch) -> None:
    parser = PEParser()

    def fake_lief(self, path: Path, data: bytes) -> dict[str, object]:
        return {
            "api_imports": ["KERNEL32.dll!VirtualProtect", "KERNEL32.dll!GetProcAddress"],
            "pe_sections": [
                {
                    "name": ".text",
                    "virtual_size": 512,
                    "raw_size": 512,
                    "entropy": 6.2,
                    "writable": True,
                    "executable": True,
                }
            ],
        }

    monkeypatch.setattr("malware_analyzer.core.parsers.pe_parser.lief", object())
    monkeypatch.setattr("malware_analyzer.core.parsers.pe_parser.pefile", None)
    monkeypatch.setattr(PEParser, "_parse_with_lief", fake_lief)

    data = b"HELLO_WORLD\x00P\x00O\x00W\x00E\x00R\x00"
    parsed = parser.parse(Path("dummy.exe"), _pe_info(), data)

    assert parsed.get("pe_parser_backend") == "lief"
    raw_strings = parsed.get("pe_strings", [])
    strings = [str(item) for item in raw_strings] if isinstance(raw_strings, list) else []
    assert any("HELLO_WORLD" in item for item in strings)
    assert any("POWER" in item for item in strings)
    assert bool(parsed.get("pe_self_modifying_suspected")) is True
    raw_indicators = parsed.get("pe_self_modifying_indicators", [])
    indicators = [str(item) for item in raw_indicators] if isinstance(raw_indicators, list) else []
    assert any("import:virtualprotect" in item for item in indicators)
    assert any("wx-section:.text" in item for item in indicators)

    behaviors = parsed.get("pe_self_modifying_behaviors", [])
    assert isinstance(behaviors, list)
    assert any("in_process_code_rewrite" in str(item) for item in behaviors)
    assert str(parsed.get("pe_self_modifying_confidence", "")).lower() in {"low", "medium", "high"}
    assert float(parsed.get("pe_self_modifying_score", 0) or 0) > 0
