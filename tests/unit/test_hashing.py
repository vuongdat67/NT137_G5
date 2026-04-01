from __future__ import annotations

from pathlib import Path

from malware_analyzer.core import hashing
from malware_analyzer.core.hashing import hash_bytes, hash_file


def test_hash_file_deterministic(tmp_path: Path) -> None:
    sample = tmp_path / "same.bin"
    sample.write_bytes(b"abcdef" * 200)

    first = hash_file(sample)
    second = hash_file(sample)

    assert first.sha256 == second.sha256
    assert len(first.sha256) == 64
    assert len(first.sha512) == 128


def test_hash_bytes_basic() -> None:
    result = hash_bytes(b"hello")
    assert result.md5
    assert result.sha1
    assert result.sha256
    assert result.sha512


def test_hash_file_imphash_parsed_from_pe_import_directory(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 256)

    class _FakePE:
        def __init__(self, _path: str, fast_load: bool = True) -> None:
            self.fast_load = fast_load
            self.parsed = False

        def parse_data_directories(self, directories) -> None:
            self.parsed = bool(directories)

        def get_imphash(self) -> str:
            return "deadbeef"

        def close(self) -> None:
            return None

    class _FakePEModule:
        DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
        PE = _FakePE

    monkeypatch.setattr(hashing, "pefile", _FakePEModule)
    result = hash_file(sample)
    assert result.imphash == "deadbeef"
