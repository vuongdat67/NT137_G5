from __future__ import annotations

from pathlib import Path

from malware_analyzer.core.hashing import hash_bytes, hash_file


def test_hash_file_deterministic(tmp_path: Path) -> None:
    sample = tmp_path / "same.bin"
    sample.write_bytes(b"abcdef" * 200)

    first = hash_file(sample)
    second = hash_file(sample)

    assert first.sha256 == second.sha256
    assert len(first.sha256) == 64


def test_hash_bytes_basic() -> None:
    result = hash_bytes(b"hello")
    assert result.md5
    assert result.sha1
    assert result.sha256
