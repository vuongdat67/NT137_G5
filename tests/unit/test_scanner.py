from __future__ import annotations

from pathlib import Path

from malware_analyzer.core.scanner import scan_folder, scan_single


def test_scan_single_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc123" * 100)

    result = scan_single(sample)

    assert result is not None
    assert result.file_info.file_name == "sample.bin"
    assert result.hash_result.sha256


def test_scan_folder_non_recursive(tmp_path: Path) -> None:
    first = tmp_path / "a.bin"
    second = tmp_path / "b.bin"
    nested_dir = tmp_path / "nested"
    nested_dir.mkdir()
    nested = nested_dir / "c.bin"

    first.write_bytes(b"a" * 128)
    second.write_bytes(b"b" * 128)
    nested.write_bytes(b"c" * 128)

    results = scan_folder(tmp_path, recursive=False, workers=1)
    names = sorted(item.file_info.file_name for item in results)

    assert names == ["a.bin", "b.bin"]


def test_scan_folder_recursive(tmp_path: Path) -> None:
    first = tmp_path / "a.bin"
    nested_dir = tmp_path / "nested"
    nested_dir.mkdir()
    nested = nested_dir / "c.bin"

    first.write_bytes(b"a" * 128)
    nested.write_bytes(b"c" * 128)

    results = scan_folder(tmp_path, recursive=True, workers=1)
    names = sorted(item.file_info.file_name for item in results)

    assert names == ["a.bin", "c.bin"]
