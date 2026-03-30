from __future__ import annotations

from pathlib import Path

from malware_analyzer.core import scanner
from malware_analyzer.core.scanner import scan_batch, scan_folder, scan_single


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


def test_scan_batch_progress_callback(tmp_path: Path) -> None:
    first = tmp_path / "a.bin"
    second = tmp_path / "b.bin"
    first.write_bytes(b"a" * 128)
    second.write_bytes(b"b" * 128)

    progress_events: list[tuple[int, int, str, str]] = []

    def _on_progress(done: int, total: int, path: Path, status: str) -> None:
        progress_events.append((done, total, path.name, status))

    results = scan_batch([first, second], workers=1, progress_callback=_on_progress)

    assert len(results) == 2
    assert [item[0] for item in progress_events] == [1, 2]
    assert all(item[1] == 2 for item in progress_events)
    assert all(item[3] == "scanned" for item in progress_events)


def test_scan_batch_error_isolation_per_file(tmp_path: Path, monkeypatch) -> None:
    good = tmp_path / "good.bin"
    bad = tmp_path / "bad.bin"
    good.write_bytes(b"g" * 128)
    bad.write_bytes(b"b" * 128)

    original_scan_single = scanner.scan_single

    def _flaky_scan(path: Path, **kwargs):
        if path.name == "bad.bin":
            raise RuntimeError("boom")
        return original_scan_single(path, **kwargs)

    monkeypatch.setattr(scanner, "scan_single", _flaky_scan)
    results = scan_batch([good, bad], workers=1)

    assert len(results) == 1
    assert results[0].file_info.file_name == "good.bin"


def test_scan_batch_resume_checkpoint(tmp_path: Path, monkeypatch) -> None:
    first = tmp_path / "a.bin"
    second = tmp_path / "b.bin"
    first.write_bytes(b"a" * 128)
    second.write_bytes(b"b" * 128)

    checkpoint_db = tmp_path / "scan_checkpoint.db"

    initial = scan_batch(
        [first, second],
        workers=1,
        resume_checkpoint=True,
        checkpoint_db_path=checkpoint_db,
    )
    assert len(initial) == 2

    def _should_not_scan(_: Path, **kwargs):
        raise AssertionError("scan_single should be skipped when checkpoint resume is active")

    monkeypatch.setattr(scanner, "scan_single", _should_not_scan)
    resumed = scan_batch(
        [first, second],
        workers=1,
        resume_checkpoint=True,
        checkpoint_db_path=checkpoint_db,
    )

    assert resumed == []
