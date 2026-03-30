from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

from malware_analyzer.intelligence import watcher
from malware_analyzer.intelligence.watcher import DebouncedPathQueue, _filter_new_paths
from malware_analyzer.storage.repository import SampleRepository



def test_debounced_path_queue_waits_until_ready(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"content")

    queue = DebouncedPathQueue(debounce_seconds=1.0)
    queue.add(sample, now=0.0)

    assert queue.pop_ready(now=0.5) == []
    assert queue.pop_ready(now=1.2) == [sample]



def test_debounced_path_queue_ignores_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    queue = DebouncedPathQueue(debounce_seconds=1.0)
    queue.add(missing, now=0.0)

    assert queue.pop_ready(now=2.0) == []



def test_filter_new_paths_skips_existing_hashes(tmp_path: Path, monkeypatch) -> None:
    known = tmp_path / "known.bin"
    fresh = tmp_path / "fresh.bin"
    known.write_bytes(b"known")
    fresh.write_bytes(b"fresh")

    by_path = {
        str(known): "a" * 64,
        str(fresh): "b" * 64,
    }

    monkeypatch.setattr(
        watcher,
        "hash_file",
        lambda path: SimpleNamespace(sha256=by_path[str(path)]),
    )

    class _Repo:
        @staticmethod
        def has_sha256(sha256: str) -> bool:
            return sha256 == ("a" * 64)

    filtered = _filter_new_paths([known, fresh], cast(SampleRepository, _Repo()))
    assert filtered == [fresh]
