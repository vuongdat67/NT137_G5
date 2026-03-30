from __future__ import annotations

import json
import shutil
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

from malware_analyzer.config.logging_setup import configure_logging
from malware_analyzer.core.identifier import identify
from malware_analyzer.core.models import FileType
from malware_analyzer.core.scanner import scan_batch

PASSWORD_CANDIDATES: tuple[bytes | None, ...] = (b"infected", None)
TARGET_FILES = 1000


def _extract_first_pe(zip_files: list[Path], scratch: Path) -> Path:
    for archive_path in zip_files:
        try:
            with zipfile.ZipFile(archive_path) as archive:
                infos = [info for info in archive.infolist() if not info.is_dir()]
                for info in infos:
                    for password in PASSWORD_CANDIDATES:
                        try:
                            with archive.open(info, pwd=password) as source:
                                candidate = scratch / Path(info.filename).name
                                candidate.write_bytes(source.read())
                            file_info = identify(candidate)
                            if file_info.file_type in {FileType.PE32, FileType.PE64}:
                                logger.info("Benchmark seed extracted: {} from {}", info.filename, archive_path)
                                return candidate
                        except Exception:
                            continue
        except Exception as exc:
            logger.warning("Failed to inspect archive {}: {}", archive_path, exc)
            continue
    fallback = Path(sys.executable).resolve()
    info = identify(fallback)
    if info.file_type in {FileType.PE32, FileType.PE64}:
        candidate = scratch / fallback.name
        shutil.copy2(fallback, candidate)
        logger.warning("No PE found in ZIP set. Fallback seed: {}", fallback)
        return candidate

    raise RuntimeError("No PE sample found in malware_samples ZIP archives and no PE fallback available")


def _prepare_dataset(seed_path: Path, dataset_dir: Path, count: int) -> list[Path]:
    dataset_dir.mkdir(parents=True, exist_ok=True)
    suffix = seed_path.suffix.lower() or ".bin"
    paths: list[Path] = []
    for index in range(1, count + 1):
        out_path = dataset_dir / f"sample_{index:04d}{suffix}"
        shutil.copy2(seed_path, out_path)
        paths.append(out_path)
    return paths


def run_benchmark() -> Path:
    configure_logging("benchmark")

    workspace_root = Path(__file__).resolve().parents[1]
    sample_dir = workspace_root / "malware_samples"
    output_dir = workspace_root / "output" / "benchmarks"
    output_dir.mkdir(parents=True, exist_ok=True)

    zip_files = sorted(sample_dir.glob("*.zip"))
    if not zip_files:
        raise RuntimeError(f"No ZIP files found in: {sample_dir}")

    with tempfile.TemporaryDirectory(prefix="msa_bench_") as tmp:
        tmp_root = Path(tmp)
        seed = _extract_first_pe(zip_files, tmp_root)
        dataset_paths = _prepare_dataset(seed, tmp_root / "dataset", TARGET_FILES)

        workers = 4
        started = time.perf_counter()
        results = scan_batch(dataset_paths, workers=workers, show_progress=True)
        elapsed = max(0.001, time.perf_counter() - started)

    throughput = len(results) / elapsed
    report = {
        "benchmark": "scan_1000_pe",
        "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
        "input_files": TARGET_FILES,
        "scanned_results": len(results),
        "workers": workers,
        "elapsed_seconds": round(elapsed, 3),
        "throughput_files_per_second": round(throughput, 3),
    }

    stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"scan_1000_pe_{stamp}.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    logger.info("Benchmark report written: {}", report_path)
    return report_path


if __name__ == "__main__":
    path = run_benchmark()
    print(path)
