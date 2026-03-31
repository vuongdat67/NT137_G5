from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger

from malware_analyzer.config.logging_setup import configure_logging
from malware_analyzer.core.identifier import identify
from malware_analyzer.core.models import FileType
from malware_analyzer.core.scanner import scan_batch

try:
    import psutil
except Exception:  # pragma: no cover - optional dependency
    psutil = None

PASSWORD_CANDIDATES: tuple[bytes | None, ...] = (b"infected", None)
SCENARIOS: tuple[int, ...] = (1000, 5000, 10000)


def _extract_seed_sample(zip_files: list[Path], scratch: Path) -> Path:
    preferred = {FileType.PE32, FileType.PE64, FileType.APK, FileType.DEX, FileType.ELF}
    generic_candidate: Path | None = None
    for archive_path in zip_files:
        try:
            with zipfile.ZipFile(archive_path) as archive:
                infos = [info for info in archive.infolist() if not info.is_dir()]
                infos.sort(key=lambda item: int(item.file_size or 0), reverse=True)
                for info in infos:
                    for password in PASSWORD_CANDIDATES:
                        try:
                            with archive.open(info, pwd=password) as source:
                                payload = source.read()
                        except Exception:
                            continue
                        if not payload:
                            continue

                        candidate = scratch / Path(info.filename).name
                        candidate.write_bytes(payload)
                        file_info = identify(candidate)
                        if file_info.file_type in preferred:
                            logger.info("Benchmark seed extracted: {} from {}", info.filename, archive_path.name)
                            return candidate
                        if generic_candidate is None:
                            generic_candidate = candidate
                            logger.info(
                                "Benchmark generic seed candidate found: {} from {} (type={})",
                                info.filename,
                                archive_path.name,
                                file_info.file_type.value,
                            )
        except Exception as exc:
            logger.warning("Failed to inspect archive {}: {}", archive_path, exc)
            continue

    if generic_candidate is not None:
        logger.warning("No preferred seed type found; using generic extracted seed: {}", generic_candidate.name)
        return generic_candidate

    fallback_executable = Path(sys.executable).resolve()
    if fallback_executable.exists() and fallback_executable.is_file():
        candidate = scratch / fallback_executable.name
        shutil.copy2(fallback_executable, candidate)
        logger.warning("No extractable members found; fallback seed from interpreter binary: {}", fallback_executable)
        return candidate

    raise RuntimeError("No extractable seed sample found in malware_samples ZIP archives")


def _prepare_dataset(seed_path: Path, dataset_dir: Path, count: int) -> list[Path]:
    dataset_dir.mkdir(parents=True, exist_ok=True)
    suffix = seed_path.suffix.lower() or ".bin"
    paths: list[Path] = []
    for index in range(1, count + 1):
        out_path = dataset_dir / f"sample_{index:05d}{suffix}"
        shutil.copy2(seed_path, out_path)
        paths.append(out_path)
    return paths


def _sampling_worker(stop_event: threading.Event, sample_every: float, bucket: dict[str, Any]) -> None:
    if psutil is None:
        return

    process = psutil.Process()
    process.cpu_percent(interval=None)
    psutil.cpu_percent(interval=None)

    process_cpu_samples: list[float] = []
    system_cpu_samples: list[float] = []
    iowait_samples: list[float] = []

    while not stop_event.is_set():
        time.sleep(sample_every)
        process_cpu_samples.append(float(process.cpu_percent(interval=None)))
        system_cpu_samples.append(float(psutil.cpu_percent(interval=None)))

        try:
            cpu_times = psutil.cpu_times_percent(interval=None)
            if hasattr(cpu_times, "iowait"):
                iowait_samples.append(float(getattr(cpu_times, "iowait", 0.0) or 0.0))
        except Exception:
            pass

    bucket["process_cpu_samples"] = process_cpu_samples
    bucket["system_cpu_samples"] = system_cpu_samples
    bucket["iowait_samples"] = iowait_samples


def _avg(values: list[float]) -> float:
    if not values:
        return 0.0
    return float(sum(values) / len(values))


def _run_one(paths: list[Path], workers: int, sample_every: float, show_progress: bool) -> dict[str, Any]:
    stop_event = threading.Event()
    sample_bucket: dict[str, Any] = {}

    disk_before = psutil.disk_io_counters() if psutil is not None else None
    cpu_time_before = time.process_time()

    sampler = threading.Thread(
        target=_sampling_worker,
        args=(stop_event, sample_every, sample_bucket),
        daemon=True,
    )
    sampler.start()

    started = time.perf_counter()
    results = scan_batch(paths, workers=workers, show_progress=show_progress)
    elapsed = max(0.001, time.perf_counter() - started)

    stop_event.set()
    sampler.join(timeout=2.0)

    cpu_time_after = time.process_time()
    disk_after = psutil.disk_io_counters() if psutil is not None else None

    throughput = len(results) / elapsed
    cpu_count = max(1, os.cpu_count() or 1)
    approx_process_cpu_pct = max(0.0, min(100.0, ((cpu_time_after - cpu_time_before) / elapsed / cpu_count) * 100.0))

    process_cpu_samples = sample_bucket.get("process_cpu_samples", []) or []
    system_cpu_samples = sample_bucket.get("system_cpu_samples", []) or []
    iowait_samples = sample_bucket.get("iowait_samples", []) or []

    read_bytes = 0
    write_bytes = 0
    if disk_before is not None and disk_after is not None:
        try:
            read_bytes = max(0, int(disk_after.read_bytes - disk_before.read_bytes))
            write_bytes = max(0, int(disk_after.write_bytes - disk_before.write_bytes))
        except Exception:
            read_bytes = 0
            write_bytes = 0

    return {
        "input_files": len(paths),
        "scanned_results": len(results),
        "workers": workers,
        "elapsed_seconds": round(elapsed, 3),
        "throughput_files_per_second": round(throughput, 3),
        "process_cpu_percent_avg": round(_avg(process_cpu_samples), 2),
        "system_cpu_percent_avg": round(_avg(system_cpu_samples), 2),
        "process_cpu_percent_estimated": round(approx_process_cpu_pct, 2),
        "io_wait_percent_avg": round(_avg(iowait_samples), 2) if iowait_samples else None,
        "disk_read_bytes": read_bytes,
        "disk_write_bytes": write_bytes,
        "disk_read_mb_per_second": round((read_bytes / (1024 * 1024)) / elapsed, 3),
        "disk_write_mb_per_second": round((write_bytes / (1024 * 1024)) / elapsed, 3),
        "notes": "io_wait_percent_avg may be null on platforms that do not expose iowait.",
    }


def _write_markdown_report(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Scan Benchmark Matrix",
        "",
        f"- Timestamp (UTC): {report.get('timestamp_utc', '')}",
        f"- Workers: {report.get('workers', 1)}",
        "",
        "| Scenario | Files | Elapsed (s) | Files/s | Proc CPU % (avg) | System CPU % (avg) | I/O wait % (avg) | Read MB/s | Write MB/s |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    scenarios = report.get("scenarios", {}) if isinstance(report.get("scenarios"), dict) else {}
    for label in ["1k", "5k", "10k"]:
        item = scenarios.get(label, {}) if isinstance(scenarios.get(label), dict) else {}
        iowait = item.get("io_wait_percent_avg")
        iowait_text = "N/A" if iowait is None else f"{float(iowait or 0):.2f}"
        lines.append(
            f"| {label} | {int(item.get('input_files', 0) or 0)} | {float(item.get('elapsed_seconds', 0) or 0):.3f} | "
            f"{float(item.get('throughput_files_per_second', 0) or 0):.3f} | "
            f"{float(item.get('process_cpu_percent_avg', 0) or 0):.2f} | "
            f"{float(item.get('system_cpu_percent_avg', 0) or 0):.2f} | "
            f"{iowait_text} | "
            f"{float(item.get('disk_read_mb_per_second', 0) or 0):.3f} | "
            f"{float(item.get('disk_write_mb_per_second', 0) or 0):.3f} |"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_matrix(workers: int, sample_every: float, show_progress: bool, malware_dir: Path | None = None) -> tuple[Path, Path]:
    configure_logging("benchmark")

    workspace_root = Path(__file__).resolve().parents[1]
    sample_dir = Path(malware_dir) if malware_dir and Path(malware_dir).exists() else workspace_root / "malware_samples"
    output_dir = workspace_root / "output" / "benchmarks"
    output_dir.mkdir(parents=True, exist_ok=True)

    zip_files = sorted(sample_dir.glob("*.zip"))
    if not zip_files:
        raise RuntimeError(f"No ZIP files found in: {sample_dir}")

    with tempfile.TemporaryDirectory(prefix="msa_bench_matrix_") as tmp:
        tmp_root = Path(tmp)
        seed = _extract_seed_sample(zip_files, tmp_root)
        dataset_paths = _prepare_dataset(seed, tmp_root / "dataset", max(SCENARIOS))

        scenarios: dict[str, dict[str, Any]] = {}
        for label, size in (("1k", 1000), ("5k", 5000), ("10k", 10000)):
            logger.info("Running benchmark scenario {} ({} files)", label, size)
            scenarios[label] = _run_one(
                dataset_paths[:size],
                workers=max(1, workers),
                sample_every=max(0.1, sample_every),
                show_progress=show_progress,
            )

    stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    report = {
        "benchmark": "scan_matrix_1k_5k_10k",
        "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
        "workers": max(1, workers),
        "scenarios": scenarios,
    }

    json_path = output_dir / f"scan_matrix_{stamp}.json"
    md_path = output_dir / f"scan_matrix_{stamp}.md"

    json_path.write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")
    _write_markdown_report(md_path, report)

    logger.info("Benchmark JSON report: {}", json_path)
    logger.info("Benchmark Markdown report: {}", md_path)
    return json_path, md_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run scan benchmark scenarios for 1k/5k/10k files.")
    parser.add_argument("--workers", type=int, default=4, help="Parallel scan workers.")
    parser.add_argument("--sample-every", type=float, default=0.5, help="System sampling interval in seconds.")
    parser.add_argument("--no-progress", action="store_true", help="Disable tqdm progress output.")
    parser.add_argument("--malware-dir", type=str, default=None, help="Override malware_samples directory.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    json_path, md_path = run_matrix(
        workers=max(1, int(args.workers)),
        sample_every=max(0.1, float(args.sample_every)),
        show_progress=not bool(args.no_progress),
        malware_dir=Path(args.malware_dir) if args.malware_dir else None,
    )
    print(json_path)
    print(md_path)


if __name__ == "__main__":
    main()
