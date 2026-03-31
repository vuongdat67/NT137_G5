# Scan Benchmark Matrix (1k/5k/10k)

This benchmark runs three official scenarios to measure scanner performance:

- 1k files
- 5k files
- 10k files

Metrics captured per scenario:

- `throughput_files_per_second`
- `process_cpu_percent_avg`
- `system_cpu_percent_avg`
- `io_wait_percent_avg` (when the OS exposes iowait)
- `disk_read_mb_per_second`
- `disk_write_mb_per_second`

## Run

```bash
python scripts/benchmark_scan_matrix.py --workers 4
```

Optional flags:

```bash
python scripts/benchmark_scan_matrix.py --workers 6 --sample-every 0.5 --no-progress
```

## Outputs

Reports are written to `output/benchmarks/`:

- `scan_matrix_<timestamp>.json`
- `scan_matrix_<timestamp>.md`

The Markdown file contains a single comparison table for 1k/5k/10k scenarios.

## Notes

- The script builds synthetic benchmark sets by copying one extracted seed sample to the required counts.
- On platforms where iowait is not exposed (common on Windows), `io_wait_percent_avg` is `null` in JSON and `N/A` in Markdown.
