# Benchmark: Scan 1000 PE Samples

## Scope

- Goal: measure static scan throughput for 1000 PE samples.
- Input source: first PE extracted from one password-protected ZIP in `malware_samples/`.
- Dataset strategy: duplicate seed PE file to 1000 files in temp workspace.
- Scanner path: `scan_batch(..., workers=4)`.

## Command

```powershell
python scripts/benchmark_scan_1000_pe.py
```

## Latest Result

- Report file: `output/benchmarks/scan_1000_pe_20260330_013833.json`
- Elapsed: `15.527` seconds for `1000` files
- Throughput: `64.405 files/second`
- Workers: `4`
- Seed PE: fallback to local `python.exe` from active venv when ZIP set had no identifiable PE

## Notes

- This benchmark is static analysis only; samples are never executed.
- Re-run after major parser/enrichment changes and keep the latest JSON report in `output/benchmarks/`.
