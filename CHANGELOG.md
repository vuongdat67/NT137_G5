# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- PyInstaller spec file `malware_analyzer.spec`
- Packaging smoke script `scripts/smoke_packaged_app.py`
- Packaging guide `docs/packaging.md`
- Cross-platform CI packaging workflow `.github/workflows/phase10-cross-platform.yml`
- Explorer migrated to `QTableView` + `SampleTableModel` with paginated data binding
- Scan worker migrated to `QRunnable` + `QThreadPool` to keep UI responsive
- Central logging bootstrap (`config/logging_setup.py`) with console + rotating file sink
- Global uncaught exception logging hooks for process/thread contexts
- API global exception handler for server-side error logging
- Security marker file `malware_samples/.noexec`
- Benchmark script `scripts/benchmark_scan_1000_pe.py`
- GUI screenshot helper `scripts/capture_gui_screenshot.py`
- Benchmark documentation `docs/benchmark-scan-1000-pe.md`
- Explorer bulk actions: flag selected and remove selected rows
- Explorer export actions: filtered/selected JSONL and CSV
- Report dataset exports with scope options
- Dataset total indicator in report view
- Intel schedule controls with active timer wiring
- Intel auto-scan propagation path for downloaded ZIP files
- Lightweight opcode unigram profile enrichment
- API import extraction for PE samples
- Additional packer signature hints: MPRESS, ASPACK, PETITE
- Documentation set under `docs/` and project README
- Repository hygiene files: `.gitattributes`

### Changed

- Makefile expanded with `build-windows`, `build-linux`, and `bundle-smoke` targets
- Added Windows marker dependency `python-magic-bin` and locked `pyinstaller`
- Pinned `pefile` to `2023.2.7` to resolve PyInstaller dependency conflict
- GUI stylesheet switched to dark high-contrast palette
- README expanded with CLI reference, screenshot section, benchmark guidance
- Toolbar labels clarified: Open Files, Queue Folder, Fetch Intel
- Intel fetch logs now include attempted/success/failed ZIP summary
- Intel apply messaging now distinguishes not-in-local-DB cases
- ZIP downloader handles binary payloads safely before JSON parsing

### Fixed

- ZIP cleanup robustness on Windows temporary directories
- Intel download UTF-8 decode crash when payload is ZIP data
- Intel view syntax regression from malformed patch insertion
- Reduced parser warning noise in GUI logs for malformed import tables

## [2026-03-27]

- Stabilization and usability improvements across Scan/Explorer/Report/Intel tabs.
