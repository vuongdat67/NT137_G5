# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

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
