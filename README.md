# Malware Static Analyzer (Windows + Android)

A Python desktop tool for static malware analysis, feature extraction, local dataset building, and Intel-assisted sample ingestion.

## Key Features

- Static scan for PE/APK/ELF-like binaries
- Hashing: MD5/SHA1/SHA256/TLSH/ssdeep/imphash (when available)
- String extraction, URL/IP extraction
- Lightweight CFG metrics: nodes/edges/cyclomatic
- Opcode profile and API import extraction
- Packer hints (UPX/MPRESS/ASPACK/PETITE/high entropy)
- Intel fetch from MalwareBazaar
- Download malware ZIP samples and optional auto-scan
- Explorer filtering, bulk flag/remove, and dataset export
- Report tab with sample detail and dataset export scopes
- Dark high-contrast GUI theme for long triage sessions
- Centralized logging to console and rotating file logs

## Project Layout

- `main.py`: CLI entrypoint and GUI launcher
- `malware_analyzer/`: main package
- `scripts/`: helper scripts (benchmark and screenshot capture)
- `tests/`: unit/integration/e2e test skeleton
- `output/`: runtime outputs (DB and generated artifacts)
- `malware_samples/`: default downloaded sample folder

## Requirements

- Python 3.11+
- Git
- OS-specific runtime packages:
  - Windows: no extra system package required
  - Ubuntu/Debian: Qt/XCB and libmagic packages (see below)
  - macOS: Homebrew packages `libmagic` and `libomp`

## Quick Start (3 OS)

### Windows (PowerShell)

1. Create and activate virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install Python dependencies

```powershell
pip install --upgrade wheel setuptools
pip install -e ".[dev,packaging]"
```

### Ubuntu / Debian

1. Install system packages

```bash
sudo apt update
sudo apt install python3.11 python3.11-venv python3.11-dev \
  libxcb-cursor0 libxkbcommon-x11-0 libxcb-icccm4 libxcb-image0 \
  libxcb-keysyms1 libxcb-render-util0 libxcb-xinerama0 libxcb-xinput0 \
  libxcb-shape0 libmagic1 libmagic-dev -y
```

2. Create and activate virtual environment

```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

3. Install Python dependencies

```bash
pip install --upgrade wheel setuptools
pip install -e ".[dev,packaging]"
```

### macOS

1. Install system packages

```bash
brew update
brew install libmagic libomp
```

2. Create and activate virtual environment

```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

3. Install Python dependencies

```bash
pip install --upgrade wheel setuptools
pip install -e ".[dev,packaging]"
```

### Verify installation

```bash
python main.py --help
pytest -q
```

### Launch GUI

```bash
python main.py gui
```

## CLI Reference

Main commands:

- `python main.py scan <path> [--recursive] [--workers N] [--format json|csv|both] [--yara <dir>] [--no-heuristic] [--watch]`
- `python main.py gui`
- `python main.py serve --host 127.0.0.1 --port 8000`
- `python main.py db stats|list|show|delete|export|import|tag|dedupe|rescore|recluster`
- `python main.py intel fetch --mode "By Tag" --value exe --limit 100`
- `python main.py report <sha256> --format html|pdf`
- `python main.py watch <folder> --recursive`
- `python main.py ml train --input-csv output/phase11_features.csv --production-preset`
- `python main.py ml train-security-gate --input-csv output/phase11_features.csv --threshold-recall-target 0.95`
- `python main.py ml backfill-security-gate --model-path models/security_gate.joblib --platform All --source All`

Production note for family model:

- For production-oriented family attribution, use `--production-preset` to enforce stronger class-balance defaults.
- The preset keeps your explicit values if stricter, but raises weak settings to safer minimums (min class samples >= 10, and max class samples = 300 when uncapped).

DB import accepts both JSONL and CSV datasets:

- `python main.py db import dataset.jsonl`
- `python main.py db import dataset.csv`
- `python main.py db import dataset.any --format jsonl|csv`

Use `--help` for command details:

```powershell
python main.py --help
python main.py scan --help
python main.py db --help
```

## GUI Screenshot

![GUI Scan Tab](docs/images/gui-scan.png)

To regenerate screenshot locally:

```powershell
python scripts/capture_gui_screenshot.py
```

## Intel Download + Auto-Scan Workflow

1. Open `Intel` tab
2. Set filter, for example `Keyword Syntax` + `file_type:apk`
3. Enable `Download samples ZIP`
4. Optionally enable `Auto-scan after download`
5. Click `Fetch Now`

Notes:

- Downloaded ZIP files are password-protected archives from MalwareBazaar.
- Intel metadata can only be applied to rows that already exist in local DB.
- If entries are not in local DB yet, scan them first (or enable auto-scan).

## Dataset Export Workflow

- In `Explorer`:
  - Export Filtered JSONL/CSV
  - Export Selected JSONL/CSV
- In `Report`:
  - Save Dataset JSONL/CSV with scope:
    - All Samples
    - Windows Only
    - Android Only
    - Source Local
    - Source MalwareBazaar
    - Current Family

## Security and Safety

- Static analysis only; no sample execution.
- Keep malware archives in isolated folders.
- Do not upload live samples to public systems.
- Review `malware_samples/.noexec` before handling downloaded artifacts.

## Benchmark

- Script: `scripts/benchmark_scan_1000_pe.py`
- Output: `output/benchmarks/scan_1000_pe_*.json`
- Report: `docs/benchmark-scan-1000-pe.md`

## Documentation

See the `docs/` folder:

- `docs/setup-env.md`
- `docs/user-guide.md`
- `docs/intel-and-dataset.md`
- `docs/troubleshooting.md`
- `docs/packaging.md`
- `docs/benchmark-scan-1000-pe.md`

## Packaging and Distribution

CI and release pipelines are in:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`

For full packaging details and fresh VM validation checklist, see `docs/packaging.md`.

## License

This project includes a `LICENSE` file in the repository root.
