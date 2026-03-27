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

## Project Layout

- `main.py`: CLI entrypoint and GUI launcher
- `malware_analyzer/`: main package
- `tests/`: unit/integration/e2e test skeleton
- `output/`: runtime outputs (DB and generated artifacts)
- `malware_samples/`: default downloaded sample folder

## Requirements

- Python 3.11+
- Windows PowerShell or compatible shell

## Quick Start

1. Create virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies

```powershell
pip install -r requirements.txt
pip install -e .
```

3. Launch GUI

```powershell
python main.py gui
```

4. Run tests

```powershell
pytest -q
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

## Documentation

See the `docs/` folder:

- `docs/setup-env.md`
- `docs/user-guide.md`
- `docs/intel-and-dataset.md`
- `docs/troubleshooting.md`

## License

This project includes a `LICENSE` file in the repository root.
