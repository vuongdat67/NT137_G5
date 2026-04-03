# Packaging and Distribution

## Targets

- Build Windows distributable with PyInstaller.
- Build Linux distributable with PyInstaller.
- Bundle required runtime assets:
  - `rules/`
  - `malware_analyzer/config/`
  - `malware_analyzer/reports/templates/`
  - `malware_analyzer/gui/assets/`
- Bundle Qt plugins.
- Bundle Windows `libmagic.dll` if available.

## Files Added for Packaging

- `malware_analyzer.spec`
- `scripts/smoke_packaged_app.py`
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`

## Build Commands

From `code/` directory:

```powershell
make build-windows
make bundle-smoke
```

On Linux host:

```bash
make build-linux
python scripts/smoke_packaged_app.py
```

## Windows libmagic Notes

- `python-magic` requires a native libmagic DLL on Windows.
- This project now installs `python-magic-bin` on Windows and attempts to bundle:
  - `libmagic.dll`
  - `magic1.dll`
- `malware_analyzer.spec` auto-discovers these DLLs from common venv/runtime paths.

## Cross-platform Check

- GitHub Actions workflow: `.github/workflows/ci.yml`
- Matrix: `windows-latest`, `ubuntu-latest`, `macos-latest`
- Steps: install system deps, install Python deps, run targeted tests, run CLI smoke, build PyInstaller bundle, run packaged smoke test.

## Release Build

- GitHub Actions workflow: `.github/workflows/release.yml`
- Trigger: manual (`workflow_dispatch`) or Git tag (`v*`)
- Output: platform binaries + bundled archives + one all-in-one zip artifact

## Fresh VM Installer Checklist

Use a clean VM (no source repo, no Python preinstalled unless needed by policy):

1. Copy `dist/malware_analyzer` from build machine to VM.
2. Launch bundled executable with `--help`.
3. Launch GUI with `gui` command and verify tabs open.
4. Run one test scan on benign sample.
5. Verify report export (HTML/PDF) works.
6. Verify logs are written under `output/logs`.

## Current Validation Status

- Windows local build: done (`PyInstaller` build completed on 2026-03-30)
- Windows packaged smoke test: done (`malware_analyzer.exe --help` passed)
- Linux build: automated via `.github/workflows/ci.yml`
- Fresh VM installer test: pending manual run
