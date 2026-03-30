from __future__ import annotations

from pathlib import Path
import platform
import subprocess
import sys


def _resolve_binary() -> Path:
    root = Path(__file__).resolve().parents[1]
    base = root / "dist" / "malware_analyzer"
    if platform.system().lower().startswith("win"):
        candidate = base / "malware_analyzer.exe"
    else:
        candidate = base / "malware_analyzer"

    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(f"Packaged binary not found: {candidate}")
    return candidate


def main() -> int:
    binary = _resolve_binary()
    process = subprocess.run(
        [str(binary), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    stdout = process.stdout.strip()
    stderr = process.stderr.strip()

    if process.returncode != 0:
        print("Smoke test failed")
        print(f"Binary: {binary}")
        print(f"Exit code: {process.returncode}")
        if stdout:
            print("stdout:")
            print(stdout)
        if stderr:
            print("stderr:")
            print(stderr)
        return process.returncode

    print("Smoke test passed")
    print(f"Binary: {binary}")
    print("--help output preview:")
    print("\n".join(stdout.splitlines()[:20]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
