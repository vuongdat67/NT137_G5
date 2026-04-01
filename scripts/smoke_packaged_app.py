from __future__ import annotations

from pathlib import Path
import platform
import subprocess
import sys
import tempfile


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

    # ML smoke: verify packaged binary can run a tiny training task.
    with tempfile.TemporaryDirectory(prefix="msa_ml_smoke_") as tmp:
        tmp_dir = Path(tmp)
        csv_path = tmp_dir / "ml_smoke.csv"
        model_path = tmp_dir / "ml_smoke.joblib"
        csv_path.write_text(
            "sha256,file_size,packed,local_score,intel_score,score,heuristic_score,cfg_nodes,cfg_edges,cfg_cyclomatic,cfg_max_depth,cfg_avg_depth,cfg_loop_count,cfg_scc_count,strings_total_count,strings_b64_count,api_risk_score,platform,family,source\n"
            "a1,12000,0,20,0,20,20,8,7,1,4,2.0,0,8,20,0,1.0,Windows,FamA,Local\n"
            "a2,14000,0,22,0,22,22,9,8,1,4,2.0,0,9,24,0,1.0,Windows,FamA,Local\n"
            "a3,13000,0,21,0,21,21,8,7,1,4,2.0,0,8,21,0,1.0,Windows,FamA,Local\n"
            "a4,12500,0,19,0,19,19,8,7,1,4,2.0,0,8,19,0,1.0,Windows,FamA,Local\n"
            "a5,13500,0,23,0,23,23,9,8,1,4,2.0,0,9,23,0,1.0,Windows,FamA,Local\n"
            "b1,22000,0,75,0,75,75,12,11,2,6,3.0,0,12,35,1,4.0,Android,FamB,MalwareBazaar\n"
            "b2,21000,0,72,0,72,72,11,10,2,6,3.0,0,11,33,1,4.0,Android,FamB,MalwareBazaar\n"
            "b3,21500,0,74,0,74,74,11,10,2,6,3.0,0,11,34,1,4.0,Android,FamB,MalwareBazaar\n"
            "b4,22500,0,76,0,76,76,12,11,2,6,3.0,0,12,36,1,4.0,Android,FamB,MalwareBazaar\n"
            "b5,21800,0,73,0,73,73,11,10,2,6,3.0,0,11,35,1,4.0,Android,FamB,MalwareBazaar\n",
            encoding="utf-8",
        )

        ml_process = subprocess.run(
            [
                str(binary),
                "ml",
                "train",
                "--input-csv",
                str(csv_path),
                "--output-model",
                str(model_path),
                "--algorithm",
                "rf",
                "--min-class-samples",
                "2",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        if ml_process.returncode != 0:
            print("ML smoke test failed")
            print(f"Binary: {binary}")
            print(f"Exit code: {ml_process.returncode}")
            if ml_process.stdout.strip():
                print("stdout:")
                print(ml_process.stdout.strip())
            if ml_process.stderr.strip():
                print("stderr:")
                print(ml_process.stderr.strip())
            return ml_process.returncode

        if not model_path.exists() or not model_path.is_file():
            print("ML smoke test failed")
            print(f"Binary: {binary}")
            print("Model output was not created")
            return 2

        print("ML smoke test passed")
        print(f"Model output: {model_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
