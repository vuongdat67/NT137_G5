# CLI Cheatsheet

## General

- Show help:
  - `python main.py --help`
- Show command help:
  - `python main.py <command> --help`

## Scan

- Scan single file:
  - `python main.py scan <file_path>`
- Scan folder recursively with workers:
  - `python main.py scan <folder_path> --recursive --workers 4`
- Watch folder:
  - `python main.py watch <folder_path> --recursive --workers 4`

## Database (`db`)

- DB stats:
  - `python main.py db stats`
- List rows:
  - `python main.py db list --page 1 --page-size 30 --platform All --family All --source All --search ""`
- Show one row:
  - `python main.py db show <sha256>`
- Delete rows:
  - `python main.py db delete <sha256> [<sha256> ...]`
- Import JSONL:
  - `python main.py db import <path_to_jsonl>`
- Export JSONL/CSV/YARA/feature-matrix:
  - `python main.py db export --format jsonl`
  - `python main.py db export --format csv`
  - `python main.py db export --format yara`
  - `python main.py db export --format feature-matrix --output output/phase11_features.csv`
- Re-score local labels:
  - `python main.py db rescore`
- Recompute clusters:
  - `python main.py db recluster --min-score 75`

## Intel (`intel`)

- Fetch intel from MalwareBazaar:
  - `python main.py intel fetch --mode "By Tag" --value exe --limit 100 --apply`
- Enrich local hashes by get_info:
  - `python main.py intel enrich-local --limit 200 --batch-order "Natural"`

## Reports (`report`)

- Sample report (HTML/PDF):
  - `python main.py report sample <sha256> --format both`
- Batch HTML report:
  - `python main.py report batch --platform All --family All --source All`

## ML (`ml`)

- `models/model_log.jsonl` is auto-created after `ml train` and appended on each training run.
- `ml report-latest` reads the newest record from `models/model_log.jsonl`.

- Train model:
  - `python main.py ml train --input-csv output/phase11_features.csv --output-model models/family_classifier.joblib --algorithm auto`
- Latest report markdown:
  - `python main.py ml report-latest`
  - `python main.py ml report-latest --log-path models/model_log.jsonl --output models/reports/latest_report.md`
- Backfill ML into existing DB rows (no rescan):
  - `python main.py ml backfill`
  - `python main.py ml backfill --source MalwareBazaar --platform Windows`
  - `python main.py ml backfill --overwrite`
- ML coverage summary (source/family):
  - `python main.py ml coverage`
  - `python main.py ml coverage --family-limit 30 --output-md models/reports/ml_coverage.md`

## API

- Start API server:
  - `python main.py serve --host 127.0.0.1 --port 8000`
