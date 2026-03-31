# User Guide

## Launch GUI

```powershell
python main.py gui
```

## Scan Tab

- Add files or folders to queue
- Start scan to extract hashes and static features
- Stop scan for hard interruption
- Use Copy Log/Clear Log for operation logs

## Explorer Tab

- Apply filters by platform, family, source, score, date, search text
- Bulk actions:
  - Edit tags
  - Flag selected
  - Tag ML (quick add `ML` tag)
  - Remove selected
- Export data for training:
  - Export Filtered JSONL/CSV
  - Export Selected JSONL/CSV

## Report Tab

- View details of selected sample:
  - Overview
  - Features
  - Strings
  - CFG metrics
  - YARA
  - Similar samples
  - Raw JSON
- Export:
  - Save sample JSONL/CSV
  - Print report
  - Save dataset JSONL/CSV by scope

## Intel Tab

- Fetch metadata from MalwareBazaar
- Query modes include By Tag/By Family/By Hash/Keyword Syntax
- Suggested broad class query: `file_type:<value>`
- Download ZIP samples
- Optional auto-scan after download
- Auto enrich local DB hashes from Intel source
- Run ML backfill directly from GUI (no CLI required):
  - model path
  - source/platform filter
  - overwrite existing ML fields
  - optional limit

## ML Workflow (CLI)

- Export feature matrix:
  - `python main.py db export --format feature-matrix --output output/phase11_features.csv`
- Train model:
  - `python main.py ml train --input-csv output/phase11_features.csv --output-model models/family_classifier.joblib --algorithm auto`
- Regenerate latest report:
  - `python main.py ml report-latest`
- Custom latest report path:
  - `python main.py ml report-latest --log-path models/model_log.jsonl --output models/reports/latest_report.md`
- Backfill all DB rows:
  - `python main.py ml backfill`
- Backfill with filter:
  - `python main.py ml backfill --source MalwareBazaar --platform Windows`
- Overwrite existing ML values:
  - `python main.py ml backfill --overwrite`
- ML coverage for demo report (group by source/family):
  - `python main.py ml coverage`
  - `python main.py ml coverage --family-limit 30 --output-md models/reports/ml_coverage.md`

## Full CLI Reference

- See [docs/cli-cheatsheet.md](docs/cli-cheatsheet.md) for quick command list by module (`scan`, `db`, `intel`, `report`, `ml`, `serve`).
