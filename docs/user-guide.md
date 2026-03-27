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
