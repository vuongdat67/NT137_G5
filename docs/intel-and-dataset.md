# Intel and Dataset Guide

## Intel Fetch Concepts

- `Fetched entries`: number of metadata entries returned by MalwareBazaar
- `downloaded_zip`: number of ZIP files successfully saved locally
- `updated`: local DB rows updated with Intel metadata
- `skipped`: entries not applied (for example hash not found in local DB)

## Why downloaded can be > 0 but updated = 0

Downloaded files are separate from local DB rows.
Intel metadata is applied only to hashes already present in local database.

Typical flow:

1. Fetch and download ZIP files
2. Scan those files into DB
3. Enrich/apply Intel metadata

Or enable `Auto-scan after download` to automate step 2.

## Export for Model Training

### Explorer exports

- Filter for your target class/platform/source
- Export Filtered JSONL or CSV
- Use Export Selected for curated sets

### Report dataset exports

Choose scope:

- All Samples
- Windows Only
- Android Only
- Source Local
- Source MalwareBazaar
- Current Family

Then export JSONL/CSV.

## Recommended dataset strategy

1. Keep raw exports immutable by date
2. Create curated subsets for experiments
3. Track label quality (family/tag confidence)
4. Version datasets before model training
