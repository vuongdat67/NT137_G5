# Malware Static Analyzer: CLI Scripts Reference

Complete documentation of all `.py` scripts in the `scripts/` directory.

---

## 1. benchmark_scan_matrix.py

**Purpose**: Measure scan throughput under realistic load (1k, 5k, 10k file scenarios)

**Location**: `scripts/benchmark_scan_matrix.py`

### Usage

```bash
python scripts/benchmark_scan_matrix.py [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--workers` | INT | 4 | Number of parallel scanner workers |
| `--malware-dir` | PATH | `malware_samples` | Directory containing `.zip` archives / files to scan |
| `--output` | PATH | `benchmark_report_{timestamp}.md` | Output report file path |
| `--verbose` | FLAG | False | Detailed logging during scan |

### Example 1: Baseline throughput test

```bash
python scripts/benchmark_scan_matrix.py --workers 4
```

**Expected output** (JSON):
```json
{
  "timestamp": "2025-01-15T10:30:45.123456",
  "worker_count": 4,
  "scenarios": {
    "1k": {
      "file_count": 1000,
      "throughput_files_per_sec": 34.89,
      "total_time_sec": 119.07,
      "avg_cpu_percent": 45.2,
      "iowait_percent": 12.3
    },
    "5k": {...},
    "10k": {...}
  }
}
```

**Markdown report** (human-readable summary):

```markdown
# Malware Analyzer Benchmark Report
**Timestamp**: 2025-01-15 10:30:45
**Workers**: 4

| Scenario | Files | Throughput (f/s) | Time (sec) | Avg CPU % | I/O Wait % |
|---|---|---|---|---|---|
| 1k | 1000 | 34.89 | 119.07 | 45.2 | 12.3 |
| 5k | 5000 | 29.06 | 171.98 | 52.1 | 18.5 |
| 10k | 10000 | 26.50 | 377.36 | 58.3 | 22.1 |
```

### Example 2: Custom malware directory with 8 workers

```bash
python scripts/benchmark_scan_matrix.py \
  --workers 8 \
  --malware-dir /mnt/fast-ssd/malware-zips \
  --output results/benchmark_2025_01_15.md \
  --verbose
```

### Performance Interpretation

**Healthy declining throughput**:
- 1k: 35 files/s → 5k: 30 files/s → 10k: 27 files/s = Expected (cache efficiency)

**Bottleneck check**:
- **Avg CPU % > 80%**, Throughput > 20 files/s → CPU-bound; reduce workers
- **I/O Wait % > 30%**, Throughput < 20 files/s → Disk I/O bound; upgrade storage
- **Throughput drops >50% at 5k** → Memory pressure; reduce workers

### Inside the script

**Seed extraction logic** (lines 240-260):
1. Looks for `.zip` files in `--malware-dir`
2. Tries to extract a test sample using fallback chain:
   - Prefers APK, EXE, DLL files if found in ZIP
   - Falls back to any extracted file (CONFIG, TXT, etc.)
   - Last resort: Creates dummy `python.exe` placeholder
3. If seed extraction fails → RuntimeError (now caught with dummy)

**Run scenarios** (function `run_matrix`):
- Internally generates 1k, 5k, 10k file lists
- Calls scanner on each list sequentially
- Records timing + CPU metrics
- Writes both JSON + Markdown outputs

---

## 2. collect_intel_matrix.py

**Purpose**: Bulk-collect malware samples from MalwareBazaar matching query criteria

**Location**: `scripts/collect_intel_matrix.py`

### Usage

```bash
python scripts/collect_intel_matrix.py [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--query-type` | CHOICE | — | Query type: `tag`, `file_type`, `signature`, `hash`, `issuer`, `serial`, `yara` |
| `--query-value` | STR | — | Value to query (e.g., `ransomware` for tag query) |
| `--limit` | INT | 100 | Max samples to fetch |
| `--apply` | FLAG | False | Import fetched samples into DB |
| `--no-apply` | FLAG | False | Fetch only, do NOT import (saves CSV for review first) |
| `--output` | PATH | `intel_{query_type}_{query_value}_{ts}.csv` | Output CSV path |

### Query Types Supported

| Type | Example | Use Case |
|---|---|---|
| `tag` | `--query-type tag --query-value ransomware` | Threat category collection |
| `file_type` | `--query-type file_type --query-value exe` | Platform-specific analysis |
| `signature` | `--query-type signature --query-value RemcosRAT` | APT family focus |
| `hash` | `--query-type hash --query-value abc123...` | Single file lookup |
| `issuer` | `--query-type issuer --query-value "CN=..."` | Signed malware detection |

### Example 1: Collect ransomware, review first

```bash
python scripts/collect_intel_matrix.py \
  --query-type tag \
  --query-value ransomware \
  --limit 500 \
  --no-apply
```

**Output**:
```
intel_tag_ransomware_2025_01_15_10_30.csv
```

**CSV preview**:
```csv
sha256,name,family,tags,threat_level,source
abc123...,sample1.exe,Emotet,ransomware;dropper,high,MalwareBazaar
def456...,sample2.exe,TrickBot,ransomware;banking,critical,MalwareBazaar
```

**Review, then import**:
```bash
python scripts/collect_intel_matrix.py \
  --query-type tag \
  --query-value ransomware \
  --limit 500 \
  --apply
```

### Example 2: Collect RemcosRAT APT samples directly into DB

```bash
python scripts/collect_intel_matrix.py \
  --query-type signature \
  --query-value RemcosRAT \
  --limit 250 \
  --apply
```

**Output**: 250 RemcosRAT samples added to DB with family + tags populated

### Example 3: Signed malware detection

```bash
python scripts/collect_intel_matrix.py \
  --query-type issuer \
  --query-value "CN=Microsoft Corp" \
  --limit 50 \
  --no-apply
```

### Inside the script

**argparse structure** (lines 40-110):
- Fixed: Dual `--apply`/`--no-apply` flags (no longer `--apply/--no-apply` syntax)
- Both can be used; mutual exclusivity enforced downstream

**Query execution** (BazaarClient):
- For each query value, hits `/api/v1/query` endpoint
- Respects rate limit (1 req/sec minimum)
- Returns metadata: sha256, family, tags, threat_level, source

**Import logic** (`--apply` mode):
- Samples added to DB with source="MalwareBazaar"
- Existing samples by hash skipped (prevents duplicates)
- Enrichment fields auto-populated

**Fallback** (line 85-95):
- If query type looks like it could be file_type (e.g., "exe", "dll", "elf"), retries as file_type on 502 error

---

## 3. export_features.py

**Purpose**: Export scan features from DB to CSV for ML training

**Location**: `scripts/export_features.py`

### Usage

```bash
python scripts/export_features.py [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--output` | PATH | `features_export.csv` | Output CSV path |
| `--filter-family` | STR | — | (Optional) Export only samples from this family |
| `--filter-source` | CHOICE | — | (Optional) Filter by source: `Local`, `MalwareBazaar` |
| `--exclude-missing` | FLAG | False | Skip rows with missing ML features |

### Example 1: Full export

```bash
python scripts/export_features.py --output training_data.csv
```

**Output CSV columns**:
```
sha256,file_size,file_type,platform,architecture,entropy,heuristic_score,
string_count,suspicious_string_count,import_count,yara_match_count,
cfg_nodes,cfg_edges,cfg_cyclomatic,cfg_max_depth,cfg_avg_depth,
cfg_loop_count,cfg_scc_count,predicted_family
```

### Example 2: Export Ransomware family only (for retraining)

```bash
python scripts/export_features.py \
  --filter-family Ransomware \
  --exclude-missing \
  --output ransomware_training.csv
```

### Example 3: MalwareBazaar enriched samples

```bash
python scripts/export_features.py \
  --filter-source MalwareBazaar \
  --output bazaar_features.csv
```

**Useful for**: Building ML pipelines on authoritative threat intel

---

## 4. model_trainer.py

**Purpose**: Train LightGBM family classifier from features CSV

**Location**: `scripts/model_trainer.py`

### Usage

```bash
python scripts/model_trainer.py [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--input` | PATH | `features_export.csv` | Input features CSV |
| `--output` | PATH | `models/family_classifier.joblib` | Output model path |
| `--model-type` | CHOICE | `lightgbm` | ML algorithm: `lightgbm`, `random_forest` (future) |
| `--test-size` | FLOAT | 0.2 | Test/validation split ratio |
| `--cv-folds` | INT | 5 | Cross-validation fold count |

### Example 1: Train from exported features

```bash
# Step 1: Export features
python scripts/export_features.py --output training_data.csv

# Step 2: Train model
python scripts/model_trainer.py \
  --input training_data.csv \
  --output models/custom_classifier.joblib \
  --cv-folds 5
```

**Training output**:
```
Loading features from training_data.csv...
Loaded 5000 samples, 12 families
Splitting 80/20 train/test...
Training LightGBM classifier...
[LGB] Iteration 1: train_logloss=1.234, validation_logloss=1.456
[LGB] Iteration 50: train_logloss=0.345, validation_logloss=0.512
Training complete in 45.3 seconds.

Evaluation:
  Accuracy: 92.3%
  Macro F1: 0.914
  Per-family precision/recall: [...]
```

### Example 2: Train on large dataset with custom split

```bash
python scripts/model_trainer.py \
  --input /mnt/large_features.csv \
  --output models/large_model.joblib \
  --test-size 0.15 \
  --cv-folds 10
```

---

## 5. predict_batch.py

**Purpose**: Backfill existing scanned samples with ML predictions

**Location**: `scripts/predict_batch.py`

### Usage

```bash
python scripts/predict_batch.py [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--model` | PATH | `models/family_classifier.joblib` | Trained model path |
| `--filter-source` | CHOICE | — | (Optional) Predict only this source |
| `--overwrite` | FLAG | False | Overwrite existing predictions |
| `--batch-size` | INT | 100 | Samples per batch |

### Example 1: Backfill all samples

```bash
python scripts/predict_batch.py --model models/family_classifier.joblib
```

**Output**:
```
Loading model...
Querying 5000 samples needing prediction...
Batch 1/50: Predicting 100 samples...
Batch 2/50: Predicting 100 samples...
...
All predictions complete. Updated 5000 rows.
```

### Example 2: Re-predict (after model retraining)

```bash
python scripts/predict_batch.py \
  --model models/family_classifier.joblib \
  --overwrite
```

---

## 6. analyze_trends.py

**Purpose**: Analyze historical benchmark data for performance regressions

**Location**: `scripts/analyze_trends.py` (if implemented)

### Usage

```bash
python scripts/analyze_trends.py [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--input` | PATH | — | Benchmark history JSON file(s) |
| `--metric` | CHOICE | `throughput` | Metric to plot: `throughput`, `cpu`, `iowait` |
| `--output` | PATH | `trend_chart.png` | Output chart path |

### Example: Plot throughput regression over time

```bash
python scripts/analyze_trends.py \
  --input benchmarks/*.json \
  --metric throughput \
  --output results/throughput_trend.png
```

---

## 7. similarity_matrix.py

**Purpose**: Compute pairwise similarity scores between all samples (expensive operation)

**Location**: `scripts/similarity_matrix.py`

### Usage

```bash
python scripts/similarity_matrix.py [OPTIONS]
```

### Example: Compute full similarity matrix

```bash
python scripts/similarity_matrix.py --workers 8 --output similarity_scores.csv
```

**Output CSV**:
```
sha256_1,sha256_2,tlsh_distance,ssdeep_match,similarity_score
abc...,def...,12,85,88
abc...,ghi...,65,12,32
```

**Warning**: O(n²) complexity; slow for >5k samples. Typically not run manually; clustering handles incrementally.

---

## CLI Integration Points

### From malware_analyzer/cli/commands.py

**Aliases** (shorter syntax):

```bash
# Scanning
python -m malware_analyzer.cli scan <file>

# Enrichment
python -m malware_analyzer.cli intel enrich-local [--force]

# ML
python -m malware_analyzer.cli ml train
python -m malware_analyzer.cli ml predict-batch
python -m malware_analyzer.cli ml coverage-report

# Export
python -m malware_analyzer.cli export csv
```

---

## Error Handling & Recovery

### Common Issues & Solutions

**benchmark_scan_matrix.py:**
- `RuntimeError: No suitable seed sample found` → Script now creates dummy python.exe fallback ✅
- `FileNotFoundError: malware_samples not found` → Use `--malware-dir /path/to/zips`

**collect_intel_matrix.py:**
- `argparse error` → Fixed; use `--apply` and `--no-apply` as separate flags ✅
- `502 Bad Gateway on tag query` → Auto-fallback to file_type if value looks like extension

**export_features.py:**
- `No samples in database` → Scan files first
- `Missing CFG metrics` → Non-PE files are OK; NULL values in export

**model_trainer.py:**
- `Insufficient training samples (<50)` → Collect more samples
- `No label column (family)` → Run enrichment first

---

## Performance Notes

| Script | Time | Bottleneck |
|---|---|---|
| benchmark_scan_matrix.py | 15-30 min (all 3 scenarios) | Disk I/O (archive extraction) |
| collect_intel_matrix.py | 1-5 min/100 samples | Network API rate limit (1 req/sec) |
| export_features.py | 1-10 sec | DB query (scales with sample count) |
| model_trainer.py | 1-5 min (10k samples) | CPU (ML training) |
| predict_batch.py | 5-10 sec (1k samples) | CPU (inference) |

---

## Batch Automation Example

**Daily threat intel refresh + model retraining**:

```bash
#!/bin/bash
# refresh_and_retrain.sh

echo "=== Collecting latest ransomware samples ==="
python scripts/collect_intel_matrix.py \
  --query-type tag \
  --query-value ransomware \
  --limit 500 \
  --apply

echo "=== Enriching local samples ==="
python -m malware_analyzer.cli intel enrich-local --workers 8

echo "=== Exporting features for training ==="
python scripts/export_features.py \
  --exclude-missing \
  --output daily_training_data.csv

echo "=== Retraining model ==="
python scripts/model_trainer.py \
  --input daily_training_data.csv \
  --output models/daily_classifier.joblib

echo "=== Backfilling predictions ==="
python scripts/predict_batch.py \
  --model models/daily_classifier.joblib \
  --overwrite

echo "=== Done. Model updated. ==="
```

**Run daily via cron**:
```
0 2 * * * cd /path/to/project && bash refresh_and_retrain.sh >> logs/daily_refresh.log 2>&1
```

