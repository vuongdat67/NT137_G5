# Malware Static Analyzer: Feature Guide

Complete walkthrough of every feature with examples and use cases.

---

## Part 1: Scanning Features

### 1.1 Scan a Single File

**GUI**: File menu → Open → Select file  
**CLI**: `python malware_analyzer/cli/commands.py scan /path/to/file.exe`

**Output**:
- File metadata (hash, size, type, architecture)
- Identification (file type auto-detected)
- Hashing (MD5, SHA256, TLSH, ssdeep, imphash)
- Enrichment features:
  - Strings (count, suspicious keywords)
  - Imports (API calls, by risk category)
  - YARA matches (if rules in `malware_analyzer/rules/`)
  - Heuristic score (0-100, auto-verdict)
  - CFG metrics (if PE file)
  - ML prediction (if model trained)

**Time**: Typical file ≈ 0.5-2 seconds

### 1.2 Batch Scan with Archive Support

**Input**: Directory with `.zip` files  
**Handling**: Automatically extracts and scans archived binaries

**Example**:
```bash
python scripts/benchmark_scan_matrix.py --workers 4 --malware-dir ./samples
```

**Archive policy**:
- Tries password "infected" (standard honeypot convention)
- Extracts PE, APK, DEX, ELF, MSI, SYS
- Skips files > 64MB (default, configurable via `archive_member_max_size_mb` in settings)
- Falls back to container-only scan if no members match

**Output**: All samples scanned and stored in DB

### 1.3 Force Rescan

**Purpose**: Re-scan existing samples (e.g., after rule update)

**GUI**: Scan tab → Right-click sample → Rescan  
**CLI**: `python malware_analyzer/cli/commands.py scan --force /path/to/file.exe`

**Effect**: Overwrites existing scan results; preserves enrichment data (hash, family, tags)

---

## Part 2: Enrichment Features

### 2.1 Automatic Enrichment (Background)

During scan, if MalwareBazaar connection available:
- File queried against Bazaar API by SHA256
- Results cached (family, signature, threat score, tags)

**Network requirement**: Active internet connection  
**Fallback**: If offline, scan completes with heuristics only (local scoring)

### 2.2 Batch Enrichment (Backfill)

**Purpose**: Re-query multiple samples at once (e.g., daily intel refresh)

**GUI**: Intel tab → "Enrich Local" button  
**CLI**: `python malware_analyzer/cli/commands.py intel enrich-local`

**Options**:
- `--batch-size`: Number of samples per query batch (default 10)
- `--workers`: Concurrent API threads (default 4)
- `--force`: Re-query even already-enriched samples

**Example**:
```bash
python malware_analyzer/cli/commands.py intel enrich-local --force --workers 8
```

**Performance**:
- Default rate limit: 1sec between requests
- 100 samples → ≈ 100-120 seconds
- Force re-query: Slower but validates current threat status

### 2.3 Targeted Enrichment (Query-Based Collection)

**Purpose**: Bulk-collect malware samples from Bazaar matching specific criteria

**Supported queries**:
- `tag:ransomware` — All ransomware tagged samples
- `signature:RemcosRAT` — APT family
- `file_type:exe` — Windows executables only
- `issuer:CN=...` — Signed malware detection
- `hash:abc123...` — Single sample lookup

**CLI**: `python scripts/collect_intel_matrix.py`

**Examples**:
```bash
# Collect 500 ransomware samples
python scripts/collect_intel_matrix.py \
  --query-type tag \
  --query-value ransomware \
  --limit 500 \
  --apply  # Import into DB

# Collect RemcosRAT samples
python scripts/collect_intel_matrix.py \
  --query-type signature \
  --query-value RemcosRAT \
  --no-apply  # Just fetch, don't import yet
```

**Output**: CSV with Bazaar sample metadata; optionally imported to DB

---

## Part 3: Analysis & Reporting

### 3.1 Sample Report

**Purpose**: Single-page forensic summary

**GUI**: Scan tab → Right-click sample → Generate Report

**Includes**:
- File metadata (all hashes, size, type, platform, architecture)
- Threat assessment (heuristic score, family, tags, threat level)
- Features extracted (strings, imports, YARA matches)
- CFG visualization (if PE)
- ML prediction confidence

**Formats**: HTML (interactive), PDF (printable)

### 3.2 Batch Report (Cluster View)

**Purpose**: Variant clustering & campaign analysis

**GUI**: Cluster View tab → Select cluster → "Generate Report"

**Shows**:
- Cluster members (similar samples)
- Similarity metrics (TLSH distances, ssdeep matches)
- Common features (shared imports, strings)
- Threat summary (dominant family, max threat score)

**Use case**: Ransomware campaign → cluster by similarity → identify variants and operators

### 3.3 Similarity Clustering

**Automatic**: Runs after enrichment; groups similar samples

**Manual recompute**: Explorer tab → "Recompute Similarity"

**Algorithm**:
1. Compare TLSH hashes (if available)
2. Compare ssdeep hashes (if available)
3. Link pairs with score ≥ 75 (configurable threshold)
4. Find connected components → clusters

**Visualization**:
- Cluster View shows members and intercommunity edges
- Color-coded by family (from enrichment)
- Size proportional to cluster membership

---

## Part 4: Machine Learning

### 4.1 Train a Custom Model

**Purpose**: Build family classifier from local samples

**Prerequisite**: ≥100 samples with known families (from manual tagging or Bazaar enrichment)

**GUI**: Tools menu → "Train Model"

**CLI**:
```bash
python malware_analyzer/cli/commands.py ml train \
  --model-type lightgbm \
  --output models/custom_family_classifier.joblib
```

**Process**:
1. Export feature matrix (file size, string counts, imports, CFG metrics, heuristic score)
2. Label from enrichment family field
3. 80/20 train/test split
4. LightGBM training with 5-fold CV
5. Report: accuracy, precision, recall per family

**Output**: Serialized model + training log

### 4.2 Apply Model (Predict)

**Real-time**: During scan, if model available, predictions attached to each sample

**Backfill existing**:
```bash
python malware_analyzer/cli/commands.py ml predict-batch \
  --model models/custom_family_classifier.joblib \
  --overwrite  # Replace existing predictions
```

**Output**: Sample rows updated with predicted_family, predicted_confidence

### 4.3 Model Evaluation

**View training coverage**:
```bash
python malware_analyzer/cli/commands.py ml coverage-report
```

**Shows**:
- % samples with families by source (Local vs. Bazaar)
- Most common families
- Families with low training sample count (need more data)

---

## Part 5: Advanced Features

### 5.1 Control Flow Graph (CFG) Analysis

**Automatic**: Extracted for all PE files during scan

**Metrics computed**:
- `cfg_nodes`: Basic block count
- `cfg_edges`: Branch/jump count
- `cfg_cyclomatic`: Cyclomatic complexity (decision path count)
- `cfg_max_depth`: Longest path from entry to exit
- `cfg_avg_depth`: Average path length
- `cfg_loop_count`: Loop/self-loop count
- `cfg_scc_count`: Strongly connected components (cycle detection)

**Interpretation**:
- **Low depth (≤3)**: Simple control flow, unlikely polymorphic
- **Medium depth (4-6)**: Typical malware obfuscation
- **High depth (7+)**: Advanced obfuscation, APT/ransomware marker

**GUI Report Tab**:
- CFG visualization with depth filtering (Auto, 2, 3, 4, 5, 6, 8, All)
- Auto mode picks optimal depth for readability
- Full graph render available with "All"

**Performance**: Rendering glitch at >500 nodes; use depth filtering for large binaries

### 5.2 YARA Rule Integration

**Purpose**: Detect known signatures

**Location**: `malware_analyzer/rules/` (.yar or .yara files)

**Example rule**:
```yara
rule Ransomware_Template_Generic {
    strings:
        $s1 = "AES-256" wide
        $s2 = "Your files have been encrypted" nocase
    condition:
        all of ($s*)
}
```

**Automatic**: Scans load rules at startup; matches recorded in scan results

**Output**: Matched rules appear in sample report + exported feature matrix

### 5.3 Custom Heuristics

**Configured in**: `malware_analyzer/config/settings.py`

**Adjustable**:
- `packed_entropy_threshold` (default 7.2) — What entropy indicates packing
- `heuristic_score_threshold` (default 50) — Auto-verdict threshold
- `suspicious_string_patterns` — Regex for high-risk keywords
- `suspicious_imports` — Win32 APIs correlated with malware

**Recompute heuristic scores** (after config change):
```bash
python malware_analyzer/cli/commands.py scan --force --refresh-heuristics
```

---

## Part 6: Benchmarking & Performance Testing

### 6.1 Benchmark Scan Matrix

**Purpose**: Measure throughput under realistic loads

**Scenarios**: 1k, 5k, 10k file samples (each in separate ZIP archives)

**CLI**:
```bash
python scripts/benchmark_scan_matrix.py --workers 4 --malware-dir ./samples
```

**Output**: JSON + Markdown report with:
- Files/second throughput
- CPU usage (process + system)
- I/O wait percentage
- Disk read/write MB/s
- Total wall-clock time

**Interpretation**:
- **1k files**: Baseline throughput (typically 30-40 files/sec with 4 workers)
- **5k files**: Scaling check (typically 25-35 files/sec; watch for memory growth)
- **10k files**: Stress test (typically 20-30 files/sec; I/O becomes dominant)

**Customization**:
- `--workers N`: Adjust parallelism (default 4)
- `--malware-dir PATH`: Override malware samples location
- `--output FILE`: Save report to specific path

### 6.2 Interpreting Benchmark Results

**Healthy run**:
```
1k files: 34.89 files/sec (119.07 sec)
5k files: 29.06 files/sec (171.98 sec)
10k files: 26.50 files/sec (377.36 sec)
```

**Explanation**:
- Throughput decreases as file count grows = expected (working set grows, cache efficiency drops)
- Trend linear on log scale = good (nothing pathological)

**Bottleneck identification**:
- High I/O wait % → Disk I/O limited; add faster storage or reduce parallelism
- High CPU % but low throughput → CPU limited; reduce workers or optimize disassembly
- CPU % < 50% with high I/O wait → I/O bound; parallelize archive extraction

### 6.3 Benchmark Data Collection Script

**Purpose**: Build historical benchmark dataset for tracking performance regressions

**CLI**: Same as 6.1, but stores results in DB

**Visualize trends**:
```bash
python scripts/analyze_benchmark_trends.py
```

**Output**: Graph showing throughput/CPU over time (if implemented)

---

## Part 7: Workflow Examples

### Example 1: Incident Response (Unknown Binary)

1. **Scan**: Drag file to GUI Scan tab
2. **Identify**: Check Type, Heuristic Score
3. **Enrich**: Auto-query MalwareBazaar (if connected)
4. **Report**: Generate HTML report for team
5. **Family match**: Use ML prediction to correlate with known campaigns

**Time**: ≈ 5 minutes total (including enrichment API wait)

### Example 2: Ransomware Campaign Analysis

1. **Collect**: `collect_intel_matrix.py --query-type tag --query-value ransomware`
2. **Import**: CLI flag `--apply` or manual import
3. **Cluster**: GUI Cluster View auto-groups similar samples
4. **Report**: Generate batch report with variant summary
5. **Visualize**: Export to MITRE or OpenIOC for response team

**Time**: ≈ 30 minutes (dependent on Bazaar API rate limits)

### Example 3: Malware Signature Detection

1. **Add YARA rules** to `malware_analyzer/rules/`
2. **Rescan** first batch: `scan --force /path/to/samples`
3. **Filter** report by YARA rule matches
4. **Compare** with heuristic scores (signature match vs. behavioral score alignment)

**Use case**: Validate custom signature effectiveness

### Example 4: Model Training & Deployment

1. **Collect** ≥500 training samples from Bazaar (multiple families)
2. **Label** via enrichment family field
3. **Train** model: `ml train --model-type lightgbm`
4. **Evaluate** coverage: `ml coverage-report`
5. **Deploy**: Model auto-loaded on startup; predictions attached to new scans
6. **Monitor**: Log predictions over time to detect label drift

**Success metric**: ≥85% F1 score on held-out test set

---

## Part 8: Configuration Reference

**Location**: `malware_analyzer/config/settings.py`

**Key settings**:

| Setting | Default | Purpose |
|---|---|---|
| `database_path` | `output/malware.db` | SQLite location |
| `archive_member_max_size_mb` | 64 | Skip ZIP members > this |
| `packed_entropy_threshold` | 7.2 | Entropy trigger for packing detection |
| `heuristic_score_threshold` | 50 | Auto-verdict cutoff |
| `max_strings_to_extract` | 1000 | Cap string list to prevent bloat |
| `max_import_functions` | 500 | Cap import list |
| `cfg_max_nodes` | 1000 | Stop disassembly over this |
| `similarity_threshold` | 75 | Clustering link threshold (0-100) |
| `ml_model_path` | `models/family_classifier.joblib` | Trained model location |
| `yara_rules_dir` | `malware_analyzer/rules/` | YARA rule location |
| `bazaar_endpoint` | `https://mb-api.abuse.ch/api/v1/` | MalwareBazaar API URL |
| `bazaar_timeout_sec` | 30 | API request timeout |
| `enrichment_workers` | 4 | Concurrent enrichment threads |

**Customize**: Edit `settings.py` and restart application

---

## Part 9: Troubleshooting

**Q: Scan shows [ERROR] for ZIP file, sample skipped**  
A: Check `archive_member_max_size_mb`. If all members > threshold, no extraction happens. Reduce threshold or decompress manually.

**Q: CFG metrics all zeros for PE file**  
A: Disassembly failed (permission denied, corrupted header, or >cfg_max_nodes bytes). File marked safe defaults; consider manual inspection.

**Q: Enrichment stalled at 10%, no progress**  
A: MalwareBazaar API rate limited or network issue. Check internet connection; wait 5-10 minutes; retry with `--force`.

**Q: GUI hangs when opening large CFG graph**  
A: Graph has >500 nodes. Use depth filter (Auto or 4) instead of All; rendering CPU-intensive at full depth.

**Q: ML model predictions all same family**  
A: Training data imbalanced (one family dominates). Collect more diverse samples; retrain.

**Q: YARA rules not matching despite being in directory**  
A: Rules syntax invalid. Run: `yara -p malware_analyzer/rules/ <test_file>` to debug.

---

## Part 10: Performance Tuning

**Fastest scan** (heuristics only):
```bash
export BAZAAR_API_TIMEOUT=1  # Skip enrichment
python malware_analyzer/cli/commands.py scan <file>
```
Baseline: 0.5-1 sec per file

**Highest accuracy** (full enrichment + ML):
- Ensure model in place
- Enrich all samples first: `intel enrich-local --force`
- Predictions attached automatically
- Trade-off: +30-50% time for +15-20% accuracy

**Largest batch** (1000+ files):
- Use 8 workers (if 8+ CPU cores)
- Archive in 100-file ZIPs to avoid memory spike
- Monitor with: `watch -n 1 "ps aux | grep python"`

**Custom YARA rules** (minimized scan overhead):
- Keep ruleset <100 rules (scales linearly)
- Avoid regex-heavy conditions (use exact strings if possible)
- Profile: `yara --version` and test on single file before batch

---

## Appendix: CLI Quick Reference

```bash
# Scanning
python malware_analyzer/cli/commands.py scan <path>               # Single file
python malware_analyzer/cli/commands.py scan --force <path>       # Rescan

# Enrichment
python malware_analyzer/cli/commands.py intel enrich-local                  # Batch backfill
python scripts/collect_intel_matrix.py --query-type tag --query-value ransomware  # Bulk collect

# ML
python malware_analyzer/cli/commands.py ml train                  # Train model
python malware_analyzer/cli/commands.py ml predict-batch          # Backfill predictions
python malware_analyzer/cli/commands.py ml coverage-report        # Coverage analysis

# Benchmarking
python scripts/benchmark_scan_matrix.py --workers 4 --malware-dir ./samples

# Reports
python malware_analyzer/cli/commands.py export csv               # Export features
```

