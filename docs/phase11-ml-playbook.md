# Phase 11 ML Playbook

## Scope
This playbook implements the practical baseline for Phase 11:
- Train classifier from exported feature matrix CSV.
- Save model artifact.
- Run optional prediction during scanning.

## What is now available
- CLI command: ml train
- CLI command: ml report-latest
- CLI command: ml backfill
- CLI command: ml coverage
- Trainer module: malware_analyzer/ml/trainer.py
- Predictor module: malware_analyzer/ml/predictor.py
- Scan integration: scanner now enriches features with optional ML predictions when model exists.

## Install ML dependencies
Use project optional extra:
- pip install .[ml]

## Step 1: Export training data
From repository root code:
- python main.py db export --format feature-matrix --output output/phase11_features.csv

## Step 2: Train baseline model
- python main.py ml train --input-csv output/phase11_features.csv --output-model models/family_classifier.joblib --algorithm auto

Algorithms supported:
- auto: prefers lightgbm if installed, else random forest.
- lightgbm
- rf

## Step 3: Use model during scan
When model file exists at models/family_classifier.joblib, scan pipeline will add:
- ml_family
- ml_confidence
- ml_score

If model is missing or dependencies are absent, scan continues normally without failing.

## Step 4: Backfill ML for existing DB samples (no rescan)
- Backfill all rows:
  - python main.py ml backfill
- Backfill with filter:
  - python main.py ml backfill --source MalwareBazaar --platform Windows
- Force overwrite existing ML fields:
  - python main.py ml backfill --overwrite

## Step 5: Generate latest report and coverage summary
- Latest training report:
  - python main.py ml report-latest
- Coverage stats by source/family:
  - python main.py ml coverage
- Coverage markdown for demo report:
  - python main.py ml coverage --output-md models/reports/ml_coverage.md

## Data requirements
- label column default is family.
- rows with empty or Unknown labels are filtered out.
- each class must have at least 2 rows for training.

## Suggested evaluation discipline
- Track at least:
  - f1_macro
  - accuracy
  - class_count
  - train_rows and test_rows
- Keep a model log with dataset export filename, training timestamp, and metrics.

## Remaining TODO items
1. Add threshold tuning and calibration strategy for low-confidence predictions.
2. Add periodic retraining workflow tied to curated sample updates.
