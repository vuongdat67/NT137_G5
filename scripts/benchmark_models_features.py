from __future__ import annotations

import argparse
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import numpy as np
import pandas as pd

from malware_analyzer.ml.trainer import (
    CATEGORICAL_FEATURES,
    FEATURE_COLUMNS,
    NUMERIC_FEATURES,
    _cap_majority_classes,
    _drop_unknown_platform_rows,
    _filter_labels,
    _normalize_columns,
    _stable_order,
)


@dataclass
class ModelSpec:
    name: str
    builder: Callable[[], Any]
    scale_numeric: bool = False


def _build_preprocess(*, numeric_features: list[str], categorical_features: list[str], scale_numeric: bool) -> Any:
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder, StandardScaler

    num_steps: list[tuple[str, Any]] = [(
        "imputer",
        SimpleImputer(strategy="median"),
    )]
    if scale_numeric:
        num_steps.append(("scaler", StandardScaler()))

    transformers: list[tuple[str, Any, list[str]]] = []
    if numeric_features:
        transformers.append((
            "num",
            Pipeline(steps=num_steps),
            numeric_features,
        ))
    if categorical_features:
        transformers.append((
            "cat",
            Pipeline(
                steps=[
                    ("imputer", SimpleImputer(strategy="most_frequent")),
                    ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
                ]
            ),
            categorical_features,
        ))

    return ColumnTransformer(
        transformers=transformers,
        sparse_threshold=0.0,
        remainder="drop",
    )


def _available_models() -> list[ModelSpec]:
    specs: list[ModelSpec] = []

    def _rf() -> Any:
        from sklearn.ensemble import RandomForestClassifier

        return RandomForestClassifier(
            n_estimators=400,
            max_depth=None,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=42,
            class_weight="balanced_subsample",
            n_jobs=-1,
        )

    def _dt() -> Any:
        from sklearn.tree import DecisionTreeClassifier

        return DecisionTreeClassifier(
            random_state=42,
            class_weight="balanced",
        )

    def _gb() -> Any:
        from sklearn.ensemble import GradientBoostingClassifier

        return GradientBoostingClassifier(random_state=42)

    def _svm() -> Any:
        from sklearn.svm import SVC

        return SVC(kernel="rbf", probability=True, class_weight="balanced", random_state=42)

    def _knn() -> Any:
        from sklearn.neighbors import KNeighborsClassifier

        return KNeighborsClassifier(n_neighbors=7)

    def _logreg() -> Any:
        from sklearn.linear_model import LogisticRegression

        return LogisticRegression(
            max_iter=2000,
            n_jobs=-1,
            class_weight="balanced",
            multi_class="auto",
        )

    def _mlp() -> Any:
        from sklearn.neural_network import MLPClassifier

        return MLPClassifier(
            hidden_layer_sizes=(128, 64),
            activation="relu",
            max_iter=300,
            random_state=42,
        )

    specs.extend(
        [
            ModelSpec("RandomForest", _rf),
            ModelSpec("DecisionTree", _dt),
            ModelSpec("GradientBoosting", _gb),
            ModelSpec("SVM_RBF", _svm, scale_numeric=True),
            ModelSpec("KNN", _knn, scale_numeric=True),
            ModelSpec("LogisticRegression", _logreg, scale_numeric=True),
            ModelSpec("MLP", _mlp, scale_numeric=True),
        ]
    )

    try:
        from lightgbm import LGBMClassifier  # type: ignore

        specs.append(
            ModelSpec(
                "LightGBM",
                lambda: LGBMClassifier(
                    n_estimators=400,
                    num_leaves=63,
                    max_depth=-1,
                    learning_rate=0.05,
                    subsample=0.9,
                    colsample_bytree=0.9,
                    random_state=42,
                ),
            )
        )
    except Exception:
        pass

    try:
        from xgboost import XGBClassifier  # type: ignore

        specs.append(
            ModelSpec(
                "XGBoost",
                lambda: XGBClassifier(
                    n_estimators=400,
                    max_depth=6,
                    learning_rate=0.05,
                    subsample=0.9,
                    colsample_bytree=0.9,
                    objective="multi:softprob",
                    eval_metric="mlogloss",
                    tree_method="hist",
                    random_state=42,
                ),
            )
        )
    except Exception:
        pass

    return specs


def _make_pipeline(spec: ModelSpec, numeric_features: list[str], categorical_features: list[str]) -> Any:
    from sklearn.pipeline import Pipeline

    preprocess = _build_preprocess(
        numeric_features=numeric_features,
        categorical_features=categorical_features,
        scale_numeric=spec.scale_numeric,
    )
    estimator = spec.builder()
    return Pipeline(
        steps=[
            ("preprocess", preprocess),
            ("classifier", estimator),
        ]
    )


def _infer_proba(model: Any, x_test: pd.DataFrame) -> np.ndarray | None:
    if hasattr(model, "predict_proba"):
        try:
            return model.predict_proba(x_test)
        except Exception:
            return None
    if hasattr(model, "decision_function"):
        try:
            return model.decision_function(x_test)
        except Exception:
            return None
    return None


def _roc_auc(y_true: np.ndarray, scores: np.ndarray | None) -> float | None:
    if scores is None:
        return None

    from sklearn.metrics import roc_auc_score

    if scores.ndim == 1:
        try:
            return float(roc_auc_score(y_true, scores))
        except Exception:
            return None

    try:
        return float(roc_auc_score(y_true, scores, multi_class="ovr", average="macro"))
    except Exception:
        return None


def _feature_group_map() -> dict[str, list[str]]:
    file_features = [
        "file_size",
        "packed",
        "local_score",
        "intel_score",
        "score",
        "heuristic_score",
    ]
    cfg_raw = [
        "cfg_nodes",
        "cfg_edges",
        "cfg_cyclomatic",
        "cfg_max_depth",
        "cfg_avg_depth",
        "cfg_loop_count",
        "cfg_scc_count",
    ]
    cfg_norm = [
        "cfg_nodes_per_kb",
        "cfg_cyclomatic_per_kb",
        "cfg_loop_density",
        "cfg_edge_density",
    ]
    strings_api = [
        "strings_total_count",
        "strings_b64_count",
        "api_risk_score",
    ]
    opcodes = [name for name in NUMERIC_FEATURES if name.startswith("op_")]

    groups = {
        "file": file_features,
        "cfg_raw": cfg_raw,
        "cfg_norm": cfg_norm,
        "cfg": [*cfg_raw, *cfg_norm],
        "strings_api": strings_api,
        "opcodes": opcodes,
        "categorical": list(CATEGORICAL_FEATURES),
        "all": list(FEATURE_COLUMNS),
    }

    all_features = list(FEATURE_COLUMNS)
    for key, values in list(groups.items()):
        if key in {"all", "categorical"}:
            continue
        groups[f"all_minus_{key}"] = [col for col in all_features if col not in values]

    groups["numeric_only"] = list(NUMERIC_FEATURES)
    groups["categorical_only"] = list(CATEGORICAL_FEATURES)
    return groups


def run_benchmark(
    *,
    input_csv: Path,
    output_dir: Path,
    label_column: str,
    min_class_samples: int,
    max_class_samples: int,
    test_size: float,
    groups: list[str] | None = None,
) -> dict[str, Path]:
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder

    if not os.environ.get("MPLBACKEND"):
        os.environ["MPLBACKEND"] = "Agg"
    mpl_cache_dir = output_dir / "mpl-cache"
    mpl_cache_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(mpl_cache_dir))

    frame_raw = pd.read_csv(input_csv)
    frame_filtered, _ = _drop_unknown_platform_rows(frame_raw)
    frame = _normalize_columns(frame_filtered)
    frame = _filter_labels(frame, label_column=label_column, min_class_samples=min_class_samples)
    frame, _, _, _ = _cap_majority_classes(frame, label_column=label_column, max_class_samples=max_class_samples)
    frame = _stable_order(frame, label_column=label_column)

    x_full = frame[FEATURE_COLUMNS].copy()
    y = frame[label_column].copy()

    x_train, x_test, y_train, y_test = train_test_split(
        x_full,
        y,
        test_size=test_size,
        random_state=42,
        stratify=y,
    )

    label_encoder = LabelEncoder()
    y_test_encoded = label_encoder.fit_transform(y_test)

    group_map = _feature_group_map()
    selected_groups = groups or ["all"]

    rows: list[dict[str, Any]] = []

    for group_name in selected_groups:
        if group_name not in group_map:
            raise ValueError(f"Unknown feature group: {group_name}")
        group_features = group_map[group_name]

        numeric_features = [name for name in group_features if name in NUMERIC_FEATURES]
        categorical_features = [name for name in group_features if name in CATEGORICAL_FEATURES]

        x_train_group = x_train[group_features].copy()
        x_test_group = x_test[group_features].copy()

        for spec in _available_models():
            model = _make_pipeline(spec, numeric_features, categorical_features)

            start_train = time.perf_counter()
            model.fit(x_train_group, y_train)
            train_time = time.perf_counter() - start_train

            start_infer = time.perf_counter()
            y_pred = model.predict(x_test_group)
            infer_time = time.perf_counter() - start_infer

            scores = _infer_proba(model, x_test_group)
            auc = _roc_auc(y_test_encoded, None if scores is None else np.array(scores))

            accuracy = float(accuracy_score(y_test, y_pred))
            f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
            precision = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
            recall = float(recall_score(y_test, y_pred, average="macro", zero_division=0))

            rows.append(
                {
                    "feature_group": group_name,
                    "model": spec.name,
                    "features": len(group_features),
                    "accuracy": accuracy,
                    "f1_macro": f1_macro,
                    "precision_macro": precision,
                    "recall_macro": recall,
                    "auc_roc": auc if auc is not None else "",
                    "train_time_s": round(train_time, 4),
                    "infer_time_s": round(infer_time, 4),
                }
            )

    summary = pd.DataFrame(rows)
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)

    csv_path = output_dir / f"benchmark_models_features_{timestamp}.csv"
    md_path = output_dir / f"benchmark_models_features_{timestamp}.md"
    summary.to_csv(csv_path, index=False)
    try:
        md_text = summary.to_markdown(index=False)
    except Exception:
        md_lines = []
        headers = list(summary.columns)
        md_lines.append("| " + " | ".join(headers) + " |")
        md_lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
        for _, row in summary.iterrows():
            md_lines.append("| " + " | ".join(str(row[col]) for col in headers) + " |")
        md_text = "\n".join(md_lines)
    md_path.write_text(md_text, encoding="utf-8")

    if not summary.empty:
        ranking = (
            summary.sort_values(by=["feature_group", "f1_macro", "accuracy"], ascending=[True, False, False])
            .groupby("feature_group", as_index=False)
            .head(1)
            .reset_index(drop=True)
        )
    else:
        ranking = summary.copy()

    ranking_csv = output_dir / f"benchmark_models_features_ranking_{timestamp}.csv"
    ranking_md = output_dir / f"benchmark_models_features_ranking_{timestamp}.md"
    ranking.to_csv(ranking_csv, index=False)
    try:
        ranking_md_text = ranking.to_markdown(index=False)
    except Exception:
        if ranking.empty:
            ranking_md_text = ""
        else:
            headers = list(ranking.columns)
            lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
            for _, row in ranking.iterrows():
                lines.append("| " + " | ".join(str(row[col]) for col in headers) + " |")
            ranking_md_text = "\n".join(lines)
    ranking_md.write_text(ranking_md_text, encoding="utf-8")

    return {
        "summary_csv": csv_path,
        "summary_md": md_path,
        "ranking_csv": ranking_csv,
        "ranking_md": ranking_md,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark ML models across feature groups (ablation).",
    )
    parser.add_argument("--input-csv", required=True, help="CSV exported from feature matrix.")
    parser.add_argument("--output-dir", default="output/benchmarks", help="Output directory.")
    parser.add_argument("--label-column", default="family", help="Label column name.")
    parser.add_argument("--min-class-samples", type=int, default=2, help="Minimum class samples.")
    parser.add_argument("--max-class-samples", type=int, default=0, help="Cap samples per class.")
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split ratio.")
    parser.add_argument(
        "--groups",
        default="all,file,cfg,strings_api,opcodes,categorical",
        help=(
            "Comma-separated feature groups. "
            "Options: file,cfg,cfg_raw,cfg_norm,strings_api,opcodes,categorical,"
            "all,all_minus_file,all_minus_cfg_raw,all_minus_cfg_norm,all_minus_strings_api,"
            "all_minus_opcodes,numeric_only,categorical_only"
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    group_list = [item.strip() for item in str(args.groups).split(",") if item.strip()]
    result = run_benchmark(
        input_csv=Path(args.input_csv),
        output_dir=Path(args.output_dir),
        label_column=str(args.label_column),
        min_class_samples=int(args.min_class_samples),
        max_class_samples=int(args.max_class_samples),
        test_size=float(args.test_size),
        groups=group_list,
    )
    print("Benchmark summary:")
    for key, value in result.items():
        if value:
            print(f"- {key}: {value}")


if __name__ == "__main__":
    main()
