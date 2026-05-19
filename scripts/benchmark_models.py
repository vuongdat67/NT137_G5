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


def _build_preprocess(*, scale_numeric: bool) -> Any:
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder, StandardScaler

    num_steps: list[tuple[str, Any]] = [("imputer", SimpleImputer(strategy="median"))]
    if scale_numeric:
        num_steps.append(("scaler", StandardScaler()))

    preprocess = ColumnTransformer(
        transformers=[
            (
                "num",
                Pipeline(steps=num_steps),
                NUMERIC_FEATURES,
            ),
            (
                "cat",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
                    ]
                ),
                CATEGORICAL_FEATURES,
            ),
        ],
        sparse_threshold=0.0,
    )
    return preprocess


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
                    verbose=-1,
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


def _make_pipeline(spec: ModelSpec) -> Any:
    from sklearn.pipeline import Pipeline

    preprocess = _build_preprocess(scale_numeric=spec.scale_numeric)
    estimator = spec.builder()
    return Pipeline(
        steps=[
            ("preprocess", preprocess),
            ("classifier", estimator),
        ]
    )


def _feature_importance(model: Any, feature_names: list[str]) -> pd.DataFrame | None:
    classifier = model.named_steps.get("classifier") if hasattr(model, "named_steps") else None
    if classifier is None:
        return None

    importances = None
    if hasattr(classifier, "feature_importances_"):
        importances = np.array(classifier.feature_importances_, dtype=float)
    elif hasattr(classifier, "coef_"):
        coef = np.array(classifier.coef_, dtype=float)
        if coef.ndim == 1:
            importances = np.abs(coef)
        else:
            importances = np.mean(np.abs(coef), axis=0)

    if importances is None:
        return None

    if len(importances) != len(feature_names):
        return None

    frame = pd.DataFrame(
        {
            "feature": feature_names,
            "importance": importances,
        }
    )
    frame = frame.sort_values(by="importance", ascending=False).reset_index(drop=True)
    return frame


def run_benchmark(
    *,
    input_csv: Path,
    output_dir: Path,
    label_column: str,
    min_class_samples: int,
    max_class_samples: int,
    test_size: float,
) -> dict[str, Path]:
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix
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

    x = frame[FEATURE_COLUMNS].copy()
    y = frame[label_column].copy()

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=test_size,
        random_state=42,
        stratify=y,
    )

    label_encoder = LabelEncoder()
    label_encoder.fit(y)

    rows: list[dict[str, Any]] = []
    best_name = ""
    best_f1 = -1.0
    best_model = None
    best_y_pred = None

    for spec in _available_models():
        model = _make_pipeline(spec)
        start_train = time.perf_counter()
        if spec.name == "XGBoost":
            y_train_encoded = label_encoder.transform(y_train)
            model.fit(x_train, y_train_encoded)
        else:
            model.fit(x_train, y_train)
        train_time = time.perf_counter() - start_train

        start_infer = time.perf_counter()
        y_pred = model.predict(x_test)
        if spec.name == "XGBoost":
            y_pred = label_encoder.inverse_transform(y_pred)
        infer_time = time.perf_counter() - start_infer

        accuracy = float(accuracy_score(y_test, y_pred))
        f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
        precision = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
        recall = float(recall_score(y_test, y_pred, average="macro", zero_division=0))

        rows.append(
            {
                "model": spec.name,
                "accuracy": accuracy,
                "f1_macro": f1_macro,
                "precision_macro": precision,
                "recall_macro": recall,
                "train_time_s": round(train_time, 4),
                "infer_time_s": round(infer_time, 4),
            }
        )

        if f1_macro > best_f1:
            best_f1 = f1_macro
            best_name = spec.name
            best_model = model
            best_y_pred = y_pred

    summary = pd.DataFrame(rows)
    timestamp = datetime.now(tz=timezone.utc).strftime("%d.%m.%Y_%H.%M")
    output_dir.mkdir(parents=True, exist_ok=True)

    ranking_csv_path = output_dir / f"{timestamp}_models_rank_acc.csv"
    ranking_md_path = output_dir / f"{timestamp}_models_rank_acc.md"

    ranking = summary.sort_values(by="accuracy", ascending=False).reset_index(drop=True)
    ranking.to_csv(ranking_csv_path, index=False)
    try:
        ranking_md_text = ranking.to_markdown(index=False)
    except Exception:
        ranking_md_lines = []
        ranking_headers = list(ranking.columns)
        ranking_md_lines.append("| " + " | ".join(ranking_headers) + " |")
        ranking_md_lines.append("| " + " | ".join(["---"] * len(ranking_headers)) + " |")
        for _, row in ranking.iterrows():
            ranking_md_lines.append("| " + " | ".join(str(row[col]) for col in ranking_headers) + " |")
        ranking_md_text = "\n".join(ranking_md_lines)
    ranking_md_path.write_text(ranking_md_text, encoding="utf-8")

    confusion_path = output_dir / f"{timestamp}_models_best_confusion.png"
    features_path = output_dir / f"{timestamp}_models_best_features.csv"

    if best_model is not None and best_y_pred is not None:
        labels = sorted({str(item) for item in y.tolist()})
        cm = confusion_matrix(y_test, best_y_pred, labels=labels)

        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(10, 8))
        image = ax.imshow(cm, interpolation="nearest", cmap="Blues")
        fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
        ax.set_title(f"Confusion Matrix - {best_name}")
        ax.set_xlabel("Predicted")
        ax.set_ylabel("True")
        ax.set_xticks(range(len(labels)))
        ax.set_yticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=90, fontsize=7)
        ax.set_yticklabels(labels, fontsize=7)
        fig.tight_layout()
        fig.savefig(confusion_path, dpi=200)
        plt.close(fig)

        feature_names = list(best_model.named_steps["preprocess"].get_feature_names_out())
        importances = _feature_importance(best_model, feature_names)
        if importances is not None and not importances.empty:
            importances.head(40).to_csv(features_path, index=False)
        else:
            features_path = Path("")

    return {
        "ranking_accuracy_csv": ranking_csv_path,
        "ranking_accuracy_md": ranking_md_path,
        "confusion_png": confusion_path,
        "feature_importance_csv": features_path,
        "best_model": Path(best_name),
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark multiple ML models on exported features.")
    parser.add_argument("--input-csv", required=True, help="CSV exported from feature matrix.")
    parser.add_argument("--output-dir", default="output/benchmarks", help="Output directory.")
    parser.add_argument("--label-column", default="family", help="Label column name.")
    parser.add_argument("--min-class-samples", type=int, default=2, help="Minimum class samples.")
    parser.add_argument("--max-class-samples", type=int, default=0, help="Cap samples per class.")
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split ratio.")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    result = run_benchmark(
        input_csv=Path(args.input_csv),
        output_dir=Path(args.output_dir),
        label_column=str(args.label_column),
        min_class_samples=int(args.min_class_samples),
        max_class_samples=int(args.max_class_samples),
        test_size=float(args.test_size),
    )
    print("Benchmark summary:")
    for key, value in result.items():
        if value:
            print(f"- {key}: {value}")


if __name__ == "__main__":
    main()
