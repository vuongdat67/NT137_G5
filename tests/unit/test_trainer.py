from __future__ import annotations

import pandas as pd

from malware_analyzer.ml.trainer import (
    _cap_majority_classes,
    _drop_unknown_platform_rows,
    _filter_labels,
    _stable_order,
    _tune_confidence_threshold,
)


def test_stable_order_by_sha256_is_deterministic() -> None:
    frame = pd.DataFrame(
        [
            {"sha256": "bbb", "family": "A", "platform": "Windows", "source": "Local", "file_size": 2},
            {"sha256": "aaa", "family": "A", "platform": "Windows", "source": "Local", "file_size": 1},
            {"sha256": "ccc", "family": "B", "platform": "Android", "source": "MalwareBazaar", "file_size": 3},
        ]
    )

    ordered = _stable_order(frame, label_column="family")
    assert list(ordered["sha256"]) == ["aaa", "bbb", "ccc"]


def test_filter_labels_respects_min_class_samples() -> None:
    frame = pd.DataFrame(
        [
            {"family": "FamA"},
            {"family": "FamA"},
            {"family": "FamA"},
            {"family": "FamC"},
            {"family": "FamC"},
            {"family": "FamC"},
            {"family": "FamB"},
            {"family": "FamB"},
            {"family": "Unknown.Generic"},
        ]
    )

    filtered = _filter_labels(frame, label_column="family", min_class_samples=3)
    assert set(filtered["family"].tolist()) == {"FamA", "FamC"}


def test_drop_unknown_platform_rows_keeps_windows_android() -> None:
    frame = pd.DataFrame(
        [
            {"platform": "Windows", "family": "A"},
            {"platform": "Android", "family": "B"},
            {"platform": "Unknown", "family": "C"},
            {"platform": "", "family": "D"},
        ]
    )

    kept, dropped = _drop_unknown_platform_rows(frame)
    assert dropped == 2
    assert set(kept["platform"].tolist()) == {"Windows", "Android"}


def test_cap_majority_classes_reduces_imbalance() -> None:
    rows = []
    for i in range(20):
        rows.append({"sha256": f"a{i}", "family": "Major", "platform": "Windows", "source": "Local", "file_size": i})
    for i in range(4):
        rows.append({"sha256": f"b{i}", "family": "Minor", "platform": "Windows", "source": "Local", "file_size": i})

    frame = pd.DataFrame(rows)
    capped, dropped, ratio_before, ratio_after = _cap_majority_classes(frame, "family", max_class_samples=6)

    assert dropped == 14
    counts = capped["family"].value_counts().to_dict()
    assert int(counts.get("Major", 0)) == 6
    assert int(counts.get("Minor", 0)) == 4
    assert ratio_before > ratio_after


def test_tune_confidence_threshold_returns_valid_selection() -> None:
    confidences = [0.95, 0.90, 0.82, 0.77, 0.65, 0.55, 0.45, 0.30]
    correctness = [True, True, True, False, True, False, False, False]

    result = _tune_confidence_threshold(confidences, correctness, recall_target=0.50)

    assert 0.0 <= float(result.get("selected_threshold", -1.0)) <= 1.0
    assert str(result.get("selection_policy", "")) in {"recall_target", "best_f1_fallback"}
    assert float(result.get("precision", -1.0)) >= 0.0
    assert float(result.get("recall", -1.0)) >= 0.0
    assert isinstance(result.get("curve", []), list)