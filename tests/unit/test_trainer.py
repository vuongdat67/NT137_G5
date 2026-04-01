from __future__ import annotations

import pandas as pd

from malware_analyzer.ml.trainer import _drop_unknown_platform_rows, _filter_labels, _stable_order


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