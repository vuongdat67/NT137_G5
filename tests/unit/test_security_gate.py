from __future__ import annotations

from pathlib import Path

from malware_analyzer.ml.security_gate import (
    _normalize_binary_label,
    _tune_binary_threshold,
    predict_security_gate,
)


class _DummyBinaryModel:
    def __init__(self, malware_probability: float) -> None:
        self.malware_probability = float(malware_probability)
        self.classes_ = [0, 1]

    def predict_proba(self, frame):  # noqa: ANN001
        out = []
        for _ in range(len(frame)):
            p = max(0.0, min(1.0, self.malware_probability))
            out.append([1.0 - p, p])
        return out


def test_normalize_binary_label() -> None:
    assert _normalize_binary_label("malware") == 1
    assert _normalize_binary_label("benign") == 0
    assert _normalize_binary_label("1") == 1
    assert _normalize_binary_label("0") == 0
    assert _normalize_binary_label("unknown") is None


def test_tune_binary_threshold_returns_valid_payload() -> None:
    probabilities = [0.9, 0.8, 0.7, 0.4, 0.2, 0.1]
    y_true = [1, 1, 1, 0, 0, 0]

    result = _tune_binary_threshold(probabilities, y_true, recall_target=0.8)

    assert 0.0 <= float(result.get("selected_threshold", -1.0)) <= 1.0
    assert str(result.get("selection_policy", "")) in {"recall_target", "best_f1_fallback"}
    assert float(result.get("precision", -1.0)) >= 0.0
    assert float(result.get("recall", -1.0)) >= 0.0
    assert isinstance(result.get("curve", []), list)


def test_predict_security_gate_uses_selected_threshold(monkeypatch, tmp_path: Path) -> None:
    model_path = tmp_path / "security_gate.joblib"

    bundle = {
        "kind": "binary_security_gate",
        "feature_columns": ["platform", "source", "file_size"],
        "pipeline": _DummyBinaryModel(malware_probability=0.85),
        "threshold_tuning": {"selected_threshold": 0.9},
    }

    from malware_analyzer.ml import security_gate as gate_mod

    monkeypatch.setattr(gate_mod, "load_security_gate_bundle", lambda _: bundle)

    result = predict_security_gate(
        {
            "platform": "Windows",
            "source": "Local",
            "file_size": 1234,
        },
        model_path=model_path,
    )

    assert result is not None
    assert bool(result.get("ml_security_is_malware", True)) is False
    assert str(result.get("ml_security_verdict", "")) == "benign"
