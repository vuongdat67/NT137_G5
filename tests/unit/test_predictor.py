from __future__ import annotations

from pathlib import Path

import joblib

from malware_analyzer.ml import predictor


class _DummyModel:
    def __init__(self, label: str, confidence: float) -> None:
        self.label = label
        self.confidence = float(confidence)

    def predict(self, frame):  # noqa: ANN001
        return [self.label for _ in range(len(frame))]

    def predict_proba(self, frame):  # noqa: ANN001
        return [[self.confidence, 1.0 - self.confidence] for _ in range(len(frame))]


def _write_bundle(path: Path, *, samples: int, class_count: int, label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "pipeline": _DummyModel(label=label, confidence=0.9),
        "feature_columns": ["platform", "source"],
        "metrics": {
            "train_rows": int(samples * 0.8),
            "test_rows": int(samples * 0.2),
            "class_count": class_count,
            "f1_macro": 0.8,
        },
        "classes": [f"Family{i}" for i in range(max(class_count, 1))],
    }
    joblib.dump(bundle, path)


def test_predictor_ignores_default_model_when_bundle_too_small(tmp_path: Path, monkeypatch) -> None:
    default_model = tmp_path / "family_classifier.joblib"
    _write_bundle(default_model, samples=20, class_count=2, label="TooSmall")

    predictor._bundle_cache = None
    monkeypatch.setattr(predictor, "DEFAULT_MODEL_PATH", default_model)

    result = predictor.predict_from_features({"platform": "Windows", "source": "Local"})
    assert result is None


def test_predictor_prefers_stronger_versioned_bundle_when_default_is_weak(tmp_path: Path, monkeypatch) -> None:
    default_model = tmp_path / "family_classifier.joblib"
    strong_model = tmp_path / "family_classifier_20260101_000000.joblib"

    _write_bundle(default_model, samples=20, class_count=2, label="Weak")
    _write_bundle(strong_model, samples=240, class_count=18, label="Strong")

    predictor._bundle_cache = None
    monkeypatch.setattr(predictor, "DEFAULT_MODEL_PATH", default_model)

    result = predictor.predict_from_features({"platform": "Windows", "source": "Local"})
    assert result is not None
    assert str(result.get("ml_family")) == "Strong"


def test_predictor_rejects_low_f1_bundle_at_runtime(tmp_path: Path, monkeypatch) -> None:
    model = tmp_path / "family_classifier.joblib"
    _write_bundle(model, samples=240, class_count=18, label="LowQuality")

    bundle = joblib.load(model)
    bundle["metrics"]["f1_macro"] = 0.45
    joblib.dump(bundle, model)

    predictor._bundle_cache = None
    monkeypatch.setattr(predictor, "DEFAULT_MODEL_PATH", model)

    result = predictor.predict_from_features({"platform": "Windows", "source": "Local"})
    assert result is None


def test_predictor_applies_selected_confidence_threshold(tmp_path: Path, monkeypatch) -> None:
    model = tmp_path / "family_classifier.joblib"
    _write_bundle(model, samples=240, class_count=18, label="Thresholded")

    bundle = joblib.load(model)
    bundle["threshold_tuning"] = {"selected_threshold": 0.95}
    joblib.dump(bundle, model)

    predictor._bundle_cache = None
    monkeypatch.setattr(predictor, "DEFAULT_MODEL_PATH", model)

    result = predictor.predict_from_features({"platform": "Windows", "source": "Local"})
    assert result is None