# Classification Report

- Timestamp (UTC): 2026-04-03T01:49:43.210897+00:00
- Model: models\family_classifier.joblib
- Confusion Matrix: models\reports\family_classifier_confusion_20260403_014941.png
- PR Curve: models\reports\family_classifier_pr_curve_20260403_014941.png
- Accuracy: 0.9727
- F1 Macro: 0.8769
- Train rows: 876
- Test rows: 220
- Class count: 12

## Threshold Tuning

- Selected threshold: 0.9942
- Selection policy: recall_target
- Recall target: 0.9000
- Precision at selected threshold: 0.9852
- Recall at selected threshold: 0.9091
- F1 at selected threshold: 0.9456
- Coverage at selected threshold: 0.9227

```text
                            precision    recall  f1-score   support

                ACRStealer     1.0000    1.0000    1.0000         2
           Android.Generic     1.0000    0.6667    0.8000         3
Android.Riskware.Installer     1.0000    0.8333    0.9091         6
    Android.Trojan.Overlay     0.6667    1.0000    0.8000         4
                    Arsink     0.7500    1.0000    0.8571         3
                  JackSkid     1.0000    0.5000    0.6667         2
              SalatStealer     1.0000    0.5000    0.6667         2
                     Vidar     0.7500    1.0000    0.8571         3
               Win.Generic     0.9672    0.9833    0.9752        60
      Win.Injector.Generic     1.0000    0.9808    0.9903        52
        Win.Packed.Generic     1.0000    1.0000    1.0000        60
    Win.Suspicious.Generic     1.0000    1.0000    1.0000        23

                  accuracy                         0.9727       220
                 macro avg     0.9278    0.8720    0.8769       220
              weighted avg     0.9782    0.9727    0.9721       220
```
