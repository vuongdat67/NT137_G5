# Classification Report

- Timestamp (UTC): 2026-05-17T07:21:01.003467+00:00
- Model: models/family_classifier.joblib
- Confusion Matrix: models/reports/family_classifier_confusion_20260517_072056.png
- PR Curve: models/reports/family_classifier_pr_curve_20260517_072056.png
- Accuracy: 0.9445
- F1 Macro: 0.4896
- Train rows: 2596
- Test rows: 649
- Class count: 47

## Threshold Tuning

- Selected threshold: 1.0000
- Selection policy: recall_target
- Recall target: 0.9000
- Precision at selected threshold: 0.9445
- Recall at selected threshold: 0.9445
- F1 at selected threshold: 0.9445
- Coverage at selected threshold: 1.0000

```text
                            precision    recall  f1-score   support

                ACRStealer     0.6667    1.0000    0.8000         2
                 AdaptixC2     0.0000    0.0000    0.0000         1
           Android.Generic     1.0000    0.3333    0.5000         3
Android.Riskware.Installer     0.8333    0.8333    0.8333         6
Android.Suspicious.Generic     0.0000    0.0000    0.0000         1
    Android.Trojan.Overlay     1.0000    0.5000    0.6667         4
                    Arsink     0.6667    0.6667    0.6667         3
                  AsyncRAT     1.0000    1.0000    1.0000         2
                 CoinMiner     0.0000    0.0000    0.0000         1
               ConnectWise     1.0000    1.0000    1.0000         1
                     DCRat     0.0000    0.0000    0.0000         0
                  Formbook     0.0000    0.0000    0.0000         1
                  GuLoader     0.0000    0.0000    0.0000         0
                  JackSkid     0.6667    1.0000    0.8000         2
                     Joker     0.3333    1.0000    0.5000         2
                   Kimwolf     0.3333    1.0000    0.5000         1
              LummaStealer     1.0000    1.0000    1.0000         1
                     Mirai     0.0000    0.0000    0.0000         1
               MossadProxy     0.0000    0.0000    0.0000         0
                 OffLoader     0.5000    1.0000    0.6667         1
            PhantomStealer     0.0000    0.0000    0.0000         1
                  Phorpiex     0.0000    0.0000    0.0000         1
                 QuasarRAT     0.5000    1.0000    0.6667         1
                 RemcosRAT     1.0000    0.5000    0.6667         2
              RustyStealer     1.0000    0.5000    0.6667         2
              SalatStealer     0.7500    1.0000    0.8571         3
                  SheetRAT     1.0000    1.0000    1.0000         1
              Smoke Loader     0.0000    0.0000    0.0000         1
              SnappyClient     0.0000    0.0000    0.0000         0
                   SpyNote     0.0000    0.0000    0.0000         2
                    Stealc     0.0000    0.0000    0.0000         1
                 ValleyRAT     1.0000    0.5000    0.6667         2
                     Vidar     0.3333    0.3333    0.3333         3
                  WannaCry     1.0000    1.0000    1.0000         1
               Win.Generic     0.9894    0.9868    0.9881       378
      Win.Injector.Generic     0.9231    0.9231    0.9231        52
        Win.Packed.Generic     0.9589    0.9859    0.9722       142
    Win.Suspicious.Generic     1.0000    0.8696    0.9302        23

                  accuracy                         0.9445       649
                 macro avg     0.5120    0.5245    0.4896       649
              weighted avg     0.9477    0.9445    0.9426       649
```
