# Classification Report

- Timestamp (UTC): 2026-05-11T08:08:53.481688+00:00
- Model: /Users/ngaphan/Library/Mobile Documents/iCloud~md~obsidian/Documents/CTFOb/01 - Subject/Kì 6/NT137-Kỹ thuật phân tích mã độc/NT137_G5/models/family_classifier.joblib
- Confusion Matrix: /Users/ngaphan/Library/Mobile Documents/iCloud~md~obsidian/Documents/CTFOb/01 - Subject/Kì 6/NT137-Kỹ thuật phân tích mã độc/NT137_G5/models/reports/family_classifier_confusion_20260511_080848.png
- PR Curve: /Users/ngaphan/Library/Mobile Documents/iCloud~md~obsidian/Documents/CTFOb/01 - Subject/Kì 6/NT137-Kỹ thuật phân tích mã độc/NT137_G5/models/reports/family_classifier_pr_curve_20260511_080848.png
- Accuracy: 0.9445
- F1 Macro: 0.4830
- Train rows: 2596
- Test rows: 649
- Class count: 47

## Threshold Tuning

- Selected threshold: 0.5205
- Selection policy: recall_target
- Recall target: 0.9000
- Precision at selected threshold: 0.9866
- Recall at selected threshold: 0.9060
- F1 at selected threshold: 0.9446
- Coverage at selected threshold: 0.9183

```text
                            precision    recall  f1-score   support

                ACRStealer     1.0000    1.0000    1.0000         2
                 AdaptixC2     0.0000    0.0000    0.0000         1
           Android.Generic     1.0000    0.6667    0.8000         3
Android.Riskware.Installer     1.0000    0.8333    0.9091         6
Android.Suspicious.Generic     0.0000    0.0000    0.0000         1
    Android.Trojan.Overlay     0.4444    1.0000    0.6154         4
                    Arsink     0.7500    1.0000    0.8571         3
                  AsyncRAT     1.0000    1.0000    1.0000         2
                 CoinMiner     0.0000    0.0000    0.0000         1
               ConnectWise     0.5000    1.0000    0.6667         1
              DarkTortilla     0.0000    0.0000    0.0000         0
                  Formbook     1.0000    1.0000    1.0000         1
                     Fuery     0.0000    0.0000    0.0000         0
                  JackSkid     0.5000    0.5000    0.5000         2
                     Joker     0.0000    0.0000    0.0000         2
                   Kimwolf     1.0000    1.0000    1.0000         1
              LummaStealer     0.5000    1.0000    0.6667         1
                     Mirai     0.0000    0.0000    0.0000         1
               MossadProxy     0.0000    0.0000    0.0000         0
                 OffLoader     0.5000    1.0000    0.6667         1
            PhantomStealer     0.0000    0.0000    0.0000         1
                  Phorpiex     0.0000    0.0000    0.0000         1
                 QuasarRAT     0.0000    0.0000    0.0000         1
                 RemcosRAT     0.0000    0.0000    0.0000         2
              RustyStealer     1.0000    0.5000    0.6667         2
              SalatStealer     0.7500    1.0000    0.8571         3
                  SheetRAT     1.0000    1.0000    1.0000         1
              Smoke Loader     0.0000    0.0000    0.0000         1
                   SpyNote     1.0000    0.5000    0.6667         2
                    Stealc     0.0000    0.0000    0.0000         1
                     VENON     0.0000    0.0000    0.0000         0
                 ValleyRAT     0.3333    0.5000    0.4000         2
                     Vidar     0.2500    0.3333    0.2857         3
                  WannaCry     1.0000    1.0000    1.0000         1
               Win.Generic     0.9868    0.9868    0.9868       378
      Win.Injector.Generic     0.9574    0.8654    0.9091        52
        Win.Packed.Generic     0.9792    0.9930    0.9860       142
    Win.Suspicious.Generic     0.9130    0.9130    0.9130        23

                  accuracy                         0.9445       649
                 macro avg     0.4833    0.5156    0.4830       649
              weighted avg     0.9461    0.9445    0.9431       649
```
