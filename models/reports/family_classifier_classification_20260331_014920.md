# Classification Report

- Timestamp (UTC): 2026-03-31T01:49:22.272264+00:00
- Model: models\family_classifier.joblib
- Confusion Matrix: models\reports\family_classifier_confusion_20260331_014920.png
- Accuracy: 0.6364
- F1 Macro: 0.4333
- Train rows: 217
- Test rows: 55
- Class count: 40

```text
                            precision    recall  f1-score   support

                ACRStealer     0.8571    1.0000    0.9231         6
                 AdaptixC2     0.0000    0.0000    0.0000         1
           Android.Generic     0.3333    1.0000    0.5000         1
Android.Riskware.Installer     0.5000    0.6667    0.5714         3
Android.Suspicious.Generic     0.0000    0.0000    0.0000         1
    Android.Trojan.Overlay     1.0000    0.5000    0.6667         2
                    Arsink     0.5000    0.6667    0.5714         3
                  AsyncRAT     1.0000    1.0000    1.0000         1
                 CoinMiner     0.0000    0.0000    0.0000         1
                    Floxif     0.0000    0.0000    0.0000         1
                     Heodo     1.0000    1.0000    1.0000         4
                  JackSkid     1.0000    1.0000    1.0000         2
                     Joker     1.0000    0.5000    0.6667         2
                   Kimwolf     0.0000    0.0000    0.0000         1
                     Mirai     0.0000    0.0000    0.0000         1
            PhantomStealer     0.0000    0.0000    0.0000         0
                 QuasarRAT     0.0000    0.0000    0.0000         1
                 RemcosRAT     1.0000    1.0000    1.0000         2
              RustyStealer     0.0000    0.0000    0.0000         1
              SalatStealer     0.0000    0.0000    0.0000         1
                  SheetRAT     1.0000    1.0000    1.0000         1
              Smoke Loader     0.0000    0.0000    0.0000         1
                   SpyNote     0.0000    0.0000    0.0000         2
                     Vidar     0.0000    0.0000    0.0000         1
                  WannaCry     1.0000    1.0000    1.0000         1
               Win.Generic     0.7500    0.5000    0.6000         6
      Win.Injector.Generic     0.5000    1.0000    0.6667         1
        Win.Packed.Generic     0.7143    1.0000    0.8333         5
    Win.Suspicious.Generic     1.0000    1.0000    1.0000         2
               Worm.Ramnit     0.0000    0.0000    0.0000         0

                  accuracy                         0.6364        55
                 macro avg     0.4385    0.4611    0.4333        55
              weighted avg     0.6190    0.6364    0.6103        55
```
