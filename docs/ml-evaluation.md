# ML Evaluation — Isolation Forest Anomaly Detector

Reproducible via:

```bash
cd backend && source .venv/bin/activate
python3 ../ml/data/generate_dataset.py
python3 ../ml/training/train.py
python3 ../ml/evaluation/evaluate.py
```

## Dataset

Synthetic (SentinelAI has no production access history yet): 4,000 "normal"
office-hours behavioral samples + 500 anomalous samples modeled on the four
README §16 attack scenarios (mass download/exfiltration, unusual-hour +
unknown-device, privilege abuse via denied-request ratio, brute-force
follow-up). See `ml/data/generate_dataset.py` for the generation logic and
`backend/app/risk/features.py` for the 9-feature schema both training and the
live risk engine share.

The Isolation Forest is trained **unsupervised**, on normal rows only (80% of
the 4,000) — standard anomaly-detection practice. The label column is used
only to measure performance afterward, on the held-out 20% of normal rows
plus all 500 anomalous rows (1,300 test rows total).

## Results (measured, `ml/evaluation/results.json`)

| Metric | Value |
|---|---|
| Precision | 83.45% |
| Recall | 98.80% |
| F1 Score | 90.48% |
| False Positive Rate | 12.25% |
| ROC-AUC | 0.9907 |

Confusion matrix (1,300 test rows): TN=702, FP=98, FN=6, TP=494.

## Interpretation

High recall (98.8%) with a materially lower precision (83.5%) is the expected
shape for this kind of detector: missing a real insider-threat/compromise
event (false negative) is far more costly than an extra manual review of a
flagged-but-benign session (false positive), so the model is tuned (via
`contamination`, set to the dataset's actual anomaly ratio) toward catching
anomalies rather than minimizing false alarms. The 12.25% false-positive rate
is why the risk engine blends this ML score with the rule-based score instead
of acting on it alone (see `docs/architecture.md`), and why the response
table (README §8) reserves hard blocking for the top risk band rather than
every flagged session.

These numbers reflect the synthetic dataset's attack patterns, not real
production traffic — if SentinelAI collects real access logs, retrain and
re-evaluate on that data before relying on these figures.
