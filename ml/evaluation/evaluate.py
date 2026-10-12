"""Evaluates the trained Isolation Forest model (README §17) and writes
precision/recall/F1/false-positive-rate/confusion-matrix results to
ml/evaluation/results.json. Metrics are measured on held-out data generated
at train time - never fabricated (see SentinelAI_README.md §17).

Usage: python ml/evaluation/evaluate.py
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

ML_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ML_DIR.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))
from app.risk.features import FEATURE_NAMES  # noqa: E402

DATASET_PATH = ML_DIR / "data" / "dataset.csv"
MODEL_PATH = ML_DIR / "models" / "isolation_forest.joblib"
RESULTS_PATH = ML_DIR / "evaluation" / "results.json"
RANDOM_STATE = 42


def main():
    if not MODEL_PATH.exists():
        sys.exit(f"Model not found at {MODEL_PATH} - run ml/training/train.py first")

    model = joblib.load(MODEL_PATH)
    df = pd.read_csv(DATASET_PATH)
    X = df[FEATURE_NAMES].to_numpy(dtype=float)
    y = df["label"].to_numpy(dtype=int)

    # Reconstruct the same held-out test split used in training (same seed).
    normal_idx = np.where(y == 0)[0]
    anomalous_idx = np.where(y == 1)[0]
    _, test_normal_idx = train_test_split(normal_idx, test_size=0.2, random_state=RANDOM_STATE)
    test_idx = np.concatenate([test_normal_idx, anomalous_idx])
    X_test, y_test = X[test_idx], y[test_idx]

    raw_pred = model.predict(X_test)  # 1 = normal, -1 = anomaly
    y_pred = (raw_pred == -1).astype(int)
    scores = model.decision_function(X_test)  # higher = more normal

    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    # roc_auc_score wants higher score = more positive class (anomaly), so negate.
    roc_auc = roc_auc_score(y_test, -scores)

    results = {
        "model": "IsolationForest",
        "test_rows": int(len(X_test)),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "roc_auc": round(float(roc_auc), 4),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }

    RESULTS_PATH.write_text(json.dumps(results, indent=2))

    print("Model: Isolation Forest")
    print(f"Precision:        {precision:.2%}")
    print(f"Recall:           {recall:.2%}")
    print(f"F1 Score:         {f1:.2%}")
    print(f"False Positive:   {fpr:.2%}")
    print(f"ROC-AUC:          {roc_auc:.4f}")
    print(f"Confusion matrix: TN={tn} FP={fp} FN={fn} TP={tp}")
    print(f"Results written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
