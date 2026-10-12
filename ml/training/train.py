"""Trains the Isolation Forest anomaly-detection model (README §7.2) on the
synthetic behavioral dataset (ml/data/generate_dataset.py) and ships the
artifact to backend/app/risk/artifacts/ so the live RiskEngine can load it.

Standard anomaly-detection practice: fit only on normal (label=0) rows so the
model learns what "normal" looks like, then let decision_function() score
everything (including held-out anomalies) by how far it deviates from that.

Usage: python ml/training/train.py
"""

import json
import shutil
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

ML_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ML_DIR.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))
from app.risk.features import FEATURE_NAMES  # noqa: E402

DATASET_PATH = ML_DIR / "data" / "dataset.csv"
MODEL_DIR = ML_DIR / "models"
MODEL_PATH = MODEL_DIR / "isolation_forest.joblib"
METADATA_PATH = MODEL_DIR / "isolation_forest.json"
ARTIFACT_DIR = BACKEND_DIR / "app" / "risk" / "artifacts"

RANDOM_STATE = 42


def main():
    if not DATASET_PATH.exists():
        sys.exit(f"Dataset not found at {DATASET_PATH} - run ml/data/generate_dataset.py first")

    df = pd.read_csv(DATASET_PATH)
    X = df[FEATURE_NAMES].to_numpy(dtype=float)
    y = df["label"].to_numpy(dtype=int)

    # Fit on normal data only (unsupervised anomaly detection). Hold out 20%
    # of normal rows + all anomalous rows for ml/evaluation/evaluate.py.
    normal_idx = np.where(y == 0)[0]
    anomalous_idx = np.where(y == 1)[0]
    train_idx, test_normal_idx = train_test_split(normal_idx, test_size=0.2, random_state=RANDOM_STATE)

    X_train = X[train_idx]
    test_idx = np.concatenate([test_normal_idx, anomalous_idx])
    X_test, y_test = X[test_idx], y[test_idx]

    model = IsolationForest(
        n_estimators=200,
        contamination=len(anomalous_idx) / len(X),
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train)

    all_scores = model.decision_function(X)
    test_scores = model.decision_function(X_test)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    metadata = {
        "feature_names": FEATURE_NAMES,
        "n_estimators": model.n_estimators,
        "contamination": model.contamination,
        "random_state": RANDOM_STATE,
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "decision_score_min": float(all_scores.min()),
        "decision_score_max": float(all_scores.max()),
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2))

    # Ship the artifact to the backend so RiskEngine (app/risk/engine.py) can
    # load it without the backend depending on the ml/ package at runtime.
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy(MODEL_PATH, ARTIFACT_DIR / MODEL_PATH.name)
    shutil.copy(METADATA_PATH, ARTIFACT_DIR / METADATA_PATH.name)

    print(f"Trained on {len(X_train)} normal rows, held out {len(X_test)} rows for evaluation.")
    print(f"decision_function range on test set: [{test_scores.min():.4f}, {test_scores.max():.4f}]")
    print(f"Model + metadata written to {MODEL_DIR} and copied to {ARTIFACT_DIR}")


if __name__ == "__main__":
    main()
