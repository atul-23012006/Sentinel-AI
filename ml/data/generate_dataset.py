"""Synthesizes a labeled behavioral dataset for training/evaluating the
Isolation Forest anomaly detector (README §7, §17).

SentinelAI has no production access-log history yet (it's a new system), so
this generates realistic feature vectors instead: a majority of "normal"
office-hours sessions, plus labeled anomalous sessions modeled directly on
the four attack scenarios in README §16 (brute force, credential compromise,
mass download / exfiltration, privilege abuse via denied-request ratio).
The label column is used ONLY for evaluation (precision/recall/F1) - the
Isolation Forest itself is trained unsupervised on the normal rows, which is
standard practice for anomaly detection (see Al-Shehari et al., IEEE Access
2023, reviewed in Review 1's literature review).

Usage: python ml/data/generate_dataset.py [--rows-normal N] [--rows-anomalous N]
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND_DIR))
from app.risk.features import FEATURE_NAMES  # noqa: E402

OUTPUT_PATH = Path(__file__).resolve().parent / "dataset.csv"


def _clip(arr, lo, hi):
    return np.clip(arr, lo, hi)


def generate_normal(n: int, rng: np.random.Generator) -> pd.DataFrame:
    login_hour = rng.integers(8, 19, size=n)  # office hours, inclusive-ish
    events_last_hour = _clip(rng.poisson(3, size=n), 0, 8)
    distinct_resources_last_hour = _clip((events_last_hour * rng.uniform(0.4, 0.8, size=n)).round(), 0, 5)
    downloads_last_hour = _clip(rng.poisson(0.5, size=n), 0, 2)
    denied_ratio_last_24h = _clip(rng.beta(1, 20, size=n), 0, 0.2)
    failed_login_count = rng.choice([0, 0, 0, 1], size=n)
    new_device = rng.choice([0, 0, 0, 0, 1], size=n)
    new_location = rng.choice([0, 0, 0, 0, 1], size=n)
    outside_business_hours = (login_hour < 9) | (login_hour >= 18)

    df = pd.DataFrame(
        {
            "login_hour": login_hour,
            "events_last_hour": events_last_hour,
            "distinct_resources_last_hour": distinct_resources_last_hour,
            "downloads_last_hour": downloads_last_hour,
            "denied_ratio_last_24h": denied_ratio_last_24h,
            "failed_login_count": failed_login_count,
            "new_device": new_device,
            "new_location": new_location,
            "outside_business_hours": outside_business_hours.astype(int),
        }
    )
    df["label"] = 0
    return df


def generate_anomalous(n: int, rng: np.random.Generator) -> pd.DataFrame:
    # Split roughly evenly across the four README §16 attack patterns.
    subtype = rng.choice(
        ["mass_download", "unusual_hour_device", "privilege_abuse", "brute_force_followup"], size=n
    )

    login_hour = np.where(
        np.isin(subtype, ["unusual_hour_device", "brute_force_followup"]),
        rng.integers(0, 6, size=n),
        rng.integers(0, 24, size=n),
    )
    events_last_hour = np.where(
        subtype == "mass_download", _clip(rng.poisson(20, size=n), 10, 60), _clip(rng.poisson(6, size=n), 1, 20)
    )
    distinct_resources_last_hour = _clip((events_last_hour * rng.uniform(0.5, 1.0, size=n)).round(), 1, 50)
    downloads_last_hour = np.where(
        subtype == "mass_download", _clip(rng.poisson(14, size=n), 6, 40), _clip(rng.poisson(1, size=n), 0, 4)
    )
    denied_ratio_last_24h = np.where(
        np.isin(subtype, ["privilege_abuse", "brute_force_followup"]),
        _clip(rng.beta(4, 3, size=n), 0.3, 1.0),
        _clip(rng.beta(1, 10, size=n), 0, 0.4),
    )
    failed_login_count = np.where(
        subtype == "brute_force_followup", rng.integers(3, 6, size=n), rng.choice([0, 0, 1, 2], size=n)
    )
    new_device = np.where(
        subtype == "unusual_hour_device", 1, rng.choice([0, 1], size=n, p=[0.6, 0.4])
    )
    new_location = np.where(
        subtype == "unusual_hour_device", rng.choice([0, 1], size=n, p=[0.3, 0.7]), rng.choice([0, 1], size=n, p=[0.7, 0.3])
    )
    outside_business_hours = (login_hour < 9) | (login_hour >= 18)

    df = pd.DataFrame(
        {
            "login_hour": login_hour,
            "events_last_hour": events_last_hour,
            "distinct_resources_last_hour": distinct_resources_last_hour,
            "downloads_last_hour": downloads_last_hour,
            "denied_ratio_last_24h": denied_ratio_last_24h,
            "failed_login_count": failed_login_count,
            "new_device": new_device.astype(int),
            "new_location": new_location.astype(int),
            "outside_business_hours": outside_business_hours.astype(int),
            "subtype": subtype,
        }
    )
    df["label"] = 1
    return df


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows-normal", type=int, default=4000)
    parser.add_argument("--rows-anomalous", type=int, default=500)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)
    normal = generate_normal(args.rows_normal, rng)
    anomalous = generate_anomalous(args.rows_anomalous, rng)
    anomalous_aligned = anomalous[[*FEATURE_NAMES, "label", "subtype"]]
    normal_aligned = normal[[*FEATURE_NAMES, "label"]]
    normal_aligned["subtype"] = "normal"

    dataset = pd.concat([normal_aligned, anomalous_aligned], ignore_index=True)
    dataset = dataset.sample(frac=1, random_state=args.seed).reset_index(drop=True)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(OUTPUT_PATH, index=False)
    print(f"Wrote {len(dataset)} rows ({len(normal)} normal, {len(anomalous)} anomalous) to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
