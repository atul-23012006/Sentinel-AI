"""Behavioral risk scoring (README §7/§8).

Produces a 0-100 risk score for the access attempt currently in flight by
blending two signals:

  - A documented, deterministic rule-based score (README §8's point table),
    which also doubles as a human-readable list of risk factors for the AI
    analyst (app/ai/service.py) and for admins reading an alert directly.
  - An Isolation Forest anomaly score (README §7.2), trained offline by
    ml/training/train.py on the same feature vector (app/risk/features.py)
    and shipped as a model artifact.

If no trained model artifact is present (e.g. a fresh checkout before
`ml/training/train.py` has been run), the engine degrades to the rule-based
score alone rather than failing - the risk engine must always return a
score since every access decision depends on it.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import settings
from app.models import User
from app.risk.features import RawFeatures, extract_features

# Points per README §8. Multiple bands within one factor are not stacked -
# only the highest matching band for that factor contributes.
_EVENTS_PER_HOUR_BANDS = [(20, 30, "Very high access frequency"), (10, 15, "Elevated access frequency")]
_DOWNLOAD_BANDS = [(6, 25, "Mass downloads"), (3, 10, "Elevated downloads")]

ML_WEIGHT = 0.6
RULE_WEIGHT = 0.4


@dataclass
class RiskResult:
    score: int
    reasons: list[str] = field(default_factory=list)
    raw_features: dict[str, float] = field(default_factory=dict)
    model_used: bool = False


def rule_based_score(raw: RawFeatures) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    if raw.outside_business_hours:
        score += 20
        reasons.append(f"Access at hour {raw.login_hour:02d}:00 is outside normal business hours (+20)")

    for threshold, points, label in _EVENTS_PER_HOUR_BANDS:
        if raw.events_last_hour >= threshold:
            score += points
            reasons.append(f"{label}: {raw.events_last_hour} requests in the last hour (+{points})")
            break

    for threshold, points, label in _DOWNLOAD_BANDS:
        if raw.downloads_last_hour >= threshold:
            score += points
            reasons.append(f"{label}: {raw.downloads_last_hour} downloads in the last hour (+{points})")
            break

    if raw.new_location:
        score += 10
        reasons.append("Access from a location not previously seen for this user (+10)")

    if raw.new_device:
        score += 15
        reasons.append("Access from a device not previously seen for this user (+15)")

    if raw.denied_ratio_last_24h > 0.3:
        score += 10
        reasons.append(
            f"{raw.denied_ratio_last_24h:.0%} of this user's requests in the last 24h were denied/blocked (+10)"
        )

    return min(score, 100), reasons


class RiskEngine:
    def __init__(self, model_path: str | None = None):
        self._model_path = Path(model_path or settings.risk_model_path)
        self._model = None
        self._metadata: dict | None = None
        self._load_attempted = False

    def _ensure_loaded(self) -> None:
        if self._load_attempted:
            return
        self._load_attempted = True
        if not self._model_path.exists():
            return
        import joblib

        self._model = joblib.load(self._model_path)
        meta_path = self._model_path.with_suffix(".json")
        if meta_path.exists():
            self._metadata = json.loads(meta_path.read_text())

    def _normalize_ml_score(self, decision_score: float) -> float:
        # sklearn IsolationForest.decision_function: higher = more normal,
        # lower/negative = more anomalous. Map the training set's observed
        # range onto 0 (normal) - 100 (anomalous), clipped for out-of-range
        # live scores.
        if not self._metadata:
            return 50.0
        lo = self._metadata["decision_score_min"]  # most anomalous seen in training
        hi = self._metadata["decision_score_max"]  # most normal seen in training
        if hi == lo:
            return 50.0
        normalized = (hi - decision_score) / (hi - lo)
        return max(0.0, min(1.0, normalized)) * 100

    def score(
        self,
        db: Session,
        user: User,
        *,
        action: str,
        device_id: str | None,
        location: str | None,
        now: datetime | None = None,
    ) -> RiskResult:
        raw = extract_features(db, user, action=action, device_id=device_id, location=location, now=now)
        rule_score, reasons = rule_based_score(raw)

        self._ensure_loaded()
        if self._model is not None:
            ml_raw = self._model.decision_function([raw.as_vector()])[0]
            ml_score = self._normalize_ml_score(ml_raw)
            final = round(ML_WEIGHT * ml_score + RULE_WEIGHT * rule_score)
            model_used = True
        else:
            final = rule_score
            model_used = False

        final = max(0, min(100, int(final)))
        if not reasons:
            reasons.append("No specific behavioral risk factors detected")
        return RiskResult(score=final, reasons=reasons, raw_features=raw.as_dict(), model_used=model_used)


risk_engine = RiskEngine()
