"""Behavioral feature engineering shared by the live risk engine (app/risk/engine.py)
and the offline training pipeline (ml/training/train.py, which imports this module
directly off the backend so the two never drift apart - see README §6/§7).
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AccessEvent, User

# Fixed order used whenever features are turned into a numeric vector for the
# Isolation Forest model - must match ml/training/train.py exactly.
FEATURE_NAMES = [
    "login_hour",
    "events_last_hour",
    "distinct_resources_last_hour",
    "downloads_last_hour",
    "denied_ratio_last_24h",
    "failed_login_count",
    "new_device",
    "new_location",
    "outside_business_hours",
]


@dataclass
class RawFeatures:
    login_hour: int
    events_last_hour: int
    distinct_resources_last_hour: int
    downloads_last_hour: int
    denied_ratio_last_24h: float
    failed_login_count: int
    new_device: int
    new_location: int
    outside_business_hours: int

    def as_dict(self) -> dict[str, float]:
        return {name: float(getattr(self, name)) for name in FEATURE_NAMES}

    def as_vector(self) -> list[float]:
        return [getattr(self, name) for name in FEATURE_NAMES]


def extract_features(
    db: Session,
    user: User,
    *,
    action: str,
    device_id: str | None,
    location: str | None,
    now: datetime | None = None,
) -> RawFeatures:
    """Builds the behavioral feature vector for the access attempt currently in
    flight, from this user's *prior* access_events history (the current attempt
    is not logged yet when this runs, so there is no leakage).
    """
    now = now or datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(hours=24)

    base = db.query(AccessEvent).filter(AccessEvent.user_id == user.user_id)

    last_hour = base.filter(AccessEvent.timestamp >= hour_ago)
    events_last_hour = last_hour.count()
    distinct_resources_last_hour = (
        last_hour.filter(AccessEvent.resource_id.isnot(None))
        .with_entities(func.count(func.distinct(AccessEvent.resource_id)))
        .scalar()
        or 0
    )
    downloads_last_hour = last_hour.filter(AccessEvent.action == "DOWNLOAD").count()

    last_day = base.filter(AccessEvent.timestamp >= day_ago)
    total_last_day = last_day.count()
    denied_last_day = last_day.filter(AccessEvent.final_decision.in_(("DENY", "BLOCK"))).count()
    denied_ratio_last_24h = (denied_last_day / total_last_day) if total_last_day else 0.0

    known_devices = {
        row[0]
        for row in base.filter(AccessEvent.device_id.isnot(None)).with_entities(AccessEvent.device_id).distinct()
    }
    known_locations = {
        row[0]
        for row in base.filter(AccessEvent.location.isnot(None)).with_entities(AccessEvent.location).distinct()
    }

    new_device = 1 if device_id and device_id not in known_devices else 0
    new_location = 1 if location and location not in known_locations else 0
    outside_business_hours = 0 if settings.tbac_start_hour <= now.hour < settings.tbac_end_hour else 1

    return RawFeatures(
        login_hour=now.hour,
        events_last_hour=events_last_hour,
        distinct_resources_last_hour=distinct_resources_last_hour,
        downloads_last_hour=downloads_last_hour,
        denied_ratio_last_24h=round(denied_ratio_last_24h, 4),
        failed_login_count=user.failed_login_count,
        new_device=new_device,
        new_location=new_location,
        outside_business_hours=outside_business_hours,
    )
