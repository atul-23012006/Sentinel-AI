from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from jwt import PyJWTError

from app.config import settings

# bcrypt silently truncates at 72 bytes; UserCreate caps password length at
# 128 chars, so reject upfront rather than let two different long passwords
# hash to the same value.
_MAX_PASSWORD_BYTES = 72


def hash_password(password: str) -> str:
    if len(password.encode("utf-8")) > _MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {_MAX_PASSWORD_BYTES} bytes")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    if len(plain_password.encode("utf-8")) > _MAX_PASSWORD_BYTES:
        return False
    return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(subject: str, extra_claims: dict | None = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": subject, "exp": expire}
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except PyJWTError:
        return None
