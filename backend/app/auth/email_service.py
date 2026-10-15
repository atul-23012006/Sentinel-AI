import logging
import secrets
import smtplib
from email.mime.text import MIMEText

from app.config import settings

logger = logging.getLogger("sentinelai.email")


def generate_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def send_verification_code(to_email: str, code: str) -> bool:
    """Sends a step-up verification code via SMTP when configured; otherwise
    logs it so the flow still works without real email infrastructure (same
    optional-service fallback pattern as the AI analyst in app/ai/service.py).
    Returns True only if it was handed to a real SMTP server.
    """
    if not settings.smtp_host:
        logger.warning(
            "SMTP not configured - verification code for %s is %s (expires in %d min)",
            to_email,
            code,
            settings.email_otp_expire_minutes,
        )
        return False

    message = MIMEText(
        f"Your SentinelAI verification code is {code}. "
        f"It expires in {settings.email_otp_expire_minutes} minutes. "
        "If you did not request this, contact your administrator."
    )
    message["Subject"] = "SentinelAI security verification code"
    message["From"] = settings.smtp_from_email or settings.smtp_username or "sentinelai@localhost"
    message["To"] = to_email

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
        server.starttls()
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password or "")
        server.sendmail(message["From"], [to_email], message.as_string())
    return True
