import logging
import secrets
import smtplib
from email.mime.text import MIMEText

from app.config import settings

logger = logging.getLogger("sentinelai.email")


def generate_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def send_email(to_email: str, subject: str, body: str) -> bool:
    """Shared SMTP sender for every outbound email (step-up codes, admin
    registration notifications). Sends via SMTP when configured; otherwise
    logs it so the flow still works without real email infrastructure (same
    optional-service fallback pattern as the AI analyst in app/ai/service.py).
    Returns True only if it was handed to a real SMTP server.
    """
    if not settings.smtp_host:
        logger.warning("SMTP not configured - email to %s not sent.\nSubject: %s\n%s", to_email, subject, body)
        return False

    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = settings.smtp_from_email or settings.smtp_username or "sentinelai@localhost"
    message["To"] = to_email

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
        server.starttls()
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password or "")
        server.sendmail(message["From"], [to_email], message.as_string())
    return True


def send_verification_code(to_email: str, code: str) -> bool:
    return send_email(
        to_email,
        "SentinelAI security verification code",
        f"Your SentinelAI verification code is {code}. "
        f"It expires in {settings.email_otp_expire_minutes} minutes. "
        "If you did not request this, contact your administrator.",
    )


def send_registration_pending_notification(admin_email: str, username: str, user_id: int) -> bool:
    return send_email(
        admin_email,
        f"SentinelAI: new account awaiting approval - {username}",
        f"A new user has registered and needs your approval before they can log in.\n\n"
        f"Username: {username}\nUser ID: {user_id}\n\n"
        "Approve them via PATCH /users/{id} with {\"account_status\": \"ACTIVE\"}, "
        "or reject via {\"account_status\": \"DISABLED\"} - or use the Users tab in the admin console.",
    )
