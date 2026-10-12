"""AI Security Analyst (README §11).

Turns a SecurityAlert + its AccessEvent into an administrator-friendly
explanation. This layer is strictly advisory: it only runs on alerts that the
deterministic risk engine and policy engine have already raised, and it never
feeds back into an access decision (app/resources/router.py never calls this
module). When ANTHROPIC_API_KEY is not configured, a deterministic template
explanation is produced instead so the feature works without an external API
key - useful for local dev, grading, and CI.
"""

from app.config import settings
from app.models import AccessEvent, SecurityAlert


def _template_explanation(alert: SecurityAlert, event: AccessEvent | None) -> str:
    lines = ["HIGH-RISK SECURITY EVENT" if alert.severity in ("HIGH", "CRITICAL") else "SECURITY EVENT"]
    lines.append("")

    if event:
        lines.append(
            f"User {event.user_id} performed action '{event.action}' on resource "
            f"{event.resource_id if event.resource_id else 'N/A'} at {event.timestamp}."
        )
        if event.device_id:
            lines.append(f"Device: {event.device_id}")
        if event.location:
            lines.append(f"Location: {event.location}")
        lines.append(f"Policy decision: {event.policy_decision}. Final decision: {event.final_decision}.")

    lines.append(f"Risk score: {alert.risk_score}/100 ({alert.severity}).")
    if alert.description:
        lines.append("")
        lines.append("Contributing behavioral factors:")
        for reason in alert.description.split("; "):
            lines.append(f"  - {reason}")

    lines.append("")
    lines.append("Possible concerns:")
    concerns = []
    if alert.severity == "CRITICAL":
        concerns += ["Credential compromise", "Data exfiltration"]
    if alert.severity in ("HIGH", "CRITICAL"):
        concerns += ["Privilege misuse"]
    concerns += ["Unusual access pattern requiring review"]
    for c in dict.fromkeys(concerns):  # de-dupe, keep order
        lines.append(f"  - {c}")

    lines.append("")
    lines.append("Recommended actions:")
    actions = ["Review the user's recent access history."]
    if alert.severity in ("HIGH", "CRITICAL"):
        actions.insert(0, "Require additional authentication (MFA) before further access.")
    if alert.severity == "CRITICAL":
        actions.append("Consider temporarily suspending the account pending investigation.")
    if event and event.device_id:
        actions.append(f"Investigate whether device '{event.device_id}' is recognized by the user.")
    for i, a in enumerate(actions, 1):
        lines.append(f"  {i}. {a}")

    return "\n".join(lines)


def _llm_explanation(alert: SecurityAlert, event: AccessEvent | None) -> str | None:
    if not settings.anthropic_api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None

    event_summary = (
        f"user_id={event.user_id}, action={event.action}, resource_id={event.resource_id}, "
        f"device={event.device_id}, location={event.location}, "
        f"policy_decision={event.policy_decision}, final_decision={event.final_decision}, "
        f"timestamp={event.timestamp}"
        if event
        else "no linked access event"
    )
    prompt = (
        "You are a security analyst assistant embedded in an enterprise access-control "
        "system called SentinelAI. Explain the following security alert to a human "
        "administrator in plain language. Summarize what happened, list possible "
        "concerns, and give concrete recommended actions. Be concise (under 150 words). "
        "Do not suggest you can take action yourself - you only explain and recommend; "
        "the deterministic policy engine already made the access decision.\n\n"
        f"Alert: type={alert.alert_type}, severity={alert.severity}, risk_score={alert.risk_score}\n"
        f"Contributing factors: {alert.description}\n"
        f"Linked access event: {event_summary}"
    )

    try:
        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        response = client.messages.create(
            model=settings.anthropic_model,
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text").strip()
    except Exception:
        # Advisory layer only - any API/network failure degrades to the
        # template explanation rather than breaking the alerts endpoint.
        return None


def explain_alert(alert: SecurityAlert, event: AccessEvent | None) -> tuple[str, str]:
    llm_text = _llm_explanation(alert, event)
    if llm_text:
        return llm_text, "llm"
    return _template_explanation(alert, event), "template"
