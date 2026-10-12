# Security Model

Extends README §21 ("Security Considerations") with how each point is
actually implemented, and known limitations to be transparent about in review.

| Consideration | Implementation |
|---|---|
| No plaintext passwords | bcrypt (`app/auth/security.py`), explicitly capped at 72 bytes to match bcrypt's own truncation limit rather than silently allowing hash collisions on longer inputs |
| Input validation | Pydantic schemas (`app/schemas.py`) on every endpoint; DB-level `CHECK` constraints mirror the enums (role, clearance, decision, severity, status) |
| Parameterized queries | SQLAlchemy ORM throughout — no raw string-interpolated SQL anywhere in the codebase |
| Protect auth tokens | JWT, HS256, server-side secret (`JWT_SECRET_KEY`), short expiry (`ACCESS_TOKEN_EXPIRE_MINUTES`, default 30 min) |
| Least privilege / separate admin privileges | `require_role("Administrator")` gates `/users`, `/audit/*`, `/alerts/*`, and `PATCH /users/{id}` (device trust, account reactivation) |
| Protect audit logs from unauthorized modification | `access_events` has no update/delete endpoint — audit rows are write-once from the server side; only admins can even read them |
| Avoid leaking info in errors | Login failures return a generic "Invalid username or password" regardless of whether the username exists, to avoid user enumeration |
| Secure API endpoints | Every endpoint except `/auth/register`, `/auth/login`, `/health` requires a valid JWT |
| Validate resource ownership | Access to a specific resource is always re-evaluated through `HybridPolicyEngine`, never assumed from a cached decision |
| Protect ML/AI endpoints from abuse | `/alerts/{id}/explain` is admin-only; the AI analyst never receives raw user input, only server-computed alert/event fields |
| Treat LLM output as advisory | `app/ai/service.py` only produces explanatory text returned to an admin - it is never read back into `app/resources/router.py`'s decision path |
| Deterministic policy enforcement | `_adaptive_decision()` (`app/resources/router.py`) is a pure function: a policy `DENY` can never be turned into an `ALLOW` by risk scoring, only the reverse (an `ALLOW` can be escalated) |
| Test for privilege escalation / policy bypass | `tests/test_attack_scenarios.py` (brute force, credential compromise, mass download, privilege abuse, policy violation) |

## MFA (step-up authentication)

TOTP (RFC 6238, via `pyotp`), the same mechanism as Google/Microsoft
Authenticator. `GET /auth/mfa/setup` provisions a secret (idempotent — an
already-paired authenticator stays valid) and returns an `otpauth://` URI;
`POST /auth/mfa/verify` checks a submitted code against it with a ±1 time-step
window. Known limitation for a college project without an email/SMS
provider: the secret/URI is returned directly over the authenticated API
response rather than delivered out-of-band, so there's no separate
"possession" channel being verified the way a production MFA rollout would
have — see `app/auth/router.py`'s `mfa_setup` docstring.

## Known limitations (be upfront about these in review)

- No rate limiting on login/MFA verify beyond the existing account-lockout
  counter — a determined attacker could still brute-force MFA codes within
  the lockout threshold.
- The risk engine's "new device" / "new location" signals rely entirely on
  client-supplied `device_id`/`location` strings with no server-side
  verification (no actual device fingerprinting or geolocation).
- `access_events.reason` and `security_alerts.description` are free text
  built from internal strings, not user input, so there's no injection
  surface there - but they are not currently redacted/sanitized before
  display in the frontend beyond React's default escaping.
