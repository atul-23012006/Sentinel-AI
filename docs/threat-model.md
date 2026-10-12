# Threat Model

Operationalizes README §22 against the implemented system: for each threat,
which component is responsible, and which test proves it.

| Threat | Detection / mitigation | Proof |
|---|---|---|
| Credential compromise (stolen password, unusual login) | TBAC denies outside-hours access outright; a policy-ALLOW session with unfamiliar device/location/frequency is escalated by the risk engine (`app/risk/engine.py`) to MFA or BLOCK | `test_attack_scenarios.py::test_scenario_2_credential_compromise_denied_despite_valid_credentials` |
| Insider misuse / mass data access | `events_last_hour` / `downloads_last_hour` features feed both the rule-based score and the Isolation Forest | `test_attack_scenarios.py::test_scenario_3_mass_download_triggers_adaptive_block_and_alert` |
| Privilege abuse | RBAC/MAC deny resources outside a role's/clearance's scope before risk scoring is even reached | `test_attack_scenarios.py::test_scenario_4_privilege_abuse_denied_by_rbac` |
| Data exfiltration (burst downloads) | Same path as insider misuse - `downloads_last_hour` is weighted +25 in the rule-based score and is part of the ML feature vector | `test_adaptive_access.py::test_critical_risk_blocks_and_ai_analyst_explains_it` |
| Brute force | `failed_login_count` + automatic `LOCKED` status after `MAX_FAILED_LOGINS`; admin-only reactivation (`PATCH /users/{id}`) | `test_attack_scenarios.py::test_scenario_1_brute_force_locks_account_and_is_audited`, `test_users_admin.py::test_admin_can_reactivate_a_locked_account_...` |
| Policy bypass (manipulated request) | All policy/risk evaluation happens server-side in `HybridPolicyEngine`/`RiskEngine`; the client only supplies `action`/`device_id`/`location`, never a decision | `test_attack_scenarios.py::test_scenario_5_policy_violation_denied_by_mac` |
| Audit tampering | No update/delete endpoint exists for `access_events`; only `Administrator`-role users can even read the audit trail | `test_audit.py::test_audit_events_require_admin_role` |
| AI misuse (malicious prompt/input) | The AI analyst (`app/ai/service.py`) only ever receives server-computed `SecurityAlert`/`AccessEvent` fields, never raw end-user text, and its output is never read back into an access decision | `test_adaptive_access.py::test_critical_risk_blocks_and_ai_analyst_explains_it` (asserts `source == "template"` with no API key configured) |

## Trust boundaries

```
Untrusted:  browser (frontend/) input - action, device_id, location strings only
Trusted:    backend/app/ - all policy, risk, and adaptive-decision logic
Trusted:    database/schema.sql - CHECK constraints are a second line of
            defense if application-level validation is ever bypassed
Advisory:   app/ai/service.py - read-only explanation layer, cannot act
```

The frontend is explicitly untrusted: every decision it displays (policy
results, risk score, alert severity) was computed server-side and is only
*rendered* client-side, never recomputed or trusted from client input.
