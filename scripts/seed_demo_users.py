"""Seeds one demo account per (role x clearance_level) combination, with
every device pre-trusted, so a live demo can show any RBAC/MAC/ABAC/TBAC
interaction by just logging in as the right persona instead of
live-registering accounts under time pressure.

Idempotent: safe to re-run (existing accounts are skipped, not recreated).
Talks to a running backend over HTTP (the same API a real client uses), not
the database directly, so it exercises the real registration/admin flow.

All demo accounts share one password. This is a local-dev/demo convenience
only - never do this against a real deployment.

If REQUIRE_ADMIN_APPROVAL is on (the default) and the backend already has
at least one user, this script's own bootstrap admin registration will come
back PENDING and the immediate login will fail - either set
REQUIRE_ADMIN_APPROVAL=false in backend/.env for seeding, or approve
`demo_bootstrap_admin` via an existing admin account first.

Usage:
    python3 scripts/seed_demo_users.py [--base-url http://localhost:8000]
"""

import argparse
import sys

import httpx

DEMO_PASSWORD = "DemoPass123!"

ROLES = [
    ("Finance Employee", "Finance"),
    ("HR Employee", "HR"),
    ("Administrator", "IT"),
]
CLEARANCES = ["PUBLIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]


def slug(role: str) -> str:
    return role.lower().replace(" ", "_")


def register(client: httpx.Client, username: str, role: str, department: str, clearance: str) -> dict | None:
    response = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": DEMO_PASSWORD,
            "role": role,
            "department": department,
            "clearance_level": clearance,
        },
    )
    if response.status_code == 201:
        return response.json()
    if response.status_code == 409:
        return None  # already exists from a previous run
    response.raise_for_status()
    return None


def login(client: httpx.Client, username: str) -> str:
    response = client.post("/auth/login", json={"username": username, "password": DEMO_PASSWORD})
    response.raise_for_status()
    return response.json()["access_token"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8000")
    args = parser.parse_args()

    client = httpx.Client(base_url=args.base_url, timeout=10)

    try:
        client.get("/health").raise_for_status()
    except httpx.HTTPError:
        sys.exit(f"Could not reach backend at {args.base_url} - is it running?")

    # Bootstrap one admin account to do the device-trusting (admin-only).
    bootstrap_username = "demo_bootstrap_admin"
    register(client, bootstrap_username, "Administrator", "IT", "TOP_SECRET")
    admin_headers = {"Authorization": f"Bearer {login(client, bootstrap_username)}"}
    bootstrap_me = client.get("/auth/me", headers=admin_headers).json()
    client.patch(f"/users/{bootstrap_me['user_id']}", json={"device_trust": "TRUSTED"}, headers=admin_headers)

    rows = [(bootstrap_username, "Administrator", "IT", "TOP_SECRET")]

    for role, department in ROLES:
        for clearance in CLEARANCES:
            username = f"demo_{slug(role)}_{clearance.lower()}"
            user = register(client, username, role, department, clearance)
            if user is None:
                users = client.get("/users", headers=admin_headers).json()
                user = next(u for u in users if u["username"] == username)
            client.patch(f"/users/{user['user_id']}", json={"device_trust": "TRUSTED"}, headers=admin_headers)
            rows.append((username, role, department, clearance))

    print(f"{'Username':32} {'Role':18} {'Department':12} {'Clearance':12}")
    print("-" * 76)
    for username, role, department, clearance in rows:
        print(f"{username:32} {role:18} {department:12} {clearance:12}")
    print(f"\nPassword for every demo account: {DEMO_PASSWORD}")
    print("All devices are already trusted (ABAC will pass for same-department resources).")


if __name__ == "__main__":
    main()
