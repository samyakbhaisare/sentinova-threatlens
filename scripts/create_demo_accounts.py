"""Create one working demo account per PRD role.

Passwords are generated locally with ``secrets`` and written only to a
git-ignored credentials file (``demo-credentials.local.txt``).  Nothing is
printed to shared logs, committed, or stored in the repository.

Usage (from the repository root, with the database reachable):

    .\\.venv-resume\\Scripts\\python.exe scripts\\create_demo_accounts.py

Existing accounts are left untouched: rerunning the script never overwrites a
password.  Use ``--reset-passwords`` to rotate every demo password and write a
fresh credentials file.
"""

from __future__ import annotations

import argparse
import secrets
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import select  # noqa: E402

from app.db import Session  # noqa: E402
from app.models import User  # noqa: E402
from app.security import audit, hasher  # noqa: E402

DEMO_USERS = [
    ("administrator", "Demo Administrator", "demo.admin@example.org"),
    ("security_engineer", "Demo Security Engineer", "demo.engineer@example.org"),
    ("incident_responder", "Demo Incident Responder", "demo.responder@example.org"),
    ("threat_hunter", "Demo Threat Hunter", "demo.hunter@example.org"),
    ("soc_analyst", "Demo SOC Analyst", "demo.analyst@example.org"),
    ("executive", "Demo Executive", "demo.executive@example.org"),
]

CREDENTIALS_FILE = ROOT / "demo-credentials.local.txt"


def generate_password() -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(24))
        if (
            any(c.islower() for c in value)
            and any(c.isupper() for c in value)
            and any(c.isdigit() for c in value)
            and any(c in "!@#$%^&*-_=+" for c in value)
        ):
            return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset-passwords", action="store_true")
    args = parser.parse_args()

    created: list[tuple[str, str, str]] = []
    with Session.begin() as db:
        for role, name, email in DEMO_USERS:
            user = db.scalar(select(User).where(User.email == email))
            password = None
            if user is None:
                password = generate_password()
                user = User(
                    name=name,
                    email=email,
                    role=role,
                    enabled=True,
                    password_hash=hasher.hash(password),
                )
                db.add(user)
                db.flush()
                audit(db, None, "user.demo_created", user.id, {"role": role})
            elif args.reset_passwords:
                password = generate_password()
                user.password_hash = hasher.hash(password)
                user.enabled = True
                user.token_version = (user.token_version or 0) + 1
                audit(db, None, "user.demo_password_rotated", user.id, {"role": role})
            if password:
                created.append((role, email, password))

    if not created:
        print("All six demo accounts already exist; no passwords were changed.")
        print(f"Credentials file: {CREDENTIALS_FILE.name}")
        return 0

    lines = [
        "Sentinova ThreatLens - local demo credentials",
        "Generated locally. Git-ignored. Do not commit or share.",
        "",
    ]
    lines += [f"{role:20} {email:34} {password}" for role, email, password in created]
    CREDENTIALS_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(created)} credential row(s) to {CREDENTIALS_FILE.name} (git-ignored).")
    print("Passwords were not printed to the console.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
