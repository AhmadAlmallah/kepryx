"""Bootstrap initial admin user. Run once after first deploy.

Usage: docker compose exec api python -m scripts.bootstrap
"""

import asyncio
import getpass
import os

from sqlalchemy import select

from app.core.database import SessionLocal
from app.core.password_policy import PasswordPolicyError, validate_password
from app.core.security import hash_password
from app.models import User


async def main():
    async with SessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "admin"))
        if result.scalar_one_or_none():
            print("Admin user already exists.")
            return

        email = os.environ.get("KEPRYX_ADMIN_EMAIL") or input("Admin email: ").strip()
        password = os.environ.get("KEPRYX_ADMIN_PASSWORD") or getpass.getpass(
            "Initial admin password: "
        )
        if not email:
            raise SystemExit("Admin email is required")
        try:
            validate_password(password, username="admin")
        except PasswordPolicyError as exc:
            raise SystemExit(f"Admin password does not meet policy: {exc}") from exc

        admin = User(
            username="admin",
            email=email,
            password_hash=hash_password(password),
            role="admin",
        )
        db.add(admin)

        await db.commit()
        print("Admin created. Username: admin")
        print("No scan networks were seeded. Add only explicitly authorized CIDRs.")
        print("Log in, change the password if temporary, and enable MFA.")


if __name__ == "__main__":
    asyncio.run(main())
