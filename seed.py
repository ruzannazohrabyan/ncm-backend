"""
Initial seed: creates default organization and admin user.
Runs automatically on first startup via entrypoint.sh.
"""
import asyncio
import os
from app.core.database import AsyncSessionLocal
from app.core.security import hash_password
from app.models.organization import Organization
from app.models.user import User


ADMIN_EMAIL = os.getenv("SEED_ADMIN_EMAIL", "admin@ncm.local")
ADMIN_PASSWORD = os.getenv("SEED_ADMIN_PASSWORD", "Admin1234!")
ORG_NAME = os.getenv("SEED_ORG_NAME", "My Organization")
ORG_SLUG = os.getenv("SEED_ORG_SLUG", "my-org")


async def seed():
    async with AsyncSessionLocal() as db:
        org = Organization(name=ORG_NAME, slug=ORG_SLUG, plan="standard")
        db.add(org)
        await db.flush()

        user = User(
            org_id=org.id,
            email=ADMIN_EMAIL,
            hashed_password=hash_password(ADMIN_PASSWORD),
            full_name="Administrator",
            role="admin",
        )
        db.add(user)
        await db.commit()

        print(f"✅ Org created  : {org.name} (id={org.id})")
        print(f"✅ Admin created: {user.email}")
        print(f"🔑 Password     : {ADMIN_PASSWORD}")
        print()
        print("⚠️  Change the password after first login!")


asyncio.run(seed())
