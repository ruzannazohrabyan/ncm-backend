# NCM Backend — Network Configuration Manager

FastAPI + PostgreSQL + Celery բազված backend` ցանցային սարքերի կոնֆիգուրացիաների backup-ի, versioning-ի և monitoring-ի համար:

## Արագ մեկնարկ

### 1. Dependencies

```bash
cp .env.example .env
# Լրացրու .env-ը (ENCRYPTION_KEY, SECRET_KEY, TELEGRAM_BOT_TOKEN)
```

Encryption key generate անել.
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Secret key generate անել.
```bash
openssl rand -hex 32
```

### 2. Docker-ով գործարկել

```bash
docker-compose up --build
```

API կլինի հասանելի `http://localhost:8000/api/docs`-ով:

### 3. Migrations

```bash
# Առաջին անգամ
docker-compose exec api alembic revision --autogenerate -m "initial"
docker-compose exec api alembic upgrade head
```

### 4. Առաջին admin user ստեղծել

```bash
docker-compose exec api python -c "
import asyncio
from app.core.database import AsyncSessionLocal
from app.core.security import hash_password
from app.models.organization import Organization
from app.models.user import User

async def seed():
    async with AsyncSessionLocal() as db:
        org = Organization(name='My Company', slug='my-company')
        db.add(org)
        await db.flush()
        user = User(
            org_id=org.id,
            email='admin@example.com',
            hashed_password=hash_password('changeme123'),
            role='admin',
        )
        db.add(user)
        await db.commit()
        print(f'Created org: {org.id}, user: {user.id}')

asyncio.run(seed())
"
```

## API Endpoints

| Method | URL | Նկարագրություն |
|--------|-----|----------------|
| POST | `/api/v1/auth/login` | Login, ստանալ JWT |
| POST | `/api/v1/auth/refresh` | Token refresh |
| GET | `/api/v1/auth/me` | Ընթացիկ user |
| GET | `/api/v1/devices` | Բոլոր սարքերը |
| POST | `/api/v1/devices` | Ավելացնել սարք |
| GET | `/api/v1/devices/{id}` | Սարքի մանրամասներ |
| PUT | `/api/v1/devices/{id}` | Թարմացնել |
| DELETE | `/api/v1/devices/{id}` | Հեռացնել |
| POST | `/api/v1/devices/{id}/pull` | Manual backup |
| GET | `/api/v1/devices/{id}/snapshots` | Config պատմություն |
| GET | `/api/v1/snapshots/{id}` | Config snapshot |
| GET | `/api/v1/snapshots/diff?before=&after=` | Diff երկու snapshot |
| GET | `/api/v1/changes` | Բոլոր փոփոխությունները |
| GET | `/api/v1/alerts/rules` | Alert կանոններ |
| POST | `/api/v1/alerts/rules` | Ավելացնել alert |

## Tech Stack

- **FastAPI** — async REST API
- **PostgreSQL** — հիմնական DB
- **SQLAlchemy 2 (async)** — ORM
- **Alembic** — migrations
- **Celery + Redis** — scheduled backups
- **Netmiko** — SSH կապ սարքերի հետ
- **WireGuard** — VPN tunnel (արտաքին)

## Supported Device Types

| Vendor | os_type |
|--------|---------|
| Cisco IOS | `cisco_ios` |
| Cisco IOS-XE | `cisco_xe` |
| Cisco NX-OS | `cisco_nxos` |
| Juniper | `junos` |
| MikroTik | `mikrotik_routeros` |
