import asyncio
import logging
from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

logger = logging.getLogger(__name__)

celery_app = Celery(
    "ncm",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    beat_schedule={
        "scheduled-config-backup": {
            "task": "app.workers.celery_app.run_scheduled_backups",
            "schedule": crontab(minute="*/5"),
        },
    },
)


@celery_app.task(name="app.workers.celery_app.run_scheduled_backups")
def run_scheduled_backups():
    asyncio.run(_scheduled_backups())


async def _scheduled_backups():
    from sqlalchemy import select
    from datetime import datetime, timezone, timedelta
    from app.core.database import AsyncSessionLocal
    from app.models.device import Device
    from app.services.collector import pull_config

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Device).where(Device.is_active == True)
        )
        devices = result.scalars().all()

    now = datetime.now(timezone.utc)
    tasks = []
    for device in devices:
        if device.last_seen is None:
            tasks.append(pull_config(device.id))
        else:
            due_at = device.last_seen + timedelta(minutes=device.backup_interval_minutes)
            if now >= due_at:
                tasks.append(pull_config(device.id))

    if tasks:
        import asyncio
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info(f"Scheduled backup: processed {len(tasks)} devices")
