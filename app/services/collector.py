import hashlib
import logging
from datetime import datetime, timezone

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.core.security import decrypt_secret
from app.models.device import Device
from app.models.credential import Credential
from app.models.config_snapshot import ConfigSnapshot
from app.models.change_event import ChangeEvent, AlertRule
from app.services.diff_engine import compute_diff
from app.services.notifier import send_alert

logger = logging.getLogger(__name__)

SHOW_RUN_COMMANDS = {
    "cisco_ios": "show running-config",
    "cisco_xe": "show running-config",
    "cisco_nxos": "show running-config",
    "junos": "show configuration | display text",
    "routeros": "export compact",
    "mikrotik_routeros": "export compact",
}


async def pull_config(device_id: str, triggered_by: str | None = None) -> bool:
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(select(Device).where(Device.id == device_id))
            device = result.scalar_one_or_none()
            if not device or not device.is_active:
                logger.warning(f"Device {device_id} not found or inactive")
                return False

            cred = None
            if device.credential_id:
                cred_result = await db.execute(
                    select(Credential).where(Credential.id == device.credential_id)
                )
                cred = cred_result.scalar_one_or_none()

            if not cred:
                logger.error(f"No credential for device {device_id}")
                return False

            config_raw = _ssh_pull(device, cred)
            config_hash = hashlib.sha256(config_raw.encode()).hexdigest()

            last_snapshot_result = await db.execute(
                select(ConfigSnapshot)
                .where(ConfigSnapshot.device_id == device_id)
                .order_by(ConfigSnapshot.captured_at.desc())
                .limit(1)
            )
            last_snapshot = last_snapshot_result.scalar_one_or_none()

            snapshot = ConfigSnapshot(
                device_id=device_id,
                triggered_by=triggered_by,
                config_raw=config_raw,
                hash=config_hash,
                trigger_type="manual" if triggered_by else "scheduled",
            )
            db.add(snapshot)
            await db.flush()

            device.last_seen = datetime.now(timezone.utc)

            if last_snapshot and last_snapshot.hash != config_hash:
                diff_text = compute_diff(last_snapshot.config_raw, config_raw)
                change = ChangeEvent(
                    device_id=device_id,
                    snapshot_before_id=last_snapshot.id,
                    snapshot_after_id=snapshot.id,
                    diff_text=diff_text,
                    severity="warning",
                )
                db.add(change)
                await db.flush()

                rules_result = await db.execute(
                    select(AlertRule).where(
                        AlertRule.org_id == device.org_id,
                        AlertRule.active == True,
                    )
                )
                rules = rules_result.scalars().all()
                for rule in rules:
                    await send_alert(rule, device, diff_text)

                change.notified = True

            await db.commit()
            logger.info(f"Config pulled for device {device.hostname}")
            return True

        except NetmikoAuthenticationException:
            logger.error(f"Auth failed for device {device_id}")
            return False
        except NetmikoTimeoutException:
            logger.error(f"Timeout connecting to device {device_id}")
            return False
        except Exception as e:
            logger.exception(f"Unexpected error pulling config for device {device_id}: {e}")
            await db.rollback()
            return False


def _ssh_pull(device: Device, cred: Credential) -> str:
    os_type = device.os_type or "cisco_ios"
    command = SHOW_RUN_COMMANDS.get(os_type, "show running-config")

    connection_params = {
        "device_type": os_type,
        "host": device.ip_address,
        "port": device.port,
        "username": cred.username,
        "password": decrypt_secret(cred.encrypted_password),
        "timeout": 30,
        "session_log": None,
    }

    with ConnectHandler(**connection_params) as conn:
        output = conn.send_command(command, read_timeout=60)

    return output
