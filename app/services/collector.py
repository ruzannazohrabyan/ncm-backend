import hashlib
import logging
from datetime import datetime, timezone

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException, SSHDetect
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.core.security import decrypt_secret
from app.models.device import Device
from app.models.credential import Credential
from app.models.config_snapshot import ConfigSnapshot
from app.models.change_event import ChangeEvent, AlertRule
from app.services.device_facts import DeviceFacts, collect_facts
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

SHOW_STARTUP_COMMANDS = {
    "cisco_ios": "show startup-config",
    "cisco_xe": "show startup-config",
    "cisco_nxos": "show startup-config",
    "junos": "show system commit",  # Junos doesn't have startup-config; show system commit is equivalent
    "routeros": None,  # RouterOS doesn't have separate startup-config
    "mikrotik_routeros": None,
}

# Fallback when SSHDetect returns an unrecognised type or None
_DEFAULT_OS = "cisco_ios"


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

            # Pull both running and startup configs
            running_config, startup_config, facts = _ssh_pull(device, cred)
            running_hash = hashlib.sha256(running_config.encode()).hexdigest()
            startup_hash = hashlib.sha256(startup_config.encode()).hexdigest() if startup_config else None

            _apply_facts_to_device(device, facts)

            # Mark previous snapshots as not latest
            await db.execute(
                select(ConfigSnapshot)
                .where(ConfigSnapshot.device_id == device_id, ConfigSnapshot.is_latest == True)
                .update({ConfigSnapshot.is_latest: False})
            )

            # Get last snapshots for change detection
            last_running_result = await db.execute(
                select(ConfigSnapshot)
                .where(
                    ConfigSnapshot.device_id == device_id,
                    ConfigSnapshot.config_type == "running",
                )
                .order_by(ConfigSnapshot.captured_at.desc())
                .limit(1)
            )
            last_running = last_running_result.scalar_one_or_none()

            last_startup_result = await db.execute(
                select(ConfigSnapshot)
                .where(
                    ConfigSnapshot.device_id == device_id,
                    ConfigSnapshot.config_type == "startup",
                )
                .order_by(ConfigSnapshot.captured_at.desc())
                .limit(1)
            )
            last_startup = last_startup_result.scalar_one_or_none()

            # Create running-config snapshot
            running_snapshot = ConfigSnapshot(
                device_id=device_id,
                triggered_by=triggered_by,
                config_raw=running_config,
                hash=running_hash,
                config_type="running",
                trigger_type="manual" if triggered_by else "scheduled",
                is_latest=True,
            )
            db.add(running_snapshot)
            await db.flush()

            # Detect changes in running-config
            if last_running and last_running.hash != running_hash:
                diff_text = compute_diff(last_running.config_raw, running_config)
                change = ChangeEvent(
                    device_id=device_id,
                    snapshot_before_id=last_running.id,
                    snapshot_after_id=running_snapshot.id,
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

            # Create startup-config snapshot if available
            if startup_config:
                startup_snapshot = ConfigSnapshot(
                    device_id=device_id,
                    triggered_by=triggered_by,
                    config_raw=startup_config,
                    hash=startup_hash,
                    config_type="startup",
                    trigger_type="manual" if triggered_by else "scheduled",
                    is_latest=True,
                )
                db.add(startup_snapshot)
                await db.flush()

                # Detect changes in startup-config
                if last_startup and last_startup.hash != startup_hash:
                    diff_text = compute_diff(last_startup.config_raw, startup_config)
                    change = ChangeEvent(
                        device_id=device_id,
                        snapshot_before_id=last_startup.id,
                        snapshot_after_id=startup_snapshot.id,
                        diff_text=diff_text,
                        severity="info",  # Startup changes are informational
                    )
                    db.add(change)
                    await db.flush()

                # Check if running and startup are in sync
                if running_hash == startup_hash:
                    now = datetime.now(timezone.utc)
                    running_snapshot.synced_at = now
                    startup_snapshot.synced_at = now
                    logger.info(f"Device {device.hostname}: running-config and startup-config are in sync")
                else:
                    logger.warning(f"Device {device.hostname}: OUT-OF-SYNC (running != startup)")

            device.last_seen = datetime.now(timezone.utc)
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


async def refresh_device_facts(device_id: str) -> DeviceFacts | None:
    """
    Open an SSH session to the given device, harvest inventory facts, persist
    them, and return the collected :class:`DeviceFacts`.

    Returns ``None`` if the device is missing/inactive, has no credential, or
    if the SSH session fails. Does **not** pull the running-config — use
    :func:`pull_config` for that.
    """
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(select(Device).where(Device.id == device_id))
            device = result.scalar_one_or_none()
            if not device or not device.is_active:
                logger.warning(f"[FACTS] Device {device_id} not found or inactive")
                return None

            if not device.credential_id:
                logger.error(f"[FACTS] No credential for device {device_id}")
                return None

            cred_result = await db.execute(
                select(Credential).where(Credential.id == device.credential_id)
            )
            cred = cred_result.scalar_one_or_none()
            if not cred:
                logger.error(f"[FACTS] Credential {device.credential_id} missing")
                return None

            os_type = device.os_type or _DEFAULT_OS
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
                facts = collect_facts(conn, os_type)

            _apply_facts_to_device(device, facts)
            device.last_seen = datetime.now(timezone.utc)
            await db.commit()
            return facts

        except NetmikoAuthenticationException:
            logger.error(f"[FACTS] Auth failed for device {device_id}")
            return None
        except NetmikoTimeoutException:
            logger.error(f"[FACTS] Timeout connecting to device {device_id}")
            return None
        except Exception as exc:
            logger.exception(f"[FACTS] Unexpected error for device {device_id}: {exc}")
            await db.rollback()
            return None


def _ssh_pull(device: Device, cred: Credential) -> tuple[str, str | None, DeviceFacts]:
    """
    Connect to ``device`` and return ``(running_config, startup_config, facts)``.

    Inventory facts are harvested in the same SSH session as the config pull
    to avoid the cost of a second login.

    Returns:
        - running_config: The current running configuration
        - startup_config: The startup configuration (None if not supported by device OS)
        - facts: DeviceFacts collected from the device
    """
    os_type = device.os_type or _DEFAULT_OS
    run_command = SHOW_RUN_COMMANDS.get(os_type, "show running-config")
    startup_command = SHOW_STARTUP_COMMANDS.get(os_type)

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
        # Pull running-config
        running_config = conn.send_command(run_command, read_timeout=60)

        # Pull startup-config if supported
        startup_config = None
        if startup_command:
            try:
                startup_config = conn.send_command(startup_command, read_timeout=60)
            except Exception as exc:
                logger.warning(
                    f"[CONFIG] Failed to get startup-config for {device.ip_address}: {exc}"
                )

        # Collect inventory facts
        try:
            facts = collect_facts(conn, os_type)
        except Exception as exc:
            logger.warning(
                f"[FACTS] Failed to collect inventory for {device.ip_address}: {exc}"
            )
            facts = DeviceFacts()

    return running_config, startup_config, facts


def _apply_facts_to_device(device: Device, facts: DeviceFacts) -> None:
    """
    Copy non-empty :class:`DeviceFacts` fields onto a :class:`Device` row.

    Existing values are overwritten only when a fresh non-``None`` value was
    parsed — this keeps the previous reading intact if the new poll could
    not parse a particular field.
    """
    if facts.vendor and not device.vendor:
        device.vendor = facts.vendor
    if facts.model:
        device.model = facts.model
    if facts.serial_number:
        device.serial_number = facts.serial_number
    if facts.os_name:
        devi