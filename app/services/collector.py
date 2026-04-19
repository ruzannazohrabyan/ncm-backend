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
    os_type = device.os_type or _DEFAULT_OS
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


def ssh_pull_direct(
    ip_address: str,
    port: int,
    os_type: str | None,
    username: str,
    password: str,
) -> tuple[str, str]:
    """
    Connect to a device via SSH, auto-detect the OS if unknown, pull the
    running configuration, and return ``(config_raw, detected_os_type)``.

    This is a *synchronous* / blocking function — callers running inside an
    async event loop must dispatch it via ``loop.run_in_executor``.

    Raises
    ------
    NetmikoAuthenticationException
        When the credentials are rejected by the device.
    NetmikoTimeoutException
        When the device is unreachable or the session times out.
    """
    logger.info(
        f"[SSH] ▶ {ip_address}:{port} | user={username} | os_hint={os_type!r}"
    )

    # ── 1. Auto-detect OS when not supplied or not in our command map ─────────
    if not os_type or os_type not in SHOW_RUN_COMMANDS:
        logger.info(
            f"[SSH] {ip_address}:{port} | os_hint={os_type!r} not in known map "
            f"— running SSHDetect"
        )
        detect_params = {
            "device_type": "autodetect",
            "host": ip_address,
            "port": port,
            "username": username,
            "password": password,
            "timeout": 30,
        }
        try:
            guesser = SSHDetect(**detect_params)
            detected = guesser.autodetect()
            logger.info(
                f"[SSH] SSHDetect raw result for {ip_address}: {detected!r}"
            )
            if detected and detected in SHOW_RUN_COMMANDS:
                os_type = detected
                logger.info(f"[SSH] {ip_address} → using detected OS: {os_type!r}")
            else:
                os_type = _DEFAULT_OS
                logger.warning(
                    f"[SSH] {ip_address} | SSHDetect returned {detected!r} "
                    f"(not in known map) → falling back to {_DEFAULT_OS!r}"
                )
        except (NetmikoAuthenticationException, NetmikoTimeoutException):
            raise
        except Exception as exc:
            logger.warning(
                f"[SSH] {ip_address}:{port} | SSHDetect failed → "
                f"falling back to {_DEFAULT_OS!r}. Reason: {exc}"
            )
            os_type = _DEFAULT_OS
    else:
        logger.info(f"[SSH] {ip_address}:{port} | using provided OS: {os_type!r}")

    # ── 2. Pull config ────────────────────────────────────────────────────────
    command = SHOW_RUN_COMMANDS.get(os_type, "show running-config")
    logger.info(
        f"[SSH] {ip_address}:{port} | os={os_type!r} | "
        f"running command: {command!r}"
    )

    connection_params = {
        "device_type": os_type,
        "host": ip_address,
        "port": port,
        "username": username,
        "password": password,
        "timeout": 30,
        "session_log": None,
    }

    with ConnectHandler(**connection_params) as conn:
        logger.info(f"[SSH] {ip_address}:{port} | connection established ✓")
        output = conn.send_command(command, read_timeout=60)

    logger.info(
        f"[SSH] {ip_address}:{port} | ✓ config pulled | "
        f"{len(output)} chars | os={os_type!r}"
    )
    return output, os_type
