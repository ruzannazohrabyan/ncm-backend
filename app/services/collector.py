import asyncio
import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException, SSHDetect
from sqlalchemy import select, update

from app.core.database import AsyncSessionLocal
from app.core.security import decrypt_secret
from app.models.device import Device
from app.models.credential import Credential
from app.models.config_snapshot import ConfigSnapshot
from app.models.change_event import ChangeEvent, AlertRule
from app.services.device_facts import DeviceFacts, collect_facts
from app.services.diff_engine import compute_diff
from app.services.notifier import send_alert


# ── Public outcome type returned by `pull_config` ─────────────────────────────

@dataclass
class PullConfigOutcome:
    """
    Rich outcome of a :func:`pull_config` call.

    ``success`` indicates whether a running-config snapshot was persisted.
    On failure, ``error_code`` is one of:

    * ``"device_missing"``       – no such device or device is inactive
    * ``"credentials_required"`` – no usable credential was supplied or saved
    * ``"credential_not_found"`` – the supplied ``credential_id`` does not exist
    * ``"auth_failed"``          – SSH credentials were rejected by the device
    * ``"timeout"``              – SSH session timed out
    * ``"ssh_error"``            – any other SSH/exec error

    All snapshot/sync fields are populated only when ``success=True``.
    """
    success: bool
    error_code: str | None = None
    error_message: str | None = None

    detected_os: str | None = None

    # Running config (always present on success)
    running_snapshot_id: str | None = None
    running_hash: str | None = None
    running_preview: str | None = None
    change_event_id: str | None = None

    # Startup config (only present when supported & pulled)
    startup_supported: bool = False
    startup_pull_failed: bool = False
    startup_snapshot_id: str | None = None
    startup_hash: str | None = None
    startup_preview: str | None = None
    in_sync: bool | None = None

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
    # Junos has no separate startup-config (candidate vs. committed). Treat as
    # unsupported rather than persisting commit history under config_type="startup",
    # which would cause permanent false-positive "out-of-sync" results.
    "junos": None,
    "routeros": None,  # RouterOS applies config immediately; no startup-config.
    "mikrotik_routeros": None,
}

# Fallback when SSHDetect returns an unrecognised type or None
_DEFAULT_OS = "cisco_ios"


async def pull_config(
    device_id: str,
    triggered_by: str | None = None,
    *,
    credential_id: str | None = None,
    username: str | None = None,
    password: str | None = None,
    port: int | None = None,
) -> PullConfigOutcome:
    """
    Pull the running-config (and startup-config when supported) for ``device_id``
    and persist it as :class:`ConfigSnapshot` rows.

    Credential resolution priority:

      1. Explicit ``credential_id`` argument (a saved Credential row).
      2. Inline ``username``+``password`` arguments (one-shot manual creds).
      3. ``device.credential_id`` (the device's saved credential).
      4. Otherwise: returns ``PullConfigOutcome(success=False,
         error_code="credentials_required")``.

    ``port`` overrides the device's stored port for this pull only and is not
    persisted onto the device row.

    The legacy scheduler call site ``await pull_config(device.id)`` still works
    because all override parameters are keyword-only and optional. The return
    type changed from ``bool`` to :class:`PullConfigOutcome`; the scheduler
    awaits and discards the result.
    """
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(select(Device).where(Device.id == device_id))
            device = result.scalar_one_or_none()
            if not device or not device.is_active:
                logger.warning(f"Device {device_id} not found or inactive")
                return PullConfigOutcome(
                    success=False,
                    error_code="device_missing",
                    error_message="Device not found or inactive",
                )

            # ── Resolve credentials ────────────────────────────────────────
            resolved_username: str | None = None
            resolved_password: str | None = None

            target_credential_id = credential_id or device.credential_id
            if target_credential_id and not (username and password):
                cred_result = await db.execute(
                    select(Credential).where(Credential.id == target_credential_id)
                )
                cred = cred_result.scalar_one_or_none()
                if cred is None:
                    if credential_id:
                        # Caller specifically asked for this credential — hard fail.
                        logger.error(
                            f"[PULL] credential_id={credential_id} not found "
                            f"for device {device_id}"
                        )
                        return PullConfigOutcome(
                            success=False,
                            error_code="credential_not_found",
                            error_message=f"Credential {credential_id} not found",
                        )
                    # Else: device's saved cred is dangling — fall through to
                    # the inline-creds path below.
                else:
                    resolved_username = cred.username
                    resolved_password = decrypt_secret(cred.encrypted_password)

            if resolved_username is None and username and password:
                resolved_username = username
                resolved_password = password

            if not resolved_username or not resolved_password:
                logger.warning(
                    f"[PULL] No credentials available for device {device_id} "
                    f"(saved={bool(device.credential_id)}, manual={bool(username)})"
                )
                return PullConfigOutcome(
                    success=False,
                    error_code="credentials_required",
                    error_message=(
                        "No SSH credentials available. Provide a saved credential "
                        "or inline username/password."
                    ),
                )

            target_port = port or device.port

            # Pull both running and startup configs. Netmiko/SSH is blocking,
            # so dispatch to the default executor to keep the event loop
            # responsive (critical now that this function is awaited directly
            # from request handlers).
            loop = asyncio.get_event_loop()
            running_config, startup_config, facts = await loop.run_in_executor(
                None,
                _ssh_pull_with_creds,
                device.ip_address,
                target_port,
                device.os_type,
                resolved_username,
                resolved_password,
            )
            running_hash = hashlib.sha256(running_config.encode()).hexdigest()
            startup_hash = hashlib.sha256(startup_config.encode()).hexdigest() if startup_config else None

            _apply_facts_to_device(device, facts)

            # Mark previous "running" snapshots as not latest. We update per
            # config_type so that a missing startup-config pull doesn't wipe the
            # is_latest flag from the previous startup snapshot.
            await db.execute(
                update(ConfigSnapshot)
                .where(
                    ConfigSnapshot.device_id == device_id,
                    ConfigSnapshot.config_type == "running",
                    ConfigSnapshot.is_latest == True,
                )
                .values(is_latest=False)
            )
            if startup_config:
                await db.execute(
                    update(ConfigSnapshot)
                    .where(
                        ConfigSnapshot.device_id == device_id,
                        ConfigSnapshot.config_type == "startup",
                        ConfigSnapshot.is_latest == True,
                    )
                    .values(is_latest=False)
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

            change_event_id: str | None = None

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
                change_event_id = change.id

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

            startup_snapshot_obj: ConfigSnapshot | None = None
            in_sync: bool | None = None

            # Create startup-config snapshot if available
            if startup_config:
                startup_snapshot_obj = ConfigSnapshot(
                    device_id=device_id,
                    triggered_by=triggered_by,
                    config_raw=startup_config,
                    hash=startup_hash,
                    config_type="startup",
                    trigger_type="manual" if triggered_by else "scheduled",
                    is_latest=True,
                )
                db.add(startup_snapshot_obj)
                await db.flush()

                # Detect changes in startup-config
                if last_startup and last_startup.hash != startup_hash:
                    diff_text = compute_diff(last_startup.config_raw, startup_config)
                    change = ChangeEvent(
                        device_id=device_id,
                        snapshot_before_id=last_startup.id,
                        snapshot_after_id=startup_snapshot_obj.id,
                        diff_text=diff_text,
                        severity="info",  # Startup changes are informational
                    )
                    db.add(change)
                    await db.flush()

                # Check if running and startup are in sync
                in_sync = running_hash == startup_hash
                if in_sync:
                    now = datetime.now(timezone.utc)
                    running_snapshot.synced_at = now
                    startup_snapshot_obj.synced_at = now
                    logger.info(
                        f"Device {device.hostname}: running-config and startup-config are in sync"
                    )
                else:
                    logger.warning(
                        f"Device {device.hostname}: OUT-OF-SYNC (running != startup)"
                    )

            device.last_seen = datetime.now(timezone.utc)
            await db.commit()
            logger.info(f"Config pulled for device {device.hostname}")

            # Whether the platform exposes a separate startup-config concept
            # at all (regardless of pull success). This stays accurate when we
            # later add `startup_pull_failed` reporting from `_ssh_pull_with_creds`.
            startup_supported = (
                SHOW_STARTUP_COMMANDS.get(device.os_type or _DEFAULT_OS) is not None
            )

            return PullConfigOutcome(
                success=True,
                detected_os=device.os_type,
                running_snapshot_id=running_snapshot.id,
                running_hash=running_hash,
                running_preview=running_config[:500],
                change_event_id=change_event_id,
                startup_supported=startup_supported,
                startup_pull_failed=startup_supported and startup_config is None,
                startup_snapshot_id=startup_snapshot_obj.id if startup_snapshot_obj else None,
                startup_hash=startup_hash,
                startup_preview=startup_config[:500] if startup_config else None,
                in_sync=in_sync,
            )

        except NetmikoAuthenticationException:
            logger.error(f"Auth failed for device {device_id}")
            return PullConfigOutcome(
                success=False,
                error_code="auth_failed",
                error_message="SSH authentication failed — check username/password",
            )
        except NetmikoTimeoutException:
            logger.error(f"Timeout connecting to device {device_id}")
            return PullConfigOutcome(
                success=False,
                error_code="timeout",
                error_message="SSH connection timed out — is the device reachable?",
            )
        except Exception as e:
            logger.exception(f"Unexpected error pulling config for device {device_id}: {e}")
            await db.rollback()
            return PullConfigOutcome(
                success=False,
                error_code="ssh_error",
                error_message=str(e),
            )


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


def _ssh_pull_with_creds(
    ip_address: str,
    port: int,
    os_type: str | None,
    username: str,
    password: str,
) -> tuple[str, str | None, DeviceFacts]:
    """
    Connect via SSH using raw credentials and return
    ``(running_config, startup_config, facts)``.

    Inventory facts are harvested in the same SSH session as the config pull
    to avoid the cost of a second login. Failures during startup-config or
    facts collection are logged as warnings but never abort the running-config
    pull.

    Note: this is a blocking call. Async callers must dispatch via
    ``loop.run_in_executor``.
    """
    effective_os = os_type or _DEFAULT_OS
    run_command = SHOW_RUN_COMMANDS.get(effective_os, "show running-config")
    startup_command = SHOW_STARTUP_COMMANDS.get(effective_os)

    connection_params = {
        "device_type": effective_os,
        "host": ip_address,
        "port": port,
        "username": username,
        "password": password,
        "timeout": 30,
        "session_log": None,
    }

    with ConnectHandler(**connection_params) as conn:
        running_config = conn.send_command(run_command, read_timeout=60)

        startup_config: str | None = None
        if startup_command:
            try:
                startup_config = conn.send_command(startup_command, read_timeout=60)
            except Exception as exc:
                logger.warning(
                    f"[CONFIG] Failed to get startup-config for {ip_address}: {exc}"
                )

        try:
            facts = collect_facts(conn, effective_os)
        except Exception as exc:
            logger.warning(
                f"[FACTS] Failed to collect inventory for {ip_address}: {exc}"
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
        device.os_name = facts.os_name
    if facts.os_version:
        device.os_version = facts.os_version
    if facts.os_image:
        device.os_image = facts.os_image
    if facts.hardware:
        device.hardware = facts.hardware
    if facts.uptime:
        device.uptime = facts.uptime
    if facts.as_dict():
        device.facts_updated_at = datetime.now(timezone.utc)


def ssh_pull_direct(
    ip_address: str,
    port: int,
    os_type: str | None,
    username: str,
    password: str,
) -> tuple[str, str | None, str, DeviceFacts, bool]:
    """
    Connect to a device via SSH, auto-detect the OS if unknown, pull both the
    running and (when supported) startup configurations, and return
    ``(running_config, startup_config, detected_os_type, facts, startup_pull_failed)``.

    ``startup_config`` is ``None`` when the platform has no separate
    startup-config concept (e.g. RouterOS, Junos) — in that case
    ``startup_pull_failed`` is ``False`` because nothing was attempted.

    ``startup_pull_failed`` is ``True`` only when the platform *does* support
    startup-config but the command failed at runtime. The running-config pull
    is the primary contract of this function and is never aborted by a failed
    startup-config pull or by ancillary fact-collection failures.

    Inventory facts (model, serial number, OS version, image, uptime, etc.)
    are gathered in the same SSH session via :func:`collect_facts`. If
    fact-collection fails for any reason, an empty :class:`DeviceFacts` is
    returned.

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

    # ── 2. Pull running- and (optionally) startup-config ──────────────────────
    run_command = SHOW_RUN_COMMANDS.get(os_type, "show running-config")
    startup_command = SHOW_STARTUP_COMMANDS.get(os_type)
    logger.info(
        f"[SSH] {ip_address}:{port} | os={os_type!r} | "
        f"running command: {run_command!r} | "
        f"startup command: {startup_command!r}"
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

    startup_output: str | None = None
    startup_pull_failed = False

    with ConnectHandler(**connection_params) as conn:
        logger.info(f"[SSH] {ip_address}:{port} | connection established ✓")
        output = conn.send_command(run_command, read_timeout=60)

        if startup_command:
            try:
                startup_output = conn.send_command(startup_command, read_timeout=60)
            except Exception as exc:
                startup_pull_failed = True
                logger.warning(
                    f"[SSH] {ip_address}:{port} | startup-config pull failed: {exc}"
                )

        try:
            facts = collect_facts(conn, os_type)
        except Exception as exc:
            logger.warning(
                f"[FACTS] {ip_address}:{port} | inventory collection failed: {exc}"
            )
            facts = DeviceFacts()

    logger.info(
        f"[SSH] {ip_address}:{port} | ✓ running pulled ({len(output)} chars) | "
        f"startup={'-' if startup_output is None else f'{len(startup_output)} chars'}"
        f"{' (FAILED)' if startup_pull_failed else ''} | "
        f"os={os_type!r} | facts={facts.as_dict()}"
    )
    return output, startup_output, os_type, facts, startup_pull_failed
