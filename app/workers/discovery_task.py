"""
Discovery Celery task.

Flow:
  1. Load job from DB, parse IP range
  2. For each IP: ping → port scan → hostname resolve → guess vendor/OS
  3. Save each alive host to DB
  4. Publish events to Redis channel  discovery:{job_id}
  5. Honour cancellation: check Redis key  discovery:{job_id}:cancel
"""
import asyncio
import ipaddress
import json
import logging
import platform
import socket
import subprocess
from datetime import datetime, timezone

import redis as sync_redis

from app.core.config import settings
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

CHANNEL = "discovery:{}"
CANCEL_KEY = "discovery:{}:cancel"


# ── Low-level probes (synchronous, called from thread pool) ──────────────────

def _ping(ip: str, timeout: float) -> bool:
    """Return True if the host responds to a single ping."""
    is_win = platform.system().lower() == "windows"
    count_flag = "-n" if is_win else "-c"
    timeout_flag = "-w" if is_win else "-W"
    # Windows timeout is in ms; Linux/Mac in seconds
    timeout_val = str(int(timeout * 1000)) if is_win else str(max(1, int(timeout)))
    try:
        result = subprocess.run(
            ["ping", count_flag, "1", timeout_flag, timeout_val, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except Exception:
        return False


def _scan_ports(ip: str, ports: list[int], timeout: float) -> list[int]:
    """Return list of open TCP ports."""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports


def _resolve_hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _guess_vendor_os(open_ports: list[int]) -> tuple[str | None, str | None]:
    """Heuristic vendor/OS guess from open ports."""
    ports = set(open_ports)
    if 830 in ports:                          # NETCONF
        return "Juniper/Cisco", "junos"
    if 22 in ports and 23 in ports:           # SSH + Telnet
        return "Network Device", "cisco_ios"
    if 23 in ports:                           # Telnet only
        return "Network Device", "cisco_ios"
    if 22 in ports:
        return "Network Device", None
    return None, None


# ── Celery entry point ────────────────────────────────────────────────────────

@celery_app.task(name="app.workers.discovery_task.run_discovery")
def run_discovery(job_id: str) -> None:
    asyncio.run(_run_discovery(job_id))


# ── Async implementation ──────────────────────────────────────────────────────

async def _run_discovery(job_id: str) -> None:
    from sqlalchemy import select
    from app.core.database import AsyncSessionLocal
    from app.models.discovery import DiscoveryJob, DiscoveredHost

    r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
    channel = CHANNEL.format(job_id)
    cancel_key = CANCEL_KEY.format(job_id)

    # ── 1. Load & validate job ────────────────────────────────────────────────
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(DiscoveryJob).where(DiscoveryJob.id == job_id))
        job = result.scalar_one_or_none()
        if not job:
            logger.warning("Discovery job %s not found", job_id)
            return

        # Cache fields we need after the session closes
        ip_range = job.ip_range
        ports = job.ports
        timeout = job.timeout
        org_id = job.org_id

        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            host_list = list(network.hosts())
        except ValueError as exc:
            job.status = "failed"
            job.error_msg = str(exc)
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            r.publish(channel, json.dumps({"event": "error", "message": str(exc)}))
            r.close()
            return

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        job.total_hosts = len(host_list)
        await db.commit()

    r.publish(channel, json.dumps({
        "event": "started",
        "total": len(host_list),
        "job_id": job_id,
    }))

    # ── 2. Scan each IP ───────────────────────────────────────────────────────
    found = 0

    for idx, host_ip in enumerate(host_list):
        # Cancellation check
        if r.get(cancel_key):
            async with AsyncSessionLocal() as db:
                result = await db.execute(select(DiscoveryJob).where(DiscoveryJob.id == job_id))
                job = result.scalar_one()
                job.status = "cancelled"
                job.completed_at = datetime.now(timezone.utc)
                job.scanned_hosts = idx
                job.found_hosts = found
                await db.commit()
            r.publish(channel, json.dumps({"event": "cancelled", "scanned": idx, "found": found}))
            r.delete(cancel_key)
            break

        ip = str(host_ip)
        alive = _ping(ip, timeout)

        if alive:
            open_ports = _scan_ports(ip, ports, timeout)
            hostname = _resolve_hostname(ip)
            vendor_hint, os_type_hint = _guess_vendor_os(open_ports)
            found += 1

            async with AsyncSessionLocal() as db:
                host = DiscoveredHost(
                    job_id=job_id,
                    org_id=org_id,
                    ip_address=ip,
                    hostname=hostname,
                    is_alive=True,
                    open_ports=open_ports,
                    vendor_hint=vendor_hint,
                    os_type_hint=os_type_hint,
                )
                db.add(host)
                await db.commit()
                host_id = host.id

            r.publish(channel, json.dumps({
                "event": "host_found",
                "host": {
                    "id": host_id,
                    "ip_address": ip,
                    "hostname": hostname,
                    "open_ports": open_ports,
                    "vendor_hint": vendor_hint,
                    "os_type_hint": os_type_hint,
                },
            }))

        # Progress event every IP (UI can debounce if needed)
        r.publish(channel, json.dumps({
            "event": "progress",
            "scanned": idx + 1,
            "total": len(host_list),
            "found": found,
        }))

    else:
        # Loop completed normally (no break → not cancelled)
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(DiscoveryJob).where(DiscoveryJob.id == job_id))
            job = result.scalar_one()
            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
            job.scanned_hosts = len(host_list)
            job.found_hosts = found
            await db.commit()

        r.publish(channel, json.dumps({
            "event": "completed",
            "total": len(host_list),
            "found": found,
        }))

    r.close()
