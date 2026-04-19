"""
Device fact harvesting.

Provides a single entry point — :func:`collect_facts` — that connects to a
device over SSH (using an already-open Netmiko connection or by opening a new
one) and returns a :class:`DeviceFacts` object describing the model, OS,
firmware version, image filename, serial number and uptime.

Each supported platform has its own ``_parse_<os>`` helper. Parsing is
regex-based and forgiving: any field that cannot be located is left as
``None`` rather than raising — partial inventory data is more useful than
none at all.

Currently supported ``os_type`` values:

* ``cisco_ios``       — IOS classic (12.x / 15.x)
* ``cisco_xe``        — IOS-XE (16.x / 17.x, including Catalyst 9k)
* ``cisco_nxos``      — NX-OS (Nexus)
* ``junos``           — Juniper JunOS
* ``mikrotik_routeros`` / ``routeros`` — Mikrotik RouterOS
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, asdict
from typing import Optional

from netmiko.base_connection import BaseConnection

logger = logging.getLogger(__name__)


# ── Public datamodel ─────────────────────────────────────────────────────────

@dataclass
class DeviceFacts:
    """Inventory facts collected from a device. Every field is optional."""
    model: Optional[str] = None
    serial_number: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_image: Optional[str] = None
    hardware: Optional[str] = None
    uptime: Optional[str] = None
    vendor: Optional[str] = None

    def as_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


# ── Per-platform commands ────────────────────────────────────────────────────
# Some platforms need more than one command to expose every field
# (e.g. Mikrotik splits "system resource" and "system routerboard").
_FACT_COMMANDS: dict[str, tuple[str, ...]] = {
    "cisco_ios": ("show version",),
    "cisco_xe": ("show version",),
    "cisco_nxos": ("show version",),
    "junos": ("show version", "show chassis hardware"),
    "mikrotik_routeros": ("/system resource print", "/system routerboard print"),
    "routeros": ("/system resource print", "/system routerboard print"),
}


# ── Public API ───────────────────────────────────────────────────────────────

def collect_facts(conn: BaseConnection, os_type: str) -> DeviceFacts:
    """
    Run the appropriate inventory command(s) on ``conn`` and return parsed
    :class:`DeviceFacts`. The connection must already be authenticated and
    in normal exec mode. Caller is responsible for opening / closing it.

    Unknown ``os_type`` values fall back to running ``show version`` and
    parsing it as Cisco IOS — this matches the collector's own
    ``_DEFAULT_OS`` behaviour and is the safest guess for an unknown SSH
    network device.
    """
    commands = _FACT_COMMANDS.get(os_type, ("show version",))
    outputs: list[str] = []
    for cmd in commands:
        try:
            out = conn.send_command(cmd, read_timeout=30)
            outputs.append(out or "")
        except Exception as exc:
            logger.warning(f"[FACTS] Command {cmd!r} failed on os={os_type!r}: {exc}")
            outputs.append("")

    parser = _PARSERS.get(os_type, _parse_cisco_ios)
    facts = parser(*outputs)
    logger.info(f"[FACTS] Parsed os={os_type!r} → {facts.as_dict()}")
    return facts


# ── Helpers ──────────────────────────────────────────────────────────────────

def _first_match(pattern: str, text: str, group: int = 1, flags: int = re.IGNORECASE) -> Optional[str]:
    """Return the first regex match group, or ``None`` if no match."""
    if not text:
        return None
    m = re.search(pattern, text, flags)
    return m.group(group).strip() if m else None


# ── Parsers ──────────────────────────────────────────────────────────────────

def _parse_cisco_ios(show_version: str = "", *_extra: str) -> DeviceFacts:
    """
    Parse ``show version`` output for classic IOS and (mostly) IOS-XE.

    Handles both the legacy single-line ``Cisco IOS Software ... Version X``
    style and the newer multiline IOS-XE banner. Falls through to
    :func:`_parse_cisco_xe` heuristics when the output looks like IOS-XE.
    """
    text = show_version or ""

    if "IOS XE" in text or "IOS-XE" in text:
        return _parse_cisco_xe(text)

    os_version = _first_match(r"Cisco IOS Software.*?Version\s+([^\s,]+)", text)
    os_name = "IOS" if os_version else None
    os_image = _first_match(r'System image file is\s+"([^"]+)"', text)
    uptime = _first_match(r"\b(?:uptime is|uptime:)\s+(.+)", text)
    serial = _first_match(r"Processor board ID\s+(\S+)", text)
    # "cisco CISCO2911/K9 (revision 1.0) with ..." or "cisco WS-C2960-24TC-L ..."
    hardware = _first_match(r"^cisco\s+(\S+)\s+(?:\([^)]+\)\s+)?with", text, flags=re.IGNORECASE | re.MULTILINE)
    model = hardware

    return DeviceFacts(
        vendor="cisco",
        os_name=os_name,
        os_version=os_version,
        os_image=os_image,
        uptime=uptime,
        serial_number=serial,
        hardware=hardware,
        model=model,
    )


def _parse_cisco_xe(show_version: str = "", *_extra: str) -> DeviceFacts:
    """Parse ``show version`` output for IOS-XE (Catalyst 9k, ISR4k, ASR1k)."""
    text = show_version or ""

    os_version = (
        _first_match(r"Cisco IOS XE Software,\s+Version\s+(\S+)", text)
        or _first_match(r"Cisco IOS Software \[[^\]]+\].*?Version\s+([^\s,]+)", text)
    )
    os_image = _first_match(r'System image file is\s+"([^"]+)"', text)
    uptime = _first_match(r"\b(?:uptime is|uptime:)\s+(.+)", text)
    # IOS-XE usually exposes the model + serial in a "Switch Ports Model ..." table
    # or as explicit "Model Number" / "System Serial Number" lines.
    model = (
        _first_match(r"Model [Nn]umber\s*:\s*(\S+)", text)
        or _first_match(r"^cisco\s+(\S+).*processor", text, flags=re.IGNORECASE | re.MULTILINE)
    )
    serial = (
        _first_match(r"System [Ss]erial [Nn]umber\s*:\s*(\S+)", text)
        or _first_match(r"Processor board ID\s+(\S+)", text)
    )

    return DeviceFacts(
        vendor="cisco",
        os_name="IOS-XE",
        os_version=os_version,
        os_image=os_image,
        uptime=uptime,
        serial_number=serial,
        hardware=model,
        model=model,
    )


def _parse_cisco_nxos(show_version: str = "", *_extra: str) -> DeviceFacts:
    """Parse ``show version`` output for NX-OS."""
    text = show_version or ""

    os_version = (
        _first_match(r"NXOS:\s+version\s+(\S+)", text)
        or _first_match(r"^\s*system:\s+version\s+(\S+)", text, flags=re.IGNORECASE | re.MULTILINE)
    )
    os_image = (
        _first_match(r"NXOS image file is:\s+(\S+)", text)
        or _first_match(r"system image file is:\s+(\S+)", text)
    )
    uptime = _first_match(r"Kernel uptime is\s+(.+)", text)
    hardware = _first_match(r"^\s*cisco\s+(.+chassis)", text, flags=re.IGNORECASE | re.MULTILINE)
    serial = _first_match(r"Processor Board ID\s+(\S+)", text)

    return DeviceFacts(
        vendor="cisco",
        os_name="NX-OS",
        os_version=os_version,
        os_image=os_image,
        uptime=uptime,
        serial_number=serial,
        hardware=hardware,
        model=hardware,
    )


def _parse_junos(show_version: str = "", chassis_hw: str = "", *_extra: str) -> DeviceFacts:
    """Parse ``show version`` and ``show chassis hardware`` for JunOS."""
    v_text = show_version or ""
    h_text = chassis_hw or ""

    model = _first_match(r"^Model:\s+(\S+)", v_text, flags=re.MULTILINE)
    os_version = (
        _first_match(r"JUNOS Software Release\s+\[([^\]]+)\]", v_text)
        or _first_match(r"^Junos:\s+(\S+)", v_text, flags=re.MULTILINE)
    )
    # In `show chassis hardware`, the Chassis line carries the serial:
    # "Chassis                                JN1234ABCD     SRX340"
    serial = _first_match(r"^Chassis\s+(\S+)", h_text, flags=re.MULTILINE)

    return DeviceFacts(
        vendor="juniper",
        os_name="JUNOS",
        os_version=os_version,
        serial_number=serial,
        hardware=model,
        model=model,
    )


def _parse_routeros(resource: str = "", routerboard: str = "", *_extra: str) -> DeviceFacts:
    """Parse ``/system resource print`` and ``/system routerboard print`` (RouterOS)."""
    r_text = resource or ""
    b_text = routerboard or ""

    os_version = _first_match(r"version:\s*([^\s\r\n]+)", r_text)
    uptime = _first_match(r"uptime:\s*([^\r\n]+)", r_text)
    board = _first_match(r"board-name:\s*([^\r\n]+)", r_text)
    model = _first_match(r"model:\s*([^\r\n]+)", b_text) or board
    serial = _first_match(r"serial-number:\s*([^\s\r\n]+)", b_text)
    firmware = _first_match(r"current-firmware:\s*([^\s\r\n]+)", b_text)

    return DeviceFacts(
        vendor="mikrotik",
        os_name="RouterOS",
        os_version=os_version,
        os_image=firmware,
        uptime=uptime,
        serial_number=serial,
        hardware=model,
        model=model,
    )


_PARSERS = {
    "cisco_ios": _parse_cisco_ios,
    "cisco_xe": _parse_cisco_xe,
    "cisco_nxos": _parse_cisco_nxos,
    "junos": _parse_junos,
    "mikrotik_routeros": _parse_routeros,
    "routeros": _parse_routeros,
}
