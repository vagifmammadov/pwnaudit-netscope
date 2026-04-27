"""Interface enumeration: psutil for live counters, scapy for NPF mapping."""
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Optional

import psutil


@dataclass
class InterfaceInfo:
    psutil_name: str          # friendly name as psutil reports it (e.g. "Wi-Fi")
    description: str          # human description (driver name)
    ipv4: Optional[str]
    ipv6: Optional[str]
    mac: Optional[str]
    is_up: bool
    speed_mbps: int
    iface_type: str           # "wifi" | "ethernet" | "bluetooth" | "loopback" | "vpn" | "other"


def _classify(name: str, description: str) -> str:
    lower = (name + " " + description).lower()
    if "loopback" in lower or name.lower() == "lo":
        return "loopback"
    if any(k in lower for k in ("wi-fi", "wifi", "wireless", "802.11", "wlan")):
        return "wifi"
    if "bluetooth" in lower:
        return "bluetooth"
    if any(k in lower for k in ("vpn", "tap", "tun", "wireguard", "openvpn", "tailscale", "anyconnect", "nordlynx", "zerotier")):
        return "vpn"
    if any(k in lower for k in ("ethernet", "lan", "gbe", "gigabit", "realtek", "intel", "broadcom", "killer", "marvell", "atheros", "aquantia")):
        return "ethernet"
    return "other"


def _windows_descriptions() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        from scapy.arch.windows import get_windows_if_list
        for iface in get_windows_if_list():
            friendly = iface.get("friendly_name") or ""
            desc = iface.get("description") or ""
            if friendly:
                out[friendly] = desc
    except Exception:
        pass
    return out


def list_local_interfaces() -> list[InterfaceInfo]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    descriptions = _windows_descriptions()

    af_link = getattr(psutil, "AF_LINK", None)

    out: list[InterfaceInfo] = []
    for nic, addr_list in addrs.items():
        ipv4 = next((a.address for a in addr_list if a.family == socket.AF_INET), None)
        ipv6 = next((a.address for a in addr_list if a.family == socket.AF_INET6), None)
        mac: Optional[str] = None
        if af_link is not None:
            mac = next((a.address for a in addr_list if a.family == af_link), None)

        stat = stats.get(nic)
        is_up = bool(stat.isup) if stat else False
        speed = int(stat.speed) if stat else 0

        desc = descriptions.get(nic) or nic
        out.append(InterfaceInfo(
            psutil_name=nic,
            description=desc,
            ipv4=ipv4,
            ipv6=ipv6,
            mac=mac,
            is_up=is_up,
            speed_mbps=speed,
            iface_type=_classify(nic, desc),
        ))

    type_order = {"wifi": 0, "ethernet": 1, "vpn": 2, "bluetooth": 3, "other": 4, "loopback": 5}
    out.sort(key=lambda i: (
        not i.is_up,
        not bool(i.ipv4),
        type_order.get(i.iface_type, 99),
        i.psutil_name.lower(),
    ))
    return out


def scapy_iface_for(psutil_name: str) -> Optional[str]:
    """
    Map a psutil-friendly interface name to its scapy / NPF GUID name.
    Returns None if no mapping was found (caller should fall back to the
    friendly name itself — scapy on Windows can usually accept it).
    """
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
    except Exception:
        return None

    for iface in ifaces:
        if iface.get("friendly_name") == psutil_name:
            return iface.get("name")
    for iface in ifaces:
        if iface.get("description") == psutil_name:
            return iface.get("name")
    for iface in ifaces:
        if iface.get("name") == psutil_name:
            return iface.get("name")
    return None
