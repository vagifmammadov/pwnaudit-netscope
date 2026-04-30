"""
Windows Wi-Fi state helpers — extract SSID, BSSID, channel, band, and signal
strength for connected adapters via the ``netsh`` CLI (always available on
Windows 10/11, no extra deps).

We use this to populate the Wireless tab with real numbers and to tag the
capture session with whether traffic is flowing over the 2.4 GHz or 5 GHz
band — useful when the user is investigating throughput / coverage between
the two on their own network.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional

# ── Channel → band mapping (IEEE 802.11) ─────────────────────────────
#   1-14         → 2.4 GHz
#   32-177       → 5 GHz
#   1-233 (6E)   → 6 GHz (channel numbers reused, distinguished by 'frequency'
#                  in netsh output when available)
_CH_24 = set(range(1, 15))
_CH_5 = set(range(32, 178))


@dataclass
class WifiAdapter:
    """One Wi-Fi adapter as reported by ``netsh wlan show interfaces``."""

    name: str = ""               # OS friendly name (matches psutil name)
    description: str = ""        # driver description
    guid: str = ""
    state: str = ""              # connected / disconnected
    ssid: str = ""
    bssid: str = ""
    radio_type: str = ""         # 802.11ax, 802.11ac, …
    channel: Optional[int] = None
    band_label: str = ""         # "2.4 GHz", "5 GHz", "6 GHz", or ""
    signal_pct: Optional[int] = None
    rx_mbps: Optional[float] = None
    tx_mbps: Optional[float] = None
    auth: str = ""
    cipher: str = ""

    @property
    def is_connected(self) -> bool:
        return self.state.lower() == "connected"


@dataclass
class WifiNetwork:
    """One nearby Wi-Fi network from ``netsh wlan show networks mode=bssid``."""

    ssid: str = ""
    bssid: str = ""
    signal_pct: Optional[int] = None
    channel: Optional[int] = None
    band_label: str = ""
    radio_type: str = ""
    auth: str = ""
    encryption: str = ""


def _run_netsh(args: list[str]) -> str:
    """Run ``netsh`` and return its stdout, or empty string on error."""
    try:
        proc = subprocess.run(
            ["netsh", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def channel_to_band(channel: Optional[int]) -> str:
    if channel is None:
        return ""
    if channel in _CH_24:
        return "2.4 GHz"
    if channel in _CH_5:
        return "5 GHz"
    return ""


def _parse_channel(value: str) -> Optional[int]:
    m = re.search(r"(\d+)", value)
    return int(m.group(1)) if m else None


def _parse_signal(value: str) -> Optional[int]:
    m = re.search(r"(\d+)\s*%", value)
    return int(m.group(1)) if m else None


def _parse_rate(value: str) -> Optional[float]:
    m = re.search(r"([\d.]+)", value)
    return float(m.group(1)) if m else None


def _split_kv(line: str) -> Optional[tuple[str, str]]:
    if ":" not in line:
        return None
    key, _, value = line.partition(":")
    return key.strip().lower(), value.strip()


def list_wifi_adapters() -> list[WifiAdapter]:
    """
    Return one ``WifiAdapter`` per Wi-Fi interface known to Windows, populated
    with the live state where available.

    Empty list if ``netsh`` isn't available or no Wi-Fi adapter is present.
    """
    output = _run_netsh(["wlan", "show", "interfaces"])
    if not output:
        return []

    adapters: list[WifiAdapter] = []
    current: Optional[WifiAdapter] = None
    for raw in output.splitlines():
        line = raw.rstrip()
        kv = _split_kv(line)
        if not kv:
            continue
        key, value = kv
        if key == "name":
            if current:
                adapters.append(current)
            current = WifiAdapter(name=value)
            continue
        if not current:
            continue
        if key == "description":
            current.description = value
        elif key == "guid":
            current.guid = value
        elif key == "state":
            current.state = value
        elif key == "ssid":
            current.ssid = value
        elif key == "bssid":
            current.bssid = value
        elif key == "radio type":
            current.radio_type = value
        elif key == "channel":
            current.channel = _parse_channel(value)
            current.band_label = channel_to_band(current.channel)
        elif key == "signal":
            current.signal_pct = _parse_signal(value)
        elif key == "receive rate (mbps)":
            current.rx_mbps = _parse_rate(value)
        elif key == "transmit rate (mbps)":
            current.tx_mbps = _parse_rate(value)
        elif key == "authentication":
            current.auth = value
        elif key == "cipher":
            current.cipher = value
    if current:
        adapters.append(current)
    return adapters


def current_wifi_for(adapter_name: str) -> Optional[WifiAdapter]:
    """Return the live state of one adapter by friendly name, or None."""
    for adapter in list_wifi_adapters():
        if adapter.name == adapter_name:
            return adapter
    return None


def list_visible_networks() -> list[WifiNetwork]:
    """
    Return all networks the radio currently sees (one entry per BSSID — so
    one SSID with two APs on different channels appears twice).

    Empty list if scanning isn't supported or netsh fails.
    """
    output = _run_netsh(["wlan", "show", "networks", "mode=bssid"])
    if not output:
        return []

    nets: list[WifiNetwork] = []
    current_ssid = ""
    current_auth = ""
    current_enc = ""
    current_radio = ""
    current_net: Optional[WifiNetwork] = None
    for raw in output.splitlines():
        line = raw.rstrip()
        kv = _split_kv(line)
        if not kv:
            continue
        key, value = kv
        if key.startswith("ssid") and not key.startswith("bssid"):
            # New SSID block — reset transients.
            current_ssid = value
            current_auth = ""
            current_enc = ""
            current_radio = ""
        elif key == "authentication":
            current_auth = value
        elif key == "encryption":
            current_enc = value
        elif key == "radio type":
            current_radio = value
            if current_net is not None:
                current_net.radio_type = value
        elif key.startswith("bssid"):
            if current_net is not None:
                nets.append(current_net)
            current_net = WifiNetwork(
                ssid=current_ssid,
                bssid=value,
                auth=current_auth,
                encryption=current_enc,
                radio_type=current_radio,
            )
        elif current_net is not None and key == "signal":
            current_net.signal_pct = _parse_signal(value)
        elif current_net is not None and key == "channel":
            current_net.channel = _parse_channel(value)
            current_net.band_label = channel_to_band(current_net.channel)
    if current_net is not None:
        nets.append(current_net)

    nets.sort(key=lambda n: (-(n.signal_pct or 0), n.ssid.lower()))
    return nets
