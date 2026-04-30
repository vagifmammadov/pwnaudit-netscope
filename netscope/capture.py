"""Live packet capture engine — wraps scapy's AsyncSniffer with a thread-safe buffer."""
from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

from scapy.all import AsyncSniffer, get_if_list

from netscope.dissect import summarize


class CaptureEngine:
    """
    Captures packets in a background thread (scapy's AsyncSniffer) and stores
    them in an in-memory buffer that the UI thread drains every ~100ms.

    Optionally invokes ``packet_observer(pkt)`` for every captured packet —
    used by the rules engine to evaluate detection rules in real time.
    """

    def __init__(self) -> None:
        self._sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()
        self._buffer: list[tuple[dict[str, Any], bytes]] = []
        self._counter = 0
        self._start_time: Optional[float] = None
        self._iface: str = ""
        self._bpf: str = ""
        self._observer: Optional[Callable[[Any], None]] = None

    def set_observer(self, observer: Optional[Callable[[Any], None]]) -> None:
        """Install a per-packet observer (e.g. RuleEngine.observe).  Set to
        ``None`` to remove.  Observer is called from the sniffer thread."""
        self._observer = observer

    def is_running(self) -> bool:
        return self._sniffer is not None

    def start(self, iface: str, bpf_filter: str = "") -> None:
        if self._sniffer is not None:
            return
        self._counter = 0
        self._start_time = time.time()
        self._iface = iface
        self._bpf = bpf_filter
        with self._lock:
            self._buffer.clear()

        def on_packet(pkt) -> None:
            try:
                self._counter += 1
                row = summarize(pkt, self._counter, time.time() - (self._start_time or time.time()))
                raw = bytes(pkt)
            except Exception:
                return
            with self._lock:
                self._buffer.append((row, raw))
            obs = self._observer
            if obs is not None:
                try:
                    obs(pkt)
                except Exception:
                    pass

        kwargs: dict[str, Any] = {"prn": on_packet, "store": False, "iface": iface}
        if bpf_filter and bpf_filter.strip():
            kwargs["filter"] = bpf_filter.strip()

        sniffer = AsyncSniffer(**kwargs)
        sniffer.start()
        self._sniffer = sniffer

    def stop(self) -> None:
        sniffer = self._sniffer
        if sniffer is None:
            return
        self._sniffer = None
        try:
            sniffer.stop()
        except Exception:
            pass

    def drain(self) -> list[tuple[dict[str, Any], bytes]]:
        with self._lock:
            items = self._buffer
            self._buffer = []
        return items

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "running": self.is_running(),
            "iface": self._iface,
            "bpf": self._bpf,
            "captured": self._counter,
            "started_at": self._start_time,
        }


def list_interfaces() -> list[tuple[str, str]]:
    """Return [(iface_id, friendly_label)] for every available capture interface."""
    try:
        from scapy.arch.windows import get_windows_if_list
        ifs = get_windows_if_list()
        results: list[tuple[str, str]] = []
        for iface in ifs:
            name = iface.get("name") or iface.get("guid") or ""
            desc = iface.get("description") or iface.get("friendly_name") or name
            ips = iface.get("ips") or []
            ipv4 = next((ip for ip in ips if ":" not in ip), None)
            label_parts = [desc]
            if ipv4:
                label_parts.append(f"({ipv4})")
            results.append((name, " ".join(label_parts)))
        results.sort(key=lambda x: ("loopback" in x[1].lower(), x[1].lower()))
        return results
    except Exception:
        return [(i, i) for i in get_if_list()]
