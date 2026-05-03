"""Live packet capture engine — wraps scapy's AsyncSniffer with a thread-safe buffer."""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

from scapy.all import AsyncSniffer, get_if_list

from netscope.dissect import summarize

logger = logging.getLogger(__name__)


class CaptureEngine:
    """
    Captures packets in a background thread (scapy's AsyncSniffer) and stores
    them in an in-memory buffer that the UI thread drains every ~100ms.

    Optionally invokes ``packet_observer(pkt)`` for every captured packet —
    used by the rules engine to evaluate detection rules in real time.
    """

    def __init__(self) -> None:
        self._sniffer: Optional[AsyncSniffer] = None
        # _lifecycle guards start/stop/is_running so two callers can't race
        # into a half-torn-down sniffer; _buf_lock guards the packet buffer
        # and counter on the (possibly multi-threaded) sniffer side.
        self._lifecycle = threading.Lock()
        self._buf_lock = threading.Lock()
        self._buffer: list[tuple[dict[str, Any], bytes]] = []
        self._counter = 0
        self._start_time: Optional[float] = None
        self._iface: str = ""
        self._bpf: str = ""
        self._observer: Optional[Callable[[Any], None]] = None
        # Surfaces of the last in-thread error so the UI can show it instead
        # of capture silently going dark.
        self._last_error: Optional[str] = None
        # Counters for diagnostics (capinfos-style stats endpoint).
        self._dropped_dissect = 0
        self._dropped_observer = 0

    def set_observer(self, observer: Optional[Callable[[Any], None]]) -> None:
        """Install a per-packet observer (e.g. RuleEngine.observe).  Set to
        ``None`` to remove.  Observer is called from the sniffer thread."""
        self._observer = observer

    def is_running(self) -> bool:
        return self._sniffer is not None

    def last_error(self) -> Optional[str]:
        return self._last_error

    def start(self, iface: str, bpf_filter: str = "") -> None:
        with self._lifecycle:
            if self._sniffer is not None:
                return
            self._counter = 0
            self._start_time = time.time()
            self._iface = iface
            self._bpf = bpf_filter
            self._last_error = None
            self._dropped_dissect = 0
            self._dropped_observer = 0
            with self._buf_lock:
                self._buffer.clear()

            def on_packet(pkt) -> None:
                # Counter increment must be atomic w.r.t. the buffer write so
                # row numbers and queued rows stay in lock-step.  Holding the
                # buffer lock for the whole hot path is fine — it's only ever
                # contended by drain() at 100ms intervals.
                t0 = self._start_time or time.time()
                try:
                    raw = bytes(pkt)
                except Exception as exc:
                    self._dropped_dissect += 1
                    logger.debug("capture: bytes(pkt) failed: %s", exc)
                    return
                try:
                    with self._buf_lock:
                        self._counter += 1
                        n = self._counter
                    row = summarize(pkt, n, time.time() - t0)
                    with self._buf_lock:
                        self._buffer.append((row, raw))
                except Exception as exc:
                    self._dropped_dissect += 1
                    # Don't spam the log on every malformed packet — debug only.
                    logger.debug("capture: summarize/append failed: %s", exc)
                    return
                obs = self._observer
                if obs is not None:
                    try:
                        obs(pkt)
                    except Exception as exc:
                        self._dropped_observer += 1
                        logger.debug("capture: observer crashed: %s", exc)

            kwargs: dict[str, Any] = {"prn": on_packet, "store": False, "iface": iface}
            if bpf_filter and bpf_filter.strip():
                kwargs["filter"] = bpf_filter.strip()

            try:
                sniffer = AsyncSniffer(**kwargs)
                sniffer.start()
            except Exception as exc:
                self._last_error = str(exc)
                logger.warning("capture: AsyncSniffer.start failed: %s", exc)
                raise
            self._sniffer = sniffer

    def stop(self) -> None:
        # Take the sniffer reference out under the lock so a concurrent
        # start() can't reuse a half-stopped sniffer; only NULL the slot
        # AFTER the underlying thread has been torn down.
        with self._lifecycle:
            sniffer = self._sniffer
            if sniffer is None:
                return
            try:
                sniffer.stop()
            except Exception as exc:
                logger.debug("capture: sniffer.stop raised: %s", exc)
            finally:
                self._sniffer = None

    def drain(self) -> list[tuple[dict[str, Any], bytes]]:
        with self._buf_lock:
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
            "dropped_dissect": self._dropped_dissect,
            "dropped_observer": self._dropped_observer,
            "last_error": self._last_error,
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
