"""Welcome / interface-picker page with live sparklines (real psutil counters)."""
from __future__ import annotations

import collections
import time
from typing import Optional

import psutil

from PyQt6.QtCore import (
    Qt, QTimer, QObject, pyqtSignal, QSize,
)
from PyQt6.QtGui import (
    QColor, QPainter, QPainterPath, QPen, QLinearGradient,
)
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QFrame, QScrollArea, QSizePolicy,
)

from netscope.interfaces import InterfaceInfo, list_local_interfaces, scapy_iface_for
from netscope.theme import (
    ACCENT, ACCENT_DEEP, BG, BORDER, SURFACE, SURFACE_ALT, TEXT, TEXT_DIM,
)


# ── Sparkline widget ──────────────────────────────────────────────────────
class Sparkline(QWidget):
    """A live mini line chart for packets-per-second over recent history."""

    def __init__(self, parent=None, history: int = 80):
        super().__init__(parent)
        self._values: collections.deque[float] = collections.deque(
            [0.0] * history, maxlen=history,
        )
        self.setFixedHeight(30)
        self.setMinimumWidth(180)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

    def push(self, value: float) -> None:
        self._values.append(max(0.0, float(value)))
        self.update()

    def reset(self) -> None:
        history = self._values.maxlen or 80
        self._values.clear()
        self._values.extend([0.0] * history)
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        w = self.width()
        h = self.height()
        if w < 4 or h < 4:
            return

        values = list(self._values)
        n = len(values)
        peak = max(values) if values else 0.0

        # Always draw a faint baseline
        p.setPen(QPen(QColor(BORDER), 1))
        p.drawLine(0, h - 1, w, h - 1)

        if peak <= 0 or n < 2:
            pen = QPen(QColor("#1F2937"))
            pen.setStyle(Qt.PenStyle.DashLine)
            p.setPen(pen)
            p.drawLine(0, h // 2, w, h // 2)
            return

        path = QPainterPath()
        for i, v in enumerate(values):
            x = i * (w - 1) / max(n - 1, 1)
            y = (h - 4) - (v / peak) * (h - 6) + 1
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)

        fill = QPainterPath(path)
        fill.lineTo(w - 1, h - 1)
        fill.lineTo(0, h - 1)
        fill.closeSubpath()

        gradient = QLinearGradient(0, 0, 0, h)
        gradient.setColorAt(0.0, QColor(0, 245, 180, 90))
        gradient.setColorAt(1.0, QColor(0, 245, 180, 0))
        p.fillPath(fill, gradient)

        line_pen = QPen(QColor(ACCENT))
        line_pen.setWidthF(1.6)
        line_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        line_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(line_pen)
        p.drawPath(path)


# ── Traffic monitor (real OS counters) ────────────────────────────────────
class TrafficMonitor(QObject):
    """Polls psutil's per-interface counters and emits real packets-per-second."""

    rates_updated = pyqtSignal(dict)  # {psutil_name: pps}

    def __init__(self, parent=None, interval_ms: int = 750):
        super().__init__(parent)
        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._poll)
        self._last_counters: Optional[dict] = None
        self._last_time: Optional[float] = None

    def start(self) -> None:
        self._last_counters = None
        self._last_time = None
        self._active = True
        self._poll()
        self._timer.start()

    def stop(self) -> None:
        self._active = False
        self._timer.stop()

    def is_active(self) -> bool:
        return getattr(self, "_active", False)

    def _poll(self) -> None:
        try:
            counters = psutil.net_io_counters(pernic=True)
        except Exception:
            return
        now = time.time()
        rates: dict[str, float] = {}
        if self._last_counters is not None and self._last_time is not None:
            dt = max(now - self._last_time, 0.001)
            for nic, stat in counters.items():
                prev = self._last_counters.get(nic)
                if prev is None:
                    continue
                cur = stat.packets_sent + stat.packets_recv
                old = prev.packets_sent + prev.packets_recv
                rates[nic] = max(0, cur - old) / dt
        self._last_counters = counters
        self._last_time = now
        if rates:
            self.rates_updated.emit(rates)


# ── Interface card ────────────────────────────────────────────────────────
_TYPE_GLYPH = {
    "wifi":      "📶",
    "ethernet":  "🖧",
    "bluetooth": "🔵",
    "vpn":       "🔐",
    "loopback":  "🔁",
    "other":     "🌐",
}

_TYPE_LABEL = {
    "wifi":      "Wi-Fi",
    "ethernet":  "Ethernet",
    "bluetooth": "Bluetooth",
    "vpn":       "VPN / Virtual",
    "loopback":  "Loopback",
    "other":     "Other",
}


class InterfaceCard(QFrame):
    """One row in the welcome list — fully clickable, with live sparkline."""

    clicked = pyqtSignal(str)  # emits psutil_name

    def __init__(self, info: InterfaceInfo, parent=None):
        super().__init__(parent)
        self.setObjectName("ifaceCard")
        self.info = info
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(64)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setProperty("inactive", "true" if not info.is_up else "false")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(14)

        glyph = QLabel(_TYPE_GLYPH.get(info.iface_type, "🌐"))
        glyph.setStyleSheet("font-size: 20px;")
        glyph.setFixedWidth(32)
        glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        glyph.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        layout.addWidget(glyph)

        text_box = QVBoxLayout()
        text_box.setContentsMargins(0, 0, 0, 0)
        text_box.setSpacing(2)

        name_color = TEXT if info.is_up else TEXT_DIM
        name_label = QLabel(info.psutil_name)
        name_label.setStyleSheet(f"color: {name_color}; font-weight: 700; font-size: 13px;")
        name_label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        text_box.addWidget(name_label)

        sub_parts = [_TYPE_LABEL.get(info.iface_type, "Network")]
        if info.description and info.description != info.psutil_name:
            sub_parts.append(info.description)
        if info.ipv4:
            sub_parts.append(info.ipv4)
        elif info.is_up:
            sub_parts.append("no IPv4")
        else:
            sub_parts.append("link down")
        sub_text = "   ·   ".join(sub_parts)
        sub_label = QLabel(sub_text)
        sub_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        sub_label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        text_box.addWidget(sub_label)

        text_widget = QWidget()
        text_widget.setLayout(text_box)
        text_widget.setMinimumWidth(280)
        text_widget.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        layout.addWidget(text_widget, 1)

        self.sparkline = Sparkline()
        layout.addWidget(self.sparkline, 1)

        self.pps_label = QLabel("0 pps")
        self.pps_label.setStyleSheet(
            f"color: {TEXT_DIM}; font-family: 'Consolas', monospace; "
            f"font-size: 11px; min-width: 80px;"
        )
        self.pps_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.pps_label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        layout.addWidget(self.pps_label)

        self.setStyleSheet(f"""
            QFrame#ifaceCard {{
                background-color: {SURFACE};
                border: 1px solid {BORDER};
                border-radius: 6px;
            }}
            QFrame#ifaceCard:hover {{
                border-color: {ACCENT};
                background-color: {SURFACE_ALT};
            }}
            QFrame#ifaceCard[inactive="true"] {{
                background-color: #08090E;
            }}
            QFrame#ifaceCard[inactive="true"]:hover {{
                border-color: {ACCENT};
                background-color: {SURFACE};
            }}
        """)

    def update_pps(self, pps: float) -> None:
        self.sparkline.push(pps)
        if pps >= 1000:
            text = f"{pps/1000:.1f}k pps"
        else:
            text = f"{pps:.0f} pps"
        self.pps_label.setText(text)
        if pps > 0:
            self.pps_label.setStyleSheet(
                f"color: {ACCENT}; font-family: 'Consolas', monospace; "
                f"font-weight: 700; font-size: 11px; min-width: 80px;"
            )
        else:
            self.pps_label.setStyleSheet(
                f"color: {TEXT_DIM}; font-family: 'Consolas', monospace; "
                f"font-size: 11px; min-width: 80px;"
            )

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit(self.info.psutil_name)
        super().mouseReleaseEvent(event)


# ── Welcome page ──────────────────────────────────────────────────────────
class WelcomePage(QWidget):
    """Wireshark-style start page — list of interfaces with live sparklines."""

    interface_chosen = pyqtSignal(str, str, str)  # (psutil_name, scapy_name, bpf)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.cards: dict[str, InterfaceCard] = {}
        self.monitor = TrafficMonitor(self)
        self.monitor.rates_updated.connect(self._on_rates)

        self._build_ui()
        self.refresh_interfaces()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(40, 28, 40, 24)
        outer.setSpacing(14)

        title = QLabel("Capture")
        title.setStyleSheet(
            f"color: {TEXT}; font-size: 28px; font-weight: 800; letter-spacing: 0.5px;"
        )
        outer.addWidget(title)

        sub = QLabel("Pick a network interface — the live sparkline shows real packet activity from the OS.")
        sub.setStyleSheet(f"color: {TEXT_DIM}; font-size: 13px;")
        outer.addWidget(sub)

        # Filter row
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)

        f_label = QLabel("Capture filter")
        f_label.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 10px; letter-spacing: 1.4px; "
            f"text-transform: uppercase; font-weight: 700;"
        )
        filter_row.addWidget(f_label)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("optional BPF · e.g.  tcp port 80     host 1.2.3.4     not arp")
        self.filter_edit.setMinimumWidth(380)
        filter_row.addWidget(self.filter_edit, 1)

        self.refresh_btn = QPushButton("⟳  Refresh")
        self.refresh_btn.clicked.connect(self.refresh_interfaces)
        filter_row.addWidget(self.refresh_btn)

        outer.addLayout(filter_row)

        # Section header
        list_header = QLabel("INTERFACES")
        list_header.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 10px; letter-spacing: 1.4px; "
            f"font-weight: 700; padding-top: 6px;"
        )
        outer.addWidget(list_header)

        # Scroll area
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setStyleSheet(f"QScrollArea {{ background-color: {BG}; border: none; }}")

        self.scroll_inner = QWidget()
        self.scroll_inner.setStyleSheet(f"background-color: {BG};")
        self.cards_layout = QVBoxLayout(self.scroll_inner)
        self.cards_layout.setContentsMargins(0, 0, 0, 0)
        self.cards_layout.setSpacing(8)
        self.cards_layout.addStretch(1)

        self.scroll.setWidget(self.scroll_inner)
        outer.addWidget(self.scroll, 1)

        hint = QLabel(
            "Tip · the capture filter runs in the kernel and drops unwanted packets before they ever reach the app."
        )
        hint.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px; padding-top: 4px;")
        outer.addWidget(hint)

    def refresh_interfaces(self):
        # Remove old cards
        for card in list(self.cards.values()):
            self.cards_layout.removeWidget(card)
            card.deleteLater()
        self.cards.clear()

        try:
            interfaces = list_local_interfaces()
        except Exception as e:
            err = QLabel(f"Could not list interfaces: {e}")
            err.setStyleSheet("color: #F87171; font-size: 12px;")
            self.cards_layout.insertWidget(0, err)
            return

        if not interfaces:
            empty = QLabel("No network interfaces detected. Install Npcap from https://npcap.com")
            empty.setStyleSheet(f"color: {TEXT_DIM}; font-size: 12px;")
            self.cards_layout.insertWidget(0, empty)
            return

        # Insert before the trailing stretch
        for info in interfaces:
            card = InterfaceCard(info, self)
            card.clicked.connect(self._on_card_clicked)
            self.cards_layout.insertWidget(self.cards_layout.count() - 1, card)
            self.cards[info.psutil_name] = card

    def _on_card_clicked(self, psutil_name: str):
        if psutil_name not in self.cards:
            return
        scapy_name = scapy_iface_for(psutil_name) or psutil_name
        bpf = self.filter_edit.text().strip()
        self.interface_chosen.emit(psutil_name, scapy_name, bpf)

    def _on_rates(self, rates: dict):
        # Guard against late signals firing after the page is hidden or while
        # cards are being rebuilt — both can leave card refs pointing at
        # widgets Qt is in the middle of destroying.
        if not self.monitor.is_active():
            return
        for psutil_name, card in list(self.cards.items()):
            try:
                card.update_pps(float(rates.get(psutil_name, 0.0)))
            except RuntimeError:
                # "wrapped C/C++ object has been deleted" — card was torn
                # down between the timer fire and this slot.  Drop the ref
                # so we don't keep poking at it.
                self.cards.pop(psutil_name, None)

    def start_monitoring(self):
        for card in self.cards.values():
            card.sparkline.reset()
            card.update_pps(0.0)
        self.monitor.start()

    def stop_monitoring(self):
        self.monitor.stop()
