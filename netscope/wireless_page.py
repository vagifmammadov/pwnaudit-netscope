"""
Wireless tab — shows live Wi-Fi adapter state and visible networks, with
2.4 GHz / 5 GHz band filtering and a one-click capture launcher that pre-fills
a BPF filter scoped to the connected SSID's BSSID.

This complements the generic Capture tab with a wireless-aware view, so a
user investigating throughput on their own 5 GHz network can see which BSSIDs
are competing for the same channel and whether their device is sticking to
the right band.

NOTE: Without monitor mode (which most consumer Wi-Fi cards don't support
on Windows via Npcap), the *capture* itself sees Ethernet-style frames the
host is part of — beacons, probes, and deauths from third-party devices
require AirPcap or a monitor-mode-capable driver. The tab is honest about
this and only offers capture starts that work in managed mode.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QComboBox, QScrollArea, QSizePolicy,
)

from netscope.theme import (
    ACCENT, ACCENT_DEEP, ACCENT_DIM, BORDER, BG, SURFACE, SURFACE_ALT,
    TEXT, TEXT_DIM, WARNING, INFO,
)
from netscope.wifi import (
    WifiAdapter, WifiNetwork, list_wifi_adapters, list_visible_networks,
)
from netscope.interfaces import scapy_iface_for


def _band_color(band_label: str) -> str:
    if "5" in band_label:
        return ACCENT
    if "2.4" in band_label:
        return WARNING
    if "6" in band_label:
        return INFO
    return TEXT_DIM


def _signal_bars(pct: Optional[int]) -> str:
    """Render a 4-segment bar like Wireshark / Windows."""
    if pct is None:
        return "─ ─ ─ ─"
    bars = max(0, min(4, int((pct + 12) / 25)))
    return "".join("█" if i < bars else "░" for i in range(4))


class StatTile(QFrame):
    """One labelled stat tile (e.g. SSID / Channel / Signal)."""

    def __init__(self, label: str, value: str = "—", value_color: str = TEXT, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            f"QFrame {{ background-color: {SURFACE}; border: 1px solid {BORDER}; "
            f"border-radius: 6px; }}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)
        self._label = QLabel(label.upper())
        self._label.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 9px; letter-spacing: 1.4px; font-weight: 700;"
        )
        layout.addWidget(self._label)
        self._value = QLabel(value)
        f = QFont()
        f.setPointSize(13)
        f.setBold(True)
        self._value.setFont(f)
        self._value.setStyleSheet(f"color: {value_color};")
        self._value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self._value)

    def set_value(self, text: str, color: str = TEXT) -> None:
        self._value.setText(text)
        self._value.setStyleSheet(f"color: {color};")


class NetworkRow(QFrame):
    """One row in the visible-networks list."""

    selected = pyqtSignal(WifiNetwork)

    def __init__(self, net: WifiNetwork, parent=None):
        super().__init__(parent)
        self._net = net
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(
            f"QFrame {{ background-color: {SURFACE}; border: 1px solid {BORDER}; "
            f"border-radius: 4px; padding: 0; }}"
            f"QFrame:hover {{ border-color: {ACCENT_DIM}; }}"
        )
        h = QHBoxLayout(self)
        h.setContentsMargins(14, 10, 14, 10)
        h.setSpacing(14)

        ssid = net.ssid or "<hidden>"
        ssid_lbl = QLabel(ssid)
        ssid_lbl.setStyleSheet(f"color: {TEXT}; font-weight: 700; font-size: 12px;")
        ssid_lbl.setMinimumWidth(180)
        h.addWidget(ssid_lbl)

        bssid_lbl = QLabel(net.bssid)
        bssid_lbl.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 11px; font-family: Consolas, monospace;"
        )
        bssid_lbl.setMinimumWidth(150)
        h.addWidget(bssid_lbl)

        ch_lbl = QLabel(f"ch {net.channel}" if net.channel else "ch ?")
        ch_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        ch_lbl.setFixedWidth(50)
        h.addWidget(ch_lbl)

        band_lbl = QLabel(net.band_label or "—")
        band_lbl.setStyleSheet(
            f"color: {_band_color(net.band_label)}; font-weight: 700; font-size: 11px;"
        )
        band_lbl.setFixedWidth(70)
        h.addWidget(band_lbl)

        sig_lbl = QLabel(f"{_signal_bars(net.signal_pct)}  {net.signal_pct or 0}%")
        sig_lbl.setStyleSheet(
            f"color: {TEXT_DIM}; font-family: Consolas, monospace; font-size: 11px;"
        )
        sig_lbl.setFixedWidth(110)
        h.addWidget(sig_lbl)

        radio_lbl = QLabel(net.radio_type or "")
        radio_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        h.addWidget(radio_lbl)

        h.addStretch(1)

        enc_lbl = QLabel(net.encryption or net.auth or "open")
        enc_lbl.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 10px; padding: 2px 8px; "
            f"background-color: {SURFACE_ALT}; border-radius: 3px;"
        )
        h.addWidget(enc_lbl)

        # all children transparent so the whole row is clickable
        for child in (ssid_lbl, bssid_lbl, ch_lbl, band_lbl, sig_lbl, radio_lbl, enc_lbl):
            child.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

    def mouseReleaseEvent(self, _event):
        self.selected.emit(self._net)


class WirelessPage(QWidget):
    """Wireless tab — adapter state + visible-networks list + capture launcher."""

    REFRESH_INTERVAL_MS = 5_000

    capture_requested = pyqtSignal(str, str, str)
    """Emitted with (psutil_name, scapy_name, bpf) when user clicks Capture."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._adapter: Optional[WifiAdapter] = None
        self._build_ui()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(self.REFRESH_INTERVAL_MS)
        self._refresh_timer.timeout.connect(self.refresh)

    # ── Build UI ────────────────────────────────────────────────────────
    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 24, 28, 24)
        outer.setSpacing(18)

        # ── Header ───────────────────────────────────────────────────
        title = QLabel("Wireless")
        f = QFont()
        f.setPointSize(20)
        f.setBold(True)
        title.setFont(f)
        title.setStyleSheet(f"color: {TEXT};")

        subtitle = QLabel(
            "Live state of every Wi-Fi radio on this machine, plus every nearby BSSID. "
            "Filter by 2.4 GHz / 5 GHz to see which APs share your channel."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(f"color: {TEXT_DIM}; font-size: 12px;")

        outer.addWidget(title)
        outer.addWidget(subtitle)

        # ── Adapter selector + tiles ─────────────────────────────────
        adapter_row = QHBoxLayout()
        adapter_row.setSpacing(12)

        adapter_lbl = QLabel("ADAPTER")
        adapter_lbl.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 10px; letter-spacing: 1.4px; font-weight: 700;"
        )
        adapter_row.addWidget(adapter_lbl)

        self.adapter_combo = QComboBox()
        self.adapter_combo.setMinimumWidth(260)
        self.adapter_combo.currentIndexChanged.connect(self._on_adapter_changed)
        adapter_row.addWidget(self.adapter_combo)

        self.refresh_btn = QPushButton("⟳  Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        adapter_row.addWidget(self.refresh_btn)

        adapter_row.addStretch(1)

        self.capture_btn = QPushButton("▶  Capture on this band")
        self.capture_btn.setObjectName("start")
        self.capture_btn.clicked.connect(self._on_capture_clicked)
        adapter_row.addWidget(self.capture_btn)

        outer.addLayout(adapter_row)

        tiles = QHBoxLayout()
        tiles.setSpacing(12)
        self.tile_ssid = StatTile("Connected SSID")
        self.tile_bssid = StatTile("BSSID (AP MAC)")
        self.tile_channel = StatTile("Channel")
        self.tile_band = StatTile("Band")
        self.tile_signal = StatTile("Signal")
        self.tile_phy = StatTile("Radio · Link")
        for t in (self.tile_ssid, self.tile_bssid, self.tile_channel,
                  self.tile_band, self.tile_signal, self.tile_phy):
            t.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            tiles.addWidget(t)
        outer.addLayout(tiles)

        # ── Networks header + band filter ────────────────────────────
        list_row = QHBoxLayout()
        list_row.setSpacing(10)

        list_title = QLabel("Visible networks")
        f2 = QFont()
        f2.setPointSize(13)
        f2.setBold(True)
        list_title.setFont(f2)
        list_title.setStyleSheet(f"color: {TEXT};")
        list_row.addWidget(list_title)

        self.count_lbl = QLabel("(0)")
        self.count_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 12px;")
        list_row.addWidget(self.count_lbl)

        list_row.addStretch(1)

        band_lbl = QLabel("BAND")
        band_lbl.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 10px; letter-spacing: 1.4px; font-weight: 700;"
        )
        list_row.addWidget(band_lbl)

        self.band_filter = QComboBox()
        self.band_filter.addItems(["All", "2.4 GHz", "5 GHz", "6 GHz"])
        self.band_filter.currentIndexChanged.connect(self._render_networks)
        self.band_filter.setMinimumWidth(120)
        list_row.addWidget(self.band_filter)

        outer.addLayout(list_row)

        # ── Networks scroll area ─────────────────────────────────────
        self.networks_container = QWidget()
        self.networks_layout = QVBoxLayout(self.networks_container)
        self.networks_layout.setContentsMargins(0, 0, 0, 0)
        self.networks_layout.setSpacing(6)
        self.networks_layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self.networks_container)
        scroll.setStyleSheet(f"background-color: {BG};")
        outer.addWidget(scroll, 1)

        # ── Hint banner ──────────────────────────────────────────────
        self.hint = QLabel("")
        self.hint.setWordWrap(True)
        self.hint.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 11px; padding: 8px 12px; "
            f"background-color: {SURFACE}; border: 1px solid {BORDER}; border-radius: 4px;"
        )
        outer.addWidget(self.hint)

        self._cache_networks: list[WifiNetwork] = []

    # ── Lifecycle ─────────────────────────────────────────────────────
    def start_monitoring(self) -> None:
        self.refresh()
        self._refresh_timer.start()

    def stop_monitoring(self) -> None:
        self._refresh_timer.stop()

    # ── Data loading ──────────────────────────────────────────────────
    def refresh(self) -> None:
        adapters = list_wifi_adapters()
        previous = self.adapter_combo.currentText()
        self.adapter_combo.blockSignals(True)
        self.adapter_combo.clear()
        for a in adapters:
            label = a.name + (f"  ·  {a.description}" if a.description else "")
            self.adapter_combo.addItem(label, a)
        if previous:
            idx = self.adapter_combo.findText(previous, Qt.MatchFlag.MatchStartsWith)
            if idx >= 0:
                self.adapter_combo.setCurrentIndex(idx)
        self.adapter_combo.blockSignals(False)

        if not adapters:
            self._adapter = None
            self._render_no_wifi()
            return

        idx = self.adapter_combo.currentIndex()
        self._adapter = self.adapter_combo.itemData(idx) if idx >= 0 else None
        self._render_adapter()
        self._cache_networks = list_visible_networks()
        self._render_networks()

    def _on_adapter_changed(self, idx: int) -> None:
        self._adapter = self.adapter_combo.itemData(idx)
        self._render_adapter()

    # ── Render: adapter tiles ─────────────────────────────────────────
    def _render_no_wifi(self) -> None:
        self.tile_ssid.set_value("No Wi-Fi adapter", TEXT_DIM)
        self.tile_bssid.set_value("—", TEXT_DIM)
        self.tile_channel.set_value("—", TEXT_DIM)
        self.tile_band.set_value("—", TEXT_DIM)
        self.tile_signal.set_value("—", TEXT_DIM)
        self.tile_phy.set_value("—", TEXT_DIM)
        self.capture_btn.setEnabled(False)
        self.hint.setText(
            "No Wi-Fi adapter found.  Plug in a USB Wi-Fi dongle or enable the "
            "internal radio, then hit Refresh."
        )
        self._clear_networks()

    def _render_adapter(self) -> None:
        a = self._adapter
        if not a:
            self._render_no_wifi()
            return
        if not a.is_connected:
            self.tile_ssid.set_value(f"Not connected ({a.state or '—'})", WARNING)
            self.tile_bssid.set_value("—", TEXT_DIM)
            self.tile_channel.set_value("—", TEXT_DIM)
            self.tile_band.set_value("—", TEXT_DIM)
            self.tile_signal.set_value("—", TEXT_DIM)
            self.tile_phy.set_value(a.radio_type or "—", TEXT_DIM)
            self.capture_btn.setEnabled(True)  # can still capture nearby traffic if monitor-capable
            self.hint.setText(
                "Adapter is not associated to a network.  Capture is still allowed but "
                "without monitor mode you'll only see traffic the host itself receives."
            )
            return

        self.tile_ssid.set_value(a.ssid or "<hidden>", ACCENT)
        self.tile_bssid.set_value(a.bssid or "—")
        self.tile_channel.set_value(str(a.channel) if a.channel else "—")
        self.tile_band.set_value(a.band_label or "—", _band_color(a.band_label))
        self.tile_signal.set_value(
            f"{a.signal_pct}%  {_signal_bars(a.signal_pct)}" if a.signal_pct is not None else "—",
        )
        rate_parts = []
        if a.radio_type:
            rate_parts.append(a.radio_type)
        if a.rx_mbps:
            rate_parts.append(f"↓{a.rx_mbps:g} Mbps")
        if a.tx_mbps:
            rate_parts.append(f"↑{a.tx_mbps:g} Mbps")
        self.tile_phy.set_value(" · ".join(rate_parts) if rate_parts else "—")
        self.capture_btn.setEnabled(True)
        self.hint.setText(
            f"Connected on {a.band_label or '?'}.  Click Capture to start a session "
            f"pre-filtered to this BSSID — useful for measuring how much traffic this "
            f"single radio is carrying."
        )

    # ── Render: networks list ─────────────────────────────────────────
    def _clear_networks(self) -> None:
        # Remove all rows except the trailing stretch
        while self.networks_layout.count() > 1:
            item = self.networks_layout.takeAt(0)
            widget = item.widget() if item else None
            if widget is not None:
                widget.deleteLater()

    def _render_networks(self) -> None:
        self._clear_networks()
        band_filter = self.band_filter.currentText()
        shown = 0
        for net in self._cache_networks:
            if band_filter != "All" and net.band_label != band_filter:
                continue
            row = NetworkRow(net)
            row.selected.connect(self._on_network_selected)
            self.networks_layout.insertWidget(self.networks_layout.count() - 1, row)
            shown += 1
        self.count_lbl.setText(f"({shown})")

    def _on_network_selected(self, net: WifiNetwork) -> None:
        # Pre-fill the capture button hint when a row is clicked.
        self.hint.setText(
            f"Selected {net.ssid or '<hidden>'} ({net.bssid}, ch {net.channel}, "
            f"{net.band_label}).  Click Capture to start a session filtered to this BSSID."
        )
        # stash the chosen BSSID so capture uses it
        self._selected_bssid = net.bssid

    _selected_bssid: str = ""

    # ── Capture launch ────────────────────────────────────────────────
    def _on_capture_clicked(self) -> None:
        a = self._adapter
        if not a:
            return
        scapy_name = scapy_iface_for(a.name) or a.name
        bssid = self._selected_bssid or a.bssid
        bpf = ""
        if bssid:
            bpf = f"ether host {bssid.replace('-', ':')}"
        self.capture_requested.emit(a.name, scapy_name, bpf)
