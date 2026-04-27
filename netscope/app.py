"""Main window — Welcome page → Capture page navigation."""
from __future__ import annotations

import time
from typing import Optional

from PyQt6.QtCore import Qt, QTimer, QModelIndex, pyqtSignal
from PyQt6.QtGui import QFont, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTableView,
    QTreeWidget, QTreeWidgetItem, QSplitter, QToolBar,
    QHeaderView, QPlainTextEdit, QMessageBox,
    QFrame, QStackedWidget,
)

from netscope.capture import CaptureEngine
from netscope.model import PacketTableModel, DisplayFilterProxy
from netscope.dissect import packet_layers
from netscope.theme import ACCENT, BORDER, SURFACE, TEXT, TEXT_DIM
from netscope.welcome import WelcomePage


def hex_dump(data: bytes) -> str:
    if not data:
        return ""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        if len(chunk) < 16:
            hex_part = hex_part.ljust(16 * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_part}   {ascii_part}")
    return "\n".join(lines)


class CapturePage(QWidget):
    """Active capture view — toolbar + tri-pane (packet list / tree / hex)."""

    DRAIN_INTERVAL_MS = 100
    STATS_INTERVAL_MS = 500
    FILTER_DEBOUNCE_MS = 250

    back_requested = pyqtSignal()

    def __init__(self, engine: CaptureEngine, model: PacketTableModel,
                 proxy: DisplayFilterProxy, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.model = model
        self.proxy = proxy
        self._last_count = 0
        self._last_count_time: Optional[float] = None

        self._build_ui()

        self.drain_timer = QTimer(self)
        self.drain_timer.setInterval(self.DRAIN_INTERVAL_MS)
        self.drain_timer.timeout.connect(self._drain)

        self.stats_timer = QTimer(self)
        self.stats_timer.setInterval(self.STATS_INTERVAL_MS)
        self.stats_timer.timeout.connect(self._update_stats)

        self.filter_timer = QTimer(self)
        self.filter_timer.setSingleShot(True)
        self.filter_timer.setInterval(self.FILTER_DEBOUNCE_MS)
        self.filter_timer.timeout.connect(self._apply_display_filter_now)

        QShortcut(QKeySequence("Ctrl+E"), self, activated=self._toggle_capture)
        QShortcut(QKeySequence("Ctrl+L"), self, activated=self._on_clear)
        QShortcut(QKeySequence("Ctrl+F"), self, activated=lambda: self.display_filter.setFocus())

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── Toolbar strip ────────────────────────────────────────────────
        tb = QFrame()
        tb.setStyleSheet(f"QFrame {{ background-color: {SURFACE}; border-bottom: 1px solid {BORDER}; }}")
        tb.setFixedHeight(54)
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(12, 8, 12, 8)
        tbl.setSpacing(10)

        self.back_btn = QPushButton("← Interfaces")
        self.back_btn.clicked.connect(self.back_requested.emit)
        tbl.addWidget(self.back_btn)

        sep1 = QFrame()
        sep1.setFrameShape(QFrame.Shape.VLine)
        sep1.setStyleSheet(f"color: {BORDER}; background-color: {BORDER};")
        sep1.setFixedWidth(1)
        tbl.addWidget(sep1)

        self.iface_label = QLabel("—")
        self.iface_label.setStyleSheet(f"color: {ACCENT}; font-weight: 700; font-size: 13px;")
        tbl.addWidget(self.iface_label)

        self.bpf_label = QLabel("")
        self.bpf_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px; font-family: Consolas, monospace;")
        tbl.addWidget(self.bpf_label)

        tbl.addStretch(1)

        df_label = QLabel("DISPLAY")
        df_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; letter-spacing: 1.4px; font-weight: 700;")
        tbl.addWidget(df_label)

        self.display_filter = QLineEdit()
        self.display_filter.setPlaceholderText("substring · ip · port · proto")
        self.display_filter.setMinimumWidth(240)
        self.display_filter.textChanged.connect(self._on_display_filter_changed)
        tbl.addWidget(self.display_filter)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.VLine)
        sep2.setStyleSheet(f"color: {BORDER}; background-color: {BORDER};")
        sep2.setFixedWidth(1)
        tbl.addWidget(sep2)

        self.stop_btn = QPushButton("■  Stop")
        self.stop_btn.setObjectName("stop")
        self.stop_btn.clicked.connect(self._on_stop)
        tbl.addWidget(self.stop_btn)

        self.start_btn = QPushButton("▶  Resume")
        self.start_btn.setObjectName("start")
        self.start_btn.clicked.connect(self._on_resume)
        self.start_btn.setEnabled(False)
        tbl.addWidget(self.start_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self._on_clear)
        tbl.addWidget(self.clear_btn)

        outer.addWidget(tb)

        # ── Tri-pane content ─────────────────────────────────────────────
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setHighlightSections(False)
        self.table.setColumnWidth(0, 70)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 170)
        self.table.setColumnWidth(3, 170)
        self.table.setColumnWidth(4, 100)
        self.table.setColumnWidth(5, 80)
        self.table.selectionModel().currentRowChanged.connect(self._on_row_selected)

        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderHidden(True)
        self.detail_tree.setIndentation(14)
        self.detail_tree.setUniformRowHeights(True)

        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        f = QFont("Consolas")
        f.setStyleHint(QFont.StyleHint.Monospace)
        f.setPointSize(10)
        self.hex_view.setFont(f)
        self.hex_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        bottom = QSplitter(Qt.Orientation.Horizontal)
        bottom.addWidget(self._panel("PROTOCOL TREE", self.detail_tree))
        bottom.addWidget(self._panel("HEX DUMP", self.hex_view))
        bottom.setSizes([580, 580])

        main_split = QSplitter(Qt.Orientation.Vertical)
        main_split.addWidget(self._panel("PACKETS", self.table))
        main_split.addWidget(bottom)
        main_split.setSizes([560, 360])

        outer.addWidget(main_split, 1)

        # ── Status bar ───────────────────────────────────────────────────
        sb = QFrame()
        sb.setStyleSheet(f"QFrame {{ background-color: {SURFACE}; border-top: 1px solid {BORDER}; }}")
        sb.setFixedHeight(28)
        sbl = QHBoxLayout(sb)
        sbl.setContentsMargins(12, 4, 12, 4)

        self.status_label = QLabel("Ready.")
        self.status_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        sbl.addWidget(self.status_label, 1)

        self.count_label = QLabel("0 packets")
        self.count_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px; font-family: Consolas, monospace;")
        sbl.addWidget(self.count_label)

        sbl.addSpacing(20)

        self.rate_label = QLabel("0 pps")
        self.rate_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px; font-family: Consolas, monospace;")
        sbl.addWidget(self.rate_label)

        outer.addWidget(sb)

    def _panel(self, title: str, body: QWidget) -> QWidget:
        wrapper = QFrame()
        wrapper.setFrameShape(QFrame.Shape.NoFrame)
        layout = QVBoxLayout(wrapper)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        header = QLabel(title)
        header.setStyleSheet(
            f"background-color: {SURFACE}; color: {TEXT_DIM}; "
            f"padding: 6px 12px; font-weight: 700; font-size: 10px; letter-spacing: 1.4px; "
            f"border-bottom: 1px solid {BORDER};"
        )
        layout.addWidget(header)
        layout.addWidget(body, 1)
        return wrapper

    # ── Lifecycle ──────────────────────────────────────────────────────────
    def set_active(self, iface_label: str, bpf: str):
        self.iface_label.setText(iface_label)
        self.bpf_label.setText(f"  filter: {bpf}" if bpf else "")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText(f"●  Capturing on {iface_label}")
        self.status_label.setStyleSheet(f"color: {ACCENT}; font-size: 11px; font-weight: 600;")
        self.display_filter.clear()
        self._last_count = 0
        self._last_count_time = None
        self.drain_timer.start()
        self.stats_timer.start()

    def deactivate(self):
        self.drain_timer.stop()
        self.stats_timer.stop()

    def _on_stop(self):
        self.engine.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Stopped.")
        self.status_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")

    def _on_resume(self):
        stats = self.engine.stats
        iface = stats.get("iface")
        bpf = stats.get("bpf") or ""
        if not iface:
            return
        try:
            self.engine.start(iface, bpf)
        except Exception as e:
            QMessageBox.critical(self, "Resume failed", str(e))
            return
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText(f"●  Capturing on {self.iface_label.text()}")
        self.status_label.setStyleSheet(f"color: {ACCENT}; font-size: 11px; font-weight: 600;")

    def _toggle_capture(self):
        if self.engine.is_running():
            self._on_stop()
        else:
            self._on_resume()

    def _on_clear(self):
        self.model.clear()
        self.detail_tree.clear()
        self.hex_view.clear()

    def _drain(self):
        items = self.engine.drain()
        if not items:
            return
        sb = self.table.verticalScrollBar()
        at_bottom = sb.value() >= sb.maximum() - 4
        self.model.append_packets(items)
        if at_bottom and not self.display_filter.text().strip():
            self.table.scrollToBottom()

    def _update_stats(self):
        count = self.model.rowCount()
        self.count_label.setText(f"{count:,} packets")
        now = time.time()
        if self._last_count_time is not None:
            dt = max(now - self._last_count_time, 0.001)
            pps = max(0, count - self._last_count) / dt
            self.rate_label.setText(f"{pps:,.0f} pps")
        self._last_count = count
        self._last_count_time = now

    def _on_display_filter_changed(self, _text: str):
        self.filter_timer.start()

    def _apply_display_filter_now(self):
        self.proxy.set_filter_text(self.display_filter.text())

    def _on_row_selected(self, current: QModelIndex, _previous: QModelIndex):
        if not current.isValid():
            return
        source_idx = self.proxy.mapToSource(current) if isinstance(self.table.model(), DisplayFilterProxy) else current
        row = source_idx.row()
        raw = self.model.get_raw(row)
        if raw is None:
            return
        self.detail_tree.clear()
        self.hex_view.setPlainText(hex_dump(raw))
        try:
            from scapy.all import Ether
            pkt = Ether(raw)
        except Exception:
            return
        for layer in packet_layers(pkt):
            top_label = layer["summary"] or layer["name"]
            top = QTreeWidgetItem([f"▸ {top_label}"])
            for fname, fval in layer["fields"]:
                value_str = fval if len(fval) <= 200 else fval[:200] + "…"
                child = QTreeWidgetItem([f"{fname} : {value_str}"])
                top.addChild(child)
            self.detail_tree.addTopLevelItem(top)
        self.detail_tree.expandToDepth(0)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PWNAudit NetScope")
        self.resize(1480, 940)

        self.engine = CaptureEngine()
        self.model = PacketTableModel(max_rows=200_000)
        self.proxy = DisplayFilterProxy(self)
        self.proxy.setSourceModel(self.model)

        self._setup_brand_titlebar()

        self.welcome = WelcomePage(self)
        self.welcome.interface_chosen.connect(self._on_interface_chosen)

        self.capture_page = CapturePage(self.engine, self.model, self.proxy, self)
        self.capture_page.back_requested.connect(self._on_back)

        self.stack = QStackedWidget()
        self.stack.addWidget(self.welcome)
        self.stack.addWidget(self.capture_page)
        self.setCentralWidget(self.stack)

        self.welcome.start_monitoring()

    def _setup_brand_titlebar(self):
        tb = QToolBar()
        tb.setMovable(False)
        tb.setFloatable(False)
        self.addToolBar(tb)

        brand_pwn = QLabel("PWN")
        brand_pwn.setObjectName("brand_dim")
        tb.addWidget(brand_pwn)
        brand_audit = QLabel("Audit")
        brand_audit.setObjectName("brand")
        tb.addWidget(brand_audit)
        sep = QLabel("│")
        sep.setStyleSheet(f"color: {BORDER}; padding: 0 12px; font-size: 16px;")
        tb.addWidget(sep)
        sub = QLabel("NetScope")
        sub.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 11px; letter-spacing: 1.6px; "
            f"text-transform: uppercase; font-weight: 700;"
        )
        tb.addWidget(sub)

    def _on_interface_chosen(self, psutil_name: str, scapy_name: str, bpf: str):
        try:
            self.engine.start(scapy_name, bpf)
        except Exception as e:
            QMessageBox.critical(
                self, "Capture failed",
                f"Could not start capture on '{psutil_name}'.\n\n{e}\n\n"
                f"Common causes:\n"
                f"  • Npcap is not installed → https://npcap.com\n"
                f"  • The app is not running as Administrator\n"
                f"  • The selected interface does not support capture (some Bluetooth adapters)\n"
                f"  • The BPF filter has a syntax error"
            )
            return
        self.welcome.stop_monitoring()
        self.capture_page.set_active(psutil_name, bpf)
        self.stack.setCurrentWidget(self.capture_page)

    def _on_back(self):
        try:
            self.engine.stop()
        except Exception:
            pass
        self.capture_page.deactivate()
        self.model.clear()
        self.welcome.start_monitoring()
        self.stack.setCurrentWidget(self.welcome)

    def closeEvent(self, event):
        try:
            self.engine.stop()
            self.welcome.stop_monitoring()
            self.capture_page.deactivate()
        except Exception:
            pass
        event.accept()
