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
from netscope.theme import ACCENT, ACCENT_DEEP, BG, BORDER, SURFACE, SURFACE_ALT, TEXT, TEXT_DIM
from netscope.welcome import WelcomePage
from netscope.wireless_page import WirelessPage
from netscope.rules import RuleEngine, Alert
from netscope.rules_page import RulesPage
from netscope.notify import NotificationCenter
from netscope.pentest_page import PentestPage


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


class SidebarButton(QPushButton):
    """Left-rail nav button with active / inactive states."""

    def __init__(self, glyph: str, label: str, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setText(f"  {glyph}   {label}")
        self.setStyleSheet(self._qss(active=False))

    def setActive(self, active: bool) -> None:
        self.setChecked(active)
        self.setStyleSheet(self._qss(active=active))

    @staticmethod
    def _qss(*, active: bool) -> str:
        if active:
            bg = ACCENT
            fg = ACCENT_DEEP
            border = ACCENT
        else:
            bg = "transparent"
            fg = TEXT
            border = "transparent"
        return (
            f"QPushButton {{ background-color: {bg}; color: {fg}; "
            f"border: 1px solid {border}; border-radius: 6px; "
            f"padding: 10px 14px; text-align: left; font-weight: 700; "
            f"font-size: 12px; letter-spacing: 0.4px; }}"
            f"QPushButton:hover {{ background-color: {SURFACE_ALT}; "
            f"border-color: {BORDER}; color: {ACCENT}; }}"
        )


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PWNAudit NetScope")
        self.resize(1480, 940)

        self.engine = CaptureEngine()
        self.model = PacketTableModel(max_rows=200_000)
        self.proxy = DisplayFilterProxy(self)
        self.proxy.setSourceModel(self.model)

        # Rules engine — observes every packet from the capture engine and
        # fires alerts.  We hand the observer to CaptureEngine so the rule
        # check happens on the sniffer thread, off the UI loop.
        self.rule_engine = RuleEngine()
        self.engine.set_observer(self.rule_engine.observe)

        self._setup_brand_titlebar()

        # In-window toast / tray notification center.
        self.notifications = NotificationCenter(self)
        self.rule_engine.add_listener(self._on_rule_alert)

        # ── Pages ────────────────────────────────────────────────────
        self.welcome = WelcomePage(self)
        self.welcome.interface_chosen.connect(self._on_interface_chosen)

        self.wireless = WirelessPage(self)
        self.wireless.capture_requested.connect(self._on_interface_chosen)

        self.rules_page = RulesPage(self.rule_engine, self)
        self.pentest_page = PentestPage(self)

        self.capture_page = CapturePage(self.engine, self.model, self.proxy, self)
        self.capture_page.back_requested.connect(self._on_back)

        # ── Sidebar + content layout ────────────────────────────────
        self.stack = QStackedWidget()
        self.stack.addWidget(self.welcome)        # 0
        self.stack.addWidget(self.wireless)       # 1
        self.stack.addWidget(self.rules_page)     # 2
        self.stack.addWidget(self.pentest_page)   # 3
        self.stack.addWidget(self.capture_page)   # 4

        sidebar = self._build_sidebar()

        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        root_layout.addWidget(sidebar)
        root_layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self._previous_page: int = 0
        self._show_welcome()

    # ── Sidebar build ─────────────────────────────────────────────────
    def _build_sidebar(self) -> QWidget:
        bar = QFrame()
        bar.setFixedWidth(196)
        bar.setStyleSheet(
            f"QFrame {{ background-color: {SURFACE}; "
            f"border-right: 1px solid {BORDER}; }}"
        )
        layout = QVBoxLayout(bar)
        layout.setContentsMargins(12, 16, 12, 16)
        layout.setSpacing(6)

        nav_label = QLabel("NAVIGATION")
        nav_label.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 9px; letter-spacing: 1.5px; "
            f"font-weight: 700; padding: 0 6px 8px 6px;"
        )
        layout.addWidget(nav_label)

        self.btn_welcome = SidebarButton("⊟", "Interfaces")
        self.btn_welcome.clicked.connect(self._show_welcome)
        layout.addWidget(self.btn_welcome)

        self.btn_wireless = SidebarButton("⌬", "Wireless")
        self.btn_wireless.clicked.connect(self._show_wireless)
        layout.addWidget(self.btn_wireless)

        self.btn_rules = SidebarButton("△", "Rules")
        self.btn_rules.clicked.connect(self._show_rules)
        layout.addWidget(self.btn_rules)

        self.btn_pentest = SidebarButton("◇", "Pentest")
        self.btn_pentest.clicked.connect(self._show_pentest)
        layout.addWidget(self.btn_pentest)

        layout.addStretch(1)

        # Authorisation reminder at the bottom of the rail.
        notice = QLabel(
            "All capture and pentest actions stay on this device.\n"
            "Use only on networks you own or are authorised to test."
        )
        notice.setWordWrap(True)
        notice.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 10px; padding: 8px 6px; "
            f"border-top: 1px solid {BORDER};"
        )
        layout.addWidget(notice)
        return bar

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

    # ── Navigation ────────────────────────────────────────────────────
    def _set_active_button(self, active: str) -> None:
        for name, btn in {
            "welcome": self.btn_welcome,
            "wireless": self.btn_wireless,
            "rules": self.btn_rules,
            "pentest": self.btn_pentest,
        }.items():
            if btn is not None:
                btn.setActive(name == active)

    def _show_welcome(self) -> None:
        if self.engine.is_running():
            return  # don't tear down active capture mid-click
        self.wireless.stop_monitoring()
        self.welcome.start_monitoring()
        self.stack.setCurrentWidget(self.welcome)
        self._set_active_button("welcome")
        self._previous_page = 0

    def _show_wireless(self) -> None:
        if self.engine.is_running():
            return
        self.welcome.stop_monitoring()
        self.rules_page.stop_monitoring()
        self.wireless.start_monitoring()
        self.stack.setCurrentWidget(self.wireless)
        self._set_active_button("wireless")
        self._previous_page = 1

    def _show_rules(self) -> None:
        # Rules tab is safe to switch to even mid-capture — it's read-only
        # against the alert log, and disabling rules has no effect on capture.
        self.welcome.stop_monitoring()
        self.wireless.stop_monitoring()
        self.rules_page.start_monitoring()
        self.stack.setCurrentWidget(self.rules_page)
        self._set_active_button("rules")
        self._previous_page = 2

    def _show_pentest(self) -> None:
        self.welcome.stop_monitoring()
        self.wireless.stop_monitoring()
        self.rules_page.stop_monitoring()
        self.stack.setCurrentWidget(self.pentest_page)
        self._set_active_button("pentest")
        self._previous_page = 3

    def _on_rule_alert(self, alert: Alert) -> None:
        """Rule engine listener — runs on the sniffer thread.  Dispatches the
        toast onto the UI thread via QTimer.singleShot(0, ...)."""
        QTimer.singleShot(
            0,
            lambda a=alert: self.notifications.show(
                title=a.title,
                message=a.message,
                severity=a.severity,
            ),
        )

    # ── Capture launch / teardown ────────────────────────────────────
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
        self.wireless.stop_monitoring()
        self.capture_page.set_active(psutil_name, bpf)
        self.stack.setCurrentWidget(self.capture_page)

    def _on_back(self):
        try:
            self.engine.stop()
        except Exception:
            pass
        self.capture_page.deactivate()
        self.model.clear()
        if self._previous_page == 1:
            self._show_wireless()
        elif self._previous_page == 2:
            self._show_rules()
        else:
            self._show_welcome()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Keep toasts pinned to the lower-right corner on resize.
        try:
            self.notifications._reflow()
        except Exception:
            pass

    def closeEvent(self, event):
        try:
            self.engine.stop()
            self.welcome.stop_monitoring()
            self.wireless.stop_monitoring()
            self.rules_page.stop_monitoring()
            self.pentest_page.stop_all()
            self.capture_page.deactivate()
        except Exception:
            pass
        event.accept()
