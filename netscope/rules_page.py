"""
Rules tab — manage detection rules and review live alerts.

Layout:
    Top half:   table of rules with toggle, severity badge, threshold info,
                "edit" / "delete" buttons.
    Bottom half: live alert log — most recent at top.

A "+ New rule" button opens an inline form for the simple DSL.
"""
from __future__ import annotations

import time
from typing import Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox, QComboBox,
    QLineEdit, QSpinBox, QFormLayout, QDialog, QDialogButtonBox, QPlainTextEdit,
    QSplitter, QMessageBox,
)

from netscope.theme import (
    ACCENT, ACCENT_DEEP, BORDER, BG, SURFACE, SURFACE_ALT, TEXT, TEXT_DIM,
    DANGER, WARNING, SUCCESS, INFO,
)
from netscope.rules import (
    RuleEngine, Rule, SimpleRule, Alert,
    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
)


_SEVERITY_BADGE = {
    SEVERITY_INFO:     INFO,
    SEVERITY_LOW:      SUCCESS,
    SEVERITY_MEDIUM:   WARNING,
    SEVERITY_HIGH:     DANGER,
    SEVERITY_CRITICAL: DANGER,
}


def _badge(severity: str) -> str:
    color = _SEVERITY_BADGE.get(severity, TEXT_DIM)
    return color


class RuleEditorDialog(QDialog):
    """Modal for creating / editing a user rule using the simple DSL."""

    def __init__(self, parent=None, *, rule: Optional[Rule] = None):
        super().__init__(parent)
        self.setWindowTitle("Edit rule" if rule else "New rule")
        self.setModal(True)
        self.setMinimumWidth(440)
        self.resize(480, 460)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        intro = QLabel(
            "Define when this rule fires.  Leave a field blank to wildcard it."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        layout.addWidget(intro)

        form = QFormLayout()
        form.setSpacing(10)

        self.id_edit = QLineEdit(rule.id if rule else "user.my-rule")
        self.id_edit.setPlaceholderText("user.my-rule")
        self.id_edit.setEnabled(rule is None)
        form.addRow("ID:", self.id_edit)

        self.title_edit = QLineEdit(rule.title if rule else "")
        self.title_edit.setPlaceholderText("Short, human-readable name")
        form.addRow("Title:", self.title_edit)

        self.severity_combo = QComboBox()
        self.severity_combo.addItems([
            SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM,
            SEVERITY_HIGH, SEVERITY_CRITICAL,
        ])
        if rule:
            idx = self.severity_combo.findText(rule.severity)
            if idx >= 0:
                self.severity_combo.setCurrentIndex(idx)
        else:
            self.severity_combo.setCurrentText(SEVERITY_MEDIUM)
        form.addRow("Severity:", self.severity_combo)

        self.proto_combo = QComboBox()
        self.proto_combo.addItems(["", "TCP", "UDP", "ICMP", "ARP", "DNS", "DHCP", "Dot11"])
        form.addRow("Protocol:", self.proto_combo)

        self.src_ip_edit = QLineEdit()
        self.src_ip_edit.setPlaceholderText("any | 10.0.0.1 | 192.168.1.0/24")
        form.addRow("Source IP:", self.src_ip_edit)

        self.dst_ip_edit = QLineEdit()
        self.dst_ip_edit.setPlaceholderText("any | 8.8.8.8 | 10.0.0.0/24")
        form.addRow("Dest IP:", self.dst_ip_edit)

        self.dst_port_edit = QLineEdit()
        self.dst_port_edit.setPlaceholderText("any | 22 | 443")
        form.addRow("Dest port:", self.dst_port_edit)

        self.flags_edit = QLineEdit()
        self.flags_edit.setPlaceholderText("S | SA | FA (TCP only)")
        form.addRow("TCP flags:", self.flags_edit)

        self.key_combo = QComboBox()
        self.key_combo.addItems(["src_ip", "src_mac", "dst_ip", "dst_port", "none"])
        form.addRow("Bucket key:", self.key_combo)

        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(1, 1_000_000)
        self.threshold_spin.setValue(rule.threshold if rule else 50)
        form.addRow("Threshold (events):", self.threshold_spin)

        self.window_spin = QSpinBox()
        self.window_spin.setRange(1, 3600)
        self.window_spin.setValue(int(rule.window_seconds) if rule else 10)
        form.addRow("Window (seconds):", self.window_spin)

        layout.addLayout(form)

        # Pre-fill from existing rule's DSL.
        if rule and rule.dsl:
            d = rule.dsl
            if d.protocol:
                self.proto_combo.setCurrentText(d.protocol)
            if d.src_ip and d.src_ip != "any":
                self.src_ip_edit.setText(d.src_ip)
            if d.dst_ip and d.dst_ip != "any":
                self.dst_ip_edit.setText(d.dst_ip)
            if d.dst_port is not None:
                self.dst_port_edit.setText(str(d.dst_port))
            if d.tcp_flags:
                self.flags_edit.setText(d.tcp_flags)
            self.key_combo.setCurrentText(d.key_by)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def to_rule(self) -> Optional[Rule]:
        rule_id = self.id_edit.text().strip()
        title = self.title_edit.text().strip()
        if not rule_id or not title:
            QMessageBox.warning(self, "Missing field", "ID and Title are required.")
            return None
        port_text = self.dst_port_edit.text().strip()
        port: Optional[int] = None
        if port_text:
            try:
                port = int(port_text)
            except ValueError:
                QMessageBox.warning(self, "Invalid port", "Dest port must be an integer.")
                return None
        dsl = SimpleRule(
            protocol=self.proto_combo.currentText() or None,
            src_ip=self.src_ip_edit.text().strip() or None,
            dst_ip=self.dst_ip_edit.text().strip() or None,
            dst_port=port,
            tcp_flags=self.flags_edit.text().strip() or None,
            key_by=self.key_combo.currentText(),
        )
        match, key_fn = dsl.compile()
        return Rule(
            id=rule_id,
            title=title,
            description="User-defined rule",
            severity=self.severity_combo.currentText(),
            enabled=True,
            threshold=self.threshold_spin.value(),
            window_seconds=float(self.window_spin.value()),
            is_builtin=False,
            match=match,
            key_fn=key_fn,
            dsl=dsl,
        )


class RulesPage(QWidget):
    """Rules tab — table of rules + alert log."""

    REFRESH_INTERVAL_MS = 1000

    alert_fired = pyqtSignal(Alert)

    def __init__(self, engine: RuleEngine, parent=None):
        super().__init__(parent)
        self._engine = engine
        self._build_ui()
        self._engine.add_listener(self.alert_fired.emit)
        self.alert_fired.connect(self._on_alert_fired)

        self._timer = QTimer(self)
        self._timer.setInterval(self.REFRESH_INTERVAL_MS)
        self._timer.timeout.connect(self._refresh_alerts)

    # ── Build UI ────────────────────────────────────────────────────
    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 24, 28, 24)
        outer.setSpacing(14)

        # Header
        title = QLabel("Detection rules")
        f = QFont()
        f.setPointSize(20)
        f.setBold(True)
        title.setFont(f)
        title.setStyleSheet(f"color: {TEXT};")
        outer.addWidget(title)

        sub = QLabel(
            "Built-in rules cover the common attacks (SYN flood, port scan, "
            "ARP spoof, deauth flood, …).  Add your own with the rule editor."
        )
        sub.setWordWrap(True)
        sub.setStyleSheet(f"color: {TEXT_DIM}; font-size: 12px;")
        outer.addWidget(sub)

        # Toolbar row
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.new_btn = QPushButton("+  New rule")
        self.new_btn.clicked.connect(self._on_new_rule)
        toolbar.addWidget(self.new_btn)

        self.edit_btn = QPushButton("Edit selected")
        self.edit_btn.clicked.connect(self._on_edit_selected)
        toolbar.addWidget(self.edit_btn)

        self.delete_btn = QPushButton("Delete selected")
        self.delete_btn.clicked.connect(self._on_delete_selected)
        toolbar.addWidget(self.delete_btn)

        toolbar.addStretch(1)

        self.test_btn = QPushButton("⚡  Run self-test")
        self.test_btn.setToolTip(
            "Generate synthetic attack packets and feed them through the rule\n"
            "engine — verifies the alert / toast / log pipeline without\n"
            "needing a real attack on the wire."
        )
        self.test_btn.clicked.connect(self._on_self_test)
        toolbar.addWidget(self.test_btn)

        self.clear_alerts_btn = QPushButton("Clear alerts")
        self.clear_alerts_btn.clicked.connect(self._on_clear_alerts)
        toolbar.addWidget(self.clear_alerts_btn)

        outer.addLayout(toolbar)

        # Splitter: rules table on top, alerts on bottom
        split = QSplitter(Qt.Orientation.Vertical)

        # ── Rules table ─────────────────────────────────────────────
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(6)
        self.rules_table.setHorizontalHeaderLabels(
            ["", "Rule", "Severity", "Threshold", "Window", "Type"]
        )
        self.rules_table.verticalHeader().setVisible(False)
        self.rules_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.rules_table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.rules_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.rules_table.setShowGrid(False)
        h = self.rules_table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.rules_table.setColumnWidth(0, 40)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        rules_panel = self._panel("RULES", self.rules_table)
        split.addWidget(rules_panel)

        # ── Alerts log ──────────────────────────────────────────────
        self.alerts_view = QPlainTextEdit()
        self.alerts_view.setReadOnly(True)
        f2 = QFont("Consolas")
        f2.setPointSize(10)
        self.alerts_view.setFont(f2)
        alerts_panel = self._panel("LIVE ALERTS", self.alerts_view)
        split.addWidget(alerts_panel)

        split.setSizes([460, 280])
        outer.addWidget(split, 1)

        self._render_rules()

    def _panel(self, title: str, body: QWidget) -> QWidget:
        wrap = QFrame()
        wrap.setFrameShape(QFrame.Shape.NoFrame)
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        header = QLabel(title)
        header.setStyleSheet(
            f"background-color: {SURFACE}; color: {TEXT_DIM}; "
            f"padding: 6px 12px; font-weight: 700; font-size: 10px; "
            f"letter-spacing: 1.4px; border-bottom: 1px solid {BORDER};"
        )
        layout.addWidget(header)
        layout.addWidget(body, 1)
        return wrap

    # ── Lifecycle ───────────────────────────────────────────────────
    def start_monitoring(self) -> None:
        self._refresh_alerts()
        self._timer.start()

    def stop_monitoring(self) -> None:
        self._timer.stop()

    # ── Render ──────────────────────────────────────────────────────
    def _render_rules(self):
        rules = self._engine.rules()
        self.rules_table.setRowCount(len(rules))
        for row, rule in enumerate(rules):
            # toggle column
            cb = QCheckBox()
            cb.setChecked(rule.enabled)
            cb.toggled.connect(lambda checked, rid=rule.id: self._on_toggled(rid, checked))
            cb_wrap = QWidget()
            wl = QHBoxLayout(cb_wrap)
            wl.setContentsMargins(8, 0, 0, 0)
            wl.addWidget(cb)
            wl.addStretch(1)
            self.rules_table.setCellWidget(row, 0, cb_wrap)

            # title cell with id underneath
            title_item = QTableWidgetItem(f"{rule.title}\n{rule.id}")
            title_item.setData(Qt.ItemDataRole.UserRole, rule.id)
            title_item.setForeground(Qt.GlobalColor.white)
            self.rules_table.setItem(row, 1, title_item)

            # severity badge
            sev_item = QTableWidgetItem("●  " + rule.severity.upper())
            from PyQt6.QtGui import QColor
            sev_item.setForeground(QColor(_badge(rule.severity)))
            sev_item.setFont(QFont("Consolas"))
            self.rules_table.setItem(row, 2, sev_item)

            self.rules_table.setItem(row, 3, QTableWidgetItem(f"{rule.threshold}"))
            self.rules_table.setItem(row, 4, QTableWidgetItem(f"{int(rule.window_seconds)}s"))
            self.rules_table.setItem(
                row, 5, QTableWidgetItem("built-in" if rule.is_builtin else "custom")
            )
            # Make rows taller for two-line titles
            self.rules_table.setRowHeight(row, 44)

    def _selected_rule(self) -> Optional[Rule]:
        items = self.rules_table.selectedItems()
        if not items:
            return None
        rule_id = items[0].data(Qt.ItemDataRole.UserRole)
        if not rule_id:
            return None
        for r in self._engine.rules():
            if r.id == rule_id:
                return r
        return None

    # ── Handlers ────────────────────────────────────────────────────
    def _on_toggled(self, rule_id: str, enabled: bool) -> None:
        self._engine.set_enabled(rule_id, enabled)

    def _on_new_rule(self) -> None:
        dlg = RuleEditorDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        rule = dlg.to_rule()
        if rule is None:
            return
        self._engine.add_user_rule(rule)
        self._render_rules()

    def _on_edit_selected(self) -> None:
        rule = self._selected_rule()
        if not rule:
            QMessageBox.information(self, "Nothing selected", "Select a rule first.")
            return
        if rule.is_builtin:
            QMessageBox.information(
                self, "Built-in rule",
                "Built-in rules can't be edited (only enabled/disabled).  "
                "Create a new custom rule instead.",
            )
            return
        dlg = RuleEditorDialog(self, rule=rule)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        new_rule = dlg.to_rule()
        if new_rule is None:
            return
        self._engine.add_user_rule(new_rule)
        self._render_rules()

    def _on_delete_selected(self) -> None:
        rule = self._selected_rule()
        if not rule:
            return
        if rule.is_builtin:
            QMessageBox.information(
                self, "Built-in rule",
                "Built-in rules can't be deleted.  Disable them with the toggle.",
            )
            return
        if QMessageBox.question(
            self, "Delete rule", f"Delete user rule {rule.id!r}?"
        ) != QMessageBox.StandardButton.Yes:
            return
        self._engine.remove_user_rule(rule.id)
        self._render_rules()

    def _on_clear_alerts(self) -> None:
        self._engine.clear_alerts()
        self.alerts_view.clear()

    def _on_self_test(self) -> None:
        """Trigger every built-in rule with synthetic packets so the user
        can confirm the alert pipeline (toast + tray balloon + log) works.
        """
        self.test_btn.setEnabled(False)
        try:
            count = self._engine.run_self_test()
        except Exception as exc:
            QMessageBox.warning(self, "Self-test failed", str(exc))
            return
        finally:
            self.test_btn.setEnabled(True)
        QMessageBox.information(
            self, "Self-test complete",
            f"Fired {count} alert(s).  Check the toast notifications in the "
            f"lower-right corner and the alert log below."
            if count else
            "No alerts fired — make sure the relevant rules are enabled.",
        )

    def _refresh_alerts(self) -> None:
        # Render the entire alert log on a tick — simple and the deque is bounded.
        alerts = self._engine.alerts()
        if not alerts:
            return
        if self.alerts_view.toPlainText().count("\n") == len(alerts):
            return  # already rendered
        lines = []
        for a in reversed(alerts):  # newest first
            ts = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
            lines.append(f"[{ts}] {a.severity.upper():<8} {a.message}")
        self.alerts_view.setPlainText("\n".join(lines))

    def _on_alert_fired(self, alert: Alert) -> None:
        # Live-prepend a single line — also queues immediate user notification.
        ts = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
        line = f"[{ts}] {alert.severity.upper():<8} {alert.message}"
        existing = self.alerts_view.toPlainText()
        self.alerts_view.setPlainText(line + ("\n" + existing if existing else ""))
