"""
In-window toast notifications + Windows tray balloon for rule alerts.

We avoid pulling in win10toast or similar — those drag heavy COM deps that
break in PyInstaller.  Instead we use:
    1. A floating QFrame in the lower-right corner that auto-fades after 6s.
    2. QSystemTrayIcon.showMessage() for native Windows notifications when
       the app window is minimised or in the background.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QPropertyAnimation, QTimer, QEasingCurve, Qt, QPoint
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QFrame, QLabel, QVBoxLayout, QHBoxLayout, QWidget, QSystemTrayIcon,
    QGraphicsDropShadowEffect,
)
from PyQt6.QtGui import QColor

from netscope.theme import (
    ACCENT, BG, BORDER, DANGER, INFO, SUCCESS, SURFACE, TEXT, TEXT_DIM, WARNING,
)


_SEVERITY_BORDER = {
    "info": INFO,
    "low": SUCCESS,
    "medium": WARNING,
    "high": DANGER,
    "critical": DANGER,
}


class Toast(QFrame):
    """One in-window toast — slides in, fades out after 6s."""

    def __init__(self, parent: QWidget, *, title: str, message: str, severity: str = "medium"):
        super().__init__(parent)
        border = _SEVERITY_BORDER.get(severity, ACCENT)
        self.setStyleSheet(
            f"QFrame {{ background-color: {SURFACE}; border: 1px solid {border}; "
            f"border-left: 3px solid {border}; border-radius: 6px; }}"
        )
        self.setMinimumWidth(360)
        self.setMaximumWidth(440)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        head = QHBoxLayout()
        head.setContentsMargins(0, 0, 0, 0)
        head.setSpacing(8)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(f"color: {TEXT}; font-weight: 700; font-size: 12px;")
        head.addWidget(title_lbl, 1)

        sev_lbl = QLabel(severity.upper())
        sev_lbl.setStyleSheet(
            f"color: {border}; font-weight: 700; font-size: 9px; "
            f"letter-spacing: 1.4px;"
        )
        head.addWidget(sev_lbl)

        layout.addLayout(head)

        msg_lbl = QLabel(message)
        msg_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        msg_lbl.setWordWrap(True)
        layout.addWidget(msg_lbl)

        # Soft drop shadow for visibility on dark backgrounds.
        eff = QGraphicsDropShadowEffect(self)
        eff.setBlurRadius(24)
        eff.setOffset(0, 4)
        eff.setColor(QColor(0, 0, 0, 180))
        self.setGraphicsEffect(eff)


class NotificationCenter:
    """Manages a stack of toasts in the lower-right of the parent window."""

    MAX_VISIBLE = 4
    DURATION_MS = 6000
    SPACING = 10

    def __init__(self, parent: QWidget) -> None:
        self._parent = parent
        self._toasts: list[Toast] = []
        self._tray: Optional[QSystemTrayIcon] = None

    def attach_tray(self, tray: QSystemTrayIcon) -> None:
        self._tray = tray

    def show(self, *, title: str, message: str, severity: str = "medium") -> None:
        toast = Toast(self._parent, title=title, message=message, severity=severity)
        toast.adjustSize()
        self._toasts.append(toast)
        # Tear down the oldest if we exceed MAX_VISIBLE.
        while len(self._toasts) > self.MAX_VISIBLE:
            old = self._toasts.pop(0)
            old.hide()
            old.deleteLater()
        toast.show()
        self._reflow()

        QTimer.singleShot(self.DURATION_MS, lambda t=toast: self._dismiss(t))

        # Native Windows notification (only when window is not active).
        if self._tray is not None and not self._parent.isActiveWindow():
            try:
                icon = QSystemTrayIcon.MessageIcon.Warning
                if severity in ("info", "low"):
                    icon = QSystemTrayIcon.MessageIcon.Information
                elif severity == "critical":
                    icon = QSystemTrayIcon.MessageIcon.Critical
                self._tray.showMessage(title, message, icon, self.DURATION_MS)
            except Exception:
                pass

    def _dismiss(self, toast: Toast) -> None:
        if toast not in self._toasts:
            return
        anim = QPropertyAnimation(toast, b"windowOpacity", toast)
        anim.setDuration(300)
        anim.setStartValue(1.0)
        anim.setEndValue(0.0)
        anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
        anim.finished.connect(lambda: self._remove(toast))
        anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    def _remove(self, toast: Toast) -> None:
        if toast in self._toasts:
            self._toasts.remove(toast)
        toast.hide()
        toast.deleteLater()
        self._reflow()

    def _reflow(self) -> None:
        if not self._toasts:
            return
        rect = self._parent.rect()
        margin = 16
        y = rect.bottom() - margin
        for toast in reversed(self._toasts):
            toast.adjustSize()
            x = rect.right() - toast.width() - margin
            y -= toast.height()
            toast.move(self._parent.mapToGlobal(QPoint(x, y)))
            toast.raise_()
            y -= self.SPACING
