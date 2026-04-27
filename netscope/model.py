"""QAbstractTableModel + filter proxy for the packet list."""
from __future__ import annotations

from typing import Any, Optional

from PyQt6.QtCore import (
    QAbstractTableModel, Qt, QModelIndex, QSortFilterProxyModel,
)
from PyQt6.QtGui import QFont

from netscope.theme import PROTOCOL_COLORS

COLUMNS = ["#", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
KEYS    = ["no", "time", "src", "dst", "proto", "length", "info"]


class PacketTableModel(QAbstractTableModel):
    """Stores packet summaries plus their raw bytes (for re-dissection on click)."""

    def __init__(self, max_rows: int = 100_000):
        super().__init__()
        self._rows: list[dict[str, Any]] = []
        self._raw: list[bytes] = []
        self._max_rows = max_rows
        self._mono_font: Optional[QFont] = None

    def _font(self) -> QFont:
        if self._mono_font is None:
            f = QFont("Consolas")
            f.setStyleHint(QFont.StyleHint.Monospace)
            f.setPointSize(10)
            self._mono_font = f
        return self._mono_font

    def append_packets(self, items: list[tuple[dict[str, Any], bytes]]) -> None:
        if not items:
            return
        first = len(self._rows)
        last = first + len(items) - 1
        self.beginInsertRows(QModelIndex(), first, last)
        for summary, raw in items:
            self._rows.append(summary)
            self._raw.append(raw)
        self.endInsertRows()

        if len(self._rows) > self._max_rows:
            extra = len(self._rows) - self._max_rows
            self.beginRemoveRows(QModelIndex(), 0, extra - 1)
            del self._rows[:extra]
            del self._raw[:extra]
            self.endRemoveRows()

    def clear(self) -> None:
        if not self._rows:
            return
        self.beginResetModel()
        self._rows.clear()
        self._raw.clear()
        self.endResetModel()

    def get_raw(self, row: int) -> Optional[bytes]:
        if 0 <= row < len(self._raw):
            return self._raw[row]
        return None

    def get_summary(self, row: int) -> Optional[dict[str, Any]]:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section]
        return str(section + 1)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        if row >= len(self._rows):
            return None
        rec = self._rows[row]

        if role == Qt.ItemDataRole.DisplayRole:
            return str(rec[KEYS[col]])
        if role == Qt.ItemDataRole.BackgroundRole:
            color = PROTOCOL_COLORS.get(rec["proto"])
            if color is not None:
                return color
        if role == Qt.ItemDataRole.FontRole:
            return self._font()
        return None


class DisplayFilterProxy(QSortFilterProxyModel):
    """Substring filter applied across all columns."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._needle = ""

    def set_filter_text(self, text: str) -> None:
        new_needle = (text or "").strip().lower()
        if new_needle == self._needle:
            return
        self._needle = new_needle
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        if not self._needle:
            return True
        model = self.sourceModel()
        if model is None:
            return True
        for col in range(model.columnCount()):
            idx = model.index(source_row, col, source_parent)
            val = model.data(idx, Qt.ItemDataRole.DisplayRole)
            if val and self._needle in str(val).lower():
                return True
        return False
