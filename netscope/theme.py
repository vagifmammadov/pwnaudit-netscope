"""PWNAudit-inspired dark theme."""
from PyQt6.QtGui import QColor

BG          = "#0A0B10"
SURFACE     = "#0F1115"
SURFACE_ALT = "#161A22"
BORDER      = "#1F2937"
ACCENT      = "#00F5B4"
ACCENT_DIM  = "#0EBF8F"
ACCENT_DEEP = "#003C2A"
TEXT        = "#F7F8FA"
TEXT_DIM    = "#9CA3AF"
DANGER      = "#F87171"
WARNING     = "#FBBF24"
SUCCESS     = "#34D399"
INFO        = "#60A5FA"

PROTOCOL_COLORS = {
    "TCP":      QColor("#11243B"),
    "UDP":      QColor("#0E2B26"),
    "DNS":      QColor("#251D38"),
    "mDNS":     QColor("#251D38"),
    "DHCP":     QColor("#2B2310"),
    "HTTP":     QColor("#3A2C0F"),
    "TLS":      QColor("#1A1E3D"),
    "TLSv1.2":  QColor("#1A1E3D"),
    "TLSv1.3":  QColor("#1A1E3D"),
    "SSH":      QColor("#102836"),
    "FTP":      QColor("#2A1B0F"),
    "SMTP":     QColor("#2A1B0F"),
    "ARP":      QColor("#2F1A0F"),
    "ICMP":     QColor("#0F2A30"),
    "ICMPv6":   QColor("#0F2A30"),
    "IPv4":     QColor("#15161E"),
    "IPv6":     QColor("#15161E"),
    "Ethernet": QColor("#15161E"),
    "SSDP":     QColor("#1F1A2E"),
    "MySQL":    QColor("#1A2A1A"),
    "PostgreSQL": QColor("#1A2A1A"),
}

QSS = f"""
* {{
    color: {TEXT};
    selection-background-color: {ACCENT};
    selection-color: {ACCENT_DEEP};
}}
QMainWindow, QWidget {{
    background-color: {BG};
    font-family: "Segoe UI", "Inter", system-ui, sans-serif;
    font-size: 12px;
}}
QToolBar {{
    background-color: {SURFACE};
    border: none;
    border-bottom: 1px solid {BORDER};
    spacing: 6px;
    padding: 8px 10px;
}}
QToolBar QLabel {{
    color: {TEXT_DIM};
    font-size: 11px;
    margin-left: 6px;
}}
QToolBar::separator {{
    background-color: {BORDER};
    width: 1px;
    margin: 4px 8px;
}}
QPushButton {{
    background-color: {SURFACE_ALT};
    border: 1px solid {BORDER};
    color: {TEXT};
    padding: 6px 14px;
    border-radius: 4px;
    font-weight: 600;
    min-height: 22px;
}}
QPushButton:hover {{
    border-color: {ACCENT};
    color: {ACCENT};
}}
QPushButton:pressed {{
    background-color: {BG};
}}
QPushButton:disabled {{
    color: #4B5563;
    border-color: #1F2937;
}}
QPushButton#start {{
    background-color: {ACCENT};
    color: {ACCENT_DEEP};
    border: 1px solid {ACCENT};
}}
QPushButton#start:hover {{
    background-color: {ACCENT_DIM};
    color: {ACCENT_DEEP};
}}
QPushButton#start:disabled {{
    background-color: {SURFACE_ALT};
    color: #4B5563;
    border-color: {BORDER};
}}
QPushButton#stop {{
    background-color: #2A1118;
    color: {DANGER};
    border: 1px solid {DANGER};
}}
QPushButton#stop:hover {{
    background-color: #3A1620;
}}
QLineEdit, QComboBox {{
    background-color: {SURFACE_ALT};
    border: 1px solid {BORDER};
    padding: 6px 10px;
    border-radius: 4px;
    color: {TEXT};
    selection-background-color: {ACCENT};
    selection-color: {ACCENT_DEEP};
    min-height: 22px;
}}
QLineEdit:focus, QComboBox:focus {{
    border-color: {ACCENT};
}}
QLineEdit::placeholder {{
    color: {TEXT_DIM};
}}
QComboBox::drop-down {{
    border: none;
    width: 20px;
}}
QComboBox::down-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {TEXT_DIM};
    margin-right: 8px;
}}
QComboBox QAbstractItemView {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT};
    selection-color: {ACCENT_DEEP};
    color: {TEXT};
    padding: 4px;
}}
QTableView {{
    background-color: {BG};
    alternate-background-color: #0D0E14;
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT};
    selection-color: {ACCENT_DEEP};
}}
QTableView::item {{
    padding: 0 4px;
    border-right: 1px solid {BORDER};
}}
QTableView::item:selected {{
    background-color: {ACCENT};
    color: {ACCENT_DEEP};
}}
QTreeWidget {{
    background-color: {BG};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT};
    selection-color: {ACCENT_DEEP};
    padding: 4px;
}}
QTreeWidget::item {{
    padding: 2px 4px;
    border: none;
}}
QTreeWidget::item:hover {{
    background-color: {SURFACE_ALT};
}}
QTreeWidget::item:selected {{
    background-color: {ACCENT};
    color: {ACCENT_DEEP};
}}
QTreeWidget::branch {{
    background: transparent;
}}
QTreeWidget::branch:has-children:closed {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {TEXT_DIM};
}}
QTreeWidget::branch:has-children:open {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {ACCENT};
}}
QHeaderView {{
    background-color: {SURFACE};
}}
QHeaderView::section {{
    background-color: {SURFACE};
    color: {TEXT_DIM};
    padding: 6px 10px;
    border: none;
    border-right: 1px solid {BORDER};
    border-bottom: 1px solid {BORDER};
    font-weight: 700;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}
QHeaderView::section:hover {{
    color: {ACCENT};
}}
QPlainTextEdit {{
    background-color: {BG};
    border: 1px solid {BORDER};
    color: {TEXT};
    padding: 8px;
    selection-background-color: {ACCENT};
    selection-color: {ACCENT_DEEP};
}}
QStatusBar {{
    background-color: {SURFACE};
    color: {TEXT_DIM};
    border-top: 1px solid {BORDER};
    padding: 2px 8px;
}}
QStatusBar QLabel {{
    color: {TEXT_DIM};
}}
QSplitter::handle {{
    background-color: {BORDER};
}}
QSplitter::handle:horizontal {{
    width: 1px;
}}
QSplitter::handle:vertical {{
    height: 1px;
}}
QScrollBar:vertical {{
    background-color: {BG};
    width: 10px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background-color: {BORDER};
    border-radius: 4px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background-color: {ACCENT_DIM};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
    background: none;
    border: none;
}}
QScrollBar:horizontal {{
    background-color: {BG};
    height: 10px;
    border: none;
}}
QScrollBar::handle:horizontal {{
    background-color: {BORDER};
    border-radius: 4px;
    min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{
    background-color: {ACCENT_DIM};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
    background: none;
    border: none;
}}
QLabel#brand {{
    color: {ACCENT};
    font-weight: 800;
    font-size: 14px;
    letter-spacing: 1.2px;
    padding-right: 8px;
}}
QLabel#brand_dim {{
    color: {TEXT};
    font-weight: 800;
    font-size: 14px;
    letter-spacing: 1.2px;
}}
QLabel#status_running {{
    color: {ACCENT};
    font-weight: 600;
}}
QLabel#status_idle {{
    color: {TEXT_DIM};
}}
QMessageBox {{
    background-color: {SURFACE};
}}
QMessageBox QLabel {{
    color: {TEXT};
}}
"""


def apply_theme(app):
    app.setStyleSheet(QSS)
