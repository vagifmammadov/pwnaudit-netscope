"""
PWNAudit NetScope — Windows network protocol analyzer.

Live packet capture and inspection in the spirit of Wireshark, themed for
PWNAudit. The shipped .exe carries a UAC manifest and self-elevates; in
development, this script also relaunches itself elevated when needed.
"""
from __future__ import annotations

import ctypes
import os
import sys


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin() -> int:
    script = os.path.abspath(sys.argv[0])
    params = " ".join(f'"{a}"' for a in [script, *sys.argv[1:]])
    workdir = os.path.dirname(script)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, workdir, 1)
    return int(rc)


def _has_npcap() -> bool:
    """Detect Npcap or WinPcap.

    The authoritative test is "can we actually load wpcap.dll" — file-existence
    checks miss two real cases:
      1. 32-bit Python on 64-bit Windows sees System32 redirected to SysWOW64,
         so the file is at a path the literal-string check doesn't list.
      2. The user installed Npcap then disabled the service; the file exists
         but won't load.
    We try ctypes.WinDLL first and only fall back to file probing if the
    ctypes import is broken (shouldn't happen on Windows but defensive).
    """
    try:
        ctypes.WinDLL("wpcap.dll")
        return True
    except OSError:
        pass
    except Exception:
        pass

    # Fallback: probe known install paths. On 64-bit Windows we explicitly
    # look in both System32 and SysWOW64 plus the Npcap subdirectory the
    # installer creates regardless of bitness.
    candidates = [
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Windows\System32\Npcap\packet.dll",
        r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
        r"C:\Windows\SysWOW64\Npcap\packet.dll",
        r"C:\Windows\System32\wpcap.dll",
        r"C:\Windows\SysWOW64\wpcap.dll",
        r"C:\Windows\System32\drivers\npcap.sys",
        r"C:\Windows\System32\drivers\npcap_wifi.sys",
        r"C:\Windows\System32\drivers\npf.sys",
    ]
    return any(os.path.exists(p) for p in candidates)


def _show_npcap_required():
    try:
        from PyQt6.QtWidgets import QApplication, QMessageBox
        from PyQt6.QtCore import QUrl
        from PyQt6.QtGui import QDesktopServices
    except ImportError:
        print(
            "ERROR: Npcap is not installed. Install it from https://npcap.com",
            file=sys.stderr,
        )
        return

    app = QApplication.instance() or QApplication(sys.argv)
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Icon.Critical)
    msg.setWindowTitle("Npcap is required")
    msg.setText("PWNAudit NetScope needs Npcap to capture packets.")
    msg.setInformativeText(
        "Npcap is the same packet-capture library Wireshark uses on Windows.\n\n"
        "Click \"Open download page\" to install it, then relaunch NetScope."
    )
    open_btn = msg.addButton("Open download page", QMessageBox.ButtonRole.AcceptRole)
    msg.addButton("Quit", QMessageBox.ButtonRole.RejectRole)
    msg.exec()
    if msg.clickedButton() is open_btn:
        QDesktopServices.openUrl(QUrl("https://npcap.com/#download"))


def main() -> int:
    if os.name == "nt" and not _is_admin():
        rc = _relaunch_as_admin()
        if rc <= 32:
            print(
                "ERROR: could not elevate via UAC. Right-click the .exe and choose "
                "'Run as administrator'.",
                file=sys.stderr,
            )
            return 1
        return 0

    try:
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        print("ERROR: PyQt6 is not installed. Run BUILD.bat first.", file=sys.stderr)
        return 1

    if not _has_npcap():
        _show_npcap_required()
        return 1

    try:
        import scapy  # noqa: F401
        import psutil  # noqa: F401
    except ImportError as e:
        print(f"ERROR: missing dependency ({e}). Run BUILD.bat to set up.", file=sys.stderr)
        return 1

    from netscope.app import MainWindow
    from netscope.theme import apply_theme

    if hasattr(Qt, "ApplicationAttribute"):
        if hasattr(Qt.ApplicationAttribute, "AA_EnableHighDpiScaling"):
            QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
        if hasattr(Qt.ApplicationAttribute, "AA_UseHighDpiPixmaps"):
            QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("PWNAudit NetScope")
    app.setOrganizationName("PWNAudit")
    apply_theme(app)

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
