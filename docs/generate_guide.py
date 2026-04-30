"""
Build PWNAudit-NetScope-Guide.pdf from the content below + the screenshots
in docs/screenshots/.

Run from the project root:
    venv\\Scripts\\python.exe docs\\generate_guide.py

Screenshots:
    Drop PNG/JPG files into docs/screenshots/.  The script looks for the
    filenames listed in SCREENSHOT_SLOTS — if the file exists it is embedded
    full-width, otherwise a dashed placeholder box with the slot name is
    shown so you can see exactly where each one goes.

Capturing screenshots on Windows:
    Win + Shift + S   →  region snip → save as PNG
    Use the suggested filename (e.g. ``01-welcome.png``) so this script
    picks it up without further edits.
"""
from __future__ import annotations

import os
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, PageBreak,
    Image, Table, TableStyle, KeepTogether,
)
from reportlab.platypus.flowables import HRFlowable, Flowable

ROOT = Path(__file__).resolve().parent
SHOTS_DIR = ROOT / "screenshots"
OUTPUT = ROOT / "PWNAudit-NetScope-Guide.pdf"

# ─── Theme ──────────────────────────────────────────────────────────
BG          = colors.HexColor("#0A0B10")
SURFACE     = colors.HexColor("#0F1115")
SURFACE_ALT = colors.HexColor("#161A22")
BORDER      = colors.HexColor("#1F2937")
ACCENT      = colors.HexColor("#00F5B4")
ACCENT_DEEP = colors.HexColor("#003C2A")
TEXT        = colors.HexColor("#F7F8FA")
TEXT_DIM    = colors.HexColor("#9CA3AF")
DANGER      = colors.HexColor("#F87171")
WARNING     = colors.HexColor("#FBBF24")
INFO        = colors.HexColor("#60A5FA")

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

# ─── Styles ─────────────────────────────────────────────────────────
def _style(name: str, **kw) -> ParagraphStyle:
    base = dict(fontName="Helvetica", fontSize=11, leading=15,
                textColor=TEXT, alignment=TA_LEFT)
    base.update(kw)
    return ParagraphStyle(name=name, **base)

S_TITLE     = _style("title", fontName="Helvetica-Bold", fontSize=32, leading=36,
                     textColor=ACCENT, alignment=TA_LEFT)
S_SUBTITLE  = _style("subtitle", fontSize=13, leading=18,
                     textColor=TEXT_DIM, alignment=TA_LEFT)
S_VERSION   = _style("version", fontName="Helvetica-Bold", fontSize=10, leading=12,
                     textColor=ACCENT, alignment=TA_LEFT)
S_H1        = _style("h1", fontName="Helvetica-Bold", fontSize=20, leading=26,
                     textColor=ACCENT, spaceBefore=18, spaceAfter=8)
S_H2        = _style("h2", fontName="Helvetica-Bold", fontSize=14, leading=20,
                     textColor=TEXT, spaceBefore=12, spaceAfter=4)
S_BODY      = _style("body", fontSize=10.5, leading=16, alignment=TA_JUSTIFY,
                     spaceAfter=6)
S_BULLET    = _style("bullet", fontSize=10.5, leading=15, leftIndent=14,
                     bulletIndent=2, spaceAfter=2)
S_CODE      = _style("code", fontName="Courier", fontSize=9.5, leading=13,
                     textColor=ACCENT, backColor=SURFACE, borderPadding=8,
                     borderColor=BORDER, borderWidth=0.5,
                     leftIndent=0, rightIndent=0, spaceBefore=4, spaceAfter=8)
S_CAPTION   = _style("caption", fontSize=9, leading=12, textColor=TEXT_DIM,
                     alignment=TA_CENTER, spaceBefore=4, spaceAfter=10)
S_NOTE      = _style("note", fontSize=10, leading=14, textColor=WARNING,
                     leftIndent=10, rightIndent=10, borderColor=WARNING,
                     borderPadding=8, borderWidth=0.5, backColor=SURFACE,
                     spaceBefore=8, spaceAfter=8)
S_DANGER    = _style("danger", fontSize=10, leading=14, textColor=DANGER,
                     leftIndent=10, rightIndent=10, borderColor=DANGER,
                     borderPadding=8, borderWidth=0.5, backColor=SURFACE,
                     spaceBefore=8, spaceAfter=8)
S_TOC       = _style("toc", fontSize=11, leading=18, textColor=TEXT)


# ─── Page templates ─────────────────────────────────────────────────
def _draw_page_chrome(canvas, doc):
    canvas.saveState()
    # full-bleed background
    canvas.setFillColor(BG)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    # footer rule
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, 14 * mm, PAGE_W - MARGIN, 14 * mm)
    # footer text
    canvas.setFillColor(TEXT_DIM)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(MARGIN, 9 * mm, "PWNAudit NetScope · User Guide")
    canvas.drawRightString(PAGE_W - MARGIN, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _draw_cover_chrome(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(BG)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    # diagonal accent panel
    canvas.setFillColor(ACCENT_DEEP)
    canvas.setStrokeColor(ACCENT_DEEP)
    p = canvas.beginPath()
    p.moveTo(0, PAGE_H * 0.62)
    p.lineTo(PAGE_W, PAGE_H * 0.78)
    p.lineTo(PAGE_W, PAGE_H)
    p.lineTo(0, PAGE_H)
    p.close()
    canvas.drawPath(p, fill=1, stroke=0)
    # accent bar
    canvas.setFillColor(ACCENT)
    canvas.rect(MARGIN, PAGE_H - 50 * mm, 56 * mm, 1.6 * mm, fill=1, stroke=0)
    canvas.restoreState()


# ─── Helpers ────────────────────────────────────────────────────────
class PlaceholderBox(Flowable):
    """Dashed-border placeholder for screenshots that haven't been added yet."""

    def __init__(self, width: float, height: float, label: str):
        super().__init__()
        self.width = width
        self.height = height
        self.label = label

    def draw(self):
        c = self.canv
        c.saveState()
        c.setStrokeColor(BORDER)
        c.setFillColor(SURFACE)
        c.setLineWidth(0.7)
        c.setDash(3, 3)
        c.roundRect(0, 0, self.width, self.height, 6, fill=1, stroke=1)
        c.setDash()
        c.setFillColor(TEXT_DIM)
        c.setFont("Helvetica-Bold", 11)
        c.drawCentredString(self.width / 2, self.height / 2 + 6,
                            f"[ Screenshot slot ]")
        c.setFont("Courier", 9)
        c.setFillColor(ACCENT)
        c.drawCentredString(self.width / 2, self.height / 2 - 10,
                            self.label)
        c.setFont("Helvetica", 8)
        c.setFillColor(TEXT_DIM)
        c.drawCentredString(self.width / 2, self.height / 2 - 26,
                            f"Drop the file at docs/screenshots/{self.label}")
        c.restoreState()


def screenshot(filename: str, caption: str, *, height_mm: float = 95):
    """Embed a screenshot if the file exists, else show a placeholder."""
    path = SHOTS_DIR / filename
    width = CONTENT_W
    height = height_mm * mm
    if path.exists():
        try:
            img = Image(str(path), width=width, height=height,
                        kind="proportional")
        except Exception:
            img = PlaceholderBox(width, height, filename)
    else:
        img = PlaceholderBox(width, height, filename)
    return KeepTogether([
        img,
        Paragraph(caption, S_CAPTION),
    ])


def code_block(text: str):
    # Reportlab-friendly escaping for <, >, &
    escaped = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    return Paragraph(escaped.replace("\n", "<br/>"), S_CODE)


def bullet(text: str) -> Paragraph:
    return Paragraph(f"•&nbsp;&nbsp;{text}", S_BULLET)


def section(title: str):
    """H1 + accent rule."""
    return [
        Paragraph(title, S_H1),
        HRFlowable(width="100%", thickness=1, color=BORDER,
                   spaceBefore=0, spaceAfter=10),
    ]


# ─── Content ────────────────────────────────────────────────────────
def cover_page():
    return [
        Spacer(1, 60 * mm),
        Paragraph("PWNAudit", S_VERSION),
        Paragraph("NetScope", S_TITLE),
        Spacer(1, 6 * mm),
        Paragraph(
            "Wireshark-style live packet analyzer for Windows<br/>"
            "with Wi-Fi 2.4 GHz / 5 GHz visibility, attack-detection rules, "
            "and an authorised pentest module.",
            S_SUBTITLE,
        ),
        Spacer(1, 80 * mm),
        Paragraph("USER GUIDE  ·  Version 0.1.0", S_VERSION),
        Spacer(1, 4 * mm),
        Paragraph("PWNAudit · pwnaudit.com", S_SUBTITLE),
    ]


def toc_page():
    rows = [
        ("1.", "Introduction", "3"),
        ("2.", "Installation", "4"),
        ("3.", "Main interface — sidebar navigation", "5"),
        ("4.", "Tab 1 · Interfaces (live capture)", "6"),
        ("5.", "Tab 2 · Wireless (2.4 / 5 GHz Wi-Fi)", "8"),
        ("6.", "Capture view — tri-pane analysis", "10"),
        ("7.", "Tab 3 · Rules — attack detection", "12"),
        ("8.", "Tab 4 · Pentest — authorised testing", "14"),
        ("9.", "Architecture — how it works inside", "17"),
        ("10.", "Troubleshooting & FAQ", "18"),
        ("11.", "Credits & licence", "20"),
    ]
    data = [[Paragraph(f"<b>{n}</b>", S_TOC),
             Paragraph(t, S_TOC),
             Paragraph(f"<para align='right'>{p}</para>", S_TOC)] for n, t, p in rows]
    table = Table(data, colWidths=[12 * mm, CONTENT_W - 30 * mm, 18 * mm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, BORDER),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
    ]))
    return [
        Paragraph("Contents", S_H1),
        HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=12),
        table,
    ]


def s1_intro():
    return [
        *section("1. Introduction"),
        Paragraph(
            "<b>PWNAudit NetScope</b> is a Windows desktop application for live "
            "network packet capture and analysis, in the style of Wireshark. "
            "Unlike Wireshark, NetScope was built specifically to make the "
            "<b>2.4 GHz vs 5 GHz Wi-Fi</b> story visible at a glance — useful "
            "when you are investigating throughput, coverage, or interference "
            "on your own network.",
            S_BODY,
        ),
        Paragraph("What you can do with it:", S_H2),
        bullet("See every Wi-Fi adapter on your machine, the SSID it is "
               "connected to, the band (2.4 GHz / 5 GHz), the channel and the "
               "live signal strength."),
        bullet("Capture every packet flowing across any local network adapter "
               "(Wi-Fi, Ethernet, VPN, virtual)."),
        bullet("Run live attack-detection rules against the capture stream — "
               "SYN floods, port scans, ARP spoofing, deauth bursts."),
        bullet("Author your own detection rules using a small JSON DSL — no "
               "code required."),
        bullet("Run authorised pentest tools (port scanner, ARP scan, ARP "
               "spoof, 802.11 deauth, beacon flood) for testing your own "
               "network or a lab environment."),
        Spacer(1, 6),
        Paragraph(
            "<b>Important:</b> NetScope is a defensive / educational tool. "
            "All traffic stays on your machine — nothing is uploaded.  Run "
            "the pentest modules only against networks you own or have "
            "explicit written permission to test.",
            S_NOTE,
        ),
    ]


def s2_install():
    return [
        *section("2. Installation"),
        Paragraph("System requirements:", S_H2),
        bullet("Windows 10 or 11 (64-bit)"),
        bullet("Administrator rights (the app self-elevates via UAC)"),
        bullet("≈ 60 MB free disk, 200 MB RAM during capture"),
        bullet("<b>Npcap</b> packet-capture driver (free, separate install)"),
        Spacer(1, 6),
        Paragraph("Step 1 — Install Npcap", S_H2),
        Paragraph(
            "Download from <font color='#00F5B4'>https://npcap.com/#download</font> "
            "and run the installer.  Use the default options — NetScope works "
            "with both WinPcap-compatible mode and the modern driver.",
            S_BODY,
        ),
        Paragraph("Step 2 — Download NetScope", S_H2),
        Paragraph(
            "Open the PWNAudit dashboard at <font color='#00F5B4'>"
            "pwnaudit.com/dashboard/netscope</font> and click "
            "<b>Download for Windows</b>.  The .exe is hosted on GitHub Releases.",
            S_BODY,
        ),
        screenshot("01-download-page.png",
                   "Figure 2.1 — The NetScope download page on the PWNAudit dashboard.",
                   height_mm=90),
        Paragraph("Step 3 — Run the installer", S_H2),
        Paragraph(
            "Double-click <font face='Courier'>PWNAudit-NetScope-Setup.exe</font>, "
            "approve the UAC prompt, and click through the wizard.  After "
            "Finish, the app shows up under <b>PWNAudit</b> in Windows Search.",
            S_BODY,
        ),
        Paragraph(
            "<b>Windows SmartScreen</b> may show a warning the first time you run an "
            "unsigned executable.  Click <b>More info</b> → <b>Run anyway</b>.  This "
            "warning disappears once the binary builds reputation or is code-signed.",
            S_NOTE,
        ),
    ]


def s3_main_interface():
    return [
        *section("3. Main interface"),
        Paragraph(
            "When you launch NetScope you land on the main window.  The left "
            "rail is the navigation sidebar; the right side is the active page.",
            S_BODY,
        ),
        screenshot("02-main-window.png",
                   "Figure 3.1 — Main window with sidebar navigation and the Interfaces page.",
                   height_mm=110),
        Paragraph("The four tabs:", S_H2),
        bullet("<b>Interfaces</b> — every local network adapter with live "
               "throughput sparklines.  Click to start a generic capture."),
        bullet("<b>Wireless</b> — Wi-Fi-aware view: connected SSID, BSSID, "
               "channel, band (2.4 / 5 GHz), nearby networks, capture launcher."),
        bullet("<b>Rules</b> — attack-detection rules and live alerts."),
        bullet("<b>Pentest</b> — authorised attack modules (port scan, ARP "
               "spoof, deauth, …).  Gated behind a confirmation banner."),
    ]


def s4_interfaces():
    return [
        *section("4. Tab 1 · Interfaces"),
        Paragraph(
            "The Interfaces tab is the default landing page.  It lists every "
            "network adapter that <font face='Courier'>psutil</font> reports — "
            "Wi-Fi, Ethernet, VPN tunnels, virtual adapters, even Bluetooth PAN.",
            S_BODY,
        ),
        Paragraph("Each row shows:", S_H2),
        bullet("Type glyph: 📶 Wi-Fi · 🔌 Ethernet · 🛡 VPN · ⓘ other"),
        bullet("Adapter name and IP address"),
        bullet("Live <b>sparkline</b> of packets-per-second over the last "
               "60 seconds — pulled directly from "
               "<font face='Courier'>psutil.net_io_counters()</font>, so the "
               "numbers match Windows Task Manager"),
        bullet("Current packets/sec rate"),
        screenshot("03-interfaces-list.png",
                   "Figure 4.1 — Interfaces list with live sparklines.  The accent-coloured "
                   "row is what your machine is currently sending traffic over.",
                   height_mm=95),
        Paragraph("BPF capture filter", S_H2),
        Paragraph(
            "The text box at the bottom accepts a kernel-level <b>BPF filter</b> "
            "(same syntax as Wireshark / tcpdump).  Examples:",
            S_BODY,
        ),
        code_block(
            "tcp port 80\n"
            "host 192.168.1.10\n"
            "udp and port 53\n"
            "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"
        ),
        Paragraph(
            "Clicking any interface row launches a capture session with the "
            "filter applied.  The view switches to the <b>Capture page</b> "
            "(see section 6).",
            S_BODY,
        ),
    ]


def s5_wireless():
    return [
        *section("5. Tab 2 · Wireless"),
        Paragraph(
            "The Wireless tab is the headline feature for the 2.4 GHz / 5 GHz "
            "use case.  It pulls live state from <font face='Courier'>"
            "netsh wlan show interfaces</font> and renders it as labelled "
            "tiles so you can read SSID / band / signal at a glance.",
            S_BODY,
        ),
        screenshot("04-wireless-overview.png",
                   "Figure 5.1 — Wireless tab showing the connected adapter on 5 GHz "
                   "(channel 36) and a list of every nearby BSSID with its band.",
                   height_mm=120),
        Paragraph("Live status tiles", S_H2),
        bullet("<b>Connected SSID</b> — the network you are joined to"),
        bullet("<b>BSSID</b> — the MAC of the AP radio you are talking to"),
        bullet("<b>Channel</b> — IEEE 802.11 channel number"),
        bullet("<b>Band</b> — derived from the channel: 1–14 → 2.4 GHz, "
               "32–177 → 5 GHz"),
        bullet("<b>Signal</b> — bar chart and percentage from the OS"),
        bullet("<b>Radio · Link</b> — 802.11 standard (ax / ac / n) and the "
               "current Rx / Tx negotiated rate"),
        Paragraph("Visible networks list", S_H2),
        Paragraph(
            "Below the tiles is every BSSID the radio currently sees, sorted "
            "by signal strength.  Use the <b>Band</b> dropdown above the list "
            "to filter to just 2.4 GHz, 5 GHz, or 6 GHz APs.",
            S_BODY,
        ),
        screenshot("05-wireless-band-filter.png",
                   "Figure 5.2 — Filtering the list to only 5 GHz.  Useful when investigating "
                   "channel congestion on a single band.",
                   height_mm=95),
        Paragraph("Launching capture", S_H2),
        Paragraph(
            "Click any row to select that BSSID, then hit "
            "<b>Capture on this band</b> — NetScope starts a session with the "
            "BPF filter <font face='Courier'>ether host &lt;BSSID&gt;</font> "
            "pre-applied, so you see only the traffic for that one AP.",
            S_BODY,
        ),
        Paragraph(
            "<b>Note:</b> Without monitor mode (which most consumer Wi-Fi "
            "cards on Windows don't support via Npcap), the capture sees "
            "Ethernet-style frames the host is part of — beacons, probes, and "
            "deauths from third-party devices require an AirPcap or a "
            "monitor-mode-capable USB adapter (e.g. Alfa AWUS036ACH with the "
            "right driver).",
            S_NOTE,
        ),
    ]


def s6_capture():
    return [
        *section("6. Capture view"),
        Paragraph(
            "Once a capture is running, the view switches to a Wireshark-style "
            "tri-pane layout: packet list at the top, protocol tree on the "
            "bottom-left, hex+ASCII dump on the bottom-right.",
            S_BODY,
        ),
        screenshot("06-capture-tripane.png",
                   "Figure 6.1 — Live capture session.  Selecting a packet "
                   "expands its protocol stack and renders the raw bytes.",
                   height_mm=130),
        Paragraph("Toolbar (top)", S_H2),
        bullet("<b>← Interfaces</b> — stop and return to the previous tab"),
        bullet("<b>Display filter</b> — substring / IP / port / proto match "
               "(debounced 250 ms)"),
        bullet("<b>■ Stop</b> / <b>▶ Resume</b> — pause and resume capture "
               "without losing already-captured packets"),
        bullet("<b>Clear</b> — drop all in-memory packets (frees RAM during "
               "long sessions)"),
        Paragraph("Packet list", S_H2),
        Paragraph(
            "The table is virtualized via <font face='Courier'>"
            "QAbstractTableModel</font> and can hold up to 200 000 packets in "
            "memory before eviction.  Columns: # · time · src · dst · proto · "
            "length · info.",
            S_BODY,
        ),
        Paragraph("Status bar (bottom)", S_H2),
        bullet("Capturing/Stopped indicator with the active interface name"),
        bullet("Total packet count"),
        bullet("Live <b>pps</b> (packets per second) over the last 500 ms window"),
        Paragraph("Keyboard shortcuts:", S_H2),
        code_block(
            "Ctrl+E    — toggle capture (stop / resume)\n"
            "Ctrl+L    — clear the packet list\n"
            "Ctrl+F    — focus the display-filter box"
        ),
    ]


def s7_rules():
    return [
        *section("7. Tab 3 · Rules — attack detection"),
        Paragraph(
            "The Rules tab is a small intrusion-detection engine that "
            "evaluates every captured packet against a list of rules.  When "
            "a sliding-window threshold is crossed an <b>Alert</b> fires — "
            "shown as a toast in the lower-right corner and as a Windows "
            "tray balloon when the app is in the background.",
            S_BODY,
        ),
        screenshot("07-rules-table.png",
                   "Figure 7.1 — Rules tab.  The toggle on each row enables / disables "
                   "the rule.  The bottom panel streams alerts in real time.",
                   height_mm=120),
        Paragraph("Built-in rules (shipped with v0.1.0)", S_H2),
    ]


def s7_rules_table():
    rows = [
        ["Rule", "Severity", "Threshold", "What it catches"],
        ["builtin.syn-flood", "high", "200 / 10s", "Half-open SYN spam from one source — DoS attempt"],
        ["builtin.port-scan", "medium", "30 / 10s", "Many distinct ports from one IP — nmap-style scan"],
        ["builtin.dns-flood", "low", "80 / 10s", "Excessive DNS queries — DGA malware indicator"],
        ["builtin.arp-spoof", "high", "20 / 10s", "Unsolicited ARP replies — possible MITM"],
        ["builtin.icmp-flood", "medium", "200 / 10s", "Ping flood / DoS"],
        ["builtin.wifi-deauth", "high", "10 / 5s", "802.11 deauth bursts (monitor mode required)"],
        ["builtin.wifi-beacon-flood", "medium", "80 / 10s", "Spoofed AP beacons (monitor mode required)"],
    ]
    table = Table(rows, colWidths=[55 * mm, 22 * mm, 26 * mm, CONTENT_W - 103 * mm])
    table.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 9),
        ("TEXTCOLOR", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 1), (-1, -1), TEXT),
        ("BACKGROUND", (0, 0), (-1, 0), SURFACE),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, ACCENT),
        ("LINEBELOW", (0, 1), (-1, -2), 0.3, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return [table, Spacer(1, 8)]


def s7_rules_continued():
    return [
        Paragraph("Writing a custom rule", S_H2),
        Paragraph(
            "Click <b>+ New rule</b> to open the rule editor.  Rules are "
            "described in a small JSON DSL — leave any field blank to "
            "wildcard it.",
            S_BODY,
        ),
        screenshot("08-rule-editor.png",
                   "Figure 7.2 — Rule editor dialog.  The example creates a rule that fires when "
                   "more than 100 DNS queries hit 8.8.8.8 in 60 seconds from any one source.",
                   height_mm=110),
        Paragraph("DSL fields:", S_H2),
        code_block(
            'protocol     = TCP | UDP | ICMP | ARP | DNS | DHCP | Dot11\n'
            'src_ip       = "any" | "10.0.0.1" | "192.168.1.0/24"\n'
            'dst_ip       = "any" | "8.8.8.8" | "10.0.0.0/24"\n'
            'dst_port     = null | 22 | 443\n'
            'tcp_flags    = null | "S" | "SA" | "FA"\n'
            'key_by       = src_ip | src_mac | dst_ip | dst_port | none\n'
            'threshold    = number of matches\n'
            'window_sec   = sliding window in seconds'
        ),
        Paragraph(
            "Custom rules are persisted at "
            "<font face='Courier'>%APPDATA%\\PWNAudit-NetScope\\rules.json</font> "
            "and reloaded on every app launch.  Built-in rules can be "
            "enabled/disabled but not edited — disable them and create a "
            "custom variant if you need different thresholds.",
            S_BODY,
        ),
    ]


def s8_pentest():
    return [
        *section("8. Tab 4 · Pentest — authorised testing"),
        Paragraph(
            "The Pentest tab contains active testing tools.  All five modules "
            "are gated behind a red authorisation banner — the Run buttons "
            "stay disabled until you tick the confirmation checkbox.",
            S_BODY,
        ),
        Paragraph(
            "<b>Authorised use only.</b>  Run these modules only against "
            "networks you own or have explicit written permission to test.  "
            "Running attacks against networks you do not own is illegal in "
            "most jurisdictions.",
            S_DANGER,
        ),
        screenshot("09-pentest-overview.png",
                   "Figure 8.1 — Pentest tab with the authorisation banner unticked "
                   "(Run buttons disabled).",
                   height_mm=120),
        Paragraph("Module 1 — TCP port scan", S_H2),
        Paragraph(
            "Touches each port on a target host with a connect()-style probe. "
            "Open ports are streamed into the attack log.",
            S_BODY,
        ),
        bullet("<b>Target:</b> hostname or IP (DNS-resolved)"),
        bullet("<b>Ports:</b> comma list and ranges, e.g. "
               "<font face='Courier'>22,80,443,8000-8010</font>"),
        screenshot("10-pentest-portscan.png",
                   "Figure 8.2 — Port scan against 192.168.1.10 finding SSH and HTTP/S open.",
                   height_mm=80),
        Paragraph("Module 2 — ARP host discovery", S_H2),
        Paragraph(
            "Sweeps a /24 (or smaller) with ARP <b>who-has</b> and lists every "
            "MAC that responds.  Hard cap of 1 024 hosts to prevent accidental "
            "scans of huge networks.",
            S_BODY,
        ),
        Paragraph("Module 3 — ARP spoof (MITM test)", S_H2),
        Paragraph(
            "Forges ARP replies so the victim learns the gateway is at your "
            "MAC.  Used to verify your own IDS / endpoint protection notices "
            "the attack.",
            S_BODY,
        ),
        Paragraph(
            "<b>Stop & restore</b> always sends five corrected ARP replies "
            "before quitting, so the victim's ARP cache is repaired.  Don't "
            "force-quit the app while spoofing — the cache stays poisoned "
            "for ~30 seconds otherwise.",
            S_NOTE,
        ),
        Paragraph("Modules 4-5 — Wi-Fi (deauth, beacon flood)", S_H2),
        Paragraph(
            "These require <b>monitor mode</b> with packet injection.  Most "
            "consumer Wi-Fi cards on Windows don't support this without "
            "specialised drivers.  If your adapter rejects the injection, "
            "the log says exactly that:",
            S_BODY,
        ),
        code_block(
            '[deauth] sendp failed: ...\n'
            '         This usually means the adapter does not support\n'
            '         monitor-mode injection on Windows.'
        ),
        Paragraph(
            "Adapters that work for monitor-mode injection on Windows "
            "include the Alfa AWUS036ACH (with the right Realtek driver) "
            "and most TP-Link cards re-flashed with the Atheros stack.",
            S_BODY,
        ),
        Paragraph("Attack log", S_H2),
        Paragraph(
            "The right-side panel records every action with a wall-clock "
            "timestamp.  Useful for school write-ups: at the end of a session "
            "click <b>Clear log</b> only after you've copied the relevant "
            "lines into your report.",
            S_BODY,
        ),
        screenshot("11-pentest-log.png",
                   "Figure 8.3 — Attack log with port-scan and ARP-spoof activity.",
                   height_mm=90),
    ]


def s9_architecture():
    return [
        *section("9. Architecture"),
        Paragraph("Tech stack:", S_H2),
        bullet("<b>Python 3.11</b> + <b>PyQt6</b> for the desktop UI"),
        bullet("<b>scapy</b> for protocol dissection and packet injection"),
        bullet("<b>Npcap</b> as the underlying capture driver"),
        bullet("<b>psutil</b> for live interface counters"),
        bullet("<b>PyInstaller</b> + <b>Inno Setup</b> for the Windows installer"),
        Paragraph("Threading model:", S_H2),
        Paragraph(
            "Capture happens on a background thread (scapy's "
            "<font face='Courier'>AsyncSniffer</font>).  Packets land in a "
            "lock-protected buffer; a 100 ms <font face='Courier'>QTimer</font> "
            "drains the buffer into a Qt model on the UI thread.  The rule "
            "engine evaluates each packet on the sniffer thread and emits "
            "alerts back to the UI via <font face='Courier'>QTimer."
            "singleShot(0, ...)</font>.",
            S_BODY,
        ),
        Paragraph("File layout:", S_H2),
        code_block(
            "netscope/\n"
            "  ├ app.py            — main window + sidebar nav\n"
            "  ├ welcome.py        — Interfaces tab + sparklines\n"
            "  ├ wireless_page.py  — Wireless tab (2.4 / 5 GHz)\n"
            "  ├ wifi.py           — netsh parser, band detection\n"
            "  ├ capture.py        — AsyncSniffer wrapper\n"
            "  ├ dissect.py        — protocol summarisation\n"
            "  ├ model.py          — Qt table model + filter proxy\n"
            "  ├ rules.py          — rules engine + built-in rules\n"
            "  ├ rules_page.py     — Rules tab UI\n"
            "  ├ notify.py         — toast + tray notifications\n"
            "  ├ pentest.py        — attack module backends\n"
            "  ├ pentest_page.py   — Pentest tab UI\n"
            "  ├ interfaces.py     — adapter enumeration\n"
            "  └ theme.py          — dark-theme QSS"
        ),
    ]


def s10_faq():
    items = [
        ("Npcap is required dialog appears every launch",
         "Npcap is not installed or its DLL was renamed.  Install / reinstall "
         "from npcap.com.  After installation, restart NetScope."),
        ("UAC prompt is denied",
         "NetScope requires admin rights for raw packet access.  If you "
         "cancel the UAC prompt the app exits.  Right-click "
         "PWNAudit-NetScope.exe → Run as administrator."),
        ("Wireless tab shows \"No Wi-Fi adapter\"",
         "Your machine has no Wi-Fi radio or Windows has it disabled.  Plug "
         "in a USB Wi-Fi dongle or enable the internal radio in Settings → "
         "Network & Internet → Wi-Fi, then click Refresh."),
        ("802.11 deauth says \"sendp failed\"",
         "The adapter doesn't support monitor-mode injection via Npcap on "
         "Windows.  Use a compatible adapter (Alfa AWUS036ACH, TP-Link "
         "TL-WN722N v1) or run from a Linux box with airmon-ng."),
        ("Windows Defender flags the .exe as unknown",
         "The binary is not yet code-signed.  Click \"More info\" → "
         "\"Run anyway\".  After enough downloads, SmartScreen builds "
         "reputation and stops warning."),
        ("Custom rules don't survive across app restarts",
         "Check that %APPDATA%\\PWNAudit-NetScope\\ exists and is writable.  "
         "If you renamed the app, the config dir name changes — copy "
         "rules.json across manually."),
        ("Capture drops packets at very high rates (>100k pps)",
         "The Python+scapy pipeline tops out around 100-150k pps on a "
         "modern CPU.  For higher rates use Wireshark with a kernel-mode "
         "capture filter to pre-filter at the driver layer."),
    ]
    out = [*section("10. Troubleshooting & FAQ")]
    for q, a in items:
        out.append(Paragraph(f"<b>{q}</b>", S_H2))
        out.append(Paragraph(a, S_BODY))
    return out


def s11_credits():
    return [
        *section("11. Credits & licence"),
        Paragraph("Open-source dependencies:", S_H2),
        bullet("<b>scapy</b> — GPLv2 (https://scapy.net)"),
        bullet("<b>PyQt6</b> — GPLv3 / commercial"),
        bullet("<b>psutil</b> — BSD"),
        bullet("<b>Npcap</b> — proprietary, free for personal use"),
        bullet("<b>Inno Setup</b> — modified BSD"),
        bullet("<b>reportlab</b> — BSD (this guide)"),
        Paragraph("Project:", S_H2),
        Paragraph(
            "PWNAudit NetScope source code: "
            "<font color='#00F5B4'>github.com/vagifmammadov/pwnaudit-netscope</font><br/>"
            "PWNAudit dashboard: <font color='#00F5B4'>pwnaudit.com</font>",
            S_BODY,
        ),
        Spacer(1, 30 * mm),
        Paragraph(
            "<font color='#9CA3AF'>End of guide.  Generated with "
            "<font face='Courier'>docs/generate_guide.py</font>.</font>",
            S_BODY,
        ),
    ]


# ─── Build ──────────────────────────────────────────────────────────
def build():
    doc = BaseDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=MARGIN + 6 * mm,
        title="PWNAudit NetScope — User Guide",
        author="PWNAudit",
    )
    cover_frame = Frame(MARGIN, MARGIN, CONTENT_W, PAGE_H - 2 * MARGIN, id="cover")
    body_frame  = Frame(MARGIN, MARGIN + 6 * mm, CONTENT_W,
                        PAGE_H - 2 * MARGIN - 6 * mm, id="body")
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=cover_frame, onPage=_draw_cover_chrome),
        PageTemplate(id="body",  frames=body_frame,  onPage=_draw_page_chrome),
    ])

    story = []
    story += cover_page()
    story.append(PageBreak())
    # switch to body template after the cover
    story.append(NextPageTemplate("body"))
    story.append(PageBreak())
    story += toc_page()
    story.append(PageBreak())
    story += s1_intro()
    story.append(PageBreak())
    story += s2_install()
    story.append(PageBreak())
    story += s3_main_interface()
    story.append(PageBreak())
    story += s4_interfaces()
    story.append(PageBreak())
    story += s5_wireless()
    story.append(PageBreak())
    story += s6_capture()
    story.append(PageBreak())
    story += s7_rules()
    story += s7_rules_table()
    story += s7_rules_continued()
    story.append(PageBreak())
    story += s8_pentest()
    story.append(PageBreak())
    story += s9_architecture()
    story.append(PageBreak())
    story += s10_faq()
    story.append(PageBreak())
    story += s11_credits()

    doc.build(story)
    size_kb = OUTPUT.stat().st_size / 1024
    print(f"Wrote {OUTPUT} ({size_kb:,.1f} KB)")


# Late import — NextPageTemplate isn't in platypus by default in some
# reportlab versions; pull from the alt path.
try:
    from reportlab.platypus import NextPageTemplate  # type: ignore
except ImportError:
    from reportlab.platypus.doctemplate import NextPageTemplate  # type: ignore


if __name__ == "__main__":
    build()
