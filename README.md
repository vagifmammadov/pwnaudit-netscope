# PWNAudit NetScope

A Wireshark-style live packet analyzer for Windows, themed for PWNAudit. Picks up where Wireshark leaves off in terms of UI: a real welcome page with **live sparklines per interface** (driven by real `psutil` OS counters — not random), then a tri-pane capture view with packet list, protocol tree, and hex dump.

> **One file to ship.** End users download a single `PWNAudit-NetScope.exe`, double-click it, accept the UAC prompt, and start capturing. No batch files, no Python install on the target machine.

---

## Two flows

### A) Producing the installer (one-time, on your dev machine)

1. Install **Python 3.10+** — tick *Add python.exe to PATH*.
2. Install **Inno Setup 6** from <https://jrsoftware.org/isdl.php> (defaults are fine — this is what wraps the `.exe` into a Windows installer).
3. Open `D:\pwnaudit-netscope\` and **double-click `BUILD.bat`**.
4. Wait ~90 seconds. The pipeline runs:
   - generates `assets\pwnaudit.ico` (10 resolutions of the brand mark)
   - PyInstaller bundles Python + PyQt6 + scapy + psutil + your code into `dist\PWNAudit-NetScope.exe`
   - Inno Setup wraps that `.exe` into `dist\PWNAudit-NetScope-Setup.exe`
5. **`dist\PWNAudit-NetScope-Setup.exe`** is the file you upload and link from `pwnaudit.com`.

> If Inno Setup isn't installed, BUILD.bat will still produce the standalone `.exe` and tell you exactly what's missing.

### B) End-user flow

1. User clicks the download link on `pwnaudit.com` → gets `PWNAudit-NetScope-Setup.exe`.
2. Double-click it → Windows UAC prompt.
3. Standard installer wizard: Welcome → License → Install location → Tasks (desktop icon ✓) → Install → Finish.
4. If Npcap isn't on the system, the installer offers to open <https://npcap.com> in the browser.
5. The "Launch PWNAudit NetScope" checkbox on the Finish page is on by default — clicking Finish opens the app on its welcome page.
6. From now on, typing **"pwnaudit"** in Windows Search shows the app and a click launches it.
7. Uninstall through Settings → Apps → PWNAudit NetScope (entry has the branded icon).

---

## What the user sees

### 1. Welcome page

- Title **Capture** with a one-line subtitle.
- Optional **capture filter** (BPF) input — applies to the next interface chosen.
- A scrollable list of every local network interface:
  - 📶 Wi-Fi · 🖧 Ethernet · 🔵 Bluetooth · 🔐 VPN/virtual · 🔁 loopback · 🌐 other
  - Driver description, IPv4 address (or *link down* / *no IPv4*)
  - **Live sparkline** showing packets-per-second over the last ~60 s, updated every 750 ms from `psutil.net_io_counters(pernic=True)` — these are the same counters Task Manager uses, so they reflect actual NIC traffic, not synthetic data.
  - Live **pps counter** turning teal when traffic is flowing.
  - Whole row is a button — click anywhere on it to start capturing.

### 2. Capture page

- Compact toolbar:
  - **← Interfaces** — back to welcome
  - Active interface name + active filter
  - **DISPLAY** filter (debounced substring search across all columns)
  - **■ Stop** / **▶ Resume** / **Clear**
- Packet list (top half) with virtualized rendering, protocol-coloured rows
- Protocol tree (bottom-left): full layer dissection of the selected packet
- Hex dump (bottom-right): raw bytes + ASCII
- Status bar: live packet count and live pps
- Shortcuts: `Ctrl+E` toggle capture · `Ctrl+L` clear · `Ctrl+F` focus filter

---

## Project layout

```
pwnaudit-netscope/
├── BUILD.bat                  # icon → PyInstaller → Inno Setup, in one shot
├── main.py                    # entry; UAC self-elevate; Npcap presence check
├── requirements.txt           # runtime: PyQt6, scapy, psutil
├── assets/
│   ├── make_icon.py           # generates the multi-res .ico from the PWNAudit mark
│   ├── pwnaudit.ico           # generated, 10 resolutions
│   └── pwnaudit-256.png       # generated, for docs / README
├── installer/
│   └── installer.iss          # Inno Setup script (wraps the .exe)
└── netscope/
    ├── app.py                 # MainWindow + WelcomePage→CapturePage navigation
    ├── welcome.py             # Sparkline, TrafficMonitor, InterfaceCard, WelcomePage
    ├── interfaces.py          # psutil + scapy interface enumeration & mapping
    ├── capture.py             # background scapy AsyncSniffer engine
    ├── dissect.py             # packet → summary row + protocol-tree extraction
    ├── model.py               # QAbstractTableModel + display-filter proxy
    └── theme.py               # PWNAudit dark+teal Qt stylesheet
```

---

## How to test it (right now, without rebuilding the .exe)

When iterating on changes, you don't need to rebuild every time. After running `BUILD.bat` once (it leaves a `venv\` behind):

1. Open **PowerShell as Administrator** in `D:\pwnaudit-netscope\`.
2. Run:
   ```powershell
   .\venv\Scripts\python.exe main.py
   ```
3. The welcome page appears immediately. Confirm:
   - Your Wi-Fi / Ethernet / VPN interfaces are listed
   - The sparkline next to the active interface jumps when you load a website
   - Bluetooth shows up but probably doesn't capture (expected — most BT adapters can't)
4. Click any interface → capture page opens, packets stream in.
5. Generate traffic to verify:
   - `https://example.com` in a browser → DNS, TLS, TCP rows
   - `ping 1.1.1.1` in PowerShell → ICMP rows
   - `nslookup github.com` → DNS query/response rows
6. Click any packet → protocol tree (Ethernet → IP → TCP → …) and hex dump update instantly.
7. Type `dns` in the **DISPLAY** filter → only DNS rows visible.
8. Click **← Interfaces** → returns to welcome page; sparklines pick back up.

To test the production build instead, run `BUILD.bat` then double-click `dist\PWNAudit-NetScope.exe`.

---

## Troubleshooting

| Symptom | Likely fix |
|---|---|
| Welcome page is empty | Npcap not installed. Install from https://npcap.com and relaunch. |
| Sparklines stay flat at 0 | psutil cannot read counters → interface is administratively down, or it's a virtual adapter without traffic. Try a different interface. |
| "Capture failed" dialog after picking an interface | Likely Bluetooth or a virtual adapter that doesn't expose libpcap. Pick a different one. Or BPF filter has a typo — clear it and retry. |
| App opens then immediately closes | Run `venv\Scripts\python.exe main.py` from a console (not via the .exe) to see the Python traceback. |
| `.exe` build fails on `scapy` import | Some scapy submodules are imported lazily. `BUILD.bat` already passes `--collect-submodules scapy`; if it still fails, add `--hidden-import` flags for the missing module to the build command. |

---

## Performance choices

- Capture runs on scapy's own background thread; UI never blocks.
- New packets drain into the table model in 100 ms batches — never per-packet.
- Table uses `QAbstractTableModel` virtualization → only visible rows paint.
- Display filter is debounced 250 ms to avoid thrashing while typing.
- Memory bounded at 200 000 packets (oldest dropped FIFO).
- Welcome page polls `psutil` once every 750 ms — costs <1 ms per tick.
- BPF capture filter runs in the kernel before packets reach userspace.

---

## What's still on the roadmap

- Open / save `.pcap` and `.pcapng` files
- Follow TCP / UDP stream
- Selection → export to PCAP
- Field-aware display filters (`tcp.port == 443`, `http.host contains foo`)
- Capture-to-disk rotation for long sessions
- Bundled installer that includes Npcap silently (kills the second download step)
