Drop your screenshots here.  The PDF generator looks for these exact
filenames; missing files become "[ Screenshot slot ]" placeholders in
the PDF, so you can see exactly where each one goes.

Capture on Windows with  Win + Shift + S  (region snip → save as PNG).
1080p resolution looks crisp; 1440p or 4K is even better.

Filenames the generator looks for:

  01-download-page.png       — pwnaudit.com/dashboard/netscope download page
  02-main-window.png         — NetScope main window with sidebar
  03-interfaces-list.png     — Interfaces tab with sparklines
  04-wireless-overview.png   — Wireless tab, connected adapter visible
  05-wireless-band-filter.png— Wireless tab with the band filter active
  06-capture-tripane.png     — Live capture: tri-pane view
  07-rules-table.png         — Rules tab with the rules table + alert log
  08-rule-editor.png         — Rule editor dialog open
  09-pentest-overview.png    — Pentest tab with the auth banner
  10-pentest-portscan.png    — Port scan output in the attack log
  11-pentest-log.png         — Attack log with several actions

After you drop the files, regenerate:

  venv\Scripts\python.exe docs\generate_guide.py
