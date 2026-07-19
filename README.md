# ⚔ SIEM Sentinel — Local Setup Guide

A real-time log analyzer and mini-SIEM dashboard that runs entirely in your browser.

---

## Requirements

- **Node.js** v16 or higher → https://nodejs.org
- **npm** (comes with Node.js)

Check you have them:
```bash
node --version
npm --version
```

---

## Install & Run

```bash
# 1. Enter the project folder
cd siem-sentinel

# 2. Install dependencies (first time only, takes ~1 min)
npm install

# 3. Start the dashboard
npm start
```

Your browser will open automatically at **http://localhost:3000**

---

## Feeding Real Logs

### Option A — Paste logs (easiest)
1. Click **⬆ Ingest** tab in the dashboard
2. On your terminal run:
   ```bash
   # Linux
   tail -n 200 /var/log/syslog

   # macOS
   log show --last 10m --style syslog

   # Windows PowerShell
   Get-EventLog -LogName System -Newest 100 | Format-List
   ```
3. Copy the output, paste into the "PASTE LOGS" box, click **Parse & Ingest**

### Option B — Upload a log file
Drag and drop any `.log` / `.txt` / `.json` file onto the upload area.

Common log file locations:
| System | Path |
|--------|------|
| Linux syslog | `/var/log/syslog` |
| Linux auth | `/var/log/auth.log` |
| nginx | `/var/log/nginx/access.log` |
| Apache | `/var/log/apache2/access.log` |
| macOS | `/var/log/system.log` |

### Option C — Live HTTP stream (real-time)
Run the included log server in a separate terminal:

```bash
# Stream your syslog over HTTP on port 8765
node log-server.js /var/log/syslog

# Or stream nginx access logs
node log-server.js /var/log/nginx/access.log
```

Then in the Ingest tab enter:
```
http://localhost:8765
```
Set interval to **2s** and click **Start**.

### Option D — WebSocket (true real-time push)
Install `websocat` and run:

```bash
# Linux x86_64
wget -O websocat https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl
chmod +x websocat
tail -f /var/log/syslog | ./websocat -s 9000
```

In the Ingest tab enter `ws://localhost:9000` and click **Connect**.

---

## Supported Log Formats

The parser auto-detects all of these — no configuration needed:

| Format | Example |
|--------|---------|
| Syslog RFC 3164 | `Apr 12 06:34:56 srv sshd[123]: Failed password` |
| Syslog RFC 5424 | `<34>1 2024-04-12T06:34:56Z host app - - msg` |
| JSON / NDJSON | `{"level":"error","msg":"DB down","host":"db-1"}` |
| logfmt | `level=error msg="DB down" host=db-1` |
| nginx access log | `192.168.1.1 - - [12/Apr/2024] "GET / HTTP/1.1" 200 612` |
| Apache access log | Same as nginx |
| journald | `May 12 06:34:56 host sshd[123]: msg` |
| Plain text | Keyword-based severity detection |

---

## Build for Production

```bash
npm run build
```
Produces a static `build/` folder you can serve with any web server.

---

## Project Structure

```
siem-sentinel/
├── public/
│   └── index.html
├── src/
│   ├── index.js       ← React entry point
│   └── App.jsx        ← Main dashboard (all logic here)
├── log-server.js      ← Optional: HTTP log server
├── package.json
└── README.md
```
