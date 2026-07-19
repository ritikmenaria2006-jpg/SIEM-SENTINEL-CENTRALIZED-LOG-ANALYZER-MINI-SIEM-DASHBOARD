import { useState, useEffect, useRef, useCallback } from "react";

// ── Colour maps ───────────────────────────────────────────────────────────────
const LEVEL_COLOR = {
  DEBUG   : "#4a9eff",
  INFO    : "#22d3a0",
  WARN    : "#f59e0b",
  ERROR   : "#f87171",
  CRITICAL: "#ff3b5c",
  EMERGENCY:"#ff3b5c",
  ALERT   : "#ff3b5c",
  NOTICE  : "#22d3a0",
  trace   : "#4a9eff",
};

const KNOWN_SOURCES = ["firewall","auth","nginx","sshd","kernel","cron","sudo","apache","mysql","postgres","app","system"];
const SOURCE_COLOR  = {
  firewall:"#a78bfa", auth:"#34d399", nginx:"#60a5fa", apache:"#60a5fa",
  sshd:"#f472b6", kernel:"#fb923c", cron:"#a3e635", sudo:"#e879f9",
  mysql:"#f59e0b", postgres:"#38bdf8", app:"#22d3ee", system:"#94a3b8",
};

function colorForSource(src) {
  if (!src) return "#8892a4";
  const k = Object.keys(SOURCE_COLOR).find(s => src.toLowerCase().includes(s));
  return k ? SOURCE_COLOR[k] : "#8892a4";
}
function colorForLevel(lvl) {
  if (!lvl) return "#8892a4";
  const k = Object.keys(LEVEL_COLOR).find(l => lvl.toUpperCase().includes(l.toUpperCase()));
  return k ? LEVEL_COLOR[k] : "#8892a4";
}

// ── Log parsers ───────────────────────────────────────────────────────────────
let _id = 1;
function makeEntry(ts, level, source, host, message, raw) {
  return { id: _id++, ts: ts || new Date().toISOString(), level: (level || "INFO").toUpperCase(),
    source: source || "unknown", host: host || "unknown", message: message || raw || "", raw };
}

// RFC 3164  Apr 12 06:34:56 hostname sshd[1234]: message
// RFC 5424  <PRI>1 2024-04-12T06:34:56Z host app - - msg
// nginx/apache combined log
// plain JSON  { "level":"error", "msg":"...", ... }
// journald  May 12 06:34:56 host sshd[123]: msg
const SYSLOG_SEVERITY = ["EMERGENCY","ALERT","CRITICAL","ERROR","WARN","NOTICE","INFO","DEBUG"];

function parseLine(raw) {
  const line = raw.trim();
  if (!line) return null;

  // ── JSON ──────────────────────────────────────────────────────────────────
  if (line.startsWith("{")) {
    try {
      const o = JSON.parse(line);
      const msg  = o.message || o.msg || o.text || o.log || JSON.stringify(o);
      const lvl  = o.level || o.severity || o.lvl || "INFO";
      const ts   = o.timestamp || o.time || o["@timestamp"] || o.ts || new Date().toISOString();
      const src  = o.source || o.service || o.app || o.logger || "app";
      const host = o.host || o.hostname || o.server || "unknown";
      return makeEntry(ts, lvl, src, host, msg, raw);
    } catch {}
  }

  // ── RFC 5424  <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME ... ────────────────
  const rfc5424 = line.match(/^<(\d+)>\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+(.*)/);
  if (rfc5424) {
    const pri = parseInt(rfc5424[1]);
    const lvl = SYSLOG_SEVERITY[pri & 7];
    return makeEntry(rfc5424[2], lvl, rfc5424[4], rfc5424[3], rfc5424[5], raw);
  }

  // ── RFC 3164 / journald  Mon DD HH:MM:SS host prog[pid]: msg ─────────────
  const rfc3164 = line.match(/^(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+([\w\-\/\.]+)(?:\[\d+\])?:\s*(.*)/);
  if (rfc3164) {
    const src = rfc3164[3].split("/").pop().split(".")[0];
    const msg = rfc3164[4];
    const lvl = /fail|error|crit|emerg|alert/i.test(msg) ? "ERROR"
              : /warn/i.test(msg) ? "WARN"
              : /denied|reject|block|drop|invalid|refused/i.test(msg) ? "WARN"
              : "INFO";
    return makeEntry(new Date().toISOString(), lvl, src, rfc3164[2], msg, raw);
  }

  // ── nginx / apache access log ─────────────────────────────────────────────
  const access = line.match(/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+\d+/);
  if (access) {
    const code = parseInt(access[4]);
    const lvl  = code >= 500 ? "ERROR" : code >= 400 ? "WARN" : "INFO";
    return makeEntry(new Date().toISOString(), lvl, "nginx", access[1], `${access[3]} ${access[4]}`, raw);
  }

  // ── W3C / IIS  date time fields… ─────────────────────────────────────────
  // ── Logfmt   key=value key=value ─────────────────────────────────────────
  if (/\w+=\S+/.test(line)) {
    const kv = {};
    line.replace(/(\w+)=("([^"]+)"|(\S+))/g, (_, k, __, q, u) => { kv[k] = q || u; });
    const msg  = kv.msg || kv.message || kv.event || line;
    const lvl  = kv.level || kv.lvl || kv.severity || "INFO";
    const ts   = kv.ts || kv.time || kv.timestamp || new Date().toISOString();
    const src  = kv.app || kv.service || kv.component || "app";
    const host = kv.host || kv.server || "unknown";
    return makeEntry(ts, lvl, src, host, msg, raw);
  }

  // ── Fallback: generic level detection ─────────────────────────────────────
  const lvl = /critical|emerg/i.test(line) ? "CRITICAL"
            : /\berror\b/i.test(line) ? "ERROR"
            : /\bwarn/i.test(line) ? "WARN"
            : /\bdebug\b/i.test(line) ? "DEBUG"
            : "INFO";
  // try to extract a timestamp
  const tsMatch = line.match(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/);
  return makeEntry(tsMatch ? new Date(tsMatch[0]).toISOString() : new Date().toISOString(),
    lvl, "unknown", "unknown", line, raw);
}

function parseText(text) {
  return text.split("\n").map(parseLine).filter(Boolean);
}

// ── Tiny sparkline ────────────────────────────────────────────────────────────
function Spark({ data, color = "#22d3a0", h = 32, w = 90 }) {
  if (!data.length || data.every(v => v === 0)) return (
    <svg width={w} height={h}><line x1={0} y1={h/2} x2={w} y2={h/2} stroke="#1a2540" strokeWidth={1}/></svg>
  );
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1 || 1)) * w;
    const y = h - (v / max) * h;
    return `${x},${y}`;
  }).join(" ");
  return (
    <svg width={w} height={h} style={{ display:"block" }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5"
        strokeLinejoin="round" strokeLinecap="round" opacity="0.9"/>
      <polyline points={`0,${h} ${pts} ${w},${h}`}
        fill={color} fillOpacity="0.12" stroke="none"/>
    </svg>
  );
}

function Ring({ pct, color, size = 56 }) {
  const r = (size - 8) / 2, circ = 2 * Math.PI * r;
  const dash = circ * Math.min(pct / 100, 1);
  return (
    <div style={{ position:"relative", width:size, height:size }}>
      <svg width={size} height={size} style={{ transform:"rotate(-90deg)" }}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1e2535" strokeWidth="6"/>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color}
          strokeWidth="6" strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round" style={{ transition:"stroke-dasharray .4s" }}/>
      </svg>
      <div style={{ position:"absolute", inset:0, display:"flex", flexDirection:"column",
        alignItems:"center", justifyContent:"center", fontSize:11, fontWeight:700, color }}>
        {pct}%
      </div>
    </div>
  );
}

function HBar({ data, colorMap }) {
  const max = Math.max(...Object.values(data), 1);
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
      {Object.entries(data).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([k,v]) => (
        <div key={k} style={{ display:"flex", alignItems:"center", gap:8, fontSize:11 }}>
          <div style={{ width:64, color:"#8892a4", textAlign:"right", fontFamily:"'JetBrains Mono',monospace",
            fontSize:10, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{k}</div>
          <div style={{ flex:1, height:10, background:"#1a2035", borderRadius:3, overflow:"hidden" }}>
            <div style={{ height:"100%", width:`${(v/max)*100}%`,
              background: colorMap ? (colorMap[k] ?? colorForSource(k)) : "#22d3a0",
              borderRadius:3, transition:"width .4s", opacity:.85 }}/>
          </div>
          <div style={{ width:28, color:"#c0c8d8", fontSize:10, textAlign:"right" }}>{v}</div>
        </div>
      ))}
    </div>
  );
}

function ThreatMeter({ score }) {
  const color = score < 30 ? "#22d3a0" : score < 60 ? "#f59e0b" : score < 80 ? "#f87171" : "#ff3b5c";
  const label = score < 30 ? "LOW" : score < 60 ? "MEDIUM" : score < 80 ? "HIGH" : "CRITICAL";
  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:4 }}>
      <div style={{ fontSize:36, fontWeight:900, color, fontFamily:"'JetBrains Mono',monospace",
        textShadow:`0 0 20px ${color}80`, letterSpacing:-1, transition:"color .4s" }}>
        {score}
      </div>
      <div style={{ fontSize:10, fontWeight:700, letterSpacing:3, color, opacity:.8 }}>{label}</div>
      <div style={{ width:80, height:4, background:"#1a2035", borderRadius:2, overflow:"hidden" }}>
        <div style={{ height:"100%", width:`${score}%`, background:color, borderRadius:2, transition:"width .4s" }}/>
      </div>
    </div>
  );
}

function Badge({ level }) {
  const c = colorForLevel(level);
  return (
    <span style={{ fontSize:9, fontWeight:700, letterSpacing:1.5, padding:"2px 6px",
      borderRadius:3, border:`1px solid ${c}50`, color:c, background:`${c}18`,
      fontFamily:"'JetBrains Mono',monospace", whiteSpace:"nowrap" }}>
      {level}
    </span>
  );
}

// ── Polling source ────────────────────────────────────────────────────────────
function usePolling(url, interval, enabled, onLines) {
  const seenRef = useRef(new Set());
  useEffect(() => {
    if (!enabled || !url) return;
    const go = async () => {
      try {
        const r = await fetch(url);
        const text = await r.text();
        const lines = text.split("\n").filter(l => l.trim() && !seenRef.current.has(l));
        if (lines.length) {
          lines.forEach(l => seenRef.current.add(l));
          onLines(lines);
        }
      } catch (e) { console.warn("Poll error", e); }
    };
    go();
    const t = setInterval(go, interval);
    return () => clearInterval(t);
  }, [url, interval, enabled]);
}

const MAX_LOGS = 2000;
const LEVELS_ORDER = ["CRITICAL","ERROR","WARN","INFO","DEBUG"];

// ── Main App ──────────────────────────────────────────────────────────────────
export default function SIEMDashboard() {
  const [logs,      setLogs     ] = useState([]);
  const [filter,    setFilter   ] = useState({ level:"ALL", source:"ALL", search:"" });
  const [selected,  setSelected ] = useState(null);
  const [rateHist,  setRateHist ] = useState(Array(30).fill(0));
  const [errHist,   setErrHist  ] = useState(Array(30).fill(0));
  const [paused,    setPaused   ] = useState(false);
  const [tab,       setTab      ] = useState("stream"); // stream | ingest
  const [pasteText, setPasteText] = useState("");
  const [fileStatus,setFileStatus] = useState("");
  // polling
  const [pollUrl,   setPollUrl  ] = useState("");
  const [pollMs,    setPollMs   ] = useState(5000);
  const [polling,   setPolling  ] = useState(false);
  // websocket
  const [wsUrl,     setWsUrl    ] = useState("");
  const [wsStatus,  setWsStatus ] = useState("disconnected"); // disconnected|connecting|connected|error
  const wsRef = useRef(null);
  const tickRef = useRef(null);

  const addLogs = useCallback((newEntries) => {
    if (paused) return;
    setLogs(prev => [...newEntries, ...prev].slice(0, MAX_LOGS));
  }, [paused]);

  // histogram tick
  useEffect(() => {
    tickRef.current = setInterval(() => {
      const now = Date.now();
      setRateHist(h => {
        const recent = logs.filter(l => now - new Date(l.ts).getTime() < 3000).length;
        return [...h.slice(1), recent];
      });
      setErrHist(h => {
        const recent = logs.filter(l => now - new Date(l.ts).getTime() < 3000 &&
          (l.level === "CRITICAL" || l.level === "ERROR")).length;
        return [...h.slice(1), recent];
      });
    }, 1500);
    return () => clearInterval(tickRef.current);
  }, [logs]);

  // WebSocket
  const connectWS = () => {
    if (wsRef.current) { wsRef.current.close(); }
    setWsStatus("connecting");
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;
    ws.onopen  = () => setWsStatus("connected");
    ws.onerror = () => setWsStatus("error");
    ws.onclose = () => setWsStatus("disconnected");
    ws.onmessage = (e) => {
      const entry = parseLine(e.data);
      if (entry) addLogs([entry]);
    };
  };
  const disconnectWS = () => {
    wsRef.current?.close();
    setWsStatus("disconnected");
  };
  useEffect(() => () => wsRef.current?.close(), []);

  // Polling
  usePolling(pollUrl, pollMs, polling, (lines) => {
    const entries = lines.map(parseLine).filter(Boolean);
    if (entries.length) addLogs(entries);
  });

  // File drop / upload
  const handleFile = async (file) => {
    setFileStatus(`Reading ${file.name}…`);
    const text = await file.text();
    const entries = parseText(text);
    setLogs(prev => [...entries.reverse(), ...prev].slice(0, MAX_LOGS));
    setFileStatus(`✓ Loaded ${entries.length} events from ${file.name}`);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  };

  const handlePaste = () => {
    const entries = parseText(pasteText);
    if (entries.length) {
      setLogs(prev => [...entries.reverse(), ...prev].slice(0, MAX_LOGS));
      setPasteText("");
      setTab("stream");
    }
  };

  // Derived stats
  const total    = logs.length;
  const critical = logs.filter(l => l.level === "CRITICAL").length;
  const errors   = logs.filter(l => l.level === "ERROR").length;
  const warns    = logs.filter(l => l.level === "WARN").length;

  const levelCounts  = LEVELS_ORDER.reduce((a,l) => ({...a, [l]: logs.filter(x=>x.level===l).length}), {});
  const sourceCounts = logs.reduce((a,l) => { a[l.source]=(a[l.source]||0)+1; return a; }, {});
  const hostCounts   = logs.reduce((a,l) => { a[l.host]  =(a[l.host]  ||0)+1; return a; }, {});

  const threatScore = total === 0 ? 0 : Math.min(100, Math.round(
    (critical*6 + errors*2.5 + warns*0.8) / Math.max(total,1) * 100
  ));

  const filtered = logs.filter(l => {
    if (filter.level  !== "ALL" && l.level  !== filter.level)  return false;
    if (filter.source !== "ALL" && l.source !== filter.source) return false;
    if (filter.search) {
      const q = filter.search.toLowerCase();
      if (!l.message.toLowerCase().includes(q) && !l.host.toLowerCase().includes(q)
        && !l.source.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  const uniqueSources = [...new Set(logs.map(l => l.source))].sort();

  const wsStatusColor = { disconnected:"#4a5568", connecting:"#f59e0b", connected:"#22d3a0", error:"#f87171" };

  return (
    <div style={{ minHeight:"100vh", background:"#080d18", fontFamily:"'Inter',sans-serif",
      color:"#c0c8d8", display:"flex", flexDirection:"column" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap');
        *{box-sizing:border-box;margin:0}
        ::-webkit-scrollbar{width:4px;height:4px}
        ::-webkit-scrollbar-track{background:#0d1425}
        ::-webkit-scrollbar-thumb{background:#2a3550;border-radius:2px}
        .log-row:hover{background:#111c33!important;cursor:pointer}
        .ctrl-btn:hover{opacity:.75}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
        @keyframes slideIn{from{opacity:0;transform:translateY(-5px)}to{opacity:1;transform:translateY(0)}}
        input,select,textarea{font-family:'Inter',sans-serif}
        textarea{resize:vertical}
      `}</style>

      {/* ── Header ── */}
      <header style={{ padding:"10px 20px", borderBottom:"1px solid #1a2540",
        display:"flex", alignItems:"center", justifyContent:"space-between",
        background:"#0a1020", position:"sticky", top:0, zIndex:50 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <div style={{ width:32, height:32, background:"#ff3b5c22", border:"1px solid #ff3b5c50",
            borderRadius:8, display:"flex", alignItems:"center", justifyContent:"center" }}>
            <span style={{ fontSize:16 }}>⚔</span>
          </div>
          <div>
            <div style={{ fontSize:15, fontWeight:700, letterSpacing:.5, color:"#e8eef8" }}>
              SIEM <span style={{ color:"#ff3b5c" }}>SENTINEL</span>
            </div>
            <div style={{ fontSize:9, color:"#4a5568", letterSpacing:2 }}>REAL-TIME LOG ANALYTICS</div>
          </div>
        </div>

        <div style={{ display:"flex", alignItems:"center", gap:20 }}>
          {[
            { label:"EVENTS",   val:total,    color:"#60a5fa" },
            { label:"CRITICAL", val:critical, color:"#ff3b5c" },
            { label:"ERRORS",   val:errors,   color:"#f87171" },
            { label:"WARNINGS", val:warns,    color:"#f59e0b" },
          ].map(s => (
            <div key={s.label} style={{ textAlign:"center" }}>
              <div style={{ fontSize:18, fontWeight:800, color:s.color,
                fontFamily:"'JetBrains Mono',monospace", textShadow:`0 0 12px ${s.color}60` }}>{s.val}</div>
              <div style={{ fontSize:9, color:"#4a5568", letterSpacing:1.5 }}>{s.label}</div>
            </div>
          ))}

          {/* Tab switcher */}
          <div style={{ display:"flex", gap:4 }}>
            {[["stream","📡 Stream"],["ingest","⬆ Ingest"]].map(([t,label]) => (
              <button key={t} onClick={() => setTab(t)} style={{
                background: tab===t ? "#1a2540" : "transparent",
                border:`1px solid ${tab===t?"#2a3a60":"#1a2540"}`,
                borderRadius:6, padding:"5px 12px", fontSize:11, fontWeight:600,
                color: tab===t ? "#e8eef8" : "#4a5568", cursor:"pointer", transition:"all .15s"
              }}>{label}</button>
            ))}
          </div>

          <div style={{ display:"flex", alignItems:"center", gap:8, padding:"6px 14px",
            background: paused ? "#1a2035" : "#0d2818",
            border:`1px solid ${paused?"#2a3550":"#22d3a040"}`,
            borderRadius:6, cursor:"pointer", fontSize:11, fontWeight:600,
            color: paused ? "#4a5568" : "#22d3a0", transition:"all .2s",
          }} onClick={() => setPaused(p => !p)}>
            <span style={{ animation: paused?"none":"pulse 1.5s infinite",
              width:6, height:6, borderRadius:"50%", background:"currentColor", display:"inline-block" }}/>
            {paused ? "PAUSED" : "LIVE"}
          </div>
        </div>
      </header>

      {/* ── Body ── */}
      <div style={{ display:"flex", flex:1, overflow:"hidden", height:"calc(100vh - 57px)" }}>

        {/* ── LEFT SIDEBAR ── */}
        <aside style={{ width:220, borderRight:"1px solid #1a2540", background:"#090e1c",
          overflowY:"auto", display:"flex", flexDirection:"column", flexShrink:0 }}>

          <div style={{ padding:"16px", borderBottom:"1px solid #1a2540" }}>
            <div style={{ fontSize:9, letterSpacing:2, color:"#4a5568", marginBottom:12 }}>THREAT SCORE</div>
            <div style={{ display:"flex", justifyContent:"center" }}>
              <ThreatMeter score={threatScore}/>
            </div>
          </div>

          <div style={{ padding:"14px 16px", borderBottom:"1px solid #1a2540" }}>
            <div style={{ fontSize:9, letterSpacing:2, color:"#4a5568", marginBottom:10 }}>SEVERITY DIST.</div>
            <HBar data={levelCounts} colorMap={LEVEL_COLOR}/>
          </div>

          <div style={{ padding:"14px 16px", borderBottom:"1px solid #1a2540" }}>
            <div style={{ fontSize:9, letterSpacing:2, color:"#4a5568", marginBottom:10 }}>TOP SOURCES</div>
            {Object.keys(sourceCounts).length
              ? <HBar data={sourceCounts}/>
              : <div style={{ fontSize:10, color:"#2a3550" }}>No data yet</div>}
          </div>

          <div style={{ padding:"14px 16px" }}>
            <div style={{ fontSize:9, letterSpacing:2, color:"#4a5568", marginBottom:10 }}>TOP HOSTS</div>
            {Object.entries(hostCounts).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([h,v]) => (
              <div key={h} style={{ display:"flex", justifyContent:"space-between", alignItems:"center",
                padding:"4px 0", borderBottom:"1px solid #111c33", fontSize:11 }}>
                <span style={{ fontFamily:"'JetBrains Mono',monospace", color:"#8892a4", fontSize:10,
                  overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", maxWidth:120 }}>{h}</span>
                <span style={{ color:"#22d3a0", fontWeight:700 }}>{v}</span>
              </div>
            ))}
            {Object.keys(hostCounts).length === 0 &&
              <div style={{ fontSize:10, color:"#2a3550" }}>No data yet</div>}
          </div>
        </aside>

        {/* ── MAIN CONTENT ── */}
        <main style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>

          {tab === "ingest" ? (
            /* ── INGEST PANEL ── */
            <div style={{ flex:1, overflowY:"auto", padding:24, display:"flex", flexDirection:"column", gap:20 }}>
              <div style={{ fontSize:13, fontWeight:600, color:"#e8eef8", letterSpacing:.5 }}>Log Ingestion</div>
              <div style={{ fontSize:11, color:"#4a5568" }}>
                Supported formats: syslog (RFC 3164 / 5424), JSON / NDJSON, logfmt, nginx/apache access logs, journald. Auto-detected.
              </div>

              {/* ── FILE UPLOAD / DROP ── */}
              <div
                onDrop={handleDrop} onDragOver={e=>e.preventDefault()}
                onClick={() => document.getElementById("fileInput").click()}
                style={{ border:"2px dashed #1a2540", borderRadius:10, padding:"28px 20px",
                  textAlign:"center", cursor:"pointer", transition:"border-color .2s",
                  background:"#090e1c" }}
                onMouseEnter={e=>e.currentTarget.style.borderColor="#2a3a60"}
                onMouseLeave={e=>e.currentTarget.style.borderColor="#1a2540"}>
                <div style={{ fontSize:28, marginBottom:8 }}>📂</div>
                <div style={{ fontSize:12, color:"#8892a4" }}>Drop log file here or click to browse</div>
                <div style={{ fontSize:10, color:"#4a5568", marginTop:4 }}>.log .txt .json .ndjson .csv</div>
                {fileStatus && <div style={{ marginTop:10, fontSize:11, color:"#22d3a0" }}>{fileStatus}</div>}
                <input id="fileInput" type="file" accept=".log,.txt,.json,.ndjson,.csv"
                  style={{ display:"none" }} onChange={e => { if(e.target.files[0]) handleFile(e.target.files[0]); }}/>
              </div>

              {/* ── PASTE ── */}
              <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                <div style={{ fontSize:11, fontWeight:600, color:"#8892a4", letterSpacing:1 }}>PASTE LOGS</div>
                <textarea
                  rows={8}
                  value={pasteText}
                  onChange={e => setPasteText(e.target.value)}
                  placeholder={"Paste log lines here…\n\nExamples:\nApr 12 06:34:56 srv-1 sshd[1234]: Failed password for root from 10.0.0.5\n{\"level\":\"error\",\"msg\":\"DB connection failed\",\"host\":\"db-1\"}\nGET /admin HTTP/1.1 403 – 198.51.100.4"}
                  style={{ background:"#0d1425", border:"1px solid #1a2540", borderRadius:6,
                    padding:"10px 12px", fontSize:11, color:"#c0c8d8", outline:"none",
                    fontFamily:"'JetBrains Mono',monospace", lineHeight:1.6 }}/>
                <button onClick={handlePaste} disabled={!pasteText.trim()}
                  style={{ alignSelf:"flex-start", background: pasteText.trim() ? "#1a3a5c" : "#0d1425",
                    border:`1px solid ${pasteText.trim()?"#2a5a8c":"#1a2540"}`,
                    borderRadius:6, padding:"7px 18px", fontSize:11, fontWeight:600,
                    color: pasteText.trim() ? "#60a5fa" : "#2a3550", cursor: pasteText.trim() ? "pointer" : "default" }}>
                  Parse & Ingest
                </button>
              </div>

              {/* ── HTTP POLLING ── */}
              <div style={{ background:"#0a1020", border:"1px solid #1a2540", borderRadius:8, padding:16 }}>
                <div style={{ fontSize:11, fontWeight:600, color:"#8892a4", letterSpacing:1, marginBottom:12 }}>HTTP ENDPOINT POLLING</div>
                <div style={{ display:"flex", gap:8, flexWrap:"wrap", alignItems:"center" }}>
                  <input value={pollUrl} onChange={e=>setPollUrl(e.target.value)}
                    placeholder="https://your-server/logs/stream"
                    style={{ flex:1, minWidth:200, background:"#0d1425", border:"1px solid #1a2540",
                      borderRadius:5, padding:"6px 10px", fontSize:11, color:"#c0c8d8", outline:"none",
                      fontFamily:"'JetBrains Mono',monospace" }}/>
                  <select value={pollMs} onChange={e=>setPollMs(+e.target.value)}
                    style={{ background:"#0d1425", border:"1px solid #1a2540", borderRadius:5,
                      padding:"6px 8px", fontSize:11, color:"#c0c8d8", outline:"none" }}>
                    <option value={2000}>2s</option>
                    <option value={5000}>5s</option>
                    <option value={10000}>10s</option>
                    <option value={30000}>30s</option>
                  </select>
                  <button onClick={() => setPolling(p => !p)} disabled={!pollUrl.trim()}
                    style={{ background: polling ? "#1a3020" : "#0d1425",
                      border:`1px solid ${polling?"#22d3a040":"#1a2540"}`,
                      borderRadius:5, padding:"6px 14px", fontSize:11, fontWeight:600,
                      color: polling ? "#22d3a0" : "#4a5568", cursor: pollUrl.trim() ? "pointer" : "default" }}>
                    {polling ? "⏹ Stop" : "▶ Start"}
                  </button>
                </div>
                <div style={{ fontSize:10, color:"#2a3550", marginTop:8 }}>
                  Fetches plain-text or NDJSON from the endpoint on each interval. New lines only.
                </div>
              </div>

              {/* ── WEBSOCKET ── */}
              <div style={{ background:"#0a1020", border:"1px solid #1a2540", borderRadius:8, padding:16 }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:12 }}>
                  <div style={{ fontSize:11, fontWeight:600, color:"#8892a4", letterSpacing:1 }}>WEBSOCKET STREAM</div>
                  <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                    <div style={{ width:6, height:6, borderRadius:"50%",
                      background: wsStatusColor[wsStatus] ?? "#4a5568",
                      boxShadow: wsStatus==="connected" ? "0 0 6px #22d3a0" : "none",
                      animation: wsStatus==="connecting" ? "pulse 1s infinite" : "none" }}/>
                    <span style={{ fontSize:10, color: wsStatusColor[wsStatus], letterSpacing:1 }}>
                      {wsStatus.toUpperCase()}
                    </span>
                  </div>
                </div>
                <div style={{ display:"flex", gap:8 }}>
                  <input value={wsUrl} onChange={e=>setWsUrl(e.target.value)}
                    placeholder="ws://your-server:9000/logs"
                    style={{ flex:1, background:"#0d1425", border:"1px solid #1a2540",
                      borderRadius:5, padding:"6px 10px", fontSize:11, color:"#c0c8d8", outline:"none",
                      fontFamily:"'JetBrains Mono',monospace" }}/>
                  {wsStatus === "connected"
                    ? <button onClick={disconnectWS} style={{ background:"#1a1020",
                        border:"1px solid #f87171",borderRadius:5,padding:"6px 14px",fontSize:11,
                        fontWeight:600,color:"#f87171",cursor:"pointer" }}>Disconnect</button>
                    : <button onClick={connectWS} disabled={!wsUrl.trim()} style={{
                        background: wsUrl.trim() ? "#0d1e30" : "#0d1425",
                        border:`1px solid ${wsUrl.trim()?"#2a5a8c":"#1a2540"}`,
                        borderRadius:5, padding:"6px 14px", fontSize:11, fontWeight:600,
                        color: wsUrl.trim() ? "#60a5fa" : "#2a3550",
                        cursor: wsUrl.trim() ? "pointer" : "default" }}>Connect</button>
                  }
                </div>
                <div style={{ fontSize:10, color:"#2a3550", marginTop:8 }}>
                  Each WebSocket message is parsed as a log event. Supports JSON and plain-text formats.
                </div>
              </div>

              <button onClick={() => { setLogs([]); setFileStatus(""); }}
                style={{ alignSelf:"flex-start", background:"#1a1525", border:"1px solid #2a1535",
                  borderRadius:6, padding:"7px 18px", fontSize:11, fontWeight:600,
                  color:"#e879f9", cursor:"pointer" }}>
                Clear All Events
              </button>
            </div>

          ) : (
            /* ── STREAM VIEW ── */
            <>
              {/* Charts row */}
              <div style={{ display:"flex", gap:0, borderBottom:"1px solid #1a2540", flexShrink:0 }}>
                {[
                  { label:"EVENT RATE / 3s", data:rateHist, color:"#60a5fa" },
                  { label:"CRITICAL + ERROR / 3s", data:errHist, color:"#ff3b5c" },
                ].map(c => (
                  <div key={c.label} style={{ flex:1, padding:"10px 16px", borderRight:"1px solid #1a2540",
                    display:"flex", alignItems:"center", gap:14 }}>
                    <div>
                      <div style={{ fontSize:9, letterSpacing:2, color:"#4a5568", marginBottom:4 }}>{c.label}</div>
                      <div style={{ fontSize:20, fontWeight:700, color:c.color, fontFamily:"'JetBrains Mono',monospace" }}>
                        {c.data[c.data.length-1]}
                      </div>
                    </div>
                    <div style={{ flex:1, display:"flex", justifyContent:"flex-end" }}>
                      <Spark data={c.data} color={c.color} w={120} h={36}/>
                    </div>
                  </div>
                ))}
                <div style={{ padding:"10px 16px", display:"flex", alignItems:"center", gap:12 }}>
                  {["CRITICAL","ERROR","WARN"].map(l => (
                    <div key={l} style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:4 }}>
                      <Ring pct={Math.round((levelCounts[l]||0)/Math.max(total,1)*100)}
                        color={colorForLevel(l)} size={48}/>
                      <div style={{ fontSize:8, letterSpacing:1.5, color:"#4a5568" }}>{l}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Filter bar */}
              <div style={{ display:"flex", alignItems:"center", gap:8, padding:"8px 16px",
                borderBottom:"1px solid #1a2540", background:"#090e1c", flexShrink:0, flexWrap:"wrap" }}>
                <input placeholder="Search messages, hosts, sources…"
                  value={filter.search}
                  onChange={e => setFilter(f => ({...f, search:e.target.value}))}
                  style={{ flex:1, minWidth:160, background:"#0d1425", border:"1px solid #1a2540",
                    borderRadius:5, padding:"5px 10px", fontSize:11, color:"#c0c8d8", outline:"none",
                    fontFamily:"'JetBrains Mono',monospace" }}/>
                <select value={filter.level} onChange={e => setFilter(f => ({...f, level:e.target.value}))}
                  style={{ background:"#0d1425", border:"1px solid #1a2540", borderRadius:5,
                    padding:"5px 8px", fontSize:11, color:"#c0c8d8", outline:"none", cursor:"pointer" }}>
                  <option value="ALL">All Levels</option>
                  {LEVELS_ORDER.map(l => <option key={l}>{l}</option>)}
                </select>
                <select value={filter.source} onChange={e => setFilter(f => ({...f, source:e.target.value}))}
                  style={{ background:"#0d1425", border:"1px solid #1a2540", borderRadius:5,
                    padding:"5px 8px", fontSize:11, color:"#c0c8d8", outline:"none", cursor:"pointer" }}>
                  <option value="ALL">All Sources</option>
                  {uniqueSources.map(s => <option key={s}>{s}</option>)}
                </select>
                <div style={{ marginLeft:"auto", fontSize:10, color:"#4a5568", fontFamily:"'JetBrains Mono',monospace" }}>
                  {filtered.length} / {total} events
                </div>
                <button onClick={() => { setLogs([]); setSelected(null); }}
                  style={{ background:"#1a1525", border:"1px solid #2a1535", borderRadius:5,
                    padding:"5px 10px", fontSize:10, color:"#e879f9", cursor:"pointer", letterSpacing:1 }}>
                  CLEAR
                </button>
              </div>

              {/* Empty state */}
              {total === 0 && (
                <div style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center",
                  justifyContent:"center", gap:14, color:"#2a3550" }}>
                  <div style={{ fontSize:48 }}>📭</div>
                  <div style={{ fontSize:14, fontWeight:600, color:"#4a5568" }}>No log events yet</div>
                  <div style={{ fontSize:11 }}>Go to <strong style={{ color:"#60a5fa" }}>⬆ Ingest</strong> to load a log file, paste logs, or connect a live source</div>
                </div>
              )}

              {/* Log stream */}
              {total > 0 && (
                <div style={{ flex:1, overflowY:"auto", fontFamily:"'JetBrains Mono',monospace" }}>
                  <table style={{ width:"100%", borderCollapse:"collapse", fontSize:11 }}>
                    <thead>
                      <tr style={{ background:"#090e1c", borderBottom:"1px solid #1a2540",
                        color:"#4a5568", fontSize:9, letterSpacing:1.5, textTransform:"uppercase",
                        position:"sticky", top:0, zIndex:10 }}>
                        {["Timestamp","Level","Source","Host","Message"].map(h => (
                          <th key={h} style={{ padding:"6px 12px", textAlign:"left", fontWeight:600, whiteSpace:"nowrap" }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((log, i) => (
                        <tr key={log.id}
                          className="log-row"
                          onClick={() => setSelected(selected?.id === log.id ? null : log)}
                          style={{
                            background: selected?.id === log.id ? "#111c33" :
                              log.level === "CRITICAL" ? "#1a0812" :
                              log.level === "ERROR"    ? "#170f0f" : "transparent",
                            borderBottom:"1px solid #0d1425",
                            borderLeft: selected?.id === log.id ? "2px solid #22d3a0" :
                              log.level === "CRITICAL" ? "2px solid #ff3b5c" :
                              log.level === "ERROR"    ? "2px solid #f87171" : "2px solid transparent",
                            animation: i < 5 ? "slideIn .25s ease" : "none",
                          }}>
                          <td style={{ padding:"5px 12px", color:"#4a5568", whiteSpace:"nowrap", fontSize:10 }}>
                            {(() => { try { return new Date(log.ts).toLocaleTimeString("en-GB",{hour12:false}); } catch { return log.ts; } })()}
                          </td>
                          <td style={{ padding:"5px 12px", whiteSpace:"nowrap" }}><Badge level={log.level}/></td>
                          <td style={{ padding:"5px 12px", whiteSpace:"nowrap" }}>
                            <span style={{ color: colorForSource(log.source) }}>{log.source}</span>
                          </td>
                          <td style={{ padding:"5px 12px", color:"#6b7a94", whiteSpace:"nowrap" }}>{log.host}</td>
                          <td style={{ padding:"5px 12px", color: log.level==="CRITICAL" ? "#ff3b5c" :
                            log.level==="ERROR" ? "#f87171" : "#8892a4",
                            maxWidth:0, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                            {log.message}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filtered.length === 0 && total > 0 && (
                    <div style={{ padding:40, textAlign:"center", color:"#2a3550", fontSize:12 }}>
                      No events match current filters
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </main>

        {/* ── DETAIL PANEL ── */}
        {selected && (
          <aside style={{ width:280, borderLeft:"1px solid #1a2540", background:"#090e1c",
            overflowY:"auto", padding:16, display:"flex", flexDirection:"column", gap:14, flexShrink:0 }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <div style={{ fontSize:10, letterSpacing:2, color:"#4a5568" }}>EVENT DETAIL</div>
              <span onClick={() => setSelected(null)}
                style={{ cursor:"pointer", color:"#4a5568", fontSize:18, lineHeight:1 }}>×</span>
            </div>

            <div style={{ background:`${colorForLevel(selected.level)}12`,
              border:`1px solid ${colorForLevel(selected.level)}30`,
              borderRadius:8, padding:12 }}>
              <Badge level={selected.level}/>
              <div style={{ marginTop:8, fontSize:11, color:"#c0c8d8", lineHeight:1.6,
                fontFamily:"'JetBrains Mono',monospace", wordBreak:"break-all" }}>
                {selected.message}
              </div>
            </div>

            {[
              { k:"Event ID",  v:`#${selected.id}` },
              { k:"Timestamp", v:(() => { try { return new Date(selected.ts).toLocaleString(); } catch { return selected.ts; } })() },
              { k:"Source",    v:selected.source, color:colorForSource(selected.source) },
              { k:"Host",      v:selected.host },
              { k:"Severity",  v:selected.level,  color:colorForLevel(selected.level) },
            ].map(r => (
              <div key={r.k} style={{ display:"flex", flexDirection:"column", gap:2 }}>
                <div style={{ fontSize:9, letterSpacing:1.5, color:"#4a5568" }}>{r.k}</div>
                <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:11,
                  color:r.color ?? "#c0c8d8", wordBreak:"break-all" }}>{r.v}</div>
              </div>
            ))}

            {selected.raw && selected.raw !== selected.message && (
              <div>
                <div style={{ fontSize:9, letterSpacing:1.5, color:"#4a5568", marginBottom:4 }}>RAW LINE</div>
                <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:10, color:"#4a5568",
                  background:"#0a1020", borderRadius:4, padding:8, wordBreak:"break-all",
                  lineHeight:1.5, maxHeight:120, overflowY:"auto" }}>{selected.raw}</div>
              </div>
            )}

            <div style={{ borderTop:"1px solid #1a2540", paddingTop:12 }}>
              <div style={{ fontSize:9, letterSpacing:2, color:"#4a5568", marginBottom:10 }}>RISK INDICATORS</div>
              {[
                { label:"Brute force pattern",    hit:/fail|invalid user|brute|attempt/i.test(selected.message) },
                { label:"Privilege escalation",   hit:/root|sudo|privilege|escalat/i.test(selected.message) },
                { label:"Lateral movement",       hit:/ssh|tunnel|connect|from \d+\.\d+/i.test(selected.message) },
                { label:"Access denied / blocked",hit:/denied|403|reject|block|drop|forbid/i.test(selected.message) },
                { label:"System resource issue",  hit:/oom|disk|cpu|lock|overflow|quota/i.test(selected.message) },
                { label:"Credential exposure",    hit:/password|token|key|secret|credential/i.test(selected.message) },
              ].map(ind => (
                <div key={ind.label} style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6 }}>
                  <div style={{ width:6, height:6, borderRadius:"50%", flexShrink:0,
                    background:ind.hit ? "#ff3b5c" : "#1a2540",
                    boxShadow:ind.hit ? "0 0 6px #ff3b5c" : "none" }}/>
                  <div style={{ fontSize:10, color:ind.hit ? "#f87171" : "#2a3550" }}>{ind.label}</div>
                </div>
              ))}
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}
