/**
 * SIEM Sentinel — Log HTTP Server
 * Tails a log file and serves it over HTTP with CORS enabled.
 *
 * Usage:
 *   node log-server.js /var/log/syslog
 *   node log-server.js /var/log/nginx/access.log 8765
 */

const http = require("http");
const fs   = require("fs");
const path = require("path");

const logFile = process.argv[2];
const port    = parseInt(process.argv[3] || "8765", 10);

if (!logFile) {
  console.error("Usage: node log-server.js <log-file-path> [port]");
  console.error("Example: node log-server.js /var/log/syslog 8765");
  process.exit(1);
}

if (!fs.existsSync(logFile)) {
  console.error(`File not found: ${logFile}`);
  process.exit(1);
}

// Ring buffer of last 500 lines
const MAX_LINES = 500;
const buffer    = [];

// Read existing tail of file first
function readTail(filePath, numLines) {
  const CHUNK = 65536;
  const fd    = fs.openSync(filePath, "r");
  const stat  = fs.fstatSync(fd);
  let size    = stat.size;
  let lines   = [];
  let leftover = "";

  while (lines.length < numLines && size > 0) {
    const readSize = Math.min(CHUNK, size);
    size -= readSize;
    const buf = Buffer.alloc(readSize);
    fs.readSync(fd, buf, 0, readSize, size);
    const chunk = buf.toString("utf8") + leftover;
    const parts = chunk.split("\n");
    leftover    = parts.shift();
    lines       = parts.concat(lines);
  }
  fs.closeSync(fd);
  if (leftover) lines.unshift(leftover);
  return lines.filter(Boolean).slice(-numLines);
}

// Seed buffer with existing lines
const existing = readTail(logFile, MAX_LINES);
buffer.push(...existing);
console.log(`📂 Loaded ${existing.length} existing lines from ${logFile}`);

// Watch for new lines
let fileSize = fs.statSync(logFile).size;
fs.watch(logFile, (event) => {
  if (event !== "change") return;
  try {
    const newSize = fs.statSync(logFile).size;
    if (newSize < fileSize) { fileSize = 0; } // log rotated
    const delta = newSize - fileSize;
    if (delta <= 0) return;

    const fd  = fs.openSync(logFile, "r");
    const buf = Buffer.alloc(delta);
    fs.readSync(fd, buf, 0, delta, fileSize);
    fs.closeSync(fd);
    fileSize = newSize;

    const newLines = buf.toString("utf8").split("\n").filter(Boolean);
    buffer.push(...newLines);
    if (buffer.length > MAX_LINES) buffer.splice(0, buffer.length - MAX_LINES);
    if (newLines.length) console.log(`+${newLines.length} new lines`);
  } catch (e) { /* file may be rotating */ }
});

// HTTP server
const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Content-Type", "text/plain; charset=utf-8");

  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
  if (req.method !== "GET")     { res.writeHead(405); res.end(); return; }

  res.writeHead(200);
  res.end(buffer.join("\n"));
});

server.listen(port, "0.0.0.0", () => {
  console.log(`\n✅ Log server running`);
  console.log(`   File  : ${path.resolve(logFile)}`);
  console.log(`   URL   : http://localhost:${port}`);
  console.log(`\n   In the dashboard → Ingest tab → HTTP Polling`);
  console.log(`   Enter : http://localhost:${port}`);
  console.log(`   Set interval to 2s and click Start\n`);
  console.log(`Press Ctrl+C to stop.\n`);
});
