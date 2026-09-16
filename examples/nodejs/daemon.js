// Daemon mode: poll a directory, scan new/changed files, print hits.
// Usage: node daemon.js [watchDir]
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { OpenEdrScanner } = require('./openedr');

const watchDir = path.resolve(process.argv[2] || path.join(os.homedir(), 'Downloads'));
const POLL_MS = 2000;
const MAX_SIZE = 48 * 1024 * 1024;
const FLAG = new Set(['Malicious', 'Suspicious']);

const scanner = new OpenEdrScanner();
const seen = new Map();          // path -> size:mtimeMs
const verdictCache = new Map();  // sha256 -> verdict
const stats = { scanned: 0, hits: 0, skipped: 0 };
let busy = false;

function walk(dir, out) {
    let entries;
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
        return;
    }
    for (const e of entries) {
        const p = path.join(dir, e.name);
        try {
            if (e.isDirectory()) walk(p, out);
            else if (e.isFile()) out.push(p);
        } catch { /* raced delete */ }
    }
}

function sha256Of(p) {
    const h = crypto.createHash('sha256');
    h.update(fs.readFileSync(p));
    return h.digest('hex');
}

function tick() {
    if (busy) return;
    busy = true;
    try {
        const files = [];
        walk(watchDir, files);
        for (const p of files) {
            let st;
            try {
                st = fs.statSync(p);
            } catch {
                continue;
            }
            if (!st.size || st.size > MAX_SIZE) continue;
            const key = st.size + ':' + st.mtimeMs;
            if (seen.get(p) === key) continue;
            seen.set(p, key);
            let digest;
            try {
                digest = sha256Of(p);
            } catch {
                continue;
            }
            if (verdictCache.has(digest)) {
                stats.skipped++;
                const v = verdictCache.get(digest);
                if (FLAG.has(v)) {
                    stats.hits++;
                    console.log(`[!] ${v} (cached) :: ${p}`);
                }
                continue;
            }
            let report;
            try {
                report = scanner.scanFile(p);
            } catch (e) {
                console.error(`[-] scan failed ${p}: ${e.message}`);
                continue;
            }
            const verdict = (report && report.verdict) || 'Unknown';
            verdictCache.set(digest, verdict);
            stats.scanned++;
            if (FLAG.has(verdict)) {
                stats.hits++;
                const dets = (report.detections || []).slice(0, 3).map((d) => d.name);
                console.log(`[!] ${verdict} :: ${p} :: ${JSON.stringify(dets)}`);
            }
        }
    } finally {
        busy = false;
    }
}

console.log(`[*] Watching ${watchDir} - Ctrl+C to stop`);
tick();
setInterval(tick, POLL_MS);
setInterval(() => console.log(`[...] stats=${JSON.stringify(stats)}`), 15000);
