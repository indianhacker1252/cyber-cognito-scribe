#!/usr/bin/env python3
"""
CyberScope Docker Worker — minimal HTTP server that runs nuclei / ffuf / sqlmap
and streams stdout line-by-line to the caller (CyberScope edge function).

ENV:
  WORKER_TOKEN  shared bearer token; required on POST /run
  PORT          default 8080

Whitelist enforced: only these binaries may be exec'd.
"""
import os, json, subprocess, shlex
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = {
    "nuclei":  ["nuclei", "-jsonl", "-silent", "-rate-limit", "50"],
    "ffuf":    ["ffuf", "-mc", "200,201,204,301,302,307,401,403,500"],
    "sqlmap":  ["sqlmap", "--batch", "--random-agent", "--level=2", "--risk=1", "--smart"],
}
TOKEN = os.environ.get("WORKER_TOKEN", "changeme")
PORT  = int(os.environ.get("PORT", "8080"))

class H(BaseHTTPRequestHandler):
    def log_message(self, *a, **kw): return
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "tools": list(TOOLS.keys())}).encode()); return
        self.send_response(404); self.end_headers()
    def do_POST(self):
        if self.path != "/run":
            self.send_response(404); self.end_headers(); return
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth.split(" ", 1)[1] != TOKEN:
            self.send_response(401); self.end_headers(); return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self.send_response(400); self.end_headers(); self.wfile.write(b"bad json"); return
        tool = payload.get("tool"); target = payload.get("target")
        if tool not in TOOLS or not target:
            self.send_response(400); self.end_headers(); self.wfile.write(b"bad tool/target"); return
        cmd = list(TOOLS[tool])
        if tool == "nuclei":  cmd += ["-target", target]
        elif tool == "ffuf":  cmd += ["-u", f"{target.rstrip('/')}/FUZZ", "-w", "/opt/sqlmap/data/txt/common-snmp-community-strings.txt"]
        elif tool == "sqlmap":cmd += ["-u", target]
        for a in payload.get("args", []) or []:
            if isinstance(a, str) and len(a) < 256: cmd.append(a)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, text=True)
            for line in iter(proc.stdout.readline, ""):
                chunk = line.rstrip() + "\n"
                self.wfile.write(f"{len(chunk):X}\r\n{chunk}\r\n".encode())
                self.wfile.flush()
            proc.wait(timeout=600)
            self.wfile.write(b"0\r\n\r\n")
        except Exception as e:
            try: self.wfile.write(f"ERROR: {e}\n".encode())
            except: pass

if __name__ == "__main__":
    print(f"cyberscope-worker listening on :{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
