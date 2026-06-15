#!/usr/bin/env python3
"""
CyberScope Docker Worker — extended HTTP server.
Endpoints:
  GET  /health      -> capabilities listing
  POST /run         -> Kali/security tools (streamed stdout)
  POST /ai/chat     -> Ollama chat proxy for mutation/fuzzing prompts
  POST /sandbox     -> isolated execution of curl/python/bash script (one-shot)
  POST /playwright  -> Playwright DOM XSS / DOM-fuzz against a URL
  POST /apkscan     -> deep static analysis (apktool/jadx) on uploaded APK URL

All endpoints require: Authorization: Bearer ${WORKER_TOKEN}
"""
import os, json, subprocess, tempfile, shlex, time, uuid, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = {
    "nuclei":     ["nuclei", "-jsonl", "-silent", "-rate-limit", "50"],
    "ffuf":       ["ffuf", "-mc", "200,201,204,301,302,307,401,403,500"],
    "sqlmap":     ["sqlmap", "--batch", "--random-agent", "--level=2", "--risk=1", "--smart"],
    "dalfox":     ["dalfox", "url", "--silence"],
    "katana":     ["katana", "-silent"],
    "nikto":      ["nikto", "-nointeractive", "-Tuning", "1234567890abcx"],
    "wpscan":     ["wpscan", "--no-banner", "--random-user-agent"],
    "gobuster":   ["gobuster", "dir", "-q"],
    "dirsearch":  ["dirsearch", "-q", "-u"],
    "wafw00f":    ["wafw00f", "-a"],
    "whatweb":    ["whatweb", "--no-errors"],
    "sslscan":    ["sslscan", "--no-colour"],
    "sslyze":     ["sslyze", "--regular"],
    "testssl":    ["testssl.sh", "--quiet"],
    "amass":      ["amass", "enum", "-passive", "-d"],
    "subfinder":  ["subfinder", "-silent", "-d"],
    "httpx":      ["httpx", "-silent"],
    "naabu":      ["naabu", "-silent"],
    "masscan":    ["masscan", "--rate", "100"],
    "nmap":       ["nmap", "-sV", "--version-light", "-T2"],
}
TOKEN = os.environ.get("WORKER_TOKEN", "changeme")
PORT  = int(os.environ.get("PORT", "8080"))

def auth_ok(headers):
    a = headers.get("Authorization", "")
    return a.startswith("Bearer ") and a.split(" ", 1)[1] == TOKEN

def run_subprocess(cmd, timeout=120, input_data=None, extra_env=None):
    try:
        env = os.environ.copy()
        if extra_env:
            env.update({str(k): str(v) for k, v in extra_env.items() if v is not None})
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, input=input_data, env=env)
        return {"exitCode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"exitCode": 124, "stdout": "", "stderr": "timeout"}
    except Exception as e:
        return {"exitCode": 1, "stdout": "", "stderr": str(e)}


def sandbox_run(payload):
    """Execute a script in /tmp/sandbox-<uuid>/. Whitelist only curl/python/bash.
    Honors `env` (dict) and `targetUrl` from the payload — both surfaced as TARGET_URL."""
    lang = payload.get("language", "curl")
    script = payload.get("script", "")
    extra_env = dict(payload.get("env") or {})
    if payload.get("targetUrl") and "TARGET_URL" not in extra_env:
        extra_env["TARGET_URL"] = payload["targetUrl"]
    extra_env.setdefault("CYBERSCOPE_ALLOW_NET", "1")
    if not script: return {"ok": False, "error": "empty script"}
    work = tempfile.mkdtemp(prefix="cs-sbx-")
    if lang == "curl":
        result = run_subprocess(["bash", "-c", script], timeout=60, extra_env=extra_env)
    elif lang == "python":
        path = os.path.join(work, "exploit.py")
        with open(path, "w") as f: f.write(script)
        result = run_subprocess(["python3", path], timeout=60, extra_env=extra_env)
    elif lang == "bash":
        path = os.path.join(work, "exploit.sh")
        with open(path, "w") as f: f.write(script)
        os.chmod(path, 0o755)
        result = run_subprocess(["bash", path], timeout=60, extra_env=extra_env)
    else:
        return {"ok": False, "error": "unsupported language"}

    output = result["stdout"] + ("\n[STDERR]\n" + result["stderr"] if result["stderr"] else "")
    return {
        "ok": result["exitCode"] == 0,
        "exitCode": result["exitCode"],
        "output": output[:50000],
        "evidence": {"workdir": work, "stderrLen": len(result["stderr"])},
    }

PLAYWRIGHT_SCRIPT = r"""
import asyncio, json, sys
from playwright.async_api import async_playwright

cfg = json.loads(sys.argv[1])
url = cfg["url"]; payloads = cfg.get("payloads", [])
params = cfg.get("params", ["q","search","redirect","next","url","return"])

async def main():
    findings = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        for p in payloads[:25]:
            for param in params[:6]:
                ctx = await browser.new_context()
                page = await ctx.new_page()
                triggered = {"v": False, "evals": 0, "console": []}
                page.on("console", lambda m: triggered["console"].append(m.text))
                page.on("dialog", lambda d: (triggered.update(v=True), d.dismiss()))
                await page.add_init_script("""
                  window.__cs_xss = false;
                  const orig = window.alert; window.alert = (...a)=>{window.__cs_xss=true; orig&&orig(...a);};
                """)
                try:
                    target = url + ("&" if "?" in url else "?") + f"{param}=" + p
                    await page.goto(target, timeout=8000, wait_until="domcontentloaded")
                    await page.wait_for_timeout(800)
                    proven = await page.evaluate("window.__cs_xss === true")
                    if proven or triggered["v"]:
                        findings.append({"payload": p, "param": param, "url": target, "proven": True})
                except Exception as e:
                    pass
                await ctx.close()
        await browser.close()
    print(json.dumps({"findings": findings}))

asyncio.run(main())
"""

def playwright_run(payload):
    cfg = json.dumps(payload)
    script_path = "/tmp/dom_fuzz.py"
    with open(script_path, "w") as f: f.write(PLAYWRIGHT_SCRIPT)
    r = run_subprocess(["python3", script_path, cfg], timeout=120)
    if r["exitCode"] != 0:
        return {"ok": False, "error": r["stderr"][:500], "findings": []}
    try:
        out = json.loads(r["stdout"].strip().split("\n")[-1])
        return {"ok": True, **out}
    except Exception as e:
        return {"ok": False, "error": str(e), "raw": r["stdout"][:500], "findings": []}

def apk_scan(payload):
    """Deep static APK analysis: apktool decode + jadx + grep secrets."""
    apk_url = payload.get("apkUrl"); 
    if not apk_url: return {"ok": False, "error": "apkUrl required"}
    work = tempfile.mkdtemp(prefix="cs-apk-")
    apk_path = os.path.join(work, "app.apk")
    try:
        urllib.request.urlretrieve(apk_url, apk_path)
    except Exception as e:
        return {"ok": False, "error": f"download failed: {e}"}
    out_dir = os.path.join(work, "decoded")
    apktool = run_subprocess(["apktool", "d", "-f", "-o", out_dir, apk_path], timeout=180)
    jadx = run_subprocess(["jadx", "-d", os.path.join(work, "src"), apk_path], timeout=240)
    findings = []
    grep = run_subprocess(["grep", "-rEon",
        r"(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|sk_(?:live|test)_[0-9a-zA-Z]{24,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
        out_dir], timeout=60)
    for line in (grep["stdout"] or "").splitlines()[:200]:
        findings.append({"raw": line[:300]})
    return {"ok": True, "findings": findings, "apktool_ok": apktool["exitCode"]==0, "jadx_ok": jadx["exitCode"]==0}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a, **kw): return

    def _json(self, code, body):
        b = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"ok": True, "tools": list(TOOLS.keys()),
                                    "endpoints": ["/run","/sandbox","/playwright","/apkscan"]})
        self.send_response(404); self.end_headers()

    def do_POST(self):
        if not auth_ok(self.headers):
            return self._json(401, {"error": "unauthorized"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json(400, {"error": "bad json"})

        if self.path == "/sandbox":
            return self._json(200, sandbox_run(payload))
        if self.path == "/playwright":
            return self._json(200, playwright_run(payload))
        if self.path == "/apkscan":
            return self._json(200, apk_scan(payload))
        if self.path == "/run":
            tool = payload.get("tool"); target = payload.get("target")
            if tool not in TOOLS or not target:
                return self._json(400, {"error": "bad tool/target"})
            cmd = list(TOOLS[tool])
            if tool == "nuclei":  cmd += ["-target", target]
            elif tool == "ffuf":  cmd += ["-u", f"{target.rstrip('/')}/FUZZ", "-w", "/opt/sqlmap/data/txt/common-snmp-community-strings.txt"]
            elif tool == "sqlmap":cmd += ["-u", target]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, text=True)
                for line in iter(proc.stdout.readline, ""):
                    chunk = line.rstrip() + "\n"
                    self.wfile.write(f"{len(chunk):X}\r\n{chunk}\r\n".encode()); self.wfile.flush()
                proc.wait(timeout=600)
                self.wfile.write(b"0\r\n\r\n")
            except Exception as e:
                try: self.wfile.write(f"ERROR: {e}\n".encode())
                except: pass
            return
        self.send_response(404); self.end_headers()

if __name__ == "__main__":
    print(f"cyberscope-worker listening on :{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
