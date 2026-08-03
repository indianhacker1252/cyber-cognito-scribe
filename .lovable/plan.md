# Local Agent Stack for VAPT — Plan

## 1. Which local agents to bundle

Group by role. Each is open-source, scriptable, and safe to auto-install on Debian/Ubuntu/Kali.

### A. Reasoning / LLM brain (local, offline-capable)
- **Ollama** (already partially wired) — runtime for local models.
  - Models to pull: `qwen2.5-coder:7b` (tool-use + code), `llama3.1:8b` (general reasoning), `deepseek-r1:7b` (chain-of-thought planning), `nomic-embed-text` (embeddings for RAG over recon output).
- **Optional heavy**: `qwen2.5:32b` for boxes with ≥24GB VRAM — gated behind a prompt.

### B. Long-lived operator agent (the XBOW-style loop)
- **Our `runtime/` container** (Node + Playwright + AI SDK) — this IS the agent. Installer should:
  - Build the Docker image
  - Register a systemd unit `cyberscope-agent.service` so it survives reboots
  - Auto-scale replicas based on CPU cores (`nproc / 2`, min 1, max 8)

### C. Recon / attack tooling the agent shells out to
Kali-grade CLIs, all apt- or go-installable:
- Recon: `subfinder`, `amass`, `assetfinder`, `httpx`, `dnsx`, `naabu`, `katana`, `waybackurls`, `gau`
- Vuln: `nuclei` (+ templates), `nikto`, `wpscan`, `sslscan`, `testssl.sh`
- Fuzzing: `ffuf`, `feroxbuster`, `dirsearch`, `arjun`, `paramspider`
- Exploit: `sqlmap`, `dalfox` (XSS), `commix` (cmdi), `tplmap` (SSTI), `NoSQLMap`
- Chain / infra: `nmap`, `masscan`, `whatweb`, `wafw00f`, `gowitness` (screenshots)
- OOB: self-hosted **interactsh-server** (Docker) so SSRF/RCE callbacks land on the user's own box, not a shared service

### D. Browser + headless
- Playwright Chromium (already in runtime image)
- **CDP proxy** via `mitmproxy` container — lets the agent intercept/replay requests (the "Repeater/Intruder" gap you called out)

### E. Data plane
- Local **Postgres 16** (already in `deploy/docker-compose.yml`) as a mirror/cache for offline runs
- **Redis** for the loop-guard + idempotency keys (currently done in Postgres — Redis makes it 20× faster)
- **MinIO** for evidence blobs (screenshots, HAR files, PoC payloads)

## 2. Installer changes (`scripts/linux-auto-install.sh`)

Add these prompted steps in order (each `ask` gated):

```text
[?] Install Ollama and pull recommended models?           (Y/n)
[?] Install ProjectDiscovery suite (subfinder/httpx/…)?   (Y/n)
[?] Install exploitation CLIs (sqlmap/dalfox/commix/…)?   (Y/n)
[?] Install nuclei templates + custom CyberScope pack?    (Y/n)
[?] Start self-hosted interactsh-server for OOB?          (Y/n)
[?] Start mitmproxy sidecar for request interception?     (Y/n)
[?] Register cyberscope-agent as systemd (auto-boot)?     (Y/n)
[?] Auto-scale agent replicas to $(nproc)/2 workers?      (Y/n)
```

Each maps to one shell function (`install_ollama`, `install_pd_suite`, `install_exploit_clis`, `install_nuclei`, `start_interactsh`, `start_mitm`, `register_systemd`, `scale_replicas`). Everything writes into `/opt/cyberscope-agent/` and logs to `journalctl -u cyberscope-agent`.

Add a final **`doctor`** step: runs `cyberscope-agent --selftest` which pings Supabase, Ollama, interactsh, and Playwright, then prints a green/red table.

## 3. How the agent uses them

Extend `runtime/src/tools/index.ts` with:
- `recon.subfinder` / `recon.httpx` / `recon.katana`
- `vuln.nuclei` (templates + severity filter)
- `exploit.sqlmap` / `exploit.dalfox` (only when `target_is_exploit_authorized`)
- `oob.register` → returns an interactsh URL for the current step
- `proxy.replay` → mitmproxy scripting API for tampered replays

Add allowlist entries for each in `SHELL_ALLOWLIST`. All results stream into `agent_events` so BrainPanel shows them live.

## 4. Honest answer: is this ready to beat XBOW / Mythos?

**No, not yet.** Where we stand:

| Capability                          | XBOW / Mythos | CyberScope today |
|-------------------------------------|:-------------:|:----------------:|
| Long-lived agent w/ browser + shell | ✅            | ✅ (runtime built, needs field hours) |
| Deterministic proof oracles         | ✅            | ⚠️ partial (`proof-oracles.ts` exists, few classes wired) |
| Multi-step exploit chains executed  | ✅            | ⚠️ runtime present, chains rarely fire end-to-end |
| World-model persistence             | ✅            | ✅ (`target_world_model`) |
| Adaptive mutator (bandit)           | ✅            | ✅ (`ai-mutator` UCB1) |
| OOB infra owned by operator         | ✅            | ❌ (planned above) |
| Request interception / replay       | ✅            | ❌ (mitmproxy planned) |
| Local model fallback                | partial       | ✅ (Ollama) |
| Trained on 100k+ real bounties      | ✅            | ❌ (no training data pipeline) |
| Continuous benchmark harness        | ✅            | ❌ |

**Gaps that matter most to close first (in order):**
1. Self-hosted **interactsh** — without OOB, SSRF/blind-RCE/blind-SQLi are guesswork.
2. **mitmproxy** replay tool — required for real Intruder/Repeater-style tampering.
3. Wire **nuclei + PD suite** into the runtime agent as first-class tools (not shell probes).
4. **Benchmark harness**: 10 known-vuln targets (Juice Shop, DVWA, WebGoat, HTB retired, PortSwigger labs) scored on every deploy — this is what tells us if we're actually improving.
5. **Evidence-based scoring** — reject findings without oracle proof at DB level (trigger exists, tighten thresholds).

Realistic call: after this plan lands + 2–3 weeks of benchmark-driven iteration, we're competitive on **web app OWASP Top 10** for known-vuln targets. Matching XBOW/Mythos on novel real-world targets needs the training-data + eval loop, which is a quarter of work, not a week.

## Deliverables of this plan (one implementation pass)

1. Extend `scripts/linux-auto-install.sh` with the 8 new prompted steps + `doctor` selftest.
2. Add `deploy/compose.tools.yml` for interactsh + mitmproxy + redis + minio.
3. Add 5 new tools to `runtime/src/tools/index.ts` (subfinder, httpx, nuclei, oob, replay) with allowlist.
4. Add `runtime/src/selftest.ts` invoked by `--selftest`.
5. Update `README.md` with the new one-liner: `curl -fsSL … | bash` → guided install.
6. Ship a `bench/` folder with 3 seed targets (Juice Shop + DVWA + WebGoat via Docker) and a `bench/run.ts` that scores agent runs.

Approve and I'll execute all 6 in one pass.
