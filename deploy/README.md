# CyberScope — Self-Host on Kali / Linux

This folder is everything you need to run the CyberScope tool worker, a
local Postgres mirror, and a local AI brain (Ollama) on your own machine.

## What you get

| Service     | Port  | Purpose                                                          |
| ----------- | ----- | ---------------------------------------------------------------- |
| `worker`    | 8080  | nuclei / ffuf / sqlmap / playwright / apktool / jadx + sandbox   |
| `postgres`  | 5544  | local mirror DB for findings (Settings → External Database)      |
| `ollama`    | 11434 | local LLM (llama3.1:8b + qwen2.5-coder:7b), OpenAI-compatible    |

Gemini still runs in the cloud and *teaches* the local model — see "AI tutor"
below.

## Option A — One-shot installer (default)

```bash
git clone <this-repo> cyberscope && cd cyberscope/deploy
sudo ./install.sh
```

The script installs Docker if missing, writes a worker token to
`deploy/.worker_token`, runs `docker compose up -d`, and prints the URLs +
token to paste into the app.

## Option B — Ansible (power user, also installs native Kali tools)

```bash
sudo apt install -y ansible
ansible-playbook -i 'localhost,' -c local deploy/ansible/playbook.yml
```

## Plug into the app

Open the deployed CyberScope UI → **Settings**:

1. **External Infrastructure → Docker Worker**
   - Endpoint: `http://<your-kali-ip>:8080`
   - Token: contents of `deploy/.worker_token`
   - Toggle Active.
2. **External Database**
   - Connection string: `postgres://cyberscope:cyberscope@<your-kali-ip>:5544/cyberscope`
   - Toggle Mirror Enabled.
3. **Local AI** (added via External Infra → "Local AI")
   - Base URL: `http://<your-kali-ip>:11434/v1`
   - Model: `llama3.1:8b` (or `qwen2.5-coder:7b` for code reasoning)

The cloud AI fallback chain will now be **Lovable AI → Local Ollama**, so
when cloud credits are exhausted the platform automatically uses your
local brain.

## AI Tutor (Gemini teaches your local model)

Two-mode pipeline:

1. **Distillation** (cheap, persistent). Run it from
   *Settings → AI Tutor → Distill VAPT corpus*. Gemini writes phase-by-phase
   playbooks (recon → fingerprint → fuzz → exploit → chain → report) into the
   `rag_corpus` table. Local Ollama queries that corpus on every decision.
2. **Live tutoring** (only on hard cases). When the local model produces a
   low-confidence triage, the platform sends the prompt to Gemini, captures
   the corrected answer in `ai_tutoring_sessions`, and appends the lesson to
   `rag_corpus` so the local model improves over time.

## Updating

```bash
cd deploy
git pull
sudo WORKER_TOKEN=$(cat .worker_token) docker compose up -d --build
```

## Uninstall

```bash
cd deploy
docker compose down -v
rm .worker_token
```
