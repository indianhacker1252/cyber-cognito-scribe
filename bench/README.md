# CyberScope Benchmark Harness

Continuous eval of the agent against known-vuln targets. Start these locally
and add them as targets in the app; `bench/run.ts` scores each session by
comparing agent findings against the expected finding list per lab.

## Bring up labs
```bash
docker compose -f bench/compose.labs.yml up -d
```

| Lab      | URL                       | Expected classes |
|----------|---------------------------|------------------|
| Juice Shop | http://localhost:3000   | XSS, SQLi, IDOR, JWT, SSRF |
| DVWA       | http://localhost:8080   | XSS, SQLi, CmdInj, CSRF, Upload |
| WebGoat    | http://localhost:8888   | XXE, SSRF, JWT, PathTrav |

## Score
```bash
tsx bench/run.ts
```
Reads `agent_sessions` completed in the last 24h against `bench/expected.json`
and prints precision/recall per lab plus a delta vs. the previous run stored
in `bench/history.json`.
