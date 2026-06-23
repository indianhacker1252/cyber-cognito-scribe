## Why the last run "completed" with nothing tested

I read the latest `scan_logs` and `mythos_runs`. Two distinct bugs are stacked on top of each other.

### Bug 1 — every probe failed silently

Every fuzz line in Neural Log looks like:

```
✓ tested: error (0, 0b, 0ms)
```

`status=0`, `bodyLen=0`, `latencyMs=0` means `fetch()` threw before a byte hit the wire. The emitter is `supabase/functions/mythos-variant-test/index.ts` (`probe()`), which catches every error and returns `{ status: 0, bodyLen: 0, latencyMs: 0 }` **without logging the underlying message**. The target was `https://testaspnet.vulnweb.com/default.aspx` — that host only serves cleartext `http://`, so the TLS handshake throws and every variant test is a no-op. The orchestrator can't see this because the error string is dropped.

### Bug 2 — pipeline stops at `advanced-modules`

`mythos_runs` row for the last run: `status=complete`, `current_phase=advanced-modules`, `completed_at` is **before** the last "Advanced modules done" log. The orchestrator only writes `current_phase='done'` when it completes; something marked it complete early. Two contributing causes in `mythos-orchestrator/index.ts`:

- Line 226 — any phase string that doesn't match a branch falls through to `return { done: true }`. A single typo / unknown `nextPhase` quietly ends the whole run.
- `parsePhase` requires exactly `^iter-(\d+)-(\w+)$`. Any malformed enqueue payload (e.g. extra suffix from a retry) hits the unknown-phase fallthrough and "completes" the run.

So the run never reached `iter-1-chain → variant → debate → kill-chain → patch`. That's why "complete testing was not completed".

---

## Fixes

### F1. Surface real fetch errors (and try the right scheme)

- In `mythos-variant-test/probe()` and `_shared/safeFetch.ts` (used by `advanced-fuzzer`, `matrix-fuzzer`, `vuln-scanner`):
  - On `catch`, record `error.name` + `error.message` (e.g. `"TypeError: error trying to connect"`).
  - Push it into `scan_logs.metadata.error` and into `mythos_variants.test_result.error` instead of dropping it.
  - Add a one-shot scheme fallback: if `https://` fails with a TLS/connect error, retry once on `http://` and tag the response with `scheme_downgraded=true`. Emit a finding `MISSING_HTTPS` when that downgrade succeeds.
- In `scope-expander.ts`: when ingesting a target URL, probe both `https://` and `http://` once and persist the reachable scheme on `scan_assets.scheme`. Every downstream module reads from there.

### F2. Make the orchestrator fail loud instead of silently completing

In `mythos-orchestrator/index.ts`:

- Replace the unknown-phase branch (line 226-227) with:
  ```ts
  await log(`❌ Unknown phase '${phase}' — refusing to complete; marking failed`);
  return { done: false, nextPhase: null, error: `unknown_phase:${phase}` };
  ```
  and update the caller (line 284) so `out.error` writes `status='failed'` + the reason to `thought_log` instead of `complete`.
- Harden `parsePhase` to also accept `iter-N-chain-retryK` and log unknown phase strings to `scan_logs` with `log_type='error'`.
- Add a guard in `scan-job-worker` for `job_type='mythos_step'`: if `payload.nextPhase` is empty or the run is not `running`, drop the job and log it.
- Add a DB index on `scan_jobs(job_type, status, priority, created_at)` so the worker dispatches `mythos_step` ahead of bulk variant_tests (it's currently starved by the variant fan-out).

### F3. Wire the missing phases end-to-end

After `advanced-modules` the chain `iter-1-chain → iter-1-variant → iter-1-debate → kill-chain-synthesis → patch → done` must actually execute. The fix above unblocks it; I'll also add an integration assertion in `e2e-selftest`:

- After triggering a run, poll `mythos_runs` for ≤180s and assert it traverses **all** of: `recon, template-runner, advanced-modules, iter-1-chain, iter-1-debate, kill-chain-synthesis, patch, done`. Missing any of them = test failure with the exact missing phase reported.
- Purge all history  need select  error which is  not working

---

## "Juicy findings" detector plan — what this tool must check

The current pipeline is heavy on injection (XSS/SQLi/SSRF) but light on the **passive/recon-grade** findings that make a report look like XBOW/ProjectDiscovery output. I'll add one new edge function per group and wire them into `advanced-modules`.

### G1. Domain & DNS hygiene — `recon-dns-audit`

- Subdomain takeover candidates: CNAME → unclaimed S3/Heroku/GitHub Pages/Azure/Fastly (fingerprint table).
- Dangling `NS`, dangling `MX`, wildcard A records pointing to parking pages.
- SPF: missing, `+all`, >10 DNS lookups, duplicate records.
- DKIM: weak key (<1024-bit), missing selector.
- DMARC: missing, `p=none`, `rua` pointing at unowned domain.
- CAA: missing or permissive (`issue ";"`).
- DNSSEC: not signed, broken chain.
- Expired/expiring domain (`whois expires_at < 30d`).
- Zone transfer (`AXFR`) allowed.

### G2. TLS & certificate posture — `recon-tls-audit`

- Cert expiring <30d, expired, self-signed, hostname mismatch, weak signature (SHA-1, MD5).
- TLS 1.0/1.1 still accepted, RC4/3DES/EXPORT ciphers, no forward secrecy.
- HSTS missing / no `includeSubDomains` / no `preload`.
- Mixed-content references in HTML/JS.
- OCSP stapling missing.
- Cert SAN leaks internal hostnames (`*.corp`, `internal.`, staging hosts).

### G3. IP, port, ASN & infra exposure — `recon-infra-audit`

- Resolve every asset, group by `/24` and ASN; flag cloud (AWS/GCP/Azure) origin behind WAF when WAF is bypassable (already handled — link findings).
- For each unique IP, probe a fixed safe-port set [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 5601, 5900, 6379, 8080, 8443, 8888, 9000, 9200, 11211, 27017] with a 2 s connect timeout — never authenticate.
- Banner-grab only on 80/443/8080/8443/9200/5601/9000/8888 and run service fingerprints:
  - Open Elasticsearch / Kibana / Grafana / Prometheus / Jenkins / Kubernetes API / Docker daemon (`/v1.40/info`) / etcd / Consul / RabbitMQ mgmt / Redis (`INFO` over HTTP via WebSocket fallback).
  - Open `.git/HEAD`, `.svn/entries`, `.DS_Store`, `.env`, `backup.zip`, `phpinfo.php`, `server-status`.
- Reverse-DNS leakage (PTR exposes `prod-db-01.internal`).

### G4. Protocol / header misconfigurations — `recon-protocol-audit`

- Missing or weak security headers: CSP (missing/`unsafe-inline`/`*`), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP.
- CORS: `Access-Control-Allow-Origin: *` with credentials, reflected-origin trust, null-origin trust.
- Cookies: missing `Secure`/`HttpOnly`/`SameSite`, overly broad `Domain=`, long `Max-Age` for session cookies.
- HTTP smuggling indicators (already in `desync-smuggling-v2` — link to this group).
- HTTP methods enabled: `TRACE`, `TRACK`, `PUT`, `DELETE`, `CONNECT`, `OPTIONS *`.
- HTTP/2 / HTTP/3 misconfig (server advertises `h2c` upgrade upstream, etc).
- Open redirect on common params (`?next=`, `?redirect=`, `?url=`).
- Cache poisoning primitives: unkeyed `X-Forwarded-Host`, `X-Original-URL`, fat GET.

### G5. Publicly exposed sensitive info — `recon-public-leaks`

- Wayback / commoncrawl / GitHub code search for the apex domain → harvest historic URLs, secret-shaped strings, leaked `.env`, S3 URLs.
- `robots.txt`, `sitemap.xml`, `.well-known/security.txt`, `humans.txt`, `crossdomain.xml`, `clientaccesspolicy.xml`.
- Source-map files (`.js.map`) → reconstruct original paths and leaked API endpoints.
- Inline JS regex sweep: `AKIA[0-9A-Z]{16}`, `AIza[0-9A-Za-z_\\-]{35}`, `xox[baprs]-`, `ghp_`, `glpat-`, JWT, RSA/PEM blocks, Stripe `sk_live_`, Slack webhooks, Twilio `SK[0-9a-f]{32}`, Mailgun, SendGrid, internal Slack URLs.
- `package.json` / `composer.json` / `requirements.txt` if served → known-vuln versions (cross-check `exploitdb_index`).
- Public S3/GCS/Azure-blob bucket discovery via subdomain naming (`{name}.s3.amazonaws.com`, `storage.googleapis.com/{name}-prod`) — check `ListBucket` allowed (read-only).
- GitHub & GitLab dorks: `"domain.com" AKIA`, `"domain.com" password`, `"domain.com" filename:.env`.
- Pastebin / Have-I-Been-Pwned breach indicator for the apex domain.

### G6. Auth & session juicy bits — extend `auth-confusion-suite`

- JWT: `alg:none`, weak HS256 secret (rockyou top-1k crack ≤5 s), `kid` path traversal, JWK injection.
- OAuth: open `redirect_uri`, missing `state`, PKCE downgrade.
- SAML: XML signature wrapping (passive detection only).
- WebAuthn / TOTP downgrade paths.
- Default credentials on discovered admin panels (Tomcat, Jenkins, Joomla, WordPress `/wp-login.php`) — single attempt with the documented vendor default only, never brute force.

### G7. Cloud-metadata & SSRF chain enrichment — extend `matrix-fuzzer`

- For every SSRF candidate, try the full metadata family: AWS IMDSv1, GCP, Azure, Alibaba, DigitalOcean, OpenStack — each with the right `Metadata-Flavor`/`X-Aws-Ec2-Metadata-Token` quirks.
- Detect Kubernetes service-account token at `/var/run/secrets/...` via file-read SSRF.

### G8. Reportability + scoring

- Every detector writes to `vulnerability_findings` with:
  - `finding_type` from a fixed enum so the dashboard can group "Domain / DNS / TLS / Infra / Protocol / Public-Leak / Auth / Cloud".
  - `severity` + `cvss_score` from a lookup table (e.g. dangling CNAME = High 8.6, missing HSTS = Low 3.1).
  - A one-paragraph `remediation` and a `poc` curl/dig command.
- Add an `e2e-selftest` assertion: at least one finding from each of G1, G2, G3, G4, G5 against the canary target `testphp.vulnweb.com`.

---

## Order of work

1. F1 — surface fetch errors + scheme fallback + persist `scan_assets.scheme`.
2. F2 — orchestrator fails loud on unknown phase, worker drops orphan jobs, scan_jobs priority index.
3. F3 — `e2e-selftest` phase-traversal assertion (will fail until F1+F2 ship).
4. G1 → G5 detectors (new edge functions, wired into `advanced-modules`).
5. G6 + G7 enrichments to existing functions.
6. G8 grouping + scoring + final E2E assertion.

I'll implement F1+F2+F3 and G1-G8 in single implementation by checking every code and wiring.