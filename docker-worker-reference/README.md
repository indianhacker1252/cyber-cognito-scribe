# CyberScope Docker Worker — Quick Deploy

Builds a small container that exposes nuclei, ffuf, and sqlmap over HTTP for
your CyberScope instance to call. All output is streamed line-by-line back into
your Live Neural Log.

## Local

```bash
cd docker-worker-reference
docker build -t cyberscope-worker .
TOKEN=$(openssl rand -hex 24)
docker run -d -p 8080:8080 -e WORKER_TOKEN=$TOKEN --name cs-worker cyberscope-worker
echo "Token: $TOKEN"
```

## Fly.io

```bash
fly launch --no-deploy --name cyberscope-worker
fly secrets set WORKER_TOKEN=$(openssl rand -hex 24)
fly deploy
fly secrets list  # copy the token
```

## Railway

1. New project → Deploy from repo → point to `docker-worker-reference/`
2. Variables → `WORKER_TOKEN` = `$(openssl rand -hex 24)` (paste a generated value)
3. Networking → expose `8080` publicly
4. Copy the public URL + token

## Plug into CyberScope

Open **Settings → External Infrastructure → Docker Worker**:

- **Endpoint URL**: `https://your-worker-host` (no trailing slash)
- **Auth token**: the `WORKER_TOKEN` you generated
- Toggle **Active**

Test with the **Test Connection** button — it pings `/health` and confirms the
three tools are available.
