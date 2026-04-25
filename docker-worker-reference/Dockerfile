# CyberScope External Tool Worker — Reference Dockerfile
#
# Builds a single container that runs nuclei, ffuf, and sqlmap, exposes a
# tiny HTTP server on :8080 that the Lovable edge function `docker-worker-dispatch`
# calls. Output of each tool is streamed line-by-line back to the caller so
# the Live Neural Log shows real tool output in real time.
#
# DEPLOY:
#   docker build -t cyberscope-worker .
#   docker run -d -p 8080:8080 -e WORKER_TOKEN=$(openssl rand -hex 24) cyberscope-worker
#   # Then in CyberScope → Settings → External Infrastructure paste:
#   #   endpoint_url = https://your-host:8080
#   #   auth_token   = <the WORKER_TOKEN you generated>
#
# PROTOCOL:
#   POST /run     Authorization: Bearer <token>
#                 { "tool": "nuclei"|"ffuf"|"sqlmap", "target": "...", "args": [...] }
#                 -> chunked text/plain stream of stdout lines
#   GET  /health  -> {"ok":true,"tools":["nuclei","ffuf","sqlmap"]}

FROM golang:1.22-alpine AS gobuild
RUN apk add --no-cache git
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/ffuf/ffuf/v2@latest

FROM python:3.12-alpine
RUN apk add --no-cache git curl bash
# sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
 && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap
COPY --from=gobuild /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=gobuild /go/bin/ffuf   /usr/local/bin/ffuf
RUN nuclei -update-templates -silent || true

WORKDIR /app
COPY worker.py /app/worker.py
ENV WORKER_TOKEN=changeme
EXPOSE 8080
CMD ["python", "/app/worker.py"]
