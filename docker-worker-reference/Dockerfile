# CyberScope External Tool Worker — Extended Dockerfile
#
# Now includes:
#   - nuclei, ffuf, sqlmap (existing)
#   - Playwright (Chromium) for DOM XSS fuzzing  -> POST /playwright
#   - apktool + jadx for deep APK analysis        -> POST /apkscan
#   - Sandbox exec endpoint for finding payloads  -> POST /sandbox
#
# DEPLOY:
#   docker build -t cyberscope-worker .
#   docker run -d -p 8080:8080 -e WORKER_TOKEN=$(openssl rand -hex 24) cyberscope-worker
#   # In CyberScope → Settings → External Infrastructure paste:
#   #   endpoint_url = https://your-host:8080
#   #   auth_token   = <WORKER_TOKEN>

FROM golang:1.22-alpine AS gobuild
RUN apk add --no-cache git
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/ffuf/ffuf/v2@latest

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl bash openjdk-17-jre-headless wget unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
 && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# apktool + jadx
RUN curl -L -o /usr/local/bin/apktool https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
 && curl -L -o /opt/apktool.jar https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar \
 && sed -i 's|/usr/local/bin/apktool.jar|/opt/apktool.jar|g' /usr/local/bin/apktool \
 && chmod +x /usr/local/bin/apktool
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip -O /tmp/jadx.zip \
 && unzip -q /tmp/jadx.zip -d /opt/jadx && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
 && rm /tmp/jadx.zip

# Playwright + Chromium
RUN pip install --no-cache-dir playwright==1.49.0 \
 && playwright install --with-deps chromium

COPY --from=gobuild /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=gobuild /go/bin/ffuf   /usr/local/bin/ffuf
RUN nuclei -update-templates -silent || true

WORKDIR /app
COPY worker.py /app/worker.py
ENV WORKER_TOKEN=changeme
EXPOSE 8080
CMD ["python", "/app/worker.py"]
