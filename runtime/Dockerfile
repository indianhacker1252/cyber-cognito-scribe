FROM mcr.microsoft.com/playwright:v1.48.0-jammy

WORKDIR /app

# Common recon tools available to the shell.run tool
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates dnsutils whois nmap jq git \
 && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm install -g tsx typescript

COPY tsconfig.json ./
COPY src ./src

ENV NODE_ENV=production
CMD ["tsx", "src/index.ts"]
