# ============================================================================
# DEMON SMP — Server Control Panel (production image)
# Build:  docker build -t demon-smp-panel .
# Run:    docker run -p 8080:8080 -v panel-data:/data --env-file .env demon-smp-panel
# ============================================================================
FROM node:20-bookworm-slim

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080 \
    DATA_DIR=/data

WORKDIR /app

# Install dependencies first so this layer is cached across source changes.
# `npm ci` uses package-lock.json; fall back to `npm install` if it is absent.
# The native `bcrypt` addon is optional — the panel transparently uses the
# pure-JS bcryptjs when a native build is unavailable.
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --no-audit --no-fund || npm install --omit=dev --no-audit --no-fund

# Application source.
COPY . .

# Persisted state (users, settings, audit, console log, JWT secret).
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
