# WebGuard
Node/Express API + PostgreSQL + multi-page animated frontend (dark/light).

## Run locally
    cp .env.example .env          # set JWT_SECRET (openssl rand -hex 32)
    docker compose --env-file .env up --build
    open http://localhost:3000

## Test
    npm install && npm test

## Deploy
- **Render / Railway / Fly.io**: create a PostgreSQL instance, set `DATABASE_URL`, `JWT_SECRET`, `PGSSL=true`, deploy this repo (uses the Dockerfile). Tables are created on boot.
- **VPS**: `docker compose up -d` behind Caddy/Nginx for HTTPS.

## API
POST /api/auth/register · POST /api/auth/login · GET /api/me · POST /api/scan · GET /api/scans · DELETE /api/scans/:id · GET /api/stats · GET /api/health
Rate limits: 120 req/min global, 15 scans/min, 20 auth attempts per 15 min.
Set `SAFE_BROWSING_KEY` for real malware/phishing lookups.
