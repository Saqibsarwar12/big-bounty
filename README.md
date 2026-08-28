# Big Bounty v2 — real-evidence security scanner

Live: https://big-bounty.vercel.app

Every finding is backed by a live HTTP / DNS / RDAP / NVD request with raw evidence included. No simulated results.

## Modes
- **basic** — recon (DoH A/MX/NS/TXT/SPF/DMARC), crt.sh subdomains, RDAP IP network info, soft-404-aware directory busting (60 paths), security headers, CORS origin-reflection probe, tech fingerprinting (100+ signatures), secret-in-HTML scan (Google/Slack/Heroku/AWS keys, JWTs, private keys)
- **advanced** — everything above + full subdomain brute (100 names), HTTP port check, XSS reflection probes (canary → 8 payloads), SQLi error-based probes (MySQL/Postgres/MSSQL/SQLite/Oracle signatures), open-redirect probes (20 params × 4 payloads), NVD CVE matching (top 25 products)
- **custom** — advanced + your own paths parsed from the instructions box

## API
```
POST /api/scan   {"target": "https://example.com", "mode": "basic|advanced|custom", "custom": "optional instructions"}
```

## Deploy
```
bash deploy.sh   # vercel CLI, production
```
