# Big Bounty - Security Testing Tool

Autonomous security testing and vulnerability scanner with three modes: basic, advanced, and custom.

## Features

- **Basic Mode**: Non-intrusive scans including SSL check, security headers analysis, and common path discovery
- **Advanced Mode**: Extended scans with API endpoint discovery
- **Custom Mode**: Custom instruction-based testing
- **Real-time Results**: Color-coded severity levels (critical, high, medium, low, info)
- **Modern UI**: Dark theme with gradient accents

## Local Development

```bash
cd /home/workspace/Projects/big-bounty
npm install
npm run dev
```

Visit http://localhost:3000

## Build

```bash
npm run build
```

## Deployment

### Vercel
1. Push to GitHub
2. Import project in Vercel
3. Deploy

### Cloudflare Workers
```bash
cd /home/workspace/Projects/big-bounty
wrangler deploy
```

## API Endpoint

POST `/api/scan`

```json
{
  "target": "example.com",
  "mode": "basic",
  "customInstructions": "optional text for custom mode"
}
```

## Security Checks

- SSL/TLS certificate validation
- Security headers (X-Frame-Options, CSP, HSTS, etc.)
- Common exposed paths (/admin, /.git, /wp-admin, etc.)
- API endpoint discovery
- Information disclosure detection
