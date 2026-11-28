# Production Deployment Checklist — Shri R.M. Patil Multi Speciality Hospital 2.0

## 1. Choose a Mumbai Region VPS (Fastest Latency for Chakur & Maharashtra)
- Recommended: Ubuntu 24.04 LTS VPS in **Mumbai (`ap-south-1` / `blr1`)** (2 vCPU, 2–4 GB RAM, SSD) on AWS Lightsail, DigitalOcean, or Hostinger.
- Point your domain's DNS **A record** (`@` and `www`) to the VPS public IPv4 address.

## 2. Clone Repo & Configure Production `.env`
```bash
git clone https://github.com/maheshsomawar/Shri-R.M.-Patil-Multi-Speciality-Hospital-2.0.git hospital
cd hospital
cp .env.production.example .env
nano .env
```
Verify inside `.env`:
- `DEBUG=false`
- `TRUST_PROXY=true` (so Caddy forwards each patient's real IP via `X-Real-IP`)
- `SECURE_COOKIES=true` (enforces HTTPS-only session cookies)
- `HOST=0.0.0.0` (inside Docker) or `HOST=127.0.0.1` (direct Linux host behind Caddy)
- `PUBLIC_BASE_URL=https://shrirmppatilhospital.in` (powers canonical `/sitemap.xml`)
- `ALLOWED_ORIGINS=https://shrirmppatilhospital.in,https://www.shrirmppatilhospital.in` (remove localhost in production)
- Fresh 64-char `SESSION_SECRET` (`python3 -c "import secrets; print(secrets.token_hex(32))"`) and unique strong staff passwords.

## 3. Run with Docker + Persistent Volumes (Never Lose SQLite Data)
```bash
mkdir -p data backups
docker compose up -d --build
```
`docker-compose.yml` pins `HOST=0.0.0.0` for the container and mounts `./data:/app/data` and `./backups:/app/backups` so container updates never erase appointments or invoices.

## 4. Enable Automatic HTTPS with Caddy
```bash
sudo apt update && sudo apt install -y caddy
sudo cp Caddyfile.example /etc/caddy/Caddyfile
sudo nano /etc/caddy/Caddyfile   # Replace domain with your real domain
sudo systemctl reload caddy
```
Caddy automatically obtains and renews free Let's Encrypt SSL certificates, enables Zstd/Gzip compression, caches `/assets/*` as immutable, and enforces `no-store, private` + `X-Robots-Tag: noindex, nofollow` on `/staff*`, `/admin*`, `/patient*`, and `/api/*`.

## 5. Schedule Daily Automated Off-Server Backups
Add a daily 2:00 AM IST cron job (`crontab -e`):
```cron
30 20 * * * cd /path/to/hospital && /usr/bin/python3 backup_db.py >> /var/log/hospital_backup.log 2>&1
```
Sync `/path/to/hospital/backups/` daily to an encrypted private off-server bucket (e.g., AWS S3 Mumbai or Backblaze B2 via `rclone`) and point an uptime monitor at `https://yourdomain.com/api/health`.

## 6. Complete India Go-Live Integrations
1. **Razorpay Live KYC:** Your homepage footer now includes **Privacy Notice**, **Refund & Cancellation Policy**, and **Terms & Conditions** modals required for Razorpay KYC approval. Once approved, set `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, and `RAZORPAY_WEBHOOK_SECRET` in `.env` and register webhook `https://yourdomain.com/api/payments/webhook`.
2. **TRAI DLT SMS Registration:** Register Shri R.M. Patil Multi Speciality Hospital on a TRAI DLT portal and set `SMS_PROVIDER`, `SMS_GATEWAY_API_KEY`, `SMS_DLT_ENTITY_ID`, `SMS_DLT_TEMPLATE_ID`, and `SMS_SENDER_ID` in `.env`.
3. **Staff Recovery SMTP Email:** Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, and `SMTP_PASSWORD` in `.env` so Gmail password-reset OTPs deliver cleanly.
4. **Real Hospital Photo:** Replace `public/assets/hospital-atrium-*.webp` with a real photo of your Chakur hospital building converted to WebP (`480w`, `800w`, `1200w`).
