# Shri R.M. Patil Multi Speciality Hospital & Trauma Care — HMS 2.0

Zero-dependency **Python 3.11 + SQLite WAL + Bounded ThreadPool** full-stack Hospital Website and Hospital Management System with online pre-visit appointment booking, instant confirmation, Pay-at-Hospital & Razorpay Test Mode (including nested webhook payload verification), non-sensitive QR code check-in, DPDP privacy/consent workflows, all 8 RBAC roles, automated 35-point security audit, and 100–1,500 concurrent-user load testing.

## Quick Start (Windows 11 / Linux / macOS)

```powershell
Copy-Item .env.example .env
python migrations.py
python db_optimize.py
python security_audit.py
python traffic_sim.py
python load_test_1500.py
python server.py
```

Open `http://127.0.0.1:8080` (public website + Patient Portal + Staff Portal) and `http://127.0.0.1:8080/admin` (strictly Admin-only).

## Database Schema (Migrations 001–008, `Asia/Kolkata` IST)
- `001_initial_schema`: `users`, `appointments`, `notifications`, `audit_logs`
- `002_departments_and_doctors`: `departments`, `doctors` (verified Reg. Nos., fees, slot durations)
- `003_patients_and_patient_links`: `patients` (`PAT-YYYYMMDD-NNN`), `appointments.patient_code`
- `004_doctor_schedules_and_slots`: `doctor_schedules`, `doctor_holidays`, `appointments.slot_time` + partial unique index `uq_appointments_active_slot`
- `005_payments_qr_and_checkin`: `payments` (`RCP-YYYYMMDD-NNN`), `payment_webhooks`, `appointments.qr_token`, `checked_in_at`, `queue_token`
- `006_clinical_pharmacy_lab_billing`: `prescriptions`, `pharmacy_inventory` (Shiv Medical Stores), `lab_tests`, `invoices` (`INV-YYYYMMDD-NNN`)
- `007_privacy_consent_refunds_billing`: `patient_consents`, `privacy_requests` (`PRV-YYYYMMDD-NNN`), `refunds` (`RFD-YYYYMMDD-NNN`), dedicated `billing` role
- `008_indexes_and_background_jobs`: composite/status indexes + `background_jobs` (idempotent durable job queue)

## 8 Enforced Backend RBAC Roles
`admin`, `doctor`, `receptionist`, `billing`, `nurse`, `pharmacist`, `lab_tech`, `patient`.

## External Credentials Required Before Live Clinical Launch
- `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET` (Test Mode during staging; live keys only after sign-off)
- `SMS_GATEWAY_API_KEY` (MSG91 / Fast2SMS / Twilio — currently operates in safe local dry-run mode when unset)
- SMTP / Email provider credentials (not yet wired to an external mail relay; configure before enabling email verification/reset)

## Backups, Docker & Scaling Notes
- **Local Backups:** `python backup_db.py` creates live WAL backups with `PRAGMA integrity_check` and `0600` permissions (unencrypted locally—encrypt before copying to off-site cloud storage).
- **Docker:** `docker compose up -d` runs as non-root with a read-only root filesystem, `/api/health` check, and persistent `./data` volume.
- **High-Traffic Scaling:** `HospitalServer` uses a bounded `ThreadPoolExecutor` (`MAX_WORKERS=64`, `request_queue_size=512`), gzip compression, and a 30s public-only catalog cache. If sustained simultaneous writes exceed single-node SQLite WAL limits, migrate to PostgreSQL + Redis + multi-worker ASGI/WSGI behind Caddy/Nginx.
