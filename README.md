# Shri R.M. Patil Multi Speciality Hospital & Trauma Care — HMS 2.0

Zero-dependency **Python 3.11 + SQLite WAL + Bounded ThreadPool** full-stack Hospital Website and Hospital Management System with online pre-visit appointment booking, instant confirmation, Pay-at-Hospital & Razorpay Test Mode (including nested webhook payload verification), non-sensitive QR code check-in, DPDP privacy/consent workflows, all 8 RBAC roles, automated 41-point security audit, and 100–1,500 concurrent-user load testing.

## Quick Start (Windows 11 / Linux / macOS)

1. Create your local environment file (never commit `.env` to Git):
   ```powershell
   Copy-Item .env.example .env
   ```
2. Generate strong secrets (`SESSION_SECRET`, unique staff passwords) and update `.env`:
   ```powershell
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
3. Run safe idempotent database migrations (`Asia/Kolkata` timezone):
   ```powershell
   python migrations.py
   ```
4. Run query-plan checks, the 41-point security audit, and load tests:
   ```powershell
   python db_optimize.py
   python security_audit.py
   python traffic_sim.py
   python load_test_1500.py
   ```
   *(If you update staff passwords in `.env` after initial seeding, run `python db.py --sync-passwords` to update their scrypt hashes in SQLite.)*
5. Start the server:
   ```powershell
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

## REST API Summary
- **Public:** `GET /api/health`, `GET /api/public/info`, `GET /api/doctors/<username>/slots?date=YYYY-MM-DD`, `GET /api/payments/config`, `GET /robots.txt`, `GET /sitemap.xml`, `POST /api/appointments`
- **Auth:** `POST /api/patients/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`
- **Patient (isolated):** `GET /api/patient/me`, `PATCH /api/patient/me`, `GET /api/patient/appointments`, `GET /api/patient/appointments/<id>`, `POST /api/patient/appointments/<id>/cancel`, `POST /api/patient/appointments/<id>/reschedule`, `GET /api/patient/prescriptions`, `POST /api/patient/consent`, `GET/POST /api/patient/privacy-requests`, `GET /api/receipts/<id>/print`, `GET /api/prescriptions/<id>/print`
- **Payments & QR Check-In:** `POST /api/payments/online/verify`, `POST /api/payments/webhook`, `POST /api/staff/payments/<id>/collect`, `POST /api/staff/checkin/scan`
- **Doctor / Staff / Clinical:** `GET /api/staff/appointments`, `GET /api/staff/appointments/summary`, `PATCH /api/staff/appointments/<id>`, `POST /api/staff/appointments/<id>/notify`, `GET /api/staff/notifications`, `GET/POST /api/staff/holidays`, `POST /api/doctor/prescriptions`
- **Pharmacy, Lab & Billing:** `GET /api/pharmacy/inventory`, `POST /api/pharmacy/dispense`, `GET/POST /api/lab/tests`, `PATCH /api/lab/tests/<id>`, `GET/POST /api/billing/invoices`, `POST /api/billing/refunds`
- **Admin:** `GET /admin`, `GET /api/admin/overview`, `GET /api/admin/metrics`, `GET /api/admin/audit`

## Reports & Scaling Notes
- See [`SECURITY_AUDIT_REPORT.md`](SECURITY_AUDIT_REPORT.md) and [`PERFORMANCE_TEST_REPORT.md`](PERFORMANCE_TEST_REPORT.md) for detailed findings and benchmarks.
- **Local Backups:** `python backup_db.py` creates live WAL backups with `PRAGMA integrity_check` and `0600` permissions (encrypt before off-site cloud storage).
- **High-Traffic Scaling:** `HospitalServer` uses a bounded `ThreadPoolExecutor` (`MAX_WORKERS=64`, `request_queue_size=512`), gzip compression, and a 30s public catalog cache.
- **Production Checklist:** Set `DEBUG=false`, `SECURE_COOKIES=true`, a 64-char random `SESSION_SECRET`, strong unique staff passwords, real Razorpay/SMS keys, and exact `ALLOWED_ORIGINS` behind TLS (Caddy/Nginx).
