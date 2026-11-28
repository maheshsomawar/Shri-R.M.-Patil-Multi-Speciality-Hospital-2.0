# Shri R.M. Patil Multi Speciality Hospital & Trauma Care — HMS 2.0

Zero-dependency **Python 3.11 + SQLite WAL + Bounded ThreadPool** full-stack Hospital Website and Hospital Management System featuring a fast isolated Patient Homepage (`/`), Check Appointment from Home (`POST /api/appointments/check`), online-only booking with `Idempotency-Key` replay guard, non-sensitive QR code check-in, standalone Patient Portal (`/patient`), role-strict Staff & Doctor Portal (`/staff` with `Ctrl+K` Command Palette + per-user password rotation), Hospital Admin User & Audit Command Center (`/admin`), automated **58-point security audit**, **8 SQLite index checks**, and **100–1,500 concurrent-user load testing**.

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
4. Run query-plan checks, the 58-point security audit, and load tests:
   ```powershell
   python db_optimize.py
   python security_audit.py
   python traffic_sim.py
   python load_test_1500.py
   ```
   *(If you update staff passwords in `.env` after initial seeding, run `python db.py --sync-passwords` to update their scrypt hashes in SQLite. Individual staff users can also change their own password in `/staff`, or the Admin can create users and reset individual passwords in `/admin`.)*
5. Start the server:
   ```powershell
   python server.py
   ```
   * **Public Patient Homepage:** `http://127.0.0.1:8080/` (responsive WebP + fingerprinted immutable `/assets/*`, Check Appointment from Home, zero internal links/logins)
   * **Patient Portal:** `http://127.0.0.1:8080/patient` (standalone registration, sign-in, receipts, Rx, reschedule/cancel, DPDP privacy, self-service password rotation)
   * **Doctor & Staff Portal:** `http://127.0.0.1:8080/staff` (`no-store`, `X-Robots-Tag: noindex, nofollow`, strictly role-scoped workspace per signed-in role + `Ctrl+K` Command Palette)
   * **Hospital Admin Command Center:** `http://127.0.0.1:8080/admin` (strictly Admin-only: analytics, individual staff logins & passwords, audit logs)
   * **Custom 404 Page:** `http://127.0.0.1:8080/test-missing-page`

## Database Schema (Migrations 001–010, `Asia/Kolkata` IST)
- `001_initial_schema`: `users`, `appointments`, `notifications`, `audit_logs`
- `002_departments_and_doctors`: `departments`, `doctors` (verified Reg. Nos., fees, slot durations)
- `003_patients_and_patient_links`: `patients` (`PAT-YYYYMMDD-NNN`), `appointments.patient_code`
- `004_doctor_schedules_and_slots`: `doctor_schedules`, `doctor_holidays`, `appointments.slot_time` + partial unique index `uq_appointments_active_slot`
- `005_payments_qr_and_checkin`: `payments` (`RCP-YYYYMMDD-NNN`), `payment_webhooks`, `appointments.qr_token`, `checked_in_at`, `queue_token`
- `006_clinical_pharmacy_lab_billing`: `prescriptions`, `pharmacy_inventory` (Shiv Medical Stores), `lab_tests`, `invoices` (`INV-YYYYMMDD-NNN`)
- `007_privacy_consent_refunds_billing`: `patient_consents`, `privacy_requests` (`PRV-YYYYMMDD-NNN`), `refunds` (`RFD-YYYYMMDD-NNN`), dedicated `billing` role
- `008_indexes_and_background_jobs`: composite/status indexes + `background_jobs` (idempotent durable job queue)
- `009_recovery_nurse_pharmacy_lab_catalog`: user recovery `email`/`phone` + `password_reset_tokens`, `nurse_notifications`, `pharmacy_bills` (`PHM-...`), `pharmacy_purchases` (`PUR-...`), `lab_test_catalog`
- `010_staff_account_active_flag`: `users.active` flag enabling per-user account activation/deactivation from `/admin`

## 8 Enforced Backend RBAC Roles
`admin`, `doctor`, `receptionist`, `billing`, `nurse`, `pharmacist`, `lab_tech`, `patient`.

## REST API Summary
- **Public & Static:** `GET /`, `GET /patient`, `GET /assets/*`, `GET /api/health`, `GET /api/public/info`, `GET /api/doctors/<username>/slots?date=YYYY-MM-DD`, `GET /api/payments/config`, `GET /robots.txt`, `GET /sitemap.xml`, `POST /api/appointments` (supports `Idempotency-Key`), `POST /api/appointments/check`
- **Auth & Self-Service Recovery:** `POST /api/patients/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`, `POST /api/auth/change-password`, `POST /api/auth/contact-info`, `POST /api/auth/forgot-password`, `POST /api/auth/reset-password`
- **Patient (isolated):** `GET /api/patient/me`, `PATCH /api/patient/me`, `GET /api/patient/appointments`, `GET /api/patient/appointments/<id>`, `POST /api/patient/appointments/<id>/cancel`, `POST /api/patient/appointments/<id>/reschedule`, `GET /api/patient/prescriptions`, `POST /api/patient/consent`, `GET/POST /api/patient/privacy-requests`, `GET /api/receipts/<id>/print`, `GET /api/prescriptions/<id>/print`
- **Payments & QR Check-In:** `POST /api/payments/online/verify`, `POST /api/payments/webhook`, `POST /api/staff/payments/<id>/collect`, `POST /api/staff/checkin/scan`
- **Doctor / Staff / Nurse:** `GET /api/staff/appointments`, `GET /api/staff/appointments/summary`, `PATCH /api/staff/appointments/<id>`, `POST /api/staff/appointments/<id>/notify`, `GET /api/staff/notifications`, `GET/POST /api/staff/holidays`, `POST /api/doctor/prescriptions`, `GET/POST /api/nurse/notifications`
- **Shiv Medical Stores, Lab & Hospital Billing:** `GET /api/pharmacy/inventory`, `POST /api/pharmacy/dispense`, `GET/POST /api/pharmacy/bills`, `GET/POST /api/pharmacy/purchases`, `GET /api/pharmacy/reports`, `GET/POST /api/lab/catalog`, `GET/POST /api/lab/tests`, `PATCH /api/lab/tests/<id>`, `GET/POST /api/billing/invoices`, `POST /api/billing/refunds`
- **Admin & Staff Portals:** `GET /staff`, `GET /admin`, `GET /api/admin/overview`, `GET /api/admin/metrics`, `GET /api/admin/audit`, `GET/POST /api/admin/users`, `POST /api/admin/users/reset-password`, `PATCH /api/admin/users/<username>`

## Reports & Scaling Notes
- See [`SECURITY_AUDIT_REPORT.md`](SECURITY_AUDIT_REPORT.md), [`PERFORMANCE_TEST_REPORT.md`](PERFORMANCE_TEST_REPORT.md), and [`PERFORMANCE_OPTIMIZATION_REPORT.md`](PERFORMANCE_OPTIMIZATION_REPORT.md) for detailed findings and benchmarks (plus `python perf_benchmark.py` for headless Chrome CWV/E2E verification).
- **Local Backups:** `python backup_db.py` creates live WAL backups with `PRAGMA integrity_check` and `0600` permissions (encrypt before off-site cloud storage).
- **High-Traffic Scaling:** `HospitalServer` uses a bounded `ThreadPoolExecutor` (`MAX_WORKERS=64`, `request_queue_size=512`), gzip compression, immutable `/assets/*` ETag caching, and a 30s public catalog cache.
- **Production Checklist:** Set `DEBUG=false`, `SECURE_COOKIES=true`, `TRUST_PROXY=true` only behind trusted loopback Caddy/Nginx (`Caddyfile.example`), a 64-char random `SESSION_SECRET`, strong unique staff passwords, real Razorpay/SMS keys, and exact `ALLOWED_ORIGINS`.
