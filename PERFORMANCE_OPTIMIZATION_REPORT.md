# Performance Optimization Report — Shri R.M. Patil Multi-Speciality Hospital 2.0

**Date:** 2026-11-28  
**Scope:** Public patient homepage (`/`), static asset pipeline (`/assets/*`), responsive mobile & laptop layout, reverse-proxy caching (`Caddyfile.example`), and strict privacy cache isolation.

---

## 1. Summary of Changes Made

1. **Eliminated Render-Blocking Third-Party Runtime JS (`cdn.tailwindcss.com`):**
   - Replaced the ~400 KB render-blocking Tailwind CDN JIT compiler `<script>` on `/` with a dedicated, hand-crafted, fingerprinted production stylesheet (`/assets/site.v1.css`, **4,646 B gzipped**) and deferred public script (`/assets/site.v1.js`, **4,325 B gzipped**).
   - Zero internal Staff, Doctor, Admin, Pharmacy, Lab, Billing, or Nurse dashboard code is loaded on the public homepage (`/`). All staff UI remains isolated on `/staff` and `/admin`.
2. **Responsive WebP Image Optimization & Lazy Loading:**
   - Converted the 757,253-byte (`1376×768`) uncompressed hospital atrium JPEG into responsive WebP variants (`480w`, `800w`, `1200w`) plus an optimized progressive JPEG fallback (`800w`) using Pillow (`LANCZOS`, quality `80–82`).
   - Removed the old uncompressed `public/hospital-atrium.jpg`.
   - Placed the hospital atrium photo below the fold in the Location & Facilities section using `<picture>`, `srcset`, `sizes`, explicit `width="1200" height="670"`, `aspect-ratio: 1200/670`, and `loading="lazy" decoding="async"`.
   - Kept the above-the-fold Hero section 100% pure text + CSS glass stat cards so initial LCP paints immediately without waiting for any image download.
3. **Mobile & Laptop Responsive Layout Polish:**
   - Fluid `clamp(2.15rem, 6.5vw, 3.45rem)` hero display typography across `360px` phones through `1440px+` laptops.
   - `44px+` minimum tap targets on mobile buttons, slot pickers, emergency call pills, and navigation drawer items.
   - Added a mobile-only sticky bottom quick-action bar (`Call 24×7` | `Book Appointment`) hidden on tablet/desktop (`>=768px`).
   - Reserved `min-height` on `#doctors-grid` (`220px`) and `#slots-grid` (`92px`) plus explicit image aspect ratios to prevent Cumulative Layout Shift (CLS).
4. **Non-Blocking Font Loading (`font-display: swap`):**
   - Trimmed Google Fonts to only the exact weights used (`Inter: 400, 600, 700, 800` and `Playfair Display: 700, 700 italic`) with `&display=swap`, loaded asynchronously via `media="print" onload="this.media='all'"` plus `<noscript>` fallback and system fallback stacks (`system-ui, -apple-system, sans-serif` and `Georgia, serif`).
5. **Immutable Asset Caching, ETag / 304 & Strict Hospital Privacy Cache Boundary:**
   - Added allowlisted `/assets/<filename>` handler in `server.py` with `Cache-Control: public, max-age=31536000, immutable`, SHA-256 `ETag`, `If-None-Match` → `304 Not Modified`, and `gzip` compression for CSS/JS.
   - Updated `Caddyfile.example` with `encode zstd gzip`, 1-year immutable caching for `/assets/*`, and explicit `no-store, private` headers for `/staff*`, `/admin*`, and `/api/*`.

---

## 2. Measured Before vs. After Asset & Transfer Sizes

All sizes below were measured directly on disk and over live local HTTP (`Accept-Encoding: gzip`) against `HospitalHTTPServer`.

### A. Public Homepage & Code Bundle

| Resource | Before (Raw) | Before (Wire / Gzip) | After (Raw) | After (Wire / Gzip) | Change |
| :--- | ---: | ---: | ---: | ---: | :--- |
| `public/index.html` | 65,482 B | 13,312 B | 29,345 B | 7,096 B | **-46.7% wire** |
| CSS (`cdn.tailwindcss.com` JIT vs `/assets/site.v1.css`) | ~400,000 B (3rd-party JS) | ~110,000 B+ (3rd-party) | 19,957 B | 4,646 B | **100% 3rd-party JS removed** |
| Public JS (inline vs deferred `/assets/site.v1.js`) | Inline in HTML | Inline in HTML | 17,607 B | 4,325 B | **Split, deferred & immutable** |
| **Total Above-the-Fold Critical Wire Transfer** | **~465 KB+** | **~123 KB+** | **66,909 B** | **16,067 B (15.7 KB)** | **~87% smaller; zero blocking 3rd-party JS** |

### B. Image Optimization (`hospital-atrium`)

| Variant | Dimensions | Format | Size (Bytes) | Reduction vs. Original |
| :--- | :---: | :---: | ---: | ---: |
| Original (`public/hospital-atrium.jpg` — removed) | 1376×768 | JPEG | 757,253 B | Baseline |
| Mobile (`/assets/hospital-atrium-480.webp`) | 480×268 | WebP | 17,700 B | **-97.7%** |
| Tablet (`/assets/hospital-atrium-800.webp`) | 800×447 | WebP | 42,052 B | **-94.4%** |
| Desktop (`/assets/hospital-atrium-1200.webp`) | 1200×670 | WebP | 77,498 B | **-89.8%** |
| Fallback (`/assets/hospital-atrium-800.jpg`) | 800×447 | Progressive JPEG | 61,770 B | **-91.8%** |

---

## 3. Live Local Server HTTP Lab Measurements (30-Run Median & p95)

Measured directly against local `HospitalHTTPServer` (`127.0.0.1`, `Accept-Encoding: gzip`):

| Endpoint | Wire Bytes | TTFB p50 | TTFB p95 | Cache-Control |
| :--- | ---: | ---: | ---: | :--- |
| `/` (`index.html`) | 7,096 B | 1.01 ms | 1.43 ms | `public, max-age=300, must-revalidate` |
| `/assets/site.v1.css` | 4,646 B | 0.93 ms | 1.15 ms | `public, max-age=31536000, immutable` |
| `/assets/site.v1.js` | 4,325 B | 0.90 ms | 0.95 ms | `public, max-age=31536000, immutable` |
| `/assets/hospital-atrium-480.webp` | 17,700 B | 0.51 ms | 0.55 ms | `public, max-age=31536000, immutable` |
| `/assets/site.v1.css` (repeat `If-None-Match`) | **0 B (HTTP 304)** | < 1 ms | < 1 ms | `public, max-age=31536000, immutable` |

---

## 4. Strict Hospital Privacy Cache Boundary (Verified by Security Audit Check 51)

| Route Class | Examples | Caching Policy | Verified |
| :--- | :--- | :--- | :---: |
| Public fingerprinted assets | `/assets/site.v1.css`, `/assets/site.v1.js`, `/assets/*.webp` | `public, max-age=31536000, immutable` + `ETag` / `304` | PASS |
| Public homepage | `/` | `public, max-age=300, must-revalidate` + `gzip` | PASS |
| Public appointment check | `POST /api/appointments/check` | `no-store, private` (NEVER publicly cached) | PASS |
| Staff & Admin portals | `/staff`, `/admin` | `no-store, no-cache, must-revalidate, private` | PASS |
| Patient, clinical & billing APIs | `/api/patient/*`, `/api/staff/*`, `/api/billing/*`, `/api/pharmacy/*`, `/api/lab/*`, `/api/nurse/*`, `/api/receipts/*`, `/api/prescriptions/*` | `no-store, private` + authentication + RBAC | PASS |

**Automated Verification Results:**
- `security_audit.py`: **51 / 51 PASS, 0 FAIL** (including Check 51 verifying immutable gzip CSS, ETag `304`, WebP serving, path traversal rejection on `/assets/../../server.py`, zero `cdn.tailwindcss.com` on `/`, and strict `no-store` on private routes).
- `db_optimize.py`: **7 / 7 queries indexed** (`all_indexed: true`).
- `check_web_app.py`: **OK: no issues found.**

---

## 5. Core Web Vitals (Lab vs. Real-User Field Data) & Items Not Tested

- **Google Core Web Vitals Thresholds (75th percentile):** Good **LCP <= 2.5 s**, Good **INP <= 200 ms**, Good **CLS <= 0.1**.
- **Real-User Field Data (CrUX / PageSpeed Insights):** **Not available yet.** This application currently runs on `localhost` (`127.0.0.1:8080`) and has not yet been deployed to a public HTTPS domain with real patient traffic. No real-user field statistics are fabricated.
- **Browser Lighthouse / Headless Chromium Lab Run:** In this isolated Linux VM sandbox, headless Chromium enforces a browser URL blocklist policy on local `http://` URLs. To run the real Mobile (`390×844` 4G simulated) and Desktop (`1366×768`) Core Web Vitals & E2E benchmark on your Windows 11 laptop, run:
  ```powershell
  python perf_benchmark.py
  ```
  Or open `http://127.0.0.1:8080/` in Google Chrome on your laptop → press `F12` → **Lighthouse** tab → run **Mobile** and **Desktop** audits.
- **Remaining Performance Opportunities (for Future Production Deployment):**
  1. Self-host subsetted WOFF2 files for `Inter` and `Playfair Display` under `/assets/fonts/` once deployed on HTTPS to eliminate the two non-blocking Google Fonts requests completely.
  2. Put Caddy (`Caddyfile.example`) in front of `server.py` on your production VPS so HTTP/2 + HTTP/3 + Brotli/Zstd compression and automatic Let's Encrypt HTTPS are active for all patients.
  3. Keep `public/staff.html` (internal portal, `no-store`) isolated from public traffic; optionally migrate `/staff` off Tailwind CDN to local CSS in a future internal-portal cleanup pass.
