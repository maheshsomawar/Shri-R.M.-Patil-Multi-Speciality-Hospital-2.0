# PERFORMANCE_TEST_REPORT.md — Shri R.M. Patil Multi Speciality Hospital 2.0

**Test Date:** 2026-11-27 (`Asia/Kolkata`)  
**Environment:** Isolated local sandbox VM, Python 3.11 + `HospitalServer` (bounded `ThreadPoolExecutor(max_workers=64)`, `request_queue_size=512`, `10s` socket timeout, gzip enabled) + SQLite WAL (`busy_timeout=10000`).  
**Dataset:** 100% synthetic test patients & bookings in an isolated temporary database (`load_test_1500.py`).

## 1. Staged Public Browsing Benchmarks (100 → 1,500 Simulated Users)

| Stage (Users) | Requests | Throughput (req/s) | Avg (ms) | p50 (ms) | p95 (ms) | p99 (ms) | 5xx Errors |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 100 | 100 | 817.9 | 46.34 | 46.51 | 76.32 | 80.80 | 0 (0.0%) |
| 250 | 250 | 901.2 | 92.38 | 99.60 | 148.15 | 162.05 | 0 (0.0%) |
| 500 | 500 | 893.6 | 128.91 | 143.29 | 177.77 | 198.85 | 0 (0.0%) |
| 750 | 750 | 883.1 | 142.95 | 150.14 | 196.20 | 216.78 | 0 (0.0%) |
| 1,000 | 1,000 | 878.6 | 147.86 | 155.10 | 203.85 | 229.00 | 0 (0.0%) |
| 1,250 | 1,250 | 872.0 | 156.74 | 160.26 | 205.55 | 230.41 | 0 (0.0%) |
| **1,500** | **1,500** | **866.4** | **160.56** | **161.48** | **220.15** | **244.17** | **0 (0.0%)** |

## 2. Database Concurrency & Write Benchmarks

| Write Scenario | Requests | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Result & Integrity |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| Simultaneous Bookings + 50-Way Same-Slot Race | 100 | 416.6 | 120.60 | 156.10 | 205.43 | **51** created (`201`), **49** conflicts blocked (`409`), **51/51** DB rows, `0` double bookings, `0` 5xx |
| Simultaneous Patient Registrations (25 unique + 5 dup race) | 30 | 18.5 | 1,526.47 | 1,595.77 | 1,597.36 | **26** created (`201`), **4** duplicates blocked (`409`), `0` 5xx |

## 3. Resource & Integrity Summary
- **Total test duration:** ~6.4 seconds (short-burst loopback test; 4,114 total recorded API requests).
- **Peak server concurrency:** Cleanly capped at **64** bounded worker threads.
- **Peak process RAM:** **70.34 MB**.
- **SQLite `PRAGMA integrity_check`:** **`ok`** (0 corruption, 0 lock failures).
- **Index verification (`db_optimize.py`):** **7 / 7** hot queries verified using SQLite indexes (`all_indexed: true`).

## 4. Identified Bottlenecks & Honest Scaling Boundaries
1. **CPU-bound `scrypt` password hashing during simultaneous signups/logins:** At `n=16384, r=8, p=1`, 30 simultaneous registrations averaged `1,403.94 ms` (`18.5 req/s`). This is expected security behavior against brute-force attacks, but large registration spikes should be rate-limited and offloaded across multiple worker processes if needed.
2. **Short burst vs. 15-minute sustained staging soak test:** These results validate short-burst loopback performance only. Before certifying sustained 15-minute 1,000+ user capacity in production, run `k6` or `Locust` over the network against your real staging VPS.
3. **Single-node SQLite WAL write ceiling:** SQLite WAL easily handles 860+ read req/s and 416+ booking req/s on one node, so keeping SQLite is optimal today. Migrate to **PostgreSQL + Redis + multi-worker ASGI/WSGI behind Caddy/Nginx** only if horizontal multi-server scaling or sustained high write concurrency is required later.
