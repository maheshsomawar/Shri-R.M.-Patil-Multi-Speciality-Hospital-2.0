"""Real Headless Chromium Core Web Vitals & Functional E2E Benchmark.

Measures laboratory LCP, CLS, INP (click interaction latency), TTFB, DOMContentLoaded,
Load time, transfer bytes, horizontal overflow, JS console errors, and end-to-end
patient booking + Check Appointment from Home + /staff load on Mobile (390x844)
and Desktop (1366x768) against a live local HospitalHTTPServer instance.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from typing import Any, Dict

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By

from server import AppConfig, create_server


CWV_OBSERVER_JS = """
window.__cwv = { lcp: 0, cls: 0, inp: 0, shifts: [] };
try {
  new PerformanceObserver((list) => {
    const entries = list.getEntries();
    if (entries.length) {
      window.__cwv.lcp = Math.round(entries[entries.length - 1].startTime * 100) / 100;
    }
  }).observe({ type: 'largest-contentful-paint', buffered: true });
} catch (e) {}
try {
  new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
      if (!entry.hadRecentInput) {
        window.__cwv.cls = Math.round((window.__cwv.cls + entry.value) * 10000) / 10000;
      }
    }
  }).observe({ type: 'layout-shift', buffered: true });
} catch (e) {}
"""


def _make_driver(width: int, height: int, is_mobile: bool) -> webdriver.Chrome:
    opts = Options()
    opts.binary_location = "/usr/bin/chromium"
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-proxy-server")
    opts.add_argument(f"--window-size={width},{height}")
    if is_mobile:
        opts.add_argument(
            "--user-agent=Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
        )
    opts.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    driver = webdriver.Chrome(options=opts)
    driver.set_page_load_timeout(15)
    driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": CWV_OBSERVER_JS})
    driver.execute_cdp_cmd("Network.enable", {})
    driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": ["*cdn.tailwindcss.com*", "*fonts.googleapis.com*", "*fonts.gstatic.com*"]})
    if is_mobile:
        # Simulate typical Indian 4G mobile network (10 Mbps down, 2 Mbps up, 70ms RTT)
        driver.execute_cdp_cmd(
            "Network.emulateNetworkConditions",
            {
                "offline": False,
                "latency": 70,
                "downloadThroughput": 10 * 1024 * 1024 / 8,
                "uploadThroughput": 2 * 1024 * 1024 / 8,
            },
        )
    return driver


def measure_viewport(base_url: str, label: str, width: int, height: int, is_mobile: bool) -> Dict[str, Any]:
    driver = _make_driver(width, height, is_mobile)
    try:
        t0 = time.perf_counter()
        driver.get(base_url + "/")
        # Wait briefly for slots & images to settle
        time.sleep(0.8)
        wall_ms = round((time.perf_counter() - t0) * 1000, 2)

        metrics = driver.execute_script(
            """
            const nav = performance.getEntriesByType('navigation')[0] || {};
            const res = performance.getEntriesByType('resource') || [];
            let localBytes = nav.transferSize || 0;
            let localCount = 1;
            let externalCount = 0;
            for (const r of res) {
              if (r.name.startsWith(location.origin)) {
                localBytes += (r.transferSize || r.encodedBodySize || 0);
                localCount += 1;
              } else {
                externalCount += 1;
              }
            }
            const imgs = Array.from(document.querySelectorAll('img')).map(img => ({
              alt: img.alt,
              complete: img.complete,
              naturalWidth: img.naturalWidth,
              hasWidthAttr: img.hasAttribute('width'),
              hasHeightAttr: img.hasAttribute('height'),
              loading: img.getAttribute('loading') || 'eager'
            }));
            return {
              ttfb_ms: Math.round((nav.responseStart - nav.requestStart) * 100) / 100 || 0,
              dcl_ms: Math.round((nav.domContentLoadedEventEnd - nav.startTime) * 100) / 100 || 0,
              load_ms: Math.round((nav.loadEventEnd - nav.startTime) * 100) / 100 || 0,
              lcp_ms: (window.__cwv && window.__cwv.lcp) || 0,
              cls: (window.__cwv && window.__cwv.cls) || 0,
              local_transfer_bytes: localBytes,
              local_requests: localCount,
              external_requests: externalCount,
              blocking_external_scripts: Array.from(document.querySelectorAll("script[src]")).filter(sc => !sc.async && !sc.defer && /^https?:/.test(sc.src)).length,
              scroll_width: document.documentElement.scrollWidth,
              client_width: document.documentElement.clientWidth,
              horizontal_overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
              images: imgs
            };
            """
        )

        # Measure real interaction latency (INP proxy): click Check Appointment tab & back to Book tab
        inp_ms = driver.execute_script(
            """
            return new Promise((resolve) => {
              const btn = document.getElementById('tab-check-btn');
              if (!btn) { resolve(-1); return; }
              const t0 = performance.now();
              btn.click();
              requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                  const dt = Math.round((performance.now() - t0) * 100) / 100;
                  document.getElementById('tab-book-btn')?.click();
                  resolve(dt);
                });
              });
            });
            """
        )

        # Functional E2E checks (Mobile menu + Booking + Check Appointment from Home)
        mobile_menu_ok = True
        if is_mobile:
            mobile_menu_ok = driver.execute_script(
                """
                const btn = document.getElementById('mobile-menu-btn');
                const menu = document.getElementById('mobile-menu');
                if (!btn || !menu) return false;
                btn.click();
                const opened = !menu.classList.contains('hidden');
                btn.click();
                const closed = menu.classList.contains('hidden');
                return opened && closed;
                """
            )

        # End-to-end booking + status lookup test on desktop
        e2e_booking_ok = None
        e2e_check_ok = None
        staff_load_ok = None
        if not is_mobile:
            driver.find_element(By.ID, "book-first").send_keys("Aarav")
            driver.find_element(By.ID, "book-last").send_keys("Deshmukh")
            driver.find_element(By.ID, "book-mobile").send_keys("9822110099")
            driver.execute_script("document.getElementById('book-submit-btn').click();")
            time.sleep(0.5)
            appt_no = driver.execute_script(
                "const c = document.getElementById('booking-confirm-card');"
                "return (!c || c.classList.contains('hidden')) ? '' : document.getElementById('conf-appt-no').textContent.trim();"
            )
            e2e_booking_ok = appt_no.startswith("APT-")
            if e2e_booking_ok:
                driver.execute_script("document.getElementById('conf-verify-btn').click();")
                time.sleep(0.5)
                res_no = driver.execute_script(
                    "const c = document.getElementById('check-result-card');"
                    "return (!c || c.classList.contains('hidden')) ? '' : document.getElementById('res-appt-no').textContent.trim();"
                )
                e2e_check_ok = (res_no == appt_no)

            driver.get(base_url + "/staff")
            time.sleep(0.4)
            staff_load_ok = driver.execute_script("return !!document.getElementById('portal-login-card');")

        logs = driver.get_log("browser")
        severe_errors = [
            l["message"]
            for l in logs
            if l.get("level") == "SEVERE"
            and "fonts.googleapis.com" not in l.get("message", "")
            and "cdn.tailwindcss.com" not in l.get("message", "")
        ]

        return {
            "viewport": label,
            "size": f"{width}x{height}",
            "wall_ms": wall_ms,
            **metrics,
            "interaction_inp_ms": inp_ms,
            "mobile_menu_ok": mobile_menu_ok,
            "e2e_booking_ok": e2e_booking_ok,
            "e2e_check_ok": e2e_check_ok,
            "staff_load_ok": staff_load_ok,
            "console_severe_errors": severe_errors,
        }
    finally:
        driver.quit()


def run_benchmark() -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rmp_perf_", ignore_cleanup_errors=True) as tmpdir:
        cfg = AppConfig()
        cfg.host = "127.0.0.1"
        cfg.port = 0
        cfg.db_path = os.path.join(tmpdir, "perf.db")
        srv = create_server(cfg)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            base = f"http://127.0.0.1:{port}"
            mobile = measure_viewport(base, "mobile_4g_sim", 390, 844, True)
            desktop = measure_viewport(base, "desktop", 1366, 768, False)
            return {"mobile": mobile, "desktop": desktop}
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    out = run_benchmark()
    print(json.dumps(out, indent=2))
