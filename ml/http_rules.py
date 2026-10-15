import time
import re
from collections import defaultdict, deque

LOGIN_WINDOW = 30          # ثواني
LOGIN_MAX_FAILS = 5        # محاولات فاشلة قبل ما يتبقى alert

SCAN_WINDOW = 20
SCAN_MAX_HITS = 8

SQLI_PATTERNS = [
    r"union\s+select",
    r"or\s+1\s*=\s*1",
    r"'\s*or\s*'",
    r"--",
    r"<script",
    r"drop\s+table",
]
SCAN_PATHS = ["admin", "wp-admin", ".env", "backup", "phpmyadmin",
              "config", ".git", "server-status"]

SQLI_RE = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)


class HttpRuleLayer:
    def __init__(self):
        self.login_fails = defaultdict(deque)   # ip -> timestamps
        self.scan_hits = defaultdict(deque)      # ip -> timestamps

    def check_login_fail(self, ip, path, status, now=None):
        now = now or time.time()
        if "login" not in (path or "").lower():
            return None
        if status not in (401, 403, 422):
            return None
        q = self.login_fails[ip]
        q.append(now)
        while q and now - q[0] > LOGIN_WINDOW:
            q.popleft()
        if len(q) >= LOGIN_MAX_FAILS:
            q.clear()
            return {
                "type": "BruteForce (repeated failed logins)",
                "ip": ip,
                "count": LOGIN_MAX_FAILS,
                "window_s": LOGIN_WINDOW,
            }
        return None

    def check_scan(self, ip, path, now=None):
        now = now or time.time()
        p = (path or "").lower().lstrip("/")
        if not any(sp in p for sp in SCAN_PATHS):
            return None
        q = self.scan_hits[ip]
        q.append(now)
        while q and now - q[0] > SCAN_WINDOW:
            q.popleft()
        if len(q) >= SCAN_MAX_HITS:
            q.clear()
            return {
                "type": "Reconnaissance (path scanning)",
                "ip": ip,
                "count": SCAN_MAX_HITS,
                "window_s": SCAN_WINDOW,
            }
        return None

    def check_sqli(self, ip, path, query):
        target = f"{path or ''} {query or ''}"
        if SQLI_RE.search(target):
            return {
                "type": "SQLi/XSS (malicious payload pattern)",
                "ip": ip,
                "matched": target[:120],
            }
        return None
