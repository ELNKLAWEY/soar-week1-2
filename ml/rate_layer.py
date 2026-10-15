import time
from collections import defaultdict, deque
from datetime import datetime


def _to_epoch(ts):
    if ts is None:
        return time.time()
    if isinstance(ts, (int, float)):
        return float(ts)
    import pandas as pd
    v = pd.to_datetime(str(ts), errors="coerce")
    if pd.isna(v):
        return time.time()
    return v.timestamp()


class RateLayer:
    # Alert when one src_ip sends a high volume of packets to the same port in a short window
    def __init__(self, window=10, max_packets=100, cooldown=10):
        self.window, self.max_packets, self.cooldown = window, max_packets, cooldown
        self.hist = defaultdict(deque)  # key -> deque of (ts, pkt_count)
        self.last_alert = {}

    def check(self, src_ip, dst_port, ts=None, pkt_count=1):
        ts = _to_epoch(ts)
        key = (src_ip, dst_port)
        q = self.hist[key]
        q.append((ts, pkt_count))
        while q and ts - q[0][0] > self.window:
            q.popleft()
        total = sum(c for _, c in q)
        if total >= self.max_packets and ts - self.last_alert.get(key, 0) > self.cooldown:
            self.last_alert[key] = ts
            return {
                "type": "DoS/DDoS (Volumetric flood)",
                "src_ip": src_ip,
                "dst_port": dst_port,
                "packets_in_window": int(total),
                "window_s": self.window,
                "source": "rate-layer",
            }
        return None
