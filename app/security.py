import hmac
import math
import os
import threading
import time
from collections import defaultdict, deque


def load_api_keys(raw=None):
    raw = os.getenv("API_KEYS", "") if raw is None else raw
    return [k.strip() for k in raw.split(",") if k.strip()]


def key_is_valid(candidate, keys):
    if not candidate:
        return False
    ok = False
    for key in keys:  # no early exit, so timing doesn't reveal which key matched
        ok |= hmac.compare_digest(candidate.encode(), key.encode())
    return ok


class RateLimiter:
    """Sliding window limiter. In memory, so it is per process."""

    def __init__(self, limit=60, window=60.0, clock=time.monotonic):
        self.limit, self.window, self._clock = limit, window, clock
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key):
        """Return 0 if the request is allowed, otherwise seconds until it would be."""
        now = self._clock()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return max(1, math.ceil(self.window - (now - hits[0])))
            hits.append(now)
            return 0
