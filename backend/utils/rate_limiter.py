"""
A tiny in-memory sliding-window rate limiter.

Why: even a local tool should show the habit of rate limiting an endpoint that
does CPU work. In production you would use a shared store (Redis) or an API
gateway; this keeps the project dependency-free.
"""
import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self, limit_per_minute: int):
        self.limit = limit_per_minute
        self._hits = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        window = self._hits[key]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= self.limit:
            return False
        window.append(now)
        return True
