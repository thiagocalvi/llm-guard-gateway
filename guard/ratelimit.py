"""
    Rate limit por usuário com janela deslizante.

    Limitar a vazão encarece a busca por uma frase que passe no detector (e o custo de tokens do LLM).
"""
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, max_requests: int = 20, window_s: float = 60.0, clock=time.monotonic):
        self.max_requests = max_requests
        self.window_s = window_s
        self.clock = clock  # injetável para testar sem sleep
        # em memória, por processo; com várias réplicas usar Redis.
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = self.clock()
        hits = self._hits[key]
        while hits and now - hits[0] >= self.window_s:
            hits.popleft()
        if len(hits) >= self.max_requests:
            return False
        hits.append(now)
        return True
