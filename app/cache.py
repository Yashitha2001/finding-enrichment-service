import time

MISSING = object()


class TTLCache:
    def __init__(self, ttl=300, clock=time.monotonic):
        self._ttl = ttl
        self._clock = clock
        self._items = {}

    def get(self, key):
        item = self._items.get(key)
        if item is None:
            return MISSING
        expires, value = item
        if self._clock() >= expires:
            self._items.pop(key, None)
            return MISSING
        return value

    def set(self, key, value, ttl=None):
        self._items[key] = (self._clock() + (self._ttl if ttl is None else ttl), value)
