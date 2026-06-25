"""A small async FakeRedis used by the multi-instance governance tests.

It models the subset of Redis commands the governance registries use, with TTL
honored against an injectable clock and an ``eval`` that faithfully runs the
velocity reserve script. A *shared* instance behind two registries models two
MCC runtime instances pointed at one Redis server.

This is test scaffolding only — never imported by runtime code.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class FakeRedis:
    def __init__(self, store: Optional[dict] = None, clock=None) -> None:
        # key -> (value, expires_at|None)
        self.kv: Dict[str, Any] = store if store is not None else {}
        self.sets: Dict[str, set] = {}
        self.ttls: Dict[str, int] = {}
        self.clock = clock or (lambda: 0.0)

    # --- expiry helpers ---
    def _expired(self, key: str) -> bool:
        cur = self.kv.get(key)
        return cur is not None and cur[1] is not None and cur[1] <= self.clock()

    def _evict(self, key: str) -> None:
        if self._expired(key):
            del self.kv[key]

    # --- string ops ---
    async def set(self, key, value, nx=False, ex=None, px=None):
        self._evict(key)
        if nx and key in self.kv:
            return None
        exp = None
        if ex is not None:
            exp = self.clock() + ex
        elif px is not None:
            exp = self.clock() + px / 1000.0
        self.kv[key] = (value, exp)
        return True

    async def get(self, key):
        self._evict(key)
        cur = self.kv.get(key)
        return None if cur is None else cur[0]

    async def delete(self, *keys):
        n = 0
        for k in keys:
            if k in self.kv:
                del self.kv[k]
                n += 1
            self.sets.pop(k, None)
        return n

    async def incr(self, key):
        self._evict(key)
        val = int(self.kv.get(key, (0, None))[0]) + 1
        _, exp = self.kv.get(key, (0, None))
        self.kv[key] = (val, exp)
        return val

    async def decr(self, key):
        self._evict(key)
        val = int(self.kv.get(key, (0, None))[0]) - 1
        _, exp = self.kv.get(key, (0, None))
        self.kv[key] = (val, exp)
        return val

    async def incrbyfloat(self, key, amt):
        self._evict(key)
        val = float(self.kv.get(key, (0.0, None))[0]) + float(amt)
        _, exp = self.kv.get(key, (0.0, None))
        self.kv[key] = (val, exp)
        return val

    async def expire(self, key, ttl):
        self.ttls[key] = ttl
        if key in self.kv:
            v, _ = self.kv[key]
            self.kv[key] = (v, self.clock() + ttl)
        return True

    async def ttl(self, key):
        return self.ttls.get(key, -1)

    # --- set ops ---
    async def sadd(self, key, *members):
        s = self.sets.setdefault(key, set())
        added = 0
        for m in members:
            if m not in s:
                s.add(m)
                added += 1
        return added

    async def srem(self, key, *members):
        s = self.sets.get(key, set())
        n = 0
        for m in members:
            if m in s:
                s.discard(m)
                n += 1
        return n

    async def scard(self, key):
        return len(self.sets.get(key, set()))

    async def sismember(self, key, member):
        return member in self.sets.get(key, set())

    # --- scripting (velocity reserve) ---
    async def eval(self, script, numkeys, *args):
        keys = list(args[:numkeys])
        a = list(args[numkeys:])
        count_key, sum_key, dest_key = keys
        window = int(a[8])
        breaches = []
        did_count = did_amount = added_dest = False
        if a[0] == "1":
            c = await self.incr(count_key)
            if c == 1:
                await self.expire(count_key, window)
            did_count = True
            if float(a[1]) >= 0 and c > float(a[1]):
                breaches.append(f"count {c} > max {a[1]}")
        if a[2] == "1" and not breaches:
            s = await self.incrbyfloat(sum_key, float(a[3]))
            if self.ttls.get(sum_key, -1) < 0:
                await self.expire(sum_key, window)
            did_amount = True
            if float(a[4]) >= 0 and float(s) > float(a[4]):
                breaches.append(f"amount {s} > max {a[4]}")
        if a[5] == "1" and not breaches:
            added = await self.sadd(dest_key, a[6])
            if self.ttls.get(dest_key, -1) < 0:
                await self.expire(dest_key, window)
            added_dest = added == 1
            card = await self.scard(dest_key)
            if float(a[7]) >= 0 and card > float(a[7]):
                breaches.append(f"new destinations {card} > max {a[7]}")
        if breaches:
            if did_count:
                await self.decr(count_key)
            if did_amount:
                await self.incrbyfloat(sum_key, -float(a[3]))
            if added_dest:
                await self.srem(dest_key, a[6])
            return [0, "; ".join(breaches)]
        return [1, "ok"]


class DownRedis:
    """Every command raises — models a Redis outage (fail-closed expectation)."""

    def __getattr__(self, _name):
        async def boom(*a, **k):
            raise ConnectionError("redis down")

        return boom
