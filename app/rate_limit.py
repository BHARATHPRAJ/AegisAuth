import hashlib
import secrets
from dataclasses import dataclass

from redis.asyncio import Redis

_SLIDING_WINDOW_SCRIPT = """
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local request_id = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms - window_ms)
local count = redis.call('ZCARD', key)
if count < limit then
  redis.call('ZADD', key, now_ms, request_id)
  redis.call('PEXPIRE', key, window_ms)
  return {1, limit - count - 1, 0}
end

local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local retry_after = math.max(1, math.ceil((tonumber(oldest[2]) + window_ms - now_ms) / 1000))
return {0, 0, retry_after}
"""


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after: int


class SlidingWindowRateLimiter:
    def __init__(self, redis: Redis, limit: int, window_seconds: int) -> None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("Rate limit and window must be positive")
        self.redis = redis
        self.limit = limit
        self.window_seconds = window_seconds

    async def check(self, identity: str, now_ms: int | None = None) -> RateLimitResult:
        if not identity:
            raise ValueError("Rate-limit identity must not be empty")

        if now_ms is None:
            seconds, microseconds = await self.redis.time()
            timestamp_ms = int(seconds) * 1000 + int(microseconds) // 1000
        else:
            timestamp_ms = now_ms
        identity_hash = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        result = await self.redis.eval(
            _SLIDING_WINDOW_SCRIPT,
            1,
            f"aegisauth:rate:{identity_hash}",
            timestamp_ms,
            self.window_seconds * 1000,
            self.limit,
            secrets.token_hex(16),
        )
        return RateLimitResult(
            allowed=bool(int(result[0])),
            remaining=int(result[1]),
            retry_after=int(result[2]),
        )
