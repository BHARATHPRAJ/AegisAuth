from collections.abc import Mapping
from time import time
from typing import Any

from redis.asyncio import Redis

_BLOCKED_BOT_ATTEMPTS_KEY = "aegisauth:metrics:blocked_bot_attempts"
_BLOCKED_BOT_ATTEMPTS_HOURLY_KEY = "aegisauth:metrics:blocked_bot_attempts:hourly"
_HOUR_SECONDS = 60 * 60


class BotAttemptCounter:
    def __init__(self, redis: Redis | None = None) -> None:
        self.redis = redis
        self.local_total = 0
        self.local_hourly: dict[int, int] = {}

    async def record(self, timestamp: int | None = None) -> None:
        current_hour = int(time() if timestamp is None else timestamp) // _HOUR_SECONDS
        bucket = current_hour * _HOUR_SECONDS
        if self.redis is None:
            self.local_total += 1
            self.local_hourly[bucket] = self.local_hourly.get(bucket, 0) + 1
            return

        pipeline = self.redis.pipeline(transaction=True)
        pipeline.incr(_BLOCKED_BOT_ATTEMPTS_KEY)
        pipeline.hincrby(_BLOCKED_BOT_ATTEMPTS_HOURLY_KEY, str(bucket), 1)
        pipeline.expire(_BLOCKED_BOT_ATTEMPTS_HOURLY_KEY, 48 * _HOUR_SECONDS)
        await pipeline.execute()

    async def total(self) -> int:
        if self.redis is None:
            return self.local_total
        value = await self.redis.get(_BLOCKED_BOT_ATTEMPTS_KEY)
        return int(value or 0)

    async def history(self, hours: int = 24, timestamp: int | None = None) -> list[dict[str, int]]:
        if hours < 1:
            raise ValueError("History window must be positive")

        current_hour = int(time() if timestamp is None else timestamp) // _HOUR_SECONDS
        first_hour = current_hour - hours + 1
        if self.redis is None:
            hourly_totals = self.local_hourly
        else:
            stored_totals = await self.redis.hgetall(_BLOCKED_BOT_ATTEMPTS_HOURLY_KEY)
            hourly_totals = {int(hour): int(count) for hour, count in stored_totals.items()}

        return [
            {
                "timestamp": hour * _HOUR_SECONDS,
                "count": hourly_totals.get(hour * _HOUR_SECONDS, 0),
            }
            for hour in range(first_hour, current_hour + 1)
        ]


def browser_risk_score(telemetry: Mapping[str, Any]) -> int:
    return int(assess_browser(telemetry)["score"])


def assess_browser(telemetry: Mapping[str, Any], block_threshold: int = 50) -> dict[str, Any]:
    score = 0
    signals: list[str] = []

    if telemetry.get("webdriver") is True:
        score += 35
        signals.append("Automation flag detected (+35).")

    interaction_ms = telemetry.get("interaction_ms")
    if isinstance(interaction_ms, (int, float)) and interaction_ms < 100:
        score += 20
        signals.append("Form submitted unusually quickly (+20).")

    interaction_events = telemetry.get("interaction_events")
    if isinstance(interaction_events, int) and interaction_events == 0:
        score += 5
        signals.append("No form interaction event was observed (+5). Autofill may not emit one.")

    plugin_count = telemetry.get("plugin_count")
    if isinstance(plugin_count, int) and plugin_count == 0:
        score += 3
        signals.append("Browser reports no plugins (+3).")

    viewport_width = telemetry.get("viewport_width")
    viewport_height = telemetry.get("viewport_height")
    if (
        isinstance(viewport_width, int)
        and isinstance(viewport_height, int)
        and (
            viewport_width < 100
            or viewport_height < 100
            or viewport_width > 4096
            or viewport_height > 4096
        )
    ):
        score += 15
        signals.append("Viewport dimensions are outside expected bounds (+15).")

    score = min(score, 100)
    if score >= block_threshold:
        level = "high"
        decision = "Block this browser request"
    elif score >= 30:
        level = "review"
        decision = "Allow with additional scrutiny"
    else:
        level = "low"
        decision = "Allow this browser request"

    if not signals:
        signals.append("No configured risk signals were detected.")
    return {"score": score, "level": level, "decision": decision, "signals": signals}


def honeypot_was_filled(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())
