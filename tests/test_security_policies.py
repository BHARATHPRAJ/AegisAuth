import pytest

from app.browser_protection import assess_browser, browser_risk_score, honeypot_was_filled
from app.database import Database, SecurityEventStore
from app.rate_limit import SlidingWindowRateLimiter


@pytest.mark.parametrize(
    ("telemetry", "expected_score"),
    [
        ({}, 0),
        ({"webdriver": True}, 35),
        ({"webdriver": False, "interaction_ms": 20}, 20),
        ({"webdriver": True, "interaction_ms": 20, "plugin_count": 0}, 58),
        (
            {
                "webdriver": True,
                "interaction_ms": 1500,
                "interaction_events": 0,
                "plugin_count": 0,
            },
            43,
        ),
    ],
)
def test_browser_risk_score(telemetry: dict[str, object], expected_score: int) -> None:
    assert browser_risk_score(telemetry) == expected_score


@pytest.mark.parametrize(
    ("value", "expected"), [("", False), ("  ", False), ("bot", True), (None, False)]
)
def test_honeypot_detection(value: object, expected: bool) -> None:
    assert honeypot_was_filled(value) is expected


class FakeRedis:
    def __init__(self, result: list[int]) -> None:
        self.result = result
        self.arguments: tuple[object, ...] = ()
        self.time_calls = 0

    async def time(self) -> tuple[int, int]:
        self.time_calls += 1
        return 1_700_000_000, 123_000

    async def eval(self, *arguments: object) -> list[int]:
        self.arguments = arguments
        return self.result


@pytest.mark.asyncio
async def test_rate_limiter_hashes_identity_and_returns_remaining_quota() -> None:
    redis = FakeRedis([1, 4, 0])
    limiter = SlidingWindowRateLimiter(redis, limit=5, window_seconds=60)

    result = await limiter.check("client-a", now_ms=1_000)

    assert result.allowed is True
    assert result.remaining == 4
    assert result.retry_after == 0
    assert "client-a" not in str(redis.arguments)


@pytest.mark.asyncio
async def test_rate_limiter_uses_redis_clock_by_default() -> None:
    redis = FakeRedis([1, 4, 0])
    limiter = SlidingWindowRateLimiter(redis, limit=5, window_seconds=60)

    await limiter.check("client-a")

    assert redis.arguments[3] == 1_700_000_000_123
    assert redis.time_calls == 1


@pytest.mark.asyncio
async def test_rate_limiter_returns_retry_after_when_blocked() -> None:
    limiter = SlidingWindowRateLimiter(FakeRedis([0, 0, 12]), limit=5, window_seconds=60)

    result = await limiter.check("client-a", now_ms=1_000)

    assert result.allowed is False
    assert result.retry_after == 12


@pytest.mark.asyncio
async def test_security_events_persist_and_aggregate_hourly(tmp_path) -> None:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'events.db'}")
    await database.initialize()
    store = SecurityEventStore(database.sessions)

    await store.record_blocked_attempt("honeypot", 100, timestamp=100 * 60 * 60)
    await store.record_blocked_attempt("risk_score", 65, timestamp=100 * 60 * 60 + 20)
    await store.record_blocked_attempt("honeypot", 100, timestamp=99 * 60 * 60)
    assert await store.total() == 3
    removed = await store.purge_before(datetime.fromtimestamp(100 * 60 * 60, UTC))
    assert removed == 1
    assert await store.total() == 2
    history = await store.history(timestamp=100 * 60 * 60 + 500)
    assert len(history) == 24
    assert history[-2]["count"] == 0
    assert history[-1]["count"] == 2

    await database.close()

    reopened = Database(f"sqlite+aiosqlite:///{tmp_path / 'events.db'}")
    store = SecurityEventStore(reopened.sessions)
    assert await store.total() == 3
    await reopened.close()


def test_browser_assessment_returns_explainable_result() -> None:
    result = assess_browser(
        {
            "webdriver": True,
            "interaction_ms": 20,
            "interaction_events": 0,
            "plugin_count": 0,
            "viewport_width": 0,
            "viewport_height": 0,
        }
    )

    assert result["score"] == 78
    assert result["level"] == "high"
    assert len(result["signals"]) == 5
