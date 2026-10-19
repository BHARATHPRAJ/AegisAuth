from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from time import time

from sqlalchemy import CheckConstraint, DateTime, Integer, String, delete, func, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

_HOUR_SECONDS = 60 * 60


class Base(DeclarativeBase):
    pass


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_security_events_risk_score"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


def async_database_url(url: str) -> str:
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


class Database:
    def __init__(self, url: str) -> None:
        self.engine: AsyncEngine = create_async_engine(
            async_database_url(url),
            pool_pre_ping=True,
        )
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)

    async def initialize(self, create_schema: bool = True) -> None:
        if create_schema:
            async with self.engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        await self.engine.dispose()


class SecurityEventStore:
    def __init__(self, sessions: async_sessionmaker) -> None:
        self.sessions = sessions

    async def record_blocked_attempt(
        self,
        event_type: str,
        risk_score: int,
        timestamp: int | None = None,
    ) -> None:
        occurred_at = (
            datetime.fromtimestamp(timestamp, UTC) if timestamp is not None else datetime.now(UTC)
        )
        async with self.sessions() as session:
            session.add(
                SecurityEvent(
                    event_type=event_type,
                    risk_score=risk_score,
                    created_at=occurred_at,
                )
            )
            await session.commit()

    async def total(self, event_types: Sequence[str] | None = None) -> int:
        async with self.sessions() as session:
            statement = select(func.count()).select_from(SecurityEvent)
            if event_types is not None:
                statement = statement.where(SecurityEvent.event_type.in_(event_types))
            result = await session.scalar(statement)
            return int(result or 0)

    async def record_simulated_requests(self, results: Sequence[tuple[int, bool]]) -> None:
        occurred_at = datetime.now(UTC)
        async with self.sessions() as session:
            session.add_all(
                [
                    SecurityEvent(
                        event_type="simulation_blocked" if blocked else "simulation_allowed",
                        risk_score=risk_score,
                        created_at=occurred_at,
                    )
                    for risk_score, blocked in results
                ]
            )
            await session.commit()

    async def purge_before(self, cutoff: datetime) -> int:
        async with self.sessions() as session:
            result = await session.execute(
                delete(SecurityEvent).where(SecurityEvent.created_at < cutoff)
            )
            await session.commit()
            return int(result.rowcount or 0)

    async def history(
        self,
        hours: int = 24,
        timestamp: int | None = None,
        event_types: Sequence[str] | None = None,
    ) -> list[dict[str, int]]:
        if hours < 1:
            raise ValueError("History window must be positive")

        current_time = int(time() if timestamp is None else timestamp)
        current_hour = current_time // _HOUR_SECONDS
        first_hour = current_hour - hours + 1
        start = datetime.fromtimestamp(first_hour * _HOUR_SECONDS, UTC)
        async with self.sessions() as session:
            statement = select(SecurityEvent.created_at).where(SecurityEvent.created_at >= start)
            if event_types is not None:
                statement = statement.where(SecurityEvent.event_type.in_(event_types))
            result = await session.scalars(statement)
            timestamps = result.all()

        counts = Counter()
        for occurred_at in timestamps:
            if occurred_at.tzinfo is None:
                occurred_at = occurred_at.replace(tzinfo=UTC)
            bucket = int(occurred_at.timestamp()) // _HOUR_SECONDS
            if first_hour <= bucket <= current_hour:
                counts[bucket] += 1

        return [
            {"timestamp": hour * _HOUR_SECONDS, "count": counts[hour]}
            for hour in range(first_hour, current_hour + 1)
        ]
