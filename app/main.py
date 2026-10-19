import secrets
import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from hmac import compare_digest
from pathlib import Path
from random import SystemRandom
from typing import Literal
from urllib.parse import parse_qs, urlsplit

import httpx
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.sessions import SessionMiddleware

from app.browser_protection import assess_browser, browser_risk_score, honeypot_was_filled
from app.config import Settings, get_settings
from app.database import Database, SecurityEvent, SecurityEventStore
from app.m2m_auth import JWTValidator, MachinePrincipal, require_machine_client
from app.rate_limit import SlidingWindowRateLimiter

settings = get_settings()
logger = logging.getLogger(__name__)
oauth = OAuth()
app_directory = Path(__file__).parent
templates = Jinja2Templates(directory=app_directory / "templates")


def validate_production_settings(config: Settings) -> None:
    if config.app_env != "production":
        return

    required = {
        "SESSION_SECRET": config.session_secret,
        "DATABASE_URL": config.database_url,
        "REDIS_URL": config.redis_url,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise RuntimeError(f"Missing production settings: {', '.join(missing)}")
    if config.session_secret in {
        "development-only-change-this-secret",
        "replace-with-a-random-secret",
    }:
        raise RuntimeError("SESSION_SECRET must not use a development placeholder")
    if len(config.session_secret) < 32:
        raise RuntimeError("SESSION_SECRET must contain at least 32 characters")
    if not config.session_https_only:
        raise RuntimeError("SESSION_HTTPS_ONLY must be enabled in production")
    if not config.redis_url.startswith("rediss://"):
        raise RuntimeError("REDIS_URL must use TLS in production")
    if urlsplit(config.database_url).scheme not in {"postgres", "postgresql", "postgresql+asyncpg"}:
        raise RuntimeError("DATABASE_URL must use PostgreSQL in production")

        if config.oidc_issuer_url and urlsplit(config.oidc_issuer_url).scheme != "https":
            raise RuntimeError("OIDC_ISSUER_URL must use HTTPS in production")

    oidc_client_settings = (
        config.oidc_metadata_url,
        config.oidc_client_id,
        config.oidc_client_secret,
    )
    if any(oidc_client_settings) and not all(oidc_client_settings):
        raise RuntimeError("OIDC metadata URL, client ID, and client secret must be configured together")
    if all(oidc_client_settings):
        if not config.oidc_issuer_url:
            raise RuntimeError("OIDC_ISSUER_URL is required when OIDC is configured")
        for name, value in (
            ("OIDC_ISSUER_URL", config.oidc_issuer_url),
            ("OIDC_METADATA_URL", config.oidc_metadata_url),
            ("OIDC_REDIRECT_URI", config.oidc_redirect_uri),
        ):
            if urlsplit(value).scheme != "https":
                raise RuntimeError(f"{name} must use HTTPS in production")

    if config.jwks_url or config.jwt_audience:
        if not config.oidc_issuer_url or not config.jwks_url or not config.jwt_audience:
            raise RuntimeError("OIDC_ISSUER_URL, JWKS_URL, and JWT_AUDIENCE must be configured together")
        if urlsplit(config.jwks_url).scheme != "https":
            raise RuntimeError("JWKS_URL must use HTTPS in production")


async def retain_security_events(store: SecurityEventStore, retention_days: int) -> None:
    while True:
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        try:
            removed = await store.purge_before(cutoff)
        except SQLAlchemyError:
            logger.exception("Security-event retention sweep failed")
        else:
            if removed:
                logger.info("Purged %s security events older than %s days", removed, retention_days)
        await asyncio.sleep(24 * 60 * 60)


@asynccontextmanager
async def lifespan(application: FastAPI):
    validate_production_settings(settings)

    database_url = settings.database_url
    if not database_url:
        if settings.app_env == "production":
            raise RuntimeError("DATABASE_URL is required in production")
        database_url = "sqlite+aiosqlite:///./aegisauth.db"
    database = Database(database_url)
    await database.initialize(create_schema=settings.app_env != "production")
    application.state.database = database
    application.state.security_event_store = SecurityEventStore(database.sessions)
    await application.state.security_event_store.purge_before(
        datetime.now(UTC) - timedelta(days=settings.security_event_retention_days)
    )
    application.state.bot_attempt_metrics_available = True
    application.state.jwt_validator = None
    application.state.rate_limiter = None
    application.state.m2m_ip_rate_limiter = None
    application.state.redis = None
    application.state.http_client = httpx.AsyncClient(timeout=5.0)

    if settings.jwks_url and settings.oidc_issuer_url and settings.jwt_audience:
        application.state.jwt_validator = JWTValidator(
            application.state.http_client,
            settings.jwks_url,
            settings.oidc_issuer_url,
            settings.jwt_audience,
        )

    if settings.oidc_issuer_url and settings.oidc_client_id and settings.oidc_client_secret:
        oauth.register(
            name="oidc",
            client_id=settings.oidc_client_id,
            client_secret=settings.oidc_client_secret,
            server_metadata_url=(settings.oidc_metadata_url),
            client_kwargs={"scope": "openid profile email"},
        )

    if settings.redis_url:
        redis = Redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            health_check_interval=30,
            max_connections=100,
        )
        try:
            await redis.ping()
        except RedisError:
            await redis.aclose()
            if settings.app_env == "production":
                raise RuntimeError("Redis is required but unavailable")
        else:
            application.state.redis = redis
            application.state.rate_limiter = SlidingWindowRateLimiter(
                redis,
                settings.rate_limit_requests,
                settings.rate_limit_window_seconds,
            )
            application.state.m2m_ip_rate_limiter = SlidingWindowRateLimiter(
                redis,
                settings.m2m_ip_rate_limit_requests,
                settings.rate_limit_window_seconds,
            )

    retention_task = asyncio.create_task(
        retain_security_events(
            application.state.security_event_store,
            settings.security_event_retention_days,
        )
    )
    try:
        yield
    finally:
        retention_task.cancel()
        try:
            await retention_task
        except asyncio.CancelledError:
            pass
        if application.state.redis is not None:
            await application.state.redis.aclose()
        await application.state.http_client.aclose()
        await database.close()


app = FastAPI(title="AegisAuth", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret or "development-only-change-this-secret",
    same_site="lax",
    https_only=settings.session_https_only,
    max_age=3600,
)
app.mount("/static", StaticFiles(directory=app_directory / "static"), name="static")


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
        "object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


class BrowserTelemetry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    webdriver: bool = False
    interaction_ms: int | None = Field(default=None, ge=0, le=600_000)
    interaction_events: int = Field(default=0, ge=0, le=1000)
    plugin_count: int | None = Field(default=None, ge=0, le=100)
    viewport_width: int | None = Field(default=None, ge=0, le=10000)
    viewport_height: int | None = Field(default=None, ge=0, le=10000)
    honeypot_filled: bool = False


class SimulationBatchRequest(BaseModel):
    count: int = Field(default=10, ge=3, le=25)
    profile: Literal["random", "headless", "form_filler", "human", "custom"] = "random"
    custom_signals: BrowserTelemetry | None = None


def browser_identity(request: Request) -> str:
    # Uvicorn's proxy middleware resolves trusted X-Forwarded-For into this field.
    client = request.client.host if request.client else "unknown"
    return f"browser:{client}"


async def enforce_browser_rate_limit(request: Request) -> None:
    limiter: SlidingWindowRateLimiter | None = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:
        if settings.app_env == "production":
            raise HTTPException(status_code=503, detail="Rate-limit service unavailable")
        return
    try:
        result = await limiter.check(browser_identity(request))
    except RedisError as exc:
        raise HTTPException(status_code=503, detail="Rate-limit service unavailable") from exc
    if not result.allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(result.retry_after)},
        )


@app.get("/health/live", tags=["health"])
async def liveness() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready", tags=["health"])
async def readiness(request: Request) -> dict[str, str]:
    database: Database | None = getattr(request.app.state, "database", None)
    if database is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    try:
        async with database.engine.connect() as connection:
            await connection.execute(select(SecurityEvent.id).limit(1))
        if settings.app_env == "production":
            redis: Redis | None = getattr(request.app.state, "redis", None)
            if redis is None:
                raise HTTPException(status_code=503, detail="Redis unavailable")
            await redis.ping()
    except (SQLAlchemyError, RedisError) as exc:
        raise HTTPException(status_code=503, detail="Dependency unavailable") from exc
    return {"status": "ready"}


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse("/#sign-in", status_code=status.HTTP_303_SEE_OTHER)


async def blocked_bot_attempt_total(request: Request) -> int | None:
    if not request.app.state.bot_attempt_metrics_available:
        return None
    store: SecurityEventStore = request.app.state.security_event_store
    try:
        return await store.total(event_types=("honeypot", "risk_score"))
    except SQLAlchemyError:
        request.app.state.bot_attempt_metrics_available = False
        return None


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse("/#dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/api/metrics/blocked-bot-attempts", include_in_schema=False)
async def blocked_bot_attempts_metric(request: Request) -> dict[str, int | None]:
    return {"blocked_bot_attempts": await blocked_bot_attempt_total(request)}


@app.get("/api/metrics/blocked-bot-attempts/history", include_in_schema=False)
async def blocked_bot_attempts_history(request: Request) -> dict[str, list[dict[str, int]] | None]:
    if not request.app.state.bot_attempt_metrics_available:
        return {"history": None}
    store: SecurityEventStore = request.app.state.security_event_store
    try:
        return {
            "history": await store.history(hours=24, event_types=("honeypot", "risk_score")),
            "simulation_history": await store.history(
                hours=24,
                event_types=("simulation_blocked", "simulation_allowed"),
            ),
        }
    except SQLAlchemyError:
        request.app.state.bot_attempt_metrics_available = False
        return {"history": None, "simulation_history": None}


@app.get("/api/metrics/simulated-requests", include_in_schema=False)
async def simulated_request_total(request: Request) -> dict[str, int | None]:
    if not request.app.state.bot_attempt_metrics_available:
        return {"simulated_requests": None}
    store: SecurityEventStore = request.app.state.security_event_store
    try:
        total = await store.total(event_types=("simulation_blocked", "simulation_allowed"))
        return {"simulated_requests": total}
    except SQLAlchemyError:
        request.app.state.bot_attempt_metrics_available = False
        return {"simulated_requests": None}


@app.post("/api/simulate/browser-risk", include_in_schema=False)
async def simulate_browser_risk(request: Request, telemetry: BrowserTelemetry) -> dict[str, object]:
    await enforce_browser_rate_limit(request)
    trace = [
        {
            "stage": "validation",
            "status": "ok",
            "message": f"Telemetry validated ({len(telemetry.model_dump())} fields).",
        },
        {
            "stage": "rate-limit",
            "status": "ok",
            "message": "Browser simulation rate limit passed.",
        },
    ]
    if telemetry.honeypot_filled:
        trace.extend(
            [
                {
                    "stage": "honeypot",
                    "status": "blocked",
                    "message": "Hidden honeypot field filled; risk scoring skipped.",
                },
                {
                    "stage": "policy",
                    "status": "blocked",
                    "message": "Hard-block policy applied to honeypot submission.",
                },
            ]
        )
        return {
            "score": 100,
            "level": "high",
            "decision": "Block this browser request",
            "signals": ["Hidden honeypot field was filled (+100)."],
            "trace": trace,
        }
    trace.append(
        {
            "stage": "honeypot",
            "status": "clear",
            "message": "No hidden honeypot value detected.",
        }
    )
    assessment = assess_browser(telemetry.model_dump(), settings.browser_risk_threshold)
    blocked = assessment["score"] >= settings.browser_risk_threshold
    trace.extend(
        [
            {
                "stage": "scoring",
                "status": "ok",
                "message": f"Risk score calculated: {assessment['score']}/100 from {len(assessment['signals'])} signal(s).",
            },
            {
                "stage": "policy",
                "status": "blocked" if blocked else "allowed",
                "message": f"Threshold {settings.browser_risk_threshold}; decision: {assessment['decision']}.",
            },
        ]
    )
    return {**assessment, "trace": trace}


def random_simulation_telemetry(
    profile: str,
    custom_signals: BrowserTelemetry | None,
    randomizer: SystemRandom,
) -> tuple[str, BrowserTelemetry]:
    if profile == "random":
        profile = randomizer.choice(("human", "headless", "form_filler"))
    if profile == "custom" and custom_signals is not None:
        return profile, custom_signals
    if profile == "human":
        return profile, BrowserTelemetry(
            webdriver=False,
            interaction_ms=randomizer.randint(250, 2500),
            interaction_events=randomizer.randint(1, 8),
            plugin_count=randomizer.randint(2, 8),
            viewport_width=randomizer.randint(1024, 1920),
            viewport_height=randomizer.randint(680, 1200),
        )
    if profile == "form_filler":
        return profile, BrowserTelemetry(
            webdriver=False,
            interaction_ms=randomizer.randint(10, 90),
            interaction_events=0,
            plugin_count=randomizer.randint(1, 6),
            viewport_width=1365,
            viewport_height=768,
            honeypot_filled=True,
        )
    return profile, BrowserTelemetry(
        webdriver=True,
        interaction_ms=randomizer.randint(5, 90),
        interaction_events=0,
        plugin_count=0,
        viewport_width=randomizer.choice((0, 320, 8000)),
        viewport_height=randomizer.choice((0, 240, 8000)),
    )


@app.post("/api/simulate/batch", include_in_schema=False)
async def simulate_request_batch(
    request: Request,
    batch: SimulationBatchRequest,
) -> dict[str, object]:
    await enforce_browser_rate_limit(request)
    if batch.profile == "custom" and batch.custom_signals is None:
        raise HTTPException(
            status_code=422, detail="Custom signals are required for a custom batch"
        )
    randomizer = SystemRandom()
    results: list[dict[str, object]] = []
    event_rows: list[tuple[int, bool]] = []
    for index in range(batch.count):
        profile, telemetry = random_simulation_telemetry(
            batch.profile,
            batch.custom_signals,
            randomizer,
        )
        assessment = (
            {
                "score": 100,
                "level": "high",
                "decision": "Block this browser request",
                "signals": ["Hidden honeypot field was filled (+100)."],
            }
            if telemetry.honeypot_filled
            else assess_browser(telemetry.model_dump(), settings.browser_risk_threshold)
        )
        blocked = assessment["score"] >= settings.browser_risk_threshold
        event_rows.append((int(assessment["score"]), blocked))
        results.append(
            {
                "request": index + 1,
                "profile": profile,
                "score": assessment["score"],
                "level": assessment["level"],
                "decision": assessment["decision"],
                "blocked": blocked,
                "signals": assessment["signals"],
            }
        )

    store: SecurityEventStore = request.app.state.security_event_store
    try:
        await store.record_simulated_requests(event_rows)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Simulation storage unavailable") from exc

    blocked_count = sum(1 for item in results if item["blocked"])
    trace = [
        {
            "stage": "validation",
            "status": "ok",
            "message": f"Batch accepted: profile={batch.profile}, requests={batch.count}.",
        },
        {
            "stage": "rate-limit",
            "status": "ok",
            "message": "Batch simulation rate limit passed.",
        },
        {
            "stage": "scoring",
            "status": "ok",
            "message": f"Policy evaluated {batch.count} simulated requests at threshold {settings.browser_risk_threshold}.",
        },
        {
            "stage": "storage",
            "status": "ok",
            "message": "Simulation totals and history recorded separately from real blocks.",
        },
    ]
    return {
        "request_count": batch.count,
        "blocked_count": blocked_count,
        "allowed_count": batch.count - blocked_count,
        "results": results,
        "trace": trace,
    }


@app.post("/auth/telemetry", include_in_schema=False)
async def submit_browser_telemetry(request: Request, telemetry: BrowserTelemetry):
    await enforce_browser_rate_limit(request)
    csrf_token = request.headers.get("x-csrf-token", "")
    expected_token = request.session.get("csrf_token", "")
    if not expected_token or not compare_digest(csrf_token, expected_token):
        raise HTTPException(status_code=403, detail="Invalid request")
    request.session["browser_risk"] = browser_risk_score(telemetry.model_dump())
    return {"status": "recorded"}


async def record_blocked_bot_attempt(request: Request, event_type: str, risk_score: int) -> None:
    store: SecurityEventStore = request.app.state.security_event_store
    try:
        await store.record_blocked_attempt(event_type, risk_score)
    except SQLAlchemyError:
        request.app.state.bot_attempt_metrics_available = False


@app.post("/auth/login", include_in_schema=False)
async def begin_login(request: Request):
    await enforce_browser_rate_limit(request)
    form = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    csrf_token = form.get("csrf_token", [""])[0]
    expected_token = request.session.get("csrf_token", "")
    if not expected_token or not compare_digest(csrf_token, expected_token):
        raise HTTPException(status_code=403, detail="Invalid request")
    if honeypot_was_filled(form.get("website_confirm", [""])[0]):
        await record_blocked_bot_attempt(request, "honeypot", 100)
        raise HTTPException(status_code=403, detail="Request rejected")
    risk_score = request.session.get("browser_risk", 0)
    if risk_score >= settings.browser_risk_threshold:
        await record_blocked_bot_attempt(request, "risk_score", risk_score)
        raise HTTPException(status_code=403, detail="Request rejected")

    client = oauth.create_client("oidc")
    if client is None:
        if settings.app_env == "development" and settings.demo_login_enabled:
            request.session.clear()
            request.session["user"] = {"sub": "local-demo", "name": "Demo User"}
            request.session["csrf_token"] = secrets.token_urlsafe(32)
            return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        raise HTTPException(status_code=503, detail="Sign-in provider is not configured")
    code_verifier = secrets.token_urlsafe(64)
    request.session["oidc_code_verifier"] = code_verifier
    return await client.authorize_redirect(
        request,
        settings.oidc_redirect_uri,
        code_verifier=code_verifier,
    )


@app.get("/auth/callback", include_in_schema=False)
async def auth_callback(request: Request):
    client = oauth.create_client("oidc")
    code_verifier = request.session.pop("oidc_code_verifier", None)
    if client is None or not code_verifier:
        raise HTTPException(status_code=400, detail="Invalid sign-in session")
    try:
        token = await client.authorize_access_token(request, code_verifier=code_verifier)
    except OAuthError as exc:
        raise HTTPException(status_code=401, detail="Sign-in failed") from exc

    user = token.get("userinfo") or {}
    subject = user.get("sub")
    if not isinstance(subject, str) or not subject:
        raise HTTPException(status_code=401, detail="Identity provider returned no user")

    request.session.clear()
    request.session["user"] = {
        "sub": subject,
        "name": user.get("name") or user.get("preferred_username") or "there",
    }
    request.session["csrf_token"] = secrets.token_urlsafe(32)
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/auth/logout", include_in_schema=False)
async def logout(request: Request):
    form = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    csrf_token = form.get("csrf_token", [""])[0]
    expected_token = request.session.get("csrf_token", "")
    if not expected_token or not compare_digest(csrf_token, expected_token):
        raise HTTPException(status_code=403, detail="Invalid request")
    request.session.clear()
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def homepage(request: Request):
    user = request.session.get("user")
    if user:
        return templates.TemplateResponse(
            request,
            "home.html",
            {
                "user": user,
                "csrf_token": request.session.get("csrf_token", ""),
            },
        )

    csrf_token = request.session.get("csrf_token")
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = csrf_token

    blocked_bot_attempts = await blocked_bot_attempt_total(request)
    history_response = await blocked_bot_attempts_history(request)
    simulated_total = await simulated_request_total(request)
    oidc_enabled = bool(
        settings.oidc_issuer_url
        and settings.oidc_metadata_url
        and settings.oidc_client_id
        and settings.oidc_client_secret
    )
    return templates.TemplateResponse(
        request,
        "portal.html",
        {
            "csrf_token": csrf_token,
            "demo_login_enabled": settings.app_env == "development" and settings.demo_login_enabled,
            "local_demo_login": settings.app_env == "development"
            and settings.demo_login_enabled
            and not oidc_enabled,
            "oidc_enabled": oidc_enabled,
            "sign_in_enabled": (settings.app_env == "development" and settings.demo_login_enabled)
            or oidc_enabled,
            "blocked_bot_attempts": blocked_bot_attempts,
            "history": history_response["history"],
            "simulated_requests": simulated_total["simulated_requests"],
            "simulation_history": history_response["simulation_history"],
        },
    )


@app.get("/api/private", tags=["machine API"])
async def private_resource(
    principal: MachinePrincipal = Depends(require_machine_client),
) -> dict[str, str]:
    return {"message": "Machine access granted", "client_id": principal.identity}
