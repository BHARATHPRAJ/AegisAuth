import re

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.config import Settings, get_settings
from app.main import app, browser_identity, validate_production_settings
from app.rate_limit import RateLimitResult


def csrf_from_page(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def test_homepage_shows_sign_in_and_dashboard_tabs_without_session() -> None:
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert 'id="panel-sign-in"' in response.text
    assert 'id="panel-dashboard"' in response.text
    assert 'id="request-flow-title"' in response.text
    assert 'id="browser-flow-title"' in response.text
    assert 'id="machine-flow-title"' in response.text


def test_login_page_renders_honeypot_and_csrf_token() -> None:
    with TestClient(app) as client:
        response = client.get("/login")

    assert response.status_code == 200
    assert 'href="#panel-dashboard"' in response.text
    assert ">Sign in</a>" in response.text
    assert 'name="website_confirm"' in response.text
    assert 'name="csrf_token"' in response.text


def test_dashboard_is_public_and_shows_attempt_total_before_sign_in() -> None:
    with TestClient(app) as client:
        page = client.get("/dashboard")
        metric = client.get("/api/metrics/blocked-bot-attempts")

    assert page.status_code == 200
    assert 'href="#panel-sign-in"' in page.text
    assert ">Dashboard</a>" in page.text
    assert 'id="blocked-bot-attempts">0<' in page.text
    assert metric.json() == {"blocked_bot_attempts": 0}


def test_dashboard_history_api_returns_hourly_chart_data() -> None:
    with TestClient(app) as client:
        page = client.get("/")
        csrf_token = csrf_from_page(page.text)
        client.post(
            "/auth/login",
            data={"csrf_token": csrf_token, "website_confirm": "blocked"},
        )
        page = client.get("/")
        history = client.get("/api/metrics/blocked-bot-attempts/history")

    assert page.status_code == 200
    assert 'id="attempts-chart"' in page.text
    assert len(history.json()["history"]) == 24
    assert all("timestamp" in item and "count" in item for item in history.json()["history"])
    assert sum(item["count"] for item in history.json()["history"]) == 1


def test_browser_simulation_explains_risk_without_recording_event() -> None:
    with TestClient(app) as client:
        simulation = client.post(
            "/api/simulate/browser-risk",
            json={
                "webdriver": True,
                "interaction_ms": 20,
                "interaction_events": 0,
                "plugin_count": 0,
                "viewport_width": 0,
                "viewport_height": 0,
            },
        )
        metrics = client.get("/api/metrics/blocked-bot-attempts")

    assert simulation.status_code == 200
    assert simulation.json()["level"] == "high"
    assert simulation.json()["decision"] == "Block this browser request"
    assert len(simulation.json()["signals"]) >= 3
    assert [item["stage"] for item in simulation.json()["trace"]] == [
        "validation",
        "rate-limit",
        "honeypot",
        "scoring",
        "policy",
    ]
    assert metrics.json() == {"blocked_bot_attempts": 0}


def test_simulated_honeypot_block_does_not_record_live_event() -> None:
    with TestClient(app) as client:
        simulation = client.post("/api/simulate/browser-risk", json={"honeypot_filled": True})
        metrics = client.get("/api/metrics/blocked-bot-attempts")

    assert simulation.json()["decision"] == "Block this browser request"
    assert simulation.json()["score"] == 100
    assert simulation.json()["trace"][-1]["status"] == "blocked"
    assert metrics.json() == {"blocked_bot_attempts": 0}


def test_random_batch_records_each_simulation_without_inflating_real_blocks() -> None:
    with TestClient(app) as client:
        batch = client.post("/api/simulate/batch", json={"count": 7, "profile": "random"})
        real_metrics = client.get("/api/metrics/blocked-bot-attempts")
        simulated_metrics = client.get("/api/metrics/simulated-requests")
        history = client.get("/api/metrics/blocked-bot-attempts/history")

    result = batch.json()
    assert batch.status_code == 200
    assert result["request_count"] == 7
    assert len(result["results"]) == 7
    assert result["blocked_count"] + result["allowed_count"] == 7
    assert {item["profile"] for item in result["results"]} <= {
        "human",
        "headless",
        "form_filler",
    }
    assert real_metrics.json() == {"blocked_bot_attempts": 0}
    assert simulated_metrics.json() == {"simulated_requests": 7}
    assert [item["stage"] for item in result["trace"]] == [
        "validation",
        "rate-limit",
        "scoring",
        "storage",
    ]
    assert sum(item["count"] for item in history.json()["history"]) == 0
    assert sum(item["count"] for item in history.json()["simulation_history"]) == 7


@pytest.mark.parametrize("count", [2, 26])
def test_simulation_batch_enforces_request_bounds(count: int) -> None:
    with TestClient(app) as client:
        response = client.post("/api/simulate/batch", json={"count": count})

    assert response.status_code == 422


def test_custom_simulation_batch_requires_signals() -> None:
    with TestClient(app) as client:
        response = client.post("/api/simulate/batch", json={"count": 3, "profile": "custom"})

    assert response.status_code == 422


def test_login_rejects_filled_honeypot() -> None:
    with TestClient(app) as client:
        page = client.get("/login")
        response = client.post(
            "/auth/login",
            data={"csrf_token": csrf_from_page(page.text), "website_confirm": "filled"},
        )
        metric = client.get("/api/metrics/blocked-bot-attempts")

    assert response.status_code == 403
    assert metric.json() == {"blocked_bot_attempts": 1}


def test_login_rejects_missing_csrf_token() -> None:
    with TestClient(app) as client:
        client.get("/login")
        response = client.post("/auth/login", data={"website_confirm": ""})

    assert response.status_code == 403


def test_high_risk_browser_telemetry_blocks_login() -> None:
    with TestClient(app) as client:
        page = client.get("/login")
        csrf_token = csrf_from_page(page.text)
        telemetry = client.post(
            "/auth/telemetry",
            headers={"X-CSRF-Token": csrf_token},
            json={"webdriver": True, "interaction_ms": 20, "plugin_count": 0},
        )
        response = client.post(
            "/auth/login",
            data={"csrf_token": csrf_token, "website_confirm": ""},
        )
        metric = client.get("/api/metrics/blocked-bot-attempts")

    assert telemetry.status_code == 200
    assert response.status_code == 403
    assert metric.json() == {"blocked_bot_attempts": 1}


def test_low_risk_login_requires_configured_oidc_provider() -> None:
    with TestClient(app) as client:
        page = client.get("/login")
        response = client.post(
            "/auth/login",
            data={"csrf_token": csrf_from_page(page.text), "website_confirm": ""},
        )

    assert response.status_code == 503


def test_demo_login_creates_local_session_only_when_explicitly_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "demo_login_enabled", True)
    monkeypatch.setattr(settings, "app_env", "development")

    with TestClient(app) as client:
        page = client.get("/login")
        assert 'name="username"' not in page.text
        assert 'name="password"' not in page.text
        assert "Enter local demo" in page.text
        blocked = client.post(
            "/auth/login",
            data={"csrf_token": csrf_from_page(page.text), "website_confirm": "automated"},
        )
        page = client.get("/login")
        response = client.post(
            "/auth/login",
            data={"csrf_token": csrf_from_page(page.text), "website_confirm": ""},
            follow_redirects=False,
        )
        homepage = client.get(response.headers["location"])
        metrics = client.get("/api/metrics/blocked-bot-attempts")

    assert response.status_code == 303
    assert blocked.status_code == 403
    assert homepage.status_code == 200
    assert "Welcome, Demo User" in homepage.text
    assert "BLOCKED BOT ATTEMPTS" not in homepage.text
    assert metrics.json() == {"blocked_bot_attempts": 1}


def test_demo_login_cannot_be_enabled_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "demo_login_enabled", True)
    monkeypatch.setattr(settings, "app_env", "development")

    with TestClient(app) as client:
        page = client.get("/login")
        monkeypatch.setattr(settings, "app_env", "production")
        app.state.rate_limiter = AllowLimiter()
        response = client.post(
            "/auth/login",
            data={"csrf_token": csrf_from_page(page.text), "website_confirm": ""},
        )

    assert response.status_code == 503


def test_local_demo_form_does_not_collect_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "demo_login_enabled", True)
    monkeypatch.setattr(settings, "app_env", "development")

    with TestClient(app) as client:
        page = client.get("/")

    assert 'name="username"' not in page.text
    assert 'name="password"' not in page.text
    assert "Enter local demo" in page.text


def test_configured_oidc_never_renders_password_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "app_env", "development")
    monkeypatch.setattr(settings, "demo_login_enabled", True)
    monkeypatch.setattr(settings, "oidc_issuer_url", "https://idp.example.test/realms/aegis")
    monkeypatch.setattr(
        settings,
        "oidc_metadata_url",
        "https://idp.example.test/realms/aegis/.well-known/openid-configuration",
    )
    monkeypatch.setattr(settings, "oidc_client_id", "aegisauth-web")
    monkeypatch.setattr(settings, "oidc_client_secret", "test-secret")

    with TestClient(app) as client:
        page = client.get("/")

    assert "Continue with organization" in page.text
    assert 'name="username"' not in page.text
    assert 'name="password"' not in page.text
    assert "Development demo only" not in page.text


class AllowLimiter:
    async def check(self, identity: str) -> RateLimitResult:
        return RateLimitResult(True, 59, 0)


class BrokenLimiter:
    async def check(self, identity: str) -> RateLimitResult:
        raise ConnectionError("Redis unavailable")


@pytest.mark.parametrize(
    "secret",
    ["development-only-change-this-secret", "replace-with-a-random-secret"],
)
def test_production_rejects_placeholder_session_secrets(secret: str) -> None:
    config = Settings(
        app_env="production",
        session_secret=secret,
        session_https_only=True,
        database_url="postgresql+asyncpg://localhost/aegisauth",
        redis_url="rediss://localhost:6379",
    )

    with pytest.raises(RuntimeError, match="placeholder"):
        validate_production_settings(config)


def test_production_requires_tls_redis() -> None:
    config = Settings(
        app_env="production",
        session_secret="a" * 48,
        session_https_only=True,
        database_url="postgresql+asyncpg://localhost/aegisauth",
        redis_url="redis://localhost:6379",
    )

    with pytest.raises(RuntimeError, match="TLS"):
        validate_production_settings(config)


def test_production_rejects_partial_oidc_configuration() -> None:
    config = Settings(
        app_env="production",
        session_secret="s" * 48,
        session_https_only=True,
        database_url="postgresql+asyncpg://localhost/aegisauth",
        redis_url="rediss://localhost:6379",
        oidc_client_id="aegisauth-web",
    )

    with pytest.raises(RuntimeError, match="configured together"):
        validate_production_settings(config)


def test_production_requires_https_m2m_issuer() -> None:
    config = Settings(
        app_env="production",
        session_secret="s" * 48,
        session_https_only=True,
        database_url="postgresql+asyncpg://localhost/aegisauth",
        redis_url="rediss://localhost:6379",
        oidc_issuer_url="http://issuer.example.test/",
        jwks_url="https://issuer.example.test/jwks",
        jwt_audience="aegisauth-api",
    )

    with pytest.raises(RuntimeError, match="OIDC_ISSUER_URL must use HTTPS"):
        validate_production_settings(config)


def test_production_rejects_sqlite_database() -> None:
    config = Settings(
        app_env="production",
        session_secret="s" * 48,
        session_https_only=True,
        database_url="sqlite+aiosqlite:///./aegisauth.db",
        redis_url="rediss://localhost:6379",
    )

    with pytest.raises(RuntimeError, match="PostgreSQL"):
        validate_production_settings(config)


def test_settings_reject_invalid_environment_and_limits() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(app_env="prod")
    with pytest.raises(ValidationError):
        Settings(rate_limit_requests=0)
    with pytest.raises(ValidationError):
        Settings(browser_risk_threshold=101)


def test_browser_ip_comes_from_trusted_proxy_forwarded_header() -> None:
    probe = FastAPI()

    @probe.get("/client-ip")
    async def client_ip(request: Request) -> dict[str, str]:
        return {"identity": browser_identity(request)}

    wrapped = ProxyHeadersMiddleware(probe, trusted_hosts="*")
    response = TestClient(wrapped).get(
        "/client-ip",
        headers={"X-Forwarded-For": "198.51.100.42, 10.0.0.8"},
    )

    assert response.json() == {"identity": "browser:198.51.100.42"}


def test_browser_rate_limit_fails_closed_when_redis_is_unavailable() -> None:
    settings = get_settings()
    previous_environment = settings.app_env
    try:
        with TestClient(app) as client:
            page = client.get("/")
            settings.app_env = "production"
            app.state.rate_limiter = BrokenLimiter()
            response = client.post(
                "/auth/login",
                data={"csrf_token": csrf_from_page(page.text), "website_confirm": ""},
            )
    finally:
        settings.app_env = previous_environment

    assert response.status_code == 503
