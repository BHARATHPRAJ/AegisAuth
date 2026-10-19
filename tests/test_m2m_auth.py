from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.m2m_auth import InvalidAccessToken, JWTValidator
from app.main import app
from app.rate_limit import RateLimitResult

ISSUER = "https://issuer.example.test/"
AUDIENCE = "aegisauth-api"
KEY_ID = "test-key"


class FakeLimiter:
    def __init__(self, result: RateLimitResult | None = None) -> None:
        self.result = result or RateLimitResult(True, 9, 0)
        self.identities: list[str] = []

    async def check(self, identity: str) -> RateLimitResult:
        self.identities.append(identity)
        return self.result


def make_jwks_transport(
    private_key: Any,
    request_count: list[int] | None = None,
) -> httpx.MockTransport:
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    public_jwk.update({"kid": KEY_ID, "use": "sig", "alg": "RS256"})

    def handler(request: httpx.Request) -> httpx.Response:
        if request_count is not None:
            request_count.append(1)
        return httpx.Response(200, json={"keys": [public_jwk]})

    return httpx.MockTransport(handler)


def issue_token(private_key: Any, *, kid: str = KEY_ID, **overrides: Any) -> str:
    claims = {
        "iss": ISSUER,
        "sub": "service-a",
        "client_id": "service-a",
        "aud": AUDIENCE,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=5),
        "scope": "api:read",
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def signing_key() -> Any:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.mark.asyncio
async def test_validator_accepts_correct_issuer_audience_and_signature(signing_key: Any) -> None:
    async with httpx.AsyncClient(transport=make_jwks_transport(signing_key)) as client:
        validator = JWTValidator(client, "https://issuer.example.test/jwks", ISSUER, AUDIENCE)
        claims = await validator.validate(issue_token(signing_key))

    assert claims["client_id"] == "service-a"


@pytest.mark.asyncio
async def test_validator_reuses_jwks_within_cache_window(signing_key: Any) -> None:
    requests: list[int] = []
    async with httpx.AsyncClient(transport=make_jwks_transport(signing_key, requests)) as client:
        validator = JWTValidator(client, "https://issuer.example.test/jwks", ISSUER, AUDIENCE)
        token = issue_token(signing_key)
        await validator.validate(token)
        await validator.validate(token)

    assert len(requests) == 1


@pytest.mark.asyncio
async def test_unknown_kid_refresh_is_cooled_down(signing_key: Any) -> None:
    requests: list[int] = []
    async with httpx.AsyncClient(transport=make_jwks_transport(signing_key, requests)) as client:
        validator = JWTValidator(
            client,
            "https://issuer.example.test/jwks",
            ISSUER,
            AUDIENCE,
            unknown_kid_refresh_seconds=60,
        )
        await validator.validate(issue_token(signing_key))
        unknown_kid_token = issue_token(signing_key, kid="unknown-key")

        for _ in range(2):
            with pytest.raises(InvalidAccessToken):
                await validator.validate(unknown_kid_token)

    assert len(requests) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://other.example.test/"},
        {"aud": "other-api"},
        {"exp": datetime.now(UTC) - timedelta(minutes=1)},
    ],
)
async def test_validator_rejects_invalid_standard_claims(
    signing_key: Any, overrides: dict[str, Any]
) -> None:
    async with httpx.AsyncClient(transport=make_jwks_transport(signing_key)) as client:
        validator = JWTValidator(client, "https://issuer.example.test/jwks", ISSUER, AUDIENCE)

        with pytest.raises(InvalidAccessToken):
            await validator.validate(issue_token(signing_key, **overrides))


def test_machine_route_requires_configured_validation_services() -> None:
    response = TestClient(app).get("/api/private", headers={"Authorization": "Bearer token"})

    assert response.status_code == 503


class FakeValidator:
    def __init__(self, claims: dict[str, Any]) -> None:
        self.claims = claims

    async def validate(self, token: str) -> dict[str, Any]:
        if token != "valid-token":
            raise InvalidAccessToken("invalid")
        return self.claims


class BrokenLimiter:
    async def check(self, identity: str) -> RateLimitResult:
        from redis.exceptions import ConnectionError

        raise ConnectionError("Redis unavailable")


@pytest.mark.parametrize(
    ("token", "scopes", "rate_allowed", "expected_status"),
    [
        ("valid-token", "api:read", True, 200),
        ("valid-token", "api:write", True, 403),
        ("invalid-token", "api:read", True, 401),
        ("valid-token", "api:read", False, 429),
    ],
)
def test_machine_route_enforces_token_scope_and_rate_limit(
    token: str,
    scopes: str,
    rate_allowed: bool,
    expected_status: int,
) -> None:
    with TestClient(app) as client:
        app.state.jwt_validator = FakeValidator(
            {"sub": "service-a", "client_id": "service-a", "scope": scopes}
        )
        app.state.rate_limiter = FakeLimiter(
            RateLimitResult(rate_allowed, 0, 10 if not rate_allowed else 0)
        )
        response = client.get(
            "/api/private",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == expected_status
    if expected_status == 429:
        assert response.headers["retry-after"] == "10"


def test_machine_route_fails_closed_when_redis_is_unavailable() -> None:
    with TestClient(app) as client:
        app.state.jwt_validator = FakeValidator(
            {"sub": "service-a", "client_id": "service-a", "scope": "api:read"}
        )
        app.state.rate_limiter = BrokenLimiter()
        response = client.get("/api/private", headers={"Authorization": "Bearer valid-token"})

    assert response.status_code == 503


def test_machine_route_limits_ip_before_verifying_token() -> None:
    blocked_limiter = FakeLimiter(RateLimitResult(False, 0, 17))
    with TestClient(app) as client:
        app.state.jwt_validator = FakeValidator(
            {"sub": "service-a", "client_id": "service-a", "scope": "api:read"}
        )
        app.state.m2m_ip_rate_limiter = blocked_limiter
        app.state.rate_limiter = FakeLimiter()
        response = client.get(
            "/api/private",
            headers={"Authorization": "Bearer invalid-token"},
        )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "17"
    assert blocked_limiter.identities == ["m2m-ip:127.0.0.1"]
