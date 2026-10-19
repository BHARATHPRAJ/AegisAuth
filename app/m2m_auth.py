import asyncio
from dataclasses import dataclass
from time import monotonic
from typing import Any

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.exceptions import RedisError

from app.rate_limit import SlidingWindowRateLimiter

_bearer_scheme = HTTPBearer(auto_error=False)


class InvalidAccessToken(Exception):
    pass


@dataclass(frozen=True)
class MachinePrincipal:
    identity: str
    scopes: frozenset[str]


class JWTValidator:
    def __init__(
        self,
        http_client: httpx.AsyncClient,
        jwks_url: str,
        issuer: str,
        audience: str,
        cache_seconds: int = 300,
        unknown_kid_refresh_seconds: int = 30,
    ) -> None:
        self.http_client = http_client
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.audience = audience
        self.cache_seconds = cache_seconds
        self.unknown_kid_refresh_seconds = unknown_kid_refresh_seconds
        self._jwks: dict[str, Any] | None = None
        self._jwks_expires_at = 0.0
        self._next_unknown_kid_refresh_at = 0.0
        self._jwks_lock = asyncio.Lock()

    async def _get_key(self, kid: str) -> Any:
        async with self._jwks_lock:
            refreshed = False
            if self._jwks is None or monotonic() >= self._jwks_expires_at:
                response = await self.http_client.get(self.jwks_url)
                response.raise_for_status()
                self._jwks = response.json()
                self._jwks_expires_at = monotonic() + self.cache_seconds
                refreshed = True

            keys = self._jwks.get("keys", [])
            key = next((item for item in keys if item.get("kid") == kid), None)
            if key is None:
                now = monotonic()
                if not refreshed and now >= self._next_unknown_kid_refresh_at:
                    response = await self.http_client.get(self.jwks_url)
                    response.raise_for_status()
                    self._jwks = response.json()
                    self._jwks_expires_at = monotonic() + self.cache_seconds
                    keys = self._jwks.get("keys", [])
                    key = next((item for item in keys if item.get("kid") == kid), None)
                self._next_unknown_kid_refresh_at = (
                    monotonic() + self.unknown_kid_refresh_seconds
                )
            if key is None:
                raise InvalidAccessToken("Unknown signing key")
            return jwt.PyJWK.from_dict(key, algorithm="RS256").key

    async def validate(self, encoded_token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(encoded_token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                raise InvalidAccessToken("Unsupported signing algorithm")
            signing_key = await self._get_key(header["kid"])
            claims = jwt.decode(
                encoded_token,
                signing_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except InvalidAccessToken:
            raise
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
            raise InvalidAccessToken("Invalid access token") from exc
        return claims


async def require_machine_client(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> MachinePrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    validator: JWTValidator | None = getattr(request.app.state, "jwt_validator", None)
    limiter: SlidingWindowRateLimiter | None = getattr(request.app.state, "rate_limiter", None)
    ip_limiter: SlidingWindowRateLimiter | None = getattr(
        request.app.state, "m2m_ip_rate_limiter", None
    )
    if validator is None or limiter is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Auth unavailable"
        )

    if ip_limiter is not None:
        client_ip = request.client.host if request.client else "unknown"
        try:
            ip_result = await ip_limiter.check(f"m2m-ip:{client_ip}")
        except RedisError as exc:
            raise HTTPException(
                status_code=503, detail="Rate-limit service unavailable"
            ) from exc
        if not ip_result.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(ip_result.retry_after)},
            )

    try:
        claims = await validator.validate(credentials.credentials)
    except InvalidAccessToken as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Token verification unavailable") from exc

    scope_claim = claims.get("scope", "")
    scopes = frozenset(scope_claim.split()) if isinstance(scope_claim, str) else frozenset()
    if "api:read" not in scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Required scope missing")

    identity = claims.get("client_id") or claims.get("sub")
    if not isinstance(identity, str) or not identity:
        raise HTTPException(status_code=401, detail="Token has no client identity")

    try:
        result = await limiter.check(identity)
    except RedisError as exc:
        raise HTTPException(status_code=503, detail="Rate-limit service unavailable") from exc
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(result.retry_after)},
        )

    return MachinePrincipal(identity=identity, scopes=scopes)
